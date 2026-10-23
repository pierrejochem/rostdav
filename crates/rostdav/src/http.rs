//! HTTP router and shared middleware.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rostdav_app::AppState;
use serde_json::json;
use tower::ServiceBuilder;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;

const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Settings the HTTP layer needs besides the application state.
#[derive(Clone, Debug, Default)]
pub struct HttpOptions {
    pub trusted_proxies: Vec<IpAddr>,
    pub public_url: Option<String>,
    pub reported_version: Option<String>,
    pub product_name: Option<String>,
    pub max_chunk_bytes: Option<u64>,
}

impl HttpOptions {
    pub fn from_config(cfg: &crate::config::Config) -> Self {
        Self {
            trusted_proxies: cfg.server.trusted_proxies.clone(),
            public_url: cfg.server.public_url.clone(),
            reported_version: Some(cfg.compat.reported_version.clone()),
            product_name: Some(cfg.compat.product_name.clone()),
            max_chunk_bytes: Some(cfg.limits.max_chunk_bytes),
        }
    }
}

/// Builds the router with default options (tests, health checks).
pub fn router(state: AppState) -> Router {
    router_with(state, &HttpOptions::default())
}

/// Builds the complete router including middleware.
pub fn router_with(state: AppState, opts: &HttpOptions) -> Router {
    let mut compat = rostdav_compat::CompatConfig::default();
    compat.public_url.clone_from(&opts.public_url);
    if let Some(v) = &opts.reported_version {
        compat.version.clone_from(v);
    }
    if let Some(n) = &opts.product_name {
        compat.product_name.clone_from(n);
    }
    compat.versioning = state.versioning_enabled();
    compat.trash = state.trash_enabled();
    if let Some(m) = opts.max_chunk_bytes {
        compat.max_chunk_bytes = m;
    }
    let proxies = Arc::new(opts.trusted_proxies.clone());

    let middleware = ServiceBuilder::new()
        .layer(SetSensitiveRequestHeadersLayer::new([header::AUTHORIZATION, header::COOKIE]))
        .layer(SetRequestIdLayer::new(REQUEST_ID, MakeRequestUuid))
        .layer(TraceLayer::new_for_http().make_span_with(|req: &Request<_>| {
            let request_id = req
                .headers()
                .get(&REQUEST_ID)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-");
            // Only the path, never the query, and secrets in paths are masked.
            tracing::info_span!("request", method = %req.method(), path = %loggable_path(req.uri().path()), request_id)
        }).on_response(DefaultOnResponse::new().level(Level::INFO)))
        .layer(PropagateRequestIdLayer::new(REQUEST_ID))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        // not overriding: web pages send `same-origin`, because with `no-referrer`
        // browsers put `Origin: null` on form posts and the same-origin check fails
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .merge(rostdav_dav::router())
        .merge(rostdav_compat::router(compat))
        .merge(rostdav_web::router())
        .layer(middleware)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            maintenance_gate,
        ))
        .layer(axum::middleware::from_fn_with_state(proxies, client_ip))
        .with_state(state)
}

/// Maintenance mode (set by an administrator): the interfaces the Nextcloud apps use answer 503
/// in the reference's formats (Nextcloud 35.0.2, recorded with `occ maintenance:mode --on`):
/// Sabre XML for WebDAV, an OCS failure for OCS. `status.php` (reports `maintenance: true`), the
/// web interface, the sign-in pages and the health checks stay reachable, so an administrator can
/// switch it off again.
async fn maintenance_gate(
    State(state): State<AppState>,
    req: Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path();
    let dav = path.starts_with("/remote.php/") || path.starts_with("/public.php/");
    let ocs = path.starts_with("/ocs/") || path.starts_with("/index.php/ocs/");
    if !state.maintenance() || !(dav || ocs) {
        return next.run(req).await;
    }
    let (ctype, body) = if dav {
        (
            "application/xml; charset=utf-8",
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
             <d:error xmlns:d=\"DAV:\" xmlns:s=\"http://sabredav.org/ns\">\n  \
             <s:exception>OCA\\DAV\\Exception\\ServerMaintenanceMode</s:exception>\n  \
             <s:message>System is in maintenance mode.</s:message>\n</d:error>\n"
                .to_owned(),
        )
    } else if req.uri().query().is_some_and(|q| q.contains("format=json")) {
        // v1 also carries the (empty) paging fields; only recorded for v2 (an assumption for v1).
        let paging = if path.contains("/v1.php/") {
            ",\"totalitems\":\"\",\"itemsperpage\":\"\""
        } else {
            ""
        };
        (
            "application/json; charset=utf-8",
            format!(
                "{{\"ocs\":{{\"meta\":{{\"status\":\"failure\",\"statuscode\":503,\"message\":\"Service unavailable\"{paging}}},\"data\":[]}}}}"
            ),
        )
    } else {
        (
            "text/xml; charset=UTF-8",
            "<?xml version=\"1.0\"?>\n<ocs>\n <meta>\n  <status>failure</status>\n  <statuscode>503</statuscode>\n  \
             <message>Service unavailable</message>\n  <totalitems></totalitems>\n  <itemsperpage></itemsperpage>\n </meta>\n <data/>\n</ocs>\n"
                .to_owned(),
        )
    };
    let mut r = (StatusCode::SERVICE_UNAVAILABLE, body).into_response();
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    r
}

/// Masks tokens that are part of a URL path before it is logged.
pub fn loggable_path(path: &str) -> std::borrow::Cow<'_, str> {
    const FLOW: &str = "/login/v2/flow/";
    match path.find(FLOW) {
        Some(i) if path.len() > i + FLOW.len() => {
            std::borrow::Cow::Owned(format!("{}{FLOW}<redacted>", &path[..i]))
        }
        _ => std::borrow::Cow::Borrowed(path),
    }
}

/// Determines the client address: the socket peer, or the right-most
/// `X-Forwarded-For` entry that is not a trusted proxy when the peer is one.
pub fn resolve_client_ip(peer: IpAddr, forwarded_for: Option<&str>, trusted: &[IpAddr]) -> IpAddr {
    if !trusted.contains(&peer) {
        return peer;
    }
    forwarded_for
        .into_iter()
        .flat_map(|v| v.split(',').rev())
        .filter_map(|e| e.trim().parse::<IpAddr>().ok())
        .find(|ip| !trusted.contains(ip))
        .unwrap_or(peer)
}

async fn client_ip(
    State(trusted): State<Arc<Vec<IpAddr>>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    if let Some(peer) = peer {
        let xff = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok());
        let ip = resolve_client_ip(peer, xff, &trusted);
        req.extensions_mut().insert(rostdav_core::ClientIp(ip));
    }
    next.run(req).await
}

/// Process is alive. Deliberately checks no dependencies.
async fn healthz() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Ready for requests: database and data directory reachable.
/// Causes are only logged, not returned.
async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    match state.readiness().await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(err) => {
            tracing::error!(error = %err, cause = ?std::error::Error::source(&err), "readiness check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "unavailable" })),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn untrusted_peer_cannot_spoof_forwarded_for() {
        assert_eq!(
            resolve_client_ip(ip("203.0.113.9"), Some("1.2.3.4"), &[ip("10.0.0.1")]),
            ip("203.0.113.9")
        );
        assert_eq!(
            resolve_client_ip(ip("203.0.113.9"), Some("1.2.3.4"), &[]),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn trusted_proxy_chain_uses_rightmost_untrusted() {
        let trusted = [ip("10.0.0.1"), ip("10.0.0.2")];
        assert_eq!(
            resolve_client_ip(
                ip("10.0.0.1"),
                Some("6.6.6.6, 198.51.100.7, 10.0.0.2"),
                &trusted
            ),
            ip("198.51.100.7")
        );
        // a client-forged left entry is ignored
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), Some("6.6.6.6, 198.51.100.7"), &trusted),
            ip("198.51.100.7")
        );
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), None, &trusted),
            ip("10.0.0.1")
        );
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), Some("garbage, 10.0.0.2"), &trusted),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn flow_tokens_are_masked_in_logs() {
        assert_eq!(
            loggable_path("/login/v2/flow/SECRET"),
            "/login/v2/flow/<redacted>"
        );
        assert_eq!(
            loggable_path("/index.php/login/v2/flow/SECRET"),
            "/index.php/login/v2/flow/<redacted>"
        );
        assert_eq!(loggable_path("/login/v2/flow"), "/login/v2/flow");
        assert_eq!(loggable_path("/healthz"), "/healthz");
    }
}
