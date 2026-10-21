//! HTTP-Router und gemeinsame Middleware.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, Request, StatusCode, header};
use axum::response::IntoResponse;
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

/// Baut den vollständigen Router inklusive Middleware.
pub fn router(state: AppState) -> Router {
    let middleware = ServiceBuilder::new()
        .layer(SetSensitiveRequestHeadersLayer::new([header::AUTHORIZATION, header::COOKIE]))
        .layer(SetRequestIdLayer::new(REQUEST_ID, MakeRequestUuid))
        .layer(TraceLayer::new_for_http().make_span_with(|req: &Request<_>| {
            let request_id = req
                .headers()
                .get(&REQUEST_ID)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-");
            // Nur der Pfad, nie die Query: dort können später Tokens stehen.
            tracing::info_span!("request", method = %req.method(), path = %req.uri().path(), request_id)
        }).on_response(DefaultOnResponse::new().level(Level::INFO)))
        .layer(PropagateRequestIdLayer::new(REQUEST_ID))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .merge(rostdav_dav::router())
        .merge(rostdav_compat::router())
        .merge(rostdav_web::router())
        .layer(middleware)
        .with_state(state)
}

/// Prozess lebt. Prüft bewusst keine Abhängigkeiten.
async fn healthz() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Bereit für Anfragen: Datenbank und Datenverzeichnis erreichbar.
/// Ursachen werden nur geloggt, nicht ausgeliefert.
async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    match state.readiness().await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(err) => {
            tracing::error!(error = %err, cause = ?std::error::Error::source(&err), "Bereitschaftsprüfung fehlgeschlagen");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "unavailable" })),
            )
        }
    }
}
