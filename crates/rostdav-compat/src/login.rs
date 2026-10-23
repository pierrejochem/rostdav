//! Login Flow v2 endpoints used by the app: start and poll.
//! The browser pages live in `rostdav-web`.

use axum::Form;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rostdav_app::AppState;
use rostdav_core::Error;
use serde::Deserialize;
use serde_json::json;

use crate::{CompatConfig, json_response};

/// Base URL for links handed to the app.
pub(crate) fn base_url(cfg: &CompatConfig, headers: &HeaderMap) -> Option<String> {
    if let Some(u) = &cfg.public_url {
        return Some(u.trim_end_matches('/').to_owned());
    }
    let host = headers.get(header::HOST)?.to_str().ok()?;
    // Only plausible host[:port] values; the header is client-controlled.
    let ok = !host.is_empty()
        && host.len() <= 255
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'));
    ok.then(|| format!("http://{host}"))
}

pub async fn start(
    State(state): State<AppState>,
    axum::Extension(cfg): axum::Extension<CompatConfig>,
    headers: HeaderMap,
) -> Response {
    let Some(base) = base_url(&cfg, &headers) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let client = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match state.start_login_flow(client).await {
        Ok(f) => json_response(json!({
            "poll": {
                "token": f.poll_token,
                "endpoint": format!("{base}/login/v2/poll"),
            },
            "login": format!("{base}/login/v2/flow/{}", f.login_token),
        })),
        Err(Error::RateLimited { retry_after_secs }) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after_secs.to_string())],
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "starting login flow failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct PollForm {
    token: String,
}

pub async fn poll(
    State(state): State<AppState>,
    axum::Extension(cfg): axum::Extension<CompatConfig>,
    headers: HeaderMap,
    Form(form): Form<PollForm>,
) -> Response {
    let Some(base) = base_url(&cfg, &headers) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match state.poll_login_flow(&form.token).await {
        Ok(Some(g)) => json_response(json!({
            "server": base,
            "loginName": g.login_name,
            "appPassword": g.app_password,
        })),
        // Same body as the reference server while pending or unknown.
        Ok(None) => {
            let mut r = json_response(json!([]));
            *r.status_mut() = StatusCode::NOT_FOUND;
            r
        }
        Err(e) => {
            tracing::error!(error = %e, "polling login flow failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
