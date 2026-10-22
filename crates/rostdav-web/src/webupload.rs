//! Chunked upload for the browser (ADR 0006, slice 11b): a small JSON/binary API
//! on web routes, backed by the same chunk store as the Nextcloud chunked upload.
//!
//! Authentication is the browser session. Every request that changes something
//! must also carry the CSRF token in the `X-CSRF-Token` header (a header a
//! cross-site form cannot set) and passes the same-origin check of [`Authed`].

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rostdav_app::AppState;
use rostdav_core::{Error, Name};
use serde::Deserialize;
use serde_json::json;
use tokio_util::io::StreamReader;

use crate::pages::parse_plain;
use crate::session::Authed;

fn api_error(e: &Error) -> Response {
    let (status, msg) = match e {
        Error::NotFound => (StatusCode::NOT_FOUND, "not found"),
        Error::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
        Error::AlreadyExists | Error::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
        Error::QuotaExceeded => (StatusCode::INSUFFICIENT_STORAGE, "storage is full"),
        Error::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too large"),
        Error::BadRequest(_) | Error::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid request"),
        other => {
            tracing::error!(error = %other, "web upload failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    };
    json_response(status, &json!({ "error": msg }))
}

fn json_response(status: StatusCode, v: &serde_json::Value) -> Response {
    let mut r = (status, Json(v)).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn csrf_ok(state: &AppState, a: &Authed, headers: &HeaderMap) -> bool {
    let given = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    state.web_check_csrf(a.session.id, given).is_ok()
}

fn forbidden() -> Response {
    json_response(StatusCode::FORBIDDEN, &json!({ "error": "forbidden" }))
}

/// Chunks already stored for a transfer: lets a client resume.
pub async fn list(State(state): State<AppState>, a: Authed, Path(id): Path<String>) -> Response {
    match state.upload_list(&a.session.principal, &id).await {
        Ok(l) => json_response(
            StatusCode::OK,
            &json!({ "chunks": l.chunks.iter().map(|c| json!({"name": c.name, "size": c.size})).collect::<Vec<_>>() }),
        ),
        Err(e) => api_error(&e),
    }
}

pub async fn create(
    State(state): State<AppState>,
    a: Authed,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !csrf_ok(&state, &a, &headers) {
        return forbidden();
    }
    match state.upload_create(&a.session.principal, &id).await {
        Ok(()) => json_response(StatusCode::CREATED, &json!({})),
        Err(e) => api_error(&e),
    }
}

pub async fn chunk(
    State(state): State<AppState>,
    a: Authed,
    headers: HeaderMap,
    Path((id, name)): Path<(String, String)>,
    body: Body,
) -> Response {
    if !csrf_ok(&state, &a, &headers) {
        return forbidden();
    }
    let reader = StreamReader::new(Adapter(body.into_data_stream()));
    match state
        .upload_chunk(&a.session.principal, &id, &name, reader)
        .await
    {
        Ok(_) => json_response(StatusCode::OK, &json!({})),
        Err(e) => api_error(&e),
    }
}

#[derive(Deserialize)]
pub struct Finish {
    dir: String,
    name: String,
    total: u64,
}

pub async fn finish(
    State(state): State<AppState>,
    a: Authed,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(f): Json<Finish>,
) -> Response {
    if !csrf_ok(&state, &a, &headers) {
        return forbidden();
    }
    let res = async {
        let dest = parse_plain(&f.dir)?.join(&Name::parse(&f.name)?);
        state
            .upload_assemble(&a.session.principal, &id, &dest, true, Some(f.total), None)
            .await
    }
    .await;
    match res {
        Ok(_) => json_response(StatusCode::OK, &json!({})),
        Err(e) => api_error(&e),
    }
}

pub async fn abort(
    State(state): State<AppState>,
    a: Authed,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !csrf_ok(&state, &a, &headers) {
        return forbidden();
    }
    match state.upload_delete(&a.session.principal, &id).await {
        Ok(()) => json_response(StatusCode::OK, &json!({})),
        Err(e) => api_error(&e),
    }
}

struct Adapter<S>(S);

impl<S> futures_core::Stream for Adapter<S>
where
    S: futures_core::Stream<Item = Result<axum::body::Bytes, axum::Error>> + Unpin,
{
    type Item = std::io::Result<axum::body::Bytes>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.0)
            .poll_next(cx)
            .map(|o| o.map(|r| r.map_err(std::io::Error::other)))
    }
}
