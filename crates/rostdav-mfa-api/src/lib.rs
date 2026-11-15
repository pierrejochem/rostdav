//! HTTP API of the RustMFA app (ADR 0014, contract `rustmfa-v1.yaml`).
//!
//! A phone proves itself with `Authorization: RustMFA-Sig …` over the method, the path and query
//! exactly as received, a timestamp, a nonce and the hash of the body; the check lives in
//! `rostdav-app`. This crate reads the request, calls the service and shapes the answer. It never
//! touches the database. Registration is the one route without a signature: it carries the
//! single-use enrollment token.

mod error;

use std::net::{IpAddr, Ipv4Addr};

use axum::body::{Body, Bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use rostdav_app::{
    AppState, ChallengeDetails, DeviceInfo, DevicePrincipal, MfaAuditEvent, MfaError, RegisterInput,
};
use rostdav_core::ClientIp;
use serde::Deserialize;
use serde_json::{Value, json};

pub use error::ApiError;

/// The longest request body read, in bytes.
const MAX_BODY: usize = 64 * 1024;

/// The ten device routes under `/api/v1`. The eleventh operation of the contract, creating an
/// enrollment token, needs the web session and belongs to the web crate. The paths are complete
/// (no nesting), so the signed path is the one the phone sent.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/devices/register", post(register))
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/devices/{device_id}", delete(revoke_device))
        .route("/api/v1/devices/{device_id}/push-token", put(push_token))
        .route("/api/v1/devices/{device_id}/rotate-key", post(rotate_key))
        .route("/api/v1/mfa/challenges", get(list_challenges))
        .route("/api/v1/mfa/challenges/{challenge_id}", get(get_challenge))
        .route(
            "/api/v1/mfa/challenges/{challenge_id}/approve",
            post(approve),
        )
        .route("/api/v1/mfa/challenges/{challenge_id}/deny", post(deny))
        .route("/api/v1/audit", get(audit))
        .layer(axum::middleware::map_response(no_store))
}

/// Answers carry personal and security data: nothing may be cached.
async fn no_store(mut res: Response) -> Response {
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn invalid(reason: &'static str) -> ApiError {
    MfaError::InvalidRequest(reason).into()
}

/// The body, at most [`MAX_BODY`] bytes.
async fn read_body(body: Body) -> Result<Bytes, ApiError> {
    axum::body::to_bytes(body, MAX_BODY)
        .await
        .map_err(|_| ApiError::TooLarge)
}

/// Strict JSON: unknown fields and anything else that does not fit the type are `INVALID_REQUEST`.
fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(bytes)
        .map_err(|_| invalid("request body is not valid for this operation"))
}

/// Checks the signature of the request and returns the phone and the raw body. Exactly one
/// `Authorization` header counts. The body is read before the check because its hash is signed.
async fn authenticate(
    state: &AppState,
    req: Request,
) -> Result<(DevicePrincipal, Bytes), ApiError> {
    let (parts, body) = req.into_parts();
    let mut values = parts.headers.get_all(header::AUTHORIZATION).iter();
    let header = match (values.next(), values.next()) {
        (Some(v), None) => v.to_str().map_err(|_| MfaError::Unauthenticated)?,
        _ => return Err(MfaError::Unauthenticated.into()),
    };
    let bytes = read_body(body).await?;
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path(), |p| p.as_str());
    let who = state
        .mfa_authenticate_device(header, parts.method.as_str(), path_and_query, &bytes)
        .await?;
    Ok((who, bytes))
}

// ---- registration -----------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    enroll_token: String,
    device_name: String,
    request_public_key: String,
    approval_public_key: String,
    key_algorithm: String,
    attestation_chain: Vec<String>,
    push_channel: String,
    push_token: String,
}

async fn register(State(state): State<AppState>, req: Request) -> Result<Response, ApiError> {
    let ip = req
        .extensions()
        .get::<ClientIp>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0);
    let bytes = read_body(req.into_body()).await?;
    let b: RegisterBody = parse(&bytes)?;
    let done = state
        .mfa_register_device(
            RegisterInput {
                enroll_token: b.enroll_token,
                device_name: b.device_name,
                request_public_key: b.request_public_key,
                approval_public_key: b.approval_public_key,
                key_algorithm: b.key_algorithm,
                attestation_chain: b.attestation_chain,
                push_channel: b.push_channel,
                push_token: b.push_token,
            },
            ip,
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "device_id": done.device_id, "status": done.status })),
    )
        .into_response())
}

// ---- devices ----------------------------------------------------------------------------------

fn device_json(d: DeviceInfo) -> Value {
    json!({
        "device_id": d.device_id,
        "device_name": d.device_name,
        "status": d.status,
        "push_channel": d.push_channel,
        "hardware_backed": d.hardware_backed,
        "strongbox": d.strongbox,
        "created_at": d.created_at,
        "last_seen_at": d.last_seen_at,
    })
}

async fn list_devices(State(state): State<AppState>, req: Request) -> Result<Response, ApiError> {
    let (who, _) = authenticate(&state, req).await?;
    let devices: Vec<Value> = state
        .mfa_list_devices(who.user_id)
        .await?
        .into_iter()
        .map(device_json)
        .collect();
    Ok(Json(json!({ "devices": devices })).into_response())
}

async fn revoke_device(
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    let (who, _) = authenticate(&state, req).await?;
    state.mfa_revoke_device_as(&who, &device_id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PushTokenBody {
    push_channel: String,
    push_token: String,
}

fn status_of(device_id: &str) -> Response {
    Json(json!({ "device_id": device_id, "status": "active" })).into_response()
}

async fn push_token(
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    let (who, bytes) = authenticate(&state, req).await?;
    let b: PushTokenBody = parse(&bytes)?;
    state
        .mfa_update_push_token(&who, &device_id, &b.push_channel, &b.push_token)
        .await?;
    Ok(status_of(&device_id))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateBody {
    request_public_key: String,
    approval_public_key: String,
    attestation_chain: Vec<String>,
}

async fn rotate_key(
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    let (who, bytes) = authenticate(&state, req).await?;
    let b: RotateBody = parse(&bytes)?;
    state
        .mfa_rotate_keys(
            &who,
            &device_id,
            &b.request_public_key,
            &b.approval_public_key,
            &b.attestation_chain,
        )
        .await?;
    Ok(status_of(&device_id))
}

// ---- challenges -------------------------------------------------------------------------------

fn challenge_json(c: ChallengeDetails) -> Value {
    json!({
        "challenge_id": c.challenge_id,
        "service_name": c.service_name,
        "login_device": c.login_device,
        "approximate_location": c.approximate_location,
        "created_at": c.created_at,
        "expires_at": c.expires_at,
        "status": c.status.as_str(),
        "candidate_numbers": c.candidate_numbers,
        "nonce": c.nonce,
        "login_id": c.login_id,
        "audience": c.audience,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    status: Option<String>,
}

/// Only pending challenges are listed (the polling fallback for a late push).
async fn list_challenges(
    State(state): State<AppState>,
    req: Request,
) -> Result<Response, ApiError> {
    let query = req.uri().query().unwrap_or("").to_owned();
    let (who, _) = authenticate(&state, req).await?;
    let q: ListQuery = serde_urlencoded::from_str(&query)
        .map_err(|_| invalid("query string is not valid for this operation"))?;
    if q.status.as_deref().is_some_and(|s| s != "pending") {
        return Err(invalid("only status=pending can be listed"));
    }
    let challenges: Vec<Value> = state
        .mfa_pending_challenges(&who)
        .await?
        .into_iter()
        .map(challenge_json)
        .collect();
    Ok(Json(json!({ "challenges": challenges })).into_response())
}

async fn get_challenge(
    State(state): State<AppState>,
    Path(id): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    let (who, _) = authenticate(&state, req).await?;
    let d = state.mfa_get_challenge(&who, &id).await?;
    Ok(Json(challenge_json(d)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveBody {
    device_id: String,
    selected_number: i64,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DenyBody {
    device_id: String,
    signature: String,
}

fn answered(id: &str, status: rostdav_app::ChallengeStatus) -> Response {
    Json(json!({ "challenge_id": id, "status": status.as_str() })).into_response()
}

/// The `device_id` in the body must be the signing phone: a phone cannot answer for another.
fn same_device(who: &DevicePrincipal, body_device: &str) -> Result<(), ApiError> {
    if body_device == who.device_id {
        Ok(())
    } else {
        Err(MfaError::DeviceNotAuthorized.into())
    }
}

async fn approve(
    State(state): State<AppState>,
    Path(id): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    let (who, bytes) = authenticate(&state, req).await?;
    let b: ApproveBody = parse(&bytes)?;
    same_device(&who, &b.device_id)?;
    let status = state
        .mfa_approve(&who, &id, b.selected_number, &b.signature)
        .await?;
    Ok(answered(&id, status))
}

async fn deny(
    State(state): State<AppState>,
    Path(id): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    let (who, bytes) = authenticate(&state, req).await?;
    let b: DenyBody = parse(&bytes)?;
    same_device(&who, &b.device_id)?;
    let status = state.mfa_deny(&who, &id, &b.signature).await?;
    Ok(answered(&id, status))
}

// ---- audit ------------------------------------------------------------------------------------

fn event_json(e: MfaAuditEvent) -> Value {
    json!({ "event": e.event, "at": e.at, "device_id": e.device_id, "detail": e.detail })
}

async fn audit(State(state): State<AppState>, req: Request) -> Result<Response, ApiError> {
    let (who, _) = authenticate(&state, req).await?;
    let events: Vec<Value> = state
        .mfa_audit_events(who.user_id)
        .await?
        .into_iter()
        .map(event_json)
        .collect();
    Ok(Json(json!({ "events": events })).into_response())
}
