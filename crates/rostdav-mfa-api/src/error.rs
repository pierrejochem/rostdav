//! Errors of the device API: the body and status of the contract.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rostdav_app::MfaError;
use serde_json::json;

/// Everything a handler can fail with.
pub enum ApiError {
    Mfa(MfaError),
    /// The body is longer than the limit (413, `INVALID_REQUEST`).
    TooLarge,
}

impl From<MfaError> for ApiError {
    fn from(e: MfaError) -> Self {
        Self::Mfa(e)
    }
}

fn body(code: &str, message: &str) -> Json<serde_json::Value> {
    Json(json!({ "error": { "code": code, "message": message } }))
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::TooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                body("INVALID_REQUEST", "The request body is too large."),
            )
                .into_response(),
            Self::Mfa(e) => {
                if let MfaError::Internal(cause) = &e {
                    // the cause stays in the log; the client gets the generic message
                    tracing::error!(error = %cause, "push sign-in request failed");
                }
                let status =
                    StatusCode::from_u16(e.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                let mut res = (status, body(e.code(), e.message())).into_response();
                if let MfaError::RateLimited { retry_after_secs } = &e
                    && let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string())
                {
                    res.headers_mut().insert(header::RETRY_AFTER, v);
                }
                res
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn text(e: ApiError) -> (StatusCode, String) {
        let res = e.into_response();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 4096)
            .await
            .expect("body");
        (status, String::from_utf8(bytes.to_vec()).expect("utf8"))
    }

    #[tokio::test]
    async fn an_internal_error_does_not_reach_the_client() {
        let cause = rostdav_core::Error::BadRequest("secret detail of the cause");
        let (status, body) = text(MfaError::Internal(cause).into()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("INTERNAL_ERROR"));
        assert!(!body.contains("secret"), "{body}");
    }

    #[tokio::test]
    async fn the_bodies_have_the_contract_shape() {
        let (status, body) = text(ApiError::TooLarge).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["error"]["code"], "INVALID_REQUEST");
        assert!(v["error"]["message"].is_string());
        assert_eq!(v.as_object().expect("object").len(), 1);
    }
}
