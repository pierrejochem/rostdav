//! Mapping of service errors to WebDAV responses (RFC 4918 status codes).

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rostdav_core::Error;

pub struct DavError(pub Error);

impl From<Error> for DavError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}

impl DavError {
    pub fn status(&self) -> StatusCode {
        match &self.0 {
            Error::NotFound => StatusCode::NOT_FOUND,
            Error::Unauthenticated => StatusCode::UNAUTHORIZED,
            Error::Forbidden => StatusCode::FORBIDDEN,
            Error::Conflict(_) => StatusCode::CONFLICT,
            Error::AlreadyExists => StatusCode::METHOD_NOT_ALLOWED,
            Error::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            Error::QuotaExceeded => StatusCode::INSUFFICIENT_STORAGE,
            Error::Locked => StatusCode::LOCKED,
            Error::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Error::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Error::BadRequest(_) => StatusCode::BAD_REQUEST,
            Error::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for DavError {
    fn into_response(self) -> Response {
        if self.0.is_internal() {
            tracing::error!(error = %self.0, cause = ?std::error::Error::source(&self.0), "internal error");
        }
        let status = self.status();
        let mut resp = status.into_response();
        if status == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"Rostdav\", charset=\"UTF-8\""),
            );
        }
        if let Error::RateLimited { retry_after_secs } = self.0 {
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        if status == StatusCode::METHOD_NOT_ALLOWED {
            resp.headers_mut().insert(
                header::ALLOW,
                HeaderValue::from_static(crate::ALLOWED_METHODS),
            );
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping() {
        let s = |e| DavError(e).status().as_u16();
        assert_eq!(s(Error::NotFound), 404);
        assert_eq!(s(Error::Unauthenticated), 401);
        assert_eq!(s(Error::Forbidden), 403);
        assert_eq!(s(Error::Conflict("x")), 409);
        assert_eq!(s(Error::AlreadyExists), 405);
        assert_eq!(s(Error::PreconditionFailed), 412);
        assert_eq!(s(Error::QuotaExceeded), 507);
        assert_eq!(s(Error::TooLarge), 413);
        assert_eq!(
            s(Error::RateLimited {
                retry_after_secs: 5
            }),
            429
        );
        assert_eq!(s(Error::BadRequest("x")), 400);
    }

    #[test]
    fn unauthenticated_carries_challenge_and_internal_hides_details() {
        let r = DavError(Error::Unauthenticated).into_response();
        assert!(r.headers().contains_key(header::WWW_AUTHENTICATE));
        let r = DavError(Error::internal(std::io::Error::other("/srv/geheim"))).into_response();
        assert_eq!(r.status(), 500);
    }
}
