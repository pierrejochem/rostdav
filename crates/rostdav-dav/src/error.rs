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
            Error::BadRequest(_) | Error::Invalid(_) => StatusCode::BAD_REQUEST,
            Error::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl DavError {
    /// Sabre/DAV exception class and message, as in the reference bodies
    /// (`tests/fixtures/nextcloud/04-webdav/`). Internal details never appear.
    fn sabre(&self) -> (&'static str, String) {
        let (class, msg): (&str, String) = match &self.0 {
            Error::NotFound => ("NotFound", "File with name could not be located".into()),
            Error::Unauthenticated => (
                "NotAuthenticated",
                "No public access to this resource.".into(),
            ),
            Error::Forbidden => ("Forbidden", "Access denied".into()),
            Error::Conflict(m) => ("Conflict", (*m).into()),
            Error::AlreadyExists => (
                "MethodNotAllowed",
                "The resource you tried to create already exists".into(),
            ),
            Error::PreconditionFailed => (
                "PreconditionFailed",
                "A precondition of the request was not met".into(),
            ),
            Error::QuotaExceeded => ("InsufficientStorage", "Insufficient storage".into()),
            Error::Locked => ("Locked", "Locked".into()),
            Error::TooLarge => ("PayloadTooLarge", "The request is too large".into()),
            Error::RateLimited { .. } => (
                "TooManyRequests",
                "Too many failed attempts, try again later".into(),
            ),
            Error::BadRequest(m) => ("BadRequest", (*m).into()),
            Error::Invalid(m) => ("BadRequest", m.clone()),
            Error::Unavailable => ("ServiceUnavailable", "Service unavailable".into()),
            Error::Internal(_) => ("ServiceUnavailable", "Internal server error".into()),
        };
        (class, msg)
    }
}

impl IntoResponse for DavError {
    fn into_response(self) -> Response {
        if self.0.is_internal() {
            tracing::error!(error = %self.0, cause = ?std::error::Error::source(&self.0), "internal error");
        }
        let status = self.status();
        let (class, msg) = self.sabre();
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:error xmlns:d=\"DAV:\" xmlns:s=\"http://sabredav.org/ns\">\n  <s:exception>Sabre\\DAV\\Exception\\{class}</s:exception>\n  <s:message>{}</s:message>\n</d:error>\n",
            crate::xml::escape_text(&msg)
        );
        let mut resp = (status, body).into_response();
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml; charset=utf-8"),
        );
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

    #[tokio::test]
    async fn bodies_are_sabre_xml_and_internal_hides_details() {
        use http_body_util_lite::body_string;
        let r = DavError(Error::Unauthenticated).into_response();
        assert!(r.headers().contains_key(header::WWW_AUTHENTICATE));
        let b = body_string(r).await;
        assert!(
            b.contains("<s:exception>Sabre\\DAV\\Exception\\NotAuthenticated</s:exception>"),
            "{b}"
        );

        let r =
            DavError(Error::internal(std::io::Error::other("/srv/secret-path"))).into_response();
        assert_eq!(r.status(), 500);
        let b = body_string(r).await;
        assert!(!b.contains("secret-path"));
        assert!(b.contains("Internal server error"));

        let r = DavError(Error::Invalid("a<b&c".into())).into_response();
        let b = body_string(r).await;
        assert!(b.contains("a&lt;b&amp;c"), "{b}");
        assert_eq!(
            DavError(Error::AlreadyExists).into_response().headers()["allow"],
            crate::ALLOWED_METHODS
        );
    }

    mod http_body_util_lite {
        pub async fn body_string(r: axum::response::Response) -> String {
            let bytes = axum::body::to_bytes(r.into_body(), 1 << 20)
                .await
                .expect("body");
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }
}
