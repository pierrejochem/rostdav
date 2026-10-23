//! `GET /index.php/avatar/<user>/<size>`: the profile picture, for the apps.
//!
//! The picture is sent as it was stored (no resizing), so `size` is ignored. Without a picture
//! the answer is 404 and the app draws its own placeholder. Sign-in is HTTP Basic with an app
//! password, like every other call of the apps; the web pages use the same path with their
//! session cookie.

use axum::extract::{Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rostdav_app::AppState;
use rostdav_core::Error;

/// Basic with an app password (the apps), else the browser session (the pages).
async fn authenticate(
    state: &AppState,
    parts: &Parts,
) -> Result<rostdav_app::Principal, Box<Response>> {
    if let Some(auth) = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        return match state
            .authenticate_basic(auth, crate::ocs::client_ip(parts))
            .await
        {
            Ok(p) => Ok(p),
            Err(Error::RateLimited { retry_after_secs }) => {
                let mut r = StatusCode::TOO_MANY_REQUESTS.into_response();
                if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                    r.headers_mut().insert(header::RETRY_AFTER, v);
                }
                Err(Box::new(r))
            }
            Err(Error::Unauthenticated) => Err(Box::new(StatusCode::UNAUTHORIZED.into_response())),
            Err(_) => Err(Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response())),
        };
    }
    // the cookie of the web interface (`rostdav_session`); only read, so no origin check is needed
    let cookie = parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().strip_prefix("rostdav_session="))
        .next();
    match cookie {
        Some(c) => match state.web_session(c).await {
            Ok(Some(s)) => Ok(s.principal),
            Ok(None) => Err(Box::new(StatusCode::UNAUTHORIZED.into_response())),
            Err(_) => Err(Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response())),
        },
        None => Err(Box::new(StatusCode::UNAUTHORIZED.into_response())),
    }
}

pub(crate) async fn get(
    State(state): State<AppState>,
    Path((user, _size)): Path<(String, String)>,
    parts: Parts,
) -> Response {
    let principal = match authenticate(&state, &parts).await {
        Ok(p) => p,
        Err(r) => return *r,
    };
    match state.avatar(&principal, &user).await {
        Ok(Some(a)) => {
            let not_modified = parts
                .headers
                .get(header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| a.matches(v));
            let mut r = if not_modified {
                StatusCode::NOT_MODIFIED.into_response()
            } else {
                (StatusCode::OK, a.data.clone()).into_response()
            };
            for (k, v) in a.headers() {
                if let (Ok(k), Ok(v)) = (HeaderName::try_from(k), HeaderValue::from_str(&v)) {
                    r.headers_mut().insert(k, v);
                }
            }
            r
        }
        Ok(None) | Err(Error::Forbidden | Error::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
