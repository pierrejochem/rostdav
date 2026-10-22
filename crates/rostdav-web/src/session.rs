//! Browser session cookie, same-origin check and the signed-in extractor (ADR 0006).

use std::net::{IpAddr, Ipv4Addr};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use rostdav_app::{AppState, WebSession};
use rostdav_core::ClientIp;

pub const SESSION_COOKIE: &str = "rostdav_session";
pub const LOGIN_COOKIE: &str = "rostdav_login";

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
}

fn is_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("https"))
}

/// `Set-Cookie` value; `max_age` of `None` makes a session cookie, `Some(0)` clears it.
pub fn set_cookie(
    headers: &HeaderMap,
    name: &str,
    value: &str,
    max_age: Option<i64>,
) -> HeaderValue {
    set_cookie_at(headers, name, value, "/", max_age)
}

pub fn set_cookie_at(
    headers: &HeaderMap,
    name: &str,
    value: &str,
    path: &str,
    max_age: Option<i64>,
) -> HeaderValue {
    let mut c = format!("{name}={value}; Path={path}; HttpOnly; SameSite=Lax");
    if let Some(m) = max_age {
        c.push_str(&format!("; Max-Age={m}"));
    }
    if is_https(headers) {
        c.push_str("; Secure");
    }
    HeaderValue::from_str(&c).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// Origin (or, failing that, Referer) of a state-changing request must be this host.
pub fn same_origin(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let source = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|v| v.to_str().ok());
    let Some(source) = source else { return false };
    let Some((_, rest)) = source.split_once("://") else {
        return false;
    };
    rest.split(['/', '?', '#']).next() == Some(host)
}

pub fn client_ip(parts: &Parts) -> IpAddr {
    parts
        .extensions
        .get::<ClientIp>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0)
}

/// A signed-in browser session. Unsafe methods must also pass the origin check.
pub struct Authed {
    pub session: WebSession,
    pub admin: bool,
    pub theme: String,
    pub csrf: String,
}

impl FromRequestParts<AppState> for Authed {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let unsafe_method = !matches!(parts.method, Method::GET | Method::HEAD);
        if unsafe_method && !same_origin(&parts.headers) {
            return Err(StatusCode::FORBIDDEN.into_response());
        }
        let session = match cookie_value(&parts.headers, SESSION_COOKIE) {
            Some(c) => state.web_session(&c).await.ok().flatten(),
            None => None,
        };
        let Some(session) = session else {
            return Err(Redirect::to("/login").into_response());
        };
        let theme = state
            .pref(&session.principal, "theme")
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        let csrf = state.web_csrf(session.id);
        Ok(Self {
            admin: session.principal.is_admin,
            session,
            theme,
            csrf,
        })
    }
}

impl Authed {
    pub fn chrome(&self) -> crate::layout::Chrome<'_> {
        crate::layout::Chrome {
            theme: &self.theme,
            admin: self.admin,
        }
    }
}
