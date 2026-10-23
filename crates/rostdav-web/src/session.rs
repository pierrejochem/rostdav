//! Browser session cookie, same-origin check and the signed-in extractor (ADR 0006).

use std::net::{IpAddr, Ipv4Addr};

use crate::i18n::Lang;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use rostdav_app::{AppState, WebSession};
use rostdav_core::ClientIp;

pub const SESSION_COOKIE: &str = "rostdav_session";
pub const LOGIN_COOKIE: &str = "rostdav_login";
/// Proof of the password step while the second factor is outstanding (ADR 0007).
pub const TWOFA_COOKIE: &str = "rostdav_2fa";

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
    /// Used bytes and quota (`None` = unlimited), for the sidebar meter.
    pub storage: (i64, Option<i64>),
    pub admin: bool,
    /// Name shown in the page header: the display name, else the user name.
    pub display: String,
    /// Version of the user's profile picture, if there is one.
    pub avatar: Option<String>,
    pub theme: String,
    pub lang: Lang,
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
        let display = match state.profile(&session.principal).await {
            Ok(p) if !p.display_name.is_empty() => p.display_name,
            _ => session.principal.name.clone(),
        };
        let lang = match state
            .pref(&session.principal, "language")
            .await
            .ok()
            .flatten()
            .as_deref()
            .and_then(Lang::from_code)
        {
            Some(l) => l,
            None => accept_lang(&parts.headers),
        };
        let csrf = state.web_csrf(session.id);
        let avatar = state.avatar_version(&session.principal).await;
        let storage = state
            .storage_summary(&session.principal)
            .await
            .unwrap_or((0, None));
        Ok(Self {
            display,
            avatar,
            lang,
            storage,
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
            user: &self.session.principal.name,
            avatar: self.avatar.as_deref(),
            theme: &self.theme,
            admin: self.admin,
            name: &self.display,
            lang: self.lang,
            storage: self.storage,
        }
    }
}

/// The language asked for by the browser (`Accept-Language`); English if none fits.
pub fn accept_lang(headers: &HeaderMap) -> Lang {
    headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .map(Lang::from_accept)
        .unwrap_or_default()
}
