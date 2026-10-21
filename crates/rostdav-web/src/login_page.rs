//! Login Flow v2 page: client name, user name, password; allow or deny.
//! Layout follows `design/mockups/web-ui/Login.dc.html`.

use std::net::{IpAddr, Ipv4Addr};

use axum::Form;
use axum::extract::{Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rostdav_app::AppState;
use rostdav_core::{ClientIp, Error};
use serde::Deserialize;

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

const CSS: &str = "\
:root{color-scheme:dark}*{box-sizing:border-box}\
body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:28px;\
padding:32px 16px;background:#15171C;color:#F4EFE8;font-family:'Space Grotesk',system-ui,sans-serif}\
.brand{font-size:34px;font-weight:700;letter-spacing:-1.5px}.brand b{color:#E8783A}\
.card{width:100%;max-width:440px;background:#1F2229;border:1px solid #2E313A;border-radius:20px;padding:28px;display:flex;flex-direction:column;gap:20px}\
.client{padding:14px;border-radius:14px;background:#2A2D35}.client b{display:block;font-size:15px}.client span{font-size:13px;color:#C9C2B9}\
h1{margin:0;font-size:26px;letter-spacing:-.8px}p{margin:8px 0 0;font-size:15px;line-height:1.5;color:#C9C2B9}\
form{display:flex;flex-direction:column;gap:14px}label{display:flex;flex-direction:column;gap:6px;font-size:14px;font-weight:600}\
input{min-height:48px;padding:0 14px;border-radius:12px;border:1px solid #3A3D45;background:#15171C;font:inherit;font-size:16px;color:#F4EFE8}\
button{min-height:48px;border-radius:12px;font:inherit;font-weight:700;cursor:pointer}\
.allow{border:0;background:#C2491D;color:#fff}.deny{border:1px solid #3A3D45;background:transparent;color:#E9E3DB;font-weight:600}\
.err{padding:12px 14px;border-radius:12px;background:#3A2419;color:#F2A65A;font-size:14px}\
.note{font-size:13px;line-height:1.5;color:#A8A29C}.foot{font:12px ui-monospace,monospace;letter-spacing:1px;color:#A8A29C;text-align:center}";

fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>Rostdav – {}</title><style>{CSS}</style></head><body>\
         <div class=\"brand\">rost<b>dav</b></div>{body}\
         <div class=\"foot\">Rostdav · compatible with Nextcloud clients · not a Nextcloud product</div>\
         </body></html>",
        esc(title)
    );
    let mut r = (status, html).into_response();
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    r
}

fn message(status: StatusCode, title: &str, text: &str) -> Response {
    page(
        status,
        title,
        &format!(
            "<div class=\"card\"><div><h1>{}</h1><p>{}</p></div></div>",
            esc(title),
            esc(text)
        ),
    )
}

fn form(state: &AppState, token: &str, client: &str, user: &str, error: Option<&str>) -> String {
    let csrf = state.flow_csrf(token, "allow");
    let err = error
        .map(|e| format!("<div class=\"err\" role=\"alert\">{}</div>", esc(e)))
        .unwrap_or_default();
    format!(
        "<div class=\"card\">\
         <div class=\"client\"><b>{client}</b><span>wants to connect to your account</span></div>\
         <div><h1>Connect device</h1><p>Sign in to allow access. The device gets its own app password, \
         which you can revoke at any time.</p></div>{err}\
         <form method=\"post\" action=\"\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <label>Username<input type=\"text\" name=\"user\" value=\"{user}\" autocomplete=\"username\" required autofocus></label>\
         <label>Password<input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label>\
         <button class=\"allow\" type=\"submit\" name=\"action\" value=\"allow\">Sign in and allow access</button>\
         <button class=\"deny\" type=\"submit\" name=\"action\" value=\"deny\" formnovalidate>Deny</button>\
         </form>\
         <div class=\"note\">Check the address in your browser before entering your password. \
         Rostdav never asks for an app password here.</div></div>",
        client = esc(client),
        user = esc(user),
        csrf = esc(&csrf),
    )
}

pub async fn show(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    match state.login_flow_client(&token).await {
        Ok(Some(client)) => page(
            StatusCode::OK,
            "Connect device",
            &form(&state, &token, &client, "", None),
        ),
        Ok(None) => message(
            StatusCode::NOT_FOUND,
            "Link invalid or expired",
            "Start the connection again from your app.",
        ),
        Err(e) => internal(&e),
    }
}

#[derive(Deserialize)]
pub struct Submit {
    csrf: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
    action: String,
}

pub async fn submit(
    State(state): State<AppState>,
    Path(token): Path<String>,
    parts: Parts,
    Form(f): Form<Submit>,
) -> Response {
    let ip = parts
        .extensions
        .get::<ClientIp>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0);

    if f.action == "deny" {
        return match state.flow_deny(&token, &f.csrf).await {
            Ok(()) => message(
                StatusCode::OK,
                "Access denied",
                "No device was connected. You can close this window.",
            ),
            Err(Error::Forbidden) => forbidden(),
            Err(e) => internal(&e),
        };
    }

    match state
        .flow_allow(&token, &f.csrf, &f.user, &f.password, ip)
        .await
    {
        Ok(()) => message(
            StatusCode::OK,
            "Device connected",
            "You can close this window and return to your app.",
        ),
        Err(Error::Forbidden) => forbidden(),
        Err(Error::NotFound) => message(
            StatusCode::NOT_FOUND,
            "Link invalid or expired",
            "Start the connection again from your app.",
        ),
        Err(e @ (Error::Unauthenticated | Error::RateLimited { .. })) => {
            let (status, text) = match e {
                Error::RateLimited { retry_after_secs } => (
                    StatusCode::TOO_MANY_REQUESTS,
                    format!(
                        "Too many attempts. Try again in {} minutes.",
                        retry_after_secs.div_ceil(60)
                    ),
                ),
                _ => (
                    StatusCode::UNAUTHORIZED,
                    "Wrong username or password.".to_owned(),
                ),
            };
            match state.login_flow_client(&token).await {
                Ok(Some(client)) => {
                    let mut r = page(
                        status,
                        "Connect device",
                        &form(&state, &token, &client, &f.user, Some(&text)),
                    );
                    if let Error::RateLimited { retry_after_secs } = e {
                        if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                            r.headers_mut().insert(header::RETRY_AFTER, v);
                        }
                    }
                    r
                }
                _ => message(
                    StatusCode::NOT_FOUND,
                    "Link invalid or expired",
                    "Start the connection again from your app.",
                ),
            }
        }
        Err(e) => internal(&e),
    }
}

fn forbidden() -> Response {
    message(
        StatusCode::FORBIDDEN,
        "Request rejected",
        "The form could not be verified. Reload the page and try again.",
    )
}

fn internal(e: &Error) -> Response {
    tracing::error!(error = %e, cause = ?std::error::Error::source(e), "login page failed");
    message(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong",
        "Please try again later.",
    )
}
