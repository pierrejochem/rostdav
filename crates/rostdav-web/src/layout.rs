//! Shared page frame, security headers, escaping and embedded static assets.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

const APP_CSS: &str = include_str!("../static/app.css");
const LOGIN_CSS: &str = include_str!("../static/login.css");

const CSP: &str = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; \
                   frame-ancestors 'none'; base-uri 'none'";

pub fn esc(s: &str) -> String {
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

const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// One path segment, percent-encoded for use in a URL.
pub fn enc(seg: &str) -> String {
    utf8_percent_encode(seg, SEGMENT).to_string()
}

/// Adds the headers every HTML response carries.
pub fn secure(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    r
}

fn html(status: StatusCode, doc: String) -> Response {
    let mut r = (status, doc).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    secure(r)
}

/// A page without navigation (sign-in, device connection).
pub fn bare(status: StatusCode, title: &str, body: &str) -> Response {
    html(
        status,
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
             <title>Rostdav – {}</title><link rel=\"stylesheet\" href=\"/static/login.css\"></head>\
             <body>{body}</body></html>",
            esc(title)
        ),
    )
}

/// A signed-in page with the navigation bar. `current` marks the active entry.
pub fn app(
    status: StatusCode,
    title: &str,
    theme: &str,
    current: &str,
    csrf: &str,
    body: &str,
) -> Response {
    let nav: String = [
        ("files", "Files", "/files"),
        ("trash", "Trash", "/trash"),
        ("devices", "Devices", "/devices"),
    ]
    .iter()
    .map(|(k, label, href)| {
        let cur = if *k == current {
            " aria-current=\"page\""
        } else {
            ""
        };
        format!("<a href=\"{href}\"{cur}>{label}</a>")
    })
    .collect();
    let theme_attr = match theme {
        "light" | "dark" => format!(" data-theme=\"{theme}\""),
        _ => String::new(),
    };
    html(
        status,
        format!(
            "<!doctype html><html lang=\"en\"{theme_attr}><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
             <title>Rostdav – {}</title><link rel=\"stylesheet\" href=\"/static/app.css\"></head><body>\
             <header class=\"top\"><span class=\"brand\">rost<b>dav</b></span><nav>{nav}</nav>\
             <form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
             <button type=\"submit\">Sign out</button></form></header>\
             <main>{body}</main></body></html>",
            esc(title),
            esc(csrf)
        ),
    )
}

pub async fn static_file(axum::extract::Path(name): axum::extract::Path<String>) -> Response {
    let body = match name.as_str() {
        "app.css" => APP_CSS,
        "login.css" => LOGIN_CSS,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut r = body.into_response();
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

/// A page for visitors without an account (public links).
pub fn public(status: StatusCode, title: &str, body: &str) -> Response {
    html(
        status,
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
             <meta name=\"robots\" content=\"noindex\">\
             <title>Rostdav – {}</title><link rel=\"stylesheet\" href=\"/static/app.css\"></head><body>\
             <header class=\"top\"><span class=\"brand\">rost<b>dav</b></span></header>\
             <main>{body}</main></body></html>",
            esc(title)
        ),
    )
}
