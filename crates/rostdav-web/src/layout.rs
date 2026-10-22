//! Shared page frame, security headers, escaping and embedded static assets.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

const APP_CSS: &str = include_str!("../static/app.css");
const UPLOAD_JS: &str = include_str!("../static/upload.js");
const PASSWORD_JS: &str = include_str!("../static/password.js");

const PASSWORD_SCRIPT: &str = "<script src=\"/static/password.js\"></script>";

const LOGO: &str = "<svg viewBox=\"0 0 140 128\" aria-hidden=\"true\"><defs>\
<linearGradient id=\"lgBack\" x1=\"0\" y1=\"0\" x2=\"0\" y2=\"1\"><stop offset=\"0\" stop-color=\"#A63B16\"/><stop offset=\"1\" stop-color=\"#5A1D0B\"/></linearGradient>\
<linearGradient id=\"lgFront\" x1=\"0\" y1=\"0\" x2=\"1\" y2=\"1\"><stop offset=\"0\" stop-color=\"#F7A266\"/><stop offset=\"1\" stop-color=\"#C2491D\"/></linearGradient>\
<linearGradient id=\"lgShine\" x1=\"0\" y1=\"0\" x2=\"0\" y2=\"1\"><stop offset=\"0\" stop-color=\"#FFFFFF\" stop-opacity=\".6\"/><stop offset=\"1\" stop-color=\"#FFFFFF\" stop-opacity=\"0\"/></linearGradient></defs>\
<path d=\"M18 34a8 8 0 0 1 8-8h22l8 9h44a8 8 0 0 1 8 8v51a8 8 0 0 1-8 8H26a8 8 0 0 1-8-8Z\" fill=\"url(#lgBack)\"/>\
<path d=\"M33 50h75a4 4 0 0 1 3.9 4.8l-9 44A4 4 0 0 1 99 102H24a4 4 0 0 1-3.9-4.8l9-44A4 4 0 0 1 33 50Z\" fill=\"url(#lgFront)\" fill-opacity=\".94\"/>\
<path d=\"M33 50h75a4 4 0 0 1 3.9 4.8l-2.6 12.2H26.4l2.7-12.2A4 4 0 0 1 33 50Z\" fill=\"url(#lgShine)\"/>\
<rect x=\"110\" y=\"84\" width=\"10\" height=\"10\" rx=\"2\" fill=\"#F2A65A\" transform=\"rotate(12 115 89)\"/>\
<rect x=\"123\" y=\"69\" width=\"7\" height=\"7\" rx=\"1.5\" fill=\"#F7C589\" transform=\"rotate(24 126.5 72.5)\"/></svg>";

/// Markup fixes applied to every page body: scrollable tables are focusable regions
/// (keyboard users can scroll them) and empty header cells get a hidden name.
fn tidy(body: &str) -> String {
    body.replace(
        "<table",
        "<div class=\"tbl\" role=\"region\" aria-label=\"Table, scrolls sideways on small screens\" tabindex=\"0\"><table",
    )
    .replace("</table>", "</table></div>")
    .replace("<th></th>", "<th><span class=\"sr\">Actions</span></th>")
    .replace("<th class=\"num\"></th>", "<th class=\"num\"><span class=\"sr\">Actions</span></th>")
}

const FAVICON: &str = "<link rel=\"icon\" type=\"image/svg+xml\" href=\"/static/favicon.svg\">";

fn icon(name: &str) -> &'static str {
    match name {
        "files" => {
            "<path d=\"M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z\"/>"
        }
        "trash" => "<path d=\"M4 7h16\"/><path d=\"M9 7V4h6v3\"/><path d=\"M6 7l1 13h10l1-13\"/>",
        "devices" => {
            "<path d=\"M4 5h12v10H4Z\"/><path d=\"M2 19h16\"/><path d=\"M19 9h3v10h-3Z\"/>"
        }
        "settings" => {
            "<path d=\"M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1\"/><path d=\"M15 4v4M9 10v4M17 16v4\"/>"
        }
        _ => {
            "<path d=\"M9 11a4 4 0 1 0 0-8a4 4 0 0 0 0 8Z\"/><path d=\"M3 21a6 6 0 0 1 12 0\"/><path d=\"M17 11a3 3 0 1 0 0-6\"/><path d=\"M21 21a5 5 0 0 0-4-4.9\"/>"
        }
    }
}

const CSP: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; \
                   img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

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
             <title>Rostdav – {}</title><link rel=\"stylesheet\" href=\"/static/app.css\">{FAVICON}</head>\
             <body class=\"bare\"><main class=\"bare-main\"><div class=\"hero\">{LOGO}</div>{}</main>{PASSWORD_SCRIPT}</body></html>",
            esc(title),
            tidy(body)
        ),
    )
}

/// What the navigation bar needs to know about the viewer.
pub struct Chrome<'a> {
    pub theme: &'a str,
    pub admin: bool,
    pub name: &'a str,
}

/// A signed-in page with the navigation bar. `current` marks the active entry.
pub fn app(
    status: StatusCode,
    title: &str,
    chrome: &Chrome<'_>,
    current: &str,
    csrf: &str,
    body: &str,
) -> Response {
    app_with_script(status, title, chrome, current, csrf, body, None)
}

fn nav_entry(key: &str, label: &str, href: &str, current: &str) -> String {
    let cur = if key == current {
        " aria-current=\"page\""
    } else {
        ""
    };
    format!(
        "<a href=\"{href}\"{cur}><svg class=\"i\" viewBox=\"0 0 24 24\" aria-hidden=\"true\">{}</svg>{label}</a>",
        icon(key)
    )
}

/// Like [`app`], with one script from `/static/` loaded at the end of the page.
pub fn app_with_script(
    status: StatusCode,
    title: &str,
    chrome: &Chrome<'_>,
    current: &str,
    csrf: &str,
    body: &str,
    script: Option<&str>,
) -> Response {
    let script = script
        .map(|s| format!("<script src=\"/static/{s}\"></script>"))
        .unwrap_or_default();
    let main_nav = format!(
        "{}{}",
        nav_entry("files", "Files", "/files", current),
        nav_entry("trash", "Trash", "/trash", current)
    );
    let account_nav = format!(
        "{}{}",
        nav_entry("devices", "Devices", "/devices", current),
        nav_entry("settings", "Settings", "/settings", current)
    );
    let server_nav = if chrome.admin {
        format!(
            "<div class=\"navgroup\"><div class=\"eyebrow\">Server</div>{}</div>",
            nav_entry("admin", "Administration", "/admin/users", current)
        )
    } else {
        String::new()
    };
    let theme_attr = match chrome.theme {
        "light" | "dark" => format!(" data-theme=\"{}\"", chrome.theme),
        _ => String::new(),
    };
    let initial: String = chrome
        .name
        .chars()
        .take(1)
        .flat_map(char::to_uppercase)
        .collect();
    html(
        status,
        format!(
            "<!doctype html><html lang=\"en\"{theme_attr}><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
             <title>Rostdav – {}</title><link rel=\"stylesheet\" href=\"/static/app.css\">{FAVICON}</head><body>\
             <div class=\"app\"><nav class=\"side\" aria-label=\"Main navigation\">\
             <a class=\"logo\" href=\"/files\">{LOGO}<span class=\"wordmark\">rost<b>dav</b></span></a>\
             <div class=\"navgroup\">{main_nav}</div>\
             <div class=\"navgroup\"><div class=\"eyebrow\">Account</div>{account_nav}</div>{server_nav}</nav>\
             <div class=\"wrap\"><header class=\"top\"><span class=\"who\">{}</span><span class=\"avatar\" aria-hidden=\"true\">{}</span>\
             <form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
             <button type=\"submit\">Sign out</button></form></header>\
             <main class=\"panel\">{}</main></div></div>{PASSWORD_SCRIPT}{script}</body></html>",
            esc(title),
            esc(chrome.name),
            esc(&initial),
            esc(csrf),
            tidy(body)
        ),
    )
}

pub async fn static_file(axum::extract::Path(name): axum::extract::Path<String>) -> Response {
    let favicon = LOGO.replacen("<svg ", "<svg xmlns=\"http://www.w3.org/2000/svg\" ", 1);
    let (body, mime) = match name.as_str() {
        "app.css" => (APP_CSS, "text/css; charset=utf-8"),
        "upload.js" => (UPLOAD_JS, "text/javascript; charset=utf-8"),
        "favicon.svg" => (favicon.as_str(), "image/svg+xml"),
        "password.js" => (PASSWORD_JS, "text/javascript; charset=utf-8"),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut r = body.to_owned().into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
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
             <title>Rostdav – {}</title><link rel=\"stylesheet\" href=\"/static/app.css\">{FAVICON}</head><body>\
             <div class=\"public-main\"><header class=\"top public\"><a class=\"logo\" href=\"/\">{LOGO}\
             <span class=\"wordmark\">rost<b>dav</b></span></a></header><br>\
             <main class=\"panel\">{}</main></div>{PASSWORD_SCRIPT}</body></html>",
            esc(title),
            tidy(body)
        ),
    )
}
