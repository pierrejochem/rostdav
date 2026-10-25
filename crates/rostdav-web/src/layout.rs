//! Shared page frame, security headers, escaping and embedded static assets.

use crate::i18n::{Lang, t, tf};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

const APP_CSS: &str = include_str!("../static/app.css");
const UPLOAD_JS: &str = include_str!("../static/upload.js");
const COPY_JS: &str = include_str!("../static/copy.js");
const PASSWORD_JS: &str = include_str!("../static/password.js");
const AVATAR_JS: &str = include_str!("../static/avatar.js");
const NAV_JS: &str = include_str!("../static/nav.js");
const DROPDOWN_JS: &str = include_str!("../static/dropdown.js");

const INTER: &[u8] = include_bytes!("../static/fonts/Inter-latin.woff2");
const JETBRAINS_MONO: &[u8] = include_bytes!("../static/fonts/JetBrainsMono-500-latin.woff2");

/// The full logo (mark and wordmark) from `assets/brand`, for use on a dark background. It is
/// put into the page itself, not loaded as an image, so that the wordmark is set in the page's
/// Inter (an SVG loaded as an image cannot use the page's fonts).
const BRAND_LOGO_ON_DARK: &str = include_str!("../../../assets/brand/rostdav-logo-dark.svg");

fn brand_logo() -> &'static str {
    static LOGO: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    LOGO.get_or_init(|| {
        // the file brings its own dark tile; the page panel is the background instead
        let svg = BRAND_LOGO_ON_DARK
            .replacen("<rect width=\"480\" height=\"128\" rx=\"16\" fill=\"#15171C\"/>", "", 1)
            .replacen(
                "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 480 128\" width=\"480\" height=\"128\" role=\"img\" aria-label=\"Rostdav\"><title>Rostdav</title>",
                "<svg class=\"auth-logo\" viewBox=\"0 0 480 128\" role=\"img\" aria-label=\"Rostdav\">",
                1,
            );
        debug_assert!(svg.starts_with("<svg class=\"auth-logo\""), "logo file changed");
        svg
    })
}

const PASSWORD_SCRIPT: &str = "<script src=\"/static/password.js\"></script>";
const NAV_SCRIPT: &str =
    "<script src=\"/static/nav.js\"></script><script src=\"/static/dropdown.js\"></script>";

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
fn tidy(body: &str, lang: Lang) -> String {
    let actions = format!(
        "<th><span class=\"sr\">{}</span></th>",
        esc(&t(lang, "Actions"))
    );
    let actions_num = format!(
        "<th class=\"num\"><span class=\"sr\">{}</span></th>",
        esc(&t(lang, "Actions"))
    );
    body.replace(
        "<table",
        &format!(
            "<div class=\"tbl\" role=\"region\" aria-label=\"{}\" tabindex=\"0\"><table",
            esc(&t(lang, "Table, scrolls sideways on small screens"))
        ),
    )
    .replace("</table>", "</table></div>")
    .replace("<th></th>", &actions)
    .replace("<th class=\"num\"></th>", &actions_num)
}

const FAVICON: &str = "<link rel=\"icon\" type=\"image/svg+xml\" href=\"/static/favicon.svg\">";

fn icon(name: &str) -> &'static str {
    match name {
        "files" => {
            "<path d=\"M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z\"/>"
        }
        "trash" => "<path d=\"M4 7h16\"/><path d=\"M9 7V4h6v3\"/><path d=\"M6 7l1 13h10l1-13\"/>",
        "recent" => "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 7v5l3 2\"/>",
        "search" => "<path d=\"M11 18a7 7 0 1 0 0-14a7 7 0 0 0 0 14Z\"/><path d=\"M20 20l-4-4\"/>",
        "shares" => {
            "<circle cx=\"18\" cy=\"5\" r=\"3\"/><circle cx=\"6\" cy=\"12\" r=\"3\"/><circle cx=\"18\" cy=\"19\" r=\"3\"/><path d=\"M8.6 13.5l6.8 4M15.4 6.5l-6.8 4\"/>"
        }
        "devices" => {
            "<path d=\"M4 5h12v10H4Z\"/><path d=\"M2 19h16\"/><path d=\"M19 9h3v10h-3Z\"/>"
        }
        "more" => {
            "<circle cx=\"5\" cy=\"12\" r=\"1.3\"/><circle cx=\"12\" cy=\"12\" r=\"1.3\"/><circle cx=\"19\" cy=\"12\" r=\"1.3\"/>"
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
                   img-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

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
pub fn bare(lang: Lang, status: StatusCode, title: &str, body: &str) -> Response {
    html(
        status,
        format!(
            "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
             <title>Rostdav – {}</title><link rel=\"stylesheet\" href=\"/static/app.css\">{FAVICON}</head>\
             <body class=\"bare\"><main class=\"auth\">\
             <section class=\"auth-brand\"><div>{}<p class=\"auth-tag\">{}</p>\
             <ul class=\"auth-points\"><li>{}</li><li>{}</li><li>{}</li></ul></div></section>\
             <section class=\"auth-form\">{}</section></main>{PASSWORD_SCRIPT}</body></html>",
            lang.code(),
            esc(&t(lang, title)),
            brand_logo(),
            esc(&t(lang, "Your files, on your own server.")),
            esc(&t(lang, "Works with the Nextcloud apps")),
            esc(&t(lang, "Versions, sharing and a trash bin")),
            esc(&t(lang, "Optional two-factor sign-in")),
            tidy(body, lang)
        ),
    )
}

/// What the navigation bar needs to know about the viewer.
pub struct Chrome<'a> {
    /// The account name (the one in addresses), not the display name.
    pub user: &'a str,
    /// Version of the profile picture, if the user has one.
    pub avatar: Option<&'a str>,
    pub theme: &'a str,
    pub admin: bool,
    pub name: &'a str,
    pub lang: Lang,
    /// Used bytes and quota (`None` = unlimited).
    pub storage: (i64, Option<i64>),
}

/// Optional parts of a signed-in page.
#[derive(Default)]
pub struct Opts<'a> {
    /// Scripts from `/static/` (names separated by spaces), loaded at the end of the page.
    pub script: Option<&'a str>,
    /// Markup for the left side of the top bar (search, actions).
    pub toolbar: Option<&'a str>,
    /// The body brings its own glass panels instead of one shared panel.
    pub bare_main: bool,
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

fn human(n: i64) -> String {
    crate::pages::human(n)
}

/// Sidebar storage meter: a `<progress>` (no inline styles allowed by the CSP).
pub(crate) fn storage_widget((used, quota): (i64, Option<i64>), lang: Lang) -> String {
    match quota {
        Some(q) if q > 0 => format!(
            "<div class=\"storage\"><div class=\"storage-head\"><span>{}</span><span class=\"muted\">{}</span></div>\
             <progress class=\"meter\" max=\"{q}\" value=\"{}\" aria-label=\"{}\"></progress></div>",
            esc(&t(lang, "Storage")),
            esc(&tf(lang, "{0} of {1}", &[&human(used), &human(q)])),
            used.clamp(0, q),
            esc(&t(lang, "Storage used"))
        ),
        _ => format!(
            "<div class=\"storage\"><div class=\"storage-head\"><span>{}</span><span class=\"muted\">{}</span></div></div>",
            esc(&t(lang, "Storage")),
            esc(&tf(lang, "{0} used", &[&human(used)]))
        ),
    }
}

pub(crate) fn nav_entry(key: &str, label: &str, href: &str, current: &str) -> String {
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
    let opts = Opts {
        script,
        ..Opts::default()
    };
    app_opts(status, title, chrome, current, csrf, body, &opts)
}

/// The general form of [`app`].
pub fn app_opts(
    status: StatusCode,
    title: &str,
    chrome: &Chrome<'_>,
    current: &str,
    csrf: &str,
    body: &str,
    opts: &Opts<'_>,
) -> Response {
    // one or more scripts from `/static/`, separated by spaces (fixed names, never user input)
    let script: String = opts
        .script
        .map(|s| {
            s.split_whitespace()
                .map(|n| format!("<script src=\"/static/{n}\"></script>"))
                .collect()
        })
        .unwrap_or_default();
    let toolbar = opts.toolbar.unwrap_or_default();
    let main_class = if opts.bare_main { "bare" } else { "panel" };
    let head_class = if opts.bare_main && opts.toolbar.is_none() {
        "top flat"
    } else {
        "top"
    };
    let lang = chrome.lang;
    let storage = storage_widget(chrome.storage, lang);
    let main_nav = format!(
        "{}{}{}{}{}",
        nav_entry("files", &t(lang, "All files"), "/files", current),
        nav_entry("search", &t(lang, "Search"), "/search", current),
        nav_entry("recent", &t(lang, "Recent"), "/recent", current),
        nav_entry("shares", &t(lang, "Shares"), "/shares", current),
        nav_entry("trash", &t(lang, "Trash bin"), "/trash", current)
    );
    let account_nav = format!(
        "{}{}{}",
        nav_entry(
            "devices",
            &t(lang, "Devices & security"),
            "/devices",
            current
        ),
        nav_entry("settings", &t(lang, "Settings"), "/settings", current),
        nav_entry("about", &t(lang, "About"), "/about", current)
    );
    let server_nav = if chrome.admin {
        format!(
            "<div class=\"navgroup\"><div class=\"eyebrow\">{}</div>{}</div>",
            esc(&t(lang, "Server")),
            nav_entry("admin", &t(lang, "Administration"), "/admin/users", current)
        )
    } else {
        String::new()
    };
    // phone: the four places used most; everything else is on the More page
    let tab_current = match current {
        "files" | "recent" | "shares" => current,
        _ => "more",
    };
    let tabbar = format!(
        "<nav class=\"tabbar\" aria-label=\"{}\">{}{}{}{}</nav>",
        esc(&t(lang, "Main navigation")),
        nav_entry("files", &t(lang, "Files"), "/files", tab_current),
        nav_entry("recent", &t(lang, "Recent"), "/recent", tab_current),
        nav_entry("shares", &t(lang, "Shares"), "/shares", tab_current),
        nav_entry("more", &t(lang, "More"), "/more", tab_current)
    );
    let top_search = format!(
        "<a class=\"topsearch\" href=\"/search\" aria-label=\"{}\"><svg class=\"i\" viewBox=\"0 0 24 24\" aria-hidden=\"true\">{}</svg></a>",
        esc(&t(lang, "Search")),
        icon("search")
    );
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
    // the profile picture when there is one, else the first letter
    let initial = match chrome.avatar {
        Some(v) => format!(
            "<img src=\"{}\" alt=\"\" width=\"42\" height=\"42\">",
            esc(&crate::ui::avatar_url(chrome.user, v))
        ),
        None => esc(&initial),
    };
    html(
        status,
        format!(
            "<!doctype html><html lang=\"{}\"{theme_attr}><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">\
             <title>Rostdav – {}</title><link rel=\"stylesheet\" href=\"/static/app.css\">{FAVICON}</head><body>\
             <div class=\"app\"><nav class=\"side\" aria-label=\"{}\">\
             <a class=\"logo\" href=\"/files\">{LOGO}<span class=\"wordmark\">rost<b>dav</b></span></a>\
             <div class=\"navgroup\">{main_nav}</div>\
             <div class=\"navgroup\"><div class=\"eyebrow\">{}</div>{account_nav}</div>{server_nav}{storage}</nav>\
             <div class=\"wrap\"><header class=\"{head_class}\"><div class=\"toolbar\">{toolbar}</div>{top_search}<details class=\"pop account\"><summary class=\"avatar\" aria-label=\"{}\">{}</summary>\
             <div class=\"popover\"><span class=\"who\">{}</span>\
             <form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
             <button type=\"submit\">{}</button></form></div></details></header>\
             <main class=\"{main_class}\">{}</main></div>{tabbar}</div>{PASSWORD_SCRIPT}{NAV_SCRIPT}{script}</body></html>",
            lang.code(),
            esc(&t(lang, title)),
            esc(&t(lang, "Main navigation")),
            esc(&t(lang, "Account")),
            esc(&tf(lang, "Account of {0}", &[chrome.name])),
            initial,
            esc(chrome.name),
            esc(csrf),
            esc(&t(lang, "Sign out")),
            tidy(body, lang)
        ),
    )
}

/// Content hash used as ETag (FNV-1a, 64 bit): enough to tell versions of an asset apart.
fn etag_of(body: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in body {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("\"{h:016x}\"")
}

/// Static assets are revalidated on every load (`no-cache` + ETag): a new build shows
/// up at once, and an unchanged asset costs only a 304.
pub async fn static_file(
    axum::extract::Path(name): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let favicon = LOGO.replacen("<svg ", "<svg xmlns=\"http://www.w3.org/2000/svg\" ", 1);
    let (body, mime): (&[u8], &'static str) = match name.as_str() {
        "app.css" => (APP_CSS.as_bytes(), "text/css; charset=utf-8"),
        "upload.js" => (UPLOAD_JS.as_bytes(), "text/javascript; charset=utf-8"),
        "favicon.svg" => (favicon.as_bytes(), "image/svg+xml"),
        "copy.js" => (COPY_JS.as_bytes(), "text/javascript; charset=utf-8"),
        "password.js" => (PASSWORD_JS.as_bytes(), "text/javascript; charset=utf-8"),
        "avatar.js" => (AVATAR_JS.as_bytes(), "text/javascript; charset=utf-8"),
        "nav.js" => (NAV_JS.as_bytes(), "text/javascript; charset=utf-8"),
        "dropdown.js" => (DROPDOWN_JS.as_bytes(), "text/javascript; charset=utf-8"),
        "Inter-latin.woff2" => (INTER, "font/woff2"),
        "JetBrainsMono-500-latin.woff2" => (JETBRAINS_MONO, "font/woff2"),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let etag = etag_of(body);
    let unchanged = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag));
    let mut r = if unchanged {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        body.to_vec().into_response()
    };
    let h = r.headers_mut();
    if !unchanged {
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    }
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

/// A page for visitors without an account (public links).
pub fn public(lang: Lang, status: StatusCode, title: &str, body: &str) -> Response {
    html(
        status,
        format!(
            "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
             <meta name=\"robots\" content=\"noindex\">\
             <title>Rostdav – {}</title><link rel=\"stylesheet\" href=\"/static/app.css\">{FAVICON}</head><body>\
             <div class=\"public-main\"><header class=\"top public\"><a class=\"logo\" href=\"/\">{LOGO}\
             <span class=\"wordmark\">rost<b>dav</b></span></a></header><br>\
             <main class=\"panel\">{}</main></div>{PASSWORD_SCRIPT}</body></html>",
            lang.code(),
            esc(&t(lang, title)),
            tidy(body, lang)
        ),
    )
}
