//! Trash and Devices pages (ADR 0006, slice 11a).

use axum::Form;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use rostdav_app::AppState;
use rostdav_core::Error;
use serde::Deserialize;

use crate::layout::{self, esc};
use crate::pages::error_response_to;
use crate::session::Authed;
use crate::ui;

fn csrf_ok(state: &AppState, a: &Authed, given: &str) -> bool {
    state.web_check_csrf(a.session.id, given).is_ok()
}

fn forbidden() -> Response {
    StatusCode::FORBIDDEN.into_response()
}

// ---- trash -----------------------------------------------------------------------------

pub async fn trash(State(state): State<AppState>, a: Authed) -> Response {
    let items = match state.trash_list(&a.session.principal).await {
        Ok(i) => i,
        Err(Error::NotFound) => Vec::new(),
        Err(e) => return error_response_to(&a, &e, "/files", "trash"),
    };
    let enabled = state.trash_enabled();
    let csrf = esc(&a.csrf);
    let mut rows = String::new();
    for i in &items {
        let entry = esc(&i.entry_name());
        rows.push_str(&format!(
            "<li class=\"row\"><span class=\"tile doc\">{}</span><div class=\"row-text\"><b>{}</b>\
             <span class=\"muted\">Deleted {}{}</span></div>\
             <form class=\"row-actions\" method=\"post\" action=\"/trash/restore\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"entry\" value=\"{entry}\">\
             <button type=\"submit\">Restore</button>\
             <a class=\"button danger\" href=\"/trash/delete?entry={}\">Delete permanently</a></form></li>",
            ui::svg("file"),
            esc(&i.orig_path),
            ui::friendly(i.deleted_at),
            i.deleted_by.as_deref().map_or_else(String::new, |b| format!(" by {}", esc(b))),
            esc(&crate::layout::enc(&i.entry_name())),
        ));
    }
    let inner = if !enabled {
        "<div class=\"empty\">The trash is turned off on this server. Deleted files are gone for good.</div>".to_owned()
    } else if items.is_empty() {
        "<div class=\"empty\">The trash is empty.</div>".to_owned()
    } else {
        format!("<ul class=\"rows\">{rows}</ul>")
    };
    let chip = if enabled && !items.is_empty() {
        "<a class=\"button danger\" href=\"/trash/empty\">Empty trash</a>".to_owned()
    } else {
        String::new()
    };
    let body = format!(
        "{}{}",
        ui::page_head(
            "Trash",
            "Deleted items still count toward your storage until they are removed.",
            ""
        ),
        ui::card(
            &format!(
                "{} item{}",
                items.len(),
                if items.len() == 1 { "" } else { "s" }
            ),
            &chip,
            &inner
        )
    );
    ui::page(&a, StatusCode::OK, "Trash", "trash", &body)
}

#[derive(Deserialize)]
pub struct EntryForm {
    csrf: String,
    entry: String,
}

pub async fn trash_restore(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<EntryForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    match state.trash_restore(&a.session.principal, &f.entry).await {
        Ok(_) => Redirect::to("/trash").into_response(),
        Err(e) => error_response_to(&a, &e, "/trash", "trash"),
    }
}

#[derive(Deserialize)]
pub struct EntryQuery {
    entry: String,
}

pub async fn trash_delete_confirm(a: Authed, Query(q): Query<EntryQuery>) -> Response {
    let body = format!(
        "<h1>Delete permanently?</h1><p>“{}” will be removed for good. This cannot be undone.</p>\
         <form method=\"post\" action=\"/trash/delete\" class=\"inline\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"entry\" value=\"{}\">\
         <button class=\"danger\" type=\"submit\">Delete permanently</button><a class=\"button\" href=\"/trash\">Cancel</a></form>",
        esc(&q.entry),
        esc(&a.csrf),
        esc(&q.entry)
    );
    layout::app(
        StatusCode::OK,
        "Delete permanently",
        &a.chrome(),
        "trash",
        &a.csrf,
        &body,
    )
}

pub async fn trash_delete(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<EntryForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    match state.trash_delete(&a.session.principal, &f.entry).await {
        Ok(()) => Redirect::to("/trash").into_response(),
        Err(e) => error_response_to(&a, &e, "/trash", "trash"),
    }
}

pub async fn trash_empty_confirm(a: Authed) -> Response {
    let body = format!(
        "<h1>Empty trash?</h1><p>Everything in the trash will be removed for good. This cannot be undone.</p>\
         <form method=\"post\" action=\"/trash/empty\" class=\"inline\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
         <button class=\"danger\" type=\"submit\">Empty trash</button><a class=\"button\" href=\"/trash\">Cancel</a></form>",
        esc(&a.csrf)
    );
    layout::app(
        StatusCode::OK,
        "Empty trash",
        &a.chrome(),
        "trash",
        &a.csrf,
        &body,
    )
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf: String,
}

pub async fn trash_empty(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<CsrfForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    match state.trash_empty(&a.session.principal).await {
        Ok(()) => Redirect::to("/trash").into_response(),
        Err(e) => error_response_to(&a, &e, "/trash", "trash"),
    }
}

// ---- devices ------------------------------------------------------------------------------

async fn devices_page(state: &AppState, a: &Authed, status: StatusCode, notice: &str) -> Response {
    let p = &a.session.principal;
    let (pw, sessions) = match (state.app_passwords(p).await, state.web_sessions(p).await) {
        (Ok(x), Ok(y)) => (x, y),
        (Err(e), _) | (_, Err(e)) => return error_response_to(a, &e, "/files", "devices"),
    };
    let csrf = esc(&a.csrf);
    let mut rows = String::new();
    for d in &pw {
        let lower = d.name.to_lowercase();
        let (tile, icon) = if [
            "android", "ios", "iphone", "ipad", "pixel", "phone", "mobile",
        ]
        .iter()
        .any(|k| lower.contains(k))
        {
            ("folder", "phone")
        } else {
            ("doc", "laptop")
        };
        rows.push_str(&format!(
            "<li class=\"row\"><span class=\"tile {tile}\">{}</span><div class=\"row-text\"><b>{}</b>\
             <span class=\"muted\">App password · created {}</span></div>\
             <span class=\"row-meta\">{}</span>\
             <form class=\"row-actions\" method=\"post\" action=\"/devices/revoke\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <input type=\"hidden\" name=\"id\" value=\"{}\"><button class=\"danger\" type=\"submit\" aria-label=\"Revoke {}\">Revoke</button></form></li>",
            ui::svg(icon),
            esc(&d.name),
            ui::friendly(d.created_at),
            d.last_used_at.map_or_else(|| "Never used".to_owned(), ui::friendly),
            d.id,
            esc(&d.name),
        ));
    }
    // this session first, then the most recently active others
    let mut sessions = sessions;
    sessions.sort_by_key(|s| (s.id != a.session.id, std::cmp::Reverse(s.last_seen)));
    let hidden_sessions = sessions.len().saturating_sub(8);
    sessions.truncate(8);
    for s in &sessions {
        let this = s.id == a.session.id;
        rows.push_str(&format!(
            "<li class=\"row session\"><span class=\"tile doc\">{}</span><div class=\"row-text\"><b>{}{}</b>\
             <span class=\"muted\">Browser session{}</span></div><span class=\"row-meta\">{}</span></li>",
            ui::svg("laptop"),
            esc(&ui::ua_summary(&s.user_agent)),
            if this { " <span class=\"chip ok\">This session</span>" } else { "" },
            if s.ip.is_empty() { String::new() } else { format!(" · {}", esc(&s.ip)) },
            if this { "Now".to_owned() } else { ui::friendly(s.last_seen) },
        ));
    }
    if hidden_sessions > 0 {
        rows.push_str(&format!(
            "<li class=\"row session\"><div class=\"row-text\"><span class=\"muted\">… and {hidden_sessions} older browser session(s). “Sign out all other browsers” ends them.</span></div></li>"
        ));
    }
    let chip = format!(
        "<span class=\"chip\">{} active</span>",
        pw.len() + sessions.len() + hidden_sessions
    );
    let list = if rows.is_empty() {
        "<div class=\"empty\">No devices are connected.</div>".to_owned()
    } else {
        format!("<ul class=\"rows\">{rows}</ul>")
    };
    let create = format!(
        "<form class=\"createrow\" method=\"post\" action=\"/devices/create\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <label>Device name<input type=\"text\" name=\"name\" placeholder=\"e.g. Backup server\" required maxlength=\"128\"></label>\
         <button class=\"primary\" type=\"submit\">Create</button></form>"
    );
    let account = format!(
        "<dl class=\"facts\"><dt>Username</dt><dd class=\"mono\">{}</dd><dt>Password hash</dt><dd>Argon2id</dd></dl>\
         <p><a class=\"button wide\" href=\"/settings/password\">Change password</a></p>\
         <form method=\"post\" action=\"/devices/sign-out-others\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <button class=\"danger wide\" type=\"submit\">Sign out all other browsers</button></form>",
        esc(&p.name)
    );
    let body = format!(
        "{}{notice}{}<div class=\"cols\">{}{}</div>",
        ui::page_head(
            "Devices & security",
            "Every device signs in with its own app password. Revoking it signs the device out immediately – your account password stays the same.",
            ""
        ),
        ui::card("Connected devices", &chip, &list),
        ui::card(
            "Create app password",
            "",
            &format!(
                "<p class=\"muted\">For clients without browser sign-in, such as rclone, davfs2 or scripts. The Nextcloud app does not need this – it connects through the sign-in page.</p>{create}"
            )
        ),
        ui::card("Account", "", &account),
    );
    ui::page(a, status, "Devices", "devices", &body)
}

pub async fn devices(State(state): State<AppState>, a: Authed) -> Response {
    devices_page(&state, &a, StatusCode::OK, "").await
}

#[derive(Deserialize)]
pub struct CreateForm {
    csrf: String,
    name: String,
}

pub async fn device_create(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<CreateForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    match state.device_create(&a.session.principal, &f.name).await {
        Ok(token) => {
            let notice = format!(
                "<div class=\"notice token\" role=\"status\"><b>App password for “{}”. It is shown only once; copy it now.</b><br>\
                 <code>{}</code></div>",
                esc(f.name.trim()),
                esc(&token)
            );
            devices_page(&state, &a, StatusCode::OK, &notice).await
        }
        Err(e) => error_response_to(&a, &e, "/devices", "devices"),
    }
}

#[derive(Deserialize)]
pub struct RevokeForm {
    csrf: String,
    id: i64,
}

pub async fn device_revoke(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<RevokeForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    match state.device_revoke(&a.session.principal, f.id).await {
        Ok(()) => Redirect::to("/devices").into_response(),
        Err(e) => error_response_to(&a, &e, "/devices", "devices"),
    }
}

pub async fn sign_out_others(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<CsrfForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    match state.web_end_other_sessions(&a.session).await {
        Ok(_) => Redirect::to("/devices").into_response(),
        Err(e) => error_response_to(&a, &e, "/devices", "devices"),
    }
}

// ---- settings -----------------------------------------------------------------------------

fn bytes(n: i64) -> String {
    crate::pages::human(n)
}

pub async fn settings(
    State(state): State<AppState>,
    a: Authed,
    parts: axum::http::request::Parts,
) -> Response {
    settings_page(&state, &a, &parts.headers, StatusCode::OK, "").await
}

async fn settings_page(
    state: &AppState,
    a: &Authed,
    headers: &axum::http::HeaderMap,
    status: StatusCode,
    notice: &str,
) -> Response {
    let p = &a.session.principal;
    let u = match state.usage_overview(p).await {
        Ok(u) => u,
        Err(e) => return error_response_to(a, &e, "/files", "settings"),
    };
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("https"));
    let url = format!(
        "{}://{}/remote.php/dav/files/{}/",
        if https { "https" } else { "http" },
        host,
        crate::layout::enc(&p.name)
    );
    let csrf = esc(&a.csrf);
    let seg = |v: &str, label: &str| {
        let on = a.theme == v || (a.theme.is_empty() && v == "system");
        format!(
            "<button type=\"submit\" name=\"theme\" value=\"{v}\" aria-pressed=\"{on}\"{}>{label}</button>",
            if on { " class=\"on\"" } else { "" }
        )
    };
    let appearance = ui::card(
        "Appearance",
        &format!(
            "<form class=\"segform\" method=\"post\" action=\"/settings/theme\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><div class=\"seg\" role=\"group\" aria-label=\"Theme\">{}{}{}</div></form>",
            seg("light", "Light"),
            seg("dark", "Dark"),
            seg("system", "Same as system")
        ),
        "<p class=\"muted\">The whole page switches when you choose.</p>",
    );
    let webdav = ui::card(
        "WebDAV address",
        "",
        &format!(
            "<p class=\"muted\">For rclone, davfs2, Finder or Explorer. Sign in there with an app password.</p>\
             <div class=\"codebox\"><code id=\"webdav-url\">{}</code>\
             <button type=\"button\" data-copy=\"webdav-url\" hidden>Copy</button></div>\
             <p><a href=\"/devices\">Create an app password</a></p>",
            esc(&url)
        ),
    );
    // stacked usage bar: files, versions, trash
    let total = u.files + u.versions + u.trash;
    let scale = u
        .quota
        .filter(|q| *q > 0)
        .map_or(total.max(1), |q| q.max(total).max(1)) as f64;
    let mut x = 0.0;
    let mut rects = String::new();
    for (cls, v) in [
        ("s-files", u.files),
        ("s-versions", u.versions),
        ("s-trash", u.trash),
    ] {
        let w = v as f64 / scale * 100.0;
        if w > 0.0 {
            rects.push_str(&format!(
                "<rect class=\"{cls}\" x=\"{x:.2}\" y=\"0\" width=\"{w:.2}\" height=\"1\"/>"
            ));
            x += w;
        }
    }
    let quota = u.quota.map_or_else(|| "unlimited".to_owned(), bytes);
    let storage = ui::card(
        "Storage",
        "",
        &format!(
            "<svg class=\"stack\" viewBox=\"0 0 100 1\" preserveAspectRatio=\"none\" role=\"img\" \
             aria-label=\"{} used of {}\"><rect class=\"s-bg\" x=\"0\" y=\"0\" width=\"100\" height=\"1\"/>{rects}</svg>\
             <ul class=\"legend\"><li><span class=\"dot s-files\" aria-hidden=\"true\"></span>Files<span>{}</span></li>\
             <li><span class=\"dot s-versions\" aria-hidden=\"true\"></span>Versions<span>{}</span></li>\
             <li><span class=\"dot s-trash\" aria-hidden=\"true\"></span>Trash bin<span>{}</span></li></ul>\
             <p class=\"muted\">Quota: {} · set by the administrator</p>",
            bytes(u.used),
            esc(&quota),
            bytes(u.files),
            bytes(u.versions),
            bytes(u.trash),
            esc(&quota)
        ),
    );
    let prof = state.profile(p).await.unwrap_or_default();
    let profile = ui::card(
        "Profile",
        "",
        &format!(
            "<form class=\"createrow\" method=\"post\" action=\"/settings/profile\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <label>Display name<input type=\"text\" name=\"display_name\" value=\"{}\" maxlength=\"80\" autocomplete=\"name\"></label>\
             <label>E-mail for notifications<input type=\"text\" name=\"email\" value=\"{}\" maxlength=\"254\" inputmode=\"email\" autocomplete=\"email\" placeholder=\"name@example.com\"></label>\
             <button class=\"primary\" type=\"submit\">Save</button></form>\
             <dl class=\"facts\"><dt>Username</dt><dd class=\"mono\">{}</dd></dl>\
             <p><a href=\"/settings/password\">Change password</a></p>",
            esc(&prof.display_name),
            esc(&prof.email),
            esc(&p.name)
        ),
    );
    let export = ui::card(
        "Export your data",
        "",
        &format!(
            "<p class=\"muted\">Downloads all your own files with their folder structure as a tar archive. Files shared with you, older versions and the trash are not included.</p>\
             <form method=\"post\" action=\"/settings/export\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><button type=\"submit\">Start export</button></form>"
        ),
    );
    let body = format!(
        "{}{notice}{profile}{appearance}<div class=\"cols\">{webdav}{storage}</div>{export}",
        ui::page_head(
            "Settings",
            "Personal settings for your account. Changes are saved immediately.",
            ""
        )
    );
    let opts = crate::layout::Opts {
        bare_main: true,
        script: Some("copy.js"),
        ..crate::layout::Opts::default()
    };
    crate::layout::app_opts(
        status,
        "Settings",
        &a.chrome(),
        "settings",
        &a.csrf,
        &body,
        &opts,
    )
}

#[derive(Deserialize)]
pub struct ThemeForm {
    csrf: String,
    theme: String,
}

pub async fn set_theme(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<ThemeForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    match state
        .set_pref(&a.session.principal, "theme", &f.theme)
        .await
    {
        Ok(()) => Redirect::to("/settings").into_response(),
        Err(e) => error_response_to(&a, &e, "/settings", "settings"),
    }
}

// ---- profile, password, export -----------------------------------------------------------

#[derive(Deserialize)]
pub struct ProfileForm {
    csrf: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    email: String,
}

pub async fn set_profile(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<ProfileForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    match state
        .set_profile(&a.session.principal, &f.display_name, &f.email)
        .await
    {
        Ok(()) => Redirect::to("/settings").into_response(),
        Err(e) => error_response_to(&a, &e, "/settings", "settings"),
    }
}

#[derive(Deserialize, Default)]
pub struct PasswordQuery {
    #[serde(default)]
    done: String,
}

pub async fn password_page(a: Authed, Query(q): Query<PasswordQuery>) -> Response {
    password_form(&a, StatusCode::OK, q.done == "1", "")
}

fn password_form(a: &Authed, status: StatusCode, done: bool, error: &str) -> Response {
    let note = if done {
        "<div class=\"notice\" role=\"status\">Password changed. All other browsers were signed out; your connected devices keep working.</div>".to_owned()
    } else if !error.is_empty() {
        format!("<div class=\"err\" role=\"alert\">{}</div>", esc(error))
    } else {
        String::new()
    };
    let form = format!(
        "{note}<form class=\"stack-form\" method=\"post\" action=\"/settings/password\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
         <label>Current password<input type=\"password\" name=\"current\" autocomplete=\"current-password\" required></label>\
         <label>New password (at least 10 characters)<input type=\"password\" name=\"new\" autocomplete=\"new-password\" required minlength=\"10\"></label>\
         <label>New password again<input type=\"password\" name=\"again\" autocomplete=\"new-password\" required minlength=\"10\"></label>\
         <div class=\"actions\"><button class=\"primary\" type=\"submit\">Change password</button><a class=\"button\" href=\"/settings\">Cancel</a></div></form>",
        esc(&a.csrf)
    );
    let body = format!(
        "{}{}",
        ui::page_head(
            "Change password",
            "Other browsers are signed out when the password changes. Connected devices keep their app passwords.",
            ""
        ),
        ui::card("Password", "", &form)
    );
    ui::page(a, status, "Change password", "settings", &body)
}

#[derive(Deserialize)]
pub struct PasswordForm {
    csrf: String,
    current: String,
    new: String,
    again: String,
}

pub async fn password_submit(
    State(state): State<AppState>,
    a: Authed,
    parts: axum::http::request::Parts,
    Form(f): Form<PasswordForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    if f.new != f.again {
        return password_form(
            &a,
            StatusCode::BAD_REQUEST,
            false,
            "The two new passwords are not the same.",
        );
    }
    match state
        .web_change_password(
            &a.session,
            &f.current,
            &f.new,
            crate::session::client_ip(&parts),
        )
        .await
    {
        Ok(()) => Redirect::to("/settings/password?done=1").into_response(),
        Err(Error::Unauthenticated) => password_form(
            &a,
            StatusCode::UNAUTHORIZED,
            false,
            "The current password is wrong.",
        ),
        Err(Error::RateLimited { retry_after_secs }) => password_form(
            &a,
            StatusCode::TOO_MANY_REQUESTS,
            false,
            &format!(
                "Too many attempts. Try again in {} minutes.",
                retry_after_secs.div_ceil(60)
            ),
        ),
        Err(Error::BadRequest(_)) => password_form(
            &a,
            StatusCode::BAD_REQUEST,
            false,
            "The new password must have at least 10 characters.",
        ),
        Err(e) => error_response_to(&a, &e, "/settings/password", "settings"),
    }
}

pub async fn export(State(state): State<AppState>, a: Authed, Form(f): Form<CsrfForm>) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let p = a.session.principal.clone();
    let (mut tx, rx) = tokio::io::duplex(256 * 1024);
    let st = state.clone();
    tokio::spawn(async move {
        // a failure mid-way closes the pipe early: the download ends truncated, not silently complete
        if let Err(e) = st.export_tar(&p, &mut tx).await {
            tracing::error!(error = %e, "data export failed");
        }
    });
    let day = rostdav_core::time::rfc3339(rostdav_app::now_secs());
    let fname: String = a
        .session
        .principal
        .name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut r = axum::response::Response::new(axum::body::Body::from_stream(
        tokio_util::io::ReaderStream::new(rx),
    ));
    let h = r.headers_mut();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/x-tar"),
    );
    h.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    if let Ok(v) = axum::http::HeaderValue::from_str(&format!(
        "attachment; filename=\"rostdav-{fname}-{}.tar\"",
        &day[..10]
    )) {
        h.insert(axum::http::header::CONTENT_DISPOSITION, v);
    }
    r
}
