//! Trash and Devices pages (ADR 0006, slice 11a).

use axum::Form;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use rostdav_app::AppState;
use rostdav_core::Error;
use serde::Deserialize;

use crate::i18n::{t, tf};
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
    let lang = a.lang;
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
        let when = match i.deleted_by.as_deref() {
            Some(b) => tf(
                lang,
                "Deleted {0} by {1}",
                &[&ui::friendly(lang, i.deleted_at), b],
            ),
            None => tf(lang, "Deleted {0}", &[&ui::friendly(lang, i.deleted_at)]),
        };
        rows.push_str(&format!(
            "<li class=\"row\"><span class=\"tile doc\">{}</span><div class=\"row-text\"><b>{}</b>\
             <span class=\"muted\">{}</span></div>\
             <form class=\"row-actions\" method=\"post\" action=\"/trash/restore\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"entry\" value=\"{entry}\">\
             <button type=\"submit\">{}</button>\
             <a class=\"button danger\" href=\"/trash/delete?entry={}\">{}</a></form></li>",
            ui::svg("file"),
            esc(&i.orig_path),
            esc(&when),
            esc(&t(lang, "Restore")),
            esc(&crate::layout::enc(&i.entry_name())),
            esc(&t(lang, "Delete permanently")),
        ));
    }
    let inner = if !enabled {
        format!(
            "<div class=\"empty\">{}</div>",
            esc(&t(
                lang,
                "The trash is turned off on this server. Deleted files are gone for good."
            ))
        )
    } else if items.is_empty() {
        format!(
            "<div class=\"empty\">{}</div>",
            esc(&t(lang, "The trash is empty."))
        )
    } else {
        format!("<ul class=\"rows\">{rows}</ul>")
    };
    let chip = if enabled && !items.is_empty() {
        format!(
            "<a class=\"button danger\" href=\"/trash/empty\">{}</a>",
            esc(&t(lang, "Empty trash"))
        )
    } else {
        String::new()
    };
    let heading = if items.len() == 1 {
        t(lang, "1 item")
    } else {
        tf(lang, "{0} items", &[&items.len().to_string()])
    };
    let body = format!(
        "{}{}",
        ui::page_head(
            lang,
            "Trash",
            "Deleted items still count toward your storage until they are removed.",
            ""
        ),
        ui::card_text(&heading, &chip, &inner)
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
    let lang = a.lang;
    let body = format!(
        "<h1>{}</h1><p>{}</p>\
         <form method=\"post\" action=\"/trash/delete\" class=\"inline\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"entry\" value=\"{}\">\
         <button class=\"danger\" type=\"submit\">{}</button><a class=\"button\" href=\"/trash\">{}</a></form>",
        esc(&t(lang, "Delete permanently?")),
        esc(&tf(
            lang,
            "“{0}” will be removed for good. This cannot be undone.",
            &[&q.entry]
        )),
        esc(&a.csrf),
        esc(&q.entry),
        esc(&t(lang, "Delete permanently")),
        esc(&t(lang, "Cancel"))
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
    let lang = a.lang;
    let body = format!(
        "<h1>{}</h1><p>{}</p>\
         <form method=\"post\" action=\"/trash/empty\" class=\"inline\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
         <button class=\"danger\" type=\"submit\">{}</button><a class=\"button\" href=\"/trash\">{}</a></form>",
        esc(&t(lang, "Empty trash?")),
        esc(&t(
            lang,
            "Everything in the trash will be removed for good. This cannot be undone."
        )),
        esc(&a.csrf),
        esc(&t(lang, "Empty trash")),
        esc(&t(lang, "Cancel"))
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
    let lang = a.lang;
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
             <span class=\"muted\">{}</span></div>\
             <span class=\"row-meta\">{}</span>\
             <form class=\"row-actions\" method=\"post\" action=\"/devices/revoke\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <input type=\"hidden\" name=\"id\" value=\"{}\"><button class=\"danger\" type=\"submit\" aria-label=\"{}\">{}</button></form></li>",
            ui::svg(icon),
            esc(&d.name),
            esc(&tf(lang, "App password · created {0}", &[&ui::friendly(lang, d.created_at)])),
            esc(&d.last_used_at.map_or_else(|| t(lang, "Never used"), |u| ui::friendly(lang, u))),
            d.id,
            esc(&tf(lang, "Revoke {0}", &[&d.name])),
            esc(&t(lang, "Revoke")),
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
             <span class=\"muted\">{}{}</span></div><span class=\"row-meta\">{}</span></li>",
            ui::svg("laptop"),
            esc(&ui::ua_summary(lang, &s.user_agent)),
            if this { format!(" <span class=\"chip ok\">{}</span>", esc(&t(lang, "This session"))) } else { String::new() },
            esc(&t(lang, "Browser session")),
            if s.ip.is_empty() { String::new() } else { format!(" · {}", esc(&s.ip)) },
            esc(&if this { t(lang, "Now") } else { ui::friendly(lang, s.last_seen) }),
        ));
    }
    if hidden_sessions > 0 {
        rows.push_str(&format!(
            "<li class=\"row session\"><div class=\"row-text\"><span class=\"muted\">{}</span></div></li>",
            esc(&tf(lang, "… and {0} older browser session(s). “Sign out all other browsers” ends them.", &[&hidden_sessions.to_string()]))
        ));
    }
    let chip = format!(
        "<span class=\"chip\">{}</span>",
        esc(&tf(
            lang,
            "{0} active",
            &[&(pw.len() + sessions.len() + hidden_sessions).to_string()]
        ))
    );
    let list = if rows.is_empty() {
        format!(
            "<div class=\"empty\">{}</div>",
            esc(&t(lang, "No devices are connected."))
        )
    } else {
        format!("<ul class=\"rows\">{rows}</ul>")
    };
    let create = format!(
        "<form class=\"createrow\" method=\"post\" action=\"/devices/create\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <label>{}<input type=\"text\" name=\"name\" placeholder=\"{}\" required maxlength=\"128\"></label>\
         <button class=\"primary\" type=\"submit\">{}</button></form>",
        esc(&t(lang, "Device name")),
        esc(&t(lang, "e.g. Backup server")),
        esc(&t(lang, "Create"))
    );
    let account = format!(
        "<dl class=\"facts\"><dt>{}</dt><dd class=\"mono\">{}</dd><dt>{}</dt><dd>Argon2id</dd></dl>\
         <p><a class=\"button wide\" href=\"/settings/password\">{}</a></p>\
         <form method=\"post\" action=\"/devices/sign-out-others\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <button class=\"danger wide\" type=\"submit\">{}</button></form>",
        esc(&t(lang, "Username")),
        esc(&p.name),
        esc(&t(lang, "Password hash")),
        esc(&t(lang, "Change password")),
        esc(&t(lang, "Sign out all other browsers"))
    );
    let twofa = match state.two_factor_status(p).await {
        Ok(st) if st.available || st.enabled => {
            let chip = format!(
                "<span class=\"chip{}\">{}</span>",
                if st.enabled { " ok" } else { "" },
                esc(&t(lang, if st.enabled { "On" } else { "Off" }))
            );
            let inner = if st.enabled {
                format!(
                    "<div class=\"twofa-row\"><p class=\"muted\">{}</p><div class=\"row-actions\">\
                     <a class=\"button\" href=\"/settings/2fa/codes\">{}</a>\
                     <a class=\"button danger\" href=\"/settings/2fa/disable\">{}</a></div></div>",
                    esc(&tf(
                        lang,
                        "{0} recovery codes left. Browser sign-in asks for a code; connected devices need nothing.",
                        &[&st.recovery_left.to_string()]
                    )),
                    esc(&t(lang, "New recovery codes")),
                    esc(&t(lang, "Turn off"))
                )
            } else {
                format!(
                    "<div class=\"twofa-row\"><p class=\"muted\">{}</p><a class=\"button primary\" href=\"/settings/2fa\">{}</a></div>",
                    esc(&t(
                        lang,
                        "Optional. On every browser sign-in, Rostdav also asks for a six-digit code from your authenticator app. Connected devices keep their app passwords and need no changes."
                    )),
                    esc(&t(lang, "Set up"))
                )
            };
            ui::card(lang, "Two-factor authentication", &chip, &inner)
        }
        _ => String::new(),
    };
    let body = format!(
        "{}{notice}{}{twofa}<div class=\"cols\">{}{}</div>",
        ui::page_head(
            lang,
            "Devices & security",
            "Every device signs in with its own app password. Revoking it signs the device out immediately – your account password stays the same.",
            ""
        ),
        ui::card(lang, "Connected devices", &chip, &list),
        ui::card(
            lang,
            "Create app password",
            "",
            &format!(
                "<p class=\"muted\">{}</p>{create}",
                esc(&t(
                    lang,
                    "For clients without browser sign-in, such as rclone, davfs2 or scripts. The Nextcloud app does not need this – it connects through the sign-in page."
                ))
            )
        ),
        ui::card(lang, "Account", "", &account),
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
                "<div class=\"notice token\" role=\"status\"><b>{}</b><br>\
                 <code>{}</code></div>",
                esc(&tf(
                    a.lang,
                    "App password for “{0}”. It is shown only once; copy it now.",
                    &[f.name.trim()]
                )),
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
    let lang = a.lang;
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
    let prof = state.profile(p).await.unwrap_or_default();
    let lang_pref = state
        .pref(p, "language")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "auto".to_owned());
    let lang_opt = |v: &str, label: &str| {
        format!(
            "<option value=\"{v}\"{}>{}</option>",
            if lang_pref == v { " selected" } else { "" },
            esc(label)
        )
    };
    let has_avatar = state.has_avatar(p).await;
    let picture = ui::card(
        lang,
        "Profile picture",
        "",
        &format!(
            "<div class=\"avatarrow\">{}<div><form id=\"avatar-form\" class=\"stack-form\" method=\"post\" action=\"/settings/avatar\" enctype=\"multipart/form-data\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <label id=\"avatar-zone\" class=\"dropzone\"><input type=\"file\" name=\"file\" accept=\"image/*\" required>\
             <canvas id=\"avatar-preview\" class=\"dz-preview\" width=\"96\" height=\"96\" hidden aria-hidden=\"true\"></canvas>\
             <svg class=\"i dz-icon\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M12 16V4\"/><path d=\"M7 9l5-5 5 5\"/><path d=\"M5 20h14\"/></svg>\
             <span class=\"dz-title\">{}</span><span class=\"dz-hint\">{}</span></label>\
             <p id=\"avatar-msg\" class=\"muted\" role=\"status\">{}</p>\
             <div class=\"actions\"><button id=\"avatar-save\" class=\"primary\" type=\"submit\">{}</button></div></form>{}</div></div>",
            if has_avatar {
                format!(
                    "<img class=\"avatar-big\" src=\"/avatar/{}/128\" alt=\"\" width=\"96\" height=\"96\">",
                    crate::layout::enc(&p.name)
                )
            } else {
                ui::avatar(&p.name)
            },
            esc(&t(lang, "Choose a picture")),
            esc(&t(lang, "or drop it here")),
            esc(&t(
                lang,
                "Any picture works: it is cropped to a square and shrunk in your browser. Without JavaScript, send a PNG or JPEG of 16 to 1024 pixels and at most 256 KiB."
            )),
            esc(&t(lang, "Upload")),
            if has_avatar {
                format!(
                    "<form class=\"inline\" method=\"post\" action=\"/settings/avatar/delete\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><button type=\"submit\">{}</button></form>",
                    esc(&t(lang, "Remove picture"))
                )
            } else {
                String::new()
            },
        ),
    );
    let profile = ui::card(
        lang,
        "Profile",
        "",
        &format!(
            "<form class=\"createrow\" method=\"post\" action=\"/settings/profile\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <label>{}<input type=\"text\" name=\"display_name\" value=\"{}\" maxlength=\"80\" autocomplete=\"name\"></label>\
             <label>{}<input type=\"text\" name=\"email\" value=\"{}\" maxlength=\"254\" inputmode=\"email\" autocomplete=\"email\" placeholder=\"name@example.com\"></label>\
             <label>{}<select name=\"language\">{}{}{}</select></label>\
             <button class=\"primary\" type=\"submit\">{}</button></form>\
             <dl class=\"facts\"><dt>{}</dt><dd class=\"mono\">{}</dd></dl>\
             <p><a href=\"/settings/password\">{}</a></p>",
            esc(&t(lang, "Display name")),
            esc(&prof.display_name),
            esc(&t(lang, "E-mail for notifications")),
            esc(&prof.email),
            esc(&t(lang, "Language")),
            lang_opt("auto", &t(lang, "Same as browser")),
            lang_opt("en", "English"),
            lang_opt("de", "Deutsch"),
            esc(&t(lang, "Save")),
            esc(&t(lang, "Username")),
            esc(&p.name),
            esc(&t(lang, "Change password"))
        ),
    );
    let seg = |v: &str, label: &str| {
        let on = a.theme == v || (a.theme.is_empty() && v == "system");
        format!(
            "<button type=\"submit\" name=\"theme\" value=\"{v}\" aria-pressed=\"{on}\"{}>{}</button>",
            if on { " class=\"on\"" } else { "" },
            esc(&t(lang, label))
        )
    };
    let appearance = ui::card(
        lang,
        "Appearance",
        &format!(
            "<form class=\"segform\" method=\"post\" action=\"/settings/theme\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><div class=\"seg\" role=\"group\" aria-label=\"{}\">{}{}{}</div></form>",
            esc(&t(lang, "Theme")),
            seg("light", "Light"),
            seg("dark", "Dark"),
            seg("system", "Same as system")
        ),
        &format!(
            "<p class=\"muted\">{}</p>",
            esc(&t(lang, "The whole page switches when you choose."))
        ),
    );
    let webdav = ui::card(
        lang,
        "WebDAV address",
        "",
        &format!(
            "<p class=\"muted\">{}</p>\
             <div class=\"codebox\"><code id=\"webdav-url\">{}</code>\
             <button type=\"button\" data-copy=\"webdav-url\" hidden>{}</button></div>\
             <p><a href=\"/devices\">{}</a></p>",
            esc(&t(
                lang,
                "For rclone, davfs2, Finder or Explorer. Sign in there with an app password."
            )),
            esc(&url),
            esc(&t(lang, "Copy")),
            esc(&t(lang, "Create an app password"))
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
    let quota = u.quota.map_or_else(|| t(lang, "unlimited"), bytes);
    let storage = ui::card(
        lang,
        "Storage",
        "",
        &format!(
            "<svg class=\"stack\" viewBox=\"0 0 100 1\" preserveAspectRatio=\"none\" role=\"img\" \
             aria-label=\"{}\"><rect class=\"s-bg\" x=\"0\" y=\"0\" width=\"100\" height=\"1\"/>{rects}</svg>\
             <ul class=\"legend\"><li><span class=\"dot s-files\" aria-hidden=\"true\"></span>{}<span>{}</span></li>\
             <li><span class=\"dot s-versions\" aria-hidden=\"true\"></span>{}<span>{}</span></li>\
             <li><span class=\"dot s-trash\" aria-hidden=\"true\"></span>{}<span>{}</span></li></ul>\
             <p class=\"muted\">{}</p>",
            esc(&tf(lang, "{0} used of {1}", &[&bytes(u.used), &quota])),
            esc(&t(lang, "Files")),
            bytes(u.files),
            esc(&t(lang, "Versions")),
            bytes(u.versions),
            esc(&t(lang, "Trash bin")),
            bytes(u.trash),
            esc(&tf(
                lang,
                "Quota: {0} · set by the administrator",
                &[&quota]
            ))
        ),
    );
    let export = ui::card(
        lang,
        "Export your data",
        "",
        &format!(
            "<p class=\"muted\">{}</p>\
             <form method=\"post\" action=\"/settings/export\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><button type=\"submit\">{}</button></form>",
            esc(&t(
                lang,
                "Downloads all your own files with their folder structure as a tar archive. Files shared with you, older versions and the trash are not included."
            )),
            esc(&t(lang, "Start export"))
        ),
    );
    let body = format!(
        "{}{notice}{profile}{picture}{appearance}<div class=\"cols\">{webdav}{storage}</div>{export}",
        ui::page_head(
            lang,
            "Settings",
            "Personal settings for your account. Changes are saved immediately.",
            ""
        )
    );
    let opts = crate::layout::Opts {
        bare_main: true,
        script: Some("copy.js avatar.js"),
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
    language: String,
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
    let res = async {
        state
            .set_profile(&a.session.principal, &f.display_name, &f.email)
            .await?;
        if !f.language.is_empty() {
            state
                .set_pref(&a.session.principal, "language", &f.language)
                .await?;
        }
        Ok::<(), Error>(())
    }
    .await;
    match res {
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
    let lang = a.lang;
    let note = if done {
        format!(
            "<div class=\"notice\" role=\"status\">{}</div>",
            esc(&t(
                lang,
                "Password changed. All other browsers were signed out; your connected devices keep working."
            ))
        )
    } else if !error.is_empty() {
        format!("<div class=\"err\" role=\"alert\">{}</div>", esc(error))
    } else {
        String::new()
    };
    let form = format!(
        "{note}<form class=\"stack-form\" method=\"post\" action=\"/settings/password\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
         <label>{}<input type=\"password\" name=\"current\" autocomplete=\"current-password\" required></label>\
         <label>{}<input type=\"password\" name=\"new\" autocomplete=\"new-password\" required minlength=\"10\"></label>\
         <label>{}<input type=\"password\" name=\"again\" autocomplete=\"new-password\" required minlength=\"10\"></label>\
         <div class=\"actions\"><button class=\"primary\" type=\"submit\">{}</button><a class=\"button\" href=\"/settings\">{}</a></div></form>",
        esc(&a.csrf),
        esc(&t(lang, "Current password")),
        esc(&t(lang, "New password (at least 10 characters)")),
        esc(&t(lang, "New password again")),
        esc(&t(lang, "Change password")),
        esc(&t(lang, "Cancel"))
    );
    let body = format!(
        "{}{}",
        ui::page_head(
            lang,
            "Change password",
            "Other browsers are signed out when the password changes. Connected devices keep their app passwords.",
            ""
        ),
        ui::card(lang, "Password", "", &form)
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
            &t(a.lang, "The two new passwords are not the same."),
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
            &t(a.lang, "The current password is wrong."),
        ),
        Err(Error::RateLimited { retry_after_secs }) => password_form(
            &a,
            StatusCode::TOO_MANY_REQUESTS,
            false,
            &tf(
                a.lang,
                "Too many attempts. Try again in {0} minutes.",
                &[&retry_after_secs.div_ceil(60).to_string()],
            ),
        ),
        Err(Error::BadRequest(_)) => password_form(
            &a,
            StatusCode::BAD_REQUEST,
            false,
            &t(a.lang, "The new password must have at least 10 characters."),
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

/// `POST /settings/avatar`: a new profile picture (multipart: `csrf`, then `file`).
pub async fn avatar_upload(
    State(state): State<AppState>,
    a: Authed,
    parts: axum::http::request::Parts,
    mut mp: axum::extract::Multipart,
) -> Response {
    let fail = |status: StatusCode, msg: &str| {
        let notice = format!(
            "<div class=\"err\" role=\"alert\">{}</div>",
            esc(&t(a.lang, msg))
        );
        let (state, a, headers) = (state.clone(), &a, parts.headers.clone());
        async move { settings_page(&state, a, &headers, status, &notice).await }
    };
    let mut csrf = None;
    loop {
        let field = match mp.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => return fail(StatusCode::BAD_REQUEST, "No picture was sent.").await,
            Err(_) => return fail(StatusCode::BAD_REQUEST, "The upload was malformed.").await,
        };
        match field.name() {
            Some("csrf") => csrf = field.text().await.ok(),
            Some("file") => {
                if !csrf.as_deref().is_some_and(|c| csrf_ok(&state, &a, c)) {
                    return StatusCode::FORBIDDEN.into_response();
                }
                let Ok(bytes) = field.bytes().await else {
                    return fail(StatusCode::BAD_REQUEST, "The upload was malformed.").await;
                };
                return match state.avatar_set(&a.session.principal, &bytes).await {
                    Ok(()) => Redirect::to("/settings").into_response(),
                    Err(Error::Invalid(m)) => {
                        let notice = format!(
                            "<div class=\"err\" role=\"alert\">{}.</div>",
                            esc(&t(a.lang, &m))
                        );
                        settings_page(&state, &a, &parts.headers, StatusCode::BAD_REQUEST, &notice)
                            .await
                    }
                    Err(e) => error_response_to(&a, &e, "/settings", "settings"),
                };
            }
            _ => {}
        }
    }
}

#[derive(Deserialize)]
pub struct CsrfOnly {
    csrf: String,
}

pub async fn avatar_remove(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<CsrfOnly>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match state.avatar_remove(&a.session.principal).await {
        Ok(()) => Redirect::to("/settings").into_response(),
        Err(e) => error_response_to(&a, &e, "/settings", "settings"),
    }
}
