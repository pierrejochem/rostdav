//! Trash and Devices pages (ADR 0006, slice 11a).

use axum::Form;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use rostdav_app::AppState;
use rostdav_core::Error;
use serde::Deserialize;

use crate::layout::{self, esc};
use crate::pages::{date, error_response_to};
use crate::session::Authed;

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
            "<tr><td>{}</td><td class=\"hide\">{}</td><td class=\"hide\">{}</td><td class=\"num\">\
             <form class=\"inline\" method=\"post\" action=\"/trash/restore\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"entry\" value=\"{entry}\">\
             <button type=\"submit\">Restore</button> \
             <a class=\"button\" href=\"/trash/delete?entry={}\">Delete permanently</a></form></td></tr>",
            esc(&i.orig_path),
            date(i.deleted_at),
            esc(i.deleted_by.as_deref().unwrap_or("")),
            esc(&crate::layout::enc(&i.entry_name())),
        ));
    }
    let body = if !enabled {
        "<h1>Trash</h1><div class=\"empty\">The trash is turned off on this server. Deleted files are gone for good.</div>".to_owned()
    } else if items.is_empty() {
        "<h1>Trash</h1><div class=\"empty\">The trash is empty.</div>".to_owned()
    } else {
        format!(
            "<h1>Trash</h1><p class=\"muted\">Deleted items still count toward your storage until they are removed.</p>\
             <div class=\"actions\"><a class=\"button danger\" href=\"/trash/empty\">Empty trash</a></div>\
             <table><thead><tr><th>Original location</th><th class=\"hide\">Deleted</th><th class=\"hide\">By</th><th></th></tr></thead><tbody>{rows}</tbody></table>"
        )
    };
    layout::app(StatusCode::OK, "Trash", &a.theme, "trash", &a.csrf, &body)
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
        &a.theme,
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
        &a.theme,
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
    let mut dev = String::new();
    for d in &pw {
        dev.push_str(&format!(
            "<tr><td>{}</td><td class=\"hide\">{}</td><td class=\"hide\">{}</td><td class=\"num\">\
             <form class=\"inline\" method=\"post\" action=\"/devices/revoke\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <input type=\"hidden\" name=\"id\" value=\"{}\"><button class=\"danger\" type=\"submit\">Revoke</button></form></td></tr>",
            esc(&d.name),
            date(d.created_at),
            d.last_used_at.map_or_else(|| "never".to_owned(), date),
            d.id
        ));
    }
    let devices = if pw.is_empty() {
        "<div class=\"empty\">No devices are connected.</div>".to_owned()
    } else {
        format!(
            "<table><thead><tr><th>Device</th><th class=\"hide\">Created</th><th class=\"hide\">Last used</th><th></th></tr></thead><tbody>{dev}</tbody></table>"
        )
    };
    let mut ses = String::new();
    for s in &sessions {
        let this = if s.id == a.session.id {
            " (this browser)"
        } else {
            ""
        };
        ses.push_str(&format!(
            "<tr><td>{}{}</td><td class=\"hide\">{}</td><td>{}</td></tr>",
            esc(&s.user_agent.chars().take(80).collect::<String>()),
            this,
            esc(&s.ip),
            date(s.last_seen)
        ));
    }
    let body = format!(
        "<h1>Devices</h1>{notice}\
         <p class=\"muted\">Each app or program gets its own app password. Revoke it here if a device is lost.</p>\
         <form class=\"inline\" method=\"post\" action=\"/devices/create\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input type=\"text\" name=\"name\" placeholder=\"Device name\" aria-label=\"Device name\" required maxlength=\"128\">\
         <button class=\"primary\" type=\"submit\">Create app password</button></form><br>{devices}\
         <h1>Browser sessions</h1>\
         <table><thead><tr><th>Browser</th><th class=\"hide\">Address</th><th>Last active</th></tr></thead><tbody>{ses}</tbody></table>\
         <form class=\"inline\" method=\"post\" action=\"/devices/sign-out-others\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <br><button type=\"submit\">Sign out all other browsers</button></form>"
    );
    layout::app(status, "Devices", &a.theme, "devices", &a.csrf, &body)
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
                "<div class=\"notice\" role=\"status\"><b>App password for “{}”. It is shown only once; copy it now.</b><br>\
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
