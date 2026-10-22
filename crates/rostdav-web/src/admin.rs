//! Administration pages (ADR 0006, slice 11c): users, event log, status and
//! consistency check, server settings. Everything also exists in the CLI; both
//! call the same `Actor`-checked service methods.

use axum::Form;
use axum::extract::{FromRequestParts, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Redirect, Response};
use rostdav_app::{Actor, AppState, DeleteMode, FsckOptions, parse_quota};
use rostdav_core::Error;
use serde::Deserialize;

use crate::layout::{enc, esc};
use crate::pages::{date, human, message_in};
use crate::session::Authed;
use crate::ui;

/// A signed-in administrator. Everyone else gets 403.
pub struct Admin(pub Authed);

impl FromRequestParts<AppState> for Admin {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let a = Authed::from_request_parts(parts, state).await?;
        if a.session.principal.is_admin {
            Ok(Self(a))
        } else {
            Err(StatusCode::FORBIDDEN.into_response())
        }
    }
}

fn forbidden() -> Response {
    StatusCode::FORBIDDEN.into_response()
}

fn csrf_ok(state: &AppState, a: &Authed, given: &str) -> bool {
    state.web_check_csrf(a.session.id, given).is_ok()
}

fn error_page(a: &Authed, e: &Error, back: &str) -> Response {
    let (status, text): (StatusCode, String) = match e {
        Error::NotFound => (StatusCode::NOT_FOUND, "Not found.".into()),
        Error::Forbidden => (StatusCode::FORBIDDEN, "Not allowed.".into()),
        // these carry fixed texts written for administrators
        Error::Conflict(m) | Error::BadRequest(m) => (StatusCode::CONFLICT, format!("{m}.")),
        Error::Invalid(m) => (StatusCode::BAD_REQUEST, format!("{m}.")),
        Error::AlreadyExists => (StatusCode::CONFLICT, "That name already exists.".into()),
        other => {
            tracing::error!(error = %other, "admin request failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong.".into(),
            )
        }
    };
    message_in(
        a,
        status,
        "Could not complete the action",
        &text,
        back,
        "admin",
    )
}

fn page(a: &Authed, title: &str, section: &str, body: &str) -> Response {
    let tab = |key: &str, label: &str, href: &str| {
        let cur = if key == section {
            " aria-current=\"page\" class=\"on\""
        } else {
            ""
        };
        format!("<a href=\"{href}\"{cur}>{label}</a>")
    };
    let tabs = format!(
        "<nav class=\"seg tabs\" aria-label=\"Administration sections\">{}{}{}{}</nav>",
        tab("users", "Users", "/admin/users"),
        tab("events", "Event log", "/admin/events"),
        tab("status", "Status", "/admin/status"),
        tab("server", "Server", "/admin/server"),
    );
    let pill = format!(
        "<div class=\"pill\"><span class=\"dot live\" aria-hidden=\"true\"></span>Server running · version {}</div>",
        esc(env!("CARGO_PKG_VERSION"))
    );
    let body = format!(
        "{}{tabs}{body}",
        ui::page_head("Administration", "Visible to administrators only.", &pill)
    );
    ui::page(a, StatusCode::OK, title, "admin", &body)
}

// ---- users ----------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct UsersQuery {
    #[serde(default)]
    q: String,
}

pub async fn users(
    State(state): State<AppState>,
    Admin(a): Admin,
    Query(q): Query<UsersQuery>,
) -> Response {
    let list = match state.users_list(&Actor::User(&a.session.principal)).await {
        Ok(l) => l,
        Err(e) => return error_page(&a, &e, "/files"),
    };
    let needle = q.q.trim().to_lowercase();
    let csrf = esc(&a.csrf);
    let mut rows = String::new();
    for u in list
        .iter()
        .filter(|u| needle.is_empty() || u.name.to_lowercase().contains(&needle))
    {
        let storage = match u.quota_bytes {
            Some(q) if q > 0 => format!(
                "<progress class=\"meter\" max=\"{q}\" value=\"{}\" aria-label=\"Storage of {}\"></progress>\
                 <span class=\"muted\">{} % of {}</span>",
                u.used_bytes.clamp(0, q),
                esc(&u.name),
                u.used_bytes * 100 / q,
                human(q)
            ),
            _ => format!(
                "<span class=\"muted\">{} used · no quota</span>",
                human(u.used_bytes)
            ),
        };
        let toggle = if u.name == a.session.principal.name {
            String::new()
        } else {
            format!(
                "<form method=\"post\" action=\"/admin/users/disabled\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                 <input type=\"hidden\" name=\"name\" value=\"{}\"><input type=\"hidden\" name=\"disabled\" value=\"{}\">\
                 <button class=\"{}\" type=\"submit\" aria-label=\"{} {}\">{}</button></form>",
                esc(&u.name),
                if u.disabled { "0" } else { "1" },
                if u.disabled { "" } else { "danger" },
                if u.disabled { "Enable" } else { "Disable" },
                esc(&u.name),
                if u.disabled { "Enable" } else { "Disable" },
            )
        };
        rows.push_str(&format!(
            "<li class=\"row userrow{}\">{}<div class=\"row-text\"><b>{}</b><span class=\"muted\">{}</span></div>\
             <span class=\"u-storage\">{storage}</span>\
             <span class=\"chip {}\">{}</span>\
             <div class=\"row-actions\"><a class=\"button\" href=\"/admin/users/manage?name={}\" aria-label=\"Edit {}\">Edit</a>{toggle}</div></li>",
            if u.disabled { " off" } else { "" },
            ui::avatar(&u.name),
            esc(&u.name),
            if u.is_admin { "Administrator" } else { "User" },
            if u.disabled { "" } else { "ok" },
            if u.disabled { "Disabled" } else { "Active" },
            esc(&enc(&u.name)),
            esc(&u.name),
        ));
    }
    let list_html = if rows.is_empty() {
        "<div class=\"empty\">No users match.</div>".to_owned()
    } else {
        format!("<ul class=\"rows\">{rows}</ul>")
    };
    let toolbar = format!(
        "<div class=\"cardbar\"><form class=\"search\" method=\"get\" action=\"/admin/users\" role=\"search\">{}\
         <input type=\"search\" name=\"q\" value=\"{}\" placeholder=\"Search users\" aria-label=\"Search users\"></form>\
         <details class=\"pop\"><summary class=\"button primary\">{}Add user</summary>\
         <form class=\"popover\" method=\"post\" action=\"/admin/users/create\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <label>Name<input type=\"text\" name=\"name\" required></label>\
         <label>Password<input type=\"password\" name=\"password\" autocomplete=\"new-password\" required></label>\
         <label class=\"check\"><input type=\"checkbox\" name=\"admin\" value=\"1\"> Administrator</label>\
         <button class=\"primary\" type=\"submit\">Add user</button></form></details></div>",
        ui::svg("search"),
        esc(&q.q),
        ui::svg("plus"),
    );
    page(
        &a,
        "Users",
        "users",
        &ui::card(
            "Users",
            &format!("<span class=\"chip\">{} total</span>", list.len()),
            &format!("{toolbar}{list_html}"),
        ),
    )
}

#[derive(Deserialize)]
pub struct CreateForm {
    csrf: String,
    name: String,
    password: String,
    #[serde(default)]
    admin: String,
}

pub async fn create(
    State(state): State<AppState>,
    Admin(a): Admin,
    Form(f): Form<CreateForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let actor = Actor::User(&a.session.principal);
    match state
        .create_user_as(&actor, f.name.trim(), &f.password, f.admin == "1")
        .await
    {
        Ok(_) => Redirect::to("/admin/users").into_response(),
        Err(e) => error_page(&a, &e, "/admin/users"),
    }
}

#[derive(Deserialize)]
pub struct NameQuery {
    name: String,
}

pub async fn manage(
    State(state): State<AppState>,
    Admin(a): Admin,
    Query(q): Query<NameQuery>,
) -> Response {
    let list = match state.users_list(&Actor::User(&a.session.principal)).await {
        Ok(l) => l,
        Err(e) => return error_page(&a, &e, "/admin/users"),
    };
    let Some(u) = list.iter().find(|u| u.name == q.name) else {
        return error_page(&a, &Error::NotFound, "/admin/users");
    };
    let csrf = esc(&a.csrf);
    let name = esc(&u.name);
    let hidden = format!(
        "<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"name\" value=\"{name}\">"
    );
    let quota = u
        .quota_bytes
        .map_or_else(|| "unlimited".to_owned(), |q| q.to_string());
    let access = format!(
        "<div class=\"actions\">\
         <form method=\"post\" action=\"/admin/users/disabled\">{hidden}<input type=\"hidden\" name=\"disabled\" value=\"{}\">\
         <button type=\"submit\">{}</button></form>\
         <form method=\"post\" action=\"/admin/users/role\">{hidden}<input type=\"hidden\" name=\"admin\" value=\"{}\">\
         <button type=\"submit\">{}</button></form></div>",
        if u.disabled { "0" } else { "1" },
        if u.disabled {
            "Allow sign-in again"
        } else {
            "Block sign-in"
        },
        if u.is_admin { "0" } else { "1" },
        if u.is_admin {
            "Remove administrator role"
        } else {
            "Make administrator"
        },
    );
    let quota_form = format!(
        "<form class=\"createrow\" method=\"post\" action=\"/admin/users/quota\">{hidden}\
         <label>Quota<input type=\"text\" name=\"quota\" value=\"{}\"></label><button type=\"submit\">Set quota</button></form>\
         <p class=\"muted\">Examples: 10G, 500M, unlimited.</p>",
        esc(&quota)
    );
    let password_form = format!(
        "<form class=\"createrow\" method=\"post\" action=\"/admin/users/password\">{hidden}\
         <label>New password<input type=\"password\" name=\"password\" autocomplete=\"new-password\" required></label>\
         <button type=\"submit\">Set password</button>\
         <label class=\"check\"><input type=\"checkbox\" name=\"revoke\" value=\"1\" checked> Sign out all devices</label></form>"
    );
    let delete = format!(
        "<p><a class=\"button danger\" href=\"/admin/users/delete?name={}\">Delete this user…</a></p>",
        esc(&enc(&u.name))
    );
    let head = format!(
        "{}<div class=\"row-text\"><b>{name}</b><span class=\"muted\">{} · {} · {} used · {} device(s) · created {}</span></div>",
        ui::avatar(&u.name),
        if u.is_admin { "Administrator" } else { "User" },
        if u.disabled { "disabled" } else { "active" },
        human(u.used_bytes),
        u.devices,
        date(u.created_at),
    );
    let body = format!(
        "<p><a href=\"/admin/users\">← Back to users</a></p><section class=\"card2\"><div class=\"row userhead\">{head}</div></section>\
         {}{}{}{}",
        ui::card("Access", "", &access),
        ui::card("Quota", "", &quota_form),
        ui::card("Reset password", "", &password_form),
        ui::card("Delete", "", &delete),
    );
    page(&a, "Manage user", "users", &body)
}

#[derive(Deserialize)]
pub struct DisabledForm {
    csrf: String,
    name: String,
    disabled: String,
}

pub async fn set_disabled(
    State(state): State<AppState>,
    Admin(a): Admin,
    Form(f): Form<DisabledForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let back = format!("/admin/users/manage?name={}", enc(&f.name));
    match state
        .user_set_disabled(
            &Actor::User(&a.session.principal),
            &f.name,
            f.disabled == "1",
        )
        .await
    {
        Ok(()) => Redirect::to(&back).into_response(),
        Err(e) => error_page(&a, &e, &back),
    }
}

#[derive(Deserialize)]
pub struct RoleForm {
    csrf: String,
    name: String,
    admin: String,
}

pub async fn set_role(
    State(state): State<AppState>,
    Admin(a): Admin,
    Form(f): Form<RoleForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let back = format!("/admin/users/manage?name={}", enc(&f.name));
    match state
        .user_set_admin(&Actor::User(&a.session.principal), &f.name, f.admin == "1")
        .await
    {
        Ok(()) => Redirect::to(&back).into_response(),
        Err(e) => error_page(&a, &e, &back),
    }
}

#[derive(Deserialize)]
pub struct QuotaForm {
    csrf: String,
    name: String,
    quota: String,
}

pub async fn set_quota(
    State(state): State<AppState>,
    Admin(a): Admin,
    Form(f): Form<QuotaForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let back = format!("/admin/users/manage?name={}", enc(&f.name));
    let res = async {
        let q = parse_quota(&f.quota)?;
        state
            .user_set_quota(&Actor::User(&a.session.principal), &f.name, q)
            .await
    }
    .await;
    match res {
        Ok(()) => Redirect::to(&back).into_response(),
        Err(e) => error_page(&a, &e, &back),
    }
}

#[derive(Deserialize)]
pub struct PasswordForm {
    csrf: String,
    name: String,
    password: String,
    #[serde(default)]
    revoke: String,
}

pub async fn set_password(
    State(state): State<AppState>,
    Admin(a): Admin,
    Form(f): Form<PasswordForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let back = format!("/admin/users/manage?name={}", enc(&f.name));
    match state
        .user_set_password(
            &Actor::User(&a.session.principal),
            &f.name,
            &f.password,
            f.revoke == "1",
        )
        .await
    {
        Ok(()) => Redirect::to(&back).into_response(),
        Err(e) => error_page(&a, &e, &back),
    }
}

pub async fn delete_confirm(Admin(a): Admin, Query(q): Query<NameQuery>) -> Response {
    let csrf = esc(&a.csrf);
    let name = esc(&q.name);
    let body = format!(
        "<h2>Delete “{name}”?</h2><p>The account and its devices are removed. Choose what happens to the files.</p>\
         <form method=\"post\" action=\"/admin/users/delete\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input type=\"hidden\" name=\"name\" value=\"{name}\">\
         <label class=\"check\"><input type=\"radio\" name=\"mode\" value=\"transfer\" checked> Move the files to another user</label>\
         <label>Receiving user<input type=\"text\" name=\"to\"></label>\
         <label class=\"check\"><input type=\"radio\" name=\"mode\" value=\"delete\"> Delete the files for good</label>\
         <div class=\"actions\"><button class=\"danger\" type=\"submit\">Delete user</button>\
         <a class=\"button\" href=\"/admin/users/manage?name={}\">Cancel</a></div></form>",
        esc(&enc(&q.name)),
    );
    page(
        &a,
        "Delete user",
        "users",
        &ui::card("Delete user", "", &body),
    )
}

#[derive(Deserialize)]
pub struct DeleteForm {
    csrf: String,
    name: String,
    mode: String,
    #[serde(default)]
    to: String,
}

pub async fn delete(
    State(state): State<AppState>,
    Admin(a): Admin,
    Form(f): Form<DeleteForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let back = format!("/admin/users/manage?name={}", enc(&f.name));
    let mode = match f.mode.as_str() {
        "delete" => DeleteMode::DeleteData,
        "transfer" if !f.to.trim().is_empty() => DeleteMode::TransferTo(f.to.trim().to_owned()),
        _ => {
            return error_page(
                &a,
                &Error::BadRequest("name the user who receives the files"),
                &back,
            );
        }
    };
    match state
        .user_delete(&Actor::User(&a.session.principal), &f.name, &mode)
        .await
    {
        Ok(()) => Redirect::to("/admin/users").into_response(),
        Err(e) => error_page(&a, &e, &back),
    }
}

// ---- event log -----------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    days: Option<i64>,
}

pub async fn events(
    State(state): State<AppState>,
    Admin(a): Admin,
    Query(q): Query<EventsQuery>,
) -> Response {
    let days = q.days.unwrap_or(7).clamp(1, 3650);
    let since = rostdav_app::now_secs() - days * 86_400;
    let mut list = match state
        .audit_events(&Actor::User(&a.session.principal), since)
        .await
    {
        Ok(l) => l,
        Err(e) => return error_page(&a, &e, "/admin/users"),
    };
    list.reverse();
    let total = list.len();
    list.truncate(500);
    let mut rows = String::new();
    for ev in &list {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"hide\">{}</td></tr>",
            date(ev.ts),
            esc(&ev.actor),
            esc(&ev.action),
            esc(&ev.target),
            esc(&ev.ip),
        ));
    }
    let more = if total > list.len() {
        format!(
            "<p class=\"muted\">Showing the newest {} of {total} events.</p>",
            list.len()
        )
    } else {
        String::new()
    };
    let opt = |d: i64| {
        let sel = if d == days { " selected" } else { "" };
        format!("<option value=\"{d}\"{sel}>Last {d} day(s)</option>")
    };
    let body = format!(
        "<form class=\"inline\" method=\"get\" action=\"/admin/events\"><select name=\"days\" aria-label=\"Period\">{}{}{}{}</select>\
         <button type=\"submit\">Show</button></form>{more}\
         <table><thead><tr><th>Time (UTC)</th><th>Actor</th><th>Event</th><th>Target</th><th class=\"hide\">Address</th></tr></thead><tbody>{rows}</tbody></table>",
        opt(1),
        opt(7),
        opt(30),
        opt(365),
    );
    page(&a, "Event log", "events", &ui::card("Event log", "", &body))
}

// ---- status and consistency check ---------------------------------------------------------------------

pub async fn status(State(state): State<AppState>, Admin(a): Admin) -> Response {
    status_page(&state, &a, "").await
}

async fn status_page(state: &AppState, a: &Authed, report: &str) -> Response {
    let list = match state.users_list(&Actor::User(&a.session.principal)).await {
        Ok(l) => l,
        Err(e) => return error_page(a, &e, "/files"),
    };
    let used: i64 = list.iter().map(|u| u.used_bytes).sum();
    let csrf = esc(&a.csrf);
    let body = format!(
        "<table><tbody><tr><td>Version</td><td class=\"num\">{}</td></tr>\
         <tr><td>Users</td><td class=\"num\">{}</td></tr><tr><td>Storage used</td><td class=\"num\">{}</td></tr></tbody></table>\
         <h2>Consistency check</h2><p class=\"muted\">Compares the database with the stored files. Safe to run while the server is in use.</p>\
         <form class=\"inline\" method=\"post\" action=\"/admin/status/check\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <label class=\"check\"><input type=\"checkbox\" name=\"checksums\" value=\"1\"> Also re-read every file (slow)</label>\
         <label class=\"check\"><input type=\"checkbox\" name=\"repair\" value=\"1\"> Repair what can be repaired</label>\
         <button type=\"submit\">Run check</button></form>{report}",
        esc(env!("CARGO_PKG_VERSION")),
        list.len(),
        human(used),
    );
    page(a, "Status", "status", &ui::card("Status", "", &body))
}

#[derive(Deserialize)]
pub struct CheckForm {
    csrf: String,
    #[serde(default)]
    checksums: String,
    #[serde(default)]
    repair: String,
}

pub async fn check(
    State(state): State<AppState>,
    Admin(a): Admin,
    Form(f): Form<CheckForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let opts = FsckOptions {
        repair: f.repair == "1",
        verify_checksums: f.checksums == "1",
        min_orphan_age_secs: 3600,
    };
    let r = match state.fsck(&Actor::User(&a.session.principal), opts).await {
        Ok(r) => r,
        Err(e) => return error_page(&a, &e, "/admin/status"),
    };
    let line =
        |label: &str, n: usize| format!("<tr><td>{label}</td><td class=\"num\">{n}</td></tr>");
    let report = format!(
        "<h3>Result: {}</h3><table><tbody>{}{}{}{}{}{}{}</tbody></table>",
        if r.is_clean() {
            "no problems"
        } else {
            "problems found"
        },
        line("Files checked", r.blobs_checked),
        line("Missing files (not repairable)", r.missing_blobs.len()),
        line("Corrupt files", r.corrupt_blobs.len()),
        line("Unreferenced files", r.orphan_blobs.len()),
        line("Wrong usage counters", r.usage_mismatches.len()),
        line("Orphan upload folders", r.orphan_session_dirs.len()),
        line(
            "Upload sessions without folder",
            r.sessions_without_dir.len()
        ),
    );
    status_page(&state, &a, &report).await
}

// ---- server settings -------------------------------------------------------------------------------------

pub async fn server(State(state): State<AppState>, Admin(a): Admin) -> Response {
    let rows = match state.settings_summary(&Actor::User(&a.session.principal)) {
        Ok(r) => r,
        Err(e) => return error_page(&a, &e, "/files"),
    };
    let rows: String = rows
        .iter()
        .map(|(k, v)| {
            format!(
                "<tr><td>{}</td><td class=\"num\">{}</td></tr>",
                esc(k),
                esc(v)
            )
        })
        .collect();
    let body = format!(
        "<p class=\"muted\">Settings come from the configuration file and environment variables. \
         Change them there and restart the server.</p><table><tbody>{rows}</tbody></table>"
    );
    page(
        &a,
        "Server",
        "server",
        &ui::card("Effective settings", "", &body),
    )
}
