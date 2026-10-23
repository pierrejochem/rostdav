//! Administration pages (ADR 0006, slice 11c): users, event log, status and
//! consistency check, server settings. Everything also exists in the CLI; both
//! call the same `Actor`-checked service methods.

use axum::Form;
use axum::extract::{FromRequestParts, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Redirect, Response};
use rostdav_app::{Actor, AppState, DeleteMode, FsckOptions, LockoutKind, Tunable, parse_quota};
use rostdav_core::Error;
use serde::Deserialize;

use crate::i18n::{t, t_quiet, tf};
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
    let lang = a.lang;
    let tab = |key: &str, label: &str, href: &str| {
        let cur = if key == section {
            " aria-current=\"page\" class=\"on\""
        } else {
            ""
        };
        format!("<a href=\"{href}\"{cur}>{}</a>", esc(&t(lang, label)))
    };
    let tabs = format!(
        "<nav class=\"seg tabs\" aria-label=\"{}\">{}{}{}{}{}</nav>",
        esc(&t(lang, "Administration sections")),
        tab("users", "Users", "/admin/users"),
        tab("events", "Event log", "/admin/events"),
        tab("status", "Status", "/admin/status"),
        tab("security", "Sign-in and maintenance", "/admin/security"),
        tab("server", "Server", "/admin/server"),
    );
    let pill = format!(
        "<div class=\"pill\"><span class=\"dot live\" aria-hidden=\"true\"></span>{}</div>",
        esc(&tf(
            lang,
            "Server running · version {0}",
            &[env!("CARGO_PKG_VERSION")]
        ))
    );
    let body = format!(
        "{}{tabs}{body}",
        ui::page_head(
            lang,
            "Administration",
            "Visible to administrators only.",
            &pill
        )
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
    let lang = a.lang;
    let needle = q.q.trim().to_lowercase();
    let csrf = esc(&a.csrf);
    let mut rows = String::new();
    for u in list
        .iter()
        .filter(|u| needle.is_empty() || u.name.to_lowercase().contains(&needle))
    {
        let storage = match u.quota_bytes {
            Some(q) if q > 0 => format!(
                "<progress class=\"meter\" max=\"{q}\" value=\"{}\" aria-label=\"{}\"></progress>\
                 <span class=\"muted\">{}</span>",
                u.used_bytes.clamp(0, q),
                esc(&tf(lang, "Storage of {0}", &[&u.name])),
                esc(&tf(
                    lang,
                    "{0} % of {1}",
                    &[&(u.used_bytes * 100 / q).to_string(), &human(q)]
                ))
            ),
            _ => format!(
                "<span class=\"muted\">{}</span>",
                esc(&tf(lang, "{0} used · no quota", &[&human(u.used_bytes)]))
            ),
        };
        let toggle = if u.name == a.session.principal.name {
            String::new()
        } else {
            format!(
                "<form method=\"post\" action=\"/admin/users/disabled\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                 <input type=\"hidden\" name=\"name\" value=\"{}\"><input type=\"hidden\" name=\"disabled\" value=\"{}\">\
                 <button class=\"{}\" type=\"submit\" aria-label=\"{}\">{}</button></form>",
                esc(&u.name),
                if u.disabled { "0" } else { "1" },
                if u.disabled { "" } else { "danger" },
                esc(&tf(
                    lang,
                    if u.disabled {
                        "Enable {0}"
                    } else {
                        "Disable {0}"
                    },
                    &[&u.name]
                )),
                esc(&t(lang, if u.disabled { "Enable" } else { "Disable" })),
            )
        };
        let twofa = if u.two_factor {
            format!(
                "<span class=\"chip\" title=\"{}\">2FA</span>",
                esc(&t(lang, "Two-factor authentication is on for this user."))
            )
        } else {
            String::new()
        };
        rows.push_str(&format!(
            "<li class=\"row userrow{}\">{}<div class=\"row-text\"><b>{}</b><span class=\"muted\">{}</span></div>\
             <span class=\"u-storage\">{storage}</span>\
             {twofa}<span class=\"chip {}\">{}</span>\
             <div class=\"row-actions\"><a class=\"button\" href=\"/admin/users/manage?name={}\" aria-label=\"{}\">{}</a>{toggle}</div></li>",
            if u.disabled { " off" } else { "" },
            ui::avatar_of(&u.name, u.avatar.as_deref()),
            esc(&u.name),
            esc(&t(lang, if u.is_admin { "Administrator" } else { "User" })),
            if u.disabled { "" } else { "ok" },
            esc(&t(lang, if u.disabled { "Disabled" } else { "Active" })),
            esc(&enc(&u.name)),
            esc(&tf(lang, "Edit {0}", &[&u.name])),
            esc(&t(lang, "Edit")),
        ));
    }
    let list_html = if rows.is_empty() {
        format!(
            "<div class=\"empty\">{}</div>",
            esc(&t(lang, "No users match."))
        )
    } else {
        format!("<ul class=\"rows\">{rows}</ul>")
    };
    let toolbar = format!(
        "<div class=\"cardbar\"><form class=\"search\" method=\"get\" action=\"/admin/users\" role=\"search\">{}\
         <input type=\"search\" name=\"q\" value=\"{}\" placeholder=\"{search}\" aria-label=\"{search}\"></form>\
         <details class=\"pop\"><summary class=\"button primary\">{}{add}</summary>\
         <form class=\"popover\" method=\"post\" action=\"/admin/users/create\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <label>{}<input type=\"text\" name=\"name\" required></label>\
         <label>{}<input type=\"password\" name=\"password\" autocomplete=\"new-password\" required></label>\
         <label class=\"check\"><input type=\"checkbox\" name=\"admin\" value=\"1\"> {}</label>\
         <button class=\"primary\" type=\"submit\">{add}</button></form></details></div>",
        ui::svg("search"),
        esc(&q.q),
        ui::svg("plus"),
        esc(&t(lang, "Name")),
        esc(&t(lang, "Password")),
        esc(&t(lang, "Administrator")),
        search = esc(&t(lang, "Search users")),
        add = esc(&t(lang, "Add user")),
    );
    page(
        &a,
        "Users",
        "users",
        &ui::card(
            lang,
            "Users",
            &format!(
                "<span class=\"chip\">{}</span>",
                esc(&tf(lang, "{0} total", &[&list.len().to_string()]))
            ),
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
    let lang = a.lang;
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
        esc(&t(
            lang,
            if u.disabled {
                "Allow sign-in again"
            } else {
                "Block sign-in"
            }
        )),
        if u.is_admin { "0" } else { "1" },
        esc(&t(
            lang,
            if u.is_admin {
                "Remove administrator role"
            } else {
                "Make administrator"
            }
        )),
    );
    let quota_form = format!(
        "<form class=\"createrow\" method=\"post\" action=\"/admin/users/quota\">{hidden}\
         <label>{}<input type=\"text\" name=\"quota\" value=\"{}\"></label><button type=\"submit\">{}</button></form>\
         <p class=\"muted\">{}</p>",
        esc(&t(lang, "Quota")),
        esc(&quota),
        esc(&t(lang, "Set quota")),
        esc(&t(lang, "Examples: 10G, 500M, unlimited."))
    );
    let password_form = format!(
        "<form class=\"createrow\" method=\"post\" action=\"/admin/users/password\">{hidden}\
         <label>{}<input type=\"password\" name=\"password\" autocomplete=\"new-password\" required></label>\
         <button type=\"submit\">{}</button>\
         <label class=\"check\"><input type=\"checkbox\" name=\"revoke\" value=\"1\" checked> {}</label></form>",
        esc(&t(lang, "New password")),
        esc(&t(lang, "Set password")),
        esc(&t(lang, "Sign out all devices"))
    );
    let twofa_on = state
        .user_two_factor_enabled(&Actor::User(&a.session.principal), &u.name)
        .await
        .unwrap_or(false);
    let twofa = format!(
        "<p class=\"muted\">{}</p>{}",
        esc(&t(
            lang,
            if twofa_on {
                "Two-factor authentication is on for this user."
            } else {
                "Two-factor authentication is off for this user."
            }
        )),
        if twofa_on {
            format!(
                "<p><a class=\"button danger\" href=\"/admin/users/two-factor-reset?name={}\">{}</a></p>",
                esc(&enc(&u.name)),
                esc(&t(lang, "Reset two-factor authentication…"))
            )
        } else {
            String::new()
        }
    );
    let delete = format!(
        "<p><a class=\"button danger\" href=\"/admin/users/delete?name={}\">{}</a></p>",
        esc(&enc(&u.name)),
        esc(&t(lang, "Delete this user…"))
    );
    let head = format!(
        "{}<div class=\"row-text\"><b>{name}</b><span class=\"muted\">{}</span></div>",
        ui::avatar_of(&u.name, u.avatar.as_deref()),
        esc(&tf(
            lang,
            "{0} · {1} · {2} used · {3} device(s) · created {4}",
            &[
                &t(lang, if u.is_admin { "Administrator" } else { "User" }),
                &t(lang, if u.disabled { "disabled" } else { "active" }),
                &human(u.used_bytes),
                &u.devices.to_string(),
                &date(u.created_at),
            ]
        )),
    );
    let body = format!(
        "<p><a href=\"/admin/users\">{}</a></p><section class=\"card2\"><div class=\"row userhead\">{head}</div></section>\
         {}{}{}{}{}",
        esc(&t(lang, "← Back to users")),
        ui::card(lang, "Access", "", &access),
        ui::card(lang, "Quota", "", &quota_form),
        ui::card(lang, "Reset password", "", &password_form),
        ui::card(lang, "Two-factor authentication", "", &twofa),
        ui::card(lang, "Delete", "", &delete),
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
    let lang = a.lang;
    let csrf = esc(&a.csrf);
    let name = esc(&q.name);
    let body = format!(
        "<h2>{}</h2><p>{}</p>\
         <form method=\"post\" action=\"/admin/users/delete\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input type=\"hidden\" name=\"name\" value=\"{name}\">\
         <label class=\"check\"><input type=\"radio\" name=\"mode\" value=\"transfer\" checked> {}</label>\
         <label>{}<input type=\"text\" name=\"to\"></label>\
         <label class=\"check\"><input type=\"radio\" name=\"mode\" value=\"delete\"> {}</label>\
         <div class=\"actions\"><button class=\"danger\" type=\"submit\">{}</button>\
         <a class=\"button\" href=\"/admin/users/manage?name={}\">{}</a></div></form>",
        esc(&tf(lang, "Delete “{0}”?", &[&q.name])),
        esc(&t(
            lang,
            "The account and its devices are removed. Choose what happens to the files."
        )),
        esc(&t(lang, "Move the files to another user")),
        esc(&t(lang, "Receiving user")),
        esc(&t(lang, "Delete the files for good")),
        esc(&t(lang, "Delete user")),
        esc(&enc(&q.name)),
        esc(&t(lang, "Cancel")),
    );
    page(
        &a,
        "Delete user",
        "users",
        &ui::card(lang, "Delete user", "", &body),
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
    let lang = a.lang;
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
            "<p class=\"muted\">{}</p>",
            esc(&tf(
                lang,
                "Showing the newest {0} of {1} events.",
                &[&list.len().to_string(), &total.to_string()]
            ))
        )
    } else {
        String::new()
    };
    let opt = |d: i64| {
        let sel = if d == days { " selected" } else { "" };
        format!(
            "<option value=\"{d}\"{sel}>{}</option>",
            esc(&tf(lang, "Last {0} day(s)", &[&d.to_string()]))
        )
    };
    let body = format!(
        "<form class=\"inline\" method=\"get\" action=\"/admin/events\"><select name=\"days\" aria-label=\"{}\">{}{}{}{}</select>\
         <button type=\"submit\">{}</button></form>{more}\
         <table><thead><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th class=\"hide\">{}</th></tr></thead><tbody>{rows}</tbody></table>",
        esc(&t(lang, "Period")),
        opt(1),
        opt(7),
        opt(30),
        opt(365),
        esc(&t(lang, "Show")),
        esc(&t(lang, "Time (UTC)")),
        esc(&t(lang, "Actor")),
        esc(&t(lang, "Event")),
        esc(&t(lang, "Target")),
        esc(&t(lang, "Address")),
    );
    page(
        &a,
        "Event log",
        "events",
        &ui::card(lang, "Event log", "", &body),
    )
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
    let lang = a.lang;
    let used: i64 = list.iter().map(|u| u.used_bytes).sum();
    let csrf = esc(&a.csrf);
    let body = format!(
        "<table><tbody><tr><td>{}</td><td class=\"num\">{}</td></tr>\
         <tr><td>{}</td><td class=\"num\">{}</td></tr><tr><td>{}</td><td class=\"num\">{}</td></tr></tbody></table>\
         <h2>{}</h2><p class=\"muted\">{}</p>\
         <form class=\"inline\" method=\"post\" action=\"/admin/status/check\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <label class=\"check\"><input type=\"checkbox\" name=\"checksums\" value=\"1\"> {}</label>\
         <label class=\"check\"><input type=\"checkbox\" name=\"repair\" value=\"1\"> {}</label>\
         <button type=\"submit\">{}</button></form>{report}",
        esc(&t(lang, "Version")),
        esc(env!("CARGO_PKG_VERSION")),
        esc(&t(lang, "Users")),
        list.len(),
        esc(&t(lang, "Storage used")),
        human(used),
        esc(&t(lang, "Consistency check")),
        esc(&t(
            lang,
            "Compares the database with the stored files. Safe to run while the server is in use."
        )),
        esc(&t(lang, "Also re-read every file (slow)")),
        esc(&t(lang, "Repair what can be repaired")),
        esc(&t(lang, "Run check")),
    );
    page(a, "Status", "status", &ui::card(lang, "Status", "", &body))
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
    let lang = a.lang;
    let line = |label: &str, n: usize| {
        format!(
            "<tr><td>{}</td><td class=\"num\">{n}</td></tr>",
            esc(&t(lang, label))
        )
    };
    let report = format!(
        "<h3>{}</h3><table><tbody>{}{}{}{}{}{}{}{}</tbody></table>",
        esc(&tf(
            lang,
            "Result: {0}",
            &[&t(
                lang,
                if r.is_clean() {
                    "no problems"
                } else {
                    "problems found"
                }
            )]
        )),
        line("Files checked", r.blobs_checked),
        line("Missing files (not repairable)", r.missing_blobs.len()),
        line("Corrupt files", r.corrupt_blobs.len()),
        line(
            "Database problems",
            r.database_problems.len() + r.orphan_rows.len()
        ),
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

/// Label, hint and input of an adjustable limit: `(label, hint, number input range)`.
fn tunable_spec(t: Tunable) -> (&'static str, &'static str, Option<(u32, u32)>) {
    match t {
        Tunable::DefaultQuota => (
            "Quota for new users",
            "A size such as 10G or 500M, or unlimited. Users that exist already keep their quota.",
            None,
        ),
        Tunable::UploadRetentionHours => (
            "Unfinished uploads are removed after",
            "Hours, 1 to 8760.",
            Some((1, 8760)),
        ),
        Tunable::MaxVersions => (
            "Versions kept per file",
            "0 keeps every version.",
            Some((0, 1000)),
        ),
        Tunable::VersionRetentionDays => (
            "Version retention",
            "Days, 0 keeps versions until another limit removes them.",
            Some((0, 3650)),
        ),
        Tunable::VersionQuotaShare => (
            "Versions share of quota",
            "Percent of a user's quota that versions may use, 0 for no limit.",
            Some((0, 100)),
        ),
        Tunable::TrashRetentionDays => (
            "Trash retention",
            "Days, 0 keeps deleted files until they are removed by hand.",
            Some((0, 3650)),
        ),
        Tunable::EventLogRetentionDays => (
            "Event log retention",
            "Days, 0 keeps the event log.",
            Some((0, 3650)),
        ),
    }
}

pub async fn server(State(state): State<AppState>, Admin(a): Admin) -> Response {
    server_page(&state, &a).await
}

async fn server_page(state: &AppState, a: &Authed) -> Response {
    let actor = Actor::User(&a.session.principal);
    let (rows, tunables) = match (state.settings_summary(&actor), state.tunables(&actor)) {
        (Ok(r), Ok(t)) => (r, t),
        (Err(e), _) | (_, Err(e)) => return error_page(a, &e, "/files"),
    };
    let lang = a.lang;
    let csrf = esc(&a.csrf);
    let items: String = tunables
        .iter()
        .map(|v| {
            let (label, hint, range) = tunable_spec(v.tunable);
            if v.locked {
                return format!(
                    "<div class=\"setting\"><label>{}<input type=\"text\" value=\"{}\" disabled></label>\
                     <p class=\"muted\"><span class=\"chip\">{}</span> {}</p></div>",
                    esc(&t(lang, label)),
                    esc(&v.value),
                    esc(&t(lang, "Set by configuration")),
                    esc(&t(
                        lang,
                        "The configuration file or an environment variable sets this; change it there."
                    )),
                );
            }
            let input = match range {
                Some((min, max)) => format!(
                    "<input type=\"number\" name=\"value\" min=\"{min}\" max=\"{max}\" step=\"1\" value=\"{}\" required>",
                    esc(&v.value)
                ),
                None => format!(
                    "<input type=\"text\" name=\"value\" value=\"{}\" required>",
                    esc(&v.value)
                ),
            };
            let note = if v.changed {
                format!(
                    "<span class=\"chip\">{}</span> <span class=\"muted\">{}</span>",
                    esc(&t(lang, "Changed")),
                    esc(&tf(lang, "In the file: {0}", &[&v.file_value]))
                )
            } else {
                String::new()
            };
            let reset = if v.changed {
                format!(
                    "<form class=\"inline\" method=\"post\" action=\"/admin/server/reset\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                     <input type=\"hidden\" name=\"key\" value=\"{}\"><button type=\"submit\">{}</button></form>",
                    esc(v.tunable.key()),
                    esc(&t(lang, "Back to default"))
                )
            } else {
                String::new()
            };
            format!(
                "<div class=\"setting\"><form class=\"inline\" method=\"post\" action=\"/admin/server/set\">\
                 <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"key\" value=\"{}\">\
                 <label>{}{input}</label><button class=\"primary\" type=\"submit\">{}</button></form>{reset}\
                 <p class=\"muted\">{}{}</p></div>",
                esc(v.tunable.key()),
                esc(&t(lang, label)),
                esc(&t(lang, "Save")),
                esc(&t(lang, hint)),
                if note.is_empty() { String::new() } else { format!(" {note}") },
            )
        })
        .collect();
    let adjustable = ui::card(
        lang,
        "Adjustable limits",
        "",
        &format!(
            "<p class=\"muted\">{}</p>{items}",
            esc(&t(
                lang,
                "These apply at once and are kept across restarts. \"Back to default\" returns to the value from the configuration file."
            ))
        ),
    );
    let rows: String = rows
        .iter()
        .map(|(k, v)| {
            format!(
                "<tr><td>{}</td><td class=\"num\">{}</td></tr>",
                esc(&t(lang, k)),
                esc(&t_quiet(lang, v))
            )
        })
        .collect();
    let body = format!(
        "<p class=\"muted\">{}</p><table><tbody>{rows}</tbody></table>",
        esc(&t(
            lang,
            "Everything else comes from the configuration file and environment variables. Change it there and restart the server."
        ))
    );
    page(
        a,
        "Server",
        "server",
        &format!(
            "{adjustable}{}",
            ui::card(lang, "Effective settings", "", &body)
        ),
    )
}

#[derive(Deserialize)]
pub struct TunableForm {
    csrf: String,
    key: String,
    #[serde(default)]
    value: String,
}

pub async fn set_tunable(
    State(state): State<AppState>,
    Admin(a): Admin,
    Form(f): Form<TunableForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    match state
        .set_tunable(&Actor::User(&a.session.principal), &f.key, &f.value)
        .await
    {
        Ok(()) => Redirect::to("/admin/server").into_response(),
        Err(e) => error_page(&a, &e, "/admin/server"),
    }
}

pub async fn reset_tunable(
    State(state): State<AppState>,
    Admin(a): Admin,
    Form(f): Form<TunableForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    match state
        .reset_tunable(&Actor::User(&a.session.principal), &f.key)
        .await
    {
        Ok(()) => Redirect::to("/admin/server").into_response(),
        Err(e) => error_page(&a, &e, "/admin/server"),
    }
}

pub async fn twofa_reset_confirm(Admin(a): Admin, Query(q): Query<NameQuery>) -> Response {
    let lang = a.lang;
    let body = format!(
        "<h2>{}</h2><p>{}</p>\
         <form method=\"post\" action=\"/admin/users/two-factor-reset\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
         <input type=\"hidden\" name=\"name\" value=\"{}\">\
         <div class=\"actions\"><button class=\"danger\" type=\"submit\">{}</button>\
         <a class=\"button\" href=\"/admin/users/manage?name={}\">{}</a></div></form>",
        esc(&tf(
            lang,
            "Reset two-factor authentication for “{0}”?",
            &[&q.name]
        )),
        esc(&t(
            lang,
            "The secret and the recovery codes are removed and the user's browser sessions end. The user can set it up again afterwards."
        )),
        esc(&a.csrf),
        esc(&q.name),
        esc(&t(lang, "Reset")),
        esc(&enc(&q.name)),
        esc(&t(lang, "Cancel")),
    );
    page(
        &a,
        "Reset two-factor authentication",
        "users",
        &ui::card(lang, "Reset two-factor authentication", "", &body),
    )
}

#[derive(Deserialize)]
pub struct TwofaResetForm {
    csrf: String,
    name: String,
}

pub async fn twofa_reset(
    State(state): State<AppState>,
    Admin(a): Admin,
    Form(f): Form<TwofaResetForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let back = format!("/admin/users/manage?name={}", enc(&f.name));
    match state
        .user_reset_two_factor(&Actor::User(&a.session.principal), &f.name)
        .await
    {
        Ok(_) => Redirect::to(&back).into_response(),
        Err(e) => error_page(&a, &e, &back),
    }
}

pub async fn security(State(state): State<AppState>, Admin(a): Admin) -> Response {
    security_page(&state, &a).await
}

async fn security_page(state: &AppState, a: &Authed) -> Response {
    let actor = Actor::User(&a.session.principal);
    let locks = match state.active_lockouts(&actor).await {
        Ok(l) => l,
        Err(e) => return error_page(a, &e, "/files"),
    };
    let lang = a.lang;
    let csrf = esc(&a.csrf);
    let on = state.maintenance();
    let maintenance = format!(
        "<p class=\"muted\">{}</p>\
         <p><strong>{}</strong></p>\
         <form method=\"post\" action=\"/admin/security/maintenance\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input type=\"hidden\" name=\"on\" value=\"{}\"><button type=\"submit\"{}>{}</button></form>",
        esc(&t(
            lang,
            "While maintenance mode is on, the Nextcloud apps and WebDAV clients get \u{201c}service unavailable\u{201d} and pause. This web interface and the sign-in pages keep working."
        )),
        esc(&t(
            lang,
            if on {
                "Maintenance mode is on."
            } else {
                "Maintenance mode is off."
            }
        )),
        if on { "0" } else { "1" },
        if on { "" } else { " class=\"danger\"" },
        esc(&t(lang, if on { "Turn off" } else { "Turn on" })),
    );
    let rows: String = locks
        .iter()
        .map(|l| {
            let (what, kind) = match (l.by_address, l.kind) {
                (true, _) => (t(lang, "Address"), "password"),
                (false, LockoutKind::Password) => (t(lang, "User"), "password"),
                (false, LockoutKind::SecondFactor) => (t(lang, "User (two-factor code)"), "2fa"),
            };
            format!(
                "<tr><td>{}</td><td>{}</td><td class=\"num\">{}</td><td>\
                 <form class=\"inline\" method=\"post\" action=\"/admin/security/unlock\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                 <input type=\"hidden\" name=\"key\" value=\"{}\"><input type=\"hidden\" name=\"kind\" value=\"{kind}\">\
                 <button type=\"submit\">{}</button></form></td></tr>",
                esc(&what),
                esc(&l.who),
                esc(&tf(lang, "{0} min", &[&l.secs_left.div_ceil(60).to_string()])),
                esc(&l.key),
                esc(&t(lang, "Unlock")),
            )
        })
        .collect();
    let locks_html = if locks.is_empty() {
        format!(
            "<p class=\"muted\">{}</p>",
            esc(&t(lang, "Nobody is locked out."))
        )
    } else {
        format!(
            "<table><thead><tr><th>{}</th><th>{}</th><th class=\"num\">{}</th><th></th></tr></thead><tbody>{rows}</tbody></table>",
            esc(&t(lang, "Kind")),
            esc(&t(lang, "Who")),
            esc(&t(lang, "Locked for")),
        )
    };
    let locks_card = format!(
        "<p class=\"muted\">{}</p>{locks_html}",
        esc(&t(
            lang,
            "After ten wrong passwords (five wrong two-factor codes) within 15 minutes, the address or user is blocked until the time is up. Unlock lifts a block at once. Blocks are kept in memory and end when the server restarts."
        )),
    );
    let body = format!(
        "{}{}",
        ui::card(lang, "Maintenance mode", "", &maintenance),
        ui::card(lang, "Active lockouts", "", &locks_card),
    );
    page(a, "Sign-in and maintenance", "security", &body)
}

#[derive(Deserialize)]
pub struct MaintenanceForm {
    csrf: String,
    on: String,
}

pub async fn set_maintenance(
    State(state): State<AppState>,
    Admin(a): Admin,
    Form(f): Form<MaintenanceForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    match state
        .set_maintenance(&Actor::User(&a.session.principal), f.on == "1")
        .await
    {
        Ok(()) => Redirect::to("/admin/security").into_response(),
        Err(e) => error_page(&a, &e, "/admin/security"),
    }
}

#[derive(Deserialize)]
pub struct UnlockForm {
    csrf: String,
    key: String,
    kind: String,
}

pub async fn unlock(
    State(state): State<AppState>,
    Admin(a): Admin,
    Form(f): Form<UnlockForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let kind = if f.kind == "2fa" {
        LockoutKind::SecondFactor
    } else {
        LockoutKind::Password
    };
    match state
        .unlock(&Actor::User(&a.session.principal), &f.key, kind)
        .await
    {
        Ok(()) => Redirect::to("/admin/security").into_response(),
        Err(e) => error_page(&a, &e, "/admin/security"),
    }
}
