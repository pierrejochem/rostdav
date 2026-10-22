//! Sharing dialog and versions panel (ADR 0006, slice 11b). Server-rendered pages.

use axum::Form;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use rostdav_app::{AppState, ShareCreate, ShareFilter, ShareView};
use rostdav_core::Error;
use rostdav_meta::{NodeKind, ShareKind};
use serde::Deserialize;

use crate::layout::{self, enc, esc};
use crate::pages::{date, error_response_to, human, parse_plain, plain};
use crate::session::Authed;

fn forbidden() -> Response {
    StatusCode::FORBIDDEN.into_response()
}

fn csrf_ok(state: &AppState, a: &Authed, given: &str) -> bool {
    state.web_check_csrf(a.session.id, given).is_ok()
}

fn share_error(a: &Authed, e: &rostdav_app::ShareError, back: &str) -> Response {
    let status = StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_REQUEST);
    let text = if e.status >= 500 {
        "Something went wrong."
    } else {
        e.message.as_str()
    };
    crate::pages::message_in(
        a,
        status,
        "Could not complete the action",
        text,
        back,
        "files",
    )
}

fn perm_label(kind: NodeKind, link: bool, perms: u8) -> &'static str {
    match (perms, kind, link) {
        (4, _, _) => "Upload only",
        (1, _, _) => "View only",
        _ => "Can edit",
    }
}

fn origin_of(headers: &axum::http::HeaderMap) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("https"));
    format!("{}://{host}", if https { "https" } else { "http" })
}

#[derive(Deserialize)]
pub struct PathQuery {
    path: String,
}

fn back(path: &str) -> String {
    format!("/share?path={}", enc(path))
}

pub async fn share_page(
    State(state): State<AppState>,
    a: Authed,
    headers: axum::http::HeaderMap,
    Query(q): Query<PathQuery>,
) -> Response {
    let p = &a.session.principal;
    let path = match parse_plain(&q.path) {
        Ok(p) if !p.is_root() => p,
        Ok(_) => return error_response_to(&a, &Error::BadRequest("root"), "/files", "files"),
        Err(e) => return error_response_to(&a, &e, "/files", "files"),
    };
    let node = match state.stat(p, &path).await {
        Ok(n) => n,
        Err(e) => return error_response_to(&a, &e, "/files", "files"),
    };
    let shares: Vec<ShareView> = match state
        .shares_list(
            p,
            ShareFilter {
                path: Some(path.clone()),
                ..Default::default()
            },
        )
        .await
    {
        Ok(s) => s,
        Err(e) => return share_error(&a, &e, "/files"),
    };
    let origin = origin_of(&headers);
    let csrf = esc(&a.csrf);
    let plain_path = esc(&plain(&path));
    let is_dir = node.kind == NodeKind::Dir;

    let mut rows = String::new();
    for s in &shares {
        let link = s.share.kind == ShareKind::Link;
        let who = if link {
            let url = format!("{origin}/s/{}", s.share.token.as_deref().unwrap_or(""));
            format!(
                "Link{}<br><code>{}</code>",
                if s.share.password_hash.is_some() {
                    " (password)"
                } else {
                    ""
                },
                esc(&url)
            )
        } else {
            esc(s.recipient.as_deref().unwrap_or("?"))
        };
        rows.push_str(&format!(
            "<tr><td>{who}</td><td>{}</td><td class=\"hide\">{}</td><td class=\"num\">\
             <form class=\"inline\" method=\"post\" action=\"/share/delete\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <input type=\"hidden\" name=\"path\" value=\"{plain_path}\"><input type=\"hidden\" name=\"id\" value=\"{}\">\
             <button class=\"danger\" type=\"submit\">Stop sharing</button></form></td></tr>",
            perm_label(node.kind, link, s.share.permissions),
            s.share.expires_at.map_or_else(|| "never".to_owned(), date),
            s.share.id
        ));
    }
    let list = if shares.is_empty() {
        "<div class=\"empty\">Not shared yet.</div>".to_owned()
    } else {
        format!(
            "<table><thead><tr><th>Shared with</th><th>Access</th><th class=\"hide\">Expires</th><th></th></tr></thead><tbody>{rows}</tbody></table>"
        )
    };
    let edit = if is_dir { 15 } else { 3 };
    let upload_opt = if is_dir {
        "<option value=\"4\">Upload only</option>"
    } else {
        ""
    };
    let body = format!(
        "<h1>Share “{}”</h1><div class=\"crumbs\"><a href=\"/files\">Back to files</a></div>{list}\
         <h2>Share with a user</h2>\
         <form class=\"inline\" method=\"post\" action=\"/share/user\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input type=\"hidden\" name=\"path\" value=\"{plain_path}\">\
         <label>User name<input type=\"text\" name=\"user\" required></label>\
         <label>Access<select name=\"perms\"><option value=\"1\">View only</option><option value=\"{edit}\">Can edit</option></select></label>\
         <button class=\"primary\" type=\"submit\">Share</button></form>\
         <h2>Create a public link</h2>\
         <form class=\"inline\" method=\"post\" action=\"/share/link\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input type=\"hidden\" name=\"path\" value=\"{plain_path}\">\
         <label>Access<select name=\"perms\"><option value=\"1\">View only</option><option value=\"{edit}\">Can edit</option>{upload_opt}</select></label>\
         <label>Password (optional)<input type=\"password\" name=\"password\" autocomplete=\"new-password\"></label>\
         <label>Expires (YYYY-MM-DD, optional)<input type=\"text\" name=\"expire\" placeholder=\"2027-01-31\"></label>\
         <button class=\"primary\" type=\"submit\">Create link</button></form>",
        esc(node.name.as_str()),
    );
    layout::app(
        StatusCode::OK,
        "Share",
        &a.chrome(),
        "files",
        &a.csrf,
        &body,
    )
}

#[derive(Deserialize)]
pub struct UserShareForm {
    csrf: String,
    path: String,
    user: String,
    perms: i64,
}

pub async fn share_user(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<UserShareForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let b = back(&f.path);
    let Ok(path) = parse_plain(&f.path) else {
        return forbidden();
    };
    let req = ShareCreate {
        path: Some(path),
        share_type: 0,
        share_with: Some(f.user.trim().to_owned()),
        permissions: Some(f.perms),
        ..Default::default()
    };
    match state.share_create(&a.session.principal, req).await {
        Ok(_) => Redirect::to(&b).into_response(),
        Err(e) => share_error(&a, &e, &b),
    }
}

#[derive(Deserialize)]
pub struct LinkShareForm {
    csrf: String,
    path: String,
    perms: i64,
    #[serde(default)]
    password: String,
    #[serde(default)]
    expire: String,
}

pub async fn share_link(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<LinkShareForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let b = back(&f.path);
    let Ok(path) = parse_plain(&f.path) else {
        return forbidden();
    };
    let req = ShareCreate {
        path: Some(path),
        share_type: 3,
        permissions: Some(f.perms),
        password: Some(f.password).filter(|p| !p.is_empty()),
        expire: Some(f.expire.trim().to_owned()).filter(|e| !e.is_empty()),
        ..Default::default()
    };
    match state.share_create(&a.session.principal, req).await {
        Ok(_) => Redirect::to(&b).into_response(),
        Err(e) => share_error(&a, &e, &b),
    }
}

#[derive(Deserialize)]
pub struct ShareDeleteForm {
    csrf: String,
    path: String,
    id: i64,
}

pub async fn share_delete(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<ShareDeleteForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let b = back(&f.path);
    match state.share_delete(&a.session.principal, f.id).await {
        Ok(()) => Redirect::to(&b).into_response(),
        Err(e) => share_error(&a, &e, &b),
    }
}

// ---- versions -------------------------------------------------------------------------------

pub async fn versions_page(
    State(state): State<AppState>,
    a: Authed,
    Query(q): Query<PathQuery>,
) -> Response {
    let p = &a.session.principal;
    let path = match parse_plain(&q.path) {
        Ok(p) if !p.is_root() => p,
        Ok(_) => return error_response_to(&a, &Error::BadRequest("root"), "/files", "files"),
        Err(e) => return error_response_to(&a, &e, "/files", "files"),
    };
    let node = match state.stat(p, &path).await {
        Ok(n) if n.kind == NodeKind::File => n,
        Ok(_) => return error_response_to(&a, &Error::BadRequest("not a file"), "/files", "files"),
        Err(e) => return error_response_to(&a, &e, "/files", "files"),
    };
    let listing = match state.version_list(p, node.id).await {
        Ok(l) => l,
        Err(e) => return error_response_to(&a, &e, "/files", "files"),
    };
    let csrf = esc(&a.csrf);
    let plain_path = esc(&plain(&path));
    let mut rows = String::new();
    for e in listing.entries.iter().rev() {
        let actions = if e.live {
            "<span class=\"muted\">Current</span>".to_owned()
        } else {
            format!(
                "<form class=\"inline\" method=\"post\" action=\"/versions/restore\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                 <input type=\"hidden\" name=\"path\" value=\"{plain_path}\"><input type=\"hidden\" name=\"time\" value=\"{t}\">\
                 <button type=\"submit\">Restore</button></form>\
                 <form class=\"inline\" method=\"post\" action=\"/versions/delete\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                 <input type=\"hidden\" name=\"path\" value=\"{plain_path}\"><input type=\"hidden\" name=\"time\" value=\"{t}\">\
                 <button class=\"danger\" type=\"submit\">Delete</button></form>",
                t = e.version_time
            )
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td class=\"num\">{}</td><td class=\"hide\">{}</td><td class=\"num\">{actions}</td></tr>",
            date(e.mtime),
            human(e.size),
            esc(e.author.as_deref().unwrap_or(""))
        ));
    }
    let body = if state.versioning_enabled() || listing.entries.len() > 1 {
        format!(
            "<h1>Versions of “{}”</h1><div class=\"crumbs\"><a href=\"/files\">Back to files</a></div>\
             <p class=\"muted\">Older versions count toward your storage.</p>\
             <table><thead><tr><th>Saved</th><th class=\"num\">Size</th><th class=\"hide\">By</th><th></th></tr></thead><tbody>{rows}</tbody></table>",
            esc(node.name.as_str())
        )
    } else {
        "<h1>Versions</h1><div class=\"empty\">Versioning is turned off on this server.</div>"
            .to_owned()
    };
    layout::app(
        StatusCode::OK,
        "Versions",
        &a.chrome(),
        "files",
        &a.csrf,
        &body,
    )
}

#[derive(Deserialize)]
pub struct VersionForm {
    csrf: String,
    path: String,
    time: i64,
}

async fn version_action(state: AppState, a: Authed, f: VersionForm, restore: bool) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let b = format!("/versions?path={}", enc(&f.path));
    let p = &a.session.principal;
    let res = async {
        let path = parse_plain(&f.path)?;
        let node = state.stat(p, &path).await?;
        if restore {
            state.version_restore(p, node.id, f.time).await.map(|_| ())
        } else {
            state.version_delete(p, node.id, f.time).await
        }
    }
    .await;
    match res {
        Ok(()) => Redirect::to(&b).into_response(),
        Err(e) => error_response_to(&a, &e, &b, "files"),
    }
}

pub async fn version_restore(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<VersionForm>,
) -> Response {
    version_action(state, a, f, true).await
}

pub async fn version_delete(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<VersionForm>,
) -> Response {
    version_action(state, a, f, false).await
}
