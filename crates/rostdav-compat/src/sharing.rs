//! OCS Sharing API (`apps/files_sharing/api/v1`): shares, sharees.
//!
//! Shape and messages from `tests/fixtures/nextcloud/10-shares/`.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::Response;
use rostdav_app::{
    AppState, Principal, ShareChange, ShareCreate, ShareError, ShareFilter, ShareView, Viewer,
};
use rostdav_core::time::sql_datetime;
use rostdav_core::{LogicalPath, Name};
use rostdav_meta::{NodeKind, ShareKind};
use serde_json::{Value, json};
use std::collections::HashMap;

use crate::CompatConfig;
use crate::ocs::{FormatQuery, Ocs, guard};

type Params = HashMap<String, String>;

/// Query string plus form body; the body wins.
fn params(parts: &Parts, body: &Bytes) -> Params {
    let mut p: Params = parts
        .uri
        .query()
        .map(|q| serde_urlencoded::from_str(q).unwrap_or_default())
        .unwrap_or_default();
    if !body.is_empty() {
        if let Ok(b) = serde_urlencoded::from_bytes::<Params>(body) {
            p.extend(b);
        }
    }
    p
}

fn truthy(p: &Params, key: &str) -> Option<bool> {
    p.get(key)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

fn path_param(p: &Params) -> Result<Option<LogicalPath>, ShareError> {
    let Some(raw) = p.get("path").filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    // OCS paths are plain (not percent-encoded) and relative to the caller's root
    let mut path = LogicalPath::root();
    for seg in raw.split('/').filter(|s| !s.is_empty()) {
        let name = Name::parse(seg).map_err(|_| ShareError {
            status: 404,
            message: "Wrong path, file/folder does not exist".into(),
        })?;
        path = path.join(&name);
    }
    Ok(Some(path))
}

fn fail(ocs: &Ocs, e: &ShareError) -> Response {
    let status = StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    ocs.fail(status, e.status, &e.message)
}

/// The share as the OCS API describes it.
pub fn share_json(v: &ShareView, cfg: &CompatConfig, base: &str) -> Value {
    let s = &v.share;
    let is_dir = v.node.kind == NodeKind::Dir;
    let recipient_view = v.viewer == Viewer::Recipient;
    let mount = s.mount_name.clone().unwrap_or_else(|| v.node.name.clone());
    let target = if recipient_view {
        format!("/{mount}")
    } else {
        v.path.clone()
    };
    let item_permissions = if recipient_view {
        i64::from(s.permissions)
    } else if is_dir {
        31
    } else {
        27
    };
    let mime = if is_dir {
        "httpd/unix-directory".to_owned()
    } else {
        mime_guess::from_path(&v.node.name)
            .first_or_octet_stream()
            .essence_str()
            .to_owned()
    };
    let _ = cfg;
    let mut j = json!({
        "id": s.id.to_string(),
        "share_type": s.kind.code(),
        "uid_owner": v.owner,
        "displayname_owner": v.owner,
        "permissions": s.permissions,
        "can_edit": !recipient_view,
        "can_delete": true,
        "stime": s.created_at,
        "parent": null,
        "expiration": s.expires_at.map(sql_datetime),
        "token": s.token,
        "uid_file_owner": v.owner,
        "note": s.note,
        "label": s.label,
        "displayname_file_owner": v.owner,
        "path": target,
        "item_type": if is_dir { "folder" } else { "file" },
        "item_permissions": item_permissions,
        "is-mount-root": recipient_view,
        "mount-type": if recipient_view { "shared" } else { "" },
        "mimetype": mime,
        "has_preview": false,
        "item_source": v.node.id,
        "file_source": v.node.id,
        "file_parent": v.node.parent_id,
        "file_target": target,
        "item_size": v.node.size,
        "item_mtime": v.node.mtime,
        "mail_send": 0,
        "hide_download": i32::from(s.hide_download),
        "attributes": null,
    });
    match s.kind {
        ShareKind::User => {
            j["share_with"] = json!(v.recipient);
            j["share_with_displayname"] = json!(v.recipient);
            j["share_with_displayname_unique"] = json!(v.recipient);
        }
        ShareKind::Link => {
            j["share_with"] = Value::Null;
            j["share_with_displayname"] = json!("(Shared link)");
            // never the hash: clients only need to know that a password is set
            j["password"] = if s.password_hash.is_some() {
                json!("protected")
            } else {
                Value::Null
            };
            j["send_password_by_talk"] = json!(false);
            j["url"] = json!(format!(
                "{base}/s/{}",
                s.token.as_deref().unwrap_or_default()
            ));
        }
    }
    j
}

fn base(cfg: &CompatConfig, parts: &Parts) -> String {
    crate::login::base_url(cfg, &parts.headers).unwrap_or_default()
}

async fn views(
    ocs: &Ocs,
    list: Result<Vec<ShareView>, ShareError>,
    cfg: &CompatConfig,
    parts: &Parts,
) -> Response {
    match list {
        Ok(v) => {
            let b = base(cfg, parts);
            ocs.ok(&Value::Array(
                v.iter().map(|v| share_json(v, cfg, &b)).collect(),
            ))
        }
        Err(e) => fail(ocs, &e),
    }
}

fn parse_id(id: &str) -> Option<i64> {
    id.parse::<i64>().ok().filter(|n| *n > 0)
}

async fn authed(
    state: &AppState,
    version: &str,
    q: &FormatQuery,
    parts: &Parts,
) -> Result<(Ocs, Principal), Box<Response>> {
    guard(state, version, q, parts).await
}

pub async fn list(
    State(state): State<AppState>,
    axum::Extension(cfg): axum::Extension<CompatConfig>,
    Path(version): Path<String>,
    Query(q): Query<FormatQuery>,
    parts: Parts,
) -> Response {
    let (ocs, p) = match authed(&state, &version, &q, &parts).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let pr = params(&parts, &Bytes::new());
    let filter = match path_param(&pr) {
        Ok(path) => ShareFilter {
            path,
            subfiles: truthy(&pr, "subfiles").unwrap_or(false),
            shared_with_me: truthy(&pr, "shared_with_me").unwrap_or(false),
        },
        Err(e) => return fail(&ocs, &e),
    };
    views(&ocs, state.shares_list(&p, filter).await, &cfg, &parts).await
}

pub async fn pending(
    State(state): State<AppState>,
    Path(version): Path<String>,
    Query(q): Query<FormatQuery>,
    parts: Parts,
) -> Response {
    match authed(&state, &version, &q, &parts).await {
        Ok((ocs, _)) => ocs.ok(&json!([])),
        Err(r) => *r,
    }
}

pub async fn get(
    State(state): State<AppState>,
    axum::Extension(cfg): axum::Extension<CompatConfig>,
    Path((version, id)): Path<(String, String)>,
    Query(q): Query<FormatQuery>,
    parts: Parts,
) -> Response {
    let (ocs, p) = match authed(&state, &version, &q, &parts).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(id) = parse_id(&id) else {
        return fail(
            &ocs,
            &ShareError {
                status: 404,
                message: "Wrong share ID, share does not exist".into(),
            },
        );
    };
    // one share, but the API answers with a list (reference: `data` is an array)
    views(
        &ocs,
        state.share_get(&p, id).await.map(|v| vec![v]),
        &cfg,
        &parts,
    )
    .await
}

pub async fn create(
    State(state): State<AppState>,
    axum::Extension(cfg): axum::Extension<CompatConfig>,
    Path(version): Path<String>,
    Query(q): Query<FormatQuery>,
    parts: Parts,
    body: Bytes,
) -> Response {
    let (ocs, p) = match authed(&state, &version, &q, &parts).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let pr = params(&parts, &body);
    let path = match path_param(&pr) {
        Ok(p) => p,
        Err(e) => return fail(&ocs, &e),
    };
    let share_type = pr
        .get("shareType")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(-1);
    let mut permissions = pr.get("permissions").and_then(|v| v.parse::<i64>().ok());
    if truthy(&pr, "publicUpload") == Some(true) && permissions.is_none() {
        permissions = Some(15);
    }
    let req = ShareCreate {
        path,
        share_type,
        share_with: pr.get("shareWith").cloned(),
        permissions,
        password: pr.get("password").cloned(),
        expire: pr.get("expireDate").cloned(),
        note: pr.get("note").cloned().unwrap_or_default(),
        label: pr.get("label").cloned().unwrap_or_default(),
        hide_download: truthy(&pr, "hideDownload").unwrap_or(false),
    };
    match state.share_create(&p, req).await {
        Ok(v) => {
            let b = base(&cfg, &parts);
            ocs.ok(&share_json(&v, &cfg, &b))
        }
        Err(e) => fail(&ocs, &e),
    }
}

pub async fn update(
    State(state): State<AppState>,
    axum::Extension(cfg): axum::Extension<CompatConfig>,
    Path((version, id)): Path<(String, String)>,
    Query(q): Query<FormatQuery>,
    parts: Parts,
    body: Bytes,
) -> Response {
    let (ocs, p) = match authed(&state, &version, &q, &parts).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(id) = parse_id(&id) else {
        return fail(
            &ocs,
            &ShareError {
                status: 404,
                message: "Wrong share ID, share does not exist".into(),
            },
        );
    };
    let pr = params(&parts, &body);
    let mut change = ShareChange {
        permissions: pr.get("permissions").and_then(|v| v.parse::<i64>().ok()),
        password: pr.get("password").cloned(),
        expire: pr.get("expireDate").cloned(),
        note: pr.get("note").cloned(),
        label: pr.get("label").cloned(),
        hide_download: truthy(&pr, "hideDownload"),
    };
    if change.permissions.is_none() && truthy(&pr, "publicUpload") == Some(true) {
        change.permissions = Some(15);
    }
    match state.share_update(&p, id, change).await {
        Ok(v) => {
            let b = base(&cfg, &parts);
            ocs.ok(&share_json(&v, &cfg, &b))
        }
        Err(e) => fail(&ocs, &e),
    }
}

pub async fn delete(
    State(state): State<AppState>,
    Path((version, id)): Path<(String, String)>,
    Query(q): Query<FormatQuery>,
    parts: Parts,
) -> Response {
    let (ocs, p) = match authed(&state, &version, &q, &parts).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(id) = parse_id(&id) else {
        return fail(
            &ocs,
            &ShareError {
                status: 404,
                message: "Wrong share ID, share does not exist".into(),
            },
        );
    };
    match state.share_delete(&p, id).await {
        Ok(()) => ocs.ok(&json!([])),
        Err(e) => fail(&ocs, &e),
    }
}

pub async fn sharees(
    State(state): State<AppState>,
    Path(version): Path<String>,
    Query(q): Query<FormatQuery>,
    parts: Parts,
) -> Response {
    let (ocs, p) = match authed(&state, &version, &q, &parts).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let pr = params(&parts, &Bytes::new());
    let search = pr.get("search").cloned().unwrap_or_default();
    let per_page = pr
        .get("perPage")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(200);
    let names = match state.sharees(&p, &search, per_page).await {
        Ok(n) => n,
        Err(e) => return fail(&ocs, &e),
    };
    let entry = |n: &str| {
        json!({
            "label": n, "subline": "", "icon": "icon-user",
            "value": {"shareType": 0, "shareWith": n},
            "shareWithDisplayNameUnique": n, "status": [],
        })
    };
    let (exact, rest): (Vec<_>, Vec<_>) = names
        .iter()
        .partition(|n| n.eq_ignore_ascii_case(search.trim()));
    ocs.ok(&json!({
        "exact": {
            "users": exact.iter().map(|n| entry(n)).collect::<Vec<_>>(),
            "groups": [], "remotes": [], "remote_groups": [], "emails": [], "circles": [], "rooms": [],
        },
        "users": rest.iter().map(|n| entry(n)).collect::<Vec<_>>(),
        "groups": [], "remotes": [], "remote_groups": [], "emails": [], "lookup": [],
        "circles": [], "rooms": [], "lookupEnabled": false,
    }))
}
