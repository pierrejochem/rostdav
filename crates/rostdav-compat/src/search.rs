//! Unified search (`/ocs/v2.php/search/providers`), the `files` provider only.
//!
//! Reference: Nextcloud 35.0.2, recorded 2026-10-24 (`tests/fixtures/nextcloud/12-search/63`–`89`).
//! The provider searches **names**; the text of files is searched on the web page. Differences
//! from the reference are listed in `docs/compatibility.md`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::Response;
use rostdav_app::{AppState, SearchQuery};
use rostdav_core::{Error, LogicalPath};
use rostdav_meta::NodeKind;
use serde_json::{Value, json};

use crate::CompatConfig;
use crate::ocs::{FormatQuery, guard};

/// The reference accepts 200 and refuses 1000 (400); in between was not probed.
const MAX_LIMIT: usize = 200;
const DEFAULT_LIMIT: usize = 5;
/// Names looked at before the paging starts.
const MAX_HITS: usize = 10_000;

/// The `files` provider as the reference lists it (`63-providers`). The reference also takes
/// `person`, `min-size`, `max-size`, `mime`, `type`, `path`, `is-favorite` and `title-only`;
/// only the filters that work here are announced, so an app does not offer the others.
pub async fn providers(
    State(state): State<AppState>,
    Path(version): Path<String>,
    Query(q): Query<FormatQuery>,
    parts: Parts,
) -> Response {
    let (ocs, _p) = match guard(&state, &version, &q, &parts).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    ocs.ok(&json!([{
        "id": "files",
        "appId": "files",
        "name": "Files",
        "icon": "/apps/files/img/app.svg",
        "order": 5,
        "isExternalProvider": false,
        "triggers": ["files"],
        "filters": {"term": "string", "since": "datetime", "until": "datetime"},
        "inAppSearch": false,
    }]))
}

fn param<'a>(q: &'a [(String, String)], key: &str) -> Option<&'a str> {
    q.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

pub async fn run(
    State(state): State<AppState>,
    axum::Extension(cfg): axum::Extension<CompatConfig>,
    Path((version, id)): Path<(String, String)>,
    Query(fq): Query<FormatQuery>,
    parts: Parts,
) -> Response {
    let (ocs, p) = match guard(&state, &version, &fq, &parts).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if id != "files" {
        return ocs.fail(StatusCode::NOT_FOUND, 404, "Unknown search provider");
    }
    let q: Vec<(String, String)> = parts
        .uri
        .query()
        .and_then(|s| serde_urlencoded::from_str(s).ok())
        .unwrap_or_default();

    let term = param(&q, "term").unwrap_or("").trim().to_owned();
    let since = param(&q, "since").filter(|s| !s.is_empty());
    let until = param(&q, "until").filter(|s| !s.is_empty());
    let (since, until) = match (since.map(date), until.map(date)) {
        (Some(None), _) | (_, Some(None)) => {
            return ocs.fail_data(StatusCode::BAD_REQUEST, 400, "", "Invalid date");
        }
        (a, b) => (a.flatten(), b.flatten()),
    };
    // a term or a date is a filter; without one the reference refuses (`74`, `75`)
    if term.is_empty() && since.is_none() && until.is_none() {
        return ocs.fail_data(
            StatusCode::BAD_REQUEST,
            400,
            "",
            "No valid filters provided",
        );
    }
    let limit = match param(&q, "limit") {
        None => DEFAULT_LIMIT,
        Some(l) => match l.parse::<usize>() {
            Ok(n) if (1..=MAX_LIMIT).contains(&n) => n,
            _ => return bare(StatusCode::BAD_REQUEST),
        },
    };
    let cursor = match param(&q, "cursor") {
        None | Some("") => 0,
        // the reference answers 500 for a cursor that is not a number
        Some(c) => match c.parse::<usize>() {
            Ok(n) => n,
            Err(_) => return bare(StatusCode::BAD_REQUEST),
        },
    };

    // a date filter alone has no name to look for: every name the caller can reach is a candidate
    let hits = if term.is_empty() {
        all_names(&state, &p).await
    } else {
        let mut query = SearchQuery::new(term);
        query.limit = MAX_HITS;
        state.search_names(&p, &query).await.map(|pg| pg.hits)
    };
    let hits = match hits {
        Ok(h) => h,
        Err(Error::Forbidden) => return ocs.fail(StatusCode::FORBIDDEN, 403, "Forbidden"),
        Err(e) => return ocs.fail(StatusCode::INTERNAL_SERVER_ERROR, 996, &e.to_string()),
    };

    let base = crate::login::base_url(&cfg, &parts.headers).unwrap_or_default();
    let entries: Vec<Value> = hits
        .iter()
        .filter(|h| {
            since.is_none_or(|s| h.node.mtime >= s) && until.is_none_or(|u| h.node.mtime <= u)
        })
        .skip(cursor)
        .take(limit)
        .map(|h| entry(&base, h))
        .collect();
    ocs.ok(&json!({
        "name": "Files",
        "isPaginated": true,
        "entries": entries,
        // the reference counts the rows it asked for, not the ones it kept (`67`, `76`, `81`)
        "cursor": cursor + limit,
    }))
}

fn bare(status: StatusCode) -> Response {
    let mut r = Response::new(axum::body::Body::empty());
    *r.status_mut() = status;
    r
}

fn date(s: &str) -> Option<i64> {
    rostdav_core::time::parse_iso_or_unix(s)
}

/// Every name the caller can reach (for a search by date alone).
async fn all_names(
    state: &AppState,
    p: &rostdav_app::Principal,
) -> Result<Vec<rostdav_app::SearchHit>, Error> {
    let (nodes, _cut) = state
        .walk_below(p, &LogicalPath::root(), MAX_HITS * 20)
        .await?;
    Ok(nodes
        .into_iter()
        .map(|(path, access)| rostdav_app::SearchHit {
            path,
            node: access.node,
            origin: access.origin,
            rank: 2,
            snippet: Vec::new(),
        })
        .collect())
}

fn entry(base: &str, h: &rostdav_app::SearchHit) -> Value {
    let segs = h.path.segments();
    let names: Vec<&str> = segs.iter().map(|s| s.as_str()).collect();
    let parent = names[..names.len().saturating_sub(1)].join("/");
    let is_dir = h.node.kind == NodeKind::Dir;
    json!({
        // no previews are made
        "thumbnailUrl": "",
        "title": names.last().copied().unwrap_or(""),
        "subline": if parent.is_empty() { String::new() } else { format!("in {parent}") },
        "resourceUrl": format!("{base}/f/{}", h.node.id),
        // UNVERIFIED which icon names the apps know; `icon-folder` is the reference's own
        "icon": if is_dir { "icon-folder" } else { "icon-file" },
        "rounded": false,
        "attributes": {
            "fileId": h.node.id.to_string(),
            "path": format!("/{}", names.join("/")),
        },
    })
}
