//! The Files page (design "Files"): file list with tiles, details panel for the
//! selected item or the open folder, upload progress card, storage meter in the
//! sidebar (layout). Everything works without scripts; `upload.js` only adds
//! chunked upload with progress.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use rostdav_app::{AppState, Origin, ShareFilter};
use rostdav_core::time::rfc3339;
use rostdav_core::{LogicalPath, Name};
use rostdav_meta::{Node, NodeKind, ShareKind};
use serde::Deserialize;

use crate::layout::{self, Opts, enc, esc};
use crate::pages::{error_response_to, human, plain, url_of};
use crate::session::Authed;

#[derive(Deserialize, Default)]
pub struct FilesQuery {
    /// Name filter for the current folder.
    #[serde(default)]
    q: String,
    /// Name of the selected file in the current folder.
    #[serde(default)]
    sel: String,
}

pub async fn files_root(
    state: State<AppState>,
    a: Authed,
    Query(q): Query<FilesQuery>,
) -> Response {
    browse(state, a, String::new(), q).await
}

pub async fn files_path(
    state: State<AppState>,
    a: Authed,
    Path(path): Path<String>,
    Query(q): Query<FilesQuery>,
) -> Response {
    browse(state, a, path, q).await
}

struct Row {
    node: Node,
    name: String,
    /// Not a received share: can be shared on.
    own: bool,
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// "Today, 09:41", "Yesterday", "Oct 12" (UTC).
fn friendly(secs: i64) -> String {
    let now = rostdav_app::now_secs();
    let (d, n, y) = (rfc3339(secs), rfc3339(now), rfc3339(now - 86_400));
    if d[..10] == n[..10] {
        format!("Today, {}", &d[11..16])
    } else if d[..10] == y[..10] {
        "Yesterday".to_owned()
    } else {
        let m: usize = d[5..7].parse().unwrap_or(1);
        let day: u32 = d[8..10].parse().unwrap_or(1);
        let year = if d[..4] == n[..4] {
            String::new()
        } else {
            format!(" {}", &d[..4])
        };
        format!("{} {day}{year}", MONTHS[(m.clamp(1, 12)) - 1])
    }
}

fn tile_class(node: &Node) -> &'static str {
    if node.kind == NodeKind::Dir {
        return "tile folder";
    }
    let ext = node
        .name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "bmp" | "heic" | "avif" => "tile image",
        _ => "tile doc",
    }
}

fn tile(node: &Node) -> String {
    let icon = match tile_class(node) {
        "tile folder" => {
            "<path d=\"M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z\"/>"
        }
        "tile image" => "<path d=\"M4 5h16v14H4Z\"/><path d=\"M4 16l5-5 4 4 2-2 5 5\"/>",
        _ => {
            "<path d=\"M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z\"/><path d=\"M14 3v5h5\"/>"
        }
    };
    format!(
        "<span class=\"{}\"><svg class=\"i\" viewBox=\"0 0 24 24\" aria-hidden=\"true\">{icon}</svg></span>",
        tile_class(node)
    )
}

fn row_link(path: &LogicalPath, r: &Row, filter: &str) -> String {
    let Ok(n) = Name::parse(&r.name) else {
        return "#".into();
    };
    let child = path.join(&n);
    match r.node.kind {
        NodeKind::Dir => url_of("/files", &child),
        NodeKind::File => {
            let mut u = url_of("/files", path);
            u.push_str(&format!("?sel={}", enc(&r.name)));
            if !filter.is_empty() {
                u.push_str(&format!("&q={}", enc(filter)));
            }
            u
        }
    }
}

async fn browse(State(state): State<AppState>, a: Authed, raw: String, q: FilesQuery) -> Response {
    let p = &a.session.principal;
    let path = match LogicalPath::from_url_path(&raw) {
        Ok(path) => path,
        Err(e) => return error_response_to(&a, &e, "/files", "files"),
    };
    let list = match state.list(p, &path).await {
        Ok(l) => l,
        Err(e) => return error_response_to(&a, &e, "/files", "files"),
    };
    let in_own = list.access.origin == Origin::Own;
    let mut rows: Vec<Row> = list
        .children
        .iter()
        .map(|n| Row {
            node: n.clone(),
            name: n.name.clone(),
            own: in_own,
        })
        .collect();
    rows.extend(list.mounts.iter().map(|m| Row {
        node: m.node.clone(),
        name: m.name.clone(),
        own: false,
    }));
    let needle = q.q.trim().to_lowercase();
    if !needle.is_empty() {
        rows.retain(|r| r.name.to_lowercase().contains(&needle));
    }
    rows.sort_by(|x, y| {
        (x.node.kind == NodeKind::File, x.name.to_lowercase())
            .cmp(&(y.node.kind == NodeKind::File, y.name.to_lowercase()))
    });
    let ids: Vec<i64> = rows.iter().map(|r| r.node.id).collect();
    let shared = state.share_kinds_of(p, &ids).await.unwrap_or_default();

    // ---- breadcrumbs and title
    let mut crumbs = String::from("<a href=\"/files\">Files</a>");
    let mut acc = LogicalPath::root();
    let mut title = "All files".to_owned();
    for seg in path.segments() {
        acc = acc.join(seg);
        crumbs.push_str(&format!(
            " <span aria-hidden=\"true\">/</span> <a href=\"{}\">{}</a>",
            esc(&url_of("/files", &acc)),
            esc(seg.as_str())
        ));
        title = seg.as_str().to_owned();
    }

    // ---- rows
    let mut body_rows = String::new();
    for r in &rows {
        let selected = r.node.kind == NodeKind::File && r.name == q.sel;
        let cur = if selected {
            " aria-current=\"true\""
        } else {
            ""
        };
        let size = match r.node.kind {
            NodeKind::Dir => String::new(),
            NodeKind::File => human(r.node.size),
        };
        let chip = if shared.contains_key(&r.node.id) {
            "<span class=\"chip ok\">Shared</span>"
        } else {
            ""
        };
        body_rows.push_str(&format!(
            "<tr{cur}><td><a class=\"name\" href=\"{}\">{}<span>{}</span></a></td><td>{}</td><td>{}</td><td>{chip}</td></tr>",
            esc(&row_link(&path, r, &q.q)),
            tile(&r.node),
            esc(&r.name),
            size,
            esc(&friendly(r.node.mtime)),
        ));
    }
    let count = rows.len();
    let listing = if rows.is_empty() {
        let msg = if needle.is_empty() {
            "This folder is empty."
        } else {
            "Nothing matches the filter."
        };
        format!("<div class=\"empty\">{msg}</div>")
    } else {
        format!(
            "<table><thead><tr><th>Name</th><th>Size</th><th>Modified</th><th>Sharing</th></tr></thead><tbody>{body_rows}</tbody></table>"
        )
    };

    // ---- details: the selected file, else the open folder
    let selected_row = rows
        .iter()
        .find(|r| r.node.kind == NodeKind::File && r.name == q.sel);
    let details = match selected_row {
        Some(r) => {
            let Ok(n) = Name::parse(&r.name) else { return error_response_to(&a, &rostdav_core::Error::BadRequest("name"), "/files", "files") };
            details_panel(&state, &a, &path.join(&n), &r.node, r.own, true).await
        }
        None if !path.is_root() => {
            let own = in_own;
            details_panel(&state, &a, &path, &list.node, own, false).await
        }
        None => "<aside class=\"glass2 details\" aria-label=\"Details\"><p class=\"muted\">Select a file to see its versions, sharing and details.</p></aside>".to_owned(),
    };

    // ---- toolbar: search, new folder, upload
    let dir = esc(&plain(&path));
    let csrf = esc(&a.csrf);
    let toolbar = format!(
        "<form class=\"search\" method=\"get\" action=\"{}\" role=\"search\"><svg class=\"i\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M11 18a7 7 0 1 0 0-14a7 7 0 0 0 0 14Z\"/><path d=\"M20 20l-4-4\"/></svg>\
         <input type=\"search\" name=\"q\" value=\"{}\" placeholder=\"Search in this folder\" aria-label=\"Search in this folder\"></form>\
         <details class=\"pop\"><summary class=\"button\"><svg class=\"i\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z\"/><path d=\"M12 10v6\"/><path d=\"M9 13h6\"/></svg>New folder</summary>\
         <form class=\"popover\" method=\"post\" action=\"/action/mkdir\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"dir\" value=\"{dir}\">\
         <label>Folder name<input type=\"text\" name=\"name\" required></label><button class=\"primary\" type=\"submit\">Create folder</button></form></details>\
         <details class=\"pop\"><summary class=\"button primary\"><svg class=\"i\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M12 16V4\"/><path d=\"M7 9l5-5 5 5\"/><path d=\"M5 20h14\"/></svg>Upload</summary>\
         <form id=\"upload-form\" class=\"popover\" method=\"post\" action=\"/action/upload\" enctype=\"multipart/form-data\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"dir\" value=\"{dir}\">\
         <label>File<input type=\"file\" name=\"file\" multiple required></label><button class=\"primary\" type=\"submit\">Upload</button></form></details>",
        esc(&url_of("/files", &path)),
        esc(&q.q),
    );

    let body = format!(
        "<div class=\"files\"><section class=\"glass-panel listing\" aria-label=\"File list\">\
         <div class=\"listing-head\"><div><div class=\"crumbs\">{crumbs}</div><h1>{}</h1></div><span class=\"chip\">{count} item{}</span></div>{listing}</section>\
         <div class=\"files-side\"><div id=\"upload-card\" class=\"glass2 upload\" role=\"status\" hidden>\
         <div class=\"upload-text\"><span id=\"upload-status\"></span><progress id=\"upload-progress\" value=\"0\" max=\"1\" aria-label=\"Upload progress\"></progress></div>\
         <button type=\"button\" id=\"upload-cancel\">Cancel</button></div>{details}</div></div>",
        esc(&title),
        if count == 1 { "" } else { "s" },
    );
    let opts = Opts {
        script: Some("upload.js"),
        toolbar: Some(&toolbar),
        bare_main: true,
    };
    layout::app_opts(
        StatusCode::OK,
        "Files",
        &a.chrome(),
        "files",
        &a.csrf,
        &body,
        &opts,
    )
}

/// Details panel of a file (`is_file`) or of the open folder.
async fn details_panel(
    state: &AppState,
    a: &Authed,
    path: &LogicalPath,
    node: &Node,
    own: bool,
    is_file: bool,
) -> String {
    let p = &a.session.principal;
    let q = esc(&enc(&plain(path)));
    let csrf = esc(&a.csrf);
    let meta = if is_file {
        format!("{} · {}", human(node.size), friendly(node.mtime))
    } else {
        format!("Folder · {}", friendly(node.mtime))
    };

    let mut buttons = String::new();
    if is_file {
        buttons.push_str(&format!(
            "<a class=\"button\" href=\"{}\">Download</a>",
            esc(&url_of("/download", path))
        ));
    }
    if own {
        buttons.push_str(&format!(
            "<a class=\"button\" href=\"/share?path={q}\">Share</a>"
        ));
    }
    buttons.push_str(&format!(
        "<a class=\"button danger\" href=\"/action/delete?path={q}\">Delete</a>"
    ));

    // versions (files only)
    let mut versions = String::new();
    if is_file {
        if let Ok(l) = state.version_list(p, node.id).await {
            let mut items = String::new();
            for e in l.entries.iter().rev().take(5) {
                let action = if e.live {
                    String::new()
                } else {
                    format!(
                        "<form method=\"post\" action=\"/versions/restore\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                         <input type=\"hidden\" name=\"path\" value=\"{}\"><input type=\"hidden\" name=\"time\" value=\"{}\">\
                         <button type=\"submit\">Restore</button></form>",
                        esc(&plain(path)),
                        e.version_time
                    )
                };
                items.push_str(&format!(
                    "<li><span class=\"dot{}\" aria-hidden=\"true\"></span><span class=\"vtext\"><b>{}</b><span class=\"muted\">{} · {}</span></span>{action}</li>",
                    if e.live { " live" } else { "" },
                    if e.live { "Current version".to_owned() } else { esc(&friendly(e.mtime)) },
                    if e.live { esc(&friendly(e.mtime)) } else { String::new() },
                    human(e.size),
                ));
            }
            versions = format!(
                "<h2 class=\"eyebrow\">Versions</h2><ul class=\"versions\">{items}</ul><p><a href=\"/versions?path={q}\">All versions</a></p>"
            );
        }
    }

    // shares
    let mut shares = String::new();
    if own {
        let list = state
            .shares_list(
                p,
                ShareFilter {
                    path: Some(path.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_or_default();
        let text = if list.is_empty() {
            "Not shared yet.".to_owned()
        } else {
            list.iter()
                .map(|s| match s.share.kind {
                    ShareKind::Link => "Public link".to_owned(),
                    _ => esc(s.recipient.as_deref().unwrap_or("?")),
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        shares = format!("<h2 class=\"eyebrow\">Shares</h2><p>{text}</p>");
    }

    format!(
        "<aside class=\"glass2 details\" aria-label=\"Details\"><div class=\"details-head\">{}<div><div class=\"details-name\">{}</div><div class=\"muted\">{}</div></div></div>\
         <div class=\"details-actions\">{buttons}</div>{versions}{shares}\
         <dl class=\"ids\"><dt>File ID</dt><dd class=\"mono\">{}</dd><dt>ETag</dt><dd class=\"mono\">{}</dd></dl></aside>",
        tile(node),
        esc(&node.name),
        esc(&meta),
        node.id,
        esc(node.etag.trim_matches('"')),
    )
}
