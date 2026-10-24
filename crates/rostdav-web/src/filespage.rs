//! The Files page (design "Files"): file list with tiles, details panel for the
//! selected item or the open folder, upload progress card, storage meter in the
//! sidebar (layout). Everything works without scripts; `upload.js` only adds
//! chunked upload with progress.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use rostdav_app::{AppState, Origin, ShareFilter};
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
    /// Column to sort by: `name` (default), `size` or `modified`.
    #[serde(default)]
    sort: String,
    /// `desc` reverses the order.
    #[serde(default)]
    dir: String,
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

use crate::i18n::{t, tf};
use crate::ui::{self, friendly};

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
    let lang = a.lang;
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
    // case, accents and the two spellings of an accented letter do not matter
    if !q.q.trim().is_empty() {
        rows.retain(|r| rostdav_core::fold::contains_loose(&r.name, &q.q));
    }
    // Folders stay first; the chosen column orders within them. Ties fall back to the name.
    let sort = match q.sort.as_str() {
        "size" | "modified" => q.sort.as_str(),
        _ => "name",
    };
    let desc = q.dir == "desc";
    rows.sort_by(|x, y| {
        let by_name = x.name.to_lowercase().cmp(&y.name.to_lowercase());
        let by_col = match sort {
            "size" => x.node.size.cmp(&y.node.size).then(by_name),
            "modified" => x.node.mtime.cmp(&y.node.mtime).then(by_name),
            _ => by_name,
        };
        (x.node.kind == NodeKind::File)
            .cmp(&(y.node.kind == NodeKind::File))
            .then(if desc { by_col.reverse() } else { by_col })
    });
    let ids: Vec<i64> = rows.iter().map(|r| r.node.id).collect();
    let shared = state.share_kinds_of(p, &ids).await.unwrap_or_default();

    // ---- breadcrumbs and title
    let mut crumbs = format!("<a href=\"/files\">{}</a>", esc(&t(lang, "Files")));
    let mut acc = LogicalPath::root();
    let mut title = t(lang, "All files");
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
            format!("<span class=\"chip ok\">{}</span>", esc(&t(lang, "Shared")))
        } else {
            String::new()
        };
        body_rows.push_str(&format!(
            "<tr{cur}><td><a class=\"name\" href=\"{}\">{}<span>{}</span></a></td><td>{}</td><td>{}</td><td>{chip}</td></tr>",
            esc(&row_link(&path, r, &q.q)),
            tile(&r.node),
            esc(&r.name),
            size,
            esc(&friendly(lang, r.node.mtime)),
        ));
    }
    let count = rows.len();
    let listing = if rows.is_empty() {
        let msg = if q.q.trim().is_empty() {
            "This folder is empty."
        } else {
            "Nothing matches the filter."
        };
        let more = if q.q.trim().is_empty() {
            String::new()
        } else {
            format!(
                " <a href=\"/search?q={}\">{}</a>",
                enc(q.q.trim()),
                esc(&t(lang, "Search all folders"))
            )
        };
        format!("<div class=\"empty\">{}{more}</div>", esc(&t(lang, msg)))
    } else {
        // A header link sorts by its column; the active one flips the direction.
        let head = |key: &str, label: &str| {
            let active = key == sort;
            let next_desc = active && !desc;
            let mut href = url_of("/files", &path);
            href.push_str(&format!(
                "?sort={key}&dir={}",
                if next_desc { "desc" } else { "asc" }
            ));
            if !q.q.is_empty() {
                href.push_str(&format!("&q={}", enc(&q.q)));
            }
            let (aria, arrow) = match (active, desc) {
                (true, true) => (" aria-sort=\"descending\"", " \u{2193}"),
                (true, false) => (" aria-sort=\"ascending\"", " \u{2191}"),
                (false, _) => ("", ""),
            };
            format!(
                "<th{aria}><a class=\"sortlink\" href=\"{}\">{}{arrow}</a></th>",
                esc(&href),
                esc(&t(lang, label))
            )
        };
        format!(
            "<table><thead><tr>{}{}{}<th>{}</th></tr></thead><tbody>{body_rows}</tbody></table>",
            head("name", "Name"),
            head("size", "Size"),
            head("modified", "Modified"),
            esc(&t(lang, "Sharing"))
        )
    };

    // ---- details: the selected file, else the open folder
    let selected_row = rows
        .iter()
        .find(|r| r.node.kind == NodeKind::File && r.name == q.sel);
    let details = match selected_row {
        Some(r) => {
            let Ok(n) = Name::parse(&r.name) else {
                return error_response_to(
                    &a,
                    &rostdav_core::Error::BadRequest("name"),
                    "/files",
                    "files",
                );
            };
            details_panel(&state, &a, &path.join(&n), &r.node, r.own, true).await
        }
        None if !path.is_root() => {
            let own = in_own;
            details_panel(&state, &a, &path, &list.node, own, false).await
        }
        None => format!(
            "<aside class=\"glass2 details\" aria-label=\"{}\"><p class=\"muted\">{}</p></aside>",
            esc(&t(lang, "Details")),
            esc(&t(
                lang,
                "Select a file to see its versions, sharing and details."
            ))
        ),
    };

    // ---- toolbar: search, new folder, upload
    let dir = esc(&plain(&path));
    let csrf = esc(&a.csrf);
    let toolbar = format!(
        "<form class=\"search\" method=\"get\" action=\"{}\" role=\"search\"><svg class=\"i\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M11 18a7 7 0 1 0 0-14a7 7 0 0 0 0 14Z\"/><path d=\"M20 20l-4-4\"/></svg>\
         <input type=\"search\" name=\"q\" value=\"{}\" placeholder=\"{search}\" aria-label=\"{search}\"></form>\
         <details class=\"pop\"><summary class=\"button\"><svg class=\"i\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z\"/><path d=\"M12 10v6\"/><path d=\"M9 13h6\"/></svg>{new_folder}</summary>\
         <form class=\"popover\" method=\"post\" action=\"/action/mkdir\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"dir\" value=\"{dir}\">\
         <label>{folder_name}<input type=\"text\" name=\"name\" required></label><button class=\"primary\" type=\"submit\">{create_folder}</button></form></details>\
         <details class=\"pop\"><summary class=\"button primary\"><svg class=\"i\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M12 16V4\"/><path d=\"M7 9l5-5 5 5\"/><path d=\"M5 20h14\"/></svg>{upload}</summary>\
         <form id=\"upload-form\" class=\"popover\" method=\"post\" action=\"/action/upload\" enctype=\"multipart/form-data\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"dir\" value=\"{dir}\">\
         <label class=\"dropzone dropzone-compact\"><input type=\"file\" name=\"file\" multiple required>\
         <svg class=\"i dz-icon\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M12 16V4\"/><path d=\"M7 9l5-5 5 5\"/><path d=\"M5 20h14\"/></svg>\
         <span class=\"dz-title\">{choose_files}</span><span class=\"dz-hint\">{drop_hint}</span></label>\
         <button class=\"primary\" type=\"submit\">{upload}</button></form></details>",
        esc(&url_of("/files", &path)),
        esc(&q.q),
        search = esc(&t(lang, "Search in this folder")),
        new_folder = esc(&t(lang, "New folder")),
        folder_name = esc(&t(lang, "Folder name")),
        create_folder = esc(&t(lang, "Create folder")),
        upload = esc(&t(lang, "Upload")),
        choose_files = esc(&t(lang, "Choose files")),
        drop_hint = esc(&t(lang, "or drop files and folders anywhere on this page")),
    );

    let body = format!(
        "<div class=\"files\"><section class=\"glass-panel listing\" aria-label=\"{filelist}\">\
         <div class=\"listing-head\"><div><div class=\"crumbs\">{crumbs}</div><h1>{}</h1></div><span class=\"chip\">{}</span></div>{listing}</section>\
         <div class=\"files-side\"><div id=\"upload-card\" class=\"glass2 upload\" role=\"status\" hidden>\
         <div class=\"upload-text\"><span id=\"upload-status\"></span><progress id=\"upload-progress\" value=\"0\" max=\"1\" aria-label=\"{}\"></progress></div>\
         <button type=\"button\" id=\"upload-cancel\">{}</button></div>{details}</div></div>",
        esc(&title),
        esc(&if count == 1 {
            t(lang, "1 item")
        } else {
            tf(lang, "{0} items", &[&count.to_string()])
        }),
        esc(&t(lang, "Upload progress")),
        esc(&t(lang, "Cancel")),
        filelist = esc(&t(lang, "File list")),
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
    let lang = a.lang;
    let q = esc(&enc(&plain(path)));
    let csrf = esc(&a.csrf);
    let meta = if is_file {
        format!("{} · {}", human(node.size), friendly(lang, node.mtime))
    } else {
        format!("{} · {}", t(lang, "Folder"), friendly(lang, node.mtime))
    };

    let mut buttons = String::new();
    if is_file {
        buttons.push_str(&format!(
            "<a class=\"button\" href=\"{}\">{}</a>",
            esc(&url_of("/download", path)),
            esc(&t(lang, "Download"))
        ));
    }
    if own {
        buttons.push_str(&format!(
            "<a class=\"button\" href=\"/share?path={q}\">{}</a>",
            esc(&t(lang, "Share"))
        ));
    }
    buttons.push_str(&format!(
        "<a class=\"button danger\" href=\"/action/delete?path={q}\">{}</a>",
        esc(&t(lang, "Delete"))
    ));

    // versions (files only)
    let mut versions = String::new();
    if is_file && let Ok(l) = state.version_list(p, node.id).await {
        let mut items = String::new();
        for e in l.entries.iter().rev().take(5) {
            let action = if e.live {
                String::new()
            } else {
                format!(
                    "<form method=\"post\" action=\"/versions/restore\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                         <input type=\"hidden\" name=\"path\" value=\"{}\"><input type=\"hidden\" name=\"time\" value=\"{}\">\
                         <button type=\"submit\">{}</button></form>",
                    esc(&plain(path)),
                    e.version_time,
                    esc(&t(lang, "Restore"))
                )
            };
            items.push_str(&format!(
                    "<li><span class=\"dot{}\" aria-hidden=\"true\"></span><span class=\"vtext\"><b>{}</b><span class=\"muted\">{} · {}</span></span>{action}</li>",
                    if e.live { " live" } else { "" },
                    if e.live { esc(&t(lang, "Current version")) } else { esc(&friendly(lang, e.mtime)) },
                    if e.live { esc(&friendly(lang, e.mtime)) } else { String::new() },
                    human(e.size),
                ));
        }
        versions = format!(
            "<h2 class=\"eyebrow\">{}</h2><ul class=\"versions\">{items}</ul><p><a href=\"/versions?path={q}\">{}</a></p>",
            esc(&t(lang, "Versions")),
            esc(&t(lang, "All versions"))
        );
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
            esc(&t(lang, "Not shared yet."))
        } else {
            list.iter()
                .map(|s| match s.share.kind {
                    ShareKind::Link => esc(&t(lang, "Public link")),
                    _ => esc(s.recipient.as_deref().unwrap_or("?")),
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        shares = format!(
            "<h2 class=\"eyebrow\">{}</h2><p>{text}</p>",
            esc(&t(lang, "Shares"))
        );
    }

    format!(
        "<aside class=\"glass2 details\" aria-label=\"{}\"><div class=\"details-head\">{}<div><div class=\"details-name\">{}</div><div class=\"muted\">{}</div></div></div>\
         <div class=\"details-actions\">{buttons}</div>{versions}{shares}\
         <dl class=\"ids\"><dt>{}</dt><dd class=\"mono\">{}</dd><dt>ETag</dt><dd class=\"mono\">{}</dd></dl></aside>",
        esc(&t(lang, "Details")),
        tile(node),
        esc(&node.name),
        esc(&meta),
        esc(&t(lang, "File ID")),
        node.id,
        esc(node.etag.trim_matches('"')),
    )
}

/// The files that changed last (own tree, newest first).
pub async fn recent(State(state): State<AppState>, a: Authed) -> Response {
    const LIMIT: i64 = 100;
    let lang = a.lang;
    let list = match state.list_recent(&a.session.principal, LIMIT).await {
        Ok(l) => l,
        Err(e) => return error_response_to(&a, &e, "/files", "recent"),
    };
    let body = if list.is_empty() {
        format!(
            "<div class=\"empty\">{}</div>",
            esc(&t(lang, "No files yet."))
        )
    } else {
        let rows: String = list
            .iter()
            .filter_map(|(path, n)| {
                // a file always has a parent folder
                let (parent, _) = path.split_last()?;
                let mut link = url_of("/files", &parent);
                link.push_str(&format!("?sel={}", enc(&n.name)));
                let folder = if parent.is_root() {
                    t(lang, "Files")
                } else {
                    plain(&parent)
                };
                Some(format!(
                    "<tr><td><a class=\"name\" href=\"{}\">{}<span>{}</span></a></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(&link),
                    tile(n),
                    esc(&n.name),
                    esc(&folder),
                    human(n.size),
                    esc(&friendly(lang, n.mtime)),
                ))
            })
            .collect();
        format!(
            "<table><thead><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>{rows}</tbody></table>",
            esc(&t(lang, "Name")),
            esc(&t(lang, "Folder")),
            esc(&t(lang, "Size")),
            esc(&t(lang, "Modified")),
        )
    };
    let head = ui::page_head(
        lang,
        "Recent",
        "The files you changed last, newest first.",
        "",
    );
    let card = ui::card(lang, "Recent files", "", &body);
    ui::page(
        &a,
        StatusCode::OK,
        "Recent",
        "recent",
        &format!("{head}{card}"),
    )
}

// ---- search ------------------------------------------------------------------------------

const SEARCH_PAGE: usize = 50;

#[derive(Deserialize, Default)]
pub struct SearchParams {
    #[serde(default)]
    q: String,
    /// A folder to search in; empty searches everything the user can reach.
    #[serde(default)]
    scope: String,
    /// `files`, `folders`, or empty for both.
    #[serde(default)]
    kind: String,
    #[serde(default)]
    page: usize,
}

/// `/search`: names in every folder the user can reach (own files and received shares).
pub async fn search(
    State(state): State<AppState>,
    a: Authed,
    Query(p): Query<SearchParams>,
) -> Response {
    let lang = a.lang;
    let scope = match crate::pages::parse_plain(&p.scope) {
        Ok(s) => s,
        Err(e) => return error_response_to(&a, &e, "/search", "search"),
    };
    let kind = match p.kind.as_str() {
        "files" => rostdav_app::KindFilter::Files,
        "folders" => rostdav_app::KindFilter::Folders,
        _ => rostdav_app::KindFilter::Any,
    };
    let has_query = !p.q.trim().is_empty();
    let page_no = p.page;
    let mut query = rostdav_app::SearchQuery::new(p.q.trim());
    query.scope = scope.clone();
    query.kind = kind;
    query.limit = SEARCH_PAGE;
    query.offset = page_no.saturating_mul(SEARCH_PAGE);
    let result = if has_query {
        match state.search(&a.session.principal, &query).await {
            Ok(r) => r,
            Err(e) => return error_response_to(&a, &e, "/search", "search"),
        }
    } else {
        rostdav_app::SearchPage::default()
    };

    let scope_plain = plain(&scope);
    let sel = |value: &str, label: &str, now: &str| {
        format!(
            "<option value=\"{value}\"{}>{}</option>",
            if now == value { " selected" } else { "" },
            esc(label)
        )
    };
    let where_options = if scope_plain.is_empty() {
        sel("", &t(lang, "Everywhere"), "")
    } else {
        format!(
            "<option value=\"\">{}</option><option value=\"{}\" selected>{}</option>",
            esc(&t(lang, "Everywhere")),
            esc(&scope_plain),
            esc(&tf(lang, "In {0}", &[&scope_plain]))
        )
    };
    let form = format!(
        "<form class=\"searchbar\" method=\"get\" action=\"/search\" role=\"search\">\
         <label>{}<input type=\"search\" name=\"q\" value=\"{}\" autofocus></label>\
         <label>{}<select name=\"scope\">{where_options}</select></label>\
         <label>{}<select name=\"kind\">{}{}{}</select></label>\
         <button class=\"primary\" type=\"submit\">{}</button></form>",
        esc(&t(lang, "Search for")),
        esc(&p.q),
        esc(&t(lang, "Where")),
        esc(&t(lang, "Type")),
        sel("", &t(lang, "Files and folders"), p.kind.as_str()),
        sel("files", &t(lang, "Files only"), p.kind.as_str()),
        sel("folders", &t(lang, "Folders only"), p.kind.as_str()),
        esc(&t(lang, "Search")),
    );

    let body = if !has_query {
        format!(
            "<div class=\"empty\">{}</div>",
            esc(&t(
                lang,
                "Type part of a name, or words from a text, to search."
            ))
        )
    } else if result.hits.is_empty() {
        format!(
            "<div class=\"empty\">{}</div>",
            esc(&tf(lang, "Nothing found for “{0}”.", &[p.q.trim()]))
        )
    } else {
        let rows: String = result
            .hits
            .iter()
            .map(|h| {
                let parent = h
                    .path
                    .split_last()
                    .map_or_else(LogicalPath::root, |(par, _)| par);
                let link = match h.node.kind {
                    NodeKind::Dir => url_of("/files", &h.path),
                    NodeKind::File => {
                        format!("{}?sel={}", url_of("/files", &parent), enc(&h.node.name))
                    }
                };
                let folder = if parent.is_root() {
                    t(lang, "Files")
                } else {
                    plain(&parent)
                };
                let size = if h.node.kind == NodeKind::Dir {
                    "–".to_owned()
                } else {
                    human(h.node.size)
                };
                // what the file says around the words, with those words marked; every part is
                // escaped, the markers are the only markup
                let snippet = if h.snippet.is_empty() {
                    String::new()
                } else {
                    let body: String = h
                        .snippet
                        .iter()
                        .map(|part| {
                            if part.hit {
                                format!("<mark>{}</mark>", esc(&part.text))
                            } else {
                                esc(&part.text)
                            }
                        })
                        .collect();
                    format!(
                        "<span class=\"snippet\"><span class=\"chip\">{}</span> {body}</span>",
                        esc(&t(lang, "In the text"))
                    )
                };
                format!(
                    "<tr><td><a class=\"name\" href=\"{}\">{}<span>{}{snippet}</span></a></td><td>{}</td><td class=\"hide\">{}</td><td class=\"hide\">{}</td></tr>",
                    esc(&link),
                    tile(&h.node),
                    esc(&h.node.name),
                    esc(&folder),
                    size,
                    esc(&friendly(lang, h.node.mtime)),
                )
            })
            .collect();
        let mut pager = String::new();
        let href = |n: usize| {
            format!(
                "/search?q={}&scope={}&kind={}&page={n}",
                enc(&p.q),
                enc(&scope_plain),
                enc(&p.kind)
            )
        };
        if page_no > 0 {
            pager.push_str(&format!(
                "<a class=\"button\" href=\"{}\">{}</a> ",
                esc(&href(page_no - 1)),
                esc(&t(lang, "Previous"))
            ));
        }
        if result.more {
            pager.push_str(&format!(
                "<a class=\"button\" href=\"{}\">{}</a>",
                esc(&href(page_no + 1)),
                esc(&t(lang, "Next"))
            ));
        }
        let notice = if result.truncated {
            format!(
                "<p class=\"muted\">{}</p>",
                esc(&t(
                    lang,
                    "The search stopped before it had looked everywhere. Narrow it to a folder."
                ))
            )
        } else {
            String::new()
        };
        format!(
            "<table><thead><tr><th>{}</th><th>{}</th><th class=\"hide\">{}</th><th class=\"hide\">{}</th></tr></thead><tbody>{rows}</tbody></table>{notice}<div class=\"pager\">{pager}</div>",
            esc(&t(lang, "Name")),
            esc(&t(lang, "Folder")),
            esc(&t(lang, "Size")),
            esc(&t(lang, "Modified")),
        )
    };
    let head = ui::page_head(
        lang,
        "Search",
        "Find files and folders by name, and files by the words in their text, in everything you can reach.",
        "",
    );
    let card = ui::card(lang, "Results", "", &format!("{form}{body}"));
    ui::page(
        &a,
        StatusCode::OK,
        "Search",
        "search",
        &format!("{head}{card}"),
    )
}
