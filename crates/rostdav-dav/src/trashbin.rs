//! Trash endpoint `/remote.php/dav/trashbin/<user>/…`.
//!
//! Shape from `tests/fixtures/nextcloud/11-trash/`:
//!
//! ```text
//! /trashbin/<user>/                 members: restore/, trash/
//! /trashbin/<user>/trash/           one member per deleted item: <name>.d<deletion time>
//! /trashbin/<user>/trash/<item>[/…] GET/HEAD content, DELETE purges, MOVE restores
//! /trashbin/<user>/restore/<any>    destination of a restore MOVE
//! ```

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use percent_encoding::{percent_decode_str, utf8_percent_encode};
use rostdav_app::{AppState, Principal, TrashEntry};
use rostdav_core::{Error, LogicalPath, Name, Result};
use rostdav_meta::{Node, NodeKind, TrashItem};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::error::DavError;
use crate::range::{RangeOutcome, parse_range};
use crate::xml::{
    DAV_NS, NC_NS, OC_NS, PropName, PropfindRequest, ResponseBuilder, escape, multistatus,
    parse_propfind,
};
use crate::{MAX_XML_BODY, empty, header_str, http_date, method_not_allowed, set};

pub const TRASH_PREFIX: &str = "/remote.php/dav/trashbin/";

#[derive(Debug, PartialEq, Eq)]
pub enum Location {
    Root,
    TrashDir,
    RestoreDir,
    /// `restore/<name>`: only valid as a destination.
    RestoreTarget,
    /// An item, or a path below it.
    Entry {
        entry: String,
        inner: LogicalPath,
    },
}

pub struct TrashTarget {
    pub user: Name,
    pub location: Location,
}

impl TrashTarget {
    pub fn parse(raw_path: &str) -> Result<Self> {
        let rest = raw_path
            .strip_prefix(TRASH_PREFIX)
            .ok_or(Error::BadRequest("unexpected path"))?;
        let mut segs = rest.split('/').filter(|s| !s.is_empty());
        let dec = |s: &str| -> Result<String> {
            percent_decode_str(s)
                .decode_utf8()
                .map(std::borrow::Cow::into_owned)
                .map_err(|_| Error::BadRequest("invalid encoding"))
        };
        let user = Name::parse(&dec(segs.next().ok_or(Error::NotFound)?)?)?;
        let location = match segs.next() {
            None => Location::Root,
            Some("trash") => match segs.next() {
                None => Location::TrashDir,
                Some(entry) => {
                    let entry = dec(entry)?;
                    let mut inner = LogicalPath::root();
                    for s in segs {
                        inner = inner.join(&Name::parse(&dec(s)?)?);
                    }
                    Location::Entry { entry, inner }
                }
            },
            Some("restore") => match segs.next() {
                None => Location::RestoreDir,
                Some(_) => Location::RestoreTarget,
            },
            Some(_) => return Err(Error::NotFound),
        };
        Ok(Self { user, location })
    }

    fn base(&self) -> String {
        format!(
            "{TRASH_PREFIX}{}",
            utf8_percent_encode(self.user.as_str(), crate::target::SEGMENT)
        )
    }
}

pub async fn handle(
    state: &AppState,
    p: &Principal,
    method: &str,
    t: &TrashTarget,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, DavError> {
    if !state.trash_enabled() {
        return Err(Error::NotFound.into());
    }
    match (method, &t.location) {
        ("PROPFIND", _) => propfind(state, p, t, headers, body).await,
        ("GET" | "HEAD", Location::Entry { entry, inner }) => {
            get(state, p, entry, inner, headers, method == "HEAD").await
        }
        ("DELETE", Location::TrashDir) => {
            state.trash_empty(p).await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        ("DELETE", Location::Entry { entry, inner }) if inner.is_root() => {
            state.trash_delete(p, entry).await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        ("MOVE", Location::Entry { entry, inner }) if inner.is_root() => {
            restore(state, p, t, entry, headers).await
        }
        // The tree is read-only apart from restore and purge (reference: 403).
        ("PUT" | "MKCOL" | "COPY" | "PROPPATCH" | "MOVE" | "DELETE", _) => {
            Err(Error::Forbidden.into())
        }
        _ => Ok(method_not_allowed()),
    }
}

async fn restore(
    state: &AppState,
    p: &Principal,
    t: &TrashTarget,
    entry: &str,
    headers: &HeaderMap,
) -> Result<Response, DavError> {
    let dest = header_str(headers, "destination")
        .ok_or(Error::BadRequest("missing Destination header"))?;
    let path = match dest
        .strip_prefix("http://")
        .or_else(|| dest.strip_prefix("https://"))
    {
        Some(rest) => format!("/{}", rest.split_once('/').map_or("", |(_, p)| p)),
        None => dest.to_owned(),
    };
    let target = TrashTarget::parse(&path).map_err(|_| Error::BadRequest("invalid Destination"))?;
    if target.user.key() != t.user.key() || target.location != Location::RestoreTarget {
        return Err(Error::BadRequest("items can only be restored to the restore folder").into());
    }
    state.trash_restore(p, entry).await?;
    Ok(empty(StatusCode::CREATED))
}

async fn get(
    state: &AppState,
    p: &Principal,
    entry: &str,
    inner: &LogicalPath,
    headers: &HeaderMap,
    head_only: bool,
) -> Result<Response, DavError> {
    let e = state.trash_entry(p, entry, inner).await?;
    if e.node.kind == NodeKind::Dir {
        return Ok(method_not_allowed());
    }
    let size = u64::try_from(e.node.size).unwrap_or(0);
    let (status, start, len) = match parse_range(header_str(headers, header::RANGE), size) {
        RangeOutcome::Full => (StatusCode::OK, 0, size),
        RangeOutcome::Partial(a, b) => (StatusCode::PARTIAL_CONTENT, a, b - a + 1),
        RangeOutcome::Unsatisfiable => {
            let mut r = empty(StatusCode::RANGE_NOT_SATISFIABLE);
            set(&mut r, header::CONTENT_RANGE, &format!("bytes */{size}"));
            return Ok(r);
        }
    };
    let body = if head_only {
        Body::empty()
    } else {
        let mut file = state.trash_open(&e).await?;
        if start > 0 {
            file.seek(std::io::SeekFrom::Start(start))
                .await
                .map_err(Error::internal)?;
        }
        Body::from_stream(ReaderStream::new(file.take(len)))
    };
    let mut r = Response::new(body);
    *r.status_mut() = status;
    set(&mut r, header::CONTENT_LENGTH, &len.to_string());
    let when = if e.top {
        e.item.deleted_at
    } else {
        e.node.mtime
    };
    set(&mut r, header::LAST_MODIFIED, &http_date(when));
    set(&mut r, header::ACCEPT_RANGES, "bytes");
    set(
        &mut r,
        header::CONTENT_TYPE,
        mime_guess::from_path(&e.node.name)
            .first_or_octet_stream()
            .essence_str(),
    );
    if status == StatusCode::PARTIAL_CONTENT {
        set(
            &mut r,
            header::CONTENT_RANGE,
            &format!("bytes {start}-{}/{size}", start + len - 1),
        );
    }
    Ok(r)
}

async fn propfind(
    state: &AppState,
    p: &Principal,
    t: &TrashTarget,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, DavError> {
    let depth = match header_str(headers, "depth").map(str::trim) {
        Some("0") => 0,
        Some("1") => 1,
        _ => return Err(Error::Forbidden.into()),
    };
    let bytes = axum::body::to_bytes(body, MAX_XML_BODY)
        .await
        .map_err(|_| Error::TooLarge)?;
    let request = parse_propfind(&bytes)?;
    let base = t.base();
    let mut out: Vec<ResponseBuilder> = Vec::new();
    let collection = |href: String| {
        let mut rb = ResponseBuilder::new(href);
        fill(&request, &mut rb, &Item::Collection);
        rb
    };
    match &t.location {
        Location::Root => {
            out.push(collection(format!("{base}/")));
            if depth == 1 {
                out.push(collection(format!("{base}/restore/")));
                out.push(collection(format!("{base}/trash/")));
            }
        }
        Location::RestoreDir => out.push(collection(format!("{base}/restore/"))),
        Location::RestoreTarget => return Err(Error::NotFound.into()),
        Location::TrashDir => {
            let items = state.trash_list(p).await?;
            out.push(collection(format!("{base}/trash/")));
            if depth == 1 {
                for it in &items {
                    let size = state
                        .trash_size(&TrashEntry {
                            item: it.clone(),
                            node: it.node.clone(),
                            top: true,
                        })
                        .await?;
                    let mut rb = ResponseBuilder::new(item_href(&base, it));
                    fill(&request, &mut rb, &Item::Top(it, size));
                    out.push(rb);
                }
            }
        }
        Location::Entry { entry, inner } => {
            let e = state.trash_entry(p, entry, inner).await?;
            let size = state.trash_size(&e).await?;
            let href = entry_href(&base, entry, inner, e.node.kind == NodeKind::Dir);
            let mut rb = ResponseBuilder::new(href.clone());
            fill(
                &request,
                &mut rb,
                &if e.top {
                    Item::Top(&e.item, size)
                } else {
                    Item::Inner(&e.node, size)
                },
            );
            out.push(rb);
            if depth == 1 && e.node.kind == NodeKind::Dir {
                for child in state.trash_children(&e).await? {
                    let cs = if child.kind == NodeKind::Dir {
                        state
                            .trash_size(&TrashEntry {
                                item: e.item.clone(),
                                node: child.clone(),
                                top: false,
                            })
                            .await?
                    } else {
                        child.size
                    };
                    let cinner = inner.join(&Name::parse(&child.name)?);
                    let mut rb = ResponseBuilder::new(entry_href(
                        &base,
                        entry,
                        &cinner,
                        child.kind == NodeKind::Dir,
                    ));
                    fill(&request, &mut rb, &Item::Inner(&child, cs));
                    out.push(rb);
                }
            }
        }
    }
    let mut r = Response::new(Body::from(multistatus(&out)));
    *r.status_mut() = StatusCode::MULTI_STATUS;
    set(
        &mut r,
        header::CONTENT_TYPE,
        "application/xml; charset=utf-8",
    );
    Ok(r)
}

fn enc(s: &str) -> String {
    utf8_percent_encode(s, crate::target::SEGMENT).to_string()
}

fn item_href(base: &str, it: &TrashItem) -> String {
    let slash = if it.node.kind == NodeKind::Dir {
        "/"
    } else {
        ""
    };
    format!("{base}/trash/{}{slash}", enc(&it.entry_name()))
}

fn entry_href(base: &str, entry: &str, inner: &LogicalPath, dir: bool) -> String {
    let mut out = format!("{base}/trash/{}", enc(entry));
    for seg in inner.segments() {
        out.push('/');
        out.push_str(&enc(seg.as_str()));
    }
    if dir {
        out.push('/');
    }
    out
}

enum Item<'a> {
    Collection,
    /// A deleted item; the size is that of the whole subtree.
    Top(&'a TrashItem, i64),
    /// Something inside a deleted folder.
    Inner(&'a Node, i64),
}

fn fill(request: &PropfindRequest, rb: &mut ResponseBuilder, item: &Item<'_>) {
    let is_dir = |n: &Node| n.kind == NodeKind::Dir;
    let wanted: Vec<PropName> = match request {
        PropfindRequest::Props(l) => l.clone(),
        PropfindRequest::AllProp | PropfindRequest::PropName => {
            let names: &[&str] = match item {
                Item::Collection => &["resourcetype"],
                Item::Top(i, _) if is_dir(&i.node) => {
                    &["getlastmodified", "resourcetype", "getetag"]
                }
                Item::Inner(n, _) if is_dir(n) => &["getlastmodified", "resourcetype", "getetag"],
                _ => &[
                    "getlastmodified",
                    "getcontentlength",
                    "resourcetype",
                    "getetag",
                    "getcontenttype",
                ],
            };
            names
                .iter()
                .map(|n| (DAV_NS.to_owned(), (*n).to_owned()))
                .collect()
        }
    };
    let names_only = matches!(request, PropfindRequest::PropName);
    for (ns, local) in wanted {
        let v: Option<(&str, String)> = match item {
            Item::Collection => (ns == DAV_NS && local == "resourcetype")
                .then(|| ("d", "<d:collection/>".to_owned())),
            Item::Top(i, size) => top_prop(i, *size, &ns, &local),
            Item::Inner(n, size) => inner_prop(n, *size, &ns, &local),
        };
        match v {
            Some((prefix, val)) => rb.ok(prefix, &local, if names_only { "" } else { &val }),
            None => rb.missing((ns, local)),
        }
    }
}

fn content_type(n: &Node) -> String {
    mime_guess::from_path(&n.name)
        .first_or_octet_stream()
        .essence_str()
        .to_owned()
}

fn top_prop(i: &TrashItem, size: i64, ns: &str, local: &str) -> Option<(&'static str, String)> {
    let n = &i.node;
    let dir = n.kind == NodeKind::Dir;
    match (ns, local) {
        (DAV_NS, "resourcetype") => Some((
            "d",
            if dir {
                "<d:collection/>".into()
            } else {
                String::new()
            },
        )),
        (DAV_NS, "getlastmodified") => Some(("d", http_date(i.deleted_at))),
        // the reference leaves the ETag of files empty and uses the deletion time for folders
        (DAV_NS, "getetag") => Some((
            "d",
            if dir {
                i.deleted_at.to_string()
            } else {
                String::new()
            },
        )),
        (DAV_NS, "getcontentlength") if !dir => Some(("d", n.size.to_string())),
        (DAV_NS, "getcontenttype") if !dir => Some(("d", content_type(n))),
        (OC_NS, "fileid" | "id") => Some(("oc", n.id.to_string())),
        (OC_NS, "size") => Some(("oc", size.to_string())),
        (OC_NS, "permissions") => Some(("oc", "GD".into())),
        (NC_NS, "trashbin-filename") => Some(("nc", escape(&n.name))),
        (NC_NS, "trashbin-original-location" | "trashbin-title") => {
            Some(("nc", escape(&i.orig_path)))
        }
        (NC_NS, "trashbin-deletion-time") => Some(("nc", i.deleted_at.to_string())),
        (NC_NS, "trashbin-deleted-by-id" | "trashbin-deleted-by-display-name") => {
            i.deleted_by.as_ref().map(|u| ("nc", escape(u)))
        }
        (NC_NS, "has-preview") => Some(("nc", "false".into())),
        _ => None,
    }
}

fn inner_prop(n: &Node, size: i64, ns: &str, local: &str) -> Option<(&'static str, String)> {
    let dir = n.kind == NodeKind::Dir;
    match (ns, local) {
        (DAV_NS, "resourcetype") => Some((
            "d",
            if dir {
                "<d:collection/>".into()
            } else {
                String::new()
            },
        )),
        (DAV_NS, "getlastmodified") => Some(("d", http_date(n.mtime))),
        (DAV_NS, "getetag") => Some(("d", escape(&crate::quoted(&n.etag)))),
        (DAV_NS, "getcontentlength") if !dir => Some(("d", n.size.to_string())),
        (DAV_NS, "getcontenttype") if !dir => Some(("d", content_type(n))),
        (OC_NS, "fileid" | "id") => Some(("oc", n.id.to_string())),
        (OC_NS, "size") => Some(("oc", size.to_string())),
        (OC_NS, "permissions") => Some(("oc", "GD".into())),
        (NC_NS, "has-preview") => Some(("nc", "false".into())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(p: &str) -> Result<Location> {
        TrashTarget::parse(&format!("{TRASH_PREFIX}{p}")).map(|t| t.location)
    }

    #[test]
    fn locations() {
        assert_eq!(loc("anna").expect("l"), Location::Root);
        assert_eq!(loc("anna/trash").expect("l"), Location::TrashDir);
        assert_eq!(loc("anna/trash/").expect("l"), Location::TrashDir);
        assert_eq!(loc("anna/restore").expect("l"), Location::RestoreDir);
        assert_eq!(
            loc("anna/restore/a.txt.d1").expect("l"),
            Location::RestoreTarget
        );
        assert_eq!(
            loc("anna/trash/a.txt.d1").expect("l"),
            Location::Entry {
                entry: "a.txt.d1".into(),
                inner: LogicalPath::root()
            }
        );
        match loc("anna/trash/sub.d5/a%20b/c.txt").expect("l") {
            Location::Entry { entry, inner } => {
                assert_eq!(entry, "sub.d5");
                assert_eq!(
                    inner
                        .segments()
                        .iter()
                        .map(Name::as_str)
                        .collect::<Vec<_>>(),
                    ["a b", "c.txt"]
                );
            }
            other => panic!("{other:?}"),
        }
        for bad in [
            "",
            "anna/other",
            "anna/trash/x/../y",
            "anna/trash/x/%2e%2e",
            "anna/trash/x/a%2fb",
            "anna/trash/x/%00",
        ] {
            assert!(loc(bad).is_err(), "{bad}");
        }
    }
}
