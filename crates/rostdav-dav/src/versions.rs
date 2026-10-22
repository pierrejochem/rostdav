//! Versions endpoint `/remote.php/dav/versions/<user>/…`.
//!
//! Shape from `tests/fixtures/nextcloud/09-versions/`:
//!
//! ```text
//! /versions/<user>/                        collection; members: versions/, restore/
//! /versions/<user>/versions/<file id>/     members: one entry per version, the live content included
//! /versions/<user>/versions/<file id>/<t>  GET/HEAD content, DELETE, MOVE to restore/target
//! /versions/<user>/restore/target          the only valid MOVE destination
//! ```

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use percent_encoding::percent_decode_str;
use rostdav_app::{AppState, Principal, VersionEntry};
use rostdav_core::{Error, Name, Result};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::error::DavError;
use crate::range::{RangeOutcome, parse_range};
use crate::xml::{
    DAV_NS, NC_NS, PropName, PropfindRequest, ResponseBuilder, escape, multistatus, parse_propfind,
};
use crate::{MAX_XML_BODY, empty, header_str, http_date, method_not_allowed, set};

pub const VERSIONS_PREFIX: &str = "/remote.php/dav/versions/";

/// Where in the versions tree a URL points.
#[derive(Debug, PartialEq, Eq)]
pub enum Location {
    Root,
    VersionsDir,
    RestoreDir,
    RestoreTarget,
    File {
        file_id: i64,
    },
    Entry {
        file_id: i64,
        version_time: i64,
    },
    /// A name below a file that is no version time: nothing to read, nothing to create.
    Unknown {
        file_id: i64,
    },
}

pub struct VersionsTarget {
    pub user: Name,
    pub location: Location,
}

impl VersionsTarget {
    pub fn parse(raw_path: &str) -> Result<Self> {
        let rest = raw_path
            .strip_prefix(VERSIONS_PREFIX)
            .ok_or(Error::BadRequest("unexpected path"))?;
        let segs: Vec<String> = rest
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| {
                percent_decode_str(s)
                    .decode_utf8()
                    .map(std::borrow::Cow::into_owned)
                    .map_err(|_| Error::BadRequest("invalid encoding"))
            })
            .collect::<Result<_>>()?;
        let mut it = segs.iter().map(String::as_str);
        let user = Name::parse(it.next().ok_or(Error::NotFound)?)?;
        let num = |s: &str| {
            s.parse::<i64>()
                .ok()
                .filter(|n| *n >= 0 && s.bytes().all(|b| b.is_ascii_digit()))
        };
        let location = match (it.next(), it.next(), it.next(), it.next()) {
            (None, ..) => Location::Root,
            (Some("versions"), None, ..) => Location::VersionsDir,
            (Some("restore"), None, ..) => Location::RestoreDir,
            // The reference accepts any single name below `restore/`; the Android app uses the file ID
            // (`restore/<fileid>`, M6), the other clients `target`.
            (Some("restore"), Some(_), None, _) => Location::RestoreTarget,
            (Some("versions"), Some(f), None, _) => Location::File {
                file_id: num(f).ok_or(Error::NotFound)?,
            },
            (Some("versions"), Some(f), Some(t), None) => {
                let file_id = num(f).ok_or(Error::NotFound)?;
                match num(t) {
                    Some(version_time) => Location::Entry {
                        file_id,
                        version_time,
                    },
                    None => Location::Unknown { file_id },
                }
            }
            _ => return Err(Error::NotFound),
        };
        Ok(Self { user, location })
    }

    fn base(&self) -> String {
        format!(
            "{VERSIONS_PREFIX}{}",
            percent_encoding::utf8_percent_encode(self.user.as_str(), crate::target::SEGMENT)
        )
    }
}

pub async fn handle(
    state: &AppState,
    p: &Principal,
    method: &str,
    t: &VersionsTarget,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, DavError> {
    if !state.versioning_enabled() {
        return Err(Error::NotFound.into());
    }
    match (method, &t.location) {
        ("PROPFIND", _) => propfind(state, p, t, headers, body).await,
        (
            "GET" | "HEAD",
            Location::Entry {
                file_id,
                version_time,
            },
        ) => get(state, p, *file_id, *version_time, headers, method == "HEAD").await,
        (
            "DELETE",
            Location::Entry {
                file_id,
                version_time,
            },
        ) => {
            state.version_delete(p, *file_id, *version_time).await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        (
            "MOVE",
            Location::Entry {
                file_id,
                version_time,
            },
        ) => restore(state, p, t, *file_id, *version_time, headers).await,
        // Names that are no version time: nothing to read, delete or restore.
        ("GET" | "HEAD" | "DELETE" | "MOVE", Location::Unknown { .. }) => {
            Err(Error::NotFound.into())
        }
        // The tree is read-only apart from delete and restore (reference: 403).
        ("PUT" | "MKCOL" | "COPY" | "PROPPATCH" | "MOVE" | "DELETE", _) => {
            Err(Error::Forbidden.into())
        }
        _ => Ok(method_not_allowed()),
    }
}

async fn restore(
    state: &AppState,
    p: &Principal,
    t: &VersionsTarget,
    file_id: i64,
    version_time: i64,
    headers: &HeaderMap,
) -> Result<Response, DavError> {
    let dest = header_str(headers, "destination")
        .ok_or(Error::BadRequest("missing Destination header"))?;
    // Only the path counts; it must be exactly this user's restore target.
    let path = match dest
        .strip_prefix("http://")
        .or_else(|| dest.strip_prefix("https://"))
    {
        Some(rest) => format!("/{}", rest.split_once('/').map_or("", |(_, p)| p)),
        None => dest.to_owned(),
    };
    let target =
        VersionsTarget::parse(&path).map_err(|_| Error::BadRequest("invalid Destination"))?;
    if target.user.key() != t.user.key() || target.location != Location::RestoreTarget {
        return Err(
            Error::BadRequest("versions can only be restored to the restore target").into(),
        );
    }
    state.version_restore(p, file_id, version_time).await?;
    Ok(empty(StatusCode::CREATED))
}

async fn get(
    state: &AppState,
    p: &Principal,
    file_id: i64,
    version_time: i64,
    headers: &HeaderMap,
    head_only: bool,
) -> Result<Response, DavError> {
    let (node, entry, mut file) = state.version_open(p, file_id, version_time).await?;
    let size = u64::try_from(entry.size).unwrap_or(0);
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
    // The reference sends the bare version name as ETag.
    let tag = entry.version_time.to_string();
    set(&mut r, header::ETAG, &tag);
    set(&mut r, header::HeaderName::from_static("oc-etag"), &tag);
    set(&mut r, header::LAST_MODIFIED, &http_date(entry.mtime));
    set(&mut r, header::ACCEPT_RANGES, "bytes");
    set(
        &mut r,
        header::CONTENT_TYPE,
        mime_guess::from_path(&node.name)
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
    t: &VersionsTarget,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, DavError> {
    let depth = match header_str(headers, "depth").map(str::trim) {
        Some("0") => 0,
        Some("1") => 1,
        // "infinity" is answered like depth 1 by the reference; we refuse it.
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
                out.push(collection(format!("{base}/versions/")));
                out.push(collection(format!("{base}/restore/")));
            }
        }
        Location::VersionsDir => out.push(collection(format!("{base}/versions/"))),
        Location::RestoreDir => out.push(collection(format!("{base}/restore/"))),
        Location::RestoreTarget | Location::Unknown { .. } => return Err(Error::NotFound.into()),
        Location::File { file_id } => {
            let listing = state.version_list(p, *file_id).await?;
            out.push(collection(format!("{base}/versions/{file_id}/")));
            if depth == 1 {
                for e in &listing.entries {
                    let mut rb = ResponseBuilder::new(format!(
                        "{base}/versions/{file_id}/{}",
                        e.version_time
                    ));
                    fill(&request, &mut rb, &Item::Entry(e, &listing.node.name));
                    out.push(rb);
                }
            }
        }
        Location::Entry {
            file_id,
            version_time,
        } => {
            let listing = state.version_list(p, *file_id).await?;
            let e = listing
                .entries
                .iter()
                .find(|e| e.version_time == *version_time)
                .ok_or(Error::NotFound)?;
            let mut rb = ResponseBuilder::new(format!("{base}/versions/{file_id}/{version_time}"));
            fill(&request, &mut rb, &Item::Entry(e, &listing.node.name));
            out.push(rb);
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

enum Item<'a> {
    Collection,
    Entry(&'a VersionEntry, &'a str),
}

fn fill(request: &PropfindRequest, rb: &mut ResponseBuilder, item: &Item<'_>) {
    let wanted: Vec<PropName> = match request {
        PropfindRequest::Props(l) => l.clone(),
        PropfindRequest::AllProp | PropfindRequest::PropName => {
            let names: &[&str] = match item {
                Item::Collection => &["resourcetype"],
                Item::Entry(..) => &[
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
        let v: Option<(&str, String)> = match (item, ns.as_str(), local.as_str()) {
            (Item::Collection, DAV_NS, "resourcetype") => Some(("d", "<d:collection/>".into())),
            (Item::Entry(..), DAV_NS, "resourcetype") => Some(("d", String::new())),
            (Item::Entry(e, _), DAV_NS, "getlastmodified") => Some(("d", http_date(e.mtime))),
            (Item::Entry(e, _), DAV_NS, "getcontentlength") => Some(("d", e.size.to_string())),
            (Item::Entry(e, _), DAV_NS, "getetag") => Some(("d", e.version_time.to_string())),
            (Item::Entry(_, name), DAV_NS, "getcontenttype") => Some((
                "d",
                mime_guess::from_path(name)
                    .first_or_octet_stream()
                    .essence_str()
                    .to_owned(),
            )),
            (Item::Entry(e, _), NC_NS, "version-author") => {
                e.author.as_ref().map(|a| ("nc", escape(a)))
            }
            _ => None,
        };
        match v {
            Some((prefix, val)) => rb.ok(prefix, &local, if names_only { "" } else { &val }),
            None => rb.missing((ns, local)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(p: &str) -> Result<Location> {
        VersionsTarget::parse(&format!("{VERSIONS_PREFIX}{p}")).map(|t| t.location)
    }

    #[test]
    fn locations() {
        assert_eq!(loc("anna").expect("l"), Location::Root);
        assert_eq!(loc("anna/").expect("l"), Location::Root);
        assert_eq!(loc("anna/versions").expect("l"), Location::VersionsDir);
        assert_eq!(loc("anna/restore").expect("l"), Location::RestoreDir);
        assert_eq!(
            loc("anna/restore/target").expect("l"),
            Location::RestoreTarget
        );
        assert_eq!(
            loc("anna/versions/12").expect("l"),
            Location::File { file_id: 12 }
        );
        assert_eq!(
            loc("anna/versions/12/1700000100").expect("l"),
            Location::Entry {
                file_id: 12,
                version_time: 1_700_000_100
            }
        );
        for bad in [
            "anna/versions/abc",
            "anna/versions/-1",
            "anna/versions/12/1/extra",
            "anna/other",
            "anna/restore/a/b",
            "anna/versions/%2e%2e",
            "anna/versions/1e3",
            "anna/versions/+5",
            "",
        ] {
            assert!(loc(bad).is_err(), "{bad}");
        }
    }
}
