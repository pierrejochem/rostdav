//! Chunked upload v2 endpoints under `/remote.php/dav/uploads/<user>/`.
//!
//! Shape taken from `tests/fixtures/nextcloud/05-chunked-upload/` and
//! `08-m5-probes/`: `MKCOL` opens a session, `PUT <session>/<chunk>` stores a
//! chunk, `MOVE <session>/.file` assembles to the `Destination`, `DELETE`
//! cancels. Differences from the reference are listed in
//! `docs/compatibility.md`.

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use percent_encoding::{percent_decode_str, utf8_percent_encode};
use rostdav_app::{AppState, Principal};
use rostdav_core::{Error, Name, Result};
use tokio_util::io::StreamReader;

use crate::error::DavError;
use crate::target::parse_destination;
use crate::xml::{PropfindRequest, ResponseBuilder, escape, multistatus, parse_propfind};
use crate::{
    MAX_XML_BODY, SEGMENT, body_stream, empty, header_str, http_date, parse_mtime, quoted, set,
};

pub const UPLOADS_PREFIX: &str = "/remote.php/dav/uploads/";

/// `<user>/<transfer id>[/<chunk>]` of an uploads URL.
pub struct UploadTarget {
    pub user: Name,
    pub transfer: Option<String>,
    pub chunk: Option<String>,
}

impl UploadTarget {
    pub fn parse(raw_path: &str) -> Result<Self> {
        let rest = raw_path
            .strip_prefix(UPLOADS_PREFIX)
            .ok_or(Error::BadRequest("unexpected path"))?;
        let mut parts = rest.split('/').filter(|s| !s.is_empty());
        let dec = |s: &str| -> Result<String> {
            percent_decode_str(s)
                .decode_utf8()
                .map(std::borrow::Cow::into_owned)
                .map_err(|_| Error::BadRequest("invalid encoding"))
        };
        let user = Name::parse(&dec(parts.next().ok_or(Error::NotFound)?)?)?;
        let transfer = parts.next().map(dec).transpose()?;
        let chunk = parts.next().map(dec).transpose()?;
        if parts.next().is_some() {
            return Err(Error::NotFound);
        }
        Ok(Self {
            user,
            transfer,
            chunk,
        })
    }

    fn href(&self, transfer: &str, chunk: Option<&str>, dir: bool) -> String {
        let mut out = format!(
            "{UPLOADS_PREFIX}{}/{}",
            utf8_percent_encode(self.user.as_str(), SEGMENT),
            utf8_percent_encode(transfer, SEGMENT)
        );
        if let Some(c) = chunk {
            out.push('/');
            out.push_str(&utf8_percent_encode(c, SEGMENT).to_string());
        } else if dir {
            out.push('/');
        }
        out
    }
}

pub async fn handle(
    state: &AppState,
    p: &Principal,
    method: &str,
    t: &UploadTarget,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, DavError> {
    let transfer = t.transfer.as_deref();
    match (method, transfer, t.chunk.as_deref()) {
        ("MKCOL", Some(id), None) => {
            state.upload_create(p, id).await?;
            Ok(empty(StatusCode::CREATED))
        }
        ("PUT", Some(id), Some(chunk)) if chunk != ".file" => {
            let replaced = state
                .upload_chunk(p, id, chunk, StreamReader::new(body_stream(body)))
                .await?;
            Ok(empty(if replaced {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::CREATED
            }))
        }
        ("DELETE", Some(id), None) => {
            state.upload_delete(p, id).await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        ("MOVE", Some(id), Some(".file")) => assemble(state, p, id, headers).await,
        ("PROPFIND", Some(id), None) => propfind(state, p, t, id, headers, body).await,
        // Listing all sessions is not offered (reference: 405 "disabled").
        ("PROPFIND", None, None) => Err(Error::AlreadyExists.into()),
        _ => Ok(crate::method_not_allowed()),
    }
}

async fn assemble(
    state: &AppState,
    p: &Principal,
    id: &str,
    headers: &HeaderMap,
) -> Result<Response, DavError> {
    let dest_raw = header_str(headers, "destination")
        .ok_or(Error::BadRequest("missing Destination header"))?;
    let principal_name = Name::parse(&p.name)?;
    let dest = parse_destination(dest_raw, &principal_name)?;
    if dest.user.key() != principal_name.key() {
        return Err(Error::Conflict("The destination node is not found").into());
    }
    let overwrite = match header_str(headers, "overwrite").map(str::trim) {
        None | Some("T" | "t") => true,
        Some("F" | "f") => false,
        Some(_) => return Err(Error::BadRequest("invalid Overwrite header").into()),
    };
    let total = header_str(headers, "oc-total-length")
        .map(|v| {
            v.trim()
                .parse::<u64>()
                .map_err(|_| Error::BadRequest("invalid OC-Total-Length header"))
        })
        .transpose()?;
    let mtime = parse_mtime(headers)?;

    let w = state
        .upload_assemble(p, id, &dest.path, overwrite, total, mtime)
        .await?;
    let mut r = empty(if w.replaced {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    });
    set(&mut r, header::ETAG, &quoted(&w.node.etag));
    set(
        &mut r,
        header::HeaderName::from_static("oc-etag"),
        &quoted(&w.node.etag),
    );
    set(
        &mut r,
        header::HeaderName::from_static("oc-fileid"),
        &state.file_id(w.node.id),
    );
    if mtime.is_some() {
        set(
            &mut r,
            header::HeaderName::from_static("x-oc-mtime"),
            "accepted",
        );
    }
    Ok(r)
}

async fn propfind(
    state: &AppState,
    p: &Principal,
    t: &UploadTarget,
    id: &str,
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
    let listing = state.upload_list(p, id).await?;

    let mut responses = Vec::new();
    let mut session = ResponseBuilder::new(t.href(id, None, true));
    let created = http_date(listing.session.created_at);
    // Only the properties that make sense for a session; others answer 404.
    fill_simple(
        &request,
        &mut session,
        &Simple {
            dir: true,
            size: 0,
            mtime: &created,
            etag: None,
            ctype: false,
        },
    );
    responses.push(session);
    if depth == 1 {
        let total = listing.total();
        let mut file = ResponseBuilder::new(t.href(id, Some(".file"), false));
        fill_simple(
            &request,
            &mut file,
            &Simple {
                dir: false,
                size: total,
                mtime: &created,
                etag: Some(blake_tag(&format!("{id}:{total}"))),
                ctype: true,
            },
        );
        responses.push(file);
        for c in &listing.chunks {
            let mut rb = ResponseBuilder::new(t.href(id, Some(&c.name), false));
            let mtime = http_date(c.mtime);
            fill_simple(
                &request,
                &mut rb,
                &Simple {
                    dir: false,
                    size: c.size,
                    mtime: &mtime,
                    etag: Some(blake_tag(&format!("{}:{}:{}", c.name, c.size, c.mtime))),
                    ctype: true,
                },
            );
            responses.push(rb);
        }
    }
    let mut r = Response::new(Body::from(multistatus(&responses)));
    *r.status_mut() = StatusCode::MULTI_STATUS;
    set(
        &mut r,
        header::CONTENT_TYPE,
        "application/xml; charset=utf-8",
    );
    Ok(r)
}

struct Simple<'a> {
    dir: bool,
    size: u64,
    mtime: &'a str,
    etag: Option<String>,
    ctype: bool,
}

fn blake_tag(s: &str) -> String {
    blake3::hash(s.as_bytes()).to_hex()[..32].to_owned()
}

fn fill_simple(request: &PropfindRequest, rb: &mut ResponseBuilder, e: &Simple<'_>) {
    use crate::xml::DAV_NS;
    let wanted: Vec<(String, String)> = match request {
        PropfindRequest::Props(l) => l.clone(),
        PropfindRequest::AllProp | PropfindRequest::PropName => [
            "getlastmodified",
            "getcontentlength",
            "resourcetype",
            "getetag",
            "getcontenttype",
        ]
        .iter()
        .map(|n| (DAV_NS.to_owned(), (*n).to_owned()))
        .collect(),
    };
    for (ns, local) in wanted {
        let v: Option<String> = if ns != DAV_NS {
            None
        } else {
            match local.as_str() {
                "resourcetype" => Some(if e.dir {
                    "<d:collection/>".into()
                } else {
                    String::new()
                }),
                "getlastmodified" => Some(e.mtime.to_owned()),
                "getcontentlength" if !e.dir => Some(e.size.to_string()),
                "getetag" => e.etag.as_ref().map(|t| escape(&quoted(t))),
                "getcontenttype" if e.ctype => Some("application/octet-stream".into()),
                _ => None,
            }
        };
        match v {
            Some(v) => rb.ok("d", &local, &v),
            None => rb.missing((ns, local)),
        }
    }
}
