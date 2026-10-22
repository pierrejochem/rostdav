//! WebDAV adapter: protocol translation only.
//!
//! No database, no file system: everything goes through [`AppState`]. RFC 4918
//! class 1 under `/remote.php/dav/files/<user>/` (and the legacy
//! `/remote.php/webdav/`) plus the Nextcloud extensions recorded in
//! `tests/fixtures/nextcloud/`: `oc:`/`nc:` properties, upload headers
//! (`X-OC-MTime`, `OC-Checksum`, `OC-FileId`, `OC-ETag`) and chunked upload v2
//! under `/remote.php/dav/uploads/<user>/`.

mod error;
mod props;
mod range;
mod target;
mod uploads;
mod versions;
mod xml;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use std::net::{IpAddr, Ipv4Addr};

use rostdav_app::{AppState, Principal, PutOptions, normalize_checksum};
use rostdav_core::{ClientIp, Error, Name, Result};
use rostdav_meta::{Node, NodeKind, WriteCondition};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::{ReaderStream, StreamReader};
use uploads::{UPLOADS_PREFIX, UploadTarget};
use versions::{VERSIONS_PREFIX, VersionsTarget};

use error::DavError;
use range::{RangeOutcome, parse_range};
use target::{SEGMENT, Target, parse_destination};
use xml::{ResponseBuilder, multistatus, parse_propfind};

pub(crate) const ALLOWED_METHODS: &str =
    "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND";

/// Maximum size of an XML request body.
pub(crate) const MAX_XML_BODY: usize = 64 * 1024;

/// Routes of this layer.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/remote.php/dav/files/{*rest}", any(entry))
        .route("/remote.php/webdav", any(entry))
        .route("/remote.php/webdav/", any(entry))
        .route("/remote.php/webdav/{*rest}", any(entry))
        .route("/remote.php/dav/uploads/{*rest}", any(entry))
        .route("/remote.php/dav/versions/{*rest}", any(entry))
        .route("/public.php/webdav", any(entry))
        .route("/public.php/webdav/", any(entry))
        .route("/public.php/webdav/{*rest}", any(entry))
}

async fn entry(State(state): State<AppState>, req: Request) -> Response {
    handle(state, req)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn handle(state: AppState, req: Request) -> Result<Response, DavError> {
    if req.method() == Method::OPTIONS {
        return Ok(options());
    }
    let ip = req
        .extensions()
        .get::<ClientIp>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0);
    let public = is_public_path(req.uri().path());
    let principal = if public {
        authenticate_link(&state, req.headers(), ip).await?
    } else {
        authenticate(&state, req.headers(), ip).await?
    };
    let principal_name = Name::parse(&principal.name)?;
    let (parts, body) = req.into_parts();
    let headers = &parts.headers;
    let method = parts.method.as_str();

    if !public && parts.uri.path().starts_with(VERSIONS_PREFIX) {
        let t = VersionsTarget::parse(parts.uri.path())?;
        if t.user.key() != principal_name.key() {
            return Err(Error::NotFound.into());
        }
        return versions::handle(&state, &principal, method, &t, headers, body).await;
    }

    if !public && parts.uri.path().starts_with(UPLOADS_PREFIX) {
        let t = UploadTarget::parse(parts.uri.path())?;
        if t.user.key() != principal_name.key() {
            // Reference: "Principal with name … not found" (404).
            return Err(Error::NotFound.into());
        }
        return uploads::handle(&state, &principal, method, &t, headers, body).await;
    }

    let target = Target::parse_any(parts.uri.path(), &principal_name)?;
    // The user in the URL must be the authenticated user; checked on the
    // NFC key so equivalent spellings match. The reference answers 404 here.
    // Link principals only use the public namespace, users never.
    if target.user.key() != principal_name.key() || target.public != public {
        return Err(Error::NotFound.into());
    }
    match method {
        "GET" => get(&state, &principal, &target, headers, false).await,
        "HEAD" => get(&state, &principal, &target, headers, true).await,
        "PUT" => put(&state, &principal, &target, headers, body).await,
        "DELETE" => delete(&state, &principal, &target, headers).await,
        "MKCOL" => mkcol(&state, &principal, &target, headers, body).await,
        "PROPFIND" => propfind(&state, &principal, &target, headers, body).await,
        "MOVE" | "COPY" => transfer(&state, &principal, &target, headers, method == "MOVE").await,
        _ => Ok(method_not_allowed()),
    }
}

fn options() -> Response {
    let mut r = StatusCode::OK.into_response();
    let h = r.headers_mut();
    h.insert("DAV", HeaderValue::from_static("1"));
    h.insert(header::ALLOW, HeaderValue::from_static(ALLOWED_METHODS));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    r
}

pub(crate) fn method_not_allowed() -> Response {
    let mut r = StatusCode::METHOD_NOT_ALLOWED.into_response();
    r.headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(ALLOWED_METHODS));
    r
}

fn is_public_path(path: &str) -> bool {
    path.strip_prefix(target::PUBLIC_PREFIX)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// `public.php/webdav`: Basic with the link token as user name.
async fn authenticate_link(state: &AppState, headers: &HeaderMap, ip: IpAddr) -> Result<Principal> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::Unauthenticated)?;
    state.authenticate_link_basic(value, ip).await
}

/// HTTP Basic with an app password or the account password.
async fn authenticate(state: &AppState, headers: &HeaderMap, ip: IpAddr) -> Result<Principal> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::Unauthenticated)?;
    state.authenticate_basic(value, ip).await
}

// ---- helpers ---------------------------------------------------------------

pub(crate) fn quoted(etag: &str) -> String {
    format!("\"{etag}\"")
}

/// Strips quotes and a weak prefix from an entity tag.
fn unquote(tag: &str) -> &str {
    tag.trim().trim_start_matches("W/").trim_matches('"')
}

pub(crate) fn header_str(h: &HeaderMap, name: impl header::AsHeaderName) -> Option<&str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

pub(crate) fn http_date(secs: i64) -> String {
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs.max(0).unsigned_abs());
    httpdate::fmt_http_date(t)
}

pub(crate) fn set(resp: &mut Response, name: header::HeaderName, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        resp.headers_mut().insert(name, v);
    }
}

pub(crate) fn empty(status: StatusCode) -> Response {
    let mut r = status.into_response();
    r.headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    r
}

/// `X-OC-MTime`: unix seconds. Garbage is a client error (the reference answers 500).
pub(crate) fn parse_mtime(headers: &HeaderMap) -> Result<Option<i64>> {
    let Some(v) = header_str(headers, "x-oc-mtime") else {
        return Ok(None);
    };
    v.trim().parse::<i64>().map(Some).map_err(|_| {
        Error::Invalid(format!(
            "X-OC-MTime header must be a valid integer (unix timestamp), got \"{}\".",
            v.chars()
                .filter(|c| !c.is_control())
                .take(40)
                .collect::<String>()
        ))
    })
}

/// Request body as a byte stream with `io::Error`s, as `StreamReader` wants.
pub(crate) fn body_stream(
    body: Body,
) -> impl futures_core::Stream<Item = std::io::Result<axum::body::Bytes>> + Unpin {
    tokio_stream_adapter(body)
}

fn name_of(node: &Node) -> Result<Name> {
    Name::parse(&node.name)
}

// ---- GET / HEAD ------------------------------------------------------------

async fn get(
    state: &AppState,
    p: &Principal,
    t: &Target,
    headers: &HeaderMap,
    head_only: bool,
) -> Result<Response, DavError> {
    let node = state.stat(p, &t.path).await?;
    if node.kind == NodeKind::Dir {
        return Ok(method_not_allowed());
    }
    let etag = quoted(&node.etag);

    if let Some(inm) = header_str(headers, header::IF_NONE_MATCH) {
        if inm.trim() == "*" || inm.split(',').any(|c| unquote(c) == node.etag) {
            let mut r = empty(StatusCode::NOT_MODIFIED);
            set(&mut r, header::ETAG, &etag);
            return Ok(r);
        }
    }

    let size = u64::try_from(node.size).unwrap_or(0);
    let outcome = parse_range(header_str(headers, header::RANGE), size);
    let (status, start, len) = match outcome {
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
        let (_, mut file) = state.read(p, &t.path).await?;
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
    set(&mut r, header::ETAG, &etag);
    set(&mut r, header::HeaderName::from_static("oc-etag"), &etag);
    set(&mut r, header::LAST_MODIFIED, &http_date(node.mtime));
    set(&mut r, header::ACCEPT_RANGES, "bytes");
    let ct = mime_guess::from_path(&node.name).first_or_octet_stream();
    set(&mut r, header::CONTENT_TYPE, ct.essence_str());
    if status == StatusCode::PARTIAL_CONTENT {
        set(
            &mut r,
            header::CONTENT_RANGE,
            &format!("bytes {start}-{}/{size}", start + len - 1),
        );
    }
    Ok(r)
}

// ---- PUT -------------------------------------------------------------------

async fn put(
    state: &AppState,
    p: &Principal,
    t: &Target,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, DavError> {
    let mut cond = WriteCondition::None;
    if let Some(inm) = header_str(headers, header::IF_NONE_MATCH) {
        if inm.trim() == "*" {
            cond = WriteCondition::MustNotExist;
        }
    }
    if let Some(im) = header_str(headers, header::IF_MATCH) {
        let im = im.trim();
        if im == "*" {
            // must exist
            if state.stat(p, &t.path).await.is_err() {
                return Err(Error::PreconditionFailed.into());
            }
        } else if im.contains(',') {
            return Err(Error::BadRequest("multiple If-Match values are not supported").into());
        } else {
            cond = WriteCondition::IfMatch(unquote(im).to_owned());
        }
    }

    let mtime = parse_mtime(headers)?;
    let opts = PutOptions {
        mtime,
        client_checksum: header_str(headers, "oc-checksum").and_then(normalize_checksum),
        cond: Some(cond),
    };
    let stream = tokio_stream_adapter(body);
    let written = state
        .put_ext(p, &t.path, StreamReader::new(stream), &opts)
        .await?;

    let status = if written.replaced {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    };
    let mut r = empty(status);
    set(&mut r, header::ETAG, &quoted(&written.node.etag));
    set(
        &mut r,
        header::HeaderName::from_static("oc-etag"),
        &quoted(&written.node.etag),
    );
    set(
        &mut r,
        header::HeaderName::from_static("oc-fileid"),
        &state.file_id(written.node.id),
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

/// Request body as a byte stream with `io::Error`s, as `StreamReader` wants.
fn tokio_stream_adapter(
    body: Body,
) -> impl futures_core::Stream<Item = std::io::Result<axum::body::Bytes>> + Unpin {
    Box::pin(StreamAdapter {
        inner: body.into_data_stream(),
    })
}

struct StreamAdapter<S> {
    inner: S,
}

impl<S, E> futures_core::Stream for StreamAdapter<S>
where
    S: futures_core::Stream<Item = Result<axum::body::Bytes, E>> + Unpin,
    E: std::error::Error + Send + Sync + 'static,
{
    type Item = std::io::Result<axum::body::Bytes>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.inner)
            .poll_next(cx)
            .map(|o| o.map(|r| r.map_err(std::io::Error::other)))
    }
}

// ---- DELETE / MKCOL --------------------------------------------------------

async fn delete(
    state: &AppState,
    p: &Principal,
    t: &Target,
    headers: &HeaderMap,
) -> Result<Response, DavError> {
    let im = header_str(headers, header::IF_MATCH)
        .map(str::trim)
        .filter(|v| *v != "*")
        .map(unquote);
    state.delete(p, &t.path, im).await?;
    Ok(empty(StatusCode::NO_CONTENT))
}

async fn mkcol(
    state: &AppState,
    p: &Principal,
    t: &Target,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, DavError> {
    // A MKCOL body is not supported (RFC 4918 §9.3: 415).
    let has_body = header_str(headers, header::CONTENT_LENGTH).is_some_and(|v| v.trim() != "0")
        || headers.contains_key(header::TRANSFER_ENCODING);
    if has_body {
        let bytes = axum::body::to_bytes(body, 1).await;
        if bytes.map_or(true, |b| !b.is_empty()) {
            return Ok(empty(StatusCode::UNSUPPORTED_MEDIA_TYPE));
        }
    }
    let node = state.mkcol(p, &t.path).await?;
    let mut r = empty(StatusCode::CREATED);
    set(
        &mut r,
        header::HeaderName::from_static("oc-fileid"),
        &state.file_id(node.id),
    );
    Ok(r)
}

// ---- MOVE / COPY -----------------------------------------------------------

async fn transfer(
    state: &AppState,
    p: &Principal,
    t: &Target,
    headers: &HeaderMap,
    is_move: bool,
) -> Result<Response, DavError> {
    let dest_raw = header_str(headers, "destination")
        .ok_or(Error::BadRequest("missing Destination header"))?;
    // Like the reference, only the path of the Destination is used; its host
    // is ignored (it may differ behind a reverse proxy).
    let dest = parse_destination(dest_raw, &t.user)?;
    if dest.user.key() != t.user.key() || dest.public != t.public {
        return Err(Error::NotFound.into());
    }
    let overwrite = match header_str(headers, "overwrite").map(str::trim) {
        None | Some("T" | "t") => true,
        Some("F" | "f") => false,
        Some(_) => return Err(Error::BadRequest("invalid Overwrite header").into()),
    };
    let written = if is_move {
        state.move_to(p, &t.path, &dest.path, overwrite).await?
    } else {
        state.copy_to(p, &t.path, &dest.path, overwrite).await?
    };
    let mut r = empty(if written.replaced {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    });
    if is_move {
        set(&mut r, header::ETAG, &quoted(&written.node.etag));
        set(
            &mut r,
            header::HeaderName::from_static("oc-etag"),
            &quoted(&written.node.etag),
        );
    }
    set(
        &mut r,
        header::HeaderName::from_static("oc-fileid"),
        &state.file_id(written.node.id),
    );
    Ok(r)
}

// ---- PROPFIND --------------------------------------------------------------

async fn propfind(
    state: &AppState,
    p: &Principal,
    t: &Target,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, DavError> {
    let depth = match header_str(headers, "depth").map(str::trim) {
        Some("0") => 0,
        Some("1") => 1,
        // RFC 4918 §9.1: servers may refuse infinity with propfind-finite-depth.
        None | Some(_) => {
            let mut r = (
                StatusCode::FORBIDDEN,
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:error xmlns:d=\"DAV:\"><d:propfind-finite-depth/></d:error>",
            )
                .into_response();
            set(
                &mut r,
                header::CONTENT_TYPE,
                "application/xml; charset=utf-8",
            );
            return Ok(r);
        }
    };
    let bytes = axum::body::to_bytes(body, MAX_XML_BODY)
        .await
        .map_err(|_| Error::TooLarge)?;
    let request = parse_propfind(&bytes)?;

    let access = state.stat_access(p, &t.path).await?;
    // (path, grant, ETag override)
    let mut entries: Vec<(
        rostdav_core::LogicalPath,
        rostdav_app::Access,
        Option<String>,
    )> = Vec::new();
    let root_etag = state.derived_root_etag(p, &access).await?;
    let owners;
    if depth == 1 && access.is_dir() {
        let listing = state.list(p, &t.path).await?;
        owners = listing.owners.clone();
        entries.push((t.path.clone(), access.clone(), root_etag));
        for child in listing.children.iter().cloned() {
            let path = t.path.join(&name_of(&child)?);
            entries.push((path, listing.child_access(child), None));
        }
        for m in &listing.mounts {
            entries.push((
                t.path.join(&Name::parse(&m.name)?),
                listing.mount_access(m),
                None,
            ));
        }
    } else {
        owners = state.owner_names(&[access.node.owner_id]).await?;
        entries.push((t.path.clone(), access, root_etag));
    }

    let ids: Vec<i64> = entries.iter().map(|(_, a, _)| a.node.id).collect();
    let ctx = props::PropCtx::new(state, p, owners, &ids).await?;
    let mut responses = Vec::with_capacity(entries.len());
    for (path, access, etag) in &entries {
        let mut rb = ResponseBuilder::new(t.href_for(path, access.is_dir()));
        props::fill(&ctx, &request, access, etag.as_deref(), &mut rb).await?;
        responses.push(rb);
    }

    let mut r = (StatusCode::MULTI_STATUS, multistatus(&responses)).into_response();
    set(
        &mut r,
        header::CONTENT_TYPE,
        "application/xml; charset=utf-8",
    );
    Ok(r)
}
