//! WebDAV adapter: protocol translation only.
//!
//! No database, no file system: everything goes through [`AppState`]. Scope of
//! M2 is plain RFC 4918 class 1 under `/remote.php/dav/files/<user>/`;
//! Nextcloud extensions (`oc:`/`nc:` properties, upload headers, chunked
//! upload) follow in M5 and are not advertised here.

mod error;
mod range;
mod target;
mod xml;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use base64::Engine;
use rostdav_app::{AppState, Principal};
use rostdav_core::{Error, Name, Result};
use rostdav_meta::{Node, NodeKind, WriteCondition};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::{ReaderStream, StreamReader};

use error::DavError;
use range::{RangeOutcome, parse_range};
use target::{DestinationError, Target, parse_destination};
use xml::{DAV_NS, PropfindRequest, ResponseBuilder, multistatus, parse_propfind};

pub(crate) const ALLOWED_METHODS: &str =
    "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND";

/// Maximum size of an XML request body.
const MAX_XML_BODY: usize = 64 * 1024;

/// Routes of this layer.
pub fn router() -> Router<AppState> {
    Router::new().route("/remote.php/dav/files/{*rest}", any(entry))
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
    let principal = authenticate(&state, req.headers()).await?;
    let target = Target::parse(req.uri().path())?;
    // The user in the URL must be the authenticated user; checked on the
    // NFC key so equivalent spellings match.
    if target.user.key() != Name::parse(&principal.name)?.key() {
        return Err(Error::Forbidden.into());
    }

    let (parts, body) = req.into_parts();
    let headers = &parts.headers;
    let method = parts.method.as_str();
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

fn method_not_allowed() -> Response {
    let mut r = StatusCode::METHOD_NOT_ALLOWED.into_response();
    r.headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(ALLOWED_METHODS));
    r
}

/// HTTP Basic with the account password (app passwords follow in M4).
async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Principal> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::Unauthenticated)?;
    let (scheme, b64) = value.split_once(' ').ok_or(Error::Unauthenticated)?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(Error::Unauthenticated);
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| Error::Unauthenticated)?;
    let decoded = String::from_utf8(decoded).map_err(|_| Error::Unauthenticated)?;
    let (user, password) = decoded.split_once(':').ok_or(Error::Unauthenticated)?;
    state.authenticate(user, password).await
}

// ---- helpers ---------------------------------------------------------------

fn quoted(etag: &str) -> String {
    format!("\"{etag}\"")
}

/// Strips quotes and a weak prefix from an entity tag.
fn unquote(tag: &str) -> &str {
    tag.trim().trim_start_matches("W/").trim_matches('"')
}

fn header_str(h: &HeaderMap, name: impl header::AsHeaderName) -> Option<&str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

fn http_date(secs: i64) -> String {
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs.max(0).unsigned_abs());
    httpdate::fmt_http_date(t)
}

fn set(resp: &mut Response, name: header::HeaderName, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        resp.headers_mut().insert(name, v);
    }
}

fn empty(status: StatusCode) -> Response {
    let mut r = status.into_response();
    r.headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    r
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

    let stream = tokio_stream_adapter(body);
    let written = state
        .put(p, &t.path, StreamReader::new(stream), None, &cond)
        .await?;

    let status = if written.replaced {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    };
    let mut r = empty(status);
    set(&mut r, header::ETAG, &quoted(&written.node.etag));
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
    set(&mut r, header::ETAG, &quoted(&node.etag));
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
    let host = header_str(headers, header::HOST);
    let dest = match parse_destination(dest_raw, host) {
        Ok(d) => d,
        Err(DestinationError::Foreign) => return Ok(empty(StatusCode::BAD_GATEWAY)),
        Err(DestinationError::Invalid(e)) => return Err(e.into()),
    };
    if dest.user.key() != t.user.key() {
        return Err(Error::Forbidden.into());
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
    Ok(empty(if written.replaced {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    }))
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

    let node = state.stat(p, &t.path).await?;
    let mut nodes = vec![(t.path.clone(), node.clone())];
    if depth == 1 && node.kind == NodeKind::Dir {
        for child in state.list(p, &t.path).await?.children {
            nodes.push((t.path.join(&name_of(&child)?), child));
        }
    }

    let mut responses = Vec::with_capacity(nodes.len());
    for (path, node) in &nodes {
        let is_dir = node.kind == NodeKind::Dir;
        let mut rb = ResponseBuilder::new(t.href_for(path, is_dir));
        fill_props(&request, node, &mut rb);
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

const KNOWN_PROPS: [&str; 6] = [
    "resourcetype",
    "displayname",
    "getlastmodified",
    "getetag",
    "getcontentlength",
    "getcontenttype",
];

fn fill_props(request: &PropfindRequest, node: &Node, rb: &mut ResponseBuilder) {
    let is_dir = node.kind == NodeKind::Dir;
    let wanted: Vec<(String, String)> = match request {
        PropfindRequest::Props(list) => list.clone(),
        PropfindRequest::AllProp | PropfindRequest::PropName => KNOWN_PROPS
            .iter()
            .filter(|k| !is_dir || !matches!(**k, "getcontentlength" | "getcontenttype"))
            .map(|k| (DAV_NS.to_owned(), (*k).to_owned()))
            .collect(),
    };
    let names_only = matches!(request, PropfindRequest::PropName);

    for (ns, local) in wanted {
        let value: Option<String> = if ns != DAV_NS {
            None
        } else {
            match local.as_str() {
                "resourcetype" => Some(if is_dir {
                    "<d:collection/>".into()
                } else {
                    String::new()
                }),
                "displayname" => Some(xml::escape(&node.name)),
                "getlastmodified" => Some(http_date(node.mtime)),
                "getetag" => Some(xml::escape(&quoted(&node.etag))),
                "getcontentlength" if !is_dir => Some(node.size.to_string()),
                "getcontenttype" if !is_dir => Some(
                    mime_guess::from_path(&node.name)
                        .first_or_octet_stream()
                        .essence_str()
                        .to_owned(),
                ),
                _ => None,
            }
        };
        match value {
            Some(v) => rb.ok(&local, if names_only { "" } else { &v }),
            None => rb.missing((ns, local)),
        }
    }
}
