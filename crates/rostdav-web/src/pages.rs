//! Sign-in, sign-out and the Files page (ADR 0006, slice 11a).

use axum::Form;
use axum::body::Body;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use futures_core::Stream;
use rostdav_app::{AppState, PutOptions};
use rostdav_core::{Error, LogicalPath, Name};
use rostdav_meta::{NodeKind, WriteCondition};
use serde::Deserialize;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::layout::{self, enc, esc};
use crate::session::{
    Authed, LOGIN_COOKIE, SESSION_COOKIE, client_ip, cookie_value, same_origin, set_cookie,
};

fn message(a: &Authed, status: StatusCode, title: &str, text: &str, back: &str) -> Response {
    message_in(a, status, title, text, back, "files")
}

fn message_in(
    a: &Authed,
    status: StatusCode,
    title: &str,
    text: &str,
    back: &str,
    nav: &str,
) -> Response {
    layout::app(
        status,
        title,
        &a.theme,
        nav,
        &a.csrf,
        &format!(
            "<h1>{}</h1><p class=\"notice\" role=\"alert\">{}</p><p><a class=\"button\" href=\"{}\">Back</a></p>",
            esc(title),
            esc(text),
            esc(back)
        ),
    )
}

fn error_response(a: &Authed, e: &Error, back: &str) -> Response {
    error_response_to(a, e, back, "files")
}

pub fn error_response_to(a: &Authed, e: &Error, back: &str, nav: &str) -> Response {
    let (status, text) = match e {
        Error::NotFound => (StatusCode::NOT_FOUND, "Not found."),
        Error::Forbidden => (StatusCode::FORBIDDEN, "You may not do that."),
        Error::AlreadyExists | Error::Conflict(_) => (
            StatusCode::CONFLICT,
            "That name is already taken or not allowed here.",
        ),
        Error::QuotaExceeded => (StatusCode::INSUFFICIENT_STORAGE, "Your storage is full."),
        Error::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "The file is too large."),
        Error::BadRequest(_) | Error::Invalid(_) => (StatusCode::BAD_REQUEST, "Invalid input."),
        other => {
            tracing::error!(error = %other, cause = ?std::error::Error::source(other), "web request failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong.")
        }
    };
    message_in(a, status, "Could not complete the action", text, back, nav)
}

/// A logical path from its plain-text form (`a/b/c`, no percent-encoding).
pub fn parse_plain(raw: &str) -> Result<LogicalPath, Error> {
    let mut p = LogicalPath::root();
    for seg in raw.split('/').filter(|s| !s.is_empty()) {
        p = p.join(&Name::parse(seg)?);
    }
    Ok(p)
}

pub fn plain(p: &LogicalPath) -> String {
    p.segments()
        .iter()
        .map(Name::as_str)
        .collect::<Vec<_>>()
        .join("/")
}

pub fn url_of(prefix: &str, p: &LogicalPath) -> String {
    let mut s = prefix.to_owned();
    for seg in p.segments() {
        s.push('/');
        s.push_str(&enc(seg.as_str()));
    }
    s
}

pub fn human(n: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

pub fn date(secs: i64) -> String {
    // "2026-01-02T03:04:05Z" -> "2026-01-02 03:04"
    rostdav_core::time::rfc3339(secs)
        .replace('T', " ")
        .chars()
        .take(16)
        .collect()
}

// ---- sign-in ---------------------------------------------------------------------------

fn login_form(
    state: &AppState,
    user: &str,
    error: Option<&str>,
    status: StatusCode,
    headers: &HeaderMap,
) -> Response {
    let (cookie, form) = state.login_csrf_issue();
    let err = error
        .map(|e| format!("<div class=\"notice\" role=\"alert\">{}</div>", esc(e)))
        .unwrap_or_default();
    let mut r = layout::bare(
        status,
        "Sign in",
        &format!(
            "<div class=\"card\"><div class=\"brand\">rost<b>dav</b></div><h1>Sign in</h1>{err}\
             <form method=\"post\" action=\"/login\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
             <label>Username<input type=\"text\" name=\"user\" value=\"{}\" autocomplete=\"username\" required autofocus></label>\
             <label>Password<input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label>\
             <button class=\"primary\" type=\"submit\">Sign in</button></form></div>",
            esc(&form),
            esc(user)
        ),
    );
    r.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(headers, LOGIN_COOKIE, &cookie, Some(900)),
    );
    r
}

pub async fn login_show(State(state): State<AppState>, headers: HeaderMap) -> Response {
    login_form(&state, "", None, StatusCode::OK, &headers)
}

#[derive(Deserialize)]
pub struct LoginForm {
    csrf: String,
    user: String,
    password: String,
}

pub async fn login_submit(
    State(state): State<AppState>,
    parts: Parts,
    Form(f): Form<LoginForm>,
) -> Response {
    let headers = &parts.headers;
    let cookie = cookie_value(headers, LOGIN_COOKIE).unwrap_or_default();
    if !same_origin(headers) || state.login_csrf_check(&cookie, &f.csrf).is_err() {
        return login_form(
            &state,
            &f.user,
            Some("The form could not be verified. Try again."),
            StatusCode::FORBIDDEN,
            headers,
        );
    }
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match state
        .web_sign_in(&f.user, &f.password, client_ip(&parts), ua)
        .await
    {
        Ok((token, _)) => {
            let mut r = Redirect::to("/files").into_response();
            let h = r.headers_mut();
            h.append(
                header::SET_COOKIE,
                set_cookie(headers, SESSION_COOKIE, &token, None),
            );
            h.append(
                header::SET_COOKIE,
                set_cookie(headers, LOGIN_COOKIE, "", Some(0)),
            );
            r
        }
        Err(Error::RateLimited { retry_after_secs }) => {
            let mut r = login_form(
                &state,
                &f.user,
                Some(&format!(
                    "Too many attempts. Try again in {} minutes.",
                    retry_after_secs.div_ceil(60)
                )),
                StatusCode::TOO_MANY_REQUESTS,
                headers,
            );
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                r.headers_mut().insert(header::RETRY_AFTER, v);
            }
            r
        }
        Err(Error::Unauthenticated) => login_form(
            &state,
            &f.user,
            Some("Wrong username or password."),
            StatusCode::UNAUTHORIZED,
            headers,
        ),
        Err(e) => {
            tracing::error!(error = %e, "sign-in failed");
            login_form(
                &state,
                &f.user,
                Some("Something went wrong."),
                StatusCode::INTERNAL_SERVER_ERROR,
                headers,
            )
        }
    }
}

#[derive(Deserialize)]
pub struct CsrfOnly {
    csrf: String,
}

pub async fn logout(
    State(state): State<AppState>,
    a: Authed,
    headers: HeaderMap,
    Form(f): Form<CsrfOnly>,
) -> Response {
    if state.web_check_csrf(a.session.id, &f.csrf).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let _ = state.web_sign_out(&a.session).await;
    let mut r = Redirect::to("/login").into_response();
    r.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(&headers, SESSION_COOKIE, "", Some(0)),
    );
    r
}

pub async fn root() -> Redirect {
    Redirect::to("/files")
}

// ---- files ------------------------------------------------------------------------------

pub async fn files_root(state: State<AppState>, a: Authed) -> Response {
    browse(state, a, String::new()).await
}

pub async fn files_path(state: State<AppState>, a: Authed, Path(path): Path<String>) -> Response {
    browse(state, a, path).await
}

async fn browse(State(state): State<AppState>, a: Authed, raw: String) -> Response {
    let p = &a.session.principal;
    let path = match LogicalPath::from_url_path(&raw) {
        Ok(path) => path,
        Err(e) => return error_response(&a, &e, "/files"),
    };
    let list = match state.list(p, &path).await {
        Ok(l) => l,
        Err(e) => return error_response(&a, &e, "/files"),
    };
    let mut crumbs = String::from("<a href=\"/files\">All files</a>");
    let mut acc = LogicalPath::root();
    for seg in path.segments() {
        acc = acc.join(seg);
        crumbs.push_str(&format!(
            " / <a href=\"{}\">{}</a>",
            esc(&url_of("/files", &acc)),
            esc(seg.as_str())
        ));
    }

    // (name, kind, size, mtime)
    let mut rows: Vec<(String, NodeKind, i64, i64)> = list
        .children
        .iter()
        .map(|n| (n.name.clone(), n.kind, n.size, n.mtime))
        .collect();
    rows.extend(
        list.mounts
            .iter()
            .map(|m| (m.name.clone(), m.node.kind, m.node.size, m.node.mtime)),
    );
    rows.sort_by(|x, y| {
        (x.1 == NodeKind::File, x.0.to_lowercase())
            .cmp(&(y.1 == NodeKind::File, y.0.to_lowercase()))
    });

    let mut table = String::new();
    for (name, kind, size, mtime) in &rows {
        let Ok(n) = Name::parse(name) else { continue };
        let child = path.join(&n);
        let (link, size_txt) = match kind {
            NodeKind::Dir => (url_of("/files", &child), String::new()),
            NodeKind::File => (url_of("/download", &child), human(*size)),
        };
        table.push_str(&format!(
            "<tr><td><a href=\"{}\">{}{}</a></td><td class=\"num\">{}</td><td class=\"hide\">{}</td>\
             <td class=\"num\"><a class=\"button\" href=\"/action/delete?path={}\">Delete</a></td></tr>",
            esc(&link),
            esc(name),
            if *kind == NodeKind::Dir { "/" } else { "" },
            size_txt,
            date(*mtime),
            esc(&enc(&plain(&child))),
        ));
    }
    let listing = if rows.is_empty() {
        "<div class=\"empty\">This folder is empty.</div>".to_owned()
    } else {
        format!(
            "<table><thead><tr><th>Name</th><th class=\"num\">Size</th><th class=\"hide\">Modified</th><th></th></tr></thead><tbody>{table}</tbody></table>"
        )
    };
    let dir = esc(&plain(&path));
    let csrf = esc(&a.csrf);
    let body = format!(
        "<h1>Files</h1><div class=\"crumbs\">{crumbs}</div>\
         <div class=\"actions\">\
         <form class=\"inline\" method=\"post\" action=\"/action/mkdir\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input type=\"hidden\" name=\"dir\" value=\"{dir}\"><input type=\"text\" name=\"name\" placeholder=\"New folder\" aria-label=\"Folder name\" required>\
         <button type=\"submit\">Create folder</button></form>\
         <form class=\"inline\" method=\"post\" action=\"/action/upload\" enctype=\"multipart/form-data\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"dir\" value=\"{dir}\">\
         <input type=\"file\" name=\"file\" aria-label=\"File\" required><button class=\"primary\" type=\"submit\">Upload</button></form>\
         </div>{listing}"
    );
    layout::app(StatusCode::OK, "Files", &a.theme, "files", &a.csrf, &body)
}

pub async fn download(
    State(state): State<AppState>,
    a: Authed,
    Path(raw): Path<String>,
) -> Response {
    let path = match LogicalPath::from_url_path(&raw) {
        Ok(p) => p,
        Err(e) => return error_response(&a, &e, "/files"),
    };
    match state.read(&a.session.principal, &path).await {
        Ok((node, file)) => attachment(&node, file),
        Err(e) => error_response(&a, &e, "/files"),
    }
}

/// A file as a forced download: never rendered by the browser.
pub fn attachment(node: &rostdav_meta::Node, file: tokio::fs::File) -> Response {
    let mut r = Response::new(Body::from_stream(ReaderStream::new(file)));
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from(node.size.max(0) as u64),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let fname: String = node
        .name
        .chars()
        .filter(|c| c.is_ascii_graphic() && !['"', '\\', ';', '%'].contains(c))
        .collect();
    if let Ok(v) = HeaderValue::from_str(&format!(
        "attachment; filename=\"{}\"; filename*=UTF-8''{}",
        if fname.is_empty() { "download" } else { &fname },
        enc(&node.name)
    )) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    r
}

fn back_to(dir: &LogicalPath) -> String {
    url_of("/files", dir)
}

#[derive(Deserialize)]
pub struct MkdirForm {
    csrf: String,
    dir: String,
    name: String,
}

pub async fn mkdir(State(state): State<AppState>, a: Authed, Form(f): Form<MkdirForm>) -> Response {
    if state.web_check_csrf(a.session.id, &f.csrf).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let dir = match parse_plain(&f.dir) {
        Ok(d) => d,
        Err(e) => return error_response(&a, &e, "/files"),
    };
    let back = back_to(&dir);
    let res = async {
        let target = dir.join(&Name::parse(f.name.trim())?);
        state.mkcol(&a.session.principal, &target).await
    }
    .await;
    match res {
        Ok(_) => Redirect::to(&back).into_response(),
        Err(e) => error_response(&a, &e, &back),
    }
}

pub async fn upload(State(state): State<AppState>, a: Authed, mut mp: Multipart) -> Response {
    // The CSRF field and the target folder come before the file.
    let mut csrf = None;
    let mut dir = None;
    loop {
        let field = match mp.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => {
                return message(
                    &a,
                    StatusCode::BAD_REQUEST,
                    "Could not upload",
                    "No file was sent.",
                    "/files",
                );
            }
            Err(_) => {
                return message(
                    &a,
                    StatusCode::BAD_REQUEST,
                    "Could not upload",
                    "The upload was malformed.",
                    "/files",
                );
            }
        };
        match field.name() {
            Some("csrf") => csrf = field.text().await.ok(),
            Some("dir") => dir = field.text().await.ok(),
            Some("file") => {
                if state
                    .web_check_csrf(a.session.id, csrf.as_deref().unwrap_or(""))
                    .is_err()
                {
                    return StatusCode::FORBIDDEN.into_response();
                }
                let Ok(dir) = parse_plain(dir.as_deref().unwrap_or("")) else {
                    return error_response(&a, &Error::BadRequest("path"), "/files");
                };
                let back = back_to(&dir);
                let Some(fname) = field.file_name().map(str::to_owned) else {
                    return error_response(&a, &Error::BadRequest("name"), &back);
                };
                let res = async {
                    let target = dir.join(&Name::parse(&fname)?);
                    let stream = ByteStream(field);
                    let reader = StreamReader::new(stream);
                    let opts = PutOptions {
                        mtime: None,
                        client_checksum: None,
                        cond: Some(WriteCondition::None),
                    };
                    state
                        .put_ext(&a.session.principal, &target, reader, &opts)
                        .await
                }
                .await;
                return match res {
                    Ok(_) => Redirect::to(&back).into_response(),
                    Err(e) => error_response(&a, &e, &back),
                };
            }
            _ => {}
        }
    }
}

/// Adapts a multipart field to a byte stream for `StreamReader`.
pub struct ByteStream<'a>(pub axum::extract::multipart::Field<'a>);

impl Stream for ByteStream<'_> {
    type Item = Result<axum::body::Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;
        let fut = self.0.chunk();
        tokio::pin!(fut);
        match fut.poll(cx) {
            Poll::Ready(Ok(Some(b))) => Poll::Ready(Some(Ok(b))),
            Poll::Ready(Ok(None)) => Poll::Ready(None),
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(std::io::Error::other(e.to_string())))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Deserialize)]
pub struct PathQuery {
    path: String,
}

pub async fn delete_confirm(a: Authed, Query(q): Query<PathQuery>) -> Response {
    let path = match parse_plain(&q.path) {
        Ok(p) => p,
        Err(e) => return error_response(&a, &e, "/files"),
    };
    let Some((parent, name)) = path.split_last() else {
        return error_response(&a, &Error::BadRequest("root"), "/files");
    };
    let back = back_to(&parent);
    let body = format!(
        "<h1>Delete “{}”?</h1><form method=\"post\" action=\"/action/delete\" class=\"inline\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"path\" value=\"{}\">\
         <button class=\"danger\" type=\"submit\">Delete</button><a class=\"button\" href=\"{}\">Cancel</a></form>",
        esc(name.as_str()),
        esc(&a.csrf),
        esc(&plain(&path)),
        esc(&back)
    );
    layout::app(StatusCode::OK, "Delete", &a.theme, "files", &a.csrf, &body)
}

#[derive(Deserialize)]
pub struct DeleteForm {
    csrf: String,
    path: String,
}

pub async fn delete(
    State(state): State<AppState>,
    a: Authed,
    Form(f): Form<DeleteForm>,
) -> Response {
    if state.web_check_csrf(a.session.id, &f.csrf).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let path = match parse_plain(&f.path) {
        Ok(p) => p,
        Err(e) => return error_response(&a, &e, "/files"),
    };
    let back = path
        .split_last()
        .map_or_else(|| "/files".to_owned(), |(p, _)| back_to(&p));
    match state.delete(&a.session.principal, &path, None).await {
        Ok(()) => Redirect::to(&back).into_response(),
        Err(e) => error_response(&a, &e, &back),
    }
}
