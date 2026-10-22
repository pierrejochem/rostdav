//! Public link page `/s/<token>` (ADR 0006): list, download, password form, upload.

use axum::Form;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use rostdav_app::{AppState, PutOptions};
use rostdav_core::{Error, LogicalPath, Name};
use rostdav_meta::{NodeKind, WriteCondition};
use serde::Deserialize;
use tokio_util::io::StreamReader;

use crate::i18n::{Lang, t, tf};
use crate::layout::{self, enc, esc};
use crate::pages::{ByteStream, date, human, parse_plain, plain};
use crate::session::{
    LOGIN_COOKIE, accept_lang, client_ip, cookie_value, same_origin, set_cookie, set_cookie_at,
};

const TICKET_COOKIE: &str = "rostdav_link";

fn gone(lang: Lang) -> Response {
    layout::public(
        lang,
        StatusCode::NOT_FOUND,
        "Link not found",
        &format!(
            "<div class=\"card\"><h1>{}</h1><p class=\"muted\">{}</p></div>",
            esc(&t(lang, "Link not found")),
            esc(&t(lang, "This link does not exist or has expired."))
        ),
    )
}

fn notice(lang: Lang, status: StatusCode, token: &str, text: &str) -> Response {
    layout::public(
        lang,
        status,
        "Public link",
        &format!(
            "<div class=\"card\"><p class=\"notice\" role=\"alert\">{}</p><a class=\"button\" href=\"/s/{}\">{}</a></div>",
            esc(&t(lang, text)),
            enc(token),
            esc(&t(lang, "Back"))
        ),
    )
}

fn error_page(lang: Lang, token: &str, e: &Error) -> Response {
    let (status, text) = match e {
        Error::NotFound => (StatusCode::NOT_FOUND, "Not found."),
        Error::Forbidden => (StatusCode::FORBIDDEN, "This link does not allow that."),
        Error::AlreadyExists | Error::Conflict(_) => (
            StatusCode::CONFLICT,
            "That name is already taken or not allowed here.",
        ),
        Error::QuotaExceeded => (StatusCode::INSUFFICIENT_STORAGE, "There is no space left."),
        Error::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "The file is too large."),
        Error::BadRequest(_) | Error::Invalid(_) => (StatusCode::BAD_REQUEST, "Invalid input."),
        other => {
            tracing::error!(error = %other, "public link request failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong.")
        }
    };
    notice(lang, status, token, text)
}

fn ticket(headers: &HeaderMap, token: &str) -> Option<String> {
    cookie_value(headers, TICKET_COOKIE)
        .and_then(|v| v.strip_prefix(&format!("{token}_")).map(str::to_owned))
}

/// Anonymous CSRF pair: cookie value, form value.
fn csrf_pair(state: &AppState) -> (String, String) {
    state.login_csrf_issue()
}

fn password_form(
    lang: Lang,
    state: &AppState,
    token: &str,
    headers: &HeaderMap,
    status: StatusCode,
    err: Option<&str>,
) -> Response {
    let (cookie, form) = csrf_pair(state);
    let err = err
        .map(|e| format!("<div class=\"notice\" role=\"alert\">{}</div>", esc(e)))
        .unwrap_or_default();
    let mut r = layout::public(
        lang,
        status,
        "Password required",
        &format!(
            "<div class=\"card\"><h1>{}</h1>{err}\
             <form method=\"post\" action=\"/s/{}/unlock\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
             <label>{}<input type=\"password\" name=\"password\" autocomplete=\"off\" required autofocus></label>\
             <button class=\"primary\" type=\"submit\">{}</button></form></div>",
            esc(&t(lang, "Password required")),
            enc(token),
            esc(&form),
            esc(&t(lang, "Password")),
            esc(&t(lang, "Open"))
        ),
    );
    r.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(headers, LOGIN_COOKIE, &cookie, Some(900)),
    );
    r
}

#[derive(Deserialize)]
pub struct ViewQuery {
    #[serde(default)]
    path: String,
}

pub async fn view(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Query(q): Query<ViewQuery>,
    headers: HeaderMap,
) -> Response {
    let lang = accept_lang(&headers);
    let p = match state
        .link_page_principal(&token, ticket(&headers, &token).as_deref())
        .await
    {
        Ok(p) => p,
        Err(Error::NotFound) => return gone(lang),
        Err(Error::Unauthenticated) => {
            return password_form(lang, &state, &token, &headers, StatusCode::OK, None);
        }
        Err(e) => return error_page(lang, &token, &e),
    };
    let rostdav_app::Scope::Link { perms, .. } = p.scope else {
        return gone(lang);
    };
    let path = match parse_plain(&q.path) {
        Ok(path) => path,
        Err(e) => return error_page(lang, &token, &e),
    };
    let (cookie, csrf) = csrf_pair(&state);

    let can_read = perms & 1 != 0;
    let mut rows = String::new();
    let mut is_dir = true;
    if can_read {
        match state.stat(&p, &path).await {
            Ok(n) if n.kind == NodeKind::File => is_dir = false,
            Ok(_) => {}
            Err(e) => return error_page(lang, &token, &e),
        }
    }
    let tok = enc(&token);
    let mut body = String::new();
    if can_read && is_dir {
        let list = match state.list(&p, &path).await {
            Ok(l) => l,
            Err(e) => return error_page(lang, &token, &e),
        };
        let mut items: Vec<_> = list.children.iter().collect();
        items.sort_by(|x, y| {
            (x.kind == NodeKind::File, x.name.to_lowercase())
                .cmp(&(y.kind == NodeKind::File, y.name.to_lowercase()))
        });
        for n in items {
            let Ok(name) = Name::parse(&n.name) else {
                continue;
            };
            let child = path.join(&name);
            let (href, size) = match n.kind {
                NodeKind::Dir => (
                    format!("/s/{tok}?path={}", enc(&plain(&child))),
                    String::new(),
                ),
                NodeKind::File => (
                    format!("/s/{tok}/dl?path={}", enc(&plain(&child))),
                    human(n.size),
                ),
            };
            rows.push_str(&format!(
                "<tr><td><a href=\"{}\">{}{}</a></td><td class=\"num\">{}</td><td class=\"hide\">{}</td></tr>",
                esc(&href),
                esc(&n.name),
                if n.kind == NodeKind::Dir { "/" } else { "" },
                size,
                date(n.mtime)
            ));
        }
        let mut crumbs = format!(
            "<a href=\"/s/{tok}\">{}</a>",
            esc(&t(lang, "Shared folder"))
        );
        let mut acc = LogicalPath::root();
        for seg in path.segments() {
            acc = acc.join(seg);
            crumbs.push_str(&format!(
                " / <a href=\"/s/{tok}?path={}\">{}</a>",
                esc(&enc(&plain(&acc))),
                esc(seg.as_str())
            ));
        }
        body.push_str(&format!(
            "<h1>{}</h1><div class=\"crumbs\">{crumbs}</div>",
            esc(&t(lang, "Shared files"))
        ));
        body.push_str(&if rows.is_empty() {
            format!("<div class=\"empty\">{}</div>", esc(&t(lang, "This folder is empty.")))
        } else {
            format!(
                "<table><thead><tr><th>{}</th><th class=\"num\">{}</th><th class=\"hide\">{}</th></tr></thead><tbody>{rows}</tbody></table>",
                esc(&t(lang, "Name")),
                esc(&t(lang, "Size")),
                esc(&t(lang, "Modified"))
            )
        });
    } else if can_read {
        let name = path
            .split_last()
            .map_or_else(String::new, |(_, n)| n.as_str().to_owned());
        body.push_str(&format!(
            "<h1>{}</h1><p><a class=\"button primary\" href=\"/s/{tok}/dl?path={}\">{}</a></p>",
            esc(&name),
            esc(&enc(&plain(&path))),
            esc(&t(lang, "Download"))
        ));
    } else {
        body.push_str(&format!(
            "<h1>{}</h1><p class=\"muted\">{}</p>",
            esc(&t(lang, "Upload files")),
            esc(&t(lang, "This folder accepts uploads only."))
        ));
    }
    if perms & 4 != 0 && is_dir {
        body.push_str(&format!(
            "<div class=\"actions\"><form class=\"inline\" method=\"post\" action=\"/s/{tok}/upload\" enctype=\"multipart/form-data\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"dir\" value=\"{}\">\
             <input type=\"file\" name=\"file\" aria-label=\"{}\" required><button class=\"primary\" type=\"submit\">{}</button></form></div>",
            esc(&csrf),
            esc(&plain(&path)),
            esc(&t(lang, "File")),
            esc(&t(lang, "Upload"))
        ));
    }
    let mut r = layout::public(lang, StatusCode::OK, "Shared files", &body);
    r.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(&headers, LOGIN_COOKIE, &cookie, Some(900)),
    );
    r
}

#[derive(Deserialize)]
pub struct UnlockForm {
    csrf: String,
    password: String,
}

pub async fn unlock(
    State(state): State<AppState>,
    Path(token): Path<String>,
    parts: Parts,
    Form(f): Form<UnlockForm>,
) -> Response {
    let headers = &parts.headers;
    let lang = accept_lang(headers);
    let cookie = cookie_value(headers, LOGIN_COOKIE).unwrap_or_default();
    if !same_origin(headers) || state.login_csrf_check(&cookie, &f.csrf).is_err() {
        return password_form(
            lang,
            &state,
            &token,
            headers,
            StatusCode::FORBIDDEN,
            Some(&t(lang, "The form could not be verified. Try again.")),
        );
    }
    match state
        .link_unlock(&token, &f.password, client_ip(&parts))
        .await
    {
        Ok(ticket) => {
            let mut r = Redirect::to(&format!("/s/{}", enc(&token))).into_response();
            r.headers_mut().append(
                header::SET_COOKIE,
                set_cookie_at(
                    headers,
                    TICKET_COOKIE,
                    &format!("{token}_{ticket}"),
                    &format!("/s/{}", enc(&token)),
                    Some(3600),
                ),
            );
            r
        }
        Err(Error::Unauthenticated) => {
            // unknown link and wrong password look alike
            if matches!(state.link_needs_password(&token).await, Ok(None)) {
                return gone(lang);
            }
            password_form(
                lang,
                &state,
                &token,
                headers,
                StatusCode::UNAUTHORIZED,
                Some(&t(lang, "Wrong password.")),
            )
        }
        Err(Error::RateLimited { retry_after_secs }) => {
            let mut r = password_form(
                lang,
                &state,
                &token,
                headers,
                StatusCode::TOO_MANY_REQUESTS,
                Some(&tf(
                    lang,
                    "Too many attempts. Try again in {0} minutes.",
                    &[&retry_after_secs.div_ceil(60).to_string()],
                )),
            );
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                r.headers_mut().insert(header::RETRY_AFTER, v);
            }
            r
        }
        Err(e) => error_page(lang, &token, &e),
    }
}

pub async fn download(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Query(q): Query<ViewQuery>,
    headers: HeaderMap,
) -> Response {
    let lang = accept_lang(&headers);
    let p = match state
        .link_page_principal(&token, ticket(&headers, &token).as_deref())
        .await
    {
        Ok(p) => p,
        Err(Error::NotFound) => return gone(lang),
        Err(Error::Unauthenticated) => {
            return Redirect::to(&format!("/s/{}", enc(&token))).into_response();
        }
        Err(e) => return error_page(lang, &token, &e),
    };
    let path = match parse_plain(&q.path) {
        Ok(path) => path,
        Err(e) => return error_page(lang, &token, &e),
    };
    match state.read(&p, &path).await {
        Ok((node, file)) => crate::pages::attachment(&node, file),
        Err(e) => error_page(lang, &token, &e),
    }
}

pub async fn upload(
    State(state): State<AppState>,
    Path(token): Path<String>,
    parts: Parts,
    mut mp: Multipart,
) -> Response {
    let headers = &parts.headers;
    let lang = accept_lang(headers);
    if !same_origin(headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let p = match state
        .link_page_principal(&token, ticket(headers, &token).as_deref())
        .await
    {
        Ok(p) => p,
        Err(Error::NotFound) => return gone(lang),
        Err(_) => return StatusCode::FORBIDDEN.into_response(),
    };
    let cookie = cookie_value(headers, LOGIN_COOKIE).unwrap_or_default();
    let (mut csrf, mut dir) = (None, None);
    loop {
        let field = match mp.next_field().await {
            Ok(Some(f)) => f,
            _ => return notice(lang, StatusCode::BAD_REQUEST, &token, "No file was sent."),
        };
        match field.name() {
            Some("csrf") => csrf = field.text().await.ok(),
            Some("dir") => dir = field.text().await.ok(),
            Some("file") => {
                if state
                    .login_csrf_check(&cookie, csrf.as_deref().unwrap_or(""))
                    .is_err()
                {
                    return StatusCode::FORBIDDEN.into_response();
                }
                let Ok(dir) = parse_plain(dir.as_deref().unwrap_or("")) else {
                    return error_page(lang, &token, &Error::BadRequest("path"));
                };
                let Some(fname) = field.file_name().map(str::to_owned) else {
                    return error_page(lang, &token, &Error::BadRequest("name"));
                };
                let res = async {
                    let target = dir.join(&Name::parse(&fname)?);
                    let reader = StreamReader::new(ByteStream(field));
                    // never replace what the owner has: links upload new files only
                    let opts = PutOptions {
                        mtime: None,
                        client_checksum: None,
                        cond: Some(WriteCondition::MustNotExist),
                    };
                    state.put_ext(&p, &target, reader, &opts).await
                }
                .await;
                return match res {
                    Ok(_) => {
                        Redirect::to(&format!("/s/{}?path={}", enc(&token), enc(&plain(&dir))))
                            .into_response()
                    }
                    Err(e) => error_page(lang, &token, &e),
                };
            }
            _ => {}
        }
    }
}
