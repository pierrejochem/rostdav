//! The phone step of the browser sign-in (ADR 0014): the user presses "Send to my phone", the
//! page shows a number, the phone answers, and the page turns the approval into a session.
//! Every step needs the ticket of the password step; a challenge never leaves that sign-in.

use axum::Form;
use axum::extract::{Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use rostdav_app::{AppState, ChallengeStatus, MfaError};
use serde::Deserialize;

use crate::i18n::{Lang, t, tf};
use crate::layout::{self, esc};
use crate::session::{
    LOGIN_COOKIE, TWOFA_COOKIE, accept_lang, client_ip, cookie_value, same_origin, set_cookie,
};
use crate::twofactor::signed_in;

pub(crate) const PHONE_SCRIPT: &str = "<script src=\"/static/phone.js\"></script>";

fn user_agent(headers: &HeaderMap) -> &str {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// What the phone shows as the sign-in device: the browser's own description, shortened.
fn login_device(headers: &HeaderMap) -> String {
    let ua: String = user_agent(headers)
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect();
    if ua.trim().is_empty() {
        "Web browser".to_owned()
    } else {
        ua
    }
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// The step page with a message, and a new CSRF value (the old form is spent).
async fn back_to_step(
    state: &AppState,
    headers: &HeaderMap,
    status: StatusCode,
    text: &str,
) -> Response {
    let ticket = cookie_value(headers, TWOFA_COOKIE).unwrap_or_default();
    crate::twofactor::step_page(state, headers, &ticket, status, Some(text)).await
}

fn error_text(lang: Lang, e: &MfaError) -> (StatusCode, String) {
    match e {
        MfaError::NotFound => (
            StatusCode::NOT_FOUND,
            t(lang, "No phone is enrolled for this account."),
        ),
        MfaError::Expired => (
            StatusCode::GONE,
            t(lang, "The request expired. Send a new one."),
        ),
        MfaError::AlreadyConsumed => (
            StatusCode::CONFLICT,
            t(lang, "This approval was already used. Sign in again."),
        ),
        MfaError::RateLimited { .. } => (
            StatusCode::TOO_MANY_REQUESTS,
            t(lang, "Too many requests. Try again later."),
        ),
        _ => (
            StatusCode::CONFLICT,
            t(lang, "Sign-in with the phone failed."),
        ),
    }
}

#[derive(Deserialize)]
pub struct StartForm {
    csrf: String,
}

/// POST /login/2fa/phone: starts the challenge and shows the number.
pub async fn start(
    State(state): State<AppState>,
    parts: Parts,
    Form(f): Form<StartForm>,
) -> Response {
    let headers = &parts.headers;
    let lang = accept_lang(headers);
    let ticket = cookie_value(headers, TWOFA_COOKIE).unwrap_or_default();
    if !state.web_ticket_valid(&ticket) {
        return Redirect::to("/login").into_response();
    }
    let cookie = cookie_value(headers, LOGIN_COOKIE).unwrap_or_default();
    if !same_origin(headers) || state.login_csrf_check(&cookie, &f.csrf).is_err() {
        return back_to_step(
            &state,
            headers,
            StatusCode::FORBIDDEN,
            &t(lang, "The form could not be verified. Try again."),
        )
        .await;
    }
    match state
        .mfa_login_start(&ticket, "", &login_device(headers), client_ip(&parts))
        .await
    {
        Ok(c) => number_page(&state, headers, lang, &c),
        Err(MfaError::Unauthenticated) => Redirect::to("/login").into_response(),
        Err(e) => {
            let (status, text) = error_text(lang, &e);
            let mut r = back_to_step(&state, headers, status, &text).await;
            if let MfaError::RateLimited { retry_after_secs } = e
                && let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string())
            {
                r.headers_mut().insert(header::RETRY_AFTER, v);
            }
            r
        }
    }
}

/// What the number card needs besides the challenge.
pub(crate) struct NumberCard<'a> {
    pub csrf: &'a str,
    /// Where the page polls; already a safe attribute value.
    pub status_url: &'a str,
    /// Where the finish form posts to.
    pub action: &'a str,
    /// More hidden fields of the finish form (already escaped markup).
    pub hidden: &'a str,
    /// Where "Use another method" and a denied or expired request lead.
    pub back_href: &'a str,
}

/// The card with the number, the waiting area (polled by `phone.js`) and the finish form.
pub(crate) fn number_card(
    lang: Lang,
    c: &rostdav_app::LoginChallenge,
    n: &NumberCard<'_>,
) -> String {
    let id = esc(&c.challenge_id);
    format!(
        "<div class=\"card\"><div class=\"stepline\"><span class=\"chip\">{}</span></div>\
         <div><h1>{}</h1><p>{}</p></div>\
         <p class=\"phone-number\">{}</p>\
         <div class=\"phone-wait\" data-status-url=\"{}\" data-finish-form=\"phone-finish\" data-back-url=\"{}\">{}</div>\
         <form id=\"phone-finish\" method=\"post\" action=\"{}\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"id\" value=\"{id}\">{}\
         <button class=\"primary\" type=\"submit\">{}</button></form>\
         <p class=\"foot\"><a href=\"{}\">{}</a></p>\
         <div class=\"note\">{}</div></div>",
        esc(&t(lang, "Step 2 of 2")),
        esc(&t(lang, "Approve on your phone")),
        esc(&t(lang, "Pick this number on your phone:")),
        c.number,
        n.status_url,
        esc(n.back_href),
        esc(&t(lang, "Waiting for approval…")),
        esc(n.action),
        esc(n.csrf),
        n.hidden,
        esc(&t(lang, "Continue")),
        esc(n.back_href),
        esc(&t(lang, "Use another method")),
        esc(&tf(
            lang,
            "Valid for {0} seconds.",
            &[&c.expires_in_seconds.to_string()]
        )),
    )
}

/// The page for the browser sign-in (it has its own LOGIN cookie for the finish form).
fn number_page(
    state: &AppState,
    headers: &HeaderMap,
    lang: Lang,
    c: &rostdav_app::LoginChallenge,
) -> Response {
    let (cookie, csrf) = state.login_csrf_issue();
    let status_url = format!("/login/2fa/phone/status?id={}", esc(&c.challenge_id));
    let body = number_card(
        lang,
        c,
        &NumberCard {
            csrf: &csrf,
            status_url: &status_url,
            action: "/login/2fa/phone/finish",
            hidden: "",
            back_href: "/login/2fa",
        },
    );
    let mut r = layout::bare_with(
        lang,
        StatusCode::OK,
        "Confirm your sign-in",
        &body,
        PHONE_SCRIPT,
    );
    r.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(headers, LOGIN_COOKIE, &cookie, Some(900)),
    );
    no_store(r)
}

#[derive(Deserialize)]
pub struct StatusQuery {
    #[serde(default)]
    id: String,
}

/// GET /login/2fa/phone/status?id=…: where the challenge stands, as JSON. The number is never in it.
pub async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<StatusQuery>,
) -> Response {
    let ticket = cookie_value(&headers, TWOFA_COOKIE).unwrap_or_default();
    let r = match state.mfa_login_status(&ticket, "", &q.id).await {
        Ok(s) => (
            [(header::CONTENT_TYPE, "application/json")],
            format!("{{\"status\":\"{}\"}}", ChallengeStatus::as_str(s)),
        )
            .into_response(),
        Err(MfaError::Unauthenticated) => StatusCode::UNAUTHORIZED.into_response(),
        Err(MfaError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    no_store(r)
}

#[derive(Deserialize)]
pub struct FinishForm {
    csrf: String,
    id: String,
}

/// POST /login/2fa/phone/finish: turns an approved challenge into the session, once.
pub async fn finish(
    State(state): State<AppState>,
    parts: Parts,
    Form(f): Form<FinishForm>,
) -> Response {
    let headers = &parts.headers;
    let lang = accept_lang(headers);
    let ticket = cookie_value(headers, TWOFA_COOKIE).unwrap_or_default();
    if !state.web_ticket_valid(&ticket) {
        return Redirect::to("/login").into_response();
    }
    let cookie = cookie_value(headers, LOGIN_COOKIE).unwrap_or_default();
    if !same_origin(headers) || state.login_csrf_check(&cookie, &f.csrf).is_err() {
        return back_to_step(
            &state,
            headers,
            StatusCode::FORBIDDEN,
            &t(lang, "The form could not be verified. Try again."),
        )
        .await;
    }
    match state
        .web_phone_finish(&ticket, &f.id, client_ip(&parts), user_agent(headers))
        .await
    {
        Ok((token, _)) => no_store(signed_in(headers, &token)),
        Err(MfaError::Unauthenticated) => Redirect::to("/login").into_response(),
        Err(e) => {
            // tell "not yet" and "denied" apart; both come back as a refusal
            let text = match state.mfa_login_status(&ticket, "", &f.id).await {
                Ok(ChallengeStatus::Pending) => t(lang, "Not approved yet."),
                Ok(ChallengeStatus::Denied) => t(lang, "The request was denied on the phone."),
                _ => error_text(lang, &e).1,
            };
            let status = match e {
                MfaError::Expired => StatusCode::GONE,
                MfaError::NotFound => StatusCode::NOT_FOUND,
                _ => StatusCode::CONFLICT,
            };
            back_to_step(&state, headers, status, &text).await
        }
    }
}
