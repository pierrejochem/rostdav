//! Two-factor authentication pages (ADR 0007): the second sign-in step, setup,
//! turning off and new recovery codes.

use axum::Form;
use axum::extract::{Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use rostdav_app::AppState;
use rostdav_core::Error;
use serde::Deserialize;

use crate::i18n::{Lang, t, tf};
use crate::layout::{self, esc};
use crate::pages::error_response_to;
use crate::session::{
    Authed, LOGIN_COOKIE, SESSION_COOKIE, TWOFA_COOKIE, accept_lang, client_ip, cookie_value,
    same_origin, set_cookie, set_cookie_at,
};
use crate::ui;

fn forbidden() -> Response {
    StatusCode::FORBIDDEN.into_response()
}

fn csrf_ok(state: &AppState, a: &Authed, given: &str) -> bool {
    state.web_check_csrf(a.session.id, given).is_ok()
}

/// The card of the second sign-in step (design "Second factor"), used by the web
/// sign-in and by the Login Flow page. `action` is where the form posts to;
/// `hidden` carries extra fields (ticket, flow action).
#[derive(Clone, Copy)]
pub struct StepCard<'a> {
    pub action: &'a str,
    pub csrf: &'a str,
    pub hidden: &'a str,
    pub recovery: bool,
    pub error: Option<&'a str>,
    pub submit_label: &'a str,
    pub toggle_href: &'a str,
    pub client: Option<&'a str>,
}

pub fn second_step_card(lang: Lang, c: &StepCard<'_>) -> String {
    let StepCard {
        action,
        csrf,
        hidden,
        recovery,
        error,
        submit_label,
        toggle_href,
        client,
    } = *c;
    let err = error
        .map(|e| format!("<div class=\"err\" role=\"alert\">{}</div>", esc(e)))
        .unwrap_or_default();
    let (heading, lead, field) = if recovery {
        (
            "Recovery code",
            "Each code works only once. Afterwards you see how many are left.",
            format!(
                "<label>{}<input class=\"codeinput small\" type=\"text\" name=\"code\" autocomplete=\"off\" \
                 placeholder=\"xxxx-xxxx-xxxx\" required autofocus></label>",
                esc(&t(lang, "Recovery code"))
            ),
        )
    } else {
        (
            "Confirm your sign-in",
            "Enter the six-digit code from your authenticator app.",
            format!(
                "<label>{}<input class=\"codeinput\" type=\"text\" name=\"code\" inputmode=\"numeric\" \
                 autocomplete=\"one-time-code\" maxlength=\"7\" placeholder=\"000000\" required autofocus></label>",
                esc(&t(lang, "Code from your authenticator app"))
            ),
        )
    };
    let toggle_text = t(
        lang,
        if recovery {
            "Use the authenticator app instead"
        } else {
            "No access to the app? Use a recovery code"
        },
    );
    // "button:<action>" = a submit button of the same form (the Login Flow page keeps its
    // state in the form, not in the address); otherwise a link
    let toggle_link = match toggle_href.strip_prefix("button:") {
        Some(action) => format!(
            "<button class=\"linkbtn\" type=\"submit\" name=\"action\" value=\"{}\" formnovalidate form=\"second-step\">{}</button>",
            esc(action),
            esc(&toggle_text)
        ),
        None => format!("<a href=\"{}\">{}</a>", esc(toggle_href), esc(&toggle_text)),
    };
    let who = client
        .map(|c| format!("<span>{}</span>", esc(c)))
        .unwrap_or_default();
    format!(
        "<div class=\"card\"><div class=\"stepline\"><span class=\"chip\">{}</span>{who}</div>\
         <div><h1>{}</h1><p>{}</p></div>{err}\
         <form id=\"second-step\" method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">{hidden}{field}\
         <button class=\"primary\" type=\"submit\" name=\"action\" value=\"second\">{}</button></form>\
         {}\
         <div class=\"note\">{}</div></div>",
        esc(&t(lang, "Step 2 of 2")),
        esc(&t(lang, heading)),
        esc(&t(lang, lead)),
        esc(action),
        esc(csrf),
        esc(submit_label),
        toggle_link,
        esc(&t(
            lang,
            "After five wrong codes, sign-in is locked for a few minutes."
        )),
    )
}

pub fn code_error_text(lang: Lang, e: &Error) -> (StatusCode, String) {
    match e {
        Error::RateLimited { retry_after_secs } => (
            StatusCode::TOO_MANY_REQUESTS,
            tf(
                lang,
                "Too many attempts. Try again in {0} minutes.",
                &[&retry_after_secs.div_ceil(60).to_string()],
            ),
        ),
        Error::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            t(lang, "That code is wrong or has been used already."),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            t(lang, "Something went wrong."),
        ),
    }
}

// ---- second step of the web sign-in -----------------------------------------------------------

fn second_step_page(
    state: &AppState,
    headers: &HeaderMap,
    recovery: bool,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let lang = accept_lang(headers);
    let (cookie, csrf) = state.login_csrf_issue();
    let toggle = if recovery {
        "/login/2fa"
    } else {
        "/login/2fa?recovery=1"
    };
    let mut r = layout::bare(
        lang,
        status,
        "Confirm your sign-in",
        &format!(
            "<div class=\"brand\">rost<b>dav</b></div>{}<p class=\"foot\"><a href=\"/login\">{}</a></p>",
            second_step_card(
                lang,
                &StepCard {
                    action: "/login/2fa",
                    csrf: &csrf,
                    hidden: "",
                    recovery,
                    error,
                    submit_label: &t(lang, "Confirm and sign in"),
                    toggle_href: toggle,
                    client: None,
                },
            ),
            esc(&t(lang, "Back to sign-in"))
        ),
    );
    r.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(headers, LOGIN_COOKIE, &cookie, Some(900)),
    );
    r
}

#[derive(Deserialize, Default)]
pub struct StepQuery {
    #[serde(default)]
    recovery: String,
}

pub async fn login_second_show(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<StepQuery>,
) -> Response {
    let ticket = cookie_value(&headers, TWOFA_COOKIE).unwrap_or_default();
    if !state.web_ticket_valid(&ticket) {
        return Redirect::to("/login").into_response();
    }
    second_step_page(&state, &headers, q.recovery == "1", None, StatusCode::OK)
}

#[derive(Deserialize)]
pub struct StepForm {
    csrf: String,
    code: String,
}

pub async fn login_second_submit(
    State(state): State<AppState>,
    parts: Parts,
    Form(f): Form<StepForm>,
) -> Response {
    let headers = &parts.headers;
    let lang = accept_lang(headers);
    let ticket = cookie_value(headers, TWOFA_COOKIE).unwrap_or_default();
    if !state.web_ticket_valid(&ticket) {
        return Redirect::to("/login").into_response();
    }
    let cookie = cookie_value(headers, LOGIN_COOKIE).unwrap_or_default();
    if !same_origin(headers) || state.login_csrf_check(&cookie, &f.csrf).is_err() {
        return second_step_page(
            &state,
            headers,
            false,
            Some(&t(lang, "The form could not be verified. Try again.")),
            StatusCode::FORBIDDEN,
        );
    }
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match state
        .web_second_factor(&ticket, &f.code, client_ip(&parts), ua)
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
            h.append(
                header::SET_COOKIE,
                set_cookie_at(headers, TWOFA_COOKIE, "", "/login", Some(0)),
            );
            r
        }
        Err(e) => {
            let (status, text) = code_error_text(lang, &e);
            let recovery = f.code.trim().len() > 7;
            let mut r = second_step_page(&state, headers, recovery, Some(&text), status);
            if let Error::RateLimited { retry_after_secs } = e {
                if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                    r.headers_mut().insert(header::RETRY_AFTER, v);
                }
            }
            r
        }
    }
}

// ---- setup -------------------------------------------------------------------------------------

fn codes_card(lang: Lang, codes: &[String]) -> String {
    let items: String = codes
        .iter()
        .map(|c| format!("<li><code>{}</code></li>", esc(c)))
        .collect();
    format!(
        "<div class=\"notice\" role=\"status\">{}</div><ul class=\"codes\">{items}</ul>\
         <p><a class=\"button primary\" href=\"/devices\">{}</a></p>",
        esc(&t(
            lang,
            "Save these recovery codes somewhere safe. Each works once, and they are not shown again."
        )),
        esc(&t(lang, "Done"))
    )
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

pub async fn setup_page(State(state): State<AppState>, a: Authed) -> Response {
    setup_view(&state, &a, None, StatusCode::OK).await
}

async fn setup_view(
    state: &AppState,
    a: &Authed,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let lang = a.lang;
    let setup = match state.two_factor_begin(&a.session.principal).await {
        Ok(s) => s,
        Err(Error::Conflict(_)) => return Redirect::to("/devices").into_response(),
        Err(Error::Unavailable) => {
            return crate::pages::message_in(
                a,
                StatusCode::NOT_FOUND,
                "Two-factor authentication",
                "Two-factor authentication is not available on this server.",
                "/devices",
                "devices",
            );
        }
        Err(e) => return error_response_to(a, &e, "/devices", "devices"),
    };
    let err = error
        .map(|e| format!("<div class=\"err\" role=\"alert\">{}</div>", esc(e)))
        .unwrap_or_default();
    let body = format!(
        "{}{}",
        ui::page_head(
            lang,
            "Set up two-factor authentication",
            "Scan the code with an authenticator app, then enter the six-digit code it shows.",
            ""
        ),
        ui::card(
            lang,
            "Authenticator app",
            "",
            &format!(
                "{err}<div class=\"qr\" role=\"img\" aria-label=\"{}\">{}</div>\
                 <p class=\"muted\">{}</p><p><code>{}</code></p>\
                 <form class=\"stack-form\" method=\"post\" action=\"/settings/2fa\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                 <label>{}<input class=\"codeinput\" type=\"text\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" maxlength=\"7\" placeholder=\"000000\" required></label>\
                 <p class=\"muted\">{}</p>\
                 <div class=\"actions\"><button class=\"primary\" type=\"submit\">{}</button><a class=\"button\" href=\"/devices\">{}</a></div></form>",
                esc(&t(lang, "QR code for the authenticator app")),
                setup.qr_svg,
                esc(&t(lang, "Cannot scan? Enter this key in the app instead:")),
                esc(&setup.secret),
                esc(&a.csrf),
                esc(&t(lang, "Code from your authenticator app")),
                esc(&t(
                    lang,
                    "Once it is on, WebDAV clients must use app passwords; your account password stops working there."
                )),
                esc(&t(lang, "Turn on")),
                esc(&t(lang, "Cancel"))
            )
        )
    );
    no_store(ui::page(
        a,
        status,
        "Set up two-factor authentication",
        "devices",
        &body,
    ))
}

#[derive(Deserialize)]
pub struct ConfirmForm {
    csrf: String,
    code: String,
}

pub async fn setup_confirm(
    State(state): State<AppState>,
    a: Authed,
    parts: Parts,
    Form(f): Form<ConfirmForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let lang = a.lang;
    match state
        .two_factor_confirm(&a.session.principal, &f.code, client_ip(&parts))
        .await
    {
        Ok(codes) => {
            let body = format!(
                "{}{}",
                ui::page_head(
                    lang,
                    "Two-factor authentication is on",
                    "From now on, signing in in the browser asks for a code.",
                    ""
                ),
                ui::card(lang, "Recovery codes", "", &codes_card(lang, &codes))
            );
            no_store(ui::page(
                &a,
                StatusCode::OK,
                "Two-factor authentication is on",
                "devices",
                &body,
            ))
        }
        Err(e @ (Error::Unauthenticated | Error::RateLimited { .. })) => {
            let (status, text) = code_error_text(lang, &e);
            setup_view(&state, &a, Some(&text), status).await
        }
        Err(e) => error_response_to(&a, &e, "/devices", "devices"),
    }
}

// ---- turning off and new recovery codes ----------------------------------------------------------

const DISABLE: Reauth<'static> = Reauth {
    action: "/settings/2fa/disable",
    heading: "Turn off two-factor authentication",
    lede: "Enter your password and a current code to confirm.",
    button: "Turn off",
    danger: true,
    error: None,
    status: StatusCode::OK,
};

const CODES: Reauth<'static> = Reauth {
    action: "/settings/2fa/codes",
    heading: "New recovery codes",
    lede: "The old codes stop working. Enter your password and a current code to confirm.",
    button: "Create new codes",
    danger: false,
    error: None,
    status: StatusCode::OK,
};

#[derive(Clone, Copy)]
struct Reauth<'a> {
    action: &'a str,
    heading: &'a str,
    lede: &'a str,
    button: &'a str,
    danger: bool,
    error: Option<&'a str>,
    status: StatusCode,
}

fn reauth_form(a: &Authed, r: &Reauth<'_>) -> Response {
    let Reauth {
        action,
        heading,
        lede,
        button,
        danger,
        error,
        status,
    } = *r;
    let lang = a.lang;
    let err = error
        .map(|e| format!("<div class=\"err\" role=\"alert\">{}</div>", esc(e)))
        .unwrap_or_default();
    let form = format!(
        "{err}<form class=\"stack-form\" method=\"post\" action=\"{action}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
         <label>{}<input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label>\
         <label>{}<input class=\"codeinput small\" type=\"text\" name=\"code\" autocomplete=\"one-time-code\" required></label>\
         <div class=\"actions\"><button class=\"{}\" type=\"submit\">{}</button><a class=\"button\" href=\"/devices\">{}</a></div></form>",
        esc(&a.csrf),
        esc(&t(lang, "Password")),
        esc(&t(
            lang,
            "Code from your authenticator app, or a recovery code"
        )),
        if danger { "danger" } else { "primary" },
        esc(&t(lang, button)),
        esc(&t(lang, "Cancel"))
    );
    let body = format!(
        "{}{}",
        ui::page_head(lang, heading, lede, ""),
        ui::card(lang, heading, "", &form)
    );
    no_store(ui::page(a, status, heading, "devices", &body))
}

pub async fn disable_page(a: Authed) -> Response {
    reauth_form(&a, &DISABLE)
}

pub async fn codes_page(a: Authed) -> Response {
    reauth_form(&a, &CODES)
}

#[derive(Deserialize)]
pub struct ReauthForm {
    csrf: String,
    password: String,
    code: String,
}

pub async fn disable_submit(
    State(state): State<AppState>,
    a: Authed,
    parts: Parts,
    Form(f): Form<ReauthForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let lang = a.lang;
    match state
        .two_factor_disable(&a.session, &f.password, &f.code, client_ip(&parts))
        .await
    {
        Ok(()) => Redirect::to("/devices").into_response(),
        Err(e @ (Error::Unauthenticated | Error::RateLimited { .. })) => {
            let (status, text) = reauth_error(lang, &e);
            reauth_form(
                &a,
                &Reauth {
                    error: Some(&text),
                    status,
                    ..DISABLE
                },
            )
        }
        Err(e) => error_response_to(&a, &e, "/devices", "devices"),
    }
}

pub async fn codes_submit(
    State(state): State<AppState>,
    a: Authed,
    parts: Parts,
    Form(f): Form<ReauthForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return forbidden();
    }
    let lang = a.lang;
    match state
        .two_factor_regenerate(&a.session, &f.password, &f.code, client_ip(&parts))
        .await
    {
        Ok(codes) => {
            let body = format!(
                "{}{}",
                ui::page_head(
                    lang,
                    "New recovery codes",
                    "The old codes no longer work.",
                    ""
                ),
                ui::card(lang, "Recovery codes", "", &codes_card(lang, &codes))
            );
            no_store(ui::page(
                &a,
                StatusCode::OK,
                "New recovery codes",
                "devices",
                &body,
            ))
        }
        Err(e @ (Error::Unauthenticated | Error::RateLimited { .. })) => {
            let (status, text) = reauth_error(lang, &e);
            reauth_form(
                &a,
                &Reauth {
                    error: Some(&text),
                    status,
                    ..CODES
                },
            )
        }
        Err(e) => error_response_to(&a, &e, "/devices", "devices"),
    }
}

fn reauth_error(lang: Lang, e: &Error) -> (StatusCode, String) {
    match e {
        Error::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            t(lang, "The password or the code is wrong."),
        ),
        other => code_error_text(lang, other),
    }
}
