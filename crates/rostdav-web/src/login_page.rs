//! Login Flow v2 page: client name, user name, password; allow or deny.
//! Layout follows `design/mockups/web-ui/Login.dc.html`.

use std::net::{IpAddr, Ipv4Addr};

use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use rostdav_app::{AppState, ChallengeStatus, MfaError};
use rostdav_core::{ClientIp, Error};
use serde::Deserialize;

use crate::i18n::{Lang, t, tf};
use crate::layout::esc;
use crate::phone_step::{NumberCard, PHONE_SCRIPT, number_card};
use crate::session::accept_lang;
use crate::twofactor::{StepCard, code_error_text, second_step_card};

fn page(lang: Lang, status: StatusCode, title: &str, body: &str) -> Response {
    crate::layout::bare(
        lang,
        status,
        title,
        &format!(
            "{body}<div class=\"foot\">{}</div>",
            esc(&t(
                lang,
                "Rostdav · compatible with Nextcloud clients · not a Nextcloud product"
            ))
        ),
    )
}

fn message(lang: Lang, status: StatusCode, title: &str, text: &str) -> Response {
    page(
        lang,
        status,
        title,
        &format!(
            "<div class=\"card\"><div><h1>{}</h1><p>{}</p></div></div>",
            esc(&t(lang, title)),
            esc(&t(lang, text))
        ),
    )
}

fn form(
    lang: Lang,
    state: &AppState,
    token: &str,
    client: &str,
    user: &str,
    error: Option<&str>,
) -> String {
    let csrf = state.flow_csrf(token, "allow");
    let err = error
        .map(|e| format!("<div class=\"err\" role=\"alert\">{}</div>", esc(e)))
        .unwrap_or_default();
    format!(
        "<div class=\"card\">\
         <div class=\"client\"><b>{client}</b><span>{}</span></div>\
         <div><h1>{}</h1><p>{}</p></div>{err}\
         <form method=\"post\" action=\"\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <label>{}<input type=\"text\" name=\"user\" value=\"{user}\" autocomplete=\"username\" required autofocus></label>\
         <label>{}<input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label>\
         <button class=\"allow\" type=\"submit\" name=\"action\" value=\"allow\">{}</button>\
         <button class=\"deny\" type=\"submit\" name=\"action\" value=\"deny\" formnovalidate>{}</button>\
         </form>\
         <div class=\"note\">{}</div></div>",
        esc(&t(lang, "wants to connect to your account")),
        esc(&t(lang, "Connect device")),
        esc(&t(
            lang,
            "Sign in to allow access. The device gets its own app password, which you can revoke at any time."
        )),
        esc(&t(lang, "Username")),
        esc(&t(lang, "Password")),
        esc(&t(lang, "Sign in and allow access")),
        esc(&t(lang, "Deny")),
        esc(&t(
            lang,
            "Check the address in your browser before entering your password. Rostdav never asks for an app password here."
        )),
        client = esc(client),
        user = esc(user),
        csrf = esc(&csrf),
    )
}

/// The second step of the flow (design "Second factor").
#[derive(Clone, Copy)]
struct Step<'a> {
    token: &'a str,
    client: &'a str,
    ticket: &'a str,
    recovery: bool,
    error: Option<&'a str>,
    status: StatusCode,
}

async fn second_page(lang: Lang, state: &AppState, s: &Step<'_>) -> Response {
    let Step {
        token,
        client,
        ticket,
        recovery,
        error,
        status,
    } = *s;
    let csrf = state.flow_csrf(token, "allow");
    let hidden = format!(
        "<input type=\"hidden\" name=\"ticket\" value=\"{}\">",
        esc(ticket)
    );
    let toggle = if recovery {
        "button:totp"
    } else {
        "button:recovery"
    };
    // a ticket that does not check out gets the code form, as before
    let opts = state
        .flow_second_step_options(token, ticket)
        .await
        .unwrap_or(rostdav_app::SecondStepOptions {
            totp: true,
            phone: false,
        });
    let phone = if opts.phone {
        let err = if opts.totp { None } else { error };
        phone_card(lang, &csrf, &hidden, client, err)
    } else {
        String::new()
    };
    let code = if opts.totp || !opts.phone {
        second_step_card(
            lang,
            &StepCard {
                action: "",
                csrf: &csrf,
                hidden: &hidden,
                recovery,
                error,
                submit_label: &t(lang, "Confirm and allow access"),
                toggle_href: toggle,
                client: Some(client),
            },
        )
    } else {
        String::new()
    };
    page(
        lang,
        status,
        "Confirm your sign-in",
        &format!("{phone}{code}"),
    )
}

/// "Send to my phone": a button of its own form (the flow keeps its state in the form).
fn phone_card(lang: Lang, csrf: &str, hidden: &str, client: &str, error: Option<&str>) -> String {
    let err = error
        .map(|e| format!("<div class=\"err\" role=\"alert\">{}</div>", esc(e)))
        .unwrap_or_default();
    format!(
        "<div class=\"card\"><div class=\"stepline\"><span class=\"chip\">{}</span><span>{}</span></div>\
         <div><h1>{}</h1><p>{}</p></div>{err}\
         <form method=\"post\" action=\"\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">{hidden}\
         <button class=\"primary\" type=\"submit\" name=\"action\" value=\"phone\">{}</button></form></div>",
        esc(&t(lang, "Step 2 of 2")),
        esc(client),
        esc(&t(lang, "Confirm your sign-in")),
        esc(&t(lang, "Approve the request on your RustMFA phone.")),
        esc(csrf),
        esc(&t(lang, "Send to my phone")),
    )
}

pub async fn show(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let lang = accept_lang(&headers);
    match state.login_flow_client(&token).await {
        Ok(Some(client)) => page(
            lang,
            StatusCode::OK,
            "Connect device",
            &form(lang, &state, &token, &client, "", None),
        ),
        Ok(None) => message(
            lang,
            StatusCode::NOT_FOUND,
            "Link invalid or expired",
            "Start the connection again from your app.",
        ),
        Err(e) => internal(lang, &e),
    }
}

#[derive(Deserialize)]
pub struct Submit {
    csrf: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
    action: String,
    /// Second step: the ticket from the password step and the code.
    #[serde(default)]
    ticket: String,
    #[serde(default)]
    code: String,
    /// Phone step: the challenge being finished.
    #[serde(default)]
    id: String,
}

pub async fn submit(
    State(state): State<AppState>,
    Path(token): Path<String>,
    parts: Parts,
    Form(f): Form<Submit>,
) -> Response {
    let lang = accept_lang(&parts.headers);
    let ip = parts
        .extensions
        .get::<ClientIp>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0);

    if f.action == "deny" {
        return match state.flow_deny(&token, &f.csrf).await {
            Ok(()) => message(
                lang,
                StatusCode::OK,
                "Access denied",
                "No device was connected. You can close this window.",
            ),
            Err(Error::Forbidden) => forbidden(lang),
            Err(e) => internal(lang, &e),
        };
    }

    if matches!(f.action.as_str(), "phone" | "phone_finish") {
        return phone_action(&state, &token, &parts, &f, lang, ip).await;
    }

    if matches!(f.action.as_str(), "second" | "recovery" | "totp") {
        let Ok(Some(client)) = state.login_flow_client(&token).await else {
            return message(
                lang,
                StatusCode::NOT_FOUND,
                "Link invalid or expired",
                "Start the connection again from your app.",
            );
        };
        if f.action != "second" {
            // only switches between code and recovery code; the CSRF value is still checked on submit
            return second_page(
                lang,
                &state,
                &Step {
                    token: &token,
                    client: &client,
                    ticket: &f.ticket,
                    recovery: f.action == "recovery",
                    error: None,
                    status: StatusCode::OK,
                },
            )
            .await;
        }
        return match state
            .flow_second_factor(&token, &f.csrf, &f.ticket, &f.code, ip)
            .await
        {
            Ok(()) => message(
                lang,
                StatusCode::OK,
                "Device connected",
                "You can close this window and return to your app.",
            ),
            Err(Error::Forbidden) => forbidden(lang),
            Err(Error::NotFound) => message(
                lang,
                StatusCode::NOT_FOUND,
                "Link invalid or expired",
                "Start the connection again from your app.",
            ),
            Err(e @ (Error::Unauthenticated | Error::RateLimited { .. })) => {
                let (status, text) = code_error_text(lang, &e);
                let mut r = second_page(
                    lang,
                    &state,
                    &Step {
                        token: &token,
                        client: &client,
                        ticket: &f.ticket,
                        recovery: f.code.trim().len() > 7,
                        error: Some(&text),
                        status,
                    },
                )
                .await;
                if let Error::RateLimited { retry_after_secs } = e
                    && let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string())
                {
                    r.headers_mut().insert(header::RETRY_AFTER, v);
                }
                r
            }
            Err(e) => internal(lang, &e),
        };
    }

    match state
        .flow_allow(&token, &f.csrf, &f.user, &f.password, ip)
        .await
    {
        Ok(rostdav_app::FlowStep::Granted) => message(
            lang,
            StatusCode::OK,
            "Device connected",
            "You can close this window and return to your app.",
        ),
        Ok(rostdav_app::FlowStep::SecondFactor { ticket }) => {
            match state.login_flow_client(&token).await {
                Ok(Some(client)) => {
                    second_page(
                        lang,
                        &state,
                        &Step {
                            token: &token,
                            client: &client,
                            ticket: &ticket,
                            recovery: false,
                            error: None,
                            status: StatusCode::OK,
                        },
                    )
                    .await
                }
                _ => message(
                    lang,
                    StatusCode::NOT_FOUND,
                    "Link invalid or expired",
                    "Start the connection again from your app.",
                ),
            }
        }
        Err(Error::Forbidden) => forbidden(lang),
        Err(Error::NotFound) => message(
            lang,
            StatusCode::NOT_FOUND,
            "Link invalid or expired",
            "Start the connection again from your app.",
        ),
        Err(e @ (Error::Unauthenticated | Error::RateLimited { .. })) => {
            let (status, text) = match e {
                Error::RateLimited { retry_after_secs } => (
                    StatusCode::TOO_MANY_REQUESTS,
                    tf(
                        lang,
                        "Too many attempts. Try again in {0} minutes.",
                        &[&retry_after_secs.div_ceil(60).to_string()],
                    ),
                ),
                _ => (
                    StatusCode::UNAUTHORIZED,
                    t(lang, "Wrong username or password."),
                ),
            };
            match state.login_flow_client(&token).await {
                Ok(Some(client)) => {
                    let mut r = page(
                        lang,
                        status,
                        "Connect device",
                        &form(lang, &state, &token, &client, &f.user, Some(&text)),
                    );
                    if let Error::RateLimited { retry_after_secs } = e
                        && let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string())
                    {
                        r.headers_mut().insert(header::RETRY_AFTER, v);
                    }
                    r
                }
                _ => message(
                    lang,
                    StatusCode::NOT_FOUND,
                    "Link invalid or expired",
                    "Start the connection again from your app.",
                ),
            }
        }
        Err(e) => internal(lang, &e),
    }
}

/// The phone step of the flow: "phone" starts a challenge and shows the number, "phone_finish"
/// turns the approval into the app password.
async fn phone_action(
    state: &AppState,
    token: &str,
    parts: &Parts,
    f: &Submit,
    lang: Lang,
    ip: IpAddr,
) -> Response {
    let Ok(Some(client)) = state.login_flow_client(token).await else {
        return message(
            lang,
            StatusCode::NOT_FOUND,
            "Link invalid or expired",
            "Start the connection again from your app.",
        );
    };
    if state.flow_check_csrf(token, &f.csrf).is_err() {
        return forbidden(lang);
    }
    let step = |error: &str, status: StatusCode| {
        let (token, client, ticket) = (token.to_owned(), client.clone(), f.ticket.clone());
        let error = error.to_owned();
        async move {
            second_page(
                lang,
                state,
                &Step {
                    token: &token,
                    client: &client,
                    ticket: &ticket,
                    recovery: false,
                    error: Some(&error),
                    status,
                },
            )
            .await
        }
    };
    if f.action == "phone" {
        let device = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let device: String = device
            .chars()
            .filter(|c| !c.is_control())
            .take(100)
            .collect();
        let device = if device.trim().is_empty() {
            "Web browser".to_owned()
        } else {
            device
        };
        return match state.flow_phone_start(token, &f.ticket, &device, ip).await {
            Ok(c) => {
                let csrf = state.flow_csrf(token, "allow");
                let ticket = esc(&f.ticket);
                let status_url = format!(
                    "/login/v2/flow/{}/phone-status?ticket={ticket}&amp;id={}",
                    esc(token),
                    esc(&c.challenge_id)
                );
                let hidden = format!(
                    "<input type=\"hidden\" name=\"ticket\" value=\"{ticket}\">\
                     <input type=\"hidden\" name=\"action\" value=\"phone_finish\">"
                );
                let back = format!("/login/v2/flow/{token}");
                let card = number_card(
                    lang,
                    &c,
                    &NumberCard {
                        csrf: &csrf,
                        status_url: &status_url,
                        action: "",
                        hidden: &hidden,
                        back_href: &back,
                    },
                );
                let mut r = crate::layout::bare_with(
                    lang,
                    StatusCode::OK,
                    "Confirm your sign-in",
                    &card,
                    PHONE_SCRIPT,
                );
                r.headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                r
            }
            Err(MfaError::Unauthenticated) => {
                step(
                    &t(lang, "Sign-in with the phone failed."),
                    StatusCode::UNAUTHORIZED,
                )
                .await
            }
            Err(MfaError::NotFound) => {
                step(
                    &t(lang, "No phone is enrolled for this account."),
                    StatusCode::NOT_FOUND,
                )
                .await
            }
            Err(MfaError::RateLimited { retry_after_secs }) => {
                let mut r = step(
                    &t(lang, "Too many requests. Try again later."),
                    StatusCode::TOO_MANY_REQUESTS,
                )
                .await;
                if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                    r.headers_mut().insert(header::RETRY_AFTER, v);
                }
                r
            }
            Err(_) => {
                step(
                    &t(lang, "Sign-in with the phone failed."),
                    StatusCode::CONFLICT,
                )
                .await
            }
        };
    }
    match state.flow_phone_finish(token, &f.ticket, &f.id, ip).await {
        Ok(()) => message(
            lang,
            StatusCode::OK,
            "Device connected",
            "You can close this window and return to your app.",
        ),
        Err(MfaError::Unauthenticated) => {
            step(
                &t(lang, "Sign-in with the phone failed."),
                StatusCode::UNAUTHORIZED,
            )
            .await
        }
        Err(e) => {
            let text = match state.flow_phone_status(token, &f.ticket, &f.id).await {
                Ok(ChallengeStatus::Pending) => t(lang, "Not approved yet."),
                Ok(ChallengeStatus::Denied) => t(lang, "The request was denied on the phone."),
                _ if matches!(e, MfaError::Expired) => {
                    t(lang, "The request expired. Send a new one.")
                }
                _ if matches!(e, MfaError::AlreadyConsumed) => {
                    t(lang, "This approval was already used. Sign in again.")
                }
                _ => t(lang, "Sign-in with the phone failed."),
            };
            let status = match e {
                MfaError::Expired => StatusCode::GONE,
                MfaError::NotFound => StatusCode::NOT_FOUND,
                _ => StatusCode::CONFLICT,
            };
            step(&text, status).await
        }
    }
}

#[derive(Deserialize)]
pub struct PhoneStatusQuery {
    #[serde(default)]
    ticket: String,
    #[serde(default)]
    id: String,
}

/// GET /login/v2/flow/<token>/phone-status: where the challenge stands, as JSON (no number).
pub async fn phone_status(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Query(q): Query<PhoneStatusQuery>,
) -> Response {
    use axum::response::IntoResponse;
    let r = match state.flow_phone_status(&token, &q.ticket, &q.id).await {
        Ok(s) => (
            [(header::CONTENT_TYPE, "application/json")],
            format!("{{\"status\":\"{}\"}}", s.as_str()),
        )
            .into_response(),
        Err(MfaError::Unauthenticated) => StatusCode::UNAUTHORIZED.into_response(),
        Err(MfaError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let mut r = r;
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn forbidden(lang: Lang) -> Response {
    message(
        lang,
        StatusCode::FORBIDDEN,
        "Request rejected",
        "The form could not be verified. Reload the page and try again.",
    )
}

fn internal(lang: Lang, e: &Error) -> Response {
    tracing::error!(error = %e, cause = ?std::error::Error::source(e), "login page failed");
    message(
        lang,
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong",
        "Please try again later.",
    )
}
