//! Login Flow v2 page: client name, user name, password; allow or deny.
//! Layout follows `design/mockups/web-ui/Login.dc.html`.

use std::net::{IpAddr, Ipv4Addr};

use axum::Form;
use axum::extract::{Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use rostdav_app::AppState;
use rostdav_core::{ClientIp, Error};
use serde::Deserialize;

use crate::i18n::{Lang, t, tf};
use crate::layout::esc;
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

fn second_page(lang: Lang, state: &AppState, s: &Step<'_>) -> Response {
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
    page(
        lang,
        status,
        "Confirm your sign-in",
        &second_step_card(
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
        ),
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
            );
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
                );
                if let Error::RateLimited { retry_after_secs } = e {
                    if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                        r.headers_mut().insert(header::RETRY_AFTER, v);
                    }
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
                Ok(Some(client)) => second_page(
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
                ),
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
                    if let Error::RateLimited { retry_after_secs } = e {
                        if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                            r.headers_mut().insert(header::RETRY_AFTER, v);
                        }
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
