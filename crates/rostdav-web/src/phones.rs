//! RustMFA phones in the web interface (ADR 0014): the list on the devices page, the enrollment
//! QR code (behind the account password) and revoking a phone.

use axum::Form;
use axum::extract::State;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use rostdav_app::{AppState, DeviceInfo, MfaError};
use rostdav_core::Error;
use serde::Deserialize;

use crate::i18n::{Lang, t, tf};
use crate::layout::esc;
use crate::pages::error_response_to;
use crate::session::{Authed, client_ip};
use crate::ui;

fn csrf_ok(state: &AppState, a: &Authed, given: &str) -> bool {
    state.web_check_csrf(a.session.id, given).is_ok()
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// The date part of an RFC 3339 time.
fn day(rfc3339: &str) -> &str {
    rfc3339.get(..10).unwrap_or(rfc3339)
}

fn event_label(lang: Lang, kind: &str) -> String {
    t(
        lang,
        match kind {
            "device_registered" => "Phone added",
            "device_revoked" => "Phone revoked",
            "key_rotated" => "Keys renewed",
            "challenge_created" => "Sign-in approval requested",
            "challenge_approved" => "Sign-in approved",
            "challenge_denied" => "Sign-in denied",
            "challenge_expired" => "Sign-in request expired",
            "number_mismatch" => "Wrong number chosen",
            _ => "Event",
        },
    )
}

fn phone_row(lang: Lang, csrf: &str, d: &DeviceInfo) -> String {
    let active = d.status == "active";
    let mut meta = tf(lang, "Added {0}", &[day(&d.created_at)]);
    if d.strongbox {
        meta.push_str(" · StrongBox");
    } else if d.hardware_backed {
        meta.push_str(" · ");
        meta.push_str(&t(lang, "Hardware key"));
    }
    let seen = d
        .last_seen_at
        .as_deref()
        .map_or_else(|| t(lang, "Never used"), |s| day(s).to_owned());
    let action = if active {
        format!(
            "<form class=\"row-actions\" method=\"post\" action=\"/devices/phones/revoke\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"device_id\" value=\"{}\">\
             <button class=\"danger\" type=\"submit\" aria-label=\"{}\">{}</button></form>",
            esc(csrf),
            esc(&d.device_id),
            esc(&tf(lang, "Revoke {0}", &[&d.device_name])),
            esc(&t(lang, "Revoke")),
        )
    } else {
        String::new()
    };
    format!(
        "<li class=\"row\"><span class=\"tile folder\">{}</span><div class=\"row-text\"><b>{}</b>\
         <span class=\"muted\">{}</span></div><span class=\"row-meta\"><span class=\"chip{}\">{}</span> {}</span>{action}</li>",
        ui::svg("phone"),
        esc(&d.device_name),
        esc(&meta),
        if active { " ok" } else { "" },
        esc(&t(lang, if active { "Active" } else { "Revoked" })),
        esc(&seen),
    )
}

/// The card of the devices page. Empty when the account has no phone and the server cannot
/// enroll one.
pub async fn phones_card(state: &AppState, a: &Authed) -> String {
    let lang = a.lang;
    let user_id = a.session.principal.user_id;
    let Ok(devices) = state.mfa_list_devices(user_id).await else {
        return String::new();
    };
    let events = state.mfa_audit_events(user_id).await.unwrap_or_default();
    let rows: String = devices
        .iter()
        .map(|d| phone_row(lang, &a.csrf, d))
        .collect();
    let list = if rows.is_empty() {
        format!(
            "<div class=\"empty\">{}</div>",
            esc(&t(lang, "No phone is set up for sign-in approval."))
        )
    } else {
        format!("<ul class=\"rows\">{rows}</ul>")
    };
    let history = if events.is_empty() {
        String::new()
    } else {
        let items: String = events
            .iter()
            .take(5)
            .map(|e| {
                format!(
                    "<li>{} · {}</li>",
                    esc(&event_label(lang, &e.event)),
                    esc(day(&e.at))
                )
            })
            .collect();
        format!(
            "<p class=\"muted\">{}</p><ul class=\"muted\">{items}</ul>",
            esc(&t(lang, "Recent events"))
        )
    };
    let active = devices.iter().filter(|d| d.status == "active").count();
    let chip = format!(
        "<span class=\"chip{}\">{}</span>",
        if active > 0 { " ok" } else { "" },
        esc(&tf(lang, "{0} active", &[&active.to_string()]))
    );
    let inner = format!(
        "<p class=\"muted\">{}</p>{list}\
         <p><a class=\"button primary\" href=\"/devices/phones/enroll\">{}</a></p>{history}",
        esc(&t(
            lang,
            "Approve browser sign-ins on your phone with the RustMFA app. Once a phone is set up, the account password no longer works for WebDAV; app passwords keep working."
        )),
        esc(&t(lang, "Add a phone")),
    );
    ui::card(lang, "Phones (RustMFA)", &chip, &inner)
}

// ---- enrollment ---------------------------------------------------------------------------------

fn enroll_form(a: &Authed, totp: bool, error: Option<&str>, status: StatusCode) -> Response {
    let lang = a.lang;
    let err = error
        .map(|e| format!("<div class=\"err\" role=\"alert\">{}</div>", esc(e)))
        .unwrap_or_default();
    let code = if totp {
        format!(
            "<label>{}<input class=\"codeinput small\" type=\"text\" name=\"code\" autocomplete=\"one-time-code\" required></label>",
            esc(&t(
                lang,
                "Code from your authenticator app, or a recovery code"
            ))
        )
    } else {
        String::new()
    };
    let form = format!(
        "{err}<form class=\"stack-form\" method=\"post\" action=\"/devices/phones/enroll\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\">\
         <label>{}<input type=\"password\" name=\"password\" autocomplete=\"current-password\" required autofocus></label>{code}\
         <div class=\"actions\"><button class=\"primary\" type=\"submit\">{}</button><a class=\"button\" href=\"/devices\">{}</a></div></form>",
        esc(&a.csrf),
        esc(&t(lang, "Password")),
        esc(&t(lang, "Show enrollment code")),
        esc(&t(lang, "Cancel")),
    );
    let body = format!(
        "{}{}",
        ui::page_head(
            lang,
            "Add a phone",
            "Enter your password to show the enrollment code for the RustMFA app.",
            ""
        ),
        ui::card(lang, "Confirm with your password", "", &form)
    );
    no_store(ui::page(a, status, "Add a phone", "devices", &body))
}

/// Whether the account has TOTP on (then enrolling asks for a code as well).
async fn totp_on(state: &AppState, a: &Authed) -> bool {
    state
        .two_factor_status(&a.session.principal)
        .await
        .is_ok_and(|s| s.enabled)
}

pub async fn enroll_page(State(state): State<AppState>, a: Authed) -> Response {
    let totp = totp_on(&state, &a).await;
    enroll_form(&a, totp, None, StatusCode::OK)
}

#[derive(Deserialize)]
pub struct EnrollForm {
    csrf: String,
    password: String,
    #[serde(default)]
    code: String,
}

/// The address the phone should talk to: `server.public_url`, else the `Host` of this request.
fn server_url(state: &AppState, headers: &HeaderMap) -> Option<String> {
    if let Some(u) = state.public_url() {
        return Some(u.trim_end_matches('/').to_owned());
    }
    let host = headers.get(header::HOST)?.to_str().ok()?;
    let ok = !host.is_empty()
        && host.len() <= 255
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'));
    ok.then(|| format!("http://{host}"))
}

pub async fn enroll_submit(
    State(state): State<AppState>,
    a: Authed,
    parts: Parts,
    Form(f): Form<EnrollForm>,
) -> Response {
    let lang = a.lang;
    if !csrf_ok(&state, &a, &f.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(server) = server_url(&state, &parts.headers) else {
        return error_response_to(
            &a,
            &Error::BadRequest("no server address"),
            "/devices",
            "devices",
        );
    };
    match state
        .web_mfa_enroll_start(&a.session, &f.password, &f.code, &server, client_ip(&parts))
        .await
    {
        Ok(q) => {
            let minutes = ((q.token.expires_in_seconds + 59) / 60).to_string();
            let inner = format!(
                "<div class=\"qr\">{}</div><p>{}</p>\
                 <p class=\"muted\">{}</p><p><code class=\"enroll-payload\">{}</code></p>\
                 <p class=\"muted\">{}</p>\
                 <p><a class=\"button\" href=\"/devices\">{}</a></p>",
                q.qr_svg,
                esc(&tf(
                    lang,
                    "Open the RustMFA app and scan this code. It is valid for {0} minutes and works once.",
                    &[&minutes]
                )),
                esc(&t(lang, "Cannot scan? This is what the code says:")),
                esc(&q.payload),
                esc(&tf(lang, "Server address: {0}", &[&server])),
                esc(&t(lang, "Done")),
            );
            let body = format!(
                "{}{}",
                ui::page_head(
                    lang,
                    "Scan with the RustMFA app",
                    "Anyone who scans this code before it expires can add a phone to your account. Keep it to yourself.",
                    ""
                ),
                ui::card(lang, "Enrollment code", "", &inner)
            );
            no_store(ui::page(
                &a,
                StatusCode::OK,
                "Add a phone",
                "devices",
                &body,
            ))
        }
        Err(MfaError::Unauthenticated) => {
            let totp = totp_on(&state, &a).await;
            let text = if totp {
                "The password or the code is wrong or has been used."
            } else {
                "Wrong password."
            };
            enroll_form(&a, totp, Some(&t(lang, text)), StatusCode::UNAUTHORIZED)
        }
        Err(MfaError::RateLimited { retry_after_secs }) => {
            let mut r = enroll_form(
                &a,
                totp_on(&state, &a).await,
                Some(&tf(
                    lang,
                    "Too many attempts. Try again in {0} minutes.",
                    &[&retry_after_secs.div_ceil(60).to_string()],
                )),
                StatusCode::TOO_MANY_REQUESTS,
            );
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                r.headers_mut().insert(header::RETRY_AFTER, v);
            }
            r
        }
        Err(MfaError::Internal(e)) => error_response_to(&a, &e, "/devices", "devices"),
        Err(_) => error_response_to(&a, &Error::Unavailable, "/devices", "devices"),
    }
}

// ---- revoking -----------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RevokeForm {
    csrf: String,
    device_id: String,
    #[serde(default)]
    password: String,
}

/// Revoking the only second factor asks for the password first.
fn revoke_confirm(
    a: &Authed,
    device_id: &str,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let lang = a.lang;
    let err = error
        .map(|e| format!("<div class=\"err\" role=\"alert\">{}</div>", esc(e)))
        .unwrap_or_default();
    let form = format!(
        "{err}<form class=\"stack-form\" method=\"post\" action=\"/devices/phones/revoke\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"device_id\" value=\"{}\">\
         <label>{}<input type=\"password\" name=\"password\" autocomplete=\"current-password\" required autofocus></label>\
         <div class=\"actions\"><button class=\"danger\" type=\"submit\">{}</button><a class=\"button\" href=\"/devices\">{}</a></div></form>",
        esc(&a.csrf),
        esc(device_id),
        esc(&t(lang, "Password")),
        esc(&t(lang, "Revoke")),
        esc(&t(lang, "Cancel")),
    );
    let body = format!(
        "{}{}",
        ui::page_head(
            lang,
            "Revoke your only second factor?",
            "This phone is your only second factor. Without it, signing in needs only the password, and WebDAV accepts it again. Enter your password to confirm.",
            ""
        ),
        ui::card(lang, "Confirm with your password", "", &form)
    );
    no_store(ui::page(a, status, "Devices", "devices", &body))
}

pub async fn revoke(
    State(state): State<AppState>,
    a: Authed,
    parts: Parts,
    Form(f): Form<RevokeForm>,
) -> Response {
    if !csrf_ok(&state, &a, &f.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let lang = a.lang;
    match state
        .web_mfa_revoke(&a.session, &f.device_id, &f.password, client_ip(&parts))
        .await
    {
        Ok(()) => Redirect::to("/devices").into_response(),
        Err(MfaError::Unauthenticated) if f.password.is_empty() => {
            revoke_confirm(&a, &f.device_id, None, StatusCode::OK)
        }
        Err(MfaError::Unauthenticated) => revoke_confirm(
            &a,
            &f.device_id,
            Some(&t(lang, "Wrong password.")),
            StatusCode::UNAUTHORIZED,
        ),
        Err(MfaError::NotFound) => error_response_to(&a, &Error::NotFound, "/devices", "devices"),
        Err(MfaError::Internal(e)) => error_response_to(&a, &e, "/devices", "devices"),
        Err(_) => error_response_to(&a, &Error::Unavailable, "/devices", "devices"),
    }
}
