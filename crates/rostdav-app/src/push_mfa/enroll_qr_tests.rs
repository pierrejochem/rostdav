//! The enrollment QR code of the web interface.

use std::net::{IpAddr, Ipv4Addr};

use super::MfaError;
use super::enroll::enroll_qr_payload;
use super::testkit::{add_user, state};
use crate::{Scope, Via, WebSession};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[test]
fn the_payload_escapes_the_server_address() {
    assert_eq!(
        enroll_qr_payload("https://cloud.example.org/x?y=1&z", "tok"),
        "rustmfa://enroll?server=https%3A%2F%2Fcloud.example.org%2Fx%3Fy%3D1%26z&token=tok"
    );
}

#[tokio::test]
async fn enrolling_needs_the_account_password() {
    let (_d, st) = state().await;
    let p = add_user(&st, "anna").await;
    let s = WebSession {
        id: 1,
        principal: p,
    };
    let r = st
        .web_mfa_enroll_start(&s, "wrong-password", "http://h", IP)
        .await;
    assert!(matches!(r, Err(MfaError::Unauthenticated)), "{r:?}");
}

#[tokio::test]
async fn enrolling_gives_a_token_a_payload_and_a_qr_code() {
    let (_d, st) = state().await;
    let p = add_user(&st, "anna").await;
    let s = WebSession {
        id: 1,
        principal: p,
    };
    let q = st
        .web_mfa_enroll_start(&s, "correct-horse-battery", "http://cloud.test", IP)
        .await
        .expect("enroll");
    assert_eq!(q.token.expires_in_seconds, 300);
    assert_eq!(
        q.payload,
        format!(
            "rustmfa://enroll?server=http%3A%2F%2Fcloud.test&token={}",
            q.token.token
        )
    );
    assert!(
        q.qr_svg.starts_with("<svg"),
        "{}",
        &q.qr_svg[..40.min(q.qr_svg.len())]
    );
    let events = st.inner.db.events_since(0).await.expect("events");
    assert!(
        events
            .iter()
            .any(|e| e.action == "mfa.enroll_token_created")
    );
    assert!(
        !events
            .iter()
            .any(|e| e.details.contains(&q.token.token) || e.target.contains(&q.token.token)),
        "the token is a secret"
    );
}

#[tokio::test]
async fn a_wrong_password_creates_no_token() {
    let (_d, st) = state().await;
    let p = add_user(&st, "anna").await;
    let s = WebSession {
        id: 1,
        principal: p,
    };
    let _ = st.web_mfa_enroll_start(&s, "nope", "http://h", IP).await;
    let events = st.inner.db.events_since(0).await.expect("events");
    assert!(
        !events
            .iter()
            .any(|e| e.action == "mfa.enroll_token_created")
    );
}

#[tokio::test]
async fn an_app_password_session_cannot_enroll() {
    let (_d, st) = state().await;
    let mut p = add_user(&st, "anna").await;
    p.via = Via::AppPassword(1);
    p.scope = Scope::Full;
    let s = WebSession {
        id: 1,
        principal: p,
    };
    let r = st
        .web_mfa_enroll_start(&s, "correct-horse-battery", "http://h", IP)
        .await;
    assert!(r.is_err(), "{r:?}");
}
