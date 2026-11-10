//! A phone is a second factor next to TOTP (ADR 0014).

use std::net::{IpAddr, Ipv4Addr};

use crate::SignIn;
use crate::push_mfa::testkit::{add_user, enrolled, state};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const PW: &str = "correct-horse-battery";

#[tokio::test]
async fn a_user_with_only_a_phone_has_a_second_factor() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    assert!(st.has_second_factor(p.user_id).await.expect("q"));
}

#[tokio::test]
async fn a_user_without_phone_or_totp_has_none() {
    let (_d, st) = state().await;
    let p = add_user(&st, "ben").await;
    assert!(!st.has_second_factor(p.user_id).await.expect("q"));
}

#[tokio::test]
async fn a_revoked_phone_does_not_count() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    st.mfa_revoke_device(p.user_id, "dev_a", "anna")
        .await
        .expect("revoke");
    assert!(!st.has_second_factor(p.user_id).await.expect("q"));
}

#[tokio::test]
async fn a_phone_makes_web_sign_in_ask_for_the_second_step() {
    let (_d, st) = state().await;
    enrolled(&st, "anna", "dev_a").await;
    let r = st.web_sign_in("anna", PW, IP, "ua").await.expect("sign in");
    assert!(matches!(r, SignIn::SecondFactor { .. }), "{r:?}");
}

#[tokio::test]
async fn without_a_factor_web_sign_in_opens_the_session() {
    let (_d, st) = state().await;
    add_user(&st, "ben").await;
    let r = st.web_sign_in("ben", PW, IP, "ua").await.expect("sign in");
    assert!(matches!(r, SignIn::Done { .. }), "{r:?}");
}

#[tokio::test]
async fn after_the_last_phone_is_revoked_web_sign_in_is_password_only_again() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    st.mfa_revoke_device(p.user_id, "dev_a", "anna")
        .await
        .expect("revoke");
    let r = st.web_sign_in("anna", PW, IP, "ua").await.expect("sign in");
    assert!(matches!(r, SignIn::Done { .. }), "{r:?}");
}

#[tokio::test]
async fn a_phone_makes_webdav_reject_the_account_password_but_not_an_app_password() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let denied = st.authenticate_with("anna", PW, IP, true).await;
    assert!(
        matches!(denied, Err(rostdav_core::Error::Unauthenticated)),
        "{denied:?}"
    );
    let app = st
        .create_app_password(p.user_id, "dav")
        .await
        .expect("app pw");
    let ok = st.authenticate_with("anna", &app, IP, true).await;
    assert!(ok.is_ok(), "{ok:?}");
}

#[tokio::test]
async fn without_a_factor_webdav_takes_the_account_password() {
    let (_d, st) = state().await;
    add_user(&st, "ben").await;
    assert!(st.authenticate_with("ben", PW, IP, true).await.is_ok());
}

// ---- recovery of a user whose only second factor is a phone -------------------------------------

use crate::Actor;

#[tokio::test]
async fn an_admin_reset_revokes_the_phones_of_a_phone_only_user() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = st
        .mfa_create_challenge(p.user_id, "dev_a", "ref_1", "Firefox", IP)
        .await
        .expect("challenge");
    assert!(
        st.user_two_factor_enabled(&Actor::Cli, "anna")
            .await
            .expect("q"),
        "the admin page must see the phone as a second factor"
    );
    let had = st
        .user_reset_two_factor(&Actor::Cli, "anna")
        .await
        .expect("reset");
    assert!(had, "the reset reports that something was removed");
    assert!(!st.has_second_factor(p.user_id).await.expect("q"));
    assert_eq!(
        st.mfa_challenge_status(&c.challenge_id).await.expect("s"),
        crate::ChallengeStatus::Expired,
        "open approvals end with the phone"
    );
    let r = st.web_sign_in("anna", PW, IP, "ua").await.expect("sign in");
    assert!(matches!(r, SignIn::Done { .. }), "{r:?}");
    let events = st.inner.db.events_since(0).await.expect("events");
    assert!(events.iter().any(|e| e.action == "mfa.device_revoked"));
}

#[tokio::test]
async fn an_admin_reset_for_a_user_without_any_factor_reports_nothing_removed() {
    let (_d, st) = state().await;
    add_user(&st, "ben").await;
    assert!(
        !st.user_reset_two_factor(&Actor::Cli, "ben")
            .await
            .expect("reset")
    );
}

// ---- revoking the last factor from the web needs the password -----------------------------------

use super::MfaError;
use super::testkit::{enroll_existing, principal};
use crate::WebSession;

async fn session(st: &crate::AppState, name: &str) -> WebSession {
    WebSession {
        id: 1,
        principal: principal(st, name, false).await,
    }
}

#[tokio::test]
async fn revoking_the_phone_that_is_the_only_factor_needs_the_password() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let s = session(&st, "anna").await;
    for pw in ["", "wrong-password"] {
        let r = st.web_mfa_revoke(&s, "dev_a", pw, IP).await;
        assert!(matches!(r, Err(MfaError::Unauthenticated)), "{pw:?}: {r:?}");
        assert!(
            st.has_second_factor(p.user_id).await.expect("q"),
            "still active"
        );
    }
    st.web_mfa_revoke(&s, "dev_a", PW, IP)
        .await
        .expect("revoke");
    assert!(!st.has_second_factor(p.user_id).await.expect("q"));
}

#[tokio::test]
async fn revoking_one_of_two_phones_needs_no_password() {
    let (_d, st) = state().await;
    enrolled(&st, "anna", "dev_a").await;
    enroll_existing(&st, "anna", "dev_b").await;
    let s = session(&st, "anna").await;
    st.web_mfa_revoke(&s, "dev_a", "", IP)
        .await
        .expect("revoke");
}

#[tokio::test]
async fn revoking_another_users_phone_is_not_found_whatever_the_password() {
    let (_d, st) = state().await;
    enrolled(&st, "anna", "dev_a").await;
    enrolled(&st, "ben", "dev_b").await;
    let s = session(&st, "anna").await;
    let r = st.web_mfa_revoke(&s, "dev_b", PW, IP).await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
}
