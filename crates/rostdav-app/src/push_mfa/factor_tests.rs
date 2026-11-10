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
