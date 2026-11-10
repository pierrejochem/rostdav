//! A challenge belongs to one sign-in (its ticket) and is released to the browser once.

use std::net::{IpAddr, Ipv4Addr};

use super::testkit::{Phone, enrolled, fixed_key, spki_b64, state};
use super::{ChallengeStatus, MfaError};
use crate::{AppState, now_secs};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn ticket(st: &AppState, user_id: i64, flow: &str) -> String {
    st.second_factor_ticket(user_id, flow)
}

async fn started(st: &AppState, p: &Phone, flow: &str) -> (String, String) {
    let t = ticket(st, p.user_id, flow);
    let c = st
        .mfa_login_start(&t, flow, "Firefox on Linux", IP)
        .await
        .expect("start");
    (t, c.challenge_id)
}

async fn approve(st: &AppState, id: &str) {
    assert!(
        st.inner
            .db
            .mfa_challenge_resolve(id, "approved", now_secs())
            .await
            .expect("resolve")
    );
}

async fn add_phone(st: &AppState, user_id: i64, id: &str, seen: i64) {
    let (a, b) = (fixed_key(), fixed_key());
    st.inner
        .db
        .mfa_device_insert(&rostdav_meta::NewDevice {
            id,
            user_id,
            name: "Second",
            request_pub: &spki_b64(&a),
            approval_pub: &spki_b64(&b),
            push_channel: "fcm",
            push_token: "t2",
            hardware_backed: true,
            strongbox: false,
        })
        .await
        .expect("insert");
    st.inner.db.mfa_device_touch(id, seen).await.expect("touch");
}

#[tokio::test]
async fn start_creates_a_challenge_for_the_newest_active_phone() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    st.inner
        .db
        .mfa_device_touch("dev_a", 1_000)
        .await
        .expect("t");
    add_phone(&st, p.user_id, "dev_b", 2_000).await;
    let (_t, id) = started(&st, &p, "").await;
    let row = st
        .inner
        .db
        .mfa_challenge_get(&id)
        .await
        .expect("q")
        .expect("row");
    assert_eq!(row.device_id, "dev_b");
}

#[tokio::test]
async fn start_skips_a_revoked_phone() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    st.inner
        .db
        .mfa_device_touch("dev_a", 1_000)
        .await
        .expect("t");
    add_phone(&st, p.user_id, "dev_b", 2_000).await;
    st.mfa_revoke_device(p.user_id, "dev_b", "anna")
        .await
        .expect("revoke");
    let (_t, id) = started(&st, &p, "").await;
    let row = st
        .inner
        .db
        .mfa_challenge_get(&id)
        .await
        .expect("q")
        .expect("row");
    assert_eq!(row.device_id, "dev_a");
}

#[tokio::test]
async fn start_without_a_phone_is_not_found() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    st.mfa_revoke_device(p.user_id, "dev_a", "anna")
        .await
        .expect("revoke");
    let t = ticket(&st, p.user_id, "");
    let r = st.mfa_login_start(&t, "", "x", IP).await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
}

#[tokio::test]
async fn start_with_a_forged_ticket_is_unauthenticated() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let r = st
        .mfa_login_start(&format!("{}.9999999999.beef", p.user_id), "", "x", IP)
        .await;
    assert!(matches!(r, Err(MfaError::Unauthenticated)), "{r:?}");
}

#[tokio::test]
async fn status_follows_the_challenge() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let (t, id) = started(&st, &p, "").await;
    assert_eq!(
        st.mfa_login_status(&t, "", &id).await.expect("s"),
        ChallengeStatus::Pending
    );
    approve(&st, &id).await;
    assert_eq!(
        st.mfa_login_status(&t, "", &id).await.expect("s"),
        ChallengeStatus::Approved
    );
}

#[tokio::test]
async fn status_of_another_tickets_challenge_is_not_found() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let b = enrolled(&st, "ben", "dev_b").await;
    let (_ta, id_a) = started(&st, &a, "").await;
    // another user's ticket
    let tb = ticket(&st, b.user_id, "");
    let r = st.mfa_login_status(&tb, "", &id_a).await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
    // the same user, but a ticket of a Login Flow v2 sign-in
    let tf = ticket(&st, a.user_id, "flowtoken");
    let r = st.mfa_login_status(&tf, "flowtoken", &id_a).await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
    // an unknown id
    let t = ticket(&st, a.user_id, "");
    let r = st.mfa_login_status(&t, "", "ch_nope").await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
}

#[tokio::test]
async fn an_expired_ticket_cannot_poll_or_release() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let (_t, id) = started(&st, &p, "").await;
    approve(&st, &id).await;
    let (uid, exp) = (p.user_id.to_string(), (now_secs() - 5).to_string());
    let sig = crate::secrets::mac(&st.inner.server_key, &["2fa", &uid, &exp, ""]);
    let old = format!("{uid}.{exp}.{sig}");
    let r = st.mfa_login_status(&old, "", &id).await;
    assert!(matches!(r, Err(MfaError::Unauthenticated)), "{r:?}");
    let r = st.mfa_login_release(&old, "", &id).await;
    assert!(matches!(r, Err(MfaError::Unauthenticated)), "{r:?}");
}

#[tokio::test]
async fn release_after_approve_returns_the_user_once() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let (t, id) = started(&st, &p, "").await;
    approve(&st, &id).await;
    assert_eq!(
        st.mfa_login_release(&t, "", &id).await.expect("release"),
        p.user_id
    );
    let again = st.mfa_login_release(&t, "", &id).await;
    assert!(matches!(again, Err(MfaError::AlreadyConsumed)), "{again:?}");
}

#[tokio::test]
async fn two_concurrent_releases_have_one_winner() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let (t, id) = started(&st, &p, "").await;
    approve(&st, &id).await;
    let (a, b) = tokio::join!(
        st.mfa_login_release(&t, "", &id),
        st.mfa_login_release(&t, "", &id)
    );
    assert_eq!(
        [a.is_ok(), b.is_ok()].iter().filter(|x| **x).count(),
        1,
        "{a:?} {b:?}"
    );
}

#[tokio::test]
async fn release_while_pending_fails_and_does_not_burn_the_challenge() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let (t, id) = started(&st, &p, "").await;
    let r = st.mfa_login_release(&t, "", &id).await;
    assert!(matches!(r, Err(MfaError::InvalidRequest(_))), "{r:?}");
    approve(&st, &id).await;
    assert!(st.mfa_login_release(&t, "", &id).await.is_ok());
}

#[tokio::test]
async fn release_after_deny_fails() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let (t, id) = started(&st, &p, "").await;
    assert!(
        st.inner
            .db
            .mfa_challenge_resolve(&id, "denied", now_secs())
            .await
            .expect("resolve")
    );
    let r = st.mfa_login_release(&t, "", &id).await;
    assert!(matches!(r, Err(MfaError::InvalidRequest(_))), "{r:?}");
}

#[tokio::test]
async fn release_of_an_expired_challenge_fails() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let (t, id) = started(&st, &p, "").await;
    assert!(
        st.inner
            .db
            .mfa_challenge_cancel(&id, now_secs())
            .await
            .expect("c")
    );
    let r = st.mfa_login_release(&t, "", &id).await;
    assert!(matches!(r, Err(MfaError::Expired)), "{r:?}");
}

#[tokio::test]
async fn a_flow_ticket_cannot_release_a_web_challenge_and_the_reverse() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let (_t, web_id) = started(&st, &p, "").await;
    approve(&st, &web_id).await;
    let tf = ticket(&st, p.user_id, "flowtoken");
    let r = st.mfa_login_release(&tf, "flowtoken", &web_id).await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
}

#[tokio::test]
async fn release_after_the_phone_was_revoked_fails() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let (t, id) = started(&st, &p, "").await;
    approve(&st, &id).await;
    st.mfa_revoke_device(p.user_id, "dev_a", "anna")
        .await
        .expect("revoke");
    let r = st.mfa_login_release(&t, "", &id).await;
    assert!(r.is_err(), "released: {r:?}");
}

#[tokio::test]
async fn a_disabled_user_cannot_release() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let (t, id) = started(&st, &p, "").await;
    approve(&st, &id).await;
    st.inner
        .db
        .set_user_disabled(p.user_id, true)
        .await
        .expect("disable");
    let r = st.mfa_login_release(&t, "", &id).await;
    assert!(matches!(r, Err(MfaError::Unauthenticated)), "{r:?}");
}

#[tokio::test]
async fn the_audit_has_start_and_release_but_never_the_number() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let (t, id) = started(&st, &p, "").await;
    approve(&st, &id).await;
    st.mfa_login_release(&t, "", &id).await.expect("release");
    let events = st.inner.db.events_since(0).await.expect("events");
    let actions: Vec<&str> = events.iter().map(|e| e.action.as_str()).collect();
    assert!(actions.contains(&"mfa.challenge_created"), "{actions:?}");
    assert!(actions.contains(&"mfa.login_released"), "{actions:?}");
    let details: String = events.iter().map(|e| e.details.as_str()).collect();
    assert!(!details.contains("number"), "{details}");
    assert!(!details.contains(&t), "the ticket is a secret");
}

#[tokio::test]
async fn second_step_options_report_what_the_user_can_use() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let t = ticket(&st, p.user_id, "");
    let o = st.web_second_step_options(&t).await.expect("options");
    assert!(o.phone && !o.totp, "{o:?}");
    assert!(st.web_second_step_options("1.2.bad").await.is_none());
    // a ticket of the Login Flow page is not one of the browser sign-in
    let tf = ticket(&st, p.user_id, "flowtoken");
    assert!(st.web_second_step_options(&tf).await.is_none());
}

#[tokio::test]
async fn web_phone_finish_opens_one_session() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let (t, id) = started(&st, &p, "").await;
    approve(&st, &id).await;
    let (cookie, principal) = st
        .web_phone_finish(&t, &id, IP, "ua")
        .await
        .expect("finish");
    assert_eq!(principal.user_id, p.user_id);
    let s = st.web_session(&cookie).await.expect("q").expect("session");
    assert_eq!(s.principal.user_id, p.user_id);
    let again = st.web_phone_finish(&t, &id, IP, "ua").await;
    assert!(matches!(again, Err(MfaError::AlreadyConsumed)), "{again:?}");
    let events = st.inner.db.events_since(0).await.expect("events");
    assert!(
        events
            .iter()
            .any(|e| e.action == "auth.login" && e.details.contains("phone")),
        "{events:?}"
    );
}

#[tokio::test]
async fn web_phone_finish_before_approval_opens_no_session() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let (t, id) = started(&st, &p, "").await;
    let r = st.web_phone_finish(&t, &id, IP, "ua").await;
    assert!(matches!(r, Err(MfaError::InvalidRequest(_))), "{r:?}");
}

#[tokio::test]
async fn starting_twice_for_one_sign_in_reuses_the_open_challenge() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let t = ticket(&st, p.user_id, "");
    let first = st.mfa_login_start(&t, "", "Firefox", IP).await.expect("1");
    // a reload of the number page, or a double click
    let second = st.mfa_login_start(&t, "", "Firefox", IP).await.expect("2");
    assert_eq!(first.challenge_id, second.challenge_id);
    assert_eq!(first.number, second.number);
    assert!(second.expires_in_seconds <= first.expires_in_seconds);
    assert_eq!(
        super::testkit::pending_challenge_ids(&st, "dev_a")
            .await
            .len(),
        1,
        "one prompt on the phone"
    );
}

#[tokio::test]
async fn a_finished_challenge_is_not_reused() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let t = ticket(&st, p.user_id, "");
    let first = st.mfa_login_start(&t, "", "Firefox", IP).await.expect("1");
    assert!(
        st.inner
            .db
            .mfa_challenge_resolve(&first.challenge_id, "denied", now_secs())
            .await
            .expect("resolve")
    );
    let second = st.mfa_login_start(&t, "", "Firefox", IP).await.expect("2");
    assert_ne!(first.challenge_id, second.challenge_id);
}

#[tokio::test]
async fn another_sign_in_of_the_same_user_gets_its_own_challenge() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let web = ticket(&st, p.user_id, "");
    let flow = ticket(&st, p.user_id, "flowtoken");
    let a = st
        .mfa_login_start(&web, "", "Firefox", IP)
        .await
        .expect("web");
    let b = st
        .mfa_login_start(&flow, "flowtoken", "Android", IP)
        .await
        .expect("flow");
    assert_ne!(a.challenge_id, b.challenge_id);
}
