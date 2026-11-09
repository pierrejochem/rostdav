use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use rostdav_meta::NewDevice;

use super::push::PushFuture;
use super::{ChallengeDetails, ChallengeStatus, DevicePrincipal, MfaError, PushChannel};
use crate::AppState;
use crate::push_mfa::testkit::{Phone, add_user, captured, enrolled, fixed_key, spki_b64, state};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

fn now() -> i64 {
    crate::now_secs()
}

fn dp(p: &Phone) -> DevicePrincipal {
    DevicePrincipal {
        device_id: p.id.clone(),
        user_id: p.user_id,
    }
}

/// Every challenge counts against the user's limit; tests that make many lift it.
fn unlimit(st: &AppState, user_id: i64) {
    st.inner
        .mfa_limiter
        .clear(&format!("mfa-challenge:{user_id}"));
}

async fn create(st: &AppState, p: &Phone, login: &str) -> super::NewChallenge {
    st.mfa_create_challenge(p.user_id, &p.id, login, "Firefox on Linux", IP)
        .await
        .expect("create")
}

/// The signature the app makes: the approval key over the canonical message of `d`.
fn sign_message(
    key: &ring::signature::EcdsaKeyPair,
    m: &rustmfa_contract::ChallengeMessage,
) -> String {
    let msg = rustmfa_contract::canonical_message(m).expect("message");
    let sig = key.sign(&SystemRandom::new(), msg.as_bytes()).expect("sig");
    URL_SAFE_NO_PAD.encode(sig.as_ref())
}

fn answer(p: &Phone, d: &ChallengeDetails) -> String {
    sign_message(
        &p.approval,
        &rustmfa_contract::ChallengeMessage {
            challenge_id: &d.challenge_id,
            nonce: &d.nonce,
            login_id: &d.login_id,
            device_id: &p.id,
            expires_at: &d.expires_at,
            audience: &d.audience,
        },
    )
}

async fn details(st: &AppState, p: &Phone, id: &str) -> ChallengeDetails {
    st.mfa_get_challenge(&dp(p), id).await.expect("details")
}

async fn row(st: &AppState, id: &str) -> rostdav_meta::ChallengeRow {
    st.inner
        .db
        .mfa_challenge_get(id)
        .await
        .expect("get")
        .expect("row")
}

async fn actions(st: &AppState) -> Vec<String> {
    st.audit_events(&crate::Actor::Cli, 0)
        .await
        .expect("events")
        .into_iter()
        .map(|e| e.action)
        .collect()
}

/// A second phone of the same account.
async fn second_phone(st: &AppState, of: &Phone, id: &str) -> Phone {
    let (request, approval) = (fixed_key(), fixed_key());
    st.inner
        .db
        .mfa_device_insert(&NewDevice {
            id,
            user_id: of.user_id,
            name: "Tablet",
            request_pub: &spki_b64(&request),
            approval_pub: &spki_b64(&approval),
            push_channel: "fcm",
            push_token: "t2",
            hardware_backed: true,
            strongbox: false,
        })
        .await
        .expect("insert");
    Phone {
        id: id.to_owned(),
        request,
        approval,
        user_id: of.user_id,
    }
}

#[tokio::test]
async fn create_makes_distinct_two_digit_number_and_two_decoys() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let mut seen_at = [0usize; 3];
    for i in 0..200 {
        unlimit(&st, p.user_id);
        let c = create(&st, &p, &format!("login-{i}")).await;
        assert!((10..=99).contains(&c.number));
        let d = details(&st, &p, &c.challenge_id).await;
        let n = d.candidate_numbers;
        assert!(n.iter().all(|x| (10..=99).contains(x)), "{n:?}");
        assert!(n[0] != n[1] && n[0] != n[2] && n[1] != n[2], "{n:?}");
        let at = n
            .iter()
            .position(|x| *x == c.number)
            .expect("right one is shown");
        seen_at[at] += 1;
        assert_eq!(row(&st, &c.challenge_id).await.number, c.number);
    }
    assert!(
        seen_at.iter().all(|c| *c > 20),
        "position is not random: {seen_at:?}"
    );
}

#[tokio::test]
async fn create_returns_the_configured_lifetime_and_a_fresh_id_and_nonce() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let a = create(&st, &p, "l1").await;
    let b = create(&st, &p, "l2").await;
    assert_eq!(a.expires_in_seconds, 90);
    assert!(a.challenge_id.starts_with("ch_") && a.challenge_id != b.challenge_id);
    let (ra, rb) = (
        row(&st, &a.challenge_id).await,
        row(&st, &b.challenge_id).await,
    );
    assert!(
        ra.nonce.len() >= 22 && ra.nonce != rb.nonce,
        "128 bit or more, never reused"
    );
    assert_eq!(ra.audience, "rostdav");
    assert_eq!(ra.login_ref, "l1");
    assert_eq!(ra.login_device, "Firefox on Linux");
    assert_eq!(ra.expires_at - ra.created_at, 90);
}

#[tokio::test]
async fn create_refuses_a_device_that_is_not_the_users_or_not_active() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let b = enrolled(&st, "ben", "dev_b").await;
    // anna's login cannot target ben's phone
    let r = st
        .mfa_create_challenge(a.user_id, &b.id, "l", "x", IP)
        .await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
    let r = st
        .mfa_create_challenge(a.user_id, "dev_nope", "l", "x", IP)
        .await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
    st.inner
        .db
        .mfa_device_revoke("dev_a", a.user_id, now())
        .await
        .expect("revoke");
    let r = st
        .mfa_create_challenge(a.user_id, "dev_a", "l", "x", IP)
        .await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
}

#[tokio::test]
async fn create_rejects_a_login_ref_that_cannot_be_signed() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    for bad in ["", "a\nb", &"x".repeat(129)] {
        let r = st
            .mfa_create_challenge(p.user_id, &p.id, bad, "x", IP)
            .await;
        assert!(
            matches!(r, Err(MfaError::InvalidRequest(_))),
            "{bad:?}: {r:?}"
        );
    }
}

#[tokio::test]
async fn the_login_device_is_cleaned() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = st
        .mfa_create_challenge(p.user_id, &p.id, "l", "Fire\nfox\u{7}", IP)
        .await
        .expect("create");
    assert_eq!(
        details(&st, &p, &c.challenge_id).await.login_device,
        "Firefox"
    );
    let c = st
        .mfa_create_challenge(p.user_id, &p.id, "l2", "\n\t", IP)
        .await
        .expect("create");
    assert_eq!(
        details(&st, &p, &c.challenge_id).await.login_device,
        "Unknown device"
    );
}

#[tokio::test]
async fn get_hides_the_correct_number() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    let d = details(&st, &p, &c.challenge_id).await;
    // every field is named: a new field that could mark the right number breaks this test
    let ChallengeDetails {
        challenge_id,
        service_name,
        login_device,
        approximate_location,
        created_at,
        expires_at,
        status,
        candidate_numbers,
        nonce,
        login_id,
        audience,
    } = d;
    assert_eq!(challenge_id, c.challenge_id);
    assert_eq!(service_name, "Rostdav");
    assert_eq!(login_device, "Firefox on Linux");
    assert_eq!(approximate_location, None);
    assert_eq!(status, ChallengeStatus::Pending);
    assert_eq!((login_id.as_str(), audience.as_str()), ("l", "rostdav"));
    assert_eq!(candidate_numbers.len(), 3);
    // dates have the exact signed form
    for t in [&created_at, &expires_at] {
        assert_eq!(t.len(), 20);
        assert!(t.ends_with('Z') && t.as_bytes()[10] == b'T');
    }
    assert!(!nonce.is_empty());
}

#[tokio::test]
async fn approve_with_valid_signature_consumes_once() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    let d = details(&st, &p, &c.challenge_id).await;
    let sig = answer(&p, &d);
    let s = st
        .mfa_approve(&dp(&p), &c.challenge_id, c.number, &sig)
        .await
        .expect("approve");
    assert_eq!(s, ChallengeStatus::Approved);
    let r = row(&st, &c.challenge_id).await;
    assert_eq!(r.status, "approved");
    assert!(r.consumed_at.is_some());
    assert_eq!(
        st.mfa_challenge_status(&c.challenge_id)
            .await
            .expect("status"),
        ChallengeStatus::Approved
    );
}

#[tokio::test]
async fn approve_twice_gives_already_consumed() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    let sig = answer(&p, &details(&st, &p, &c.challenge_id).await);
    st.mfa_approve(&dp(&p), &c.challenge_id, c.number, &sig)
        .await
        .expect("first");
    let r = st
        .mfa_approve(&dp(&p), &c.challenge_id, c.number, &sig)
        .await;
    assert!(matches!(r, Err(MfaError::AlreadyConsumed)), "{r:?}");
    let r = st.mfa_deny(&dp(&p), &c.challenge_id, &sig).await;
    assert!(matches!(r, Err(MfaError::AlreadyConsumed)), "{r:?}");
}

#[tokio::test]
async fn concurrent_approves_one_wins() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    for i in 0..10 {
        unlimit(&st, p.user_id);
        let c = create(&st, &p, &format!("l{i}")).await;
        let sig = answer(&p, &details(&st, &p, &c.challenge_id).await);
        let d = dp(&p);
        let (a, b) = tokio::join!(
            st.mfa_approve(&d, &c.challenge_id, c.number, &sig),
            st.mfa_approve(&d, &c.challenge_id, c.number, &sig)
        );
        let oks = [&a, &b].iter().filter(|r| r.is_ok()).count();
        assert_eq!(oks, 1, "{a:?} {b:?}");
        let lost = if a.is_ok() { b } else { a };
        assert!(matches!(lost, Err(MfaError::AlreadyConsumed)), "{lost:?}");
        let events = actions(&st).await;
        let approved = events
            .iter()
            .filter(|a| *a == "mfa.challenge_approved")
            .count();
        assert_eq!(approved, i + 1, "one audit event per won approval");
    }
}

#[tokio::test]
async fn approve_wrong_number_denies_and_audits() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    let d = details(&st, &p, &c.challenge_id).await;
    let wrong = d
        .candidate_numbers
        .iter()
        .copied()
        .find(|n| *n != c.number)
        .expect("decoy");
    let r = st
        .mfa_approve(&dp(&p), &c.challenge_id, wrong, &answer(&p, &d))
        .await;
    assert!(matches!(r, Err(MfaError::NumberMismatch)), "{r:?}");
    assert_eq!(row(&st, &c.challenge_id).await.status, "denied");
    assert!(
        actions(&st)
            .await
            .contains(&"mfa.number_mismatch".to_owned())
    );
    // the right number afterwards is too late
    let r = st
        .mfa_approve(&dp(&p), &c.challenge_id, c.number, &answer(&p, &d))
        .await;
    assert!(matches!(r, Err(MfaError::AlreadyConsumed)), "{r:?}");
}

#[tokio::test]
async fn a_wrong_number_with_a_bad_signature_does_not_deny() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    let d = details(&st, &p, &c.challenge_id).await;
    let wrong = d
        .candidate_numbers
        .iter()
        .copied()
        .find(|n| *n != c.number)
        .expect("decoy");
    // signed by the request key, which is not biometric-gated
    let bad = sign_message(
        &p.request,
        &rustmfa_contract::ChallengeMessage {
            challenge_id: &d.challenge_id,
            nonce: &d.nonce,
            login_id: &d.login_id,
            device_id: &p.id,
            expires_at: &d.expires_at,
            audience: &d.audience,
        },
    );
    let r = st.mfa_approve(&dp(&p), &c.challenge_id, wrong, &bad).await;
    assert!(matches!(r, Err(MfaError::DeviceNotAuthorized)), "{r:?}");
    assert_eq!(row(&st, &c.challenge_id).await.status, "pending");
    // and the right answer still works
    let ok = st
        .mfa_approve(&dp(&p), &c.challenge_id, c.number, &answer(&p, &d))
        .await;
    assert_eq!(ok.expect("approve"), ChallengeStatus::Approved);
}

#[tokio::test]
async fn approve_after_expiry_gives_expired() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    let sig = answer(&p, &details(&st, &p, &c.challenge_id).await);
    let late = now() + 91;
    let r = st
        .mfa_approve_at(&dp(&p), &c.challenge_id, c.number, &sig, late)
        .await;
    assert!(matches!(r, Err(MfaError::Expired)), "{r:?}");
    assert_eq!(row(&st, &c.challenge_id).await.status, "expired");
    assert!(
        actions(&st)
            .await
            .contains(&"mfa.challenge_expired".to_owned())
    );
    // the last second is still inside, the boundary second is not
    let c2 = create(&st, &p, "l2").await;
    let sig2 = answer(&p, &details(&st, &p, &c2.challenge_id).await);
    let exp = row(&st, &c2.challenge_id).await.expires_at;
    let r = st
        .mfa_approve_at(&dp(&p), &c2.challenge_id, c2.number, &sig2, exp)
        .await;
    assert!(matches!(r, Err(MfaError::Expired)), "{r:?}");
    let c3 = create(&st, &p, "l3").await;
    let sig3 = answer(&p, &details(&st, &p, &c3.challenge_id).await);
    let exp3 = row(&st, &c3.challenge_id).await.expires_at;
    let ok = st
        .mfa_approve_at(&dp(&p), &c3.challenge_id, c3.number, &sig3, exp3 - 1)
        .await;
    assert!(ok.is_ok(), "{ok:?}");
}

#[tokio::test]
async fn expiry_is_audited_once_and_status_maps_lazily() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    assert_eq!(
        st.mfa_challenge_status_at(&c.challenge_id, now())
            .await
            .expect("s"),
        ChallengeStatus::Pending
    );
    let late = now() + 100;
    for _ in 0..3 {
        assert_eq!(
            st.mfa_challenge_status_at(&c.challenge_id, late)
                .await
                .expect("s"),
            ChallengeStatus::Expired
        );
    }
    let n = actions(&st)
        .await
        .iter()
        .filter(|a| *a == "mfa.challenge_expired")
        .count();
    assert_eq!(n, 1);
    let r = st.mfa_challenge_status("ch_unknown").await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
}

#[tokio::test]
async fn get_of_an_expired_challenge_gives_expired() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    let r = st
        .mfa_get_challenge_at(&dp(&p), &c.challenge_id, now() + 100)
        .await;
    assert!(matches!(r, Err(MfaError::Expired)), "{r:?}");
}

#[tokio::test]
async fn approve_by_other_device_of_same_user_gives_not_authorized() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let b = second_phone(&st, &a, "dev_b").await;
    let c = create(&st, &a, "l").await;
    let d = details(&st, &a, &c.challenge_id).await;
    // b even signs with its own approval key over a message naming itself
    let sig = answer(&b, &d);
    let r = st
        .mfa_approve(&dp(&b), &c.challenge_id, c.number, &sig)
        .await;
    assert!(matches!(r, Err(MfaError::DeviceNotAuthorized)), "{r:?}");
    let r = st.mfa_deny(&dp(&b), &c.challenge_id, &sig).await;
    assert!(matches!(r, Err(MfaError::DeviceNotAuthorized)), "{r:?}");
    let r = st.mfa_get_challenge(&dp(&b), &c.challenge_id).await;
    assert!(matches!(r, Err(MfaError::DeviceNotAuthorized)), "{r:?}");
    assert_eq!(row(&st, &c.challenge_id).await.status, "pending");
}

#[tokio::test]
async fn challenge_of_other_user_gives_not_found() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let b = enrolled(&st, "ben", "dev_b").await;
    let c = create(&st, &a, "l").await;
    let sig = answer(&a, &details(&st, &a, &c.challenge_id).await);
    let r = st
        .mfa_approve(&dp(&b), &c.challenge_id, c.number, &sig)
        .await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
    let r = st.mfa_deny(&dp(&b), &c.challenge_id, &sig).await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
    let r = st.mfa_get_challenge(&dp(&b), &c.challenge_id).await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
    // the same answer as for a challenge that does not exist
    let r = st.mfa_get_challenge(&dp(&b), "ch_unknown").await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
    assert_eq!(row(&st, &c.challenge_id).await.status, "pending");
}

#[tokio::test]
async fn revoked_device_cannot_approve_and_challenge_stays_pending() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    let sig = answer(&p, &details(&st, &p, &c.challenge_id).await);
    st.inner
        .db
        .mfa_device_revoke("dev_a", p.user_id, now())
        .await
        .expect("revoke");
    let r = st
        .mfa_approve(&dp(&p), &c.challenge_id, c.number, &sig)
        .await;
    assert!(matches!(r, Err(MfaError::DeviceRevoked)), "{r:?}");
    let r = st.mfa_deny(&dp(&p), &c.challenge_id, &sig).await;
    assert!(matches!(r, Err(MfaError::DeviceRevoked)), "{r:?}");
    assert_eq!(row(&st, &c.challenge_id).await.status, "pending");
}

#[tokio::test]
async fn signature_over_wrong_login_or_device_or_nonce_is_rejected() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "login-1").await;
    let d = details(&st, &p, &c.challenge_id).await;
    let sign = |f: &dyn Fn(&mut [String; 6])| {
        let mut v = [
            d.challenge_id.clone(),
            d.nonce.clone(),
            d.login_id.clone(),
            p.id.clone(),
            d.expires_at.clone(),
            d.audience.clone(),
        ];
        f(&mut v);
        sign_message(
            &p.approval,
            &rustmfa_contract::ChallengeMessage {
                challenge_id: &v[0],
                nonce: &v[1],
                login_id: &v[2],
                device_id: &v[3],
                expires_at: &v[4],
                audience: &v[5],
            },
        )
    };
    let altered = [
        ("challenge", sign(&|v| v[0] = "ch_other".into())),
        ("nonce", sign(&|v| v[1] = "othernonce".into())),
        ("login", sign(&|v| v[2] = "login-2".into())),
        ("device", sign(&|v| v[3] = "dev_x".into())),
        ("expiry", sign(&|v| v[4] = "2099-01-01T00:00:00Z".into())),
        ("audience", sign(&|v| v[5] = "elsewhere".into())),
    ];
    for (name, sig) in altered {
        let r = st
            .mfa_approve(&dp(&p), &c.challenge_id, c.number, &sig)
            .await;
        assert!(
            matches!(r, Err(MfaError::DeviceNotAuthorized)),
            "{name}: {r:?}"
        );
        let r = st.mfa_deny(&dp(&p), &c.challenge_id, &sig).await;
        assert!(
            matches!(r, Err(MfaError::DeviceNotAuthorized)),
            "{name}: {r:?}"
        );
        assert_eq!(row(&st, &c.challenge_id).await.status, "pending", "{name}");
    }
}

#[tokio::test]
async fn der_and_garbage_signatures_are_rejected_and_do_not_consume() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    let d = details(&st, &p, &c.challenge_id).await;
    let rng = SystemRandom::new();
    let alg = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).expect("key");
    let asn1 = ring::signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).expect("p");
    let msg = rustmfa_contract::canonical_message(&rustmfa_contract::ChallengeMessage {
        challenge_id: &d.challenge_id,
        nonce: &d.nonce,
        login_id: &d.login_id,
        device_id: &p.id,
        expires_at: &d.expires_at,
        audience: &d.audience,
    })
    .expect("m");
    let der = URL_SAFE_NO_PAD.encode(asn1.sign(&rng, msg.as_bytes()).expect("s").as_ref());
    for bad in [der.as_str(), "", "!!!", "AAAA"] {
        let r = st
            .mfa_approve(&dp(&p), &c.challenge_id, c.number, bad)
            .await;
        assert!(
            matches!(r, Err(MfaError::InvalidRequest(_))),
            "{bad:?}: {r:?}"
        );
        let r = st.mfa_deny(&dp(&p), &c.challenge_id, bad).await;
        assert!(
            matches!(r, Err(MfaError::InvalidRequest(_))),
            "{bad:?}: {r:?}"
        );
    }
    assert_eq!(row(&st, &c.challenge_id).await.status, "pending");
}

#[tokio::test]
async fn deny_requires_valid_signature_and_never_approves() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    let d = details(&st, &p, &c.challenge_id).await;
    let bad = sign_message(
        &p.request,
        &rustmfa_contract::ChallengeMessage {
            challenge_id: &d.challenge_id,
            nonce: &d.nonce,
            login_id: &d.login_id,
            device_id: &p.id,
            expires_at: &d.expires_at,
            audience: &d.audience,
        },
    );
    let r = st.mfa_deny(&dp(&p), &c.challenge_id, &bad).await;
    assert!(matches!(r, Err(MfaError::DeviceNotAuthorized)), "{r:?}");
    assert_eq!(row(&st, &c.challenge_id).await.status, "pending");
    let s = st
        .mfa_deny(&dp(&p), &c.challenge_id, &answer(&p, &d))
        .await
        .expect("deny");
    assert_eq!(s, ChallengeStatus::Denied);
    assert_eq!(row(&st, &c.challenge_id).await.status, "denied");
    assert!(
        actions(&st)
            .await
            .contains(&"mfa.challenge_denied".to_owned())
    );
    // a denied challenge cannot be approved afterwards
    let r = st
        .mfa_approve(&dp(&p), &c.challenge_id, c.number, &answer(&p, &d))
        .await;
    assert!(matches!(r, Err(MfaError::AlreadyConsumed)), "{r:?}");
}

#[tokio::test]
async fn deny_after_expiry_gives_expired() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    let sig = answer(&p, &details(&st, &p, &c.challenge_id).await);
    let r = st
        .mfa_deny_at(&dp(&p), &c.challenge_id, &sig, now() + 100)
        .await;
    assert!(matches!(r, Err(MfaError::Expired)), "{r:?}");
}

#[tokio::test]
async fn pending_list_excludes_resolved_and_expired() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let other = second_phone(&st, &p, "dev_b").await;
    let open = create(&st, &p, "l1").await;
    let done = create(&st, &p, "l2").await;
    let _elsewhere = create(&st, &other, "l3").await;
    let sig = answer(&p, &details(&st, &p, &done.challenge_id).await);
    st.mfa_deny(&dp(&p), &done.challenge_id, &sig)
        .await
        .expect("deny");
    let list = st.mfa_pending_challenges(&dp(&p)).await.expect("list");
    let ids: Vec<&str> = list.iter().map(|d| d.challenge_id.as_str()).collect();
    assert_eq!(ids, [open.challenge_id.as_str()]);
    assert_eq!(list[0].status, ChallengeStatus::Pending);
    let later = st
        .mfa_pending_challenges_at(&dp(&p), now() + 100)
        .await
        .expect("list");
    assert!(later.is_empty());
}

struct Recording {
    calls: AtomicUsize,
    fail: bool,
}

impl PushChannel for Recording {
    fn notify<'a>(&'a self, channel: &'a str, token: &'a str, id: &'a str) -> PushFuture<'a> {
        Box::pin(async move {
            assert_eq!((channel, token), ("fcm", "fcm-secret-token"));
            assert!(id.starts_with("ch_"));
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err("gateway said no".into())
            } else {
                Ok(())
            }
        })
    }
}

async fn wait_for(mut cond: impl FnMut() -> bool) {
    for _ in 0..200 {
        if cond() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("condition not reached");
}

#[tokio::test]
async fn push_is_sent_after_creation_with_the_challenge_id() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    st.inner
        .db
        .mfa_device_set_push("dev_a", "fcm", "fcm-secret-token")
        .await
        .expect("set");
    let rec = Arc::new(Recording {
        calls: AtomicUsize::new(0),
        fail: false,
    });
    st.set_push_channel_for_tests(rec.clone());
    create(&st, &p, "l").await;
    wait_for(|| rec.calls.load(Ordering::SeqCst) == 1).await;
}

#[tokio::test]
async fn push_failure_does_not_fail_creation_and_is_logged_without_token() {
    let cap = captured();
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_pushfail").await;
    st.inner
        .db
        .mfa_device_set_push("dev_pushfail", "fcm", "fcm-secret-token")
        .await
        .expect("set");
    let rec = Arc::new(Recording {
        calls: AtomicUsize::new(0),
        fail: true,
    });
    st.set_push_channel_for_tests(rec.clone());
    let c = create(&st, &p, "l").await;
    assert_eq!(row(&st, &c.challenge_id).await.status, "pending");
    let logged = || {
        let out = String::from_utf8(cap.0.lock().expect("lock").clone()).expect("utf8");
        out.lines()
            .any(|l| l.contains(&c.challenge_id) && l.contains("gateway said no"))
    };
    wait_for(logged).await;
    let out = String::from_utf8(cap.0.lock().expect("lock").clone()).expect("utf8");
    assert!(!out.contains("fcm-secret-token"));
}

#[tokio::test]
async fn create_is_rate_limited_per_user() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let b = enrolled(&st, "ben", "dev_b").await;
    for i in 0..5 {
        create(&st, &a, &format!("l{i}")).await;
    }
    let r = st
        .mfa_create_challenge(a.user_id, &a.id, "l9", "x", IP)
        .await;
    assert!(matches!(r, Err(MfaError::RateLimited { .. })), "{r:?}");
    create(&st, &b, "l1").await;
}

#[tokio::test]
async fn audit_events_written_for_create_approve_deny_mismatch_expire() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let ok = create(&st, &p, "l1").await;
    let no = create(&st, &p, "l2").await;
    let mis = create(&st, &p, "l3").await;
    let old = create(&st, &p, "l4").await;
    let sig = |id: &str| {
        let id = id.to_owned();
        let st = &st;
        let p = &p;
        async move { answer(p, &details(st, p, &id).await) }
    };
    st.mfa_approve(
        &dp(&p),
        &ok.challenge_id,
        ok.number,
        &sig(&ok.challenge_id).await,
    )
    .await
    .expect("approve");
    st.mfa_deny(&dp(&p), &no.challenge_id, &sig(&no.challenge_id).await)
        .await
        .expect("deny");
    let d = details(&st, &p, &mis.challenge_id).await;
    let wrong = d
        .candidate_numbers
        .iter()
        .copied()
        .find(|n| *n != mis.number)
        .expect("w");
    let _ = st
        .mfa_approve(
            &dp(&p),
            &mis.challenge_id,
            wrong,
            &sig(&mis.challenge_id).await,
        )
        .await;
    let _ = st
        .mfa_challenge_status_at(&old.challenge_id, now() + 100)
        .await;
    let events = st
        .audit_events(&crate::Actor::Cli, 0)
        .await
        .expect("events");
    let has = |a: &str, target: &str| events.iter().any(|e| e.action == a && e.target == target);
    assert!(has("mfa.challenge_created", &ok.challenge_id));
    assert!(has("mfa.challenge_approved", &ok.challenge_id));
    assert!(has("mfa.challenge_denied", &no.challenge_id));
    assert!(has("mfa.number_mismatch", &mis.challenge_id));
    assert!(has("mfa.challenge_expired", &old.challenge_id));
    let actors: Vec<&str> = events
        .iter()
        .filter(|e| e.action.starts_with("mfa.challenge") || e.action == "mfa.number_mismatch")
        .map(|e| e.actor.as_str())
        .collect();
    assert!(actors.iter().all(|a| *a == "anna"), "{actors:?}");
    let all: String = events
        .iter()
        .map(|e| format!("{} {} {}", e.target, e.details, e.actor))
        .collect();
    let d = details(&st, &p, &ok.challenge_id).await;
    for secret in [d.nonce.as_str(), "fcm-token", &answer(&p, &d)] {
        assert!(!all.contains(secret), "audit contains {secret}");
    }
    let _ = add_user;
}

#[tokio::test]
async fn the_lifetime_follows_the_configuration() {
    let (_d, st) = state().await;
    let st = st.with_mfa(crate::MfaConfig {
        challenge_ttl_secs: 30,
        ..crate::MfaConfig::default()
    });
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    assert_eq!(c.expires_in_seconds, 30);
    let r = row(&st, &c.challenge_id).await;
    assert_eq!(r.expires_at - r.created_at, 30);
}

#[tokio::test]
async fn pending_list_never_shows_a_challenge_of_another_user() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let b = enrolled(&st, "ben", "dev_b").await;
    // a row that breaks the rule "a challenge belongs to its device's user"
    st.inner
        .db
        .mfa_challenge_insert(&rostdav_meta::NewChallenge {
            id: "ch_stray",
            user_id: b.user_id,
            device_id: &a.id,
            login_ref: "l",
            nonce: "n",
            number: 42,
            candidates: "[42,11,12]",
            audience: "rostdav",
            login_device: "x",
            expires_at: now() + 90,
        })
        .await
        .expect("insert");
    let list = st.mfa_pending_challenges(&dp(&a)).await.expect("list");
    assert!(list.is_empty(), "{list:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_approves_still_give_exactly_one_winner() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    for round in 0..5 {
        unlimit(&st, p.user_id);
        let c = create(&st, &p, &format!("l{round}")).await;
        let sig = answer(&p, &details(&st, &p, &c.challenge_id).await);
        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let (st, d, id, sig) = (st.clone(), dp(&p), c.challenge_id.clone(), sig.clone());
                tokio::spawn(async move { st.mfa_approve(&d, &id, c.number, &sig).await })
            })
            .collect();
        let mut oks = 0;
        for t in tasks {
            match t.await.expect("join") {
                Ok(_) => oks += 1,
                Err(MfaError::AlreadyConsumed) => {}
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        assert_eq!(oks, 1, "round {round}");
    }
}

#[tokio::test]
async fn a_stale_row_loses_to_an_answer_that_came_first() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    let stale = row(&st, &c.challenge_id).await;
    assert!(
        st.inner
            .db
            .mfa_challenge_resolve(&c.challenge_id, "approved", now())
            .await
            .expect("resolve")
    );
    let r = st
        .finish(
            &stale,
            ChallengeStatus::Approved,
            "mfa.challenge_approved",
            now(),
        )
        .await;
    assert!(matches!(r, Err(MfaError::AlreadyConsumed)), "{r:?}");
    // lost to a denial the same way
    let r = st
        .finish(
            &stale,
            ChallengeStatus::Denied,
            "mfa.challenge_denied",
            now(),
        )
        .await;
    assert!(matches!(r, Err(MfaError::AlreadyConsumed)), "{r:?}");
    assert_eq!(
        actions(&st)
            .await
            .iter()
            .filter(|a| *a == "mfa.challenge_approved")
            .count(),
        0
    );
}

#[tokio::test]
async fn a_stale_row_whose_time_ran_out_gives_expired() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let c = create(&st, &p, "l").await;
    let stale = row(&st, &c.challenge_id).await;
    let r = st
        .finish(
            &stale,
            ChallengeStatus::Approved,
            "mfa.challenge_approved",
            now() + 100,
        )
        .await;
    assert!(matches!(r, Err(MfaError::Expired)), "{r:?}");
    assert_eq!(row(&st, &c.challenge_id).await.status, "expired");
}
