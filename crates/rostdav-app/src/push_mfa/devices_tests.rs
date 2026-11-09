use std::net::{IpAddr, Ipv4Addr};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;

use super::{DevicePrincipal, MfaError};
use crate::AppState;
use crate::push_mfa::testkit::{
    Opts, Phone, enrolled, fixed_key, fixture, live_opts, spki_b64, state,
};
use crate::push_mfa::{AttestationPolicy, MfaConfig};

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

fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

async fn device(st: &AppState, id: &str) -> rostdav_meta::DeviceRow {
    st.inner
        .db
        .mfa_device_get(id)
        .await
        .expect("get")
        .expect("row")
}

#[tokio::test]
async fn list_shows_only_own_devices() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let _b = enrolled(&st, "ben", "dev_b").await;
    let list = st.mfa_list_devices(a.user_id).await.expect("list");
    assert_eq!(list.len(), 1);
    let d = &list[0];
    assert_eq!(
        (
            d.device_id.as_str(),
            d.device_name.as_str(),
            d.status.as_str()
        ),
        ("dev_a", "Pixel", "active")
    );
    assert_eq!(
        (d.push_channel.as_str(), d.hardware_backed, d.strongbox),
        ("fcm", true, false)
    );
    assert_eq!(d.created_at.len(), 20);
    assert_eq!(d.last_seen_at, None);
    // a revoked phone stays in the list, marked as such
    st.mfa_revoke_device(a.user_id, "dev_a", "anna")
        .await
        .expect("revoke");
    let list = st.mfa_list_devices(a.user_id).await.expect("list");
    assert_eq!(list[0].status, "revoked");
    assert!(st.mfa_list_devices(9999).await.expect("none").is_empty());
}

#[tokio::test]
async fn list_has_no_secret_fields() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    // every field is named: a new field that could carry a key or token breaks this test
    let super::DeviceInfo {
        device_id: _,
        device_name: _,
        status: _,
        push_channel: _,
        hardware_backed: _,
        strongbox: _,
        created_at: _,
        last_seen_at: _,
    } = st
        .mfa_list_devices(a.user_id)
        .await
        .expect("list")
        .remove(0);
}

#[tokio::test]
async fn revoke_marks_revoked_and_pending_challenges_expire() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let open = st
        .mfa_create_challenge(a.user_id, "dev_a", "l1", "x", IP)
        .await
        .expect("c1");
    let other = st
        .mfa_create_challenge(a.user_id, "dev_a", "l2", "x", IP)
        .await
        .expect("c2");
    st.mfa_revoke_device(a.user_id, "dev_a", "anna")
        .await
        .expect("revoke");
    let d = device(&st, "dev_a").await;
    assert_eq!(d.status, "revoked");
    assert!(d.revoked_at.is_some());
    for c in [&open, &other] {
        assert_eq!(
            st.mfa_challenge_status(&c.challenge_id).await.expect("s"),
            crate::ChallengeStatus::Expired
        );
    }
    let events = st
        .audit_events(&crate::Actor::Cli, 0)
        .await
        .expect("events");
    let revoked: Vec<_> = events
        .iter()
        .filter(|e| e.action == "mfa.device_revoked")
        .collect();
    assert_eq!(revoked.len(), 1);
    assert_eq!(
        (revoked[0].actor.as_str(), revoked[0].target.as_str()),
        ("anna", "dev_a")
    );
    let expired = events
        .iter()
        .filter(|e| e.action == "mfa.challenge_expired")
        .count();
    assert_eq!(expired, 2);
    // a second revoke finds no active device
    let r = st.mfa_revoke_device(a.user_id, "dev_a", "anna").await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
}

#[tokio::test]
async fn a_challenge_answered_before_the_revoke_keeps_its_status() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let c = st
        .mfa_create_challenge(a.user_id, "dev_a", "l1", "x", IP)
        .await
        .expect("c");
    assert!(
        st.inner
            .db
            .mfa_challenge_resolve(&c.challenge_id, "approved", now())
            .await
            .expect("r")
    );
    st.mfa_revoke_device(a.user_id, "dev_a", "anna")
        .await
        .expect("revoke");
    assert_eq!(
        st.mfa_challenge_status(&c.challenge_id).await.expect("s"),
        crate::ChallengeStatus::Approved
    );
}

#[tokio::test]
async fn revoke_other_users_device_gives_not_found() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let b = enrolled(&st, "ben", "dev_b").await;
    let r = st.mfa_revoke_device(a.user_id, "dev_b", "anna").await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
    let r = st.mfa_revoke_device(a.user_id, "dev_nope", "anna").await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
    assert_eq!(device(&st, "dev_b").await.status, "active");
    let _ = b;
}

#[tokio::test]
async fn revoked_device_fails_authentication() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    st.mfa_revoke_device(a.user_id, "dev_a", "anna")
        .await
        .expect("revoke");
    let ts = now();
    let msg = rustmfa_contract::request_signing_string("GET", "/x", ts, "n1", b"").expect("m");
    let sig = a
        .request
        .sign(&SystemRandom::new(), msg.as_bytes())
        .expect("sig");
    let h = format!(
        r#"RustMFA-Sig device_id="dev_a",ts="{ts}",nonce="n1",sig="{}""#,
        URL_SAFE_NO_PAD.encode(sig.as_ref())
    );
    let r = st.mfa_authenticate_device(&h, "GET", "/x", b"").await;
    assert!(matches!(r, Err(MfaError::DeviceRevoked)), "{r:?}");
}

#[tokio::test]
async fn device_may_revoke_only_devices_of_its_own_user() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let b = enrolled(&st, "ben", "dev_b").await;
    // a second phone of anna
    let a2 = Phone {
        id: "dev_a2".into(),
        request: fixed_key(),
        approval: fixed_key(),
        user_id: a.user_id,
    };
    st.inner
        .db
        .mfa_device_insert(&rostdav_meta::NewDevice {
            id: "dev_a2",
            user_id: a.user_id,
            name: "Tablet",
            request_pub: &spki_b64(&a2.request),
            approval_pub: &spki_b64(&a2.approval),
            push_channel: "fcm",
            push_token: "t",
            hardware_backed: true,
            strongbox: false,
        })
        .await
        .expect("insert");
    let r = st.mfa_revoke_device_as(&dp(&a), "dev_b").await;
    assert!(matches!(r, Err(MfaError::NotFound)), "{r:?}");
    assert_eq!(device(&st, "dev_b").await.status, "active");
    // anna's phone may revoke her other phone, and itself
    st.mfa_revoke_device_as(&dp(&a), "dev_a2")
        .await
        .expect("other own");
    assert_eq!(device(&st, "dev_a2").await.status, "revoked");
    st.mfa_revoke_device_as(&dp(&a), "dev_a")
        .await
        .expect("self");
    // the audit actor is the owner's name
    let events = st
        .audit_events(&crate::Actor::Cli, 0)
        .await
        .expect("events");
    assert!(
        events
            .iter()
            .filter(|e| e.action == "mfa.device_revoked")
            .all(|e| e.actor == "anna")
    );
    let _ = b;
}

#[tokio::test]
async fn update_push_token_changes_the_channel_and_audits_without_the_token() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    st.mfa_update_push_token(
        &dp(&a),
        "dev_a",
        "unifiedpush",
        "https://up.example/secret-endpoint",
    )
    .await
    .expect("update");
    let d = device(&st, "dev_a").await;
    assert_eq!(
        (d.push_channel.as_str(), d.push_token.as_str()),
        ("unifiedpush", "https://up.example/secret-endpoint")
    );
    let events = st
        .audit_events(&crate::Actor::Cli, 0)
        .await
        .expect("events");
    let e = events
        .iter()
        .find(|e| e.action == "mfa.push_token_updated")
        .expect("audited");
    assert_eq!((e.actor.as_str(), e.target.as_str()), ("anna", "dev_a"));
    let all: String = events
        .iter()
        .map(|e| format!("{} {} {}", e.target, e.details, e.actor))
        .collect();
    assert!(!all.contains("secret-endpoint"));
}

#[tokio::test]
async fn update_push_token_validates_channel_and_token() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let long = "x".repeat(4097);
    for (ch, tok) in [
        ("sms", "t"),
        ("fcm", ""),
        ("fcm", long.as_str()),
        ("fcm", "a\nb"),
    ] {
        let r = st.mfa_update_push_token(&dp(&a), "dev_a", ch, tok).await;
        assert!(
            matches!(r, Err(MfaError::InvalidRequest(_))),
            "{ch} {tok:?}: {r:?}"
        );
    }
    assert_eq!(device(&st, "dev_a").await.push_token, "t");
}

#[tokio::test]
async fn update_push_token_for_other_device_is_forbidden() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let _b = enrolled(&st, "ben", "dev_b").await;
    // even a device of the same user may only change its own token
    let r = st
        .mfa_update_push_token(&dp(&a), "dev_b", "fcm", "evil")
        .await;
    assert!(matches!(r, Err(MfaError::DeviceNotAuthorized)), "{r:?}");
    assert_eq!(device(&st, "dev_b").await.push_token, "t");
}

#[tokio::test]
async fn update_push_token_of_a_revoked_device_is_refused() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    st.mfa_revoke_device(a.user_id, "dev_a", "anna")
        .await
        .expect("revoke");
    let r = st
        .mfa_update_push_token(&dp(&a), "dev_a", "fcm", "new")
        .await;
    assert!(r.is_err());
    assert_eq!(device(&st, "dev_a").await.push_token, "t");
}

struct Rotation {
    request: ring::signature::EcdsaKeyPair,
    request_pub: String,
    chain: Vec<String>,
    approval_pub: String,
    root: Vec<u8>,
}

/// New keys with a chain that attests the new approval key for `"rotate:<id>:<request_pub>"`.
fn rotation(st: &AppState, id: &str, strongbox: bool) -> Rotation {
    let request = fixed_key();
    let request_pub = spki_b64(&request);
    let f = fixture(Opts {
        challenge: sha256(format!("rotate:{id}:{request_pub}").as_bytes()),
        attestation_level: if strongbox { 2 } else { 1 },
        keymaster_level: if strongbox { 2 } else { 1 },
        ..live_opts()
    });
    st.set_attestation_roots_for_tests(vec![f.root.clone()]);
    Rotation {
        request,
        request_pub,
        chain: f.chain.clone(),
        approval_pub: f.approval_spki.clone(),
        root: f.root.clone(),
    }
}

#[tokio::test]
async fn rotate_keys_replaces_both_keys_and_old_signatures_stop_working() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let r = rotation(&st, "dev_a", true);
    st.mfa_rotate_keys(&dp(&a), "dev_a", &r.request_pub, &r.approval_pub, &r.chain)
        .await
        .expect("rotate");
    let d = device(&st, "dev_a").await;
    assert_eq!(
        (d.request_pub.as_str(), d.approval_pub.as_str()),
        (r.request_pub.as_str(), r.approval_pub.as_str())
    );
    assert_eq!((d.hardware_backed, d.strongbox), (true, true));
    let ts = now();
    let header = |key: &ring::signature::EcdsaKeyPair, nonce: &str| {
        let msg = rustmfa_contract::request_signing_string("GET", "/x", ts, nonce, b"").expect("m");
        let sig = key.sign(&SystemRandom::new(), msg.as_bytes()).expect("sig");
        format!(
            r#"RustMFA-Sig device_id="dev_a",ts="{ts}",nonce="{nonce}",sig="{}""#,
            URL_SAFE_NO_PAD.encode(sig.as_ref())
        )
    };
    let old = st
        .mfa_authenticate_device(&header(&a.request, "o1"), "GET", "/x", b"")
        .await;
    assert!(matches!(old, Err(MfaError::Unauthenticated)), "{old:?}");
    st.mfa_authenticate_device(&header(&r.request, "n1"), "GET", "/x", b"")
        .await
        .expect("new request key works");
    // the old approval key no longer answers challenges
    let c = st
        .mfa_create_challenge(a.user_id, "dev_a", "l", "x", IP)
        .await
        .expect("c");
    let det = st
        .mfa_get_challenge(&dp(&a), &c.challenge_id)
        .await
        .expect("d");
    let msg = rustmfa_contract::canonical_message(&rustmfa_contract::ChallengeMessage {
        challenge_id: &det.challenge_id,
        nonce: &det.nonce,
        login_id: &det.login_id,
        device_id: "dev_a",
        expires_at: &det.expires_at,
        audience: &det.audience,
    })
    .expect("m");
    let sig = a
        .approval
        .sign(&SystemRandom::new(), msg.as_bytes())
        .expect("sig");
    let out = st
        .mfa_approve(
            &dp(&a),
            &c.challenge_id,
            c.number,
            &URL_SAFE_NO_PAD.encode(sig.as_ref()),
        )
        .await;
    assert!(matches!(out, Err(MfaError::DeviceNotAuthorized)), "{out:?}");
    let events = st
        .audit_events(&crate::Actor::Cli, 0)
        .await
        .expect("events");
    assert!(
        events
            .iter()
            .any(|e| e.action == "mfa.key_rotated" && e.target == "dev_a" && e.actor == "anna")
    );
}

#[tokio::test]
async fn rotate_requires_valid_attestation_when_policy_required() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let good = rotation(&st, "dev_a", false);
    // an attestation made for another device id
    let other = rotation(&st, "dev_zzz", false);
    // both chains share one test root only if it is trusted: trust both
    st.set_attestation_roots_for_tests(vec![good.root.clone(), other.root.clone()]);
    let wrong = st
        .mfa_rotate_keys(
            &dp(&a),
            "dev_a",
            &good.request_pub,
            &other.approval_pub,
            &other.chain,
        )
        .await;
    assert!(
        matches!(wrong, Err(MfaError::InvalidRequest(_))),
        "{wrong:?}"
    );
    // an attestation that belongs to a different request key
    let swapped = st
        .mfa_rotate_keys(
            &dp(&a),
            "dev_a",
            &spki_b64(&fixed_key()),
            &good.approval_pub,
            &good.chain,
        )
        .await;
    assert!(
        matches!(swapped, Err(MfaError::InvalidRequest(_))),
        "{swapped:?}"
    );
    // no chain
    let none = st
        .mfa_rotate_keys(&dp(&a), "dev_a", &good.request_pub, &good.approval_pub, &[])
        .await;
    assert!(matches!(none, Err(MfaError::InvalidRequest(_))), "{none:?}");
    // a chain that no trusted root signed
    st.set_attestation_roots_for_tests(vec![other.root.clone()]);
    let untrusted = st
        .mfa_rotate_keys(
            &dp(&a),
            "dev_a",
            &good.request_pub,
            &good.approval_pub,
            &good.chain,
        )
        .await;
    assert!(
        matches!(untrusted, Err(MfaError::InvalidRequest(_))),
        "{untrusted:?}"
    );
    let d = device(&st, "dev_a").await;
    assert_ne!(d.request_pub, good.request_pub);
    assert_ne!(d.approval_pub, good.approval_pub);
    // and the right one works
    st.set_attestation_roots_for_tests(vec![good.root.clone()]);
    st.mfa_rotate_keys(
        &dp(&a),
        "dev_a",
        &good.request_pub,
        &good.approval_pub,
        &good.chain,
    )
    .await
    .expect("rotate");
}

#[tokio::test]
async fn rotate_without_attestation_is_allowed_when_the_policy_is_off() {
    let (_d, st) = state().await;
    let st = st.with_mfa(MfaConfig {
        attestation: AttestationPolicy::Off,
        ..MfaConfig::default()
    });
    let a = enrolled(&st, "anna", "dev_a").await;
    let (req, app) = (spki_b64(&fixed_key()), spki_b64(&fixed_key()));
    st.mfa_rotate_keys(&dp(&a), "dev_a", &req, &app, &[])
        .await
        .expect("rotate");
    let d = device(&st, "dev_a").await;
    assert_eq!((d.request_pub, d.approval_pub), (req, app));
    assert_eq!((d.hardware_backed, d.strongbox), (false, false));
}

#[tokio::test]
async fn rotate_validates_keys_and_the_device() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let _b = enrolled(&st, "ben", "dev_b").await;
    let r = rotation(&st, "dev_a", false);
    let k = spki_b64(&fixed_key());
    for (req, app) in [
        ("not a key", r.approval_pub.as_str()),
        (r.request_pub.as_str(), "not a key"),
        (r.request_pub.as_str(), r.request_pub.as_str()),
    ] {
        let out = st
            .mfa_rotate_keys(&dp(&a), "dev_a", req, app, &r.chain)
            .await;
        assert!(
            matches!(out, Err(MfaError::InvalidRequest(_))),
            "{req} {app}: {out:?}"
        );
    }
    // another device is not the caller's to rotate
    let out = st
        .mfa_rotate_keys(&dp(&a), "dev_b", &r.request_pub, &r.approval_pub, &r.chain)
        .await;
    assert!(matches!(out, Err(MfaError::DeviceNotAuthorized)), "{out:?}");
    assert_ne!(device(&st, "dev_b").await.request_pub, r.request_pub);
    let _ = k;
}

#[tokio::test]
async fn audit_view_contains_only_own_mfa_events_and_no_secrets() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let b = enrolled(&st, "ben", "dev_b").await;
    // registration events come from enrollment; simulate its audit rows the same way
    st.audit(
        "anna",
        "mfa.device_registered",
        "dev_a",
        None,
        serde_json::json!({}),
    )
    .await;
    st.audit(
        "ben",
        "mfa.device_registered",
        "dev_b",
        None,
        serde_json::json!({}),
    )
    .await;
    st.audit("anna", "auth.login", "x", None, serde_json::json!({}))
        .await;
    st.audit(
        "anna",
        "mfa.enroll_token_created",
        "",
        None,
        serde_json::json!({}),
    )
    .await;
    st.audit(
        "anna",
        "mfa.push_token_updated",
        "dev_a",
        None,
        serde_json::json!({}),
    )
    .await;
    let c = st
        .mfa_create_challenge(a.user_id, "dev_a", "l1", "x", IP)
        .await
        .expect("c");
    st.mfa_create_challenge(b.user_id, "dev_b", "l2", "x", IP)
        .await
        .expect("c");
    st.mfa_revoke_device(a.user_id, "dev_a", "anna")
        .await
        .expect("revoke");
    let view = st.mfa_audit_events(a.user_id).await.expect("view");
    let names: Vec<&str> = view.iter().map(|e| e.event.as_str()).collect();
    // newest first; challenge expiry from the revoke, then the revoke itself
    assert_eq!(
        names,
        [
            "device_revoked",
            "challenge_expired",
            "challenge_created",
            "device_registered"
        ]
    );
    let created = view
        .iter()
        .find(|e| e.event == "challenge_created")
        .expect("created");
    assert_eq!(created.device_id.as_deref(), Some("dev_a"));
    let revoked = view
        .iter()
        .find(|e| e.event == "device_revoked")
        .expect("revoked");
    assert_eq!(revoked.device_id.as_deref(), Some("dev_a"));
    assert!(view.iter().all(|e| e.at.len() == 20 && e.at.ends_with('Z')));
    let all = format!("{view:?}");
    for secret in [c.challenge_id.as_str(), "fcm", "l1"] {
        assert!(!all.contains(secret), "view contains {secret}");
    }
    // ben sees his own and nothing of anna's
    let bens = st.mfa_audit_events(b.user_id).await.expect("view");
    assert!(bens.iter().all(|e| e.device_id.as_deref() == Some("dev_b")));
    assert_eq!(bens.len(), 2);
    assert!(st.mfa_audit_events(9999).await.expect("none").is_empty());
}

#[tokio::test]
async fn audit_view_is_capped_to_the_newest_events() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    for i in 0..250 {
        st.inner
            .db
            .record_event_at(
                1_000 + i,
                "anna",
                "mfa.challenge_created",
                "ch_x",
                "",
                r#"{"device_id":"dev_a"}"#,
            )
            .await
            .expect("event");
    }
    let view = st.mfa_audit_events(a.user_id).await.expect("view");
    assert_eq!(view.len(), 200);
}

#[tokio::test]
async fn the_owner_can_revoke_whoever_the_owner_is() {
    let (_d, st) = state().await;
    let _a = enrolled(&st, "anna", "dev_a").await;
    let b = enrolled(&st, "ben", "dev_b").await;
    assert_ne!(
        b.user_id, 1,
        "the test needs an owner who is not the first user"
    );
    st.mfa_revoke_device(b.user_id, "dev_b", "ben")
        .await
        .expect("revoke");
    assert_eq!(device(&st, "dev_b").await.status, "revoked");
    assert_eq!(device(&st, "dev_a").await.status, "active");
}

#[tokio::test]
async fn rotate_checks_the_keys_even_when_attestation_is_off() {
    let (_d, st) = state().await;
    let st = st.with_mfa(MfaConfig {
        attestation: AttestationPolicy::Off,
        ..MfaConfig::default()
    });
    let a = enrolled(&st, "anna", "dev_a").await;
    let before = device(&st, "dev_a").await;
    let k = spki_b64(&fixed_key());
    for (req, app) in [
        ("not a key", k.as_str()),
        (k.as_str(), "not a key"),
        (k.as_str(), k.as_str()),
    ] {
        let out = st.mfa_rotate_keys(&dp(&a), "dev_a", req, app, &[]).await;
        assert!(
            matches!(out, Err(MfaError::InvalidRequest(_))),
            "{req} {app}: {out:?}"
        );
    }
    let after = device(&st, "dev_a").await;
    assert_eq!(
        (after.request_pub, after.approval_pub),
        (before.request_pub, before.approval_pub)
    );
}
