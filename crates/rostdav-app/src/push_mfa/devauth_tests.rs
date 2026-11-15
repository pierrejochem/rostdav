use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::EcdsaKeyPair;

use super::devauth::parse_authorization;
use crate::AppState;
use crate::push_mfa::MfaError;
use crate::push_mfa::testkit::{NOW, Phone, captured, enrolled, fixed_key, spki_b64, state};

const PATH: &str = "/mfa/v1/challenges?status=pending";

fn sign_with(
    key: &EcdsaKeyPair,
    method: &str,
    path: &str,
    ts: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    let msg = rustmfa_contract::request_signing_string(method, path, ts, nonce, body).expect("msg");
    let sig = key.sign(&SystemRandom::new(), msg.as_bytes()).expect("sig");
    URL_SAFE_NO_PAD.encode(sig.as_ref())
}

fn header(device: &str, ts: i64, nonce: &str, sig: &str) -> String {
    format!(r#"RustMFA-Sig device_id="{device}",ts="{ts}",nonce="{nonce}",sig="{sig}""#)
}

/// A correctly signed GET of `PATH`.
fn good(p: &Phone, ts: i64, nonce: &str) -> String {
    header(
        &p.id,
        ts,
        nonce,
        &sign_with(&p.request, "GET", PATH, ts, nonce, b""),
    )
}

async fn auth(st: &AppState, h: &str, now: i64) -> Result<super::DevicePrincipal, MfaError> {
    st.mfa_authenticate_device_at(h, "GET", PATH, b"", now)
        .await
}

fn is_unauth<T: std::fmt::Debug>(r: Result<T, MfaError>) -> bool {
    matches!(r, Err(MfaError::Unauthenticated))
}

#[tokio::test]
async fn valid_signed_request_authenticates() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let got = auth(&st, &good(&p, NOW, "n1"), NOW).await.expect("auth");
    assert_eq!((got.device_id.as_str(), got.user_id), ("dev_a", p.user_id));
}

#[tokio::test]
async fn skew_over_60_seconds_is_rejected() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    assert!(is_unauth(auth(&st, &good(&p, NOW - 61, "n1"), NOW).await));
    assert!(is_unauth(auth(&st, &good(&p, NOW + 61, "n2"), NOW).await));
    // the edges are inside
    assert!(auth(&st, &good(&p, NOW - 60, "n3"), NOW).await.is_ok());
    assert!(auth(&st, &good(&p, NOW + 60, "n4"), NOW).await.is_ok());
}

#[tokio::test]
async fn replayed_nonce_is_rejected() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let h = good(&p, NOW, "n1");
    assert!(auth(&st, &h, NOW).await.is_ok());
    assert!(is_unauth(auth(&st, &h, NOW + 1).await));
}

#[tokio::test]
async fn the_same_nonce_of_two_devices_does_not_collide() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let b = enrolled(&st, "ben", "dev_b").await;
    assert!(auth(&st, &good(&a, NOW, "same"), NOW).await.is_ok());
    assert!(auth(&st, &good(&b, NOW, "same"), NOW).await.is_ok());
}

#[tokio::test]
async fn nonce_after_window_is_accepted_again_and_old_nonces_purged() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    assert!(auth(&st, &good(&p, NOW, "n1"), NOW).await.is_ok());
    // still inside the window at 299 s
    assert!(is_unauth(
        auth(&st, &good(&p, NOW + 299, "n1"), NOW + 299).await
    ));
    // 301 s later the old row is purged and the nonce works again
    assert!(
        auth(&st, &good(&p, NOW + 301, "n1"), NOW + 301)
            .await
            .is_ok()
    );
    assert!(
        auth(&st, &good(&p, NOW + 302, "n2"), NOW + 302)
            .await
            .is_ok()
    );
    // only the nonces of the last window are left: n1 (new) and n2
    assert_eq!(
        st.inner
            .db
            .mfa_nonces_purge(NOW + 10_000)
            .await
            .expect("purge"),
        2
    );
}

#[tokio::test]
async fn revoked_device_gives_device_revoked() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    assert!(
        st.inner
            .db
            .mfa_device_revoke("dev_a", p.user_id, NOW)
            .await
            .expect("revoke")
    );
    let r = auth(&st, &good(&p, NOW, "n1"), NOW).await;
    assert!(matches!(r, Err(MfaError::DeviceRevoked)), "{r:?}");
}

#[tokio::test]
async fn a_forged_request_for_a_revoked_device_does_not_reveal_the_revocation() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    st.inner
        .db
        .mfa_device_revoke("dev_a", p.user_id, NOW)
        .await
        .expect("revoke");
    let forged = header(
        "dev_a",
        NOW,
        "n1",
        &sign_with(&fixed_key(), "GET", PATH, NOW, "n1", b""),
    );
    assert!(is_unauth(auth(&st, &forged, NOW).await));
}

#[tokio::test]
async fn a_disabled_account_cannot_authenticate_a_device() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    st.inner
        .db
        .set_user_disabled(p.user_id, true)
        .await
        .expect("disable");
    assert!(is_unauth(auth(&st, &good(&p, NOW, "n1"), NOW).await));
}

#[tokio::test]
async fn unknown_device_gives_unauthenticated() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let ghost = Phone {
        id: "dev_ghost".into(),
        request: fixed_key(),
        approval: fixed_key(),
        user_id: p.user_id,
    };
    assert!(is_unauth(auth(&st, &good(&ghost, NOW, "n1"), NOW).await));
}

#[tokio::test]
async fn tampered_body_or_query_is_rejected() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let sig = sign_with(&p.request, "POST", "/mfa/v1/x?a=1", NOW, "n1", b"{\"a\":1}");
    let h = header("dev_a", NOW, "n1", &sig);
    let ok = st
        .mfa_authenticate_device_at(&h, "POST", "/mfa/v1/x?a=1", b"{\"a\":1}", NOW)
        .await;
    assert!(ok.is_ok());
    for (m, path, body) in [
        ("POST", "/mfa/v1/x?a=1", &b"{\"a\":2}"[..]),
        ("POST", "/mfa/v1/x?a=2", &b"{\"a\":1}"[..]),
        ("PUT", "/mfa/v1/x?a=1", &b"{\"a\":1}"[..]),
    ] {
        // a fresh nonce for each try so only the signature can fail
        let nonce = format!("t-{m}-{path}-{}", body.len());
        let sig = sign_with(
            &p.request,
            "POST",
            "/mfa/v1/x?a=1",
            NOW,
            &nonce,
            b"{\"a\":1}",
        );
        let r = st
            .mfa_authenticate_device_at(&header("dev_a", NOW, &nonce, &sig), m, path, body, NOW)
            .await;
        assert!(is_unauth(r), "{m} {path} {body:?}");
    }
}

#[tokio::test]
async fn signature_by_approval_key_is_rejected() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let sig = sign_with(&p.approval, "GET", PATH, NOW, "n1", b"");
    assert!(is_unauth(
        auth(&st, &header("dev_a", NOW, "n1", &sig), NOW).await
    ));
}

#[tokio::test]
async fn a_bad_signature_does_not_burn_the_nonce() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let bad = sign_with(&p.approval, "GET", PATH, NOW, "n1", b"");
    assert!(is_unauth(
        auth(&st, &header("dev_a", NOW, "n1", &bad), NOW).await
    ));
    assert!(auth(&st, &good(&p, NOW, "n1"), NOW).await.is_ok());
}

#[tokio::test]
async fn der_signatures_are_rejected() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let rng = SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("key");
    let asn1 = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .expect("pair");
    // even with the right message, DER is not accepted
    let msg = rustmfa_contract::request_signing_string("GET", PATH, NOW, "n1", b"").expect("m");
    let der = asn1.sign(&rng, msg.as_bytes()).expect("sig");
    let h = header("dev_a", NOW, "n1", &URL_SAFE_NO_PAD.encode(der.as_ref()));
    assert!(is_unauth(auth(&st, &h, NOW).await));
    let _ = p;
}

#[test]
fn grammar_accepts_the_documented_form() {
    let a = parse_authorization(
        r#"RustMFA-Sig device_id="dev_a-1",ts="1800000000",nonce="n_1",sig="abc-_""#,
    )
    .expect("parse");
    assert_eq!(
        (a.device_id.as_str(), a.ts, a.nonce.as_str(), a.sig.as_str()),
        ("dev_a-1", 1_800_000_000, "n_1", "abc-_")
    );
}

#[test]
fn grammar_rejects_quotes_commas_newlines_and_oversize() {
    let ok = |d: &str, t: &str, n: &str, s: &str| {
        format!(r#"RustMFA-Sig device_id="{d}",ts="{t}",nonce="{n}",sig="{s}""#)
    };
    let long = "a".repeat(129);
    let edge = "a".repeat(128);
    assert!(parse_authorization(&ok("d", "1", &edge, "s")).is_ok());
    let bad = [
        ok("d", "1", &long, "s"),
        ok(&long, "1", "n", "s"),
        ok("d", "1", "n", &long),
        ok("d\"x", "1", "n", "s"),
        ok("d,x", "1", "n", "s"),
        ok("d\nx", "1", "n", "s"),
        ok("d\r", "1", "n", "s"),
        ok("d x", "1", "n", "s"),
        ok("d", "-1", "n", "s"),
        ok("d", "+1", "n", "s"),
        ok("d", "1.5", "n", "s"),
        ok("d", "", "n", "s"),
        ok("d", "99999999999999999999", "n", "s"),
        ok("", "1", "n", "s"),
        ok("d", "1", "", "s"),
        ok("d", "1", "n", ""),
        ok("dé", "1", "n", "s"),
        // wrong scheme, case, order, spacing, extra or repeated fields
        "Bearer abc".to_owned(),
        r#"rustmfa-sig device_id="d",ts="1",nonce="n",sig="s""#.to_owned(),
        r#"RustMFA-Sig ts="1",device_id="d",nonce="n",sig="s""#.to_owned(),
        r#"RustMFA-Sig device_id="d", ts="1", nonce="n", sig="s""#.to_owned(),
        r#"RustMFA-Sig  device_id="d",ts="1",nonce="n",sig="s""#.to_owned(),
        r#"RustMFA-Sig device_id="d",ts="1",nonce="n",sig="s",x="y""#.to_owned(),
        r#"RustMFA-Sig device_id="d",device_id="e",ts="1",nonce="n",sig="s""#.to_owned(),
        r#"RustMFA-Sig device_id="d",ts="1",nonce="n""#.to_owned(),
        format!("{} ", ok("d", "1", "n", "s")),
        String::new(),
    ];
    for h in bad {
        assert!(
            matches!(parse_authorization(&h), Err(MfaError::Unauthenticated)),
            "accepted: {h:?}"
        );
    }
}

#[tokio::test]
async fn failed_auth_is_rate_limited_per_device() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let b = enrolled(&st, "ben", "dev_b").await;
    let forged = |p: &Phone, n: &str| {
        header(
            &p.id,
            NOW,
            n,
            &sign_with(&fixed_key(), "GET", PATH, NOW, n, b""),
        )
    };
    for i in 0..5 {
        assert!(is_unauth(
            auth(&st, &forged(&a, &format!("f{i}")), NOW).await
        ));
    }
    // blocked: even a correct request is refused
    let r = auth(&st, &good(&a, NOW, "ok1"), NOW).await;
    assert!(matches!(r, Err(MfaError::RateLimited { .. })), "{r:?}");
    // another device is not affected
    assert!(auth(&st, &good(&b, NOW, "ok1"), NOW).await.is_ok());
}

#[tokio::test]
async fn four_failures_do_not_block_and_a_success_resets_the_count() {
    let (_d, st) = state().await;
    let a = enrolled(&st, "anna", "dev_a").await;
    let forged = |n: &str| {
        header(
            "dev_a",
            NOW,
            n,
            &sign_with(&fixed_key(), "GET", PATH, NOW, n, b""),
        )
    };
    for i in 0..4 {
        assert!(is_unauth(auth(&st, &forged(&format!("f{i}")), NOW).await));
    }
    assert!(auth(&st, &good(&a, NOW, "ok1"), NOW).await.is_ok());
    for i in 4..8 {
        assert!(is_unauth(auth(&st, &forged(&format!("f{i}")), NOW).await));
    }
    assert!(auth(&st, &good(&a, NOW, "ok2"), NOW).await.is_ok());
}

#[tokio::test]
async fn last_seen_is_updated_on_success_only() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    let seen = || async {
        st.inner
            .db
            .mfa_device_get("dev_a")
            .await
            .expect("get")
            .expect("row")
            .last_seen_at
    };
    assert_eq!(seen().await, None);
    let bad = sign_with(&p.approval, "GET", PATH, NOW, "n0", b"");
    let _ = auth(&st, &header("dev_a", NOW, "n0", &bad), NOW).await;
    assert_eq!(seen().await, None);
    auth(&st, &good(&p, NOW, "n1"), NOW).await.expect("auth");
    assert_eq!(seen().await, Some(NOW));
}

#[tokio::test]
async fn no_secret_or_signature_in_logs() {
    let cap = captured();
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_logtest").await;
    let nonce = "secretnonce-0123";
    let sig = sign_with(&p.approval, "GET", PATH, NOW, nonce, b"");
    // bad signature, replay, skew and unknown device
    let _ = auth(&st, &header("dev_logtest", NOW, nonce, &sig), NOW).await;
    let h = good(&p, NOW, nonce);
    let _ = auth(&st, &h, NOW).await;
    let _ = auth(&st, &h, NOW).await;
    let _ = auth(&st, &good(&p, NOW - 500, "late"), NOW).await;
    let ghost = header("dev_logtest_ghost", NOW, nonce, &sig);
    let _ = auth(&st, &ghost, NOW).await;
    let good_sig = sign_with(&p.request, "GET", PATH, NOW, nonce, b"");
    let out = String::from_utf8(cap.0.lock().expect("lock").clone()).expect("utf8");
    let ours: String = out
        .lines()
        .filter(|l| l.contains("dev_logtest"))
        .collect::<Vec<_>>()
        .join("\n");
    for reason in [
        "signature does not verify",
        "nonce was already used",
        "timestamp outside the allowed skew",
        "unknown device",
    ] {
        assert!(ours.contains(reason), "missing log reason {reason}");
    }
    for secret in [sig.as_str(), good_sig.as_str(), nonce, "Authorization"] {
        assert!(!out.contains(secret), "log leaks {secret}");
    }
    assert!(!out.contains(&spki_b64(&p.request)));
}

#[tokio::test]
async fn a_nonce_is_free_again_exactly_300_seconds_later() {
    let (_d, st) = state().await;
    let p = enrolled(&st, "anna", "dev_a").await;
    assert!(auth(&st, &good(&p, NOW, "n1"), NOW).await.is_ok());
    assert!(
        auth(&st, &good(&p, NOW + 300, "n1"), NOW + 300)
            .await
            .is_ok()
    );
}
