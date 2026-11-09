use std::net::{IpAddr, Ipv4Addr};

use crate::push_mfa::testkit::{Opts, add_user, fixture, key, spki_b64, state};
use crate::push_mfa::{AttestationPolicy, MfaConfig, MfaError};
use crate::{AppState, Principal, Scope, Via};

use super::enroll::RegisterInput;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

fn input(token: &str, f: &crate::push_mfa::testkit::Fixture) -> RegisterInput {
    RegisterInput {
        enroll_token: token.to_owned(),
        device_name: "Pixel 8".into(),
        request_public_key: spki_b64(&key()),
        approval_public_key: f.approval_spki.clone(),
        key_algorithm: "ES256".into(),
        attestation_chain: f.chain.clone(),
        push_channel: "fcm".into(),
        push_token: "fcm-token".into(),
    }
}

/// A token for `p`, and a chain that attests a key for exactly that token.
async fn enrollable(st: &AppState, p: &Principal) -> (String, crate::push_mfa::testkit::Fixture) {
    let token = st.mfa_create_enroll_token(p).await.expect("token").token;
    let f = fixture(Opts {
        challenge: sha256(token.as_bytes()),
        ..opts()
    });
    st.set_attestation_roots_for_tests(vec![f.root.clone()]);
    (token, f)
}

/// Chains that are valid now: the service reads the real clock.
fn opts() -> Opts {
    let now = crate::now_secs();
    Opts {
        base: now,
        leaf_validity: (now - 1000, now + 1000),
        ..Opts::default()
    }
}

/// One way to break a registration request.
type Mutation = Box<dyn Fn(&mut RegisterInput)>;

fn invalid_reason<T: std::fmt::Debug>(r: Result<T, MfaError>) -> &'static str {
    match r {
        Err(MfaError::InvalidRequest(why)) => why,
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

#[tokio::test]
async fn enrollment_happy_path_creates_an_active_device() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let (token, f) = enrollable(&st, &anna).await;
    let done = st
        .mfa_register_device(input(&token, &f), IP)
        .await
        .expect("register");
    assert_eq!(done.status, "active");
    assert!(done.device_id.starts_with("dev_") && done.device_id.len() > 12);
    let row = st
        .inner
        .db
        .mfa_device_get(&done.device_id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!((row.user_id, row.status.as_str()), (anna.user_id, "active"));
    assert_eq!((row.hardware_backed, row.strongbox), (true, false));
    assert_eq!(row.approval_pub, f.approval_spki);
    assert_eq!(
        (row.push_channel.as_str(), row.push_token.as_str()),
        ("fcm", "fcm-token")
    );
}

#[tokio::test]
async fn token_has_the_configured_lifetime() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let t = st.mfa_create_enroll_token(&anna).await.expect("token");
    assert_eq!(t.expires_in_seconds, 300);
    assert!(t.token.len() >= 40);
    let st = st.with_mfa(MfaConfig {
        enroll_ttl_secs: 120,
        ..MfaConfig::default()
    });
    assert_eq!(
        st.mfa_create_enroll_token(&anna)
            .await
            .expect("token")
            .expires_in_seconds,
        120
    );
}

#[tokio::test]
async fn token_is_single_use() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let (token, f) = enrollable(&st, &anna).await;
    st.mfa_register_device(input(&token, &f), IP)
        .await
        .expect("first");
    let again = st.mfa_register_device(input(&token, &f), IP).await;
    assert_eq!(
        invalid_reason(again),
        "enrollment token is invalid or expired"
    );
    assert_eq!(
        st.inner
            .db
            .mfa_devices_of(anna.user_id)
            .await
            .expect("list")
            .len(),
        1
    );
}

#[tokio::test]
async fn unknown_and_expired_tokens_look_the_same() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let (_token, f) = enrollable(&st, &anna).await;
    let unknown = st.mfa_register_device(input("no-such-token", &f), IP).await;
    assert_eq!(
        invalid_reason(unknown),
        "enrollment token is invalid or expired"
    );
    let expired_hash = crate::secrets::hash_token("old-token");
    st.inner
        .db
        .mfa_enroll_token_put(&expired_hash, anna.user_id, crate::now_secs() - 1)
        .await
        .expect("put");
    let expired = st.mfa_register_device(input("old-token", &f), IP).await;
    assert_eq!(
        invalid_reason(expired),
        "enrollment token is invalid or expired"
    );
}

#[tokio::test]
async fn device_belongs_to_the_user_who_created_the_token() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let bob = add_user(&st, "bob").await;
    let (anna_token, f) = enrollable(&st, &anna).await;
    let (bob_token, g) = enrollable(&st, &bob).await;
    st.set_attestation_roots_for_tests(vec![f.root.clone(), g.root.clone()]);
    let a = st
        .mfa_register_device(input(&anna_token, &f), IP)
        .await
        .expect("anna");
    let b = st
        .mfa_register_device(input(&bob_token, &g), IP)
        .await
        .expect("bob");
    let owner = |id: String| {
        let st = st.clone();
        async move {
            st.inner
                .db
                .mfa_device_get(&id)
                .await
                .expect("get")
                .expect("row")
                .user_id
        }
    };
    assert_eq!(owner(a.device_id).await, anna.user_id);
    assert_eq!(owner(b.device_id).await, bob.user_id);
}

#[tokio::test]
async fn token_is_stored_only_hashed() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let token = st
        .mfa_create_enroll_token(&anna)
        .await
        .expect("token")
        .token;
    let now = crate::now_secs();
    assert_eq!(
        st.inner
            .db
            .mfa_enroll_token_consume(&token, now)
            .await
            .expect("plain"),
        None
    );
    let hashed = crate::secrets::hash_token(&token);
    assert_eq!(
        st.inner
            .db
            .mfa_enroll_token_consume(&hashed, now)
            .await
            .expect("hash"),
        Some(anna.user_id)
    );
}

#[tokio::test]
async fn software_attestation_is_rejected_and_burns_the_token() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let token = st
        .mfa_create_enroll_token(&anna)
        .await
        .expect("token")
        .token;
    let f = fixture(Opts {
        attestation_level: 0,
        keymaster_level: 0,
        challenge: sha256(token.as_bytes()),
        ..opts()
    });
    st.set_attestation_roots_for_tests(vec![f.root.clone()]);
    let r = st.mfa_register_device(input(&token, &f), IP).await;
    assert_eq!(invalid_reason(r), "key is not hardware backed");
    assert!(
        st.inner
            .db
            .mfa_devices_of(anna.user_id)
            .await
            .expect("list")
            .is_empty()
    );
    let retry = st.mfa_register_device(input(&token, &f), IP).await;
    assert_eq!(
        invalid_reason(retry),
        "enrollment token is invalid or expired"
    );
}

#[tokio::test]
async fn attestation_for_another_token_is_rejected() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let token = st
        .mfa_create_enroll_token(&anna)
        .await
        .expect("token")
        .token;
    let f = fixture(Opts {
        challenge: sha256(b"some other token"),
        ..opts()
    });
    st.set_attestation_roots_for_tests(vec![f.root.clone()]);
    let r = st.mfa_register_device(input(&token, &f), IP).await;
    assert_eq!(invalid_reason(r), "attestation challenge does not match");
    assert!(
        st.inner
            .db
            .mfa_devices_of(anna.user_id)
            .await
            .expect("list")
            .is_empty()
    );
}

#[tokio::test]
async fn untrusted_root_is_rejected_by_default() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let token = st
        .mfa_create_enroll_token(&anna)
        .await
        .expect("token")
        .token;
    let f = fixture(Opts {
        challenge: sha256(token.as_bytes()),
        ..opts()
    });
    // no test roots set: the pinned Google roots apply, and a synthetic chain does not reach them
    let r = st.mfa_register_device(input(&token, &f), IP).await;
    assert_eq!(
        invalid_reason(r),
        "attestation chain does not end in a trusted root"
    );
}

#[tokio::test]
async fn policy_off_skips_attestation() {
    let (_d, st) = state().await;
    let st = st.with_mfa(MfaConfig {
        attestation: AttestationPolicy::Off,
        ..MfaConfig::default()
    });
    let anna = add_user(&st, "anna").await;
    let token = st
        .mfa_create_enroll_token(&anna)
        .await
        .expect("token")
        .token;
    let f = fixture(opts());
    let mut i = input(&token, &f);
    i.attestation_chain = Vec::new();
    let done = st.mfa_register_device(i, IP).await.expect("register");
    let row = st
        .inner
        .db
        .mfa_device_get(&done.device_id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!((row.hardware_backed, row.strongbox), (false, false));
}

#[tokio::test]
async fn bad_input_is_rejected_without_burning_the_token() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let (token, f) = enrollable(&st, &anna).await;
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "key algorithm must be ES256",
            Box::new(|i| i.key_algorithm = "RS256".into()),
        ),
        (
            "request public key is not a P-256 key",
            Box::new(|i| i.request_public_key = "AAAA".into()),
        ),
        (
            "approval public key is not a P-256 key",
            Box::new(|i| i.approval_public_key = "!!!".into()),
        ),
        (
            "push channel must be fcm or unifiedpush",
            Box::new(|i| i.push_channel = "apns".into()),
        ),
        (
            "push token is missing or too long",
            Box::new(|i| i.push_token = String::new()),
        ),
        (
            "push token is missing or too long",
            Box::new(|i| i.push_token = "x".repeat(4097)),
        ),
        (
            "push token is missing or too long",
            Box::new(|i| i.push_token = "to\nken".into()),
        ),
        (
            "device name is missing",
            Box::new(|i| i.device_name = " \n\t".into()),
        ),
    ];
    for (why, mutate) in cases {
        let mut i = input(&token, &f);
        mutate(&mut i);
        assert_eq!(invalid_reason(st.mfa_register_device(i, IP).await), why);
    }
    // the token still works after all those mistakes
    assert!(st.mfa_register_device(input(&token, &f), IP).await.is_ok());
}

#[tokio::test]
async fn both_keys_must_differ() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let (token, f) = enrollable(&st, &anna).await;
    let mut i = input(&token, &f);
    i.request_public_key = f.approval_spki.clone();
    assert_eq!(
        invalid_reason(st.mfa_register_device(i, IP).await),
        "request key and approval key must differ"
    );
}

#[tokio::test]
async fn device_name_is_cleaned() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let (token, f) = enrollable(&st, &anna).await;
    let mut i = input(&token, &f);
    i.device_name = "My\nPhone\u{7}".into();
    let done = st.mfa_register_device(i, IP).await.expect("register");
    let row = st
        .inner
        .db
        .mfa_device_get(&done.device_id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(row.name, "MyPhone");
}

#[tokio::test]
async fn registration_is_rate_limited_per_address_after_failures() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let (token, f) = enrollable(&st, &anna).await;
    for _ in 0..5 {
        let r = st.mfa_register_device(input("guess", &f), IP).await;
        assert!(matches!(r, Err(MfaError::InvalidRequest(_))));
    }
    let blocked = st.mfa_register_device(input(&token, &f), IP).await;
    assert!(
        matches!(blocked, Err(MfaError::RateLimited { retry_after_secs }) if retry_after_secs > 0)
    );
    // another address is not affected
    let other = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    assert!(
        st.mfa_register_device(input(&token, &f), other)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn token_creation_is_rate_limited_per_user() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let bob = add_user(&st, "bob").await;
    for _ in 0..5 {
        st.mfa_create_enroll_token(&anna).await.expect("token");
    }
    assert!(matches!(
        st.mfa_create_enroll_token(&anna).await,
        Err(MfaError::RateLimited { .. })
    ));
    assert!(st.mfa_create_enroll_token(&bob).await.is_ok());
}

#[tokio::test]
async fn only_a_signed_in_account_can_create_tokens() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let app = Principal {
        via: Via::AppPassword(1),
        ..anna.clone()
    };
    let link = Principal {
        via: Via::Link(1),
        ..anna.clone()
    };
    let scoped = Principal {
        scope: Scope::Link {
            share_id: 1,
            node_id: 1,
            perms: 1,
        },
        ..anna.clone()
    };
    for p in [app, link, scoped] {
        assert!(matches!(
            st.mfa_create_enroll_token(&p).await,
            Err(MfaError::Unauthenticated)
        ));
    }
}

#[tokio::test]
async fn a_disabled_user_cannot_enroll() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let (token, f) = enrollable(&st, &anna).await;
    st.inner
        .db
        .set_user_disabled(anna.user_id, true)
        .await
        .expect("disable");
    let r = st.mfa_register_device(input(&token, &f), IP).await;
    assert_eq!(invalid_reason(r), "enrollment token is invalid or expired");
}

#[tokio::test]
async fn audit_records_token_and_device_without_secrets() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let (token, f) = enrollable(&st, &anna).await;
    let done = st
        .mfa_register_device(input(&token, &f), IP)
        .await
        .expect("register");
    let events = st
        .audit_events(&crate::Actor::Cli, 0)
        .await
        .expect("events");
    let actions: Vec<&str> = events.iter().map(|e| e.action.as_str()).collect();
    assert!(actions.contains(&"mfa.enroll_token_created"), "{actions:?}");
    let reg = events
        .iter()
        .find(|e| e.action == "mfa.device_registered")
        .expect("registered");
    assert_eq!(
        (reg.actor.as_str(), reg.target.as_str()),
        ("anna", done.device_id.as_str())
    );
    let all: String = events
        .iter()
        .map(|e| format!("{} {} {}", e.target, e.details, e.actor))
        .collect();
    for secret in [token.as_str(), f.approval_spki.as_str(), "fcm-token"] {
        assert!(!all.contains(secret), "audit contains {secret}");
    }
}
