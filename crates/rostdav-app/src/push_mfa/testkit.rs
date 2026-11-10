//! Test helpers: synthetic Android attestation chains signed with throwaway keys, fake phones,
//! a fresh application state. Compiled for this crate's tests and, with the `test-util` feature,
//! for the integration tests of the HTTP crate. Never part of a production build.

use base64::{Engine, engine::general_purpose::STANDARD};
use der::asn1::{BitString, ObjectIdentifier, OctetString, UtcTime};
use der::{Any, Encode};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use std::str::FromStr;
use std::time::Duration;
use x509_cert::Certificate;
use x509_cert::TbsCertificate;
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

use crate::{AppState, Principal, Scope, Via};
use ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
use rostdav_meta::Db;
use rostdav_meta::NewDevice;
use rostdav_storage::LocalStore;
use std::sync::{Arc, Mutex};

pub const NOW: i64 = 1_800_000_000;
pub const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
pub const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
pub const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
pub const KEY_DESCRIPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");

pub fn key() -> EcdsaKeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).expect("key");
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).expect("pair")
}

pub fn spki(kp: &EcdsaKeyPair) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: EC_PUBLIC_KEY,
            parameters: Some(Any::encode_from(&P256).expect("param")),
        },
        subject_public_key: BitString::from_bytes(kp.public_key().as_ref()).expect("bits"),
    }
}

pub fn spki_b64(kp: &EcdsaKeyPair) -> String {
    STANDARD.encode(spki(kp).to_der().expect("der"))
}

pub fn time(secs: i64) -> Time {
    let d = Duration::from_secs(u64::try_from(secs).expect("positive"));
    Time::UtcTime(UtcTime::from_unix_duration(d).expect("utc time"))
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n if n < 128 => out.push(u8::try_from(n).expect("short")),
        n => {
            out.push(0x82);
            out.extend(u16::try_from(n).expect("len").to_be_bytes());
        }
    }
    out.extend(content);
    out
}

/// The value of the Android key description extension (only the fields the verifier reads).
pub fn key_description(attestation_level: u8, keymaster_level: u8, challenge: &[u8]) -> Vec<u8> {
    let mut seq = Vec::new();
    seq.extend(tlv(0x02, &[4])); // attestationVersion
    seq.extend(tlv(0x0a, &[attestation_level]));
    seq.extend(tlv(0x02, &[4])); // keymasterVersion
    seq.extend(tlv(0x0a, &[keymaster_level]));
    seq.extend(tlv(0x04, challenge)); // attestationChallenge
    seq.extend(tlv(0x04, &[])); // uniqueId
    seq.extend(tlv(0x30, &[])); // softwareEnforced
    seq.extend(tlv(0x30, &[])); // teeEnforced
    tlv(0x30, &seq)
}

pub fn issue(
    subject: &str,
    subject_kp: &EcdsaKeyPair,
    issuer: &str,
    issuer_kp: &EcdsaKeyPair,
    validity: (i64, i64),
    extension: Option<Vec<u8>>,
) -> Vec<u8> {
    let alg = AlgorithmIdentifierOwned {
        oid: ECDSA_SHA256,
        parameters: None,
    };
    let tbs = TbsCertificate {
        version: x509_cert::certificate::Version::V3,
        serial_number: SerialNumber::new(&[1]).expect("serial"),
        signature: alg.clone(),
        issuer: Name::from_str(issuer).expect("issuer"),
        validity: Validity {
            not_before: time(validity.0),
            not_after: time(validity.1),
        },
        subject: Name::from_str(subject).expect("subject"),
        subject_public_key_info: spki(subject_kp),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: extension.map(|v| {
            vec![Extension {
                extn_id: KEY_DESCRIPTION,
                critical: false,
                extn_value: OctetString::new(v).expect("octets"),
            }]
        }),
    };
    let sig = issuer_kp
        .sign(&SystemRandom::new(), &tbs.to_der().expect("tbs"))
        .expect("sign");
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: alg,
        signature: BitString::from_bytes(sig.as_ref()).expect("sig"),
    }
    .to_der()
    .expect("cert")
}

pub struct Opts {
    pub attestation_level: u8,
    pub keymaster_level: u8,
    pub challenge: Vec<u8>,
    pub leaf_validity: (i64, i64),
    pub with_extension: bool,
    pub include_root: bool,
    /// The time the root and intermediate certificates are valid around.
    pub base: i64,
    pub leaf_issuer: &'static str,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            attestation_level: 1,
            keymaster_level: 1,
            challenge: b"challenge-bytes".to_vec(),
            leaf_validity: (NOW - 1000, NOW + 1000),
            with_extension: true,
            include_root: true,
            base: NOW,
            leaf_issuer: "CN=Test Intermediate",
        }
    }
}

pub struct Fixture {
    pub chain: Vec<String>,
    pub approval_spki: String,
    pub root: Vec<u8>,
    pub leaf_der: Vec<u8>,
    pub intermediate_der: Vec<u8>,
    #[allow(dead_code)] // signs the challenge answers in the challenge tests
    pub approval_kp: EcdsaKeyPair,
}

pub fn fixture(o: Opts) -> Fixture {
    let (root_kp, inter_kp, leaf_kp) = (key(), key(), key());
    let wide = (o.base - 100_000, o.base + 100_000);
    let root = issue(
        "CN=Test Root",
        &root_kp,
        "CN=Test Root",
        &root_kp,
        wide,
        None,
    );
    let inter = issue(
        "CN=Test Intermediate",
        &inter_kp,
        "CN=Test Root",
        &root_kp,
        wide,
        None,
    );
    let ext = o
        .with_extension
        .then(|| key_description(o.attestation_level, o.keymaster_level, &o.challenge));
    let leaf = issue(
        "CN=Test Leaf",
        &leaf_kp,
        o.leaf_issuer,
        &inter_kp,
        o.leaf_validity,
        ext,
    );
    let mut chain = vec![STANDARD.encode(&leaf), STANDARD.encode(&inter)];
    if o.include_root {
        chain.push(STANDARD.encode(&root));
    }
    Fixture {
        chain,
        approval_spki: spki_b64(&leaf_kp),
        root,
        leaf_der: leaf,
        intermediate_der: inter,
        approval_kp: leaf_kp,
    }
}

/// A fresh application state in a temporary directory.
pub async fn state() -> (tempfile::TempDir, AppState) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = LocalStore::open(dir.path().join("data"))
        .await
        .expect("store");
    let db = Db::open(&Db::default_url(store.root())).await.expect("db");
    db.migrate().await.expect("migrate");
    (dir, AppState::new(db, store).await.expect("state"))
}

/// A user who signed in with the account password, as the web interface sees them.
pub async fn add_user(st: &AppState, name: &str) -> Principal {
    let u = st
        .add_user(name, "correct-horse-battery", false)
        .await
        .expect("user");
    Principal {
        user_id: u.id,
        name: name.to_owned(),
        is_admin: false,
        via: Via::AccountPassword,
        scope: Scope::Full,
    }
}

/// A key whose signatures are raw R||S, as the phone's are.
pub fn fixed_key() -> EcdsaKeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("key");
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).expect("pair")
}

pub struct Phone {
    pub id: String,
    pub request: EcdsaKeyPair,
    pub approval: EcdsaKeyPair,
    pub user_id: i64,
}

pub async fn enrolled(st: &AppState, user: &str, id: &str) -> Phone {
    add_user(st, user).await;
    enroll_existing(st, user, id).await
}

/// A phone for a user that already exists.
pub async fn enroll_existing(st: &AppState, user: &str, id: &str) -> Phone {
    let user_id = st
        .inner
        .db
        .find_user(user)
        .await
        .expect("query")
        .expect("user exists")
        .id;
    let (request, approval) = (fixed_key(), fixed_key());
    st.inner
        .db
        .mfa_device_insert(&NewDevice {
            id,
            user_id,
            name: "Pixel",
            request_pub: &spki_b64(&request),
            approval_pub: &spki_b64(&approval),
            push_channel: "fcm",
            push_token: "t",
            hardware_backed: true,
            strongbox: false,
        })
        .await
        .expect("insert");
    Phone {
        id: id.to_owned(),
        request,
        approval,
        user_id,
    }
}

/// Answers a pending challenge as the phone would (`approved` or `denied`), without the signed
/// request. For tests of the sign-in pages, which do not test the phone's protocol.
pub async fn resolve_challenge(st: &AppState, challenge_id: &str, to: &str) -> bool {
    st.inner
        .db
        .mfa_challenge_resolve(challenge_id, to, crate::now_secs())
        .await
        .expect("resolve")
}

#[derive(Clone, Default)]
pub struct Capture(pub Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut g) = self.0.lock() {
            g.extend_from_slice(b);
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

/// One capturing subscriber for the whole test binary. A per-test subscriber is not reliable:
/// tracing caches whether a call site is enabled, and a parallel test without a subscriber can
/// switch it off.
pub fn captured() -> &'static Capture {
    static CAPTURE: std::sync::OnceLock<Capture> = std::sync::OnceLock::new();
    CAPTURE.get_or_init(|| {
        let cap = Capture::default();
        let sub = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(cap.clone())
            .finish();
        // the first test to get here wins; no other test sets a global subscriber
        let _ = tracing::subscriber::set_global_default(sub);
        cap
    })
}

/// Attestation options whose certificates are valid now: the service reads the real clock.
pub fn live_opts() -> Opts {
    let now = crate::now_secs();
    Opts {
        base: now,
        leaf_validity: (now - 1000, now + 1000),
        ..Opts::default()
    }
}

/// Ids of the open challenges of one phone.
pub async fn pending_challenge_ids(st: &AppState, device_id: &str) -> Vec<String> {
    st.inner
        .db
        .mfa_challenges_pending(device_id, crate::now_secs())
        .await
        .expect("pending")
        .into_iter()
        .map(|c| c.id)
        .collect()
}

/// The id of an existing user.
pub async fn user_id(st: &AppState, name: &str) -> i64 {
    st.inner
        .db
        .find_user(name)
        .await
        .expect("query")
        .expect("user exists")
        .id
}

/// An existing user as the web interface sees them after the password step.
pub async fn principal(st: &AppState, name: &str, is_admin: bool) -> Principal {
    Principal {
        user_id: user_id(st, name).await,
        name: name.to_owned(),
        is_admin,
        via: Via::AccountPassword,
        scope: Scope::Full,
    }
}
