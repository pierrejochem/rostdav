//! Verification of Android key attestation chains (ADR 0014).
//!
//! A phone proves that its approval key lives in secure hardware: the certificate chain that
//! Android issues for the key must lead to a pinned Google root, and the key description in the
//! leaf must name the expected challenge and a hardware security level. Format:
//! <https://source.android.com/docs/security/features/keystore/attestation>.

use base64::{Engine, engine::general_purpose::STANDARD};
use der::asn1::{AnyRef, ObjectIdentifier};
use der::{Decode, Encode, Reader, SliceReader, Tag, Tagged};
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use x509_cert::Certificate;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

use super::MfaError;

/// Most certificates a chain may have (Android sends three to five).
const MAX_CHAIN: usize = 8;
/// Largest accepted certificate: real ones are about 1 KiB.
const MAX_CERT_BYTES: usize = 16 * 1024;

const KEY_DESCRIPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const CURVE_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

/// What the chain proved about the approval key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestationResult {
    /// The key lives in a trusted execution environment or in a StrongBox.
    pub hardware_backed: bool,
    /// The key lives in a StrongBox (a separate secure element).
    pub strongbox: bool,
}

fn invalid(reason: &'static str) -> MfaError {
    MfaError::InvalidRequest(reason)
}

/// Checks an attestation chain.
///
/// `chain_b64` is leaf first, base64 (standard) DER; `trust_roots` are DER certificates. The chain
/// may end with a trusted root or with a certificate that one of the roots signed. Every
/// certificate must be valid at `now` (Unix seconds).
pub fn verify_attestation(
    chain_b64: &[String],
    approval_spki_b64: &str,
    expected_challenge: &[u8],
    trust_roots: &[Vec<u8>],
    now: i64,
) -> Result<AttestationResult, MfaError> {
    if chain_b64.is_empty() || chain_b64.len() > MAX_CHAIN {
        return Err(invalid("attestation chain is missing or too long"));
    }
    let mut ders = Vec::with_capacity(chain_b64.len());
    let mut certs = Vec::with_capacity(chain_b64.len());
    for b in chain_b64 {
        let unreadable = || invalid("attestation certificate cannot be read");
        let der_bytes = STANDARD.decode(b).map_err(|_| unreadable())?;
        if der_bytes.len() > MAX_CERT_BYTES {
            return Err(unreadable());
        }
        certs.push(Certificate::from_der(&der_bytes).map_err(|_| unreadable())?);
        ders.push(der_bytes);
    }
    if !certs.iter().all(|c| valid_at(c, now)) {
        return Err(invalid("attestation certificate is not valid now"));
    }
    for i in 0..certs.len() - 1 {
        let issuer = &certs[i + 1];
        let linked = certs[i].tbs_certificate.issuer == issuer.tbs_certificate.subject
            && verify_cert_signature(
                &ders[i],
                &certs[i],
                &issuer.tbs_certificate.subject_public_key_info,
            );
        if !linked {
            return Err(invalid("attestation chain is not signed correctly"));
        }
    }
    check_trust(&ders, &certs, trust_roots, now)?;

    let leaf = &certs[0];
    let description = leaf
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id == KEY_DESCRIPTION)
        .ok_or_else(|| invalid("attestation key description is missing"))?;
    let kd = parse_key_description(description.extn_value.as_bytes())
        .ok_or_else(|| invalid("attestation key description cannot be read"))?;

    // levels: 0 software, 1 trusted environment, 2 StrongBox
    if kd.attestation_level < 1 || kd.keymaster_level < 1 {
        return Err(invalid("key is not hardware backed"));
    }
    if !crate::secrets::ct_eq(kd.challenge, expected_challenge) {
        return Err(invalid("attestation challenge does not match"));
    }
    let attested = leaf.tbs_certificate.subject_public_key_info.to_der().ok();
    let claimed = STANDARD.decode(approval_spki_b64).ok();
    if attested.is_none() || attested != claimed {
        return Err(invalid("attested key is not the approval key"));
    }
    Ok(AttestationResult {
        hardware_backed: true,
        strongbox: kd.attestation_level == 2 && kd.keymaster_level == 2,
    })
}

/// The chain must end in a trusted root: the last certificate is one, or one signed it.
fn check_trust(
    ders: &[Vec<u8>],
    certs: &[Certificate],
    trust_roots: &[Vec<u8>],
    now: i64,
) -> Result<(), MfaError> {
    let (Some(last_der), Some(last)) = (ders.last(), certs.last()) else {
        return Err(invalid("attestation chain is missing or too long"));
    };
    let trusted = trust_roots.iter().any(|root_der| {
        if root_der == last_der {
            return true;
        }
        let Ok(root) = Certificate::from_der(root_der) else {
            return false;
        };
        valid_at(&root, now)
            && root.tbs_certificate.subject == last.tbs_certificate.issuer
            && verify_cert_signature(
                last_der,
                last,
                &root.tbs_certificate.subject_public_key_info,
            )
    });
    if trusted {
        Ok(())
    } else {
        Err(invalid("attestation chain does not end in a trusted root"))
    }
}

fn valid_at(cert: &Certificate, now: i64) -> bool {
    let secs = |t: &x509_cert::time::Time| i64::try_from(t.to_unix_duration().as_secs()).ok();
    let v = &cert.tbs_certificate.validity;
    matches!((secs(&v.not_before), secs(&v.not_after)), (Some(a), Some(b)) if a <= now && now <= b)
}

/// Whether `cert` is signed by the key in `issuer`. The signed bytes are taken from the
/// original encoding, not from a re-encoding.
pub(crate) fn verify_cert_signature(
    cert_der: &[u8],
    cert: &Certificate,
    issuer: &SubjectPublicKeyInfoOwned,
) -> bool {
    let Some(tbs) = tbs_bytes(cert_der) else {
        return false;
    };
    let Some(sig) = cert.signature.as_bytes() else {
        return false;
    };
    let Some(alg) = signature_algorithm(cert.signature_algorithm.oid, issuer) else {
        return false;
    };
    let Some(key) = issuer.subject_public_key.as_bytes() else {
        return false;
    };
    UnparsedPublicKey::new(alg, key).verify(tbs, sig).is_ok()
}

/// The `tbsCertificate` of a DER certificate, exactly as it was signed.
fn tbs_bytes(cert_der: &[u8]) -> Option<&[u8]> {
    let outer = AnyRef::from_der(cert_der).ok()?;
    if outer.tag() != Tag::Sequence {
        return None;
    }
    let body = outer.value();
    let mut reader = SliceReader::new(body).ok()?;
    AnyRef::decode(&mut reader).ok()?;
    let len = usize::try_from(u32::from(reader.position())).ok()?;
    body.get(..len)
}

fn signature_algorithm(
    sig_alg: ObjectIdentifier,
    issuer: &SubjectPublicKeyInfoOwned,
) -> Option<&'static dyn VerificationAlgorithm> {
    let key_alg = issuer.algorithm.oid;
    if key_alg == RSA_ENCRYPTION {
        return match sig_alg {
            RSA_SHA256 => Some(&signature::RSA_PKCS1_2048_8192_SHA256),
            RSA_SHA384 => Some(&signature::RSA_PKCS1_2048_8192_SHA384),
            RSA_SHA512 => Some(&signature::RSA_PKCS1_2048_8192_SHA512),
            _ => None,
        };
    }
    if key_alg != EC_PUBLIC_KEY {
        return None;
    }
    let curve = issuer
        .algorithm
        .parameters
        .as_ref()?
        .decode_as::<ObjectIdentifier>()
        .ok()?;
    match (curve, sig_alg) {
        (CURVE_P256, ECDSA_SHA256) => Some(&signature::ECDSA_P256_SHA256_ASN1),
        (CURVE_P256, ECDSA_SHA384) => Some(&signature::ECDSA_P256_SHA384_ASN1),
        (CURVE_P384, ECDSA_SHA256) => Some(&signature::ECDSA_P384_SHA256_ASN1),
        (CURVE_P384, ECDSA_SHA384) => Some(&signature::ECDSA_P384_SHA384_ASN1),
        _ => None,
    }
}

struct KeyDescription<'a> {
    attestation_level: u8,
    keymaster_level: u8,
    challenge: &'a [u8],
}

/// Reads the first five fields of the key description: attestationVersion,
/// attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel, attestationChallenge.
fn parse_key_description(value: &[u8]) -> Option<KeyDescription<'_>> {
    let seq = AnyRef::from_der(value).ok()?;
    if seq.tag() != Tag::Sequence {
        return None;
    }
    let mut r = SliceReader::new(seq.value()).ok()?;
    let level = |any: AnyRef<'_>| -> Option<u8> {
        match any.value() {
            [b] if any.tag() == Tag::Enumerated => Some(*b),
            _ => None,
        }
    };
    let version = AnyRef::decode(&mut r).ok()?;
    let attestation_level = level(AnyRef::decode(&mut r).ok()?)?;
    let keymaster_version = AnyRef::decode(&mut r).ok()?;
    let keymaster_level = level(AnyRef::decode(&mut r).ok()?)?;
    let challenge = AnyRef::decode(&mut r).ok()?;
    if version.tag() != Tag::Integer
        || keymaster_version.tag() != Tag::Integer
        || challenge.tag() != Tag::OctetString
    {
        return None;
    }
    Some(KeyDescription {
        attestation_level,
        keymaster_level,
        challenge: challenge.value(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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

    const NOW: i64 = 1_800_000_000;
    const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    const KEY_DESCRIPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");

    fn key() -> EcdsaKeyPair {
        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).expect("key");
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("pair")
    }

    fn spki(kp: &EcdsaKeyPair) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: EC_PUBLIC_KEY,
                parameters: Some(Any::encode_from(&P256).expect("param")),
            },
            subject_public_key: BitString::from_bytes(kp.public_key().as_ref()).expect("bits"),
        }
    }

    fn spki_b64(kp: &EcdsaKeyPair) -> String {
        STANDARD.encode(spki(kp).to_der().expect("der"))
    }

    fn time(secs: i64) -> Time {
        let d = Duration::from_secs(u64::try_from(secs).expect("positive"));
        Time::UtcTime(UtcTime::from_unix_duration(d).expect("utc time"))
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
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
    fn key_description(attestation_level: u8, keymaster_level: u8, challenge: &[u8]) -> Vec<u8> {
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

    fn issue(
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

    struct Opts {
        attestation_level: u8,
        keymaster_level: u8,
        challenge: Vec<u8>,
        leaf_validity: (i64, i64),
        with_extension: bool,
        include_root: bool,
        leaf_issuer: &'static str,
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
                leaf_issuer: "CN=Test Intermediate",
            }
        }
    }

    struct Fixture {
        chain: Vec<String>,
        approval_spki: String,
        root: Vec<u8>,
        leaf_der: Vec<u8>,
        intermediate_der: Vec<u8>,
    }

    fn fixture(o: Opts) -> Fixture {
        let (root_kp, inter_kp, leaf_kp) = (key(), key(), key());
        let wide = (NOW - 100_000, NOW + 100_000);
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
        }
    }

    fn verify(f: &Fixture) -> Result<AttestationResult, MfaError> {
        verify_attestation(
            &f.chain,
            &f.approval_spki,
            b"challenge-bytes",
            std::slice::from_ref(&f.root),
            NOW,
        )
    }

    fn reason(r: Result<AttestationResult, MfaError>) -> &'static str {
        match r {
            Err(MfaError::InvalidRequest(why)) => why,
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn accepts_tee_chain() {
        let r = verify(&fixture(Opts::default())).expect("ok");
        assert_eq!((r.hardware_backed, r.strongbox), (true, false));
    }

    #[test]
    fn accepts_strongbox_chain() {
        let f = fixture(Opts {
            attestation_level: 2,
            keymaster_level: 2,
            ..Opts::default()
        });
        let r = verify(&f).expect("ok");
        assert_eq!((r.hardware_backed, r.strongbox), (true, true));
    }

    #[test]
    fn strongbox_needs_both_levels() {
        let f = fixture(Opts {
            attestation_level: 2,
            keymaster_level: 1,
            ..Opts::default()
        });
        let r = verify(&f).expect("ok");
        assert_eq!((r.hardware_backed, r.strongbox), (true, false));
    }

    #[test]
    fn accepts_chain_that_leaves_out_the_root() {
        let f = fixture(Opts {
            include_root: false,
            ..Opts::default()
        });
        assert_eq!(f.chain.len(), 2);
        assert!(verify(&f).is_ok());
    }

    #[test]
    fn rejects_software_attestation_level() {
        let f = fixture(Opts {
            attestation_level: 0,
            keymaster_level: 0,
            ..Opts::default()
        });
        assert_eq!(reason(verify(&f)), "key is not hardware backed");
    }

    #[test]
    fn rejects_software_keymaster_under_tee_attestation() {
        let f = fixture(Opts {
            attestation_level: 1,
            keymaster_level: 0,
            ..Opts::default()
        });
        assert_eq!(reason(verify(&f)), "key is not hardware backed");
    }

    #[test]
    fn rejects_wrong_challenge() {
        let f = fixture(Opts {
            challenge: b"other".to_vec(),
            ..Opts::default()
        });
        assert_eq!(reason(verify(&f)), "attestation challenge does not match");
    }

    #[test]
    fn rejects_challenge_that_only_starts_with_the_expected_one() {
        let f = fixture(Opts {
            challenge: b"challenge-bytes-and-more".to_vec(),
            ..Opts::default()
        });
        assert_eq!(reason(verify(&f)), "attestation challenge does not match");
    }

    #[test]
    fn rejects_leaf_key_that_is_not_the_approval_key() {
        let mut f = fixture(Opts::default());
        f.approval_spki = spki_b64(&key());
        assert_eq!(reason(verify(&f)), "attested key is not the approval key");
    }

    #[test]
    fn rejects_unknown_root() {
        let f = fixture(Opts::default());
        let other = fixture(Opts::default()).root;
        let r = verify_attestation(
            &f.chain,
            &f.approval_spki,
            b"challenge-bytes",
            &[other],
            NOW,
        );
        assert_eq!(
            reason(r),
            "attestation chain does not end in a trusted root"
        );
    }

    #[test]
    fn rejects_no_trusted_roots() {
        let f = fixture(Opts::default());
        let r = verify_attestation(&f.chain, &f.approval_spki, b"challenge-bytes", &[], NOW);
        assert_eq!(
            reason(r),
            "attestation chain does not end in a trusted root"
        );
    }

    #[test]
    fn rejects_broken_signature_in_chain() {
        let mut f = fixture(Opts::default());
        let mut leaf = f.leaf_der.clone();
        *leaf.last_mut().expect("byte") ^= 0x01;
        f.chain[0] = STANDARD.encode(leaf);
        assert_eq!(
            reason(verify(&f)),
            "attestation chain is not signed correctly"
        );
    }

    #[test]
    fn rejects_chain_in_the_wrong_order() {
        let mut f = fixture(Opts::default());
        f.chain.swap(0, 1);
        assert!(matches!(verify(&f), Err(MfaError::InvalidRequest(_))));
        f.chain.swap(0, 1);
        f.chain[1] = STANDARD.encode(&f.leaf_der);
        assert!(matches!(verify(&f), Err(MfaError::InvalidRequest(_))));
    }

    #[test]
    fn rejects_a_valid_signature_under_the_wrong_issuer_name() {
        let f = fixture(Opts {
            leaf_issuer: "CN=Someone Else",
            ..Opts::default()
        });
        assert_eq!(
            reason(verify(&f)),
            "attestation chain is not signed correctly"
        );
    }

    #[test]
    fn rejects_expired_and_not_yet_valid_leaf() {
        let f = fixture(Opts {
            leaf_validity: (NOW - 1000, NOW - 1),
            ..Opts::default()
        });
        assert_eq!(
            reason(verify(&f)),
            "attestation certificate is not valid now"
        );
        let f = fixture(Opts {
            leaf_validity: (NOW + 1, NOW + 1000),
            ..Opts::default()
        });
        assert_eq!(
            reason(verify(&f)),
            "attestation certificate is not valid now"
        );
    }

    #[test]
    fn validity_bounds_are_inclusive() {
        let f = fixture(Opts {
            leaf_validity: (NOW, NOW),
            ..Opts::default()
        });
        assert!(verify(&f).is_ok());
    }

    #[test]
    fn rejects_missing_extension() {
        let f = fixture(Opts {
            with_extension: false,
            ..Opts::default()
        });
        assert_eq!(reason(verify(&f)), "attestation key description is missing");
    }

    #[test]
    fn rejects_garbage_extension() {
        let f = fixture(Opts::default());
        // a leaf whose extension is not a key description
        let (root_kp, leaf_kp) = (key(), key());
        let wide = (NOW - 1000, NOW + 1000);
        let root = issue("CN=R", &root_kp, "CN=R", &root_kp, wide, None);
        let leaf = issue(
            "CN=L",
            &leaf_kp,
            "CN=R",
            &root_kp,
            wide,
            Some(vec![0x01, 0x02]),
        );
        let chain = vec![STANDARD.encode(leaf)];
        let r = verify_attestation(
            &chain,
            &spki_b64(&leaf_kp),
            b"challenge-bytes",
            &[root],
            NOW,
        );
        assert_eq!(reason(r), "attestation key description cannot be read");
        drop(f);
    }

    #[test]
    fn rejects_empty_and_too_long_chains() {
        let f = fixture(Opts::default());
        let r = verify_attestation(
            &[],
            &f.approval_spki,
            b"challenge-bytes",
            std::slice::from_ref(&f.root),
            NOW,
        );
        assert_eq!(reason(r), "attestation chain is missing or too long");
        let long: Vec<String> =
            std::iter::repeat_n(STANDARD.encode(&f.intermediate_der), 9).collect();
        let r = verify_attestation(
            &long,
            &f.approval_spki,
            b"challenge-bytes",
            std::slice::from_ref(&f.root),
            NOW,
        );
        assert_eq!(reason(r), "attestation chain is missing or too long");
    }

    #[test]
    fn accepts_a_chain_of_eight() {
        // length limit is inclusive; the chain itself is checked after the length
        let f = fixture(Opts::default());
        let eight: Vec<String> = std::iter::repeat_n(f.chain[0].clone(), 8).collect();
        let r = verify_attestation(
            &eight,
            &f.approval_spki,
            b"challenge-bytes",
            std::slice::from_ref(&f.root),
            NOW,
        );
        assert_ne!(reason(r), "attestation chain is missing or too long");
    }

    #[test]
    fn rejects_bad_base64_and_bad_der() {
        let f = fixture(Opts::default());
        let r = verify_attestation(
            &["!!!".into()],
            &f.approval_spki,
            b"c",
            std::slice::from_ref(&f.root),
            NOW,
        );
        assert_eq!(reason(r), "attestation certificate cannot be read");
        let r = verify_attestation(
            &["AAAA".into()],
            &f.approval_spki,
            b"c",
            std::slice::from_ref(&f.root),
            NOW,
        );
        assert_eq!(reason(r), "attestation certificate cannot be read");
        let r = verify_attestation(
            &f.chain,
            "!!!",
            b"challenge-bytes",
            std::slice::from_ref(&f.root),
            NOW,
        );
        assert_eq!(reason(r), "attested key is not the approval key");
    }

    #[test]
    fn a_self_signed_chain_of_one_is_not_trusted_unless_it_is_a_root() {
        let f = fixture(Opts::default());
        let single = vec![STANDARD.encode(&f.root)];
        let r = verify_attestation(
            &single,
            &f.approval_spki,
            b"challenge-bytes",
            std::slice::from_ref(&f.root),
            NOW,
        );
        // trusted root, but it carries no key description
        assert_eq!(reason(r), "attestation key description is missing");
    }
}
