//! Enrolling a phone (ADR 0014): a single-use token from a signed-in account, then
//! registration with the phone's two public keys and a key attestation.

use std::net::IpAddr;

use rostdav_meta::NewDevice;
use serde_json::json;

use super::attestation::{AttestationResult, verify_attestation};
use super::{AttestationPolicy, MfaError, google_roots};
use crate::audit::sanitize_text;
use crate::secrets::{hash_token, random_token};
use crate::{AppState, Principal, Scope, Via, now_secs};

const TOKEN_LEN: usize = 40;
const MAX_TOKEN_INPUT: usize = 128;
const MAX_PUSH_TOKEN: usize = 4096;
/// One message for unknown, used, expired and foreign tokens, so nothing is learned from it.
const TOKEN_REASON: &str = "enrollment token is invalid or expired";

/// A token to put in the enrollment QR code.
#[derive(Debug)]
pub struct EnrollToken {
    pub token: String,
    pub expires_in_seconds: i64,
}

/// What the phone sends to register. No `Debug`: it holds the enrollment token.
pub struct RegisterInput {
    pub enroll_token: String,
    pub device_name: String,
    /// Base64 of the X.509 SubjectPublicKeyInfo DER; signs the requests.
    pub request_public_key: String,
    /// Same encoding; biometric-gated, signs the challenge answers.
    pub approval_public_key: String,
    pub key_algorithm: String,
    /// Base64 DER certificates, leaf first, for the approval key.
    pub attestation_chain: Vec<String>,
    pub push_channel: String,
    pub push_token: String,
}

#[derive(Debug)]
pub struct Registered {
    pub device_id: String,
    pub status: &'static str,
}

fn invalid(reason: &'static str) -> MfaError {
    MfaError::InvalidRequest(reason)
}

fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

/// Checks the input without touching the token; returns the cleaned device name.
fn validate(i: &RegisterInput) -> Result<String, MfaError> {
    if i.enroll_token.is_empty() || i.enroll_token.len() > MAX_TOKEN_INPUT {
        return Err(invalid(TOKEN_REASON));
    }
    if i.key_algorithm != "ES256" {
        return Err(invalid("key algorithm must be ES256"));
    }
    if rustmfa_contract::check_spki(&i.request_public_key).is_err() {
        return Err(invalid("request public key is not a P-256 key"));
    }
    if rustmfa_contract::check_spki(&i.approval_public_key).is_err() {
        return Err(invalid("approval public key is not a P-256 key"));
    }
    if i.request_public_key == i.approval_public_key {
        return Err(invalid("request key and approval key must differ"));
    }
    if !matches!(i.push_channel.as_str(), "fcm" | "unifiedpush") {
        return Err(invalid("push channel must be fcm or unifiedpush"));
    }
    if i.push_token.is_empty()
        || i.push_token.len() > MAX_PUSH_TOKEN
        || i.push_token.chars().any(char::is_control)
    {
        return Err(invalid("push token is missing or too long"));
    }
    let name = sanitize_text(&i.device_name).trim().to_owned();
    if name.is_empty() {
        return Err(invalid("device name is missing"));
    }
    Ok(name)
}

impl AppState {
    /// A single-use token for the enrollment QR code. Only a user who signed in with the
    /// account itself may create one: not an app password, not a public link.
    pub async fn mfa_create_enroll_token(&self, p: &Principal) -> Result<EnrollToken, MfaError> {
        if p.via != Via::AccountPassword || p.scope != Scope::Full {
            return Err(MfaError::Unauthenticated);
        }
        let key = format!("mfa-enroll:{}", p.user_id);
        self.inner
            .mfa_limiter
            .check(&key)
            .map_err(|retry_after_secs| MfaError::RateLimited { retry_after_secs })?;
        let ttl = self.mfa_cfg().enroll_ttl_secs;
        let token = random_token(TOKEN_LEN);
        self.inner
            .db
            .mfa_enroll_token_put(&hash_token(&token), p.user_id, now_secs() + ttl)
            .await?;
        // every token counts, not only failures: five per 15 minutes
        self.inner.mfa_limiter.record_failure(&key);
        self.audit(&p.name, "mfa.enroll_token_created", "", None, json!({}))
            .await;
        Ok(EnrollToken {
            token,
            expires_in_seconds: ttl,
        })
    }

    /// Registers a phone. A wrong token or a failed attestation counts against the caller's
    /// address (five in 15 minutes); a malformed request does not. The token is used up before
    /// the attestation is checked, so a failed attempt burns it.
    pub async fn mfa_register_device(
        &self,
        input: RegisterInput,
        ip: IpAddr,
    ) -> Result<Registered, MfaError> {
        let key = format!("mfa-register:{ip}");
        self.inner
            .mfa_limiter
            .check(&key)
            .map_err(|retry_after_secs| MfaError::RateLimited { retry_after_secs })?;
        let name = validate(&input)?;
        let result = self.register_checked(&input, &name, ip).await;
        if matches!(result, Err(MfaError::InvalidRequest(_))) {
            self.inner.mfa_limiter.record_failure(&key);
        }
        result
    }

    async fn register_checked(
        &self,
        input: &RegisterInput,
        name: &str,
        ip: IpAddr,
    ) -> Result<Registered, MfaError> {
        let now = now_secs();
        let user_id = self
            .inner
            .db
            .mfa_enroll_token_consume(&hash_token(&input.enroll_token), now)
            .await?
            .ok_or(invalid(TOKEN_REASON))?;
        let user = self
            .inner
            .db
            .find_user_by_id(user_id)
            .await?
            .filter(|u| !u.disabled)
            .ok_or(invalid(TOKEN_REASON))?;
        let attested = match self.mfa_cfg().attestation {
            AttestationPolicy::Required => verify_attestation(
                &input.attestation_chain,
                &input.approval_public_key,
                &sha256(input.enroll_token.as_bytes()),
                &self.attestation_roots(),
                now,
            )?,
            AttestationPolicy::Off => AttestationResult {
                hardware_backed: false,
                strongbox: false,
            },
        };
        let device_id = format!("dev_{}", random_token(22));
        self.inner
            .db
            .mfa_device_insert(&NewDevice {
                id: &device_id,
                user_id,
                name,
                request_pub: &input.request_public_key,
                approval_pub: &input.approval_public_key,
                push_channel: &input.push_channel,
                push_token: &input.push_token,
                hardware_backed: attested.hardware_backed,
                strongbox: attested.strongbox,
            })
            .await?;
        self.audit(
            &user.name,
            "mfa.device_registered",
            &device_id,
            Some(ip),
            json!({
                "hardware_backed": attested.hardware_backed,
                "strongbox": attested.strongbox,
                "push_channel": input.push_channel,
            }),
        )
        .await;
        Ok(Registered {
            device_id,
            status: "active",
        })
    }

    /// Google's roots, unless a test set its own.
    fn attestation_roots(&self) -> Vec<Vec<u8>> {
        self.inner
            .mfa_roots
            .lock()
            .map_or_else(|e| e.into_inner().clone(), |g| g.clone())
            .unwrap_or_else(google_roots)
    }

    #[cfg(test)]
    pub(crate) fn set_attestation_roots_for_tests(&self, roots: Vec<Vec<u8>>) {
        if let Ok(mut g) = self.inner.mfa_roots.lock() {
            *g = Some(roots);
        }
    }
}
