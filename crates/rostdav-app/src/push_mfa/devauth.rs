//! Authenticating a phone's requests (ADR 0014).
//!
//! Every request carries `Authorization: RustMFA-Sig device_id="…",ts="…",nonce="…",sig="…"`.
//! The signature is made with the device's non-biometric request key over the request signing
//! string of the contract (method, path and query, timestamp, nonce, body hash).

use super::MfaError;
use crate::AppState;

/// How far a request timestamp may differ from the server clock.
const MAX_SKEW_SECS: i64 = 60;
/// How long a used nonce is remembered. It must exceed twice the skew.
const NONCE_WINDOW_SECS: i64 = 300;
const SCHEME: &str = "RustMFA-Sig ";
const MAX_VALUE: usize = 128;

/// The phone and account behind a verified request.
#[derive(Debug, PartialEq, Eq)]
pub struct DevicePrincipal {
    pub device_id: String,
    pub user_id: i64,
}

/// The parts of an `Authorization: RustMFA-Sig …` header. No `Debug`: it holds a signature.
pub struct ParsedAuth {
    pub device_id: String,
    pub ts: i64,
    pub nonce: String,
    pub sig: String,
}

/// The value of `name="…"`: one to 128 characters of `[A-Za-z0-9_-]`.
fn field<'a>(part: &'a str, name: &str) -> Option<&'a str> {
    let value = part
        .strip_prefix(name)?
        .strip_prefix("=\"")?
        .strip_suffix('"')?;
    let ok = !value.is_empty()
        && value.len() <= MAX_VALUE
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    ok.then_some(value)
}

/// Strict grammar, fixed order, no spaces after the commas. Anything else is `Unauthenticated`.
pub fn parse_authorization(header: &str) -> Result<ParsedAuth, MfaError> {
    let parts: Vec<&str> = header
        .strip_prefix(SCHEME)
        .ok_or(MfaError::Unauthenticated)?
        .split(',')
        .collect();
    let [device_id, ts, nonce, sig] = parts.as_slice() else {
        return Err(MfaError::Unauthenticated);
    };
    let device_id = field(device_id, "device_id").ok_or(MfaError::Unauthenticated)?;
    let ts = field(ts, "ts").ok_or(MfaError::Unauthenticated)?;
    let nonce = field(nonce, "nonce").ok_or(MfaError::Unauthenticated)?;
    let sig = field(sig, "sig").ok_or(MfaError::Unauthenticated)?;
    if !ts.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MfaError::Unauthenticated);
    }
    Ok(ParsedAuth {
        device_id: device_id.to_owned(),
        ts: ts.parse().map_err(|_| MfaError::Unauthenticated)?,
        nonce: nonce.to_owned(),
        sig: sig.to_owned(),
    })
}

impl AppState {
    /// Verifies a request of a phone. Five failures for one device in 15 minutes block it.
    pub async fn mfa_authenticate_device(
        &self,
        header: &str,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> Result<DevicePrincipal, MfaError> {
        self.mfa_authenticate_device_at(header, method, path_and_query, body, crate::now_secs())
            .await
    }

    /// Order: parse, rate limit, skew, device lookup, signature, revoked and account checks,
    /// nonce. The nonce is recorded last, so a bad signature cannot burn one. A revoked device is
    /// only named as such to someone who proved they hold its key.
    pub(crate) async fn mfa_authenticate_device_at(
        &self,
        header: &str,
        method: &str,
        path_and_query: &str,
        body: &[u8],
        now: i64,
    ) -> Result<DevicePrincipal, MfaError> {
        let auth = parse_authorization(header)?;
        let key = format!("mfa-auth:{}", auth.device_id);
        self.inner
            .mfa_limiter
            .check(&key)
            .map_err(|retry_after_secs| MfaError::RateLimited { retry_after_secs })?;
        let result = self
            .verify_device_request(&auth, method, path_and_query, body, now)
            .await;
        match &result {
            Ok(_) => self.inner.mfa_limiter.clear(&key),
            Err(MfaError::Unauthenticated) => {
                self.inner.mfa_limiter.record_failure(&key);
            }
            Err(_) => {}
        }
        result
    }

    async fn verify_device_request(
        &self,
        auth: &ParsedAuth,
        method: &str,
        path_and_query: &str,
        body: &[u8],
        now: i64,
    ) -> Result<DevicePrincipal, MfaError> {
        let reject = |reason: &'static str| {
            tracing::debug!(device_id = %auth.device_id, reason, "device request rejected");
            MfaError::Unauthenticated
        };
        if auth.ts.abs_diff(now) > MAX_SKEW_SECS.unsigned_abs() {
            return Err(reject("timestamp outside the allowed skew"));
        }
        let device = self
            .inner
            .db
            .mfa_device_get(&auth.device_id)
            .await?
            .ok_or_else(|| reject("unknown device"))?;
        let message = rustmfa_contract::request_signing_string(
            method,
            path_and_query,
            auth.ts,
            &auth.nonce,
            body,
        )
        .map_err(|_| reject("request cannot be signed"))?;
        rustmfa_contract::verify_es256_raw(&device.request_pub, message.as_bytes(), &auth.sig)
            .map_err(|_| reject("signature does not verify"))?;
        if device.status != "active" {
            return Err(MfaError::DeviceRevoked);
        }
        let user_active = self
            .inner
            .db
            .find_user_by_id(device.user_id)
            .await?
            .is_some_and(|u| !u.disabled);
        if !user_active {
            return Err(reject("account is disabled"));
        }
        self.inner.db.mfa_nonces_purge(now).await?;
        if !self
            .inner
            .db
            .mfa_nonce_insert(&auth.device_id, &auth.nonce, now + NONCE_WINDOW_SECS)
            .await?
        {
            return Err(reject("nonce was already used"));
        }
        self.inner.db.mfa_device_touch(&auth.device_id, now).await?;
        Ok(DevicePrincipal {
            device_id: device.id,
            user_id: device.user_id,
        })
    }
}
