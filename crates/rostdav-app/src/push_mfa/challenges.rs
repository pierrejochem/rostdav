//! Sign-in challenges with number matching (ADR 0014).

use std::net::IpAddr;
use std::sync::Arc;

use rostdav_core::Error;
use rostdav_core::time::rfc3339;
use rostdav_meta::{ChallengeRow, DeviceRow};
use serde_json::json;

use super::{DevicePrincipal, MfaError, PushChannel};
use crate::audit::sanitize_text;
use crate::secrets::{random_bytes, random_token};
use crate::{AppState, now_secs};

const SERVICE_NAME: &str = "Rostdav";
const MAX_LOGIN_REF: usize = 128;
const NONCE_LEN: usize = 32;

/// Where a challenge stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

impl ChallengeStatus {
    /// The word the contract uses (`pending`, `approved`, `denied`, `expired`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }

    fn from_db(s: &str) -> Result<Self, MfaError> {
        match s {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "denied" => Ok(Self::Denied),
            "expired" => Ok(Self::Expired),
            _ => Err(MfaError::Internal(Error::BadRequest(
                "unknown challenge status",
            ))),
        }
    }
}

/// A challenge that was just created, for the sign-in page.
#[derive(Debug)]
pub struct NewChallenge {
    pub challenge_id: String,
    /// The number the sign-in page shows and the user must pick on the phone.
    pub number: i64,
    pub expires_in_seconds: i64,
}

/// What a phone may see of a challenge. Nothing here says which candidate is right.
#[derive(Debug)]
pub struct ChallengeDetails {
    pub challenge_id: String,
    pub service_name: String,
    pub login_device: String,
    pub approximate_location: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub status: ChallengeStatus,
    pub candidate_numbers: [i64; 3],
    pub nonce: String,
    pub login_id: String,
    pub audience: String,
}

/// A uniform number in `10..=99` (rejection sampling: 180 = 2 * 90, so no bias).
fn random_number() -> i64 {
    loop {
        let [b] = random_bytes::<1>();
        if b < 180 {
            return 10 + i64::from(b % 90);
        }
    }
}

/// A uniform index in `0..3` (255 = 3 * 85).
fn random_index() -> usize {
    loop {
        let [b] = random_bytes::<1>();
        if b < 255 {
            return usize::from(b % 3);
        }
    }
}

/// The right number and two different decoys, the right one at a random place.
fn candidates(number: i64) -> [i64; 3] {
    let mut decoys = Vec::with_capacity(2);
    while decoys.len() < 2 {
        let n = random_number();
        if n != number && !decoys.contains(&n) {
            decoys.push(n);
        }
    }
    let at = random_index();
    let mut out = [0; 3];
    let mut next = decoys.into_iter();
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = if i == at {
            number
        } else {
            next.next().unwrap_or(number)
        };
    }
    out
}

fn valid_login_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_LOGIN_REF
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn details_of(row: &ChallengeRow, status: ChallengeStatus) -> Result<ChallengeDetails, MfaError> {
    let numbers: Vec<i64> = serde_json::from_str(&row.candidates)
        .map_err(|_| MfaError::Internal(Error::BadRequest("stored candidates are unreadable")))?;
    let candidate_numbers: [i64; 3] = numbers
        .try_into()
        .map_err(|_| MfaError::Internal(Error::BadRequest("stored candidates are unreadable")))?;
    Ok(ChallengeDetails {
        challenge_id: row.id.clone(),
        service_name: SERVICE_NAME.to_owned(),
        login_device: row.login_device.clone(),
        approximate_location: None,
        created_at: rfc3339(row.created_at),
        expires_at: rfc3339(row.expires_at),
        status,
        candidate_numbers,
        nonce: row.nonce.clone(),
        login_id: row.login_ref.clone(),
        audience: row.audience.clone(),
    })
}

impl AppState {
    /// Starts an approval for one phone of `user_id`. Five per user in 15 minutes, so a stolen
    /// password cannot flood the phone. `ip` is only audited.
    pub async fn mfa_create_challenge(
        &self,
        user_id: i64,
        device_id: &str,
        login_ref: &str,
        login_device: &str,
        ip: IpAddr,
    ) -> Result<NewChallenge, MfaError> {
        self.mfa_create_challenge_at(user_id, device_id, login_ref, login_device, ip, now_secs())
            .await
    }

    pub(crate) async fn mfa_create_challenge_at(
        &self,
        user_id: i64,
        device_id: &str,
        login_ref: &str,
        login_device: &str,
        ip: IpAddr,
        now: i64,
    ) -> Result<NewChallenge, MfaError> {
        if !valid_login_ref(login_ref) {
            return Err(MfaError::InvalidRequest("login reference is not valid"));
        }
        let key = format!("mfa-challenge:{user_id}");
        self.inner
            .mfa_limiter
            .check(&key)
            .map_err(|retry_after_secs| MfaError::RateLimited { retry_after_secs })?;
        let device = self
            .inner
            .db
            .mfa_device_get(device_id)
            .await?
            .filter(|d| d.user_id == user_id && d.status == "active")
            .ok_or(MfaError::NotFound)?;
        let user = self
            .inner
            .db
            .find_user_by_id(user_id)
            .await?
            .ok_or(MfaError::NotFound)?;
        let cfg = self.mfa_cfg();
        let number = random_number();
        let shown = candidates(number);
        let id = format!("ch_{}", random_token(22));
        let nonce = random_token(NONCE_LEN);
        let login_device = match sanitize_text(login_device).trim() {
            "" => "Unknown device".to_owned(),
            s => s.to_owned(),
        };
        let candidates_json = json!(shown).to_string();
        self.inner
            .db
            .mfa_challenge_insert(&rostdav_meta::NewChallenge {
                id: &id,
                user_id,
                device_id,
                login_ref,
                nonce: &nonce,
                number,
                candidates: &candidates_json,
                audience: &cfg.audience,
                login_device: &login_device,
                expires_at: now + cfg.challenge_ttl_secs,
            })
            .await?;
        // every challenge counts, not only failures
        self.inner.mfa_limiter.record_failure(&key);
        self.audit(
            &user.name,
            "mfa.challenge_created",
            &id,
            Some(ip),
            json!({ "device_id": device_id }),
        )
        .await;
        self.push_in_background(&device, &id);
        Ok(NewChallenge {
            challenge_id: id,
            number,
            expires_in_seconds: cfg.challenge_ttl_secs,
        })
    }

    /// Wakes the phone after the challenge is stored. A failure is only logged, and the log has
    /// the challenge id but never the push token.
    fn push_in_background(&self, device: &DeviceRow, challenge_id: &str) {
        let channel = self.push_channel();
        let (kind, token, id) = (
            device.push_channel.clone(),
            device.push_token.clone(),
            challenge_id.to_owned(),
        );
        tokio::spawn(async move {
            if let Err(e) = channel.notify(&kind, &token, &id).await {
                tracing::warn!(challenge_id = %id, error = %e, "push notification failed");
            }
        });
    }

    fn push_channel(&self) -> Arc<dyn PushChannel> {
        self.inner
            .mfa_push
            .read()
            .map_or_else(|e| e.into_inner().clone(), |g| g.clone())
    }

    /// For the sign-in page: where the challenge stands. A pending one past its time becomes
    /// `Expired`.
    pub async fn mfa_challenge_status(&self, id: &str) -> Result<ChallengeStatus, MfaError> {
        self.mfa_challenge_status_at(id, now_secs()).await
    }

    pub(crate) async fn mfa_challenge_status_at(
        &self,
        id: &str,
        now: i64,
    ) -> Result<ChallengeStatus, MfaError> {
        let row = self
            .inner
            .db
            .mfa_challenge_get(id)
            .await?
            .ok_or(MfaError::NotFound)?;
        self.current_status(&row, now).await
    }

    /// The status of `row` now. The first caller to see a pending challenge past its time marks
    /// it expired and audits that once.
    async fn current_status(
        &self,
        row: &ChallengeRow,
        now: i64,
    ) -> Result<ChallengeStatus, MfaError> {
        let status = ChallengeStatus::from_db(&row.status)?;
        if status == ChallengeStatus::Pending && row.expires_at <= now {
            if self.inner.db.mfa_challenge_expire(&row.id, now).await? {
                self.audit_challenge(row, "mfa.challenge_expired").await;
            }
            return Ok(ChallengeStatus::Expired);
        }
        Ok(status)
    }

    async fn audit_challenge(&self, row: &ChallengeRow, action: &str) {
        let actor = match self.inner.db.find_user_by_id(row.user_id).await {
            Ok(Some(u)) => u.name,
            _ => String::new(),
        };
        self.audit(
            &actor,
            action,
            &row.id,
            None,
            json!({ "device_id": row.device_id }),
        )
        .await;
    }

    /// The challenge of this phone. Another user's challenge is `NotFound`, the same as one that
    /// does not exist; another phone of the same user is `DeviceNotAuthorized`.
    async fn owned_challenge(
        &self,
        d: &DevicePrincipal,
        id: &str,
    ) -> Result<ChallengeRow, MfaError> {
        let row = self
            .inner
            .db
            .mfa_challenge_get(id)
            .await?
            .filter(|r| r.user_id == d.user_id)
            .ok_or(MfaError::NotFound)?;
        if row.device_id != d.device_id {
            return Err(MfaError::DeviceNotAuthorized);
        }
        Ok(row)
    }

    pub async fn mfa_get_challenge(
        &self,
        d: &DevicePrincipal,
        id: &str,
    ) -> Result<ChallengeDetails, MfaError> {
        self.mfa_get_challenge_at(d, id, now_secs()).await
    }

    pub(crate) async fn mfa_get_challenge_at(
        &self,
        d: &DevicePrincipal,
        id: &str,
        now: i64,
    ) -> Result<ChallengeDetails, MfaError> {
        let row = self.owned_challenge(d, id).await?;
        match self.current_status(&row, now).await? {
            ChallengeStatus::Expired => Err(MfaError::Expired),
            status => details_of(&row, status),
        }
    }

    pub async fn mfa_pending_challenges(
        &self,
        d: &DevicePrincipal,
    ) -> Result<Vec<ChallengeDetails>, MfaError> {
        self.mfa_pending_challenges_at(d, now_secs()).await
    }

    pub(crate) async fn mfa_pending_challenges_at(
        &self,
        d: &DevicePrincipal,
        now: i64,
    ) -> Result<Vec<ChallengeDetails>, MfaError> {
        self.inner
            .db
            .mfa_challenges_pending(&d.device_id, now)
            .await?
            .iter()
            .filter(|r| r.user_id == d.user_id)
            .map(|r| details_of(r, ChallengeStatus::Pending))
            .collect()
    }

    /// Approves with the number the user picked and the approval key's signature. A wrong number
    /// denies the challenge (`NumberMismatch`). Both need a valid signature first, so the request
    /// key alone, which is not biometric-gated, cannot end a challenge.
    pub async fn mfa_approve(
        &self,
        d: &DevicePrincipal,
        id: &str,
        selected_number: i64,
        signature: &str,
    ) -> Result<ChallengeStatus, MfaError> {
        self.mfa_approve_at(d, id, selected_number, signature, now_secs())
            .await
    }

    pub(crate) async fn mfa_approve_at(
        &self,
        d: &DevicePrincipal,
        id: &str,
        selected_number: i64,
        signature: &str,
        now: i64,
    ) -> Result<ChallengeStatus, MfaError> {
        self.answer(d, id, Some(selected_number), signature, now)
            .await
    }

    pub async fn mfa_deny(
        &self,
        d: &DevicePrincipal,
        id: &str,
        signature: &str,
    ) -> Result<ChallengeStatus, MfaError> {
        self.mfa_deny_at(d, id, signature, now_secs()).await
    }

    pub(crate) async fn mfa_deny_at(
        &self,
        d: &DevicePrincipal,
        id: &str,
        signature: &str,
        now: i64,
    ) -> Result<ChallengeStatus, MfaError> {
        self.answer(d, id, None, signature, now).await
    }

    /// Order: ownership, phone still active, challenge open, signature, number, then one
    /// conditional update that only one caller can win. A bad signature never consumes.
    async fn answer(
        &self,
        d: &DevicePrincipal,
        id: &str,
        selected: Option<i64>,
        signature: &str,
        now: i64,
    ) -> Result<ChallengeStatus, MfaError> {
        let row = self.owned_challenge(d, id).await?;
        let device = self
            .inner
            .db
            .mfa_device_get(&d.device_id)
            .await?
            .filter(|x| x.user_id == d.user_id)
            .ok_or(MfaError::NotFound)?;
        if device.status != "active" {
            return Err(MfaError::DeviceRevoked);
        }
        Self::open_or_err(self.current_status(&row, now).await?)?;
        let expires_at = rfc3339(row.expires_at);
        let message = rustmfa_contract::canonical_message(&rustmfa_contract::ChallengeMessage {
            challenge_id: &row.id,
            nonce: &row.nonce,
            login_id: &row.login_ref,
            device_id: &row.device_id,
            expires_at: &expires_at,
            audience: &row.audience,
        })
        .map_err(|_| MfaError::Internal(Error::BadRequest("challenge cannot be signed")))?;
        rustmfa_contract::verify_es256_raw(&device.approval_pub, message.as_bytes(), signature)
            .map_err(|e| match e {
                rustmfa_contract::ContractError::VerifyFailed => MfaError::DeviceNotAuthorized,
                _ => MfaError::InvalidRequest("signature is not a raw ES256 signature"),
            })?;
        let (to, action) = match selected {
            Some(n) if n == row.number => (ChallengeStatus::Approved, "mfa.challenge_approved"),
            Some(_) => (ChallengeStatus::Denied, "mfa.number_mismatch"),
            None => (ChallengeStatus::Denied, "mfa.challenge_denied"),
        };
        self.finish(&row, to, action, now).await?;
        if action == "mfa.number_mismatch" {
            return Err(MfaError::NumberMismatch);
        }
        Ok(to)
    }

    /// The one conditional update. `row` was read earlier, so someone may have answered since,
    /// or the time may have run out: then the fresh row says which error applies.
    pub(crate) async fn finish(
        &self,
        row: &ChallengeRow,
        to: ChallengeStatus,
        action: &str,
        now: i64,
    ) -> Result<(), MfaError> {
        if !self
            .inner
            .db
            .mfa_challenge_resolve(&row.id, to.as_str(), now)
            .await?
        {
            let fresh = self
                .inner
                .db
                .mfa_challenge_get(&row.id)
                .await?
                .ok_or(MfaError::NotFound)?;
            Self::open_or_err(self.current_status(&fresh, now).await?)?;
            // still open: the update refused because the phone was revoked in between
            let revoked = self
                .inner
                .db
                .mfa_device_get(&row.device_id)
                .await?
                .is_none_or(|d| d.status != "active");
            return Err(if revoked {
                MfaError::DeviceRevoked
            } else {
                MfaError::AlreadyConsumed
            });
        }
        self.audit_challenge(row, action).await;
        Ok(())
    }

    /// `Ok` only for a challenge that can still be answered.
    fn open_or_err(status: ChallengeStatus) -> Result<(), MfaError> {
        match status {
            ChallengeStatus::Pending => Ok(()),
            ChallengeStatus::Expired => Err(MfaError::Expired),
            ChallengeStatus::Approved | ChallengeStatus::Denied => Err(MfaError::AlreadyConsumed),
        }
    }

    /// Replaces the push channel (the server installs FCM at start-up).
    pub fn set_push_channel(&self, p: Arc<dyn PushChannel>) {
        if let Ok(mut g) = self.inner.mfa_push.write() {
            *g = p;
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn set_push_channel_for_tests(&self, p: Arc<dyn PushChannel>) {
        self.set_push_channel(p);
    }
}
