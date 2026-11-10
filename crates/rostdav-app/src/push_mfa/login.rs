//! The link between a password step and a phone approval (ADR 0014). The browser holds a ticket
//! from the password step. Every challenge it starts carries a `login_ref` derived from that
//! ticket, so only the holder can poll it, and only once can it be turned into a session.

use std::net::IpAddr;

use serde_json::json;

use super::{ChallengeStatus, MfaError};
use crate::secrets::mac;
use crate::{AppState, now_secs};

/// A challenge started for a sign-in, for the page that shows the number.
#[derive(Debug)]
pub struct LoginChallenge {
    pub challenge_id: String,
    /// The number the page shows and the user must pick on the phone.
    pub number: i64,
    pub expires_in_seconds: i64,
}

impl AppState {
    /// The user of a genuine, current ticket for this flow (`""` is the browser sign-in).
    fn login_user(&self, ticket: &str, flow: &str) -> Result<i64, MfaError> {
        self.second_factor_ticket_user(ticket, flow)
            .ok_or(MfaError::Unauthenticated)
    }

    /// What ties a challenge to one ticket. Hex of a keyed hash: 64 characters, no secret leaks.
    fn login_ref_for(&self, ticket: &str, flow: &str) -> String {
        mac(&self.inner.server_key, &["mfa-login", flow, ticket])
    }

    /// Starts an approval on the user's most recently seen active phone.
    pub async fn mfa_login_start(
        &self,
        ticket: &str,
        flow: &str,
        login_device: &str,
        ip: IpAddr,
    ) -> Result<LoginChallenge, MfaError> {
        let user_id = self.login_user(ticket, flow)?;
        let devices = self.inner.db.mfa_devices_of(user_id).await?;
        let device = devices
            .iter()
            .filter(|d| d.status == "active")
            .max_by_key(|d| d.last_seen_at.unwrap_or(d.created_at))
            .ok_or(MfaError::NotFound)?;
        let c = self
            .mfa_create_challenge(
                user_id,
                &device.id,
                &self.login_ref_for(ticket, flow),
                login_device,
                ip,
            )
            .await?;
        Ok(LoginChallenge {
            challenge_id: c.challenge_id,
            number: c.number,
            expires_in_seconds: c.expires_in_seconds,
        })
    }

    /// The row of a challenge that this ticket started. Anything else is `NotFound`.
    async fn login_challenge(
        &self,
        ticket: &str,
        flow: &str,
        challenge_id: &str,
    ) -> Result<(i64, String), MfaError> {
        let user_id = self.login_user(ticket, flow)?;
        let login_ref = self.login_ref_for(ticket, flow);
        let row = self
            .inner
            .db
            .mfa_challenge_get(challenge_id)
            .await?
            .filter(|r| r.user_id == user_id && r.login_ref == login_ref)
            .ok_or(MfaError::NotFound)?;
        Ok((user_id, row.login_ref))
    }

    /// Where the challenge of this sign-in stands.
    pub async fn mfa_login_status(
        &self,
        ticket: &str,
        flow: &str,
        challenge_id: &str,
    ) -> Result<ChallengeStatus, MfaError> {
        self.login_challenge(ticket, flow, challenge_id).await?;
        self.mfa_challenge_status(challenge_id).await
    }

    /// Takes the approval: true for one caller only. Returns the user who may now get a session.
    pub async fn mfa_login_release(
        &self,
        ticket: &str,
        flow: &str,
        challenge_id: &str,
    ) -> Result<i64, MfaError> {
        let (user_id, login_ref) = self.login_challenge(ticket, flow, challenge_id).await?;
        match self.mfa_challenge_status(challenge_id).await? {
            ChallengeStatus::Approved => {}
            ChallengeStatus::Pending => {
                return Err(MfaError::InvalidRequest("challenge is not approved"));
            }
            ChallengeStatus::Denied => {
                return Err(MfaError::InvalidRequest("challenge was denied"));
            }
            ChallengeStatus::Expired => return Err(MfaError::Expired),
        }
        let user = self
            .inner
            .db
            .find_user_by_id(user_id)
            .await?
            .filter(|u| !u.disabled)
            .ok_or(MfaError::Unauthenticated)?;
        if !self
            .inner
            .db
            .mfa_challenge_release(challenge_id, &login_ref, now_secs())
            .await?
        {
            // used before, or the approving phone was revoked in the meantime
            return Err(MfaError::AlreadyConsumed);
        }
        self.audit(
            &user.name,
            "mfa.login_released",
            challenge_id,
            None,
            json!({}),
        )
        .await;
        Ok(user_id)
    }
}
