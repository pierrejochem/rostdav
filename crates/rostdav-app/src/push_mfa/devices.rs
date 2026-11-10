//! A user's phones: list, revoke, push token, key rotation, own audit events (ADR 0014).

use rostdav_core::time::rfc3339;
use rostdav_meta::DeviceRow;
use serde_json::json;

use super::attestation::{AttestationResult, verify_attestation};
use super::enroll::{check_push, sha256};
use super::{AttestationPolicy, DevicePrincipal, MfaError};
use crate::{AppState, now_secs};

/// How many events the own-events view shows.
const AUDIT_LIMIT: i64 = 200;
/// The events of the contract (`AuditEvent.event`). Other `mfa.*` actions stay in the server log.
const VIEWED: [&str; 8] = [
    "device_registered",
    "device_revoked",
    "key_rotated",
    "challenge_created",
    "challenge_approved",
    "challenge_denied",
    "challenge_expired",
    "number_mismatch",
];

/// What the app and the web page show of a phone. No keys, no push token.
#[derive(Debug)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub status: String,
    pub push_channel: String,
    pub hardware_backed: bool,
    pub strongbox: bool,
    pub created_at: String,
    pub last_seen_at: Option<String>,
}

/// One entry of a user's own security history.
#[derive(Debug)]
pub struct MfaAuditEvent {
    pub event: String,
    pub at: String,
    pub device_id: Option<String>,
    pub detail: Option<String>,
}

fn info(d: DeviceRow) -> DeviceInfo {
    DeviceInfo {
        device_id: d.id,
        device_name: d.name,
        status: d.status,
        push_channel: d.push_channel,
        hardware_backed: d.hardware_backed,
        strongbox: d.strongbox,
        created_at: rfc3339(d.created_at),
        last_seen_at: d.last_seen_at.map(rfc3339),
    }
}

impl AppState {
    /// All phones of the user, revoked ones included and marked, oldest first.
    pub async fn mfa_list_devices(&self, user_id: i64) -> Result<Vec<DeviceInfo>, MfaError> {
        Ok(self
            .inner
            .db
            .mfa_devices_of(user_id)
            .await?
            .into_iter()
            .map(info)
            .collect())
    }

    /// Revokes an active phone of `user_id` and ends its open challenges. Unknown, foreign and
    /// already revoked phones are all `NotFound`. The phone is blocked first, so an answer that
    /// is in flight cannot approve after this returns.
    pub async fn mfa_revoke_device(
        &self,
        user_id: i64,
        device_id: &str,
        actor: &str,
    ) -> Result<(), MfaError> {
        let now = now_secs();
        if !self
            .inner
            .db
            .mfa_device_revoke(device_id, user_id, now)
            .await?
        {
            return Err(MfaError::NotFound);
        }
        for c in self.inner.db.mfa_challenges_pending(device_id, now).await? {
            if self.inner.db.mfa_challenge_cancel(&c.id, now).await? {
                self.audit(
                    actor,
                    "mfa.challenge_expired",
                    &c.id,
                    None,
                    json!({ "device_id": device_id }),
                )
                .await;
            }
        }
        self.audit(actor, "mfa.device_revoked", device_id, None, json!({}))
            .await;
        Ok(())
    }

    /// Revoking from the web interface. Revoking the phone that is the account's only second
    /// factor takes the factor away (browser sign-in and WebDAV fall back to the password), so it
    /// needs the account password, like turning TOTP off: a stolen session cookie alone must not
    /// be able to do it. Another user's phone is `NotFound` whatever the password.
    pub async fn web_mfa_revoke(
        &self,
        s: &crate::WebSession,
        device_id: &str,
        password: &str,
        ip: std::net::IpAddr,
    ) -> Result<(), MfaError> {
        let p = &s.principal;
        let devices = self.inner.db.mfa_devices_of(p.user_id).await?;
        let own_active = devices
            .iter()
            .any(|d| d.id == device_id && d.status == "active");
        let active = devices.iter().filter(|d| d.status == "active").count();
        if own_active && active == 1 && !self.inner.db.totp_enabled(p.user_id).await? {
            match self.authenticate_with(&p.name, password, ip, false).await {
                Ok(_) => {}
                Err(rostdav_core::Error::Unauthenticated) => return Err(MfaError::Unauthenticated),
                Err(rostdav_core::Error::RateLimited { retry_after_secs }) => {
                    return Err(MfaError::RateLimited { retry_after_secs });
                }
                Err(e) => return Err(e.into()),
            }
        }
        self.mfa_revoke_device(p.user_id, device_id, &p.name).await
    }

    /// A phone revokes a phone of its own account (itself or another one).
    pub async fn mfa_revoke_device_as(
        &self,
        d: &DevicePrincipal,
        device_id: &str,
    ) -> Result<(), MfaError> {
        let name = self.mfa_user_name(d.user_id).await?;
        self.mfa_revoke_device(d.user_id, device_id, &name).await
    }

    async fn mfa_user_name(&self, user_id: i64) -> Result<String, MfaError> {
        Ok(self
            .inner
            .db
            .find_user_by_id(user_id)
            .await?
            .ok_or(MfaError::NotFound)?
            .name)
    }

    /// The calling phone's own, still active row.
    async fn own_active_device(
        &self,
        d: &DevicePrincipal,
        device_id: &str,
    ) -> Result<DeviceRow, MfaError> {
        if device_id != d.device_id {
            return Err(MfaError::DeviceNotAuthorized);
        }
        let row = self
            .inner
            .db
            .mfa_device_get(device_id)
            .await?
            .filter(|r| r.user_id == d.user_id)
            .ok_or(MfaError::NotFound)?;
        if row.status != "active" {
            return Err(MfaError::DeviceRevoked);
        }
        Ok(row)
    }

    /// A phone changes its own push channel or token.
    pub async fn mfa_update_push_token(
        &self,
        d: &DevicePrincipal,
        device_id: &str,
        channel: &str,
        token: &str,
    ) -> Result<(), MfaError> {
        self.own_active_device(d, device_id).await?;
        check_push(channel, token)?;
        if !self
            .inner
            .db
            .mfa_device_set_push(device_id, channel, token)
            .await?
        {
            return Err(MfaError::DeviceRevoked);
        }
        let name = self.mfa_user_name(d.user_id).await?;
        self.audit(
            &name,
            "mfa.push_token_updated",
            device_id,
            None,
            json!({ "push_channel": channel }),
        )
        .await;
        Ok(())
    }

    /// A phone replaces both of its keys. Under the default policy the new approval key must be
    /// attested for the string `rotate:<device_id>:<request_pub>`, which ties the attestation to
    /// this device and to the new request key. (The spec left rotation unattested.) The request
    /// itself is signed with the old request key.
    pub async fn mfa_rotate_keys(
        &self,
        d: &DevicePrincipal,
        device_id: &str,
        request_pub: &str,
        approval_pub: &str,
        chain: &[String],
    ) -> Result<(), MfaError> {
        self.own_active_device(d, device_id).await?;
        if rustmfa_contract::check_spki(request_pub).is_err() {
            return Err(MfaError::InvalidRequest(
                "request public key is not a P-256 key",
            ));
        }
        if rustmfa_contract::check_spki(approval_pub).is_err() {
            return Err(MfaError::InvalidRequest(
                "approval public key is not a P-256 key",
            ));
        }
        if request_pub == approval_pub {
            return Err(MfaError::InvalidRequest(
                "request key and approval key must differ",
            ));
        }
        let attested = match self.mfa_cfg().attestation {
            AttestationPolicy::Required => verify_attestation(
                chain,
                approval_pub,
                &sha256(format!("rotate:{device_id}:{request_pub}").as_bytes()),
                &self.attestation_roots(),
                now_secs(),
            )?,
            AttestationPolicy::Off => AttestationResult {
                hardware_backed: false,
                strongbox: false,
            },
        };
        if !self
            .inner
            .db
            .mfa_device_set_keys(
                device_id,
                request_pub,
                approval_pub,
                attested.hardware_backed,
                attested.strongbox,
            )
            .await?
        {
            return Err(MfaError::DeviceRevoked);
        }
        let name = self.mfa_user_name(d.user_id).await?;
        self.audit(
            &name,
            "mfa.key_rotated",
            device_id,
            None,
            json!({
                "hardware_backed": attested.hardware_backed,
                "strongbox": attested.strongbox,
            }),
        )
        .await;
        Ok(())
    }

    /// The user's own security history: the newest events first, only their own, only the kinds
    /// of the contract, no ids of challenges and no secrets.
    pub async fn mfa_audit_events(&self, user_id: i64) -> Result<Vec<MfaAuditEvent>, MfaError> {
        let Some(user) = self.inner.db.find_user_by_id(user_id).await? else {
            return Ok(Vec::new());
        };
        let rows = self
            .inner
            .db
            .events_of_actor_with_prefix(&user.name, "mfa.", AUDIT_LIMIT)
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|e| {
                let event = e
                    .action
                    .strip_prefix("mfa.")
                    .filter(|n| VIEWED.contains(n))?;
                // device events name the device as target, challenge events in their details
                let device_id = if event.starts_with("device_") || event == "key_rotated" {
                    Some(e.target.clone())
                } else {
                    serde_json::from_str::<serde_json::Value>(&e.details)
                        .ok()
                        .and_then(|v| v["device_id"].as_str().map(str::to_owned))
                };
                Some(MfaAuditEvent {
                    event: event.to_owned(),
                    at: rfc3339(e.ts),
                    device_id,
                    detail: None,
                })
            })
            .collect())
    }
}
