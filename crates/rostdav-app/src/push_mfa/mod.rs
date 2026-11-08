//! Push sign-in approval with the RustMFA app (ADR 0014).

mod attestation;
mod error;
mod google_roots;

pub use attestation::{AttestationResult, verify_attestation};
pub use error::MfaError;
pub use google_roots::google_roots;

use crate::AppState;

/// Whether a registering phone must prove a hardware-backed key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationPolicy {
    /// The attestation chain must verify to a pinned Google root and show a TEE or StrongBox key.
    Required,
    /// No attestation check (custom ROMs); documented with its trade-off.
    Off,
}

/// Settings of the push sign-in approval.
#[derive(Clone, Debug)]
pub struct MfaConfig {
    /// How long a challenge can be answered.
    pub challenge_ttl_secs: i64,
    /// How long an enrollment token is valid.
    pub enroll_ttl_secs: i64,
    /// Service identifier that is part of every signed challenge message.
    pub audience: String,
    pub attestation: AttestationPolicy,
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            challenge_ttl_secs: 90,
            enroll_ttl_secs: 300,
            audience: "rostdav".into(),
            attestation: AttestationPolicy::Required,
        }
    }
}

impl AppState {
    /// The settings in force (a copy, like the other settings).
    pub fn mfa_cfg(&self) -> MfaConfig {
        self.cfg().mfa
    }
}

#[cfg(test)]
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::{AppState, AttestationPolicy, MfaConfig};
    use rostdav_meta::Db;
    use rostdav_storage::LocalStore;

    async fn state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalStore::open(dir.path().join("data"))
            .await
            .expect("store");
        let db = Db::open(&Db::default_url(store.root())).await.expect("db");
        db.migrate().await.expect("migrate");
        (dir, AppState::new(db, store).await.expect("state"))
    }

    #[tokio::test]
    async fn a_new_state_has_the_designed_defaults() {
        let (_d, st) = state().await;
        let c = st.mfa_cfg();
        assert_eq!(c.challenge_ttl_secs, 90);
        assert_eq!(c.enroll_ttl_secs, 300);
        assert_eq!(c.audience, "rostdav");
        assert_eq!(c.attestation, AttestationPolicy::Required);
    }

    #[tokio::test]
    async fn with_mfa_replaces_the_settings() {
        let (_d, st) = state().await;
        let st = st.with_mfa(MfaConfig {
            challenge_ttl_secs: 30,
            enroll_ttl_secs: 120,
            audience: "x".into(),
            attestation: AttestationPolicy::Off,
        });
        let c = st.mfa_cfg();
        assert_eq!((c.challenge_ttl_secs, c.enroll_ttl_secs), (30, 120));
        assert_eq!(c.attestation, AttestationPolicy::Off);
    }
}
