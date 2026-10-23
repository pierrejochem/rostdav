//! Login Flow v2 (ADR 0003).
//!
//! The browser page is one form (sign in and allow, or deny); its CSRF value
//! is a MAC over the flow's login token, so no cookies or sessions are needed.

use std::net::IpAddr;

use rostdav_core::{Error, Result};
use serde_json::json;

use crate::AppState;
use crate::secrets::{flow_key, hash_token, mac, mac_eq, open, random_token, seal};

const TOKEN_LEN: usize = 128;
const FLOW_TTL_SECS: i64 = 20 * 60;
const MAX_CLIENT_NAME: usize = 128;
/// Open flows at one time. `POST /login/v2` needs no sign-in, so the table must not grow
/// without bound; past this, new flows wait until old ones expire (ADR 0003).
const MAX_OPEN_FLOWS: i64 = 1000;

#[derive(Debug, Clone)]
pub struct StartedFlow {
    pub poll_token: String,
    pub login_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Granted {
    pub login_name: String,
    pub app_password: String,
}

fn clean_client_name(raw: &str) -> String {
    let s: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_CLIENT_NAME)
        .collect();
    let s = s.trim();
    if s.is_empty() {
        "Unknown client".to_owned()
    } else {
        s.to_owned()
    }
}

/// What the password step of the Login Flow page leads to.
#[derive(Debug)]
pub enum FlowStep {
    /// The app password was created.
    Granted,
    /// The code is still needed.
    SecondFactor { ticket: String },
}

impl AppState {
    pub async fn start_login_flow(&self, client_name: &str) -> Result<StartedFlow> {
        let poll_token = random_token(TOKEN_LEN);
        let login_token = random_token(TOKEN_LEN);
        self.inner
            .db
            .create_login_flow(
                &hash_token(&poll_token),
                &hash_token(&login_token),
                &clean_client_name(client_name),
                FLOW_TTL_SECS,
                MAX_OPEN_FLOWS,
            )
            .await?;
        Ok(StartedFlow {
            poll_token,
            login_token,
        })
    }

    /// Name of the client for an open flow; `None` if unknown, expired or used.
    pub async fn login_flow_client(&self, login_token: &str) -> Result<Option<String>> {
        Ok(self
            .inner
            .db
            .open_flow_by_login(&hash_token(login_token))
            .await?
            .map(|f| f.client_name))
    }

    /// CSRF value for a form of this flow. `purpose` separates the forms.
    pub fn flow_csrf(&self, login_token: &str, purpose: &str) -> String {
        mac(&self.inner.server_key, &["csrf", purpose, login_token])
    }

    fn check_csrf(&self, login_token: &str, purpose: &str, given: &str) -> Result<()> {
        if mac_eq(&self.flow_csrf(login_token, purpose), given) {
            Ok(())
        } else {
            Err(Error::Forbidden)
        }
    }

    /// The user signed in and allowed access: create the app password and hand
    /// it to the poller. Browser logins accept the account password only. With
    /// two-factor authentication on, the code is asked for first (ticket).
    pub async fn flow_allow(
        &self,
        login_token: &str,
        csrf: &str,
        user: &str,
        password: &str,
        ip: IpAddr,
    ) -> Result<FlowStep> {
        self.check_csrf(login_token, "allow", csrf)?;
        let flow = self
            .inner
            .db
            .open_flow_by_login(&hash_token(login_token))
            .await?
            .ok_or(Error::NotFound)?;
        let p = self.authenticate_with(user, password, ip, false).await?;
        if self.inner.db.totp_enabled(p.user_id).await? {
            return Ok(FlowStep::SecondFactor {
                ticket: self.second_factor_ticket(p.user_id, login_token),
            });
        }
        self.grant_flow_to(&flow, &p, ip).await?;
        Ok(FlowStep::Granted)
    }

    /// Second step of the flow: the ticket from [`flow_allow`](Self::flow_allow) and a code.
    pub async fn flow_second_factor(
        &self,
        login_token: &str,
        csrf: &str,
        ticket: &str,
        code: &str,
        ip: IpAddr,
    ) -> Result<()> {
        self.check_csrf(login_token, "allow", csrf)?;
        let user_id = self
            .second_factor_ticket_user(ticket, login_token)
            .ok_or(Error::Unauthenticated)?;
        let flow = self
            .inner
            .db
            .open_flow_by_login(&hash_token(login_token))
            .await?
            .ok_or(Error::NotFound)?;
        let p = self.second_factor_principal(user_id, code, ip).await?;
        self.grant_flow_to(&flow, &p, ip).await
    }

    async fn grant_flow_to(
        &self,
        flow: &rostdav_meta::LoginFlow,
        p: &crate::auth::Principal,
        ip: IpAddr,
    ) -> Result<()> {
        let (pw_id, token) = self
            .create_app_password_with_id(p.user_id, &flow.client_name)
            .await?;
        // Encrypted while it waits for the poll, bound to the poll token's hash.
        let sealed = seal(&flow_key(&self.inner.server_key), &flow.poll_hash, &token)?;
        if !self
            .inner
            .db
            .grant_flow(flow.id, p.user_id, &sealed)
            .await?
        {
            // Lost a race (double submit): do not leave an unused credential behind.
            self.inner.db.revoke_app_password(p.user_id, pw_id).await?;
            return Err(Error::NotFound);
        }
        self.audit(&p.name, "auth.login", "login_flow", Some(ip), json!({}))
            .await;
        self.audit(
            &p.name,
            "device.connected",
            &flow.client_name,
            Some(ip),
            json!({}),
        )
        .await;
        Ok(())
    }

    /// The user pressed "Deny": the flow is closed and the poller never gets credentials.
    pub async fn flow_deny(&self, login_token: &str, csrf: &str) -> Result<()> {
        self.check_csrf(login_token, "allow", csrf)?;
        self.inner
            .db
            .delete_open_flow(&hash_token(login_token))
            .await?;
        Ok(())
    }

    /// Poll: the granted credentials exactly once, otherwise `None`.
    pub async fn poll_login_flow(&self, poll_token: &str) -> Result<Option<Granted>> {
        Ok(
            match self.inner.db.poll_flow(&hash_token(poll_token)).await? {
                rostdav_meta::PollResult::Pending => None,
                rostdav_meta::PollResult::Granted {
                    login_name,
                    app_password,
                } => Some(Granted {
                    login_name,
                    app_password: open(
                        &flow_key(&self.inner.server_key),
                        &hash_token(poll_token),
                        &app_password,
                    )?,
                }),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rostdav_meta::{Db, PollResult};
    use rostdav_storage::LocalStore;

    const PW: &str = "korrekt-pferd-batterie";

    #[tokio::test]
    async fn the_app_password_waits_for_the_poll_encrypted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalStore::open(dir.path().join("data"))
            .await
            .expect("store");
        let db = Db::open(&Db::default_url(store.root())).await.expect("db");
        db.migrate().await.expect("migrate");
        let st = AppState::new(db, store).await.expect("state");
        st.add_user("anna", PW, false).await.expect("anna");
        let ip: IpAddr = "192.0.2.10".parse().expect("ip");

        let f = st.start_login_flow("Phone").await.expect("start");
        let csrf = st.flow_csrf(&f.login_token, "allow");
        let step = st
            .flow_allow(&f.login_token, &csrf, "anna", PW, ip)
            .await
            .expect("allow");
        assert!(matches!(step, FlowStep::Granted));

        // What the database holds before the poll: not an app password, but ciphertext.
        let PollResult::Granted { app_password, .. } = st
            .inner
            .db
            .poll_flow(&hash_token(&f.poll_token))
            .await
            .expect("raw poll")
        else {
            panic!("granted")
        };
        assert!(app_password.len() > crate::auth::APP_PASSWORD_LEN);
        let clear = open(
            &flow_key(&st.inner.server_key),
            &hash_token(&f.poll_token),
            &app_password,
        )
        .expect("decrypts with the poll token's hash");
        assert_eq!(clear.len(), crate::auth::APP_PASSWORD_LEN);
        assert!(
            !app_password.contains(&clear),
            "the clear value is not stored"
        );

        // Through the real poll the app gets a working app password, once.
        let f = st.start_login_flow("Phone").await.expect("start");
        let csrf = st.flow_csrf(&f.login_token, "allow");
        st.flow_allow(&f.login_token, &csrf, "anna", PW, ip)
            .await
            .expect("allow");
        let g = st
            .poll_login_flow(&f.poll_token)
            .await
            .expect("poll")
            .expect("granted");
        assert_eq!(g.login_name, "anna");
        st.authenticate("anna", &g.app_password, ip)
            .await
            .expect("app password works");
        assert!(
            st.poll_login_flow(&f.poll_token)
                .await
                .expect("2nd")
                .is_none()
        );
    }
}
