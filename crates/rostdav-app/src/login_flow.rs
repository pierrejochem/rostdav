//! Login Flow v2 (ADR 0003).
//!
//! The browser page is one form (sign in and allow, or deny); its CSRF value
//! is a MAC over the flow's login token, so no cookies or sessions are needed.

use std::net::IpAddr;

use rostdav_core::{Error, Result};

use crate::AppState;
use crate::secrets::{hash_token, mac, mac_eq, random_token};

const TOKEN_LEN: usize = 128;
const FLOW_TTL_SECS: i64 = 20 * 60;
const MAX_CLIENT_NAME: usize = 128;

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
    /// it to the poller. Browser logins accept the account password only.
    pub async fn flow_allow(
        &self,
        login_token: &str,
        csrf: &str,
        user: &str,
        password: &str,
        ip: IpAddr,
    ) -> Result<()> {
        self.check_csrf(login_token, "allow", csrf)?;
        let flow = self
            .inner
            .db
            .open_flow_by_login(&hash_token(login_token))
            .await?
            .ok_or(Error::NotFound)?;
        let p = self.authenticate_with(user, password, ip, false).await?;

        let (pw_id, token) = self
            .create_app_password_with_id(p.user_id, &flow.client_name)
            .await?;
        if !self.inner.db.grant_flow(flow.id, p.user_id, &token).await? {
            // Lost a race (double submit): do not leave an unused credential behind.
            self.inner.db.revoke_app_password(p.user_id, pw_id).await?;
            return Err(Error::NotFound);
        }
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
                    app_password,
                }),
            },
        )
    }
}
