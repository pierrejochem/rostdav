//! Browser sessions, CSRF values and the small services the web interface needs
//! (ADR 0006). Everything file-related goes through the normal file service.

use std::net::IpAddr;

use rostdav_core::{Error, Result};
use rostdav_meta::{AppPassword, Session};
use serde_json::json;

use crate::AppState;
use crate::auth::{Principal, Scope, Via};
use crate::secrets::{hash_token, mac, mac_eq, random_token};

/// Session cookie length (characters, ~6 bits each).
const COOKIE_LEN: usize = 43;

#[derive(Clone, Debug)]
pub struct WebOptions {
    /// Seconds of inactivity after which a session ends.
    pub idle_secs: i64,
    /// Seconds after which a session ends regardless of activity.
    pub max_secs: i64,
}

impl Default for WebOptions {
    fn default() -> Self {
        Self {
            idle_secs: 8 * 3600,
            max_secs: 14 * 86_400,
        }
    }
}

/// A signed-in browser session.
#[derive(Clone, Debug)]
pub struct WebSession {
    pub id: i64,
    pub principal: Principal,
}

/// Optional personal details.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Profile {
    pub display_name: String,
    pub email: String,
}

/// Where a user's storage goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageOverview {
    pub files: i64,
    pub versions: i64,
    pub trash: i64,
    pub used: i64,
    /// `None` = unlimited.
    pub quota: Option<i64>,
}

/// Preference keys the interface may set, with their allowed values.
const PREFS: &[(&str, &[&str])] = &[("theme", &["system", "light", "dark"])];

impl AppState {
    // ---- sessions ----------------------------------------------------------------

    /// Checks the account password and opens a session. Returns the cookie value.
    pub async fn web_sign_in(
        &self,
        user: &str,
        password: &str,
        ip: IpAddr,
        user_agent: &str,
    ) -> Result<(String, Principal)> {
        let p = self.authenticate_with(user, password, ip, false).await?;
        let token = random_token(COOKIE_LEN);
        let web = &self.inner.config.web;
        let ua: String = user_agent
            .chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect();
        self.inner
            .db
            .create_session(
                p.user_id,
                &hash_token(&token),
                crate::now_secs() + web.max_secs,
                &if ip.is_unspecified() {
                    String::new()
                } else {
                    ip.to_string()
                },
                &ua,
            )
            .await?;
        self.audit(&p.name, "auth.login", "web", Some(ip), json!({}))
            .await;
        Ok((token, p))
    }

    /// The session behind a cookie value, if it is valid.
    pub async fn web_session(&self, cookie: &str) -> Result<Option<WebSession>> {
        if cookie.len() != COOKIE_LEN || !cookie.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Ok(None);
        }
        let Some((s, user)) = self
            .inner
            .db
            .find_session(&hash_token(cookie), self.inner.config.web.idle_secs)
            .await?
        else {
            return Ok(None);
        };
        self.inner.db.touch_session(s.id).await?;
        Ok(Some(WebSession {
            id: s.id,
            principal: Principal {
                user_id: user.id,
                name: user.name,
                is_admin: user.is_admin,
                via: Via::AccountPassword,
                scope: Scope::Full,
            },
        }))
    }

    pub async fn web_sign_out(&self, s: &WebSession) -> Result<()> {
        self.inner.db.delete_session(s.id).await?;
        self.audit(&s.principal.name, "auth.logout", "web", None, json!({}))
            .await;
        Ok(())
    }

    pub async fn web_sessions(&self, p: &Principal) -> Result<Vec<Session>> {
        Self::require_full(p)?;
        self.inner.db.list_sessions(p.user_id).await
    }

    /// Ends all other browser sessions of the user ("sign out everywhere else").
    pub async fn web_end_other_sessions(&self, s: &WebSession) -> Result<u64> {
        self.inner
            .db
            .delete_other_sessions(s.principal.user_id, s.id)
            .await
    }

    // ---- CSRF ------------------------------------------------------------------------

    /// The CSRF value of a signed-in session.
    pub fn web_csrf(&self, session_id: i64) -> String {
        mac(
            &self.inner.server_key,
            &["web-csrf", &session_id.to_string()],
        )
    }

    pub fn web_check_csrf(&self, session_id: i64, given: &str) -> Result<()> {
        if mac_eq(&self.web_csrf(session_id), given) {
            Ok(())
        } else {
            Err(Error::Forbidden)
        }
    }

    /// For the anonymous sign-in form: a random cookie value and the form value derived from it.
    pub fn login_csrf_issue(&self) -> (String, String) {
        let cookie = random_token(32);
        let form = mac(&self.inner.server_key, &["login-csrf", &cookie]);
        (cookie, form)
    }

    pub fn login_csrf_check(&self, cookie: &str, form: &str) -> Result<()> {
        if cookie.len() == 32 && mac_eq(&mac(&self.inner.server_key, &["login-csrf", cookie]), form)
        {
            Ok(())
        } else {
            Err(Error::Forbidden)
        }
    }

    // ---- public link page -----------------------------------------------------------------

    /// Proof that the visitor entered the link's password, valid for an hour. Stateless.
    pub fn link_ticket(&self, token: &str) -> String {
        let expiry = crate::now_secs() + 3600;
        format!(
            "{expiry}.{}",
            mac(
                &self.inner.server_key,
                &["link-ticket", token, &expiry.to_string()]
            )
        )
    }

    pub fn link_ticket_valid(&self, token: &str, ticket: &str) -> bool {
        let Some((expiry, sig)) = ticket.split_once('.') else {
            return false;
        };
        let Ok(exp) = expiry.parse::<i64>() else {
            return false;
        };
        exp > crate::now_secs()
            && mac_eq(
                &mac(&self.inner.server_key, &["link-ticket", token, expiry]),
                sig,
            )
    }

    /// Whether a live public link with this token exists and whether it has a password.
    /// `None` for unknown, expired or malformed tokens.
    pub async fn link_needs_password(&self, token: &str) -> Result<Option<bool>> {
        if !(8..=64).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Ok(None);
        }
        Ok(self
            .inner
            .db
            .find_link(token)
            .await?
            .map(|s| s.password_hash.is_some()))
    }

    /// The principal of a link page visit: a password-less link, or one whose
    /// password the visitor proved with a valid ticket. Never checks passwords.
    pub async fn link_page_principal(
        &self,
        token: &str,
        ticket: Option<&str>,
    ) -> Result<Principal> {
        let Some(needs) = self.link_needs_password(token).await? else {
            return Err(Error::NotFound);
        };
        if needs && !ticket.is_some_and(|t| self.link_ticket_valid(token, t)) {
            return Err(Error::Unauthenticated);
        }
        let s = self
            .inner
            .db
            .find_link(token)
            .await?
            .ok_or(Error::NotFound)?;
        Ok(Principal {
            user_id: s.owner_id,
            name: "public link".to_owned(),
            is_admin: false,
            via: Via::Link(s.id),
            scope: Scope::Link {
                share_id: s.id,
                node_id: s.node_id,
                perms: s.permissions & 15,
            },
        })
    }

    /// Checks the link password (rate limited) and returns a ticket for the cookie.
    pub async fn link_unlock(&self, token: &str, password: &str, ip: IpAddr) -> Result<String> {
        self.authenticate_link(token, password, ip).await?;
        Ok(self.link_ticket(token))
    }

    // ---- devices -------------------------------------------------------------------------

    pub async fn app_passwords(&self, p: &Principal) -> Result<Vec<AppPassword>> {
        Self::require_full(p)?;
        self.inner.db.list_app_passwords(p.user_id).await
    }

    /// Creates an app password from the Devices page; the token is shown once.
    pub async fn device_create(&self, p: &Principal, name: &str) -> Result<String> {
        Self::require_full(p)?;
        let name: String = name.chars().filter(|c| !c.is_control()).take(128).collect();
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::BadRequest("a device needs a name"));
        }
        let token = self.create_app_password(p.user_id, name).await?;
        self.audit(
            &p.name,
            "device.connected",
            name,
            None,
            json!({"how": "web"}),
        )
        .await;
        Ok(token)
    }

    pub async fn device_revoke(&self, p: &Principal, id: i64) -> Result<()> {
        Self::require_full(p)?;
        let name = self
            .inner
            .db
            .list_app_passwords(p.user_id)
            .await?
            .into_iter()
            .find(|d| d.id == id)
            .map(|d| d.name);
        if !self.inner.db.revoke_app_password(p.user_id, id).await? {
            return Err(Error::NotFound);
        }
        self.audit(
            &p.name,
            "device.revoked",
            &name.unwrap_or_default(),
            None,
            json!({"how": "web"}),
        )
        .await;
        Ok(())
    }

    // ---- settings --------------------------------------------------------------------------

    pub async fn pref(&self, p: &Principal, key: &str) -> Result<Option<String>> {
        Self::require_full(p)?;
        self.inner.db.get_pref(p.user_id, key).await
    }

    pub async fn set_pref(&self, p: &Principal, key: &str, value: &str) -> Result<()> {
        Self::require_full(p)?;
        let allowed = PREFS
            .iter()
            .find(|(k, _)| *k == key)
            .is_some_and(|(_, vs)| vs.contains(&value));
        if !allowed {
            return Err(Error::BadRequest("invalid setting"));
        }
        self.inner.db.set_pref(p.user_id, key, value).await
    }

    /// Used bytes and quota (`None` = unlimited) for the storage meter on every page.
    pub async fn storage_summary(&self, p: &Principal) -> Result<(i64, Option<i64>)> {
        Self::require_full(p)?;
        let (quota, used) = self.inner.db.quota_info(p.user_id).await?;
        Ok((used, quota))
    }

    // ---- profile and password ---------------------------------------------------------------

    /// Display name and e-mail address of the user (empty if not set).
    pub async fn profile(&self, p: &Principal) -> Result<Profile> {
        Self::require_full(p)?;
        Ok(Profile {
            display_name: self
                .inner
                .db
                .get_pref(p.user_id, "display_name")
                .await?
                .unwrap_or_default(),
            email: self
                .inner
                .db
                .get_pref(p.user_id, "email")
                .await?
                .unwrap_or_default(),
        })
    }

    pub async fn set_profile(&self, p: &Principal, display_name: &str, email: &str) -> Result<()> {
        Self::require_full(p)?;
        let display_name = display_name.trim();
        let email = email.trim();
        if display_name.chars().count() > 80 || display_name.chars().any(char::is_control) {
            return Err(Error::BadRequest(
                "the display name is too long or has invalid characters",
            ));
        }
        if !email.is_empty() {
            let ok = email.len() <= 254
                && !email.chars().any(|c| c.is_control() || c.is_whitespace())
                && email.split_once('@').is_some_and(|(l, d)| {
                    !l.is_empty() && d.contains('.') && !d.starts_with('.') && !d.ends_with('.')
                });
            if !ok {
                return Err(Error::BadRequest(
                    "that does not look like an e-mail address",
                ));
            }
        }
        self.inner
            .db
            .set_pref(p.user_id, "display_name", display_name)
            .await?;
        self.inner.db.set_pref(p.user_id, "email", email).await?;
        Ok(())
    }

    /// Changes the account password after checking the current one (rate limited
    /// like a sign-in). All other browser sessions end; app passwords stay.
    pub async fn web_change_password(
        &self,
        s: &WebSession,
        current: &str,
        new: &str,
        ip: IpAddr,
    ) -> Result<()> {
        let p = &s.principal;
        // verifies the account password only (app passwords do not count here)
        self.authenticate_with(&p.name, current, ip, false).await?;
        let hash = crate::hash_password(new)?;
        self.inner.db.set_password_hash(p.user_id, &hash).await?;
        let ended = self.inner.db.delete_other_sessions(p.user_id, s.id).await?;
        self.audit(
            &p.name,
            "auth.password_changed",
            "web",
            Some(ip),
            json!({"sessions_ended": ended}),
        )
        .await;
        Ok(())
    }

    pub async fn usage_overview(&self, p: &Principal) -> Result<UsageOverview> {
        Self::require_full(p)?;
        let (files, versions, trash) = self.inner.db.usage_breakdown(p.user_id).await?;
        let (quota, used) = self.inner.db.quota_info(p.user_id).await?;
        Ok(UsageOverview {
            files,
            versions,
            trash,
            used,
            quota,
        })
    }
}

#[cfg(test)]
mod tests {
    use rostdav_meta::Db;
    use rostdav_storage::LocalStore;

    use super::*;

    async fn state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalStore::open(dir.path().join("data"))
            .await
            .expect("store");
        let db = Db::open(&Db::default_url(store.root())).await.expect("db");
        db.migrate().await.expect("migrate");
        (dir, AppState::new(db, store).await.expect("state"))
    }

    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));

    #[tokio::test]
    async fn sign_in_session_and_sign_out() {
        let (_d, st) = state().await;
        st.add_user("alice", "correct horse battery", false)
            .await
            .expect("user");
        assert!(st.web_sign_in("alice", "wrong", IP, "ua").await.is_err());
        let (cookie, _) = st
            .web_sign_in("alice", "correct horse battery", IP, "ua")
            .await
            .expect("login");
        let s = st
            .web_session(&cookie)
            .await
            .expect("lookup")
            .expect("valid");
        assert_eq!(s.principal.name, "alice");
        assert!(st.web_session("short").await.expect("lookup").is_none());
        st.web_sign_out(&s).await.expect("out");
        assert!(st.web_session(&cookie).await.expect("lookup").is_none());
    }

    #[tokio::test]
    async fn csrf_is_bound_to_the_session() {
        let (_d, st) = state().await;
        let t = st.web_csrf(1);
        assert!(st.web_check_csrf(1, &t).is_ok());
        assert!(st.web_check_csrf(2, &t).is_err());
        assert!(st.web_check_csrf(1, "").is_err());
        let (cookie, form) = st.login_csrf_issue();
        assert!(st.login_csrf_check(&cookie, &form).is_ok());
        assert!(st.login_csrf_check(&cookie, "x").is_err());
        let (other, _) = st.login_csrf_issue();
        assert!(st.login_csrf_check(&other, &form).is_err());
    }

    #[tokio::test]
    async fn link_ticket_is_bound_to_token_and_unforgeable() {
        let (_d, st) = state().await;
        let t = st.link_ticket("abc");
        assert!(st.link_ticket_valid("abc", &t));
        assert!(!st.link_ticket_valid("abd", &t));
        assert!(!st.link_ticket_valid("abc", "9999999999.deadbeef"));
        assert!(!st.link_ticket_valid("abc", "garbage"));
    }

    #[tokio::test]
    async fn devices_and_preferences() {
        let (_d, st) = state().await;
        let u = st
            .add_user("bob", "correct horse battery", false)
            .await
            .expect("user");
        let p = st
            .authenticate("bob", "correct horse battery", IP)
            .await
            .expect("auth");
        assert_eq!(p.user_id, u.id);
        assert!(st.device_create(&p, "  ").await.is_err());
        let token = st.device_create(&p, "phone").await.expect("create");
        assert_eq!(token.len(), 72);
        let list = st.app_passwords(&p).await.expect("list");
        assert_eq!(list.len(), 1);
        st.device_revoke(&p, list[0].id).await.expect("revoke");
        assert!(st.device_revoke(&p, list[0].id).await.is_err());
        assert!(st.set_pref(&p, "theme", "neon").await.is_err());
        assert!(st.set_pref(&p, "other", "dark").await.is_err());
        st.set_pref(&p, "theme", "dark").await.expect("set");
        assert_eq!(
            st.pref(&p, "theme").await.expect("get").as_deref(),
            Some("dark")
        );
    }
}
