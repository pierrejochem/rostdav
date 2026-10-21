//! Principals, authentication and authorization.
//!
//! `authorize()` is the only place that decides who may touch a node. It runs
//! on the resolved node, never on a path string.

use std::net::IpAddr;
use std::sync::OnceLock;

use base64::Engine;

use rostdav_core::{Error, Name, Result};
use rostdav_meta::Node;

use crate::AppState;
use crate::password::{hash_password, verify_password};
use crate::secrets::{hash_token, random_token};

/// Length of generated app passwords.
pub const APP_PASSWORD_LEN: usize = 72;

/// How the caller proved their identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    AccountPassword,
    /// ID of the app password used.
    AppPassword(i64),
}

/// The authenticated caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub user_id: i64,
    pub name: String,
    pub is_admin: bool,
    pub via: Via,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Read,
    Write,
}

/// Until shares exist (M9) only the owner may access a node. Administrators
/// get no implicit access to other users' files.
pub fn authorize(principal: &Principal, node: &Node, _action: Action) -> Result<()> {
    if node.owner_id == principal.user_id {
        Ok(())
    } else {
        Err(Error::Forbidden)
    }
}

/// Hash verified for unknown users so that response time does not reveal
/// whether a user exists.
fn dummy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| hash_password("dummy-password-for-timing").unwrap_or_default())
}

impl AppState {
    /// Authenticates an `Authorization: Basic …` header value.
    ///
    /// The password may be an app password of that user or the account
    /// password. Failed attempts count against the client IP and the user
    /// name; a blocked key yields [`Error::RateLimited`] before any hashing.
    /// All other failures look alike: [`Error::Unauthenticated`].
    pub async fn authenticate_basic(&self, header: &str, ip: IpAddr) -> Result<Principal> {
        let (scheme, b64) = header.split_once(' ').ok_or(Error::Unauthenticated)?;
        if !scheme.eq_ignore_ascii_case("basic") {
            return Err(Error::Unauthenticated);
        }
        let ip_key = format!("ip:{ip}");
        self.inner.limiter.check(&ip_key).map_err(retry)?;
        let creds = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .ok()
            .and_then(|d| String::from_utf8(d).ok())
            .and_then(|d| d.split_once(':').map(|(u, p)| (u.to_owned(), p.to_owned())));
        let Some((user, password)) = creds else {
            self.inner.limiter.record_failure(&ip_key);
            return Err(Error::Unauthenticated);
        };
        self.authenticate(&user, &password, ip).await
    }

    /// Checks a user name plus app password or account password.
    pub async fn authenticate(&self, name: &str, password: &str, ip: IpAddr) -> Result<Principal> {
        self.authenticate_with(name, password, ip, true).await
    }

    /// Like [`authenticate`](Self::authenticate); `allow_app_password = false`
    /// accepts only the account password (browser login forms).
    pub(crate) async fn authenticate_with(
        &self,
        name: &str,
        password: &str,
        ip: IpAddr,
        allow_app_password: bool,
    ) -> Result<Principal> {
        let ip_key = format!("ip:{ip}");
        let user_key = format!(
            "user:{}",
            Name::parse(name).map_or_else(|_| name.to_owned(), |n| n.key().to_owned())
        );
        self.inner.limiter.check(&ip_key).map_err(retry)?;
        self.inner.limiter.check(&user_key).map_err(retry)?;

        let user = self.inner.db.find_user(name).await?;
        if let Some(u) = user.as_ref().filter(|_| allow_app_password) {
            // App passwords are random and long: an indexed hash lookup is enough.
            if let Some(id) = self
                .inner
                .db
                .find_app_password(u.id, &hash_token(password))
                .await?
            {
                self.inner.db.touch_app_password(id).await?;
                self.inner.limiter.clear(&user_key);
                return Ok(Principal {
                    user_id: u.id,
                    name: u.name.clone(),
                    is_admin: u.is_admin,
                    via: Via::AppPassword(id),
                });
            }
        }

        let hash = user
            .as_ref()
            .map_or_else(|| dummy_hash().to_owned(), |u| u.password_hash.clone());
        let password = password.to_owned();
        // Argon2 is CPU-heavy: keep it off the async workers.
        let ok = tokio::task::spawn_blocking(move || verify_password(&password, &hash))
            .await
            .map_err(Error::internal)?;
        match user {
            Some(u) if ok => {
                self.inner.limiter.clear(&user_key);
                Ok(Principal {
                    user_id: u.id,
                    name: u.name,
                    is_admin: u.is_admin,
                    via: Via::AccountPassword,
                })
            }
            _ => {
                self.inner.limiter.record_failure(&ip_key);
                self.inner.limiter.record_failure(&user_key);
                Err(Error::Unauthenticated)
            }
        }
    }

    /// Creates an app password for `user_id` and returns the clear token (shown once).
    pub async fn create_app_password(&self, user_id: i64, name: &str) -> Result<String> {
        Ok(self.create_app_password_with_id(user_id, name).await?.1)
    }

    pub(crate) async fn create_app_password_with_id(
        &self,
        user_id: i64,
        name: &str,
    ) -> Result<(i64, String)> {
        let token = random_token(APP_PASSWORD_LEN);
        let id = self
            .inner
            .db
            .create_app_password(user_id, name, &hash_token(&token))
            .await?;
        Ok((id, token))
    }

    /// Revokes the app password the principal signed in with (sign-out).
    pub async fn revoke_current_app_password(&self, p: &Principal) -> Result<()> {
        match p.via {
            Via::AppPassword(id) => {
                self.inner.db.revoke_app_password(p.user_id, id).await?;
                Ok(())
            }
            Via::AccountPassword => Err(Error::BadRequest("not signed in with an app password")),
        }
    }
}

fn retry(retry_after_secs: u64) -> Error {
    Error::RateLimited { retry_after_secs }
}
