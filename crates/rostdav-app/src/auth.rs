//! Principals, authentication and authorization.
//!
//! `authorize()` is the only place that decides who may touch a node. It runs
//! on the resolved node, never on a path string.

use std::sync::OnceLock;

use rostdav_core::{Error, Result};
use rostdav_meta::Node;

use crate::AppState;
use crate::password::{hash_password, verify_password};

/// The authenticated caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub user_id: i64,
    pub name: String,
    pub is_admin: bool,
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
    /// Checks a user name and account password.
    ///
    /// All failures look alike: [`Error::Unauthenticated`].
    pub async fn authenticate(&self, name: &str, password: &str) -> Result<Principal> {
        let user = self.inner.db.find_user(name).await?;
        let hash = user
            .as_ref()
            .map_or_else(|| dummy_hash().to_owned(), |u| u.password_hash.clone());
        let password = password.to_owned();
        // Argon2 is CPU-heavy: keep it off the async workers.
        let ok = tokio::task::spawn_blocking(move || verify_password(&password, &hash))
            .await
            .map_err(Error::internal)?;
        match user {
            Some(u) if ok => Ok(Principal {
                user_id: u.id,
                name: u.name,
                is_admin: u.is_admin,
            }),
            _ => Err(Error::Unauthenticated),
        }
    }
}
