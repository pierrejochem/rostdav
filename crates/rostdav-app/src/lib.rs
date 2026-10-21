//! Service layer of Rostdav.
//!
//! The only place that coordinates the metadata database and blob storage.
//! Protocol crates (`dav`, `compat`, `web`) talk only to [`AppState`].

use std::sync::Arc;

mod password;

pub use password::{MIN_PASSWORD_CHARS, hash_password, verify_password};

use rostdav_core::Result;
use rostdav_meta::{Db, NewUser, User};
use rostdav_storage::LocalStore;

/// Shared state of all requests.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    db: Db,
    store: LocalStore,
}

impl AppState {
    pub fn new(db: Db, store: LocalStore) -> Self {
        Self {
            inner: Arc::new(Inner { db, store }),
        }
    }

    /// Readiness check: the database responds and the data directory is writable.
    pub async fn readiness(&self) -> Result<()> {
        let (db, store) = tokio::join!(self.inner.db.ping(), self.inner.store.check_writable());
        db?;
        store?;
        Ok(())
    }

    /// Creates a user (admin CLI). The password is hashed here.
    pub async fn add_user(&self, name: &str, password: &str, is_admin: bool) -> Result<User> {
        let password_hash = hash_password(password)?;
        self.inner
            .db
            .create_user(NewUser {
                name,
                password_hash: &password_hash,
                is_admin,
            })
            .await
    }

    /// Orderly shutdown.
    pub async fn shutdown(&self) {
        self.inner.db.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rostdav_core::Error;

    async fn state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalStore::open(dir.path().join("data"))
            .await
            .expect("store");
        let url = Db::default_url(store.root());
        let db = Db::open(&url).await.expect("db");
        db.migrate().await.expect("migrate");
        (dir, AppState::new(db, store))
    }

    #[tokio::test]
    async fn add_user_stores_verifiable_hash_not_password() {
        let (_d, st) = state().await;
        let u = st
            .add_user("anna", "correct-horse-battery", false)
            .await
            .expect("add");
        assert!(u.password_hash.starts_with("$argon2id$"));
        assert!(verify_password("correct-horse-battery", &u.password_hash));
        let dup = st.add_user("anna", "correct-horse-battery", false).await;
        assert!(matches!(dup, Err(Error::Conflict(_))));
        let weak = st.add_user("bob", "short", false).await;
        assert!(matches!(weak, Err(Error::BadRequest(_))));
    }

    /// Crash between blob placement and DB commit (ADR 0002, step 2 -> 3):
    /// the database does not know the blob; it can only be found as an orphan.
    #[tokio::test]
    async fn crash_between_blob_and_commit_leaves_only_orphan() {
        let (_d, st) = state().await;
        let blob = st
            .inner
            .store
            .put(&b"content"[..], 1024)
            .await
            .expect("put");
        // Process "crashes": no commit. A restart sees the same data.
        let on_disk = st.inner.store.list_blobs().await.expect("list");
        assert_eq!(on_disk, vec![blob.id.clone()]);
        let known = st.inner.db.count_blobs().await.expect("count");
        assert_eq!(known, 0, "DB must not reference an incomplete blob");
    }
}
