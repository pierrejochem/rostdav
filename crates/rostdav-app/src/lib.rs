//! Service layer of Rostdav.
//!
//! The only place that coordinates the metadata database and blob storage.
//! Protocol crates (`dav`, `compat`, `web`) talk only to [`AppState`].

use std::sync::Arc;

mod auth;
mod files;
mod password;

pub use auth::{Action, Principal, authorize};
pub use files::Listing;
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
    limits: Limits,
}

/// Operating limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum size of a single upload in bytes.
    pub max_upload_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_upload_bytes: 16 * 1024 * 1024 * 1024,
        }
    }
}

impl AppState {
    pub fn new(db: Db, store: LocalStore) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                store,
                limits: Limits::default(),
            }),
        }
    }

    #[must_use]
    pub fn with_limits(self, limits: Limits) -> Self {
        // Called during start-up, before the state is shared.
        let inner = &*self.inner;
        Self {
            inner: Arc::new(Inner {
                db: inner.db.clone(),
                store: inner.store.clone(),
                limits,
            }),
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

    use rostdav_core::LogicalPath;
    use rostdav_meta::WriteCondition;
    use tokio::io::AsyncReadExt;

    fn lp(s: &str) -> LogicalPath {
        LogicalPath::from_url_path(s).expect("path")
    }

    async fn login(st: &AppState, name: &str) -> Principal {
        st.add_user(name, "korrekt-pferd-batterie", false)
            .await
            .expect("add");
        st.authenticate(name, "korrekt-pferd-batterie")
            .await
            .expect("auth")
    }

    #[tokio::test]
    async fn authenticate_accepts_only_correct_credentials() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        assert_eq!(anna.name, "anna");
        for (u, pw) in [
            ("anna", "falsches-passwort"),
            ("niemand", "korrekt-pferd-batterie"),
            ("", ""),
            ("../anna", "korrekt-pferd-batterie"),
        ] {
            assert!(
                matches!(st.authenticate(u, pw).await, Err(Error::Unauthenticated)),
                "{u:?}"
            );
        }
    }

    #[tokio::test]
    async fn put_then_read_roundtrip() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        st.mkcol(&anna, &lp("/docs")).await.expect("mkcol");
        let w = st
            .put(
                &anna,
                &lp("/docs/a.txt"),
                &b"hello"[..],
                None,
                &WriteCondition::None,
            )
            .await
            .expect("put");
        assert_eq!(w.node.size, 5);
        let (node, mut file) = st.read(&anna, &lp("/docs/a.txt")).await.expect("read");
        let mut out = String::new();
        file.read_to_string(&mut out).await.expect("read");
        assert_eq!(out, "hello");
        assert_eq!(node.id, w.node.id);
        let l = st.list(&anna, &lp("/docs")).await.expect("list");
        assert_eq!(l.children.len(), 1);
        assert_eq!(st.size_of(&anna, &l.node).await.expect("size"), 5);
    }

    #[tokio::test]
    async fn failed_commit_leaves_no_blob_on_disk() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        st.put(&anna, &lp("/f"), &b"1"[..], None, &WriteCondition::None)
            .await
            .expect("put");
        let err = st
            .put(
                &anna,
                &lp("/f"),
                &b"2"[..],
                None,
                &WriteCondition::MustNotExist,
            )
            .await;
        assert!(matches!(err, Err(Error::PreconditionFailed)));
        assert_eq!(st.inner.store.list_blobs().await.expect("l").len(), 1);
    }

    #[tokio::test]
    async fn missing_parent_is_conflict_not_not_found() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        let r = st
            .put(
                &anna,
                &lp("/nope/f"),
                &b"1"[..],
                None,
                &WriteCondition::None,
            )
            .await;
        assert!(matches!(r, Err(Error::Conflict(_))));
        assert!(matches!(
            st.mkcol(&anna, &lp("/a/b")).await,
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            st.mkcol(&anna, &lp("/")).await,
            Err(Error::Conflict(_))
        ));
        st.mkcol(&anna, &lp("/a")).await.expect("a");
        assert!(matches!(
            st.mkcol(&anna, &lp("/a")).await,
            Err(Error::AlreadyExists)
        ));
    }

    #[tokio::test]
    async fn second_user_cannot_see_or_touch_first_users_files() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        let bob = login(&st, "bob").await;
        st.mkcol(&anna, &lp("/private")).await.expect("mkcol");
        st.put(
            &anna,
            &lp("/private/secret.txt"),
            &b"geheim"[..],
            None,
            &WriteCondition::None,
        )
        .await
        .expect("put");

        let p = lp("/private/secret.txt");
        assert!(matches!(st.stat(&bob, &p).await, Err(Error::NotFound)));
        assert!(matches!(st.read(&bob, &p).await, Err(Error::NotFound)));
        assert!(matches!(
            st.list(&bob, &lp("/private")).await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            st.delete(&bob, &p, None).await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            st.move_to(&bob, &p, &lp("/x"), true).await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            st.copy_to(&bob, &p, &lp("/x"), true).await,
            Err(Error::NotFound)
        ));
        let w = st
            .put(
                &bob,
                &lp("/private/secret.txt"),
                &b"bobs"[..],
                None,
                &WriteCondition::None,
            )
            .await;
        assert!(matches!(w, Err(Error::Conflict(_))), "bob has no /private");

        // bob's own file of the same name does not touch anna's
        st.mkcol(&bob, &lp("/private")).await.expect("bob mkcol");
        st.put(&bob, &p, &b"bobs"[..], None, &WriteCondition::None)
            .await
            .expect("bob put");
        let (_, mut f) = st.read(&anna, &p).await.expect("anna read");
        let mut out = String::new();
        f.read_to_string(&mut out).await.expect("read");
        assert_eq!(out, "geheim");
    }

    #[tokio::test]
    async fn authorize_denies_foreign_nodes_even_when_resolved_by_id() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        let bob = login(&st, "bob").await;
        let node = st.stat(&anna, &lp("/")).await.expect("root");
        assert!(authorize(&anna, &node, Action::Write).is_ok());
        assert!(matches!(
            authorize(&bob, &node, Action::Read),
            Err(Error::Forbidden)
        ));
        let admin = Principal {
            is_admin: true,
            ..bob
        };
        assert!(
            matches!(
                authorize(&admin, &node, Action::Read),
                Err(Error::Forbidden)
            ),
            "admins get no implicit access"
        );
        assert!(matches!(
            st.size_of(&admin, &node).await,
            Err(Error::Forbidden)
        ));
    }

    #[tokio::test]
    async fn upload_limit_and_quota() {
        let (_d, st) = state().await;
        let st = st.with_limits(Limits {
            max_upload_bytes: 8,
        });
        let anna = login(&st, "anna").await;
        let big = st
            .put(
                &anna,
                &lp("/big"),
                &[0u8; 9][..],
                None,
                &WriteCondition::None,
            )
            .await;
        assert!(matches!(big, Err(Error::TooLarge)));

        st.inner
            .db
            .set_quota(anna.user_id, Some(10))
            .await
            .expect("quota");
        st.put(&anna, &lp("/a"), &[0u8; 8][..], None, &WriteCondition::None)
            .await
            .expect("a");
        let over = st
            .put(&anna, &lp("/b"), &[0u8; 3][..], None, &WriteCondition::None)
            .await;
        assert!(matches!(over, Err(Error::QuotaExceeded)));
        // replacing /a with 8 bytes again fits: the old size is freed
        st.put(&anna, &lp("/a"), &[0u8; 8][..], None, &WriteCondition::None)
            .await
            .expect("replace");
        assert_eq!(st.inner.store.list_blobs().await.expect("l").len(), 2);
    }

    #[tokio::test]
    async fn garbage_collection_removes_only_unreferenced_blobs() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        st.put(&anna, &lp("/f"), &b"1"[..], None, &WriteCondition::None)
            .await
            .expect("put");
        st.put(&anna, &lp("/g"), &b"2"[..], None, &WriteCondition::None)
            .await
            .expect("put");
        // unregistered blob = upload in flight; GC must not touch it
        let inflight = st.inner.store.put(&b"3"[..], 10).await.expect("inflight");
        st.delete(&anna, &lp("/f"), None).await.expect("delete");
        assert_eq!(st.collect_garbage().await.expect("gc"), 1);
        let left = st.inner.store.list_blobs().await.expect("l");
        assert_eq!(left.len(), 2);
        assert!(left.contains(&inflight.id));
    }
}
