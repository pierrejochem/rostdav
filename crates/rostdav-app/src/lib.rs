//! Dienstschicht von Rostdav.
//!
//! Einzige Stelle, die Metadaten-Datenbank und Blob-Speicher koordiniert.
//! Protokoll-Crates (`dav`, `compat`, `web`) sprechen nur mit [`AppState`].

use std::sync::Arc;

mod password;

pub use password::{MIN_PASSWORD_CHARS, hash_password, verify_password};

use rostdav_core::Result;
use rostdav_meta::{Db, NewUser, User};
use rostdav_storage::LocalStore;

/// Gemeinsamer Zustand aller Anfragen.
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

    /// Bereitschaftsprüfung: Datenbank antwortet und Datenverzeichnis ist beschreibbar.
    pub async fn readiness(&self) -> Result<()> {
        let (db, store) = tokio::join!(self.inner.db.ping(), self.inner.store.check_writable());
        db?;
        store?;
        Ok(())
    }

    /// Legt einen Benutzer an (Admin-CLI). Das Passwort wird hier gehasht.
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

    /// Geordnetes Herunterfahren.
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
            .add_user("anna", "korrekt-pferd-batterie", false)
            .await
            .expect("add");
        assert!(u.password_hash.starts_with("$argon2id$"));
        assert!(verify_password("korrekt-pferd-batterie", &u.password_hash));
        let dup = st.add_user("anna", "korrekt-pferd-batterie", false).await;
        assert!(matches!(dup, Err(Error::Conflict(_))));
        let weak = st.add_user("bob", "kurz", false).await;
        assert!(matches!(weak, Err(Error::BadRequest(_))));
    }

    /// Absturz zwischen Blob-Ablage und DB-Commit (ADR 0002, Schritt 2 → 3):
    /// Die Datenbank kennt den Blob nicht; er ist nur als Waise auffindbar.
    #[tokio::test]
    async fn crash_between_blob_and_commit_leaves_only_orphan() {
        let (_d, st) = state().await;
        let blob = st.inner.store.put(&b"inhalt"[..], 1024).await.expect("put");
        // Prozess "stürzt ab": kein Commit. Neustart sieht dieselben Daten.
        let on_disk = st.inner.store.list_blobs().await.expect("list");
        assert_eq!(on_disk, vec![blob.id.clone()]);
        let known = st.inner.db.count_blobs().await.expect("count");
        assert_eq!(
            known, 0,
            "DB darf keinen unvollständigen Blob referenzieren"
        );
    }
}
