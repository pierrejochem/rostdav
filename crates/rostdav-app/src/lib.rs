//! Dienstschicht von Rostdav.
//!
//! Einzige Stelle, die Metadaten-Datenbank und Blob-Speicher koordiniert.
//! Protokoll-Crates (`dav`, `compat`, `web`) sprechen nur mit [`AppState`].

use std::sync::Arc;

use rostdav_core::Result;
use rostdav_meta::Db;
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

    /// Geordnetes Herunterfahren.
    pub async fn shutdown(&self) {
        self.inner.db.close().await;
    }
}
