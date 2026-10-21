//! Metadaten-Datenbank.
//!
//! Schema und Migrationen nach ADR 0002. Repositories entstehen mit dem
//! jeweiligen Bedarf der Meilensteine.

mod users;

pub use users::{NewUser, User};

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use rostdav_core::{Error, Result};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};

/// Verbindungspool zur Metadaten-Datenbank.
#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    /// Öffnet (und erzeugt bei Bedarf) eine SQLite-Datenbank.
    ///
    /// `url` hat die Form `sqlite://<pfad>`. WAL-Modus, Fremdschlüssel und
    /// ein Busy-Timeout sind immer aktiv.
    pub async fn open(url: &str) -> Result<Self> {
        let options = SqliteConnectOptions::from_str(url)
            .map_err(Error::internal)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .map_err(Error::internal)?;

        tracing::info!("Metadaten-Datenbank geöffnet");
        Ok(Self { pool })
    }

    /// Wendet ausstehende Migrationen an.
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(Error::internal)?;
        tracing::info!("Migrationen angewendet");
        Ok(())
    }

    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Baut die Standard-URL für eine SQLite-Datei unterhalb des Datenverzeichnisses.
    pub fn default_url(data_dir: &Path) -> String {
        format!(
            "sqlite://{}",
            data_dir.join("db").join("rostdav.sqlite").display()
        )
    }

    /// Prüft, ob die Datenbank Anfragen beantwortet.
    pub async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(Error::internal)
    }

    /// Schließt alle Verbindungen geordnet.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_creates_file_and_pings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("t.sqlite");
        let db = Db::open(&format!("sqlite://{}", path.display()))
            .await
            .expect("open");
        db.ping().await.expect("ping");
        assert!(path.exists());
        db.close().await;
    }

    pub(crate) async fn test_db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Db::open(&format!(
            "sqlite://{}",
            dir.path().join("t.sqlite").display()
        ))
        .await
        .expect("open");
        db.migrate().await.expect("migrate");
        (dir, db)
    }

    #[tokio::test]
    async fn migrate_is_idempotent() {
        let (_d, db) = test_db().await;
        db.migrate().await.expect("zweiter Lauf");
    }

    #[tokio::test]
    async fn file_node_requires_blob_and_dir_forbids_it() {
        let (_d, db) = test_db().await;
        let u = db
            .create_user(NewUser {
                name: "anna",
                password_hash: "x",
                is_admin: false,
            })
            .await
            .expect("user");
        let root: i64 = sqlx::query_scalar("SELECT id FROM nodes WHERE owner_id = ?")
            .bind(u.id)
            .fetch_one(db.pool())
            .await
            .expect("root");
        let insert = |kind: &'static str, blob: Option<&'static str>| {
            sqlx::query(
                "INSERT INTO nodes (owner_id, parent_id, name, name_key, kind, mtime, etag, blob_id, created_at, updated_at)
                 VALUES (?, ?, 'f', 'f', ?, 0, 'e', ?, 0, 0)",
            )
            .bind(u.id)
            .bind(root)
            .bind(kind)
            .bind(blob)
            .execute(db.pool())
        };
        assert!(insert("file", None).await.is_err(), "Datei ohne Blob");
        assert!(
            insert("dir", Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"))
                .await
                .is_err(),
            "Ordner mit Blob"
        );
        assert!(
            insert("file", Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"))
                .await
                .is_err(),
            "Blob unbekannt (FK)"
        );
        assert!(insert("dir", None).await.is_ok());
    }

    #[tokio::test]
    async fn sibling_names_unique_by_nfc_key_only() {
        let (_d, db) = test_db().await;
        let u = db
            .create_user(NewUser {
                name: "anna",
                password_hash: "x",
                is_admin: false,
            })
            .await
            .expect("user");
        let root: i64 = sqlx::query_scalar("SELECT id FROM nodes WHERE owner_id = ?")
            .bind(u.id)
            .fetch_one(db.pool())
            .await
            .expect("root");
        let mk = |key: &'static str| {
            sqlx::query(
                "INSERT INTO nodes (owner_id, parent_id, name, name_key, kind, mtime, etag, created_at, updated_at)
                 VALUES (?, ?, ?, ?, 'dir', 0, 'e', 0, 0)",
            )
            .bind(u.id)
            .bind(root)
            .bind(key)
            .bind(key)
            .execute(db.pool())
        };
        mk("a").await.expect("a");
        assert!(mk("a").await.is_err(), "Duplikat");
        mk("A").await.expect("Groß-/Kleinschreibung zählt");
    }
}
