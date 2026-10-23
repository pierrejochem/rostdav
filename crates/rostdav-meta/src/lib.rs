//! Metadaten-Datenbank.
//!
//! Schema and migrations per ADR 0002. Repositories are added as the
//! milestones require them.

mod admin;
mod auth;
mod avatars;
mod favorites;
mod nodes;
mod shares;
mod trash;
mod two_factor;
mod users;
mod versions;

pub use admin::{Event, UsageMismatch, UserSummary};
pub use auth::{
    AppPassword, LoginFlow, MAX_UPLOAD_SESSIONS_PER_USER, PollResult, Session, UploadSession,
};
pub use avatars::StoredAvatar;
pub use nodes::{CommitOpts, NewBlob, Node, NodeKind, VersionPolicy, WriteCondition, Written};
pub use shares::{
    NewShare, PERM_ALL, PERM_CREATE, PERM_DELETE, PERM_READ, PERM_UPDATE, Share, ShareKind,
    ShareUpdate,
};
pub use trash::TrashItem;
pub use two_factor::TotpRow;
pub use users::{NewUser, User};
pub use versions::Version;

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use rostdav_core::{Error, Result};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};

/// Connection pool to the metadata database.
#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    /// Opens (and creates if needed) a SQLite database.
    ///
    /// `url` has the form `sqlite://<path>`. WAL mode, foreign keys and
    /// a busy timeout are always enabled.
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

        tracing::info!("metadata database opened");
        Ok(Self { pool })
    }

    /// Applies pending migrations.
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(Error::internal)?;
        tracing::info!("migrations applied");
        Ok(())
    }

    /// Number of blobs registered in the database.
    pub async fn count_blobs(&self) -> Result<i64> {
        sqlx::query_scalar("SELECT count(*) FROM blobs")
            .fetch_one(&self.pool)
            .await
            .map_err(Error::internal)
    }

    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Builds the default URL for a SQLite file below the data directory.
    pub fn default_url(data_dir: &Path) -> String {
        format!(
            "sqlite://{}",
            data_dir.join("db").join("rostdav.sqlite").display()
        )
    }

    /// Checks whether the database answers queries.
    pub async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(Error::internal)
    }

    /// Closes all connections in an orderly way.
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
        db.migrate().await.expect("second run");
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
        assert!(insert("file", None).await.is_err(), "file without blob");
        assert!(
            insert("dir", Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"))
                .await
                .is_err(),
            "directory with blob"
        );
        assert!(
            insert("file", Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"))
                .await
                .is_err(),
            "unknown blob (FK)"
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
        assert!(mk("a").await.is_err(), "duplicate");
        mk("A").await.expect("case is significant");
    }
}
