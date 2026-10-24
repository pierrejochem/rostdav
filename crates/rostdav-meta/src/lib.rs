//! Metadaten-Datenbank.
//!
//! Schema and migrations per ADR 0002. Repositories are added as the
//! milestones require them.

mod admin;
mod auth;
mod avatars;
mod favorites;
mod nodes;
mod search_index;
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
pub use search_index::{
    Candidate, Content, DocFacts, FORMAT_VERSION as SEARCH_FORMAT_VERSION, IndexStatus, MAX_FAILS,
    NodeFacts, Pending, SearchIndex, state as search_state,
};
pub use shares::{
    NewShare, PERM_ALL, PERM_CREATE, PERM_DELETE, PERM_READ, PERM_UPDATE, Share, ShareKind,
    ShareUpdate,
};
pub use trash::TrashItem;
pub use two_factor::TotpRow;
pub use users::{NewUser, User};
pub use versions::Version;

use std::path::Path;

use rostdav_core::{Error, Result};

mod sql;

/// The schema, in order. A new migration is a new file and a new line here.
const MIGRATIONS: &[(i64, &str, &str)] = &[
    (1, "init", include_str!("../migrations/0001_init.sql")),
    (2, "auth", include_str!("../migrations/0002_auth.sql")),
    (
        3,
        "nextcloud_ext",
        include_str!("../migrations/0003_nextcloud_ext.sql"),
    ),
    (4, "admin", include_str!("../migrations/0004_admin.sql")),
    (
        5,
        "versions",
        include_str!("../migrations/0005_versions.sql"),
    ),
    (6, "shares", include_str!("../migrations/0006_shares.sql")),
    (7, "trash", include_str!("../migrations/0007_trash.sql")),
    (8, "web", include_str!("../migrations/0008_web.sql")),
    (
        9,
        "two_factor",
        include_str!("../migrations/0009_two_factor.sql"),
    ),
    (
        10,
        "favorites",
        include_str!("../migrations/0010_favorites.sql"),
    ),
    (
        11,
        "avatars",
        include_str!("../migrations/0011_avatars.sql"),
    ),
    (
        12,
        "cascade_indexes",
        include_str!("../migrations/0012_cascade_indexes.sql"),
    ),
];

/// The metadata database (Turso Database, SQLite file format): one writer, a few readers.
#[derive(Clone)]
pub struct Db {
    pool: sql::Pool,
}

impl Db {
    /// Opens (and creates, if needed) the database.
    ///
    /// `url` has the form `sqlite://<path>` (the file format is SQLite's). WAL mode, foreign
    /// keys and full synchronisation are always on.
    pub async fn open(url: &str) -> Result<Self> {
        let path = url.strip_prefix("sqlite://").unwrap_or(url);
        // `sqlite::memory:` (what the SQLite-based versions accepted) is a database in memory
        let path = if path == "sqlite::memory:" {
            ":memory:"
        } else {
            path
        };
        if path != ":memory:" {
            if let Some(dir) = Path::new(path).parent() {
                std::fs::create_dir_all(dir).map_err(Error::internal)?;
            }
        }
        let pool = sql::Pool::open(path).await.map_err(Error::internal)?;
        tracing::info!("metadata database opened");
        Ok(Self { pool })
    }

    /// Applies pending migrations, each in a transaction of its own.
    ///
    /// Databases made by the SQLite-based versions (0.2 and older) kept their history in
    /// `_sqlx_migrations`; those versions count as applied.
    pub async fn migrate(&self) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(Error::internal)?;
        sql::query(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version    INTEGER PRIMARY KEY,
                 name       TEXT    NOT NULL,
                 applied_at INTEGER NOT NULL
             ) STRICT",
        )
        .execute(&mut *tx)
        .await
        .map_err(Error::internal)?;
        let old: i64 = sql::query_scalar(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(Error::internal)?;
        if old > 0 {
            sql::query(
                "INSERT OR IGNORE INTO schema_migrations (version, name, applied_at)
                 SELECT version, description, 0 FROM _sqlx_migrations WHERE success = 1",
            )
            .execute(&mut *tx)
            .await
            .map_err(Error::internal)?;
        }
        tx.commit().await.map_err(Error::internal)?;
        self.convert_without_rowid_favorites().await?;

        for &(version, name, script) in MIGRATIONS {
            let done: i64 =
                sql::query_scalar("SELECT count(*) FROM schema_migrations WHERE version = ?")
                    .bind(version)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(Error::internal)?;
            if done > 0 {
                continue;
            }
            let tx = self.pool.begin().await.map_err(Error::internal)?;
            let res = async {
                tx.execute_batch(script).await?;
                tx.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
                    (version, name, crate::users::now_secs()),
                )
                .await?;
                Ok::<(), turso::Error>(())
            }
            .await;
            match res {
                Ok(()) => tx.commit().await.map_err(Error::internal)?,
                Err(e) => {
                    let _ = tx.rollback().await;
                    return Err(Error::internal(sql::Error::from(e)));
                }
            }
            tracing::info!(version, name, "migration applied");
        }
        tracing::info!("migrations applied");
        Ok(())
    }

    /// Databases from the SQLite-based versions have `favorites` as a `WITHOUT ROWID` table.
    /// The engine reads such tables but cannot change them, so the table is rebuilt as an
    /// ordinary one (same columns, same key, same rows).
    async fn convert_without_rowid_favorites(&self) -> Result<()> {
        let def: Option<String> = sql::query_scalar(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'favorites'",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(Error::internal)?;
        if !def.is_some_and(|d| d.to_ascii_uppercase().contains("WITHOUT ROWID")) {
            return Ok(());
        }
        let tx = self.pool.begin().await.map_err(Error::internal)?;
        let res = tx
            .execute_batch(
                "CREATE TABLE favorites_rowid (
                     user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                     node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                     PRIMARY KEY (user_id, node_id)
                 ) STRICT;
                 INSERT INTO favorites_rowid (user_id, node_id) SELECT user_id, node_id FROM favorites;
                 DROP TABLE favorites;
                 ALTER TABLE favorites_rowid RENAME TO favorites;
                 CREATE INDEX IF NOT EXISTS favorites_node ON favorites(node_id);",
            )
            .await;
        match res {
            Ok(()) => tx.commit().await.map_err(Error::internal)?,
            Err(e) => {
                let _ = tx.rollback().await;
                return Err(Error::internal(sql::Error::from(e)));
            }
        }
        tracing::info!("favorites table converted to an ordinary table");
        Ok(())
    }

    /// Number of blobs registered in the database.
    pub async fn count_blobs(&self) -> Result<i64> {
        sql::query_scalar("SELECT count(*) FROM blobs")
            .fetch_one(&self.pool)
            .await
            .map_err(Error::internal)
    }

    pub(crate) fn pool(&self) -> &sql::Pool {
        &self.pool
    }

    /// Builds the default URL for the database file below the data directory.
    pub fn default_url(data_dir: &Path) -> String {
        format!(
            "sqlite://{}",
            data_dir.join("db").join("rostdav.sqlite").display()
        )
    }

    /// Checks whether the database answers queries.
    pub async fn ping(&self) -> Result<()> {
        sql::query_scalar::<i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map(|_| ())
            .map_err(Error::internal)
    }

    /// Closes the database in an orderly way (a last checkpoint).
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

    /// The engine's `ON DELETE CASCADE` can skip rows of a parent with several children when the
    /// foreign key column has no plain index (found with Turso 0.8.3). Every foreign key therefore
    /// needs a non-partial index that starts with its column, and this test keeps it that way.
    #[tokio::test]
    async fn every_foreign_key_has_a_plain_index_for_cascades() {
        let (_d, db) = test_db().await;
        let tables: Vec<String> = sql::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )
        .fetch_all(db.pool())
        .await
        .expect("tables");
        let mut missing = Vec::new();
        for t in &tables {
            let fks: Vec<(String, String)> = sql::query_as(format!(
                "SELECT \"from\", \"table\" FROM pragma_foreign_key_list('{t}')"
            ))
            .fetch_all(db.pool())
            .await
            .expect("foreign keys");
            let indexes: Vec<(String, bool)> = sql::query_as(format!(
                "SELECT name, \"partial\" FROM pragma_index_list('{t}')"
            ))
            .fetch_all(db.pool())
            .await
            .expect("indexes");
            let mut leading: Vec<String> = Vec::new();
            for (name, partial) in indexes {
                if partial {
                    continue;
                }
                let first: Option<String> = sql::query_scalar(format!(
                    "SELECT name FROM pragma_index_info('{name}') WHERE seqno = 0"
                ))
                .fetch_optional(db.pool())
                .await
                .expect("index info");
                leading.extend(first);
            }
            // a column that is the whole primary key is the row id: it needs no index
            let pk: Vec<String> = sql::query_scalar(format!(
                "SELECT name FROM pragma_table_info('{t}') WHERE pk > 0"
            ))
            .fetch_all(db.pool())
            .await
            .expect("primary key");
            for (col, parent) in fks {
                if !leading.contains(&col) && pk != [col.clone()] {
                    missing.push(format!("{t}.{col} -> {parent}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "foreign keys without a plain index: {missing:?}"
        );
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
        let root: i64 = sql::query_scalar("SELECT id FROM nodes WHERE owner_id = ?")
            .bind(u.id)
            .fetch_one(db.pool())
            .await
            .expect("root");
        let insert = |kind: &'static str, blob: Option<&'static str>| {
            sql::query(
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
        let root: i64 = sql::query_scalar("SELECT id FROM nodes WHERE owner_id = ?")
            .bind(u.id)
            .fetch_one(db.pool())
            .await
            .expect("root");
        let mk = |key: &'static str| {
            sql::query(
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
