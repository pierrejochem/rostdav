//! Metadaten-Datenbank.
//!
//! In M0 nur Verbindungsaufbau und Erreichbarkeitsprüfung. Das Schema folgt
//! nach Freigabepunkt 2 (ADR 0002) in M1.

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
}
