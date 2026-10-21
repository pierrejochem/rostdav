//! Verdrahtung von Rostdav: Konfiguration, Telemetrie, HTTP-Router.

pub mod config;
pub mod http;
pub mod telemetry;

use anyhow::Context;
use rostdav_app::AppState;
use rostdav_meta::Db;
use rostdav_storage::LocalStore;

/// Baut den Anwendungszustand aus der Konfiguration.
pub async fn build_state(cfg: &config::Config) -> anyhow::Result<AppState> {
    let store = LocalStore::open(&cfg.storage.data_dir)
        .await
        .context("Datenverzeichnis konnte nicht geöffnet werden")?;
    let url = cfg
        .database
        .url
        .clone()
        .unwrap_or_else(|| Db::default_url(store.root()));
    let db = Db::open(&url)
        .await
        .context("Datenbank konnte nicht geöffnet werden")?;
    db.migrate().await.context("Migrationen fehlgeschlagen")?;
    let swept = store
        .sweep_tmp()
        .await
        .context("Aufräumen von tmp/ fehlgeschlagen")?;
    if swept > 0 {
        tracing::warn!(swept, "unvollständige Schreibvorgänge entfernt");
    }
    Ok(AppState::new(db, store))
}
