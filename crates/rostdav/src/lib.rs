//! Wiring of Rostdav: configuration, telemetry, HTTP router.

pub mod config;
pub mod http;
pub mod telemetry;

use anyhow::Context;
use rostdav_app::AppState;
use rostdav_meta::Db;
use rostdav_storage::LocalStore;

/// Builds the application state from the configuration.
pub async fn build_state(cfg: &config::Config) -> anyhow::Result<AppState> {
    let store = LocalStore::open(&cfg.storage.data_dir)
        .await
        .context("could not open data directory")?;
    let url = cfg
        .database
        .url
        .clone()
        .unwrap_or_else(|| Db::default_url(store.root()));
    let db = Db::open(&url).await.context("could not open database")?;
    db.migrate().await.context("migrations failed")?;
    let swept = store.sweep_tmp().await.context("cleaning up tmp/ failed")?;
    if swept > 0 {
        tracing::warn!(swept, "removed incomplete writes");
    }
    let state = AppState::new(db, store)
        .await
        .context("initializing the application state failed")?;
    Ok(state.with_limits(rostdav_app::Limits {
        max_upload_bytes: cfg.limits.max_upload_bytes,
        max_chunk_bytes: cfg.limits.max_chunk_bytes,
    }))
}
