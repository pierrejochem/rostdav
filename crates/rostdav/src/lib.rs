//! Wiring of Rostdav: configuration, telemetry, HTTP router.

pub mod cli;
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
    let state = AppState::new(db, store)
        .await
        .context("initializing the application state failed")?;
    Ok(state
        .with_limits(rostdav_app::Limits {
            max_upload_bytes: cfg.limits.max_upload_bytes,
            max_chunk_bytes: cfg.limits.max_chunk_bytes,
        })
        .with_versioning(rostdav_app::VersioningOptions {
            enabled: cfg.versioning.enabled,
            max_versions: cfg.versioning.max_versions,
            max_age_days: cfg.versioning.max_age_days,
            max_quota_share_percent: cfg.versioning.max_quota_share_percent,
        })
        .with_trash(rostdav_app::TrashOptions {
            enabled: cfg.trash.enabled,
            retention_days: cfg.trash.retention_days,
        })
        .with_web(rostdav_app::WebOptions {
            idle_secs: i64::from(cfg.web.session_idle_hours.max(1)) * 3600,
            max_secs: i64::from(cfg.web.session_max_days.max(1)) * 86_400,
        })
        .with_audit(rostdav_app::AuditOptions {
            anonymize_ip: cfg.audit.anonymize_ip,
            retention_days: cfg.audit.retention_days,
        }))
}
