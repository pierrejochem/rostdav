//! Wiring of Rostdav: configuration, telemetry, HTTP router.

pub mod admin_socket;
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
            upload_retention_secs: i64::from(cfg.limits.upload_retention_hours.max(1)) * 3600,
            default_quota: rostdav_app::parse_quota(&cfg.limits.default_quota)
                .map_err(|e| anyhow::anyhow!("limits.default_quota: {e}"))?,
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
        .with_search(rostdav_app::SearchOptions {
            content: cfg.search.content_indexing,
            max_file_bytes: u64::from(cfg.search.max_file_mib.max(1)) << 20,
            max_text_bytes: (cfg.search.max_text_kib.max(16) as usize) << 10,
        })
        .with_security(rostdav_app::SecurityOptions {
            totp_key: totp_key_source(cfg)?,
        })
        .with_web(rostdav_app::WebOptions {
            idle_secs: i64::from(cfg.web.session_idle_hours.max(1)) * 3600,
            max_secs: i64::from(cfg.web.session_max_days.max(1)) * 86_400,
        })
        .with_audit(rostdav_app::AuditOptions {
            anonymize_ip: cfg.audit.anonymize_ip,
            retention_days: cfg.audit.retention_days,
        })
        // what the file and the environment leave open can be changed in the web interface
        .with_locked_settings(cfg.set_explicitly.iter().cloned())
        .load_setting_overrides()
        .await?)
}

/// Where the key for the two-factor secrets comes from (ADR 0007).
fn totp_key_source(cfg: &config::Config) -> anyhow::Result<rostdav_app::TotpKeySource> {
    use base64::Engine;
    if let Some(k) = &cfg.security.totp_key {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(k.trim())
            .context("security.totp_key is not valid base64")?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("security.totp_key must be 32 bytes (base64)"))?;
        return Ok(rostdav_app::TotpKeySource::Fixed(key));
    }
    let path = cfg
        .security
        .totp_key_file
        .clone()
        .unwrap_or_else(|| cfg.storage.data_dir.join("totp.key"));
    Ok(rostdav_app::TotpKeySource::File(path))
}
