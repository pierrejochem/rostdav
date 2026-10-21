//! Logging.
//!
//! Rules: no passwords, tokens, `Authorization`/`Cookie` headers or file
//! contents in logs. Headers are marked sensitive in the HTTP layer;
//! spans contain only method, path without query and request ID.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::{Log, LogFormat};

/// Initializes global logging. `RUST_LOG` takes precedence over the configuration.
pub fn init(cfg: &Log) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.level));
    let registry = tracing_subscriber::registry().with(filter);
    match cfg.format {
        LogFormat::Json => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true),
            )
            .init(),
        LogFormat::Pretty => registry.with(tracing_subscriber::fmt::layer()).init(),
    }
}
