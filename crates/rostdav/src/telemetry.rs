//! Logging.
//!
//! Regeln: keine Passwörter, Tokens, `Authorization`-/`Cookie`-Header oder
//! Dateiinhalte in Logs. Header werden im HTTP-Layer als sensibel markiert;
//! Spans enthalten nur Methode, Pfad ohne Query und Request-ID.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::{Log, LogFormat};

/// Initialisiert das globale Logging. `RUST_LOG` hat Vorrang vor der Konfiguration.
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
