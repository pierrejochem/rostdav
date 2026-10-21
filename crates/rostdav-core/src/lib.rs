//! Domänentypen und Fehler von Rostdav.
//!
//! Dieses Crate hat keine Abhängigkeiten zu anderen Rostdav-Crates. Alle
//! Protokoll- und Dienstschichten bilden ihre Fehler auf [`Error`] ab.

pub mod error;
pub mod path;

pub use error::{Error, Result};
pub use path::{LogicalPath, Name};

/// Produktname, wie er Clients und in Logs gemeldet wird.
pub const PRODUCT_NAME: &str = "Rostdav";

/// Version dieses Builds.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
