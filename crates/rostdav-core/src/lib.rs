//! Domain types and errors of Rostdav.
//!
//! This crate has no dependencies on other Rostdav crates. All protocol and
//! service layers map their errors to [`Error`].

pub mod error;
pub mod path;
pub mod time;

pub use error::{Error, Result};
pub use path::{LogicalPath, Name};

/// Product name as reported to clients and in logs.
pub const PRODUCT_NAME: &str = "Rostdav";

/// Version dieses Builds.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Address of the client as determined by the HTTP layer (socket peer, or the
/// forwarded address when the peer is a trusted proxy). Inserted into request
/// extensions; protocol crates read it for rate limiting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientIp(pub std::net::IpAddr);
