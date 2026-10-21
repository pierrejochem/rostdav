//! Configuration.
//!
//! Precedence (highest first): environment variables `ROSTDAV_<SECTION>__<KEY>`,
//! configuration file (`rostdav.toml`), built-in defaults. Later, the command
//! line (on top) and database settings from the UI (at the bottom) will be added.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: Server,
    pub storage: Storage,
    pub database: Database,
    pub limits: Limits,
    pub compat: Compat,
    pub log: Log,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Compat {
    /// Version reported to clients (`status.php`, capabilities): `major.minor.micro[.build]`.
    pub reported_version: String,
    /// `productname` reported to clients.
    pub product_name: String,
}

impl Default for Compat {
    fn default() -> Self {
        Self {
            // Version of the reference server the fixtures were recorded from.
            reported_version: "35.0.2.2".into(),
            product_name: "Rostdav".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Maximum size of a single upload in bytes.
    pub max_upload_bytes: u64,
    /// Maximum size of one chunk of a chunked upload in bytes.
    pub max_chunk_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_upload_bytes: 16 * 1024 * 1024 * 1024,
            max_chunk_bytes: 100 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    /// Address on which Rostdav speaks HTTP. TLS is handled by the reverse proxy.
    pub listen: SocketAddr,
    /// Externally visible base URL, e.g. `https://cloud.example.org`. Used in
    /// links handed to clients. If unset, `http://<Host header>` is used.
    pub public_url: Option<String>,
    /// Reverse proxies whose `X-Forwarded-For` header is trusted.
    pub trusted_proxies: Vec<IpAddr>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            public_url: None,
            trusted_proxies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Storage {
    /// Data directory containing `blobs/`, `tmp/`, `uploads/` and `db/`.
    pub data_dir: PathBuf,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Database {
    /// Database URL; if unset, SQLite at `<data_dir>/db/rostdav.sqlite`.
    pub url: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Json,
    Pretty,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Log {
    pub format: LogFormat,
    /// Filter in the format of `tracing_subscriber::EnvFilter`, e.g. `info,rostdav=debug`.
    pub level: String,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            format: LogFormat::Json,
            level: "info".into(),
        }
    }
}

impl Config {
    /// Loads the configuration. An explicitly given file must exist;
    /// the default file `rostdav.toml` is optional.
    pub fn load(explicit_file: Option<&Path>) -> anyhow::Result<Self> {
        let mut figment = Figment::from(Serialized::defaults(Config::default()));
        match explicit_file {
            Some(path) => {
                anyhow::ensure!(
                    path.is_file(),
                    "configuration file not found: {}",
                    path.display()
                );
                figment = figment.merge(Toml::file(path));
            }
            None => figment = figment.merge(Toml::file("rostdav.toml")),
        }
        figment = figment.merge(Env::prefixed("ROSTDAV_").split("__"));
        Ok(figment.extract()?)
    }
}

#[cfg(test)]
// figment::Jail forces figment::Error as the error type of the test closures.
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_local_only() {
        let cfg = Config::default();
        assert!(cfg.server.listen.ip().is_loopback());
        assert_eq!(cfg.log.format, LogFormat::Json);
    }

    #[test]
    fn file_and_env_precedence() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "custom.toml",
                r#"
                [server]
                listen = "0.0.0.0:9000"
                [storage]
                data_dir = "/srv/rostdav"
                "#,
            )?;
            jail.set_env("ROSTDAV_SERVER__LISTEN", "127.0.0.1:9100");
            let cfg = Config::load(Some(Path::new("custom.toml"))).map_err(|e| e.to_string())?;
            assert_eq!(
                cfg.server.listen,
                "127.0.0.1:9100".parse::<SocketAddr>().expect("addr")
            );
            assert_eq!(cfg.storage.data_dir, PathBuf::from("/srv/rostdav"));
            Ok(())
        });
    }

    #[test]
    fn unknown_keys_are_rejected() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("bad.toml", "[server]\nlisten = \"127.0.0.1:1\"\ntypo = 1\n")?;
            assert!(Config::load(Some(Path::new("bad.toml"))).is_err());
            Ok(())
        });
    }

    #[test]
    fn explicit_missing_file_is_an_error() {
        figment::Jail::expect_with(|_jail| {
            assert!(Config::load(Some(Path::new("missing.toml"))).is_err());
            Ok(())
        });
    }
}
