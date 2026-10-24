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
    pub audit: Audit,
    pub versioning: Versioning,
    pub trash: Trash,
    pub search: Search,
    pub web: Web,
    pub security: Security,
    pub log: Log,
    /// Keys (`section.name`) that the file or an environment variable set. The web interface
    /// shows those as "set by configuration" and does not let an administrator change them.
    #[serde(skip)]
    pub set_explicitly: std::collections::BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Trash {
    /// Deleted files go to the trash first; off = deleting is permanent.
    pub enabled: bool,
    /// Items older than this many days are deleted for good; 0 = keep until emptied.
    pub retention_days: u32,
}

impl Default for Trash {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 30,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Security {
    /// Key for the two-factor secrets: 32 random bytes, base64. Prefer the environment
    /// variable `ROSTDAV_SECURITY__TOTP_KEY` to a value in the file.
    pub totp_key: Option<String>,
    /// File with the 32 raw key bytes. Default: `totp.key` in the data directory,
    /// created when the first user starts a setup.
    pub totp_key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Web {
    /// A browser session ends after this many hours without activity (at least 1).
    pub session_idle_hours: u32,
    /// A browser session ends after this many days regardless of activity (at least 1).
    pub session_max_days: u32,
}

impl Default for Web {
    fn default() -> Self {
        Self {
            session_idle_hours: 8,
            session_max_days: 14,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Versioning {
    /// Keep the previous content when a file is overwritten.
    pub enabled: bool,
    /// Archived versions kept per file; 0 = unlimited.
    pub max_versions: u32,
    /// Versions older than this many days are deleted; 0 = keep.
    pub max_age_days: u32,
    /// Versions of a user may use at most this percentage of the quota (users
    /// without quota are not limited); 0 = no limit.
    pub max_quota_share_percent: u32,
}

impl Default for Versioning {
    fn default() -> Self {
        Self {
            enabled: true,
            max_versions: 50,
            max_age_days: 365,
            max_quota_share_percent: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Search {
    /// Read the text of files into the search index (names are searchable either way).
    pub content_indexing: bool,
    /// Files larger than this many MiB are not read.
    pub max_file_mib: u32,
    /// At most this many KiB of text are kept of one file.
    pub max_text_kib: u32,
}

impl Default for Search {
    fn default() -> Self {
        Self {
            content_indexing: true,
            max_file_mib: 64,
            max_text_kib: 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Audit {
    /// Store client addresses shortened (IPv4 /24, IPv6 /48).
    pub anonymize_ip: bool,
    /// Events older than this many days are deleted; 0 keeps everything.
    pub retention_days: u32,
}

impl Default for Audit {
    fn default() -> Self {
        Self {
            anonymize_ip: false,
            retention_days: 365,
        }
    }
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
    /// Chunked uploads that were not finished within this many hours are removed (at least 1).
    pub upload_retention_hours: u32,
    /// Quota of users created from now on: `10G`, `500M`, bytes or `unlimited`.
    pub default_quota: String,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_upload_bytes: 16 * 1024 * 1024 * 1024,
            max_chunk_bytes: 100 * 1024 * 1024,
            upload_retention_hours: 24,
            default_quota: "unlimited".to_owned(),
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
        let mut cfg: Config = figment.extract()?;
        // the same sources without the defaults layer: what is in there was set on purpose
        let mut given = Figment::new();
        match explicit_file {
            Some(path) => given = given.merge(Toml::file(path)),
            None => given = given.merge(Toml::file("rostdav.toml")),
        }
        given = given.merge(Env::prefixed("ROSTDAV_").split("__"));
        cfg.set_explicitly = rostdav_app::Tunable::ALL
            .into_iter()
            .map(rostdav_app::Tunable::key)
            .filter(|k| given.contains(k))
            .map(str::to_owned)
            .collect();
        Ok(cfg)
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
    fn settings_given_by_file_or_environment_are_recorded() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("c.toml", "[versioning]\nmax_versions = 50\n")?;
            jail.set_env("ROSTDAV_TRASH__RETENTION_DAYS", "30");
            let cfg = Config::load(Some(Path::new("c.toml"))).map_err(|e| e.to_string())?;
            // set on purpose, even if the value equals the default
            let given: Vec<&str> = cfg.set_explicitly.iter().map(String::as_str).collect();
            assert_eq!(given, ["trash.retention_days", "versioning.max_versions"]);
            // nothing given: nothing recorded
            jail.create_file("empty.toml", "")?;
            jail.clear_env();
            let cfg = Config::load(Some(Path::new("empty.toml"))).map_err(|e| e.to_string())?;
            assert!(cfg.set_explicitly.is_empty());
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
