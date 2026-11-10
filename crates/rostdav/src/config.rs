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
    pub mfa: Mfa,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MfaAttestation {
    /// Phones must prove a hardware-backed key (default).
    Required,
    /// No check; for custom ROMs, with the trade-off described in `docs/admin.md`.
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Mfa {
    /// Seconds a sign-in challenge can be answered (10 to 300).
    pub challenge_ttl_seconds: u32,
    /// Seconds an enrollment QR code stays valid (60 to 900).
    pub enroll_ttl_seconds: u32,
    /// Service identifier signed into every challenge (1 to 64 of `A-Za-z0-9._-`).
    pub audience: String,
    /// Whether phones must attest a hardware-backed key.
    pub attestation: MfaAttestation,
    /// Waking phones through Firebase Cloud Messaging. Off unless both keys are set.
    pub fcm: MfaFcm,
}

/// `[mfa.fcm]`: the Firebase project and the service-account file that may send to it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct MfaFcm {
    /// Firebase project id.
    pub project_id: Option<String>,
    /// Google service-account JSON file (the key never goes into the configuration itself).
    pub service_account_file: Option<PathBuf>,
}

impl Default for Mfa {
    fn default() -> Self {
        Self {
            challenge_ttl_seconds: 90,
            enroll_ttl_seconds: 300,
            audience: "rostdav".into(),
            attestation: MfaAttestation::Required,
            fcm: MfaFcm::default(),
        }
    }
}

impl Mfa {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (10..=300).contains(&self.challenge_ttl_seconds),
            "mfa.challenge_ttl_seconds must be between 10 and 300"
        );
        anyhow::ensure!(
            (60..=900).contains(&self.enroll_ttl_seconds),
            "mfa.enroll_ttl_seconds must be between 60 and 900"
        );
        anyhow::ensure!(
            (1..=64).contains(&self.audience.len())
                && self
                    .audience
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
            "mfa.audience must be 1 to 64 characters of A-Z a-z 0-9 . _ -"
        );
        anyhow::ensure!(
            self.fcm.project_id.is_some() == self.fcm.service_account_file.is_some(),
            "mfa.fcm needs both project_id and service_account_file, or neither"
        );
        if let Some(id) = &self.fcm.project_id {
            anyhow::ensure!(
                (1..=128).contains(&id.len())
                    && id.bytes().all(
                        |b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':')
                    ),
                "mfa.fcm.project_id must be 1 to 128 characters of A-Z a-z 0-9 . _ - :"
            );
        }
        Ok(())
    }
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
    /// Read PDF and Office files too.
    pub documents: bool,
}

impl Default for Search {
    fn default() -> Self {
        Self {
            content_indexing: true,
            max_file_mib: 64,
            max_text_kib: 1024,
            documents: true,
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
        cfg.mfa.validate()?;
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
    fn mfa_defaults_match_the_design() {
        let m = Config::default().mfa;
        assert_eq!(m.challenge_ttl_seconds, 90);
        assert_eq!(m.enroll_ttl_seconds, 300);
        assert_eq!(m.audience, "rostdav");
        assert_eq!(m.attestation, MfaAttestation::Required);
    }

    #[test]
    fn mfa_section_overrides_defaults() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "m.toml",
                "[mfa]\nchallenge_ttl_seconds = 60\nattestation = \"off\"\n",
            )?;
            let cfg = Config::load(Some(Path::new("m.toml"))).map_err(|e| e.to_string())?;
            assert_eq!(cfg.mfa.challenge_ttl_seconds, 60);
            assert_eq!(cfg.mfa.attestation, MfaAttestation::Off);
            assert_eq!(cfg.mfa.enroll_ttl_seconds, 300);
            Ok(())
        });
    }

    #[test]
    fn mfa_rejects_values_out_of_range() {
        let cases = [
            ("challenge_ttl_seconds = 9", "mfa.challenge_ttl_seconds"),
            ("challenge_ttl_seconds = 301", "mfa.challenge_ttl_seconds"),
            ("enroll_ttl_seconds = 59", "mfa.enroll_ttl_seconds"),
            ("enroll_ttl_seconds = 901", "mfa.enroll_ttl_seconds"),
            ("audience = \"\"", "mfa.audience"),
            ("audience = \"a b\"", "mfa.audience"),
            ("audience = \"a\\nb\"", "mfa.audience"),
        ];
        for (line, key) in cases {
            figment::Jail::expect_with(|jail| {
                jail.create_file("m.toml", &format!("[mfa]\n{line}\n"))?;
                let err = Config::load(Some(Path::new("m.toml"))).expect_err(line);
                assert!(err.to_string().contains(key), "{line}: {err}");
                Ok(())
            });
        }
    }

    #[test]
    fn fcm_settings_are_off_by_default_and_need_both_keys_or_none() {
        assert_eq!(Config::default().mfa.fcm, MfaFcm::default());
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "m.toml",
                "[mfa.fcm]\nproject_id = \"demo-project\"\nservice_account_file = \"/etc/rostdav/fcm.json\"\n",
            )?;
            let cfg = Config::load(Some(Path::new("m.toml"))).map_err(|e| e.to_string())?;
            assert_eq!(cfg.mfa.fcm.project_id.as_deref(), Some("demo-project"));
            assert_eq!(
                cfg.mfa.fcm.service_account_file,
                Some(PathBuf::from("/etc/rostdav/fcm.json"))
            );
            Ok(())
        });
        for line in [
            "project_id = \"demo-project\"",
            "service_account_file = \"/etc/rostdav/fcm.json\"",
            "project_id = \"bad id!\"\nservice_account_file = \"/x\"",
            "project_id = \"\"\nservice_account_file = \"/x\"",
        ] {
            figment::Jail::expect_with(|jail| {
                jail.create_file("m.toml", &format!("[mfa.fcm]\n{line}\n"))?;
                let err = Config::load(Some(Path::new("m.toml"))).expect_err(line);
                assert!(err.to_string().contains("mfa.fcm"), "{line}: {err}");
                Ok(())
            });
        }
    }

    #[test]
    fn mfa_accepts_the_range_limits() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "m.toml",
                "[mfa]\nchallenge_ttl_seconds = 10\nenroll_ttl_seconds = 900\naudience = \"a.b_c-1\"\n",
            )?;
            Config::load(Some(Path::new("m.toml"))).map_err(|e| e.to_string())?;
            Ok(())
        });
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
