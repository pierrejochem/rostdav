//! Konfiguration.
//!
//! Vorrang (höchster zuerst): Umgebungsvariablen `ROSTDAV_<ABSCHNITT>__<SCHLÜSSEL>`,
//! Konfigurationsdatei (`rostdav.toml`), eingebaute Defaults. Später kommen
//! Kommandozeile (oben) und Datenbank-Einstellungen aus der Oberfläche (unten) hinzu.

use std::net::SocketAddr;
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
    pub log: Log,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    /// Adresse, auf der Rostdav HTTP spricht. TLS übernimmt der Reverse Proxy.
    pub listen: SocketAddr,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Storage {
    /// Datenverzeichnis mit `blobs/`, `tmp/`, `uploads/` und `db/`.
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
    /// Datenbank-URL; ohne Angabe SQLite unter `<data_dir>/db/rostdav.sqlite`.
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
    /// Filter im Format von `tracing_subscriber::EnvFilter`, z. B. `info,rostdav=debug`.
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
    /// Lädt die Konfiguration. Eine ausdrücklich angegebene Datei muss existieren;
    /// die Standarddatei `rostdav.toml` ist optional.
    pub fn load(explicit_file: Option<&Path>) -> anyhow::Result<Self> {
        let mut figment = Figment::from(Serialized::defaults(Config::default()));
        match explicit_file {
            Some(path) => {
                anyhow::ensure!(
                    path.is_file(),
                    "Konfigurationsdatei nicht gefunden: {}",
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
// figment::Jail erzwingt figment::Error als Fehlertyp der Test-Closures.
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
            assert!(Config::load(Some(Path::new("fehlt.toml"))).is_err());
            Ok(())
        });
    }
}
