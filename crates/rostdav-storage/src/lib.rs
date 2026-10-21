//! Blob-Speicher im lokalen Dateisystem.
//!
//! Layout unterhalb des Datenverzeichnisses (ADR 0002):
//!
//! ```text
//! <data>/blobs/    unveränderliche Inhalte
//! <data>/tmp/      laufende Schreibvorgänge (gleiches Dateisystem wie blobs/)
//! <data>/uploads/  Chunks laufender Chunked Uploads
//! <data>/db/       SQLite-Datenbank
//! ```
//!
//! In M0 nur Anlegen der Verzeichnisse und Schreibbarkeitsprüfung.

use std::path::{Path, PathBuf};

use rostdav_core::{Error, Result};

const SUBDIRS: [&str; 4] = ["blobs", "tmp", "uploads", "db"];

/// Lokaler Blob-Speicher.
#[derive(Clone, Debug)]
pub struct LocalStore {
    root: PathBuf,
}

impl LocalStore {
    /// Öffnet das Datenverzeichnis und legt fehlende Unterverzeichnisse an.
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        for sub in SUBDIRS {
            tokio::fs::create_dir_all(root.join(sub))
                .await
                .map_err(Error::internal)?;
        }
        #[cfg(unix)]
        restrict_permissions(&root).await?;
        tracing::info!("Datenverzeichnis geöffnet");
        Ok(Self { root })
    }

    /// Wurzel des Datenverzeichnisses.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Prüft, ob im temporären Verzeichnis geschrieben werden kann.
    pub async fn check_writable(&self) -> Result<()> {
        let probe = self.root.join("tmp").join(".ready-probe");
        tokio::fs::write(&probe, b"ok")
            .await
            .map_err(Error::internal)?;
        tokio::fs::remove_file(&probe)
            .await
            .map_err(Error::internal)?;
        Ok(())
    }
}

/// Datenverzeichnis nur für den Dienstbenutzer zugänglich machen (0700).
#[cfg(unix)]
async fn restrict_permissions(root: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    tokio::fs::set_permissions(root, perms)
        .await
        .map_err(Error::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_creates_layout_and_is_writable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalStore::open(dir.path().join("data"))
            .await
            .expect("open");
        for sub in SUBDIRS {
            assert!(store.root().join(sub).is_dir(), "{sub} fehlt");
        }
        store.check_writable().await.expect("writable");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn root_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalStore::open(dir.path().join("data"))
            .await
            .expect("open");
        let mode = std::fs::metadata(store.root())
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
