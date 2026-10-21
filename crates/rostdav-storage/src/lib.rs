//! Blob storage on the local file system.
//!
//! Layout below the data directory (ADR 0002):
//!
//! ```text
//! <data>/blobs/    immutable contents
//! <data>/tmp/      writes in progress (same file system as blobs/)
//! <data>/uploads/  chunks of chunked uploads in progress
//! <data>/db/       SQLite database
//! ```
//!
//! Blobs are immutable and addressed by a random [`BlobId`]; no part of the
//! physical path comes from user input.

use std::path::{Path, PathBuf};

use rostdav_core::{Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

mod blob;

pub use blob::{BlobId, StoredBlob};

const SUBDIRS: [&str; 4] = ["blobs", "tmp", "uploads", "db"];

/// Local blob storage.
#[derive(Clone, Debug)]
pub struct LocalStore {
    root: PathBuf,
}

impl LocalStore {
    /// Opens the data directory and creates missing subdirectories.
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        for sub in SUBDIRS {
            tokio::fs::create_dir_all(root.join(sub))
                .await
                .map_err(Error::internal)?;
        }
        #[cfg(unix)]
        restrict_permissions(&root).await?;
        tracing::info!("data directory opened");
        Ok(Self { root })
    }

    /// Root of the data directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Physical path of a blob: `blobs/<id[0..2]>/<id[2..4]>/<id>`.
    fn blob_path(&self, id: &BlobId) -> PathBuf {
        let s = id.as_str();
        self.root
            .join("blobs")
            .join(&s[0..2])
            .join(&s[2..4])
            .join(s)
    }

    /// Writes a stream as a new blob (ADR 0002, write flow steps 1-2).
    ///
    /// After returning, the blob is completely and durably on disk. If the
    /// stream exceeds `max_size`, the call aborts with [`Error::TooLarge`] and
    /// leaves nothing behind. The database may reference the blob only after
    /// that.
    pub async fn put<R>(&self, mut reader: R, max_size: u64) -> Result<StoredBlob>
    where
        R: AsyncRead + Unpin,
    {
        let id = BlobId::generate();
        let tmp = self.root.join("tmp").join(format!("{id}.part"));
        let result = self.write_blob(&mut reader, &tmp, &id, max_size).await;
        if result.is_err() {
            // Best effort; leftover .part files are cleaned up by sweep_tmp.
            let _ = tokio::fs::remove_file(&tmp).await;
        }
        result
    }

    async fn write_blob<R>(
        &self,
        reader: &mut R,
        tmp: &Path,
        id: &BlobId,
        max_size: u64,
    ) -> Result<StoredBlob>
    where
        R: AsyncRead + Unpin,
    {
        let mut file = tokio::fs::File::create(tmp)
            .await
            .map_err(Error::internal)?;
        let mut hasher = blake3::Hasher::new();
        let mut size: u64 = 0;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf).await.map_err(Error::internal)?;
            if n == 0 {
                break;
            }
            size += n as u64;
            if size > max_size {
                return Err(Error::TooLarge);
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n]).await.map_err(Error::internal)?;
        }
        file.flush().await.map_err(Error::internal)?;
        file.sync_all().await.map_err(Error::internal)?;
        drop(file);

        let dest = self.blob_path(id);
        let dir = dest
            .parent()
            .ok_or_else(|| Error::BadRequest("blob path"))?;
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(Error::internal)?;
        tokio::fs::rename(tmp, &dest)
            .await
            .map_err(Error::internal)?;
        sync_dir(dir).await?;

        Ok(StoredBlob {
            id: id.clone(),
            size,
            checksum: hasher.finalize().to_hex().to_string(),
        })
    }

    /// Opens a blob for reading.
    pub async fn open_blob(&self, id: &BlobId) -> Result<tokio::fs::File> {
        tokio::fs::File::open(self.blob_path(id))
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Error::NotFound,
                _ => Error::internal(e),
            })
    }

    /// Deletes a blob. A missing blob is not an error.
    pub async fn delete_blob(&self, id: &BlobId) -> Result<()> {
        match tokio::fs::remove_file(self.blob_path(id)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::internal(e)),
        }
    }

    /// All blobs on disk (for cleanup and `fsck`).
    ///
    /// Files with an invalid name are skipped.
    pub async fn list_blobs(&self) -> Result<Vec<BlobId>> {
        let mut ids = Vec::new();
        let mut stack = vec![self.root.join("blobs")];
        while let Some(dir) = stack.pop() {
            let mut rd = tokio::fs::read_dir(&dir).await.map_err(Error::internal)?;
            while let Some(entry) = rd.next_entry().await.map_err(Error::internal)? {
                let ty = entry.file_type().await.map_err(Error::internal)?;
                if ty.is_dir() {
                    stack.push(entry.path());
                } else if let Some(id) = entry
                    .file_name()
                    .to_str()
                    .and_then(|n| BlobId::parse(n).ok())
                {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    }

    /// Removes leftover temporary files (start after a crash).
    /// Returns the number of removed files.
    pub async fn sweep_tmp(&self) -> Result<usize> {
        let mut removed = 0;
        let mut rd = tokio::fs::read_dir(self.root.join("tmp"))
            .await
            .map_err(Error::internal)?;
        while let Some(entry) = rd.next_entry().await.map_err(Error::internal)? {
            if entry.file_name().to_string_lossy().ends_with(".part") {
                tokio::fs::remove_file(entry.path())
                    .await
                    .map_err(Error::internal)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Checks whether the temporary directory is writable.
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

/// `fsync` on a directory so the `rename` survives a crash.
async fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let d = tokio::fs::File::open(dir).await.map_err(Error::internal)?;
        d.sync_all().await.map_err(Error::internal)?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Make the data directory accessible to the service user only (0700).
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
            assert!(store.root().join(sub).is_dir(), "{sub} missing");
        }
        store.check_writable().await.expect("writable");
    }

    async fn store() -> (tempfile::TempDir, LocalStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalStore::open(dir.path().join("data"))
            .await
            .expect("open");
        (dir, store)
    }

    #[tokio::test]
    async fn put_roundtrip_with_size_and_checksum() {
        let (_d, store) = store().await;
        let blob = store.put(&b"hello world"[..], 1024).await.expect("put");
        assert_eq!(blob.size, 11);
        assert_eq!(
            blob.checksum,
            blake3::hash(b"hello world").to_hex().to_string()
        );

        let mut out = Vec::new();
        store
            .open_blob(&blob.id)
            .await
            .expect("open")
            .read_to_end(&mut out)
            .await
            .expect("read");
        assert_eq!(out, b"hello world");
        assert_eq!(
            store.list_blobs().await.expect("list"),
            vec![blob.id.clone()]
        );
        assert_eq!(store.sweep_tmp().await.expect("sweep"), 0);
    }

    #[tokio::test]
    async fn blob_path_is_sharded_and_id_derived() {
        let (_d, store) = store().await;
        let blob = store.put(&b"x"[..], 10).await.expect("put");
        let s = blob.id.as_str();
        let expected = store
            .root()
            .join("blobs")
            .join(&s[0..2])
            .join(&s[2..4])
            .join(s);
        assert!(expected.is_file());
    }

    #[tokio::test]
    async fn empty_blob_is_allowed() {
        let (_d, store) = store().await;
        let blob = store.put(&b""[..], 10).await.expect("put");
        assert_eq!(blob.size, 0);
    }

    #[tokio::test]
    async fn too_large_leaves_nothing_behind() {
        let (_d, store) = store().await;
        let err = store.put(&[0u8; 100][..], 99).await.expect_err("too large");
        assert!(matches!(err, Error::TooLarge));
        assert!(store.list_blobs().await.expect("list").is_empty());
        let tmp_entries = std::fs::read_dir(store.root().join("tmp"))
            .expect("dir")
            .count();
        assert_eq!(tmp_entries, 0);
    }

    #[tokio::test]
    async fn exactly_max_size_is_allowed() {
        let (_d, store) = store().await;
        store.put(&[0u8; 99][..], 99).await.expect("put");
    }

    /// Reader that fails with an error after a few bytes (connection drop).
    struct Failing(bool);
    impl AsyncRead for Failing {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.0 {
                return std::task::Poll::Ready(Err(std::io::Error::other("aborted")));
            }
            self.0 = true;
            buf.put_slice(b"part");
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn aborted_stream_leaves_no_blob() {
        let (_d, store) = store().await;
        assert!(store.put(Failing(false), 1024).await.is_err());
        assert!(store.list_blobs().await.expect("list").is_empty());
        assert_eq!(store.sweep_tmp().await.expect("sweep"), 0);
    }

    #[tokio::test]
    async fn crash_before_rename_leaves_only_sweepable_tmp() {
        let (_d, store) = store().await;
        // Crash in the middle of writing: only a .part file, no blob.
        let stale = store
            .root()
            .join("tmp")
            .join("01ARZ3NDEKTSV4RRFFQ69G5FAV.part");
        std::fs::write(&stale, b"half").expect("write");
        assert!(store.list_blobs().await.expect("list").is_empty());
        assert_eq!(store.sweep_tmp().await.expect("sweep"), 1);
        assert!(!stale.exists());
    }

    #[tokio::test]
    async fn delete_is_idempotent_and_open_missing_is_not_found() {
        let (_d, store) = store().await;
        let blob = store.put(&b"x"[..], 10).await.expect("put");
        store.delete_blob(&blob.id).await.expect("delete");
        store.delete_blob(&blob.id).await.expect("delete again");
        assert!(matches!(
            store.open_blob(&blob.id).await,
            Err(Error::NotFound)
        ));
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
