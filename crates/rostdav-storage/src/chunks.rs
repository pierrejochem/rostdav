//! Chunked upload sessions on disk.
//!
//! Layout: `<data>/uploads/<session dir>/<chunk name>`. The session directory
//! is a server-generated ULID; chunk names are restricted to
//! `[A-Za-z0-9_-]{1,32}`, so no client input can form a path (ADR 0002).

use std::cmp::Ordering;
use std::path::PathBuf;

use rostdav_core::{Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::{BlobId, LocalStore, StoredBlob, sync_dir};

/// Maximum number of chunks in one session.
pub const MAX_CHUNKS: usize = 5000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkName(String);

impl ChunkName {
    pub fn parse(s: &str) -> Result<Self> {
        let ok = (1..=32).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(Error::BadRequest("invalid chunk name"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkInfo {
    pub name: String,
    pub size: u64,
    /// Unix seconds.
    pub mtime: i64,
}

/// Digit runs compare by value, everything else bytewise: `2` < `10`, `00001` < `00003` < `abc`.
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    loop {
        match (a.first(), b.first()) {
            (None, None) => return Ordering::Equal,
            (None, _) => return Ordering::Less,
            (_, None) => return Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let da = a.iter().take_while(|c| c.is_ascii_digit()).count();
                let db = b.iter().take_while(|c| c.is_ascii_digit()).count();
                let (na, nb) = (trim_zeros(&a[..da]), trim_zeros(&b[..db]));
                let ord = na.len().cmp(&nb.len()).then_with(|| na.cmp(nb));
                if ord != Ordering::Equal {
                    return ord;
                }
                a = &a[da..];
                b = &b[db..];
            }
            (Some(x), Some(y)) => {
                if x != y {
                    return x.cmp(y);
                }
                a = &a[1..];
                b = &b[1..];
            }
        }
    }
}

fn trim_zeros(d: &[u8]) -> &[u8] {
    let n = d.iter().take_while(|c| **c == b'0').count();
    &d[n.min(d.len().saturating_sub(1))..]
}

impl LocalStore {
    fn session_path(&self, dir: &BlobId) -> PathBuf {
        self.root().join("uploads").join(dir.as_str())
    }

    pub async fn create_session(&self, dir: &BlobId) -> Result<()> {
        tokio::fs::create_dir(self.session_path(dir))
            .await
            .map_err(Error::internal)
    }

    /// Stores one chunk atomically; returns `true` if it replaced an earlier chunk.
    pub async fn put_chunk<R>(
        &self,
        dir: &BlobId,
        name: &ChunkName,
        mut reader: R,
        max_size: u64,
    ) -> Result<bool>
    where
        R: AsyncRead + Unpin,
    {
        let base = self.session_path(dir);
        let dest = base.join(name.as_str());
        let existed = tokio::fs::try_exists(&dest)
            .await
            .map_err(Error::internal)?;
        if !existed && self.list_chunks(dir).await?.len() >= MAX_CHUNKS {
            return Err(Error::Conflict("too many chunks"));
        }

        let tmp = self
            .root()
            .join("tmp")
            .join(format!("{}.part", BlobId::generate()));
        let result = async {
            let mut file = tokio::fs::File::create(&tmp)
                .await
                .map_err(Error::internal)?;
            let mut size = 0u64;
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
                file.write_all(&buf[..n]).await.map_err(Error::internal)?;
            }
            file.flush().await.map_err(Error::internal)?;
            file.sync_all().await.map_err(Error::internal)?;
            drop(file);
            tokio::fs::rename(&tmp, &dest)
                .await
                .map_err(Error::internal)?;
            sync_dir(&base).await
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&tmp).await;
        }
        result.map(|()| existed)
    }

    /// Chunks in natural order.
    pub async fn list_chunks(&self, dir: &BlobId) -> Result<Vec<ChunkInfo>> {
        let mut rd = tokio::fs::read_dir(self.session_path(dir))
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Error::NotFound,
                _ => Error::internal(e),
            })?;
        let mut out = Vec::new();
        while let Some(entry) = rd.next_entry().await.map_err(Error::internal)? {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if ChunkName::parse(&name).is_err() {
                continue;
            }
            let meta = entry.metadata().await.map_err(Error::internal)?;
            if !meta.is_file() {
                continue;
            }
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
            out.push(ChunkInfo {
                name,
                size: meta.len(),
                mtime,
            });
        }
        out.sort_by(|a, b| natural_cmp(&a.name, &b.name));
        Ok(out)
    }

    /// Concatenates all chunks (natural order) into one new blob.
    /// The session stays untouched; the caller removes it after the commit.
    pub async fn assemble(&self, dir: &BlobId, max_size: u64) -> Result<StoredBlob> {
        let chunks = self.list_chunks(dir).await?;
        let id = BlobId::generate();
        let tmp = self.root().join("tmp").join(format!("{id}.part"));
        let result = async {
            let mut out = tokio::fs::File::create(&tmp)
                .await
                .map_err(Error::internal)?;
            let mut hasher = blake3::Hasher::new();
            let mut size = 0u64;
            let mut buf = vec![0u8; 256 * 1024];
            for c in &chunks {
                let mut f = tokio::fs::File::open(self.session_path(dir).join(&c.name))
                    .await
                    .map_err(Error::internal)?;
                loop {
                    let n = f.read(&mut buf).await.map_err(Error::internal)?;
                    if n == 0 {
                        break;
                    }
                    size += n as u64;
                    if size > max_size {
                        return Err(Error::TooLarge);
                    }
                    hasher.update(&buf[..n]);
                    out.write_all(&buf[..n]).await.map_err(Error::internal)?;
                }
            }
            self.finish_blob(out, &tmp, &id, hasher, size).await
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&tmp).await;
        }
        result
    }

    /// Deletes a session directory with all chunks. A missing one is fine.
    pub async fn remove_session(&self, dir: &BlobId) -> Result<()> {
        match tokio::fs::remove_dir_all(self.session_path(dir)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::internal(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> (tempfile::TempDir, LocalStore, BlobId) {
        let d = tempfile::tempdir().expect("tempdir");
        let s = LocalStore::open(d.path().join("data")).await.expect("open");
        let id = BlobId::generate();
        s.create_session(&id).await.expect("session");
        (d, s, id)
    }

    #[test]
    fn natural_order() {
        let mut v = vec!["10", "2", "00003", "abc", "1", "b", "a2", "a10"];
        v.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(v, ["1", "2", "00003", "10", "a2", "a10", "abc", "b"]);
        assert_eq!(natural_cmp("00001", "1"), Ordering::Equal);
        assert_eq!(natural_cmp("0", "00"), Ordering::Equal);
    }

    #[test]
    fn chunk_names_cannot_form_paths() {
        for ok in ["1", "00001", "a-b_c", &"x".repeat(32)] {
            assert!(ChunkName::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            ".",
            "..",
            ".file",
            "a/b",
            "a\\b",
            "a b",
            "a\0",
            &"x".repeat(33),
            "é",
        ] {
            assert!(ChunkName::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn put_list_assemble_in_natural_order() {
        let (_d, s, id) = store().await;
        let n = |x: &str| ChunkName::parse(x).expect("name");
        assert!(
            !s.put_chunk(&id, &n("10"), &b"CC"[..], 100)
                .await
                .expect("10")
        );
        assert!(!s.put_chunk(&id, &n("2"), &b"BB"[..], 100).await.expect("2"));
        assert!(!s.put_chunk(&id, &n("1"), &b"AA"[..], 100).await.expect("1"));
        assert!(
            s.put_chunk(&id, &n("1"), &b"aa"[..], 100)
                .await
                .expect("again"),
            "replace"
        );
        let names: Vec<_> = s
            .list_chunks(&id)
            .await
            .expect("l")
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert_eq!(names, ["1", "2", "10"]);

        let blob = s.assemble(&id, 100).await.expect("assemble");
        assert_eq!(blob.size, 6);
        let mut out = String::new();
        s.open_blob(&blob.id)
            .await
            .expect("o")
            .read_to_string(&mut out)
            .await
            .expect("r");
        assert_eq!(out, "aaBBCC");
        assert_eq!(blob.checksum, blake3::hash(b"aaBBCC").to_hex().to_string());

        s.remove_session(&id).await.expect("rm");
        s.remove_session(&id).await.expect("rm again");
        assert!(matches!(s.list_chunks(&id).await, Err(Error::NotFound)));
    }

    #[tokio::test]
    async fn limits_leave_nothing_behind() {
        let (_d, s, id) = store().await;
        let n = ChunkName::parse("1").expect("n");
        assert!(matches!(
            s.put_chunk(&id, &n, &[0u8; 10][..], 9).await,
            Err(Error::TooLarge)
        ));
        assert!(s.list_chunks(&id).await.expect("l").is_empty());
        s.put_chunk(&id, &n, &[0u8; 10][..], 10).await.expect("ok");
        assert!(matches!(s.assemble(&id, 9).await, Err(Error::TooLarge)));
        assert!(s.list_blobs().await.expect("b").is_empty());
        assert_eq!(s.sweep_tmp().await.expect("sweep"), 0, "no tmp file left");
    }
}
