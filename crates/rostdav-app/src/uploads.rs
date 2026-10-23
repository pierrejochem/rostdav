//! Chunked upload v2: sessions, chunks, assembly.
//!
//! The transfer ID chosen by the client only keys a database row; chunks live
//! in a server-named directory (`rostdav-storage`).

use rostdav_core::{Error, LogicalPath, Result};
use rostdav_meta::{NewBlob, UploadSession, WriteCondition, Written};
use rostdav_storage::{BlobId, ChunkInfo, ChunkName};
use tokio::io::AsyncRead;

use crate::AppState;
use crate::access::{Need, authorize_access};
use crate::auth::Principal;

fn valid_transfer_id(id: &str) -> Result<()> {
    let ok = (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && id != "."
        && id != "..";
    if ok {
        Ok(())
    } else {
        Err(Error::BadRequest("invalid transfer id"))
    }
}

/// A session with its chunks.
#[derive(Debug)]
pub struct UploadListing {
    pub session: UploadSession,
    pub chunks: Vec<ChunkInfo>,
}

impl UploadListing {
    pub fn total(&self) -> u64 {
        self.chunks.iter().map(|c| c.size).sum()
    }
}

impl AppState {
    async fn session(&self, p: &Principal, transfer_id: &str) -> Result<UploadSession> {
        Self::require_full(p)?;
        valid_transfer_id(transfer_id).map_err(|_| Error::NotFound)?;
        self.inner
            .db
            .find_upload_session(p.user_id, transfer_id)
            .await?
            .ok_or(Error::NotFound)
    }

    pub async fn upload_create(&self, p: &Principal, transfer_id: &str) -> Result<()> {
        Self::require_full(p)?;
        valid_transfer_id(transfer_id)?;
        let dir = BlobId::generate();
        self.inner.store.create_session(&dir).await?;
        if let Err(e) = self
            .inner
            .db
            .create_upload_session(p.user_id, transfer_id, dir.as_str())
            .await
        {
            self.inner.store.remove_session(&dir).await?;
            return Err(e);
        }
        Ok(())
    }

    /// Stores a chunk; `true` if it replaced an earlier one.
    pub async fn upload_chunk<R>(
        &self,
        p: &Principal,
        transfer_id: &str,
        chunk: &str,
        body: R,
    ) -> Result<bool>
    where
        R: AsyncRead + Unpin,
    {
        let s = self.session(p, transfer_id).await?;
        let name = ChunkName::parse(chunk)?;
        let dir = BlobId::parse(&s.dir)?;
        let existing = self.inner.store.list_chunks(&dir).await?;
        let others: u64 = existing
            .iter()
            .filter(|c| c.name != name.as_str())
            .map(|c| c.size)
            .sum();

        // The whole upload may not exceed the upload limit or the remaining quota.
        let limits = self.cfg().limits;
        let mut room = limits.max_upload_bytes.saturating_sub(others);
        let mut quota_bound = false;
        if let Some(h) = self.inner.db.quota_headroom(p.user_id).await? {
            let q = h.unsigned_abs().saturating_sub(others);
            if q < room {
                room = q;
                quota_bound = true;
            }
        }
        let max = room.min(limits.max_chunk_bytes);
        match self.inner.store.put_chunk(&dir, &name, body, max).await {
            Err(Error::TooLarge) if quota_bound && room <= limits.max_chunk_bytes => {
                Err(Error::QuotaExceeded)
            }
            other => other,
        }
    }

    pub async fn upload_list(&self, p: &Principal, transfer_id: &str) -> Result<UploadListing> {
        let session = self.session(p, transfer_id).await?;
        let chunks = self
            .inner
            .store
            .list_chunks(&BlobId::parse(&session.dir)?)
            .await?;
        Ok(UploadListing { session, chunks })
    }

    /// Concatenates the chunks into `dest` (`MOVE …/.file`).
    ///
    /// `total_length` (`OC-Total-Length`), if given, must equal the sum of the
    /// chunks. On any error the session is kept so the client can retry.
    pub async fn upload_assemble(
        &self,
        p: &Principal,
        transfer_id: &str,
        dest: &LogicalPath,
        overwrite: bool,
        total_length: Option<u64>,
        mtime: Option<i64>,
    ) -> Result<Written> {
        let s = self.session(p, transfer_id).await?;
        let dir = BlobId::parse(&s.dir)?;
        let sum: u64 = self
            .inner
            .store
            .list_chunks(&dir)
            .await?
            .iter()
            .map(|c| c.size)
            .sum();
        if let Some(t) = total_length {
            if t != sum {
                return Err(Error::Invalid(format!(
                    "Chunks on server do not sum up to {t} but to {sum} bytes"
                )));
            }
        }

        let (parent, name) = match self.parent_access(p, dest, None).await {
            Err(Error::Conflict(_)) => {
                return Err(Error::Conflict("The destination node is not found"));
            }
            other => other?,
        };
        let existing = match self.resolve_access(p, dest).await {
            Ok(a) => Some(a),
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        match &existing {
            Some(a) if a.is_dir() || a.mount_root => {
                return Err(Error::Conflict("target is a directory"));
            }
            Some(_) if !overwrite => return Err(Error::PreconditionFailed),
            Some(a) => authorize_access(p, a, Need::Update)?,
            None => authorize_access(p, &parent, Need::Create)?,
        }
        if sum > self.cfg().limits.max_upload_bytes {
            return Err(Error::TooLarge);
        }
        let freed = if self.cfg().versioning.enabled {
            0
        } else {
            existing
                .as_ref()
                .map_or(0, |a| a.node.size.max(0))
                .unsigned_abs()
        };
        if let Some(h) = self.inner.db.quota_headroom(parent.node.owner_id).await? {
            if sum > h.unsigned_abs().saturating_add(freed) {
                return Err(Error::QuotaExceeded);
            }
        }

        let stored = self
            .inner
            .store
            .assemble(&dir, self.cfg().limits.max_upload_bytes)
            .await?;
        let blob = NewBlob {
            id: stored.id.to_string(),
            size: i64::try_from(stored.size).map_err(|_| Error::TooLarge)?,
            checksum: stored.checksum.clone(),
        };
        let cond = if overwrite {
            WriteCondition::None
        } else {
            WriteCondition::MustNotExist
        };
        match self
            .inner
            .db
            .commit_file_with(
                parent.node.id,
                name,
                &blob,
                &self.commit_opts(p, mtime, None),
                &cond,
            )
            .await
        {
            Ok(w) => {
                self.inner.db.delete_upload_session(s.id).await?;
                self.inner.store.remove_session(&dir).await?;
                Ok(w)
            }
            Err(e) => {
                if let Err(c) = self.inner.store.delete_blob(&stored.id).await {
                    tracing::warn!(error = %c, "could not remove unreferenced blob");
                }
                Err(e)
            }
        }
    }

    pub async fn upload_delete(&self, p: &Principal, transfer_id: &str) -> Result<()> {
        let s = self.session(p, transfer_id).await?;
        self.inner.db.delete_upload_session(s.id).await?;
        self.inner
            .store
            .remove_session(&BlobId::parse(&s.dir)?)
            .await
    }

    /// Removes sessions older than `max_age_secs`; returns how many.
    pub async fn expire_uploads(&self, max_age_secs: i64) -> Result<usize> {
        let cutoff = crate::now_secs() - max_age_secs;
        let old = self.inner.db.upload_sessions_older_than(cutoff).await?;
        for s in &old {
            self.inner.db.delete_upload_session(s.id).await?;
            self.inner
                .store
                .remove_session(&BlobId::parse(&s.dir)?)
                .await?;
        }
        Ok(old.len())
    }
}
