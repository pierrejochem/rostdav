//! File service: the only code that coordinates database and blob store.
//!
//! Paths are relative to the principal's root. Resolution always starts at
//! that root, and `authorize()` runs on every resolved node as a second line
//! of defense.

use rostdav_core::{Error, LogicalPath, Name, Result};
use rostdav_meta::{NewBlob, Node, NodeKind, WriteCondition, Written};
use rostdav_storage::BlobId;
use tokio::io::AsyncRead;

use crate::AppState;
use crate::auth::{Action, Principal, authorize};

/// What a client may attach to an upload.
#[derive(Clone, Debug, Default)]
pub struct PutOptions {
    /// `X-OC-MTime`
    pub mtime: Option<i64>,
    /// `OC-Checksum`, stored verbatim (see [`normalize_checksum`]).
    pub client_checksum: Option<String>,
    pub cond: Option<WriteCondition>,
}

/// Accepts `ALGO:hexdigest` and returns it unchanged; anything else is ignored.
pub fn normalize_checksum(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let (algo, digest) = raw.split_once(':')?;
    let ok = (1..=16).contains(&algo.len())
        && algo.bytes().all(|b| b.is_ascii_alphanumeric())
        && (1..=128).contains(&digest.len())
        && digest.bytes().all(|b| b.is_ascii_hexdigit());
    ok.then(|| raw.to_owned())
}

/// Extensions clients must not create (reference: `files.forbidden_filename_extensions`,
/// `tests/fixtures/nextcloud/08-m5-probes/16-put-name-part`).
pub const FORBIDDEN_EXTENSIONS: [&str; 2] = [".filepart", ".part"];

/// Policy for names of newly created files and folders.
pub fn check_new_name(name: &Name) -> Result<()> {
    let lower = name.as_str().to_lowercase();
    for ext in FORBIDDEN_EXTENSIONS {
        if lower.ends_with(ext) {
            return Err(Error::Invalid(format!(
                "\"{ext}\" is a forbidden file type."
            )));
        }
    }
    Ok(())
}

/// A directory with its children.
#[derive(Debug)]
pub struct Listing {
    pub node: Node,
    pub children: Vec<Node>,
}

impl AppState {
    async fn resolve_authorized(
        &self,
        p: &Principal,
        path: &LogicalPath,
        action: Action,
    ) -> Result<Node> {
        let node = self
            .inner
            .db
            .resolve(p.user_id, path)
            .await?
            .ok_or(Error::NotFound)?;
        authorize(p, &node, action)?;
        Ok(node)
    }

    /// Splits a path into its (existing, authorized, directory) parent and the final name.
    pub(crate) async fn parent_of<'a>(
        &self,
        p: &Principal,
        path: &'a LogicalPath,
    ) -> Result<(Node, &'a Name)> {
        let (parent_path, name) = path
            .split_last()
            .ok_or(Error::Conflict("the root cannot be addressed this way"))?;
        let parent = match self
            .resolve_authorized(p, &parent_path, Action::Write)
            .await
        {
            Err(Error::NotFound) => return Err(Error::Conflict("parent does not exist")),
            other => other?,
        };
        check_new_name(name)?;
        Ok((parent, name))
    }

    pub async fn stat(&self, p: &Principal, path: &LogicalPath) -> Result<Node> {
        self.resolve_authorized(p, path, Action::Read).await
    }

    pub async fn list(&self, p: &Principal, path: &LogicalPath) -> Result<Listing> {
        let node = self.resolve_authorized(p, path, Action::Read).await?;
        if node.kind != NodeKind::Dir {
            return Err(Error::BadRequest("not a directory"));
        }
        let children = self.inner.db.children(node.id).await?;
        Ok(Listing { node, children })
    }

    /// Total size of a node (for directories: all files below).
    pub async fn size_of(&self, p: &Principal, node: &Node) -> Result<i64> {
        authorize(p, node, Action::Read)?;
        match node.kind {
            NodeKind::File => Ok(node.size),
            NodeKind::Dir => self.inner.db.subtree_size(node.id).await,
        }
    }

    /// Opens a file for reading.
    pub async fn read(&self, p: &Principal, path: &LogicalPath) -> Result<(Node, tokio::fs::File)> {
        let node = self.resolve_authorized(p, path, Action::Read).await?;
        let blob = node
            .blob_id
            .as_deref()
            .ok_or(Error::BadRequest("not a file"))?;
        let file = self.inner.store.open_blob(&BlobId::parse(blob)?).await?;
        Ok((node, file))
    }

    pub async fn mkcol(&self, p: &Principal, path: &LogicalPath) -> Result<Node> {
        let (parent, name) = self.parent_of(p, path).await?;
        self.inner.db.create_dir(parent.id, name).await
    }

    /// Streams `body` into a new blob and commits it as `path`.
    pub async fn put<R>(
        &self,
        p: &Principal,
        path: &LogicalPath,
        body: R,
        mtime: Option<i64>,
        cond: &WriteCondition,
    ) -> Result<Written>
    where
        R: AsyncRead + Unpin,
    {
        let opts = PutOptions {
            mtime,
            client_checksum: None,
            cond: Some(cond.clone()),
        };
        self.put_ext(p, path, body, &opts).await
    }

    /// [`put`](Self::put) with mtime, client checksum and precondition.
    ///
    /// A missing parent is [`Error::NotFound`] (the reference answers 404 for PUT).
    pub async fn put_ext<R>(
        &self,
        p: &Principal,
        path: &LogicalPath,
        body: R,
        opts: &PutOptions,
    ) -> Result<Written>
    where
        R: AsyncRead + Unpin,
    {
        let cond = opts.cond.clone().unwrap_or(WriteCondition::None);
        let (parent, name) = match self.parent_of(p, path).await {
            Err(Error::Conflict("parent does not exist")) => return Err(Error::NotFound),
            other => other?,
        };

        // Limit the stream by the upload limit and the remaining quota
        // (a replaced file's old size is freed by the commit).
        let existing = self.inner.db.resolve(p.user_id, path).await?;
        let freed = existing.map_or(0, |n| n.size.max(0)).unsigned_abs();
        let headroom = self.inner.db.quota_headroom(p.user_id).await?;
        let quota_limit = headroom.map(|h| h.unsigned_abs().saturating_add(freed));
        let max = quota_limit.map_or(self.inner.config.limits.max_upload_bytes, |q| {
            q.min(self.inner.config.limits.max_upload_bytes)
        });

        let stored = match self.inner.store.put(body, max).await {
            Err(Error::TooLarge)
                if quota_limit.is_some_and(|q| q < self.inner.config.limits.max_upload_bytes) =>
            {
                return Err(Error::QuotaExceeded);
            }
            other => other?,
        };

        let blob = NewBlob {
            id: stored.id.to_string(),
            size: i64::try_from(stored.size).map_err(|_| Error::TooLarge)?,
            checksum: stored.checksum.clone(),
        };
        match self
            .inner
            .db
            .commit_file_ext(
                parent.id,
                name,
                &blob,
                opts.mtime,
                opts.client_checksum.as_deref(),
                &cond,
            )
            .await
        {
            Ok(w) => Ok(w),
            Err(e) => {
                // The blob was never referenced; remove it right away.
                if let Err(cleanup) = self.inner.store.delete_blob(&stored.id).await {
                    tracing::warn!(error = %cleanup, "could not remove unreferenced blob");
                }
                Err(e)
            }
        }
    }

    pub async fn delete(
        &self,
        p: &Principal,
        path: &LogicalPath,
        if_match: Option<&str>,
    ) -> Result<()> {
        let node = self.resolve_authorized(p, path, Action::Write).await?;
        self.inner.db.delete_node(node.id, if_match).await
    }

    pub async fn move_to(
        &self,
        p: &Principal,
        from: &LogicalPath,
        to: &LogicalPath,
        overwrite: bool,
    ) -> Result<Written> {
        let src = self.resolve_authorized(p, from, Action::Write).await?;
        let (parent, name) = self.parent_of(p, to).await?;
        self.inner
            .db
            .move_node(src.id, parent.id, name, overwrite)
            .await
    }

    pub async fn copy_to(
        &self,
        p: &Principal,
        from: &LogicalPath,
        to: &LogicalPath,
        overwrite: bool,
    ) -> Result<Written> {
        let src = self.resolve_authorized(p, from, Action::Read).await?;
        let (parent, name) = self.parent_of(p, to).await?;
        self.inner
            .db
            .copy_node(src.id, parent.id, name, overwrite)
            .await
    }

    /// Removes blobs that no node references any more. Returns how many.
    ///
    /// Blob files that are on disk but not yet registered (an upload between
    /// steps 2 and 3 of the write flow) are never touched: only registered,
    /// unreferenced blobs are deleted.
    pub async fn collect_garbage(&self) -> Result<usize> {
        let ids = self.inner.db.delete_unreferenced_blobs().await?;
        for id in &ids {
            self.inner.store.delete_blob(&BlobId::parse(id)?).await?;
        }
        let expired = self
            .expire_uploads(crate::uploads::SESSION_MAX_AGE_SECS)
            .await?;
        Ok(ids.len() + expired)
    }
}
