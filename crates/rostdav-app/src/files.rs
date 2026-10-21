//! File service: the only code that coordinates database and blob store.
//!
//! Paths are relative to the principal's root. Resolution always starts at
//! that root, and `authorize()` runs on every resolved node as a second line
//! of defense.

use std::collections::HashMap;

use rostdav_core::{Error, LogicalPath, Name, Result};
use rostdav_meta::{NewBlob, Node, NodeKind, WriteCondition, Written};
use rostdav_storage::BlobId;
use tokio::io::AsyncRead;

use crate::AppState;
use crate::access::{Access, MountView, Need, Origin, authorize_access, split_target};
use crate::auth::Principal;

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
    pub access: Access,
    /// The directory itself.
    pub node: Node,
    pub children: Vec<Node>,
    /// Shares mounted here (only in a user's own root).
    pub mounts: Vec<MountView>,
    /// Names of the owners of everything listed, by user ID.
    pub owners: HashMap<i64, String>,
}

impl Listing {
    /// The caller's rights on a listed child (children inherit the directory's).
    pub fn child_access(&self, child: Node) -> Access {
        Access {
            node: child,
            holder: self.access.holder,
            perms: self.access.perms,
            origin: self.access.origin,
            mount_root: false,
        }
    }

    /// The caller's rights on a mounted share.
    pub fn mount_access(&self, m: &MountView) -> Access {
        Access {
            node: m.node.clone(),
            holder: self.access.holder,
            perms: m.share.permissions,
            origin: Origin::Share(m.share.id),
            mount_root: true,
        }
    }
}

impl AppState {
    async fn access_for(&self, p: &Principal, path: &LogicalPath, need: Need) -> Result<Access> {
        let a = self.resolve_access(p, path).await?;
        authorize_access(p, &a, need)?;
        Ok(a)
    }

    /// The parent directory of a path to create something in, checked for `need`,
    /// and the new name. A missing parent is a conflict (409), as in WebDAV.
    pub(crate) async fn parent_access<'a>(
        &self,
        p: &Principal,
        path: &'a LogicalPath,
        need: Option<Need>,
    ) -> Result<(Access, &'a Name)> {
        let (parent_path, name) = split_target(path)?;
        let parent = match self.resolve_access(p, &parent_path).await {
            Err(Error::NotFound) => return Err(Error::Conflict("parent does not exist")),
            other => other?,
        };
        if !parent.is_dir() {
            return Err(Error::Conflict("parent is not a directory"));
        }
        check_new_name(name)?;
        if let Some(need) = need {
            authorize_access(p, &parent, need)?;
        }
        Ok((parent, name))
    }

    pub async fn stat(&self, p: &Principal, path: &LogicalPath) -> Result<Node> {
        Ok(self.stat_access(p, path).await?.node)
    }

    /// The node with the caller's rights on it.
    pub async fn stat_access(&self, p: &Principal, path: &LogicalPath) -> Result<Access> {
        self.access_for(p, path, Need::Read).await
    }

    pub async fn list(&self, p: &Principal, path: &LogicalPath) -> Result<Listing> {
        let access = self.access_for(p, path, Need::Read).await?;
        if !access.is_dir() {
            return Err(Error::BadRequest("not a directory"));
        }
        let children = self.inner.db.children(access.node.id).await?;
        let mounts = if access.origin == Origin::Own && access.node.parent_id.is_none() {
            self.mounts_of(p).await?
        } else {
            Vec::new()
        };
        let mut ids: Vec<i64> = children.iter().map(|c| c.owner_id).collect();
        ids.extend(mounts.iter().map(|m| m.node.owner_id));
        ids.push(access.node.owner_id);
        ids.sort_unstable();
        ids.dedup();
        let owners = self.inner.db.user_names(&ids).await?;
        Ok(Listing {
            node: access.node.clone(),
            access,
            children,
            mounts,
            owners,
        })
    }

    /// Total size of a node (for directories: all files below).
    pub async fn size_of(&self, p: &Principal, access: &Access) -> Result<i64> {
        authorize_access(p, access, Need::Read)?;
        match access.node.kind {
            NodeKind::File => Ok(access.node.size),
            NodeKind::Dir => self.inner.db.subtree_size(access.node.id).await,
        }
    }

    /// Opens a file for reading.
    pub async fn read(&self, p: &Principal, path: &LogicalPath) -> Result<(Node, tokio::fs::File)> {
        let a = self.access_for(p, path, Need::Read).await?;
        let blob = a
            .node
            .blob_id
            .as_deref()
            .ok_or(Error::BadRequest("not a file"))?;
        let file = self.inner.store.open_blob(&BlobId::parse(blob)?).await?;
        Ok((a.node, file))
    }

    pub async fn mkcol(&self, p: &Principal, path: &LogicalPath) -> Result<Node> {
        let (parent, name) = self.parent_access(p, path, Some(Need::Create)).await?;
        self.inner.db.create_dir(parent.node.id, name).await
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
    /// Creating needs the create right on the directory, replacing needs the
    /// update right on the file. A missing parent is [`Error::NotFound`] (the
    /// reference answers 404 for PUT). Space is taken from the node owner's quota.
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
        // visible parent first (404/409), then the rights that depend on whether the file exists
        let (parent, name) = match self.parent_access(p, path, None).await {
            Err(Error::Conflict("parent does not exist")) => return Err(Error::NotFound),
            other => other?,
        };
        let existing = match self.resolve_access(p, path).await {
            Ok(a) => Some(a),
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        match &existing {
            Some(a) if a.mount_root && matches!(a.origin, Origin::Share(_)) => {
                return Err(Error::AlreadyExists);
            }
            Some(a) if a.is_dir() => return Err(Error::Conflict("target is a directory")),
            Some(a) => authorize_access(p, a, Need::Update)?,
            None => authorize_access(p, &parent, Need::Create)?,
        }

        // Limit the stream by the upload limit and the owner's remaining quota
        // (a replaced file's old size is freed by the commit).
        let owner = parent.node.owner_id;
        // A replaced file's old content stays as a version and keeps counting.
        let freed = if self.inner.config.versioning.enabled {
            0
        } else {
            existing
                .as_ref()
                .map_or(0, |a| a.node.size.max(0))
                .unsigned_abs()
        };
        let headroom = self.inner.db.quota_headroom(owner).await?;
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
            .commit_file_with(
                parent.node.id,
                name,
                &blob,
                &self.commit_opts(p, opts.mtime, opts.client_checksum.clone()),
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

    /// Deletes a node. Deleting a mount point leaves the share (for the
    /// recipient this ends the share, as in the reference).
    pub async fn delete(
        &self,
        p: &Principal,
        path: &LogicalPath,
        if_match: Option<&str>,
    ) -> Result<()> {
        let a = self.resolve_access(p, path).await?;
        if a.mount_root {
            return match a.origin {
                Origin::Share(id) => {
                    self.inner.db.delete_share(id).await?;
                    self.audit(
                        &p.name,
                        "share.revoked",
                        &a.node.name,
                        None,
                        serde_json::json!({"by": "recipient"}),
                    )
                    .await;
                    Ok(())
                }
                _ => Err(Error::Forbidden),
            };
        }
        authorize_access(p, &a, Need::Delete)?;
        self.inner.db.delete_node(a.node.id, if_match).await
    }

    /// Moves or renames. Within one tree or one share only (ADR 0004); renaming
    /// a mount point renames it for the recipient.
    pub async fn move_to(
        &self,
        p: &Principal,
        from: &LogicalPath,
        to: &LogicalPath,
        overwrite: bool,
    ) -> Result<Written> {
        let src = self.resolve_access(p, from).await?;
        if src.mount_root {
            return self.rename_mount(p, &src, to).await;
        }
        authorize_access(p, &src, Need::Delete)?;
        let (parent, name) = self.parent_access(p, to, Some(Need::Create)).await?;
        if !src.same_domain(&parent) {
            return Err(Error::Conflict(
                "cannot move between different shares or accounts",
            ));
        }
        self.authorize_overwrite(p, to, overwrite).await?;
        self.inner
            .db
            .move_node(src.node.id, parent.node.id, name, overwrite)
            .await
    }

    async fn rename_mount(&self, p: &Principal, src: &Access, to: &LogicalPath) -> Result<Written> {
        let Origin::Share(id) = src.origin else {
            return Err(Error::Forbidden);
        };
        let [name] = to.segments() else {
            return Err(Error::Conflict(
                "a mount point can only be renamed inside the root",
            ));
        };
        check_new_name(name)?;
        match self.inner.db.rename_mount(id, p.user_id, name).await {
            Ok(()) => Ok(Written {
                node: src.node.clone(),
                replaced: false,
            }),
            // name taken by an own item or another mount: refuse like an existing target
            Err(Error::AlreadyExists) => Err(Error::PreconditionFailed),
            Err(e) => Err(e),
        }
    }

    /// An existing move/copy target that is to be replaced needs the delete right.
    async fn authorize_overwrite(
        &self,
        p: &Principal,
        to: &LogicalPath,
        overwrite: bool,
    ) -> Result<()> {
        if !overwrite {
            return Ok(());
        }
        match self.resolve_access(p, to).await {
            Ok(t) if t.mount_root => Err(Error::Conflict("target is a mount point")),
            Ok(t) => authorize_access(p, &t, Need::Delete),
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Copies a subtree. Copies may leave a share (read right needed) or enter
    /// one (create right needed); the copy belongs to the destination's owner.
    pub async fn copy_to(
        &self,
        p: &Principal,
        from: &LogicalPath,
        to: &LogicalPath,
        overwrite: bool,
    ) -> Result<Written> {
        let src = self.access_for(p, from, Need::Read).await?;
        let (parent, name) = self.parent_access(p, to, Some(Need::Create)).await?;
        self.authorize_overwrite(p, to, overwrite).await?;
        self.inner
            .db
            .copy_node(src.node.id, parent.node.id, name, overwrite)
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
        self.purge_old_events().await?;
        // retention may leave blobs without a reference: collect them in the same run
        let versions = self.cleanup_versions().await?;
        let mut more = 0;
        if versions > 0 {
            for id in self.inner.db.delete_unreferenced_blobs().await? {
                self.inner.store.delete_blob(&BlobId::parse(&id)?).await?;
                more += 1;
            }
        }
        Ok(ids.len() + more + expired)
    }
}
