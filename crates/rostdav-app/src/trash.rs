//! Trash service (ADR 0005). The trash belongs to the node's owner; only the
//! owner lists, reads, restores or purges.

use rostdav_core::{Error, LogicalPath, Result};
use rostdav_meta::{Node, NodeKind, TrashItem};
use rostdav_storage::BlobId;

use crate::AppState;
use crate::auth::Principal;

#[derive(Clone, Debug)]
pub struct TrashOptions {
    /// Deleted files go to the trash first. Off = deleting is permanent.
    pub enabled: bool,
    /// Items older than this many days are purged; 0 = keep until emptied.
    pub retention_days: u32,
}

impl Default for TrashOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 30,
        }
    }
}

/// An item (or something inside a trashed folder) with its context.
#[derive(Clone, Debug)]
pub struct TrashEntry {
    pub item: TrashItem,
    pub node: Node,
    /// The node is the top of the deleted subtree.
    pub top: bool,
}

impl AppState {
    pub fn trash_enabled(&self) -> bool {
        self.cfg().trash.enabled
    }

    fn trash_guard(&self, p: &Principal) -> Result<()> {
        Self::require_full(p)?;
        if self.cfg().trash.enabled {
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    pub async fn trash_list(&self, p: &Principal) -> Result<Vec<TrashItem>> {
        self.trash_guard(p)?;
        self.inner.db.list_trash(p.user_id).await
    }

    /// A listed item or something below it; `inner` are the names inside a trashed folder.
    pub async fn trash_entry(
        &self,
        p: &Principal,
        entry: &str,
        inner: &LogicalPath,
    ) -> Result<TrashEntry> {
        self.trash_guard(p)?;
        let item = self
            .inner
            .db
            .find_trash_item(p.user_id, entry)
            .await?
            .ok_or(Error::NotFound)?;
        let node = self
            .inner
            .db
            .resolve_in_trash(&item, inner.segments())
            .await?
            .ok_or(Error::NotFound)?;
        Ok(TrashEntry {
            top: inner.is_root(),
            item,
            node,
        })
    }

    pub async fn trash_children(&self, e: &TrashEntry) -> Result<Vec<Node>> {
        if e.node.kind != NodeKind::Dir {
            return Err(Error::BadRequest("not a directory"));
        }
        self.inner.db.trash_children(e.item.id, e.node.id).await
    }

    /// Total size of a trashed item or of something below it.
    pub async fn trash_size(&self, e: &TrashEntry) -> Result<i64> {
        if e.top {
            self.inner.db.trash_item_size(e.item.id).await
        } else {
            Ok(e.node.size)
        }
    }

    pub async fn trash_open(&self, e: &TrashEntry) -> Result<tokio::fs::File> {
        let blob = e
            .node
            .blob_id
            .as_deref()
            .ok_or(Error::BadRequest("not a file"))?;
        self.inner.store.open_blob(&BlobId::parse(blob)?).await
    }

    pub async fn trash_restore(&self, p: &Principal, entry: &str) -> Result<Node> {
        self.trash_guard(p)?;
        let item = self
            .inner
            .db
            .find_trash_item(p.user_id, entry)
            .await?
            .ok_or(Error::NotFound)?;
        self.inner.db.restore_trash(item.id).await
    }

    /// Purges one item; its blobs are collected by the next garbage run.
    pub async fn trash_delete(&self, p: &Principal, entry: &str) -> Result<()> {
        self.trash_guard(p)?;
        let item = self
            .inner
            .db
            .find_trash_item(p.user_id, entry)
            .await?
            .ok_or(Error::NotFound)?;
        self.inner.db.purge_trash_item(item.id).await?;
        self.collect_garbage().await?;
        Ok(())
    }

    pub async fn trash_empty(&self, p: &Principal) -> Result<()> {
        self.trash_guard(p)?;
        self.inner.db.purge_all_trash(p.user_id).await?;
        self.collect_garbage().await?;
        Ok(())
    }

    /// Retention: purge items older than the configured age.
    pub(crate) async fn cleanup_trash(&self) -> Result<usize> {
        let t = self.cfg().trash;
        if !t.enabled || t.retention_days == 0 {
            return Ok(0);
        }
        let cutoff = crate::now_secs() - i64::from(t.retention_days) * 86_400;
        self.inner.db.purge_trash_before(cutoff).await
    }
}
