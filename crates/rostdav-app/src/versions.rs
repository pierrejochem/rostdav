//! File versions: policy, listing, access, restore, deletion, retention.

use rostdav_core::{Error, Result};
use rostdav_meta::{CommitOpts, Node, VersionPolicy};
use rostdav_storage::BlobId;

use crate::AppState;
use crate::auth::{Action, Principal, authorize};

#[derive(Clone, Debug)]
pub struct VersioningOptions {
    /// Keep the previous content on overwrite.
    pub enabled: bool,
    /// At most this many archived versions per file; 0 = unlimited.
    pub max_versions: u32,
    /// Versions older than this many days are removed; 0 = keep.
    pub max_age_days: u32,
    /// Versions of a user may take at most this share of the quota (1-100); 0 = no limit.
    pub max_quota_share_percent: u32,
}

impl Default for VersioningOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            max_versions: 50,
            max_age_days: 365,
            max_quota_share_percent: 50,
        }
    }
}

/// One entry of a file's version list: an archived version or the live content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionEntry {
    /// Name in the DAV URL.
    pub version_time: i64,
    pub mtime: i64,
    pub size: i64,
    pub author: Option<String>,
    /// The current content of the file (listed last, as in the reference).
    pub live: bool,
}

#[derive(Debug)]
pub struct VersionListing {
    pub node: Node,
    pub entries: Vec<VersionEntry>,
}

impl AppState {
    pub fn versioning_enabled(&self) -> bool {
        self.cfg().versioning.enabled
    }

    pub(crate) fn version_policy(&self) -> VersionPolicy {
        let v = self.cfg().versioning;
        VersionPolicy {
            enabled: v.enabled,
            max_versions: v.max_versions,
        }
    }

    pub(crate) fn commit_opts(
        &self,
        p: &Principal,
        mtime: Option<i64>,
        client_checksum: Option<String>,
    ) -> CommitOpts {
        CommitOpts {
            mtime,
            client_checksum,
            versioning: self.version_policy(),
            author: Some(p.user_id),
        }
    }

    /// The file addressed by its ID, only if `p` may access it. Anything else is NotFound.
    async fn versioned_file(&self, p: &Principal, file_id: i64, action: Action) -> Result<Node> {
        // Versions are the owner's business (ADR 0004): recipients and links never see them.
        Self::require_full(p).map_err(|_| Error::NotFound)?;
        let node = self
            .inner
            .db
            .file_of_owner(p.user_id, file_id)
            .await?
            .ok_or(Error::NotFound)?;
        authorize(p, &node, action).map_err(|_| Error::NotFound)?;
        Ok(node)
    }

    /// Archived versions plus the live content (named by its mtime, moved to a
    /// free name if an archived version already has it).
    pub async fn version_list(&self, p: &Principal, file_id: i64) -> Result<VersionListing> {
        let node = self.versioned_file(p, file_id, Action::Read).await?;
        let stored = self.inner.db.list_versions(node.id).await?;
        let mut entries: Vec<VersionEntry> = stored
            .iter()
            .map(|v| VersionEntry {
                version_time: v.version_time,
                mtime: v.mtime,
                size: v.size,
                author: v.author.clone(),
                live: false,
            })
            .collect();
        let mut t = node.mtime;
        while stored.iter().any(|v| v.version_time == t) {
            t += 1;
        }
        entries.push(VersionEntry {
            version_time: t,
            mtime: node.mtime,
            size: node.size,
            author: Some(p.name.clone()),
            live: true,
        });
        // ascending by name, like the reference: a restored (older) live entry sorts first
        entries.sort_by_key(|e| e.version_time);
        Ok(VersionListing { node, entries })
    }

    /// Opens the content of one entry (archived or live).
    pub async fn version_open(
        &self,
        p: &Principal,
        file_id: i64,
        version_time: i64,
    ) -> Result<(Node, VersionEntry, tokio::fs::File)> {
        let listing = self.version_list(p, file_id).await?;
        let entry = listing
            .entries
            .iter()
            .find(|e| e.version_time == version_time)
            .cloned()
            .ok_or(Error::NotFound)?;
        let blob = if entry.live {
            listing.node.blob_id.clone().ok_or(Error::NotFound)?
        } else {
            self.inner
                .db
                .find_version(listing.node.id, version_time)
                .await?
                .ok_or(Error::NotFound)?
                .blob_id
        };
        let file = self.inner.store.open_blob(&BlobId::parse(&blob)?).await?;
        Ok((listing.node, entry, file))
    }

    /// Makes an entry the live content. Restoring the live entry changes nothing.
    pub async fn version_restore(
        &self,
        p: &Principal,
        file_id: i64,
        version_time: i64,
    ) -> Result<Node> {
        let listing = self.version_list(p, file_id).await?;
        let entry = listing
            .entries
            .iter()
            .find(|e| e.version_time == version_time)
            .ok_or(Error::NotFound)?;
        self.versioned_file(p, file_id, Action::Write).await?;
        if entry.live {
            return Ok(listing.node);
        }
        self.inner
            .db
            .restore_version(
                listing.node.id,
                version_time,
                self.version_policy(),
                Some(p.user_id),
            )
            .await
    }

    /// Deletes an archived version. The live entry cannot be deleted this way.
    pub async fn version_delete(
        &self,
        p: &Principal,
        file_id: i64,
        version_time: i64,
    ) -> Result<()> {
        let listing = self.version_list(p, file_id).await?;
        self.versioned_file(p, file_id, Action::Write).await?;
        match listing
            .entries
            .iter()
            .find(|e| e.version_time == version_time)
        {
            None => Err(Error::NotFound),
            Some(e) if e.live => Err(Error::Forbidden),
            Some(_) => {
                self.inner
                    .db
                    .delete_version(listing.node.id, version_time)
                    .await
            }
        }
    }

    /// Retention: age and quota share. Returns how many versions were removed.
    pub(crate) async fn cleanup_versions(&self) -> Result<usize> {
        let v = self.cfg().versioning;
        let mut removed = 0u64;
        if v.max_age_days > 0 {
            let cutoff = crate::now_secs() - i64::from(v.max_age_days) * 86_400;
            removed += self.inner.db.expire_versions(cutoff).await?;
        }
        if v.max_quota_share_percent > 0 {
            removed += self
                .inner
                .db
                .trim_versions_to_quota_share(v.max_quota_share_percent.min(100))
                .await?;
        }
        Ok(usize::try_from(removed).unwrap_or(usize::MAX))
    }
}
