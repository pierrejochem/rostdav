//! Favorites (`oc:favorite`): a per-user mark on any node the user can read.

use std::collections::HashSet;

use rostdav_core::{LogicalPath, Name, Result};

use crate::AppState;
use crate::access::{Access, Need, authorize_access};
use crate::auth::Principal;

impl AppState {
    /// Marks or unmarks the node at `path` as a favorite of the caller.
    pub async fn set_favorite(&self, p: &Principal, path: &LogicalPath, on: bool) -> Result<()> {
        Self::require_full(p)?;
        let a = self.resolve_access(p, path).await?;
        authorize_access(p, &a, Need::Read)?;
        self.inner.db.favorite_set(p.user_id, a.node.id, on).await
    }

    /// Those of `node_ids` the caller marked as favorite.
    pub async fn favorites_among(&self, p: &Principal, node_ids: &[i64]) -> Result<HashSet<i64>> {
        if Self::require_full(p).is_err() {
            return Ok(HashSet::new());
        }
        self.inner.db.favorites_among(p.user_id, node_ids).await
    }

    /// The caller's own files that changed last, with their paths, newest first. Files that
    /// others shared with the caller are not included.
    pub async fn list_recent(
        &self,
        p: &Principal,
        limit: i64,
    ) -> Result<Vec<(LogicalPath, rostdav_meta::Node)>> {
        Self::require_full(p)?;
        let mut out = Vec::new();
        for node in self.inner.db.recent_files(p.user_id, limit).await? {
            let node_path = self.inner.db.node_path(node.id).await?;
            // Names are joined one by one: a name may contain `%`, which a URL decoder would eat.
            if let Ok(path) = node_path
                .split('/')
                .filter(|s| !s.is_empty())
                .try_fold(LogicalPath::root(), |acc, seg| {
                    Ok::<_, rostdav_core::Error>(acc.join(&Name::parse(seg)?))
                })
            {
                out.push((path, node));
            }
        }
        Ok(out)
    }

    /// Favorites in the caller's own tree with their paths, in file ID order.
    pub async fn list_favorites(&self, p: &Principal) -> Result<Vec<(LogicalPath, Access)>> {
        Self::require_full(p)?;
        let mut out = Vec::new();
        for id in self.inner.db.favorites_own(p.user_id).await? {
            let node_path = self.inner.db.node_path(id).await?;
            // Names are joined one by one: a name may contain `%`, which a URL decoder would eat.
            let Ok(path) = node_path
                .split('/')
                .filter(|s| !s.is_empty())
                .try_fold(LogicalPath::root(), |acc, seg| {
                    Ok::<_, rostdav_core::Error>(acc.join(&Name::parse(seg)?))
                })
            else {
                continue;
            };
            // Re-resolved so the usual rules apply; a node that vanished meanwhile is skipped.
            if let Ok(a) = self.resolve_access(p, &path).await
                && authorize_access(p, &a, Need::Read).is_ok()
            {
                out.push((path, a));
            }
        }
        Ok(out)
    }
}
