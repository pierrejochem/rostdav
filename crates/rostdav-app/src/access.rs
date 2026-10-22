//! Access grants and the permission check (ADR 0004).
//!
//! Resolving a path yields an [`Access`]: the node plus what the caller may do
//! with it and by which right they reach it. [`authorize_access`] is the single
//! place that compares needs with grants.

use rostdav_core::{Error, LogicalPath, Name, Result};
use rostdav_meta::{
    Node, NodeKind, PERM_ALL, PERM_CREATE, PERM_DELETE, PERM_READ, PERM_UPDATE, Share,
};

use crate::AppState;
use crate::auth::{Principal, Scope};

/// By which right a node is reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// In the caller's own tree.
    Own,
    /// Through a share mounted in the caller's root.
    Share(i64),
    /// As the root of a public link.
    Link(i64),
}

/// What an operation needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Need {
    Read,
    /// Overwrite an existing file or change it.
    Update,
    /// Create a file or folder in a directory.
    Create,
    Delete,
}

impl Need {
    fn bit(self) -> u8 {
        match self {
            Need::Read => PERM_READ,
            Need::Update => PERM_UPDATE,
            Need::Create => PERM_CREATE,
            Need::Delete => PERM_DELETE,
        }
    }
}

/// A resolved node with the caller's rights on it.
#[derive(Clone, Debug)]
pub struct Access {
    pub node: Node,
    /// The user (or, for links, the share owner) this grant was resolved for.
    pub holder: i64,
    /// Permission bits (`PERM_*`).
    pub perms: u8,
    pub origin: Origin,
    /// The node is the shared root itself (the mount point or the link root).
    pub mount_root: bool,
}

impl Access {
    pub fn is_dir(&self) -> bool {
        self.node.kind == NodeKind::Dir
    }

    /// Same tree and same right: nodes may be moved between such accesses.
    pub fn same_domain(&self, other: &Access) -> bool {
        self.origin == other.origin && self.node.owner_id == other.node.owner_id
    }

    /// The `oc:permissions` letters (Nextcloud DAV permission string). The
    /// share letter `R` is never produced because resharing is not supported.
    pub fn dav_permissions(&self) -> String {
        let shared = self.origin != Origin::Own;
        let p = self.perms;
        let mut out = String::new();
        if shared && matches!(self.origin, Origin::Share(_)) {
            out.push('S');
        }
        if p & PERM_READ != 0 {
            out.push('G');
        }
        // the recipient may always leave (delete) and rename the mount point itself
        let mount = self.mount_root && matches!(self.origin, Origin::Share(_));
        if p & PERM_DELETE != 0 || mount {
            out.push('D');
        }
        if p & PERM_UPDATE != 0 || mount {
            out.push('N');
        }
        if p & PERM_UPDATE != 0 {
            out.push('V');
        }
        if self.is_dir() {
            if p & PERM_CREATE != 0 {
                out.push_str("CK");
            }
        } else if p & PERM_UPDATE != 0 {
            out.push('W');
        }
        out
    }
}

/// The check. `p` must be the principal the access was resolved for.
pub fn authorize_access(p: &Principal, a: &Access, need: Need) -> Result<()> {
    // The grant must belong to the caller: own nodes only to their owner,
    // links only to the principal of that link.
    let consistent = a.holder == p.user_id
        && match (a.origin, p.scope) {
            (Origin::Own, Scope::Full) => a.node.owner_id == p.user_id,
            (Origin::Share(_), Scope::Full) => a.node.owner_id != p.user_id,
            (Origin::Link(id), Scope::Link { share_id, .. }) => id == share_id,
            _ => false,
        };
    if !consistent || a.perms & need.bit() == 0 {
        return Err(Error::Forbidden);
    }
    Ok(())
}

/// A user share as shown in the recipient's root.
#[derive(Clone, Debug)]
pub struct MountView {
    pub share: Share,
    /// The shared node.
    pub node: Node,
    pub name: String,
}

impl AppState {
    /// Resolves a path in the caller's view of the world.
    ///
    /// Full principals see their own tree plus the mount points of shares in
    /// their root; link principals see exactly the shared node as their root.
    /// Nothing here ever walks upwards, so a share cannot be left.
    pub(crate) async fn resolve_access(&self, p: &Principal, path: &LogicalPath) -> Result<Access> {
        let db = &self.inner.db;
        match p.scope {
            Scope::Link {
                share_id,
                node_id,
                perms,
            } => {
                let node = db
                    .resolve_from(node_id, path.segments())
                    .await?
                    .ok_or(Error::NotFound)?;
                Ok(Access {
                    node,
                    holder: p.user_id,
                    perms,
                    origin: Origin::Link(share_id),
                    mount_root: path.is_root(),
                })
            }
            Scope::Full => {
                if let Some(node) = db.resolve(p.user_id, path).await? {
                    return Ok(Access {
                        node,
                        holder: p.user_id,
                        perms: PERM_ALL,
                        origin: Origin::Own,
                        mount_root: false,
                    });
                }
                let Some((first, rest)) = path.segments().split_first() else {
                    return Err(Error::NotFound);
                };
                let share = db
                    .find_mount(p.user_id, first)
                    .await?
                    .ok_or(Error::NotFound)?;
                let node = db
                    .resolve_from(share.node_id, rest)
                    .await?
                    .ok_or(Error::NotFound)?;
                Ok(Access {
                    node,
                    holder: p.user_id,
                    perms: share.permissions,
                    origin: Origin::Share(share.id),
                    mount_root: rest.is_empty(),
                })
            }
        }
    }

    /// Mount points shown in the caller's root.
    pub(crate) async fn mounts_of(&self, p: &Principal) -> Result<Vec<MountView>> {
        if p.scope != Scope::Full {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for share in self.inner.db.shares_for_recipient(p.user_id).await? {
            let Some(node) = self.inner.db.node_by_id(share.node_id).await? else {
                continue;
            };
            let name = share
                .mount_name
                .clone()
                .unwrap_or_else(|| node.name.clone());
            out.push(MountView { share, node, name });
        }
        out.sort_by_key(|m| m.name.to_lowercase());
        Ok(out)
    }

    /// ETag of a user's own root as clients should see it: it also changes when
    /// anything inside a mounted share changes. `None` where the stored one is right.
    pub async fn derived_root_etag(&self, p: &Principal, a: &Access) -> Result<Option<String>> {
        if a.origin != Origin::Own || a.node.parent_id.is_some() {
            return Ok(None);
        }
        let mounts = self.mounts_of(p).await?;
        if mounts.is_empty() {
            return Ok(None);
        }
        let mut h = blake3::Hasher::new();
        h.update(a.node.etag.as_bytes());
        for m in &mounts {
            h.update(&[0]);
            h.update(m.name.as_bytes());
            h.update(&[0]);
            h.update(m.node.etag.as_bytes());
            h.update(&[m.share.permissions]);
        }
        Ok(Some(h.finalize().to_hex()[..32].to_owned()))
    }

    /// Owner names for display.
    pub async fn owner_names(&self, ids: &[i64]) -> Result<std::collections::HashMap<i64, String>> {
        self.inner.db.user_names(ids).await
    }

    /// Only a full principal (signed in with a password) may use this; links never.
    pub(crate) fn require_full(p: &Principal) -> Result<()> {
        if p.scope == Scope::Full {
            Ok(())
        } else {
            Err(Error::Forbidden)
        }
    }
}

/// Splits `path` into the parent path and the final name.
pub(crate) fn split_target(path: &LogicalPath) -> Result<(LogicalPath, &Name)> {
    path.split_last()
        .ok_or(Error::Conflict("the root cannot be addressed this way"))
}
