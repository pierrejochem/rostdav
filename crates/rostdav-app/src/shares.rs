//! Sharing service: user shares, public links, link sign-in (ADR 0004).
//!
//! Messages and status codes follow the recorded reference
//! (`tests/fixtures/nextcloud/10-shares/`).

use std::net::IpAddr;

use rostdav_core::time::parse_datetime;
use rostdav_core::{Error, LogicalPath, Result};
use rostdav_meta::{
    NewShare, Node, NodeKind, PERM_ALL, PERM_READ, PERM_UPDATE, Share, ShareKind, ShareUpdate,
};
use serde_json::json;

use crate::AppState;
use crate::access::Origin;
use crate::auth::{Principal, Scope, Via};
use crate::password::{MIN_PASSWORD_CHARS, hash_password, verify_password};
use crate::secrets::{hash_token, random_token};

/// Length of generated link tokens.
pub const LINK_TOKEN_LEN: usize = 24;

/// A failure with the status and message the OCS API shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareError {
    pub status: u16,
    pub message: String,
}

impl ShareError {
    fn new(status: u16, message: &str) -> Self {
        Self {
            status,
            message: message.to_owned(),
        }
    }
}

impl From<Error> for ShareError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => Self::new(404, "Not found"),
            Error::Forbidden => Self::new(403, "Forbidden"),
            Error::RateLimited { .. } => Self::new(429, "Too many requests"),
            Error::Unauthenticated => Self::new(401, "Unauthorised"),
            Error::BadRequest(m) => Self::new(400, m),
            Error::Invalid(m) => Self {
                status: 400,
                message: m,
            },
            other => {
                if other.is_internal() {
                    tracing::error!(error = %other, "sharing failed");
                }
                Self::new(500, "Internal server error")
            }
        }
    }
}

type R<T> = std::result::Result<T, ShareError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Viewer {
    Owner,
    Recipient,
}

#[derive(Clone, Debug)]
pub struct ShareCreate {
    pub path: Option<LogicalPath>,
    /// OCS share type: 0 user, 3 link.
    pub share_type: i64,
    pub share_with: Option<String>,
    pub permissions: Option<i64>,
    pub password: Option<String>,
    pub expire: Option<String>,
    pub note: String,
    pub label: String,
    pub hide_download: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ShareChange {
    pub permissions: Option<i64>,
    /// Empty string removes the password.
    pub password: Option<String>,
    /// Empty string removes the expiry.
    pub expire: Option<String>,
    pub note: Option<String>,
    pub label: Option<String>,
    pub hide_download: Option<bool>,
}

#[derive(Clone, Debug, Default)]
pub struct ShareFilter {
    pub path: Option<LogicalPath>,
    pub subfiles: bool,
    pub shared_with_me: bool,
}

#[derive(Clone, Debug)]
pub struct ShareView {
    pub share: Share,
    pub viewer: Viewer,
    pub node: Node,
    /// Path of the node below its owner's root.
    pub path: String,
    pub owner: String,
    pub recipient: Option<String>,
}

/// Permission bits a share of this node may carry.
fn allowed_permissions(node: &Node) -> u8 {
    if node.kind == NodeKind::Dir {
        PERM_ALL
    } else {
        PERM_READ | PERM_UPDATE
    }
}

fn parse_permissions(raw: Option<i64>, default: i64, node: &Node, kind: ShareKind) -> R<u8> {
    let v = raw.unwrap_or(default);
    // user shares need the read right; a link may be upload-only ("file drop", create right alone)
    let needed = if kind == ShareKind::Link && node.kind == NodeKind::Dir {
        1 | 4
    } else {
        1
    };
    if !(1..=31).contains(&v) || v & needed == 0 {
        return Err(ShareError::new(
            403,
            "Valid permissions are required for sharing",
        ));
    }
    // bit 16 (share) is accepted and dropped: no resharing
    let masked = u8::try_from(v & 15).unwrap_or(1) & allowed_permissions(node);
    Ok(if masked == 0 { PERM_READ } else { masked })
}

fn parse_expiry(raw: &str) -> R<Option<i64>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let t = parse_datetime(raw)
        .ok_or_else(|| ShareError::new(400, "Invalid date. Format must be YYYY-MM-DD"))?;
    if t <= crate::now_secs() {
        return Err(ShareError::new(404, "Expiration date is in the past"));
    }
    Ok(Some(t))
}

fn link_password_hash(pw: &str) -> R<Option<String>> {
    if pw.is_empty() {
        return Ok(None);
    }
    if pw.chars().count() < MIN_PASSWORD_CHARS {
        return Err(ShareError::new(
            400,
            &format!("The password must be at least {MIN_PASSWORD_CHARS} characters long"),
        ));
    }
    Ok(Some(hash_password(pw)?))
}

impl AppState {
    async fn view(&self, p: &Principal, share: Share) -> R<ShareView> {
        let viewer = if share.owner_id == p.user_id {
            Viewer::Owner
        } else if share.recipient_id == Some(p.user_id) {
            Viewer::Recipient
        } else {
            return Err(ShareError::new(404, "Wrong share ID, share does not exist"));
        };
        let node = self
            .inner
            .db
            .node_by_id(share.node_id)
            .await?
            .ok_or_else(|| ShareError::new(404, "Wrong share ID, share does not exist"))?;
        let path = self.inner.db.node_path(node.id).await?;
        let mut ids = vec![share.owner_id];
        ids.extend(share.recipient_id);
        let names = self.inner.db.user_names(&ids).await?;
        Ok(ShareView {
            owner: names.get(&share.owner_id).cloned().unwrap_or_default(),
            recipient: share.recipient_id.and_then(|r| names.get(&r).cloned()),
            share,
            viewer,
            node,
            path,
        })
    }

    pub async fn share_create(&self, p: &Principal, req: ShareCreate) -> R<ShareView> {
        Self::require_full(p)?;
        let path = req
            .path
            .as_ref()
            .ok_or_else(|| ShareError::new(404, "Please specify a file or folder path"))?;
        let kind = match req.share_type {
            0 => ShareKind::User,
            3 => ShareKind::Link,
            _ => return Err(ShareError::new(400, "Unknown share type")),
        };
        // The path is resolved in the caller's own view; a received share cannot be shared on.
        let access = match self.resolve_access(p, path).await {
            Ok(a) => a,
            Err(Error::NotFound) => {
                return Err(ShareError::new(
                    404,
                    "Wrong path, file/folder does not exist",
                ));
            }
            Err(e) => return Err(e.into()),
        };
        match access.origin {
            Origin::Own => {}
            Origin::Share(_) => return Err(ShareError::new(403, "Resharing is not allowed")),
            Origin::Link(_) => return Err(ShareError::new(403, "Forbidden")),
        }
        if access.node.parent_id.is_none() {
            return Err(ShareError::new(403, "The root folder cannot be shared"));
        }

        let (recipient_id, default_perms) = match kind {
            ShareKind::User => {
                let name = req.share_with.as_deref().unwrap_or("");
                let who = self
                    .inner
                    .db
                    .find_user(name)
                    .await?
                    .filter(|u| !u.disabled)
                    .ok_or_else(|| {
                        ShareError::new(404, "Please specify a valid account to share with")
                    })?;
                if who.id == p.user_id {
                    return Err(ShareError::new(403, "Cannot share with yourself"));
                }
                (Some(who.id), 31)
            }
            ShareKind::Link => (None, 1),
        };
        let permissions = parse_permissions(req.permissions, default_perms, &access.node, kind)?;
        let expires_at = match &req.expire {
            Some(e) => parse_expiry(e)?,
            None => None,
        };
        let password_hash = match (kind, &req.password) {
            (ShareKind::Link, Some(pw)) => link_password_hash(pw)?,
            _ => None,
        };
        let share = self
            .inner
            .db
            .create_share(NewShare {
                kind,
                owner_id: p.user_id,
                node_id: access.node.id,
                recipient_id,
                permissions,
                token: (kind == ShareKind::Link).then(|| random_token(LINK_TOKEN_LEN)),
                password_hash,
                expires_at,
                note: req.note.chars().take(1000).collect(),
                label: req.label.chars().take(255).collect(),
                hide_download: req.hide_download,
            })
            .await?;
        self.audit(
            &p.name,
            "share.created",
            &access.node.name,
            None,
            json!({"type": share.kind.code(), "permissions": share.permissions, "with": req.share_with}),
        )
        .await;
        self.view(p, share).await
    }

    pub async fn share_get(&self, p: &Principal, id: i64) -> R<ShareView> {
        Self::require_full(p)?;
        let share = self
            .inner
            .db
            .get_share(id)
            .await?
            .ok_or_else(|| ShareError::new(404, "Wrong share ID, share does not exist"))?;
        self.view(p, share).await
    }

    pub async fn shares_list(&self, p: &Principal, filter: ShareFilter) -> R<Vec<ShareView>> {
        Self::require_full(p)?;
        let db = &self.inner.db;
        let shares = if filter.shared_with_me {
            db.shares_for_recipient(p.user_id).await?
        } else if let Some(path) = &filter.path {
            let a = match self.resolve_access(p, path).await {
                Ok(a) if a.origin == Origin::Own => a,
                Ok(_) | Err(Error::NotFound) => {
                    return Err(ShareError::new(
                        404,
                        "Wrong path, file/folder does not exist",
                    ));
                }
                Err(e) => return Err(e.into()),
            };
            let mut out = db.shares_for_node(a.node.id).await?;
            if filter.subfiles && a.is_dir() {
                for child in db.children(a.node.id).await? {
                    out.extend(db.shares_for_node(child.id).await?);
                }
            }
            out.retain(|s| s.owner_id == p.user_id);
            out
        } else {
            db.shares_by_owner(p.user_id).await?
        };
        let mut views = Vec::with_capacity(shares.len());
        for s in shares {
            views.push(self.view(p, s).await?);
        }
        Ok(views)
    }

    pub async fn share_update(&self, p: &Principal, id: i64, change: ShareChange) -> R<ShareView> {
        Self::require_full(p)?;
        let share = self
            .inner
            .db
            .get_share(id)
            .await?
            .ok_or_else(|| ShareError::new(404, "Wrong share ID, share does not exist"))?;
        if share.owner_id != p.user_id {
            return if share.recipient_id == Some(p.user_id) {
                Err(ShareError::new(
                    403,
                    "You are not allowed to edit incoming shares",
                ))
            } else {
                Err(ShareError::new(404, "Wrong share ID, share does not exist"))
            };
        }
        let node = self
            .inner
            .db
            .node_by_id(share.node_id)
            .await?
            .ok_or_else(|| ShareError::new(404, "Wrong share ID, share does not exist"))?;
        let mut upd = ShareUpdate::default();
        if let Some(v) = change.permissions {
            if !(1..=31).contains(&v) || v & 1 == 0 {
                return Err(ShareError::new(
                    403,
                    "File share needs at least read permission.",
                ));
            }
            upd.permissions = Some(parse_permissions(Some(v), v, &node, share.kind)?);
        }
        if let (Some(pw), ShareKind::Link) = (&change.password, share.kind) {
            upd.password_hash = Some(link_password_hash(pw)?);
        }
        if let Some(e) = &change.expire {
            upd.expires_at = Some(parse_expiry(e)?);
        }
        upd.note = change.note.map(|n| n.chars().take(1000).collect());
        upd.label = change.label.map(|n| n.chars().take(255).collect());
        upd.hide_download = change.hide_download;
        let updated = self.inner.db.update_share(id, &upd).await?;
        self.view(p, updated).await
    }

    pub async fn share_delete(&self, p: &Principal, id: i64) -> R<()> {
        Self::require_full(p)?;
        let share = self
            .inner
            .db
            .get_share(id)
            .await?
            .filter(|s| s.owner_id == p.user_id)
            .ok_or_else(|| ShareError::new(404, "Wrong share ID, share does not exist"))?;
        self.inner.db.delete_share(share.id).await?;
        let name = self
            .inner
            .db
            .node_by_id(share.node_id)
            .await?
            .map(|n| n.name)
            .unwrap_or_default();
        self.audit(
            &p.name,
            "share.revoked",
            &name,
            None,
            json!({"type": share.kind.code(), "by": "owner"}),
        )
        .await;
        Ok(())
    }

    /// User names to offer when sharing: contain `search`, enabled, not the caller.
    pub async fn sharees(&self, p: &Principal, search: &str, limit: i64) -> R<Vec<String>> {
        Self::require_full(p)?;
        Ok(self
            .inner
            .db
            .search_users(search.trim(), p.user_id, limit.clamp(1, 200))
            .await?)
    }

    /// Kinds of shares on these nodes, only for nodes the caller owns (`oc:share-types`).
    pub async fn share_kinds_of(
        &self,
        p: &Principal,
        node_ids: &[i64],
    ) -> Result<std::collections::HashMap<i64, Vec<i64>>> {
        if p.scope != Scope::Full || node_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let mut kinds = self.inner.db.share_kinds_of_nodes(node_ids).await?;
        // only the owner learns who a node is shared with
        let mine = self
            .inner
            .db
            .nodes_owned_by(p.user_id, &kinds.keys().copied().collect::<Vec<_>>())
            .await?;
        kinds.retain(|id, _| mine.contains(id));
        Ok(kinds)
    }

    // ---- public links ----------------------------------------------------------

    /// Signs in with `Authorization: Basic <token>:<password>` for `public.php/webdav`.
    pub async fn authenticate_link_basic(&self, header: &str, ip: IpAddr) -> Result<Principal> {
        use base64::Engine;
        let (scheme, b64) = header.split_once(' ').ok_or(Error::Unauthenticated)?;
        let ip_key = format!("ip:{ip}");
        self.inner
            .limiter
            .check(&ip_key)
            .map_err(|s| Error::RateLimited {
                retry_after_secs: s,
            })?;
        let creds = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .ok()
            .and_then(|d| String::from_utf8(d).ok())
            .and_then(|d| d.split_once(':').map(|(t, p)| (t.to_owned(), p.to_owned())));
        match (scheme.eq_ignore_ascii_case("basic"), creds) {
            (true, Some((token, password))) => self.authenticate_link(&token, &password, ip).await,
            _ => {
                self.inner.limiter.record_failure(&ip_key);
                Err(Error::Unauthenticated)
            }
        }
    }

    pub async fn authenticate_link(
        &self,
        token: &str,
        password: &str,
        ip: IpAddr,
    ) -> Result<Principal> {
        // failures count per address and per link, so a leaked token cannot be hammered from many addresses
        let ip_key = format!("ip:{ip}");
        let link_key = format!("link:{}", &hash_token(token)[..16]);
        self.inner
            .limiter
            .check(&ip_key)
            .map_err(|s| Error::RateLimited {
                retry_after_secs: s,
            })?;
        self.inner
            .limiter
            .check(&link_key)
            .map_err(|s| Error::RateLimited {
                retry_after_secs: s,
            })?;

        let share = if (8..=64).contains(&token.len())
            && token.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            self.inner.db.find_link(token).await?
        } else {
            None
        };
        // always spend the hashing time, with the real hash or a dummy
        let hash = share
            .as_ref()
            .and_then(|s| s.password_hash.clone())
            .unwrap_or_else(|| crate::auth::dummy_hash().to_owned());
        let needs_password = share.as_ref().is_some_and(|s| s.password_hash.is_some());
        let password = password.to_owned();
        let ok = if needs_password || share.is_none() {
            tokio::task::spawn_blocking(move || verify_password(&password, &hash))
                .await
                .map_err(Error::internal)?
        } else {
            true
        };
        match share {
            Some(s) if ok => {
                self.inner.limiter.clear(&link_key);
                let perms = s.permissions & 15;
                Ok(Principal {
                    user_id: s.owner_id,
                    name: "public link".to_owned(),
                    is_admin: false,
                    via: Via::Link(s.id),
                    scope: Scope::Link {
                        share_id: s.id,
                        node_id: s.node_id,
                        perms,
                    },
                })
            }
            _ => {
                let by_ip = self.inner.limiter.record_failure(&ip_key);
                let by_link = self.inner.limiter.record_failure(&link_key);
                self.audit("public link", "auth.login_failed", "", Some(ip), json!({}))
                    .await;
                if by_ip || by_link {
                    self.audit("public link", "auth.locked", "", Some(ip), json!({}))
                        .await;
                }
                Err(Error::Unauthenticated)
            }
        }
    }
}
