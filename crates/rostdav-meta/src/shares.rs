//! Shares: user shares (mount points) and public links (ADR 0004).
//!
//! This layer stores and looks up shares. Who may do what with a share is
//! decided in `rostdav-app`.

use std::collections::HashMap;

use rostdav_core::{Error, Name, Result};
use sqlx::SqliteConnection;

use crate::Db;
use crate::nodes::{COLS, Node, NodeKind, Row, db_err, fetch, to_node};
use crate::users::now_secs;

pub const PERM_READ: u8 = 1;
pub const PERM_UPDATE: u8 = 2;
pub const PERM_CREATE: u8 = 4;
pub const PERM_DELETE: u8 = 8;
pub const PERM_ALL: u8 = 15;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareKind {
    User,
    Link,
}

impl ShareKind {
    pub fn code(self) -> i64 {
        match self {
            ShareKind::User => 0,
            ShareKind::Link => 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub id: i64,
    pub kind: ShareKind,
    pub owner_id: i64,
    pub node_id: i64,
    pub recipient_id: Option<i64>,
    pub permissions: u8,
    pub mount_name: Option<String>,
    pub token: Option<String>,
    pub password_hash: Option<String>,
    pub expires_at: Option<i64>,
    pub note: String,
    pub label: String,
    pub hide_download: bool,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct NewShare {
    pub kind: ShareKind,
    pub owner_id: i64,
    pub node_id: i64,
    pub recipient_id: Option<i64>,
    pub permissions: u8,
    pub token: Option<String>,
    pub password_hash: Option<String>,
    pub expires_at: Option<i64>,
    pub note: String,
    pub label: String,
    pub hide_download: bool,
}

/// Fields of a share that may change; `None` = keep.
#[derive(Clone, Debug, Default)]
pub struct ShareUpdate {
    pub permissions: Option<u8>,
    /// `Some(None)` removes the password.
    pub password_hash: Option<Option<String>>,
    /// `Some(None)` removes the expiry.
    pub expires_at: Option<Option<i64>>,
    pub note: Option<String>,
    pub label: Option<String>,
    pub hide_download: Option<bool>,
}

type ShareRow = (
    i64,
    i64,
    i64,
    i64,
    Option<i64>,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    String,
    String,
    bool,
    i64,
);

const SCOLS: &str = "id, kind, owner_id, node_id, recipient_id, permissions, mount_name, token, password_hash, expires_at, note, label, hide_download, created_at";

fn to_share(r: ShareRow) -> Share {
    Share {
        id: r.0,
        kind: if r.1 == 3 {
            ShareKind::Link
        } else {
            ShareKind::User
        },
        owner_id: r.2,
        node_id: r.3,
        recipient_id: r.4,
        permissions: u8::try_from(r.5).unwrap_or(0),
        mount_name: r.6,
        token: r.7,
        password_hash: r.8,
        expires_at: r.9,
        note: r.10,
        label: r.11,
        hide_download: r.12,
        created_at: r.13,
    }
}

/// A share is live while it has not expired.
/// ... and its node is not in the trash (the share is inactive until it is restored).
const LIVE: &str = "(expires_at IS NULL OR expires_at > strftime('%s','now'))
    AND NOT EXISTS (SELECT 1 FROM nodes tn WHERE tn.id = shares.node_id AND tn.trash_id IS NOT NULL)";

async fn mount_clash(conn: &mut SqliteConnection, user: i64, key: &str) -> Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM nodes n JOIN nodes r ON r.id = n.parent_id
                       WHERE r.owner_id = ?1 AND r.parent_id IS NULL AND n.name_key = ?2 AND n.trash_id IS NULL)
             OR EXISTS(SELECT 1 FROM shares WHERE recipient_id = ?1 AND mount_key = ?2)",
    )
    .bind(user)
    .bind(key)
    .fetch_one(conn)
    .await
    .map_err(db_err)
}

/// For creations in a user's root: the name must not be a mount point.
pub(crate) async fn ensure_no_mount_clash(
    conn: &mut SqliteConnection,
    parent: &Node,
    key: &str,
) -> Result<()> {
    if parent.parent_id.is_some() {
        return Ok(());
    }
    let clash: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM shares WHERE recipient_id = ? AND mount_key = ?)",
    )
    .bind(parent.owner_id)
    .bind(key)
    .fetch_one(conn)
    .await
    .map_err(db_err)?;
    if clash {
        Err(Error::AlreadyExists)
    } else {
        Ok(())
    }
}

impl Db {
    /// Creates a share. A user share gets a mount name that is free in the
    /// recipient's root; an existing share of the same node to the same user is returned unchanged.
    pub async fn create_share(&self, new: NewShare) -> Result<Share> {
        let now = now_secs();
        let mut tx = self.write_tx().await?;
        let node = fetch(&mut tx, new.node_id).await?.ok_or(Error::NotFound)?;
        if node.parent_id.is_none() {
            return Err(Error::Conflict("the root cannot be shared"));
        }
        if let Some(rec) = new.recipient_id {
            let existing: Option<ShareRow> = sqlx::query_as(&format!(
                "SELECT {SCOLS} FROM shares WHERE node_id = ? AND recipient_id = ?"
            ))
            .bind(new.node_id)
            .bind(rec)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
            if let Some(e) = existing {
                return Ok(to_share(e));
            }
        }
        let (mount_name, mount_key) = match new.recipient_id {
            Some(rec) => {
                let base = node.name.clone();
                let mut name = base.clone();
                let mut n = 1;
                while mount_clash(&mut tx, rec, Name::parse(&name)?.key()).await? {
                    n += 1;
                    name = format!("{base} ({n})");
                }
                let key = Name::parse(&name)?.key().to_owned();
                (Some(name), Some(key))
            }
            None => (None, None),
        };
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO shares (kind, owner_id, node_id, recipient_id, permissions, mount_name, mount_key, token,
                                 password_hash, expires_at, note, label, hide_download, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(new.kind.code())
        .bind(new.owner_id)
        .bind(new.node_id)
        .bind(new.recipient_id)
        .bind(i64::from(new.permissions))
        .bind(&mount_name)
        .bind(&mount_key)
        .bind(&new.token)
        .bind(&new.password_hash)
        .bind(new.expires_at)
        .bind(&new.note)
        .bind(&new.label)
        .bind(new.hide_download)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        let row: ShareRow = sqlx::query_as(&format!("SELECT {SCOLS} FROM shares WHERE id = ?"))
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(Error::internal)?;
        Ok(to_share(row))
    }

    pub async fn get_share(&self, id: i64) -> Result<Option<Share>> {
        let row: Option<ShareRow> = sqlx::query_as(&format!(
            "SELECT {SCOLS} FROM shares WHERE id = ? AND {LIVE}"
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(db_err)?;
        Ok(row.map(to_share))
    }

    /// A live link by token.
    pub async fn find_link(&self, token: &str) -> Result<Option<Share>> {
        let row: Option<ShareRow> = sqlx::query_as(&format!(
            "SELECT {SCOLS} FROM shares WHERE kind = 3 AND token = ? AND {LIVE}"
        ))
        .bind(token)
        .fetch_optional(self.pool())
        .await
        .map_err(db_err)?;
        Ok(row.map(to_share))
    }

    /// The live user share mounted under this name in the user's root.
    pub async fn find_mount(&self, user_id: i64, name: &Name) -> Result<Option<Share>> {
        let row: Option<ShareRow> = sqlx::query_as(&format!(
            "SELECT {SCOLS} FROM shares WHERE recipient_id = ? AND mount_key = ? AND {LIVE}"
        ))
        .bind(user_id)
        .bind(name.key())
        .fetch_optional(self.pool())
        .await
        .map_err(db_err)?;
        Ok(row.map(to_share))
    }

    /// Live shares of a user: given by them, or received by them.
    pub async fn shares_by_owner(&self, owner_id: i64) -> Result<Vec<Share>> {
        self.query_shares(&format!("owner_id = ? AND {LIVE}"), owner_id)
            .await
    }

    pub async fn shares_for_recipient(&self, user_id: i64) -> Result<Vec<Share>> {
        self.query_shares(&format!("recipient_id = ? AND {LIVE}"), user_id)
            .await
    }

    pub async fn shares_for_node(&self, node_id: i64) -> Result<Vec<Share>> {
        self.query_shares(&format!("node_id = ? AND {LIVE}"), node_id)
            .await
    }

    async fn query_shares(&self, cond: &str, arg: i64) -> Result<Vec<Share>> {
        let rows: Vec<ShareRow> = sqlx::query_as(&format!(
            "SELECT {SCOLS} FROM shares WHERE {cond} ORDER BY id"
        ))
        .bind(arg)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(to_share).collect())
    }

    /// For each of these nodes, the kinds of live shares on it (for `oc:share-types`).
    pub async fn share_kinds_of_nodes(&self, node_ids: &[i64]) -> Result<HashMap<i64, Vec<i64>>> {
        let mut out: HashMap<i64, Vec<i64>> = HashMap::new();
        for chunk in node_ids.chunks(400) {
            let marks = vec!["?"; chunk.len()].join(",");
            let sql = format!(
                "SELECT DISTINCT node_id, kind FROM shares WHERE node_id IN ({marks}) AND {LIVE} ORDER BY kind"
            );
            let mut q = sqlx::query_as::<_, (i64, i64)>(&sql);
            for id in chunk {
                q = q.bind(id);
            }
            for (node, kind) in q.fetch_all(self.pool()).await.map_err(db_err)? {
                out.entry(node).or_default().push(kind);
            }
        }
        Ok(out)
    }

    /// Which of these node IDs belong to `owner_id`.
    pub async fn nodes_owned_by(
        &self,
        owner_id: i64,
        ids: &[i64],
    ) -> Result<std::collections::HashSet<i64>> {
        let mut out = std::collections::HashSet::new();
        for chunk in ids.chunks(400) {
            let marks = vec!["?"; chunk.len()].join(",");
            let sql = format!("SELECT id FROM nodes WHERE owner_id = ? AND id IN ({marks})");
            let mut q = sqlx::query_scalar::<_, i64>(&sql).bind(owner_id);
            for id in chunk {
                q = q.bind(id);
            }
            out.extend(q.fetch_all(self.pool()).await.map_err(db_err)?);
        }
        Ok(out)
    }

    pub async fn update_share(&self, id: i64, upd: &ShareUpdate) -> Result<Share> {
        let mut tx = self.write_tx().await?;
        let row: Option<ShareRow> =
            sqlx::query_as(&format!("SELECT {SCOLS} FROM shares WHERE id = ?"))
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        let mut s = to_share(row.ok_or(Error::NotFound)?);
        if let Some(p) = upd.permissions {
            s.permissions = p;
        }
        if let Some(p) = &upd.password_hash {
            s.password_hash.clone_from(p);
        }
        if let Some(e) = upd.expires_at {
            s.expires_at = e;
        }
        if let Some(n) = &upd.note {
            s.note.clone_from(n);
        }
        if let Some(l) = &upd.label {
            s.label.clone_from(l);
        }
        if let Some(h) = upd.hide_download {
            s.hide_download = h;
        }
        sqlx::query(
            "UPDATE shares SET permissions = ?, password_hash = ?, expires_at = ?, note = ?, label = ?, hide_download = ? WHERE id = ?",
        )
        .bind(i64::from(s.permissions))
        .bind(&s.password_hash)
        .bind(s.expires_at)
        .bind(&s.note)
        .bind(&s.label)
        .bind(s.hide_download)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(Error::internal)?;
        Ok(s)
    }

    pub async fn delete_share(&self, id: i64) -> Result<bool> {
        let r = sqlx::query("DELETE FROM shares WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(db_err)?;
        Ok(r.rows_affected() > 0)
    }

    /// Renames the recipient's mount point. The new name must be free in their root.
    pub async fn rename_mount(&self, share_id: i64, recipient_id: i64, name: &Name) -> Result<()> {
        let mut tx = self.write_tx().await?;
        let own: Option<i64> =
            sqlx::query_scalar("SELECT id FROM shares WHERE id = ? AND recipient_id = ?")
                .bind(share_id)
                .bind(recipient_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        own.ok_or(Error::NotFound)?;
        if mount_clash(&mut tx, recipient_id, name.key()).await? {
            return Err(Error::AlreadyExists);
        }
        sqlx::query("UPDATE shares SET mount_name = ?, mount_key = ? WHERE id = ?")
            .bind(name.as_str())
            .bind(name.key())
            .bind(share_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(Error::internal)?;
        Ok(())
    }

    /// Path of a node below its owner's root, e.g. `/Docs/a.txt`.
    pub async fn node_path(&self, node_id: i64) -> Result<String> {
        let names: Vec<String> = sqlx::query_scalar(
            "WITH RECURSIVE chain(id, parent_id, name, depth) AS (
                 SELECT id, parent_id, name, 0 FROM nodes WHERE id = ?1
                 UNION ALL
                 SELECT n.id, n.parent_id, n.name, c.depth + 1 FROM nodes n JOIN chain c ON n.id = c.parent_id
             )
             SELECT name FROM chain WHERE parent_id IS NOT NULL ORDER BY depth DESC",
        )
        .bind(node_id)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)?;
        Ok(format!("/{}", names.join("/")))
    }

    /// Resolves segments below `start` (a directory) without ever leaving it.
    pub async fn resolve_from(&self, start: i64, segments: &[Name]) -> Result<Option<Node>> {
        let mut conn = self.pool().acquire().await.map_err(Error::internal)?;
        let Some(mut cur) = fetch(&mut conn, start).await? else {
            return Ok(None);
        };
        for seg in segments {
            if cur.kind != NodeKind::Dir {
                return Ok(None);
            }
            let row: Option<Row> = sqlx::query_as(&format!(
                "SELECT {COLS} FROM nodes WHERE parent_id = ? AND name_key = ? AND trash_id IS NULL"
            ))
            .bind(cur.id)
            .bind(seg.key())
            .fetch_optional(&mut *conn)
            .await
            .map_err(db_err)?;
            match row.map(to_node).transpose()? {
                Some(n) => cur = n,
                None => return Ok(None),
            }
        }
        Ok(Some(cur))
    }

    /// User names for owner display; unknown IDs are left out.
    pub async fn user_names(&self, ids: &[i64]) -> Result<HashMap<i64, String>> {
        let mut out = HashMap::new();
        for chunk in ids.chunks(400) {
            let marks = vec!["?"; chunk.len()].join(",");
            let sql = format!("SELECT id, name FROM users WHERE id IN ({marks})");
            let mut q = sqlx::query_as::<_, (i64, String)>(&sql);
            for id in chunk {
                q = q.bind(id);
            }
            out.extend(q.fetch_all(self.pool()).await.map_err(db_err)?);
        }
        Ok(out)
    }

    /// Users whose name contains `needle` (case-insensitive), for the sharee search.
    pub async fn search_users(&self, needle: &str, except: i64, limit: i64) -> Result<Vec<String>> {
        let like = format!(
            "%{}%",
            needle
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        sqlx::query_scalar(
            "SELECT name FROM users WHERE disabled = 0 AND id != ? AND lower(name_key) LIKE ? ESCAPE '\\' ORDER BY name_key LIMIT ?",
        )
        .bind(except)
        .bind(like.to_lowercase())
        .bind(limit)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_db;
    use crate::{NewBlob, NewUser, WriteCondition};

    async fn user(db: &Db, name: &str) -> (i64, i64) {
        let u = db
            .create_user(NewUser {
                name,
                password_hash: "h",
                is_admin: false,
            })
            .await
            .expect("user")
            .id;
        (u, db.root_node(u).await.expect("root").id)
    }

    fn name(s: &str) -> Name {
        Name::parse(s).expect("name")
    }

    fn user_share(owner: i64, node: i64, rec: i64, perms: u8) -> NewShare {
        NewShare {
            kind: ShareKind::User,
            owner_id: owner,
            node_id: node,
            recipient_id: Some(rec),
            permissions: perms,
            token: None,
            password_hash: None,
            expires_at: None,
            note: String::new(),
            label: String::new(),
            hide_download: false,
        }
    }

    fn link(owner: i64, node: i64, token: &str) -> NewShare {
        NewShare {
            kind: ShareKind::Link,
            recipient_id: None,
            token: Some(token.into()),
            ..user_share(owner, node, 0, 1)
        }
    }

    #[tokio::test]
    async fn user_share_gets_a_free_mount_name() {
        let (_d, db) = test_db().await;
        let (a, ra) = user(&db, "anna").await;
        let (b, rb) = user(&db, "bob").await;
        let docs = db.create_dir(ra, &name("Docs")).await.expect("d").id;
        let docs2 = db.create_dir(ra, &name("Other")).await.expect("d").id;
        db.create_dir(rb, &name("Docs"))
            .await
            .expect("bob has Docs");

        let s = db
            .create_share(user_share(a, docs, b, 15))
            .await
            .expect("share");
        assert_eq!(
            s.mount_name.as_deref(),
            Some("Docs (2)"),
            "own folder keeps its name"
        );
        // idempotent for the same node and recipient
        assert_eq!(
            db.create_share(user_share(a, docs, b, 1))
                .await
                .expect("again")
                .id,
            s.id
        );
        let t = db
            .create_share(user_share(a, docs2, b, 1))
            .await
            .expect("second");
        assert_eq!(t.mount_name.as_deref(), Some("Other"));

        assert_eq!(
            db.find_mount(b, &name("Docs (2)"))
                .await
                .expect("f")
                .map(|s| s.id),
            Some(s.id)
        );
        assert!(
            db.find_mount(b, &name("Docs")).await.expect("f").is_none(),
            "own folders are not mounts"
        );
        assert!(
            db.find_mount(a, &name("Docs (2)"))
                .await
                .expect("f")
                .is_none(),
            "mounts are per recipient"
        );

        // names of mounts are taken: creating an own child with that name fails
        assert!(matches!(
            db.create_dir(rb, &name("Other")).await,
            Err(Error::AlreadyExists)
        ));
        let blob = NewBlob {
            id: format!("{:0>26}", "1"),
            size: 1,
            checksum: "c".into(),
        };
        assert!(matches!(
            db.commit_file(rb, &name("Docs (2)"), &blob, None, &WriteCondition::None)
                .await,
            Err(Error::AlreadyExists)
        ));
        // ... also by move and copy into the root
        let sub = db.create_dir(rb, &name("sub")).await.expect("sub").id;
        let f = db.create_dir(sub, &name("x")).await.expect("x").id;
        assert!(matches!(
            db.move_node(f, rb, &name("Other"), false).await,
            Err(Error::AlreadyExists)
        ));
        assert!(matches!(
            db.copy_node(f, rb, &name("Other"), false).await,
            Err(Error::AlreadyExists)
        ));

        // renaming a mount obeys the same rule
        assert!(matches!(
            db.rename_mount(s.id, b, &name("Other")).await,
            Err(Error::AlreadyExists)
        ));
        assert!(
            matches!(
                db.rename_mount(s.id, a, &name("x")).await,
                Err(Error::NotFound)
            ),
            "only the recipient"
        );
        db.rename_mount(s.id, b, &name("Team"))
            .await
            .expect("rename");
        assert_eq!(
            db.find_mount(b, &name("Team"))
                .await
                .expect("f")
                .map(|s| s.id),
            Some(s.id)
        );
        db.create_dir(rb, &name("Docs (2)"))
            .await
            .expect("old name is free again");
    }

    #[tokio::test]
    async fn links_tokens_expiry_and_updates() {
        let (_d, db) = test_db().await;
        let (a, ra) = user(&db, "anna").await;
        let docs = db.create_dir(ra, &name("Docs")).await.expect("d").id;
        let l = db
            .create_share(link(a, docs, "tok123"))
            .await
            .expect("link");
        assert_eq!((l.mount_name, l.token.as_deref()), (None, Some("tok123")));
        assert!(
            matches!(
                db.create_share(link(a, docs, "tok123")).await,
                Err(Error::AlreadyExists)
            ),
            "tokens are unique"
        );
        let l2 = db
            .create_share(link(a, docs, "tok456"))
            .await
            .expect("several links per node");
        assert_ne!(l.id, l2.id);
        assert_eq!(
            db.find_link("tok123").await.expect("f").map(|s| s.id),
            Some(l.id)
        );
        assert!(db.find_link("nope").await.expect("f").is_none());

        let u = db
            .update_share(
                l.id,
                &ShareUpdate {
                    permissions: Some(15),
                    password_hash: Some(Some("hash".into())),
                    expires_at: Some(Some(32_503_680_000)),
                    note: Some("n".into()),
                    ..ShareUpdate::default()
                },
            )
            .await
            .expect("update");
        assert_eq!(
            (
                u.permissions,
                u.password_hash.as_deref(),
                u.expires_at,
                u.note.as_str()
            ),
            (15, Some("hash"), Some(32_503_680_000), "n")
        );
        let u = db
            .update_share(
                l.id,
                &ShareUpdate {
                    password_hash: Some(None),
                    expires_at: Some(None),
                    ..ShareUpdate::default()
                },
            )
            .await
            .expect("clear");
        assert_eq!(
            (u.password_hash, u.expires_at, u.permissions),
            (None, None, 15)
        );

        // an expired link is gone for lookups
        db.update_share(
            l.id,
            &ShareUpdate {
                expires_at: Some(Some(1)),
                ..ShareUpdate::default()
            },
        )
        .await
        .expect("expire");
        assert!(db.find_link("tok123").await.expect("f").is_none());
        assert!(db.get_share(l.id).await.expect("g").is_none());
        assert!(
            db.shares_for_node(docs)
                .await
                .expect("l")
                .iter()
                .all(|s| s.id != l.id)
        );

        assert!(db.delete_share(l2.id).await.expect("delete"));
        assert!(!db.delete_share(l2.id).await.expect("again"));
    }

    #[tokio::test]
    async fn shares_follow_their_node() {
        let (_d, db) = test_db().await;
        let (a, ra) = user(&db, "anna").await;
        let (b, _) = user(&db, "bob").await;
        let docs = db.create_dir(ra, &name("Docs")).await.expect("d").id;
        let dir = db.create_dir(ra, &name("Dir")).await.expect("d").id;
        let s = db
            .create_share(user_share(a, docs, b, 3))
            .await
            .expect("share");
        // moving the node keeps the share, the path changes
        db.move_node(docs, dir, &name("Moved"), false)
            .await
            .expect("move");
        assert_eq!(db.node_path(docs).await.expect("p"), "/Dir/Moved");
        assert_eq!(
            db.get_share(s.id).await.expect("g").map(|s| s.permissions),
            Some(3)
        );
        // deleting the node ends it
        db.delete_node(dir, None).await.expect("delete");
        assert!(db.get_share(s.id).await.expect("g").is_none());
        // deleting a user removes their shares both ways
        let n2 = db.create_dir(ra, &name("N2")).await.expect("n").id;
        let s2 = db
            .create_share(user_share(a, n2, b, 1))
            .await
            .expect("share");
        db.delete_user(b).await.expect("delete bob");
        assert!(db.get_share(s2.id).await.expect("g").is_none());
        assert_eq!(db.node_path(ra).await.expect("p"), "/");
    }

    #[tokio::test]
    async fn resolve_from_stays_inside_and_root_cannot_be_shared() {
        let (_d, db) = test_db().await;
        let (a, ra) = user(&db, "anna").await;
        let (b, _) = user(&db, "bob").await;
        let top = db.create_dir(ra, &name("Top")).await.expect("d").id;
        let sub = db.create_dir(top, &name("sub")).await.expect("d").id;
        let found = db
            .resolve_from(top, &[name("sub")])
            .await
            .expect("r")
            .expect("some");
        assert_eq!(found.id, sub);
        assert!(
            db.resolve_from(top, &[name("nope")])
                .await
                .expect("r")
                .is_none()
        );
        assert!(db.resolve_from(top, &[]).await.expect("r").map(|n| n.id) == Some(top));
        assert!(matches!(
            db.create_share(user_share(a, ra, b, 1)).await,
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            db.create_share(user_share(a, 99_999, b, 1)).await,
            Err(Error::NotFound)
        ));
        assert_eq!(
            db.share_kinds_of_nodes(&[top, sub]).await.expect("k").len(),
            0
        );
        db.create_share(user_share(a, sub, b, 1)).await.expect("s");
        db.create_share(link(a, sub, "t1")).await.expect("l");
        assert_eq!(
            db.share_kinds_of_nodes(&[top, sub]).await.expect("k")[&sub],
            vec![0, 3]
        );
        assert_eq!(
            db.search_users("BO", a, 10).await.expect("s"),
            vec!["bob".to_owned()]
        );
        assert!(
            db.search_users("an", a, 10).await.expect("s").is_empty(),
            "never the caller"
        );
    }
}
