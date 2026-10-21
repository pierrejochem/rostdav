//! The node tree: directories and files, ETags, quota accounting.
//!
//! All mutations run in one `BEGIN IMMEDIATE` transaction and renew the ETags
//! of every ancestor (ADR 0002). Blob rows are inserted in the same
//! transaction as the node that references them, so the database never
//! references a blob that is not completely on disk (the caller stores the blob
//! first).
//!
//! Until shares exist (M9) every operation stays inside one owner's tree.

use rostdav_core::{Error, LogicalPath, Name, Result};
use sqlx::SqliteConnection;

use crate::Db;
use crate::users::{new_etag, now_secs};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Dir,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub id: i64,
    pub owner_id: i64,
    /// `None` only for the owner's root node.
    pub parent_id: Option<i64>,
    pub name: String,
    pub kind: NodeKind,
    /// File size in bytes; always 0 for directories (see [`Db::subtree_size`]).
    pub size: i64,
    pub mtime: i64,
    pub etag: String,
    pub blob_id: Option<String>,
    pub checksum: Option<String>,
    /// Verbatim `OC-Checksum` sent by the client, e.g. `SHA1:…`.
    pub client_checksum: Option<String>,
    /// Unix time the content was stored; 0 if unknown.
    pub upload_time: i64,
}

/// A blob that is already completely stored on disk.
#[derive(Clone, Debug)]
pub struct NewBlob {
    pub id: String,
    pub size: i64,
    pub checksum: String,
}

/// Precondition of a write, evaluated inside the transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteCondition {
    None,
    /// `If-None-Match: *`
    MustNotExist,
    /// `If-Match: <etag>`
    IfMatch(String),
}

#[derive(Clone, Debug)]
pub struct Written {
    pub node: Node,
    /// `true` if an existing file was replaced.
    pub replaced: bool,
}

const COLS: &str = "id, owner_id, parent_id, name, kind, size, mtime, etag, blob_id, checksum, client_checksum, upload_time";

type Row = (
    i64,
    i64,
    Option<i64>,
    String,
    String,
    i64,
    i64,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
);

fn to_node(r: Row) -> Result<Node> {
    let kind = match r.4.as_str() {
        "file" => NodeKind::File,
        "dir" => NodeKind::Dir,
        _ => return Err(Error::internal(std::io::Error::other("unknown node kind"))),
    };
    Ok(Node {
        id: r.0,
        owner_id: r.1,
        parent_id: r.2,
        name: r.3,
        kind,
        size: r.5,
        mtime: r.6,
        etag: r.7,
        blob_id: r.8,
        checksum: r.9,
        client_checksum: r.10,
        upload_time: r.11,
    })
}

fn db_err(e: sqlx::Error) -> Error {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => Error::AlreadyExists,
        _ => Error::internal(e),
    }
}

async fn fetch(conn: &mut SqliteConnection, id: i64) -> Result<Option<Node>> {
    let row: Option<Row> = sqlx::query_as(&format!("SELECT {COLS} FROM nodes WHERE id = ?"))
        .bind(id)
        .fetch_optional(conn)
        .await
        .map_err(db_err)?;
    row.map(to_node).transpose()
}

async fn require(conn: &mut SqliteConnection, id: i64) -> Result<Node> {
    fetch(conn, id).await?.ok_or(Error::NotFound)
}

async fn find_child(
    conn: &mut SqliteConnection,
    parent: i64,
    name_key: &str,
) -> Result<Option<Node>> {
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM nodes WHERE parent_id = ? AND name_key = ?"
    ))
    .bind(parent)
    .bind(name_key)
    .fetch_optional(conn)
    .await
    .map_err(db_err)?;
    row.map(to_node).transpose()
}

/// Renews ETag and mtime of `start` and all its ancestors.
async fn touch_chain(conn: &mut SqliteConnection, start: i64, now: i64) -> Result<()> {
    sqlx::query(
        "WITH RECURSIVE chain(id, parent_id) AS (
             SELECT id, parent_id FROM nodes WHERE id = ?1
             UNION ALL
             SELECT n.id, n.parent_id FROM nodes n JOIN chain c ON n.id = c.parent_id
         )
         UPDATE nodes SET etag = ?2, mtime = ?3, updated_at = ?3
         WHERE id IN (SELECT id FROM chain)",
    )
    .bind(start)
    .bind(new_etag())
    .bind(now)
    .execute(conn)
    .await
    .map_err(db_err)?;
    Ok(())
}

async fn subtree_size(conn: &mut SqliteConnection, id: i64) -> Result<i64> {
    sqlx::query_scalar(
        "WITH RECURSIVE sub(id) AS (
             SELECT id FROM nodes WHERE id = ?1
             UNION ALL
             SELECT n.id FROM nodes n JOIN sub s ON n.parent_id = s.id
         )
         SELECT COALESCE(SUM(size), 0) FROM nodes WHERE id IN (SELECT id FROM sub)",
    )
    .bind(id)
    .fetch_one(conn)
    .await
    .map_err(db_err)
}

/// Is `candidate` equal to `ancestor` or located below it?
async fn is_within(conn: &mut SqliteConnection, candidate: i64, ancestor: i64) -> Result<bool> {
    sqlx::query_scalar(
        "WITH RECURSIVE chain(id, parent_id) AS (
             SELECT id, parent_id FROM nodes WHERE id = ?1
             UNION ALL
             SELECT n.id, n.parent_id FROM nodes n JOIN chain c ON n.id = c.parent_id
         )
         SELECT EXISTS(SELECT 1 FROM chain WHERE id = ?2)",
    )
    .bind(candidate)
    .bind(ancestor)
    .fetch_one(conn)
    .await
    .map_err(db_err)
}

/// Adjusts the owner's usage; refuses to exceed the quota when growing.
async fn adjust_used(conn: &mut SqliteConnection, owner: i64, delta: i64) -> Result<()> {
    if delta == 0 {
        return Ok(());
    }
    let (quota, used): (Option<i64>, i64) =
        sqlx::query_as("SELECT quota_bytes, used_bytes FROM users WHERE id = ?")
            .bind(owner)
            .fetch_one(&mut *conn)
            .await
            .map_err(db_err)?;
    let new_used = used.saturating_add(delta).max(0);
    if delta > 0 && quota.is_some_and(|q| new_used > q) {
        return Err(Error::QuotaExceeded);
    }
    sqlx::query("UPDATE users SET used_bytes = ? WHERE id = ?")
        .bind(new_used)
        .bind(owner)
        .execute(conn)
        .await
        .map_err(db_err)?;
    Ok(())
}

async fn require_dir(conn: &mut SqliteConnection, id: i64) -> Result<Node> {
    let n = require(conn, id).await?;
    if n.kind != NodeKind::Dir {
        return Err(Error::Conflict("parent is not a directory"));
    }
    Ok(n)
}

impl Db {
    async fn write_tx(&self) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>> {
        // IMMEDIATE: take the write lock up front; a deferred read-then-write
        // transaction can fail with SQLITE_BUSY that busy_timeout cannot cure.
        self.pool()
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(Error::internal)
    }

    /// Sets or clears the owner's quota (admin CLI, tests).
    pub async fn set_quota(&self, owner_id: i64, quota: Option<i64>) -> Result<()> {
        sqlx::query("UPDATE users SET quota_bytes = ? WHERE id = ?")
            .bind(quota)
            .bind(owner_id)
            .execute(self.pool())
            .await
            .map_err(db_err)?;
        Ok(())
    }

    /// `(quota_bytes, used_bytes)` of a user.
    pub async fn quota_info(&self, owner_id: i64) -> Result<(Option<i64>, i64)> {
        sqlx::query_as("SELECT quota_bytes, used_bytes FROM users WHERE id = ?")
            .bind(owner_id)
            .fetch_one(self.pool())
            .await
            .map_err(db_err)
    }

    /// Bytes the owner may still add, or `None` without a quota.
    pub async fn quota_headroom(&self, owner_id: i64) -> Result<Option<i64>> {
        let (quota, used): (Option<i64>, i64) =
            sqlx::query_as("SELECT quota_bytes, used_bytes FROM users WHERE id = ?")
                .bind(owner_id)
                .fetch_one(self.pool())
                .await
                .map_err(db_err)?;
        Ok(quota.map(|q| (q - used).max(0)))
    }

    pub async fn node_by_id(&self, id: i64) -> Result<Option<Node>> {
        let mut conn = self.pool().acquire().await.map_err(Error::internal)?;
        fetch(&mut conn, id).await
    }

    pub async fn root_node(&self, owner_id: i64) -> Result<Node> {
        let row: Option<Row> = sqlx::query_as(&format!(
            "SELECT {COLS} FROM nodes WHERE owner_id = ? AND parent_id IS NULL"
        ))
        .bind(owner_id)
        .fetch_optional(self.pool())
        .await
        .map_err(db_err)?;
        row.map(to_node).transpose()?.ok_or(Error::NotFound)
    }

    /// Resolves a path below the owner's root. `None` if a segment is missing
    /// or a non-final segment is a file.
    pub async fn resolve(&self, owner_id: i64, path: &LogicalPath) -> Result<Option<Node>> {
        let mut conn = self.pool().acquire().await.map_err(Error::internal)?;
        let mut cur = self.root_node(owner_id).await?;
        for seg in path.segments() {
            if cur.kind != NodeKind::Dir {
                return Ok(None);
            }
            match find_child(&mut conn, cur.id, seg.key()).await? {
                Some(n) => cur = n,
                None => return Ok(None),
            }
        }
        Ok(Some(cur))
    }

    /// Children ordered by name.
    pub async fn children(&self, parent_id: i64) -> Result<Vec<Node>> {
        let rows: Vec<Row> = sqlx::query_as(&format!(
            "SELECT {COLS} FROM nodes WHERE parent_id = ? ORDER BY name_key"
        ))
        .bind(parent_id)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)?;
        rows.into_iter().map(to_node).collect()
    }

    /// Total size of all files in the subtree (what clients show for a folder).
    pub async fn subtree_size(&self, id: i64) -> Result<i64> {
        let mut conn = self.pool().acquire().await.map_err(Error::internal)?;
        subtree_size(&mut conn, id).await
    }

    pub async fn create_dir(&self, parent_id: i64, name: &Name) -> Result<Node> {
        let now = now_secs();
        let mut tx = self.write_tx().await?;
        let parent = require_dir(&mut tx, parent_id).await?;
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO nodes (owner_id, parent_id, name, name_key, kind, mtime, etag, created_at, updated_at)
             VALUES (?, ?, ?, ?, 'dir', ?, ?, ?, ?) RETURNING id",
        )
        .bind(parent.owner_id)
        .bind(parent.id)
        .bind(name.as_str())
        .bind(name.key())
        .bind(now)
        .bind(new_etag())
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        touch_chain(&mut tx, parent.id, now).await?;
        let node = require(&mut tx, id).await?;
        tx.commit().await.map_err(Error::internal)?;
        Ok(node)
    }

    /// Creates or replaces a file (ADR 0002, write flow step 3).
    ///
    /// The old blob of a replaced file stays registered; it is removed by
    /// garbage collection once nothing references it.
    pub async fn commit_file(
        &self,
        parent_id: i64,
        name: &Name,
        blob: &NewBlob,
        mtime: Option<i64>,
        cond: &WriteCondition,
    ) -> Result<Written> {
        self.commit_file_ext(parent_id, name, blob, mtime, None, cond)
            .await
    }

    /// Like [`commit_file`](Self::commit_file), also recording the client's checksum.
    pub async fn commit_file_ext(
        &self,
        parent_id: i64,
        name: &Name,
        blob: &NewBlob,
        mtime: Option<i64>,
        client_checksum: Option<&str>,
        cond: &WriteCondition,
    ) -> Result<Written> {
        let now = now_secs();
        let mtime = mtime.unwrap_or(now);
        let mut tx = self.write_tx().await?;
        let parent = require_dir(&mut tx, parent_id).await?;
        let existing = find_child(&mut tx, parent.id, name.key()).await?;

        match (cond, &existing) {
            (WriteCondition::MustNotExist, Some(_)) => return Err(Error::PreconditionFailed),
            (WriteCondition::IfMatch(want), Some(n)) if &n.etag != want => {
                return Err(Error::PreconditionFailed);
            }
            (WriteCondition::IfMatch(_), None) => return Err(Error::PreconditionFailed),
            _ => {}
        }
        if existing.as_ref().is_some_and(|n| n.kind == NodeKind::Dir) {
            return Err(Error::Conflict("target is a directory"));
        }

        sqlx::query("INSERT INTO blobs (id, size, checksum, created_at) VALUES (?, ?, ?, ?)")
            .bind(&blob.id)
            .bind(blob.size)
            .bind(&blob.checksum)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        let (id, delta, replaced) = match existing {
            Some(old) => {
                sqlx::query(
                    "UPDATE nodes SET size = ?, mtime = ?, etag = ?, blob_id = ?, checksum = ?, client_checksum = ?,
                     upload_time = ?, updated_at = ?
                     WHERE id = ?",
                )
                .bind(blob.size)
                .bind(mtime)
                .bind(new_etag())
                .bind(&blob.id)
                .bind(&blob.checksum)
                .bind(client_checksum)
                .bind(now)
                .bind(now)
                .bind(old.id)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
                (old.id, blob.size - old.size, true)
            }
            None => {
                let id: i64 = sqlx::query_scalar(
                    "INSERT INTO nodes (owner_id, parent_id, name, name_key, kind, size, mtime, etag, blob_id, checksum, client_checksum, upload_time, created_at, updated_at)
                     VALUES (?, ?, ?, ?, 'file', ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
                )
                .bind(parent.owner_id)
                .bind(parent.id)
                .bind(name.as_str())
                .bind(name.key())
                .bind(blob.size)
                .bind(mtime)
                .bind(new_etag())
                .bind(&blob.id)
                .bind(&blob.checksum)
                .bind(client_checksum)
                .bind(now)
                .bind(now)
                .bind(now)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_err)?;
                (id, blob.size, false)
            }
        };

        adjust_used(&mut tx, parent.owner_id, delta).await?;
        touch_chain(&mut tx, parent.id, now).await?;
        let node = require(&mut tx, id).await?;
        tx.commit().await.map_err(Error::internal)?;
        Ok(Written { node, replaced })
    }

    /// Deletes a node with its subtree. The root cannot be deleted.
    pub async fn delete_node(&self, id: i64, if_match: Option<&str>) -> Result<()> {
        let now = now_secs();
        let mut tx = self.write_tx().await?;
        let node = require(&mut tx, id).await?;
        let parent = node
            .parent_id
            .ok_or(Error::Conflict("cannot delete the root"))?;
        if if_match.is_some_and(|want| want != node.etag) {
            return Err(Error::PreconditionFailed);
        }
        let freed = subtree_size(&mut tx, id).await?;
        sqlx::query("DELETE FROM nodes WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        adjust_used(&mut tx, node.owner_id, -freed).await?;
        touch_chain(&mut tx, parent, now).await?;
        tx.commit().await.map_err(Error::internal)?;
        Ok(())
    }

    /// Moves/renames a node; the node ID is preserved. With `overwrite`, an
    /// existing target is deleted first.
    pub async fn move_node(
        &self,
        id: i64,
        new_parent: i64,
        name: &Name,
        overwrite: bool,
    ) -> Result<Written> {
        let now = now_secs();
        let mut tx = self.write_tx().await?;
        let node = require(&mut tx, id).await?;
        let old_parent = node
            .parent_id
            .ok_or(Error::Conflict("cannot move the root"))?;
        let parent = require_dir(&mut tx, new_parent).await?;
        if parent.owner_id != node.owner_id {
            return Err(Error::Forbidden);
        }
        if is_within(&mut tx, parent.id, node.id).await? {
            return Err(Error::Conflict("cannot move into itself"));
        }
        let replaced = clear_target(&mut tx, &parent, name, overwrite, node.id).await?;
        sqlx::query(
            "UPDATE nodes SET parent_id = ?, name = ?, name_key = ?, updated_at = ? WHERE id = ?",
        )
        .bind(parent.id)
        .bind(name.as_str())
        .bind(name.key())
        .bind(now)
        .bind(node.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        touch_chain(&mut tx, old_parent, now).await?;
        touch_chain(&mut tx, parent.id, now).await?;
        let node = require(&mut tx, id).await?;
        tx.commit().await.map_err(Error::internal)?;
        Ok(Written { node, replaced })
    }

    /// Copies a subtree. New nodes get new IDs and ETags and reference the
    /// same blobs.
    pub async fn copy_node(
        &self,
        id: i64,
        new_parent: i64,
        name: &Name,
        overwrite: bool,
    ) -> Result<Written> {
        let now = now_secs();
        let mut tx = self.write_tx().await?;
        let src = require(&mut tx, id).await?;
        if src.parent_id.is_none() {
            return Err(Error::Conflict("cannot copy the root"));
        }
        let parent = require_dir(&mut tx, new_parent).await?;
        if parent.owner_id != src.owner_id {
            return Err(Error::Forbidden);
        }
        if is_within(&mut tx, parent.id, src.id).await? {
            return Err(Error::Conflict("cannot copy into itself"));
        }
        let replaced = clear_target(&mut tx, &parent, name, overwrite, src.id).await?;

        let added = subtree_size(&mut tx, src.id).await?;
        adjust_used(&mut tx, src.owner_id, added).await?;

        let new_id = copy_one(&mut tx, &src, parent.id, name.as_str(), name.key(), now).await?;
        let mut stack = vec![(src.id, new_id)];
        while let Some((old_dir, new_dir)) = stack.pop() {
            let rows: Vec<Row> =
                sqlx::query_as(&format!("SELECT {COLS} FROM nodes WHERE parent_id = ?"))
                    .bind(old_dir)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(db_err)?;
            for row in rows {
                let child = to_node(row)?;
                // Stored names were validated on the way in.
                let key = Name::parse(&child.name)?.key().to_owned();
                let nid = copy_one(&mut tx, &child, new_dir, &child.name, &key, now).await?;
                if child.kind == NodeKind::Dir {
                    stack.push((child.id, nid));
                }
            }
        }
        touch_chain(&mut tx, parent.id, now).await?;
        let node = require(&mut tx, new_id).await?;
        tx.commit().await.map_err(Error::internal)?;
        Ok(Written { node, replaced })
    }

    /// Removes blob rows that no node references and returns their IDs; the
    /// caller then deletes the files.
    pub async fn delete_unreferenced_blobs(&self) -> Result<Vec<String>> {
        sqlx::query_scalar(
            "DELETE FROM blobs
             WHERE id NOT IN (SELECT blob_id FROM nodes WHERE blob_id IS NOT NULL)
             RETURNING id",
        )
        .fetch_all(self.pool())
        .await
        .map_err(db_err)
    }
}

/// Handles an existing node at the target of a move/copy.
async fn clear_target(
    tx: &mut SqliteConnection,
    parent: &Node,
    name: &Name,
    overwrite: bool,
    moving: i64,
) -> Result<bool> {
    let Some(target) = find_child(tx, parent.id, name.key()).await? else {
        return Ok(false);
    };
    if target.id == moving {
        return Err(Error::Conflict("source and destination are identical"));
    }
    if !overwrite {
        return Err(Error::PreconditionFailed);
    }
    let freed = subtree_size(tx, target.id).await?;
    sqlx::query("DELETE FROM nodes WHERE id = ?")
        .bind(target.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    adjust_used(tx, target.owner_id, -freed).await?;
    Ok(true)
}

async fn copy_one(
    conn: &mut SqliteConnection,
    src: &Node,
    parent: i64,
    name: &str,
    name_key: &str,
    now: i64,
) -> Result<i64> {
    let kind = match src.kind {
        NodeKind::File => "file",
        NodeKind::Dir => "dir",
    };
    sqlx::query_scalar(
        "INSERT INTO nodes (owner_id, parent_id, name, name_key, kind, size, mtime, etag, blob_id, checksum, client_checksum, upload_time, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(src.owner_id)
    .bind(parent)
    .bind(name)
    .bind(name_key)
    .bind(kind)
    .bind(src.size)
    .bind(src.mtime)
    .bind(new_etag())
    .bind(&src.blob_id)
    .bind(&src.checksum)
    .bind(&src.client_checksum)
    .bind(if src.kind == NodeKind::File { now } else { 0 })
    .bind(now)
    .bind(now)
    .fetch_one(conn)
    .await
    .map_err(db_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NewUser;
    use crate::tests::test_db;

    fn n(s: &str) -> Name {
        Name::parse(s).expect("name")
    }

    fn blob(tag: &str, size: i64) -> NewBlob {
        // 26 chars like a ULID; the DB only checks the length.
        NewBlob {
            id: format!("{tag:0>26}"),
            size,
            checksum: "c".into(),
        }
    }

    async fn user(db: &Db, name: &str) -> (i64, i64) {
        let u = db
            .create_user(NewUser {
                name,
                password_hash: "h",
                is_admin: false,
            })
            .await
            .expect("user");
        (u.id, db.root_node(u.id).await.expect("root").id)
    }

    async fn put(db: &Db, parent: i64, name: &str, tag: &str, size: i64) -> Node {
        db.commit_file(
            parent,
            &n(name),
            &blob(tag, size),
            None,
            &WriteCondition::None,
        )
        .await
        .expect("commit")
        .node
    }

    async fn etag(db: &Db, id: i64) -> String {
        db.node_by_id(id).await.expect("q").expect("node").etag
    }

    async fn used(db: &Db, owner: i64) -> i64 {
        sqlx::query_scalar("SELECT used_bytes FROM users WHERE id = ?")
            .bind(owner)
            .fetch_one(db.pool())
            .await
            .expect("used")
    }

    #[tokio::test]
    async fn create_dir_resolve_and_conflict() {
        let (_d, db) = test_db().await;
        let (uid, root) = user(&db, "anna").await;
        let a = db.create_dir(root, &n("a")).await.expect("a");
        let b = db.create_dir(a.id, &n("b")).await.expect("b");
        let p = LogicalPath::from_url_path("/a/b").expect("p");
        assert_eq!(db.resolve(uid, &p).await.expect("r"), Some(b));
        assert!(matches!(
            db.create_dir(root, &n("a")).await,
            Err(Error::AlreadyExists)
        ));
        // NFC-equivalent name conflicts as well
        db.create_dir(root, &n("\u{e9}")).await.expect("composed");
        assert!(db.create_dir(root, &n("e\u{301}")).await.is_err());
        let missing = LogicalPath::from_url_path("/a/x/y").expect("p");
        assert_eq!(db.resolve(uid, &missing).await.expect("r"), None);
        assert_eq!(
            db.resolve(uid, &LogicalPath::root())
                .await
                .expect("r")
                .map(|r| r.id),
            Some(root)
        );
    }

    #[tokio::test]
    async fn changes_renew_all_ancestor_etags_but_not_siblings() {
        let (_d, db) = test_db().await;
        let (_, root) = user(&db, "anna").await;
        let a = db.create_dir(root, &n("a")).await.expect("a");
        let b = db.create_dir(a.id, &n("b")).await.expect("b");
        let sib = db.create_dir(root, &n("sib")).await.expect("sib");
        let (er, ea, eb, es) = (
            etag(&db, root).await,
            etag(&db, a.id).await,
            etag(&db, b.id).await,
            etag(&db, sib.id).await,
        );
        put(&db, b.id, "f.txt", "1", 3).await;
        assert_ne!(etag(&db, root).await, er);
        assert_ne!(etag(&db, a.id).await, ea);
        assert_ne!(etag(&db, b.id).await, eb);
        assert_eq!(etag(&db, sib.id).await, es);
    }

    #[tokio::test]
    async fn put_replace_and_preconditions() {
        let (_d, db) = test_db().await;
        let (_, root) = user(&db, "anna").await;
        let w = db
            .commit_file(
                root,
                &n("f"),
                &blob("1", 5),
                Some(1000),
                &WriteCondition::MustNotExist,
            )
            .await
            .expect("create");
        assert!(!w.replaced);
        assert_eq!(w.node.mtime, 1000);
        let again = db
            .commit_file(
                root,
                &n("f"),
                &blob("2", 5),
                None,
                &WriteCondition::MustNotExist,
            )
            .await;
        assert!(matches!(again, Err(Error::PreconditionFailed)));
        let stale = db
            .commit_file(
                root,
                &n("f"),
                &blob("2", 5),
                None,
                &WriteCondition::IfMatch("nope".into()),
            )
            .await;
        assert!(matches!(stale, Err(Error::PreconditionFailed)));
        let missing = db
            .commit_file(
                root,
                &n("g"),
                &blob("2", 5),
                None,
                &WriteCondition::IfMatch("x".into()),
            )
            .await;
        assert!(matches!(missing, Err(Error::PreconditionFailed)));
        let ok = db
            .commit_file(
                root,
                &n("f"),
                &blob("3", 7),
                None,
                &WriteCondition::IfMatch(w.node.etag.clone()),
            )
            .await
            .expect("replace");
        assert!(ok.replaced);
        assert_eq!(ok.node.id, w.node.id, "file ID stays on replace");
        assert_ne!(ok.node.etag, w.node.etag);
        assert_eq!(ok.node.size, 7);
        // failed attempts registered no blob rows
        assert_eq!(db.count_blobs().await.expect("c"), 2);
    }

    #[tokio::test]
    async fn put_onto_directory_or_below_file_fails() {
        let (_d, db) = test_db().await;
        let (_, root) = user(&db, "anna").await;
        let d = db.create_dir(root, &n("d")).await.expect("d");
        let f = put(&db, root, "f", "1", 1).await;
        let onto_dir = db
            .commit_file(root, &n("d"), &blob("2", 1), None, &WriteCondition::None)
            .await;
        assert!(matches!(onto_dir, Err(Error::Conflict(_))));
        let below_file = db
            .commit_file(f.id, &n("x"), &blob("3", 1), None, &WriteCondition::None)
            .await;
        assert!(matches!(below_file, Err(Error::Conflict(_))));
        assert!(db.create_dir(f.id, &n("x")).await.is_err());
        assert!(db.children(d.id).await.expect("c").is_empty());
    }

    #[tokio::test]
    async fn quota_is_enforced_and_accounted() {
        let (_d, db) = test_db().await;
        let (uid, root) = user(&db, "anna").await;
        sqlx::query("UPDATE users SET quota_bytes = 10 WHERE id = ?")
            .bind(uid)
            .execute(db.pool())
            .await
            .expect("quota");
        let f = put(&db, root, "f", "1", 6).await;
        assert_eq!(used(&db, uid).await, 6);
        let over = db
            .commit_file(root, &n("g"), &blob("2", 5), None, &WriteCondition::None)
            .await;
        assert!(matches!(over, Err(Error::QuotaExceeded)));
        assert_eq!(used(&db, uid).await, 6);
        // replacing with a bigger file counts only the difference
        put(&db, root, "f", "3", 10).await;
        assert_eq!(used(&db, uid).await, 10);
        db.delete_node(f.id, None).await.expect("delete");
        assert_eq!(used(&db, uid).await, 0);
    }

    #[tokio::test]
    async fn delete_subtree_and_gc() {
        let (_d, db) = test_db().await;
        let (uid, root) = user(&db, "anna").await;
        let a = db.create_dir(root, &n("a")).await.expect("a");
        let b = db.create_dir(a.id, &n("b")).await.expect("b");
        put(&db, a.id, "f1", "1", 4).await;
        put(&db, b.id, "f2", "2", 6).await;
        let keep = put(&db, root, "keep", "3", 1).await;
        assert_eq!(db.subtree_size(a.id).await.expect("s"), 10);
        let before = etag(&db, root).await;
        assert!(matches!(
            db.delete_node(a.id, Some("wrong")).await,
            Err(Error::PreconditionFailed)
        ));
        db.delete_node(a.id, None).await.expect("delete");
        assert_ne!(etag(&db, root).await, before);
        assert!(db.node_by_id(b.id).await.expect("q").is_none());
        assert_eq!(used(&db, uid).await, 1);
        let mut gone = db.delete_unreferenced_blobs().await.expect("gc");
        gone.sort();
        assert_eq!(gone, vec![format!("{:0>26}", "1"), format!("{:0>26}", "2")]);
        assert!(db.node_by_id(keep.id).await.expect("q").is_some());
        assert!(matches!(
            db.delete_node(root, None).await,
            Err(Error::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn move_keeps_id_and_updates_both_chains() {
        let (_d, db) = test_db().await;
        let (_, root) = user(&db, "anna").await;
        let a = db.create_dir(root, &n("a")).await.expect("a");
        let b = db.create_dir(root, &n("b")).await.expect("b");
        let f = put(&db, a.id, "f", "1", 2).await;
        let (ea, eb) = (etag(&db, a.id).await, etag(&db, b.id).await);
        let moved = db
            .move_node(f.id, b.id, &n("g"), false)
            .await
            .expect("move");
        assert_eq!(moved.node.id, f.id);
        assert_eq!(moved.node.name, "g");
        assert_ne!(etag(&db, a.id).await, ea);
        assert_ne!(etag(&db, b.id).await, eb);
        assert!(db.children(a.id).await.expect("c").is_empty());
    }

    #[tokio::test]
    async fn move_rejects_cycles_root_and_existing_target() {
        let (_d, db) = test_db().await;
        let (_, root) = user(&db, "anna").await;
        let a = db.create_dir(root, &n("a")).await.expect("a");
        let b = db.create_dir(a.id, &n("b")).await.expect("b");
        assert!(matches!(
            db.move_node(a.id, b.id, &n("a"), false).await,
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            db.move_node(a.id, a.id, &n("a"), false).await,
            Err(Error::Conflict(_))
        ));
        assert!(db.move_node(root, a.id, &n("r"), false).await.is_err());
        let x = put(&db, root, "x", "1", 1).await;
        put(&db, a.id, "x", "2", 1).await;
        assert!(matches!(
            db.move_node(x.id, a.id, &n("x"), false).await,
            Err(Error::PreconditionFailed)
        ));
        let over = db
            .move_node(x.id, a.id, &n("x"), true)
            .await
            .expect("overwrite");
        assert!(over.replaced);
        assert_eq!(db.children(a.id).await.expect("c").len(), 2);
    }

    #[tokio::test]
    async fn copy_creates_new_ids_shares_blobs_and_counts_quota() {
        let (_d, db) = test_db().await;
        let (uid, root) = user(&db, "anna").await;
        let a = db.create_dir(root, &n("a")).await.expect("a");
        let f = put(&db, a.id, "f", "1", 4).await;
        let sub = db.create_dir(a.id, &n("sub")).await.expect("sub");
        put(&db, sub.id, "g", "2", 6).await;
        assert_eq!(used(&db, uid).await, 10);
        let c = db
            .copy_node(a.id, root, &n("a2"), false)
            .await
            .expect("copy");
        assert_ne!(c.node.id, a.id);
        assert_eq!(used(&db, uid).await, 20);
        let kids = db.children(c.node.id).await.expect("c");
        assert_eq!(kids.len(), 2);
        let copied_f = kids.iter().find(|k| k.name == "f").expect("f");
        assert_ne!(copied_f.id, f.id);
        assert_eq!(copied_f.blob_id, f.blob_id);
        assert_ne!(copied_f.etag, f.etag);
        assert_eq!(db.subtree_size(c.node.id).await.expect("s"), 10);
        // deleting the original keeps the shared blobs referenced
        db.delete_node(a.id, None).await.expect("delete");
        assert!(db.delete_unreferenced_blobs().await.expect("gc").is_empty());
        // copy into itself / onto existing target
        assert!(matches!(
            db.copy_node(c.node.id, c.node.id, &n("x"), false).await,
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            db.copy_node(c.node.id, root, &n("a2"), true).await,
            Err(Error::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn copy_over_quota_changes_nothing() {
        let (_d, db) = test_db().await;
        let (uid, root) = user(&db, "anna").await;
        sqlx::query("UPDATE users SET quota_bytes = 15 WHERE id = ?")
            .bind(uid)
            .execute(db.pool())
            .await
            .expect("quota");
        let f = put(&db, root, "f", "1", 10).await;
        let err = db.copy_node(f.id, root, &n("g"), false).await;
        assert!(matches!(err, Err(Error::QuotaExceeded)));
        assert_eq!(db.children(root).await.expect("c").len(), 1);
        assert_eq!(used(&db, uid).await, 10);
    }

    #[tokio::test]
    async fn users_cannot_cross_trees() {
        let (_d, db) = test_db().await;
        let (_, ra) = user(&db, "anna").await;
        let (ub, rb) = user(&db, "bob").await;
        let f = put(&db, ra, "f", "1", 1).await;
        assert!(matches!(
            db.move_node(f.id, rb, &n("f"), false).await,
            Err(Error::Forbidden)
        ));
        assert!(matches!(
            db.copy_node(f.id, rb, &n("f"), false).await,
            Err(Error::Forbidden)
        ));
        let p = LogicalPath::from_url_path("/f").expect("p");
        assert_eq!(db.resolve(ub, &p).await.expect("r"), None);
    }
}
