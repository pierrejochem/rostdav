//! Trash (ADR 0005): deleted subtrees stay in `nodes`, marked with a trash ID.
//!
//! The top node of a deleted subtree is re-homed under the owner's root; its
//! original location is kept as text. Space keeps counting until a purge.

use rostdav_core::{Error, Name, Result};
use sqlx::SqliteConnection;

use crate::Db;
use crate::nodes::{
    COLS, Node, NodeKind, Row, adjust_used, db_err, fetch, require, to_node, touch_chain,
};
use crate::users::{new_etag, now_secs};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrashItem {
    pub id: i64,
    /// The top node of the deleted subtree (still carries its original name).
    pub node: Node,
    /// Below the owner's root, no leading slash, e.g. `Docs/a.txt`.
    pub orig_path: String,
    pub deleted_at: i64,
    pub deleted_by: Option<String>,
}

impl TrashItem {
    /// Name in the trash listing: `<name>.d<deletion time>`.
    pub fn entry_name(&self) -> String {
        format!("{}.d{}", self.node.name, self.deleted_at)
    }
}

type ItemRow = (i64, i64, String, i64, Option<String>);
const ICOLS: &str = "t.id, t.node_id, t.orig_path, t.deleted_at, u.name";
const IFROM: &str = "FROM trash t LEFT JOIN users u ON u.id = t.deleted_by";

async fn path_of(conn: &mut SqliteConnection, id: i64) -> Result<String> {
    let names: Vec<String> = sqlx::query_scalar(
        "WITH RECURSIVE chain(id, parent_id, name, depth) AS (
             SELECT id, parent_id, name, 0 FROM nodes WHERE id = ?1
             UNION ALL
             SELECT n.id, n.parent_id, n.name, c.depth + 1 FROM nodes n JOIN chain c ON n.id = c.parent_id
         )
         SELECT name FROM chain WHERE parent_id IS NOT NULL ORDER BY depth DESC",
    )
    .bind(id)
    .fetch_all(conn)
    .await
    .map_err(db_err)?;
    Ok(names.join("/"))
}

async fn root_of(conn: &mut SqliteConnection, owner: i64) -> Result<i64> {
    sqlx::query_scalar("SELECT id FROM nodes WHERE owner_id = ? AND parent_id IS NULL")
        .bind(owner)
        .fetch_one(conn)
        .await
        .map_err(db_err)
}

async fn live_child(conn: &mut SqliteConnection, parent: i64, key: &str) -> Result<Option<Node>> {
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM nodes WHERE parent_id = ? AND name_key = ? AND trash_id IS NULL"
    ))
    .bind(parent)
    .bind(key)
    .fetch_optional(conn)
    .await
    .map_err(db_err)?;
    row.map(to_node).transpose()
}

async fn load_item(conn: &mut SqliteConnection, id: i64) -> Result<Option<TrashItem>> {
    let row: Option<ItemRow> = sqlx::query_as(&format!("SELECT {ICOLS} {IFROM} WHERE t.id = ?"))
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_err)?;
    let Some((id, node_id, orig_path, deleted_at, by)) = row else {
        return Ok(None);
    };
    let Some(node) = fetch(conn, node_id).await? else {
        return Ok(None);
    };
    Ok(Some(TrashItem {
        id,
        node,
        orig_path,
        deleted_at,
        deleted_by: by,
    }))
}

/// A name for `base` that is free below `parent`: `a (restored).txt`, `a (restored 2).txt`, ...
async fn free_name(
    conn: &mut SqliteConnection,
    parent: &Node,
    base: &str,
    is_file: bool,
) -> Result<String> {
    let (stem, ext) = match base.rsplit_once('.') {
        Some((s, e)) if is_file && !s.is_empty() => (s, format!(".{e}")),
        _ => (base, String::new()),
    };
    let mut n = 0;
    loop {
        let candidate = match n {
            0 => base.to_owned(),
            1 => format!("{stem} (restored){ext}"),
            k => format!("{stem} (restored {k}){ext}"),
        };
        let key = Name::parse(&candidate)?.key().to_owned();
        let taken = live_child(conn, parent.id, &key).await?.is_some()
            || crate::shares::ensure_no_mount_clash(conn, parent, &key)
                .await
                .is_err();
        if !taken {
            return Ok(candidate);
        }
        n += 1;
    }
}

impl Db {
    /// Moves a live subtree into the trash. Space stays accounted to the owner.
    pub async fn trash_node(
        &self,
        node_id: i64,
        deleted_by: i64,
        if_match: Option<&str>,
    ) -> Result<TrashItem> {
        let now = now_secs();
        let mut tx = self.write_tx().await?;
        let node = require(&mut tx, node_id).await?;
        let live: Option<i64> = sqlx::query_scalar("SELECT trash_id FROM nodes WHERE id = ?")
            .bind(node_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
        if live.is_some() {
            return Err(Error::NotFound);
        }
        let old_parent = node
            .parent_id
            .ok_or(Error::Conflict("cannot delete the root"))?;
        if if_match.is_some_and(|want| want != node.etag) {
            return Err(Error::PreconditionFailed);
        }
        let orig_path = path_of(&mut tx, node_id).await?;
        let mut deleted_at = now;
        while sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM trash WHERE owner_id = ? AND orig_name = ? AND deleted_at = ?)")
            .bind(node.owner_id)
            .bind(&node.name)
            .bind(deleted_at)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?
        {
            deleted_at += 1;
        }
        let trash_id: i64 = sqlx::query_scalar(
            "INSERT INTO trash (node_id, owner_id, orig_path, orig_name, deleted_at, deleted_by) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(node_id)
        .bind(node.owner_id)
        .bind(&orig_path)
        .bind(&node.name)
        .bind(deleted_at)
        .bind(deleted_by)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        sqlx::query(
            "WITH RECURSIVE sub(id) AS (
                 SELECT id FROM nodes WHERE id = ?2
                 UNION ALL SELECT n.id FROM nodes n JOIN sub s ON n.parent_id = s.id WHERE n.trash_id IS NULL
             )
             UPDATE nodes SET trash_id = ?1 WHERE id IN (SELECT id FROM sub)",
        )
        .bind(trash_id)
        .bind(node_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        // independent of the old parent from now on
        let root = root_of(&mut tx, node.owner_id).await?;
        sqlx::query("UPDATE nodes SET parent_id = ?, updated_at = ? WHERE id = ?")
            .bind(root)
            .bind(now)
            .bind(node_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        touch_chain(&mut tx, old_parent, now).await?;
        let item = load_item(&mut tx, trash_id).await?.ok_or(Error::NotFound)?;
        tx.commit().await.map_err(Error::internal)?;
        Ok(item)
    }

    /// The owner's trash, newest first.
    pub async fn list_trash(&self, owner_id: i64) -> Result<Vec<TrashItem>> {
        let ids: Vec<i64> = sqlx::query_scalar(
            "SELECT id FROM trash WHERE owner_id = ? ORDER BY deleted_at DESC, id DESC",
        )
        .bind(owner_id)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)?;
        let mut conn = self.pool().acquire().await.map_err(Error::internal)?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(i) = load_item(&mut conn, id).await? {
                out.push(i);
            }
        }
        Ok(out)
    }

    /// An item by its listing name `<name>.d<time>`.
    pub async fn find_trash_item(
        &self,
        owner_id: i64,
        entry_name: &str,
    ) -> Result<Option<TrashItem>> {
        let Some((name, time)) = entry_name.rsplit_once(".d") else {
            return Ok(None);
        };
        let Ok(deleted_at) = time.parse::<i64>() else {
            return Ok(None);
        };
        let id: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM trash WHERE owner_id = ? AND orig_name = ? AND deleted_at = ?",
        )
        .bind(owner_id)
        .bind(name)
        .bind(deleted_at)
        .fetch_optional(self.pool())
        .await
        .map_err(db_err)?;
        match id {
            Some(id) => {
                let mut conn = self.pool().acquire().await.map_err(Error::internal)?;
                load_item(&mut conn, id).await
            }
            None => Ok(None),
        }
    }

    /// Children of a node inside a trashed subtree.
    pub async fn trash_children(&self, trash_id: i64, parent: i64) -> Result<Vec<Node>> {
        let rows: Vec<Row> = sqlx::query_as(&format!(
            "SELECT {COLS} FROM nodes WHERE parent_id = ? AND trash_id = ? ORDER BY name_key"
        ))
        .bind(parent)
        .bind(trash_id)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)?;
        rows.into_iter().map(to_node).collect()
    }

    /// Walks names below the top node of a trashed subtree.
    pub async fn resolve_in_trash(
        &self,
        item: &TrashItem,
        segments: &[Name],
    ) -> Result<Option<Node>> {
        let mut cur = item.node.clone();
        for seg in segments {
            if cur.kind != NodeKind::Dir {
                return Ok(None);
            }
            let row: Option<Row> = sqlx::query_as(&format!(
                "SELECT {COLS} FROM nodes WHERE parent_id = ? AND name_key = ? AND trash_id = ?"
            ))
            .bind(cur.id)
            .bind(seg.key())
            .bind(item.id)
            .fetch_optional(self.pool())
            .await
            .map_err(db_err)?;
            match row.map(to_node).transpose()? {
                Some(n) => cur = n,
                None => return Ok(None),
            }
        }
        Ok(Some(cur))
    }

    /// Sum of file sizes in a trashed subtree.
    pub async fn trash_item_size(&self, trash_id: i64) -> Result<i64> {
        sqlx::query_scalar("SELECT COALESCE(SUM(size), 0) FROM nodes WHERE trash_id = ?")
            .bind(trash_id)
            .fetch_one(self.pool())
            .await
            .map_err(db_err)
    }

    /// Puts an item back: under its old parent if that is a live folder, else
    /// under the root; a taken name gets a ` (restored)` suffix. IDs, versions
    /// and shares come back with it.
    pub async fn restore_trash(&self, trash_id: i64) -> Result<Node> {
        let now = now_secs();
        let mut tx = self.write_tx().await?;
        let item = load_item(&mut tx, trash_id).await?.ok_or(Error::NotFound)?;
        let owner = item.node.owner_id;
        let root_id = root_of(&mut tx, owner).await?;
        let root = require(&mut tx, root_id).await?;

        // the old parent, by walking the stored path
        let mut parent = root.clone();
        let segs: Vec<&str> = item
            .orig_path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        if let Some((_, dirs)) = segs.split_last() {
            for seg in dirs {
                match live_child(&mut tx, parent.id, Name::parse(seg)?.key()).await? {
                    Some(n) if n.kind == NodeKind::Dir => parent = n,
                    _ => {
                        parent = root.clone();
                        break;
                    }
                }
            }
        }
        let name = free_name(
            &mut tx,
            &parent,
            &item.node.name,
            item.node.kind == NodeKind::File,
        )
        .await?;
        let key = Name::parse(&name)?.key().to_owned();

        sqlx::query("UPDATE nodes SET trash_id = NULL WHERE trash_id = ?")
            .bind(trash_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        sqlx::query("UPDATE nodes SET parent_id = ?, name = ?, name_key = ?, etag = ?, updated_at = ? WHERE id = ?")
            .bind(parent.id)
            .bind(&name)
            .bind(&key)
            .bind(new_etag())
            .bind(now)
            .bind(item.node.id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        sqlx::query("DELETE FROM trash WHERE id = ?")
            .bind(trash_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        touch_chain(&mut tx, parent.id, now).await?;
        let node = require(&mut tx, item.node.id).await?;
        tx.commit().await.map_err(Error::internal)?;
        Ok(node)
    }

    /// Deletes an item for good and gives its space back. Returns the bytes freed.
    pub async fn purge_trash_item(&self, trash_id: i64) -> Result<i64> {
        let mut tx = self.write_tx().await?;
        let freed = purge_in_tx(&mut tx, trash_id)
            .await?
            .ok_or(Error::NotFound)?;
        tx.commit().await.map_err(Error::internal)?;
        Ok(freed)
    }

    /// Empties a user's trash.
    pub async fn purge_all_trash(&self, owner_id: i64) -> Result<usize> {
        self.purge_where("owner_id = ?", owner_id).await
    }

    /// Purges everything deleted before `cutoff` (unix seconds).
    pub async fn purge_trash_before(&self, cutoff: i64) -> Result<usize> {
        self.purge_where("deleted_at < ?", cutoff).await
    }

    async fn purge_where(&self, cond: &str, arg: i64) -> Result<usize> {
        let mut tx = self.write_tx().await?;
        let ids: Vec<i64> = sqlx::query_scalar(&format!("SELECT id FROM trash WHERE {cond}"))
            .bind(arg)
            .fetch_all(&mut *tx)
            .await
            .map_err(db_err)?;
        for id in &ids {
            purge_in_tx(&mut tx, *id).await?;
        }
        tx.commit().await.map_err(Error::internal)?;
        Ok(ids.len())
    }
}

async fn purge_in_tx(tx: &mut SqliteConnection, trash_id: i64) -> Result<Option<i64>> {
    let row: Option<(i64, i64)> =
        sqlx::query_as("SELECT node_id, owner_id FROM trash WHERE id = ?")
            .bind(trash_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    let Some((node_id, owner)) = row else {
        return Ok(None);
    };
    let files: i64 =
        sqlx::query_scalar("SELECT COALESCE(SUM(size), 0) FROM nodes WHERE trash_id = ?")
            .bind(trash_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
    let versions: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(v.size), 0) FROM versions v JOIN nodes n ON n.id = v.node_id WHERE n.trash_id = ?",
    )
    .bind(trash_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    // children go with their parent (foreign key cascade), versions and the trash row too
    sqlx::query("DELETE FROM nodes WHERE id = ?")
        .bind(node_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    adjust_used(tx, owner, -(files + versions)).await?;
    Ok(Some(files + versions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_db;
    use crate::{CommitOpts, NewBlob, NewShare, NewUser, ShareKind, VersionPolicy, WriteCondition};
    use rostdav_core::LogicalPath;

    fn name(s: &str) -> Name {
        Name::parse(s).expect("name")
    }

    async fn setup() -> (tempfile::TempDir, Db, i64, i64) {
        let (d, db) = test_db().await;
        let u = db
            .create_user(NewUser {
                name: "anna",
                password_hash: "h",
                is_admin: false,
            })
            .await
            .expect("user")
            .id;
        let root = db.root_node(u).await.expect("root").id;
        (d, db, u, root)
    }

    async fn file(db: &Db, parent: i64, n: &str, tag: &str, body: &str, versions: bool) -> Node {
        let blob = NewBlob {
            id: format!("{tag:0>26}"),
            size: body.len() as i64,
            checksum: format!("sum-{body}"),
        };
        let opts = CommitOpts {
            mtime: Some(1000),
            versioning: VersionPolicy {
                enabled: versions,
                max_versions: 0,
            },
            ..CommitOpts::default()
        };
        db.commit_file_with(parent, &name(n), &blob, &opts, &WriteCondition::None)
            .await
            .expect("commit")
            .node
    }

    async fn used(db: &Db, u: i64) -> i64 {
        db.quota_info(u).await.expect("q").1
    }

    fn path(p: &str) -> LogicalPath {
        LogicalPath::from_url_path(p).expect("path")
    }

    #[tokio::test]
    async fn deleting_hides_the_subtree_but_keeps_the_space() {
        let (_d, db, u, root) = setup().await;
        let dir = db.create_dir(root, &name("Docs")).await.expect("d").id;
        let sub = db.create_dir(dir, &name("sub")).await.expect("d").id;
        file(&db, dir, "a.txt", "1", "aaaa", false).await;
        file(&db, sub, "inner.txt", "2", "inner", false).await;
        file(&db, root, "keep.txt", "3", "k", false).await;
        assert_eq!(used(&db, u).await, 10);

        let item = db.trash_node(dir, u, None).await.expect("trash");
        assert_eq!((item.orig_path.as_str(), item.node.id), ("Docs", dir));
        assert_eq!(item.entry_name(), format!("Docs.d{}", item.deleted_at));
        assert_eq!(item.deleted_by.as_deref(), Some("anna"));

        // gone from the live tree in every way
        assert!(db.resolve(u, &path("/Docs")).await.expect("r").is_none());
        assert!(
            db.resolve(u, &path("/Docs/a.txt"))
                .await
                .expect("r")
                .is_none()
        );
        let names: Vec<_> = db
            .children(root)
            .await
            .expect("c")
            .into_iter()
            .map(|n| n.name)
            .collect();
        assert_eq!(names, ["keep.txt"]);
        assert_eq!(
            db.subtree_size(root).await.expect("s"),
            1,
            "folder sizes ignore the trash"
        );
        // ... but the space still counts, and fsck agrees
        assert_eq!(used(&db, u).await, 10);
        assert!(db.usage_mismatches().await.expect("m").is_empty());
        assert_eq!(db.count_blobs().await.expect("c"), 3);
        assert!(
            db.delete_unreferenced_blobs().await.expect("gc").is_empty(),
            "trashed blobs are still referenced"
        );

        // the name is free again
        db.create_dir(root, &name("Docs"))
            .await
            .expect("new Docs next to the trashed one");
        // browse the trash
        let listed = db.list_trash(u).await.expect("l");
        assert_eq!(listed.len(), 1);
        let found = db
            .find_trash_item(u, &item.entry_name())
            .await
            .expect("f")
            .expect("some");
        assert_eq!(found.id, item.id);
        let kids: Vec<_> = db
            .trash_children(item.id, dir)
            .await
            .expect("k")
            .into_iter()
            .map(|n| n.name)
            .collect();
        assert_eq!(kids, ["a.txt", "sub"]);
        let inner = db
            .resolve_in_trash(&found, &[name("sub"), name("inner.txt")])
            .await
            .expect("r")
            .expect("some");
        assert_eq!(inner.size, 5);
        assert!(
            db.resolve_in_trash(&found, &[name("nope")])
                .await
                .expect("r")
                .is_none()
        );
        assert_eq!(db.trash_item_size(item.id).await.expect("s"), 9);
        // malformed entry names
        for bad in [
            "Docs",
            "Docs.d",
            "Docs.dxyz",
            "Docs.d1",
            "nothere.d5",
            ".d5",
        ] {
            assert!(
                db.find_trash_item(u, bad).await.expect("f").is_none(),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn the_root_and_trashed_nodes_cannot_be_trashed_again() {
        let (_d, db, u, root) = setup().await;
        let f = file(&db, root, "f", "1", "x", false).await;
        assert!(matches!(
            db.trash_node(root, u, None).await,
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            db.trash_node(f.id, u, Some("stale")).await,
            Err(Error::PreconditionFailed)
        ));
        db.trash_node(f.id, u, Some(&f.etag)).await.expect("trash");
        assert!(matches!(
            db.trash_node(f.id, u, None).await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            db.trash_node(9999, u, None).await,
            Err(Error::NotFound)
        ));
    }

    #[tokio::test]
    async fn restore_returns_the_item_where_it_was_with_its_identity() {
        let (_d, db, u, root) = setup().await;
        let dir = db.create_dir(root, &name("Docs")).await.expect("d").id;
        let f = file(&db, dir, "a.txt", "1", "one", true).await;
        file(&db, dir, "a.txt", "2", "second", true).await;
        let etag_before = db.node_by_id(dir).await.expect("n").expect("some").etag;
        let item = db.trash_node(f.id, u, None).await.expect("trash");
        assert_ne!(
            db.node_by_id(dir).await.expect("n").expect("some").etag,
            etag_before,
            "the folder changed"
        );

        let back = db.restore_trash(item.id).await.expect("restore");
        assert_eq!(
            (back.id, back.parent_id, back.name.as_str()),
            (f.id, Some(dir), "a.txt")
        );
        assert!(
            db.resolve(u, &path("/Docs/a.txt"))
                .await
                .expect("r")
                .is_some()
        );
        assert_eq!(
            db.list_versions(f.id).await.expect("v").len(),
            1,
            "versions come back"
        );
        assert!(db.list_trash(u).await.expect("l").is_empty());
        assert_eq!(used(&db, u).await, 3 + 6);
        assert!(
            matches!(db.restore_trash(item.id).await, Err(Error::NotFound)),
            "only once"
        );
    }

    #[tokio::test]
    async fn restore_handles_missing_parents_and_taken_names() {
        let (_d, db, u, root) = setup().await;
        let dir = db.create_dir(root, &name("Docs")).await.expect("d").id;
        let a = file(&db, dir, "report.txt", "1", "old", false).await;
        let t1 = db.trash_node(a.id, u, None).await.expect("trash");
        // the name is taken
        file(&db, dir, "report.txt", "2", "new", false).await;
        let r1 = db.restore_trash(t1.id).await.expect("restore");
        assert_eq!(r1.name, "report (restored).txt");
        // taken again: the next free suffix
        let t2 = db.trash_node(r1.id, u, None).await.expect("trash");
        file(&db, dir, "report (restored).txt", "3", "x", false).await;
        let r2 = db.restore_trash(t2.id).await.expect("restore");
        assert_eq!(r2.name, "report (restored) (restored).txt");
        let t4 = db.trash_node(r2.id, u, None).await.expect("trash");
        file(
            &db,
            dir,
            "report (restored) (restored).txt",
            "7",
            "y",
            false,
        )
        .await;
        file(
            &db,
            dir,
            "report (restored) (restored) (restored).txt",
            "8",
            "z",
            false,
        )
        .await;
        assert_eq!(
            db.restore_trash(t4.id).await.expect("restore").name,
            "report (restored) (restored) (restored 2).txt"
        );
        // a folder keeps its dots
        let d = db.create_dir(dir, &name("v1.2")).await.expect("d").id;
        let t3 = db.trash_node(d, u, None).await.expect("trash");
        db.create_dir(dir, &name("v1.2")).await.expect("taken");
        assert_eq!(
            db.restore_trash(t3.id).await.expect("r").name,
            "v1.2 (restored)"
        );

        // parent folder deleted: the item returns to the root
        let b = file(&db, dir, "b.txt", "4", "b", false).await;
        let tb = db.trash_node(b.id, u, None).await.expect("trash b");
        let td = db.trash_node(dir, u, None).await.expect("trash dir");
        let rb = db.restore_trash(tb.id).await.expect("restore b");
        assert_eq!(rb.parent_id, Some(root));
        // the parent comes back later, the child stays where it is
        let rd = db.restore_trash(td.id).await.expect("restore dir");
        assert_eq!(rd.name, "Docs");
        assert!(db.resolve(u, &path("/b.txt")).await.expect("r").is_some());
        // a name that is a mount point counts as taken
        let (v, rv) = {
            let id = db
                .create_user(NewUser {
                    name: "bob",
                    password_hash: "h",
                    is_admin: false,
                })
                .await
                .expect("bob")
                .id;
            (id, db.root_node(id).await.expect("r").id)
        };
        let shared = db.create_dir(root, &name("Team")).await.expect("d").id;
        db.create_share(NewShare {
            kind: ShareKind::User,
            owner_id: u,
            node_id: shared,
            recipient_id: Some(v),
            permissions: 15,
            token: None,
            password_hash: None,
            expires_at: None,
            note: String::new(),
            label: String::new(),
            hide_download: false,
        })
        .await
        .expect("share");
        let mine = db.create_dir(rv, &name("Notes")).await.expect("d").id;
        let tn = db.trash_node(mine, v, None).await.expect("trash");
        // "Notes" is free, but make it a mount name first
        let notes = db.create_dir(root, &name("Notes")).await.expect("d").id;
        db.create_share(NewShare {
            kind: ShareKind::User,
            owner_id: u,
            node_id: notes,
            recipient_id: Some(v),
            permissions: 15,
            token: None,
            password_hash: None,
            expires_at: None,
            note: String::new(),
            label: String::new(),
            hide_download: false,
        })
        .await
        .expect("share");
        assert_eq!(
            db.restore_trash(tn.id).await.expect("restore").name,
            "Notes (restored)"
        );
    }

    #[tokio::test]
    async fn trashed_items_do_not_depend_on_their_old_parent() {
        let (_d, db, u, root) = setup().await;
        let dir = db.create_dir(root, &name("Docs")).await.expect("d").id;
        let b = file(&db, dir, "b.txt", "1", "bbb", false).await;
        let tb = db.trash_node(b.id, u, None).await.expect("trash b");
        let td = db.trash_node(dir, u, None).await.expect("trash dir");
        // purging the parent does not take the earlier item with it
        db.purge_trash_item(td.id).await.expect("purge dir");
        assert_eq!(db.list_trash(u).await.expect("l").len(), 1);
        assert_eq!(used(&db, u).await, 3);
        let back = db.restore_trash(tb.id).await.expect("restore");
        assert_eq!(back.parent_id, Some(root));
        assert!(db.usage_mismatches().await.expect("m").is_empty());
    }

    #[tokio::test]
    async fn shares_are_asleep_while_trashed() {
        let (_d, db, u, root) = setup().await;
        let b = db
            .create_user(NewUser {
                name: "bob",
                password_hash: "h",
                is_admin: false,
            })
            .await
            .expect("bob")
            .id;
        let dir = db.create_dir(root, &name("Shared")).await.expect("d").id;
        let inner = db.create_dir(dir, &name("inner")).await.expect("d").id;
        let mk = |node, rec: Option<i64>, token: Option<&str>| NewShare {
            kind: if rec.is_some() {
                ShareKind::User
            } else {
                ShareKind::Link
            },
            owner_id: u,
            node_id: node,
            recipient_id: rec,
            permissions: 1,
            token: token.map(str::to_owned),
            password_hash: None,
            expires_at: None,
            note: String::new(),
            label: String::new(),
            hide_download: false,
        };
        let s = db
            .create_share(mk(dir, Some(b), None))
            .await
            .expect("share");
        let l = db
            .create_share(mk(inner, None, Some("tok123456789")))
            .await
            .expect("link");
        assert!(
            db.find_mount(b, &name("Shared"))
                .await
                .expect("m")
                .is_some()
        );
        let item = db.trash_node(dir, u, None).await.expect("trash");
        assert!(
            db.find_mount(b, &name("Shared"))
                .await
                .expect("m")
                .is_none()
        );
        assert!(db.get_share(s.id).await.expect("g").is_none());
        assert!(
            db.find_link("tok123456789").await.expect("l").is_none(),
            "a link below a trashed folder is off too"
        );
        assert!(db.shares_for_recipient(b).await.expect("l").is_empty());
        assert!(db.shares_by_owner(u).await.expect("l").is_empty());
        assert!(
            db.share_kinds_of_nodes(&[dir, inner])
                .await
                .expect("k")
                .is_empty()
        );
        db.restore_trash(item.id).await.expect("restore");
        assert!(
            db.find_mount(b, &name("Shared"))
                .await
                .expect("m")
                .is_some()
        );
        assert_eq!(
            db.find_link("tok123456789").await.expect("l").map(|x| x.id),
            Some(l.id)
        );
    }

    #[tokio::test]
    async fn purging_frees_space_blobs_and_versions() {
        let (_d, db, u, root) = setup().await;
        let dir = db.create_dir(root, &name("Docs")).await.expect("d").id;
        file(&db, dir, "a.txt", "1", "one", true).await;
        file(&db, dir, "a.txt", "2", "second", true).await;
        file(&db, root, "keep", "3", "kk", false).await;
        assert_eq!(used(&db, u).await, 3 + 6 + 2);
        let item = db.trash_node(dir, u, None).await.expect("trash");
        assert_eq!(
            db.purge_trash_item(item.id).await.expect("purge"),
            9,
            "file and its version"
        );
        assert_eq!(used(&db, u).await, 2);
        assert!(matches!(
            db.purge_trash_item(item.id).await,
            Err(Error::NotFound)
        ));
        let mut gone = db.delete_unreferenced_blobs().await.expect("gc");
        gone.sort();
        assert_eq!(gone, vec![format!("{:0>26}", "1"), format!("{:0>26}", "2")]);
        assert!(db.usage_mismatches().await.expect("m").is_empty());

        // empty all / purge by age
        let a = file(&db, root, "x", "4", "x", false).await;
        let b = file(&db, root, "y", "5", "y", false).await;
        db.trash_node(a.id, u, None).await.expect("t");
        db.trash_node(b.id, u, None).await.expect("t");
        assert_eq!(db.purge_trash_before(0).await.expect("p"), 0);
        assert_eq!(db.purge_trash_before(i64::MAX).await.expect("p"), 2);
        assert_eq!(used(&db, u).await, 2);
        let c = file(&db, root, "z", "6", "z", false).await;
        db.trash_node(c.id, u, None).await.expect("t");
        assert_eq!(db.purge_all_trash(u).await.expect("p"), 1);
        assert!(db.list_trash(u).await.expect("l").is_empty());
    }

    #[tokio::test]
    async fn same_name_deleted_in_the_same_second_gets_distinct_entries() {
        let (_d, db, u, root) = setup().await;
        let mut names = Vec::new();
        for i in 0..3 {
            let f = file(&db, root, "a.txt", &format!("{i}"), &format!("v{i}"), false).await;
            names.push(db.trash_node(f.id, u, None).await.expect("t").entry_name());
        }
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 3, "{names:?}");
        for n in &names {
            assert!(db.find_trash_item(u, n).await.expect("f").is_some());
        }
    }

    #[tokio::test]
    async fn user_removal_and_transfer_ignore_the_trash_of_others() {
        let (_d, db, u, root) = setup().await;
        let b = db
            .create_user(NewUser {
                name: "bob",
                password_hash: "h",
                is_admin: false,
            })
            .await
            .expect("bob")
            .id;
        let f = file(&db, root, "gone", "1", "gone", false).await;
        file(&db, root, "kept", "2", "kept", false).await;
        db.trash_node(f.id, u, None).await.expect("trash");
        db.transfer_tree(u, b, "from anna").await.expect("transfer");
        let rb = db.root_node(b).await.expect("r").id;
        let names: Vec<_> = db
            .children(rb)
            .await
            .expect("c")
            .into_iter()
            .map(|n| n.name)
            .collect();
        assert_eq!(names, ["from anna"]);
        let moved: Vec<_> = db
            .resolve(b, &path("/from%20anna"))
            .await
            .expect("r")
            .iter()
            .map(|n| n.id)
            .collect();
        assert_eq!(
            db.children(moved[0]).await.expect("c").len(),
            1,
            "only the live file moved"
        );
        assert_eq!(
            db.list_trash(u).await.expect("l").len(),
            1,
            "the trash stays with its owner"
        );
        db.delete_user(u).await.expect("delete");
        assert_eq!(
            db.delete_unreferenced_blobs().await.expect("gc").len(),
            1,
            "its blob goes with the user"
        );
    }
}
