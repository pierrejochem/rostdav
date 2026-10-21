//! File versions: archiving on overwrite, listing, restore, deletion, retention.
//!
//! The archived content keeps its blob; usage of the owner counts versions
//! (documented decision, docs/instructions.md 2.4). A version is named by the
//! modification time of its content, like in the reference server.

use rostdav_core::{Error, Result};
use sqlx::SqliteConnection;

use crate::Db;
use crate::nodes::{
    COLS, Node, Row, VersionPolicy, adjust_used, db_err, fetch, require, to_node, touch_chain,
};
use crate::users::{new_etag, now_secs};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub id: i64,
    pub node_id: i64,
    /// Name in the DAV URL.
    pub version_time: i64,
    pub mtime: i64,
    pub size: i64,
    pub blob_id: String,
    pub checksum: String,
    pub client_checksum: Option<String>,
    /// Name of the user who caused the archiving, if still known.
    pub author: Option<String>,
    pub created_at: i64,
}

type VRow = (
    i64,
    i64,
    i64,
    i64,
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    i64,
);
const VCOLS: &str = "v.id, v.node_id, v.version_time, v.mtime, v.size, v.blob_id, v.checksum, v.client_checksum, u.name, v.created_at";
const VFROM: &str = "FROM versions v LEFT JOIN users u ON u.id = v.author_id";

fn to_version(r: VRow) -> Version {
    Version {
        id: r.0,
        node_id: r.1,
        version_time: r.2,
        mtime: r.3,
        size: r.4,
        blob_id: r.5,
        checksum: r.6,
        client_checksum: r.7,
        author: r.8,
        created_at: r.9,
    }
}

/// Stores the current content of `node` as a version. Returns the new row ID.
pub(crate) async fn archive(
    conn: &mut SqliteConnection,
    node: &Node,
    author: Option<i64>,
    now: i64,
) -> Result<i64> {
    let (Some(blob), Some(checksum)) = (&node.blob_id, &node.checksum) else {
        return Err(Error::Conflict("only files have versions"));
    };
    // names are unique per file: move to the next free second
    let mut t = node.mtime;
    while sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM versions WHERE node_id = ? AND version_time = ?)",
    )
    .bind(node.id)
    .bind(t)
    .fetch_one(&mut *conn)
    .await
    .map_err(db_err)?
    {
        t += 1;
    }
    sqlx::query_scalar(
        "INSERT INTO versions (node_id, version_time, mtime, size, blob_id, checksum, client_checksum, author_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(node.id)
    .bind(t)
    .bind(node.mtime)
    .bind(node.size)
    .bind(blob)
    .bind(checksum)
    .bind(&node.client_checksum)
    .bind(author)
    .bind(now)
    .fetch_one(conn)
    .await
    .map_err(db_err)
}

/// Deletes the oldest versions beyond `keep` (0 = unlimited); returns the bytes freed.
pub(crate) async fn trim(conn: &mut SqliteConnection, node_id: i64, keep: u32) -> Result<i64> {
    if keep == 0 {
        return Ok(0);
    }
    let doomed: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT id, size FROM versions WHERE node_id = ? ORDER BY version_time DESC LIMIT -1 OFFSET ?",
    )
    .bind(node_id)
    .bind(i64::from(keep))
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)?;
    for (id, _) in &doomed {
        sqlx::query("DELETE FROM versions WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(db_err)?;
    }
    Ok(doomed.iter().map(|(_, s)| s).sum())
}

/// Size of all versions of all files in the subtree (for delete accounting).
pub(crate) async fn subtree_versions_size(conn: &mut SqliteConnection, id: i64) -> Result<i64> {
    sqlx::query_scalar(
        "WITH RECURSIVE sub(id) AS (
             SELECT id FROM nodes WHERE id = ?1
             UNION ALL SELECT n.id FROM nodes n JOIN sub s ON n.parent_id = s.id
         )
         SELECT COALESCE(SUM(size), 0) FROM versions WHERE node_id IN (SELECT id FROM sub)",
    )
    .bind(id)
    .fetch_one(conn)
    .await
    .map_err(db_err)
}

impl Db {
    /// Archived versions of a file, oldest first (the live content is not included).
    pub async fn list_versions(&self, node_id: i64) -> Result<Vec<Version>> {
        let rows: Vec<VRow> = sqlx::query_as(&format!(
            "SELECT {VCOLS} {VFROM} WHERE v.node_id = ? ORDER BY v.version_time"
        ))
        .bind(node_id)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(to_version).collect())
    }

    pub async fn find_version(&self, node_id: i64, version_time: i64) -> Result<Option<Version>> {
        let row: Option<VRow> = sqlx::query_as(&format!(
            "SELECT {VCOLS} {VFROM} WHERE v.node_id = ? AND v.version_time = ?"
        ))
        .bind(node_id)
        .bind(version_time)
        .fetch_optional(self.pool())
        .await
        .map_err(db_err)?;
        Ok(row.map(to_version))
    }

    /// Deletes one archived version and gives its bytes back to the owner.
    pub async fn delete_version(&self, node_id: i64, version_time: i64) -> Result<()> {
        let mut tx = self.write_tx().await?;
        let node = require(&mut tx, node_id).await?;
        let size: Option<i64> = sqlx::query_scalar(
            "DELETE FROM versions WHERE node_id = ? AND version_time = ? RETURNING size",
        )
        .bind(node_id)
        .bind(version_time)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;
        let size = size.ok_or(Error::NotFound)?;
        adjust_used(&mut tx, node.owner_id, -size).await?;
        tx.commit().await.map_err(Error::internal)?;
        Ok(())
    }

    /// Makes an archived version the live content. The content it replaces is
    /// archived in turn (unless identical), so nothing is lost.
    pub async fn restore_version(
        &self,
        node_id: i64,
        version_time: i64,
        policy: VersionPolicy,
        author: Option<i64>,
    ) -> Result<Node> {
        let now = now_secs();
        let mut tx = self.write_tx().await?;
        let node = require(&mut tx, node_id).await?;
        let parent = node.parent_id.ok_or(Error::NotFound)?;
        let row: Option<VRow> = sqlx::query_as(&format!(
            "SELECT {VCOLS} {VFROM} WHERE v.node_id = ? AND v.version_time = ?"
        ))
        .bind(node_id)
        .bind(version_time)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;
        let v = to_version(row.ok_or(Error::NotFound)?);

        let before = node.size + v.size;
        // free the name first, then archive the live content
        sqlx::query("DELETE FROM versions WHERE id = ?")
            .bind(v.id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        let keep_old = node.checksum.as_deref() != Some(v.checksum.as_str());
        if keep_old {
            crate::versions::archive(&mut tx, &node, author, now).await?;
        }
        sqlx::query(
            "UPDATE nodes SET size = ?, mtime = ?, etag = ?, blob_id = ?, checksum = ?, client_checksum = ?,
             upload_time = ?, updated_at = ? WHERE id = ?",
        )
        .bind(v.size)
        .bind(v.mtime)
        .bind(new_etag())
        .bind(&v.blob_id)
        .bind(&v.checksum)
        .bind(&v.client_checksum)
        .bind(now)
        .bind(now)
        .bind(node_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        let mut after = v.size + if keep_old { node.size } else { 0 };
        if keep_old {
            after -= trim(&mut tx, node_id, policy.max_versions).await?;
        }
        adjust_used(&mut tx, node.owner_id, after - before).await?;
        touch_chain(&mut tx, parent, now).await?;
        let out = fetch(&mut tx, node_id).await?.ok_or(Error::NotFound)?;
        tx.commit().await.map_err(Error::internal)?;
        Ok(out)
    }

    /// Deletes versions archived before `cutoff` (unix seconds); returns how many.
    pub async fn expire_versions(&self, cutoff: i64) -> Result<u64> {
        let mut tx = self.write_tx().await?;
        let old: Vec<(i64, i64, i64)> = sqlx::query_as(
            "SELECT v.id, v.size, n.owner_id FROM versions v JOIN nodes n ON n.id = v.node_id WHERE v.created_at < ?",
        )
        .bind(cutoff)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
        for (id, size, owner) in &old {
            sqlx::query("DELETE FROM versions WHERE id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            adjust_used(&mut tx, *owner, -size).await?;
        }
        tx.commit().await.map_err(Error::internal)?;
        Ok(old.len() as u64)
    }

    /// For users with a quota: deletes the oldest versions until their versions
    /// take at most `percent` of the quota. Returns how many were deleted.
    pub async fn trim_versions_to_quota_share(&self, percent: u32) -> Result<u64> {
        let mut tx = self.write_tx().await?;
        let users: Vec<(i64, i64)> =
            sqlx::query_as("SELECT id, quota_bytes FROM users WHERE quota_bytes IS NOT NULL")
                .fetch_all(&mut *tx)
                .await
                .map_err(db_err)?;
        let mut deleted = 0u64;
        for (user, quota) in users {
            let limit = quota.saturating_mul(i64::from(percent)) / 100;
            loop {
                let total: i64 = sqlx::query_scalar(
                    "SELECT COALESCE(SUM(v.size), 0) FROM versions v JOIN nodes n ON n.id = v.node_id WHERE n.owner_id = ?",
                )
                .bind(user)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_err)?;
                if total <= limit {
                    break;
                }
                let oldest: Option<(i64, i64)> = sqlx::query_as(
                    "SELECT v.id, v.size FROM versions v JOIN nodes n ON n.id = v.node_id
                     WHERE n.owner_id = ? ORDER BY v.created_at, v.id LIMIT 1",
                )
                .bind(user)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
                let Some((id, size)) = oldest else { break };
                sqlx::query("DELETE FROM versions WHERE id = ?")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                adjust_used(&mut tx, user, -size).await?;
                deleted += 1;
            }
        }
        tx.commit().await.map_err(Error::internal)?;
        Ok(deleted)
    }

    /// The live node for a file ID of a given owner (versions are addressed by file ID).
    pub async fn file_of_owner(&self, owner_id: i64, node_id: i64) -> Result<Option<Node>> {
        let row: Option<Row> = sqlx::query_as(&format!(
            "SELECT {COLS} FROM nodes WHERE id = ? AND owner_id = ? AND kind = 'file'"
        ))
        .bind(node_id)
        .bind(owner_id)
        .fetch_optional(self.pool())
        .await
        .map_err(db_err)?;
        row.map(to_node).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_db;
    use crate::{CommitOpts, NewBlob, NewUser, WriteCondition};
    use rostdav_core::Name;

    const ON: VersionPolicy = VersionPolicy {
        enabled: true,
        max_versions: 0,
    };

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

    async fn write(
        db: &Db,
        parent: i64,
        name: &str,
        tag: &str,
        body: &str,
        mtime: i64,
        policy: VersionPolicy,
    ) -> Node {
        let blob = NewBlob {
            id: format!("{tag:0>26}"),
            size: body.len() as i64,
            checksum: format!("sum-{body}"),
        };
        let opts = CommitOpts {
            mtime: Some(mtime),
            versioning: policy,
            ..CommitOpts::default()
        };
        db.commit_file_with(
            parent,
            &Name::parse(name).expect("n"),
            &blob,
            &opts,
            &WriteCondition::None,
        )
        .await
        .expect("commit")
        .node
    }

    async fn used(db: &Db, user: i64) -> i64 {
        db.quota_info(user).await.expect("q").1
    }

    #[tokio::test]
    async fn overwrite_archives_the_old_content_and_counts_it() {
        let (_d, db, u, root) = setup().await;
        let f = write(&db, root, "f", "1", "one", 1000, ON).await;
        assert!(db.list_versions(f.id).await.expect("l").is_empty());
        write(&db, root, "f", "2", "second", 2000, ON).await;
        write(&db, root, "f", "3", "3", 3000, ON).await;
        let v = db.list_versions(f.id).await.expect("l");
        assert_eq!(
            v.iter()
                .map(|v| (v.version_time, v.size))
                .collect::<Vec<_>>(),
            [(1000, 3), (2000, 6)]
        );
        assert_eq!(used(&db, u).await, 3 + 6 + 1, "versions count toward usage");
        assert!(db.usage_mismatches().await.expect("m").is_empty());
        // identical content creates no version
        write(&db, root, "f", "4", "3", 4000, ON).await;
        assert_eq!(db.list_versions(f.id).await.expect("l").len(), 2);
        assert_eq!(used(&db, u).await, 3 + 6 + 1);
    }

    #[tokio::test]
    async fn disabled_policy_keeps_the_old_behavior() {
        let (_d, db, u, root) = setup().await;
        let f = write(&db, root, "f", "1", "one", 1000, VersionPolicy::default()).await;
        write(
            &db,
            root,
            "f",
            "2",
            "second",
            2000,
            VersionPolicy::default(),
        )
        .await;
        assert!(db.list_versions(f.id).await.expect("l").is_empty());
        assert_eq!(used(&db, u).await, 6);
    }

    #[tokio::test]
    async fn names_are_unique_and_the_count_is_limited() {
        let (_d, db, u, root) = setup().await;
        let policy = VersionPolicy {
            enabled: true,
            max_versions: 2,
        };
        // all with the same mtime: names move to the next free second
        let f = write(&db, root, "f", "1", "a", 500, policy).await;
        for (i, body) in ["bb", "ccc", "dddd"].iter().enumerate() {
            write(&db, root, "f", &format!("{}", i + 2), body, 500, policy).await;
        }
        let v = db.list_versions(f.id).await.expect("l");
        assert_eq!(v.len(), 2, "at most two versions");
        assert_eq!(
            v.iter().map(|v| v.size).collect::<Vec<_>>(),
            [2, 3],
            "the oldest went"
        );
        assert!(v[0].version_time < v[1].version_time);
        assert_eq!(used(&db, u).await, 2 + 3 + 4);
        assert!(db.usage_mismatches().await.expect("m").is_empty());
    }

    #[tokio::test]
    async fn restore_swaps_content_and_keeps_everything() {
        let (_d, db, u, root) = setup().await;
        let f = write(&db, root, "f", "1", "one", 1000, ON).await;
        write(&db, root, "f", "2", "second!", 2000, ON).await;
        let etag_before = db.node_by_id(f.id).await.expect("n").expect("some").etag;

        let n = db
            .restore_version(f.id, 1000, ON, Some(u))
            .await
            .expect("restore");
        assert_eq!(
            (n.size, n.mtime, n.blob_id.as_deref()),
            (3, 1000, Some(format!("{:0>26}", "1").as_str()))
        );
        assert_ne!(n.etag, etag_before);
        let v = db.list_versions(f.id).await.expect("l");
        assert_eq!(
            v.iter()
                .map(|v| (v.version_time, v.size))
                .collect::<Vec<_>>(),
            [(2000, 7)],
            "old live content is a version now"
        );
        assert_eq!(used(&db, u).await, 10);
        assert!(db.usage_mismatches().await.expect("m").is_empty());
        assert!(
            matches!(
                db.restore_version(f.id, 1000, ON, None).await,
                Err(Error::NotFound)
            ),
            "the restored version is consumed"
        );

        // and back again
        let n = db
            .restore_version(f.id, 2000, ON, Some(u))
            .await
            .expect("restore back");
        assert_eq!(n.size, 7);
        assert_eq!(db.list_versions(f.id).await.expect("l").len(), 1);
        assert_eq!(used(&db, u).await, 10);
    }

    #[tokio::test]
    async fn delete_version_gives_bytes_back_and_node_delete_removes_all() {
        let (_d, db, u, root) = setup().await;
        let f = write(&db, root, "f", "1", "one", 1000, ON).await;
        write(&db, root, "f", "2", "second", 2000, ON).await;
        write(&db, root, "f", "3", "third!!", 3000, ON).await;
        assert_eq!(used(&db, u).await, 3 + 6 + 7);
        db.delete_version(f.id, 1000).await.expect("delete");
        assert_eq!(used(&db, u).await, 6 + 7);
        assert!(matches!(
            db.delete_version(f.id, 1000).await,
            Err(Error::NotFound)
        ));
        // blob 1 is unreferenced now; 2 is still a version, 3 is live
        assert_eq!(
            db.delete_unreferenced_blobs().await.expect("gc"),
            vec![format!("{:0>26}", "1")]
        );
        db.delete_node(f.id, None).await.expect("delete file");
        assert_eq!(used(&db, u).await, 0);
        assert_eq!(db.delete_unreferenced_blobs().await.expect("gc").len(), 2);
    }

    #[tokio::test]
    async fn retention_by_age_and_quota_share() {
        let (_d, db, u, root) = setup().await;
        let f = write(&db, root, "f", "1", "aaaa", 1000, ON).await;
        write(&db, root, "f", "2", "bbbb", 2000, ON).await;
        write(&db, root, "f", "3", "cccc", 3000, ON).await;
        assert_eq!(used(&db, u).await, 12);
        assert_eq!(db.list_versions(f.id).await.expect("l").len(), 2);
        // age: everything archived before "the future" goes
        assert_eq!(db.expire_versions(0).await.expect("e"), 0);
        db.set_quota(u, Some(100)).await.expect("quota");
        assert_eq!(
            db.trim_versions_to_quota_share(5).await.expect("t"),
            1,
            "5% of 100 = 5 bytes: one 4-byte version fits"
        );
        let left = db.list_versions(f.id).await.expect("l");
        assert_eq!(
            left.iter().map(|v| v.version_time).collect::<Vec<_>>(),
            [2000],
            "the oldest went first"
        );
        assert_eq!(used(&db, u).await, 8);
    }

    #[tokio::test]
    async fn expire_removes_old_versions_only() {
        let (_d, db, u, root) = setup().await;
        let f = write(&db, root, "f", "1", "aaaa", 1000, ON).await;
        write(&db, root, "f", "2", "bbbb", 2000, ON).await;
        assert_eq!(db.expire_versions(i64::MAX).await.expect("e"), 1);
        assert!(db.list_versions(f.id).await.expect("l").is_empty());
        assert_eq!(used(&db, u).await, 4);
    }

    #[tokio::test]
    async fn file_of_owner_hides_foreign_and_dirs() {
        let (_d, db, u, root) = setup().await;
        let other = db
            .create_user(NewUser {
                name: "bob",
                password_hash: "h",
                is_admin: false,
            })
            .await
            .expect("bob")
            .id;
        let f = write(&db, root, "f", "1", "x", 1, ON).await;
        let dir = db
            .create_dir(root, &Name::parse("d").expect("n"))
            .await
            .expect("d");
        assert!(db.file_of_owner(u, f.id).await.expect("f").is_some());
        assert!(db.file_of_owner(other, f.id).await.expect("f").is_none());
        assert!(db.file_of_owner(u, dir.id).await.expect("f").is_none());
        assert!(db.file_of_owner(u, 9999).await.expect("f").is_none());
    }

    #[tokio::test]
    async fn move_keeps_versions_copy_does_not_copy_them() {
        let (_d, db, u, root) = setup().await;
        let f = write(&db, root, "f", "1", "one", 1000, ON).await;
        write(&db, root, "f", "2", "two", 2000, ON).await;
        let dir = db
            .create_dir(root, &Name::parse("d").expect("n"))
            .await
            .expect("d");
        db.move_node(f.id, dir.id, &Name::parse("g").expect("n"), false)
            .await
            .expect("move");
        assert_eq!(db.list_versions(f.id).await.expect("l").len(), 1);
        let c = db
            .copy_node(f.id, root, &Name::parse("copy").expect("n"), false)
            .await
            .expect("copy");
        assert!(db.list_versions(c.node.id).await.expect("l").is_empty());
        assert_eq!(used(&db, u).await, 3 + 3 + 3, "live + version + copy");
        assert!(db.usage_mismatches().await.expect("m").is_empty());
    }
}
