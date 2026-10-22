//! Administration: user management, event log, consistency queries.
//!
//! Policy (who may do what, last-admin rules) lives in `rostdav-app`; this
//! layer only provides the transactions.

use rostdav_core::{Error, Name, Result};
use sqlx::SqliteConnection;

use crate::Db;
use crate::users::{new_etag, now_secs};

fn err(e: sqlx::Error) -> Error {
    Error::internal(e)
}

type SummaryRow = (i64, String, bool, bool, Option<i64>, i64, i64, i64);
type EventRow = (i64, i64, String, String, String, String, String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserSummary {
    pub id: i64,
    pub name: String,
    pub is_admin: bool,
    pub disabled: bool,
    pub quota_bytes: Option<i64>,
    pub used_bytes: i64,
    pub created_at: i64,
    pub devices: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub id: i64,
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub ip: String,
    /// JSON text.
    pub details: String,
}

/// Disk usage as stored versus as computed from the nodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageMismatch {
    pub user_id: i64,
    pub user: String,
    pub stored: i64,
    pub actual: i64,
}

impl Db {
    pub async fn list_users(&self) -> Result<Vec<UserSummary>> {
        let rows: Vec<SummaryRow> = sqlx::query_as(
            "SELECT u.id, u.name, u.is_admin, u.disabled, u.quota_bytes, u.used_bytes, u.created_at,
                    (SELECT count(*) FROM app_passwords a WHERE a.user_id = u.id)
             FROM users u ORDER BY u.name_key",
        )
        .fetch_all(self.pool())
        .await
        .map_err(err)?;
        Ok(rows
            .into_iter()
            .map(
                |(id, name, is_admin, disabled, quota_bytes, used_bytes, created_at, devices)| {
                    UserSummary {
                        id,
                        name,
                        is_admin,
                        disabled,
                        quota_bytes,
                        used_bytes,
                        created_at,
                        devices,
                    }
                },
            )
            .collect())
    }

    /// Enabled administrators other than `except`.
    pub async fn count_enabled_admins_except(&self, except: i64) -> Result<i64> {
        sqlx::query_scalar(
            "SELECT count(*) FROM users WHERE is_admin = 1 AND disabled = 0 AND id != ?",
        )
        .bind(except)
        .fetch_one(self.pool())
        .await
        .map_err(err)
    }

    pub async fn set_user_disabled(&self, id: i64, disabled: bool) -> Result<()> {
        self.update_user("UPDATE users SET disabled = ? WHERE id = ?", disabled, id)
            .await
    }

    pub async fn set_user_admin(&self, id: i64, admin: bool) -> Result<()> {
        self.update_user("UPDATE users SET is_admin = ? WHERE id = ?", admin, id)
            .await
    }

    async fn update_user(&self, sql: &str, flag: bool, id: i64) -> Result<()> {
        let r = sqlx::query(sql)
            .bind(flag)
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(err)?;
        if r.rows_affected() == 0 {
            Err(Error::NotFound)
        } else {
            Ok(())
        }
    }

    pub async fn set_password_hash(&self, id: i64, hash: &str) -> Result<()> {
        let r = sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(hash)
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(err)?;
        if r.rows_affected() == 0 {
            Err(Error::NotFound)
        } else {
            Ok(())
        }
    }

    pub async fn revoke_all_app_passwords(&self, user_id: i64) -> Result<u64> {
        let r = sqlx::query("DELETE FROM app_passwords WHERE user_id = ?")
            .bind(user_id)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(r.rows_affected())
    }

    /// Deletes a user with everything they own (nodes, devices, sessions) in one
    /// transaction. Blob rows stay; garbage collection removes them.
    pub async fn delete_user(&self, id: i64) -> Result<()> {
        let r = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(err)?;
        if r.rows_affected() == 0 {
            Err(Error::NotFound)
        } else {
            Ok(())
        }
    }

    /// Moves everything in `from`'s tree into a new folder in `to`'s root and
    /// returns the folder name. Sizes move with the data (a quota of `to` is
    /// not enforced: this is an administrator decision).
    pub async fn transfer_tree(&self, from: i64, to: i64, base_name: &str) -> Result<String> {
        let now = now_secs();
        let mut tx = self
            .pool()
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(err)?;
        let from_root = root_id(&mut tx, from).await?;
        let to_root = root_id(&mut tx, to).await?;

        // pick a free folder name below the target's root
        let mut name = base_name.to_owned();
        let mut n = 1;
        while exists_child(&mut tx, to_root, &name).await? {
            n += 1;
            name = format!("{base_name} {n}");
        }
        let key = Name::parse(&name)?.key().to_owned();
        let folder: i64 = sqlx::query_scalar(
            "INSERT INTO nodes (owner_id, parent_id, name, name_key, kind, mtime, etag, created_at, updated_at)
             VALUES (?, ?, ?, ?, 'dir', ?, ?, ?, ?) RETURNING id",
        )
        .bind(to)
        .bind(to_root)
        .bind(&name)
        .bind(&key)
        .bind(now)
        .bind(new_etag())
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(err)?;

        // top-level children of the old root move below the new folder ...
        sqlx::query("UPDATE nodes SET parent_id = ?, updated_at = ? WHERE parent_id = ? AND trash_id IS NULL")
            .bind(folder)
            .bind(now)
            .bind(from_root)
            .execute(&mut *tx)
            .await
            .map_err(err)?;
        // ... and the whole subtree changes owner
        sqlx::query(
            "WITH RECURSIVE sub(id) AS (
                 SELECT id FROM nodes WHERE parent_id = ?1 AND trash_id IS NULL
                 UNION ALL SELECT n.id FROM nodes n JOIN sub s ON n.parent_id = s.id WHERE n.trash_id IS NULL
             )
             UPDATE nodes SET owner_id = ?2 WHERE id IN (SELECT id FROM sub) OR id = ?1",
        )
        .bind(folder)
        .bind(to)
        .execute(&mut *tx)
        .await
        .map_err(err)?;

        // shares on the moved nodes now belong to the new owner; a share to the new owner makes no sense any more
        sqlx::query(
            "WITH RECURSIVE sub(id) AS (
                 SELECT id FROM nodes WHERE parent_id = ?1 AND trash_id IS NULL
                 UNION ALL SELECT n.id FROM nodes n JOIN sub s ON n.parent_id = s.id WHERE n.trash_id IS NULL
             )
             UPDATE shares SET owner_id = ?2 WHERE node_id IN (SELECT id FROM sub)",
        )
        .bind(folder)
        .bind(to)
        .execute(&mut *tx)
        .await
        .map_err(err)?;
        sqlx::query("DELETE FROM shares WHERE owner_id = ?1 AND recipient_id = ?1")
            .bind(to)
            .execute(&mut *tx)
            .await
            .map_err(err)?;

        let moved: i64 = sqlx::query_scalar(
            "WITH RECURSIVE sub(id) AS (
                 SELECT id FROM nodes WHERE parent_id = ?1 AND trash_id IS NULL
                 UNION ALL SELECT n.id FROM nodes n JOIN sub s ON n.parent_id = s.id WHERE n.trash_id IS NULL
             )
             SELECT COALESCE((SELECT SUM(size) FROM nodes WHERE id IN (SELECT id FROM sub)), 0)
                  + COALESCE((SELECT SUM(size) FROM versions WHERE node_id IN (SELECT id FROM sub)), 0)",
        )
        .bind(folder)
        .fetch_one(&mut *tx)
        .await
        .map_err(err)?;
        sqlx::query("UPDATE users SET used_bytes = used_bytes + ? WHERE id = ?")
            .bind(moved)
            .bind(to)
            .execute(&mut *tx)
            .await
            .map_err(err)?;
        sqlx::query("UPDATE users SET used_bytes = MAX(used_bytes - ?, 0) WHERE id = ?")
            .bind(moved)
            .bind(from)
            .execute(&mut *tx)
            .await
            .map_err(err)?;
        // ancestors of the new folder change
        sqlx::query("UPDATE nodes SET etag = ?, mtime = ?, updated_at = ? WHERE id = ?")
            .bind(new_etag())
            .bind(now)
            .bind(now)
            .bind(to_root)
            .execute(&mut *tx)
            .await
            .map_err(err)?;
        tx.commit().await.map_err(err)?;
        Ok(name)
    }

    // ---- event log ----------------------------------------------------------

    pub async fn record_event(
        &self,
        actor: &str,
        action: &str,
        target: &str,
        ip: &str,
        details: &str,
    ) -> Result<()> {
        self.record_event_at(now_secs(), actor, action, target, ip, details)
            .await
    }

    /// Like [`record_event`](Self::record_event) with an explicit time (tests, imports).
    pub async fn record_event_at(
        &self,
        ts: i64,
        actor: &str,
        action: &str,
        target: &str,
        ip: &str,
        details: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO events (ts, actor, action, target, ip, details) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(ts)
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(ip)
        .bind(details)
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(())
    }

    /// Events at or after `since` (unix seconds), oldest first.
    pub async fn events_since(&self, since: i64) -> Result<Vec<Event>> {
        let rows: Vec<EventRow> = sqlx::query_as(
            "SELECT id, ts, actor, action, target, ip, details FROM events WHERE ts >= ? ORDER BY id",
        )
        .bind(since)
        .fetch_all(self.pool())
        .await
        .map_err(err)?;
        Ok(rows
            .into_iter()
            .map(|(id, ts, actor, action, target, ip, details)| Event {
                id,
                ts,
                actor,
                action,
                target,
                ip,
                details,
            })
            .collect())
    }

    pub async fn purge_events_before(&self, cutoff: i64) -> Result<u64> {
        let r = sqlx::query("DELETE FROM events WHERE ts < ?")
            .bind(cutoff)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(r.rows_affected())
    }

    // ---- consistency (fsck) -----------------------------------------------------

    /// All registered blobs as `(id, size, checksum)`.
    pub async fn all_blobs(&self) -> Result<Vec<(String, i64, String)>> {
        sqlx::query_as("SELECT id, size, checksum FROM blobs")
            .fetch_all(self.pool())
            .await
            .map_err(err)
    }

    /// Paths of nodes that reference a blob (for reporting damage).
    pub async fn nodes_using_blob(&self, blob_id: &str) -> Result<Vec<(String, String)>> {
        sqlx::query_as(
            "SELECT u.name, n.name FROM nodes n JOIN users u ON u.id = n.owner_id WHERE n.blob_id = ?1
             UNION
             SELECT u.name, n.name || ' (version ' || v.version_time || ')' FROM versions v
               JOIN nodes n ON n.id = v.node_id JOIN users u ON u.id = n.owner_id WHERE v.blob_id = ?1
             LIMIT 20",
        )
        .bind(blob_id)
        .fetch_all(self.pool())
        .await
        .map_err(err)
    }

    pub async fn usage_mismatches(&self) -> Result<Vec<UsageMismatch>> {
        let rows: Vec<(i64, String, i64, i64)> = sqlx::query_as(
            "SELECT u.id, u.name, u.used_bytes,
                    COALESCE((SELECT SUM(size) FROM nodes n WHERE n.owner_id = u.id AND n.kind = 'file'), 0)
                    + COALESCE((SELECT SUM(v.size) FROM versions v JOIN nodes n ON n.id = v.node_id WHERE n.owner_id = u.id), 0)
             FROM users u",
        )
        .fetch_all(self.pool())
        .await
        .map_err(err)?;
        Ok(rows
            .into_iter()
            .filter(|(_, _, stored, actual)| stored != actual)
            .map(|(user_id, user, stored, actual)| UsageMismatch {
                user_id,
                user,
                stored,
                actual,
            })
            .collect())
    }

    pub async fn set_used_bytes(&self, user_id: i64, used: i64) -> Result<()> {
        sqlx::query("UPDATE users SET used_bytes = ? WHERE id = ?")
            .bind(used)
            .bind(user_id)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(())
    }

    pub async fn all_upload_sessions(&self) -> Result<Vec<crate::UploadSession>> {
        self.upload_sessions_older_than(i64::MAX).await
    }

    /// Blob rows deleted by the caller after confirming the file is gone for good.
    pub async fn delete_blob_row(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM blobs WHERE id = ? AND id NOT IN (SELECT blob_id FROM nodes WHERE blob_id IS NOT NULL)")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(())
    }
}

async fn root_id(conn: &mut SqliteConnection, user: i64) -> Result<i64> {
    sqlx::query_scalar("SELECT id FROM nodes WHERE owner_id = ? AND parent_id IS NULL")
        .bind(user)
        .fetch_optional(conn)
        .await
        .map_err(err)?
        .ok_or(Error::NotFound)
}

async fn exists_child(conn: &mut SqliteConnection, parent: i64, name: &str) -> Result<bool> {
    let key = Name::parse(name)?.key().to_owned();
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nodes WHERE parent_id = ? AND name_key = ? AND trash_id IS NULL)")
        .bind(parent)
        .bind(key)
        .fetch_one(conn)
        .await
        .map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_db;
    use crate::{NewBlob, NewUser, WriteCondition};

    async fn user(db: &Db, name: &str, admin: bool) -> i64 {
        db.create_user(NewUser {
            name,
            password_hash: "h",
            is_admin: admin,
        })
        .await
        .expect("user")
        .id
    }

    async fn file(
        db: &Db,
        owner: i64,
        parent: Option<i64>,
        name: &str,
        tag: &str,
        size: i64,
    ) -> i64 {
        let root = match parent {
            Some(p) => p,
            None => db.root_node(owner).await.expect("root").id,
        };
        let blob = NewBlob {
            id: format!("{tag:0>26}"),
            size,
            checksum: "c".into(),
        };
        db.commit_file(
            root,
            &Name::parse(name).expect("n"),
            &blob,
            None,
            &WriteCondition::None,
        )
        .await
        .expect("commit")
        .node
        .id
    }

    #[tokio::test]
    async fn listing_flags_and_admin_counts() {
        let (_d, db) = test_db().await;
        let (a, b) = (user(&db, "anna", true).await, user(&db, "bob", true).await);
        user(&db, "carl", false).await;
        db.create_app_password(a, "Phone", "h1").await.expect("app");
        let list = db.list_users().await.expect("list");
        assert_eq!(
            list.iter().map(|u| u.name.as_str()).collect::<Vec<_>>(),
            ["anna", "bob", "carl"]
        );
        assert_eq!(list[0].devices, 1);
        assert_eq!(db.count_enabled_admins_except(a).await.expect("c"), 1);
        db.set_user_disabled(b, true).await.expect("disable");
        assert_eq!(
            db.count_enabled_admins_except(a).await.expect("c"),
            0,
            "disabled admins do not count"
        );
        db.set_user_disabled(b, false).await.expect("enable");
        db.set_user_admin(b, false).await.expect("demote");
        assert_eq!(db.count_enabled_admins_except(a).await.expect("c"), 0);
        assert!(matches!(
            db.set_user_disabled(999, true).await,
            Err(Error::NotFound)
        ));
        db.set_password_hash(a, "new").await.expect("pw");
        assert_eq!(
            db.find_user("anna")
                .await
                .expect("f")
                .expect("u")
                .password_hash,
            "new"
        );
        assert_eq!(db.revoke_all_app_passwords(a).await.expect("r"), 1);
    }

    #[tokio::test]
    async fn events_roundtrip_and_purge() {
        let (_d, db) = test_db().await;
        db.record_event("cli", "admin.user_created", "anna", "", "{\"admin\":true}")
            .await
            .expect("e");
        db.record_event("anna", "auth.login", "", "10.0.0.0", "{}")
            .await
            .expect("e");
        let all = db.events_since(0).await.expect("all");
        assert_eq!(all.len(), 2);
        assert_eq!(
            (all[0].actor.as_str(), all[0].action.as_str()),
            ("cli", "admin.user_created")
        );
        assert_eq!(all[1].ip, "10.0.0.0");
        assert!(db.events_since(i64::MAX).await.expect("none").is_empty());
        assert_eq!(db.purge_events_before(i64::MAX).await.expect("purge"), 2);
        assert!(db.events_since(0).await.expect("e").is_empty());
    }

    #[tokio::test]
    async fn transfer_moves_tree_ownership_and_usage() {
        let (_d, db) = test_db().await;
        let (a, b) = (
            user(&db, "anna", false).await,
            user(&db, "bob", false).await,
        );
        let ra = db.root_node(a).await.expect("r").id;
        let docs = db
            .create_dir(ra, &Name::parse("Docs").expect("n"))
            .await
            .expect("d")
            .id;
        file(&db, a, Some(docs), "f.txt", "1", 5).await;
        file(&db, a, None, "top.txt", "2", 7).await;
        file(&db, b, None, "mine.txt", "3", 1).await;
        // name clash in bob's root
        let rb = db.root_node(b).await.expect("r").id;
        db.create_dir(rb, &Name::parse("anna (transferred)").expect("n"))
            .await
            .expect("clash");

        let folder = db
            .transfer_tree(a, b, "anna (transferred)")
            .await
            .expect("transfer");
        assert_eq!(folder, "anna (transferred) 2");
        let list = db.list_users().await.expect("l");
        assert_eq!((list[0].used_bytes, list[1].used_bytes), (0, 13));
        assert!(db.usage_mismatches().await.expect("m").is_empty());
        let path = rostdav_core::LogicalPath::from_url_path("/anna%20(transferred)%202/Docs/f.txt")
            .expect("p");
        let n = db.resolve(b, &path).await.expect("r").expect("moved");
        assert_eq!(n.owner_id, b);
        // anna's root is empty now and she can be deleted without touching bob's data
        assert!(db.children(ra).await.expect("c").is_empty());
        db.delete_user(a).await.expect("delete");
        assert!(db.resolve(b, &path).await.expect("r").is_some());
        assert!(matches!(db.delete_user(a).await, Err(Error::NotFound)));
    }

    #[tokio::test]
    async fn delete_user_removes_data_and_leaves_blobs_for_gc() {
        let (_d, db) = test_db().await;
        let a = user(&db, "anna", false).await;
        file(&db, a, None, "f", "1", 5).await;
        db.delete_user(a).await.expect("delete");
        assert_eq!(db.count_blobs().await.expect("c"), 1);
        assert_eq!(
            db.delete_unreferenced_blobs().await.expect("gc"),
            vec![format!("{:0>26}", "1")]
        );
    }

    #[tokio::test]
    async fn usage_mismatch_is_detected_and_fixable() {
        let (_d, db) = test_db().await;
        let a = user(&db, "anna", false).await;
        file(&db, a, None, "f", "1", 5).await;
        db.set_used_bytes(a, 99).await.expect("break");
        let m = db.usage_mismatches().await.expect("m");
        assert_eq!(
            m,
            vec![UsageMismatch {
                user_id: a,
                user: "anna".into(),
                stored: 99,
                actual: 5
            }]
        );
        db.set_used_bytes(a, 5).await.expect("fix");
        assert!(db.usage_mismatches().await.expect("m").is_empty());
        assert_eq!(
            db.nodes_using_blob(&format!("{:0>26}", "1"))
                .await
                .expect("n"),
            vec![("anna".to_owned(), "f".to_owned())]
        );
    }
}
