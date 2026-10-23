//! Favorites: a set of (user, node) pairs.

use crate::sql;
use std::collections::HashSet;

use rostdav_core::{Error, Result};

use crate::Db;

fn err(e: sql::Error) -> Error {
    Error::internal(e)
}

impl Db {
    /// Marks or unmarks `node_id` as a favorite of `user_id`.
    pub async fn favorite_set(&self, user_id: i64, node_id: i64, on: bool) -> Result<()> {
        let sql = if on {
            "INSERT OR IGNORE INTO favorites (user_id, node_id) VALUES (?, ?)"
        } else {
            "DELETE FROM favorites WHERE user_id = ? AND node_id = ?"
        };
        sql::query(sql)
            .bind(user_id)
            .bind(node_id)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(())
    }

    /// Those of `node_ids` that are favorites of the user.
    pub async fn favorites_among(&self, user_id: i64, node_ids: &[i64]) -> Result<HashSet<i64>> {
        if node_ids.is_empty() {
            return Ok(HashSet::new());
        }
        let marks = vec!["?"; node_ids.len()].join(",");
        let sql =
            format!("SELECT node_id FROM favorites WHERE user_id = ? AND node_id IN ({marks})");
        let mut q = sql::query_scalar::<i64>(&sql).bind(user_id);
        for id in node_ids {
            q = q.bind(id);
        }
        Ok(q.fetch_all(self.pool())
            .await
            .map_err(err)?
            .into_iter()
            .collect())
    }

    /// Favorites of the user that live in the user's own tree (not in the trash).
    pub async fn favorites_own(&self, user_id: i64) -> Result<Vec<i64>> {
        sql::query_scalar(
            "SELECT f.node_id FROM favorites f JOIN nodes n ON n.id = f.node_id
             WHERE f.user_id = ?1 AND n.owner_id = ?1 AND n.trash_id IS NULL AND n.parent_id IS NOT NULL
             ORDER BY f.node_id",
        )
        .bind(user_id)
        .fetch_all(self.pool())
        .await
        .map_err(err)
    }
}

#[cfg(test)]
mod tests {

    use crate::NewUser;
    use crate::tests::test_db;

    #[tokio::test]
    async fn set_unset_and_cascade() {
        let (_dir, db) = test_db().await;
        let u = db
            .create_user(NewUser {
                name: "alice",
                password_hash: "h",
                is_admin: false,
            })
            .await
            .expect("u")
            .id;
        let root = db.root_node(u).await.expect("root");
        let n = db
            .create_dir(root.id, &rostdav_core::Name::parse("A").expect("n"))
            .await
            .expect("dir");
        db.favorite_set(u, n.id, true).await.expect("set");
        db.favorite_set(u, n.id, true).await.expect("idempotent");
        assert_eq!(db.favorites_own(u).await.expect("l"), vec![n.id]);
        assert!(
            db.favorites_among(u, &[n.id, 999])
                .await
                .expect("a")
                .contains(&n.id)
        );
        db.favorite_set(u, n.id, false).await.expect("unset");
        assert!(db.favorites_own(u).await.expect("l").is_empty());
    }
}
