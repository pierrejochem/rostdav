use crate::sql;
use rostdav_core::{Error, Result};

use crate::Db;
use crate::users::now_secs;

fn err(e: sql::Error) -> Error {
    Error::internal(e)
}

/// A stored profile picture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAvatar {
    pub mime: String,
    pub data: Vec<u8>,
    pub etag: String,
}

impl Db {
    /// Stores or replaces the picture of a user.
    pub async fn avatar_set(
        &self,
        user_id: i64,
        mime: &str,
        data: &[u8],
        etag: &str,
    ) -> Result<()> {
        sql::query(
            "INSERT INTO avatars (user_id, mime, data, etag, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(user_id) DO UPDATE SET mime = ?2, data = ?3, etag = ?4, updated_at = ?5",
        )
        .bind(user_id)
        .bind(mime)
        .bind(data)
        .bind(etag)
        .bind(now_secs())
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(())
    }

    pub async fn avatar_get(&self, user_id: i64) -> Result<Option<StoredAvatar>> {
        let row: Option<(String, Vec<u8>, String)> =
            sql::query_as("SELECT mime, data, etag FROM avatars WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(self.pool())
                .await
                .map_err(err)?;
        Ok(row.map(|(mime, data, etag)| StoredAvatar { mime, data, etag }))
    }

    /// The version (ETag) of the user's picture, if there is one, without reading the picture.
    pub async fn avatar_etag(&self, user_id: i64) -> Result<Option<String>> {
        sql::query_scalar::<String>("SELECT etag FROM avatars WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(self.pool())
            .await
            .map_err(err)
    }

    pub async fn avatar_delete(&self, user_id: i64) -> Result<bool> {
        let r = sql::query("DELETE FROM avatars WHERE user_id = ?")
            .bind(user_id)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(r.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::NewUser;
    use crate::tests::test_db;

    #[tokio::test]
    async fn set_replace_get_delete_and_cascade() {
        let (_d, db) = test_db().await;
        let u = db
            .create_user(NewUser {
                name: "anna",
                password_hash: "h",
                is_admin: false,
            })
            .await
            .expect("user");
        assert!(db.avatar_get(u.id).await.expect("get").is_none());
        db.avatar_set(u.id, "image/png", b"one", "e1")
            .await
            .expect("set");
        db.avatar_set(u.id, "image/jpeg", b"two", "e2")
            .await
            .expect("replace");
        let a = db.avatar_get(u.id).await.expect("get").expect("some");
        assert_eq!(
            (a.mime.as_str(), a.data.as_slice(), a.etag.as_str()),
            ("image/jpeg", &b"two"[..], "e2")
        );
        assert_eq!(
            db.avatar_etag(u.id).await.expect("etag").as_deref(),
            Some("e2")
        );
        // the database refuses other types and big blobs even if the application did not
        assert!(
            db.avatar_set(u.id, "image/svg+xml", b"x", "e")
                .await
                .is_err()
        );
        assert!(
            db.avatar_set(u.id, "image/png", &vec![0u8; 262_145], "e")
                .await
                .is_err()
        );
        assert!(db.avatar_delete(u.id).await.expect("delete"));
        assert!(!db.avatar_delete(u.id).await.expect("again"));
        db.avatar_set(u.id, "image/png", b"x", "e")
            .await
            .expect("set");
        crate::sql::query("DELETE FROM users WHERE id = ?")
            .bind(u.id)
            .execute(db.pool())
            .await
            .expect("delete user");
        assert!(
            db.avatar_get(u.id).await.expect("get").is_none(),
            "removed with the user"
        );
    }
}
