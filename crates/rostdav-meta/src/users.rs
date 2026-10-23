//! Users and their root nodes.

use crate::sql;
use rostdav_core::{Error, Name, Result};

use crate::Db;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub password_hash: String,
    pub is_admin: bool,
    pub disabled: bool,
}

pub struct NewUser<'a> {
    pub name: &'a str,
    /// Finished hash (PHC string); plaintext passwords never reach this layer.
    pub password_hash: &'a str,
    pub is_admin: bool,
}

impl Db {
    /// Creates a user and its root node in one transaction.
    ///
    /// The user name is unique by its NFC form; duplicates yield
    /// [`Error::Conflict`].
    pub async fn create_user(&self, new: NewUser<'_>) -> Result<User> {
        let name = Name::parse(new.name)?;
        let now = now_secs();
        let mut tx = self.pool().begin().await.map_err(Error::internal)?;

        let id: i64 = sql::query_scalar(
            "INSERT INTO users (name, name_key, password_hash, is_admin, created_at)
             VALUES (?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(name.as_str())
        .bind(name.key())
        .bind(new.password_hash)
        .bind(new.is_admin)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match &e {
            e if e.is_unique_violation() => Error::Conflict("user already exists"),
            _ => Error::internal(e),
        })?;

        sql::query(
            "INSERT INTO nodes (owner_id, parent_id, name, name_key, kind, mtime, etag, created_at, updated_at)
             VALUES (?, NULL, '', '', 'dir', ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(now)
        .bind(new_etag())
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(Error::internal)?;

        tx.commit().await.map_err(Error::internal)?;
        Ok(User {
            id,
            name: name.as_str().to_owned(),
            password_hash: new.password_hash.to_owned(),
            is_admin: new.is_admin,
            disabled: false,
        })
    }

    /// Looks up a user by the NFC form of the name.
    pub async fn find_user(&self, name: &str) -> Result<Option<User>> {
        let Ok(name) = Name::parse(name) else {
            return Ok(None);
        };
        let row: Option<(i64, String, String, bool, bool)> = sql::query_as(
            "SELECT id, name, password_hash, is_admin, disabled FROM users WHERE name_key = ?",
        )
        .bind(name.key())
        .fetch_optional(self.pool())
        .await
        .map_err(Error::internal)?;
        Ok(
            row.map(|(id, name, password_hash, is_admin, disabled)| User {
                id,
                name,
                password_hash,
                is_admin,
                disabled,
            }),
        )
    }
}

pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Random ETag (a ULID suffices: unique, not guessable enough for cache validation).
pub(crate) fn new_etag() -> String {
    ulid::Ulid::generate().to_string().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_db;

    fn nu(name: &str) -> NewUser<'_> {
        NewUser {
            name,
            password_hash: "h",
            is_admin: false,
        }
    }

    #[tokio::test]
    async fn create_and_find_with_root_node() {
        let (_d, db) = test_db().await;
        let u = db.create_user(nu("anna")).await.expect("create");
        let found = db.find_user("anna").await.expect("find").expect("some");
        assert_eq!(found, u);
        let roots: i64 = sql::query_scalar(
            "SELECT count(*) FROM nodes WHERE owner_id = ? AND parent_id IS NULL AND kind = 'dir'",
        )
        .bind(u.id)
        .fetch_one(db.pool())
        .await
        .expect("count");
        assert_eq!(roots, 1);
    }

    #[tokio::test]
    async fn duplicate_is_conflict_and_nfc_equivalent() {
        let (_d, db) = test_db().await;
        db.create_user(nu("\u{00E9}va")).await.expect("create");
        let err = db.create_user(nu("e\u{0301}va")).await.expect_err("dup");
        assert!(matches!(err, Error::Conflict(_)));
        assert!(db.find_user("e\u{0301}va").await.expect("find").is_some());
    }

    #[tokio::test]
    async fn failed_create_leaves_no_user_or_node() {
        let (_d, db) = test_db().await;
        db.create_user(nu("anna")).await.expect("create");
        let _ = db.create_user(nu("anna")).await;
        let users: i64 = sql::query_scalar("SELECT count(*) FROM users")
            .fetch_one(db.pool())
            .await
            .expect("c");
        let nodes: i64 = sql::query_scalar("SELECT count(*) FROM nodes")
            .fetch_one(db.pool())
            .await
            .expect("c");
        assert_eq!((users, nodes), (1, 1));
    }

    #[tokio::test]
    async fn invalid_names_rejected_and_unknown_is_none() {
        let (_d, db) = test_db().await;
        assert!(matches!(
            db.create_user(nu("a/b")).await,
            Err(Error::BadRequest(_))
        ));
        assert!(db.find_user("nobody").await.expect("find").is_none());
        assert!(db.find_user("../x").await.expect("find").is_none());
    }
}
