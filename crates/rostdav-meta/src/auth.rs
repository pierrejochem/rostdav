//! App passwords, login flows and settings (ADR 0003).

use rostdav_core::{Error, Result};

use crate::Db;
use crate::users::now_secs;

fn err(e: sqlx::Error) -> Error {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => Error::AlreadyExists,
        _ => Error::internal(e),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppPassword {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginFlow {
    pub id: i64,
    pub client_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PollResult {
    /// Unknown, expired or not yet granted.
    Pending,
    Granted {
        login_name: String,
        app_password: String,
    },
}

impl Db {
    // ---- settings ----------------------------------------------------------

    /// Returns the value, creating it with `make()` if absent. Safe under races.
    pub async fn setting_or_init(
        &self,
        key: &str,
        make: impl FnOnce() -> Vec<u8>,
    ) -> Result<Vec<u8>> {
        sqlx::query("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)")
            .bind(key)
            .bind(make())
            .execute(self.pool())
            .await
            .map_err(err)?;
        sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
            .bind(key)
            .fetch_one(self.pool())
            .await
            .map_err(err)
    }

    // ---- app passwords -----------------------------------------------------

    pub async fn create_app_password(
        &self,
        user_id: i64,
        name: &str,
        token_hash: &str,
    ) -> Result<i64> {
        sqlx::query_scalar(
            "INSERT INTO app_passwords (user_id, name, token_hash, created_at) VALUES (?, ?, ?, ?) RETURNING id",
        )
        .bind(user_id)
        .bind(name)
        .bind(token_hash)
        .bind(now_secs())
        .fetch_one(self.pool())
        .await
        .map_err(err)
    }

    /// Looks up an app password of exactly this user.
    pub async fn find_app_password(&self, user_id: i64, token_hash: &str) -> Result<Option<i64>> {
        sqlx::query_scalar("SELECT id FROM app_passwords WHERE token_hash = ? AND user_id = ?")
            .bind(token_hash)
            .bind(user_id)
            .fetch_optional(self.pool())
            .await
            .map_err(err)
    }

    /// Records use, at most once per minute.
    pub async fn touch_app_password(&self, id: i64) -> Result<()> {
        let now = now_secs();
        sqlx::query(
            "UPDATE app_passwords SET last_used_at = ?1 WHERE id = ?2 AND (last_used_at IS NULL OR last_used_at < ?1 - 60)",
        )
        .bind(now)
        .bind(id)
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(())
    }

    /// Deletes an app password of this user; returns whether one existed.
    pub async fn revoke_app_password(&self, user_id: i64, id: i64) -> Result<bool> {
        let r = sqlx::query("DELETE FROM app_passwords WHERE id = ? AND user_id = ?")
            .bind(id)
            .bind(user_id)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn list_app_passwords(&self, user_id: i64) -> Result<Vec<AppPassword>> {
        let rows: Vec<(i64, i64, String, i64, Option<i64>)> = sqlx::query_as(
            "SELECT id, user_id, name, created_at, last_used_at FROM app_passwords WHERE user_id = ? ORDER BY id",
        )
        .bind(user_id)
        .fetch_all(self.pool())
        .await
        .map_err(err)?;
        Ok(rows
            .into_iter()
            .map(
                |(id, user_id, name, created_at, last_used_at)| AppPassword {
                    id,
                    user_id,
                    name,
                    created_at,
                    last_used_at,
                },
            )
            .collect())
    }

    // ---- login flow v2 -----------------------------------------------------

    pub async fn create_login_flow(
        &self,
        poll_hash: &str,
        login_hash: &str,
        client_name: &str,
        ttl_secs: i64,
    ) -> Result<()> {
        let now = now_secs();
        // Opportunistic cleanup keeps the table small without a background job.
        sqlx::query("DELETE FROM login_flows WHERE expires_at < ?")
            .bind(now)
            .execute(self.pool())
            .await
            .map_err(err)?;
        sqlx::query(
            "INSERT INTO login_flows (poll_hash, login_hash, client_name, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(poll_hash)
        .bind(login_hash)
        .bind(client_name)
        .bind(now)
        .bind(now + ttl_secs)
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(())
    }

    /// An open (not expired, not yet granted) flow by its login token hash.
    pub async fn open_flow_by_login(&self, login_hash: &str) -> Result<Option<LoginFlow>> {
        let row: Option<(i64, String)> = sqlx::query_as(
            "SELECT id, client_name FROM login_flows WHERE login_hash = ? AND expires_at >= ? AND user_id IS NULL",
        )
        .bind(login_hash)
        .bind(now_secs())
        .fetch_optional(self.pool())
        .await
        .map_err(err)?;
        Ok(row.map(|(id, client_name)| LoginFlow { id, client_name }))
    }

    /// Marks an open flow as granted. Returns `false` if it was no longer open.
    pub async fn grant_flow(&self, flow_id: i64, user_id: i64, app_password: &str) -> Result<bool> {
        let r = sqlx::query(
            "UPDATE login_flows SET user_id = ?, app_password = ? WHERE id = ? AND user_id IS NULL AND expires_at >= ?",
        )
        .bind(user_id)
        .bind(app_password)
        .bind(flow_id)
        .bind(now_secs())
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(r.rows_affected() > 0)
    }

    /// Returns the granted credentials exactly once and deletes the flow.
    pub async fn poll_flow(&self, poll_hash: &str) -> Result<PollResult> {
        let row: Option<(String, String)> = sqlx::query_as(
            "DELETE FROM login_flows
             WHERE poll_hash = ? AND expires_at >= ? AND user_id IS NOT NULL
             RETURNING (SELECT name FROM users WHERE id = login_flows.user_id), app_password",
        )
        .bind(poll_hash)
        .bind(now_secs())
        .fetch_optional(self.pool())
        .await
        .map_err(err)?;
        Ok(
            row.map_or(PollResult::Pending, |(login_name, app_password)| {
                PollResult::Granted {
                    login_name,
                    app_password,
                }
            }),
        )
    }

    pub async fn find_user_by_id(&self, id: i64) -> Result<Option<crate::User>> {
        let row: Option<(i64, String, String, bool)> =
            sqlx::query_as("SELECT id, name, password_hash, is_admin FROM users WHERE id = ?")
                .bind(id)
                .fetch_optional(self.pool())
                .await
                .map_err(err)?;
        Ok(row.map(|(id, name, password_hash, is_admin)| crate::User {
            id,
            name,
            password_hash,
            is_admin,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NewUser;
    use crate::tests::test_db;

    async fn user(db: &Db, name: &str) -> i64 {
        db.create_user(NewUser {
            name,
            password_hash: "h",
            is_admin: false,
        })
        .await
        .expect("user")
        .id
    }

    #[tokio::test]
    async fn settings_init_once() {
        let (_d, db) = test_db().await;
        let a = db.setting_or_init("k", || vec![1, 2, 3]).await.expect("a");
        let b = db.setting_or_init("k", || vec![9]).await.expect("b");
        assert_eq!(a, vec![1, 2, 3]);
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn app_password_lifecycle_and_isolation() {
        let (_d, db) = test_db().await;
        let (anna, bob) = (user(&db, "anna").await, user(&db, "bob").await);
        let id = db
            .create_app_password(anna, "Phone", "hash1")
            .await
            .expect("create");
        assert_eq!(
            db.find_app_password(anna, "hash1").await.expect("f"),
            Some(id)
        );
        assert_eq!(
            db.find_app_password(bob, "hash1").await.expect("f"),
            None,
            "other user"
        );
        assert_eq!(db.find_app_password(anna, "nope").await.expect("f"), None);
        assert!(matches!(
            db.create_app_password(bob, "x", "hash1").await,
            Err(Error::AlreadyExists)
        ));
        db.touch_app_password(id).await.expect("touch");
        let list = db.list_app_passwords(anna).await.expect("list");
        assert_eq!(list.len(), 1);
        assert!(list[0].last_used_at.is_some());
        assert!(!db.revoke_app_password(bob, id).await.expect("bob revoke"));
        assert!(db.revoke_app_password(anna, id).await.expect("revoke"));
        assert_eq!(db.find_app_password(anna, "hash1").await.expect("f"), None);
    }

    #[tokio::test]
    async fn login_flow_grant_and_single_poll() {
        let (_d, db) = test_db().await;
        let anna = user(&db, "anna").await;
        db.create_login_flow("p", "l", "Phone", 600)
            .await
            .expect("create");
        assert_eq!(db.poll_flow("p").await.expect("poll"), PollResult::Pending);
        let flow = db
            .open_flow_by_login("l")
            .await
            .expect("open")
            .expect("some");
        assert_eq!(flow.client_name, "Phone");
        assert!(db.grant_flow(flow.id, anna, "secret").await.expect("grant"));
        assert!(
            !db.grant_flow(flow.id, anna, "again")
                .await
                .expect("2nd grant")
        );
        assert!(
            db.open_flow_by_login("l").await.expect("open").is_none(),
            "granted flows are closed"
        );
        assert_eq!(
            db.poll_flow("p").await.expect("poll"),
            PollResult::Granted {
                login_name: "anna".into(),
                app_password: "secret".into()
            }
        );
        assert_eq!(
            db.poll_flow("p").await.expect("poll"),
            PollResult::Pending,
            "only once"
        );
    }

    #[tokio::test]
    async fn expired_flows_are_invisible() {
        let (_d, db) = test_db().await;
        let anna = user(&db, "anna").await;
        db.create_login_flow("p", "l", "Phone", -1)
            .await
            .expect("create");
        assert!(db.open_flow_by_login("l").await.expect("open").is_none());
        // even a granted-but-expired flow is not returned
        sqlx::query("UPDATE login_flows SET user_id = ?, app_password = 's'")
            .bind(anna)
            .execute(db.pool())
            .await
            .expect("force");
        assert_eq!(db.poll_flow("p").await.expect("poll"), PollResult::Pending);
    }

    #[tokio::test]
    async fn deleting_user_removes_credentials() {
        let (_d, db) = test_db().await;
        let anna = user(&db, "anna").await;
        db.create_app_password(anna, "Phone", "h")
            .await
            .expect("create");
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(anna)
            .execute(db.pool())
            .await
            .expect("del");
        assert_eq!(db.find_app_password(anna, "h").await.expect("f"), None);
    }
}
