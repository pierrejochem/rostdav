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

/// A browser session (ADR 0006).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub id: i64,
    pub user_id: i64,
    pub created_at: i64,
    pub last_seen: i64,
    pub expires_at: i64,
    pub ip: String,
    pub user_agent: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginFlow {
    pub id: i64,
    pub client_name: String,
    pub poll_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadSession {
    pub id: i64,
    pub user_id: i64,
    pub transfer_id: String,
    /// Directory name below `<data>/uploads/`.
    pub dir: String,
    pub created_at: i64,
}

/// Open chunked-upload sessions allowed per user.
pub const MAX_UPLOAD_SESSIONS_PER_USER: i64 = 200;

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
        max_open: i64,
    ) -> Result<()> {
        let now = now_secs();
        // Opportunistic cleanup keeps the table small without a background job.
        sqlx::query("DELETE FROM login_flows WHERE expires_at < ?")
            .bind(now)
            .execute(self.pool())
            .await
            .map_err(err)?;
        let (open,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM login_flows")
            .fetch_one(self.pool())
            .await
            .map_err(err)?;
        if open >= max_open {
            return Err(Error::RateLimited {
                retry_after_secs: 60,
            });
        }
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
        let row: Option<(i64, String, String)> = sqlx::query_as(
            "SELECT id, client_name, poll_hash FROM login_flows WHERE login_hash = ? AND expires_at >= ? AND user_id IS NULL",
        )
        .bind(login_hash)
        .bind(now_secs())
        .fetch_optional(self.pool())
        .await
        .map_err(err)?;
        Ok(row.map(|(id, client_name, poll_hash)| LoginFlow {
            id,
            client_name,
            poll_hash,
        }))
    }

    /// Deletes a flow that has not been granted yet.
    pub async fn delete_open_flow(&self, login_hash: &str) -> Result<()> {
        sqlx::query("DELETE FROM login_flows WHERE login_hash = ? AND user_id IS NULL")
            .bind(login_hash)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(())
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

    // ---- chunked upload sessions ---------------------------------------------

    /// Registers a session; [`Error::AlreadyExists`] if the transfer ID is in use.
    pub async fn create_upload_session(
        &self,
        user_id: i64,
        transfer_id: &str,
        dir: &str,
    ) -> Result<UploadSession> {
        let open: i64 =
            sqlx::query_scalar("SELECT count(*) FROM upload_sessions WHERE user_id = ?")
                .bind(user_id)
                .fetch_one(self.pool())
                .await
                .map_err(err)?;
        if open >= MAX_UPLOAD_SESSIONS_PER_USER {
            return Err(Error::Conflict("too many open uploads"));
        }
        let created_at = now_secs();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO upload_sessions (user_id, transfer_id, dir, created_at) VALUES (?, ?, ?, ?) RETURNING id",
        )
        .bind(user_id)
        .bind(transfer_id)
        .bind(dir)
        .bind(created_at)
        .fetch_one(self.pool())
        .await
        .map_err(err)?;
        Ok(UploadSession {
            id,
            user_id,
            transfer_id: transfer_id.to_owned(),
            dir: dir.to_owned(),
            created_at,
        })
    }

    pub async fn find_upload_session(
        &self,
        user_id: i64,
        transfer_id: &str,
    ) -> Result<Option<UploadSession>> {
        let row: Option<(i64, String, i64)> = sqlx::query_as(
            "SELECT id, dir, created_at FROM upload_sessions WHERE user_id = ? AND transfer_id = ?",
        )
        .bind(user_id)
        .bind(transfer_id)
        .fetch_optional(self.pool())
        .await
        .map_err(err)?;
        Ok(row.map(|(id, dir, created_at)| UploadSession {
            id,
            user_id,
            transfer_id: transfer_id.to_owned(),
            dir,
            created_at,
        }))
    }

    pub async fn delete_upload_session(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM upload_sessions WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(())
    }

    /// Sessions created before `cutoff` (unix seconds).
    pub async fn upload_sessions_older_than(&self, cutoff: i64) -> Result<Vec<UploadSession>> {
        let rows: Vec<(i64, i64, String, String, i64)> = sqlx::query_as(
            "SELECT id, user_id, transfer_id, dir, created_at FROM upload_sessions WHERE created_at < ?",
        )
        .bind(cutoff)
        .fetch_all(self.pool())
        .await
        .map_err(err)?;
        Ok(rows
            .into_iter()
            .map(
                |(id, user_id, transfer_id, dir, created_at)| UploadSession {
                    id,
                    user_id,
                    transfer_id,
                    dir,
                    created_at,
                },
            )
            .collect())
    }

    // ---- browser sessions -------------------------------------------------------

    pub async fn create_session(
        &self,
        user_id: i64,
        token_hash: &str,
        expires_at: i64,
        ip: &str,
        user_agent: &str,
    ) -> Result<Session> {
        let now = now_secs();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO sessions (user_id, token_hash, created_at, last_seen, expires_at, ip, user_agent)
             VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(user_id)
        .bind(token_hash)
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .bind(ip)
        .bind(user_agent)
        .fetch_one(self.pool())
        .await
        .map_err(err)?;
        Ok(Session {
            id,
            user_id,
            created_at: now,
            last_seen: now,
            expires_at,
            ip: ip.into(),
            user_agent: user_agent.into(),
        })
    }

    /// The session for a cookie hash, if it has not expired (`idle_secs` of
    /// inactivity count as expired too). Never returns sessions of disabled users.
    pub async fn find_session(
        &self,
        token_hash: &str,
        idle_secs: i64,
    ) -> Result<Option<(Session, crate::User)>> {
        let now = now_secs();
        let row: Option<(i64, i64, i64, i64, i64, String, String)> = sqlx::query_as(
            "SELECT s.id, s.user_id, s.created_at, s.last_seen, s.expires_at, s.ip, s.user_agent
             FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = ? AND s.expires_at > ? AND s.last_seen > ? AND u.disabled = 0",
        )
        .bind(token_hash)
        .bind(now)
        .bind(now - idle_secs)
        .fetch_optional(self.pool())
        .await
        .map_err(err)?;
        let Some((id, user_id, created_at, last_seen, expires_at, ip, user_agent)) = row else {
            return Ok(None);
        };
        let Some(user) = self.find_user_by_id(user_id).await? else {
            return Ok(None);
        };
        Ok(Some((
            Session {
                id,
                user_id,
                created_at,
                last_seen,
                expires_at,
                ip,
                user_agent,
            },
            user,
        )))
    }

    /// Records activity, at most once a minute.
    pub async fn touch_session(&self, id: i64) -> Result<()> {
        let now = now_secs();
        sqlx::query("UPDATE sessions SET last_seen = ?1 WHERE id = ?2 AND last_seen < ?1 - 60")
            .bind(now)
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(())
    }

    pub async fn delete_session(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(())
    }

    /// Ends all sessions of a user except `keep`. Returns how many.
    pub async fn delete_other_sessions(&self, user_id: i64, keep: i64) -> Result<u64> {
        let r = sqlx::query("DELETE FROM sessions WHERE user_id = ? AND id != ?")
            .bind(user_id)
            .bind(keep)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(r.rows_affected())
    }

    pub async fn delete_user_sessions(&self, user_id: i64) -> Result<u64> {
        let r = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(user_id)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(r.rows_affected())
    }

    pub async fn list_sessions(&self, user_id: i64) -> Result<Vec<Session>> {
        let rows: Vec<(i64, i64, i64, i64, String, String)> = sqlx::query_as(
            "SELECT id, created_at, last_seen, expires_at, ip, user_agent FROM sessions WHERE user_id = ? ORDER BY last_seen DESC",
        )
        .bind(user_id)
        .fetch_all(self.pool())
        .await
        .map_err(err)?;
        Ok(rows
            .into_iter()
            .map(
                |(id, created_at, last_seen, expires_at, ip, user_agent)| Session {
                    id,
                    user_id,
                    created_at,
                    last_seen,
                    expires_at,
                    ip,
                    user_agent,
                },
            )
            .collect())
    }

    /// Removes expired and idle sessions.
    pub async fn purge_sessions(&self, idle_secs: i64) -> Result<u64> {
        let now = now_secs();
        let r = sqlx::query("DELETE FROM sessions WHERE expires_at <= ? OR last_seen <= ?")
            .bind(now)
            .bind(now - idle_secs)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(r.rows_affected())
    }

    // ---- preferences ----------------------------------------------------------------

    pub async fn get_pref(&self, user_id: i64, key: &str) -> Result<Option<String>> {
        sqlx::query_scalar("SELECT value FROM user_prefs WHERE user_id = ? AND key = ?")
            .bind(user_id)
            .bind(key)
            .fetch_optional(self.pool())
            .await
            .map_err(err)
    }

    pub async fn set_pref(&self, user_id: i64, key: &str, value: &str) -> Result<()> {
        sqlx::query("INSERT INTO user_prefs (user_id, key, value) VALUES (?, ?, ?) ON CONFLICT (user_id, key) DO UPDATE SET value = excluded.value")
            .bind(user_id)
            .bind(key)
            .bind(value)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(())
    }

    pub async fn find_user_by_id(&self, id: i64) -> Result<Option<crate::User>> {
        let row: Option<(i64, String, String, bool, bool)> = sqlx::query_as(
            "SELECT id, name, password_hash, is_admin, disabled FROM users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(err)?;
        Ok(row.map(
            |(id, name, password_hash, is_admin, disabled)| crate::User {
                id,
                name,
                password_hash,
                is_admin,
                disabled,
            },
        ))
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
    async fn open_login_flows_are_capped_and_expired_ones_do_not_count() {
        let (_d, db) = test_db().await;
        db.create_login_flow("p1", "l1", "A", 600, 2)
            .await
            .expect("1");
        db.create_login_flow("p2", "l2", "B", 600, 2)
            .await
            .expect("2");
        assert!(matches!(
            db.create_login_flow("p3", "l3", "C", 600, 2).await,
            Err(Error::RateLimited { .. })
        ));
        sqlx::query("UPDATE login_flows SET expires_at = 0 WHERE poll_hash = 'p1'")
            .execute(db.pool())
            .await
            .expect("expire");
        db.create_login_flow("p3", "l3", "C", 600, 2)
            .await
            .expect("room again");
    }

    #[tokio::test]
    async fn login_flow_grant_and_single_poll() {
        let (_d, db) = test_db().await;
        let anna = user(&db, "anna").await;
        db.create_login_flow("p", "l", "Phone", 600, 100)
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
        db.create_login_flow("p", "l", "Phone", -1, 100)
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
    async fn upload_sessions_unique_per_user_and_expire() {
        let (_d, db) = test_db().await;
        let (a, b) = (user(&db, "anna").await, user(&db, "bob").await);
        let dir = |c: char| c.to_string().repeat(26);
        let s = db
            .create_upload_session(a, "t1", &dir('A'))
            .await
            .expect("create");
        assert!(matches!(
            db.create_upload_session(a, "t1", &dir('B')).await,
            Err(Error::AlreadyExists)
        ));
        db.create_upload_session(b, "t1", &dir('C'))
            .await
            .expect("other user, same transfer id");
        assert_eq!(
            db.find_upload_session(a, "t1").await.expect("f"),
            Some(s.clone())
        );
        assert!(
            db.find_upload_session(a, "nope")
                .await
                .expect("f")
                .is_none()
        );
        assert_eq!(
            db.upload_sessions_older_than(s.created_at + 1)
                .await
                .expect("old")
                .len(),
            2
        );
        assert!(
            db.upload_sessions_older_than(s.created_at - 1)
                .await
                .expect("old")
                .is_empty()
        );
        db.delete_upload_session(s.id).await.expect("del");
        assert!(db.find_upload_session(a, "t1").await.expect("f").is_none());
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

    #[tokio::test]
    async fn sessions_expire_idle_out_and_follow_the_user() {
        let (_d, db) = test_db().await;
        let (a, b) = (user(&db, "anna").await, user(&db, "bob").await);
        let far = i64::MAX / 2;
        let s1 = db
            .create_session(a, "h1", far, "10.0.0.1", "UA")
            .await
            .expect("create");
        let s2 = db
            .create_session(a, "h2", far, "", "")
            .await
            .expect("create");
        db.create_session(b, "h3", far, "", "")
            .await
            .expect("create");
        let (found, user_row) = db.find_session("h1", 3600).await.expect("f").expect("some");
        assert_eq!(
            (found.id, user_row.name.as_str(), found.ip.as_str()),
            (s1.id, "anna", "10.0.0.1")
        );
        assert!(db.find_session("nope", 3600).await.expect("f").is_none());
        // idle timeout
        assert!(db.find_session("h1", -1).await.expect("f").is_none());
        // absolute expiry
        db.create_session(a, "old", 1, "", "")
            .await
            .expect("create");
        assert!(db.find_session("old", 3600).await.expect("f").is_none());
        assert_eq!(db.purge_sessions(3600).await.expect("p"), 1);
        // disabled users have no sessions
        db.set_user_disabled(b, true).await.expect("disable");
        assert!(db.find_session("h3", 3600).await.expect("f").is_none());
        // listing and ending
        assert_eq!(db.list_sessions(a).await.expect("l").len(), 2);
        assert_eq!(db.delete_other_sessions(a, s1.id).await.expect("d"), 1);
        assert!(db.find_session("h2", 3600).await.expect("f").is_none());
        db.touch_session(s1.id).await.expect("touch");
        db.delete_session(s1.id).await.expect("delete");
        assert!(db.find_session("h1", 3600).await.expect("f").is_none());
        let _ = s2;
        db.create_session(a, "h4", far, "", "")
            .await
            .expect("create");
        assert_eq!(db.delete_user_sessions(a).await.expect("d"), 1);
        // deleting the user removes the rest
        db.set_user_disabled(b, false).await.expect("enable");
        db.delete_user(b).await.expect("delete");
        assert!(db.find_session("h3", 3600).await.expect("f").is_none());
    }

    #[tokio::test]
    async fn preferences_roundtrip() {
        let (_d, db) = test_db().await;
        let a = user(&db, "anna").await;
        assert_eq!(db.get_pref(a, "theme").await.expect("g"), None);
        db.set_pref(a, "theme", "dark").await.expect("set");
        db.set_pref(a, "theme", "light").await.expect("set again");
        assert_eq!(
            db.get_pref(a, "theme").await.expect("g").as_deref(),
            Some("light")
        );
        assert_eq!(db.usage_breakdown(a).await.expect("u"), (0, 0, 0));
    }
}
