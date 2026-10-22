//! Storage for two-factor authentication (ADR 0007): the encrypted TOTP secret and
//! the hashed recovery codes. Nothing here knows how codes are computed.

use rostdav_core::{Error, Result};

use crate::Db;
use crate::users::now_secs;

fn err(e: sqlx::Error) -> Error {
    Error::internal(e)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpRow {
    pub secret_enc: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: i64,
    /// `None` while the setup is not confirmed.
    pub enabled_at: Option<i64>,
    pub last_step: i64,
}

impl Db {
    /// Starts (or restarts) a setup: replaces any earlier row of the user.
    pub async fn totp_put_pending(
        &self,
        user_id: i64,
        secret_enc: &[u8],
        nonce: &[u8],
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO totp (user_id, secret_enc, nonce, created_at, enabled_at, last_step)
             VALUES (?, ?, ?, ?, NULL, 0)
             ON CONFLICT(user_id) DO UPDATE SET secret_enc = excluded.secret_enc, nonce = excluded.nonce,
                 created_at = excluded.created_at, enabled_at = NULL, last_step = 0",
        )
        .bind(user_id)
        .bind(secret_enc)
        .bind(nonce)
        .bind(now_secs())
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(())
    }

    pub async fn totp_get(&self, user_id: i64) -> Result<Option<TotpRow>> {
        type Row = (Vec<u8>, Vec<u8>, i64, Option<i64>, i64);
        let row: Option<Row> = sqlx::query_as(
            "SELECT secret_enc, nonce, created_at, enabled_at, last_step FROM totp WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_optional(self.pool())
        .await
        .map_err(err)?;
        Ok(row.map(
            |(secret_enc, nonce, created_at, enabled_at, last_step)| TotpRow {
                secret_enc,
                nonce,
                created_at,
                enabled_at,
                last_step,
            },
        ))
    }

    /// Whether 2FA is switched on (setups in progress do not count).
    pub async fn totp_enabled(&self, user_id: i64) -> Result<bool> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM totp WHERE user_id = ? AND enabled_at IS NOT NULL",
        )
        .bind(user_id)
        .fetch_one(self.pool())
        .await
        .map_err(err)?;
        Ok(n > 0)
    }

    /// Records a code as used. `true` only if `step` is larger than every step accepted
    /// before (atomic: two requests with the same code cannot both succeed).
    pub async fn totp_accept_step(&self, user_id: i64, step: i64) -> Result<bool> {
        let r = sqlx::query("UPDATE totp SET last_step = ? WHERE user_id = ? AND last_step < ?")
            .bind(step)
            .bind(user_id)
            .bind(step)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(r.rows_affected() == 1)
    }

    /// Switches 2FA on after a valid first code and stores the recovery codes (replacing old ones).
    pub async fn totp_enable(
        &self,
        user_id: i64,
        step: i64,
        recovery_hashes: &[String],
    ) -> Result<()> {
        let mut tx = self
            .pool()
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(err)?;
        let r = sqlx::query("UPDATE totp SET enabled_at = ?, last_step = ? WHERE user_id = ? AND enabled_at IS NULL")
            .bind(now_secs())
            .bind(step)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(err)?;
        if r.rows_affected() != 1 {
            return Err(Error::Conflict("no setup in progress"));
        }
        replace_codes(&mut tx, user_id, recovery_hashes).await?;
        tx.commit().await.map_err(err)
    }

    /// Removes the secret and all recovery codes (disable or administrator reset).
    pub async fn totp_delete(&self, user_id: i64) -> Result<bool> {
        let mut tx = self
            .pool()
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(err)?;
        sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(err)?;
        let r = sqlx::query("DELETE FROM totp WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(err)?;
        tx.commit().await.map_err(err)?;
        Ok(r.rows_affected() > 0)
    }

    /// Removes setups that were never confirmed.
    pub async fn totp_purge_pending(&self, older_than_secs: i64) -> Result<u64> {
        let r = sqlx::query("DELETE FROM totp WHERE enabled_at IS NULL AND created_at <= ?")
            .bind(now_secs() - older_than_secs)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(r.rows_affected())
    }

    pub async fn recovery_replace(&self, user_id: i64, hashes: &[String]) -> Result<()> {
        let mut tx = self
            .pool()
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(err)?;
        replace_codes(&mut tx, user_id, hashes).await?;
        tx.commit().await.map_err(err)
    }

    /// `(id, hash)` of the unused recovery codes.
    pub async fn recovery_unused(&self, user_id: i64) -> Result<Vec<(i64, String)>> {
        sqlx::query_as("SELECT id, code_hash FROM recovery_codes WHERE user_id = ? AND used_at IS NULL ORDER BY id")
            .bind(user_id)
            .fetch_all(self.pool())
            .await
            .map_err(err)
    }

    /// Marks a code as used; `false` if it was used already (two requests, one code).
    pub async fn recovery_use(&self, id: i64) -> Result<bool> {
        let r =
            sqlx::query("UPDATE recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL")
                .bind(now_secs())
                .bind(id)
                .execute(self.pool())
                .await
                .map_err(err)?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn recovery_remaining(&self, user_id: i64) -> Result<i64> {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(self.pool())
        .await
        .map_err(err)
    }
}

async fn replace_codes(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: i64,
    hashes: &[String],
) -> Result<()> {
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut **tx)
        .await
        .map_err(err)?;
    for h in hashes {
        sqlx::query("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)")
            .bind(user_id)
            .bind(h)
            .execute(&mut **tx)
            .await
            .map_err(err)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NewUser;

    async fn db_with_user() -> (Db, i64) {
        let db = Db::open("sqlite::memory:").await.expect("db");
        db.migrate().await.expect("migrate");
        let u = db
            .create_user(NewUser {
                name: "anna",
                password_hash: "x",
                is_admin: false,
            })
            .await
            .expect("user");
        (db, u.id)
    }

    #[tokio::test]
    async fn setup_enable_replay_and_recovery() {
        let (db, id) = db_with_user().await;
        assert!(!db.totp_enabled(id).await.expect("q"));
        db.totp_put_pending(id, b"sec", b"nonce")
            .await
            .expect("pending");
        assert!(
            !db.totp_enabled(id).await.expect("q"),
            "a setup in progress is not 2FA"
        );
        assert!(
            db.totp_get(id)
                .await
                .expect("q")
                .expect("row")
                .enabled_at
                .is_none()
        );

        db.totp_enable(id, 100, &["h1".into(), "h2".into(), "h3".into()])
            .await
            .expect("enable");
        assert!(db.totp_enabled(id).await.expect("q"));
        assert_eq!(db.recovery_remaining(id).await.expect("q"), 3);
        // enabling twice fails
        assert!(db.totp_enable(id, 101, &[]).await.is_err());

        // replay protection: only larger steps
        assert!(!db.totp_accept_step(id, 100).await.expect("q"));
        assert!(!db.totp_accept_step(id, 99).await.expect("q"));
        assert!(db.totp_accept_step(id, 101).await.expect("q"));
        assert!(!db.totp_accept_step(id, 101).await.expect("q"));

        // recovery codes are single-use
        let codes = db.recovery_unused(id).await.expect("q");
        assert!(db.recovery_use(codes[0].0).await.expect("q"));
        assert!(!db.recovery_use(codes[0].0).await.expect("q"));
        assert_eq!(db.recovery_remaining(id).await.expect("q"), 2);
        db.recovery_replace(id, &["n1".into()])
            .await
            .expect("replace");
        assert_eq!(db.recovery_unused(id).await.expect("q").len(), 1);

        // delete removes everything; unknown user is not an error
        assert!(db.totp_delete(id).await.expect("q"));
        assert!(!db.totp_enabled(id).await.expect("q"));
        assert_eq!(db.recovery_remaining(id).await.expect("q"), 0);
        assert!(!db.totp_delete(id).await.expect("q"));
    }

    #[tokio::test]
    async fn restarting_a_setup_resets_it_and_pending_rows_expire() {
        let (db, id) = db_with_user().await;
        db.totp_put_pending(id, b"a", b"n").await.expect("p");
        db.totp_enable(id, 5, &[]).await.expect("e");
        // a new setup replaces the active one only when explicitly started (the service
        // refuses while 2FA is on); at the storage level it resets to pending
        db.totp_put_pending(id, b"b", b"n").await.expect("p");
        assert!(!db.totp_enabled(id).await.expect("q"));
        assert_eq!(db.totp_purge_pending(3600).await.expect("q"), 0);
        assert_eq!(db.totp_purge_pending(-10).await.expect("q"), 1);
    }

    #[tokio::test]
    async fn rows_go_with_the_user() {
        let (db, id) = db_with_user().await;
        db.totp_put_pending(id, b"a", b"n").await.expect("p");
        db.totp_enable(id, 1, &["h".into()]).await.expect("e");
        db.delete_user(id).await.expect("delete");
        assert!(db.totp_get(id).await.expect("q").is_none());
        assert_eq!(db.recovery_remaining(id).await.expect("q"), 0);
    }
}
