//! Storage for push sign-in approval (ADR 0014): enrollment tokens, phones, challenges and
//! request nonces. Nothing here knows how signatures are checked.

use rostdav_core::{Error, Result};

use crate::Db;
use crate::sql;
use crate::users::now_secs;

fn err(e: sql::Error) -> Error {
    Error::internal(e)
}

/// A phone to register.
pub struct NewDevice<'a> {
    pub id: &'a str,
    pub user_id: i64,
    pub name: &'a str,
    pub request_pub: &'a str,
    pub approval_pub: &'a str,
    pub push_channel: &'a str,
    pub push_token: &'a str,
    pub hardware_backed: bool,
    pub strongbox: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRow {
    pub id: String,
    pub user_id: i64,
    pub name: String,
    /// `active` or `revoked`.
    pub status: String,
    pub request_pub: String,
    pub approval_pub: String,
    pub push_channel: String,
    pub push_token: String,
    pub hardware_backed: bool,
    pub strongbox: bool,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

const DEVICE_COLUMNS: &str = "id, user_id, name, status, request_pub, approval_pub, push_channel, \
     push_token, hardware_backed, strongbox, created_at, last_seen_at, revoked_at";

type DeviceTuple = (
    String,
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    bool,
    bool,
    i64,
    Option<i64>,
    Option<i64>,
);

impl From<DeviceTuple> for DeviceRow {
    fn from(t: DeviceTuple) -> Self {
        Self {
            id: t.0,
            user_id: t.1,
            name: t.2,
            status: t.3,
            request_pub: t.4,
            approval_pub: t.5,
            push_channel: t.6,
            push_token: t.7,
            hardware_backed: t.8,
            strongbox: t.9,
            created_at: t.10,
            last_seen_at: t.11,
            revoked_at: t.12,
        }
    }
}

/// A challenge to create. `created_at` is taken from the clock.
pub struct NewChallenge<'a> {
    pub id: &'a str,
    pub user_id: i64,
    pub device_id: &'a str,
    pub login_ref: &'a str,
    pub nonce: &'a str,
    /// The number the user must pick (10 to 99).
    pub number: i64,
    /// JSON array of the three numbers shown on the phone.
    pub candidates: &'a str,
    pub audience: &'a str,
    /// What the user is signing in with, shown on the phone (for example "Firefox on Linux").
    pub login_device: &'a str,
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeRow {
    pub id: String,
    pub user_id: i64,
    pub device_id: String,
    pub login_ref: String,
    pub nonce: String,
    pub number: i64,
    pub candidates: String,
    pub audience: String,
    pub created_at: i64,
    pub expires_at: i64,
    /// `pending`, `approved`, `denied` or `expired`.
    pub status: String,
    pub consumed_at: Option<i64>,
    pub login_device: String,
}

const CHALLENGE_COLUMNS: &str = "id, user_id, device_id, login_ref, nonce, number, candidates, \
     audience, created_at, expires_at, status, consumed_at, login_device";

type ChallengeTuple = (
    String,
    i64,
    String,
    String,
    String,
    i64,
    String,
    String,
    i64,
    i64,
    String,
    Option<i64>,
    String,
);

impl From<ChallengeTuple> for ChallengeRow {
    fn from(t: ChallengeTuple) -> Self {
        Self {
            id: t.0,
            user_id: t.1,
            device_id: t.2,
            login_ref: t.3,
            nonce: t.4,
            number: t.5,
            candidates: t.6,
            audience: t.7,
            created_at: t.8,
            expires_at: t.9,
            status: t.10,
            consumed_at: t.11,
            login_device: t.12,
        }
    }
}

impl Db {
    pub async fn mfa_enroll_token_put(
        &self,
        token_hash: &str,
        user_id: i64,
        expires_at: i64,
    ) -> Result<()> {
        sql::query(
            "INSERT INTO mfa_enroll_tokens (token_hash, user_id, expires_at, used_at)
             VALUES (?, ?, ?, NULL)",
        )
        .bind(token_hash)
        .bind(user_id)
        .bind(expires_at)
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(())
    }

    /// Uses a token: one statement, so two callers cannot both get the user.
    pub async fn mfa_enroll_token_consume(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<i64>> {
        sql::query_scalar(
            "UPDATE mfa_enroll_tokens SET used_at = ?
             WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? RETURNING user_id",
        )
        .bind(now)
        .bind(token_hash)
        .bind(now)
        .fetch_optional(self.pool())
        .await
        .map_err(err)
    }

    pub async fn mfa_device_insert(&self, d: &NewDevice<'_>) -> Result<()> {
        sql::query(
            "INSERT INTO mfa_devices (id, user_id, name, status, request_pub, approval_pub,
                 push_channel, push_token, hardware_backed, strongbox, created_at)
             VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(d.id)
        .bind(d.user_id)
        .bind(d.name)
        .bind(d.request_pub)
        .bind(d.approval_pub)
        .bind(d.push_channel)
        .bind(d.push_token)
        .bind(d.hardware_backed)
        .bind(d.strongbox)
        .bind(now_secs())
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(())
    }

    pub async fn mfa_device_get(&self, id: &str) -> Result<Option<DeviceRow>> {
        let row: Option<DeviceTuple> = sql::query_as(format!(
            "SELECT {DEVICE_COLUMNS} FROM mfa_devices WHERE id = ?"
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(err)?;
        Ok(row.map(DeviceRow::from))
    }

    /// How many active phones a user has.
    pub async fn mfa_active_device_count(&self, user_id: i64) -> Result<i64> {
        let n: (i64,) = sql::query_as(
            "SELECT COUNT(*) FROM mfa_devices WHERE user_id = ? AND status = 'active'",
        )
        .bind(user_id)
        .fetch_one(self.pool())
        .await
        .map_err(err)?;
        Ok(n.0)
    }

    pub async fn mfa_devices_of(&self, user_id: i64) -> Result<Vec<DeviceRow>> {
        let rows: Vec<DeviceTuple> = sql::query_as(format!(
            "SELECT {DEVICE_COLUMNS} FROM mfa_devices WHERE user_id = ? ORDER BY created_at, id"
        ))
        .bind(user_id)
        .fetch_all(self.pool())
        .await
        .map_err(err)?;
        Ok(rows.into_iter().map(DeviceRow::from).collect())
    }

    /// Revokes an active device of this user; false if there is no such active device.
    pub async fn mfa_device_revoke(&self, id: &str, user_id: i64, now: i64) -> Result<bool> {
        let r = sql::query(
            "UPDATE mfa_devices SET status = 'revoked', revoked_at = ?
             WHERE id = ? AND user_id = ? AND status = 'active'",
        )
        .bind(now)
        .bind(id)
        .bind(user_id)
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn mfa_device_set_push(&self, id: &str, channel: &str, token: &str) -> Result<bool> {
        let r = sql::query(
            "UPDATE mfa_devices SET push_channel = ?, push_token = ?
             WHERE id = ? AND status = 'active'",
        )
        .bind(channel)
        .bind(token)
        .bind(id)
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn mfa_device_set_keys(
        &self,
        id: &str,
        request_pub: &str,
        approval_pub: &str,
        hardware_backed: bool,
        strongbox: bool,
    ) -> Result<bool> {
        let r = sql::query(
            "UPDATE mfa_devices SET request_pub = ?, approval_pub = ?, hardware_backed = ?,
                 strongbox = ?
             WHERE id = ? AND status = 'active'",
        )
        .bind(request_pub)
        .bind(approval_pub)
        .bind(hardware_backed)
        .bind(strongbox)
        .bind(id)
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn mfa_device_touch(&self, id: &str, now: i64) -> Result<()> {
        sql::query("UPDATE mfa_devices SET last_seen_at = ? WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(())
    }

    /// Records a request nonce; false if the device already used it.
    pub async fn mfa_nonce_insert(
        &self,
        device_id: &str,
        nonce: &str,
        expires_at: i64,
    ) -> Result<bool> {
        match sql::query("INSERT INTO mfa_nonces (device_id, nonce, expires_at) VALUES (?, ?, ?)")
            .bind(device_id)
            .bind(nonce)
            .bind(expires_at)
            .execute(self.pool())
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if e.is_unique_violation() => Ok(false),
            Err(e) => Err(err(e)),
        }
    }

    /// Removes nonces whose window has ended.
    pub async fn mfa_nonces_purge(&self, now: i64) -> Result<u64> {
        let r = sql::query("DELETE FROM mfa_nonces WHERE expires_at <= ?")
            .bind(now)
            .execute(self.pool())
            .await
            .map_err(err)?;
        Ok(r.rows_affected())
    }

    pub async fn mfa_challenge_insert(&self, c: &NewChallenge<'_>) -> Result<()> {
        sql::query(
            "INSERT INTO mfa_challenges (id, user_id, device_id, login_ref, nonce, number,
                 candidates, audience, created_at, expires_at, status, consumed_at, login_device)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, ?)",
        )
        .bind(c.id)
        .bind(c.user_id)
        .bind(c.device_id)
        .bind(c.login_ref)
        .bind(c.nonce)
        .bind(c.number)
        .bind(c.candidates)
        .bind(c.audience)
        .bind(now_secs())
        .bind(c.expires_at)
        .bind(c.login_device)
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(())
    }

    pub async fn mfa_challenge_get(&self, id: &str) -> Result<Option<ChallengeRow>> {
        let row: Option<ChallengeTuple> = sql::query_as(format!(
            "SELECT {CHALLENGE_COLUMNS} FROM mfa_challenges WHERE id = ?"
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(err)?;
        Ok(row.map(ChallengeRow::from))
    }

    pub async fn mfa_challenges_pending(
        &self,
        device_id: &str,
        now: i64,
    ) -> Result<Vec<ChallengeRow>> {
        let rows: Vec<ChallengeTuple> = sql::query_as(format!(
            "SELECT {CHALLENGE_COLUMNS} FROM mfa_challenges
             WHERE device_id = ? AND status = 'pending' AND expires_at > ?
             ORDER BY created_at, id"
        ))
        .bind(device_id)
        .bind(now)
        .fetch_all(self.pool())
        .await
        .map_err(err)?;
        Ok(rows.into_iter().map(ChallengeRow::from).collect())
    }

    /// Moves a pending, unexpired challenge of an active device to `to` (`approved`, `denied` or
    /// `expired`). One conditional statement: true for exactly one caller, and never after the
    /// device was revoked.
    pub async fn mfa_challenge_resolve(&self, id: &str, to: &str, now: i64) -> Result<bool> {
        let r = sql::query(
            "UPDATE mfa_challenges SET status = ?, consumed_at = ?
             WHERE id = ? AND status = 'pending' AND expires_at > ?
               AND device_id IN (SELECT id FROM mfa_devices WHERE status = 'active')",
        )
        .bind(to)
        .bind(now)
        .bind(id)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(r.rows_affected() > 0)
    }

    /// Hands an approved challenge to the sign-in that started it, once. True for exactly one
    /// caller, and only while the approving phone is still active (a phone revoked after it
    /// approved releases nothing).
    pub async fn mfa_challenge_release(&self, id: &str, login_ref: &str, now: i64) -> Result<bool> {
        let r = sql::query(
            "UPDATE mfa_challenges SET released_at = ?
             WHERE id = ? AND login_ref = ? AND status = 'approved' AND released_at IS NULL
               AND device_id IN (SELECT id FROM mfa_devices WHERE status = 'active')",
        )
        .bind(now)
        .bind(id)
        .bind(login_ref)
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(r.rows_affected() > 0)
    }

    /// Ends a pending challenge as `expired` whatever its time (its phone was revoked). True for
    /// the one caller that changed it.
    pub async fn mfa_challenge_cancel(&self, id: &str, now: i64) -> Result<bool> {
        let r = sql::query(
            "UPDATE mfa_challenges SET status = 'expired', consumed_at = ?
             WHERE id = ? AND status = 'pending'",
        )
        .bind(now)
        .bind(id)
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(r.rows_affected() > 0)
    }

    /// The newest `limit` events of `actor` whose action starts with `prefix`, newest first.
    /// `prefix` must end in a character that has a successor ASCII character (like the dot).
    pub async fn events_of_actor_with_prefix(
        &self,
        actor: &str,
        prefix: &str,
        limit: i64,
    ) -> Result<Vec<crate::Event>> {
        let mut upper = prefix.to_owned();
        let last = upper
            .pop()
            .ok_or(rostdav_core::Error::BadRequest("empty prefix"))?;
        upper.push(char::from(
            u8::try_from(last).map_or(0x7f, |b| b.saturating_add(1)),
        ));
        let rows: Vec<(i64, i64, String, String, String, String, String)> = sql::query_as(
            "SELECT id, ts, actor, action, target, ip, details FROM events
             WHERE actor = ? AND action >= ? AND action < ? ORDER BY id DESC LIMIT ?",
        )
        .bind(actor)
        .bind(prefix)
        .bind(upper)
        .bind(limit)
        .fetch_all(self.pool())
        .await
        .map_err(err)?;
        Ok(rows
            .into_iter()
            .map(
                |(id, ts, actor, action, target, ip, details)| crate::Event {
                    id,
                    ts,
                    actor,
                    action,
                    target,
                    ip,
                    details,
                },
            )
            .collect())
    }

    /// Marks a pending challenge whose time has run out as `expired`. True for the one caller
    /// that changed it, so the expiry is recorded once.
    pub async fn mfa_challenge_expire(&self, id: &str, now: i64) -> Result<bool> {
        let r = sql::query(
            "UPDATE mfa_challenges SET status = 'expired', consumed_at = ?
             WHERE id = ? AND status = 'pending' AND expires_at <= ?",
        )
        .bind(now)
        .bind(id)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(err)?;
        Ok(r.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Db, NewChallenge, NewDevice, NewUser};

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

    fn device(id: &str, user_id: i64) -> NewDevice<'_> {
        NewDevice {
            id,
            user_id,
            name: "Pixel 8",
            request_pub: "req-pub",
            approval_pub: "app-pub",
            push_channel: "fcm",
            push_token: "tok",
            hardware_backed: true,
            strongbox: false,
        }
    }

    fn challenge<'a>(
        id: &'a str,
        device_id: &'a str,
        user_id: i64,
        expires_at: i64,
    ) -> NewChallenge<'a> {
        NewChallenge {
            id,
            user_id,
            device_id,
            login_ref: "login-1",
            nonce: "n0nce",
            number: 47,
            candidates: "[47,12,83]",
            audience: "rostdav",
            login_device: "Firefox on Linux",
            expires_at,
        }
    }

    #[tokio::test]
    async fn cancel_ends_a_pending_challenge_once_whatever_its_time() {
        let (db, uid) = db_with_user().await;
        db.mfa_device_insert(&device("d1", uid)).await.expect("dev");
        for id in ["c1", "c2"] {
            db.mfa_challenge_insert(&challenge(id, "d1", uid, 2_000_000_000))
                .await
                .expect("insert");
        }
        assert!(
            db.mfa_challenge_resolve("c2", "approved", 5)
                .await
                .expect("r")
        );
        assert!(db.mfa_challenge_cancel("c1", 10).await.expect("cancel"));
        assert!(!db.mfa_challenge_cancel("c1", 11).await.expect("again"));
        assert!(!db.mfa_challenge_cancel("c2", 11).await.expect("answered"));
        let st = |id: &'static str| {
            let db = db.clone();
            async move {
                db.mfa_challenge_get(id)
                    .await
                    .expect("g")
                    .expect("row")
                    .status
            }
        };
        assert_eq!(
            (st("c1").await.as_str(), st("c2").await.as_str()),
            ("expired", "approved")
        );
    }

    #[tokio::test]
    async fn events_of_an_actor_are_limited_to_the_prefix_newest_first() {
        let (db, _uid) = db_with_user().await;
        for (ts, actor, action) in [
            (1, "anna", "mfa.device_registered"),
            (2, "anna", "auth.login"),
            (3, "ben", "mfa.device_registered"),
            (4, "anna", "mfa.challenge_created"),
            (5, "anna", "mfb.other"),
            (6, "anna", "mfa"),
            (7, "anna", "mfa.challenge_approved"),
        ] {
            db.record_event_at(ts, actor, action, "t", "", "{}")
                .await
                .expect("event");
        }
        let got: Vec<(i64, String)> = db
            .events_of_actor_with_prefix("anna", "mfa.", 2)
            .await
            .expect("events")
            .into_iter()
            .map(|e| (e.ts, e.action))
            .collect();
        assert_eq!(
            got,
            [
                (7, "mfa.challenge_approved".to_owned()),
                (4, "mfa.challenge_created".to_owned())
            ]
        );
        let all = db
            .events_of_actor_with_prefix("anna", "mfa.", 10)
            .await
            .expect("e");
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn a_revoked_device_cannot_resolve_its_challenge() {
        let (db, uid) = db_with_user().await;
        db.mfa_device_insert(&device("d1", uid)).await.expect("dev");
        db.mfa_challenge_insert(&challenge("c1", "d1", uid, 2_000_000_000))
            .await
            .expect("insert");
        assert!(db.mfa_device_revoke("d1", uid, 5).await.expect("revoke"));
        assert!(
            !db.mfa_challenge_resolve("c1", "approved", 6)
                .await
                .expect("resolve")
        );
        let row = db.mfa_challenge_get("c1").await.expect("g").expect("row");
        assert_eq!(row.status, "pending");
    }

    #[tokio::test]
    async fn challenge_keeps_the_login_device() {
        let (db, uid) = db_with_user().await;
        db.mfa_device_insert(&device("d1", uid)).await.expect("dev");
        db.mfa_challenge_insert(&challenge("c1", "d1", uid, 2_000_000_000))
            .await
            .expect("insert");
        let row = db.mfa_challenge_get("c1").await.expect("get").expect("row");
        assert_eq!(row.login_device, "Firefox on Linux");
    }

    #[tokio::test]
    async fn expire_marks_only_pending_challenges_that_are_past_due() {
        let (db, uid) = db_with_user().await;
        db.mfa_device_insert(&device("d1", uid)).await.expect("dev");
        for id in ["c1", "c2", "c3"] {
            db.mfa_challenge_insert(&challenge(id, "d1", uid, 1_000))
                .await
                .expect("insert");
        }
        // not due yet
        assert!(!db.mfa_challenge_expire("c1", 999).await.expect("e"));
        // c2 was answered before it ran out
        assert!(
            db.mfa_challenge_resolve("c2", "denied", 500)
                .await
                .expect("r")
        );
        assert!(db.mfa_challenge_expire("c1", 1_000).await.expect("e"));
        // once only, and an answered challenge keeps its status
        assert!(!db.mfa_challenge_expire("c1", 1_001).await.expect("e"));
        assert!(!db.mfa_challenge_expire("c2", 1_001).await.expect("e"));
        let status = |id: &'static str| {
            let db = db.clone();
            async move {
                db.mfa_challenge_get(id)
                    .await
                    .expect("g")
                    .expect("row")
                    .status
            }
        };
        assert_eq!(status("c1").await, "expired");
        assert_eq!(status("c2").await, "denied");
        assert_eq!(status("c3").await, "pending");
    }

    #[tokio::test]
    async fn enroll_token_is_single_use_and_expires() {
        let (db, uid) = db_with_user().await;
        db.mfa_enroll_token_put("h1", uid, 1_000)
            .await
            .expect("put");
        assert_eq!(
            db.mfa_enroll_token_consume("h1", 999).await.expect("c"),
            Some(uid)
        );
        assert_eq!(
            db.mfa_enroll_token_consume("h1", 999).await.expect("c"),
            None
        );
        db.mfa_enroll_token_put("h2", uid, 1_000)
            .await
            .expect("put");
        assert_eq!(
            db.mfa_enroll_token_consume("h2", 1_000).await.expect("c"),
            None
        );
        assert_eq!(
            db.mfa_enroll_token_consume("unknown", 1).await.expect("c"),
            None
        );
    }

    #[tokio::test]
    async fn device_roundtrip_and_updates() {
        let (db, uid) = db_with_user().await;
        db.mfa_device_insert(&device("dev_a", uid))
            .await
            .expect("insert");
        let d = db.mfa_device_get("dev_a").await.expect("get").expect("row");
        assert_eq!(
            (d.user_id, d.status.as_str(), d.hardware_backed, d.strongbox),
            (uid, "active", true, false)
        );
        assert_eq!(d.last_seen_at, None);
        assert!(
            db.mfa_device_set_push("dev_a", "unifiedpush", "t2")
                .await
                .expect("push")
        );
        assert!(
            db.mfa_device_set_keys("dev_a", "r2", "a2", false, true)
                .await
                .expect("keys")
        );
        db.mfa_device_touch("dev_a", 77).await.expect("touch");
        let d = db.mfa_device_get("dev_a").await.expect("get").expect("row");
        assert_eq!(
            (d.push_channel.as_str(), d.push_token.as_str()),
            ("unifiedpush", "t2")
        );
        assert_eq!(
            (
                d.request_pub.as_str(),
                d.approval_pub.as_str(),
                d.last_seen_at
            ),
            ("r2", "a2", Some(77))
        );
        assert_eq!((d.hardware_backed, d.strongbox), (false, true));
        assert!(
            !db.mfa_device_set_push("missing", "fcm", "t")
                .await
                .expect("push")
        );
        assert!(
            db.mfa_device_insert(&device("dev_a", uid)).await.is_err(),
            "duplicate id"
        );
        assert_eq!(db.mfa_devices_of(uid).await.expect("list").len(), 1);
    }

    #[tokio::test]
    async fn revoke_requires_matching_user() {
        let (db, uid) = db_with_user().await;
        let other = db
            .create_user(NewUser {
                name: "bob",
                password_hash: "x",
                is_admin: false,
            })
            .await
            .expect("user")
            .id;
        db.mfa_device_insert(&device("dev_a", uid))
            .await
            .expect("insert");
        assert!(
            !db.mfa_device_revoke("dev_a", other, 5)
                .await
                .expect("revoke")
        );
        assert_eq!(
            db.mfa_device_get("dev_a")
                .await
                .expect("get")
                .expect("row")
                .status,
            "active"
        );
        assert!(db.mfa_device_revoke("dev_a", uid, 5).await.expect("revoke"));
        let d = db.mfa_device_get("dev_a").await.expect("get").expect("row");
        assert_eq!((d.status.as_str(), d.revoked_at), ("revoked", Some(5)));
        assert!(
            !db.mfa_device_revoke("dev_a", uid, 6).await.expect("again"),
            "already revoked"
        );
    }

    #[tokio::test]
    async fn nonce_insert_detects_replay_and_purge_removes_expired() {
        let (db, uid) = db_with_user().await;
        db.mfa_device_insert(&device("dev_a", uid))
            .await
            .expect("insert");
        assert!(db.mfa_nonce_insert("dev_a", "n1", 100).await.expect("n"));
        assert!(
            !db.mfa_nonce_insert("dev_a", "n1", 100)
                .await
                .expect("replay")
        );
        assert!(db.mfa_nonce_insert("dev_a", "n2", 500).await.expect("n"));
        assert_eq!(db.mfa_nonces_purge(100).await.expect("purge"), 1);
        assert!(
            db.mfa_nonce_insert("dev_a", "n1", 600)
                .await
                .expect("again after purge")
        );
        assert!(
            !db.mfa_nonce_insert("dev_a", "n2", 600)
                .await
                .expect("still there")
        );
    }

    #[tokio::test]
    async fn challenge_resolve_is_atomic() {
        let (db, uid) = db_with_user().await;
        db.mfa_device_insert(&device("dev_a", uid))
            .await
            .expect("insert");
        db.mfa_challenge_insert(&challenge("ch_1", "dev_a", uid, 1_000))
            .await
            .expect("ins");
        assert!(
            db.mfa_challenge_resolve("ch_1", "approved", 10)
                .await
                .expect("r")
        );
        assert!(
            !db.mfa_challenge_resolve("ch_1", "approved", 11)
                .await
                .expect("second")
        );
        assert!(
            !db.mfa_challenge_resolve("ch_1", "denied", 12)
                .await
                .expect("other")
        );
        let c = db
            .mfa_challenge_get("ch_1")
            .await
            .expect("get")
            .expect("row");
        assert_eq!((c.status.as_str(), c.consumed_at), ("approved", Some(10)));
    }

    #[tokio::test]
    async fn challenge_resolve_refuses_after_expiry() {
        let (db, uid) = db_with_user().await;
        db.mfa_device_insert(&device("dev_a", uid))
            .await
            .expect("insert");
        db.mfa_challenge_insert(&challenge("ch_1", "dev_a", uid, 1_000))
            .await
            .expect("ins");
        assert!(
            !db.mfa_challenge_resolve("ch_1", "approved", 1_000)
                .await
                .expect("r")
        );
        let c = db
            .mfa_challenge_get("ch_1")
            .await
            .expect("get")
            .expect("row");
        assert_eq!((c.status.as_str(), c.consumed_at), ("pending", None));
        assert!(
            db.mfa_challenge_get("missing")
                .await
                .expect("get")
                .is_none()
        );
    }

    #[tokio::test]
    async fn pending_list_excludes_resolved_expired_and_other_devices() {
        let (db, uid) = db_with_user().await;
        db.mfa_device_insert(&device("dev_a", uid))
            .await
            .expect("insert");
        db.mfa_device_insert(&device("dev_b", uid))
            .await
            .expect("insert");
        db.mfa_challenge_insert(&challenge("ch_live", "dev_a", uid, 1_000))
            .await
            .expect("ins");
        db.mfa_challenge_insert(&challenge("ch_old", "dev_a", uid, 50))
            .await
            .expect("ins");
        db.mfa_challenge_insert(&challenge("ch_done", "dev_a", uid, 1_000))
            .await
            .expect("ins");
        db.mfa_challenge_insert(&challenge("ch_other", "dev_b", uid, 1_000))
            .await
            .expect("ins");
        assert!(
            db.mfa_challenge_resolve("ch_done", "denied", 10)
                .await
                .expect("r")
        );
        let ids: Vec<String> = db
            .mfa_challenges_pending("dev_a", 100)
            .await
            .expect("pending")
            .into_iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(ids, vec!["ch_live".to_string()]);
    }

    #[tokio::test]
    async fn deleting_the_user_cascades_to_everything() {
        let (db, uid) = db_with_user().await;
        db.mfa_enroll_token_put("h1", uid, 1_000)
            .await
            .expect("put");
        db.mfa_device_insert(&device("dev_a", uid))
            .await
            .expect("insert");
        db.mfa_nonce_insert("dev_a", "n1", 500).await.expect("n");
        db.mfa_challenge_insert(&challenge("ch_1", "dev_a", uid, 1_000))
            .await
            .expect("ins");
        db.delete_user(uid).await.expect("delete");
        assert!(db.mfa_device_get("dev_a").await.expect("get").is_none());
        assert!(db.mfa_challenge_get("ch_1").await.expect("get").is_none());
        assert_eq!(db.mfa_enroll_token_consume("h1", 1).await.expect("c"), None);
        assert!(
            db.mfa_nonce_insert("dev_a", "n1", 500).await.is_err(),
            "device row is gone"
        );
    }
    /// The engine can ignore an index (see `CLAUDE.md`, "Database"); these are the queries that
    /// run on every request or every sign-in, so a changed plan must fail a test.
    #[tokio::test]
    async fn hot_queries_use_their_indexes() {
        use crate::sql;
        let (db, _uid) = db_with_user().await;
        let cases = [
            (
                "SELECT id FROM mfa_challenges WHERE device_id = 'd' AND status = 'pending' AND expires_at > 1",
                "mfa_challenges_device",
            ),
            (
                "SELECT id FROM mfa_challenges WHERE login_ref = 'x'",
                "mfa_challenges_login",
            ),
            (
                "DELETE FROM mfa_nonces WHERE expires_at <= 5",
                "mfa_nonces_expiry",
            ),
            (
                "SELECT id FROM mfa_devices WHERE user_id = 1",
                "mfa_devices_user",
            ),
            (
                "SELECT id FROM events WHERE actor = 'a' AND action >= 'mfa.' AND action < 'mfa/' ORDER BY id DESC LIMIT 5",
                "events_actor",
            ),
        ];
        for (q, index) in cases {
            let rows: Vec<(i64, i64, i64, String)> =
                sql::query_as(format!("EXPLAIN QUERY PLAN {q}"))
                    .fetch_all(db.pool())
                    .await
                    .expect("plan");
            assert!(
                rows.iter().any(|r| r.3.contains(index)),
                "{q} does not use {index}: {rows:?}"
            );
        }
    }
}
