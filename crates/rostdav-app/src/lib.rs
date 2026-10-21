//! Service layer of Rostdav.
//!
//! The only place that coordinates the metadata database and blob storage.
//! Protocol crates (`dav`, `compat`, `web`) talk only to [`AppState`].

use std::sync::Arc;

mod auth;
mod files;
mod login_flow;
mod password;
mod ratelimit;
mod secrets;

pub use auth::{APP_PASSWORD_LEN, Action, Principal, Via, authorize};
pub use files::Listing;
pub use login_flow::{Confirmation, Granted, StartedFlow};
pub use password::{MIN_PASSWORD_CHARS, hash_password, verify_password};

use rostdav_core::Result;
use rostdav_meta::{Db, NewUser, User};
use rostdav_storage::LocalStore;

/// Shared state of all requests.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    db: Db,
    store: LocalStore,
    limits: Limits,
    limiter: ratelimit::RateLimiter,
    /// 32-byte key for stateless tickets and CSRF values (stored in `settings`).
    server_key: [u8; 32],
}

pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Operating limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum size of a single upload in bytes.
    pub max_upload_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_upload_bytes: 16 * 1024 * 1024 * 1024,
        }
    }
}

impl AppState {
    /// Builds the state; creates the server key on first start.
    pub async fn new(db: Db, store: LocalStore) -> Result<Self> {
        let key = db
            .setting_or_init("server_key", || secrets::random_bytes::<32>().to_vec())
            .await?;
        let server_key: [u8; 32] = key.try_into().map_err(|_| {
            rostdav_core::Error::BadRequest("stored server key has the wrong length")
        })?;
        Ok(Self {
            inner: Arc::new(Inner {
                db,
                store,
                limits: Limits::default(),
                limiter: ratelimit::RateLimiter::new(10, std::time::Duration::from_secs(15 * 60)),
                server_key,
            }),
        })
    }

    #[must_use]
    pub fn with_limits(self, limits: Limits) -> Self {
        // Called during start-up, before the state is shared.
        let old = &*self.inner;
        Self {
            inner: Arc::new(Inner {
                db: old.db.clone(),
                store: old.store.clone(),
                limits,
                limiter: ratelimit::RateLimiter::new(10, std::time::Duration::from_secs(15 * 60)),
                server_key: old.server_key,
            }),
        }
    }

    /// Readiness check: the database responds and the data directory is writable.
    pub async fn readiness(&self) -> Result<()> {
        let (db, store) = tokio::join!(self.inner.db.ping(), self.inner.store.check_writable());
        db?;
        store?;
        Ok(())
    }

    /// Creates a user (admin CLI). The password is hashed here.
    pub async fn add_user(&self, name: &str, password: &str, is_admin: bool) -> Result<User> {
        let password_hash = hash_password(password)?;
        self.inner
            .db
            .create_user(NewUser {
                name,
                password_hash: &password_hash,
                is_admin,
            })
            .await
    }

    /// Orderly shutdown.
    pub async fn shutdown(&self) {
        self.inner.db.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rostdav_core::Error;

    async fn state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalStore::open(dir.path().join("data"))
            .await
            .expect("store");
        let url = Db::default_url(store.root());
        let db = Db::open(&url).await.expect("db");
        db.migrate().await.expect("migrate");
        (dir, AppState::new(db, store).await.expect("state"))
    }

    #[tokio::test]
    async fn add_user_stores_verifiable_hash_not_password() {
        let (_d, st) = state().await;
        let u = st
            .add_user("anna", "correct-horse-battery", false)
            .await
            .expect("add");
        assert!(u.password_hash.starts_with("$argon2id$"));
        assert!(verify_password("correct-horse-battery", &u.password_hash));
        let dup = st.add_user("anna", "correct-horse-battery", false).await;
        assert!(matches!(dup, Err(Error::Conflict(_))));
        let weak = st.add_user("bob", "short", false).await;
        assert!(matches!(weak, Err(Error::BadRequest(_))));
    }

    /// Crash between blob placement and DB commit (ADR 0002, step 2 -> 3):
    /// the database does not know the blob; it can only be found as an orphan.
    #[tokio::test]
    async fn crash_between_blob_and_commit_leaves_only_orphan() {
        let (_d, st) = state().await;
        let blob = st
            .inner
            .store
            .put(&b"content"[..], 1024)
            .await
            .expect("put");
        // Process "crashes": no commit. A restart sees the same data.
        let on_disk = st.inner.store.list_blobs().await.expect("list");
        assert_eq!(on_disk, vec![blob.id.clone()]);
        let known = st.inner.db.count_blobs().await.expect("count");
        assert_eq!(known, 0, "DB must not reference an incomplete blob");
    }

    use rostdav_core::LogicalPath;
    use rostdav_meta::WriteCondition;
    use tokio::io::AsyncReadExt;

    const IP: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    fn lp(s: &str) -> LogicalPath {
        LogicalPath::from_url_path(s).expect("path")
    }

    async fn login(st: &AppState, name: &str) -> Principal {
        st.add_user(name, "korrekt-pferd-batterie", false)
            .await
            .expect("add");
        st.authenticate(name, "korrekt-pferd-batterie", IP)
            .await
            .expect("auth")
    }

    #[tokio::test]
    async fn authenticate_accepts_only_correct_credentials() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        assert_eq!(anna.name, "anna");
        for (u, pw) in [
            ("anna", "falsches-passwort"),
            ("niemand", "korrekt-pferd-batterie"),
            ("", ""),
            ("../anna", "korrekt-pferd-batterie"),
        ] {
            assert!(
                matches!(
                    st.authenticate(u, pw, IP).await,
                    Err(Error::Unauthenticated)
                ),
                "{u:?}"
            );
        }
    }

    #[tokio::test]
    async fn put_then_read_roundtrip() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        st.mkcol(&anna, &lp("/docs")).await.expect("mkcol");
        let w = st
            .put(
                &anna,
                &lp("/docs/a.txt"),
                &b"hello"[..],
                None,
                &WriteCondition::None,
            )
            .await
            .expect("put");
        assert_eq!(w.node.size, 5);
        let (node, mut file) = st.read(&anna, &lp("/docs/a.txt")).await.expect("read");
        let mut out = String::new();
        file.read_to_string(&mut out).await.expect("read");
        assert_eq!(out, "hello");
        assert_eq!(node.id, w.node.id);
        let l = st.list(&anna, &lp("/docs")).await.expect("list");
        assert_eq!(l.children.len(), 1);
        assert_eq!(st.size_of(&anna, &l.node).await.expect("size"), 5);
    }

    #[tokio::test]
    async fn failed_commit_leaves_no_blob_on_disk() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        st.put(&anna, &lp("/f"), &b"1"[..], None, &WriteCondition::None)
            .await
            .expect("put");
        let err = st
            .put(
                &anna,
                &lp("/f"),
                &b"2"[..],
                None,
                &WriteCondition::MustNotExist,
            )
            .await;
        assert!(matches!(err, Err(Error::PreconditionFailed)));
        assert_eq!(st.inner.store.list_blobs().await.expect("l").len(), 1);
    }

    #[tokio::test]
    async fn missing_parent_is_conflict_not_not_found() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        let r = st
            .put(
                &anna,
                &lp("/nope/f"),
                &b"1"[..],
                None,
                &WriteCondition::None,
            )
            .await;
        assert!(matches!(r, Err(Error::Conflict(_))));
        assert!(matches!(
            st.mkcol(&anna, &lp("/a/b")).await,
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            st.mkcol(&anna, &lp("/")).await,
            Err(Error::Conflict(_))
        ));
        st.mkcol(&anna, &lp("/a")).await.expect("a");
        assert!(matches!(
            st.mkcol(&anna, &lp("/a")).await,
            Err(Error::AlreadyExists)
        ));
    }

    #[tokio::test]
    async fn second_user_cannot_see_or_touch_first_users_files() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        let bob = login(&st, "bob").await;
        st.mkcol(&anna, &lp("/private")).await.expect("mkcol");
        st.put(
            &anna,
            &lp("/private/secret.txt"),
            &b"geheim"[..],
            None,
            &WriteCondition::None,
        )
        .await
        .expect("put");

        let p = lp("/private/secret.txt");
        assert!(matches!(st.stat(&bob, &p).await, Err(Error::NotFound)));
        assert!(matches!(st.read(&bob, &p).await, Err(Error::NotFound)));
        assert!(matches!(
            st.list(&bob, &lp("/private")).await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            st.delete(&bob, &p, None).await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            st.move_to(&bob, &p, &lp("/x"), true).await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            st.copy_to(&bob, &p, &lp("/x"), true).await,
            Err(Error::NotFound)
        ));
        let w = st
            .put(
                &bob,
                &lp("/private/secret.txt"),
                &b"bobs"[..],
                None,
                &WriteCondition::None,
            )
            .await;
        assert!(matches!(w, Err(Error::Conflict(_))), "bob has no /private");

        // bob's own file of the same name does not touch anna's
        st.mkcol(&bob, &lp("/private")).await.expect("bob mkcol");
        st.put(&bob, &p, &b"bobs"[..], None, &WriteCondition::None)
            .await
            .expect("bob put");
        let (_, mut f) = st.read(&anna, &p).await.expect("anna read");
        let mut out = String::new();
        f.read_to_string(&mut out).await.expect("read");
        assert_eq!(out, "geheim");
    }

    #[tokio::test]
    async fn authorize_denies_foreign_nodes_even_when_resolved_by_id() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        let bob = login(&st, "bob").await;
        let node = st.stat(&anna, &lp("/")).await.expect("root");
        assert!(authorize(&anna, &node, Action::Write).is_ok());
        assert!(matches!(
            authorize(&bob, &node, Action::Read),
            Err(Error::Forbidden)
        ));
        let admin = Principal {
            is_admin: true,
            ..bob
        };
        assert!(
            matches!(
                authorize(&admin, &node, Action::Read),
                Err(Error::Forbidden)
            ),
            "admins get no implicit access"
        );
        assert!(matches!(
            st.size_of(&admin, &node).await,
            Err(Error::Forbidden)
        ));
    }

    #[tokio::test]
    async fn upload_limit_and_quota() {
        let (_d, st) = state().await;
        let st = st.with_limits(Limits {
            max_upload_bytes: 8,
        });
        let anna = login(&st, "anna").await;
        let big = st
            .put(
                &anna,
                &lp("/big"),
                &[0u8; 9][..],
                None,
                &WriteCondition::None,
            )
            .await;
        assert!(matches!(big, Err(Error::TooLarge)));

        st.inner
            .db
            .set_quota(anna.user_id, Some(10))
            .await
            .expect("quota");
        st.put(&anna, &lp("/a"), &[0u8; 8][..], None, &WriteCondition::None)
            .await
            .expect("a");
        let over = st
            .put(&anna, &lp("/b"), &[0u8; 3][..], None, &WriteCondition::None)
            .await;
        assert!(matches!(over, Err(Error::QuotaExceeded)));
        // replacing /a with 8 bytes again fits: the old size is freed
        st.put(&anna, &lp("/a"), &[0u8; 8][..], None, &WriteCondition::None)
            .await
            .expect("replace");
        assert_eq!(st.inner.store.list_blobs().await.expect("l").len(), 2);
    }

    #[tokio::test]
    async fn garbage_collection_removes_only_unreferenced_blobs() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        st.put(&anna, &lp("/f"), &b"1"[..], None, &WriteCondition::None)
            .await
            .expect("put");
        st.put(&anna, &lp("/g"), &b"2"[..], None, &WriteCondition::None)
            .await
            .expect("put");
        // unregistered blob = upload in flight; GC must not touch it
        let inflight = st.inner.store.put(&b"3"[..], 10).await.expect("inflight");
        st.delete(&anna, &lp("/f"), None).await.expect("delete");
        assert_eq!(st.collect_garbage().await.expect("gc"), 1);
        let left = st.inner.store.list_blobs().await.expect("l");
        assert_eq!(left.len(), 2);
        assert!(left.contains(&inflight.id));
    }

    #[tokio::test]
    async fn app_password_signs_in_only_its_own_user_and_can_be_revoked() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        login(&st, "bob").await;
        let token = st
            .create_app_password(anna.user_id, "Phone")
            .await
            .expect("token");
        assert_eq!(token.len(), APP_PASSWORD_LEN);

        let p = st
            .authenticate("anna", &token, IP)
            .await
            .expect("app password");
        assert!(matches!(p.via, Via::AppPassword(_)));
        assert_eq!(p.user_id, anna.user_id);
        assert!(matches!(
            st.authenticate("bob", &token, IP).await,
            Err(Error::Unauthenticated)
        ));

        // the stored value is a hash, not the token
        let stored = st
            .inner
            .db
            .list_app_passwords(anna.user_id)
            .await
            .expect("list");
        assert_eq!(stored.len(), 1);
        assert!(stored[0].last_used_at.is_some());

        st.revoke_current_app_password(&p).await.expect("revoke");
        assert!(matches!(
            st.authenticate("anna", &token, IP).await,
            Err(Error::Unauthenticated)
        ));
        // the account password still works and cannot be "revoked" this way
        let acct = st
            .authenticate("anna", "korrekt-pferd-batterie", IP)
            .await
            .expect("acct");
        assert_eq!(acct.via, Via::AccountPassword);
        assert!(st.revoke_current_app_password(&acct).await.is_err());
    }

    #[tokio::test]
    async fn basic_header_parsing_and_rate_limit() {
        let (_d, st) = state().await;
        login(&st, "anna").await;
        let hdr = |u: &str, p: &str| {
            use base64::Engine;
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
            )
        };
        assert!(
            st.authenticate_basic(&hdr("anna", "korrekt-pferd-batterie"), IP)
                .await
                .is_ok()
        );
        for bad in ["", "Basic", "Bearer x", "Basic !!!", "Basic YWJj"] {
            assert!(
                matches!(
                    st.authenticate_basic(bad, IP).await,
                    Err(Error::Unauthenticated)
                ),
                "{bad}"
            );
        }
        // that was 5 failures from IP; 5 more block the address
        let other = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 9));
        for _ in 0..10 {
            let _ = st
                .authenticate_basic(&hdr("anna", "falsch-falsch-falsch"), other)
                .await;
        }
        let blocked = st
            .authenticate_basic(&hdr("anna", "korrekt-pferd-batterie"), other)
            .await;
        assert!(
            matches!(blocked, Err(Error::RateLimited { retry_after_secs }) if retry_after_secs > 0)
        );
        // the correct password from a clean address is blocked by the per-user key too
        let third = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 10));
        assert!(matches!(
            st.authenticate_basic(&hdr("anna", "korrekt-pferd-batterie"), third)
                .await,
            Err(Error::RateLimited { .. })
        ));
    }

    // ---- Login Flow v2 --------------------------------------------------------

    async fn flow_through_login(st: &AppState, user: &str, pw: &str) -> Result<Confirmation> {
        let f = st.start_login_flow("Test Phone").await.expect("start");
        let csrf = st.flow_csrf(&f.login_token, "login");
        st.flow_login(&f.login_token, &csrf, user, pw, IP).await
    }

    #[tokio::test]
    async fn login_flow_happy_path_yields_working_app_password_once() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        let f = st.start_login_flow("Test Phone\u{7}").await.expect("start");
        assert_eq!(f.poll_token.len(), 128);
        assert_ne!(f.poll_token, f.login_token);
        assert!(
            st.poll_login_flow(&f.poll_token)
                .await
                .expect("poll")
                .is_none()
        );
        assert_eq!(
            st.login_flow_client(&f.login_token)
                .await
                .expect("c")
                .as_deref(),
            Some("Test Phone")
        );

        let c = st
            .flow_login(
                &f.login_token,
                &st.flow_csrf(&f.login_token, "login"),
                "anna",
                "korrekt-pferd-batterie",
                IP,
            )
            .await
            .expect("login");
        assert_eq!(c.user_name, "anna");
        assert!(
            st.poll_login_flow(&f.poll_token)
                .await
                .expect("poll")
                .is_none(),
            "not granted yet"
        );

        st.flow_grant(
            &f.login_token,
            &st.flow_csrf(&f.login_token, "grant"),
            &c.ticket,
        )
        .await
        .expect("grant");
        let g = st
            .poll_login_flow(&f.poll_token)
            .await
            .expect("poll")
            .expect("granted");
        assert_eq!(g.login_name, "anna");
        assert_eq!(g.app_password.len(), APP_PASSWORD_LEN);
        assert!(
            st.poll_login_flow(&f.poll_token)
                .await
                .expect("poll")
                .is_none(),
            "only once"
        );
        let p = st
            .authenticate("anna", &g.app_password, IP)
            .await
            .expect("auth");
        assert_eq!(p.user_id, anna.user_id);
        assert!(
            st.login_flow_client(&f.login_token)
                .await
                .expect("c")
                .is_none(),
            "flow closed"
        );
    }

    #[tokio::test]
    async fn login_flow_rejects_bad_csrf_credentials_and_app_passwords() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        let f = st.start_login_flow("Phone").await.expect("start");
        let good = st.flow_csrf(&f.login_token, "login");
        assert!(matches!(
            st.flow_login(&f.login_token, "nope", "anna", "korrekt-pferd-batterie", IP)
                .await,
            Err(Error::Forbidden)
        ));
        // csrf of another purpose or another flow does not work
        let other = st.start_login_flow("Other").await.expect("start");
        for bad in [
            st.flow_csrf(&f.login_token, "grant"),
            st.flow_csrf(&other.login_token, "login"),
        ] {
            assert!(matches!(
                st.flow_login(&f.login_token, &bad, "anna", "korrekt-pferd-batterie", IP)
                    .await,
                Err(Error::Forbidden)
            ));
        }
        assert!(matches!(
            st.flow_login(&f.login_token, &good, "anna", "falsch-falsch-falsch", IP)
                .await,
            Err(Error::Unauthenticated)
        ));
        // an app password is not accepted on the login form
        let app = st
            .create_app_password(anna.user_id, "x")
            .await
            .expect("app");
        assert!(matches!(
            st.flow_login(&f.login_token, &good, "anna", &app, IP).await,
            Err(Error::Unauthenticated)
        ));
        // unknown flow
        let bogus = st.flow_csrf("bogus", "login");
        assert!(matches!(
            st.flow_login("bogus", &bogus, "anna", "korrekt-pferd-batterie", IP)
                .await,
            Err(Error::NotFound)
        ));
    }

    #[tokio::test]
    async fn login_flow_ticket_cannot_be_forged_or_reused() {
        let (_d, st) = state().await;
        login(&st, "anna").await;
        let bob = login(&st, "bob").await;
        let c = flow_through_login(&st, "anna", "korrekt-pferd-batterie")
            .await
            .expect("c");
        // second flow
        let f2 = st.start_login_flow("Phone 2").await.expect("start");
        let grant2 = st.flow_csrf(&f2.login_token, "grant");
        // a ticket for flow 1 does not work on flow 2
        assert!(matches!(
            st.flow_grant(&f2.login_token, &grant2, &c.ticket).await,
            Err(Error::Forbidden)
        ));
        // tampering with the user id
        let (body, sig) = c.ticket.rsplit_once('.').expect("ticket");
        let mut parts: Vec<&str> = body.split('.').collect();
        let bob_id = bob.user_id.to_string();
        parts[1] = &bob_id;
        let forged = format!("{}.{sig}", parts.join("."));
        let f3 = st.start_login_flow("Phone 3").await.expect("start");
        let _ = f3;
        for t in [forged.as_str(), "", "a.b.c.d", "1.2.3.sig"] {
            assert!(
                matches!(
                    st.flow_grant(&f2.login_token, &grant2, t).await,
                    Err(Error::Forbidden)
                ),
                "{t:?}"
            );
        }
        assert!(
            st.poll_login_flow(&f2.poll_token)
                .await
                .expect("poll")
                .is_none()
        );
    }

    #[tokio::test]
    async fn login_flow_double_grant_creates_one_credential() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        let f = st.start_login_flow("Phone").await.expect("start");
        let c = st
            .flow_login(
                &f.login_token,
                &st.flow_csrf(&f.login_token, "login"),
                "anna",
                "korrekt-pferd-batterie",
                IP,
            )
            .await
            .expect("login");
        let grant = st.flow_csrf(&f.login_token, "grant");
        st.flow_grant(&f.login_token, &grant, &c.ticket)
            .await
            .expect("first");
        assert!(matches!(
            st.flow_grant(&f.login_token, &grant, &c.ticket).await,
            Err(Error::NotFound)
        ));
        assert_eq!(
            st.inner
                .db
                .list_app_passwords(anna.user_id)
                .await
                .expect("l")
                .len(),
            1
        );
    }
}
