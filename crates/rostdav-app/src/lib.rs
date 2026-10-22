//! Service layer of Rostdav.
//!
//! The only place that coordinates the metadata database and blob storage.
//! Protocol crates (`dav`, `compat`, `web`) talk only to [`AppState`].

use std::sync::Arc;

mod access;
mod admin;
#[cfg(test)]
mod admin_tests;
mod audit;
mod auth;
mod export;
mod files;
mod login_flow;
mod password;
mod ratelimit;
mod secrets;
#[cfg(test)]
mod share_tests;
mod shares;
mod trash;
mod two_factor;
mod uploads;
mod versions;
mod web;

pub use access::{Access, MountView, Need, Origin, authorize_access};
pub use admin::parse_quota;
pub use admin::{Actor, DeleteMode, FsckOptions, FsckReport, ImportOptions, ImportReport};
pub use audit::AuditOptions;
pub use auth::{APP_PASSWORD_LEN, Action, Principal, Scope, UserInfo, Via, authorize};
pub use files::{FORBIDDEN_EXTENSIONS, Listing, PutOptions, check_new_name, normalize_checksum};
pub use login_flow::FlowStep;
pub use login_flow::{Granted, StartedFlow};
pub use password::{MIN_PASSWORD_CHARS, hash_password, verify_password};
pub use shares::{
    LINK_TOKEN_LEN, ShareChange, ShareCreate, ShareError, ShareFilter, ShareView, Viewer,
};
pub use trash::{TrashEntry, TrashOptions};
pub use two_factor::{SignIn, TotpKeySource, TwoFactorSetup, TwoFactorStatus};
pub use uploads::UploadListing;
pub use versions::{VersionEntry, VersionListing, VersioningOptions};
pub use web::{Profile, UsageOverview, WebOptions, WebSession};

use rostdav_core::Result;
use rostdav_meta::Db;
use rostdav_storage::LocalStore;

/// Shared state of all requests.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    db: Db,
    store: LocalStore,
    config: AppConfig,
    limiter: ratelimit::RateLimiter,
    /// Wrong second-factor codes: five per user in 15 minutes (ADR 0007).
    totp_limiter: ratelimit::RateLimiter,
    /// Instance ID used in Nextcloud-style file IDs (`oc:id`), e.g. `oc` + 10 characters.
    instance_id: String,
    /// 32-byte key for stateless tickets and CSRF values (stored in `settings`).
    server_key: [u8; 32],
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Runtime settings that are not part of the stored state.
#[derive(Clone, Debug, Default)]
struct AppConfig {
    limits: Limits,
    audit: AuditOptions,
    versioning: VersioningOptions,
    trash: TrashOptions,
    web: WebOptions,
    security: SecurityOptions,
}

/// Settings of the security features.
#[derive(Clone, Debug, Default)]
pub struct SecurityOptions {
    /// Where the key for the two-factor secrets comes from (ADR 0007).
    pub totp_key: TotpKeySource,
}

/// Operating limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum size of a single upload in bytes.
    pub max_upload_bytes: u64,
    /// Maximum size of one chunk of a chunked upload in bytes.
    pub max_chunk_bytes: u64,
    /// Chunked uploads that were not finished within this time are removed.
    pub upload_retention_secs: i64,
    /// Quota given to users created from now on (`None` = unlimited).
    pub default_quota: Option<i64>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_upload_bytes: 16 * 1024 * 1024 * 1024,
            max_chunk_bytes: 100 * 1024 * 1024,
            upload_retention_secs: 24 * 60 * 60,
            default_quota: None,
        }
    }
}

impl AppState {
    /// Builds the state; creates the server key on first start.
    pub async fn new(db: Db, store: LocalStore) -> Result<Self> {
        let key = db
            .setting_or_init("server_key", || secrets::random_bytes::<32>().to_vec())
            .await?;
        let instance = db
            .setting_or_init("instance_id", || {
                format!("oc{}", secrets::random_token(10).to_ascii_lowercase()).into_bytes()
            })
            .await?;
        let instance_id = String::from_utf8(instance)
            .map_err(|_| rostdav_core::Error::BadRequest("stored instance id is invalid"))?;
        let server_key: [u8; 32] = key.try_into().map_err(|_| {
            rostdav_core::Error::BadRequest("stored server key has the wrong length")
        })?;
        Ok(Self {
            inner: Arc::new(Inner {
                db,
                store,
                config: AppConfig::default(),
                limiter: ratelimit::RateLimiter::new(10, std::time::Duration::from_secs(15 * 60)),
                totp_limiter: ratelimit::RateLimiter::new(
                    5,
                    std::time::Duration::from_secs(15 * 60),
                ),
                instance_id,
                server_key,
            }),
        })
    }

    fn reconfigured(&self, config: AppConfig) -> Self {
        // Called during start-up, before the state is shared.
        let old = &*self.inner;
        Self {
            inner: Arc::new(Inner {
                db: old.db.clone(),
                store: old.store.clone(),
                config,
                limiter: ratelimit::RateLimiter::new(10, std::time::Duration::from_secs(15 * 60)),
                totp_limiter: ratelimit::RateLimiter::new(
                    5,
                    std::time::Duration::from_secs(15 * 60),
                ),
                instance_id: old.instance_id.clone(),
                server_key: old.server_key,
            }),
        }
    }

    #[must_use]
    pub fn with_limits(self, limits: Limits) -> Self {
        let config = AppConfig {
            limits,
            ..self.inner.config.clone()
        };
        self.reconfigured(config)
    }

    #[must_use]
    pub fn with_versioning(self, versioning: VersioningOptions) -> Self {
        let config = AppConfig {
            versioning,
            ..self.inner.config.clone()
        };
        self.reconfigured(config)
    }

    #[must_use]
    pub fn with_security(self, security: SecurityOptions) -> Self {
        let config = AppConfig {
            security,
            ..self.inner.config.clone()
        };
        self.reconfigured(config)
    }

    #[must_use]
    pub fn with_web(self, web: WebOptions) -> Self {
        let config = AppConfig {
            web,
            ..self.inner.config.clone()
        };
        self.reconfigured(config)
    }

    #[must_use]
    pub fn with_trash(self, trash: TrashOptions) -> Self {
        let config = AppConfig {
            trash,
            ..self.inner.config.clone()
        };
        self.reconfigured(config)
    }

    #[must_use]
    pub fn with_audit(self, audit: AuditOptions) -> Self {
        let config = AppConfig {
            audit,
            ..self.inner.config.clone()
        };
        self.reconfigured(config)
    }

    /// Readiness check: the database responds and the data directory is writable.
    pub async fn readiness(&self) -> Result<()> {
        let (db, store) = tokio::join!(self.inner.db.ping(), self.inner.store.check_writable());
        db?;
        store?;
        Ok(())
    }

    /// Nextcloud-style file ID (`oc:id`, `OC-FileId`): 8-digit node ID + instance ID.
    pub fn file_id(&self, node_id: i64) -> String {
        format!("{node_id:08}{}", self.inner.instance_id)
    }

    /// Removes temporary files left by an interrupted run. Only the server calls
    /// this at start-up: the CLI runs next to a live server, whose uploads must not be touched.
    pub async fn sweep_tmp(&self) -> Result<usize> {
        self.inner.store.sweep_tmp().await
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
        assert_eq!(st.size_of(&anna, &l.access).await.expect("size"), 5);
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
    async fn missing_parent_is_conflict_for_mkcol_and_not_found_for_put() {
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
        assert!(
            matches!(r, Err(Error::NotFound)),
            "PUT into a missing parent: 404 like the reference"
        );
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
        assert!(matches!(w, Err(Error::NotFound)), "bob has no /private");

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
            ..bob.clone()
        };
        assert!(
            matches!(
                authorize(&admin, &node, Action::Read),
                Err(Error::Forbidden)
            ),
            "admins get no implicit access"
        );
        let access = st.stat_access(&anna, &lp("/")).await.expect("access");
        assert!(matches!(
            st.size_of(&admin, &access).await,
            Err(Error::Forbidden)
        ));
        assert!(
            matches!(
                authorize_access(&bob, &access, Need::Read),
                Err(Error::Forbidden)
            ),
            "an access grant resolved for anna is useless for bob"
        );
    }

    #[tokio::test]
    async fn new_users_get_the_default_quota() {
        let (_d, st) = state().await;
        st.add_user("anna", "korrekt-pferd-batterie", false)
            .await
            .expect("anna");
        let st = st.with_limits(Limits {
            default_quota: Some(5_000),
            ..Limits::default()
        });
        st.add_user("carl", "korrekt-pferd-batterie", false)
            .await
            .expect("user");
        let list = st.users_list(&crate::Actor::Cli).await.expect("list");
        let carl = list.iter().find(|u| u.name == "carl").expect("carl");
        assert_eq!(carl.quota_bytes, Some(5_000));
        // users that exist already are not touched, and a later explicit quota wins
        let anna = list.iter().find(|u| u.name == "anna").expect("anna");
        assert_eq!(anna.quota_bytes, None);
        st.set_quota("carl", None).await.expect("quota");
        let list = st.users_list(&crate::Actor::Cli).await.expect("list");
        assert_eq!(
            list.iter()
                .find(|u| u.name == "carl")
                .expect("c")
                .quota_bytes,
            None
        );
    }

    #[tokio::test]
    async fn upload_limit_and_quota() {
        let (_d, st) = state().await;
        let st = st.with_limits(Limits {
            max_upload_bytes: 8,
            ..Limits::default()
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
        // with versioning the replaced content stays and keeps counting: no room
        let same = st
            .put(&anna, &lp("/a"), &[1u8; 8][..], None, &WriteCondition::None)
            .await;
        assert!(matches!(same, Err(Error::QuotaExceeded)), "{same:?}");

        // without versioning the old size is freed and the replacement fits
        let st = st.with_versioning(VersioningOptions {
            enabled: false,
            ..VersioningOptions::default()
        });
        st.put(&anna, &lp("/a"), &[1u8; 8][..], None, &WriteCondition::None)
            .await
            .expect("replace");
        assert_eq!(st.inner.store.list_blobs().await.expect("l").len(), 2);
    }

    #[tokio::test]
    async fn garbage_collection_removes_only_unreferenced_blobs() {
        let (_d, st) = state().await;
        let st = st.with_trash(TrashOptions {
            enabled: false,
            retention_days: 0,
        });
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

    async fn allow(st: &AppState, f: &StartedFlow, user: &str, pw: &str) -> Result<()> {
        st.flow_allow(
            &f.login_token,
            &st.flow_csrf(&f.login_token, "allow"),
            user,
            pw,
            IP,
        )
        .await
        .map(|_| ())
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

        allow(&st, &f, "anna", "korrekt-pferd-batterie")
            .await
            .expect("allow");
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
        let other = st.start_login_flow("Other").await.expect("start");
        for bad in [
            "".to_owned(),
            "nope".to_owned(),
            st.flow_csrf(&other.login_token, "allow"),
        ] {
            assert!(matches!(
                st.flow_allow(&f.login_token, &bad, "anna", "korrekt-pferd-batterie", IP)
                    .await,
                Err(Error::Forbidden)
            ));
        }
        assert!(matches!(
            allow(&st, &f, "anna", "falsch-falsch-falsch").await,
            Err(Error::Unauthenticated)
        ));
        assert!(matches!(
            allow(&st, &f, "niemand", "korrekt-pferd-batterie").await,
            Err(Error::Unauthenticated)
        ));
        // an app password is not accepted on the login form
        let app = st
            .create_app_password(anna.user_id, "x")
            .await
            .expect("app");
        assert!(matches!(
            allow(&st, &f, "anna", &app).await,
            Err(Error::Unauthenticated)
        ));
        // unknown flow
        let bogus = StartedFlow {
            poll_token: String::new(),
            login_token: "bogus".into(),
        };
        assert!(matches!(
            allow(&st, &bogus, "anna", "korrekt-pferd-batterie").await,
            Err(Error::NotFound)
        ));
        assert!(
            st.poll_login_flow(&f.poll_token)
                .await
                .expect("poll")
                .is_none()
        );
    }

    #[tokio::test]
    async fn login_flow_deny_closes_flow_without_credentials() {
        let (_d, st) = state().await;
        login(&st, "anna").await;
        let f = st.start_login_flow("Phone").await.expect("start");
        assert!(matches!(
            st.flow_deny(&f.login_token, "bad").await,
            Err(Error::Forbidden)
        ));
        st.flow_deny(&f.login_token, &st.flow_csrf(&f.login_token, "allow"))
            .await
            .expect("deny");
        assert!(matches!(
            allow(&st, &f, "anna", "korrekt-pferd-batterie").await,
            Err(Error::NotFound)
        ));
        assert!(
            st.poll_login_flow(&f.poll_token)
                .await
                .expect("poll")
                .is_none()
        );
    }

    #[tokio::test]
    async fn login_flow_double_submit_creates_one_credential() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        let f = st.start_login_flow("Phone").await.expect("start");
        allow(&st, &f, "anna", "korrekt-pferd-batterie")
            .await
            .expect("first");
        assert!(matches!(
            allow(&st, &f, "anna", "korrekt-pferd-batterie").await,
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

    // ---- chunked uploads ------------------------------------------------------

    #[tokio::test]
    async fn chunked_upload_assembles_in_order_and_cleans_up() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        st.mkcol(&anna, &lp("/Docs")).await.expect("mkcol");
        st.upload_create(&anna, "t1").await.expect("create");
        assert!(matches!(
            st.upload_create(&anna, "t1").await,
            Err(Error::AlreadyExists)
        ));
        assert!(
            !st.upload_chunk(&anna, "t1", "00002", &b"world"[..])
                .await
                .expect("c2")
        );
        assert!(
            !st.upload_chunk(&anna, "t1", "00001", &b"hello "[..])
                .await
                .expect("c1")
        );
        let l = st.upload_list(&anna, "t1").await.expect("list");
        assert_eq!((l.chunks.len(), l.total()), (2, 11));

        // wrong total length keeps the session
        let err = st
            .upload_assemble(&anna, "t1", &lp("/Docs/f.txt"), true, Some(50), None)
            .await;
        assert!(
            matches!(&err, Err(Error::Invalid(m)) if m == "Chunks on server do not sum up to 50 but to 11 bytes"),
            "{err:?}"
        );
        assert!(st.upload_list(&anna, "t1").await.is_ok());

        let w = st
            .upload_assemble(
                &anna,
                "t1",
                &lp("/Docs/f.txt"),
                true,
                Some(11),
                Some(1_700_000_000),
            )
            .await
            .expect("assemble");
        assert!(!w.replaced);
        assert_eq!((w.node.size, w.node.mtime), (11, 1_700_000_000));
        let (_, mut f) = st.read(&anna, &lp("/Docs/f.txt")).await.expect("read");
        let mut out = String::new();
        f.read_to_string(&mut out).await.expect("r");
        assert_eq!(out, "hello world");
        assert!(
            matches!(st.upload_list(&anna, "t1").await, Err(Error::NotFound)),
            "session consumed"
        );
        assert_eq!(
            std::fs::read_dir(st.inner.store.root().join("uploads"))
                .expect("d")
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn chunked_upload_errors_and_isolation() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        let bob = login(&st, "bob").await;
        st.put(
            &anna,
            &lp("/exists"),
            &b"old"[..],
            None,
            &WriteCondition::None,
        )
        .await
        .expect("put");
        st.upload_create(&anna, "t").await.expect("create");
        st.upload_chunk(&anna, "t", "1", &b"new"[..])
            .await
            .expect("chunk");

        // bob cannot see, feed or assemble anna's session
        assert!(matches!(
            st.upload_list(&bob, "t").await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            st.upload_chunk(&bob, "t", "2", &b"x"[..]).await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            st.upload_assemble(&bob, "t", &lp("/stolen"), true, None, None)
                .await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            st.upload_delete(&bob, "t").await,
            Err(Error::NotFound)
        ));

        // invalid ids and chunk names
        for bad in ["", "..", "a/b", "a b", &"x".repeat(129)] {
            assert!(st.upload_create(&anna, bad).await.is_err(), "{bad:?}");
        }
        for bad in ["", ".file", "../x", "a/b"] {
            assert!(
                st.upload_chunk(&anna, "t", bad, &b"x"[..]).await.is_err(),
                "{bad:?}"
            );
        }

        // overwrite = false on an existing file, parent missing, directory target
        assert!(matches!(
            st.upload_assemble(&anna, "t", &lp("/exists"), false, None, None)
                .await,
            Err(Error::PreconditionFailed)
        ));
        assert!(matches!(
            st.upload_assemble(&anna, "t", &lp("/no/parent"), true, None, None)
                .await,
            Err(Error::Conflict(_))
        ));
        st.mkcol(&anna, &lp("/dir")).await.expect("mkcol");
        assert!(matches!(
            st.upload_assemble(&anna, "t", &lp("/dir"), true, None, None)
                .await,
            Err(Error::Conflict(_))
        ));
        // session survived all failures; overwrite works and replaces
        let w = st
            .upload_assemble(&anna, "t", &lp("/exists"), true, None, None)
            .await
            .expect("ok");
        assert!(w.replaced);
        st.upload_delete(&anna, "other").await.expect_err("missing");
    }

    #[tokio::test]
    async fn chunked_upload_respects_limits_quota_and_expiry() {
        let (_d, st) = state().await;
        let st = st.with_limits(Limits {
            max_upload_bytes: 20,
            max_chunk_bytes: 8,
            ..Limits::default()
        });
        let anna = login(&st, "anna").await;
        st.upload_create(&anna, "t").await.expect("create");
        assert!(
            matches!(
                st.upload_chunk(&anna, "t", "1", &[0u8; 9][..]).await,
                Err(Error::TooLarge)
            ),
            "chunk limit"
        );
        st.upload_chunk(&anna, "t", "1", &[0u8; 8][..])
            .await
            .expect("1");
        st.upload_chunk(&anna, "t", "2", &[0u8; 8][..])
            .await
            .expect("2");
        assert!(
            matches!(
                st.upload_chunk(&anna, "t", "3", &[0u8; 8][..]).await,
                Err(Error::TooLarge)
            ),
            "total limit"
        );
        st.upload_chunk(&anna, "t", "3", &[0u8; 4][..])
            .await
            .expect("3");

        st.inner
            .db
            .set_quota(anna.user_id, Some(10))
            .await
            .expect("quota");
        let w = st
            .upload_assemble(&anna, "t", &lp("/f"), true, None, None)
            .await;
        assert!(matches!(w, Err(Error::QuotaExceeded)), "{w:?}");
        assert_eq!(
            st.inner.store.list_blobs().await.expect("l").len(),
            0,
            "no blob left"
        );

        // expiry removes the session and its chunks
        assert_eq!(st.expire_uploads(3600).await.expect("e"), 0);
        assert_eq!(st.expire_uploads(-1).await.expect("e"), 1);
        assert!(matches!(
            st.upload_list(&anna, "t").await,
            Err(Error::NotFound)
        ));
        assert_eq!(
            std::fs::read_dir(st.inner.store.root().join("uploads"))
                .expect("d")
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn put_ext_records_checksum_and_mtime_and_reports_missing_parent_as_not_found() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        let opts = PutOptions {
            mtime: Some(1_500_000_000),
            client_checksum: normalize_checksum("SHA1:a9993e364706816aba3e25717850c26c9cd0d89d"),
            cond: None,
        };
        let w = st
            .put_ext(&anna, &lp("/f"), &b"abc"[..], &opts)
            .await
            .expect("put");
        assert_eq!(w.node.mtime, 1_500_000_000);
        assert_eq!(
            w.node.client_checksum.as_deref(),
            Some("SHA1:a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert!(w.node.upload_time > 0);
        // replacing without a checksum clears the old one
        let w = st
            .put_ext(&anna, &lp("/f"), &b"abd"[..], &PutOptions::default())
            .await
            .expect("put");
        assert_eq!(w.node.client_checksum, None);
        assert!(matches!(
            st.put_ext(&anna, &lp("/nope/f"), &b"x"[..], &PutOptions::default())
                .await,
            Err(Error::NotFound)
        ));
        assert_eq!(normalize_checksum("nocolon"), None);
        assert_eq!(normalize_checksum("SHA1:xyz"), None);
        assert_eq!(
            normalize_checksum(" MD5:AbC123 "),
            Some("MD5:AbC123".into())
        );
        assert_eq!(st.file_id(7).len(), 8 + 12);
        assert!(st.file_id(7).starts_with("00000007oc"));
    }

    // ---- versions -------------------------------------------------------------

    async fn versioned(st: &AppState, p: &Principal, path: &str, body: &str, mtime: i64) {
        st.put(
            p,
            &lp(path),
            body.as_bytes(),
            Some(mtime),
            &WriteCondition::None,
        )
        .await
        .expect("put");
    }

    #[tokio::test]
    async fn overwrites_create_versions_that_can_be_read_restored_and_deleted() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        versioned(&st, &anna, "/doc.txt", "one", 1000).await;
        versioned(&st, &anna, "/doc.txt", "second", 2000).await;
        versioned(&st, &anna, "/doc.txt", "3", 3000).await;
        let id = st.stat(&anna, &lp("/doc.txt")).await.expect("stat").id;

        let l = st.version_list(&anna, id).await.expect("list");
        let names: Vec<_> = l
            .entries
            .iter()
            .map(|e| (e.version_time, e.size, e.live))
            .collect();
        assert_eq!(names, [(1000, 3, false), (2000, 6, false), (3000, 1, true)]);
        assert_eq!(l.entries[0].author.as_deref(), Some("anna"));

        let read = |t: i64| {
            let st = st.clone();
            let anna = anna.clone();
            async move {
                let (_, _, mut f) = st.version_open(&anna, id, t).await.expect("open");
                let mut s = String::new();
                f.read_to_string(&mut s).await.expect("read");
                s
            }
        };
        assert_eq!(read(1000).await, "one");
        assert_eq!(read(2000).await, "second");
        assert_eq!(read(3000).await, "3", "the live entry is readable too");
        assert!(matches!(
            st.version_open(&anna, id, 1234).await,
            Err(Error::NotFound)
        ));

        // restore the oldest: it becomes live, the replaced content is archived
        let n = st.version_restore(&anna, id, 1000).await.expect("restore");
        assert_eq!((n.size, n.mtime), (3, 1000));
        let l = st.version_list(&anna, id).await.expect("list");
        assert_eq!(
            l.entries
                .iter()
                .map(|e| (e.version_time, e.live))
                .collect::<Vec<_>>(),
            [(1000, true), (2000, false), (3000, false)]
        );
        let (_, mut f) = st.read(&anna, &lp("/doc.txt")).await.expect("read");
        let mut s = String::new();
        f.read_to_string(&mut s).await.expect("r");
        assert_eq!(s, "one");
        // restoring the live entry is a no-op
        st.version_restore(&anna, id, 1000).await.expect("noop");
        assert_eq!(
            st.version_list(&anna, id).await.expect("l").entries.len(),
            3
        );

        // delete: archived yes, live no, missing 404
        st.version_delete(&anna, id, 2000).await.expect("delete");
        assert!(matches!(
            st.version_delete(&anna, id, 2000).await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            st.version_delete(&anna, id, 1000).await,
            Err(Error::Forbidden)
        ));
        assert_eq!(st.user_info(&anna).await.expect("i").used, 3 + 1);
    }

    #[tokio::test]
    async fn versions_are_private_and_follow_the_file() {
        let (_d, st) = state().await;
        let st = st.with_trash(TrashOptions {
            enabled: false,
            retention_days: 0,
        });
        let anna = login(&st, "anna").await;
        let bob = login(&st, "bob").await;
        versioned(&st, &anna, "/f", "one", 1000).await;
        versioned(&st, &anna, "/f", "two", 2000).await;
        let id = st.stat(&anna, &lp("/f")).await.expect("s").id;
        assert!(matches!(
            st.version_list(&bob, id).await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            st.version_open(&bob, id, 1000).await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            st.version_restore(&bob, id, 1000).await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            st.version_delete(&bob, id, 1000).await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            st.version_list(&anna, 99_999).await,
            Err(Error::NotFound)
        ));
        // a directory has no versions
        st.mkcol(&anna, &lp("/d")).await.expect("mkcol");
        let d = st.stat(&anna, &lp("/d")).await.expect("s").id;
        assert!(matches!(
            st.version_list(&anna, d).await,
            Err(Error::NotFound)
        ));

        // move keeps them, delete removes them
        st.mkcol(&anna, &lp("/dir")).await.expect("mkcol");
        st.move_to(&anna, &lp("/f"), &lp("/dir/g"), false)
            .await
            .expect("move");
        assert_eq!(
            st.version_list(&anna, id).await.expect("l").entries.len(),
            2
        );
        st.delete(&anna, &lp("/dir/g"), None).await.expect("delete");
        assert!(matches!(
            st.version_list(&anna, id).await,
            Err(Error::NotFound)
        ));
        assert_eq!(st.user_info(&anna).await.expect("i").used, 0);
        st.collect_garbage().await.expect("gc");
        assert!(
            st.inner.store.list_blobs().await.expect("l").is_empty(),
            "version blobs are collected with the file"
        );
    }

    #[tokio::test]
    async fn versioning_can_be_switched_off_and_limited() {
        let (_d, st) = state().await;
        let st = st.with_versioning(VersioningOptions {
            enabled: false,
            ..VersioningOptions::default()
        });
        let anna = login(&st, "anna").await;
        versioned(&st, &anna, "/f", "one", 1000).await;
        versioned(&st, &anna, "/f", "two", 2000).await;
        let id = st.stat(&anna, &lp("/f")).await.expect("s").id;
        assert_eq!(
            st.version_list(&anna, id).await.expect("l").entries.len(),
            1,
            "only the live entry"
        );
        assert!(!st.versioning_enabled());

        let (_d2, st2) = state().await;
        let st2 = st2.with_versioning(VersioningOptions {
            max_versions: 1,
            ..VersioningOptions::default()
        });
        let anna = login(&st2, "anna").await;
        for (i, body) in ["a", "bb", "ccc", "dddd"].iter().enumerate() {
            versioned(&st2, &anna, "/f", body, 1000 + i as i64).await;
        }
        let id = st2.stat(&anna, &lp("/f")).await.expect("s").id;
        let l = st2.version_list(&anna, id).await.expect("l");
        assert_eq!(
            l.entries.iter().map(|e| e.size).collect::<Vec<_>>(),
            [3, 4],
            "one version plus live"
        );
    }

    #[tokio::test]
    async fn chunked_assembly_and_cleanup_use_versioning_too() {
        let (_d, st) = state().await;
        let anna = login(&st, "anna").await;
        versioned(&st, &anna, "/f", "old", 1000).await;
        st.upload_create(&anna, "t").await.expect("session");
        st.upload_chunk(&anna, "t", "1", &b"new content"[..])
            .await
            .expect("chunk");
        st.upload_assemble(&anna, "t", &lp("/f"), true, None, Some(2000))
            .await
            .expect("assemble");
        let id = st.stat(&anna, &lp("/f")).await.expect("s").id;
        let l = st.version_list(&anna, id).await.expect("l");
        assert_eq!(
            l.entries.iter().map(|e| e.size).collect::<Vec<_>>(),
            [3, 11]
        );

        // quota share: versions may take 5% of a 100 byte quota -> the 3-byte version fits, a bigger one does not
        st.set_quota("anna", Some(100)).await.expect("quota");
        let st = st.with_versioning(VersioningOptions {
            max_quota_share_percent: 2,
            ..VersioningOptions::default()
        });
        st.collect_garbage().await.expect("gc");
        assert_eq!(
            st.version_list(&anna, id).await.expect("l").entries.len(),
            1,
            "2 bytes allowed: the 3-byte version went"
        );
        assert!(
            st.inner.store.list_blobs().await.expect("l").len() == 1,
            "its blob was collected"
        );
    }
}
