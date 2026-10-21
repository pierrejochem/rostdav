use std::net::{IpAddr, Ipv4Addr};

use rostdav_core::{Error, LogicalPath};
use rostdav_meta::{Db, WriteCondition};
use rostdav_storage::{BlobId, LocalStore};
use tokio::io::AsyncReadExt;

use crate::*;

const PW: &str = "korrekt-pferd-batterie";
const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

async fn state() -> (tempfile::TempDir, AppState) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = LocalStore::open(dir.path().join("data"))
        .await
        .expect("store");
    let db = Db::open(&Db::default_url(store.root())).await.expect("db");
    db.migrate().await.expect("migrate");
    (dir, AppState::new(db, store).await.expect("state"))
}

fn lp(s: &str) -> LogicalPath {
    LogicalPath::from_url_path(s).expect("path")
}

async fn login(st: &AppState, name: &str) -> Principal {
    st.authenticate(name, PW, IP).await.expect("auth")
}

async fn put(st: &AppState, p: &Principal, path: &str, body: &'static str) {
    st.put(p, &lp(path), body.as_bytes(), None, &WriteCondition::None)
        .await
        .expect("put");
}

async fn actions(st: &AppState) -> Vec<String> {
    st.audit_events(&Actor::Cli, 0)
        .await
        .expect("events")
        .into_iter()
        .map(|e| e.action)
        .collect()
}

#[tokio::test]
async fn admin_rules_protect_the_last_administrator() {
    let (_d, st) = state().await;
    st.add_user("anna", PW, true).await.expect("anna");
    st.add_user("bob", PW, true).await.expect("bob");
    st.add_user("carl", PW, false).await.expect("carl");
    let anna = login(&st, "anna").await;

    // not yourself
    let e = st
        .user_set_disabled(&Actor::User(&anna), "anna", true)
        .await;
    assert!(matches!(e, Err(Error::Conflict(m)) if m.contains("yourself")));
    assert!(matches!(
        st.user_delete(&Actor::User(&anna), "anna", &DeleteMode::DeleteData)
            .await,
        Err(Error::Conflict(_))
    ));

    // disabling bob works while anna remains; then anna is the last admin
    st.user_set_disabled(&Actor::User(&anna), "bob", true)
        .await
        .expect("disable bob");
    assert!(matches!(
        st.user_set_disabled(&Actor::Cli, "anna", true).await,
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        st.user_set_admin(&Actor::Cli, "anna", false).await,
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        st.user_delete(&Actor::Cli, "anna", &DeleteMode::DeleteData)
            .await,
        Err(Error::Conflict(_))
    ));
    // a disabled admin does not count: promoting carl first makes it possible
    st.user_set_admin(&Actor::Cli, "carl", true)
        .await
        .expect("promote");
    st.user_set_admin(&Actor::Cli, "anna", false)
        .await
        .expect("demote anna");
    assert!(matches!(
        st.user_set_admin(&Actor::Cli, "carl", false).await,
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        st.user_set_disabled(&Actor::Cli, "ghost", true).await,
        Err(Error::NotFound)
    ));
}

#[tokio::test]
async fn only_administrators_may_administer() {
    let (_d, st) = state().await;
    st.add_user("anna", PW, true).await.expect("anna");
    st.add_user("carl", PW, false).await.expect("carl");
    let carl = login(&st, "carl").await;
    let a = Actor::User(&carl);
    assert!(matches!(st.users_list(&a).await, Err(Error::Forbidden)));
    assert!(matches!(
        st.user_set_disabled(&a, "anna", true).await,
        Err(Error::Forbidden)
    ));
    assert!(
        matches!(
            st.user_set_admin(&a, "carl", true).await,
            Err(Error::Forbidden)
        ),
        "no self-promotion"
    );
    assert!(matches!(
        st.user_set_quota(&a, "carl", None).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        st.user_set_password(&a, "anna", "neues-passwort-123", true)
            .await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        st.user_delete(&a, "anna", &DeleteMode::DeleteData).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        st.audit_events(&a, 0).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        st.fsck(&a, FsckOptions::default()).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        st.import_tree(
            &a,
            std::path::Path::new("/tmp"),
            "carl",
            &ImportOptions::default()
        )
        .await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        st.create_user_as(&a, "x", PW, false).await,
        Err(Error::Forbidden)
    ));
    // nothing changed
    assert!(
        !st.users_list(&Actor::Cli)
            .await
            .expect("l")
            .iter()
            .any(|u| u.disabled)
    );
}

#[tokio::test]
async fn disabled_users_cannot_sign_in_anywhere() {
    let (_d, st) = state().await;
    st.add_user("anna", PW, true).await.expect("anna");
    let bob = st.add_user("bob", PW, false).await.expect("bob");
    let app = st.create_app_password(bob.id, "Phone").await.expect("app");
    assert!(st.authenticate("bob", &app, IP).await.is_ok());

    st.user_set_disabled(&Actor::Cli, "bob", true)
        .await
        .expect("disable");
    assert!(matches!(
        st.authenticate("bob", PW, IP).await,
        Err(Error::Unauthenticated)
    ));
    assert!(matches!(
        st.authenticate("bob", &app, IP).await,
        Err(Error::Unauthenticated)
    ));
    let f = st.start_login_flow("Phone").await.expect("flow");
    let csrf = st.flow_csrf(&f.login_token, "allow");
    assert!(matches!(
        st.flow_allow(&f.login_token, &csrf, "bob", PW, IP).await,
        Err(Error::Unauthenticated)
    ));
    // the correct password of a disabled user does not lock the address out
    for _ in 0..15 {
        let _ = st.authenticate("bob", PW, IP).await;
    }
    assert!(st.authenticate("anna", PW, IP).await.is_ok());

    st.user_set_disabled(&Actor::Cli, "bob", false)
        .await
        .expect("enable");
    assert!(st.authenticate("bob", PW, IP).await.is_ok());
    assert!(
        st.authenticate("bob", &app, IP).await.is_ok(),
        "devices survive a disable/enable"
    );
}

#[tokio::test]
async fn password_reset_and_device_revocation() {
    let (_d, st) = state().await;
    st.add_user("anna", PW, true).await.expect("anna");
    let bob = st.add_user("bob", PW, false).await.expect("bob");
    let app = st.create_app_password(bob.id, "Phone").await.expect("app");

    assert!(matches!(
        st.user_set_password(&Actor::Cli, "bob", "kurz", false)
            .await,
        Err(Error::BadRequest(_))
    ));
    st.user_set_password(&Actor::Cli, "bob", "ganz-neues-passwort", false)
        .await
        .expect("reset");
    assert!(matches!(
        st.authenticate("bob", PW, IP).await,
        Err(Error::Unauthenticated)
    ));
    assert!(
        st.authenticate("bob", "ganz-neues-passwort", IP)
            .await
            .is_ok()
    );
    assert!(
        st.authenticate("bob", &app, IP).await.is_ok(),
        "devices kept without --revoke-devices"
    );
    st.user_set_password(&Actor::Cli, "bob", "noch-ein-passwort", true)
        .await
        .expect("reset");
    assert!(matches!(
        st.authenticate("bob", &app, IP).await,
        Err(Error::Unauthenticated)
    ));

    // no secret ended up in the event log
    let log = serde_json::to_string(
        &st.audit_events(&Actor::Cli, 0)
            .await
            .expect("e")
            .iter()
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>(),
    )
    .expect("json");
    for secret in [PW, "ganz-neues-passwort", "noch-ein-passwort", app.as_str()] {
        assert!(!log.contains(secret), "{secret} leaked into the event log");
    }
}

#[tokio::test]
async fn events_cover_logins_locks_devices_and_admin_actions() {
    let (_d, st) = state().await;
    st.add_user("anna", PW, true).await.expect("anna");
    for _ in 0..10 {
        let _ = st.authenticate("anna", "falsch-falsch-falsch", IP).await;
    }
    let f = st.start_login_flow("Pixel 8").await.expect("flow");
    // locked by now: use another address for the browser login
    let other: IpAddr = "198.51.100.7".parse().expect("ip");
    let _ = other;
    let a = actions(&st).await;
    assert!(a.contains(&"admin.user_created".to_owned()));
    assert_eq!(a.iter().filter(|x| *x == "auth.login_failed").count(), 10);
    assert_eq!(
        a.iter().filter(|x| *x == "auth.locked").count(),
        1,
        "locking is recorded once"
    );

    // a fresh instance for the flow so the lock does not interfere
    let (_d2, st2) = state().await;
    st2.add_user("anna", PW, true).await.expect("anna");
    let f2 = st2.start_login_flow("Pixel 8").await.expect("flow");
    st2.flow_allow(
        &f2.login_token,
        &st2.flow_csrf(&f2.login_token, "allow"),
        "anna",
        PW,
        IP,
    )
    .await
    .expect("allow");
    let g = st2
        .poll_login_flow(&f2.poll_token)
        .await
        .expect("poll")
        .expect("granted");
    let p = st2
        .authenticate("anna", &g.app_password, IP)
        .await
        .expect("auth");
    st2.revoke_current_app_password(&p).await.expect("revoke");
    let ev = st2.audit_events(&Actor::Cli, 0).await.expect("events");
    let by = |action: &str| {
        ev.iter()
            .find(|e| e.action == action)
            .unwrap_or_else(|| panic!("no {action}"))
    };
    assert_eq!(by("auth.login").actor, "anna");
    assert_eq!(by("device.connected").target, "Pixel 8");
    assert_eq!(by("device.revoked").target, "Pixel 8");
    assert_eq!(by("auth.login").ip, "127.0.0.1");
    let _ = f;
}

#[tokio::test]
async fn event_ip_anonymization_export_filter_and_retention() {
    let (_d, st) = state().await;
    let st = st.with_audit(AuditOptions {
        anonymize_ip: true,
        retention_days: 1,
    });
    st.add_user("anna", PW, true).await.expect("anna");
    let ip: IpAddr = "203.0.113.77".parse().expect("ip");
    let _ = st.authenticate("anna", "falsch-falsch-falsch", ip).await;
    let ev = st.audit_events(&Actor::Cli, 0).await.expect("e");
    let failed = ev
        .iter()
        .find(|e| e.action == "auth.login_failed")
        .expect("failed");
    assert_eq!(failed.ip, "203.0.113.0");
    assert!(
        st.audit_events(&Actor::Cli, i64::MAX)
            .await
            .expect("e")
            .is_empty()
    );

    // retention: old events go, new ones stay
    st.inner
        .db
        .record_event_at(1_000, "x", "ancient", "", "", "{}")
        .await
        .expect("e");
    let before = st.audit_events(&Actor::Cli, 0).await.expect("e").len();
    assert_eq!(st.purge_old_events().await.expect("purge"), 1);
    let after = st.audit_events(&Actor::Cli, 0).await.expect("e");
    assert_eq!(after.len(), before - 1);
    assert!(after.iter().all(|e| e.action != "ancient"));
    st.inner
        .db
        .record_event_at(1_000, "x", "ancient", "", "", "{}")
        .await
        .expect("e");
    let st0 = st.clone().with_audit(AuditOptions {
        anonymize_ip: false,
        retention_days: 0,
    });
    assert_eq!(
        st0.purge_old_events().await.expect("purge"),
        0,
        "0 days keeps everything"
    );
}

#[tokio::test]
async fn delete_user_with_data_frees_blobs_and_sessions() {
    let (_d, st) = state().await;
    st.add_user("anna", PW, true).await.expect("anna");
    st.add_user("bob", PW, false).await.expect("bob");
    let bob = login(&st, "bob").await;
    put(&st, &bob, "/f.txt", "inhalt").await;
    st.upload_create(&bob, "t").await.expect("session");
    st.upload_chunk(&bob, "t", "1", &b"abc"[..])
        .await
        .expect("chunk");

    st.user_delete(&Actor::Cli, "bob", &DeleteMode::DeleteData)
        .await
        .expect("delete");
    assert!(st.inner.db.find_user("bob").await.expect("f").is_none());
    assert!(
        st.inner.store.list_blobs().await.expect("l").is_empty(),
        "blob removed"
    );
    assert!(
        st.inner
            .store
            .list_session_dirs()
            .await
            .expect("l")
            .is_empty(),
        "chunks removed"
    );
    assert!(matches!(
        st.authenticate("bob", PW, IP).await,
        Err(Error::Unauthenticated)
    ));
    assert!(
        actions(&st)
            .await
            .contains(&"admin.user_deleted".to_owned())
    );
}

#[tokio::test]
async fn delete_user_can_transfer_data() {
    let (_d, st) = state().await;
    st.add_user("anna", PW, true).await.expect("anna");
    st.add_user("bob", PW, false).await.expect("bob");
    let (anna, bob) = (login(&st, "anna").await, login(&st, "bob").await);
    st.mkcol(&bob, &lp("/Docs")).await.expect("mkcol");
    put(&st, &bob, "/Docs/f.txt", "inhalt").await;

    assert!(matches!(
        st.user_delete(&Actor::Cli, "bob", &DeleteMode::TransferTo("bob".into()))
            .await,
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        st.user_delete(&Actor::Cli, "bob", &DeleteMode::TransferTo("ghost".into()))
            .await,
        Err(Error::NotFound)
    ));
    st.user_delete(&Actor::Cli, "bob", &DeleteMode::TransferTo("anna".into()))
        .await
        .expect("delete");

    let (_, mut f) = st
        .read(&anna, &lp("/bob%20(transferred)/Docs/f.txt"))
        .await
        .expect("moved");
    let mut s = String::new();
    f.read_to_string(&mut s).await.expect("r");
    assert_eq!(s, "inhalt");
    let info = st.user_info(&anna).await.expect("i");
    assert_eq!(info.used, 6);
    assert_eq!(
        st.inner.store.list_blobs().await.expect("l").len(),
        1,
        "blob survives the delete"
    );
    let users = st.users_list(&Actor::Cli).await.expect("l");
    assert_eq!(users.len(), 1);
}

#[tokio::test]
async fn fsck_finds_and_repairs_inconsistencies() {
    let (_d, st) = state().await;
    st.add_user("anna", PW, true).await.expect("anna");
    let anna = login(&st, "anna").await;
    put(&st, &anna, "/good.txt", "good").await;
    put(&st, &anna, "/lost.txt", "lost").await;
    put(&st, &anna, "/bad.txt", "1234").await;

    let report = st
        .fsck(
            &Actor::Cli,
            FsckOptions {
                verify_checksums: true,
                ..FsckOptions::default()
            },
        )
        .await
        .expect("fsck");
    assert!(report.is_clean(), "{report:?}");
    assert_eq!(report.blobs_checked, 3);

    // 1. a blob file disappears
    let lost = st.inner.db.nodes_using_blob("x").await.expect("n");
    let _ = lost;
    let node = st.stat(&anna, &lp("/lost.txt")).await.expect("stat");
    st.inner
        .store
        .delete_blob(&BlobId::parse(node.blob_id.as_deref().expect("blob")).expect("id"))
        .await
        .expect("rm");
    // 2. a blob changes on disk (same size)
    let node = st.stat(&anna, &lp("/bad.txt")).await.expect("stat");
    let bad_id = BlobId::parse(node.blob_id.as_deref().expect("blob")).expect("id");
    let path = st
        .inner
        .store
        .root()
        .join("blobs")
        .join(&bad_id.as_str()[0..2])
        .join(&bad_id.as_str()[2..4])
        .join(bad_id.as_str());
    std::fs::write(&path, b"4321").expect("tamper");
    // 3. an orphan file, an old and a young one
    let orphan = st
        .inner
        .store
        .put(&b"orphan"[..], 100)
        .await
        .expect("orphan");
    // 4. wrong usage counter
    st.inner
        .db
        .set_used_bytes(anna.user_id, 999)
        .await
        .expect("break");
    // 5. orphan session dir and a session row without dir
    let dir = BlobId::generate();
    st.inner.store.create_session(&dir).await.expect("dir");
    st.upload_create(&anna, "nodir").await.expect("s");
    let s = st
        .inner
        .db
        .find_upload_session(anna.user_id, "nodir")
        .await
        .expect("f")
        .expect("row");
    st.inner
        .store
        .remove_session(&BlobId::parse(&s.dir).expect("id"))
        .await
        .expect("rm");

    let r = st
        .fsck(
            &Actor::Cli,
            FsckOptions {
                verify_checksums: true,
                min_orphan_age_secs: 3600,
                ..FsckOptions::default()
            },
        )
        .await
        .expect("fsck");
    assert!(!r.is_clean());
    assert_eq!(r.missing_blobs.len(), 1);
    assert_eq!(r.missing_blobs[0].1, vec!["anna:lost.txt".to_owned()]);
    assert_eq!(r.corrupt_blobs, vec![bad_id.to_string()]);
    assert!(
        r.orphan_blobs.is_empty(),
        "young orphans (maybe an upload in flight) are left alone"
    );
    assert_eq!(r.usage_mismatches.len(), 1);
    assert_eq!(r.orphan_session_dirs, vec![dir.to_string()]);
    assert_eq!(r.sessions_without_dir, vec!["nodir".to_owned()]);

    // report-only runs change nothing
    let r = st
        .fsck(
            &Actor::Cli,
            FsckOptions {
                min_orphan_age_secs: 0,
                ..FsckOptions::default()
            },
        )
        .await
        .expect("fsck");
    assert_eq!(r.orphan_blobs, vec![orphan.id.to_string()]);
    assert!(
        st.inner.store.open_blob(&orphan.id).await.is_ok(),
        "not repaired without --repair"
    );

    // repair fixes what is fixable; damaged files stay reported
    let r = st
        .fsck(
            &Actor::Cli,
            FsckOptions {
                repair: true,
                min_orphan_age_secs: 0,
                ..FsckOptions::default()
            },
        )
        .await
        .expect("fsck");
    assert_eq!(r.orphan_blobs.len(), 1);
    assert!(matches!(
        st.inner.store.open_blob(&orphan.id).await,
        Err(Error::NotFound)
    ));
    let r = st
        .fsck(
            &Actor::Cli,
            FsckOptions {
                verify_checksums: true,
                ..FsckOptions::default()
            },
        )
        .await
        .expect("fsck");
    assert!(r.orphan_blobs.is_empty() && r.usage_mismatches.is_empty());
    assert!(r.orphan_session_dirs.is_empty() && r.sessions_without_dir.is_empty());
    assert_eq!(
        (r.missing_blobs.len(), r.corrupt_blobs.len()),
        (1, 1),
        "data damage is never hidden"
    );
    assert!(!r.is_clean());
    assert!(
        actions(&st)
            .await
            .iter()
            .filter(|a| *a == "admin.fsck")
            .count()
            >= 4
    );
}

#[cfg(unix)]
#[tokio::test]
async fn import_copies_a_tree_safely() {
    let (_d, st) = state().await;
    st.add_user("anna", PW, true).await.expect("anna");
    let anna = login(&st, "anna").await;
    let host = tempfile::tempdir().expect("host");
    let root = host.path().join("src");
    std::fs::create_dir_all(root.join("a/b")).expect("dirs");
    std::fs::write(root.join("top.txt"), "top").expect("f");
    std::fs::write(root.join("a/b/deep.txt"), "deep").expect("f");
    std::fs::write(root.join("a/skip.part"), "x").expect("f");
    std::fs::write(root.join("a/back\\slash"), "x").expect("f");
    std::os::unix::fs::symlink("/etc/passwd", root.join("link")).expect("symlink");
    std::os::unix::fs::symlink(&root, root.join("a/loop")).expect("symlink");
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    std::fs::File::options()
        .write(true)
        .open(root.join("top.txt"))
        .expect("o")
        .set_modified(t)
        .expect("mtime");

    let r = st
        .import_tree(
            &Actor::Cli,
            &root,
            "anna",
            &ImportOptions {
                overwrite: false,
                dest: Some("Import/Old".into()),
            },
        )
        .await
        .expect("import");
    assert_eq!((r.files, r.dirs, r.bytes), (2, 2, 7), "{r:?}");
    assert_eq!(r.skipped_total, 4, "{:?}", r.skipped);
    let reasons: Vec<_> = r.skipped.iter().map(|(_, why)| why.as_str()).collect();
    assert!(
        reasons.iter().filter(|w| **w == "symbolic link").count() == 2,
        "{reasons:?}"
    );
    assert!(reasons.iter().any(|w| w.contains(".part")), "{reasons:?}");

    let n = st
        .stat(&anna, &lp("/Import/Old/top.txt"))
        .await
        .expect("top");
    assert_eq!((n.size, n.mtime), (3, 1_600_000_000));
    assert!(
        st.stat(&anna, &lp("/Import/Old/a/b/deep.txt"))
            .await
            .is_ok()
    );
    assert!(matches!(
        st.stat(&anna, &lp("/Import/Old/link")).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        st.stat(&anna, &lp("/Import/Old/a/skip.part")).await,
        Err(Error::NotFound)
    ));

    // a second run skips what exists, overwrite replaces
    let r = st
        .import_tree(
            &Actor::Cli,
            &root,
            "anna",
            &ImportOptions {
                overwrite: false,
                dest: Some("Import/Old".into()),
            },
        )
        .await
        .expect("again");
    assert_eq!((r.files, r.skipped_existing), (0, 2));
    std::fs::write(root.join("top.txt"), "TOP2").expect("f");
    let r = st
        .import_tree(
            &Actor::Cli,
            &root,
            "anna",
            &ImportOptions {
                overwrite: true,
                dest: Some("Import/Old".into()),
            },
        )
        .await
        .expect("overwrite");
    assert_eq!(r.files, 2);
    assert_eq!(
        st.stat(&anna, &lp("/Import/Old/top.txt"))
            .await
            .expect("n")
            .size,
        4
    );

    // errors
    assert!(matches!(
        st.import_tree(
            &Actor::Cli,
            &root.join("top.txt"),
            "anna",
            &ImportOptions::default()
        )
        .await,
        Err(Error::BadRequest(_))
    ));
    assert!(matches!(
        st.import_tree(&Actor::Cli, &root, "ghost", &ImportOptions::default())
            .await,
        Err(Error::NotFound)
    ));
    assert!(
        st.import_tree(
            &Actor::Cli,
            &root,
            "anna",
            &ImportOptions {
                dest: Some("../x".into()),
                ..ImportOptions::default()
            }
        )
        .await
        .is_err()
    );
    st.set_quota("anna", Some(5)).await.expect("quota");
    let r = st
        .import_tree(
            &Actor::Cli,
            &root,
            "anna",
            &ImportOptions {
                overwrite: false,
                dest: Some("Q".into()),
            },
        )
        .await;
    assert!(matches!(r, Err(Error::QuotaExceeded)), "{r:?}");
}
