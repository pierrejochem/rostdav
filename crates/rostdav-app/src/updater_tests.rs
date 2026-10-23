//! The updater against a local server and a scratch "program file" (ADR 0009).
//! The signing key and signatures are test fixtures made once with the `minisign` library; the
//! secret key was thrown away.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rostdav_core::Error;
use rostdav_meta::Db;
use rostdav_storage::LocalStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::admin::Actor;
use crate::web::WebSession;
use crate::*;

const PW: &str = "korrekt-pferd-batterie";
const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const OLD_PROGRAM: &str = "#!/bin/sh\necho \"rostdav 0.0.1\"\n";

const KEY: &str = "untrusted comment: minisign public key: FB5BD003E2F3A363\nRWRjo/PiA9Bb+xu5Pjf2QwaS6RWaVjOu+zz7l58y8m2TrUKG0w5Feu76\n";
const NEW_PROGRAM: &str = "#!/bin/sh\necho \"rostdav 99.1.0\"\n";
const NEW_SIGNATURE: &str = "untrusted comment: rostdav test\nRURjo/PiA9Bb+6ZQZC2r8ObmLr3Cm9aFCr8GxRQQ4EIl3+SSqrHl/k0f6w01dCxh+iHwV35b3sBS0+FFzRmivh7nvjvX5iF/5QE=\ntrusted comment: timestamp:1\n1gbe8hLTc1wjXzd6YyEvgz7oilHj9LXVRlj1nHcExL2WSon6+JVoU4LN1MZ+vetQYiIdzGWx4jlxZt5Q9cNhCg==\n";
const OTHER_PROGRAM: &str = "#!/bin/sh\necho \"rostdav 99.0.5\"\n";
const OTHER_SIGNATURE: &str = "untrusted comment: rostdav test\nRURjo/PiA9Bb+4WTlRToYIMbd25Es1QYfrP3vtNUwK8hTiy+fU59H+09zT/sM/xEE803ij0Pqp2jEADMQLDgpvekT+yU90EstA4=\ntrusted comment: timestamp:1\n9Mf1pRsHyNMWBpUxSMfvcq6glDQzm04YKV2CYZwTIkC7cru577V0CLJLmZRUBl/BGc8xIF5QohgLZXguACIyAw==\n";

fn file_target() -> &'static str {
    crate::updater::target().unwrap_or("test-target")
}

type Routes = HashMap<String, (u16, Vec<u8>)>;

/// Serves fixed answers by path; counts requests per path prefix `/v` (the release files).
async fn serve(routes: Routes) -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let asset_requests = Arc::new(AtomicUsize::new(0));
    let counter = asset_requests.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).into_owned();
            let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
            if path.starts_with("/dl/") {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            let (status, body) = routes.get(&path).cloned().unwrap_or((404, Vec::new()));
            let reply = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(reply.as_bytes()).await;
            let _ = sock.write_all(&body).await;
        }
    });
    (base, asset_requests)
}

fn release_json(version: &str) -> Vec<u8> {
    serde_json::json!({
        "tag_name": format!("v{version}"),
        "html_url": format!("https://github.com/pierrejochem/rostdav/releases/tag/v{version}"),
        "published_at": "2026-10-23T12:00:00Z",
        "body": "### Added\n\n- a thing",
    })
    .to_string()
    .into_bytes()
}

struct Setup {
    _dir: tempfile::TempDir,
    st: AppState,
    admin: WebSession,
    exe: PathBuf,
    assets: Arc<AtomicUsize>,
}

/// A state whose version check found `latest`, serving `program` and `signature` as the release
/// files of 99.1.0, and a scratch program file to replace.
async fn setup(latest: &str, program: &str, signature: &str) -> Setup {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = LocalStore::open(dir.path().join("data"))
        .await
        .expect("store");
    let db = Db::open(&Db::default_url(store.root())).await.expect("db");
    db.migrate().await.expect("migrate");
    let st = AppState::new(db, store).await.expect("state");
    st.add_user("root", PW, true).await.expect("root");
    let principal = st.authenticate("root", PW, IP).await.expect("auth");

    let mut routes = Routes::new();
    routes.insert("/latest".into(), (200, release_json(latest)));
    routes.insert(
        format!("/dl/v99.1.0/rostdav-99.1.0-{}", file_target()),
        (200, program.as_bytes().to_vec()),
    );
    routes.insert(
        format!("/dl/v99.1.0/rostdav-99.1.0-{}.minisig", file_target()),
        (200, signature.as_bytes().to_vec()),
    );
    let (base, assets) = serve(routes).await;
    st.set_update_source(&format!("{base}/latest"));
    st.update_set_enabled(&Actor::Cli, true)
        .await
        .expect("check");

    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).expect("bin dir");
    let exe = bin.join("rostdav");
    std::fs::write(&exe, OLD_PROGRAM).expect("old program");
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).expect("mode");
    st.set_updater_for_tests(Some(KEY), &exe, &format!("{base}/dl"), false);
    Setup {
        _dir: dir,
        st,
        admin: WebSession { id: 1, principal },
        exe,
        assets,
    }
}

fn nothing_changed(s: &Setup) {
    assert_eq!(std::fs::read_to_string(&s.exe).expect("exe"), OLD_PROGRAM);
    let dir = s.exe.parent().expect("dir");
    let names: Vec<String> = std::fs::read_dir(dir)
        .expect("ls")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        ["rostdav"],
        "no staged or previous file may stay: {names:?}"
    );
    assert!(!s.st.restart_requested());
}

#[tokio::test]
async fn a_signed_newer_release_is_installed_and_the_old_program_is_kept() {
    let s = setup("99.1.0", NEW_PROGRAM, NEW_SIGNATURE).await;
    assert_eq!(
        s.st.update_install_support(&Actor::Cli)
            .await
            .expect("support"),
        InstallSupport::Ready
    );
    let v =
        s.st.update_install(&s.admin, PW, IP)
            .await
            .expect("install");
    assert_eq!(v, "99.1.0");
    assert_eq!(std::fs::read_to_string(&s.exe).expect("exe"), NEW_PROGRAM);
    let mode = std::fs::metadata(&s.exe)
        .expect("meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o755);
    let prev = s.exe.with_file_name("rostdav.previous");
    assert_eq!(
        std::fs::read_to_string(prev).expect("previous"),
        OLD_PROGRAM
    );
    let backup = s._dir.path().join("data/backups/before-99.1.0.sqlite");
    assert!(backup.metadata().expect("backup").len() > 0);
    assert!(s.st.restart_requested());
    let events = s.st.audit_events(&Actor::Cli, 0).await.expect("events");
    assert!(events.iter().any(|e| e.action == "admin.update_installed"));
    // nothing but the three files is left in the program folder
    let mut names: Vec<String> = std::fs::read_dir(s.exe.parent().expect("dir"))
        .expect("ls")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["rostdav", "rostdav.previous"]);
}

#[tokio::test]
async fn a_download_that_does_not_match_its_signature_is_refused() {
    // the signature is for NEW_PROGRAM; the server hands out something else
    let s = setup(
        "99.1.0",
        "#!/bin/sh\necho \"rostdav 99.1.0\"\necho tampered\n",
        NEW_SIGNATURE,
    )
    .await;
    let e =
        s.st.update_install(&s.admin, PW, IP)
            .await
            .expect_err("refused");
    assert!(
        matches!(&e, Error::Invalid(m) if m.contains("signature")),
        "{e:?}"
    );
    nothing_changed(&s);
}

#[tokio::test]
async fn a_signature_of_another_key_or_garbage_is_refused() {
    let s = setup("99.1.0", NEW_PROGRAM, "not a signature").await;
    assert!(s.st.update_install(&s.admin, PW, IP).await.is_err());
    nothing_changed(&s);
    // a valid signature, but our fixture key is not the one built in
    let other_key = "untrusted comment: minisign public key: 0000000000000000\nRWQAAAAAAAAAAMfR3CNbpdGCLQ6rdQ7vZ2l9TqjGYbwE0qjCm8mVyD4o\n";
    s.st.set_updater_for_tests(
        Some(other_key),
        &s.exe,
        &format!("{}/dl", "http://127.0.0.1:1"),
        false,
    );
    assert!(s.st.update_install(&s.admin, PW, IP).await.is_err());
    nothing_changed(&s);
}

#[tokio::test]
async fn a_program_that_reports_another_version_is_not_installed() {
    // correctly signed, but it says 99.0.5
    let s = setup("99.1.0", OTHER_PROGRAM, OTHER_SIGNATURE).await;
    let e =
        s.st.update_install(&s.admin, PW, IP)
            .await
            .expect_err("refused");
    assert!(
        matches!(&e, Error::Invalid(m) if m.contains("another version")),
        "{e:?}"
    );
    nothing_changed(&s);
}

#[tokio::test]
async fn a_program_that_does_not_start_is_not_installed() {
    // the smoke test on its own: a file that starts and fails
    let dir = tempfile::tempdir().expect("tempdir");
    let broken = dir.path().join("broken");
    std::fs::write(&broken, "#!/bin/sh\nexit 3\n").expect("write");
    std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o755)).expect("mode");
    let v = rostdav_core::release::Version::parse("99.1.0").expect("version");
    assert!(
        crate::updater::smoke_test_for_tests(&broken, &v)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_wrong_password_or_a_non_administrator_installs_nothing() {
    let s = setup("99.1.0", NEW_PROGRAM, NEW_SIGNATURE).await;
    let e =
        s.st.update_install(&s.admin, "falsches-passwort-1", IP)
            .await
            .expect_err("refused");
    assert!(
        matches!(&e, Error::Invalid(m) if m.contains("password")),
        "{e:?}"
    );
    nothing_changed(&s);
    assert_eq!(
        s.assets.load(Ordering::SeqCst),
        0,
        "nothing is downloaded before the password"
    );

    s.st.add_user("anna", PW, false).await.expect("anna");
    let anna = s.st.authenticate("anna", PW, IP).await.expect("auth");
    let ws = WebSession {
        id: 2,
        principal: anna,
    };
    assert!(matches!(
        s.st.update_install(&ws, PW, IP).await,
        Err(Error::Forbidden)
    ));
    nothing_changed(&s);
    assert_eq!(s.assets.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_container_a_missing_key_and_a_readonly_folder_cannot_install() {
    let s = setup("99.1.0", NEW_PROGRAM, NEW_SIGNATURE).await;
    let base = "http://127.0.0.1:1/dl";

    s.st.set_updater_for_tests(Some(KEY), &s.exe, base, true);
    assert_eq!(
        s.st.update_install_support(&Actor::Cli)
            .await
            .expect("support"),
        InstallSupport::Container
    );
    assert!(s.st.update_install(&s.admin, PW, IP).await.is_err());

    s.st.set_updater_for_tests(None, &s.exe, base, false);
    assert_eq!(
        s.st.update_install_support(&Actor::Cli)
            .await
            .expect("support"),
        InstallSupport::NoKey
    );
    // the placeholder file shipped in the repository holds no key
    s.st.set_updater_for_tests(Some("untrusted comment: no key\n"), &s.exe, base, false);
    assert_eq!(
        s.st.update_install_support(&Actor::Cli)
            .await
            .expect("support"),
        InstallSupport::NoKey
    );
    assert!(s.st.update_install(&s.admin, PW, IP).await.is_err());

    let dir = s.exe.parent().expect("dir").to_path_buf();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).expect("mode");
    s.st.set_updater_for_tests(Some(KEY), &s.exe, base, false);
    let support =
        s.st.update_install_support(&Actor::Cli)
            .await
            .expect("support");
    let writable_anyway = std::fs::write(dir.join("probe"), "x").is_ok(); // running as root
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("mode");
    if !writable_anyway {
        assert_eq!(support, InstallSupport::NotWritable);
    }
    assert_eq!(s.assets.load(Ordering::SeqCst), 0);
    let _ = std::fs::remove_file(dir.join("probe"));
    nothing_changed(&s);
}

#[tokio::test]
async fn an_older_equal_or_unknown_version_is_not_installed() {
    // the check found 0.0.1: nothing newer
    let s = setup("0.0.1", NEW_PROGRAM, NEW_SIGNATURE).await;
    let e =
        s.st.update_install(&s.admin, PW, IP)
            .await
            .expect_err("refused");
    assert!(
        matches!(&e, Error::Invalid(m) if m.contains("no newer")),
        "{e:?}"
    );
    nothing_changed(&s);
    assert_eq!(s.assets.load(Ordering::SeqCst), 0);
    // the version check is off or never ran: nothing to install either
    let t = setup("99.1.0", NEW_PROGRAM, NEW_SIGNATURE).await;
    t.st.update_set_enabled(&Actor::Cli, false)
        .await
        .expect("off");
    // (the stored answer stays; only a fresh state has none)
    let fresh = {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalStore::open(dir.path().join("data"))
            .await
            .expect("store");
        let db = Db::open(&Db::default_url(store.root())).await.expect("db");
        db.migrate().await.expect("migrate");
        let st = AppState::new(db, store).await.expect("state");
        st.add_user("root", PW, true).await.expect("root");
        let p = st.authenticate("root", PW, IP).await.expect("auth");
        st.set_updater_for_tests(Some(KEY), &t.exe, "http://127.0.0.1:1/dl", false);
        (dir, st, p)
    };
    let ws = WebSession {
        id: 1,
        principal: fresh.2,
    };
    assert!(fresh.1.update_install(&ws, PW, IP).await.is_err());
}

#[tokio::test]
async fn a_missing_signature_file_or_a_failed_backup_installs_nothing() {
    let s = setup("99.1.0", NEW_PROGRAM, NEW_SIGNATURE).await;
    // no signature on the server
    let mut routes = Routes::new();
    routes.insert(
        format!("/dl/v99.1.0/rostdav-99.1.0-{}", file_target()),
        (200, NEW_PROGRAM.as_bytes().to_vec()),
    );
    let (base, _) = serve(routes).await;
    s.st.set_updater_for_tests(Some(KEY), &s.exe, &format!("{base}/dl"), false);
    assert!(s.st.update_install(&s.admin, PW, IP).await.is_err());
    nothing_changed(&s);

    // a backup that cannot be written (a directory is in the way)
    let s = setup("99.1.0", NEW_PROGRAM, NEW_SIGNATURE).await;
    let in_the_way = s._dir.path().join("data/backups/before-99.1.0.sqlite");
    std::fs::create_dir_all(&in_the_way).expect("dir");
    let e =
        s.st.update_install(&s.admin, PW, IP)
            .await
            .expect_err("refused");
    assert!(
        matches!(&e, Error::Invalid(m) if m.contains("backup")),
        "{e:?}"
    );
    nothing_changed(&s);
}

#[test]
fn only_githubs_https_hosts_are_trusted() {
    use crate::updater::trusted_for_tests as trusted;
    for ok in [
        "https://github.com/pierrejochem/rostdav/releases/download/v1.0.0/x",
        "https://objects.githubusercontent.com/a/b",
        "https://release-assets.githubusercontent.com/a",
    ] {
        assert!(trusted(ok), "{ok}");
    }
    for bad in [
        "http://github.com/x",
        "https://github.com.evil.example/x",
        "https://evil.example/github.com",
        "https://evilgithub.com/x",
        "https://user@evil.example/",
        "https://githubusercontent.com/x",
        "ftp://github.com/x",
        "//github.com/x",
        "/x",
    ] {
        assert!(!trusted(bad), "{bad}");
    }
}

#[test]
fn signatures_are_checked_against_the_key() {
    use crate::updater::verify_signature as v;
    assert!(v(KEY, NEW_SIGNATURE, NEW_PROGRAM.as_bytes()));
    assert!(!v(KEY, NEW_SIGNATURE, OTHER_PROGRAM.as_bytes()), "content");
    assert!(
        !v(KEY, OTHER_SIGNATURE, NEW_PROGRAM.as_bytes()),
        "signature of other content"
    );
    assert!(!v(KEY, "", NEW_PROGRAM.as_bytes()));
    assert!(!v("", NEW_SIGNATURE, NEW_PROGRAM.as_bytes()), "no key");
    assert!(!v(
        "untrusted comment: only a comment\n",
        NEW_SIGNATURE,
        NEW_PROGRAM.as_bytes()
    ));
}
