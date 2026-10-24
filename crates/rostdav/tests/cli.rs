//! `rostdav admin …` driven as a real process.

use std::io::Write;
use std::process::{Command, Stdio};

const PW: &str = "korrekt-pferd-batterie";

struct Cli {
    dir: tempfile::TempDir,
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Cli {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn run(&self, args: &[&str], stdin: &str) -> Out {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rostdav"))
            .arg("admin")
            .args(args)
            .env("ROSTDAV_STORAGE__DATA_DIR", self.dir.path().join("data"))
            .current_dir(self.dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes())
            .expect("write");
        let o = child.wait_with_output().expect("wait");
        Out {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }

    fn ok(&self, args: &[&str], stdin: &str) -> String {
        let o = self.run(args, stdin);
        assert_eq!(o.code, 0, "{args:?}: {}{}", o.stdout, o.stderr);
        o.stdout
    }

    fn fail(&self, args: &[&str], stdin: &str) -> String {
        let o = self.run(args, stdin);
        assert_ne!(o.code, 0, "{args:?} should fail: {}", o.stdout);
        o.stderr
    }
}

#[test]
fn user_lifecycle() {
    let c = Cli::new();
    assert!(
        c.ok(&["user", "add", "anna", "--admin"], &format!("{PW}\n"))
            .contains("user anna created")
    );
    c.ok(&["user", "add", "bob"], &format!("{PW}\n"));
    assert!(
        c.fail(&["user", "add", "bob"], &format!("{PW}\n"))
            .contains("already exists")
    );
    assert!(
        c.fail(&["user", "add", "carl"], "kurz\n")
            .contains("too short")
    );

    let list = c.ok(&["user", "list"], "");
    assert!(
        list.contains("NAME")
            && list.contains("anna")
            && list.contains("admin")
            && list.contains("unlimited"),
        "{list}"
    );
    assert!(!list.contains(PW));

    c.ok(&["user", "set-quota", "bob", "2G"], "");
    c.ok(&["user", "disable", "bob"], "");
    let json = c.ok(&["user", "list", "--json"], "");
    let rows: Vec<serde_json::Value> = json
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();
    let bob = rows.iter().find(|r| r["name"] == "bob").expect("bob");
    assert_eq!(
        (bob["disabled"].as_bool(), bob["quota_bytes"].as_i64()),
        (Some(true), Some(2 * 1024 * 1024 * 1024))
    );
    assert!(
        rows.iter().find(|r| r["name"] == "anna").expect("anna")["admin"]
            .as_bool()
            .expect("b")
    );
    c.ok(&["user", "enable", "bob"], "");
    c.ok(&["user", "set-quota", "bob", "unlimited"], "");

    // role changes and the last-admin rule
    assert!(
        c.fail(&["user", "role", "anna", "user"], "")
            .contains("last administrator")
    );
    assert!(
        c.fail(&["user", "disable", "anna"], "")
            .contains("last administrator")
    );
    c.ok(&["user", "role", "bob", "admin"], "");
    c.ok(&["user", "role", "anna", "user"], "");
    assert!(
        c.fail(&["user", "set-quota", "ghost", "1G"], "")
            .contains("not found")
    );
    assert!(
        c.fail(&["user", "set-quota", "bob", "lots"], "")
            .contains("unknown size unit")
    );

    // password
    c.ok(
        &["user", "set-password", "bob", "--revoke-devices"],
        "ganz-neues-passwort\n",
    );
    assert!(
        c.fail(&["user", "set-password", "bob"], "kurz\n")
            .contains("too short")
    );

    // deleting needs --yes and obeys the rules
    assert!(c.fail(&["user", "delete", "anna"], "").contains("--yes"));
    assert!(
        c.fail(&["user", "delete", "bob", "--yes"], "")
            .contains("last administrator")
    );
    c.ok(&["user", "delete", "anna", "--yes"], "");
    assert!(!c.ok(&["user", "list"], "").contains("anna"));
}

#[test]
fn audit_export_lists_admin_actions_without_secrets() {
    let c = Cli::new();
    c.ok(&["user", "add", "anna", "--admin"], &format!("{PW}\n"));
    c.ok(&["user", "set-password", "anna"], "ein-anderes-passwort\n");
    c.ok(&["user", "set-quota", "anna", "1M"], "");
    let out = c.ok(&["audit", "export"], "");
    let ev: Vec<serde_json::Value> = out
        .lines()
        .map(|l| serde_json::from_str(l).expect("jsonl"))
        .collect();
    let actions: Vec<_> = ev
        .iter()
        .map(|e| e["action"].as_str().expect("a"))
        .collect();
    assert_eq!(
        actions,
        [
            "admin.user_created",
            "admin.user_password_reset",
            "admin.user_quota_set"
        ]
    );
    assert!(
        ev.iter()
            .all(|e| e["actor"] == "cli" && e["time"].as_str().expect("t").ends_with('Z'))
    );
    assert_eq!(ev[2]["details"]["quota_bytes"], 1024 * 1024);
    assert!(!out.contains(PW) && !out.contains("ein-anderes-passwort"));

    assert_eq!(c.ok(&["audit", "export", "--since", "2999-01-01"], ""), "");
    assert_eq!(
        c.ok(&["audit", "export", "--since", "2000-01-01"], "")
            .lines()
            .count(),
        3
    );
    assert!(
        c.fail(&["audit", "export", "--since", "yesterday"], "")
            .contains("not a date")
    );
}

#[test]
fn fsck_exit_codes_and_repair() {
    let c = Cli::new();
    c.ok(&["user", "add", "anna"], &format!("{PW}\n"));
    let out = c.ok(&["fsck", "--verify"], "");
    assert!(
        out.contains("blobs checked: 0") && out.trim_end().ends_with("ok"),
        "{out}"
    );

    // plant an old orphan blob file and a stale tmp-independent session dir
    let blobs = c.dir.path().join("data/blobs/01/AR");
    std::fs::create_dir_all(&blobs).expect("dirs");
    let orphan = blobs.join("01ARZ3NDEKTSV4RRFFQ69G5FAV");
    std::fs::write(&orphan, b"orphan").expect("write");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
    std::fs::File::options()
        .write(true)
        .open(&orphan)
        .expect("open")
        .set_modified(old)
        .expect("mtime");

    let o = c.run(&["fsck"], "");
    assert_eq!(o.code, 1, "{}", o.stdout);
    assert!(
        o.stdout
            .contains("orphan   blob file 01ARZ3NDEKTSV4RRFFQ69G5FAV")
    );
    assert!(orphan.exists(), "report only");
    let o = c.run(&["fsck", "--repair"], "");
    assert_eq!(o.code, 0, "{}", o.stdout);
    assert!(!orphan.exists());
    assert_eq!(c.run(&["fsck", "--verify"], "").code, 0);
}

#[cfg(unix)]
#[test]
fn import_and_delete_with_transfer() {
    let c = Cli::new();
    c.ok(&["user", "add", "anna", "--admin"], &format!("{PW}\n"));
    c.ok(&["user", "add", "bob"], &format!("{PW}\n"));
    let src = c.dir.path().join("photos");
    std::fs::create_dir_all(src.join("2024")).expect("dirs");
    std::fs::write(src.join("2024/a.jpg"), "jpeg").expect("f");
    std::fs::write(src.join("b.part"), "x").expect("f");

    let out = c.ok(
        &[
            "import",
            src.to_str().expect("p"),
            "--user",
            "bob",
            "--dest",
            "Photos",
        ],
        "",
    );
    assert!(out.contains("imported 1 files"), "{out}");
    assert!(out.contains("skipped") && out.contains("b.part"), "{out}");
    let list = c.ok(&["user", "list", "--json"], "");
    assert!(list.contains("\"used_bytes\":4"), "{list}");
    assert!(
        c.ok(
            &[
                "import",
                src.to_str().expect("p"),
                "--user",
                "bob",
                "--dest",
                "Photos"
            ],
            ""
        )
        .contains("skipped 1 existing")
    );
    assert!(
        c.fail(&["import", "/nonexistent-dir", "--user", "bob"], "")
            .contains("import failed")
    );
    assert!(
        c.fail(&["import", src.to_str().expect("p"), "--user", "ghost"], "")
            .contains("not found")
    );

    c.ok(
        &["user", "delete", "bob", "--transfer-to", "anna", "--yes"],
        "",
    );
    let list = c.ok(&["user", "list", "--json"], "");
    assert!(
        list.contains("\"used_bytes\":4") && !list.contains("\"bob\""),
        "{list}"
    );
    let events = c.ok(&["audit", "export"], "");
    assert!(
        events.contains("admin.import") && events.contains("\"data\":\"transferred\""),
        "{events}"
    );
}

#[test]
fn reset_2fa_works_from_the_command_line() {
    let c = Cli::new();
    c.ok(&["user", "add", "anna"], &format!("{PW}\n"));
    let out = c.ok(&["user", "reset-2fa", "anna"], "");
    assert!(out.contains("had no two-factor authentication"), "{out}");
    assert!(
        c.fail(&["user", "reset-2fa", "nobody"], "")
            .contains("not found")
    );
    let events = c.ok(&["audit", "export"], "");
    assert!(events.contains("admin.2fa_reset"), "{events}");
}

#[test]
fn default_quota_and_upload_retention_come_from_the_configuration() {
    let c = Cli::new();
    // a bad value stops the command with a clear message
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_rostdav"));
    let o = cmd
        .args(["admin", "user", "list"])
        .env("ROSTDAV_STORAGE__DATA_DIR", c.dir.path().join("data"))
        .env("ROSTDAV_LIMITS__DEFAULT_QUOTA", "lots")
        .output()
        .expect("run");
    assert!(!o.status.success());
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("default_quota"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );

    // a valid value applies to users created afterwards
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_rostdav"))
        .args(["admin", "user", "add", "anna"])
        .env("ROSTDAV_STORAGE__DATA_DIR", c.dir.path().join("data"))
        .env("ROSTDAV_LIMITS__DEFAULT_QUOTA", "2G")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{PW}\n").as_bytes())
        .expect("write");
    assert!(child.wait_with_output().expect("wait").status.success());
    let out = c.ok(&["user", "list", "--json"], "");
    assert!(
        out.contains("\"quota_bytes\":2147483648") || out.contains("\"quota_bytes\": 2147483648"),
        "{out}"
    );
}

#[test]
fn backup_and_restore_through_the_command_line() {
    let c = Cli::new();
    c.ok(&["user", "add", "anna"], &format!("{PW}\n"));
    let src = c.dir.path().join("to-import");
    std::fs::create_dir_all(src.join("sub")).expect("dir");
    std::fs::write(src.join("a.txt"), "alpha").expect("file");
    std::fs::write(src.join("sub/b.bin"), vec![7u8; 100_000]).expect("file");
    c.ok(
        &["import", src.to_str().expect("utf8"), "--user", "anna"],
        "",
    );

    let dest = c.dir.path().join("backup");
    let out = c.ok(&["backup", dest.to_str().expect("utf8")], "");
    assert!(
        out.contains("backup written") && out.contains("2 blobs"),
        "{out}"
    );
    assert!(dest.join("db/rostdav.sqlite").exists() && dest.join("blobs").is_dir());
    assert!(!dest.join("totp.key").exists());
    // a second run into the same place is refused
    assert!(
        c.fail(&["backup", dest.to_str().expect("utf8")], "")
            .contains("already exists")
    );

    // restore: the backup directory becomes a data directory of a fresh installation
    let restored = Cli::new();
    let data = restored.dir.path().join("data");
    std::fs::create_dir_all(&data).expect("dir");
    for part in ["db", "blobs"] {
        copy_all(&dest.join(part), &data.join(part));
    }
    let out = restored.ok(&["fsck", "--verify"], "");
    assert!(
        out.to_lowercase().contains("no problems") || out.contains("clean") || out.contains("ok"),
        "{out}"
    );
    let list = restored.ok(&["user", "list"], "");
    assert!(list.contains("anna"), "{list}");
    let events = restored.ok(&["audit", "export"], "");
    assert!(
        events.contains("admin.backup") || events.contains("admin.import"),
        "{events}"
    );
}

fn copy_all(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).expect("dir");
    for e in std::fs::read_dir(from).expect("read_dir") {
        let e = e.expect("entry");
        let t = to.join(e.file_name());
        if e.file_type().expect("type").is_dir() {
            copy_all(&e.path(), &t);
        } else {
            std::fs::copy(e.path(), t).expect("copy");
        }
    }
}

#[test]
fn check_config_never_prints_the_two_factor_key() {
    let c = Cli::new();
    let key = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU="; // 32 bytes, base64
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_rostdav"))
        .arg("check-config")
        .env("ROSTDAV_STORAGE__DATA_DIR", c.dir.path().join("data"))
        .env("ROSTDAV_SECURITY__TOTP_KEY", key)
        .output()
        .expect("run");
    assert!(o.status.success());
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(!out.contains(key) && out.contains("<set>"), "{out}");
}

/// The container image sets its environment in the Dockerfile. Every `ROSTDAV_*` variable there
/// is read as configuration, and an unknown one stops the server at start (this happened once
/// with a variable that was meant for the updater). So: start the program with exactly that
/// environment.
#[test]
fn the_dockerfile_environment_is_valid_configuration() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Dockerfile"))
        .expect("Dockerfile");
    let mut vars: Vec<(String, String)> = Vec::new();
    let mut in_env = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("ENV ") {
            in_env = true;
        } else if !in_env {
            continue;
        }
        let l = l.trim_start_matches("ENV ").trim_end_matches('\\').trim();
        if let Some((k, v)) = l.split_once('=') {
            vars.push((k.trim().to_owned(), v.trim().to_owned()));
        }
        if !line.trim_end().ends_with('\\') {
            in_env = false;
        }
    }
    assert!(
        vars.iter().any(|(k, _)| k == "ROSTDAV_SERVER__LISTEN"),
        "the parser found the ENV block: {vars:?}"
    );
    let c = Cli::new();
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_rostdav"));
    cmd.arg("check-config").current_dir(c.dir.path());
    for (k, v) in &vars {
        cmd.env(k, v);
    }
    // /data does not exist here
    cmd.env("ROSTDAV_STORAGE__DATA_DIR", c.dir.path().join("data"));
    let o = cmd.output().expect("run");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

// ---- `rostdav admin` beside a running server: the admin socket (ADR 0010) ----------------------

/// A real `rostdav serve` on the data directory of `cli`; stopped when dropped.
struct Server {
    child: std::process::Child,
}

impl Server {
    fn start(cli: &Cli) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_rostdav"))
            .arg("serve")
            .env("ROSTDAV_STORAGE__DATA_DIR", cli.dir.path().join("data"))
            .env("ROSTDAV_SERVER__LISTEN", "127.0.0.1:0")
            .current_dir(cli.dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn server");
        Self { child }
    }

    /// Waits until the server has opened the database (the socket appears, or, for a server
    /// that gets none, the database file exists and a moment has passed).
    fn wait_ready(cli: &Cli, socket: bool) {
        let sock = cli.dir.path().join("data/admin.sock");
        let db = cli.dir.path().join("data/db/rostdav.sqlite");
        for _ in 0..100 {
            if (socket && sock.exists()) || (!socket && db.exists()) {
                std::thread::sleep(std::time::Duration::from_millis(700));
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("the server did not come up");
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

#[test]
fn admin_commands_work_while_the_server_runs() {
    let c = Cli::new();
    let _server = Server::start(&c);
    Server::wait_ready(&c, true);

    let o = c.run(&["user", "add", "anna", "--admin"], &format!("{PW}\n"));
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.contains("anna"), "{}", o.stdout);
    let o = c.run(&["user", "list", "--json"], "");
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.contains("\"anna\""), "{}", o.stdout);

    // a relative path is relative to where the command was typed, not to the server
    let o = c.run(&["backup", "mybackup"], "");
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(c.dir.path().join("mybackup/db/rostdav.sqlite").exists());

    // failures come back as the process would have printed them, with the same exit codes
    let o = c.run(&["user", "add", "bob"], "kurz\n");
    assert_eq!(o.code, 1, "{}", o.stdout);
    assert!(o.stderr.starts_with("Error:"), "{}", o.stderr);
    let o = c.run(&["user", "frobnicate"], "");
    assert_eq!(o.code, 2);
    assert!(o.stderr.contains("Usage"), "{}", o.stderr);
    let o = c.run(&["audit", "export"], "");
    assert_eq!(o.code, 0);
    assert!(o.stdout.contains("anna"), "{}", o.stdout);
    // the server is still there
    assert_eq!(c.run(&["user", "list"], "").code, 0);
}

#[test]
fn a_stale_socket_is_ignored_once_the_server_is_gone() {
    let c = Cli::new();
    let mut server = Server::start(&c);
    Server::wait_ready(&c, true);
    assert_eq!(c.run(&["user", "add", "anna"], &format!("{PW}\n")).code, 0);
    server.stop(); // killed: the socket file stays
    assert!(c.dir.path().join("data/admin.sock").exists());
    let o = c.run(&["user", "list"], "");
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.contains("anna"), "{}", o.stdout);
}

#[test]
fn the_socket_is_private_to_the_owner() {
    use std::os::unix::fs::PermissionsExt;
    let c = Cli::new();
    let _server = Server::start(&c);
    Server::wait_ready(&c, true);
    let mode = std::fs::metadata(c.dir.path().join("data/admin.sock"))
        .expect("socket")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let mode = std::fs::metadata(c.dir.path().join("data"))
        .expect("data")
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "the data directory is closed to others");
}

#[test]
fn a_server_without_a_socket_makes_the_command_say_what_to_do() {
    let c = Cli::new();
    let _server = Server::start(&c);
    Server::wait_ready(&c, true);
    // as if the server had been started without the socket
    std::fs::remove_file(c.dir.path().join("data/admin.sock")).expect("remove");
    let o = c.run(&["user", "list"], "");
    assert_eq!(o.code, 1);
    assert!(
        o.stderr.contains("in use by a running server"),
        "{}",
        o.stderr
    );
}

#[tokio::test]
async fn a_data_directory_open_to_others_gets_no_socket() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("dir");
    let mut cfg = rostdav::config::Config::default();
    cfg.storage.data_dir = dir.path().join("data");
    let state = rostdav::build_state(&cfg).await.expect("state");
    let data = &cfg.storage.data_dir;
    std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o750)).expect("chmod");
    let err = rostdav::admin_socket::serve(state.clone(), data)
        .await
        .expect_err("refused");
    assert!(
        err.to_string().contains("accessible by other users"),
        "{err}"
    );
    assert!(!data.join("admin.sock").exists());
    // closed again: it opens
    std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    rostdav::admin_socket::serve(state, data)
        .await
        .expect("serve");
    assert!(data.join("admin.sock").exists());
}

#[tokio::test]
async fn the_socket_refuses_garbage_and_oversized_requests() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().expect("dir");
    let mut cfg = rostdav::config::Config::default();
    cfg.storage.data_dir = dir.path().join("data");
    let state = rostdav::build_state(&cfg).await.expect("state");
    rostdav::admin_socket::serve(state, &cfg.storage.data_dir)
        .await
        .expect("serve");
    let sock = rostdav::admin_socket::path_for(&cfg.storage.data_dir);
    let ask = |body: Vec<u8>| {
        let sock = sock.clone();
        async move {
            let mut c = tokio::net::UnixStream::connect(sock)
                .await
                .expect("connect");
            let _ = c.write_all(&body).await;
            let _ = c.shutdown().await;
            let mut out = String::new();
            // a server that stops reading may reset the connection instead of answering
            let _ = c.read_to_string(&mut out).await;
            out
        }
    };
    assert!(ask(b"not json".to_vec()).await.contains("not valid"));
    assert!(
        ask(br#"{"v":99,"args":[],"stdin":""}"#.to_vec())
            .await
            .contains("another version")
    );
    let big = ask(vec![b' '; 2 << 20]).await;
    assert!(big.is_empty() || big.contains("too large"), "{big}");
    // and an honest request still works afterwards
    let r = rostdav::admin_socket::call(&sock, &["user".into(), "list".into()], "", None)
        .await
        .expect("call");
    assert_eq!(r.code, 0, "{}", r.stderr);
}
