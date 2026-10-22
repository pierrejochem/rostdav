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
