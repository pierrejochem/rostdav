//! `rostdav admin …`: the command line for administration.
//!
//! Output goes to the writer passed in, so the commands can be tested. Secrets
//! are read from stdin, never from arguments.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::{Args, Subcommand};
use rostdav_app::{Actor, AppState, DeleteMode, FsckOptions, ImportOptions};
use rostdav_core::time::rfc3339;

#[derive(Subcommand)]
pub enum AdminCommand {
    /// User management.
    #[command(subcommand)]
    User(UserCommand),
    /// Checks database and blob storage for inconsistencies. Exit code 1 if damage remains.
    Fsck(FsckArgs),
    /// Copies a directory from this host into a user's files.
    Import(ImportArgs),
    /// Writes a consistent copy of the database and the blobs into a new directory
    /// (the server may keep running). Restore: see docs/deployment.md.
    Backup(BackupArgs),
    /// Event log.
    #[command(subcommand)]
    Audit(AuditCommand),
}

#[derive(Subcommand)]
pub enum UserCommand {
    /// Creates a user. The password is read as one line from stdin
    /// (never as an argument, so it does not end up in process lists or shell history).
    Add {
        name: String,
        /// The user is granted administrator rights.
        #[arg(long)]
        admin: bool,
    },
    /// Lists users with role, state, quota and usage.
    List {
        /// One JSON object per line.
        #[arg(long)]
        json: bool,
    },
    /// Blocks every sign-in of the user (devices are kept).
    Disable { name: String },
    /// Allows the user to sign in again.
    Enable { name: String },
    /// Removes the two-factor secret and recovery codes of a user who is locked out and
    /// ends their browser sessions. The user can set it up again.
    #[command(name = "reset-2fa")]
    Reset2fa { name: String },
    /// Makes the user an administrator or a normal user.
    Role {
        name: String,
        #[arg(value_enum)]
        role: Role,
    },
    /// Sets the quota: `10G`, `500M`, `1024` (bytes) or `unlimited`.
    SetQuota { name: String, quota: String },
    /// Sets a new password, read as one line from stdin.
    SetPassword {
        name: String,
        /// Also sign out all devices (revoke their app passwords).
        #[arg(long)]
        revoke_devices: bool,
    },
    /// Deletes a user. Requires `--yes`.
    Delete {
        name: String,
        /// Move the files into a folder of this user instead of deleting them.
        #[arg(long)]
        transfer_to: Option<String>,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Role {
    Admin,
    User,
}

#[derive(Args)]
pub struct BackupArgs {
    /// New directory for the backup (it must not exist yet).
    pub dest: PathBuf,
    /// Also copy the two-factor key file (keep such a backup away from the database copy).
    #[arg(long)]
    pub include_key: bool,
}

#[derive(Args)]
pub struct FsckArgs {
    /// Delete orphan files and fix usage counters. Without it nothing is changed.
    #[arg(long)]
    pub repair: bool,
    /// Read every blob and compare size and checksum (slow).
    #[arg(long)]
    pub verify: bool,
    /// Ignore unreferenced blob files younger than this many seconds (uploads in flight).
    #[arg(long, default_value_t = 3600)]
    pub min_orphan_age: i64,
}

#[derive(Args)]
pub struct ImportArgs {
    pub path: PathBuf,
    #[arg(long)]
    pub user: String,
    /// Folder below the user's root, created if missing.
    #[arg(long)]
    pub dest: Option<String>,
    /// Replace files that already exist (default: skip them).
    #[arg(long)]
    pub overwrite: bool,
}

#[derive(Subcommand)]
pub enum AuditCommand {
    /// Prints events as JSON Lines.
    Export {
        /// `2026-01-31`, `2026-01-31T12:00:00Z` or unix seconds.
        #[arg(long)]
        since: Option<String>,
    },
}

/// The words after `rostdav admin`, as the server parses them when they come over the socket.
#[derive(clap::Parser)]
#[command(name = "rostdav admin", no_binary_name = true)]
struct AdminLine {
    #[command(subcommand)]
    cmd: AdminCommand,
}

/// What a command printed, and its exit code.
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Parses and runs a command given as words (not as a process). Relative paths in the arguments
/// are taken relative to `cwd`, the directory of whoever sent the command.
pub async fn execute(
    state: &AppState,
    args: &[String],
    stdin: &mut (dyn BufRead + Send),
    cwd: Option<&std::path::Path>,
) -> Output {
    use clap::Parser;
    let mut cmd = match AdminLine::try_parse_from(args) {
        Ok(l) => l.cmd,
        Err(e) => {
            let text = e.to_string();
            let code = e.exit_code();
            return if e.use_stderr() {
                Output {
                    code,
                    stdout: String::new(),
                    stderr: text,
                }
            } else {
                Output {
                    code,
                    stdout: text,
                    stderr: String::new(),
                }
            };
        }
    };
    if let Some(cwd) = cwd {
        let absolute = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = cwd.join(&*p);
            }
        };
        match &mut cmd {
            AdminCommand::Import(a) => absolute(&mut a.path),
            AdminCommand::Backup(a) => absolute(&mut a.dest),
            _ => {}
        }
    }
    let mut out = Vec::new();
    let result = run(state, cmd, stdin, &mut out).await;
    let stdout = String::from_utf8_lossy(&out).into_owned();
    match result {
        Ok(code) => Output {
            code,
            stdout,
            stderr: String::new(),
        },
        // the same text a failing process prints
        Err(e) => Output {
            code: 1,
            stdout,
            stderr: format!("Error: {e:?}\n"),
        },
    }
}

/// Runs a command; returns the process exit code.
pub async fn run(
    state: &AppState,
    cmd: AdminCommand,
    stdin: &mut (dyn BufRead + Send),
    out: &mut (dyn Write + Send),
) -> anyhow::Result<i32> {
    let actor = Actor::Cli;
    match cmd {
        AdminCommand::User(u) => user(state, &actor, u, stdin, out).await?,
        AdminCommand::Fsck(a) => return fsck(state, &actor, &a, out).await,
        AdminCommand::Import(a) => import(state, &actor, a, out).await?,
        AdminCommand::Backup(a) => {
            let r = state
                .backup(&actor, &a.dest, a.include_key)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            writeln!(
                out,
                "backup written to {}: {} blobs, {} bytes ({} hard-linked, {} copied)",
                a.dest.display(),
                r.blobs,
                r.bytes,
                r.blobs - r.copied,
                r.copied
            )?;
        }
        AdminCommand::Audit(AuditCommand::Export { since }) => {
            let since = since
                .as_deref()
                .map(rostdav_core::time::parse_since)
                .transpose()
                .map_err(|e| anyhow::anyhow!(e))?
                .unwrap_or(0);
            for e in state.audit_events(&actor, since).await? {
                writeln!(out, "{}", event_line(&e))?;
            }
        }
    }
    Ok(0)
}

fn read_password(stdin: &mut (dyn BufRead + Send)) -> anyhow::Result<String> {
    let mut line = String::new();
    stdin
        .read_line(&mut line)
        .context("could not read password from stdin")?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

async fn user(
    state: &AppState,
    actor: &Actor<'_>,
    cmd: UserCommand,
    stdin: &mut (dyn BufRead + Send),
    out: &mut (dyn Write + Send),
) -> anyhow::Result<()> {
    match cmd {
        UserCommand::Add { name, admin } => {
            let password = read_password(stdin)?;
            let u = state
                .create_user_as(actor, &name, &password, admin)
                .await
                .map_err(|e| anyhow::anyhow!("user not created: {e}"))?;
            writeln!(out, "user {} created", u.name)?;
        }
        UserCommand::List { json } => {
            let users = state.users_list(actor).await?;
            if json {
                for u in users {
                    writeln!(
                        out,
                        "{}",
                        serde_json::json!({
                            "name": u.name, "admin": u.is_admin, "disabled": u.disabled,
                            "quota_bytes": u.quota_bytes, "used_bytes": u.used_bytes,
                            "devices": u.devices, "created": rfc3339(u.created_at),
                        })
                    )?;
                }
            } else {
                writeln!(
                    out,
                    "{:<24} {:<6} {:<9} {:>10} {:>10} {:>7}",
                    "NAME", "ROLE", "STATE", "USED", "QUOTA", "DEVICES"
                )?;
                for u in users {
                    writeln!(
                        out,
                        "{:<24} {:<6} {:<9} {:>10} {:>10} {:>7}",
                        u.name,
                        if u.is_admin { "admin" } else { "user" },
                        if u.disabled { "disabled" } else { "active" },
                        format_size(u.used_bytes),
                        u.quota_bytes
                            .map_or_else(|| "unlimited".to_owned(), format_size),
                        u.devices,
                    )?;
                }
            }
        }
        UserCommand::Disable { name } => {
            state
                .user_set_disabled(actor, &name, true)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            writeln!(out, "user {name} disabled")?;
        }
        UserCommand::Reset2fa { name } => {
            let was = state
                .user_reset_two_factor(actor, &name)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            writeln!(
                out,
                "{}",
                if was {
                    format!("two-factor authentication of {name} removed; browser sessions ended")
                } else {
                    format!("{name} had no two-factor authentication; browser sessions ended")
                }
            )?;
        }
        UserCommand::Enable { name } => {
            state
                .user_set_disabled(actor, &name, false)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            writeln!(out, "user {name} enabled")?;
        }
        UserCommand::Role { name, role } => {
            let admin = matches!(role, Role::Admin);
            state
                .user_set_admin(actor, &name, admin)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            writeln!(
                out,
                "user {name} is now {}",
                if admin {
                    "an administrator"
                } else {
                    "a normal user"
                }
            )?;
        }
        UserCommand::SetQuota { name, quota } => {
            let q = parse_quota(&quota)?;
            state
                .user_set_quota(actor, &name, q)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            writeln!(
                out,
                "quota of {name}: {}",
                q.map_or_else(|| "unlimited".to_owned(), format_size)
            )?;
        }
        UserCommand::SetPassword {
            name,
            revoke_devices,
        } => {
            let password = read_password(stdin)?;
            state
                .user_set_password(actor, &name, &password, revoke_devices)
                .await
                .map_err(|e| anyhow::anyhow!("password not changed: {e}"))?;
            writeln!(out, "password of {name} changed")?;
        }
        UserCommand::Delete {
            name,
            transfer_to,
            yes,
        } => {
            if !yes {
                bail!(
                    "refusing to delete {name} without --yes (this removes the account and, unless --transfer-to is given, all files)"
                );
            }
            let mode = transfer_to.map_or(DeleteMode::DeleteData, DeleteMode::TransferTo);
            state
                .user_delete(actor, &name, &mode)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            writeln!(out, "user {name} deleted")?;
        }
    }
    Ok(())
}

async fn fsck(
    state: &AppState,
    actor: &Actor<'_>,
    a: &FsckArgs,
    out: &mut (dyn Write + Send),
) -> anyhow::Result<i32> {
    let r = state
        .fsck(
            actor,
            FsckOptions {
                repair: a.repair,
                verify_checksums: a.verify,
                min_orphan_age_secs: a.min_orphan_age,
            },
        )
        .await?;
    let verb = if a.repair { "removed/fixed" } else { "found" };
    writeln!(out, "blobs checked: {}", r.blobs_checked)?;
    for (id, examples) in &r.missing_blobs {
        writeln!(
            out,
            "DAMAGE   blob {id} is missing on disk (used by: {})",
            examples.join(", ")
        )?;
    }
    for id in &r.corrupt_blobs {
        writeln!(
            out,
            "DAMAGE   blob {id} differs from its recorded size or checksum"
        )?;
    }
    for p in &r.database_problems {
        writeln!(out, "DAMAGE   database: {p}")?;
    }
    for p in &r.orphan_rows {
        writeln!(out, "DAMAGE   database: {p}")?;
    }
    for id in &r.orphan_blobs {
        writeln!(out, "orphan   blob file {id} {verb}")?;
    }
    for m in &r.usage_mismatches {
        writeln!(
            out,
            "usage    {}: stored {} but files add up to {} ({verb})",
            m.user, m.stored, m.actual
        )?;
    }
    for d in &r.orphan_session_dirs {
        writeln!(out, "orphan   upload directory {d} {verb}")?;
    }
    for t in &r.sessions_without_dir {
        writeln!(out, "orphan   upload session {t} without data {verb}")?;
    }
    if r.is_clean() {
        writeln!(out, "ok")?;
        Ok(0)
    } else {
        writeln!(
            out,
            "problems remain{}",
            if a.repair {
                ""
            } else {
                " (run with --repair to fix what can be fixed)"
            }
        )?;
        Ok(1)
    }
}

async fn import(
    state: &AppState,
    actor: &Actor<'_>,
    a: ImportArgs,
    out: &mut (dyn Write + Send),
) -> anyhow::Result<()> {
    let r = state
        .import_tree(
            &actor.clone(),
            &a.path,
            &a.user,
            &ImportOptions {
                overwrite: a.overwrite,
                dest: a.dest,
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("import failed: {e}"))?;
    writeln!(
        out,
        "imported {} files ({}), created {} folders, skipped {} existing",
        r.files,
        format_size(i64::try_from(r.bytes).unwrap_or(i64::MAX)),
        r.dirs,
        r.skipped_existing
    )?;
    for (path, why) in &r.skipped {
        writeln!(out, "skipped  {path}: {why}")?;
    }
    if r.skipped_total as usize > r.skipped.len() {
        writeln!(
            out,
            "... and {} more skipped",
            r.skipped_total as usize - r.skipped.len()
        )?;
    }
    Ok(())
}

// ---- helpers ------------------------------------------------------------------

/// `10G`, `1.5T`, `500M`, `2048`, `unlimited` / `none`.
pub fn parse_quota(s: &str) -> anyhow::Result<Option<i64>> {
    Ok(rostdav_app::parse_quota(s)?)
}

pub fn format_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// One JSON object per event; `details` stays an object.
pub fn event_line(e: &rostdav_meta::Event) -> String {
    let details: serde_json::Value =
        serde_json::from_str(&e.details).unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "id": e.id, "ts": e.ts, "time": rfc3339(e.ts), "actor": e.actor,
        "action": e.action, "target": e.target, "ip": e.ip, "details": details,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_parsing() {
        assert_eq!(parse_quota("unlimited").expect("q"), None);
        assert_eq!(parse_quota("NONE").expect("q"), None);
        assert_eq!(parse_quota("1024").expect("q"), Some(1024));
        assert_eq!(
            parse_quota("10G").expect("q"),
            Some(10 * 1024 * 1024 * 1024)
        );
        assert_eq!(parse_quota("1.5m").expect("q"), Some(1_572_864));
        assert_eq!(parse_quota("0").expect("q"), Some(0));
        for bad in ["", "abc", "-5", "10X", "1e30T", "NaN"] {
            assert!(parse_quota(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn size_formatting() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1536), "1.5 KiB");
        assert_eq!(format_size(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }

    #[test]
    fn event_lines_are_json_with_object_details() {
        let e = rostdav_meta::Event {
            id: 3,
            ts: 1_700_000_000,
            actor: "cli".into(),
            action: "admin.user_created".into(),
            target: "anna".into(),
            ip: String::new(),
            details: "{\"admin\":true}".into(),
        };
        let v: serde_json::Value = serde_json::from_str(&event_line(&e)).expect("json");
        assert_eq!(v["details"]["admin"], true);
        assert_eq!(v["time"], "2023-11-14T22:13:20Z");
        assert_eq!(v["action"], "admin.user_created");
    }
}
