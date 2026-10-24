//! Administration: users, event export, consistency check, import.
//!
//! Every function takes an [`Actor`]. The CLI is trusted (local access to the
//! data directory); a web user must be an administrator. Every change is
//! recorded in the event log.

use std::path::{Path, PathBuf};

use rostdav_core::{Error, LogicalPath, Name, Result};
use rostdav_meta::{Event, NewUser, UsageMismatch, User, UserSummary};
use rostdav_storage::BlobId;
use serde_json::json;

use crate::auth::{Principal, Via};
use crate::{AppState, files::PutOptions, hash_password};

/// Who performs an administrative operation.
#[derive(Clone, Copy)]
pub enum Actor<'a> {
    /// The local command line.
    Cli,
    /// A signed-in user; must be an administrator.
    User(&'a Principal),
}

impl Actor<'_> {
    pub(crate) fn name(&self) -> String {
        match self {
            Actor::Cli => "cli".into(),
            Actor::User(p) => p.name.clone(),
        }
    }

    pub(crate) fn require_admin(&self) -> Result<()> {
        match self {
            Actor::Cli => Ok(()),
            Actor::User(p) if p.is_admin => Ok(()),
            Actor::User(_) => Err(Error::Forbidden),
        }
    }

    fn is_user(&self, id: i64) -> bool {
        matches!(self, Actor::User(p) if p.user_id == id)
    }
}

/// What a lockout counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockoutKind {
    /// Failed password checks.
    Password,
    /// Wrong two-factor codes.
    SecondFactor,
}

/// A client address or user that is blocked for now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lockout {
    pub key: String,
    pub by_address: bool,
    pub who: String,
    pub kind: LockoutKind,
    pub secs_left: u64,
}

/// `10G`, `1.5T`, `500M`, `2048`, `unlimited` / `none` (no quota).
pub fn parse_quota(s: &str) -> Result<Option<i64>> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("unlimited") || s.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    let (num, mult) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            let m: f64 = match c.to_ascii_uppercase() {
                'K' => 1024.0,
                'M' => 1024.0 * 1024.0,
                'G' => 1024.0 * 1024.0 * 1024.0,
                'T' => 1024.0 * 1024.0 * 1024.0 * 1024.0,
                'B' => 1.0,
                _ => return Err(Error::BadRequest("unknown size unit (use K, M, G, T)")),
            };
            (&s[..s.len() - 1], m)
        }
        _ => (s, 1.0),
    };
    let n: f64 = num
        .trim()
        .parse()
        .map_err(|_| Error::BadRequest("not a size"))?;
    if !n.is_finite() || n < 0.0 {
        return Err(Error::BadRequest("a quota must not be negative"));
    }
    let bytes = n * mult;
    if bytes > 9.0e18 {
        return Err(Error::BadRequest("quota too large"));
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok(Some(bytes as i64))
}

/// What a backup contains.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BackupReport {
    pub blobs: u64,
    pub bytes: u64,
    /// Blobs that had to be copied because a hard link was not possible (other file system).
    pub copied: u64,
}

/// What happens to a deleted user's files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeleteMode {
    DeleteData,
    /// Move everything into a folder in this user's root.
    TransferTo(String),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FsckOptions {
    /// Remove orphans and correct usage counters.
    pub repair: bool,
    /// Re-read every blob and compare size and checksum.
    pub verify_checksums: bool,
    /// Unreferenced blob files younger than this are left alone (uploads in flight).
    pub min_orphan_age_secs: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsckReport {
    pub blobs_checked: usize,
    /// Registered blobs whose file is gone: `(blob id, "user:file" examples)`. Not repairable.
    pub missing_blobs: Vec<(String, Vec<String>)>,
    /// Registered blobs whose content differs from the recorded size/checksum.
    pub corrupt_blobs: Vec<String>,
    /// Files in `blobs/` without a database row (older than the minimum age).
    pub orphan_blobs: Vec<String>,
    pub usage_mismatches: Vec<UsageMismatch>,
    /// Upload directories without a database row.
    pub orphan_session_dirs: Vec<String>,
    /// Upload sessions whose directory is gone.
    pub sessions_without_dir: Vec<String>,
    /// Problems the database reports about itself (`integrity_check`). Not repairable.
    pub database_problems: Vec<String>,
    /// Rows whose parent row is gone (`foreign_key_check`). Not repairable.
    pub orphan_rows: Vec<String>,
    pub repaired: bool,
}

impl FsckReport {
    /// No inconsistency was found (or all found ones are repaired).
    pub fn is_clean(&self) -> bool {
        self.missing_blobs.is_empty()
            && self.corrupt_blobs.is_empty()
            && self.database_problems.is_empty()
            && self.orphan_rows.is_empty()
            && (self.repaired
                || (self.orphan_blobs.is_empty()
                    && self.usage_mismatches.is_empty()
                    && self.orphan_session_dirs.is_empty()
                    && self.sessions_without_dir.is_empty()))
    }
}

#[derive(Clone, Debug, Default)]
pub struct ImportOptions {
    /// Replace files that already exist; default is to skip them.
    pub overwrite: bool,
    /// Folder below the user's root, e.g. `Import/Photos`; created if missing.
    pub dest: Option<String>,
    /// For files that exist already: replace them when size or modification time differ
    /// (the old content becomes a version), and leave identical ones alone.
    pub update: bool,
    /// Count what would be imported; write nothing.
    pub dry_run: bool,
    /// Nextcloud data directory import (ADR 0011): the user's `files_versions` folder. Versions
    /// (`<file>.v<unix time>`) of files that are new here are imported as versions; files whose
    /// content Nextcloud encrypted are skipped.
    pub nextcloud_versions: Option<PathBuf>,
    pub nextcloud: bool,
}

/// The result of [`AppState::import_nextcloud`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NextcloudReport {
    /// `(Nextcloud user, Rostdav user, what was imported)`.
    pub users: Vec<(String, String, ImportReport)>,
    /// `(Nextcloud folder, why it was not imported)`.
    pub skipped_users: Vec<(String, String)>,
    /// Things that exist in the data directory and are not imported.
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub skipped_existing: u64,
    /// Files replaced because they changed (`update`).
    pub updated: u64,
    /// Versions imported from a Nextcloud `files_versions` folder.
    pub versions: u64,
    /// `(path, reason)`, at most 50 entries; `skipped_total` has the real number.
    pub skipped: Vec<(String, String)>,
    pub skipped_total: u64,
}

impl AppState {
    pub(crate) async fn target_user(&self, name: &str) -> Result<User> {
        self.inner.db.find_user(name).await?.ok_or(Error::NotFound)
    }

    // ---- users --------------------------------------------------------------

    /// Creates a user (admin CLI). The password is hashed here.
    pub async fn add_user(&self, name: &str, password: &str, is_admin: bool) -> Result<User> {
        self.create_user_as(&Actor::Cli, name, password, is_admin)
            .await
    }

    pub async fn create_user_as(
        &self,
        actor: &Actor<'_>,
        name: &str,
        password: &str,
        is_admin: bool,
    ) -> Result<User> {
        actor.require_admin()?;
        let password_hash = hash_password(password)?;
        let u = self
            .inner
            .db
            .create_user(NewUser {
                name,
                password_hash: &password_hash,
                is_admin,
            })
            .await?;
        if let Some(q) = self.cfg().limits.default_quota {
            self.inner.db.set_quota(u.id, Some(q)).await?;
        }
        self.audit(
            &actor.name(),
            "admin.user_created",
            &u.name,
            None,
            json!({"admin": is_admin}),
        )
        .await;
        Ok(u)
    }

    pub async fn users_list(&self, actor: &Actor<'_>) -> Result<Vec<UserSummary>> {
        actor.require_admin()?;
        self.inner.db.list_users().await
    }

    pub async fn user_set_disabled(
        &self,
        actor: &Actor<'_>,
        name: &str,
        disabled: bool,
    ) -> Result<()> {
        actor.require_admin()?;
        let u = self.target_user(name).await?;
        if disabled {
            if actor.is_user(u.id) {
                return Err(Error::Conflict("you cannot disable yourself"));
            }
            if u.is_admin && self.inner.db.count_enabled_admins_except(u.id).await? == 0 {
                return Err(Error::Conflict("the last administrator cannot be disabled"));
            }
        }
        self.inner.db.set_user_disabled(u.id, disabled).await?;
        let action = if disabled {
            "admin.user_disabled"
        } else {
            "admin.user_enabled"
        };
        self.audit(&actor.name(), action, &u.name, None, json!({}))
            .await;
        Ok(())
    }

    /// Whether the server is in maintenance mode.
    pub fn maintenance(&self) -> bool {
        self.inner
            .maintenance
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub async fn set_maintenance(&self, actor: &Actor<'_>, on: bool) -> Result<()> {
        actor.require_admin()?;
        self.inner
            .db
            .set_setting("maintenance", if on { b"1" } else { b"0" })
            .await?;
        self.inner
            .maintenance
            .store(on, std::sync::atomic::Ordering::Relaxed);
        let action = if on {
            "admin.maintenance_on"
        } else {
            "admin.maintenance_off"
        };
        self.audit(&actor.name(), action, "", None, json!({})).await;
        Ok(())
    }

    /// Sign-in blocks in force: `(who, seconds left)`. `who` is a client address or a user name.
    pub async fn active_lockouts(&self, actor: &Actor<'_>) -> Result<Vec<Lockout>> {
        actor.require_admin()?;
        let mut out = Vec::new();
        let names: std::collections::HashMap<String, String> = self
            .inner
            .db
            .list_users()
            .await?
            .into_iter()
            .map(|u| (u.id.to_string(), u.name))
            .collect();
        for (list, kind) in [
            (self.inner.limiter.blocked(), LockoutKind::Password),
            (self.inner.totp_limiter.blocked(), LockoutKind::SecondFactor),
        ] {
            for (key, secs_left) in list {
                if let Some((scope, who)) = key.split_once(':') {
                    out.push(Lockout {
                        key: key.clone(),
                        by_address: scope == "ip",
                        // Second-factor keys hold the user ID, password keys the user name.
                        who: match names.get(who) {
                            Some(name) if scope == "totp" => name.clone(),
                            _ => who.to_owned(),
                        },
                        kind,
                        secs_left,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Lifts one block (`key` and `kind` as listed by [`active_lockouts`](Self::active_lockouts)).
    pub async fn unlock(&self, actor: &Actor<'_>, key: &str, kind: LockoutKind) -> Result<()> {
        actor.require_admin()?;
        match kind {
            LockoutKind::Password => self.inner.limiter.clear(key),
            LockoutKind::SecondFactor => self.inner.totp_limiter.clear(key),
        }
        self.audit(&actor.name(), "admin.unlocked", key, None, json!({}))
            .await;
        Ok(())
    }

    pub async fn user_set_admin(&self, actor: &Actor<'_>, name: &str, admin: bool) -> Result<()> {
        actor.require_admin()?;
        let u = self.target_user(name).await?;
        if !admin && u.is_admin && self.inner.db.count_enabled_admins_except(u.id).await? == 0 {
            return Err(Error::Conflict(
                "the last administrator role cannot be removed",
            ));
        }
        self.inner.db.set_user_admin(u.id, admin).await?;
        self.audit(
            &actor.name(),
            "admin.user_role_changed",
            &u.name,
            None,
            json!({"admin": admin}),
        )
        .await;
        Ok(())
    }

    /// Sets or clears a user's quota.
    pub async fn set_quota(&self, user: &str, quota_bytes: Option<i64>) -> Result<()> {
        self.user_set_quota(&Actor::Cli, user, quota_bytes).await
    }

    pub async fn user_set_quota(
        &self,
        actor: &Actor<'_>,
        name: &str,
        quota_bytes: Option<i64>,
    ) -> Result<()> {
        actor.require_admin()?;
        let u = self.target_user(name).await?;
        if quota_bytes.is_some_and(|q| q < 0) {
            return Err(Error::BadRequest("quota must not be negative"));
        }
        self.inner.db.set_quota(u.id, quota_bytes).await?;
        self.audit(
            &actor.name(),
            "admin.user_quota_set",
            &u.name,
            None,
            json!({"quota_bytes": quota_bytes}),
        )
        .await;
        Ok(())
    }

    /// Sets a new password. With `revoke_devices` all app passwords are removed too.
    pub async fn user_set_password(
        &self,
        actor: &Actor<'_>,
        name: &str,
        password: &str,
        revoke_devices: bool,
    ) -> Result<()> {
        actor.require_admin()?;
        let u = self.target_user(name).await?;
        let hash = hash_password(password)?;
        self.inner.db.set_password_hash(u.id, &hash).await?;
        let revoked = if revoke_devices {
            self.inner.db.revoke_all_app_passwords(u.id).await?
        } else {
            0
        };
        self.audit(
            &actor.name(),
            "admin.user_password_reset",
            &u.name,
            None,
            json!({"devices_revoked": revoked}),
        )
        .await;
        Ok(())
    }

    pub async fn user_delete(
        &self,
        actor: &Actor<'_>,
        name: &str,
        mode: &DeleteMode,
    ) -> Result<()> {
        actor.require_admin()?;
        let u = self.target_user(name).await?;
        if actor.is_user(u.id) {
            return Err(Error::Conflict("you cannot delete yourself"));
        }
        if u.is_admin && self.inner.db.count_enabled_admins_except(u.id).await? == 0 {
            return Err(Error::Conflict("the last administrator cannot be deleted"));
        }
        let mut transferred_to = None;
        if let DeleteMode::TransferTo(to) = mode {
            let target = self.target_user(to).await?;
            if target.id == u.id {
                return Err(Error::Conflict("cannot transfer data to the deleted user"));
            }
            if target.disabled {
                return Err(Error::Conflict("the receiving user is disabled"));
            }
            let folder = self
                .inner
                .db
                .transfer_tree(u.id, target.id, &format!("{} (transferred)", u.name))
                .await?;
            transferred_to = Some((target.name, folder));
        }
        // chunk directories of open uploads are not covered by the database cascade
        for s in self
            .inner
            .db
            .all_upload_sessions()
            .await?
            .into_iter()
            .filter(|s| s.user_id == u.id)
        {
            self.inner
                .store
                .remove_session(&BlobId::parse(&s.dir)?)
                .await?;
        }
        self.inner.db.delete_user(u.id).await?;
        let details = match &transferred_to {
            Some((to, folder)) => json!({"data": "transferred", "to": to, "folder": folder}),
            None => json!({"data": "deleted"}),
        };
        self.audit(&actor.name(), "admin.user_deleted", &u.name, None, details)
            .await;
        self.collect_garbage().await?;
        Ok(())
    }

    /// The effective operating settings, for the administration page (read-only).
    pub fn settings_summary(&self, actor: &Actor<'_>) -> Result<Vec<(&'static str, String)>> {
        actor.require_admin()?;
        let c = self.cfg();
        let on = |b: bool| if b { "on" } else { "off" }.to_owned();
        Ok(vec![
            (
                "Maximum upload size",
                format!("{} bytes", c.limits.max_upload_bytes),
            ),
            (
                "Maximum chunk size",
                format!("{} bytes", c.limits.max_chunk_bytes),
            ),
            ("Versioning", on(c.versioning.enabled)),
            ("Trash", on(c.trash.enabled)),
            ("Anonymise addresses in event log", on(c.audit.anonymize_ip)),
            (
                "Browser session idle timeout",
                format!("{} hours", c.web.idle_secs / 3600),
            ),
            (
                "Browser session maximum age",
                format!("{} days", c.web.max_secs / 86_400),
            ),
        ])
    }

    // ---- backup ----------------------------------------------------------------------

    /// Copies the database and the blobs into the new directory `dest` while the server
    /// runs (ADR 0002: blobs are immutable and the database never points at an incomplete
    /// blob, so "database first, then blobs" is consistent). Blobs are hard-linked when
    /// `dest` is on the same file system (no extra space), otherwise copied. The two-factor
    /// key file is only included on request, because a backup next to the database would
    /// undo what keeping the key outside of it is for.
    pub async fn backup(
        &self,
        actor: &Actor<'_>,
        dest: &std::path::Path,
        include_key: bool,
    ) -> Result<BackupReport> {
        actor.require_admin()?;
        if dest.exists() {
            return Err(Error::Conflict("the backup target already exists"));
        }
        let root = self.inner.store.root().to_path_buf();
        let io = |e: std::io::Error| Error::internal(e);
        tokio::fs::create_dir_all(dest.join("db"))
            .await
            .map_err(io)?;
        // 1. database (a snapshot that is consistent in itself)
        self.inner
            .db
            .backup_to(&dest.join("db").join("rostdav.sqlite"))
            .await?;
        // 2. blobs, afterwards: every blob the snapshot refers to exists by now
        let src = root.join("blobs");
        let dst = dest.join("blobs");
        let report = tokio::task::spawn_blocking(move || copy_blobs(&src, &dst))
            .await
            .map_err(Error::internal)?
            .map_err(io)?;
        if include_key {
            let key = root.join("totp.key");
            if key.exists() {
                tokio::fs::copy(&key, dest.join("totp.key"))
                    .await
                    .map_err(io)?;
            }
        }
        self.audit(
            &actor.name(),
            "admin.backup",
            "",
            None,
            json!({"blobs": report.blobs, "bytes": report.bytes, "copied": report.copied, "key": include_key}),
        )
        .await;
        Ok(report)
    }

    // ---- event log ------------------------------------------------------------

    pub async fn audit_events(&self, actor: &Actor<'_>, since: i64) -> Result<Vec<Event>> {
        actor.require_admin()?;
        self.events_since(since).await
    }

    // ---- consistency check ------------------------------------------------------

    pub async fn fsck(&self, actor: &Actor<'_>, opts: FsckOptions) -> Result<FsckReport> {
        actor.require_admin()?;
        let db = &self.inner.db;
        let store = &self.inner.store;
        let mut report = FsckReport {
            repaired: opts.repair,
            ..FsckReport::default()
        };

        // registered blobs must exist, be as big as recorded and (optionally) intact
        let registered = db.all_blobs().await?;
        report.blobs_checked = registered.len();
        let mut known = std::collections::HashSet::new();
        for (id, size, checksum) in &registered {
            known.insert(id.clone());
            let blob = BlobId::parse(id)?;
            if opts.verify_checksums {
                match store.verify_blob(&blob).await? {
                    None => report
                        .missing_blobs
                        .push((id.clone(), self.damage_examples(id).await?)),
                    Some((disk_size, disk_sum)) => {
                        if i64::try_from(disk_size).ok() != Some(*size) || &disk_sum != checksum {
                            report.corrupt_blobs.push(id.clone());
                        }
                    }
                }
            } else if store.blob_modified(&blob).await?.is_none() {
                report
                    .missing_blobs
                    .push((id.clone(), self.damage_examples(id).await?));
            }
        }

        // files without a row: leftovers of crashes (young ones may be uploads in flight)
        let cutoff = crate::now_secs() - opts.min_orphan_age_secs;
        for blob in store.list_blobs().await? {
            if known.contains(blob.as_str()) {
                continue;
            }
            if store
                .blob_modified(&blob)
                .await?
                .is_some_and(|m| m <= cutoff)
            {
                if opts.repair {
                    store.delete_blob(&blob).await?;
                }
                report.orphan_blobs.push(blob.to_string());
            }
        }

        report.database_problems = db.integrity_problems().await?;
        report.orphan_rows = db.foreign_key_violations().await?;
        report.usage_mismatches = db.usage_mismatches().await?;
        if opts.repair {
            for m in &report.usage_mismatches {
                db.set_used_bytes(m.user_id, m.actual).await?;
            }
        }

        // upload sessions: rows and directories must match
        let sessions = db.all_upload_sessions().await?;
        let dirs = store.list_session_dirs().await?;
        for d in &dirs {
            if !sessions.iter().any(|s| s.dir == d.as_str()) {
                if opts.repair {
                    store.remove_session(d).await?;
                }
                report.orphan_session_dirs.push(d.to_string());
            }
        }
        for s in &sessions {
            if !dirs.iter().any(|d| d.as_str() == s.dir) {
                if opts.repair {
                    db.delete_upload_session(s.id).await?;
                }
                report.sessions_without_dir.push(s.transfer_id.clone());
            }
        }

        self.audit(
            &actor.name(),
            "admin.fsck",
            "",
            None,
            json!({
                "repair": opts.repair, "verify": opts.verify_checksums,
                "missing": report.missing_blobs.len(), "corrupt": report.corrupt_blobs.len(),
                "orphans": report.orphan_blobs.len(), "usage_fixed": report.usage_mismatches.len(),
            }),
        )
        .await;
        Ok(report)
    }

    async fn damage_examples(&self, blob_id: &str) -> Result<Vec<String>> {
        Ok(self
            .inner
            .db
            .nodes_using_blob(blob_id)
            .await?
            .into_iter()
            .map(|(u, f)| format!("{u}:{f}"))
            .collect())
    }

    // ---- import -----------------------------------------------------------------

    /// Copies a directory tree from the host into a user's files. Symbolic
    /// links are never followed; names that are not valid are skipped.
    pub async fn import_tree(
        &self,
        actor: &Actor<'_>,
        host_path: &Path,
        user: &str,
        opts: &ImportOptions,
    ) -> Result<ImportReport> {
        actor.require_admin()?;
        let u = self.target_user(user).await?;
        let p = Principal {
            user_id: u.id,
            name: u.name.clone(),
            is_admin: u.is_admin,
            via: Via::AccountPassword,
            scope: crate::auth::Scope::Full,
        };

        let meta = tokio::fs::symlink_metadata(host_path)
            .await
            .map_err(|_| Error::NotFound)?;
        if !meta.is_dir() {
            return Err(Error::BadRequest("the import source must be a directory"));
        }

        // destination folder chain
        let mut base = LogicalPath::root();
        if let Some(d) = &opts.dest {
            for seg in d.split('/').filter(|s| !s.is_empty()) {
                base = base.join(&Name::parse(seg)?);
                if opts.dry_run {
                    continue;
                }
                match self.mkcol(&p, &base).await {
                    Ok(_) | Err(Error::AlreadyExists) => {}
                    Err(e) => return Err(e),
                }
            }
        }

        let mut report = ImportReport::default();
        let mut stack: Vec<(PathBuf, LogicalPath)> = vec![(host_path.to_path_buf(), base)];
        while let Some((dir, logical)) = stack.pop() {
            let mut rd = tokio::fs::read_dir(&dir).await.map_err(Error::internal)?;
            let mut entries = Vec::new();
            while let Some(e) = rd.next_entry().await.map_err(Error::internal)? {
                entries.push(e);
            }
            entries.sort_by_key(tokio::fs::DirEntry::file_name);
            for e in entries {
                let host = e.path();
                let Some(file_name) = e.file_name().to_str().map(str::to_owned) else {
                    report.skip(&host, "name is not valid UTF-8");
                    continue;
                };
                let ty = e.file_type().await.map_err(Error::internal)?;
                if ty.is_symlink() {
                    report.skip(&host, "symbolic link");
                    continue;
                }
                let name = match Name::parse(&file_name)
                    .and_then(|n| crate::files::check_new_name(&n).map(|()| n))
                {
                    Ok(n) => n,
                    Err(err) => {
                        report.skip(&host, &err.to_string());
                        continue;
                    }
                };
                let path = logical.join(&name);
                if ty.is_dir() {
                    if opts.dry_run {
                        report.dirs += 1;
                    } else {
                        match self.mkcol(&p, &path).await {
                            Ok(_) => report.dirs += 1,
                            Err(Error::AlreadyExists) => {}
                            Err(err) => {
                                report.skip(&host, &err.to_string());
                                continue;
                            }
                        }
                    }
                    stack.push((host, path));
                } else if ty.is_file() {
                    self.import_file(&p, host_path, &host, &path, opts, &mut report)
                        .await?;
                } else {
                    report.skip(&host, "not a regular file");
                }
            }
        }
        self.audit(
            &actor.name(),
            "admin.import",
            &u.name,
            None,
            json!({"files": report.files, "dirs": report.dirs, "bytes": report.bytes, "skipped": report.skipped_total}),
        )
        .await;
        Ok(report)
    }

    /// Imports a Nextcloud data directory (ADR 0011): for each Nextcloud user with a `files`
    /// folder, the files (with their modification times) and the versions Nextcloud kept, into
    /// the Rostdav user of the same name (or the one given in `map`). The directory is only read.
    /// What is not imported is listed in the report: trash (its original places are only in
    /// Nextcloud's database), group folders, external storage, encrypted files.
    pub async fn import_nextcloud(
        &self,
        actor: &Actor<'_>,
        data_dir: &Path,
        map: &[(String, String)],
        only: &[String],
        opts: &ImportOptions,
    ) -> Result<NextcloudReport> {
        actor.require_admin()?;
        let meta = tokio::fs::metadata(data_dir)
            .await
            .map_err(|_| Error::BadRequest("the Nextcloud data directory cannot be read"))?;
        if !meta.is_dir() {
            return Err(Error::BadRequest(
                "the Nextcloud data directory is not a directory",
            ));
        }
        let mut names = Vec::new();
        let mut rd = tokio::fs::read_dir(data_dir)
            .await
            .map_err(Error::internal)?;
        while let Some(e) = rd.next_entry().await.map_err(Error::internal)? {
            if let (Some(n), Ok(t)) = (
                e.file_name().to_str().map(str::to_owned),
                e.file_type().await,
            ) {
                if t.is_dir() {
                    names.push(n);
                }
            }
        }
        names.sort();
        let mut out = NextcloudReport::default();
        for nc in names {
            let dir = data_dir.join(&nc);
            if nc == "__groupfolders" {
                out.notes
                    .push("group folders (`__groupfolders`) are not imported".to_owned());
                continue;
            }
            if nc.starts_with('.')
                || nc.starts_with("appdata_")
                || nc.starts_with("updater-")
                || nc == "files_external"
                || nc == "lost+found"
            {
                continue;
            }
            // a user has a `files` folder; anything else is not a user (or has no files)
            if !tokio::fs::metadata(dir.join("files"))
                .await
                .is_ok_and(|m| m.is_dir())
            {
                out.skipped_users
                    .push((nc, "no `files` folder: not a user with files".to_owned()));
                continue;
            }
            if !only.is_empty() && !only.contains(&nc) {
                continue;
            }
            let target = map
                .iter()
                .find(|(from, _)| *from == nc)
                .map_or_else(|| nc.clone(), |(_, to)| to.clone());
            if self.target_user(&target).await.is_err() {
                out.skipped_users.push((
                    nc,
                    format!("no Rostdav user `{target}` (create it first, or map it with --map)"),
                ));
                continue;
            }
            let versions = dir.join("files_versions");
            let mut o = opts.clone();
            o.nextcloud = true;
            o.nextcloud_versions = tokio::fs::metadata(&versions)
                .await
                .is_ok_and(|m| m.is_dir())
                .then_some(versions);
            let trash = dir.join("files_trashbin").join("files");
            if let Ok(mut t) = tokio::fs::read_dir(&trash).await {
                let mut n = 0u64;
                while let Ok(Some(_)) = t.next_entry().await {
                    n += 1;
                }
                if n > 0 {
                    out.notes.push(format!(
                        "{nc}: {n} items in the trash bin are not imported (their original places are only in Nextcloud's database)"
                    ));
                }
            }
            let report = self
                .import_tree(actor, &dir.join("files"), &target, &o)
                .await?;
            out.users.push((nc, target, report));
        }
        Ok(out)
    }

    async fn import_file(
        &self,
        p: &Principal,
        root: &Path,
        host: &Path,
        path: &LogicalPath,
        opts: &ImportOptions,
        report: &mut ImportReport,
    ) -> Result<()> {
        let meta = tokio::fs::metadata(host).await.map_err(Error::internal)?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|d| i64::try_from(d.as_secs()).ok());
        if opts.nextcloud && is_nextcloud_encrypted(host).await {
            report.skip(host, "encrypted by Nextcloud (server-side encryption)");
            return Ok(());
        }
        // what is there already decides: skip, update, or import as new (with versions)
        let existing = match self.stat(p, path).await {
            Ok(n) => Some(n),
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        match &existing {
            None => {}
            Some(_) if opts.overwrite => {}
            Some(n) if opts.update => {
                let same =
                    n.size == i64::try_from(meta.len()).unwrap_or(-1) && Some(n.mtime) == mtime;
                if same {
                    report.skipped_existing += 1;
                    return Ok(());
                }
            }
            Some(_) => {
                report.skipped_existing += 1;
                return Ok(());
            }
        }
        if opts.dry_run {
            report.files += 1;
            report.bytes += meta.len();
            if existing.is_none() {
                report.versions += self.nextcloud_versions_of(opts, root, host).await.len() as u64;
            }
            return Ok(());
        }
        // versions first, oldest to newest, so that each overwrite archives the one before it
        if existing.is_none() {
            for (ts, vfile) in self.nextcloud_versions_of(opts, root, host).await {
                if is_nextcloud_encrypted(&vfile).await {
                    report.skip(&vfile, "encrypted by Nextcloud (server-side encryption)");
                    continue;
                }
                let file = tokio::fs::File::open(&vfile)
                    .await
                    .map_err(Error::internal)?;
                let put = PutOptions {
                    mtime: Some(ts),
                    client_checksum: None,
                    cond: None,
                };
                match self.put_ext(p, path, file, &put).await {
                    Ok(_) => report.versions += 1,
                    Err(e @ (Error::QuotaExceeded | Error::TooLarge)) => return Err(e),
                    Err(e) => report.skip(&vfile, &e.to_string()),
                }
            }
        }
        let file = tokio::fs::File::open(host).await.map_err(Error::internal)?;
        let put = PutOptions {
            mtime,
            client_checksum: None,
            cond: None,
        };
        match self.put_ext(p, path, file, &put).await {
            Ok(w) => {
                if existing.is_some() && opts.update && !opts.overwrite {
                    report.updated += 1;
                } else {
                    report.files += 1;
                }
                report.bytes += u64::try_from(w.node.size).unwrap_or(0);
            }
            Err(Error::PreconditionFailed) => report.skipped_existing += 1,
            // quota and size problems stop the import: continuing would only repeat them
            Err(e @ (Error::QuotaExceeded | Error::TooLarge)) => return Err(e),
            Err(e) => report.skip(host, &e.to_string()),
        }
        Ok(())
    }

    /// The versions Nextcloud kept of `host` (below the files folder `root`): files named
    /// `<name>.v<unix time>` in the same place of `files_versions`, oldest first.
    async fn nextcloud_versions_of(
        &self,
        opts: &ImportOptions,
        root: &Path,
        host: &Path,
    ) -> Vec<(i64, PathBuf)> {
        let Some(versions) = &opts.nextcloud_versions else {
            return Vec::new();
        };
        let (Ok(rel), Some(name)) = (
            host.strip_prefix(root),
            host.file_name().and_then(|n| n.to_str()),
        ) else {
            return Vec::new();
        };
        let dir = versions.join(rel.parent().unwrap_or_else(|| Path::new("")));
        let Ok(mut rd) = tokio::fs::read_dir(&dir).await else {
            return Vec::new();
        };
        let prefix = format!("{name}.v");
        let mut found = Vec::new();
        while let Ok(Some(e)) = rd.next_entry().await {
            let fname = e.file_name();
            let Some(fname) = fname.to_str() else {
                continue;
            };
            let Some(ts) = fname.strip_prefix(&prefix) else {
                continue;
            };
            if ts.is_empty() || !ts.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let (Ok(ts), Ok(ty)) = (ts.parse::<i64>(), e.file_type().await) else {
                continue;
            };
            if ty.is_file() {
                found.push((ts, e.path()));
            }
        }
        found.sort();
        found
    }
}

/// Nextcloud's server-side encryption puts a text header in front of the content.
async fn is_nextcloud_encrypted(file: &Path) -> bool {
    use tokio::io::AsyncReadExt;
    let Ok(mut f) = tokio::fs::File::open(file).await else {
        return false;
    };
    let mut head = [0u8; 27];
    let n = f.read(&mut head).await.unwrap_or(0);
    head[..n].starts_with(b"HBEGIN:oc_encryption_module")
}

impl ImportReport {
    fn skip(&mut self, host: &Path, reason: &str) {
        self.skipped_total += 1;
        if self.skipped.len() < 50 {
            self.skipped
                .push((host.display().to_string(), reason.to_owned()));
        }
    }
}

/// Hard-links (or copies) every file below `src` to the same relative path below `dst`.
fn copy_blobs(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<BackupReport> {
    let mut report = BackupReport::default();
    let mut stack = vec![src.to_path_buf()];
    std::fs::create_dir_all(dst)?;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let rel = path.strip_prefix(src).unwrap_or(&path);
            let target = dst.join(rel);
            let ty = entry.file_type()?;
            if ty.is_dir() {
                std::fs::create_dir_all(&target)?;
                stack.push(path);
            } else if ty.is_file() {
                // a blob deleted by the cleanup while we walk is not part of the snapshot
                let size = match entry.metadata() {
                    Ok(m) => m.len(),
                    Err(_) => continue,
                };
                if std::fs::hard_link(&path, &target).is_err() {
                    match std::fs::copy(&path, &target) {
                        Ok(_) => report.copied += 1,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(e) => return Err(e),
                    }
                }
                report.blobs += 1;
                report.bytes += size;
            }
        }
    }
    Ok(report)
}
