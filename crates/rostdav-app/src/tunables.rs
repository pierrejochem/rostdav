//! Limits an administrator may change while the server runs.
//!
//! The configuration file and the environment give the starting values. A change made in the web
//! interface is stored in the `settings` table (keys `cfg.<name>`), applies at once and survives
//! a restart; "back to default" removes it. Only the settings listed in [`Tunable`] can be
//! changed: sign-in and session settings, file locations and the like stay in the file.

use rostdav_core::{Error, Result};
use serde_json::json;

use crate::admin::Actor;
use crate::{AppConfig, AppState, parse_quota};

const PREFIX: &str = "cfg.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tunable {
    DefaultQuota,
    UploadRetentionHours,
    MaxVersions,
    VersionRetentionDays,
    VersionQuotaShare,
    TrashRetentionDays,
    EventLogRetentionDays,
    SearchContent,
    SearchMaxFileMiB,
    SearchMaxTextKiB,
}

impl Tunable {
    pub const ALL: [Tunable; 10] = [
        Tunable::DefaultQuota,
        Tunable::UploadRetentionHours,
        Tunable::MaxVersions,
        Tunable::VersionRetentionDays,
        Tunable::VersionQuotaShare,
        Tunable::TrashRetentionDays,
        Tunable::EventLogRetentionDays,
        Tunable::SearchContent,
        Tunable::SearchMaxFileMiB,
        Tunable::SearchMaxTextKiB,
    ];

    /// The name in the configuration file (`section.name`) and, after `cfg.`, in the database.
    pub fn key(self) -> &'static str {
        match self {
            Tunable::DefaultQuota => "limits.default_quota",
            Tunable::UploadRetentionHours => "limits.upload_retention_hours",
            Tunable::MaxVersions => "versioning.max_versions",
            Tunable::VersionRetentionDays => "versioning.max_age_days",
            Tunable::VersionQuotaShare => "versioning.max_quota_share_percent",
            Tunable::TrashRetentionDays => "trash.retention_days",
            Tunable::EventLogRetentionDays => "audit.retention_days",
            Tunable::SearchContent => "search.content_indexing",
            Tunable::SearchMaxFileMiB => "search.max_file_mib",
            Tunable::SearchMaxTextKiB => "search.max_text_kib",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.key() == key)
    }

    /// The value as the administrator writes it.
    fn read(self, c: &AppConfig) -> String {
        match self {
            Tunable::DefaultQuota => format_quota(c.limits.default_quota),
            Tunable::UploadRetentionHours => (c.limits.upload_retention_secs / 3600).to_string(),
            Tunable::MaxVersions => c.versioning.max_versions.to_string(),
            Tunable::VersionRetentionDays => c.versioning.max_age_days.to_string(),
            Tunable::VersionQuotaShare => c.versioning.max_quota_share_percent.to_string(),
            Tunable::TrashRetentionDays => c.trash.retention_days.to_string(),
            Tunable::EventLogRetentionDays => c.audit.retention_days.to_string(),
            Tunable::SearchContent => u8::from(c.search.content).to_string(),
            Tunable::SearchMaxFileMiB => (c.search.max_file_bytes >> 20).to_string(),
            Tunable::SearchMaxTextKiB => (c.search.max_text_bytes >> 10).to_string(),
        }
    }

    /// Checks `text` and puts it into `c`; on an error `c` is unchanged.
    fn apply(self, c: &mut AppConfig, text: &str) -> Result<()> {
        let text = text.trim();
        let number = |max: u32, msg: &'static str| -> Result<u32> {
            text.parse::<u32>()
                .ok()
                .filter(|n| *n <= max)
                .ok_or(Error::BadRequest(msg))
        };
        match self {
            Tunable::DefaultQuota => c.limits.default_quota = parse_quota(text)?,
            Tunable::UploadRetentionHours => {
                let h = number(8760, "hours must be a number from 1 to 8760")?;
                if h == 0 {
                    return Err(Error::BadRequest("hours must be a number from 1 to 8760"));
                }
                c.limits.upload_retention_secs = i64::from(h) * 3600;
            }
            Tunable::MaxVersions => {
                c.versioning.max_versions =
                    number(1000, "versions must be a number from 0 to 1000")?;
            }
            Tunable::VersionRetentionDays => {
                c.versioning.max_age_days = number(3650, "days must be a number from 0 to 3650")?;
            }
            Tunable::VersionQuotaShare => {
                c.versioning.max_quota_share_percent =
                    number(100, "percent must be a number from 0 to 100")?;
            }
            Tunable::TrashRetentionDays => {
                c.trash.retention_days = number(3650, "days must be a number from 0 to 3650")?;
            }
            Tunable::EventLogRetentionDays => {
                c.audit.retention_days = number(3650, "days must be a number from 0 to 3650")?;
            }
            Tunable::SearchContent => {
                c.search.content = number(1, "must be 1 (on) or 0 (off)")? == 1;
            }
            Tunable::SearchMaxFileMiB => {
                let n = number(4096, "MiB must be a number from 1 to 4096")?;
                if n == 0 {
                    return Err(Error::BadRequest("MiB must be a number from 1 to 4096"));
                }
                c.search.max_file_bytes = u64::from(n) << 20;
            }
            Tunable::SearchMaxTextKiB => {
                let n = number(16384, "KiB must be a number from 16 to 16384")?;
                if n < 16 {
                    return Err(Error::BadRequest("KiB must be a number from 16 to 16384"));
                }
                c.search.max_text_bytes = (n as usize) << 10;
            }
        }
        Ok(())
    }
}

/// `unlimited`, or the largest unit that divides the size (`10G`, `512M`, or plain bytes).
fn format_quota(q: Option<i64>) -> String {
    let Some(n) = q else {
        return "unlimited".to_owned();
    };
    for (unit, size) in [
        ("T", 1i64 << 40),
        ("G", 1 << 30),
        ("M", 1 << 20),
        ("K", 1 << 10),
    ] {
        if n > 0 && n % size == 0 {
            return format!("{}{unit}", n / size);
        }
    }
    n.to_string()
}

/// One setting as the administration page shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunableView {
    pub tunable: Tunable,
    /// In force now.
    pub value: String,
    /// From the file and the environment.
    pub file_value: String,
    /// An administrator changed it.
    pub changed: bool,
    /// The file or an environment variable sets it: it cannot be changed here.
    pub locked: bool,
}

impl AppState {
    /// Applies the changes stored in the database on top of the starting values.
    /// A stored value that no longer passes the checks is ignored (and logged).
    pub async fn load_setting_overrides(self) -> Result<Self> {
        let rows = self.inner.db.settings_with_prefix(PREFIX).await?;
        let mut c = self.cfg();
        for (key, value) in rows {
            let name = key.strip_prefix(PREFIX).unwrap_or(&key);
            let text = String::from_utf8_lossy(&value);
            let tunable = Tunable::from_key(name);
            if tunable.is_some_and(|t| self.inner.locked.contains(&t)) {
                continue; // the file or the environment decides
            }
            match tunable.map(|t| t.apply(&mut c, &text)) {
                Some(Ok(())) => {}
                _ => tracing::warn!(
                    setting = name,
                    "ignoring a stored setting that is not valid"
                ),
            }
        }
        self.set_config(c);
        Ok(self)
    }

    fn set_config(&self, c: AppConfig) {
        match self.inner.config.write() {
            Ok(mut w) => *w = c,
            Err(e) => *e.into_inner() = c,
        }
    }

    pub fn tunables(&self, actor: &Actor<'_>) -> Result<Vec<TunableView>> {
        actor.require_admin()?;
        let now = self.cfg();
        let base = &self.inner.base_config;
        Ok(Tunable::ALL
            .into_iter()
            .map(|t| {
                let (value, file_value) = (t.read(&now), t.read(base));
                TunableView {
                    tunable: t,
                    changed: value != file_value,
                    locked: self.inner.locked.contains(&t),
                    value,
                    file_value,
                }
            })
            .collect())
    }

    /// Sets one value. The same value as in the file removes the change.
    pub async fn set_tunable(&self, actor: &Actor<'_>, key: &str, value: &str) -> Result<()> {
        actor.require_admin()?;
        let t = Tunable::from_key(key).ok_or(Error::NotFound)?;
        if self.inner.locked.contains(&t) {
            return Err(Error::Conflict(
                "this setting is set by the configuration file or an environment variable",
            ));
        }
        let mut c = self.cfg();
        let before = t.read(&c);
        t.apply(&mut c, value)?;
        let after = t.read(&c);
        if after == t.read(&self.inner.base_config) {
            self.inner
                .db
                .delete_setting(&format!("{PREFIX}{}", t.key()))
                .await?;
        } else {
            self.inner
                .db
                .set_setting(&format!("{PREFIX}{}", t.key()), after.as_bytes())
                .await?;
        }
        self.set_config(c);
        self.audit(
            &actor.name(),
            "admin.setting_changed",
            t.key(),
            None,
            json!({"from": before, "to": after}),
        )
        .await;
        Ok(())
    }

    /// Back to the value from the file and the environment.
    pub async fn reset_tunable(&self, actor: &Actor<'_>, key: &str) -> Result<()> {
        actor.require_admin()?;
        let t = Tunable::from_key(key).ok_or(Error::NotFound)?;
        let file_value = t.read(&self.inner.base_config);
        self.set_tunable(actor, key, &file_value).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_text_roundtrips() {
        for q in [
            None,
            Some(1 << 30),
            Some(5 << 40),
            Some(1500),
            Some(3 << 20),
        ] {
            assert_eq!(parse_quota(&format_quota(q)).expect("parse"), q, "{q:?}");
        }
        assert_eq!(format_quota(Some(10 << 30)), "10G");
        assert_eq!(format_quota(Some(0)), "0");
    }

    #[test]
    fn values_are_checked_and_a_bad_one_changes_nothing() {
        let mut c = AppConfig::default();
        let before = Tunable::MaxVersions.read(&c);
        for (t, bad) in [
            (Tunable::MaxVersions, "1001"),
            (Tunable::MaxVersions, "-1"),
            (Tunable::MaxVersions, "many"),
            (Tunable::UploadRetentionHours, "0"),
            (Tunable::UploadRetentionHours, "9000"),
            (Tunable::VersionQuotaShare, "101"),
            (Tunable::TrashRetentionDays, "99999"),
            (Tunable::DefaultQuota, "10X"),
            (Tunable::DefaultQuota, "-5G"),
        ] {
            assert!(t.apply(&mut c, bad).is_err(), "{bad} for {}", t.key());
        }
        assert_eq!(Tunable::MaxVersions.read(&c), before);
        Tunable::MaxVersions.apply(&mut c, " 7 ").expect("ok");
        Tunable::UploadRetentionHours
            .apply(&mut c, "48")
            .expect("ok");
        Tunable::DefaultQuota.apply(&mut c, "2G").expect("ok");
        assert_eq!(c.versioning.max_versions, 7);
        assert_eq!(c.limits.upload_retention_secs, 48 * 3600);
        assert_eq!(c.limits.default_quota, Some(2 << 30));
    }

    #[test]
    fn every_key_is_known_and_unique() {
        for t in Tunable::ALL {
            assert_eq!(Tunable::from_key(t.key()), Some(t));
        }
        assert_eq!(Tunable::from_key("security.totp_key"), None);
        assert_eq!(Tunable::from_key("web.session_idle_hours"), None);
    }
}
