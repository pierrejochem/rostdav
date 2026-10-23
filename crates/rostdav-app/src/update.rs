//! Version check (ADR 0009).
//!
//! Off until an administrator switches it on; then, once a day and on request, one `GET` to the
//! GitHub releases API. The request has no user data: no cookies, no instance identifier, only
//! `User-Agent: rostdav/<version>`. The answer is reduced to four fields that are validated
//! before they are stored; a failure is recorded and shown, and never affects serving files.

use std::time::Duration;

use rostdav_core::release::Version;
use rostdav_core::{Error, Result};
use serde_json::{Value, json};

use crate::admin::Actor;
use crate::{AppState, now_secs};

/// Where the newest release is announced.
pub(crate) const RELEASES_API: &str =
    "https://api.github.com/repos/pierrejochem/rostdav/releases/latest";
/// Release pages must be below this address (the API answer is not trusted to name another).
const RELEASE_PAGES: &str = "https://github.com/pierrejochem/rostdav/";

const ENABLED: &str = "update.enabled";
const CHECKED_AT: &str = "update.checked_at";
const LATEST: &str = "update.latest";
const ERROR: &str = "update.error";

/// A check is repeated after a day; after a failure, after an hour.
const INTERVAL_SECS: i64 = 24 * 3600;
const RETRY_SECS: i64 = 3600;
/// The answer of the API is far smaller; this only bounds what is read.
const MAX_ANSWER: u64 = 1 << 20;
/// Release notes are shown, not interpreted; this bounds what is stored.
const MAX_NOTES: usize = 32 * 1024;

/// What the check learned about the newest release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatestRelease {
    pub version: Version,
    /// `YYYY-MM-DD`.
    pub published: String,
    /// The release page on GitHub.
    pub url: String,
    /// Release notes in the `CHANGELOG.md` form (`### Added`, `- entry`).
    pub notes: String,
}

/// The state of the version check as the administration page shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateStatus {
    pub enabled: bool,
    /// Seconds since the epoch of the last attempt.
    pub checked_at: Option<i64>,
    pub latest: Option<LatestRelease>,
    /// Why the last attempt failed.
    pub error: Option<String>,
}

impl UpdateStatus {
    /// The newest release when it is newer than the running build.
    pub fn available(&self) -> Option<&LatestRelease> {
        self.latest
            .as_ref()
            .filter(|l| l.version > Version::current())
    }
}

/// Reads the answer of `releases/latest`. Only what is used is looked at, and all of it is
/// checked: the tag must be a SemVer version, the page must be ours, drafts and pre-releases
/// are not offered.
pub(crate) fn parse_release(body: &[u8]) -> Result<LatestRelease> {
    let bad = || Error::BadRequest("the answer is not a release");
    let v: Value = serde_json::from_slice(body).map_err(|_| bad())?;
    let text = |k: &str| v.get(k).and_then(Value::as_str);
    if v.get("draft").and_then(Value::as_bool) == Some(true)
        || v.get("prerelease").and_then(Value::as_bool) == Some(true)
    {
        return Err(Error::BadRequest("the newest release is not a final one"));
    }
    let version = text("tag_name")
        .and_then(Version::parse)
        .filter(|v| v.pre.is_empty())
        .ok_or_else(bad)?;
    let url = text("html_url")
        .filter(|u| u.starts_with(RELEASE_PAGES) && !u.contains(['"', '<', '>', ' ']))
        .ok_or_else(bad)?;
    // "2026-10-23T12:00:00Z": the date is all that is shown
    let published = text("published_at")
        .and_then(|p| p.get(..10))
        .filter(|d| {
            d.bytes().enumerate().all(|(i, b)| {
                if i == 4 || i == 7 {
                    b == b'-'
                } else {
                    b.is_ascii_digit()
                }
            })
        })
        .unwrap_or("")
        .to_owned();
    let mut notes = text("body").unwrap_or("").to_owned();
    if notes.len() > MAX_NOTES {
        let mut end = MAX_NOTES;
        while !notes.is_char_boundary(end) {
            end -= 1;
        }
        notes.truncate(end);
    }
    Ok(LatestRelease {
        version,
        published,
        url: url.to_owned(),
        notes,
    })
}

/// One blocking request; call it from `spawn_blocking`.
fn fetch(url: &str) -> std::result::Result<Vec<u8>, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .max_redirects(2)
        .https_only(url.starts_with("https://"))
        .user_agent(format!("rostdav/{}", rostdav_core::VERSION))
        .build()
        .into();
    let mut answer = agent
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| match e {
            ureq::Error::StatusCode(404) => "no release has been published yet".to_owned(),
            ureq::Error::StatusCode(c) => format!("the server answered {c}"),
            // the text of the error holds the host and the reason, never what was sent
            other => other.to_string(),
        })?;
    answer
        .body_mut()
        .with_config()
        .limit(MAX_ANSWER)
        .read_to_vec()
        .map_err(|e| e.to_string())
}

impl AppState {
    /// The state of the version check (administrators only).
    pub async fn update_status(&self, actor: &Actor<'_>) -> Result<UpdateStatus> {
        actor.require_admin()?;
        self.update_status_inner().await
    }

    async fn update_status_inner(&self) -> Result<UpdateStatus> {
        let db = &self.inner.db;
        let text = |v: Option<Vec<u8>>| v.and_then(|b| String::from_utf8(b).ok());
        let checked_at = text(db.setting(CHECKED_AT).await?).and_then(|s| s.parse().ok());
        // a stored answer that no longer validates is dropped, not trusted
        let latest = text(db.setting(LATEST).await?).and_then(|s| parse_release(s.as_bytes()).ok());
        Ok(UpdateStatus {
            enabled: db.setting(ENABLED).await?.as_deref() == Some(b"1"),
            checked_at,
            latest,
            error: text(db.setting(ERROR).await?),
        })
    }

    /// Switches the check on or off. Switching it on checks at once.
    pub async fn update_set_enabled(&self, actor: &Actor<'_>, on: bool) -> Result<UpdateStatus> {
        actor.require_admin()?;
        self.inner
            .db
            .set_setting(ENABLED, if on { b"1" } else { b"0" })
            .await?;
        let action = if on {
            "admin.update_check_on"
        } else {
            "admin.update_check_off"
        };
        self.audit(&actor.name(), action, "", None, json!({})).await;
        if on {
            self.update_check().await;
        }
        self.update_status_inner().await
    }

    /// "Check now": asks even when the last check is recent. Only when the check is switched on.
    pub async fn update_check_now(&self, actor: &Actor<'_>) -> Result<UpdateStatus> {
        actor.require_admin()?;
        if self.update_status_inner().await?.enabled {
            self.update_check().await;
        }
        self.update_status_inner().await
    }

    /// Called every few minutes by the background task: checks when switched on and due.
    pub async fn update_check_if_due(&self) {
        let Ok(status) = self.update_status_inner().await else {
            return;
        };
        let wait = if status.error.is_some() {
            RETRY_SECS
        } else {
            INTERVAL_SECS
        };
        if status.enabled && status.checked_at.is_none_or(|t| now_secs() - t >= wait) {
            self.update_check().await;
        }
    }

    /// Asks, validates and records the result. Never fails: a failure is recorded.
    async fn update_check(&self) {
        let url = self.update_source();
        let outcome = match tokio::task::spawn_blocking(move || fetch(&url)).await {
            Ok(Ok(body)) => parse_release(&body)
                .map(|_| body)
                .map_err(|e| e.to_string()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("the check was interrupted".to_owned()),
        };
        let db = &self.inner.db;
        let stored = async {
            db.set_setting(CHECKED_AT, now_secs().to_string().as_bytes())
                .await?;
            match &outcome {
                Ok(body) => {
                    db.set_setting(LATEST, body).await?;
                    db.delete_setting(ERROR).await
                }
                Err(e) => db.set_setting(ERROR, e.as_bytes()).await,
            }
        };
        if let Err(err) = stored.await {
            tracing::warn!(error = %err, "could not record the result of the version check");
        }
        match outcome {
            Ok(_) => tracing::info!("version check done"),
            Err(e) => tracing::warn!(reason = %e, "version check failed"),
        }
    }

    fn update_source(&self) -> String {
        self.inner
            .update_source
            .lock()
            .map_or_else(|e| e.into_inner().clone(), |s| s.clone())
    }

    /// Points the check at another address (tests use a local server).
    #[doc(hidden)]
    pub fn set_update_source(&self, url: &str) {
        if let Ok(mut s) = self.inner.update_source.lock() {
            *s = url.to_owned();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(extra: Value) -> Vec<u8> {
        let mut v = json!({
            "tag_name": "v9.8.7",
            "html_url": "https://github.com/pierrejochem/rostdav/releases/tag/v9.8.7",
            "published_at": "2026-10-23T12:00:00Z",
            "body": "### Added\n\n- thing",
        });
        if let (Some(v), Some(e)) = (v.as_object_mut(), extra.as_object()) {
            v.extend(e.clone());
        }
        v.to_string().into_bytes()
    }

    #[test]
    fn reads_a_release() {
        let r = parse_release(&release(json!({}))).expect("release");
        assert_eq!(r.version.to_string(), "9.8.7");
        assert_eq!(r.published, "2026-10-23");
        assert!(r.url.ends_with("/tag/v9.8.7"));
        assert_eq!(r.notes, "### Added\n\n- thing");
    }

    #[test]
    fn refuses_what_is_not_a_final_release_of_ours() {
        assert!(parse_release(&release(json!({"draft": true}))).is_err());
        assert!(parse_release(&release(json!({"prerelease": true}))).is_err());
        for bad in [
            &b"not json"[..],
            br#"{}"#,
            br#"{"tag_name":"latest","html_url":"https://github.com/pierrejochem/rostdav/x"}"#,
            br#"{"tag_name":"v1.0.0-rc.1","html_url":"https://github.com/pierrejochem/rostdav/x"}"#,
            // a page that is not ours
            br#"{"tag_name":"v1.0.0","html_url":"https://evil.example/pierrejochem/rostdav/"}"#,
            br#"{"tag_name":"v1.0.0","html_url":"https://github.com/pierrejochem/rostdav-evil/x"}"#,
            br#"{"tag_name":"v1.0.0","html_url":"https://github.com/pierrejochem/rostdav/x\"onmouseover=\"y"}"#,
        ] {
            assert!(parse_release(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn long_notes_are_cut_on_a_character_boundary() {
        let body = "ä".repeat(MAX_NOTES);
        let json = json!({
            "tag_name": "v1.0.0",
            "html_url": "https://github.com/pierrejochem/rostdav/releases/tag/v1.0.0",
            "body": body,
        });
        let r = parse_release(json.to_string().as_bytes()).expect("release");
        assert!(r.notes.len() <= MAX_NOTES && r.notes.chars().all(|c| c == 'ä'));
    }
}
