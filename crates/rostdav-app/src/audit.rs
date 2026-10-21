//! Event log recording (docs/admin.md).
//!
//! Recording is best effort: a failure is logged but never fails the request.
//! Details are built by Rostdav code only and never contain contents,
//! passwords or tokens.

use std::net::IpAddr;

use rostdav_core::Result;
use rostdav_meta::Event;
use serde_json::Value;

use crate::AppState;

#[derive(Clone, Debug)]
pub struct AuditOptions {
    /// Store client addresses shortened (IPv4 /24, IPv6 /48).
    pub anonymize_ip: bool,
    /// Events older than this are removed by garbage collection; 0 keeps everything.
    pub retention_days: u32,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            anonymize_ip: false,
            retention_days: 365,
        }
    }
}

/// Shortens an address for storage.
pub fn anonymize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            IpAddr::V4([o[0], o[1], o[2], 0].into())
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            IpAddr::V6([s[0], s[1], s[2], 0, 0, 0, 0, 0].into())
        }
    }
}

/// Free text from clients is shortened and stripped of control characters.
pub fn sanitize_text(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(128).collect()
}

impl AppState {
    pub async fn audit(
        &self,
        actor: &str,
        action: &str,
        target: &str,
        ip: Option<IpAddr>,
        details: Value,
    ) {
        let ip = ip
            .filter(|i| !i.is_unspecified())
            .map(|i| {
                if self.inner.config.audit.anonymize_ip {
                    anonymize(i)
                } else {
                    i
                }
            })
            .map(|i| i.to_string())
            .unwrap_or_default();
        if let Err(e) = self
            .inner
            .db
            .record_event(
                &sanitize_text(actor),
                action,
                &sanitize_text(target),
                &ip,
                &details.to_string(),
            )
            .await
        {
            tracing::warn!(error = %e, action, "could not record event");
        }
    }

    /// Events at or after `since` (unix seconds).
    pub(crate) async fn events_since(&self, since: i64) -> Result<Vec<Event>> {
        self.inner.db.events_since(since).await
    }

    /// Removes events past the retention period; returns how many.
    pub async fn purge_old_events(&self) -> Result<u64> {
        let days = self.inner.config.audit.retention_days;
        if days == 0 {
            return Ok(0);
        }
        let cutoff = crate::now_secs() - i64::from(days) * 86_400;
        self.inner.db.purge_events_before(cutoff).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymization() {
        assert_eq!(
            anonymize("203.0.113.77".parse().expect("ip")),
            "203.0.113.0".parse::<IpAddr>().expect("ip")
        );
        assert_eq!(
            anonymize("2001:db8:abcd:1234::1".parse().expect("ip")),
            "2001:db8:abcd::".parse::<IpAddr>().expect("ip")
        );
    }

    #[test]
    fn text_is_bounded_and_clean() {
        assert_eq!(sanitize_text("a\nb\u{7}c"), "abc");
        assert_eq!(sanitize_text(&"x".repeat(500)).len(), 128);
    }
}
