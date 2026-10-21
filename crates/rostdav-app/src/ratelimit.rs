//! In-memory brute-force limiter (ADR 0003).
//!
//! Counts *failed* attempts per key inside a fixed window. Once `max_failures`
//! is reached the key is blocked until the window ends.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 50_000;

struct Entry {
    failures: u32,
    window_start: Instant,
}

pub struct RateLimiter {
    max_failures: u32,
    window: Duration,
    entries: Mutex<HashMap<String, Entry>>,
}

impl RateLimiter {
    pub fn new(max_failures: u32, window: Duration) -> Self {
        Self {
            max_failures,
            window,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// `Err(retry_after_secs)` if the key is currently blocked.
    pub fn check(&self, key: &str) -> Result<(), u64> {
        self.check_at(key, Instant::now())
    }

    /// Counts a failure; `true` if this failure just blocked the key.
    pub fn record_failure(&self, key: &str) -> bool {
        self.record_failure_at(key, Instant::now())
    }

    pub fn clear(&self, key: &str) {
        if let Ok(mut m) = self.entries.lock() {
            m.remove(key);
        }
    }

    fn check_at(&self, key: &str, now: Instant) -> Result<(), u64> {
        let Ok(m) = self.entries.lock() else {
            return Ok(());
        };
        match m.get(key) {
            Some(e) if e.failures >= self.max_failures => {
                let elapsed = now.saturating_duration_since(e.window_start);
                if elapsed >= self.window {
                    Ok(())
                } else {
                    Err((self.window - elapsed).as_secs().max(1))
                }
            }
            _ => Ok(()),
        }
    }

    fn record_failure_at(&self, key: &str, now: Instant) -> bool {
        let Ok(mut m) = self.entries.lock() else {
            return false;
        };
        if m.len() >= MAX_ENTRIES {
            let window = self.window;
            m.retain(|_, e| now.saturating_duration_since(e.window_start) < window);
            if m.len() >= MAX_ENTRIES {
                return false; // under attack with many keys: do not grow without bound
            }
        }
        let e = m.entry(key.to_owned()).or_insert(Entry {
            failures: 0,
            window_start: now,
        });
        if now.saturating_duration_since(e.window_start) >= self.window {
            e.failures = 0;
            e.window_start = now;
        }
        e.failures += 1;
        e.failures == self.max_failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_max_failures_and_recovers() {
        let l = RateLimiter::new(3, Duration::from_secs(60));
        let t0 = Instant::now();
        for _ in 0..2 {
            l.record_failure_at("k", t0);
            assert!(l.check_at("k", t0).is_ok());
        }
        l.record_failure_at("k", t0);
        let wait = l
            .check_at("k", t0 + Duration::from_secs(10))
            .expect_err("blocked");
        assert!((49..=50).contains(&wait), "{wait}");
        assert!(l.check_at("other", t0).is_ok());
        assert!(l.check_at("k", t0 + Duration::from_secs(61)).is_ok());
        // a new window starts counting from zero
        l.record_failure_at("k", t0 + Duration::from_secs(61));
        assert!(l.check_at("k", t0 + Duration::from_secs(62)).is_ok());
    }

    #[test]
    fn clear_resets() {
        let l = RateLimiter::new(1, Duration::from_secs(60));
        l.record_failure("k");
        assert!(l.check("k").is_err());
        l.clear("k");
        assert!(l.check("k").is_ok());
    }
}
