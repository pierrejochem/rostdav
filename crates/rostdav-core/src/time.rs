//! Civil dates without a date library (UTC only).

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `2023-11-14T22:13:20Z`
pub fn rfc3339(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// `2023-11-14 22:13:20` (the form the OCS API uses for expiry dates).
pub fn sql_datetime(secs: i64) -> String {
    rfc3339(secs)
        .replace('T', " ")
        .trim_end_matches('Z')
        .to_owned()
}

/// `YYYY-MM-DD`, `YYYY-MM-DD HH:MM:SS`, `YYYY-MM-DDTHH:MM:SSZ` or plain unix seconds.
pub fn parse_datetime(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    let (date, time) = s.split_once(['T', ' ']).unwrap_or((s, "00:00:00"));
    let mut dp = date.split('-');
    let (Some(y), Some(m), Some(d), None) = (dp.next(), dp.next(), dp.next(), dp.next()) else {
        return None;
    };
    let (y, m, d): (i64, i64, i64) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || !(0..=9999).contains(&y) {
        return None;
    }
    let mut tp = time.trim_end_matches('Z').split(':');
    let (h, mi, sec): (i64, i64, i64) = (
        tp.next().unwrap_or("0").parse().ok()?,
        tp.next().unwrap_or("0").parse().ok()?,
        tp.next().unwrap_or("0").parse().ok()?,
    );
    if !(0..24).contains(&h) || !(0..60).contains(&mi) || !(0..61).contains(&sec) {
        return None;
    }
    Some(days_from_civil(y, m, d) * 86_400 + h * 3600 + mi * 60 + sec)
}

/// For the command line: like [`parse_datetime`] with an explanatory error.
pub fn parse_since(s: &str) -> Result<i64, String> {
    parse_datetime(s).ok_or_else(|| {
        format!("not a date: {s:?} (use 2026-01-31, 2026-01-31T12:00:00Z or unix seconds)")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_roundtrip() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(sql_datetime(1_700_000_000), "2023-11-14 22:13:20");
        assert_eq!(parse_datetime("2023-11-14T22:13:20Z"), Some(1_700_000_000));
        assert_eq!(parse_datetime("2023-11-14 22:13:20"), Some(1_700_000_000));
        assert_eq!(parse_datetime("2023-11-14"), Some(1_699_920_000));
        assert_eq!(parse_datetime("1700000000"), Some(1_700_000_000));
        assert_eq!(parse_datetime("2024-02-29"), Some(1_709_164_800));
        for t in [-86_400, 0, 951_782_400, 4_102_444_800] {
            assert_eq!(parse_datetime(&rfc3339(t)), Some(t));
        }
        for bad in [
            "",
            "yesterday",
            "2026-13-01",
            "2026-01-32",
            "2026-01",
            "2026-01-01T25:00:00Z",
            "2026-1-x",
        ] {
            assert_eq!(parse_datetime(bad), None, "{bad}");
        }
        assert!(
            parse_since("yesterday")
                .expect_err("e")
                .contains("not a date")
        );
    }
}
