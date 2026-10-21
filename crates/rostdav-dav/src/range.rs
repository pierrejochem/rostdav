//! `Range` header handling (single byte range; multi-range is ignored).

#[derive(Debug, PartialEq, Eq)]
pub enum RangeOutcome {
    /// Serve the whole entity (no or unusable header).
    Full,
    /// Serve `start..=end`.
    Partial(u64, u64),
    /// 416.
    Unsatisfiable,
}

pub fn parse_range(header: Option<&str>, size: u64) -> RangeOutcome {
    let Some(h) = header else {
        return RangeOutcome::Full;
    };
    let Some(spec) = h.trim().strip_prefix("bytes=") else {
        return RangeOutcome::Full;
    };
    if spec.contains(',') {
        return RangeOutcome::Full;
    }
    let Some((a, b)) = spec.split_once('-') else {
        return RangeOutcome::Full;
    };
    let (a, b) = (a.trim(), b.trim());
    match (a.is_empty(), b.is_empty()) {
        (true, true) => RangeOutcome::Full,
        // suffix: last n bytes
        (true, false) => match b.parse::<u64>() {
            Ok(0) => RangeOutcome::Unsatisfiable,
            Ok(n) if size > 0 => RangeOutcome::Partial(size.saturating_sub(n), size - 1),
            Ok(_) => RangeOutcome::Unsatisfiable,
            Err(_) => RangeOutcome::Full,
        },
        (false, _) => {
            let Ok(start) = a.parse::<u64>() else {
                return RangeOutcome::Full;
            };
            let end = if b.is_empty() {
                u64::MAX
            } else {
                match b.parse::<u64>() {
                    Ok(e) => e,
                    Err(_) => return RangeOutcome::Full,
                }
            };
            if end < start {
                return RangeOutcome::Full; // invalid per RFC 9110: ignore
            }
            if start >= size {
                return RangeOutcome::Unsatisfiable;
            }
            RangeOutcome::Partial(start, end.min(size - 1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use RangeOutcome::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range(None, 10), Full);
        assert_eq!(parse_range(Some("bytes=0-3"), 10), Partial(0, 3));
        assert_eq!(parse_range(Some("bytes=4-"), 10), Partial(4, 9));
        assert_eq!(parse_range(Some("bytes=-3"), 10), Partial(7, 9));
        assert_eq!(parse_range(Some("bytes=-30"), 10), Partial(0, 9));
        assert_eq!(parse_range(Some("bytes=5-500"), 10), Partial(5, 9));
        assert_eq!(parse_range(Some("bytes=10-"), 10), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=-0"), 10), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=0-0"), 0), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=5-2"), 10), Full);
        assert_eq!(parse_range(Some("bytes=0-1,4-5"), 10), Full);
        assert_eq!(parse_range(Some("items=0-1"), 10), Full);
        assert_eq!(parse_range(Some("bytes=a-b"), 10), Full);
        assert_eq!(parse_range(Some("bytes=-"), 10), Full);
        assert_eq!(parse_range(Some("bytes=99999999999999999999-"), 10), Full);
    }
}
