//! Versions and the release notes that are compiled into the binary.
//!
//! The notes are `CHANGELOG.md` (Keep a Changelog format), so the "About" page works offline and
//! shows exactly what the running build contains.

use std::cmp::Ordering;

/// The changelog of this build.
const CHANGELOG: &str = include_str!("../../../CHANGELOG.md");

/// A semantic version (`1.2.3` or `1.2.3-rc.1`). Build metadata is ignored, as in SemVer ordering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// Pre-release identifiers after the `-`, empty for a release.
    pub pre: Vec<String>,
}

impl Version {
    /// Parses `1.2.3`, `v1.2.3` and `1.2.3-rc.1`; anything else is `None`.
    pub fn parse(text: &str) -> Option<Version> {
        let text = text.trim().trim_start_matches('v');
        let text = text.split('+').next().unwrap_or(text);
        let (core, pre) = match text.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (text, None),
        };
        let mut parts = core.split('.');
        let mut number = || -> Option<u64> {
            let p = parts.next()?;
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse().ok()
        };
        let (major, minor, patch) = (number()?, number()?, number()?);
        if parts.next().is_some() {
            return None;
        }
        let pre: Vec<String> = if let Some(pre) = pre {
            let ids: Vec<String> = pre.split('.').map(str::to_owned).collect();
            if ids
                .iter()
                .any(|i| i.is_empty() || !i.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
            {
                return None;
            }
            ids
        } else {
            Vec::new()
        };
        Some(Version {
            major,
            minor,
            patch,
            pre,
        })
    }

    /// The version of the running build.
    pub fn current() -> Version {
        // CARGO_PKG_VERSION is always valid SemVer
        Version::parse(crate::VERSION).unwrap_or(Version {
            major: 0,
            minor: 0,
            patch: 0,
            pre: Vec::new(),
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            write!(f, "-{}", self.pre.join("."))?;
        }
        Ok(())
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let core =
            (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch));
        if core != Ordering::Equal {
            return core;
        }
        // a release is newer than its pre-releases; pre-release identifiers compare one by one
        match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => {
                for (a, b) in self.pre.iter().zip(&other.pre) {
                    let o = match (a.parse::<u64>(), b.parse::<u64>()) {
                        (Ok(x), Ok(y)) => x.cmp(&y),
                        (Ok(_), Err(_)) => Ordering::Less,
                        (Err(_), Ok(_)) => Ordering::Greater,
                        (Err(_), Err(_)) => a.cmp(b),
                    };
                    if o != Ordering::Equal {
                        return o;
                    }
                }
                self.pre.len().cmp(&other.pre.len())
            }
        }
    }
}

/// One heading of a release (`Added`, `Changed`, `Fixed`, ...) and its entries as Markdown text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub heading: String,
    pub items: Vec<String>,
}

/// One released version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub version: Version,
    /// `YYYY-MM-DD`, as written in the changelog.
    pub date: String,
    pub sections: Vec<Section>,
}

/// Parses a changelog: `## [x.y.z] - date`, `### Heading`, `- entry` (continuation lines are
/// joined). Sections that are not a version (such as `[Unreleased]`) are left out.
pub fn parse_changelog(text: &str) -> Vec<Release> {
    let mut releases: Vec<Release> = Vec::new();
    let mut skipping = true;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            skipping = true;
            let Some(rest) = rest.strip_prefix('[') else {
                continue;
            };
            let Some((version, tail)) = rest.split_once(']') else {
                continue;
            };
            let Some(version) = Version::parse(version) else {
                continue;
            };
            let date = tail.trim_start_matches([' ', '-']).trim().to_owned();
            releases.push(Release {
                version,
                date,
                sections: Vec::new(),
            });
            skipping = false;
        } else if skipping {
            continue;
        } else if let Some(heading) = line.strip_prefix("### ") {
            if let Some(r) = releases.last_mut() {
                r.sections.push(Section {
                    heading: heading.trim().to_owned(),
                    items: Vec::new(),
                });
            }
        } else if let Some(item) = line.strip_prefix("- ") {
            if let Some(s) = releases.last_mut().and_then(|r| r.sections.last_mut()) {
                s.items.push(item.trim().to_owned());
            }
        } else if line.starts_with("  ") && !line.trim().is_empty() {
            if let Some(last) = releases
                .last_mut()
                .and_then(|r| r.sections.last_mut())
                .and_then(|s| s.items.last_mut())
            {
                last.push(' ');
                last.push_str(line.trim());
            }
        }
    }
    releases
}

/// The release notes of this build, newest first.
pub fn releases() -> Vec<Release> {
    parse_changelog(CHANGELOG)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).expect("version")
    }

    #[test]
    fn parses_versions_and_rejects_junk() {
        assert_eq!(v("1.2.3").to_string(), "1.2.3");
        assert_eq!(v("v0.3.0").to_string(), "0.3.0");
        assert_eq!(v("1.0.0-rc.1+build5").to_string(), "1.0.0-rc.1");
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "a.b.c",
            "1.2.x",
            "1.2.3-",
            "1.-2.3",
            "1.2.3-a..b",
        ] {
            assert!(Version::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn orders_like_semver() {
        // the ordering example from the SemVer 2.0.0 specification, item 11
        let ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.1.0",
            "2.0.0",
        ];
        for pair in ordered.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
        assert!(v("0.10.0") > v("0.9.9"));
    }

    #[test]
    fn parses_a_changelog() {
        let text = "# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- not yet\n\n\
                    ## [0.2.0] - 2026-10-23\n\n### Added\n\n- one thing\n  continued here\n- two\n\n\
                    ### Fixed\n\n- three\n\n## [0.1.0] - 2026-10-21\n\n### Added\n\n- first\n";
        let r = parse_changelog(text);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].version, v("0.2.0"));
        assert_eq!(r[0].date, "2026-10-23");
        assert_eq!(r[0].sections.len(), 2);
        assert_eq!(r[0].sections[0].heading, "Added");
        assert_eq!(r[0].sections[0].items, ["one thing continued here", "two"]);
        assert_eq!(r[1].sections[0].items, ["first"]);
    }

    #[test]
    fn the_embedded_changelog_has_the_running_version() {
        let r = releases();
        assert!(!r.is_empty());
        assert!(
            r.windows(2).all(|w| w[0].version > w[1].version),
            "newest first"
        );
        // the release workflow checks the tag against the changelog; a build between releases
        // has the version of the last one in `Cargo.toml`, so it must be listed
        assert!(
            r.iter().any(|x| x.version == Version::current()),
            "CHANGELOG.md has no section for {}",
            crate::VERSION
        );
        assert!(r.iter().all(|x| !x.sections.is_empty()));
    }
}
