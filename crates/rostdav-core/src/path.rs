//! Names and logical paths.
//!
//! Everything coming from clients passes through [`Name::parse`] or
//! [`LogicalPath::from_url_path`]. Logical paths are never physical paths
//! (ADR 0002): storage addresses blobs only by their ID.

use std::fmt;

use percent_encoding::percent_decode_str;
use unicode_normalization::UnicodeNormalization;

use crate::{Error, Result};

/// Maximum length of a name in bytes (like common file systems).
pub const MAX_NAME_BYTES: usize = 255;
/// Maximale Anzahl Segmente eines Pfads.
pub const MAX_DEPTH: usize = 64;

/// A single path segment.
///
/// The name is kept as given (for display); [`Name::key`] returns the NFC
/// form that decides uniqueness within a folder.
/// Case is significant, as in Nextcloud.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name {
    display: String,
    key: String,
}

impl Name {
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.is_empty() {
            return Err(Error::BadRequest("leerer Name"));
        }
        if raw == "." || raw == ".." {
            return Err(Error::BadRequest("invalid name"));
        }
        if raw.chars().any(|c| c == '/' || c == '\\' || c.is_control()) {
            return Err(Error::BadRequest("name contains forbidden characters"));
        }
        let key: String = raw.nfc().collect();
        // Check after normalization: it may change the length.
        if raw.len() > MAX_NAME_BYTES || key.len() > MAX_NAME_BYTES {
            return Err(Error::BadRequest("name too long"));
        }
        Ok(Self {
            display: raw.to_owned(),
            key,
        })
    }

    /// Name as the client sent it.
    pub fn as_str(&self) -> &str {
        &self.display
    }

    /// NFC form for `UNIQUE(parent_id, name_key)`.
    pub fn key(&self) -> &str {
        &self.key
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display)
    }
}

/// Pfad relativ zur Wurzel eines Benutzers. Leer = Wurzel.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogicalPath {
    segments: Vec<Name>,
}

impl LogicalPath {
    pub fn root() -> Self {
        Self::default()
    }

    /// Parses the path part of a URL (still percent-encoded, without prefix).
    ///
    /// Decodes exactly once. `%2F` and `%00` in a segment are rejected,
    /// as are `.`/`..` and invalid UTF-8. Duplicate slashes and
    /// a trailing slash are allowed and ignored.
    pub fn from_url_path(raw: &str) -> Result<Self> {
        let mut segments = Vec::new();
        for part in raw.split('/').filter(|s| !s.is_empty()) {
            let decoded = percent_decode_str(part)
                .decode_utf8()
                .map_err(|_| Error::BadRequest("path is not valid UTF-8"))?;
            segments.push(Name::parse(&decoded)?);
            if segments.len() > MAX_DEPTH {
                return Err(Error::BadRequest("path too deep"));
            }
        }
        Ok(Self { segments })
    }

    pub fn segments(&self) -> &[Name] {
        &self.segments
    }

    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// Last segment and parent path; `None` for the root.
    pub fn split_last(&self) -> Option<(LogicalPath, &Name)> {
        let (last, rest) = self.segments.split_last()?;
        Some((
            LogicalPath {
                segments: rest.to_vec(),
            },
            last,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bad(raw: &str) {
        assert!(
            matches!(LogicalPath::from_url_path(raw), Err(Error::BadRequest(_))),
            "{raw:?} should have been rejected"
        );
    }

    #[test]
    fn plain_path() {
        let p = LogicalPath::from_url_path("/a/b/c.txt").expect("parse");
        let names: Vec<_> = p.segments().iter().map(Name::as_str).collect();
        assert_eq!(names, ["a", "b", "c.txt"]);
    }

    #[test]
    fn root_and_slashes() {
        assert!(LogicalPath::from_url_path("").expect("p").is_root());
        assert!(LogicalPath::from_url_path("/").expect("p").is_root());
        let p = LogicalPath::from_url_path("//a///b/").expect("p");
        assert_eq!(p.segments().len(), 2);
    }

    #[test]
    fn dot_segments_rejected() {
        bad("/a/../b");
        bad("/./a");
        bad("/a/..");
        bad("/%2e%2e/etc/passwd");
        bad("/%2E/a");
        bad("/a/%2e%2E/b");
    }

    #[test]
    fn encoded_separators_and_nul_rejected() {
        bad("/a%2Fb");
        bad("/a%2fb");
        bad("/a%5Cb");
        bad("/a%00b");
        bad("/a\0b");
        bad("/a%0Ab");
    }

    #[test]
    fn backslash_rejected() {
        bad("/a\\b");
        bad("/..\\x");
    }

    #[test]
    fn invalid_utf8_rejected() {
        bad("/%ff%fe");
        bad("/%C0%AF");
    }

    #[test]
    fn decoded_once_only() {
        // %252e%252e becomes the name "%2e%2e", not "..".
        let p = LogicalPath::from_url_path("/%252e%252e").expect("p");
        assert_eq!(p.segments()[0].as_str(), "%2e%2e");
    }

    #[test]
    fn percent_decoded_unicode() {
        let p = LogicalPath::from_url_path("/caf%C3%A9/%E6%97%A5%E6%9C%AC").expect("p");
        assert_eq!(p.segments()[0].as_str(), "café");
        assert_eq!(p.segments()[1].as_str(), "日本");
    }

    #[test]
    fn nfc_key_equal_for_composed_and_decomposed() {
        let composed = Name::parse("\u{00E9}.txt").expect("n");
        let decomposed = Name::parse("e\u{0301}.txt").expect("n");
        assert_ne!(composed.as_str(), decomposed.as_str());
        assert_eq!(composed.key(), decomposed.key());
    }

    #[test]
    fn case_is_significant() {
        let a = Name::parse("File").expect("n");
        let b = Name::parse("file").expect("n");
        assert_ne!(a.key(), b.key());
    }

    #[test]
    fn length_limits() {
        assert!(Name::parse(&"a".repeat(255)).is_ok());
        assert!(Name::parse(&"a".repeat(256)).is_err());
        // 128 * 2 bytes = 256 bytes
        assert!(Name::parse(&"é".repeat(128)).is_err());
    }

    #[test]
    fn depth_limit() {
        let deep = "/a".repeat(MAX_DEPTH + 1);
        bad(&deep);
        assert!(LogicalPath::from_url_path(&"/a".repeat(MAX_DEPTH)).is_ok());
    }

    #[test]
    fn control_chars_rejected() {
        assert!(Name::parse("a\tb").is_err());
        assert!(Name::parse("a\u{7f}b").is_err());
        assert!(Name::parse("").is_err());
    }

    #[test]
    fn split_last() {
        let p = LogicalPath::from_url_path("/a/b").expect("p");
        let (parent, last) = p.split_last().expect("split");
        assert_eq!(last.as_str(), "b");
        assert_eq!(parent.segments().len(), 1);
        assert!(LogicalPath::root().split_last().is_none());
    }
}
