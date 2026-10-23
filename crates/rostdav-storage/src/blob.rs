use std::fmt;

use rostdav_core::{Error, Result};

/// ID of a blob: 26-character ULID (Crockford base32, uppercase).
///
/// Only validated IDs reach path construction, so no `..` or `/` can end up
/// in the physical path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlobId(String);

impl BlobId {
    pub fn generate() -> Self {
        Self(ulid::Ulid::generate().to_string())
    }

    pub fn parse(s: &str) -> Result<Self> {
        let ok = s.len() == 26 && s.parse::<ulid::Ulid>().is_ok() && s.is_ascii();
        if ok {
            Ok(Self(s.to_ascii_uppercase()))
        } else {
            Err(Error::BadRequest("invalid blob ID"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Result of `LocalStore::put`: stored completely and durably.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBlob {
    pub id: BlobId,
    pub size: u64,
    /// BLAKE3, hex-encoded.
    pub checksum: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_parse() {
        let id = BlobId::generate();
        assert_eq!(BlobId::parse(id.as_str()).expect("parse"), id);
    }

    #[test]
    fn traversal_and_garbage_rejected() {
        for bad in [
            "",
            "..",
            "../../etc/passwd",
            "01ARZ3NDEKTSV4RRFFQ69G5FA/",
            "01ARZ3NDEKTSV4RRFFQ69G5FAVX",
            "01ARZ3NDEKTSV4RRFFQ69G5FA\0",
            "../ARZ3NDEKTSV4RRFFQ69G5FAV",
        ] {
            assert!(BlobId::parse(bad).is_err(), "{bad:?}");
        }
    }
}
