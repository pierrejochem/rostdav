//! Profile pictures: one PNG or JPEG per user, shown in the web interface and through the
//! Nextcloud avatar endpoint (`/index.php/avatar/<user>/<size>`).
//!
//! The picture is not decoded or resized: the server checks that the bytes are what they claim
//! to be (signature and image header) and keeps them as they are. SVG and other types are
//! refused, because they can carry scripts.

use rostdav_core::{Error, Name, Result};
use serde_json::json;

use crate::AppState;
use crate::auth::Principal;

/// Largest picture in bytes.
pub const MAX_AVATAR_BYTES: usize = 256 * 1024;
const MIN_SIDE: u32 = 16;
const MAX_SIDE: u32 = 1024;

/// A picture ready to be sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Avatar {
    pub mime: &'static str,
    pub data: Vec<u8>,
    pub etag: String,
}

impl Avatar {
    /// Header lines for the answer: type, validator and the restrictions for a user-supplied file.
    pub fn headers(&self) -> [(&'static str, String); 5] {
        [
            ("content-type", self.mime.to_owned()),
            ("etag", format!("\"{}\"", self.etag)),
            ("cache-control", "private, max-age=300".to_owned()),
            (
                "content-security-policy",
                "default-src 'none'; sandbox".to_owned(),
            ),
            ("x-content-type-options", "nosniff".to_owned()),
        ]
    }

    /// Whether an `If-None-Match` header names this version.
    pub fn matches(&self, if_none_match: &str) -> bool {
        if_none_match
            .split(',')
            .any(|t| t.trim().trim_start_matches("W/").trim_matches('"') == self.etag)
    }
}

/// `(mime type, width, height)` of a PNG or JPEG, read from its header.
fn sniff(b: &[u8]) -> Result<(&'static str, u32, u32)> {
    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";
    let bad = || Error::Invalid("The file is not a PNG or JPEG picture".to_owned());
    let be16 = |i: usize| {
        b.get(i..i + 2)
            .map(|s| u32::from(u16::from_be_bytes([s[0], s[1]])))
    };
    let be32 = |i: usize| {
        b.get(i..i + 4)
            .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    };
    if b.starts_with(PNG) {
        // the first chunk is IHDR: length (4), "IHDR", width (4), height (4)
        if b.get(12..16) != Some(b"IHDR") {
            return Err(bad());
        }
        return Ok((
            "image/png",
            be32(16).ok_or_else(bad)?,
            be32(20).ok_or_else(bad)?,
        ));
    }
    if b.starts_with(&[0xFF, 0xD8]) {
        // walk the segments up to the first start-of-frame marker
        let mut i = 2;
        while i + 4 <= b.len() {
            if b[i] != 0xFF {
                return Err(bad());
            }
            let marker = b[i + 1];
            if marker == 0xFF {
                i += 1; // fill byte
                continue;
            }
            let len = be16(i + 2).ok_or_else(bad)? as usize;
            let sof = matches!(marker, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF);
            if sof {
                return Ok((
                    "image/jpeg",
                    be16(i + 7).ok_or_else(bad)?,
                    be16(i + 5).ok_or_else(bad)?,
                ));
            }
            if marker == 0xDA || len < 2 {
                return Err(bad()); // scan data before any frame header
            }
            i += 2 + len;
        }
    }
    Err(bad())
}

impl AppState {
    /// Sets the caller's picture.
    pub async fn avatar_set(&self, p: &Principal, bytes: &[u8]) -> Result<()> {
        Self::require_full(p)?;
        if bytes.len() > MAX_AVATAR_BYTES {
            return Err(Error::Invalid(
                "The picture is larger than 256 KiB".to_owned(),
            ));
        }
        let (mime, w, h) = sniff(bytes)?;
        if !(MIN_SIDE..=MAX_SIDE).contains(&w) || !(MIN_SIDE..=MAX_SIDE).contains(&h) {
            return Err(Error::Invalid(
                "The picture must be between 16 and 1024 pixels on each side".to_owned(),
            ));
        }
        let etag = &blake3::hash(bytes).to_hex()[..16];
        self.inner
            .db
            .avatar_set(p.user_id, mime, bytes, etag)
            .await?;
        self.audit(
            &p.name,
            "user.avatar_set",
            "",
            None,
            json!({"bytes": bytes.len()}),
        )
        .await;
        Ok(())
    }

    pub async fn avatar_remove(&self, p: &Principal) -> Result<()> {
        Self::require_full(p)?;
        if self.inner.db.avatar_delete(p.user_id).await? {
            self.audit(&p.name, "user.avatar_removed", "", None, json!({}))
                .await;
        }
        Ok(())
    }

    /// The picture of `user`, if there is one. Any signed-in user may fetch it, as in Nextcloud;
    /// an unknown user and a user without a picture look the same.
    pub async fn avatar(&self, p: &Principal, user: &str) -> Result<Option<Avatar>> {
        Self::require_full(p)?;
        let Ok(name) = Name::parse(user) else {
            return Ok(None);
        };
        let Some(u) = self.inner.db.find_user(name.as_str()).await? else {
            return Ok(None);
        };
        Ok(self.inner.db.avatar_get(u.id).await?.map(|a| Avatar {
            mime: if a.mime == "image/png" {
                "image/png"
            } else {
                "image/jpeg"
            },
            data: a.data,
            etag: a.etag,
        }))
    }

    /// The version of the caller's profile picture, for the address of the image in a page
    /// (`/avatar/<user>/64?v=<version>`: a new picture is a new address, so it shows at once).
    pub async fn avatar_version(&self, p: &Principal) -> Option<String> {
        self.inner.db.avatar_etag(p.user_id).await.ok().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest header a PNG/JPEG checker needs: not a viewable picture.
    fn png(w: u32, h: u32) -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
        v.extend(w.to_be_bytes());
        v.extend(h.to_be_bytes());
        v.extend([8, 6, 0, 0, 0]);
        v
    }

    fn jpeg(w: u16, h: u16) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 4, 0, 0]; // SOI, a 2-byte APP0
        v.extend([0xFF, 0xC0, 0, 11, 8]);
        v.extend(h.to_be_bytes());
        v.extend(w.to_be_bytes());
        v.extend([1, 1, 0x11, 0]);
        v
    }

    #[test]
    fn reads_size_and_type_from_the_header() {
        assert_eq!(sniff(&png(300, 200)).expect("png"), ("image/png", 300, 200));
        assert_eq!(
            sniff(&jpeg(640, 480)).expect("jpeg"),
            ("image/jpeg", 640, 480)
        );
    }

    #[test]
    fn refuses_everything_else() {
        for bad in [
            &b""[..],
            b"GIF89a....",
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
            b"\x89PNG\r\n\x1a\n",
            b"\x89PNG\r\n\x1a\n\0\0\0\x0dXXXX\0\0\0\x10\0\0\0\x10",
            &[0xFF, 0xD8],
            &[0xFF, 0xD8, 0xFF, 0xDA, 0, 2],
            &[0xFF, 0xD8, 0x00, 0x00, 0, 0, 0, 0],
            b"%PDF-1.7",
        ] {
            assert!(sniff(bad).is_err(), "{bad:?}");
        }
        // a truncated frame header does not panic
        for n in 0..jpeg(1, 1).len() {
            let _ = sniff(&jpeg(32, 32)[..n]);
        }
        for n in 0..png(1, 1).len() {
            let _ = sniff(&png(32, 32)[..n]);
        }
    }

    #[test]
    fn etag_matching() {
        let a = Avatar {
            mime: "image/png",
            data: vec![],
            etag: "abc".into(),
        };
        assert!(a.matches("\"abc\""));
        assert!(a.matches("W/\"abc\""));
        assert!(a.matches("\"x\", \"abc\""));
        assert!(!a.matches("\"abd\"") && !a.matches(""));
    }
}
