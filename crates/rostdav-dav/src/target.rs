//! Request targets: URL ↔ (user, logical path), `Destination` headers, hrefs.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use rostdav_core::{Error, LogicalPath, Name, Result};

pub const FILES_PREFIX: &str = "/remote.php/dav/files/";
/// Legacy root: always the authenticated user's home (advertised as `core.webdav-root`).
pub const LEGACY_PREFIX: &str = "/remote.php/webdav";

/// Encode everything except unreserved characters.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// A parsed `/remote.php/dav/files/<user>/<path>` URL path.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub user: Name,
    pub path: LogicalPath,
    /// Hrefs are built under the same prefix the request used.
    pub legacy: bool,
}

impl Target {
    /// Parses either URL space. `principal` supplies the user for the legacy
    /// root, where the URL carries none.
    pub fn parse_any(raw_path: &str, principal: &Name) -> Result<Self> {
        if let Some(rest) = raw_path.strip_prefix(LEGACY_PREFIX) {
            if rest.is_empty() || rest.starts_with('/') {
                return Ok(Self {
                    user: principal.clone(),
                    path: LogicalPath::from_url_path(rest)?,
                    legacy: true,
                });
            }
        }
        Self::parse(raw_path)
    }

    /// Parses the raw (still percent-encoded) URL path.
    pub fn parse(raw_path: &str) -> Result<Self> {
        let rest = raw_path
            .strip_prefix(FILES_PREFIX)
            .ok_or(Error::BadRequest("unexpected path"))?;
        let (user_raw, path_raw) = rest.split_once('/').unwrap_or((rest, ""));
        let user = percent_decode_str(user_raw)
            .decode_utf8()
            .map_err(|_| Error::BadRequest("invalid user name encoding"))?;
        Ok(Self {
            user: Name::parse(&user)?,
            path: LogicalPath::from_url_path(path_raw)?,
            legacy: false,
        })
    }

    /// Href for a path below this target's user; directories end with `/`.
    pub fn href_for(&self, path: &LogicalPath, is_dir: bool) -> String {
        let mut out = String::new();
        if self.legacy {
            out.push_str(LEGACY_PREFIX);
        } else {
            out.push_str(FILES_PREFIX);
            out.extend(utf8_percent_encode(self.user.as_str(), SEGMENT));
        }
        out.push('/');
        for (i, seg) in path.segments().iter().enumerate() {
            if i > 0 {
                out.push('/');
            }
            out.extend(utf8_percent_encode(seg.as_str(), SEGMENT));
        }
        if is_dir && !path.is_root() {
            out.push('/');
        }
        out
    }
}

/// Resolves a `Destination` header to a target on *this* server.
///
/// Absolute URIs must name the same authority as the `Host` header; a foreign
/// host is reported as [`DestinationError::Foreign`] (RFC 4918: 502).
pub fn parse_destination(
    value: &str,
    host: Option<&str>,
    principal: &Name,
) -> Result<Target, DestinationError> {
    let path = if let Some(rest) = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
    {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        match host {
            Some(h) if h.eq_ignore_ascii_case(authority) => {}
            _ => return Err(DestinationError::Foreign),
        }
        format!("/{path}")
    } else if value.starts_with('/') {
        value.to_owned()
    } else {
        return Err(DestinationError::Invalid(Error::BadRequest(
            "invalid Destination",
        )));
    };
    if path.contains(['?', '#']) {
        return Err(DestinationError::Invalid(Error::BadRequest(
            "invalid Destination",
        )));
    }
    Target::parse_any(&path, principal).map_err(DestinationError::Invalid)
}

#[derive(Debug)]
pub enum DestinationError {
    Foreign,
    Invalid(Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_and_path() {
        let t = Target::parse("/remote.php/dav/files/anna/a%20b/c.txt").expect("t");
        assert_eq!(t.user.as_str(), "anna");
        assert_eq!(t.path.segments()[0].as_str(), "a b");
        let root = Target::parse("/remote.php/dav/files/anna").expect("t");
        assert!(root.path.is_root());
        let root = Target::parse("/remote.php/dav/files/anna/").expect("t");
        assert!(root.path.is_root());
    }

    #[test]
    fn traversal_variants_rejected() {
        for p in [
            "/remote.php/dav/files/anna/../bob/x",
            "/remote.php/dav/files/anna/%2e%2e/bob",
            "/remote.php/dav/files/anna/a%2f..%2fb",
            "/remote.php/dav/files/%2e%2e/x",
            "/remote.php/dav/files/an%2Fna/x",
            "/remote.php/dav/files/anna/%00",
            "/elsewhere/x",
        ] {
            assert!(Target::parse(p).is_err(), "{p}");
        }
    }

    #[test]
    fn href_encoding_roundtrip() {
        let t = Target::parse("/remote.php/dav/files/anna").expect("t");
        let p = LogicalPath::from_url_path("/a%20b/%C3%A4%23%3F").expect("p");
        let href = t.href_for(&p, true);
        assert_eq!(href, "/remote.php/dav/files/anna/a%20b/%C3%A4%23%3F/");
        assert_eq!(Target::parse(&href).expect("t").path, p);
        assert_eq!(
            t.href_for(&LogicalPath::root(), true),
            "/remote.php/dav/files/anna/"
        );
    }

    fn anna() -> Name {
        Name::parse("anna").expect("name")
    }

    #[test]
    fn legacy_root_maps_to_the_principal() {
        let t = Target::parse_any("/remote.php/webdav/a%20b/c", &anna()).expect("t");
        assert!(t.legacy);
        assert_eq!(t.user.as_str(), "anna");
        assert_eq!(t.path.segments().len(), 2);
        assert_eq!(t.href_for(&t.path, false), "/remote.php/webdav/a%20b/c");
        assert!(
            Target::parse_any("/remote.php/webdav", &anna())
                .expect("t")
                .path
                .is_root()
        );
        assert!(Target::parse_any("/remote.php/webdav/../x", &anna()).is_err());
        // a look-alike prefix is not the legacy root
        assert!(Target::parse_any("/remote.php/webdavx/a", &anna()).is_err());
    }

    #[test]
    fn destination_same_host_relative_and_foreign() {
        let ok = parse_destination(
            "https://cloud.example/remote.php/dav/files/anna/x",
            Some("cloud.example"),
            &anna(),
        )
        .expect("dest");
        assert_eq!(ok.path.segments()[0].as_str(), "x");
        assert!(parse_destination("/remote.php/dav/files/anna/x", None, &anna()).is_ok());
        assert!(matches!(
            parse_destination(
                "https://evil.example/remote.php/dav/files/anna/x",
                Some("cloud.example"),
                &anna()
            ),
            Err(DestinationError::Foreign)
        ));
        assert!(matches!(
            parse_destination(
                "https://cloud.example/remote.php/dav/files/anna/x",
                None,
                &anna()
            ),
            Err(DestinationError::Foreign)
        ));
        for bad in [
            "x",
            "/remote.php/dav/files/anna/x?y=1",
            "ftp://h/x",
            "//host/x",
        ] {
            assert!(parse_destination(bad, Some("h"), &anna()).is_err(), "{bad}");
        }
        // userinfo trick must not match the host
        assert!(matches!(
            parse_destination(
                "https://cloud.example@evil.example/remote.php/dav/files/anna/x",
                Some("cloud.example"),
                &anna()
            ),
            Err(DestinationError::Foreign)
        ));
    }
}
