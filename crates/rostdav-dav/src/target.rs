//! Request targets: URL ↔ (user, logical path), `Destination` headers, hrefs.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use rostdav_core::{Error, LogicalPath, Name, Result};

pub const FILES_PREFIX: &str = "/remote.php/dav/files/";
/// Legacy root: always the authenticated user's home (advertised as `core.webdav-root`).
pub const LEGACY_PREFIX: &str = "/remote.php/webdav";
/// Public links: the shared node is the root (`Basic <token>:<password>`).
pub const PUBLIC_PREFIX: &str = "/public.php/webdav";

/// Encode everything except unreserved characters.
pub(crate) const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
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
    /// `public.php/webdav`: only valid for link principals.
    pub public: bool,
}

impl Target {
    /// Parses either URL space. `principal` supplies the user for the legacy
    /// root, where the URL carries none.
    pub fn parse_any(raw_path: &str, principal: &Name) -> Result<Self> {
        if let Some(rest) = raw_path.strip_prefix(PUBLIC_PREFIX) {
            if rest.is_empty() || rest.starts_with('/') {
                return Ok(Self {
                    user: principal.clone(),
                    path: LogicalPath::from_url_path(rest)?,
                    legacy: false,
                    public: true,
                });
            }
        }
        if let Some(rest) = raw_path.strip_prefix(LEGACY_PREFIX) {
            if rest.is_empty() || rest.starts_with('/') {
                return Ok(Self {
                    user: principal.clone(),
                    path: LogicalPath::from_url_path(rest)?,
                    legacy: true,
                    public: false,
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
            public: false,
        })
    }

    /// Href for a path below this target's user; directories end with `/`.
    pub fn href_for(&self, path: &LogicalPath, is_dir: bool) -> String {
        let mut out = String::new();
        if self.public {
            out.push_str(PUBLIC_PREFIX);
        } else if self.legacy {
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

/// Resolves a `Destination` header to a target on this server.
///
/// Only the path counts. The reference server ignores the host of an absolute
/// URI (`04-webdav/25-move-foreign-host`), and behind a reverse proxy it often
/// differs from the one the client used. Nothing is fetched from that host.
pub fn parse_destination(value: &str, principal: &Name) -> Result<Target> {
    let path = if let Some(rest) = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
    {
        let (_authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        format!("/{path}")
    } else if value.starts_with('/') {
        value.to_owned()
    } else {
        return Err(Error::BadRequest("invalid Destination"));
    };
    if path.contains(['?', '#']) || path.starts_with("//") {
        return Err(Error::BadRequest("invalid Destination"));
    }
    Target::parse_any(&path, principal)
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
    fn public_root_maps_to_the_link() {
        let t = Target::parse_any("/public.php/webdav/a%20b/c", &anna()).expect("t");
        assert!(t.public && !t.legacy);
        assert_eq!(t.href_for(&t.path, false), "/public.php/webdav/a%20b/c");
        assert_eq!(
            t.href_for(&LogicalPath::root(), true),
            "/public.php/webdav/"
        );
        assert!(
            Target::parse_any("/public.php/webdav", &anna())
                .expect("t")
                .path
                .is_root()
        );
        assert!(Target::parse_any("/public.php/webdav/../x", &anna()).is_err());
        assert!(Target::parse_any("/public.php/webdavx/a", &anna()).is_err());
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
    fn destination_uses_only_the_path() {
        let ok = parse_destination("https://cloud.example/remote.php/dav/files/anna/x", &anna())
            .expect("dest");
        assert_eq!(ok.path.segments()[0].as_str(), "x");
        // the host is not interpreted at all
        let other = parse_destination(
            "http://evil.example:81/remote.php/dav/files/anna/x",
            &anna(),
        )
        .expect("dest");
        assert_eq!(other.path, ok.path);
        assert!(parse_destination("/remote.php/dav/files/anna/x", &anna()).is_ok());
        assert!(
            parse_destination("/remote.php/webdav/x", &anna())
                .expect("legacy")
                .legacy
        );
        for bad in [
            "x",
            "/remote.php/dav/files/anna/x?y=1",
            "ftp://h/x",
            "//host/x",
            "http://h",
            "/other/x",
            "/remote.php/dav/files/anna/../bob/x",
            "https://h/remote.php/dav/files/anna/%2e%2e/x",
        ] {
            assert!(parse_destination(bad, &anna()).is_err(), "{bad}");
        }
    }
}
