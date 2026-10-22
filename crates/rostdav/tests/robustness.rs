//! Phase 5: robustness. Hostile paths, XML bodies and header values must never
//! cause a server error, a panic, a hang or a file outside the data layout.
//! Deterministic pseudo-random inputs (the seed is printed on failure), so a
//! failure can be reproduced; `cargo fuzz` targets can be added on top of this.

use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use rostdav::config::Config;
use tower::ServiceExt;

const PW: &str = "korrekt-pferd-batterie";

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap_or(0)
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

struct Env {
    counter: std::sync::atomic::AtomicU32,
    app: Router,
    dir: tempfile::TempDir,
    auth: String,
}

async fn env() -> Env {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().join("data");
    let state = rostdav::build_state(&cfg).await.expect("state");
    state.add_user("anna", PW, false).await.expect("user");
    let ip = "192.0.2.9".parse().expect("ip");
    let anna = state.authenticate("anna", PW, ip).await.expect("auth");
    let app_pw = state.device_create(&anna, "phone").await.expect("device");
    let lp = |p: &str| rostdav_core::LogicalPath::from_url_path(p).expect("path");
    state.mkcol(&anna, &lp("Docs")).await.expect("mkcol");
    state
        .put(
            &anna,
            &lp("Docs/a.txt"),
            &b"hello"[..],
            None,
            &rostdav_meta::WriteCondition::None,
        )
        .await
        .expect("put");
    Env {
        counter: std::sync::atomic::AtomicU32::new(1),
        app: rostdav::http::router_with(state, &rostdav::http::HttpOptions::from_config(&cfg)),
        dir,
        auth: format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("anna:{app_pw}"))
        ),
    }
}

async fn send(
    e: &Env,
    method: &str,
    uri: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
) -> (StatusCode, Duration) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "cloud.test")
        .header("authorization", &e.auth);
    for (k, v) in headers {
        b = b.header(k.as_str(), v.as_str());
    }
    let Ok(mut req) = b.body(Body::from(body)) else {
        // the HTTP layer of the test client refused it (invalid URI or header): nothing reached the server
        return (StatusCode::BAD_REQUEST, Duration::ZERO);
    };
    // every request comes from its own address: the brute-force limiter must not hide the
    // code behind it (its behaviour is tested elsewhere)
    let n = e.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [10, (n >> 16) as u8, (n >> 8) as u8, n as u8],
            4000,
        ))));
    let t = Instant::now();
    let r = e
        .app
        .clone()
        .oneshot(req)
        .await
        .expect("the service never fails");
    let (p, body) = r.into_parts();
    let _ = body.collect().await.expect("body");
    (p.status, t.elapsed())
}

const PIECES: &[&str] = &[
    "a",
    "b",
    "Docs",
    "a.txt",
    "..",
    ".",
    "%2e%2e",
    "%2E",
    "%2f",
    "%2F",
    "%5c",
    "%00",
    "%0a",
    "%25",
    "%252e",
    "%",
    "%zz",
    "%c0%af",
    "%e2%80%ae",
    "\\",
    "~",
    "//",
    "ä",
    "ü",
    "日本",
    "🙂",
    " ",
    "a b",
    "..;",
    "....",
    "a.",
    ".a",
    "CON",
    "con.txt",
    ":",
    "*",
    "?",
    "#",
    "\u{202e}",
];

fn hostile_path(r: &mut Rng, base: &str) -> String {
    let mut p = base.to_owned();
    for _ in 0..=r.below(6) {
        p.push('/');
        if r.below(40) == 0 {
            p.push_str(&"x".repeat(300));
        } else {
            p.push_str(r.pick(PIECES));
        }
    }
    // only characters a client could really put into a URI
    p.chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '_' })
        .collect::<String>()
        .replace(' ', "%20")
}

/// Everything below the data directory must be in the known layout.
fn check_layout(dir: &std::path::Path) {
    fn walk(p: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
            let path = e.path();
            if path.is_dir() {
                walk(&path, out);
            }
            out.push(path);
        }
    }
    let data = dir.join("data");
    let mut all = Vec::new();
    walk(dir, &mut all);
    for p in all {
        assert!(
            p.starts_with(&data),
            "{} is outside the data directory",
            p.display()
        );
    }
    for top in std::fs::read_dir(&data).expect("data").flatten() {
        let n = top.file_name().to_string_lossy().into_owned();
        assert!(
            ["blobs", "tmp", "uploads", "db", "totp.key"].contains(&n.as_str()),
            "unexpected entry {n} in the data directory"
        );
    }
}

#[tokio::test]
async fn hostile_paths_never_cause_server_errors_or_stray_files() {
    let e = env().await;
    let seed = 0x5EED_0001_u64;
    let mut r = Rng(seed);
    let methods = [
        "GET",
        "HEAD",
        "PUT",
        "DELETE",
        "MKCOL",
        "PROPFIND",
        "MOVE",
        "COPY",
        "OPTIONS",
        "PROPPATCH",
        "LOCK",
        "REPORT",
        "SEARCH",
        "TRACE",
        "FOO",
    ];
    let bases = [
        "/remote.php/dav/files/anna",
        "/remote.php/webdav",
        "/remote.php/dav/uploads/anna",
        "/remote.php/dav/versions/anna/versions",
        "/remote.php/dav/trashbin/anna/trash",
        "/public.php/webdav",
        "/remote.php/dav/files/anna/Docs",
    ];
    let mut worst = Duration::ZERO;
    for i in 0..1500 {
        let m = *r.pick(&methods);
        let base = *r.pick(&bases);
        let path = hostile_path(&mut r, base);
        let mut headers = vec![];
        if matches!(m, "MOVE" | "COPY") {
            let dest = hostile_path(&mut r, "http://cloud.test/remote.php/dav/files/anna");
            headers.push(("destination".to_owned(), dest));
            headers.push((
                "overwrite".to_owned(),
                r.pick(&["T", "F", "x", ""]).to_string(),
            ));
        }
        if m == "PROPFIND" {
            headers.push((
                "depth".to_owned(),
                r.pick(&["0", "1", "infinity", "2", "-1", "x", ""])
                    .to_string(),
            ));
        }
        let body = if matches!(m, "PUT") {
            b"data".to_vec()
        } else {
            Vec::new()
        };
        let (status, took) = send(&e, m, &path, &headers, body).await;
        worst = worst.max(took);
        assert!(
            status.as_u16() < 500,
            "seed {seed:#x} iteration {i}: {m} {path} -> {status}"
        );
        assert!(
            took < Duration::from_secs(5),
            "seed {seed:#x} iteration {i}: {m} {path} took {took:?}"
        );
    }
    check_layout(e.dir.path());
    // the seeded data survived
    let (s, _) = send(
        &e,
        "GET",
        "/remote.php/dav/files/anna/Docs/a.txt",
        &[],
        vec![],
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "the original file is still there (worst request {worst:?})"
    );
}

const XML_BASE: &[&str] = &[
    r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getetag/></d:prop></d:propfind>"#,
    r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:allprop/></d:propfind>"#,
    r#"<d:propertyupdate xmlns:d="DAV:"><d:set><d:prop><d:displayname>x</d:displayname></d:prop></d:set></d:propertyupdate>"#,
    r#"<oc:filter-files xmlns:oc="http://owncloud.org/ns"><oc:filter-rules><oc:favorite>1</oc:favorite></oc:filter-rules></oc:filter-files>"#,
];

fn mutate_xml(r: &mut Rng, base: &str) -> Vec<u8> {
    let mut b = base.as_bytes().to_vec();
    match r.below(12) {
        0 => b.truncate(r.below(b.len().max(1))),
        1 => {
            let i = r.below(b.len().max(1));
            b.insert(i, *r.pick(&[b'<', b'>', b'&', b'"', 0u8, 0xff, b'\'']));
        }
        2 => b = format!(r#"<!DOCTYPE x [<!ENTITY a "{}">]>{}"#, "A".repeat(1000), base).into_bytes(),
        3 => b = format!(
            r#"<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><d:propfind xmlns:d="DAV:"><d:prop><d:getetag>&lol3;</d:getetag></d:prop></d:propfind>"#
        )
        .into_bytes(),
        4 => b = format!(r#"<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><d:propfind xmlns:d="DAV:"><d:prop><d:{}/></d:prop></d:propfind>"#, "&xxe;").into_bytes(),
        5 => b = format!("{}{}", "<a>".repeat(5000), "</a>".repeat(5000)).into_bytes(),
        6 => b = format!(r#"<d:propfind xmlns:d="DAV:"><d:prop>{}</d:prop></d:propfind>"#, "<d:x/>".repeat(20_000)).into_bytes(),
        7 => b = format!(r#"<d:propfind xmlns:d="DAV:" {}><d:allprop/></d:propfind>"#, (0..2000).map(|i| format!("a{i}=\"1\"")).collect::<Vec<_>>().join(" ")).into_bytes(),
        8 => b = vec![0xef, 0xbb, 0xbf, b'<', 0xc3, 0x28, b'>'],
        9 => b = "\u{feff}".as_bytes().iter().chain(b.iter()).copied().collect(),
        10 => b = (0..r.below(2000)).map(|_| (r.next() & 0xff) as u8).collect(),
        _ => {}
    }
    b
}

#[tokio::test]
async fn hostile_xml_bodies_are_rejected_quickly_without_expansion() {
    let e = env().await;
    let seed = 0x5EED_0002_u64;
    let mut r = Rng(seed);
    let mut seen_ok = false;
    let mut seen_rejected = false;
    for i in 0..800 {
        let method = *r.pick(&["PROPFIND", "PROPPATCH", "REPORT", "SEARCH"]);
        let base = *r.pick(XML_BASE);
        let body = mutate_xml(&mut r, base);
        let headers = vec![
            ("depth".to_owned(), "1".to_owned()),
            ("content-type".to_owned(), "application/xml".to_owned()),
        ];
        let (status, took) = send(
            &e,
            method,
            "/remote.php/dav/files/anna/Docs",
            &headers,
            body,
        )
        .await;
        assert!(
            status.as_u16() < 500,
            "seed {seed:#x} iteration {i}: {method} -> {status}"
        );
        assert!(
            took < Duration::from_secs(3),
            "seed {seed:#x} iteration {i}: {method} took {took:?}"
        );
        seen_ok |= status.is_success();
        seen_rejected |= status.is_client_error();
    }
    assert!(
        seen_ok && seen_rejected,
        "the generator should produce both valid and invalid bodies"
    );
    // an entity must never be expanded into the answer, a file must never be read
    let bomb = br#"<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><d:propfind xmlns:d="DAV:"><d:prop><d:displayname>&xxe;</d:displayname></d:prop></d:propfind>"#;
    let r = e
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("PROPFIND")
                .uri("/remote.php/dav/files/anna/Docs")
                .header("host", "cloud.test")
                .header("authorization", &e.auth)
                .header("depth", "1")
                .body(Body::from(bomb.to_vec()))
                .expect("req"),
        )
        .await
        .expect("resp");
    let status = r.status();
    let text =
        String::from_utf8_lossy(&r.into_body().collect().await.expect("b").to_bytes()).into_owned();
    assert!(status.is_client_error(), "{status}");
    assert!(
        !text.contains("root:"),
        "a local file leaked through an entity"
    );
    check_layout(e.dir.path());
}

#[tokio::test]
async fn hostile_header_values_never_cause_server_errors() {
    let e = env().await;
    let seed = 0x5EED_0003_u64;
    let mut r = Rng(seed);
    let names = [
        "if-match",
        "if-none-match",
        "if-modified-since",
        "range",
        "x-oc-mtime",
        "oc-checksum",
        "oc-total-length",
        "x-oc-mtime",
        "overwrite",
        "depth",
        "destination",
        "content-length",
        "content-range",
        "if",
        "timeout",
        "lock-token",
        "x-requested-with",
        "ocs-apirequest",
        "x-forwarded-for",
        "accept-language",
        "cookie",
    ];
    let values = [
        "",
        "*",
        "\"x\"",
        "W/\"x\"",
        "bytes=0-",
        "bytes=5-2",
        "bytes=-0",
        "bytes=99999999999999999999-",
        "bytes=0-0,1-1,2-2,3-3",
        "-1",
        "NaN",
        "1e99",
        "9999999999999999999999",
        "0",
        "SHA1:zzz",
        "SHA1:",
        "MD5:abc",
        ":",
        "Thu, 01 Jan 1970 00:00:00 GMT",
        "garbage",
        "(<opaquelocktoken:x>)",
        "Second-99999999999",
        "Infinite",
        "../../etc/passwd",
        "http://evil.test/remote.php/dav/files/anna/x",
        "//",
        "%",
        "a\u{00e4}",
    ];
    let mut sent = 0;
    for i in 0..1200 {
        let m = *r.pick(&[
            "GET", "HEAD", "PUT", "PROPFIND", "MOVE", "COPY", "DELETE", "MKCOL",
        ]);
        let mut headers = vec![];
        for _ in 0..=r.below(4) {
            let n = (*r.pick(&names)).to_owned();
            let v = (*r.pick(&values)).to_owned();
            headers.push((n, v));
        }
        // a header the client library refuses is skipped, not a server problem
        headers.retain(|(n, v)| {
            axum::http::HeaderName::from_bytes(n.as_bytes()).is_ok()
                && axum::http::HeaderValue::from_str(v).is_ok()
        });
        let path = *r.pick(&[
            "/remote.php/dav/files/anna/Docs/a.txt",
            "/remote.php/dav/files/anna/Docs/",
            "/remote.php/dav/files/anna/Docs/new.txt",
            "/remote.php/dav/files/anna/",
        ]);
        let (status, took) = send(&e, m, path, &headers, b"x".to_vec()).await;
        sent += 1;
        assert!(
            status.as_u16() < 500,
            "seed {seed:#x} iteration {i}: {m} {path} {headers:?} -> {status}"
        );
        assert!(
            took < Duration::from_secs(3),
            "seed {seed:#x} iteration {i}: took {took:?}"
        );
    }
    assert!(sent > 1000);
    check_layout(e.dir.path());
}
