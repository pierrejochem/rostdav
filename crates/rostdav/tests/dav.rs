//! Integration tests for the WebDAV core (M2), driven through the full router.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use rostdav::config::Config;
use rostdav_app::AppState;
use tower::ServiceExt;

const PW: &str = "korrekt-pferd-batterie";

struct Env {
    app: Router,
    _dir: tempfile::TempDir,
}

async fn env() -> Env {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().join("data");
    cfg.limits.max_upload_bytes = 8 * 1024 * 1024;
    let state: AppState = rostdav::build_state(&cfg).await.expect("state");
    state.add_user("anna", PW, false).await.expect("anna");
    state.add_user("bob", PW, false).await.expect("bob");
    Env {
        app: rostdav::http::router(state),
        _dir: dir,
    }
}

struct Res {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Res {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
}

fn basic(user: &str, pw: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pw}"))
    )
}

struct Call<'a> {
    method: &'a str,
    uri: String,
    user: Option<&'a str>,
    body: Vec<u8>,
    headers: Vec<(&'a str, String)>,
}

fn call<'a>(method: &'a str, uri: &str, user: &'a str) -> Call<'a> {
    Call {
        method,
        uri: uri.to_owned(),
        user: Some(user),
        body: Vec::new(),
        headers: Vec::new(),
    }
}

impl<'a> Call<'a> {
    fn body(mut self, b: impl Into<Vec<u8>>) -> Self {
        self.body = b.into();
        self
    }
    fn h(mut self, k: &'a str, v: impl Into<String>) -> Self {
        self.headers.push((k, v.into()));
        self
    }
    async fn send(self, env: &Env) -> Res {
        let mut b = Request::builder()
            .method(Method::from_bytes(self.method.as_bytes()).expect("method"))
            .uri(&self.uri)
            .header("host", "cloud.test");
        if let Some(u) = self.user {
            b = b.header("authorization", basic(u, PW));
        }
        for (k, v) in &self.headers {
            b = b.header(*k, v);
        }
        let res = env
            .app
            .clone()
            .oneshot(b.body(Body::from(self.body)).expect("request"))
            .await
            .expect("response");
        let (parts, body) = res.into_parts();
        Res {
            status: parts.status,
            headers: parts.headers,
            body: body.collect().await.expect("body").to_bytes().to_vec(),
        }
    }
}

const A: &str = "/remote.php/dav/files/anna";
const B: &str = "/remote.php/dav/files/bob";

async fn put(env: &Env, path: &str, body: &str) -> Res {
    call("PUT", path, "anna").body(body).send(env).await
}

fn etag_of(r: &Res) -> String {
    r.header("etag").to_owned()
}

// ---- authentication --------------------------------------------------------

#[tokio::test]
async fn requires_basic_auth() {
    let e = env().await;
    let mut c = call("PROPFIND", &format!("{A}/"), "anna");
    c.user = None;
    let r = c.h("depth", "0").send(&e).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.header("www-authenticate").starts_with("Basic"));
}

#[tokio::test]
async fn wrong_password_and_unknown_user_are_401() {
    let e = env().await;
    let r = Request::builder()
        .method("GET")
        .uri(format!("{A}/f"))
        .header("authorization", basic("anna", "falsch-falsch-falsch"))
        .body(Body::empty())
        .expect("req");
    assert_eq!(e.app.clone().oneshot(r).await.expect("res").status(), 401);
    let r = Request::builder()
        .method("GET")
        .uri(format!("{A}/f"))
        .header("authorization", basic("nobody", PW))
        .body(Body::empty())
        .expect("req");
    assert_eq!(e.app.clone().oneshot(r).await.expect("res").status(), 401);
    for bad in ["Basic !!!", "Basic", "Bearer abc", "Basic YWJj"] {
        let r = Request::builder()
            .method("GET")
            .uri(format!("{A}/f"))
            .header("authorization", bad)
            .body(Body::empty())
            .expect("req");
        assert_eq!(
            e.app.clone().oneshot(r).await.expect("res").status(),
            401,
            "{bad}"
        );
    }
}

#[tokio::test]
async fn options_advertises_class_1_only() {
    let e = env().await;
    let mut c = call("OPTIONS", &format!("{A}/"), "anna");
    c.user = None;
    let r = c.send(&e).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("dav"), "1");
    assert!(r.header("allow").contains("PROPFIND"));
    assert!(!r.header("allow").contains("LOCK"));
}

#[tokio::test]
async fn unsupported_method_is_405() {
    let e = env().await;
    let r = call("LOCK", &format!("{A}/f"), "anna").send(&e).await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    let r = call("PATCH", &format!("{A}/f"), "anna").send(&e).await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
}

// ---- PUT / GET / HEAD ------------------------------------------------------

#[tokio::test]
async fn put_get_roundtrip_with_etags() {
    let e = env().await;
    let r = put(&e, &format!("{A}/hello.txt"), "hello world").await;
    assert_eq!(r.status, StatusCode::CREATED);
    let tag1 = etag_of(&r);
    assert!(tag1.starts_with('"') && tag1.ends_with('"'));

    let g = call("GET", &format!("{A}/hello.txt"), "anna")
        .send(&e)
        .await;
    assert_eq!(g.status, StatusCode::OK);
    assert_eq!(g.text(), "hello world");
    assert_eq!(g.header("etag"), tag1);
    assert_eq!(g.header("content-length"), "11");
    assert_eq!(g.header("content-type"), "text/plain");
    assert!(g.header("last-modified").ends_with("GMT"));
    assert_eq!(g.header("accept-ranges"), "bytes");

    let r2 = put(&e, &format!("{A}/hello.txt"), "changed").await;
    assert_eq!(r2.status, StatusCode::NO_CONTENT);
    assert_ne!(etag_of(&r2), tag1);

    let h = call("HEAD", &format!("{A}/hello.txt"), "anna")
        .send(&e)
        .await;
    assert_eq!(h.status, StatusCode::OK);
    assert_eq!(h.header("content-length"), "7");
    assert!(h.body.is_empty());
}

#[tokio::test]
async fn large_upload_streams_and_roundtrips() {
    let e = env().await;
    let data: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let r = call("PUT", &format!("{A}/big.bin"), "anna")
        .body(data.clone())
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let g = call("GET", &format!("{A}/big.bin"), "anna").send(&e).await;
    assert_eq!(g.body, data);
}

#[tokio::test]
async fn upload_over_limit_is_413_and_leaves_nothing() {
    let e = env().await;
    let r = call("PUT", &format!("{A}/huge"), "anna")
        .body(vec![0u8; 9 * 1024 * 1024])
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    let g = call("GET", &format!("{A}/huge"), "anna").send(&e).await;
    assert_eq!(g.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn put_preconditions() {
    let e = env().await;
    let r = put(&e, &format!("{A}/f"), "1").await;
    let tag = etag_of(&r);

    let r = call("PUT", &format!("{A}/f"), "anna")
        .h("if-none-match", "*")
        .body("2")
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::PRECONDITION_FAILED);

    let r = call("PUT", &format!("{A}/f"), "anna")
        .h("if-match", "\"stale\"")
        .body("2")
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::PRECONDITION_FAILED);

    let r = call("PUT", &format!("{A}/missing"), "anna")
        .h("if-match", "*")
        .body("2")
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::PRECONDITION_FAILED);

    let r = call("PUT", &format!("{A}/f"), "anna")
        .h("if-match", tag)
        .body("3")
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);

    let r = call("PUT", &format!("{A}/new"), "anna")
        .h("if-none-match", "*")
        .body("x")
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
}

#[tokio::test]
async fn put_errors() {
    let e = env().await;
    let r = put(&e, &format!("{A}/nodir/f"), "x").await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    call("MKCOL", &format!("{A}/d"), "anna").send(&e).await;
    let r = put(&e, &format!("{A}/d"), "x").await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    put(&e, &format!("{A}/file"), "x").await;
    let r = put(&e, &format!("{A}/file/child"), "x").await;
    assert_eq!(r.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn get_ranges_and_conditionals() {
    let e = env().await;
    let r = put(&e, &format!("{A}/r.txt"), "0123456789").await;
    let tag = etag_of(&r);
    let get = |range: &'static str| {
        let e = &e;
        async move {
            call("GET", &format!("{A}/r.txt"), "anna")
                .h("range", range)
                .send(e)
                .await
        }
    };
    let p = get("bytes=2-4").await;
    assert_eq!(p.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(p.text(), "234");
    assert_eq!(p.header("content-range"), "bytes 2-4/10");
    assert_eq!(p.header("content-length"), "3");
    assert_eq!(get("bytes=7-").await.text(), "789");
    assert_eq!(get("bytes=-2").await.text(), "89");
    assert_eq!(get("bytes=8-100").await.text(), "89");
    let bad = get("bytes=10-").await;
    assert_eq!(bad.status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(bad.header("content-range"), "bytes */10");
    assert_eq!(get("bytes=0-1,4-5").await.text(), "0123456789");

    let nm = call("GET", &format!("{A}/r.txt"), "anna")
        .h("if-none-match", tag)
        .send(&e)
        .await;
    assert_eq!(nm.status, StatusCode::NOT_MODIFIED);
    assert!(nm.body.is_empty());

    assert_eq!(
        call("GET", &format!("{A}/missing"), "anna")
            .send(&e)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    call("MKCOL", &format!("{A}/dir"), "anna").send(&e).await;
    assert_eq!(
        call("GET", &format!("{A}/dir"), "anna")
            .send(&e)
            .await
            .status,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

// ---- MKCOL / DELETE --------------------------------------------------------

#[tokio::test]
async fn mkcol_cases() {
    let e = env().await;
    assert_eq!(
        call("MKCOL", &format!("{A}/d"), "anna")
            .send(&e)
            .await
            .status,
        201
    );
    assert_eq!(
        call("MKCOL", &format!("{A}/d"), "anna")
            .send(&e)
            .await
            .status,
        405
    );
    assert_eq!(
        call("MKCOL", &format!("{A}/x/y"), "anna")
            .send(&e)
            .await
            .status,
        409
    );
    assert_eq!(
        call("MKCOL", &format!("{A}/"), "anna")
            .send(&e)
            .await
            .status,
        409
    );
    let with_body = call("MKCOL", &format!("{A}/b"), "anna")
        .h("content-length", "3")
        .body("abc")
        .send(&e)
        .await;
    assert_eq!(with_body.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        call("GET", &format!("{A}/b"), "anna").send(&e).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn delete_cases() {
    let e = env().await;
    call("MKCOL", &format!("{A}/d"), "anna").send(&e).await;
    let f = put(&e, &format!("{A}/d/f"), "x").await;
    let stale = call("DELETE", &format!("{A}/d/f"), "anna")
        .h("if-match", "\"stale\"")
        .send(&e)
        .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    let ok = call("DELETE", &format!("{A}/d/f"), "anna")
        .h("if-match", etag_of(&f))
        .send(&e)
        .await;
    assert_eq!(ok.status, StatusCode::NO_CONTENT);
    assert_eq!(
        call("DELETE", &format!("{A}/d/f"), "anna")
            .send(&e)
            .await
            .status,
        404
    );
    put(&e, &format!("{A}/d/g"), "x").await;
    assert_eq!(
        call("DELETE", &format!("{A}/d"), "anna")
            .send(&e)
            .await
            .status,
        204
    );
    assert_eq!(
        call("GET", &format!("{A}/d/g"), "anna")
            .send(&e)
            .await
            .status,
        404
    );
    assert_eq!(
        call("DELETE", &format!("{A}/"), "anna")
            .send(&e)
            .await
            .status,
        409
    );
}

// ---- PROPFIND --------------------------------------------------------------

#[tokio::test]
async fn propfind_depth_0_and_1() {
    let e = env().await;
    call("MKCOL", &format!("{A}/docs"), "anna").send(&e).await;
    put(&e, &format!("{A}/docs/a%20b.txt"), "12345").await;

    let d0 = call("PROPFIND", &format!("{A}/docs"), "anna")
        .h("depth", "0")
        .send(&e)
        .await;
    assert_eq!(d0.status, StatusCode::MULTI_STATUS);
    assert!(d0.header("content-type").starts_with("application/xml"));
    let t = d0.text();
    assert!(
        t.contains("<d:href>/remote.php/dav/files/anna/docs/</d:href>"),
        "{t}"
    );
    assert!(t.contains("<d:collection/>"));
    assert!(!t.contains("a%20b"));

    let d1 = call("PROPFIND", &format!("{A}/docs/"), "anna")
        .h("depth", "1")
        .send(&e)
        .await;
    let t = d1.text();
    assert!(
        t.contains("<d:href>/remote.php/dav/files/anna/docs/a%20b.txt</d:href>"),
        "{t}"
    );
    assert!(t.contains("<d:getcontentlength>5</d:getcontentlength>"));
    assert!(t.contains("<d:getcontenttype>text/plain</d:getcontenttype>"));
    assert!(t.contains("<d:getetag>&quot;"));
    assert_eq!(t.matches("<d:response>").count(), 2);

    let missing = call("PROPFIND", &format!("{A}/nope"), "anna")
        .h("depth", "0")
        .send(&e)
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn propfind_prop_list_unknown_props_and_infinity() {
    let e = env().await;
    put(&e, &format!("{A}/f"), "x").await;
    let body = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
        <d:prop><d:getetag/><oc:fileid/></d:prop></d:propfind>"#;
    let r = call("PROPFIND", &format!("{A}/f"), "anna")
        .h("depth", "0")
        .body(body)
        .send(&e)
        .await;
    let t = r.text();
    assert_eq!(r.status, StatusCode::MULTI_STATUS);
    assert!(t.contains("<d:getetag>"));
    assert!(t.contains("HTTP/1.1 404 Not Found"));
    assert!(t.contains("fileid xmlns:x0=\"http://owncloud.org/ns\""));
    assert!(!t.contains("<d:getcontentlength>"), "only requested props");

    for depth in ["infinity", "2", ""] {
        let r = call("PROPFIND", &format!("{A}/"), "anna")
            .h("depth", depth)
            .send(&e)
            .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{depth:?}");
        assert!(r.text().contains("propfind-finite-depth"));
    }
    // missing Depth header means infinity per RFC 4918
    let r = call("PROPFIND", &format!("{A}/"), "anna").send(&e).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn propfind_rejects_xxe_and_oversized_bodies() {
    let e = env().await;
    let xxe = r#"<?xml version="1.0"?><!DOCTYPE p [<!ENTITY x SYSTEM "file:///etc/passwd">]>
        <d:propfind xmlns:d="DAV:"><d:prop><d:displayname>&x;</d:displayname></d:prop></d:propfind>"#;
    let r = call("PROPFIND", &format!("{A}/"), "anna")
        .h("depth", "0")
        .body(xxe)
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(!r.text().contains("root:"));
    let huge = format!(
        "<d:propfind xmlns:d=\"DAV:\">{}</d:propfind>",
        " ".repeat(100_000)
    );
    let r = call("PROPFIND", &format!("{A}/"), "anna")
        .h("depth", "0")
        .body(huge)
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn folder_etags_change_recursively() {
    let e = env().await;
    call("MKCOL", &format!("{A}/a"), "anna").send(&e).await;
    call("MKCOL", &format!("{A}/a/b"), "anna").send(&e).await;
    call("MKCOL", &format!("{A}/other"), "anna").send(&e).await;
    let tag = |path: String| {
        let e = &e;
        async move {
            let r = call("PROPFIND", &path, "anna")
                .h("depth", "0")
                .body(r#"<d:propfind xmlns:d="DAV:"><d:prop><d:getetag/></d:prop></d:propfind>"#)
                .send(e)
                .await;
            r.text()
        }
    };
    let (root0, a0, b0, o0) = (
        tag(format!("{A}/")).await,
        tag(format!("{A}/a")).await,
        tag(format!("{A}/a/b")).await,
        tag(format!("{A}/other")).await,
    );
    put(&e, &format!("{A}/a/b/f"), "x").await;
    assert_ne!(tag(format!("{A}/")).await, root0);
    assert_ne!(tag(format!("{A}/a")).await, a0);
    assert_ne!(tag(format!("{A}/a/b")).await, b0);
    assert_eq!(tag(format!("{A}/other")).await, o0);
}

// ---- MOVE / COPY -----------------------------------------------------------

#[tokio::test]
async fn move_and_copy() {
    let e = env().await;
    call("MKCOL", &format!("{A}/d"), "anna").send(&e).await;
    put(&e, &format!("{A}/d/f"), "content").await;

    let dest = |p: &str| format!("http://cloud.test{A}/{p}");
    let r = call("COPY", &format!("{A}/d"), "anna")
        .h("destination", dest("d2"))
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert_eq!(
        call("GET", &format!("{A}/d2/f"), "anna")
            .send(&e)
            .await
            .text(),
        "content"
    );

    // existing target without overwrite
    let r = call("COPY", &format!("{A}/d"), "anna")
        .h("destination", dest("d2"))
        .h("overwrite", "F")
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::PRECONDITION_FAILED);
    // with overwrite
    let r = call("COPY", &format!("{A}/d"), "anna")
        .h("destination", dest("d2"))
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);

    let r = call("MOVE", &format!("{A}/d/f"), "anna")
        .h("destination", format!("{A}/moved%20file.txt"))
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert_eq!(
        call("GET", &format!("{A}/moved%20file.txt"), "anna")
            .send(&e)
            .await
            .text(),
        "content"
    );
    assert_eq!(
        call("GET", &format!("{A}/d/f"), "anna")
            .send(&e)
            .await
            .status,
        404
    );

    // errors
    let r = call("MOVE", &format!("{A}/d"), "anna")
        .h("destination", dest("d/inside"))
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "move into itself");
    let r = call("MOVE", &format!("{A}/d"), "anna")
        .h("destination", dest("no/parent"))
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "missing parent");
    let r = call("MOVE", &format!("{A}/nope"), "anna")
        .h("destination", dest("x"))
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = call("MOVE", &format!("{A}/d"), "anna").send(&e).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "no Destination");
    let r = call("MOVE", &format!("{A}/d"), "anna")
        .h("destination", dest("x"))
        .h("overwrite", "maybe")
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn destination_must_stay_on_this_server_and_in_own_tree() {
    let e = env().await;
    put(&e, &format!("{A}/f"), "x").await;
    let r = call("COPY", &format!("{A}/f"), "anna")
        .h("destination", format!("https://evil.test{A}/g"))
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
    // into bob's tree
    let r = call("COPY", &format!("{A}/f"), "anna")
        .h("destination", format!("{B}/g"))
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = call("MOVE", &format!("{A}/f"), "anna")
        .h("destination", format!("{B}/g"))
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // traversal in Destination
    let r = call("MOVE", &format!("{A}/f"), "anna")
        .h("destination", format!("{A}/../bob/g"))
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        call("GET", &format!("{A}/f"), "anna").send(&e).await.status,
        200
    );
    assert_eq!(
        call("GET", &format!("{B}/g"), "bob").send(&e).await.status,
        404
    );
}

// ---- isolation and traversal ----------------------------------------------

#[tokio::test]
async fn second_user_cannot_access_first_users_files() {
    let e = env().await;
    call("MKCOL", &format!("{A}/private"), "anna")
        .send(&e)
        .await;
    put(&e, &format!("{A}/private/secret.txt"), "geheim").await;

    // bob addressing anna's URL space with his own credentials
    for (m, extra) in [
        ("GET", None),
        ("HEAD", None),
        ("PROPFIND", Some("0")),
        ("PROPFIND", Some("1")),
        ("DELETE", None),
        ("MKCOL", None),
        ("PUT", None),
        ("COPY", None),
        ("MOVE", None),
    ] {
        let mut c = call(m, &format!("{A}/private/secret.txt"), "bob");
        if let Some(d) = extra {
            c = c.h("depth", d);
        }
        if matches!(m, "COPY" | "MOVE") {
            c = c.h("destination", format!("{B}/stolen.txt"));
        }
        let r = c.body(if m == "PUT" { "evil" } else { "" }).send(&e).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{m}");
        assert!(!r.text().contains("geheim"));
    }

    // bob's own URL space does not contain anna's data
    assert_eq!(
        call("GET", &format!("{B}/private/secret.txt"), "bob")
            .send(&e)
            .await
            .status,
        404
    );
    // data untouched
    assert_eq!(
        call("GET", &format!("{A}/private/secret.txt"), "anna")
            .send(&e)
            .await
            .text(),
        "geheim"
    );
}

#[tokio::test]
async fn path_traversal_attempts_are_rejected() {
    let e = env().await;
    call("PUT", &format!("{B}/bobsecret"), "bob")
        .body("bobs")
        .send(&e)
        .await;
    for p in [
        "/remote.php/dav/files/anna/../bob/bobsecret",
        "/remote.php/dav/files/anna/%2e%2e/bob/bobsecret",
        "/remote.php/dav/files/anna/%2E%2E%2Fbob%2Fbobsecret",
        "/remote.php/dav/files/anna/a/..%2f..%2fbob/bobsecret",
        "/remote.php/dav/files/anna/%00",
        "/remote.php/dav/files/anna/a%5c..%5cb",
        "/remote.php/dav/files/%2e%2e/etc/passwd",
    ] {
        let r = call("GET", p, "anna").send(&e).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{p}");
        assert!(!r.text().contains("bobs"), "{p}");
    }
}

#[tokio::test]
async fn unicode_and_case_names() {
    let e = env().await;
    // composed vs decomposed é must be the same file
    let r = put(&e, &format!("{A}/caf%C3%A9.txt"), "one").await;
    assert_eq!(r.status, StatusCode::CREATED);
    let r = put(&e, &format!("{A}/cafe%CC%81.txt"), "two").await;
    assert_eq!(
        r.status,
        StatusCode::NO_CONTENT,
        "NFC-equivalent name is the same file"
    );
    assert_eq!(
        call("GET", &format!("{A}/caf%C3%A9.txt"), "anna")
            .send(&e)
            .await
            .text(),
        "two"
    );
    // case is significant
    let r = put(&e, &format!("{A}/CAF%C3%89.txt"), "upper").await;
    assert_eq!(r.status, StatusCode::CREATED);
}
