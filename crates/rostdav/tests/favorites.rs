//! Favorites (M6, found with the real Android app): `oc:favorite` via PROPPATCH, PROPFIND and
//! `REPORT oc:filter-files`. Reference: Nextcloud 35.0.2, 2026-10-23 (`docs/compatibility.md`).

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
    body: Vec<u8>,
}

impl Res {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
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
            body: body.collect().await.expect("body").to_bytes().to_vec(),
        }
    }
}

const A: &str = "/remote.php/dav/files/anna";
const B: &str = "/remote.php/dav/files/bob";

async fn put(env: &Env, path: &str, body: &str) -> Res {
    call("PUT", path, "anna").body(body).send(env).await
}

fn patch_body(value: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:set><d:prop><oc:favorite>{value}</oc:favorite></d:prop></d:set></d:propertyupdate>"#
    )
}

const REPORT_BODY: &str = r#"<?xml version="1.0"?><oc:filter-files xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><d:displayname/><oc:fileid/><oc:favorite/></d:prop><oc:filter-rules><oc:favorite>1</oc:favorite></oc:filter-rules></oc:filter-files>"#;

const FAV_PROPFIND: &str = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:favorite/></d:prop></d:propfind>"#;

async fn favorite(e: &Env, user: &str, uri: &str, value: &str) -> Res {
    call("PROPPATCH", uri, user)
        .body(patch_body(value))
        .send(e)
        .await
}

async fn is_favorite(e: &Env, user: &str, uri: &str) -> bool {
    let r = call("PROPFIND", uri, user)
        .h("depth", "0")
        .body(FAV_PROPFIND)
        .send(e)
        .await;
    assert_eq!(r.status, StatusCode::MULTI_STATUS);
    r.text().contains("<oc:favorite>1</oc:favorite>")
}

async fn report(e: &Env, user: &str, uri: &str) -> Res {
    call("REPORT", uri, user).body(REPORT_BODY).send(e).await
}

#[tokio::test]
async fn proppatch_sets_and_clears_the_favorite_like_the_reference() {
    let e = env().await;
    put(&e, &format!("{A}/a.txt"), "x").await;
    assert!(!is_favorite(&e, "anna", &format!("{A}/a.txt")).await);

    let r = favorite(&e, "anna", &format!("{A}/a.txt"), "1").await;
    assert_eq!(r.status, StatusCode::MULTI_STATUS);
    let t = r.text();
    assert!(
        t.contains("<d:href>/remote.php/dav/files/anna/a.txt</d:href>"),
        "{t}"
    );
    assert!(t.contains("<oc:favorite/>"), "{t}");
    assert!(t.contains("HTTP/1.1 200 OK"), "{t}");
    assert!(is_favorite(&e, "anna", &format!("{A}/a.txt")).await);

    let r = favorite(&e, "anna", &format!("{A}/a.txt"), "0").await;
    assert_eq!(r.status, StatusCode::MULTI_STATUS);
    assert!(!is_favorite(&e, "anna", &format!("{A}/a.txt")).await);
}

#[tokio::test]
async fn favorite_shows_in_depth_1_listing_and_for_folders() {
    let e = env().await;
    call("MKCOL", &format!("{A}/docs"), "anna").send(&e).await;
    put(&e, &format!("{A}/docs/a.txt"), "x").await;
    put(&e, &format!("{A}/docs/b.txt"), "y").await;
    favorite(&e, "anna", &format!("{A}/docs/b.txt"), "1").await;
    favorite(&e, "anna", &format!("{A}/docs"), "1").await;
    let r = call("PROPFIND", &format!("{A}/docs/"), "anna")
        .h("depth", "1")
        .body(FAV_PROPFIND)
        .send(&e)
        .await;
    let t = r.text();
    assert_eq!(t.matches("<oc:favorite>1</oc:favorite>").count(), 2, "{t}");
    assert_eq!(t.matches("<oc:favorite>0</oc:favorite>").count(), 1, "{t}");
}

#[tokio::test]
async fn report_lists_the_favorites_with_the_requested_properties() {
    let e = env().await;
    call("MKCOL", &format!("{A}/docs"), "anna").send(&e).await;
    put(&e, &format!("{A}/docs/a.txt"), "x").await;
    put(&e, &format!("{A}/other.txt"), "y").await;
    favorite(&e, "anna", &format!("{A}/docs/a.txt"), "1").await;

    let r = report(&e, "anna", &format!("{A}/")).await;
    assert_eq!(r.status, StatusCode::MULTI_STATUS);
    let t = r.text();
    assert!(
        t.contains("<d:href>/remote.php/dav/files/anna/docs/a.txt</d:href>"),
        "{t}"
    );
    assert!(t.contains("<d:displayname>a.txt</d:displayname>"), "{t}");
    assert!(t.contains("<oc:fileid>"), "{t}");
    assert!(t.contains("<oc:favorite>1</oc:favorite>"), "{t}");
    assert!(!t.contains("other.txt"), "{t}");

    // below another folder nothing matches
    call("MKCOL", &format!("{A}/empty"), "anna").send(&e).await;
    let r = report(&e, "anna", &format!("{A}/empty/")).await;
    assert_eq!(r.status, StatusCode::MULTI_STATUS);
    assert!(!r.text().contains("<d:response>"));
}

#[tokio::test]
async fn favorites_follow_renames_and_vanish_with_deleted_files() {
    let e = env().await;
    put(&e, &format!("{A}/a.txt"), "x").await;
    favorite(&e, "anna", &format!("{A}/a.txt"), "1").await;
    call("MOVE", &format!("{A}/a.txt"), "anna")
        .h("destination", format!("http://cloud.test{A}/b%25c.txt"))
        .send(&e)
        .await;
    let t = report(&e, "anna", &format!("{A}/")).await.text();
    assert!(
        t.contains("<d:href>/remote.php/dav/files/anna/b%25c.txt</d:href>"),
        "{t}"
    );
    assert!(t.contains("<d:displayname>b%c.txt</d:displayname>"), "{t}");

    call("DELETE", &format!("{A}/b%25c.txt"), "anna")
        .send(&e)
        .await;
    let t = report(&e, "anna", &format!("{A}/")).await.text();
    assert!(!t.contains("<d:response>"), "{t}");
}

#[tokio::test]
async fn favorites_belong_to_one_user_and_cannot_be_set_on_foreign_files() {
    let e = env().await;
    put(&e, &format!("{A}/a.txt"), "x").await;
    favorite(&e, "anna", &format!("{A}/a.txt"), "1").await;

    // bob sees nothing of anna's, and cannot touch her files
    let r = report(&e, "bob", &format!("{B}/")).await;
    assert!(!r.text().contains("<d:response>"));
    let r = favorite(&e, "bob", &format!("{A}/a.txt"), "1").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = report(&e, "bob", &format!("{A}/")).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // still only anna's mark
    assert!(is_favorite(&e, "anna", &format!("{A}/a.txt")).await);

    // no credentials
    let mut c = call("PROPPATCH", &format!("{A}/a.txt"), "anna").body(patch_body("0"));
    c.user = None;
    assert_eq!(c.send(&e).await.status, StatusCode::UNAUTHORIZED);
    let mut c = call("REPORT", &format!("{A}/"), "anna").body(REPORT_BODY);
    c.user = None;
    assert_eq!(c.send(&e).await.status, StatusCode::UNAUTHORIZED);
    assert!(is_favorite(&e, "anna", &format!("{A}/a.txt")).await);
}

#[tokio::test]
async fn proppatch_and_report_reject_what_they_do_not_support() {
    let e = env().await;
    put(&e, &format!("{A}/a.txt"), "x").await;

    // other properties are not stored: 403 in their own propstat (the reference stores them)
    let body = r#"<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:set><d:prop><oc:foo>1</oc:foo><oc:favorite>1</oc:favorite></d:prop></d:set></d:propertyupdate>"#;
    let r = call("PROPPATCH", &format!("{A}/a.txt"), "anna")
        .body(body)
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::MULTI_STATUS);
    let t = r.text();
    assert!(
        t.contains("<oc:foo/></d:prop><d:status>HTTP/1.1 403 Forbidden"),
        "{t}"
    );
    assert!(is_favorite(&e, "anna", &format!("{A}/a.txt")).await);

    for bad in [
        "",
        "<d:propfind xmlns:d=\"DAV:\"/>",
        "<!DOCTYPE x [<!ENTITY a \"b\">]><d:propertyupdate xmlns:d=\"DAV:\"/>",
        "<d:propertyupdate xmlns:d=\"DAV:\">",
    ] {
        let r = call("PROPPATCH", &format!("{A}/a.txt"), "anna")
            .body(bad)
            .send(&e)
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let r = favorite(&e, "anna", &format!("{A}/missing"), "1").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // REPORT: only the favorite rule exists
    let other = r#"<?xml version="1.0"?><oc:filter-files xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><d:displayname/></d:prop><oc:filter-rules><oc:systemtag>5</oc:systemtag></oc:filter-rules></oc:filter-files>"#;
    let r = call("REPORT", &format!("{A}/"), "anna")
        .body(other)
        .send(&e)
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = call("REPORT", &format!("{A}/"), "anna").send(&e).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}
