//! M10: trash through the Nextcloud trashbin endpoint, checked against the
//! recorded fixtures (`tests/fixtures/nextcloud/11-trash/`).

use std::collections::BTreeMap;
use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use quick_xml::NsReader;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use rostdav::config::Config;
use serde_json::Value;
use tower::ServiceExt;

const PW: &str = "korrekt-pferd-batterie";
const API: &str = "/ocs/v2.php/apps/files_sharing/api/v1";

struct Env {
    app: Router,
    state: rostdav_app::AppState,
    _dir: tempfile::TempDir,
}

async fn env_with(f: impl FnOnce(&mut Config)) -> Env {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().join("data");
    f(&mut cfg);
    let state = rostdav::build_state(&cfg).await.expect("state");
    for n in ["anna", "bob", "carl"] {
        state.add_user(n, PW, false).await.expect("user");
    }
    Env {
        app: rostdav::http::router_with(
            state.clone(),
            &rostdav::http::HttpOptions::from_config(&cfg),
        ),
        state,
        _dir: dir,
    }
}

async fn env() -> Env {
    env_with(|_| {}).await
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
    fn h(&self, n: &str) -> &str {
        self.headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
}

async fn send(
    e: &Env,
    auth: Option<(&str, &str)>,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: impl Into<Vec<u8>>,
) -> Res {
    let mut b = Request::builder()
        .method(Method::from_bytes(method.as_bytes()).expect("method"))
        .uri(uri)
        .header("host", "cloud.test");
    if let Some((u, p)) = auth {
        b = b.header(
            "authorization",
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
            ),
        );
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let res = e
        .app
        .clone()
        .oneshot(b.body(Body::from(body.into())).expect("req"))
        .await
        .expect("res");
    let (parts, body) = res.into_parts();
    Res {
        status: parts.status,
        headers: parts.headers,
        body: body.collect().await.expect("body").to_bytes().to_vec(),
    }
}

async fn dav(
    e: &Env,
    user: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: impl Into<Vec<u8>>,
) -> Res {
    send(
        e,
        Some((user, PW)),
        method,
        &format!("/remote.php/dav/files/{user}{path}"),
        headers,
        body,
    )
    .await
}

async fn tb(
    e: &Env,
    user: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: impl Into<Vec<u8>>,
) -> Res {
    send(
        e,
        Some((user, PW)),
        method,
        &format!("/remote.php/dav/trashbin/{user}{path}"),
        headers,
        body,
    )
    .await
}

fn fixture(path: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/nextcloud")
        .join(format!("{path}.json"));
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p:?}: {e}")))
        .expect("json")
}

fn fx_status(path: &str) -> u16 {
    fixture(path)["response"]["status"]
        .as_u64()
        .expect("status") as u16
}

fn fx_text(path: &str) -> String {
    fixture(path)["response"]["body"]["text"]
        .as_str()
        .unwrap_or("")
        .to_owned()
}

fn exception(body: &str) -> String {
    body.split("<s:exception>")
        .nth(1)
        .and_then(|r| r.split("</s:exception>").next())
        .unwrap_or("")
        .to_owned()
}

/// `{key: {property: status}}`; key = last path segment with deletion times as `N`.
fn prop_statuses(xml: &str) -> BTreeMap<String, BTreeMap<String, u16>> {
    let mut rd = NsReader::from_str(xml);
    let mut out: BTreeMap<String, BTreeMap<String, u16>> = BTreeMap::new();
    let (mut href, mut in_href, mut in_status) = (String::new(), false, false);
    let mut props: Vec<String> = Vec::new();
    let (mut in_prop, mut depth) = (false, 0usize);
    loop {
        let (ns, ev) = rd.read_resolved_event().expect("xml");
        let is_dav = matches!(&ns, ResolveResult::Bound(n) if n.as_ref() == "DAV:");
        match ev {
            Event::Start(e) => {
                let local = e.local_name().as_ref().to_owned();
                if in_prop {
                    if depth == 0 {
                        props.push(local);
                    }
                    depth += 1;
                } else if is_dav && local == "prop" {
                    in_prop = true;
                    depth = 0;
                } else if is_dav && local == "href" {
                    in_href = true;
                    href.clear();
                } else if is_dav && local == "status" {
                    in_status = true;
                }
            }
            Event::Empty(e) => {
                if in_prop && depth == 0 {
                    props.push(e.local_name().as_ref().to_owned());
                }
            }
            Event::Text(t) => {
                let s = t.xml10_content().into_owned();
                if in_href {
                    href.push_str(&s);
                } else if in_status {
                    let code: u16 = s
                        .split_whitespace()
                        .nth(1)
                        .and_then(|c| c.parse().ok())
                        .expect("status");
                    let last = href
                        .trim_end_matches('/')
                        .rsplit('/')
                        .next()
                        .unwrap_or("")
                        .to_owned();
                    let last = if last == "admin" || last == "anna" {
                        "<user>".to_owned()
                    } else {
                        last
                    };
                    let key = match last.rsplit_once(".d") {
                        Some((n, t)) if t.bytes().all(|b| b.is_ascii_digit()) && !t.is_empty() => {
                            format!("{n}.dN")
                        }
                        _ => last,
                    };
                    for p in props.drain(..) {
                        out.entry(key.clone()).or_default().insert(p, code);
                    }
                }
            }
            Event::End(e) => {
                let local = e.local_name().as_ref().to_owned();
                if in_prop {
                    if depth == 0 {
                        in_prop = false;
                    } else {
                        depth -= 1;
                    }
                } else if local == "href" {
                    in_href = false;
                } else if local == "status" {
                    in_status = false;
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    out
}

const PROPS: &str = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns"><d:prop>
<nc:trashbin-filename/><nc:trashbin-original-location/><nc:trashbin-deletion-time/><nc:trashbin-title/><nc:trashbin-deleted-by-id/><nc:trashbin-deleted-by-display-name/>
<d:getlastmodified/><d:getcontentlength/><d:getcontenttype/><d:resourcetype/><d:getetag/><oc:fileid/><oc:id/><oc:size/><oc:permissions/><nc:has-preview/></d:prop></d:propfind>"#;

const X: [(&str, &str); 2] = [("depth", "1"), ("content-type", "application/xml")];

/// `(entry names in the listing, response)`
async fn listing(e: &Env, user: &str) -> (Vec<String>, Res) {
    let r = tb(e, user, "PROPFIND", "/trash", &X, PROPS).await;
    assert_eq!(r.status, 207, "{}", r.text());
    let names = r
        .text()
        .split("<d:href>")
        .skip(2)
        .map(|s| {
            s.split("</d:href>")
                .next()
                .unwrap_or("")
                .rsplit('/')
                .find(|p| !p.is_empty())
                .unwrap_or("")
                .to_owned()
        })
        .collect();
    (names, r)
}

async fn used(e: &Env, user: &str) -> i64 {
    let q = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:quota-used-bytes/></d:prop></d:propfind>"#;
    let r = dav(e, user, "PROPFIND", "/", &[("depth", "0")], q).await;
    r.text()
        .split("<d:quota-used-bytes>")
        .nth(1)
        .and_then(|s| s.split('<').next())
        .expect("q")
        .parse()
        .expect("n")
}

async fn restore(e: &Env, user: &str, entry: &str) -> Res {
    tb(
        e,
        user,
        "MOVE",
        &format!("/trash/{entry}"),
        &[(
            "destination",
            &format!("http://cloud.test/remote.php/dav/trashbin/{user}/restore/{entry}"),
        )],
        "",
    )
    .await
}

// ---- structure and properties -------------------------------------------------------

#[tokio::test]
async fn deleting_moves_to_the_trash_and_the_listing_matches_the_reference() {
    let e = env().await;
    dav(&e, "anna", "MKCOL", "/Docs", &[], "").await;
    dav(
        &e,
        "anna",
        "PUT",
        "/Docs/a.txt",
        &[("x-oc-mtime", "1700000100")],
        "file a, second version\n",
    )
    .await;
    dav(&e, "anna", "MKCOL", "/Docs/sub", &[], "").await;
    dav(&e, "anna", "PUT", "/Docs/sub/inner.txt", &[], "inner\n").await;
    let before = used(&e, "anna").await;

    // the root of the trash
    let root = tb(&e, "anna", "PROPFIND", "/", &X, PROPS).await;
    assert_eq!(
        prop_statuses(&root.text()),
        prop_statuses(&fx_text("11-trash/10-trash-root-d1-empty"))
    );
    let d0 = tb(
        &e,
        "anna",
        "PROPFIND",
        "/",
        &[("depth", "0"), ("content-type", "application/xml")],
        PROPS,
    )
    .await;
    assert_eq!(
        prop_statuses(&d0.text()),
        prop_statuses(&fx_text("11-trash/09-trash-root-d0"))
    );
    assert_eq!(
        prop_statuses(&tb(&e, "anna", "PROPFIND", "/trash", &X, PROPS).await.text()).len(),
        1,
        "empty trash: only the collection"
    );

    // delete a file and a folder
    assert_eq!(
        dav(&e, "anna", "DELETE", "/Docs/a.txt", &[], "")
            .await
            .status,
        204
    );
    assert_eq!(
        dav(&e, "anna", "DELETE", "/Docs/sub", &[], "").await.status,
        204
    );
    assert_eq!(
        dav(&e, "anna", "GET", "/Docs/a.txt", &[], "").await.status,
        fx_status("11-trash/12-get-deleted")
    );
    assert_eq!(
        dav(&e, "anna", "GET", "/Docs/sub/inner.txt", &[], "")
            .await
            .status,
        404
    );
    assert!(
        !dav(&e, "anna", "PROPFIND", "/Docs", &[("depth", "1")], "")
            .await
            .text()
            .contains("a.txt")
    );
    assert_eq!(
        used(&e, "anna").await,
        before,
        "space keeps counting while it is in the trash"
    );

    let (names, r) = listing(&e, "anna").await;
    assert_eq!(names.len(), 2, "{names:?}");
    let file_entry = names
        .iter()
        .find(|n| n.starts_with("a.txt.d"))
        .expect("file")
        .clone();
    let dir_entry = names
        .iter()
        .find(|n| n.starts_with("sub.d"))
        .expect("folder")
        .clone();

    // same properties found / not found as the reference, for a file and for a folder
    let got = prop_statuses(&r.text());
    let want = prop_statuses(&fx_text("11-trash/28-trash-list-with-folder"));
    assert_eq!(
        got["a.txt.dN"],
        want.iter()
            .find(|(k, _)| k.as_str() == "{{item}}")
            .expect("ref file")
            .1
            .clone()
    );
    assert_eq!(got["sub.dN"], want["sub.dN"]);

    // values
    let t = r.text();
    let item = |e: &str| {
        t.split(&format!("<d:href>/remote.php/dav/trashbin/anna/trash/{e}"))
            .nth(1)
            .expect("entry")
            .split("</d:response>")
            .next()
            .unwrap_or("")
            .to_owned()
    };
    let f = item(&file_entry);
    assert!(f.contains("<nc:trashbin-filename>a.txt</nc:trashbin-filename>"));
    assert!(
        f.contains("<nc:trashbin-original-location>Docs/a.txt</nc:trashbin-original-location>")
    );
    assert!(f.contains("<nc:trashbin-title>Docs/a.txt</nc:trashbin-title>"));
    assert!(f.contains("<nc:trashbin-deleted-by-id>anna</nc:trashbin-deleted-by-id>"));
    assert!(
        f.contains("<d:getcontentlength>23</d:getcontentlength>")
            && f.contains("<d:getcontenttype>text/plain</d:getcontenttype>")
    );
    assert!(f.contains("<oc:permissions>GD</oc:permissions>"));
    assert!(f.contains("<oc:size>23</oc:size>"));
    let time: i64 = f
        .split("<nc:trashbin-deletion-time>")
        .nth(1)
        .and_then(|s| s.split('<').next())
        .expect("t")
        .parse()
        .expect("n");
    assert!(file_entry.ends_with(&format!(".d{time}")));
    assert!(f.contains(&format!(
        "<d:getlastmodified>{}</d:getlastmodified>",
        httpdate::fmt_http_date(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(time.unsigned_abs())
        )
    )));
    let id_plain = f
        .split("<oc:fileid>")
        .nth(1)
        .and_then(|s| s.split('<').next())
        .expect("id")
        .to_owned();
    assert!(
        f.contains(&format!("<oc:id>{id_plain}</oc:id>")),
        "plain numbers in the trash"
    );
    let d = item(&dir_entry);
    assert!(d.contains("<d:resourcetype><d:collection/></d:resourcetype>"));
    assert!(d.contains("<oc:size>6</oc:size>"), "{d}");
    assert!(d.contains(&format!(
        "<d:getetag>{}</d:getetag>",
        dir_entry.rsplit_once(".d").expect("d").1
    )));
    assert!(
        dir_entry.len() > 4 && t.contains(&format!("trash/{dir_entry}/")),
        "folders end with a slash"
    );

    // allprop / no body: the reference's sets
    let plain = tb(&e, "anna", "PROPFIND", "/trash", &[("depth", "1")], "").await;
    let ps = prop_statuses(&plain.text());
    let want = prop_statuses(&fx_text("11-trash/16-trash-list-no-body"));
    assert_eq!(ps["a.txt.dN"], want["{{item}}"]);
}

#[tokio::test]
async fn reading_trashed_files_and_folders() {
    let e = env().await;
    dav(&e, "anna", "MKCOL", "/Docs", &[], "").await;
    dav(
        &e,
        "anna",
        "PUT",
        "/Docs/a.txt",
        &[],
        "file a, second version\n",
    )
    .await;
    dav(&e, "anna", "MKCOL", "/Docs/sub", &[], "").await;
    dav(&e, "anna", "PUT", "/Docs/sub/inner.txt", &[], "inner\n").await;
    dav(&e, "anna", "DELETE", "/Docs/a.txt", &[], "").await;
    dav(&e, "anna", "DELETE", "/Docs/sub", &[], "").await;
    let (names, _) = listing(&e, "anna").await;
    let file = names
        .iter()
        .find(|n| n.starts_with("a.txt"))
        .expect("f")
        .clone();
    let dir = names
        .iter()
        .find(|n| n.starts_with("sub"))
        .expect("d")
        .clone();

    let g = tb(&e, "anna", "GET", &format!("/trash/{file}"), &[], "").await;
    assert_eq!(
        (g.status, g.text().as_str()),
        (StatusCode::OK, "file a, second version\n")
    );
    assert_eq!(g.h("content-length"), "23");
    assert_eq!(g.h("content-type"), "text/plain");
    let h = tb(&e, "anna", "HEAD", &format!("/trash/{file}"), &[], "").await;
    assert_eq!((h.status, h.h("content-length")), (StatusCode::OK, "23"));
    assert!(h.body.is_empty());
    let r = tb(
        &e,
        "anna",
        "GET",
        &format!("/trash/{file}"),
        &[("range", "bytes=0-3")],
        "",
    )
    .await;
    assert_eq!(
        (r.status.as_u16(), r.text().as_str(), r.h("content-range")),
        (206, "file", "bytes 0-3/23")
    );
    assert_eq!(fx_status("11-trash/21-trash-get-range"), 206);
    assert_eq!(
        tb(
            &e,
            "anna",
            "GET",
            &format!("/trash/{file}"),
            &[("range", "bytes=99-")],
            ""
        )
        .await
        .status,
        416
    );

    // into a trashed folder
    let l = tb(
        &e,
        "anna",
        "PROPFIND",
        &format!("/trash/{dir}"),
        &[("depth", "1")],
        "",
    )
    .await;
    assert_eq!(l.status, 207);
    assert!(
        l.text()
            .contains("<d:href>/remote.php/dav/trashbin/anna/trash/")
            && l.text().contains("/inner.txt</d:href>"),
        "{}",
        l.text()
    );
    assert_eq!(
        tb(
            &e,
            "anna",
            "GET",
            &format!("/trash/{dir}/inner.txt"),
            &[],
            ""
        )
        .await
        .text(),
        "inner\n"
    );
    assert_eq!(
        tb(
            &e,
            "anna",
            "GET",
            &format!("/trash/{dir}/nope.txt"),
            &[],
            ""
        )
        .await
        .status,
        404
    );
    assert_eq!(
        tb(&e, "anna", "GET", &format!("/trash/{dir}"), &[], "")
            .await
            .status,
        405,
        "folders are not downloadable"
    );
    // items inside cannot be restored or purged on their own
    assert_eq!(
        restore(&e, "anna", &format!("{dir}/inner.txt"))
            .await
            .status,
        403
    );
    assert_eq!(
        tb(
            &e,
            "anna",
            "DELETE",
            &format!("/trash/{dir}/inner.txt"),
            &[],
            ""
        )
        .await
        .status,
        403
    );
}

#[tokio::test]
async fn errors_and_access_rules() {
    let e = env().await;
    dav(&e, "anna", "PUT", "/a.txt", &[], "secret a").await;
    dav(&e, "anna", "DELETE", "/a.txt", &[], "").await;
    let (names, _) = listing(&e, "anna").await;
    let entry = names[0].clone();

    // missing
    let r = tb(&e, "anna", "GET", "/trash/nothere.d1", &[], "").await;
    assert_eq!(
        r.status.as_u16(),
        fx_status("11-trash/22-trash-get-missing")
    );
    assert_eq!(
        exception(&r.text()),
        exception(&fx_text("11-trash/22-trash-get-missing"))
    );
    for bad in [
        "nothere",
        "a.txt.d",
        "a.txt.dxx",
        "a.txt.d-5",
        &format!("{}x", entry),
    ] {
        assert_eq!(
            tb(&e, "anna", "GET", &format!("/trash/{bad}"), &[], "")
                .await
                .status,
            404,
            "{bad}"
        );
    }
    // read-only apart from restore and purge (fixtures 24, 25)
    for (m, p, fx) in [
        ("PUT", "/trash/new.txt", "11-trash/24-trash-put"),
        ("MKCOL", "/trash/newdir", "11-trash/25-trash-mkcol"),
    ] {
        let r = tb(&e, "anna", m, p, &[], "x").await;
        assert_eq!(
            (r.status.as_u16(), exception(&r.text())),
            (fx_status(fx), exception(&fx_text(fx))),
            "{m}"
        );
    }
    assert_eq!(
        tb(
            &e,
            "anna",
            "COPY",
            &format!("/trash/{entry}"),
            &[("destination", "/x")],
            ""
        )
        .await
        .status,
        403
    );
    assert_eq!(
        tb(
            &e,
            "anna",
            "PUT",
            &format!("/trash/{entry}"),
            &[],
            "overwrite"
        )
        .await
        .status,
        403
    );
    assert_eq!(tb(&e, "anna", "DELETE", "/", &[], "").await.status, 403);
    assert_eq!(
        tb(&e, "anna", "DELETE", "/restore", &[], "").await.status,
        403
    );

    // other users: their own trash is empty, anna's is not reachable
    let (bobs, _) = listing(&e, "bob").await;
    assert!(bobs.is_empty());
    let r = send(
        &e,
        Some(("bob", PW)),
        "PROPFIND",
        "/remote.php/dav/trashbin/anna/trash",
        &X,
        PROPS,
    )
    .await;
    assert_eq!(
        (r.status.as_u16(), fx_status("11-trash/23-trash-other-user")),
        (404, 404)
    );
    for (m, p) in [
        ("GET", format!("/trash/{entry}")),
        ("DELETE", format!("/trash/{entry}")),
        ("MOVE", format!("/trash/{entry}")),
    ] {
        let r = send(
            &e,
            Some(("bob", PW)),
            m,
            &format!("/remote.php/dav/trashbin/anna{p}"),
            &[],
            "",
        )
        .await;
        assert_eq!(r.status, 404, "{m}");
    }
    // bob using his own URL with anna's entry name
    assert_eq!(
        tb(&e, "bob", "GET", &format!("/trash/{entry}"), &[], "")
            .await
            .status,
        404
    );
    assert_eq!(restore(&e, "bob", &entry).await.status, 404);
    assert_eq!(
        tb(&e, "bob", "DELETE", &format!("/trash/{entry}"), &[], "")
            .await
            .status,
        404
    );
    assert_eq!(
        listing(&e, "anna").await.0.len(),
        1,
        "nothing happened to anna's item"
    );
    // unauthenticated, infinity
    assert_eq!(
        send(
            &e,
            None,
            "PROPFIND",
            "/remote.php/dav/trashbin/anna/trash",
            &X,
            ""
        )
        .await
        .status,
        401
    );
    assert_eq!(
        tb(
            &e,
            "anna",
            "PROPFIND",
            "/trash",
            &[("depth", "infinity")],
            ""
        )
        .await
        .status,
        403
    );
    // a link or a received share cannot reach it either
    assert_eq!(
        send(
            &e,
            Some(("sometoken", "")),
            "PROPFIND",
            "/remote.php/dav/trashbin/anna/trash",
            &X,
            ""
        )
        .await
        .status,
        401
    );
}

#[tokio::test]
async fn the_same_name_deleted_twice_gives_two_entries() {
    let e = env().await;
    for body in ["first", "second"] {
        dav(&e, "anna", "PUT", "/a.txt", &[], body).await;
        assert_eq!(
            dav(&e, "anna", "DELETE", "/a.txt", &[], "").await.status,
            204
        );
    }
    let (names, _) = listing(&e, "anna").await;
    assert_eq!(names.len(), 2);
    assert_ne!(names[0], names[1]);
    let mut contents = Vec::new();
    for n in &names {
        contents.push(
            tb(&e, "anna", "GET", &format!("/trash/{n}"), &[], "")
                .await
                .text(),
        );
    }
    contents.sort();
    assert_eq!(contents, ["first", "second"]);
}

// ---- restore and purge -----------------------------------------------------------------

#[tokio::test]
async fn restore_puts_files_folders_versions_and_ids_back() {
    let e = env().await;
    dav(&e, "anna", "MKCOL", "/Docs", &[], "").await;
    dav(
        &e,
        "anna",
        "PUT",
        "/Docs/a.txt",
        &[("x-oc-mtime", "1700000000")],
        "file a\n",
    )
    .await;
    dav(
        &e,
        "anna",
        "PUT",
        "/Docs/a.txt",
        &[("x-oc-mtime", "1700000100")],
        "file a, second version\n",
    )
    .await;
    dav(&e, "anna", "MKCOL", "/Docs/sub", &[], "").await;
    dav(&e, "anna", "PUT", "/Docs/sub/inner.txt", &[], "inner\n").await;
    let fid = |path: &'static str| {
        let e = &e;
        async move {
            let q = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>"#;
            dav(e, "anna", "PROPFIND", path, &[("depth", "0")], q)
                .await
                .text()
                .split("<oc:fileid>")
                .nth(1)
                .and_then(|s| s.split('<').next())
                .expect("id")
                .to_owned()
        }
    };
    let (id_a, id_sub) = (fid("/Docs/a.txt").await, fid("/Docs/sub").await);
    let space = used(&e, "anna").await;
    dav(&e, "anna", "DELETE", "/Docs/a.txt", &[], "").await;
    dav(&e, "anna", "DELETE", "/Docs/sub", &[], "").await;
    let vdav = format!("/remote.php/dav/versions/anna/versions/{id_a}");
    assert_eq!(
        send(
            &e,
            Some(("anna", PW)),
            "PROPFIND",
            &vdav,
            &[("depth", "1")],
            ""
        )
        .await
        .status,
        404,
        "versions are hidden with the file"
    );
    let (names, _) = listing(&e, "anna").await;
    let file = names
        .iter()
        .find(|n| n.starts_with("a.txt"))
        .expect("f")
        .clone();
    let dir = names
        .iter()
        .find(|n| n.starts_with("sub"))
        .expect("d")
        .clone();

    // wrong or missing destinations are refused and change nothing (the reference moves anywhere / answers 500)
    let r = tb(&e, "anna", "MOVE", &format!("/trash/{file}"), &[], "").await;
    assert_eq!(
        (
            r.status.as_u16(),
            fx_status("11-trash/32-restore-no-destination")
        ),
        (400, 500)
    );
    for bad in [
        "http://cloud.test/remote.php/dav/files/anna/Docs/elsewhere.txt".to_owned(),
        "http://cloud.test/remote.php/dav/trashbin/anna/trash/x".to_owned(),
        "http://cloud.test/remote.php/dav/trashbin/bob/restore/x".to_owned(),
        "/remote.php/dav/trashbin/anna/restore".to_owned(),
        "nowhere".to_owned(),
    ] {
        let r = tb(
            &e,
            "anna",
            "MOVE",
            &format!("/trash/{file}"),
            &[("destination", &bad)],
            "",
        )
        .await;
        assert_eq!(r.status, 400, "{bad}");
    }
    assert_eq!(
        dav(&e, "anna", "GET", "/Docs/elsewhere.txt", &[], "")
            .await
            .status,
        404
    );
    assert_eq!(listing(&e, "anna").await.0.len(), 2);

    // the real restore
    assert_eq!(restore(&e, "anna", &file).await.status, 201);
    assert_eq!(fx_status("11-trash/39-restore-name-taken"), 201);
    let g = dav(&e, "anna", "GET", "/Docs/a.txt", &[], "").await;
    assert_eq!(g.text(), "file a, second version\n");
    assert_eq!(
        g.h("last-modified"),
        "Tue, 14 Nov 2023 22:15:00 GMT",
        "the content's own mtime, not the deletion time"
    );
    assert_eq!(fid("/Docs/a.txt").await, id_a, "same file ID");
    let v = send(
        &e,
        Some(("anna", PW)),
        "PROPFIND",
        &vdav,
        &[("depth", "1")],
        "",
    )
    .await;
    assert_eq!(
        v.text().matches("<d:response>").count(),
        3,
        "collection, the old version and the live content"
    );
    assert_eq!(
        restore(&e, "anna", &file).await.status,
        404,
        "restoring twice"
    );
    assert_eq!(
        tb(&e, "anna", "GET", &format!("/trash/{file}"), &[], "")
            .await
            .status,
        404
    );

    assert_eq!(restore(&e, "anna", &dir).await.status, 201);
    assert_eq!(
        dav(&e, "anna", "GET", "/Docs/sub/inner.txt", &[], "")
            .await
            .text(),
        "inner\n"
    );
    assert_eq!(fid("/Docs/sub").await, id_sub);
    assert!(listing(&e, "anna").await.0.is_empty());
    assert_eq!(used(&e, "anna").await, space, "nothing leaked or got lost");
}

#[tokio::test]
async fn restore_deals_with_taken_names_and_missing_parents() {
    let e = env().await;
    dav(&e, "anna", "MKCOL", "/Docs", &[], "").await;
    dav(&e, "anna", "PUT", "/Docs/a.txt", &[], "old").await;
    dav(&e, "anna", "DELETE", "/Docs/a.txt", &[], "").await;
    dav(&e, "anna", "PUT", "/Docs/a.txt", &[], "new").await;
    let (names, _) = listing(&e, "anna").await;
    assert_eq!(restore(&e, "anna", &names[0]).await.status, 201);
    assert_eq!(
        dav(&e, "anna", "GET", "/Docs/a.txt", &[], "").await.text(),
        "new",
        "the live file is never replaced"
    );
    assert_eq!(
        dav(&e, "anna", "GET", "/Docs/a%20(restored).txt", &[], "")
            .await
            .text(),
        "old"
    );

    // the parent folder is gone: the item goes to the root (fixtures 45, 46)
    dav(&e, "anna", "PUT", "/Docs/b.txt", &[], "bbb").await;
    dav(&e, "anna", "DELETE", "/Docs/b.txt", &[], "").await;
    dav(&e, "anna", "DELETE", "/Docs", &[], "").await;
    let (names, _) = listing(&e, "anna").await;
    let b = names
        .iter()
        .find(|n| n.starts_with("b.txt"))
        .expect("b")
        .clone();
    assert_eq!(restore(&e, "anna", &b).await.status, 201);
    assert_eq!(
        dav(&e, "anna", "GET", "/b.txt", &[], "").await.text(),
        "bbb"
    );
    assert_eq!(fx_status("11-trash/45-restore-parent-missing"), 201);
    // the folder returns later and the earlier file stays where it went
    let d = listing(&e, "anna")
        .await
        .0
        .into_iter()
        .find(|n| n.starts_with("Docs"))
        .expect("docs");
    assert_eq!(restore(&e, "anna", &d).await.status, 201);
    assert_eq!(
        dav(&e, "anna", "GET", "/Docs/a.txt", &[], "").await.text(),
        "new"
    );
    assert_eq!(
        dav(&e, "anna", "GET", "/b.txt", &[], "").await.text(),
        "bbb"
    );
}

#[tokio::test]
async fn purging_frees_the_space() {
    let e = env().await;
    dav(&e, "anna", "PUT", "/keep.txt", &[], "kk").await;
    dav(&e, "anna", "PUT", "/x.bin", &[], vec![1u8; 100]).await;
    dav(&e, "anna", "PUT", "/x.bin", &[], vec![2u8; 100]).await; // makes a version
    dav(&e, "anna", "PUT", "/y.bin", &[], vec![3u8; 50]).await;
    assert_eq!(used(&e, "anna").await, 2 + 200 + 50);
    dav(&e, "anna", "DELETE", "/x.bin", &[], "").await;
    dav(&e, "anna", "DELETE", "/y.bin", &[], "").await;
    assert_eq!(used(&e, "anna").await, 252, "still counted");
    let (names, _) = listing(&e, "anna").await;
    let x = names
        .iter()
        .find(|n| n.starts_with("x.bin"))
        .expect("x")
        .clone();

    let r = tb(&e, "anna", "DELETE", &format!("/trash/{x}"), &[], "").await;
    assert_eq!(r.status, 204);
    assert_eq!(used(&e, "anna").await, 52, "file and version are gone");
    let again = tb(&e, "anna", "DELETE", &format!("/trash/{x}"), &[], "").await;
    assert_eq!(again.status, 404);
    let r = tb(&e, "anna", "DELETE", "/trash", &[], "").await;
    assert_eq!(
        (r.status.as_u16(), fx_status("11-trash/49-empty-trash")),
        (204, 204)
    );
    assert_eq!(used(&e, "anna").await, 2);
    assert!(listing(&e, "anna").await.0.is_empty());
    assert_eq!(
        dav(&e, "anna", "GET", "/keep.txt", &[], "").await.text(),
        "kk"
    );
    // the blobs are gone from disk
    assert_eq!(
        e.state.collect_garbage().await.expect("gc"),
        0,
        "purging already collected them"
    );
}

#[tokio::test]
async fn the_trash_counts_toward_the_quota() {
    let e = env().await;
    e.state.set_quota("anna", Some(100)).await.expect("quota");
    dav(&e, "anna", "PUT", "/big.bin", &[], vec![0u8; 80]).await;
    dav(&e, "anna", "DELETE", "/big.bin", &[], "").await;
    let r = dav(&e, "anna", "PUT", "/other.bin", &[], vec![0u8; 80]).await;
    assert_eq!(r.status, 507, "deleting did not free the space");
    tb(&e, "anna", "DELETE", "/trash", &[], "").await;
    assert_eq!(
        dav(&e, "anna", "PUT", "/other.bin", &[], vec![0u8; 80])
            .await
            .status,
        201
    );
}

// ---- shares, links, configuration -----------------------------------------------------------

#[tokio::test]
async fn deletions_in_shares_go_to_the_owners_trash() {
    let e = env().await;
    dav(&e, "anna", "MKCOL", "/Shared", &[], "").await;
    dav(&e, "anna", "PUT", "/Shared/one.txt", &[], "one").await;
    let form = [
        ("ocs-apirequest", "true"),
        ("content-type", "application/x-www-form-urlencoded"),
    ];
    let r = send(
        &e,
        Some(("anna", PW)),
        "POST",
        &format!("{API}/shares?format=json"),
        &form,
        "path=/Shared&shareType=0&shareWith=bob&permissions=15",
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        dav(&e, "bob", "DELETE", "/Shared/one.txt", &[], "")
            .await
            .status,
        204
    );
    assert!(
        listing(&e, "bob").await.0.is_empty(),
        "the recipient's trash stays empty"
    );
    let (names, r) = listing(&e, "anna").await;
    assert_eq!(names.len(), 1);
    assert!(
        r.text()
            .contains("<nc:trashbin-deleted-by-id>bob</nc:trashbin-deleted-by-id>")
    );
    assert!(
        r.text().contains(
            "<nc:trashbin-original-location>Shared/one.txt</nc:trashbin-original-location>"
        )
    );
    assert_eq!(
        restore(&e, "bob", &names[0]).await.status,
        404,
        "only the owner restores"
    );
    assert_eq!(restore(&e, "anna", &names[0]).await.status, 201);
    assert_eq!(
        dav(&e, "bob", "GET", "/Shared/one.txt", &[], "")
            .await
            .text(),
        "one",
        "visible in the share again"
    );

    // the owner deletes the shared folder: the share sleeps, restoring wakes it up
    dav(&e, "anna", "DELETE", "/Shared", &[], "").await;
    assert!(
        !dav(&e, "bob", "PROPFIND", "/", &[("depth", "1")], "")
            .await
            .text()
            .contains("Shared")
    );
    assert_eq!(
        send(
            &e,
            Some(("anna", PW)),
            "GET",
            &format!("{API}/shares?format=json"),
            &[("ocs-apirequest", "true")],
            ""
        )
        .await
        .text()
        .matches("\"id\"")
        .count(),
        0
    );
    let (names, _) = listing(&e, "anna").await;
    assert_eq!(restore(&e, "anna", &names[0]).await.status, 201);
    assert!(
        dav(&e, "bob", "PROPFIND", "/", &[("depth", "1")], "")
            .await
            .text()
            .contains("Shared")
    );
    assert_eq!(
        dav(&e, "bob", "GET", "/Shared/one.txt", &[], "")
            .await
            .text(),
        "one"
    );
    assert_eq!(
        send(
            &e,
            Some(("anna", PW)),
            "GET",
            &format!("{API}/shares?format=json"),
            &[("ocs-apirequest", "true")],
            ""
        )
        .await
        .text()
        .matches("\"id\"")
        .count(),
        1
    );
}

#[tokio::test]
async fn editable_links_delete_into_the_owners_trash() {
    let e = env().await;
    dav(&e, "anna", "MKCOL", "/Pub", &[], "").await;
    dav(&e, "anna", "PUT", "/Pub/f.txt", &[], "f").await;
    let form = [
        ("ocs-apirequest", "true"),
        ("content-type", "application/x-www-form-urlencoded"),
    ];
    let r = send(
        &e,
        Some(("anna", PW)),
        "POST",
        &format!("{API}/shares?format=json"),
        &form,
        "path=/Pub&shareType=3&permissions=15",
    )
    .await;
    let token = serde_json::from_slice::<Value>(&r.body).expect("j")["ocs"]["data"]["token"]
        .as_str()
        .expect("t")
        .to_owned();
    let d = send(
        &e,
        Some((&token, "")),
        "DELETE",
        "/public.php/webdav/f.txt",
        &[],
        "",
    )
    .await;
    assert_eq!(d.status, 204);
    let (names, _) = listing(&e, "anna").await;
    assert_eq!(names.len(), 1);
    assert_eq!(
        dav(&e, "anna", "GET", "/Pub/f.txt", &[], "").await.status,
        404
    );
    // links have no trash of their own
    let r = send(
        &e,
        Some((&token, "")),
        "PROPFIND",
        "/remote.php/dav/trashbin/anna/trash",
        &X,
        PROPS,
    )
    .await;
    assert!(r.status.is_client_error());
}

#[tokio::test]
async fn capabilities_and_the_switch() {
    let on = env().await;
    let caps = |e: &Env| {
        let req = Request::builder()
            .uri("/ocs/v2.php/cloud/capabilities?format=json")
            .header("ocs-apirequest", "true")
            .header(
                "authorization",
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(format!("anna:{PW}"))
                ),
            )
            .body(Body::empty())
            .expect("req");
        let app = e.app.clone();
        async move {
            let res = app.oneshot(req).await.expect("res");
            serde_json::from_slice::<Value>(&res.into_body().collect().await.expect("b").to_bytes())
                .expect("json")["ocs"]["data"]["capabilities"]["files"]
                .clone()
        }
    };
    let files = caps(&on).await;
    assert_eq!(
        (
            files["undelete"].as_bool(),
            files["delete_from_trash"].as_bool()
        ),
        (Some(true), Some(true))
    );
    let reference: Value =
        serde_json::from_str(&fx_text("11-trash/63-capabilities-end")).expect("json");
    for k in ["undelete", "delete_from_trash"] {
        assert!(
            reference["ocs"]["data"]["capabilities"]["files"]
                .get(k)
                .is_some()
        );
    }

    let off = env_with(|c| c.trash.enabled = false).await;
    let files = caps(&off).await;
    assert!(files.get("undelete").is_none() && files.get("delete_from_trash").is_none());
    dav(&off, "anna", "PUT", "/a.txt", &[], "abc").await;
    assert_eq!(
        dav(&off, "anna", "DELETE", "/a.txt", &[], "").await.status,
        204
    );
    assert_eq!(
        tb(&off, "anna", "PROPFIND", "/", &X, PROPS).await.status,
        404,
        "no trash endpoint"
    );
    assert_eq!(
        used(&off, "anna").await,
        0,
        "deleting is permanent and frees the space"
    );
}
