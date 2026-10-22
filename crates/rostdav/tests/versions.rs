//! M8: file versions through the Nextcloud versions endpoint, checked against
//! the recorded fixtures (`tests/fixtures/nextcloud/09-versions/`).

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
const A: &str = "/remote.php/dav/files/anna";
const V: &str = "/remote.php/dav/versions/anna";

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
    state.add_user("anna", PW, false).await.expect("anna");
    state.add_user("bob", PW, false).await.expect("bob");
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

async fn req(
    e: &Env,
    user: &str,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: impl Into<Vec<u8>>,
) -> Res {
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{PW}"))
    );
    let mut b = Request::builder()
        .method(Method::from_bytes(method.as_bytes()).expect("method"))
        .uri(uri)
        .header("host", "cloud.test")
        .header("authorization", auth);
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

async fn anna(
    e: &Env,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: impl Into<Vec<u8>>,
) -> Res {
    req(e, "anna", method, uri, headers, body).await
}

fn fixture(path: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/nextcloud")
        .join(format!("{path}.json"));
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p:?}: {e}")))
        .expect("json")
}

fn fx_body(path: &str) -> String {
    fixture(path)["response"]["body"]["text"]
        .as_str()
        .unwrap_or("")
        .to_owned()
}

fn fx_status(path: &str) -> u16 {
    fixture(path)["response"]["status"]
        .as_u64()
        .expect("status") as u16
}

fn fx_header(path: &str, name: &str) -> String {
    fixture(path)["response"]["headers"]
        .as_array()
        .expect("headers")
        .iter()
        .find(|h| h[0].as_str().is_some_and(|n| n.eq_ignore_ascii_case(name)))
        .and_then(|h| h[1].as_str())
        .unwrap_or("")
        .to_owned()
}

/// `{key: {property: status}}`; the key is the path below the user with numeric
/// file IDs replaced by `ID` so that reference and ours compare.
fn prop_statuses(xml: &str) -> BTreeMap<String, BTreeMap<String, u16>> {
    let mut rd = NsReader::from_str(xml);
    let mut out: BTreeMap<String, BTreeMap<String, u16>> = BTreeMap::new();
    let (mut href, mut in_href, mut in_status) = (String::new(), false, false);
    let mut props: Vec<String> = Vec::new();
    let (mut in_prop, mut depth) = (false, 0usize);
    loop {
        let (ns, ev) = rd.read_resolved_event().expect("xml");
        let dav = matches!(&ns, ResolveResult::Bound(n) if n.as_ref() == b"DAV:");
        match ev {
            Event::Start(e) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if in_prop {
                    if depth == 0 {
                        props.push(local);
                    }
                    depth += 1;
                } else if dav && local == "prop" {
                    in_prop = true;
                    depth = 0;
                } else if dav && local == "href" {
                    in_href = true;
                    href.clear();
                } else if dav && local == "status" {
                    in_status = true;
                }
            }
            Event::Empty(e) => {
                if in_prop && depth == 0 {
                    props.push(String::from_utf8_lossy(e.local_name().as_ref()).into_owned());
                }
            }
            Event::Text(t) => {
                let s = t.unescape().expect("text").into_owned();
                if in_href {
                    href.push_str(&s);
                } else if in_status {
                    let code: u16 = s
                        .split_whitespace()
                        .nth(1)
                        .and_then(|c| c.parse().ok())
                        .expect("status");
                    let key: Vec<String> = href
                        .trim_end_matches('/')
                        .splitn(6, '/')
                        .nth(5)
                        .unwrap_or("")
                        .split('/')
                        .enumerate()
                        .map(|(i, seg)| {
                            if i == 1 && seg.bytes().all(|b| b.is_ascii_digit()) {
                                "ID".to_owned()
                            } else {
                                seg.to_owned()
                            }
                        })
                        .collect();
                    for p in props.drain(..) {
                        out.entry(key.join("/")).or_default().insert(p, code);
                    }
                }
            }
            Event::End(e) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
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

fn exception(body: &str) -> String {
    body.split("<s:exception>")
        .nth(1)
        .and_then(|r| r.split("</s:exception>").next())
        .unwrap_or("")
        .to_owned()
}

const PROPS: &str = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns"><d:prop>
<d:getlastmodified/><d:getcontentlength/><d:getcontenttype/><d:getetag/><d:resourcetype/><nc:version-label/><nc:version-author/><oc:fileid/></d:prop></d:propfind>"#;

/// The three overwrites of the recording: mtimes 1700000100/200/300.
async fn three_versions(e: &Env) -> i64 {
    anna(e, "MKCOL", &format!("{A}/ver"), &[], "").await;
    for (i, body) in ["version one\n", "second version, longer\n", "third\n"]
        .iter()
        .enumerate()
    {
        let mtime = (1_700_000_100 + i * 100).to_string();
        let r = anna(
            e,
            "PUT",
            &format!("{A}/ver/doc.txt"),
            &[("x-oc-mtime", &mtime)],
            *body,
        )
        .await;
        assert!(r.status.is_success(), "{}", r.status);
    }
    e.state
        .stat(&principal(e).await, &lp("/ver/doc.txt"))
        .await
        .expect("stat")
        .id
}

async fn principal(e: &Env) -> rostdav_app::Principal {
    e.state
        .authenticate("anna", PW, std::net::Ipv4Addr::LOCALHOST.into())
        .await
        .expect("auth")
}

fn lp(p: &str) -> rostdav_core::LogicalPath {
    rostdav_core::LogicalPath::from_url_path(p).expect("path")
}

// ---- structure ---------------------------------------------------------------------

#[tokio::test]
async fn collections_match_the_reference() {
    let e = env().await;
    let id = three_versions(&e).await;
    let x = [("depth", "1"), ("content-type", "application/xml")];

    let root = anna(&e, "PROPFIND", &format!("{V}/"), &x, PROPS).await;
    assert_eq!(root.status, StatusCode::MULTI_STATUS);
    assert_eq!(
        prop_statuses(&root.text()),
        prop_statuses(&fx_body("09-versions/06-propfind-versions-root"))
    );

    let vs = anna(&e, "PROPFIND", &format!("{V}/versions"), &x, PROPS).await;
    assert_eq!(
        prop_statuses(&vs.text()),
        prop_statuses(&fx_body("09-versions/07-propfind-versions-versions"))
    );

    let list = anna(&e, "PROPFIND", &format!("{V}/versions/{id}"), &x, PROPS).await;
    assert_eq!(list.status, 207);
    let (ours, theirs) = (
        prop_statuses(&list.text()),
        prop_statuses(&fx_body("09-versions/08-propfind-version-list")),
    );
    assert_eq!(
        ours.keys().collect::<Vec<_>>(),
        theirs.keys().collect::<Vec<_>>(),
        "same entries: 100, 200, 300"
    );
    assert_eq!(ours, theirs, "same properties found / not found");
    assert!(
        list.text()
            .contains("<nc:version-author>anna</nc:version-author>")
    );
    assert!(
        list.text().contains("<d:getetag>1700000100</d:getetag>"),
        "plain version name as ETag, like the reference"
    );
    assert!(
        list.text()
            .contains("<d:getlastmodified>Tue, 14 Nov 2023 22:15:00 GMT</d:getlastmodified>")
    );

    let d0 = anna(
        &e,
        "PROPFIND",
        &format!("{V}/versions/{id}"),
        &[("depth", "0"), ("content-type", "application/xml")],
        PROPS,
    )
    .await;
    assert_eq!(
        prop_statuses(&d0.text()),
        prop_statuses(&fx_body("09-versions/09-propfind-version-list-d0"))
    );

    let allprop = anna(
        &e,
        "PROPFIND",
        &format!("{V}/versions/{id}"),
        &[("depth", "1")],
        "",
    )
    .await;
    assert_eq!(
        prop_statuses(&allprop.text()),
        prop_statuses(&fx_body("09-versions/10-propfind-version-list-no-body"))
    );

    // infinity is refused (the reference answers it like depth 1)
    let inf = anna(
        &e,
        "PROPFIND",
        &format!("{V}/versions/{id}"),
        &[("depth", "infinity")],
        PROPS,
    )
    .await;
    assert_eq!(inf.status, 403);
}

#[tokio::test]
async fn reading_versions() {
    let e = env().await;
    let id = three_versions(&e).await;
    let g = anna(&e, "GET", &format!("{V}/versions/{id}/1700000100"), &[], "").await;
    assert_eq!(g.status, 200);
    assert_eq!(g.text(), "version one\n");
    assert_eq!(g.h("etag"), "1700000100");
    assert_eq!(
        g.h("etag"),
        fx_header("09-versions/12-get-version-0", "etag")
    );
    assert_eq!(g.h("oc-etag"), "1700000100");
    assert_eq!(
        g.h("last-modified"),
        fx_header("09-versions/12-get-version-0", "last-modified")
    );
    assert_eq!(g.h("content-length"), "12");
    assert_eq!(g.h("content-type"), "text/plain");
    assert_eq!(
        anna(&e, "GET", &format!("{V}/versions/{id}/1700000200"), &[], "")
            .await
            .text(),
        "second version, longer\n"
    );
    // the live content is addressable as well (the reference answers 404 for GET but 200 for HEAD)
    assert_eq!(
        anna(&e, "GET", &format!("{V}/versions/{id}/1700000300"), &[], "")
            .await
            .text(),
        "third\n"
    );
    let h = anna(
        &e,
        "HEAD",
        &format!("{V}/versions/{id}/1700000300"),
        &[],
        "",
    )
    .await;
    assert_eq!((h.status, h.h("content-length")), (StatusCode::OK, "6"));
    assert!(h.body.is_empty());
    // ranges
    let r = anna(
        &e,
        "GET",
        &format!("{V}/versions/{id}/1700000100"),
        &[("range", "bytes=0-6")],
        "",
    )
    .await;
    assert_eq!(
        (r.status, r.text().as_str(), r.h("content-range")),
        (StatusCode::PARTIAL_CONTENT, "version", "bytes 0-6/12")
    );
    assert_eq!(fx_status("09-versions/18-get-version-range"), 206);
    assert_eq!(
        anna(
            &e,
            "GET",
            &format!("{V}/versions/{id}/1700000100"),
            &[("range", "bytes=50-")],
            ""
        )
        .await
        .status,
        416
    );
}

#[tokio::test]
async fn errors_match_the_reference() {
    let e = env().await;
    let id = three_versions(&e).await;
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "GET",
            format!("{V}/versions/{id}/123"),
            "09-versions/19-get-version-missing",
        ),
        (
            "GET",
            format!("{V}/versions/{id}/abc"),
            "09-versions/20-get-version-garbage",
        ),
        (
            "PROPFIND",
            format!("{V}/versions/999999999"),
            "09-versions/21-propfind-versions-missing-file",
        ),
        (
            "PUT",
            format!("{V}/versions/{id}/1700000300"),
            "09-versions/23-put-version-readonly",
        ),
        (
            "MKCOL",
            format!("{V}/versions/{id}/new"),
            "09-versions/24-mkcol-in-versions",
        ),
    ];
    for (m, uri, fx) in cases {
        let body = if m == "PUT" { "x" } else { "" };
        let r = anna(&e, m, &uri, &[("depth", "1")], body).await;
        assert_eq!(r.status.as_u16(), fx_status(fx), "{m} {uri}");
        assert_eq!(exception(&r.text()), exception(&fx_body(fx)), "{m} {uri}");
    }
    // another user's URL space and files
    let r = req(
        &e,
        "bob",
        "PROPFIND",
        &format!("{V}/versions/{id}"),
        &[("depth", "1")],
        "",
    )
    .await;
    assert_eq!(r.status, 404, "bob in anna's space");
    let r = req(
        &e,
        "bob",
        "PROPFIND",
        &format!("/remote.php/dav/versions/bob/versions/{id}"),
        &[("depth", "1")],
        "",
    )
    .await;
    assert_eq!(r.status, 404, "bob's space, anna's file");
    for (m, uri) in [
        ("GET", format!("{V}/versions/{id}/1700000100")),
        ("DELETE", format!("{V}/versions/{id}/1700000100")),
    ] {
        assert_eq!(req(&e, "bob", m, &uri, &[], "").await.status, 404);
    }
    let r = req(
        &e,
        "bob",
        "GET",
        &format!("/remote.php/dav/versions/bob/versions/{id}/1700000100"),
        &[],
        "",
    )
    .await;
    assert_eq!(r.status, 404, "{}", r.text());
    // unauthenticated
    let r = e
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("PROPFIND")
                .uri(format!("{V}/"))
                .body(Body::empty())
                .expect("r"),
        )
        .await
        .expect("res");
    assert_eq!(r.status(), 401);
    // a folder has no versions
    let dir = e
        .state
        .stat(&principal(&e).await, &lp("/ver"))
        .await
        .expect("s")
        .id;
    assert_eq!(
        anna(
            &e,
            "PROPFIND",
            &format!("{V}/versions/{dir}"),
            &[("depth", "1")],
            ""
        )
        .await
        .status,
        404
    );
}

// ---- restore and delete ---------------------------------------------------------------

/// The Android app (M6, 35.0.1) restores with `Destination: …/versions/<user>/restore/<fileid>`;
/// the reference accepts any single name below `restore/`.
#[tokio::test]
async fn restore_accepts_the_android_apps_destination() {
    let e = env().await;
    let id = three_versions(&e).await;
    let r = anna(
        &e,
        "MOVE",
        &format!("{V}/versions/{id}/1700000100"),
        &[
            ("destination", &format!("http://cloud.test{V}/restore/{id}")),
            ("overwrite", "T"),
        ],
        "",
    )
    .await;
    assert_eq!(r.status, 201, "{}", r.text());
    let g = anna(&e, "GET", &format!("{A}/ver/doc.txt"), &[], "").await;
    assert_eq!(g.text(), "version one\n");
}

#[tokio::test]
async fn restore_matches_the_reference() {
    let e = env().await;
    let id = three_versions(&e).await;
    let dest = format!("http://cloud.test{V}/restore/target");

    // errors
    let r = anna(
        &e,
        "MOVE",
        &format!("{V}/versions/{id}/abc"),
        &[("destination", &dest)],
        "",
    )
    .await;
    assert_eq!(
        r.status.as_u16(),
        fx_status("09-versions/26-restore-garbage")
    );
    let r = anna(
        &e,
        "MOVE",
        &format!("{V}/versions/{id}/1700000100"),
        &[],
        "",
    )
    .await;
    assert_eq!(r.status, 400, "the reference answers 500 (TypeError)");
    for bad in [
        format!("http://cloud.test{A}/ver/elsewhere.txt"),
        format!("{V}/restore/a/b"),
        "http://cloud.test/remote.php/dav/versions/bob/restore/target".to_owned(),
        format!("{V}/versions/{id}/1700000200"),
        "restore/target".to_owned(),
    ] {
        let r = anna(
            &e,
            "MOVE",
            &format!("{V}/versions/{id}/1700000100"),
            &[("destination", &bad)],
            "",
        )
        .await;
        assert_eq!(r.status, 400, "{bad}");
    }
    assert_eq!(
        anna(&e, "GET", &format!("{A}/ver/elsewhere.txt"), &[], "")
            .await
            .status,
        404,
        "nothing was copied out"
    );
    assert_eq!(
        anna(&e, "GET", &format!("{A}/ver/doc.txt"), &[], "")
            .await
            .text(),
        "third\n",
        "no failed restore changed the file"
    );

    // restore the oldest
    let r = anna(
        &e,
        "MOVE",
        &format!("{V}/versions/{id}/1700000100"),
        &[("destination", &dest)],
        "",
    )
    .await;
    assert_eq!(r.status.as_u16(), fx_status("09-versions/28-restore"));
    assert_eq!(r.status, 201);
    let g = anna(&e, "GET", &format!("{A}/ver/doc.txt"), &[], "").await;
    assert_eq!(g.text(), "version one\n");
    assert_eq!(
        g.h("last-modified"),
        fx_header("09-versions/29-get-file-after-restore", "last-modified")
    );

    // the list afterwards: same names and sizes as the reference
    let list = anna(
        &e,
        "PROPFIND",
        &format!("{V}/versions/{id}"),
        &[("depth", "1"), ("content-type", "application/xml")],
        PROPS,
    )
    .await;
    let sizes = |t: &str| -> Vec<String> {
        t.split("<d:getcontentlength>")
            .skip(1)
            .map(|s| s.split('<').next().unwrap_or("").to_owned())
            .collect()
    };
    assert_eq!(
        sizes(&list.text()),
        sizes(&fx_body(
            "09-versions/31-propfind-version-list-after-restore"
        ))
    );
    assert_eq!(
        prop_statuses(&list.text()),
        prop_statuses(&fx_body(
            "09-versions/31-propfind-version-list-after-restore"
        ))
    );

    // restoring the live entry (now 100) is accepted and changes nothing
    let r = anna(
        &e,
        "MOVE",
        &format!("{V}/versions/{id}/1700000100"),
        &[("destination", &dest)],
        "",
    )
    .await;
    assert_eq!(
        (
            r.status.as_u16(),
            fx_status("09-versions/32-restore-again-same")
        ),
        (201, 201)
    );
    assert_eq!(
        anna(&e, "GET", &format!("{A}/ver/doc.txt"), &[], "")
            .await
            .text(),
        "version one\n"
    );
    // and the old live content is a version now, restorable again
    let r = anna(
        &e,
        "MOVE",
        &format!("{V}/versions/{id}/1700000300"),
        &[("destination", &dest)],
        "",
    )
    .await;
    assert_eq!(r.status, 201);
    assert_eq!(
        anna(&e, "GET", &format!("{A}/ver/doc.txt"), &[], "")
            .await
            .text(),
        "third\n"
    );
}

#[tokio::test]
async fn delete_versions() {
    let e = env().await;
    let id = three_versions(&e).await;
    let used = || async {
        let p = principal(&e).await;
        e.state.user_info(&p).await.expect("i").used
    };
    assert_eq!(used().await, 12 + 23 + 6);
    let r = anna(
        &e,
        "DELETE",
        &format!("{V}/versions/{id}/1700000100"),
        &[],
        "",
    )
    .await;
    assert_eq!(
        (
            r.status.as_u16(),
            fx_status("09-versions/40-delete-version")
        ),
        (204, 204)
    );
    assert_eq!(
        used().await,
        23 + 6,
        "deleting a version gives the space back"
    );
    let again = anna(
        &e,
        "DELETE",
        &format!("{V}/versions/{id}/1700000100"),
        &[],
        "",
    )
    .await;
    assert_eq!(
        again.status.as_u16(),
        fx_status("09-versions/41-delete-version-again")
    );
    assert_eq!(
        exception(&again.text()),
        exception(&fx_body("09-versions/41-delete-version-again"))
    );
    // the live entry cannot be deleted (the reference answers 204 and does something odd)
    let r = anna(
        &e,
        "DELETE",
        &format!("{V}/versions/{id}/1700000300"),
        &[],
        "",
    )
    .await;
    assert_eq!(r.status, 403);
    assert_eq!(
        anna(&e, "GET", &format!("{A}/ver/doc.txt"), &[], "")
            .await
            .text(),
        "third\n"
    );

    // deleting the file hides its versions (the trash keeps them)
    anna(&e, "DELETE", &format!("{A}/ver/doc.txt"), &[], "").await;
    assert_eq!(
        anna(
            &e,
            "PROPFIND",
            &format!("{V}/versions/{id}"),
            &[("depth", "1")],
            ""
        )
        .await
        .status
        .as_u16(),
        fx_status("09-versions/49-propfind-versions-after-file-delete")
    );
    // the file and its versions sit in the trash and keep counting until it is emptied
    assert_eq!(used().await, 23 + 6);
    e.state
        .trash_empty(&principal(&e).await)
        .await
        .expect("empty");
    assert_eq!(used().await, 0);
}

#[tokio::test]
async fn moves_keep_versions_copies_do_not() {
    let e = env().await;
    let id = three_versions(&e).await;
    let r = anna(
        &e,
        "MOVE",
        &format!("{A}/ver/doc.txt"),
        &[("destination", &format!("{A}/ver/moved.txt"))],
        "",
    )
    .await;
    assert_eq!(r.status, 201);
    let list = anna(
        &e,
        "PROPFIND",
        &format!("{V}/versions/{id}"),
        &[("depth", "1")],
        "",
    )
    .await;
    assert_eq!(
        list.text().matches("<d:response>").count(),
        4,
        "collection + 3 entries"
    );
    let c = anna(
        &e,
        "COPY",
        &format!("{A}/ver/moved.txt"),
        &[("destination", &format!("{A}/ver/copy.txt"))],
        "",
    )
    .await;
    let cid = c.h("oc-fileid")[..8].trim_start_matches('0').to_owned();
    let list = anna(
        &e,
        "PROPFIND",
        &format!("{V}/versions/{cid}"),
        &[("depth", "1")],
        "",
    )
    .await;
    assert_eq!(
        list.text().matches("<d:response>").count(),
        2,
        "collection + live entry only"
    );
}

// ---- policy ----------------------------------------------------------------------------

#[tokio::test]
async fn quota_counts_versions_and_blocks_when_full() {
    let e = env().await;
    e.state.set_quota("anna", Some(30)).await.expect("quota");
    anna(&e, "PUT", &format!("{A}/f"), &[], vec![b'a'; 12]).await;
    assert_eq!(
        anna(&e, "PUT", &format!("{A}/f"), &[], vec![b'b'; 12])
            .await
            .status,
        204
    );
    let q = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:quota-used-bytes/><d:quota-available-bytes/></d:prop></d:propfind>"#;
    let r = anna(&e, "PROPFIND", &format!("{A}/"), &[("depth", "0")], q).await;
    assert!(
        r.text()
            .contains("<d:quota-used-bytes>24</d:quota-used-bytes>"),
        "{}",
        r.text()
    );
    assert!(
        r.text()
            .contains("<d:quota-available-bytes>6</d:quota-available-bytes>")
    );
    let r = anna(&e, "PUT", &format!("{A}/f"), &[], vec![b'c'; 12]).await;
    assert_eq!(
        r.status, 507,
        "the old content stays, there is no room for a third copy"
    );
    assert_eq!(
        anna(&e, "GET", &format!("{A}/f"), &[], "").await.body,
        vec![b'b'; 12],
        "a failed overwrite changes nothing"
    );
}

#[tokio::test]
async fn versioning_can_be_turned_off_and_is_advertised_only_when_on() {
    let on = env().await;
    let caps = |e: &Env| {
        let auth = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("anna:{PW}"))
        );
        let req = Request::builder()
            .uri("/ocs/v2.php/cloud/capabilities?format=json")
            .header("ocs-apirequest", "true")
            .header("authorization", auth)
            .body(Body::empty())
            .expect("req");
        let app = e.app.clone();
        async move {
            let res = app.oneshot(req).await.expect("res");
            let b = res.into_body().collect().await.expect("b").to_bytes();
            serde_json::from_slice::<Value>(&b).expect("json")["ocs"]["data"]["capabilities"]["files"].clone()
        }
    };
    let files = caps(&on).await;
    assert_eq!(
        (
            files["versioning"].as_bool(),
            files["version_deletion"].as_bool()
        ),
        (Some(true), Some(true))
    );
    let reference = fixture("09-versions/50-capabilities");
    let theirs: Value =
        serde_json::from_str(reference["response"]["body"]["text"].as_str().expect("t"))
            .expect("json");
    for k in files.as_object().expect("o").keys() {
        assert!(
            theirs["ocs"]["data"]["capabilities"]["files"]
                .get(k)
                .is_some(),
            "invented capability files.{k}"
        );
    }

    let off = env_with(|c| c.versioning.enabled = false).await;
    let files = caps(&off).await;
    assert!(files.get("versioning").is_none() && files.get("version_deletion").is_none());
    anna(&off, "PUT", &format!("{A}/f"), &[], "one").await;
    anna(&off, "PUT", &format!("{A}/f"), &[], "two").await;
    let id = off
        .state
        .stat(&principal(&off).await, &lp("/f"))
        .await
        .expect("s")
        .id;
    assert_eq!(
        anna(
            &off,
            "PROPFIND",
            &format!("{V}/versions/{id}"),
            &[("depth", "1")],
            ""
        )
        .await
        .status,
        404
    );
    assert_eq!(
        anna(&off, "PROPFIND", &format!("{V}/"), &[("depth", "1")], "")
            .await
            .status,
        404
    );
}

#[tokio::test]
async fn chunked_overwrite_and_per_file_limit() {
    let e = env_with(|c| c.versioning.max_versions = 2).await;
    anna(
        &e,
        "PUT",
        &format!("{A}/f"),
        &[("x-oc-mtime", "1000")],
        "v1",
    )
    .await;
    anna(&e, "MKCOL", "/remote.php/dav/uploads/anna/t", &[], "").await;
    anna(
        &e,
        "PUT",
        "/remote.php/dav/uploads/anna/t/1",
        &[],
        "chunked content",
    )
    .await;
    let r = anna(
        &e,
        "MOVE",
        "/remote.php/dav/uploads/anna/t/.file",
        &[
            ("destination", &format!("http://cloud.test{A}/f")),
            ("x-oc-mtime", "2000"),
        ],
        "",
    )
    .await;
    assert_eq!(r.status, 204);
    for (i, body) in ["v3", "v4", "v5"].iter().enumerate() {
        anna(
            &e,
            "PUT",
            &format!("{A}/f"),
            &[("x-oc-mtime", &(3000 + i).to_string())],
            *body,
        )
        .await;
    }
    let id = e
        .state
        .stat(&principal(&e).await, &lp("/f"))
        .await
        .expect("s")
        .id;
    let list = anna(
        &e,
        "PROPFIND",
        &format!("{V}/versions/{id}"),
        &[("depth", "1")],
        "",
    )
    .await;
    assert_eq!(
        list.text().matches("<d:response>").count(),
        1 + 2 + 1,
        "collection, two versions, live"
    );
    assert!(
        !list.text().contains("1000") && !list.text().contains(">15<"),
        "the oldest versions were dropped"
    );
}
