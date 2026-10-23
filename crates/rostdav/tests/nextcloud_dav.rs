//! M5: Nextcloud WebDAV extensions, checked against the recorded reference
//! fixtures (`tests/fixtures/nextcloud/`).

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
use rostdav_app::AppState;
use serde_json::Value;
use tower::ServiceExt;

const PW: &str = "korrekt-pferd-batterie";
const A: &str = "/remote.php/dav/files/anna";
const UP: &str = "/remote.php/dav/uploads/anna";

struct Env {
    app: Router,
    state: AppState,
    _dir: tempfile::TempDir,
}

async fn env() -> Env {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().join("data");
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

fn fx_req_body(path: &str) -> String {
    fixture(path)["request"]["body"]["text"]
        .as_str()
        .unwrap_or("")
        .to_owned()
}

fn fx_header_names(path: &str) -> Vec<String> {
    fixture(path)["response"]["headers"]
        .as_array()
        .expect("headers")
        .iter()
        .map(|h| h[0].as_str().expect("name").to_ascii_lowercase())
        .collect()
}

/// `{local property name: status}` per response, keyed by the path below the user ("" = root).
#[allow(dead_code)]
fn debug_keys(m: &BTreeMap<String, BTreeMap<String, u16>>) -> Vec<&String> {
    m.keys().collect()
}

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
                    let key = href
                        .trim_end_matches('/')
                        .splitn(6, '/')
                        .nth(5)
                        .unwrap_or("")
                        .to_owned();
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

fn sabre(body: &str) -> (String, String) {
    let tag = |t: &str| {
        body.split(&format!("<s:{t}>"))
            .nth(1)
            .and_then(|r| r.split(&format!("</s:{t}>")).next())
            .unwrap_or("")
            .to_owned()
    };
    (tag("exception"), tag("message"))
}

// ---- headers -----------------------------------------------------------------

#[tokio::test]
async fn upload_and_create_headers_match_the_reference() {
    let e = env().await;
    let r = anna(
        &e,
        "PUT",
        &format!("{A}/hello.txt"),
        &[
            ("x-oc-mtime", "1700000000"),
            ("oc-checksum", "SHA256:abc123"),
        ],
        "hello world\n",
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    for h in ["x-oc-mtime", "oc-fileid", "etag", "oc-etag"] {
        assert!(
            fx_header_names("04-webdav/10-put-small").contains(&h.to_owned()),
            "reference has {h}"
        );
        assert!(r.headers.contains_key(h), "missing {h}");
    }
    assert_eq!(r.h("x-oc-mtime"), "accepted");
    assert_eq!(r.h("etag"), r.h("oc-etag"));
    let id = r.h("oc-fileid");
    assert_eq!(id.len(), 8 + 12);
    assert!(
        id[..8].bytes().all(|b| b.is_ascii_digit()) && id[8..].starts_with("oc"),
        "{id}"
    );

    // the stored mtime is the client's
    let g = anna(&e, "GET", &format!("{A}/hello.txt"), &[], "").await;
    assert_eq!(g.h("last-modified"), "Tue, 14 Nov 2023 22:13:20 GMT");
    assert_eq!(g.h("etag"), g.h("oc-etag"));
    assert!(fx_header_names("04-webdav/17-get").contains(&"oc-etag".to_owned()));

    // overwrite keeps the file ID, changes the ETag; no X-OC-MTime header -> not echoed
    let r2 = anna(&e, "PUT", &format!("{A}/hello.txt"), &[], "changed").await;
    assert_eq!(r2.status, StatusCode::NO_CONTENT);
    assert_eq!(r2.h("oc-fileid"), id);
    assert_ne!(r2.h("etag"), r.h("etag"));
    assert!(!r2.headers.contains_key("x-oc-mtime"));

    // MKCOL: OC-FileId only; COPY: OC-FileId; MOVE: OC-ETag, ETag, OC-FileId
    let mk = anna(&e, "MKCOL", &format!("{A}/d"), &[], "").await;
    assert_eq!(mk.status, 201);
    assert!(mk.h("oc-fileid").len() == 20);
    let cp = anna(
        &e,
        "COPY",
        &format!("{A}/hello.txt"),
        &[("destination", &format!("{A}/copy.txt"))],
        "",
    )
    .await;
    assert_eq!(
        (cp.status, cp.h("oc-fileid").len()),
        (StatusCode::CREATED, 20)
    );
    assert_ne!(cp.h("oc-fileid"), id);
    let mv = anna(
        &e,
        "MOVE",
        &format!("{A}/copy.txt"),
        &[("destination", &format!("{A}/d/moved.txt"))],
        "",
    )
    .await;
    assert_eq!(mv.status, 201);
    assert!(mv.headers.contains_key("etag") && mv.headers.contains_key("oc-etag"));
    assert_eq!(
        mv.h("oc-fileid"),
        cp.h("oc-fileid"),
        "MOVE keeps the file ID"
    );
    for h in ["oc-etag", "etag", "oc-fileid"] {
        assert!(fx_header_names("04-webdav/23-move").contains(&h.to_owned()));
    }

    // garbage mtime is a client error with the reference wording
    let bad = anna(&e, "PUT", &format!("{A}/x"), &[("x-oc-mtime", "abc")], "x").await;
    assert_eq!(bad.status, 400);
    let (_, msg) = sabre(&bad.text());
    let (_, ref_msg) = sabre(&fx_body("08-m5-probes/14-put-mtime-garbage"));
    assert_eq!(msg, ref_msg);
}

// ---- properties ----------------------------------------------------------------

#[tokio::test]
async fn propfind_property_sets_match_the_reference() {
    let e = env().await;
    anna(&e, "MKCOL", &format!("{A}/Docs"), &[], "").await;
    anna(
        &e,
        "PUT",
        &format!("{A}/Docs/bad.txt"),
        &[("oc-checksum", "SHA256:00")],
        "abc",
    )
    .await;

    let props = fx_req_body("04-webdav/01-propfind-root-d0");
    let ours = anna(
        &e,
        "PROPFIND",
        &format!("{A}/"),
        &[("depth", "0"), ("content-type", "application/xml")],
        props.clone(),
    )
    .await;
    assert_eq!(ours.status, StatusCode::MULTI_STATUS);
    assert!(
        ours.text()
            .contains("xmlns:oc=\"http://owncloud.org/ns\" xmlns:nc=\"http://nextcloud.org/ns\""),
        "prefixes must be declared"
    );
    let ours_dir = prop_statuses(&ours.text());
    let theirs_dir = prop_statuses(&fx_body("04-webdav/01-propfind-root-d0"));
    assert_eq!(
        ours_dir[""], theirs_dir[""],
        "folder: same properties found / not found as the reference"
    );

    let ours = anna(
        &e,
        "PROPFIND",
        &format!("{A}/Docs/"),
        &[("depth", "1"), ("content-type", "application/xml")],
        props,
    )
    .await;
    let ours = prop_statuses(&ours.text());
    let theirs = prop_statuses(&fx_body("04-webdav/16-propfind-docs-d1"));
    assert_eq!(
        ours["Docs/bad.txt"], theirs["Docs/bad.txt"],
        "file with checksum"
    );
    assert_eq!(ours["Docs"], theirs["Docs"], "sub folder");
}

#[tokio::test]
async fn property_values() {
    let e = env().await;
    anna(&e, "MKCOL", &format!("{A}/Docs"), &[], "").await;
    anna(
        &e,
        "PUT",
        &format!("{A}/Docs/f.txt"),
        &[
            (
                "oc-checksum",
                "SHA1:a9993e364706816aba3e25717850c26c9cd0d89d",
            ),
            ("x-oc-mtime", "1500000000"),
        ],
        "abc",
    )
    .await;
    let body = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns"><d:prop>
        <oc:id/><oc:fileid/><oc:size/><oc:permissions/><oc:owner-id/><oc:owner-display-name/><oc:checksums/><oc:favorite/>
        <nc:has-preview/><nc:upload_time/><d:getcontentlength/><d:getlastmodified/><d:getcontenttype/></d:prop></d:propfind>"#;
    let r = anna(
        &e,
        "PROPFIND",
        &format!("{A}/Docs/f.txt"),
        &[("depth", "0")],
        body,
    )
    .await;
    let t = r.text();
    assert!(t.contains("<oc:size>3</oc:size>"), "{t}");
    assert!(t.contains("<oc:permissions>RGDNVW</oc:permissions>"));
    assert!(
        t.contains("<oc:owner-id>anna</oc:owner-id>")
            && t.contains("<oc:owner-display-name>anna</oc:owner-display-name>")
    );
    assert!(t.contains("<oc:checksums><oc:checksum>SHA1:a9993e364706816aba3e25717850c26c9cd0d89d</oc:checksum></oc:checksums>"));
    assert!(t.contains("<oc:favorite>0</oc:favorite>"));
    assert!(
        t.contains("<nc:has-preview>false</nc:has-preview>"),
        "no previews are offered"
    );
    assert!(t.contains("<d:getlastmodified>Fri, 14 Jul 2017 02:40:00 GMT</d:getlastmodified>"));
    assert!(t.contains("<d:getcontenttype>text/plain</d:getcontenttype>"));
    let id = t
        .split("<oc:id>")
        .nth(1)
        .and_then(|s| s.split("</oc:id>").next())
        .expect("id");
    let fileid = t
        .split("<oc:fileid>")
        .nth(1)
        .and_then(|s| s.split("</oc:fileid>").next())
        .expect("fileid");
    assert_eq!(id, format!("{:0>8}{}", fileid, &id[8..]));
    let up: i64 = t
        .split("<nc:upload_time>")
        .nth(1)
        .and_then(|s| s.split('<').next())
        .expect("u")
        .parse()
        .expect("n");
    assert!(up > 1_700_000_000);

    // folder size is the sum below; permissions of a folder
    let r = anna(&e, "PROPFIND", &format!("{A}/"), &[("depth", "0")], body).await;
    assert!(r.text().contains("<oc:size>3</oc:size>"));
    assert!(
        r.text()
            .contains("<oc:permissions>RGDNVCK</oc:permissions>")
    );

    // the same file has the same IDs for every user's view: another user sees nothing
    let r = req(
        &e,
        "bob",
        "PROPFIND",
        &format!("{A}/Docs/f.txt"),
        &[("depth", "0")],
        body,
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn quota_properties() {
    let e = env().await;
    anna(&e, "PUT", &format!("{A}/f"), &[], "12345").await;
    let body = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:quota-used-bytes/><d:quota-available-bytes/></d:prop></d:propfind>"#;
    let r = anna(&e, "PROPFIND", &format!("{A}/"), &[("depth", "0")], body).await;
    assert!(
        r.text()
            .contains("<d:quota-used-bytes>5</d:quota-used-bytes>")
    );
    assert!(
        r.text()
            .contains("<d:quota-available-bytes>-3</d:quota-available-bytes>"),
        "unlimited is -3"
    );

    e.state.set_quota("anna", Some(100)).await.expect("quota");
    let r = anna(&e, "PROPFIND", &format!("{A}/"), &[("depth", "0")], body).await;
    assert!(
        r.text()
            .contains("<d:quota-available-bytes>95</d:quota-available-bytes>"),
        "{}",
        r.text()
    );
    // files have no quota properties (reference: 404 propstat)
    let r = anna(&e, "PROPFIND", &format!("{A}/f"), &[("depth", "0")], body).await;
    assert!(r.text().contains("HTTP/1.1 404 Not Found"));
    assert!(!r.text().contains("<d:quota-used-bytes>"));

    // allprop on a folder includes them, as in the reference
    let r = anna(&e, "PROPFIND", &format!("{A}/"), &[("depth", "0")], "").await;
    let got = prop_statuses(&r.text());
    let want = prop_statuses(&fx_body("04-webdav/03-propfind-no-body"));
    assert_eq!(got[""], want[""]);
}

// ---- 507 -------------------------------------------------------------------------

#[tokio::test]
async fn quota_exceeded_is_507_everywhere() {
    let e = env().await;
    e.state.set_quota("anna", Some(10)).await.expect("quota");
    let r = anna(&e, "PUT", &format!("{A}/big"), &[], vec![0u8; 11]).await;
    assert_eq!(r.status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(
        sabre(&r.text()).0,
        "Sabre\\DAV\\Exception\\InsufficientStorage"
    );
    assert_eq!(
        anna(&e, "GET", &format!("{A}/big"), &[], "").await.status,
        404
    );
    assert_eq!(
        anna(&e, "PUT", &format!("{A}/ok"), &[], vec![0u8; 10])
            .await
            .status,
        201
    );

    // chunked: a chunk that would exceed the quota and an assembly that would
    e.state.set_quota("anna", Some(20)).await.expect("quota");
    anna(&e, "MKCOL", &format!("{UP}/q"), &[], "").await;
    assert_eq!(
        anna(&e, "PUT", &format!("{UP}/q/1"), &[], vec![0u8; 5])
            .await
            .status,
        201
    );
    e.state.set_quota("anna", Some(12)).await.expect("quota");
    let r = anna(&e, "PUT", &format!("{UP}/q/2"), &[], vec![0u8; 5]).await;
    assert_eq!(r.status, StatusCode::INSUFFICIENT_STORAGE);
    let r = anna(
        &e,
        "MOVE",
        &format!("{UP}/q/.file"),
        &[("destination", &format!("{A}/assembled"))],
        "",
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::INSUFFICIENT_STORAGE,
        "10 used + 5 > 12"
    );
}

// ---- errors ----------------------------------------------------------------------

#[tokio::test]
async fn error_bodies_use_the_reference_exception_classes() {
    let e = env().await;
    let cases: Vec<(Res, &str)> = vec![
        (
            anna(&e, "PROPFIND", &format!("{A}/nope"), &[("depth", "0")], "").await,
            "04-webdav/05-propfind-missing",
        ),
        (
            anna(&e, "MKCOL", &format!("{A}/x/y"), &[], "").await,
            "04-webdav/09-mkcol-no-parent",
        ),
        (
            anna(&e, "PUT", &format!("{A}/nope/f"), &[], "x").await,
            "04-webdav/12-put-no-parent",
        ),
    ];
    for (r, fx) in cases {
        let want = fixture(fx)["response"]["status"].as_u64().expect("s") as u16;
        assert_eq!(r.status.as_u16(), want, "{fx}");
        assert!(r.h("content-type").starts_with("application/xml"), "{fx}");
        assert_eq!(sabre(&r.text()).0, sabre(&fx_body(fx)).0, "{fx}");
    }
    anna(&e, "MKCOL", &format!("{A}/d"), &[], "").await;
    let r = anna(&e, "MKCOL", &format!("{A}/d"), &[], "").await;
    assert_eq!(r.status, 405);
    assert_eq!(
        sabre(&r.text()),
        sabre(&fx_body("04-webdav/08-mkcol-exists"))
    );
    anna(&e, "PUT", &format!("{A}/f"), &[], "1").await;
    let r = anna(&e, "PUT", &format!("{A}/f"), &[("if-none-match", "*")], "2").await;
    assert_eq!(r.status, 412);
    assert_eq!(
        sabre(&r.text()).0,
        sabre(&fx_body("04-webdav/13-put-if-none-match-star")).0
    );
    // no credentials
    let r = e
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("PROPFIND")
                .uri(format!("{A}/"))
                .body(Body::empty())
                .expect("r"),
        )
        .await
        .expect("res");
    assert_eq!(r.status(), 401);
    let b =
        String::from_utf8_lossy(&r.into_body().collect().await.expect("b").to_bytes()).into_owned();
    assert_eq!(
        sabre(&b).0,
        sabre(&fx_body("04-webdav/06-propfind-no-auth")).0
    );
}

#[tokio::test]
async fn forbidden_names_use_reference_messages() {
    let e = env().await;
    let r = anna(&e, "PUT", &format!("{A}/a.part"), &[], "x").await;
    assert_eq!(r.status, 400);
    assert_eq!(
        sabre(&r.text()).1,
        sabre(&fx_body("08-m5-probes/16-put-name-part")).1
    );
    assert_eq!(
        anna(&e, "PUT", &format!("{A}/B.FILEPART"), &[], "x")
            .await
            .status,
        400
    );
    assert_eq!(
        anna(&e, "MKCOL", &format!("{A}/dir.part"), &[], "")
            .await
            .status,
        400
    );
    anna(&e, "PUT", &format!("{A}/ok.txt"), &[], "x").await;
    assert_eq!(
        anna(
            &e,
            "MOVE",
            &format!("{A}/ok.txt"),
            &[("destination", &format!("{A}/ok.part"))],
            ""
        )
        .await
        .status,
        400
    );
    assert_eq!(
        anna(
            &e,
            "COPY",
            &format!("{A}/ok.txt"),
            &[("destination", &format!("{A}/ok.filepart"))],
            ""
        )
        .await
        .status,
        400
    );
    // backslash, newline, too long: 400 as in the reference
    for (path, fx) in [
        ("a%5Cb".to_owned(), "08-m5-probes/19-put-name-backslash"),
        ("a%0Ab".to_owned(), "08-m5-probes/21-mkcol-name-newline"),
        ("a".repeat(300), "08-m5-probes/20-put-name-long"),
    ] {
        let r = anna(&e, "PUT", &format!("{A}/{path}"), &[], "x").await;
        assert_eq!(
            r.status.as_u16(),
            fixture(fx)["response"]["status"].as_u64().expect("s") as u16,
            "{fx}"
        );
    }
    // names the reference allows
    assert_eq!(
        anna(&e, "PUT", &format!("{A}/trail%20"), &[], "x")
            .await
            .status,
        201
    );
    assert_eq!(
        anna(&e, "PUT", &format!("{A}/empty.txt"), &[], "")
            .await
            .status,
        201
    );
}

// ---- chunked upload ----------------------------------------------------------------

#[tokio::test]
async fn chunked_upload_flow_matches_the_reference() {
    let e = env().await;
    anna(&e, "MKCOL", &format!("{A}/Docs"), &[], "").await;
    let dest = format!("http://cloud.test{A}/Docs/chunked.bin");
    let id = "rec-transfer-1";

    let r = anna(
        &e,
        "MKCOL",
        &format!("{UP}/{id}"),
        &[("destination", &dest), ("oc-total-length", "20")],
        "",
    )
    .await;
    assert_eq!(r.status, 201);
    let r = anna(
        &e,
        "MKCOL",
        &format!("{UP}/{id}"),
        &[("destination", &dest)],
        "",
    )
    .await;
    assert_eq!(r.status, 405, "session exists");
    assert_eq!(
        sabre(&r.text()).1,
        sabre(&fx_body("08-m5-probes/26-chunk-mkcol-again")).1
    );

    assert_eq!(
        anna(
            &e,
            "PUT",
            &format!("{UP}/{id}/00002"),
            &[("oc-total-length", "20")],
            vec![b'B'; 10]
        )
        .await
        .status,
        201
    );
    assert_eq!(
        anna(
            &e,
            "PUT",
            &format!("{UP}/{id}/00001"),
            &[("oc-total-length", "20")],
            vec![b'A'; 10]
        )
        .await
        .status,
        201
    );
    assert_eq!(
        anna(&e, "PUT", &format!("{UP}/{id}/00001"), &[], vec![b'a'; 10])
            .await
            .status,
        204,
        "replacing a chunk"
    );

    // session listing: collection, .file (virtual, total length) and the chunks
    let l = anna(&e, "PROPFIND", &format!("{UP}/{id}"), &[("depth", "1")], "").await;
    assert_eq!(l.status, 207);
    let got = prop_statuses(&l.text());
    let want = prop_statuses(&fx_body("05-chunked-upload/04-propfind-session"));
    assert_eq!(got.keys().collect::<Vec<_>>().len(), want.keys().count());
    for k in ["00001", "00002", ".file"] {
        assert_eq!(
            got[&format!("{id}/{k}")],
            want[&format!("rec-transfer-1/{k}")],
            "{k}"
        );
    }
    assert_eq!(got[id], want["rec-transfer-1"]);
    assert!(
        l.text()
            .contains("<d:getcontentlength>20</d:getcontentlength>")
    );
    let d0 = anna(&e, "PROPFIND", &format!("{UP}/{id}"), &[("depth", "0")], "").await;
    assert_eq!(d0.text().matches("<d:response>").count(), 1);

    // wrong total length: 400 with the reference wording, session kept
    let r = anna(
        &e,
        "MOVE",
        &format!("{UP}/{id}/.file"),
        &[("destination", &dest), ("oc-total-length", "50")],
        "",
    )
    .await;
    assert_eq!(r.status, 400);
    assert_eq!(
        sabre(&r.text()).1,
        "Chunks on server do not sum up to 50 but to 20 bytes"
    );

    // overwrite: F onto an existing file keeps the session
    anna(&e, "PUT", &format!("{A}/Docs/chunked.bin"), &[], "old").await;
    let r = anna(
        &e,
        "MOVE",
        &format!("{UP}/{id}/.file"),
        &[("destination", &dest), ("overwrite", "F")],
        "",
    )
    .await;
    assert_eq!(r.status, 412);
    assert_eq!(
        anna(&e, "PROPFIND", &format!("{UP}/{id}"), &[("depth", "0")], "")
            .await
            .status,
        207
    );

    // assemble
    let r = anna(
        &e,
        "MOVE",
        &format!("{UP}/{id}/.file"),
        &[
            ("destination", &dest),
            ("oc-total-length", "20"),
            ("x-oc-mtime", "1700000200"),
        ],
        "",
    )
    .await;
    assert_eq!(r.status, 204, "replaced the old file");
    for h in ["oc-etag", "etag", "oc-fileid", "x-oc-mtime"] {
        assert!(r.headers.contains_key(h), "{h}");
    }
    let g = anna(&e, "GET", &format!("{A}/Docs/chunked.bin"), &[], "").await;
    assert_eq!(g.body, [vec![b'a'; 10], vec![b'B'; 10]].concat());
    assert_eq!(g.h("last-modified"), "Tue, 14 Nov 2023 22:16:40 GMT");

    // the session is gone
    assert_eq!(
        anna(&e, "PROPFIND", &format!("{UP}/{id}"), &[("depth", "0")], "")
            .await
            .status,
        404
    );
    assert_eq!(
        anna(
            &e,
            "MOVE",
            &format!("{UP}/{id}/.file"),
            &[("destination", &dest)],
            ""
        )
        .await
        .status,
        404
    );
}

#[tokio::test]
async fn chunked_upload_edge_cases() {
    let e = env().await;
    let dest = |p: &str| format!("http://cloud.test{A}/{p}");
    // no session
    assert_eq!(
        anna(&e, "PUT", &format!("{UP}/missing/00001"), &[], "A")
            .await
            .status,
        404
    );
    assert_eq!(
        anna(&e, "DELETE", &format!("{UP}/missing"), &[], "")
            .await
            .status,
        404
    );

    anna(&e, "MKCOL", &format!("{UP}/t"), &[], "").await;
    // chunks assemble in natural order, including non-numeric names
    for (n, c) in [("10", "C"), ("2", "B"), ("1", "A"), ("abc", "Z")] {
        assert_eq!(
            anna(&e, "PUT", &format!("{UP}/t/{n}"), &[], c).await.status,
            201,
            "{n}"
        );
    }
    // names that could escape are refused
    for bad in ["..%2Fx", ".file", "a%2Fb", "%2e%2e"] {
        let r = anna(&e, "PUT", &format!("{UP}/t/{bad}"), &[], "x").await;
        assert!(r.status.is_client_error(), "{bad}: {}", r.status);
    }
    // no destination / foreign user / traversal in the destination
    assert_eq!(
        anna(&e, "MOVE", &format!("{UP}/t/.file"), &[], "")
            .await
            .status,
        400
    );
    let r = anna(
        &e,
        "MOVE",
        &format!("{UP}/t/.file"),
        &[(
            "destination",
            "http://cloud.test/remote.php/dav/files/bob/x",
        )],
        "",
    )
    .await;
    assert_eq!(
        r.status, 409,
        "reference: The destination node is not found"
    );
    assert_eq!(
        anna(
            &e,
            "MOVE",
            &format!("{UP}/t/.file"),
            &[("destination", &dest("../bob/x"))],
            ""
        )
        .await
        .status,
        400
    );
    assert_eq!(
        anna(
            &e,
            "MOVE",
            &format!("{UP}/t/.file"),
            &[("destination", &dest("no/parent"))],
            ""
        )
        .await
        .status,
        409
    );
    assert_eq!(
        anna(
            &e,
            "MOVE",
            &format!("{UP}/t/.file"),
            &[("destination", &dest("x.part"))],
            ""
        )
        .await
        .status,
        400
    );

    let r = anna(
        &e,
        "MOVE",
        &format!("{UP}/t/.file"),
        &[("destination", &dest("out.bin"))],
        "",
    )
    .await;
    assert_eq!(r.status, 201);
    assert_eq!(
        anna(&e, "GET", &format!("{A}/out.bin"), &[], "")
            .await
            .text(),
        "ABCZ"
    );

    // other users: sessions are invisible and unusable
    anna(&e, "MKCOL", &format!("{UP}/mine"), &[], "").await;
    assert_eq!(
        req(
            &e,
            "bob",
            "PUT",
            "/remote.php/dav/uploads/bob/mine/1",
            &[],
            "x"
        )
        .await
        .status,
        404
    );
    assert_eq!(
        req(&e, "bob", "PUT", &format!("{UP}/mine/1"), &[], "x")
            .await
            .status,
        404,
        "bob in anna's URL space"
    );
    assert_eq!(
        req(&e, "bob", "DELETE", &format!("{UP}/mine"), &[], "")
            .await
            .status,
        404
    );
    assert_eq!(
        req(&e, "bob", "MKCOL", &format!("{UP}/mine"), &[], "")
            .await
            .status,
        404
    );
    // same transfer id for another user is a different session
    assert_eq!(
        req(
            &e,
            "bob",
            "MKCOL",
            "/remote.php/dav/uploads/bob/mine",
            &[],
            ""
        )
        .await
        .status,
        201
    );

    // listing all sessions is disabled; delete cancels
    let r = anna(&e, "PROPFIND", UP, &[("depth", "1")], "").await;
    assert_eq!(r.status, 405);
    assert!(!sabre(&r.text()).1.is_empty());
    assert_eq!(
        anna(&e, "DELETE", &format!("{UP}/mine"), &[], "")
            .await
            .status,
        204
    );
    assert_eq!(
        anna(&e, "PUT", &format!("{UP}/mine/1"), &[], "x")
            .await
            .status,
        404
    );
    // transfer ids are validated
    assert!(
        anna(&e, "MKCOL", &format!("{UP}/a%20b"), &[], "")
            .await
            .status
            .is_client_error()
    );
}

#[tokio::test]
async fn chunked_upload_of_more_than_100_mb() {
    let e = env().await;
    anna(&e, "MKCOL", &format!("{UP}/big"), &[], "").await;
    const CHUNK: usize = 5 * 1024 * 1024;
    const N: usize = 21; // 105 MiB
    for i in 0..N {
        // every chunk has its own byte value so ordering errors are visible
        let r = anna(
            &e,
            "PUT",
            &format!("{UP}/big/{:05}", i + 1),
            &[],
            vec![(i % 251) as u8; CHUNK],
        )
        .await;
        assert_eq!(r.status, 201, "chunk {i}");
    }
    let total = (CHUNK * N).to_string();
    let r = anna(
        &e,
        "MOVE",
        &format!("{UP}/big/.file"),
        &[
            ("destination", &format!("http://cloud.test{A}/big.bin")),
            ("oc-total-length", &total),
        ],
        "",
    )
    .await;
    assert_eq!(r.status, 201);
    let h = anna(&e, "HEAD", &format!("{A}/big.bin"), &[], "").await;
    assert_eq!(h.h("content-length"), total);
    const { assert!(CHUNK * N > 100 * 1024 * 1024) };
    // spot checks at chunk boundaries
    for i in [0usize, 7, 20] {
        let from = i * CHUNK + CHUNK - 2;
        let range = format!("bytes={from}-{}", from + 3);
        let g = anna(&e, "GET", &format!("{A}/big.bin"), &[("range", &range)], "").await;
        assert_eq!(g.status, 206);
        let expect = [
            vec![(i % 251) as u8; 2],
            if i + 1 < N {
                vec![((i + 1) % 251) as u8; 2]
            } else {
                vec![]
            },
        ]
        .concat();
        assert_eq!(g.body, expect, "boundary after chunk {i}");
    }
    // quota accounting and cleanup
    let info = e
        .state
        .user_info(
            &e.state
                .authenticate("anna", PW, std::net::Ipv4Addr::LOCALHOST.into())
                .await
                .expect("a"),
        )
        .await
        .expect("i");
    assert_eq!(info.used, (CHUNK * N) as i64);
    assert_eq!(
        anna(&e, "PROPFIND", &format!("{UP}/big"), &[("depth", "0")], "")
            .await
            .status,
        404
    );
}

#[tokio::test]
async fn expired_upload_sessions_are_collected() {
    let e = env().await;
    anna(&e, "MKCOL", &format!("{UP}/old"), &[], "").await;
    anna(&e, "PUT", &format!("{UP}/old/1"), &[], "x").await;
    assert_eq!(e.state.expire_uploads(-1).await.expect("expire"), 1);
    assert_eq!(
        anna(&e, "PUT", &format!("{UP}/old/2"), &[], "x")
            .await
            .status,
        404
    );
}

// ---- preview / avatar -----------------------------------------------------------------

#[tokio::test]
async fn previews_and_avatars_answer_404_cleanly() {
    let e = env().await;
    anna(&e, "PUT", &format!("{A}/pic.png"), &[], "x").await;
    for uri in [
        "/index.php/core/preview?fileId=1&x=64&y=64",
        "/index.php/core/preview.png?file=/pic.png&x=64&y=64",
        "/index.php/avatar/anna/64",
        "/avatar/anna/64",
    ] {
        let r = anna(&e, "GET", uri, &[], "").await;
        assert_eq!(r.status, 404, "{uri}");
    }
    assert_eq!(fixture("06-misc/01-preview")["response"]["status"], 404);
}
