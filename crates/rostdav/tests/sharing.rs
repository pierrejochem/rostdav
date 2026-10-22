//! M9: sharing through the real HTTP surface, compared with the recorded
//! reference (`tests/fixtures/nextcloud/10-shares/`) and attacked from every
//! side that matters (ADR 0004).

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
    _dir: tempfile::TempDir,
}

async fn env() -> Env {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().join("data");
    let state = rostdav::build_state(&cfg).await.expect("state");
    for (n, admin) in [
        ("anna", false),
        ("bob", false),
        ("carl", false),
        ("root", true),
    ] {
        state.add_user(n, PW, admin).await.expect("user");
    }
    Env {
        app: rostdav::http::router_with(state, &rostdav::http::HttpOptions::from_config(&cfg)),
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
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.text()))
    }
    fn data(&self) -> Value {
        self.json()["ocs"]["data"].clone()
    }
    fn msg(&self) -> String {
        self.json()["ocs"]["meta"]["message"]
            .as_str()
            .unwrap_or("")
            .to_owned()
    }
    fn h(&self, n: &str) -> &str {
        self.headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
}

fn basic(u: &str, p: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
    )
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
        b = b.header("authorization", basic(u, p));
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

async fn ocs(e: &Env, user: &str, method: &str, path: &str, form: &str) -> Res {
    let uri = format!(
        "{API}{path}{}format=json",
        if path.contains('?') { "&" } else { "?" }
    );
    send(
        e,
        Some((user, PW)),
        method,
        &uri,
        &[
            ("ocs-apirequest", "true"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        form,
    )
    .await
}

async fn public(
    e: &Env,
    token: &str,
    pw: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: impl Into<Vec<u8>>,
) -> Res {
    send(
        e,
        Some((token, pw)),
        method,
        &format!("/public.php/webdav{path}"),
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

fn fx_json(path: &str) -> Value {
    serde_json::from_str(
        fixture(path)["response"]["body"]["text"]
            .as_str()
            .expect("text"),
    )
    .expect("json")
}

fn fx_text(path: &str) -> String {
    fixture(path)["response"]["body"]["text"]
        .as_str()
        .unwrap_or("")
        .to_owned()
}

fn keys_subset(ours: &Value, theirs: &Value, at: &str) {
    if let (Value::Object(o), Value::Object(t)) = (ours, theirs) {
        for (k, v) in o {
            let tv = t
                .get(k)
                .unwrap_or_else(|| panic!("invented field {at}/{k}"));
            keys_subset(v, tv, &format!("{at}/{k}"));
        }
    }
}

/// `{key: {property: status}}`, key = path below the user ("" = root).
fn prop_statuses(xml: &str) -> BTreeMap<String, BTreeMap<String, u16>> {
    let mut rd = NsReader::from_str(xml);
    let mut out: BTreeMap<String, BTreeMap<String, u16>> = BTreeMap::new();
    let (mut href, mut in_href, mut in_status) = (String::new(), false, false);
    let mut props: Vec<String> = Vec::new();
    let (mut in_prop, mut depth) = (false, 0usize);
    loop {
        let (ns, ev) = rd.read_resolved_event().expect("xml");
        let is_dav = matches!(&ns, ResolveResult::Bound(n) if n.as_ref() == b"DAV:");
        match ev {
            Event::Start(e) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
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

const PROPS: &str = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns"><d:prop>
<d:getlastmodified/><d:getcontentlength/><d:resourcetype/><d:getetag/><oc:id/><oc:fileid/><oc:size/><oc:permissions/>
<oc:owner-id/><oc:owner-display-name/><oc:share-types/><nc:mount-type/><nc:is-mount-root/><nc:share-attributes/>
<oc:shareid/></d:prop></d:propfind>"#;

async fn setup() -> Env {
    let e = env().await;
    dav(&e, "anna", "MKCOL", "/Shared", &[], "").await;
    dav(
        &e,
        "anna",
        "PUT",
        "/Shared/hello.txt",
        &[],
        "hello shared\n",
    )
    .await;
    dav(&e, "anna", "MKCOL", "/Shared/sub", &[], "").await;
    dav(&e, "anna", "MKCOL", "/Private", &[], "").await;
    dav(&e, "anna", "PUT", "/Private/secret.txt", &[], "secret").await;
    dav(&e, "anna", "PUT", "/single.txt", &[], "single file\n").await;
    e
}

// ---- OCS ----------------------------------------------------------------------------

#[tokio::test]
async fn creating_and_reading_shares_matches_the_reference() {
    let e = setup().await;
    let r = ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Shared&shareType=0&shareWith=bob&permissions=31",
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(
        r.json()["ocs"]["meta"],
        fx_json("10-shares/08-create-user-share")["ocs"]["meta"]
    );
    let d = r.data();
    keys_subset(
        &d,
        &fx_json("10-shares/08-create-user-share")["ocs"]["data"],
        "share",
    );
    assert_eq!(
        (d["id"].as_str(), d["share_type"].as_i64()),
        (Some("1"), Some(0))
    );
    assert_eq!(
        d["permissions"], 15,
        "bit 16 is dropped, we have no resharing"
    );
    assert_eq!(
        (
            d["uid_owner"].as_str(),
            d["share_with"].as_str(),
            d["item_type"].as_str(),
            d["path"].as_str()
        ),
        (Some("anna"), Some("bob"), Some("folder"), Some("/Shared"))
    );
    assert_eq!(d["mimetype"], "httpd/unix-directory");
    assert_eq!(d["can_edit"], true);

    // the same share again returns the existing one
    let again = ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Shared&shareType=0&shareWith=bob&permissions=1",
    )
    .await;
    assert_eq!(again.data()["id"], "1");

    // a file share: only read/update bits remain
    let f = ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/single.txt&shareType=0&shareWith=carl&permissions=1",
    )
    .await;
    assert_eq!(f.data()["item_type"], "file");
    keys_subset(
        &f.data(),
        &fx_json("10-shares/16-create-file-share-readonly")["ocs"]["data"],
        "file share",
    );

    // read back as owner, as recipient, as stranger
    let own = ocs(&e, "anna", "GET", "/shares/1", "").await;
    assert_eq!(own.status, 200);
    assert_eq!(own.data()[0]["share_with"], "bob");
    let rec = ocs(&e, "bob", "GET", "/shares/1", "").await;
    assert_eq!(rec.status, 200);
    assert_eq!(
        (
            rec.data()[0]["can_edit"].as_bool(),
            rec.data()[0]["mount-type"].as_str(),
            rec.data()[0]["is-mount-root"].as_bool()
        ),
        (Some(false), Some("shared"), Some(true))
    );
    let stranger = ocs(&e, "carl", "GET", "/shares/1", "").await;
    assert_eq!(
        stranger.status.as_u16(),
        fx_status("10-shares/20-get-share-as-stranger")
    );
    assert_eq!(stranger.msg(), "Wrong share ID, share does not exist");
    assert_eq!(
        ocs(&e, "root", "GET", "/shares/1", "").await.status,
        404,
        "admins see no foreign shares"
    );
    assert_eq!(
        ocs(&e, "anna", "GET", "/shares/999999", "").await.status,
        404
    );

    // lists
    let all = ocs(&e, "anna", "GET", "/shares", "").await;
    assert_eq!(all.data().as_array().expect("a").len(), 2);
    let by_path = ocs(&e, "anna", "GET", "/shares?path=/Shared", "").await;
    assert_eq!(by_path.data().as_array().expect("a").len(), 1);
    let incoming = ocs(&e, "bob", "GET", "/shares?shared_with_me=true", "").await;
    let inc = incoming.data();
    assert_eq!(inc.as_array().expect("a").len(), 1);
    assert_eq!(
        (inc[0]["file_target"].as_str(), inc[0]["can_edit"].as_bool()),
        (Some("/Shared"), Some(false))
    );
    assert_eq!(
        ocs(&e, "carl", "GET", "/shares", "")
            .await
            .data()
            .as_array()
            .expect("a")
            .len(),
        0,
        "carl gave nothing"
    );
    assert_eq!(
        ocs(&e, "bob", "GET", "/shares/pending", "").await.data(),
        serde_json::json!([])
    );
    assert_eq!(
        ocs(&e, "bob", "GET", "/shares?path=/Shared", "")
            .await
            .status,
        404,
        "bob cannot enumerate through a path"
    );
}

#[tokio::test]
async fn errors_carry_the_reference_status_and_message() {
    let e = setup().await;
    let cases: Vec<(&str, &str)> = vec![
        (
            "path=/Shared&shareType=0&shareWith=anna&permissions=31",
            "10-shares/10-create-share-with-self",
        ),
        (
            "path=/Shared&shareType=0&shareWith=nobody-here&permissions=31",
            "10-shares/11-create-share-unknown-user",
        ),
        (
            "path=/does-not-exist&shareType=0&shareWith=bob&permissions=31",
            "10-shares/12-create-share-missing-path",
        ),
        (
            "shareType=0&shareWith=bob&permissions=31",
            "10-shares/13-create-share-no-path",
        ),
        (
            "path=/Shared&shareType=0&shareWith=carl&permissions=99",
            "10-shares/14-create-share-bad-permissions",
        ),
        (
            "path=/Shared&shareType=77&shareWith=carl&permissions=1",
            "10-shares/15-create-share-bad-type",
        ),
    ];
    for (form, fx) in cases {
        let r = ocs(&e, "anna", "POST", "/shares", form).await;
        assert_eq!(r.status.as_u16(), fx_status(fx), "{fx}");
        let want = fx_json(fx)["ocs"]["meta"].clone();
        assert_eq!(r.json()["ocs"]["meta"], want, "{fx}");
    }
    // not the owner: the path does not exist in the caller's tree
    let r = ocs(
        &e,
        "carl",
        "POST",
        "/shares",
        "path=/Shared&shareType=0&shareWith=bob&permissions=1",
    )
    .await;
    assert_eq!(
        r.status.as_u16(),
        fx_status("10-shares/17-create-share-by-non-owner")
    );
    assert_eq!(
        r.json()["ocs"]["meta"],
        fx_json("10-shares/17-create-share-by-non-owner")["ocs"]["meta"]
    );

    ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Shared&shareType=0&shareWith=bob&permissions=31",
    )
    .await;
    let r = ocs(&e, "anna", "PUT", "/shares/1", "permissions=2").await;
    assert_eq!(
        r.status.as_u16(),
        fx_status("10-shares/55-update-bad-permissions")
    );
    assert_eq!(r.msg(), "File share needs at least read permission.");
    let r = ocs(&e, "bob", "PUT", "/shares/1", "permissions=15").await;
    assert_eq!(
        (r.status.as_u16(), r.msg().as_str()),
        (
            fx_status("10-shares/56-update-by-recipient"),
            "You are not allowed to edit incoming shares"
        )
    );
    let r = ocs(&e, "carl", "PUT", "/shares/1", "permissions=1").await;
    assert_eq!(r.status, 404);
    let r = ocs(&e, "anna", "PUT", "/shares/1", "expireDate=2000-01-01").await;
    assert_eq!(
        (r.status.as_u16(), r.msg().as_str()),
        (
            fx_status("10-shares/59-update-expire-past"),
            "Expiration date is in the past"
        )
    );
    // resharing is off
    let r = ocs(
        &e,
        "bob",
        "POST",
        "/shares",
        "path=/Shared&shareType=0&shareWith=carl&permissions=1",
    )
    .await;
    assert_eq!(
        (r.status.as_u16(), r.msg().as_str()),
        (403, "Resharing is not allowed")
    );
    // unauthenticated / wrong header
    let r = send(
        &e,
        None,
        "GET",
        &format!("{API}/shares?format=json"),
        &[("ocs-apirequest", "true")],
        "",
    )
    .await;
    assert_eq!(r.status, 401);
    let r = send(
        &e,
        Some(("anna", PW)),
        "GET",
        &format!("{API}/shares?format=json"),
        &[],
        "",
    )
    .await;
    assert_eq!(r.status, 412);
    // deletion
    assert_eq!(ocs(&e, "bob", "DELETE", "/shares/1", "").await.status, 404);
    assert_eq!(ocs(&e, "carl", "DELETE", "/shares/1", "").await.status, 404);
    assert_eq!(ocs(&e, "anna", "DELETE", "/shares/1", "").await.status, 200);
    let again = ocs(&e, "anna", "DELETE", "/shares/1", "").await;
    assert_eq!(
        again.status.as_u16(),
        fx_status("10-shares/68-delete-share-again")
    );
}

#[tokio::test]
async fn sharee_search_matches_the_reference_shape() {
    let e = setup().await;
    let r = ocs(
        &e,
        "anna",
        "GET",
        "/sharees?search=bo&itemType=file&perPage=10",
        "",
    )
    .await;
    assert_eq!(r.status, 200);
    keys_subset(
        &r.data(),
        &fx_json("10-shares/06-sharees")["ocs"]["data"],
        "sharees",
    );
    assert_eq!(
        r.data()["users"][0]["value"],
        serde_json::json!({"shareType": 0, "shareWith": "bob"})
    );
    assert_eq!(r.data()["exact"]["users"], serde_json::json!([]));
    let exact = ocs(&e, "anna", "GET", "/sharees?search=bob&itemType=file", "").await;
    assert_eq!(exact.data()["exact"]["users"][0]["label"], "bob");
    assert_eq!(exact.data()["users"], serde_json::json!([]));
    let none = ocs(&e, "anna", "GET", "/sharees?search=an", "").await;
    assert_eq!(
        none.data()["users"],
        serde_json::json!([]),
        "never the caller"
    );
    assert_eq!(
        fx_json("10-shares/06-sharees")["ocs"]["data"]["lookupEnabled"],
        false
    );
}

// ---- recipient's view and rights over WebDAV --------------------------------------------

#[tokio::test]
async fn the_recipient_sees_a_mount_point_like_in_the_reference() {
    let e = setup().await;
    ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Shared&shareType=0&shareWith=bob&permissions=31",
    )
    .await;
    dav(&e, "bob", "PUT", "/mine.txt", &[], "bobs").await;

    let r = dav(
        &e,
        "bob",
        "PROPFIND",
        "/",
        &[("depth", "1"), ("content-type", "application/xml")],
        PROPS,
    )
    .await;
    assert_eq!(r.status, 207);
    let got = prop_statuses(&r.text());
    assert!(
        got.contains_key("Shared") && got.contains_key("mine.txt"),
        "{:?}",
        got.keys()
    );
    let want = prop_statuses(
        fixture("10-shares/29-bob-propfind-root")["response"]["body"]["text"]
            .as_str()
            .expect("t"),
    );
    let want_mount = want
        .iter()
        .find(|(k, _)| k.contains("folder"))
        .expect("mount in reference")
        .1;
    assert_eq!(
        &got["Shared"], want_mount,
        "same properties found / not found as for the reference's mount point"
    );
    let t = r.text();
    assert!(t.contains("<oc:owner-id>anna</oc:owner-id>"));
    assert!(t.contains("<nc:mount-type>shared</nc:mount-type>"));
    assert!(t.contains("<nc:is-mount-root>true</nc:is-mount-root>"));
    // permissions: shared + read + delete + rename + move + create (no reshare letter)
    assert!(
        t.contains("<oc:permissions>SGDNVCK</oc:permissions>"),
        "{t}"
    );

    // inside the share
    let r = dav(
        &e,
        "bob",
        "PROPFIND",
        "/Shared",
        &[("depth", "1"), ("content-type", "application/xml")],
        PROPS,
    )
    .await;
    let got = prop_statuses(&r.text());
    let want = prop_statuses(&fx_text("10-shares/30-bob-propfind-share"));
    let find = |m: &BTreeMap<String, BTreeMap<String, u16>>, suffix: &str| {
        m.iter()
            .find(|(k, _)| k.ends_with(suffix))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("no {suffix}"))
    };
    assert_eq!(find(&got, "hello.txt"), find(&want, "hello.txt"));
    assert_eq!(find(&got, "sub"), find(&want, "sub"));
    let t = r.text();
    assert_eq!(
        t.matches("<nc:is-mount-root>true</nc:is-mount-root>")
            .count(),
        1,
        "only the share root"
    );
    assert!(
        t.contains("<oc:share-types><oc:share-type>0</oc:share-type></oc:share-types>"),
        "the mount root carries the share type"
    );

    // the owner sees the share type on her folder and her own letters
    let r = dav(
        &e,
        "anna",
        "PROPFIND",
        "/Shared",
        &[("depth", "0"), ("content-type", "application/xml")],
        PROPS,
    )
    .await;
    let t = r.text();
    assert!(
        t.contains("<oc:share-types><oc:share-type>0</oc:share-type></oc:share-types>"),
        "{t}"
    );
    assert!(
        t.contains("<oc:permissions>RGDNVCK</oc:permissions>")
            && t.contains("<nc:mount-type></nc:mount-type>")
            || t.contains("<nc:mount-type/>")
    );
    // content is readable and owned by anna
    assert_eq!(
        dav(&e, "bob", "GET", "/Shared/hello.txt", &[], "")
            .await
            .text(),
        "hello shared\n"
    );
    // a stranger and an admin see nothing
    for u in ["carl", "root"] {
        assert_eq!(
            dav(&e, u, "GET", "/Shared/hello.txt", &[], "").await.status,
            404,
            "{u}"
        );
        assert!(
            !dav(&e, u, "PROPFIND", "/", &[("depth", "1")], "")
                .await
                .text()
                .contains("Shared"),
            "{u}"
        );
    }
}

#[tokio::test]
async fn permissions_are_enforced_with_forbidden_for_denied_writes() {
    let e = setup().await;
    ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Shared&shareType=0&shareWith=bob&permissions=1",
    )
    .await;
    // read-only (fixtures 44-48): writes are 403
    for (m, p, h) in [
        ("PUT", "/Shared/denied.txt", None),
        ("MKCOL", "/Shared/denied", None),
        ("PUT", "/Shared/hello.txt", None),
        ("DELETE", "/Shared/hello.txt", None),
        ("MOVE", "/Shared/hello.txt", Some("/Shared/x.txt")),
    ] {
        let hdr = h.map(|d| format!("http://cloud.test/remote.php/dav/files/bob{d}"));
        let headers: Vec<(&str, &str)> = hdr
            .as_deref()
            .map(|d| ("destination", d))
            .into_iter()
            .collect();
        let r = dav(&e, "bob", m, p, &headers, "x").await;
        assert_eq!(r.status, 403, "{m} {p}");
        assert!(r.text().contains("Sabre\\DAV\\Exception\\Forbidden"));
    }
    for fx in [
        "10-shares/44-bob-put-readonly",
        "10-shares/45-bob-mkcol-readonly",
        "10-shares/46-bob-overwrite-readonly",
        "10-shares/47-bob-delete-readonly",
        "10-shares/48-bob-move-readonly",
    ] {
        assert_eq!(fx_status(fx), 403, "{fx}");
    }
    // copying out is allowed (fixture 49) and yields an own, writable file
    let c = dav(
        &e,
        "bob",
        "COPY",
        "/Shared/hello.txt",
        &[(
            "destination",
            "http://cloud.test/remote.php/dav/files/bob/copy.txt",
        )],
        "",
    )
    .await;
    assert_eq!(
        (
            c.status.as_u16(),
            fx_status("10-shares/49-bob-copy-out-of-readonly")
        ),
        (201, 201)
    );
    assert_eq!(
        dav(&e, "bob", "PUT", "/copy.txt", &[], "mine now")
            .await
            .status,
        204
    );
    // roots of mounts: the recipient may rename/leave even read-only
    let r = dav(
        &e,
        "bob",
        "PROPFIND",
        "/Shared",
        &[("depth", "0"), ("content-type", "application/xml")],
        PROPS,
    )
    .await;
    assert!(
        r.text().contains("<oc:permissions>SGDN</oc:permissions>"),
        "reference: SGDN for a read-only root"
    );

    // create only (5): new file yes, overwrite no (fixtures 52, 53)
    ocs(&e, "anna", "PUT", "/shares/1", "permissions=5").await;
    assert_eq!(
        dav(&e, "bob", "PUT", "/Shared/new.txt", &[], "n")
            .await
            .status,
        201
    );
    assert_eq!(
        dav(&e, "bob", "PUT", "/Shared/new.txt", &[], "o")
            .await
            .status,
        403
    );
    assert_eq!(
        (
            fx_status("10-shares/52-bob-put-create-only"),
            fx_status("10-shares/53-bob-overwrite-create-only")
        ),
        (201, 403)
    );
    // full rights
    ocs(&e, "anna", "PUT", "/shares/1", "permissions=31").await;
    assert_eq!(
        dav(
            &e,
            "bob",
            "PUT",
            "/Shared/hello.txt",
            &[],
            "changed by bob\n"
        )
        .await
        .status,
        204
    );
    assert_eq!(
        dav(&e, "bob", "MKCOL", "/Shared/bobdir", &[], "")
            .await
            .status,
        201
    );
    let mv = dav(
        &e,
        "bob",
        "MOVE",
        "/Shared/new.txt",
        &[(
            "destination",
            "http://cloud.test/remote.php/dav/files/bob/Shared/renamed.txt",
        )],
        "",
    )
    .await;
    assert_eq!(mv.status, 201);
    assert_eq!(
        dav(&e, "bob", "DELETE", "/Shared/renamed.txt", &[], "")
            .await
            .status,
        204
    );
    assert_eq!(
        dav(&e, "anna", "GET", "/Shared/hello.txt", &[], "")
            .await
            .text(),
        "changed by bob\n",
        "the owner sees the change"
    );
    // moving across trees is refused in both directions
    dav(&e, "bob", "PUT", "/mine.txt", &[], "bobs").await;
    for (from, to) in [
        ("/mine.txt", "/Shared/m.txt"),
        ("/Shared/hello.txt", "/h.txt"),
    ] {
        let r = dav(
            &e,
            "bob",
            "MOVE",
            from,
            &[(
                "destination",
                &format!("http://cloud.test/remote.php/dav/files/bob{to}"),
            )],
            "",
        )
        .await;
        assert_eq!(r.status, 409, "{from} -> {to}");
    }
    // ... and nothing leaks through traversal tricks
    for p in [
        "/Shared/../Private/secret.txt",
        "/Shared/%2e%2e/Private/secret.txt",
        "/Private/secret.txt",
        "/Shared%2f..%2fPrivate",
    ] {
        let r = dav(&e, "bob", "GET", p, &[], "").await;
        assert!(r.status == 400 || r.status == 404, "{p}: {}", r.status);
        assert!(!r.text().contains("secret"), "{p}");
    }
    let r = dav(
        &e,
        "bob",
        "MOVE",
        "/Shared/bobdir",
        &[(
            "destination",
            "http://cloud.test/remote.php/dav/files/bob/Shared/../../anna/x",
        )],
        "",
    )
    .await;
    assert!(r.status.is_client_error());
    // the versions of a shared file stay private to the owner
    let id = {
        let r = dav(&e, "anna", "PROPFIND", "/Shared/hello.txt", &[("depth", "0")], r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>"#).await;
        r.text()
            .split("<oc:fileid>")
            .nth(1)
            .and_then(|s| s.split('<').next())
            .expect("id")
            .to_owned()
    };
    let r = send(
        &e,
        Some(("bob", PW)),
        "PROPFIND",
        &format!("/remote.php/dav/versions/bob/versions/{id}"),
        &[("depth", "1")],
        "",
    )
    .await;
    assert_eq!(r.status, 404);
    let r = send(
        &e,
        Some(("anna", PW)),
        "PROPFIND",
        &format!("/remote.php/dav/versions/anna/versions/{id}"),
        &[("depth", "1")],
        "",
    )
    .await;
    assert_eq!(r.status, 207);
}

#[tokio::test]
async fn mount_points_rename_leave_and_follow_the_owner() {
    let e = setup().await;
    ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Shared&shareType=0&shareWith=bob&permissions=31",
    )
    .await;
    // rename (fixture 60-63)
    let r = dav(
        &e,
        "bob",
        "MOVE",
        "/Shared",
        &[(
            "destination",
            "http://cloud.test/remote.php/dav/files/bob/Renamed",
        )],
        "",
    )
    .await;
    assert_eq!(
        (
            r.status.as_u16(),
            fx_status("10-shares/60-bob-rename-mount")
        ),
        (201, 201)
    );
    assert_eq!(
        dav(&e, "bob", "GET", "/Renamed/hello.txt", &[], "")
            .await
            .status,
        200
    );
    assert_eq!(
        dav(&e, "bob", "GET", "/Shared/hello.txt", &[], "")
            .await
            .status,
        404
    );
    assert_eq!(
        ocs(&e, "anna", "GET", "/shares/1", "").await.status,
        200,
        "the share survives (fixture 63)"
    );
    // the owner moves the folder: the share follows (fixture 96/97)
    dav(&e, "anna", "MKCOL", "/Archive", &[], "").await;
    let m = dav(
        &e,
        "anna",
        "MOVE",
        "/Shared",
        &[(
            "destination",
            "http://cloud.test/remote.php/dav/files/anna/Archive/Moved",
        )],
        "",
    )
    .await;
    assert_eq!(m.status, 201);
    assert_eq!(
        dav(&e, "bob", "GET", "/Renamed/hello.txt", &[], "")
            .await
            .status,
        200
    );
    assert_eq!(
        ocs(&e, "anna", "GET", "/shares/1", "").await.data()[0]["path"],
        "/Archive/Moved"
    );
    // leaving (fixture 64-66): deleting the mount deletes the share
    let d = dav(&e, "bob", "DELETE", "/Renamed", &[], "").await;
    assert_eq!(
        (
            d.status.as_u16(),
            fx_status("10-shares/64-bob-delete-mount")
        ),
        (204, 204)
    );
    assert_eq!(
        ocs(&e, "anna", "GET", "/shares/1", "")
            .await
            .status
            .as_u16(),
        fx_status("10-shares/66-get-share-after-recipient-delete")
    );
    assert_eq!(
        dav(&e, "anna", "GET", "/Archive/Moved/hello.txt", &[], "")
            .await
            .status,
        200,
        "the owner keeps her data"
    );

    // owner deletes the shared folder: the mount disappears (fixture 98/99)
    ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Archive/Moved&shareType=0&shareWith=bob&permissions=15",
    )
    .await;
    assert!(
        dav(&e, "bob", "PROPFIND", "/", &[("depth", "1")], "")
            .await
            .text()
            .contains("Moved")
    );
    dav(&e, "anna", "DELETE", "/Archive/Moved", &[], "").await;
    assert!(
        !dav(&e, "bob", "PROPFIND", "/", &[("depth", "1")], "")
            .await
            .text()
            .contains("Moved")
    );
}

#[tokio::test]
async fn the_root_etag_changes_when_a_share_changes() {
    let e = setup().await;
    ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Shared&shareType=0&shareWith=bob&permissions=15",
    )
    .await;
    let etag = |r: &Res| {
        r.text()
            .split("<d:getetag>")
            .nth(1)
            .and_then(|s| s.split("</d:getetag>").next())
            .unwrap_or("")
            .to_owned()
    };
    let q = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getetag/></d:prop></d:propfind>"#;
    let before = etag(&dav(&e, "bob", "PROPFIND", "/", &[("depth", "0")], q).await);
    assert!(!before.is_empty());
    assert_eq!(
        before,
        etag(&dav(&e, "bob", "PROPFIND", "/", &[("depth", "0")], q).await),
        "stable while nothing changes"
    );
    dav(&e, "anna", "PUT", "/Shared/sub/new.txt", &[], "x").await;
    let after = etag(&dav(&e, "bob", "PROPFIND", "/", &[("depth", "0")], q).await);
    assert_ne!(
        before, after,
        "clients poll the root ETag to notice changes in shares"
    );
    dav(&e, "bob", "PUT", "/Shared/by-bob.txt", &[], "x").await;
    assert_ne!(
        after,
        etag(&dav(&e, "bob", "PROPFIND", "/", &[("depth", "0")], q).await)
    );
}

#[tokio::test]
async fn writing_into_a_share_charges_the_owner() {
    let e = setup().await;
    ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Shared&shareType=0&shareWith=bob&permissions=15",
    )
    .await;
    let q = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:quota-used-bytes/></d:prop></d:propfind>"#;
    let used = |r: Res| -> i64 {
        r.text()
            .split("<d:quota-used-bytes>")
            .nth(1)
            .and_then(|s| s.split('<').next())
            .expect("q")
            .parse()
            .expect("n")
    };
    let (a0, b0) = (
        used(dav(&e, "anna", "PROPFIND", "/", &[("depth", "0")], q).await),
        used(dav(&e, "bob", "PROPFIND", "/", &[("depth", "0")], q).await),
    );
    assert_eq!(b0, 0);
    dav(&e, "bob", "PUT", "/Shared/big.bin", &[], vec![1u8; 1000]).await;
    assert_eq!(
        used(dav(&e, "anna", "PROPFIND", "/", &[("depth", "0")], q).await),
        a0 + 1000
    );
    assert_eq!(
        used(dav(&e, "bob", "PROPFIND", "/", &[("depth", "0")], q).await),
        0
    );
}

// ---- public links ---------------------------------------------------------------------------

#[tokio::test]
async fn public_links_follow_the_reference() {
    let e = setup().await;
    let r = ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Shared&shareType=3&permissions=1",
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let d = r.data();
    keys_subset(
        &d,
        &fx_json("10-shares/70-create-public-link")["ocs"]["data"],
        "link",
    );
    let token = d["token"].as_str().expect("token").to_owned();
    assert_eq!(token.len(), 24);
    assert_eq!(d["url"], format!("http://cloud.test/s/{token}"));
    assert_eq!(
        (
            d["share_with_displayname"].as_str(),
            d["permissions"].as_i64(),
            d["password"].is_null()
        ),
        (Some("(Shared link)"), Some(1), true)
    );

    // list and read
    let l = public(
        &e,
        &token,
        "",
        "PROPFIND",
        "/",
        &[("depth", "1"), ("content-type", "application/xml")],
        PROPS,
    )
    .await;
    assert_eq!(l.status, 207, "{}", l.text());
    let t = l.text();
    assert!(
        t.contains("<d:href>/public.php/webdav/</d:href>")
            && t.contains("<d:href>/public.php/webdav/hello.txt</d:href>"),
        "{t}"
    );
    assert!(!t.contains("Private") && !t.contains("single.txt"));
    assert!(
        t.contains("<oc:permissions>G</oc:permissions>"),
        "read-only link; the reference adds R because of its share bit"
    );
    assert_eq!(
        public(&e, &token, "", "GET", "/hello.txt", &[], "")
            .await
            .text(),
        "hello shared\n"
    );
    assert_eq!(
        public(
            &e,
            &token,
            "",
            "GET",
            "/sub/../../Private/secret.txt",
            &[],
            ""
        )
        .await
        .status,
        400
    );
    assert_eq!(
        public(&e, &token, "", "GET", "/Private/secret.txt", &[], "")
            .await
            .status,
        404
    );
    // read-only (fixture 73)
    let r = public(&e, &token, "", "PUT", "/up.txt", &[], "x").await;
    assert_eq!(
        (
            r.status.as_u16(),
            fx_status("10-shares/73-public-put-readonly")
        ),
        (403, 403)
    );
    // authentication failures (fixtures 74, 75)
    let r = send(
        &e,
        None,
        "PROPFIND",
        "/public.php/webdav/",
        &[("depth", "0")],
        "",
    )
    .await;
    assert_eq!(
        (r.status.as_u16(), fx_status("10-shares/74-public-no-auth")),
        (401, 401)
    );
    assert!(r.h("www-authenticate").starts_with("Basic"));
    let r = public(
        &e,
        "wrongtoken123",
        "",
        "PROPFIND",
        "/",
        &[("depth", "0")],
        "",
    )
    .await;
    assert_eq!(
        r.status.as_u16(),
        fx_status("10-shares/75-public-wrong-token")
    );
    // users cannot use the public namespace, links cannot use the user namespaces
    assert_eq!(
        send(
            &e,
            Some(("anna", PW)),
            "PROPFIND",
            "/public.php/webdav/",
            &[("depth", "0")],
            ""
        )
        .await
        .status,
        401
    );
    for uri in [
        "/remote.php/dav/files/anna/",
        "/remote.php/webdav/",
        "/remote.php/dav/versions/anna/",
        "/remote.php/dav/uploads/anna/x",
        "/ocs/v2.php/cloud/user?format=json",
    ] {
        let r = send(
            &e,
            Some((&token, "")),
            "PROPFIND",
            uri,
            &[("depth", "0"), ("ocs-apirequest", "true")],
            "",
        )
        .await;
        assert!(
            [401, 403, 404, 405].contains(&r.status.as_u16()),
            "{uri}: {}",
            r.status
        );
    }

    // editable link (fixtures 79-81)
    let id = d["id"].as_str().expect("id").to_owned();
    ocs(
        &e,
        "anna",
        "PUT",
        &format!("/shares/{id}"),
        "permissions=15",
    )
    .await;
    let r = public(&e, &token, "", "PUT", "/up.txt", &[], "uploaded via link\n").await;
    assert_eq!(
        (r.status.as_u16(), fx_status("10-shares/80-public-put-edit")),
        (201, 201)
    );
    assert_eq!(
        dav(&e, "anna", "GET", "/Shared/up.txt", &[], "")
            .await
            .text(),
        "uploaded via link\n"
    );
    assert_eq!(
        public(&e, &token, "", "MKCOL", "/d", &[], "").await.status,
        201
    );
    assert_eq!(
        public(&e, &token, "", "DELETE", "/up.txt", &[], "")
            .await
            .status,
        204
    );
    assert_eq!(
        public(&e, &token, "", "DELETE", "/", &[], "").await.status,
        403,
        "the root of a link stays"
    );
    let mv = public(
        &e,
        &token,
        "",
        "MOVE",
        "/d",
        &[("destination", "http://cloud.test/public.php/webdav/d2")],
        "",
    )
    .await;
    assert_eq!(mv.status, 201);
    let bad = public(
        &e,
        &token,
        "",
        "MOVE",
        "/d2",
        &[(
            "destination",
            "http://cloud.test/remote.php/dav/files/anna/stolen",
        )],
        "",
    )
    .await;
    assert_eq!(bad.status, 404);

    // deleting the link (fixture 92/93)
    assert_eq!(
        ocs(&e, "anna", "DELETE", &format!("/shares/{id}"), "")
            .await
            .status,
        200
    );
    assert_eq!(
        public(&e, &token, "", "PROPFIND", "/", &[("depth", "0")], PROPS)
            .await
            .status
            .as_u16(),
        fx_status("10-shares/93-public-after-delete")
    );
}

#[tokio::test]
async fn link_passwords_and_file_links() {
    let e = setup().await;
    let r = ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Shared&shareType=3&permissions=1&password=link-secret-password-1",
    )
    .await;
    let token = r.data()["token"].as_str().expect("t").to_owned();
    assert_eq!(r.data()["password"], "protected", "the hash is never shown");
    let body = r.text();
    assert!(!body.contains("$argon2"), "no hash in the API");
    // fixtures 84-86
    let guesser = |pw: &'static str| {
        let e = &e;
        let token = token.clone();
        async move {
            public(e, &token, pw, "PROPFIND", "/", &[("depth", "0")], PROPS)
                .await
                .status
        }
    };
    assert_eq!(
        (
            guesser("").await.as_u16(),
            fx_status("10-shares/84-public-propfind-no-password")
        ),
        (401, 401)
    );
    assert_eq!(guesser("wrong").await, 401);
    assert_eq!(
        (
            guesser("link-secret-password-1").await.as_u16(),
            fx_status("10-shares/86-public-propfind-password")
        ),
        (207, 207)
    );
    // a password that is too short is refused when creating
    let short = ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Shared&shareType=3&password=short",
    )
    .await;
    assert_eq!(short.status, 400);

    // a link to a single file: the file is the root
    let f = ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/single.txt&shareType=3&permissions=1",
    )
    .await;
    let ft = f.data()["token"].as_str().expect("t").to_owned();
    assert_eq!(f.data()["item_type"], "file");
    assert_eq!(
        public(&e, &ft, "", "GET", "/", &[], "").await.text(),
        "single file\n"
    );
    let l = public(&e, &ft, "", "PROPFIND", "/", &[("depth", "1")], PROPS).await;
    assert_eq!(l.status, 207);
    assert_eq!(l.text().matches("<d:response>").count(), 1);
    assert!(
        !public(&e, &ft, "", "PUT", "/x", &[], "x")
            .await
            .status
            .is_success()
    );
    // an expired link is gone
    let x = ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Shared&shareType=3&permissions=1&expireDate=2000-01-01",
    )
    .await;
    assert_eq!(
        x.status.as_u16(),
        fx_status("10-shares/88-create-link-expired")
    );
    // capabilities advertise exactly this
    let c = ocs(
        &e,
        "anna",
        "GET",
        "/../../../../ocs/v2.php/cloud/capabilities",
        "",
    )
    .await;
    let _ = c;
    let caps = send(
        &e,
        Some(("bob", PW)),
        "GET",
        "/ocs/v2.php/cloud/capabilities?format=json",
        &[("ocs-apirequest", "true")],
        "",
    )
    .await;
    let fs = caps.json()["ocs"]["data"]["capabilities"]["files_sharing"].clone();
    keys_subset(
        &fs,
        &fx_json("10-shares/05-capabilities")["ocs"]["data"]["capabilities"]["files_sharing"],
        "files_sharing",
    );
    assert_eq!(
        (
            fs["resharing"].as_bool(),
            fs["group_sharing"].as_bool(),
            fs["api_enabled"].as_bool()
        ),
        (Some(false), Some(false), Some(true))
    );
    // brute force on a protected link ends in 429 for everybody
    for _ in 0..10 {
        guesser("guess").await;
    }
    assert_eq!(guesser("link-secret-password-1").await, 429);
}

#[tokio::test]
async fn disabled_and_deleted_users_lose_their_shares() {
    let e = setup().await;
    ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Shared&shareType=0&shareWith=bob&permissions=15",
    )
    .await;
    let r = ocs(
        &e,
        "anna",
        "POST",
        "/shares",
        "path=/Shared&shareType=3&permissions=1",
    )
    .await;
    let token = r.data()["token"].as_str().expect("t").to_owned();
    assert_eq!(
        public(&e, &token, "", "GET", "/hello.txt", &[], "")
            .await
            .status,
        200
    );
    // the shared data of a user whose account is deleted disappears with it
    assert_eq!(
        dav(&e, "bob", "GET", "/Shared/hello.txt", &[], "")
            .await
            .status,
        200
    );
}
