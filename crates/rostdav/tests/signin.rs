//! M4: sign-in like Nextcloud. Responses are checked against the recorded
//! reference fixtures (`tests/fixtures/nextcloud/`) and against browser-like
//! use of the Login Flow v2 page.

use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use rostdav::config::Config;
use serde_json::Value;
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
    let state = rostdav::build_state(&cfg).await.expect("state");
    state.add_user("anna", PW, false).await.expect("anna");
    state.add_user("bob", PW, true).await.expect("bob");
    Env {
        app: rostdav::http::router_with(state, &rostdav::http::HttpOptions::from_config(&cfg)),
        _dir: dir,
    }
}

struct Res {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Res {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.body))
    }
    fn header(&self, n: &str) -> &str {
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

async fn send(e: &Env, method: &str, uri: &str, headers: &[(&str, String)], body: &str) -> Res {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "cloud.test");
    for (k, v) in headers {
        b = b.header(*k, v);
    }
    let res = e
        .app
        .clone()
        .oneshot(b.body(Body::from(body.to_owned())).expect("req"))
        .await
        .expect("res");
    let (parts, body) = res.into_parts();
    Res {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&body.collect().await.expect("body").to_bytes()).into_owned(),
    }
}

fn fixture(path: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/nextcloud")
        .join(format!("{path}.json"));
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p:?}: {e}")))
        .expect("fixture json")
}

fn fixture_body_json(path: &str) -> Value {
    let f = fixture(path);
    serde_json::from_str(f["response"]["body"]["text"].as_str().expect("text")).expect("body json")
}

/// Every key we send must exist in the reference (we never invent fields).
fn assert_keys_subset(ours: &Value, theirs: &Value, at: &str) {
    if let (Value::Object(o), Value::Object(t)) = (ours, theirs) {
        for (k, v) in o {
            let tv = t
                .get(k)
                .unwrap_or_else(|| panic!("invented field {at}/{k}"));
            assert_keys_subset(v, tv, &format!("{at}/{k}"));
        }
    }
}

fn ocs_headers(u: &str, p: &str) -> Vec<(&'static str, String)> {
    vec![
        ("ocs-apirequest", "true".into()),
        ("authorization", basic(u, p)),
    ]
}

// ---- status.php -------------------------------------------------------------

#[tokio::test]
async fn status_php_matches_reference_shape() {
    let e = env().await;
    let r = send(&e, "GET", "/status.php", &[], "").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), "application/json");
    let ours = r.json();
    let theirs = fixture_body_json("01-discovery/01-status");
    let mut a: Vec<_> = ours.as_object().expect("obj").keys().collect();
    let mut b: Vec<_> = theirs.as_object().expect("obj").keys().collect();
    a.sort();
    b.sort();
    assert_eq!(a, b);
    assert_eq!(ours["installed"], true);
    assert_eq!(ours["maintenance"], false);
    assert_eq!(ours["version"], "35.0.2.2");
    assert_eq!(ours["versionstring"], "35.0.2");
    assert_eq!(ours["productname"], "Rostdav");
}

// ---- OCS ----------------------------------------------------------------------

#[tokio::test]
async fn ocs_requires_header_then_auth_with_reference_bodies() {
    let e = env().await;
    // no OCS-APIRequest header -> 412 {"message":"CSRF check failed"}
    let r = send(
        &e,
        "GET",
        "/ocs/v2.php/cloud/user?format=json",
        &[("authorization", basic("anna", PW))],
        "",
    )
    .await;
    assert_eq!(r.status, 412);
    assert_eq!(
        r.json(),
        fixture_body_json("03-ocs/03-capabilities-no-ocs-header")
    );

    // no credentials
    let r = send(
        &e,
        "GET",
        "/ocs/v2.php/cloud/user?format=json",
        &[("ocs-apirequest", "true".into())],
        "",
    )
    .await;
    assert_eq!(r.status, 401);
    assert_eq!(r.json(), fixture_body_json("03-ocs/08-user-no-auth"));

    // wrong password
    let r = send(
        &e,
        "GET",
        "/ocs/v2.php/cloud/user?format=json",
        &ocs_headers("anna", "falsch-falsch-falsch"),
        "",
    )
    .await;
    assert_eq!(r.status, 401);
    assert_eq!(r.json(), fixture_body_json("03-ocs/07-user-bad-password"));

    // unknown API version
    let r = send(
        &e,
        "GET",
        "/ocs/v9.php/cloud/user",
        &ocs_headers("anna", PW),
        "",
    )
    .await;
    assert_eq!(r.status, 404);
}

#[tokio::test]
async fn ocs_user_json_xml_and_versions() {
    let e = env().await;
    let r = send(
        &e,
        "GET",
        "/ocs/v2.php/cloud/user?format=json",
        &ocs_headers("anna", PW),
        "",
    )
    .await;
    assert_eq!(r.status, 200);
    assert!(r.header("content-type").starts_with("application/json"));
    let ours = r.json();
    assert_eq!(
        ours["ocs"]["meta"],
        fixture_body_json("03-ocs/04-user-json")["ocs"]["meta"]
    );
    assert_keys_subset(
        &ours["ocs"]["data"],
        &fixture_body_json("03-ocs/04-user-json")["ocs"]["data"],
        "user",
    );
    let d = &ours["ocs"]["data"];
    assert_eq!(d["id"], "anna");
    assert_eq!(d["quota"]["total"], -3);
    assert_eq!(d["quota"]["free"], -3);
    assert_eq!(d["groups"], serde_json::json!([]));

    // v1: HTTP 200, statuscode 100, totalitems/itemsperpage present
    let r = send(
        &e,
        "GET",
        "/ocs/v1.php/cloud/user?format=json",
        &ocs_headers("anna", PW),
        "",
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json()["ocs"]["meta"],
        fixture_body_json("03-ocs/06-user-v1-json")["ocs"]["meta"]
    );

    // XML is the default
    let r = send(
        &e,
        "GET",
        "/ocs/v2.php/cloud/user",
        &ocs_headers("bob", PW),
        "",
    )
    .await;
    assert!(r.header("content-type").starts_with("application/xml"));
    assert!(r.body.starts_with("<?xml version=\"1.0\"?>\n<ocs>"));
    assert!(r.body.contains("<statuscode>200</statuscode>"));
    assert!(r.body.contains("<id>bob</id>"));
    assert!(r.body.contains("<enabled>1</enabled>"));
    assert!(r.body.contains("<element>admin</element>"));
    // Accept: application/json also selects JSON
    let mut h = ocs_headers("anna", PW);
    h.push(("accept", "application/json".into()));
    let r = send(&e, "GET", "/ocs/v2.php/cloud/user", &h, "").await;
    assert!(r.header("content-type").starts_with("application/json"));
}

#[tokio::test]
async fn capabilities_advertise_only_what_exists() {
    let e = env().await;
    let r = send(
        &e,
        "GET",
        "/ocs/v2.php/cloud/capabilities?format=json",
        &ocs_headers("anna", PW),
        "",
    )
    .await;
    assert_eq!(r.status, 200);
    let ours = r.json();
    let theirs = fixture_body_json("03-ocs/01-capabilities-json");
    assert_keys_subset(&ours["ocs"]["data"], &theirs["ocs"]["data"], "capabilities");
    let caps = ours["ocs"]["data"]["capabilities"]
        .as_object()
        .expect("caps");
    let mut keys: Vec<_> = caps.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["core", "dav", "files", "files_sharing"],
        "nothing else is implemented"
    );
    assert_eq!(caps["core"]["webdav-root"], "remote.php/webdav");
    assert_eq!(caps["dav"]["chunking"], "1.0");
    assert_eq!(
        caps["files"]["chunked_upload"]["max_size"],
        100 * 1024 * 1024
    );
    assert_eq!(caps["files"]["chunked_upload"]["max_parallel_count"], 5);
    assert_eq!(
        caps["files"]["forbidden_filename_extensions"],
        serde_json::json!([".filepart", ".part"])
    );
    let v = &ours["ocs"]["data"]["version"];
    assert_eq!(
        (v["major"].as_u64(), v["string"].as_str()),
        (Some(35), Some("35.0.2"))
    );
}

#[tokio::test]
async fn quota_block_reflects_usage() {
    let e = env().await;
    let auth = vec![("authorization", basic("anna", PW))];
    send(&e, "PUT", "/remote.php/dav/files/anna/f", &auth, "12345").await;
    let r = send(
        &e,
        "GET",
        "/ocs/v2.php/cloud/user?format=json",
        &ocs_headers("anna", PW),
        "",
    )
    .await;
    assert_eq!(r.json()["ocs"]["data"]["quota"]["used"], 5);
}

// ---- Login Flow v2 ------------------------------------------------------------

struct Flow {
    poll_token: String,
    login_path: String,
    poll_path: String,
    csrf: String,
}

fn path_of(url: &str) -> String {
    format!("/{}", url.splitn(4, '/').nth(3).expect("url path"))
}

fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            let enc = |s: &str| {
                s.bytes()
                    .map(|b| {
                        if b.is_ascii_alphanumeric() {
                            (b as char).to_string()
                        } else {
                            format!("%{b:02X}")
                        }
                    })
                    .collect::<String>()
            };
            format!("{}={}", enc(k), enc(v))
        })
        .collect::<Vec<_>>()
        .join("&")
}

async fn start_flow(e: &Env) -> Flow {
    let r = send(
        e,
        "POST",
        "/index.php/login/v2",
        &[("user-agent", "Nextcloud-Android/3.30".into())],
        "",
    )
    .await;
    assert_eq!(r.status, 200);
    let j = r.json();
    let reference = fixture_body_json("02-login-flow-v2/01-start");
    assert_eq!(
        j.as_object().expect("o").keys().collect::<Vec<_>>(),
        reference.as_object().expect("o").keys().collect::<Vec<_>>()
    );
    assert_eq!(j["poll"]["token"].as_str().expect("t").len(), 128);
    let login_path = path_of(j["login"].as_str().expect("login"));
    assert!(login_path.starts_with("/login/v2/flow/"), "{login_path}");
    assert!(
        j["login"]
            .as_str()
            .expect("l")
            .starts_with("http://cloud.test/")
    );
    let poll_path = path_of(j["poll"]["endpoint"].as_str().expect("ep"));
    assert_eq!(poll_path, "/login/v2/poll");
    let page = send(e, "GET", &login_path, &[], "").await;
    assert_eq!(page.status, 200);
    let csrf = page
        .body
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf")
        .to_owned();
    Flow {
        poll_token: j["poll"]["token"].as_str().expect("t").to_owned(),
        login_path,
        poll_path,
        csrf,
    }
}

async fn poll(e: &Env, f: &Flow) -> Res {
    send(
        e,
        "POST",
        &f.poll_path,
        &[("content-type", "application/x-www-form-urlencoded".into())],
        &form_encode(&[("token", &f.poll_token)]),
    )
    .await
}

async fn submit(e: &Env, f: &Flow, action: &str, user: &str, pw: &str, csrf: &str) -> Res {
    send(
        e,
        "POST",
        &f.login_path,
        &[("content-type", "application/x-www-form-urlencoded".into())],
        &form_encode(&[
            ("csrf", csrf),
            ("user", user),
            ("password", pw),
            ("action", action),
        ]),
    )
    .await
}

#[tokio::test]
async fn login_flow_end_to_end_then_sign_out() {
    let e = env().await;
    let f = start_flow(&e).await;

    // pending: 404 with the reference body
    let r = poll(&e, &f).await;
    let reference = fixture("02-login-flow-v2/02-poll-before-grant");
    assert_eq!(
        r.status,
        reference["response"]["status"].as_u64().expect("s") as u16
    );
    assert_eq!(r.body, "[]");

    // the page shows the client name and never the secrets
    let page = send(&e, "GET", &f.login_path, &[], "").await;
    assert!(page.body.contains("Nextcloud-Android/3.30"));
    assert!(!page.body.contains(&f.poll_token));
    assert_eq!(page.header("x-frame-options"), "DENY");
    assert!(
        page.header("content-security-policy")
            .contains("frame-ancestors 'none'")
    );
    assert_eq!(page.header("cache-control"), "no-store");

    // wrong password: 401, form again, no credentials issued
    let r = submit(&e, &f, "allow", "anna", "falsch-falsch-falsch", &f.csrf).await;
    assert_eq!(r.status, 401);
    assert!(r.body.contains("Wrong username or password"));
    assert_eq!(poll(&e, &f).await.status, 404);

    // allow
    let r = submit(&e, &f, "allow", "anna", PW, &f.csrf).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("Device connected"));

    // poll: credentials exactly once, same shape as the reference
    let r = poll(&e, &f).await;
    assert_eq!(r.status, 200);
    let j = r.json();
    let reference = fixture_body_json("02-login-flow-v2/08-poll-after-grant");
    assert_eq!(
        j.as_object().expect("o").keys().collect::<Vec<_>>(),
        reference.as_object().expect("o").keys().collect::<Vec<_>>()
    );
    assert_eq!(j["server"], "http://cloud.test");
    assert_eq!(j["loginName"], "anna");
    let app_pw = j["appPassword"].as_str().expect("pw").to_owned();
    assert_eq!(app_pw.len(), 72);
    assert_eq!(poll(&e, &f).await.status, 404, "only once");
    assert_eq!(
        send(&e, "GET", &f.login_path, &[], "").await.status,
        404,
        "flow is closed"
    );

    // the app password works on WebDAV and OCS
    let dav = send(
        &e,
        "PROPFIND",
        "/remote.php/dav/files/anna/",
        &[
            ("authorization", basic("anna", &app_pw)),
            ("depth", "0".into()),
        ],
        "",
    )
    .await;
    assert_eq!(dav.status, 207);
    let me = send(
        &e,
        "GET",
        "/ocs/v2.php/cloud/user?format=json",
        &ocs_headers("anna", &app_pw),
        "",
    )
    .await;
    assert_eq!(me.status, 200);
    // ... but not for another user
    let other = send(
        &e,
        "PROPFIND",
        "/remote.php/dav/files/bob/",
        &[
            ("authorization", basic("bob", &app_pw)),
            ("depth", "0".into()),
        ],
        "",
    )
    .await;
    assert_eq!(other.status, 401);

    // sign out revokes it
    let r = send(
        &e,
        "DELETE",
        "/ocs/v2.php/core/apppassword?format=json",
        &ocs_headers("anna", &app_pw),
        "",
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json(),
        fixture_body_json("07-logout/01-revoke-app-password")
    );
    let dav = send(
        &e,
        "PROPFIND",
        "/remote.php/dav/files/anna/",
        &[
            ("authorization", basic("anna", &app_pw)),
            ("depth", "0".into()),
        ],
        "",
    )
    .await;
    assert_eq!(dav.status, 401, "revoked app password");
    let me = send(
        &e,
        "GET",
        "/ocs/v2.php/cloud/user?format=json",
        &ocs_headers("anna", &app_pw),
        "",
    )
    .await;
    assert_eq!(me.status, 401);

    // account password still works for Basic
    let dav = send(
        &e,
        "PROPFIND",
        "/remote.php/dav/files/anna/",
        &[("authorization", basic("anna", PW)), ("depth", "0".into())],
        "",
    )
    .await;
    assert_eq!(dav.status, 207);
    // and cannot be "signed out" via the app password endpoint
    let r = send(
        &e,
        "DELETE",
        "/ocs/v2.php/core/apppassword?format=json",
        &ocs_headers("anna", PW),
        "",
    )
    .await;
    assert_eq!(r.status, 400);
}

#[tokio::test]
async fn login_flow_deny_and_forged_forms() {
    let e = env().await;
    let f = start_flow(&e).await;

    // forged / missing CSRF value
    for csrf in ["", "x", &"0".repeat(64)] {
        let r = submit(&e, &f, "allow", "anna", PW, csrf).await;
        assert_eq!(r.status, 403, "{csrf:?}");
    }
    // CSRF value of another flow
    let other = start_flow(&e).await;
    assert_eq!(
        submit(&e, &f, "allow", "anna", PW, &other.csrf)
            .await
            .status,
        403
    );
    assert_eq!(poll(&e, &f).await.status, 404);

    // deny closes the flow
    let r = submit(&e, &f, "deny", "", "", &f.csrf).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("Access denied"));
    assert_eq!(
        submit(&e, &f, "allow", "anna", PW, &f.csrf).await.status,
        404
    );
    assert_eq!(poll(&e, &f).await.status, 404);

    // unknown tokens
    assert_eq!(
        send(&e, "GET", "/login/v2/flow/unknown", &[], "")
            .await
            .status,
        404
    );
    let r = send(
        &e,
        "POST",
        "/login/v2/poll",
        &[("content-type", "application/x-www-form-urlencoded".into())],
        "token=unknown",
    )
    .await;
    assert_eq!(r.status, 404);
}

#[tokio::test]
async fn login_page_escapes_user_input() {
    let e = env().await;
    let f = start_flow(&e).await;
    let r = submit(&e, &f, "allow", "<script>alert(1)</script>", "x", &f.csrf).await;
    assert_eq!(r.status, 401);
    assert!(!r.body.contains("<script>alert"));
    assert!(r.body.contains("&lt;script&gt;"));
}

#[tokio::test]
async fn client_name_from_user_agent_is_escaped_and_bounded() {
    let e = env().await;
    let r = send(
        &e,
        "POST",
        "/login/v2",
        &[("user-agent", format!("<b>{}", "x".repeat(500)))],
        "",
    )
    .await;
    let login = path_of(r.json()["login"].as_str().expect("l"));
    let page = send(&e, "GET", &login, &[], "").await;
    assert!(page.body.contains("&lt;b&gt;"));
    assert!(!page.body.contains(&"x".repeat(200)));
}

// ---- rate limiting -------------------------------------------------------------

#[tokio::test]
async fn repeated_failures_lead_to_429_on_every_login_path() {
    let e = env().await;
    for _ in 0..10 {
        let r = send(
            &e,
            "GET",
            "/remote.php/dav/files/anna/",
            &[("authorization", basic("anna", "falsch-falsch-falsch"))],
            "",
        )
        .await;
        assert_eq!(r.status, 401);
    }
    // now even the correct password is refused, on WebDAV ...
    let r = send(
        &e,
        "GET",
        "/remote.php/dav/files/anna/",
        &[("authorization", basic("anna", PW))],
        "",
    )
    .await;
    assert_eq!(r.status, 429);
    assert!(r.header("retry-after").parse::<u64>().expect("secs") > 0);
    // ... on OCS ...
    let r = send(
        &e,
        "GET",
        "/ocs/v2.php/cloud/user?format=json",
        &ocs_headers("anna", PW),
        "",
    )
    .await;
    assert_eq!(r.status, 429);
    assert!(r.header("retry-after").parse::<u64>().is_ok());
    // ... and on the login page
    let f = start_flow(&e).await;
    let r = submit(&e, &f, "allow", "anna", PW, &f.csrf).await;
    assert_eq!(r.status, 429);
    assert!(r.body.contains("Too many attempts"));
}

// ---- legacy root -----------------------------------------------------------------

#[tokio::test]
async fn legacy_webdav_root_maps_to_the_signed_in_user() {
    let e = env().await;
    let a = vec![("authorization", basic("anna", PW))];
    let b = vec![("authorization", basic("bob", PW))];
    assert_eq!(
        send(&e, "PUT", "/remote.php/webdav/legacy.txt", &a, "hi")
            .await
            .status,
        201
    );
    let g = send(&e, "GET", "/remote.php/dav/files/anna/legacy.txt", &a, "").await;
    assert_eq!(g.body, "hi");
    let l = send(
        &e,
        "PROPFIND",
        "/remote.php/webdav/",
        &[a[0].clone(), ("depth", "1".into())],
        "",
    )
    .await;
    assert_eq!(l.status, 207);
    assert!(
        l.body
            .contains("<d:href>/remote.php/webdav/legacy.txt</d:href>"),
        "{}",
        l.body
    );
    // bob sees his own (empty) root, not anna's
    let l = send(
        &e,
        "PROPFIND",
        "/remote.php/webdav/",
        &[b[0].clone(), ("depth", "1".into())],
        "",
    )
    .await;
    assert!(!l.body.contains("legacy.txt"));
    assert_eq!(
        send(&e, "GET", "/remote.php/webdav/legacy.txt", &b, "")
            .await
            .status,
        404
    );
    // MOVE inside the legacy root with a legacy Destination
    let m = send(
        &e,
        "MOVE",
        "/remote.php/webdav/legacy.txt",
        &[
            a[0].clone(),
            ("destination", "/remote.php/webdav/moved.txt".into()),
        ],
        "",
    )
    .await;
    assert_eq!(m.status, 201);
    assert_eq!(
        send(&e, "GET", "/remote.php/dav/files/anna/moved.txt", &a, "")
            .await
            .body,
        "hi"
    );
}
