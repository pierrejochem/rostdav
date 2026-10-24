//! Unified search, provider `files` (search plan, stage 4). Reference: Nextcloud 35.0.2, recorded
//! 2026-10-24 (`tests/fixtures/nextcloud/12-search/63`–`89`). The reference's home folder holds its
//! default files, so only the entries below the test folder are compared.

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

async fn env(users: &[&str]) -> Env {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().join("data");
    let state: AppState = rostdav::build_state(&cfg).await.expect("state");
    for u in users {
        state.add_user(u, PW, false).await.expect("user");
    }
    Env {
        app: rostdav::http::router(state),
        _dir: dir,
    }
}

struct Res {
    status: StatusCode,
    body: String,
}

async fn send(
    env: &Env,
    method: &str,
    uri: &str,
    user: Option<&str>,
    headers: &[(&str, &str)],
    body: &str,
) -> Res {
    let mut b = Request::builder()
        .method(Method::from_bytes(method.as_bytes()).expect("method"))
        .uri(uri)
        .header("host", "cloud.test");
    if let Some(u) = user {
        b = b.header(
            "authorization",
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{u}:{PW}"))
            ),
        );
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let res = env
        .app
        .clone()
        .oneshot(b.body(Body::from(body.to_owned())).expect("request"))
        .await
        .expect("response");
    let (parts, body) = res.into_parts();
    Res {
        status: parts.status,
        body: String::from_utf8_lossy(&body.collect().await.expect("body").to_bytes()).into_owned(),
    }
}

async fn put(env: &Env, user: &str, path: &str, body: &str, mtime: Option<&str>) {
    let h: Vec<(&str, &str)> = mtime.map(|m| ("x-oc-mtime", m)).into_iter().collect();
    let r = send(
        env,
        "PUT",
        &format!("/remote.php/dav/files/{user}{path}"),
        Some(user),
        &h,
        body,
    )
    .await;
    assert!(r.status.is_success(), "PUT {path}: {}", r.status);
}

async fn mkcol(env: &Env, user: &str, path: &str) {
    let r = send(
        env,
        "MKCOL",
        &format!("/remote.php/dav/files/{user}{path}"),
        Some(user),
        &[],
        "",
    )
    .await;
    assert!(r.status.is_success(), "MKCOL {path}: {}", r.status);
}

/// The tree the recording was made on.
async fn recorded_tree(env: &Env) {
    mkcol(env, "admin", "/F").await;
    mkcol(env, "admin", "/F/Sub").await;
    put(
        env,
        "admin",
        "/F/Report%202024.txt",
        "quarterly report\n",
        Some("1700000000"),
    )
    .await;
    put(
        env,
        "admin",
        "/F/report-final.pdf",
        "%PDF-1.4 not a real pdf\n",
        Some("1700000000"),
    )
    .await;
    put(
        env,
        "admin",
        "/F/Sub/Notes.md",
        "# notes about the report\n",
        Some("1700000000"),
    )
    .await;
    put(
        env,
        "admin",
        "/F/Sub/%C3%9Cbung.txt",
        "Übung macht den Meister\n",
        Some("1700000000"),
    )
    .await;
    put(
        env,
        "admin",
        "/F/big.bin",
        &"x".repeat(5000),
        Some("1700000000"),
    )
    .await;
    let fav = r#"<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:set><d:prop><oc:favorite>1</oc:favorite></d:prop></d:set></d:propertyupdate>"#;
    let r = send(
        env,
        "PROPPATCH",
        "/remote.php/dav/files/admin/F/Report%202024.txt",
        Some("admin"),
        &[],
        fav,
    )
    .await;
    assert_eq!(r.status, StatusCode::MULTI_STATUS);
}

fn fixture(prefix: &str) -> serde_json::Value {
    let dir = format!(
        "{}/../../tests/fixtures/nextcloud/12-search",
        env!("CARGO_MANIFEST_DIR")
    );
    for e in std::fs::read_dir(dir).expect("fixtures") {
        let p = e.expect("entry").path();
        if p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(prefix))
        {
            return serde_json::from_slice(&std::fs::read(p).expect("read")).expect("json");
        }
    }
    panic!("no fixture {prefix}");
}

fn ref_body(prefix: &str) -> serde_json::Value {
    let fx = fixture(prefix);
    serde_json::from_str(fx["response"]["body"]["text"].as_str().expect("text")).expect("ocs json")
}

async fn get(e: &Env, user: Option<&str>, uri: &str) -> Res {
    send(e, "GET", uri, user, &[("ocs-apirequest", "true")], "").await
}

fn data(r: &Res) -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(&r.body).expect("json")["ocs"]["data"].clone()
}

const FS: &str = "/ocs/v2.php/search/providers/files/search";

fn below_folder(entries: &serde_json::Value, folder: &str) -> Vec<serde_json::Value> {
    entries
        .as_array()
        .expect("entries")
        .iter()
        .filter(|e| {
            e["attributes"]["path"]
                .as_str()
                .is_some_and(|p| p.starts_with(&format!("/{folder}")))
        })
        .cloned()
        .collect()
}

fn keys(v: &serde_json::Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().expect("object").keys().cloned().collect();
    k.sort();
    k
}

#[tokio::test]
async fn the_files_provider_is_listed_and_nothing_else() {
    let e = env(&["admin"]).await;
    let r = get(
        &e,
        Some("admin"),
        "/ocs/v2.php/search/providers?format=json",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let list = data(&r);
    let list = list.as_array().expect("list");
    assert_eq!(list.len(), 1, "only providers that exist are listed");
    let ours = &list[0];
    let reference = ref_body("63-")["ocs"]["data"].clone();
    let theirs = reference
        .as_array()
        .expect("list")
        .iter()
        .find(|p| p["id"] == "files")
        .expect("files")
        .clone();
    assert_eq!(keys(ours), keys(&theirs));
    assert_eq!(ours["id"], "files");
    assert_eq!(ours["triggers"], theirs["triggers"]);
    // the announced filters are a subset of the reference's, with the same types
    for (k, v) in ours["filters"].as_object().expect("filters") {
        assert_eq!(&theirs["filters"][k], v, "filter {k}");
    }
    // unauthenticated: 997 as in the reference (`66`)
    let r = get(&e, None, "/ocs/v2.php/search/providers?format=json").await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(json(&r.body), json(&ref_body_text("66-")));
}

fn json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).expect("json")
}

fn ref_body_text(prefix: &str) -> String {
    fixture(prefix)["response"]["body"]["text"]
        .as_str()
        .expect("text")
        .to_owned()
}

#[tokio::test]
async fn entries_look_like_the_references_below_the_test_folder() {
    let e = env(&["admin"]).await;
    recorded_tree(&e).await;
    let r = get(&e, Some("admin"), &format!("{FS}?format=json&term=report")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let d = data(&r);
    let reference = ref_body("67-")["ocs"]["data"].clone();
    assert_eq!(keys(&d), keys(&reference));
    assert_eq!(d["name"], "Files");
    assert_eq!(d["isPaginated"], true);
    let ours = below_folder(&d["entries"], "F");
    let theirs = below_folder(&reference["entries"], "{{folder}}");
    assert_eq!(ours.len(), theirs.len());
    let path = |v: &serde_json::Value| {
        v["attributes"]["path"]
            .as_str()
            .expect("path")
            .replace("{{folder}}", "F")
    };
    let mut a: Vec<String> = ours.iter().map(path).collect();
    let mut b: Vec<String> = theirs.iter().map(path).collect();
    a.sort();
    b.sort();
    assert_eq!(a, b);
    for (o, t) in ours.iter().zip(theirs.iter()) {
        assert_eq!(keys(o), keys(t));
        assert_eq!(keys(&o["attributes"]), keys(&t["attributes"]));
    }
    let report = ours
        .iter()
        .find(|x| x["title"] == "Report 2024.txt")
        .expect("hit");
    assert_eq!(report["subline"], "in F");
    assert_eq!(report["rounded"], false);
    let id = report["attributes"]["fileId"].as_str().expect("id");
    assert_eq!(report["resourceUrl"], format!("http://cloud.test/f/{id}"));
    // sub folder: the subline names the path
    let r = get(
        &e,
        Some("admin"),
        &format!("{FS}?format=json&term=%C3%9Cbung"),
    )
    .await;
    let hit = &data(&r)["entries"][0];
    assert_eq!(hit["subline"], "in F/Sub");
    assert_eq!(hit["attributes"]["path"], "/F/Sub/Übung.txt");
    // a folder
    let r = get(&e, Some("admin"), &format!("{FS}?format=json&term=Sub")).await;
    let hit = &data(&r)["entries"][0];
    assert_eq!(hit["icon"], "icon-folder");
    // the XML form works too
    let r = get(&e, Some("admin"), &format!("{FS}?term=report")).await;
    assert!(
        r.body.starts_with("<?xml") && r.body.contains("<isPaginated>"),
        "{}",
        r.body
    );
}

#[tokio::test]
async fn paging_and_the_errors_of_the_reference() {
    let e = env(&["admin"]).await;
    recorded_tree(&e).await;
    // 2 hits for "report" in this tree (names): page by page
    let r = get(
        &e,
        Some("admin"),
        &format!("{FS}?format=json&term=e&limit=2"),
    )
    .await;
    let d = data(&r);
    assert_eq!(d["entries"].as_array().expect("e").len(), 2);
    assert_eq!(d["cursor"], 2);
    let r = get(
        &e,
        Some("admin"),
        &format!("{FS}?format=json&term=e&limit=2&cursor=2"),
    )
    .await;
    let d2 = data(&r);
    assert_eq!(d2["cursor"], 4);
    assert_ne!(d["entries"][0], d2["entries"][0]);
    // past the end: no entries, the cursor still moves on (`81`)
    let r = get(
        &e,
        Some("admin"),
        &format!("{FS}?format=json&term=report&cursor=500"),
    )
    .await;
    let d = data(&r);
    assert_eq!(d["entries"].as_array().expect("e").len(), 0);
    assert_eq!(d["cursor"], 505);
    // no filter at all (`74`, `75`)
    for uri in [
        format!("{FS}?format=json&term="),
        format!("{FS}?format=json"),
    ] {
        let r = get(&e, Some("admin"), &uri).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert_eq!(json(&r.body), json(&ref_body_text("74-")));
    }
    // limits (`77`, `78` answer 400 for 0 and 1000)
    for l in ["0", "1000", "abc"] {
        let r = get(
            &e,
            Some("admin"),
            &format!("{FS}?format=json&term=e&limit={l}"),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "limit {l}");
    }
    // a cursor that is no number: the reference answers 500, Rostdav 400
    let r = get(
        &e,
        Some("admin"),
        &format!("{FS}?format=json&term=e&cursor=abc"),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // an unknown provider: the reference answers 500, Rostdav 404
    let r = get(
        &e,
        Some("admin"),
        "/ocs/v2.php/search/providers/nonsense/search?format=json&term=x",
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // POST is not allowed (`89`)
    let r = send(
        &e,
        "POST",
        &format!("{FS}?format=json&term=e"),
        Some("admin"),
        &[("ocs-apirequest", "true")],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    // no sign-in (`87`)
    let r = get(&e, None, &format!("{FS}?format=json&term=report")).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(json(&r.body), json(&ref_body_text("87-")));
}

#[tokio::test]
async fn dates_filter_by_modification_time() {
    let e = env(&["admin"]).await;
    recorded_tree(&e).await;
    // the files were written with the modification time 2023-11-14 22:13:20 UTC
    let q = |extra: &str| format!("{FS}?format=json&term=report{extra}");
    let r = get(&e, Some("admin"), &q("&since=2023-11-14T22:00:00%2B00:00")).await;
    assert_eq!(
        below_folder(&data(&r)["entries"], "F").len(),
        2,
        "{}",
        r.body
    );
    let r = get(&e, Some("admin"), &q("&since=2023-11-14T23:00:00%2B00:00")).await;
    assert_eq!(below_folder(&data(&r)["entries"], "F").len(), 0);
    let r = get(&e, Some("admin"), &q("&until=2000-01-01T00:00:00%2B00:00")).await;
    assert_eq!(below_folder(&data(&r)["entries"], "F").len(), 0);
    let r = get(&e, Some("admin"), &q("&until=2023-11-15T00:00:00%2B00:00")).await;
    assert_eq!(below_folder(&data(&r)["entries"], "F").len(), 2);
    // a date alone is a filter
    let r = get(
        &e,
        Some("admin"),
        &format!(
            "{FS}?format=json&since=2023-11-14T23:00:00%2B00:00&until=2023-11-15T00:00:00%2B00:00"
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = get(&e, Some("admin"), &q("&since=garbage")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn nobody_finds_the_files_of_somebody_else_here_either() {
    let e = env(&["admin", "bob"]).await;
    recorded_tree(&e).await;
    put(&e, "bob", "/bobs-own-report.txt", "x", None).await;
    let r = get(&e, Some("bob"), &format!("{FS}?format=json&term=report")).await;
    let d = data(&r);
    let titles: Vec<&str> = d["entries"]
        .as_array()
        .expect("e")
        .iter()
        .map(|x| x["title"].as_str().expect("t"))
        .collect();
    assert_eq!(titles, ["bobs-own-report.txt"]);
    let r = get(
        &e,
        Some("bob"),
        &format!("{FS}?format=json&since=2000-01-01"),
    )
    .await;
    let all = data(&r).to_string();
    assert!(
        !all.contains("Notes.md") && !all.contains("report-final"),
        "{all}"
    );
}
