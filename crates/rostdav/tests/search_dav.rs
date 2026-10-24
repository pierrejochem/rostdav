//! WebDAV `SEARCH` (search plan, stage 4). The requests and answers of Nextcloud 35.0.2 were
//! recorded on 2026-10-24 (`tests/fixtures/nextcloud/12-search/`, `scripts/record_nextcloud_extra.py search`);
//! the first test replays them against the same tree. Where Rostdav answers differently on
//! purpose, the table `DEVIATIONS` says so, with the reason.

use std::collections::BTreeMap;

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
    state: AppState,
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
        app: rostdav::http::router(state.clone()),
        state,
        _dir: dir,
    }
}

struct Res {
    status: StatusCode,
    headers: axum::http::HeaderMap,
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
        headers: parts.headers,
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

fn fixtures() -> Vec<(String, serde_json::Value)> {
    let dir = format!(
        "{}/../../tests/fixtures/nextcloud/12-search",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .expect("fixtures")
        .filter_map(|e| {
            let p = e.ok()?.path();
            if p.extension()? != "json" {
                return None;
            }
            let name = p.file_stem()?.to_str()?.to_owned();
            let v = serde_json::from_slice(&std::fs::read(&p).ok()?).ok()?;
            Some((name, v))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn names(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<d:displayname>") {
        let after = &rest[i + "<d:displayname>".len()..];
        let end = after.find('<').expect("end");
        out.push(after[..end].replace("&amp;", "&"));
        rest = &after[end..];
    }
    out
}

fn responses(xml: &str) -> usize {
    xml.matches("<d:response>").count()
}

/// (fixture name without its number) -> the status Rostdav answers, with the reason.
const DEVIATIONS: &[(&str, u16, &str)] = &[
    ("no-where", 400, "the reference answers 500 (a TypeError)"),
    (
        "eq-owner-id",
        400,
        "the reference answers 500 below the home folder",
    ),
    (
        "eq-owner-id-other",
        400,
        "the reference answers 500 below the home folder",
    ),
    ("limit-not-a-number", 400, "the reference answers 500"),
    (
        "scope-other-user",
        404,
        "the reference answers 500; another user's files do not exist here",
    ),
    (
        "doctype-entity",
        400,
        "the reference accepts a DOCTYPE; Rostdav never does",
    ),
    (
        "external-entity",
        400,
        "the reference accepts a DOCTYPE; Rostdav never does",
    ),
    ("101-operators", 400, "the reference answers 500"),
    (
        "at-files-url",
        405,
        "the reference answers 501; only the DAV root takes SEARCH",
    ),
    (
        "at-folder-url",
        405,
        "the reference answers 501; only the DAV root takes SEARCH",
    ),
    (
        "content-type-json",
        207,
        "the reference answers 501 for other content types; the body decides here",
    ),
];

/// Not replayed: they depend on the reference's own data or are known not to agree.
const SKIPPED: &[(&str, &str)] = &[
    (
        "bob-searches-own",
        "bob's tree on the reference holds the default files",
    ),
    (
        "scope-root",
        "the root of the reference holds its default files",
    ),
    (
        "gte-lte-mtime",
        "the reference found nothing for a range that holds the files (a bug there); see mtime_ranges",
    ),
];

#[tokio::test]
async fn recorded_requests_get_the_recorded_answers() {
    let e = env(&["admin", "bob"]).await;
    recorded_tree(&e).await;
    let mut checked = 0;
    for (full, fx) in fixtures() {
        let name = full.split_once('-').expect("numbered").1.to_owned();
        let req = &fx["request"];
        if req["method"] != "SEARCH" {
            if name == "trashed-file-setup" {
                let r = send(
                    &e,
                    "DELETE",
                    "/remote.php/dav/files/admin/F/big.bin",
                    Some("admin"),
                    &[],
                    "",
                )
                .await;
                assert_eq!(r.status, StatusCode::NO_CONTENT);
            }
            continue;
        }
        if SKIPPED.iter().any(|(n, _)| *n == name) {
            continue;
        }
        let body = req["body"]["text"]
            .as_str()
            .unwrap_or("")
            .replace("{{folder}}", "F");
        let user = if name == "no-auth" {
            None
        } else if name.starts_with("bob-") {
            Some("bob")
        } else {
            Some("admin")
        };
        let path = req["path"]
            .as_str()
            .expect("path")
            .replace("{{folder}}", "F");
        let res = send(
            &e,
            "SEARCH",
            &path,
            user,
            &[("content-type", "text/xml")],
            &body,
        )
        .await;
        let want = fx["response"]["status"].as_u64().expect("status") as u16;
        let deviation = DEVIATIONS.iter().find(|(n, _, _)| *n == name);
        let expected = deviation.map_or(want, |(_, s, _)| *s);
        assert_eq!(res.status.as_u16(), expected, "{full}: {}", res.body);
        checked += 1;
        if want != 207 || deviation.is_some() {
            continue;
        }
        let ref_xml = fx["response"]["body"]["text"].as_str().expect("body");
        let (mut got, mut exp) = (names(&res.body), names(ref_xml));
        assert_eq!(
            responses(&res.body),
            responses(ref_xml),
            "{full}: number of results"
        );
        if name.contains("limit") {
            // the order without `orderby` is the reference's database order
            continue;
        }
        if !name.contains("orderby") {
            got.sort();
            exp.sort();
        } else if name == "orderby-size-desc" {
            // `Notes.md` and `Übung.txt` are both 25 bytes: the order of equal sizes is not defined
            got[2..4].sort();
            exp[2..4].sort();
        }
        assert_eq!(got, exp, "{full}");
    }
    assert!(checked > 40, "only {checked} requests replayed");
}

#[tokio::test]
async fn only_the_dav_root_allows_search() {
    let e = env(&["admin"]).await;
    let root = send(&e, "OPTIONS", "/remote.php/dav/", Some("admin"), &[], "").await;
    assert!(
        root.headers["allow"]
            .to_str()
            .expect("allow")
            .contains("SEARCH")
    );
    let files = send(
        &e,
        "OPTIONS",
        "/remote.php/dav/files/admin/",
        Some("admin"),
        &[],
        "",
    )
    .await;
    assert!(
        !files.headers["allow"]
            .to_str()
            .expect("allow")
            .contains("SEARCH")
    );
}

const SEL: &str = "<d:select><d:prop><d:displayname/></d:prop></d:select>";

fn query(scope: &str, where_: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><d:searchrequest xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:basicsearch>{SEL}<d:from><d:scope><d:href>{scope}</d:href><d:depth>infinity</d:depth></d:scope></d:from><d:where>{where_}</d:where></d:basicsearch></d:searchrequest>"#
    )
}

const ALL: &str = "<d:like><d:prop><d:displayname/></d:prop><d:literal>%</d:literal></d:like>";

async fn search(e: &Env, user: &str, scope: &str, where_: &str) -> Res {
    send(
        e,
        "SEARCH",
        "/remote.php/dav/",
        Some(user),
        &[("content-type", "text/xml")],
        &query(scope, where_),
    )
    .await
}

#[tokio::test]
async fn mtime_ranges_accept_the_forms_the_reference_takes() {
    let e = env(&["admin"]).await;
    recorded_tree(&e).await;
    let range = |gte: &str, lte: &str| {
        format!(
            "<d:and><d:gte><d:prop><d:getlastmodified/></d:prop><d:literal>{gte}</d:literal></d:gte><d:lte><d:prop><d:getlastmodified/></d:prop><d:literal>{lte}</d:literal></d:lte></d:and>"
        )
    };
    for (gte, lte, n) in [
        ("2023-11-14T22:00:00Z", "2023-11-15T22:00:00Z", 5),
        ("1699999200", "1700003600", 5),
        (
            "Tue, 14 Nov 2023 22:00:00 GMT",
            "Wed, 15 Nov 2023 22:00:00 GMT",
            5,
        ),
        ("2023-11-14T23:00:00Z", "2023-11-15T22:00:00Z", 0),
        ("2023-11-14", "2023-11-14", 0),
    ] {
        let r = search(&e, "admin", "/files/admin/F", &range(gte, lte)).await;
        assert_eq!(r.status, StatusCode::MULTI_STATUS, "{gte}");
        // the folder `Sub` was created now: it is in no range of 2023
        assert_eq!(responses(&r.body), n, "{gte} .. {lte}: {}", r.body);
    }
    let r = search(
        &e,
        "admin",
        "/files/admin/F",
        &range("garbage", "2023-11-14"),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn nobody_finds_the_files_of_somebody_else() {
    let e = env(&["admin", "bob"]).await;
    recorded_tree(&e).await;
    put(&e, "bob", "/bobs-secret-report.txt", "x", None).await;
    // bob searches his own tree: only his file
    let r = search(&e, "bob", "/files/bob", ALL).await;
    assert_eq!(names(&r.body), ["bobs-secret-report.txt"]);
    // bob names admin's folder as the scope
    let r = search(&e, "bob", "/files/admin/F", ALL).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = search(&e, "bob", "/files/admin", ALL).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // admin searching from the root does not see bob's file
    let r = search(&e, "admin", "/files/admin", ALL).await;
    assert!(!r.body.contains("bobs-secret"), "{}", r.body);
    // the name of the user in the scope is compared as the account, not as text
    let r = search(&e, "bob", "/files/Bob", ALL).await;
    assert_ne!(names(&r.body).len(), 99, "{}", r.status);
    // no password, no search
    let r = send(
        &e,
        "SEARCH",
        "/remote.php/dav/",
        None,
        &[("content-type", "text/xml")],
        &query("/files/bob", ALL),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_received_share_is_searched_under_its_mount_and_a_revoked_one_is_not() {
    let e = env(&["admin", "bob"]).await;
    recorded_tree(&e).await;
    let state = &e.state;
    let admin = state
        .authenticate("admin", PW, std::net::Ipv4Addr::LOCALHOST.into())
        .await
        .expect("auth");
    let share = state
        .share_create(
            &admin,
            rostdav_app::ShareCreate {
                path: Some(rostdav_core::LogicalPath::from_url_path("/F/Sub").expect("path")),
                share_type: 0,
                share_with: Some("bob".into()),
                permissions: Some(1),
                password: None,
                expire: None,
                note: String::new(),
                label: String::new(),
                hide_download: false,
            },
        )
        .await
        .expect("share");
    let r = search(&e, "bob", "/files/bob", ALL).await;
    let mut n = names(&r.body);
    n.sort();
    assert_eq!(n, ["Notes.md", "Sub", "Übung.txt"], "{}", r.body);
    assert!(
        r.body.contains("/remote.php/dav/files/bob/Sub/Notes.md"),
        "{}",
        r.body
    );
    // the scope inside the mount
    let r = search(&e, "bob", "/files/bob/Sub", ALL).await;
    assert_eq!(responses(&r.body), 2);
    // nothing outside the share leaks through it
    assert!(!r.body.contains("big.bin") && !r.body.contains("Report"));
    state
        .share_delete(&admin, share.share.id)
        .await
        .expect("revoke");
    let r = search(&e, "bob", "/files/bob", ALL).await;
    assert_eq!(responses(&r.body), 0, "{}", r.body);
    let r = search(&e, "bob", "/files/bob/Sub", ALL).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn deleted_files_are_not_found_and_public_links_cannot_search() {
    let e = env(&["admin"]).await;
    recorded_tree(&e).await;
    let r = send(
        &e,
        "DELETE",
        "/remote.php/dav/files/admin/F/Sub",
        Some("admin"),
        &[],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = search(&e, "admin", "/files/admin", ALL).await;
    assert!(
        !r.body.contains("Notes.md") && !r.body.contains("Übung"),
        "{}",
        r.body
    );
    // SEARCH on the public namespace is not a thing
    let r = send(
        &e,
        "SEARCH",
        "/public.php/webdav/",
        Some("admin"),
        &[("content-type", "text/xml")],
        &query("/files/admin", ALL),
    )
    .await;
    assert!(!r.status.is_success(), "{}", r.status);
}

#[test]
fn every_deviation_and_skip_has_a_recorded_fixture() {
    let have: BTreeMap<String, ()> = fixtures()
        .into_iter()
        .map(|(n, _)| (n.split_once('-').expect("numbered").1.to_owned(), ()))
        .collect();
    for (n, _, _) in DEVIATIONS {
        assert!(have.contains_key(*n), "no fixture {n}");
    }
    for (n, _) in SKIPPED {
        assert!(have.contains_key(*n), "no fixture {n}");
    }
}
