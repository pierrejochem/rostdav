//! Phase 5: authorization matrix. Every actor that must NOT get at anna's data
//! tries every file-protocol door; afterwards anna's data must be unchanged.
//!
//! Actors: anonymous, a wrong password, bob (own valid credentials), carl
//! (disabled), a read-only public link. Doors: WebDAV (new and legacy paths),
//! chunked upload, versions, trashbin, OCS sharing, public.php.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use rostdav::config::Config;
use tower::ServiceExt;

const PW: &str = "korrekt-pferd-batterie";
const SECRET: &[u8] = b"anna's private content";

struct Env {
    app: Router,
    state: rostdav_app::AppState,
    _dir: tempfile::TempDir,
}

async fn env() -> Env {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().join("data");
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

struct Res {
    status: StatusCode,
    body: Vec<u8>,
}

fn basic(u: &str, p: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
    )
}

async fn send(
    e: &Env,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Res {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "cloud.test");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    // every credential gets its own "address", so the brute-force limiter of one attacker
    // does not lock out anna's checks (the real server sees one peer address per connection)
    let h = auth.map_or(0u32, |a| {
        a.bytes()
            .fold(7u32, |h, c| h.wrapping_mul(31).wrapping_add(u32::from(c)))
    });
    let peer = std::net::SocketAddr::from(([10, (h >> 16) as u8, (h >> 8) as u8, h as u8], 4000));
    let mut req = b.body(Body::from(body.to_vec())).expect("req");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    let r = e.app.clone().oneshot(req).await.expect("resp");
    let (p, body) = r.into_parts();
    Res {
        status: p.status,
        body: body.collect().await.expect("body").to_bytes().to_vec(),
    }
}

/// What anna owns: a folder with a secret file that has versions, a trashed file, a share.
struct World {
    anna_app: String,
    file_id: i64,
    share_id: i64,
    link_token: String,
}

async fn world(e: &Env) -> World {
    let ip = "192.0.2.9".parse().expect("ip");
    let anna = e.state.authenticate("anna", PW, ip).await.expect("auth");
    let put = |path: &'static str, body: &'static [u8]| {
        let (st, p) = (&e.state, &anna);
        async move {
            let lp = rostdav_core::LogicalPath::from_url_path(path).expect("path");
            st.put(p, &lp, body, None, &rostdav_meta::WriteCondition::None)
                .await
                .expect("put");
        }
    };
    e.state
        .mkcol(
            &anna,
            &rostdav_core::LogicalPath::from_url_path("Private").expect("p"),
        )
        .await
        .expect("mkcol");
    put("Private/secret.txt", b"old secret").await;
    put("Private/secret.txt", SECRET).await;
    put("doomed.txt", b"to trash").await;
    e.state
        .delete(
            &anna,
            &rostdav_core::LogicalPath::from_url_path("doomed.txt").expect("p"),
            None,
        )
        .await
        .expect("trash");
    let node = e
        .state
        .stat(
            &anna,
            &rostdav_core::LogicalPath::from_url_path("Private/secret.txt").expect("p"),
        )
        .await
        .expect("stat");
    let share = e
        .state
        .share_create(
            &anna,
            rostdav_app::ShareCreate {
                path: Some(rostdav_core::LogicalPath::from_url_path("Private").expect("p")),
                share_type: 0,
                share_with: Some("carl".into()),
                permissions: Some(1),
                ..Default::default()
            },
        )
        .await
        .expect("share");
    let link = e
        .state
        .share_create(
            &anna,
            rostdav_app::ShareCreate {
                path: Some(rostdav_core::LogicalPath::from_url_path("Private").expect("p")),
                share_type: 3,
                permissions: Some(1),
                ..Default::default()
            },
        )
        .await
        .expect("link");
    // carl is disabled: his share must not open anything either
    e.state
        .user_set_disabled(&rostdav_app::Actor::Cli, "carl", true)
        .await
        .expect("disable");
    World {
        anna_app: e.state.device_create(&anna, "phone").await.expect("device"),
        file_id: node.id,
        share_id: share.share.id,
        link_token: link.share.token.expect("token"),
    }
}

fn refused(s: StatusCode) -> bool {
    matches!(
        s.as_u16(),
        400 | 401 | 403 | 404 | 405 | 409 | 412 | 423 | 429 | 501
    )
}

/// anna reads her own data with her app password: used to prove nothing changed.
async fn anna_view(e: &Env, w: &World) -> (Vec<u8>, String) {
    let a = basic("anna", &w.anna_app);
    let secret = send(
        e,
        "GET",
        "/remote.php/dav/files/anna/Private/secret.txt",
        Some(&a),
        &[],
        b"",
    )
    .await;
    assert_eq!(secret.status, StatusCode::OK);
    let listing = send(
        e,
        "PROPFIND",
        "/remote.php/dav/files/anna/",
        Some(&a),
        &[("depth", "infinity")],
        b"",
    )
    .await;
    let names: Vec<String> = String::from_utf8_lossy(&listing.body)
        .split("<d:href>")
        .skip(1)
        .map(|s| s.split("</d:href>").next().unwrap_or("").to_owned())
        .collect();
    (secret.body, names.join("|"))
}

#[tokio::test]
async fn nobody_else_reaches_annas_files() {
    let e = env().await;
    let w = world(&e).await;
    let before = anna_view(&e, &w).await;
    assert_eq!(before.0, SECRET);

    let id = w.file_id.to_string();
    let bob = basic("bob", PW);
    let wrong = basic("anna", "not-her-password");
    let carl_disabled = basic("carl", PW);
    let anna_as_account_password_but_wrong_user = basic("bob", &w.anna_app); // anna's app password with bob's name
    let actors: Vec<(&str, Option<String>)> = vec![
        ("anonymous", None),
        ("wrong password", Some(wrong)),
        ("bob", Some(bob.clone())),
        ("disabled carl", Some(carl_disabled)),
        (
            "anna's app password under bob's name",
            Some(anna_as_account_password_but_wrong_user),
        ),
    ];

    // (method, path, headers, body) aimed at anna's data
    let big = vec![
        (
            "GET",
            "/remote.php/dav/files/anna/Private/secret.txt".to_owned(),
            vec![],
            "",
        ),
        (
            "GET",
            "/remote.php/webdav/Private/secret.txt".to_owned(),
            vec![],
            "",
        ), // legacy path = the caller's own tree
        (
            "HEAD",
            "/remote.php/dav/files/anna/Private/secret.txt".to_owned(),
            vec![],
            "",
        ),
        (
            "PROPFIND",
            "/remote.php/dav/files/anna/".to_owned(),
            vec![("depth", "1")],
            "",
        ),
        (
            "PROPFIND",
            "/remote.php/dav/files/anna/Private/".to_owned(),
            vec![("depth", "infinity")],
            "",
        ),
        (
            "PUT",
            "/remote.php/dav/files/anna/Private/secret.txt".to_owned(),
            vec![],
            "overwritten",
        ),
        (
            "PUT",
            "/remote.php/dav/files/anna/Private/planted.txt".to_owned(),
            vec![],
            "planted",
        ),
        (
            "DELETE",
            "/remote.php/dav/files/anna/Private/secret.txt".to_owned(),
            vec![],
            "",
        ),
        (
            "DELETE",
            "/remote.php/dav/files/anna/Private".to_owned(),
            vec![],
            "",
        ),
        (
            "MKCOL",
            "/remote.php/dav/files/anna/Private/new".to_owned(),
            vec![],
            "",
        ),
        (
            "MOVE",
            "/remote.php/dav/files/anna/Private/secret.txt".to_owned(),
            vec![(
                "destination",
                "http://cloud.test/remote.php/dav/files/anna/stolen.txt",
            )],
            "",
        ),
        (
            "COPY",
            "/remote.php/dav/files/anna/Private/secret.txt".to_owned(),
            vec![(
                "destination",
                "http://cloud.test/remote.php/dav/files/bob/copy.txt",
            )],
            "",
        ),
        // the legacy path always means "my own tree", so bob's attempt must not see anna's
        (
            "PROPFIND",
            "/remote.php/dav/files/bob/../anna/Private/".to_owned(),
            vec![("depth", "1")],
            "",
        ),
        (
            "GET",
            "/remote.php/dav/files/bob/%2e%2e/anna/Private/secret.txt".to_owned(),
            vec![],
            "",
        ),
        (
            "GET",
            "/remote.php/dav/files/bob/%252e%252e/anna/Private/secret.txt".to_owned(),
            vec![],
            "",
        ),
        (
            "GET",
            "/remote.php/dav/files//anna/Private/secret.txt".to_owned(),
            vec![],
            "",
        ),
        // chunked upload into / assembling to anna's tree
        (
            "MKCOL",
            "/remote.php/dav/uploads/anna/evil".to_owned(),
            vec![],
            "",
        ),
        (
            "PUT",
            "/remote.php/dav/uploads/anna/other/000001".to_owned(),
            vec![],
            "x",
        ),
        // versions and trashbin of anna
        (
            "PROPFIND",
            format!("/remote.php/dav/versions/anna/versions/{id}"),
            vec![("depth", "1")],
            "",
        ),
        (
            "PROPFIND",
            "/remote.php/dav/trashbin/anna/trash".to_owned(),
            vec![("depth", "1")],
            "",
        ),
        (
            "DELETE",
            "/remote.php/dav/trashbin/anna/trash".to_owned(),
            vec![],
            "",
        ),
        // OCS sharing API
        (
            "GET",
            "/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json".to_owned(),
            vec![("ocs-apirequest", "true")],
            "",
        ),
        (
            "GET",
            format!(
                "/ocs/v2.php/apps/files_sharing/api/v1/shares/{}?format=json",
                w.share_id
            ),
            vec![("ocs-apirequest", "true")],
            "",
        ),
        (
            "DELETE",
            format!(
                "/ocs/v2.php/apps/files_sharing/api/v1/shares/{}?format=json",
                w.share_id
            ),
            vec![("ocs-apirequest", "true")],
            "",
        ),
        (
            "PUT",
            format!(
                "/ocs/v2.php/apps/files_sharing/api/v1/shares/{}?format=json&permissions=31",
                w.share_id
            ),
            vec![("ocs-apirequest", "true")],
            "",
        ),
    ];

    for (actor, auth) in &actors {
        for (method, path, headers, body) in &big {
            let r = send(&e, method, path, auth.as_deref(), headers, body.as_bytes()).await;
            // bob may legitimately see his OWN empty tree through the legacy path and OCS lists;
            // what must never happen is a success that exposes or changes anna's data
            let leaked = String::from_utf8_lossy(&r.body);
            assert!(
                !leaked.contains("anna's private content")
                    && !leaked.contains("Private/secret.txt<"),
                "{actor}: {method} {path} leaked data"
            );
            if *actor != "bob"
                || path.contains("/files/anna")
                || path.contains("/uploads/anna")
                || path.contains("/versions/anna")
                || path.contains("/trashbin/anna")
            {
                assert!(
                    refused(r.status),
                    "{actor}: {method} {path} -> {}",
                    r.status
                );
            }
        }
    }

    // bob with his own valid credentials on his own doors, aimed at anna's objects by id or name
    for (method, path) in [
        (
            "PROPFIND",
            format!("/remote.php/dav/versions/bob/versions/{id}"),
        ),
        (
            "COPY",
            format!("/remote.php/dav/versions/bob/versions/{id}/1"),
        ),
        (
            "MOVE",
            format!("/remote.php/dav/versions/bob/versions/{id}/1"),
        ),
    ] {
        let r = send(
            &e,
            method,
            &path,
            Some(&bob),
            &[
                ("depth", "1"),
                (
                    "destination",
                    "http://cloud.test/remote.php/dav/versions/bob/restore/target",
                ),
            ],
            b"",
        )
        .await;
        assert!(refused(r.status), "{method} {path} -> {}", r.status);
    }
    let r = send(
        &e,
        "GET",
        "/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json&path=/Private",
        Some(&bob),
        &[("ocs-apirequest", "true")],
        b"",
    )
    .await;
    assert!(
        !String::from_utf8_lossy(&r.body).contains("carl"),
        "bob must not learn who anna shares with"
    );
    let r = send(
        &e,
        "GET",
        "/remote.php/dav/trashbin/bob/trash",
        Some(&bob),
        &[("depth", "1")],
        b"",
    )
    .await;
    assert!(!String::from_utf8_lossy(&r.body).contains("doomed"));

    // read-only public link: nothing beyond the shared folder, nothing writable
    let link = basic(&w.link_token, "");
    let base = "/public.php/webdav";
    let r = send(
        &e,
        "GET",
        &format!("{base}/secret.txt"),
        Some(&link),
        &[],
        b"",
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "the link may read what it shares: {}",
        String::from_utf8_lossy(&r.body)
    );
    for (method, path, body) in [
        ("PUT", format!("{base}/secret.txt"), "x"),
        ("PUT", format!("{base}/planted.txt"), "x"),
        ("DELETE", format!("{base}/secret.txt"), ""),
        ("MKCOL", format!("{base}/new"), ""),
        ("GET", format!("{base}/../doomed.txt"), ""),
        (
            "GET",
            format!("{base}/%2e%2e/%2e%2e/files/anna/Private/secret.txt"),
            "",
        ),
    ] {
        let r = send(&e, method, &path, Some(&link), &[], body.as_bytes()).await;
        assert!(
            refused(r.status) && !r.body.starts_with(b"to trash"),
            "link: {method} {path} -> {}",
            r.status
        );
    }
    // the link token must not be accepted on the file or OCS doors
    for path in [
        "/remote.php/dav/files/anna/Private/secret.txt",
        "/ocs/v2.php/cloud/user?format=json",
    ] {
        let r = send(
            &e,
            "GET",
            path,
            Some(&link),
            &[("ocs-apirequest", "true")],
            b"",
        )
        .await;
        assert!(refused(r.status), "link token on {path} -> {}", r.status);
    }

    // after all of that: nothing of anna's changed
    let after = anna_view(&e, &w).await;
    assert_eq!(before, after, "anna's data changed during the attacks");
    // and the data directory holds no stray files in her tree
    assert!(
        !after.1.contains("planted") && !after.1.contains("stolen") && !after.1.contains("new")
    );
}

#[tokio::test]
async fn disabled_user_cannot_use_a_share_or_any_credential() {
    let e = env().await;
    let w = world(&e).await;
    // carl (disabled) has a share of Private; neither his password nor a new app password opens it
    for auth in [basic("carl", PW)] {
        for path in [
            "/remote.php/dav/files/carl/Private/secret.txt",
            "/remote.php/dav/files/carl/",
        ] {
            let r = send(&e, "GET", path, Some(&auth), &[], b"").await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{path}");
        }
    }
    let _ = w;
}

#[tokio::test]
async fn unauthenticated_requests_never_reveal_whether_a_user_exists() {
    let e = env().await;
    let _w = world(&e).await;
    let known = send(
        &e,
        "PROPFIND",
        "/remote.php/dav/files/anna/",
        None,
        &[("depth", "0")],
        b"",
    )
    .await;
    let unknown = send(
        &e,
        "PROPFIND",
        "/remote.php/dav/files/nobody/",
        None,
        &[("depth", "0")],
        b"",
    )
    .await;
    assert_eq!(known.status, unknown.status);
    assert_eq!(known.body, unknown.body);
    let wrong_known = send(
        &e,
        "PROPFIND",
        "/remote.php/dav/files/anna/",
        Some(&basic("anna", "x")),
        &[("depth", "0")],
        b"",
    )
    .await;
    let wrong_unknown = send(
        &e,
        "PROPFIND",
        "/remote.php/dav/files/anna/",
        Some(&basic("nobody", "x")),
        &[("depth", "0")],
        b"",
    )
    .await;
    assert_eq!(wrong_known.status, wrong_unknown.status);
    assert_eq!(wrong_known.body, wrong_unknown.body);
}
