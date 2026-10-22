//! `/remote.php/dav/`: found with the real Android app (M6). The app probes
//! `HEAD /remote.php/dav` and reports "Server not found" unless the answer is 401
//! (not signed in), as the reference gives. Reference: Nextcloud 35.0.2, 2026-10-22.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use rostdav::config::Config;
use tower::ServiceExt;

const PW: &str = "korrekt-pferd-batterie";

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    depth: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "cloud.test");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    if let Some(d) = depth {
        b = b.header("depth", d);
    }
    let r = app
        .clone()
        .oneshot(b.body(Body::empty()).expect("req"))
        .await
        .expect("resp");
    let (p, body) = r.into_parts();
    (
        p.status,
        p.headers,
        String::from_utf8_lossy(&body.collect().await.expect("b").to_bytes()).into_owned(),
    )
}

#[tokio::test]
async fn dav_root_is_401_for_strangers_and_answers_signed_in_users() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().join("data");
    let state = rostdav::build_state(&cfg).await.expect("state");
    state.add_user("anna", PW, false).await.expect("user");
    let app = rostdav::http::router_with(state, &rostdav::http::HttpOptions::from_config(&cfg));
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("anna:{PW}"))
    );

    for uri in ["/remote.php/dav", "/remote.php/dav/"] {
        for m in ["HEAD", "GET", "PROPFIND"] {
            let (s, h, _) = call(&app, m, uri, None, Some("0")).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "{m} {uri}");
            assert!(
                h["www-authenticate"]
                    .to_str()
                    .expect("h")
                    .starts_with("Basic realm="),
                "{m} {uri}"
            );
        }
        let (s, _, _) = call(&app, "HEAD", uri, Some(&auth), None).await;
        assert_eq!(s, StatusCode::OK);
        let (s, h, body) = call(&app, "GET", uri, Some(&auth), None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(
            h["content-type"]
                .to_str()
                .expect("h")
                .starts_with("text/html")
                && body.contains("WebDAV interface")
        );
        let (s, h, _) = call(&app, "OPTIONS", uri, Some(&auth), None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(h["dav"].to_str().expect("h").starts_with('1'));
        let (s, _, body) = call(&app, "PROPFIND", uri, Some(&auth), Some("1")).await;
        assert_eq!(s, StatusCode::MULTI_STATUS);
        assert!(
            body.contains("<d:href>/remote.php/dav/</d:href>")
                && body.contains("<d:href>/remote.php/dav/files/</d:href>")
        );
        let (s, _, _) = call(&app, "DELETE", uri, Some(&auth), None).await;
        assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
    }
    // a wrong password is still a 401
    let wrong = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("anna:nope")
    );
    assert_eq!(
        call(&app, "HEAD", "/remote.php/dav", Some(&wrong), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}
