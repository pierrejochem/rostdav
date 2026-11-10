//! The RustMFA device API is mounted in the server and is not behind the web session or the
//! CSRF check (phones have no cookies); it answers in the contract's error format.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rostdav::config::Config;
use tower::ServiceExt;

async fn app() -> (axum::Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().join("data");
    let state = rostdav::build_state(&cfg).await.expect("state");
    (rostdav::http::router(state), dir)
}

async fn call(
    app: &axum::Router,
    req: Request<Body>,
) -> (StatusCode, serde_json::Value, axum::http::HeaderMap) {
    let res = app.clone().oneshot(req).await.expect("response");
    let (parts, body) = res.into_parts();
    let bytes = body.collect().await.expect("body").to_bytes();
    (
        parts.status,
        serde_json::from_slice(&bytes).unwrap_or_default(),
        parts.headers,
    )
}

#[tokio::test]
async fn device_routes_are_mounted_and_ask_for_a_signature() {
    let (app, _d) = app().await;
    for (method, path) in [
        ("GET", "/api/v1/devices"),
        ("GET", "/api/v1/mfa/challenges"),
        ("GET", "/api/v1/mfa/challenges/ch_x"),
        ("GET", "/api/v1/audit"),
        ("DELETE", "/api/v1/devices/dev_x"),
    ] {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .expect("req");
        let (status, body, headers) = call(&app, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(body["error"]["code"], "UNAUTHENTICATED", "{method} {path}");
        // the server-wide headers apply too
        assert!(headers.contains_key("x-request-id"));
        assert_eq!(headers["cache-control"], "no-store");
    }
}

#[tokio::test]
async fn registration_is_not_blocked_by_the_web_csrf_check() {
    let (app, _d) = app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/devices/register")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("req");
    let (status, body, _) = call(&app, req).await;
    // refused for its content, not for a missing CSRF token or session
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "INVALID_REQUEST");
}
