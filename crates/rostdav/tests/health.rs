//! Integration tests for the health and readiness endpoints.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rostdav::config::Config;
use tower::ServiceExt;

async fn app_with_tempdir() -> (axum::Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().join("data");
    let state = rostdav::build_state(&cfg).await.expect("state");
    (rostdav::http::router(state), dir)
}

async fn get(app: axum::Router, uri: &str) -> axum::response::Response {
    app.oneshot(Request::get(uri).body(Body::empty()).expect("request"))
        .await
        .expect("response")
}

#[tokio::test]
async fn healthz_ok() {
    let (app, _dir) = app_with_tempdir().await;
    let res = get(app, "/healthz").await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.expect("body").to_bytes();
    assert_eq!(&body[..], br#"{"status":"ok"}"#);
}

#[tokio::test]
async fn readyz_ok_with_working_storage() {
    let (app, _dir) = app_with_tempdir().await;
    assert_eq!(get(app, "/readyz").await.status(), StatusCode::OK);
}

#[tokio::test]
async fn readyz_unavailable_when_tmp_missing() {
    let (app, dir) = app_with_tempdir().await;
    std::fs::remove_dir_all(dir.path().join("data").join("tmp")).expect("remove tmp");
    let res = get(app, "/readyz").await;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = res.into_body().collect().await.expect("body").to_bytes();
    // No internal paths or causes in the response.
    assert_eq!(&body[..], br#"{"status":"unavailable"}"#);
}

#[tokio::test]
async fn responses_carry_request_id_and_security_headers() {
    let (app, _dir) = app_with_tempdir().await;
    let res = get(app, "/healthz").await;
    assert!(res.headers().contains_key("x-request-id"));
    assert_eq!(res.headers()["x-content-type-options"], "nosniff");
    assert_eq!(res.headers()["referrer-policy"], "no-referrer");
}

#[tokio::test]
async fn unknown_route_is_404() {
    let (app, _dir) = app_with_tempdir().await;
    assert_eq!(get(app, "/nope").await.status(), StatusCode::NOT_FOUND);
}
