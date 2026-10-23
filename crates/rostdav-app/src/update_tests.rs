//! The version check against a local server (ADR 0009).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rostdav_core::Error;
use rostdav_meta::Db;
use rostdav_storage::LocalStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::*;

const PW: &str = "korrekt-pferd-batterie";

async fn state() -> (tempfile::TempDir, AppState) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = LocalStore::open(dir.path().join("data"))
        .await
        .expect("store");
    let db = Db::open(&Db::default_url(store.root())).await.expect("db");
    db.migrate().await.expect("migrate");
    (dir, AppState::new(db, store).await.expect("state"))
}

/// Answers every request with `status` and `body`; counts the requests and keeps the last head.
async fn serve(
    status: &'static str,
    body: String,
) -> (String, Arc<AtomicUsize>, Arc<std::sync::Mutex<String>>) {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let url = format!("http://{}/latest", listener.local_addr().expect("addr"));
    let count = Arc::new(AtomicUsize::new(0));
    let head = Arc::new(std::sync::Mutex::new(String::new()));
    let (c, h) = (count.clone(), head.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            c.fetch_add(1, Ordering::SeqCst);
            *h.lock().expect("head") = String::from_utf8_lossy(&buf[..n]).into_owned();
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(reply.as_bytes()).await;
        }
    });
    (url, count, head)
}

fn release_json(tag: &str) -> String {
    serde_json::json!({
        "tag_name": tag,
        "html_url": format!("https://github.com/pierrejochem/rostdav/releases/tag/{tag}"),
        "published_at": "2026-10-23T12:00:00Z",
        "body": "### Added\n\n- a thing",
    })
    .to_string()
}

#[tokio::test]
async fn nothing_is_requested_until_an_administrator_switches_the_check_on() {
    let (_d, st) = state().await;
    let (url, count, _) = serve("200 OK", release_json("v99.0.0")).await;
    st.set_update_source(&url);
    let before = st.update_status(&Actor::Cli).await.expect("status");
    assert!(!before.enabled && before.latest.is_none() && before.checked_at.is_none());
    // neither "check now" nor the background task asks while it is off
    st.update_check_now(&Actor::Cli).await.expect("now");
    st.update_check_if_due().await;
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn switching_on_checks_records_and_offers_a_newer_version() {
    let (_d, st) = state().await;
    let (url, count, head) = serve("200 OK", release_json("v99.0.0")).await;
    st.set_update_source(&url);
    let s = st
        .update_set_enabled(&Actor::Cli, true)
        .await
        .expect("enable");
    assert!(s.enabled && s.error.is_none() && s.checked_at.is_some());
    assert_eq!(
        s.available().map(|l| l.version.to_string()),
        Some("99.0.0".into())
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    // the request names the program and nothing else about the installation
    let head = head.lock().expect("head").to_ascii_lowercase();
    assert!(head.contains(&format!("user-agent: rostdav/{}", rostdav_core::VERSION)));
    for forbidden in ["cookie", "authorization", "x-"] {
        assert!(!head.contains(forbidden), "{forbidden} in {head}");
    }
    // a second background tick within the day does not ask again; "check now" does
    st.update_check_if_due().await;
    assert_eq!(count.load(Ordering::SeqCst), 1);
    st.update_check_now(&Actor::Cli).await.expect("now");
    assert_eq!(count.load(Ordering::SeqCst), 2);
    // the result survives a restart (it is stored), and switching off is recorded
    let s = st
        .update_set_enabled(&Actor::Cli, false)
        .await
        .expect("disable");
    assert!(!s.enabled && s.latest.is_some());
    let events: Vec<String> = st
        .audit_events(&Actor::Cli, 0)
        .await
        .expect("events")
        .into_iter()
        .map(|e| e.action)
        .collect();
    assert!(events.contains(&"admin.update_check_on".to_owned()));
    assert!(events.contains(&"admin.update_check_off".to_owned()));
}

#[tokio::test]
async fn an_older_or_equal_version_is_not_offered() {
    let (_d, st) = state().await;
    let (url, _, _) = serve(
        "200 OK",
        release_json(&format!("v{}", rostdav_core::VERSION)),
    )
    .await;
    st.set_update_source(&url);
    let s = st
        .update_set_enabled(&Actor::Cli, true)
        .await
        .expect("enable");
    assert!(s.latest.is_some() && s.available().is_none());
}

#[tokio::test]
async fn failures_are_recorded_and_not_raised() {
    let (_d, st) = state().await;
    for (status, body, reason) in [
        ("500 Internal Server Error", String::new(), "500"),
        ("404 Not Found", String::new(), "no release"),
        (
            "200 OK",
            "{\"tag_name\":\"v99.0.0\",\"html_url\":\"https://evil.example/\"}".into(),
            "not a release",
        ),
    ] {
        let (url, _, _) = serve(status, body).await;
        st.set_update_source(&url);
        let s = st
            .update_set_enabled(&Actor::Cli, true)
            .await
            .expect("enable never fails because of the network");
        let err = s.error.as_ref().expect("error recorded");
        assert!(err.contains(reason), "{err}");
        assert!(s.latest.is_none() && s.available().is_none());
    }
    // nothing is listening: still recorded
    st.set_update_source("http://127.0.0.1:1/latest");
    let s = st.update_check_now(&Actor::Cli).await.expect("now");
    assert!(s.error.is_some());
}

#[tokio::test]
async fn only_administrators_may_use_it() {
    let (_d, st) = state().await;
    st.add_user("anna", PW, false).await.expect("anna");
    let anna = st
        .authenticate("anna", PW, IpAddr::V4(Ipv4Addr::LOCALHOST))
        .await
        .expect("auth");
    let who = Actor::User(&anna);
    assert!(matches!(
        st.update_status(&who).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        st.update_set_enabled(&who, true).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        st.update_check_now(&who).await,
        Err(Error::Forbidden)
    ));
    assert!(!st.update_status(&Actor::Cli).await.expect("status").enabled);
}
