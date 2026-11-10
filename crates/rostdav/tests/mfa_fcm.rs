//! The FCM push channel is built from the settings at start-up. A wrong setting stops the
//! server with a message that names the key and does not echo the file.

use rostdav::config::Config;

const KEY_PEM: &str = include_str!("../../rostdav-app/src/push_mfa/testdata/test_rsa_key.pem");

fn config(dir: &tempfile::TempDir, file: &str) -> Config {
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().join("data");
    cfg.mfa.fcm.project_id = Some("demo-project".into());
    cfg.mfa.fcm.service_account_file = Some(dir.path().join(file));
    cfg
}

async fn start(cfg: &Config) -> Result<(), String> {
    rostdav::build_state(cfg)
        .await
        .map(|_| ())
        .map_err(|e| format!("{e:#}"))
}

#[tokio::test]
async fn a_missing_service_account_file_stops_start_up() {
    let dir = tempfile::tempdir().expect("tempdir");
    let e = start(&config(&dir, "nope.json"))
        .await
        .expect_err("refused");
    assert!(e.contains("mfa.fcm.service_account_file"), "{e}");
}

#[tokio::test]
async fn a_file_that_is_no_service_account_stops_start_up_without_echoing_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("bad.json"),
        r#"{"private_key": "SECRET-GARBAGE"}"#,
    )
    .expect("write");
    let e = start(&config(&dir, "bad.json")).await.expect_err("refused");
    assert!(e.contains("mfa.fcm.service_account_file"), "{e}");
    assert!(!e.contains("SECRET-GARBAGE"), "{e}");
}

#[tokio::test]
async fn a_valid_service_account_file_starts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let json = serde_json::json!({
        "client_email": "svc@demo-project.iam.gserviceaccount.com",
        "private_key": KEY_PEM,
    });
    std::fs::write(dir.path().join("ok.json"), json.to_string()).expect("write");
    start(&config(&dir, "ok.json")).await.expect("starts");
}

#[tokio::test]
async fn without_fcm_settings_the_server_starts_with_no_push() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().join("data");
    start(&cfg).await.expect("starts");
}
