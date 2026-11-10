//! The FCM adapter against a fake Google: one local server answers the token and the send
//! endpoint, and records what it received.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey};
use serde_json::{Value, json};

use super::fcm::FcmPush;
use super::push::PushChannel;

const KEY_PEM: &str = include_str!("testdata/test_rsa_key.pem");
const PUSH_TOKEN: &str = "phone-push-token-secret";
const ACCESS_TOKEN: &str = "ya29.access-token-secret";
const EMAIL: &str = "svc@demo-project.iam.gserviceaccount.com";

#[derive(Clone, Debug)]
struct Seen {
    path: String,
    authorization: String,
    body: String,
}

struct Behaviour {
    token_status: u16,
    token_body: String,
    send_status: u16,
    send_body: String,
    delay: Duration,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self {
            token_status: 200,
            token_body: json!({"access_token": ACCESS_TOKEN, "expires_in": 3600}).to_string(),
            send_status: 200,
            send_body: json!({"name": "projects/demo-project/messages/1"}).to_string(),
            delay: Duration::ZERO,
        }
    }
}

struct Fake {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    behaviour: Arc<Mutex<Behaviour>>,
}

impl Fake {
    fn start() -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let behaviour = Arc::new(Mutex::new(Behaviour::default()));
        let (s2, b2) = (seen.clone(), behaviour.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (s3, b3) = (s2.clone(), b2.clone());
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head_end, len) = loop {
                        let n = stream.read(&mut chunk).unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                            let len = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            break (i + 4, len);
                        }
                    };
                    while buf.len() < head_end + len {
                        let n = stream.read(&mut chunk).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let path = head
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_owned();
                    let authorization = head
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("authorization:"))
                        .map(|l| l.split_once(':').map_or("", |x| x.1).trim().to_owned())
                        .unwrap_or_default();
                    let body = String::from_utf8_lossy(&buf[head_end..]).to_string();
                    s3.lock().expect("seen").push(Seen {
                        path: path.clone(),
                        authorization,
                        body,
                    });
                    let (status, answer, delay) = {
                        let b = b3.lock().expect("behaviour");
                        if path == "/token" {
                            (b.token_status, b.token_body.clone(), b.delay)
                        } else {
                            (b.send_status, b.send_body.clone(), b.delay)
                        }
                    };
                    std::thread::sleep(delay);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
                        answer.len()
                    );
                });
            }
        });
        Fake {
            base,
            seen,
            behaviour,
        }
    }

    fn requests(&self, path_prefix: &str) -> Vec<Seen> {
        self.seen
            .lock()
            .expect("seen")
            .iter()
            .filter(|s| s.path.starts_with(path_prefix))
            .cloned()
            .collect()
    }

    fn push(&self) -> FcmPush {
        let json = json!({
            "type": "service_account",
            "client_email": EMAIL,
            "private_key": KEY_PEM,
            "token_uri": format!("{}/token", self.base),
        })
        .to_string();
        FcmPush::from_service_account("demo-project", &json)
            .expect("service account")
            .with_endpoints(format!("{}/token", self.base), self.base.clone())
    }
}

#[tokio::test]
async fn sends_a_data_message_with_the_challenge_id_only() {
    let f = Fake::start();
    f.push()
        .notify("fcm", PUSH_TOKEN, "ch_abc")
        .await
        .expect("sent");
    let sent = f.requests("/v1/projects/demo-project/messages:send");
    assert_eq!(sent.len(), 1, "{:?}", f.seen.lock().expect("seen"));
    assert_eq!(sent[0].authorization, format!("Bearer {ACCESS_TOKEN}"));
    let m: Value = serde_json::from_str(&sent[0].body).expect("json");
    assert_eq!(m["message"]["token"], PUSH_TOKEN);
    assert_eq!(m["message"]["data"], json!({"challenge_id": "ch_abc"}));
    assert!(m["message"].get("notification").is_none(), "{m}");
    assert!(!sent[0].body.contains("number"), "no number in the message");
}

#[tokio::test]
async fn the_message_has_high_priority() {
    let f = Fake::start();
    f.push()
        .notify("fcm", PUSH_TOKEN, "ch_1")
        .await
        .expect("sent");
    let m: Value = serde_json::from_str(&f.requests("/v1/")[0].body).expect("json");
    assert_eq!(m["message"]["android"]["priority"], "HIGH");
}

#[tokio::test]
async fn the_jwt_is_rs256_with_the_right_claims() {
    let f = Fake::start();
    f.push()
        .notify("fcm", PUSH_TOKEN, "ch_1")
        .await
        .expect("sent");
    let t = f.requests("/token");
    assert_eq!(t.len(), 1);
    let form = &t[0].body;
    assert!(
        form.starts_with(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
        ),
        "{form}"
    );
    let jwt = form.split("assertion=").nth(1).expect("assertion");
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let dec = |s: &str| -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(s).expect("b64")).expect("json")
    };
    assert_eq!(dec(parts[0]), json!({"alg": "RS256", "typ": "JWT"}));
    let claims = dec(parts[1]);
    assert_eq!(claims["iss"], EMAIL);
    assert_eq!(
        claims["scope"],
        "https://www.googleapis.com/auth/firebase.messaging"
    );
    assert_eq!(claims["aud"], format!("{}/token", f.base));
    let (iat, exp) = (
        claims["iat"].as_i64().expect("iat"),
        claims["exp"].as_i64().expect("exp"),
    );
    assert_eq!(exp - iat, 3600);
    // the signature verifies with the public half of the key
    let der = {
        let b64: String = KEY_PEM
            .lines()
            .filter(|l| !l.starts_with('#') && !l.starts_with("-----"))
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("pem")
    };
    let pair = RsaKeyPair::from_pkcs8(&der).expect("key");
    let sig = URL_SAFE_NO_PAD.decode(parts[2]).expect("sig");
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pair.public().as_ref())
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .expect("signature");
}

#[tokio::test]
async fn the_access_token_is_reused_until_it_expires() {
    let f = Fake::start();
    let p = f.push();
    p.notify("fcm", PUSH_TOKEN, "ch_1").await.expect("1");
    p.notify("fcm", PUSH_TOKEN, "ch_2").await.expect("2");
    assert_eq!(f.requests("/token").len(), 1);
    assert_eq!(f.requests("/v1/").len(), 2);
}

#[tokio::test]
async fn a_short_lived_access_token_is_fetched_again() {
    let f = Fake::start();
    f.behaviour.lock().expect("b").token_body =
        json!({"access_token": ACCESS_TOKEN, "expires_in": 30}).to_string();
    let p = f.push();
    p.notify("fcm", PUSH_TOKEN, "ch_1").await.expect("1");
    p.notify("fcm", PUSH_TOKEN, "ch_2").await.expect("2");
    assert_eq!(
        f.requests("/token").len(),
        2,
        "30 s is inside the 60 s margin"
    );
}

#[tokio::test]
async fn an_error_answer_gives_a_short_error_without_secrets() {
    let f = Fake::start();
    {
        let mut b = f.behaviour.lock().expect("b");
        b.send_status = 400;
        b.send_body = json!({"error": {"code": 400,
            "message": format!("bad token {PUSH_TOKEN} for {ACCESS_TOKEN}"),
            "status": "INVALID_ARGUMENT"}})
        .to_string();
    }
    let e = f
        .push()
        .notify("fcm", PUSH_TOKEN, "ch_1")
        .await
        .expect_err("refused");
    assert!(e.contains("400") && e.contains("INVALID_ARGUMENT"), "{e}");
    for secret in [PUSH_TOKEN, ACCESS_TOKEN, "bad token"] {
        assert!(!e.contains(secret), "{e}");
    }
}

#[tokio::test]
async fn an_unregistered_phone_is_an_error_text_not_a_panic() {
    let f = Fake::start();
    {
        let mut b = f.behaviour.lock().expect("b");
        b.send_status = 404;
        b.send_body = json!({"error": {"code": 404, "status": "NOT_FOUND",
            "details": [{"errorCode": "UNREGISTERED"}]}})
        .to_string();
    }
    let e = f
        .push()
        .notify("fcm", PUSH_TOKEN, "ch_1")
        .await
        .expect_err("refused");
    assert!(e.contains("404") && e.contains("UNREGISTERED"), "{e}");
}

#[tokio::test]
async fn a_failing_token_endpoint_is_an_error_without_the_assertion() {
    let f = Fake::start();
    {
        let mut b = f.behaviour.lock().expect("b");
        b.token_status = 401;
        b.token_body =
            json!({"error": "invalid_grant", "error_description": "private key rejected"})
                .to_string();
    }
    let e = f
        .push()
        .notify("fcm", PUSH_TOKEN, "ch_1")
        .await
        .expect_err("refused");
    assert!(e.contains("401"), "{e}");
    let jwt = f.requests("/token")[0]
        .body
        .split("assertion=")
        .nth(1)
        .expect("a")
        .to_owned();
    assert!(!e.contains(&jwt) && !e.contains("private key"), "{e}");
    assert!(
        f.requests("/v1/").is_empty(),
        "nothing is sent without a token"
    );
}

#[tokio::test]
async fn a_slow_server_times_out() {
    let f = Fake::start();
    f.behaviour.lock().expect("b").delay = Duration::from_millis(1500);
    let p = f.push().with_timeout(Duration::from_millis(300));
    let started = std::time::Instant::now();
    let e = p
        .notify("fcm", PUSH_TOKEN, "ch_1")
        .await
        .expect_err("timeout");
    assert!(started.elapsed() < Duration::from_secs(1), "{e}");
    assert!(!e.contains(PUSH_TOKEN), "{e}");
}

#[tokio::test]
async fn the_unifiedpush_channel_is_left_alone() {
    let f = Fake::start();
    f.push()
        .notify("unifiedpush", "https://up.example/x", "ch_1")
        .await
        .expect("noop");
    assert!(f.seen.lock().expect("seen").is_empty());
}

#[test]
fn a_bad_service_account_is_refused_without_echoing_the_key() {
    for json in [
        "not json".to_owned(),
        json!({"client_email": EMAIL}).to_string(),
        json!({"client_email": EMAIL, "private_key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}).to_string(),
    ] {
        let e = FcmPush::from_service_account("demo-project", &json).err().expect("refused");
        assert!(!e.contains("AAAA"), "{e}");
    }
}
