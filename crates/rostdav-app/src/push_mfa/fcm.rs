//! Waking a phone through Firebase Cloud Messaging (ADR 0014, spec 4.8). The message is a data
//! message with the challenge id only, at high priority: nothing secret goes through Google.
//! Authentication is the OAuth2 service-account flow: a JWT signed with the account's RSA key is
//! exchanged for a short-lived access token, which is kept until a minute before it ends.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde_json::{Value, json};

use super::push::{PushChannel, PushFuture};

const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const DEFAULT_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const DEFAULT_SEND_BASE: &str = "https://fcm.googleapis.com";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const JWT_LIFETIME_SECS: i64 = 3600;
/// An access token is replaced this long before it ends.
const TOKEN_MARGIN_SECS: i64 = 60;
const MAX_ANSWER: u64 = 64 * 1024;

struct Inner {
    project: String,
    client_email: String,
    key: RsaKeyPair,
    token_url: String,
    send_base: String,
    timeout: Duration,
    /// Access token and the second it expires at.
    cached: Mutex<Option<(String, i64)>>,
}

/// The FCM channel. Cheap to clone; the access token is shared.
#[derive(Clone)]
pub struct FcmPush {
    inner: Arc<Inner>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

/// A word of an error answer that is safe to log: capital letters, digits and `_`, short.
fn enum_word(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    (!s.is_empty()
        && s.len() <= 40
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'))
    .then(|| s.to_owned())
}

/// What an error answer of Google says, reduced to enum words. Free text never gets through: it
/// can echo the push token.
fn error_words(body: &[u8]) -> String {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return String::new();
    };
    let mut out = Vec::new();
    out.extend(enum_word(&v["error"]["status"]));
    if let Some(d) = v["error"]["details"].as_array() {
        out.extend(d.iter().filter_map(|x| enum_word(&x["errorCode"])));
    }
    if out.is_empty() {
        String::new()
    } else {
        format!(" ({})", out.join(", "))
    }
}

impl FcmPush {
    /// Reads a Google service-account file. The error text never holds the key.
    pub fn from_service_account(project_id: &str, json: &str) -> Result<FcmPush, String> {
        let v: Value = serde_json::from_str(json)
            .map_err(|_| "the service account file is not JSON".to_owned())?;
        let email = v["client_email"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("the service account file has no client_email")?;
        let pem = v["private_key"]
            .as_str()
            .ok_or("the service account file has no private_key")?;
        let b64: String = pem
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#') && !l.starts_with("-----"))
            .collect();
        let der = STANDARD
            .decode(b64)
            .map_err(|_| "the private key is not valid PEM".to_owned())?;
        let key = RsaKeyPair::from_pkcs8(&der)
            .map_err(|_| "the private key is not a PKCS#8 RSA key".to_owned())?;
        let token_url = v["token_uri"]
            .as_str()
            .unwrap_or(DEFAULT_TOKEN_URL)
            .to_owned();
        Ok(FcmPush {
            inner: Arc::new(Inner {
                project: project_id.to_owned(),
                client_email: email.to_owned(),
                key,
                token_url,
                send_base: DEFAULT_SEND_BASE.to_owned(),
                timeout: DEFAULT_TIMEOUT,
                cached: Mutex::new(None),
            }),
        })
    }

    /// Other addresses for the token and the send endpoint (tests talk to a local server).
    #[must_use]
    pub fn with_endpoints(self, token_url: String, send_base: String) -> FcmPush {
        self.rebuild(|i| {
            i.token_url = token_url;
            i.send_base = send_base;
        })
    }

    #[must_use]
    pub fn with_timeout(self, timeout: Duration) -> FcmPush {
        self.rebuild(|i| i.timeout = timeout)
    }

    /// Changes the settings of a channel that is not shared yet; a shared one is left as it is.
    fn rebuild(mut self, f: impl FnOnce(&mut Inner)) -> FcmPush {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            f(inner);
        }
        self
    }
}

impl Inner {
    fn agent(&self) -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .max_redirects(0)
            .http_status_as_error(false)
            .user_agent(format!("rostdav/{}", rostdav_core::VERSION))
            .build()
            .into()
    }

    fn jwt(&self, at: i64) -> Result<String, String> {
        let part = |v: &Value| URL_SAFE_NO_PAD.encode(v.to_string());
        let signing_input = format!(
            "{}.{}",
            part(&json!({"alg": "RS256", "typ": "JWT"})),
            part(&json!({
                "iss": self.client_email,
                "scope": SCOPE,
                "aud": self.token_url,
                "iat": at,
                "exp": at + JWT_LIFETIME_SECS,
            }))
        );
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut sig,
            )
            .map_err(|_| "signing the token request failed".to_owned())?;
        Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)))
    }

    /// A valid access token: the cached one, or a new one from the token endpoint.
    fn access_token(&self) -> Result<String, String> {
        let at = now();
        if let Ok(g) = self.cached.lock()
            && let Some((tok, exp)) = g.as_ref()
            && *exp - TOKEN_MARGIN_SECS > at
        {
            return Ok(tok.clone());
        }
        let form = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}",
            self.jwt(at)?
        );
        let mut resp = self
            .agent()
            .post(&self.token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send(form)
            .map_err(|e| format!("token request failed: {e}"))?;
        let code = resp.status().as_u16();
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER)
            .read_to_vec()
            .map_err(|_| format!("token request answered {code}, unreadable"))?;
        let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        if code != 200 {
            // the OAuth error code is a short lowercase word; the description can say more
            let word = v["error"]
                .as_str()
                .filter(|s| s.len() <= 40 && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
                .map(|s| format!(" ({s})"))
                .unwrap_or_default();
            return Err(format!("token request answered {code}{word}"));
        }
        let tok = v["access_token"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("token answer has no access_token")?
            .to_owned();
        let lifetime = v["expires_in"].as_i64().unwrap_or(0).clamp(0, 86_400);
        if let Ok(mut g) = self.cached.lock() {
            *g = Some((tok.clone(), at + lifetime));
        }
        Ok(tok)
    }

    fn send(&self, push_token: &str, challenge_id: &str) -> Result<(), String> {
        let access = self.access_token()?;
        let body = json!({"message": {
            "token": push_token,
            "data": {"challenge_id": challenge_id},
            "android": {"priority": "HIGH"},
        }})
        .to_string();
        let url = format!(
            "{}/v1/projects/{}/messages:send",
            self.send_base.trim_end_matches('/'),
            self.project
        );
        let mut resp = self
            .agent()
            .post(&url)
            .header("Authorization", format!("Bearer {access}"))
            .header("Content-Type", "application/json")
            .send(body)
            .map_err(|e| format!("FCM request failed: {e}"))?;
        let code = resp.status().as_u16();
        if (200..300).contains(&code) {
            return Ok(());
        }
        let answer = resp
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER)
            .read_to_vec()
            .unwrap_or_default();
        // a rejected access token is dropped, the next message asks for a new one
        if code == 401
            && let Ok(mut g) = self.cached.lock()
        {
            *g = None;
        }
        Err(format!("FCM answered {code}{}", error_words(&answer)))
    }
}

impl PushChannel for FcmPush {
    fn notify<'a>(
        &'a self,
        channel: &'a str,
        token: &'a str,
        challenge_id: &'a str,
    ) -> PushFuture<'a> {
        Box::pin(async move {
            if channel != "fcm" {
                tracing::debug!(channel, challenge_id, "not an FCM phone; nothing sent");
                return Ok(());
            }
            let (inner, token, id) = (
                self.inner.clone(),
                token.to_owned(),
                challenge_id.to_owned(),
            );
            tokio::task::spawn_blocking(move || inner.send(&token, &id))
                .await
                .map_err(|_| "the push task stopped".to_owned())?
        })
    }
}
