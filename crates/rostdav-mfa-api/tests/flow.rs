//! The device API end to end: a fake phone signs with the contract's formats against the router.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::EcdsaKeyPair;
use rostdav_app::AppState;
use rostdav_app::testkit::{self, Opts};
use serde_json::{Value, json};
use tower::ServiceExt;

static NONCE: AtomicU64 = AtomicU64::new(0);

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

// ---- the contract as JSON ---------------------------------------------------------------------

fn spec() -> Value {
    serde_json::from_str(rustmfa_contract::OPENAPI_JSON).expect("contract JSON")
}

fn resolve<'a>(spec: &'a Value, schema: &'a Value) -> &'a Value {
    match schema["$ref"].as_str() {
        Some(r) => {
            let name = r.strip_prefix("#/components/schemas/").expect("local ref");
            &spec["components"]["schemas"][name]
        }
        None => schema,
    }
}

/// Checks `v` against a schema of the contract: types, enums, constants, required fields, and
/// that no field is present that the contract does not name. The error names the field.
fn validate(spec: &Value, schema: &Value, v: &Value, at: &str) -> Result<(), String> {
    let schema = resolve(spec, schema);
    if let Some(c) = schema.get("const")
        && v != c
    {
        return Err(format!("{at}: expected {c}, got {v}"));
    }
    if let Some(e) = schema["enum"].as_array()
        && !e.contains(v)
    {
        return Err(format!("{at}: {v} is not one of {e:?}"));
    }
    let types: Vec<&str> = match &schema["type"] {
        Value::String(t) => vec![t.as_str()],
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    };
    if types.is_empty() {
        return Ok(());
    }
    let ok = types.iter().any(|t| match *t {
        "string" => v.is_string(),
        "integer" => v.is_i64() || v.is_u64(),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        "array" => v.is_array(),
        "object" => v.is_object(),
        other => panic!("unhandled type {other}"),
    });
    if !ok {
        return Err(format!("{at}: {v} is not of type {types:?}"));
    }
    if let (Some(items), Some(arr)) = (schema.get("items"), v.as_array()) {
        for (i, x) in arr.iter().enumerate() {
            validate(spec, items, x, &format!("{at}[{i}]"))?;
        }
        if let Some(min) = schema["minItems"].as_u64()
            && (arr.len() as u64) < min
        {
            return Err(format!("{at}: fewer than {min} items"));
        }
        if let Some(max) = schema["maxItems"].as_u64()
            && (arr.len() as u64) > max
        {
            return Err(format!("{at}: more than {max} items"));
        }
    }
    if let Some(obj) = v.as_object() {
        let props = schema["properties"].as_object();
        for r in schema["required"].as_array().into_iter().flatten() {
            let r = r.as_str().expect("required name");
            if !obj.contains_key(r) {
                return Err(format!("{at}.{r}: required field missing"));
            }
        }
        for (k, x) in obj {
            let Some(p) = props.and_then(|p| p.get(k)) else {
                return Err(format!("{at}.{k}: field is not in the contract"));
            };
            validate(spec, p, x, &format!("{at}.{k}"))?;
        }
    }
    Ok(())
}

fn conforms(schema: &str, v: &Value) {
    let spec = spec();
    let s = json!({ "$ref": format!("#/components/schemas/{schema}") });
    if let Err(e) = validate(&spec, &s, v, schema) {
        panic!("{e}\nbody: {v}");
    }
}

/// The success schema of an operation, for `status`.
fn response_schema(path: &str, method: &str, status: &str) -> Value {
    let spec = spec();
    spec["paths"][path][method]["responses"][status]["content"]["application/json"]["schema"]
        .clone()
}

fn conforms_to_operation(path: &str, method: &str, status: &str, v: &Value) {
    let spec = spec();
    let schema = response_schema(path, method, status);
    assert!(!schema.is_null(), "{method} {path} {status} has no schema");
    if let Err(e) = validate(&spec, &schema, v, &format!("{method} {path}")) {
        panic!("{e}\nbody: {v}");
    }
}

// ---- harness and fake phone -------------------------------------------------------------------

struct Harness {
    _dir: tempfile_guard::Dir,
    st: AppState,
    app: Router,
}

mod tempfile_guard {
    // keeps the temporary directory of the test state alive without naming its crate
    pub struct Dir(#[allow(dead_code)] pub Box<dyn std::any::Any>);
}

async fn harness() -> Harness {
    let (dir, st) = testkit::state().await;
    let app = rostdav_mfa_api::router().with_state(st.clone());
    Harness {
        _dir: tempfile_guard::Dir(Box::new(dir)),
        st,
        app,
    }
}

struct Phone {
    id: String,
    user_id: i64,
    request: EcdsaKeyPair,
    /// Signs DER; the fake phone converts to the raw form like the real app does.
    approval: EcdsaKeyPair,
}

fn raw_sign_request(key: &EcdsaKeyPair, msg: &str) -> String {
    let sig = key.sign(&SystemRandom::new(), msg.as_bytes()).expect("sig");
    URL_SAFE_NO_PAD.encode(sig.as_ref())
}

fn der_to_raw_b64(der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(rustmfa_contract::der_to_raw(der).expect("raw"))
}

impl Phone {
    fn request(&self, method: &str, pq: &str, body: &[u8]) -> Request<Body> {
        let ts = now();
        let nonce = format!("n{}", NONCE.fetch_add(1, Ordering::SeqCst));
        let msg =
            rustmfa_contract::request_signing_string(method, pq, ts, &nonce, body).expect("msg");
        let sig = raw_sign_request(&self.request, &msg);
        Request::builder()
            .method(method)
            .uri(pq)
            .header(
                "authorization",
                format!(
                    r#"RustMFA-Sig device_id="{}",ts="{ts}",nonce="{nonce}",sig="{sig}""#,
                    self.id
                ),
            )
            .header("content-type", "application/json")
            .body(Body::from(body.to_vec()))
            .expect("request")
    }

    /// The answer signature over the canonical message of challenge details `d`.
    fn answer(&self, d: &Value) -> String {
        let f = |k: &str| d[k].as_str().expect("field").to_owned();
        let (c, n, l, e, a) = (
            f("challenge_id"),
            f("nonce"),
            f("login_id"),
            f("expires_at"),
            f("audience"),
        );
        let msg = rustmfa_contract::canonical_message(&rustmfa_contract::ChallengeMessage {
            challenge_id: &c,
            nonce: &n,
            login_id: &l,
            device_id: &self.id,
            expires_at: &e,
            audience: &a,
        })
        .expect("message");
        let der = self
            .approval
            .sign(&SystemRandom::new(), msg.as_bytes())
            .expect("sig");
        der_to_raw_b64(der.as_ref())
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
    raw: Vec<u8>,
}

async fn send(app: &Router, req: Request<Body>) -> Reply {
    let res = app.clone().oneshot(req).await.expect("response");
    let (parts, body) = res.into_parts();
    let raw = axum::body::to_bytes(body, 1 << 20)
        .await
        .expect("body")
        .to_vec();
    let body = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    Reply {
        status: parts.status,
        headers: parts.headers,
        body,
        raw,
    }
}

fn error_of(r: &Reply) -> (StatusCode, String) {
    let code = r.body["error"]["code"].as_str().unwrap_or("").to_owned();
    assert!(
        r.body["error"]["message"].is_string() || r.status == StatusCode::NO_CONTENT,
        "no error message in {}",
        r.body
    );
    (r.status, code)
}

fn live() -> Opts {
    let t = now();
    Opts {
        base: t,
        leaf_validity: (t - 1000, t + 1000),
        ..Opts::default()
    }
}

/// Registers a phone for a new user through the HTTP route, like the app does.
async fn enroll(h: &Harness, user: &str) -> Phone {
    let principal = testkit::add_user(&h.st, user).await;
    let token =
        h.st.mfa_create_enroll_token(&principal)
            .await
            .expect("token")
            .token;
    let f = testkit::fixture(Opts {
        challenge: sha256(token.as_bytes()),
        ..live()
    });
    h.st.set_attestation_roots_for_tests(vec![f.root.clone()]);
    let request = testkit::fixed_key();
    let body = json!({
        "enroll_token": token,
        "device_name": "Pixel 8",
        "request_public_key": testkit::spki_b64(&request),
        "approval_public_key": f.approval_spki,
        "key_algorithm": "ES256",
        "attestation_chain": f.chain,
        "push_channel": "fcm",
        "push_token": "fcm-token",
    });
    let r = send(
        &h.app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/devices/register")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    Phone {
        id: r.body["device_id"].as_str().expect("device_id").to_owned(),
        user_id: principal.user_id,
        request,
        approval: f.approval_kp,
    }
}

fn ip() -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7))
}

async fn challenge(h: &Harness, p: &Phone, login: &str) -> (String, i64) {
    let c =
        h.st.mfa_create_challenge(p.user_id, &p.id, login, "Firefox on Linux", ip())
            .await
            .expect("challenge");
    (c.challenge_id, c.number)
}

async fn details(h: &Harness, p: &Phone, id: &str) -> Value {
    let r = send(
        &h.app,
        p.request("GET", &format!("/api/v1/mfa/challenges/{id}"), b""),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    r.body
}

fn approve_body(p: &Phone, d: &Value, number: i64) -> Vec<u8> {
    json!({ "device_id": p.id, "selected_number": number, "signature": p.answer(d) })
        .to_string()
        .into_bytes()
}

// ---- tests ------------------------------------------------------------------------------------

#[tokio::test]
async fn full_happy_path() {
    let h = harness().await;
    let p = enroll(&h, "anna").await;
    let (id, number) = challenge(&h, &p, "login-1").await;

    let list = send(
        &h.app,
        p.request("GET", "/api/v1/mfa/challenges?status=pending", b""),
    )
    .await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    assert_eq!(list.body["challenges"][0]["challenge_id"], id);

    let d = details(&h, &p, &id).await;
    assert_eq!(d["status"], "pending");
    assert!(
        d["candidate_numbers"]
            .as_array()
            .expect("3")
            .contains(&json!(number))
    );

    let path = format!("/api/v1/mfa/challenges/{id}/approve");
    let r = send(
        &h.app,
        p.request("POST", &path, &approve_body(&p, &d, number)),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body, json!({ "challenge_id": id, "status": "approved" }));
    assert_eq!(
        h.st.mfa_challenge_status(&id).await.expect("status"),
        rostdav_app::ChallengeStatus::Approved
    );
    assert_eq!(details(&h, &p, &id).await["status"], "approved");
}

#[tokio::test]
async fn register_response_matches_openapi_schema() {
    let h = harness().await;
    // `enroll` asserts 201; read the body again through a second user to keep the raw reply
    let principal = testkit::add_user(&h.st, "ben").await;
    let token =
        h.st.mfa_create_enroll_token(&principal)
            .await
            .expect("t")
            .token;
    let f = testkit::fixture(Opts {
        challenge: sha256(token.as_bytes()),
        ..live()
    });
    h.st.set_attestation_roots_for_tests(vec![f.root.clone()]);
    let body = json!({
        "enroll_token": token, "device_name": "P", "request_public_key": testkit::spki_b64(&testkit::fixed_key()),
        "approval_public_key": f.approval_spki, "key_algorithm": "ES256",
        "attestation_chain": f.chain, "push_channel": "fcm", "push_token": "t",
    });
    let r = send(
        &h.app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/devices/register")
            .body(Body::from(body.to_string()))
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    conforms("DeviceStatusResponse", &r.body);
    conforms_to_operation("/api/v1/devices/register", "post", "201", &r.body);
    assert_eq!(r.body["status"], "active");
}

#[tokio::test]
async fn all_success_responses_match_the_openapi_schemas() {
    let h = harness().await;
    let p = enroll(&h, "anna").await;
    let (id, number) = challenge(&h, &p, "login-1").await;
    let d = details(&h, &p, &id).await;
    conforms("ChallengeDetails", &d);

    let r = send(&h.app, p.request("GET", "/api/v1/devices", b"")).await;
    assert_eq!(r.status, StatusCode::OK);
    conforms_to_operation("/api/v1/devices", "get", "200", &r.body);
    assert_eq!(r.body["devices"][0]["device_id"], p.id);

    let r = send(&h.app, p.request("GET", "/api/v1/mfa/challenges", b"")).await;
    conforms_to_operation("/api/v1/mfa/challenges", "get", "200", &r.body);

    let path = format!("/api/v1/mfa/challenges/{id}/approve");
    let r = send(
        &h.app,
        p.request("POST", &path, &approve_body(&p, &d, number)),
    )
    .await;
    conforms_to_operation(
        "/api/v1/mfa/challenges/{challenge_id}/approve",
        "post",
        "200",
        &r.body,
    );

    let (id2, _) = challenge(&h, &p, "login-2").await;
    let d2 = details(&h, &p, &id2).await;
    let body = json!({ "device_id": p.id, "signature": p.answer(&d2) }).to_string();
    let r = send(
        &h.app,
        p.request(
            "POST",
            &format!("/api/v1/mfa/challenges/{id2}/deny"),
            body.as_bytes(),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    conforms_to_operation(
        "/api/v1/mfa/challenges/{challenge_id}/deny",
        "post",
        "200",
        &r.body,
    );
    assert_eq!(r.body["status"], "denied");

    let body = json!({ "push_channel": "unifiedpush", "push_token": "https://up/x" }).to_string();
    let r = send(
        &h.app,
        p.request(
            "PUT",
            &format!("/api/v1/devices/{}/push-token", p.id),
            body.as_bytes(),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    conforms_to_operation(
        "/api/v1/devices/{device_id}/push-token",
        "put",
        "200",
        &r.body,
    );

    let r = send(&h.app, p.request("GET", "/api/v1/audit", b"")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    conforms_to_operation("/api/v1/audit", "get", "200", &r.body);
    assert!(!r.body["events"].as_array().expect("events").is_empty());

    // rotate last: it changes the request key
    let new_request = testkit::fixed_key();
    let req_pub = testkit::spki_b64(&new_request);
    let f = testkit::fixture(Opts {
        challenge: sha256(format!("rotate:{}:{req_pub}", p.id).as_bytes()),
        ..live()
    });
    h.st.set_attestation_roots_for_tests(vec![f.root.clone()]);
    let body = json!({
        "request_public_key": req_pub,
        "approval_public_key": f.approval_spki,
        "attestation_chain": f.chain,
    })
    .to_string();
    let r = send(
        &h.app,
        p.request(
            "POST",
            &format!("/api/v1/devices/{}/rotate-key", p.id),
            body.as_bytes(),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    conforms_to_operation(
        "/api/v1/devices/{device_id}/rotate-key",
        "post",
        "200",
        &r.body,
    );
    // the old request key no longer authenticates
    let r = send(&h.app, p.request("GET", "/api/v1/devices", b"")).await;
    assert_eq!(
        error_of(&r),
        (StatusCode::UNAUTHORIZED, "UNAUTHENTICATED".into())
    );
}

#[tokio::test]
async fn revoking_a_device_answers_204_and_blocks_it() {
    let h = harness().await;
    let p = enroll(&h, "anna").await;
    let r = send(
        &h.app,
        p.request("DELETE", &format!("/api/v1/devices/{}", p.id), b""),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(r.raw.is_empty());
    let r = send(&h.app, p.request("GET", "/api/v1/devices", b"")).await;
    assert_eq!(
        error_of(&r),
        (StatusCode::FORBIDDEN, "DEVICE_REVOKED".into())
    );
}

fn authenticated_routes() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("GET", "/api/v1/devices", ""),
        ("DELETE", "/api/v1/devices/dev_x", ""),
        (
            "PUT",
            "/api/v1/devices/dev_x/push-token",
            r#"{"push_channel":"fcm","push_token":"t"}"#,
        ),
        (
            "POST",
            "/api/v1/devices/dev_x/rotate-key",
            r#"{"request_public_key":"a","approval_public_key":"b","attestation_chain":[]}"#,
        ),
        ("GET", "/api/v1/mfa/challenges", ""),
        ("GET", "/api/v1/mfa/challenges/ch_x", ""),
        (
            "POST",
            "/api/v1/mfa/challenges/ch_x/approve",
            r#"{"device_id":"d","selected_number":10,"signature":"s"}"#,
        ),
        (
            "POST",
            "/api/v1/mfa/challenges/ch_x/deny",
            r#"{"device_id":"d","signature":"s"}"#,
        ),
        ("GET", "/api/v1/audit", ""),
    ]
}

#[tokio::test]
async fn unauthenticated_requests_get_401_with_error_body() {
    let h = harness().await;
    let p = enroll(&h, "anna").await;
    for (i, (method, path, body)) in authenticated_routes().into_iter().enumerate() {
        let plain = |auth: Option<&str>| {
            let mut b = Request::builder().method(method).uri(path);
            if let Some(a) = auth {
                b = b.header("authorization", a);
            }
            b.body(Body::from(body.to_owned())).expect("req")
        };
        // five failures block a device, so a real device gets one bad signature and the other
        // routes get an unknown one
        let device = if i == 0 {
            p.id.clone()
        } else {
            format!("dev_ghost{i}")
        };
        for (label, req) in [
            ("no header", plain(None)),
            ("garbage", plain(Some("Bearer abc"))),
            (
                "bad signature",
                plain(Some(&format!(
                    r#"RustMFA-Sig device_id="{device}",ts="{}",nonce="zz",sig="AAAA""#,
                    now()
                ))),
            ),
        ] {
            let r = send(&h.app, req).await;
            assert_eq!(
                error_of(&r),
                (StatusCode::UNAUTHORIZED, "UNAUTHENTICATED".into()),
                "{method} {path} ({label})"
            );
        }
        // two Authorization headers are refused, even when each would be fine alone
        let mut req = p.request(method, path, body.as_bytes());
        let first = req.headers().get("authorization").cloned().expect("auth");
        req.headers_mut().append("authorization", first);
        let r = send(&h.app, req).await;
        assert_eq!(
            r.status,
            StatusCode::UNAUTHORIZED,
            "{method} {path} (two headers)"
        );
    }
}

#[tokio::test]
async fn query_string_is_part_of_the_signature() {
    let h = harness().await;
    let p = enroll(&h, "anna").await;
    let mut req = p.request("GET", "/api/v1/mfa/challenges?status=pending", b"");
    *req.uri_mut() = "/api/v1/mfa/challenges?status=approved"
        .parse()
        .expect("uri");
    let r = send(&h.app, req).await;
    assert_eq!(
        error_of(&r),
        (StatusCode::UNAUTHORIZED, "UNAUTHENTICATED".into())
    );
    // and the body
    let body = json!({ "push_channel": "fcm", "push_token": "t" }).to_string();
    let mut req = p.request(
        "PUT",
        &format!("/api/v1/devices/{}/push-token", p.id),
        body.as_bytes(),
    );
    let tampered = json!({ "push_channel": "fcm", "push_token": "evil" }).to_string();
    *req.body_mut() = Body::from(tampered);
    let r = send(&h.app, req).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn error_codes_and_statuses_match_the_contract() {
    let h = harness().await;
    let h = Harness {
        st: h.st.clone().with_mfa(rostdav_app::MfaConfig {
            challenge_ttl_secs: 1,
            ..rostdav_app::MfaConfig::default()
        }),
        ..h
    };
    // the router holds its own clone of the state: build it from the configured one
    let h = Harness {
        app: rostdav_mfa_api::router().with_state(h.st.clone()),
        ..h
    };
    let p = enroll(&h, "anna").await;
    let mut seen: Vec<(&str, StatusCode, String)> = Vec::new();

    // not found: unknown challenge
    let r = send(
        &h.app,
        p.request("GET", "/api/v1/mfa/challenges/ch_unknown", b""),
    )
    .await;
    let (s, c) = error_of(&r);
    seen.push(("unknown challenge", s, c));

    // expired
    let (id, number) = challenge(&h, &p, "l-exp").await;
    let d = details(&h, &p, &id).await;
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    let path = format!("/api/v1/mfa/challenges/{id}/approve");
    let r = send(
        &h.app,
        p.request("POST", &path, &approve_body(&p, &d, number)),
    )
    .await;
    let (s, c) = error_of(&r);
    seen.push(("expired", s, c));

    // consumed and mismatch need a longer lifetime
    let h2 = {
        let st = h.st.clone().with_mfa(rostdav_app::MfaConfig::default());
        Harness {
            app: rostdav_mfa_api::router().with_state(st.clone()),
            st,
            ..h
        }
    };
    let (id, number) = challenge(&h2, &p, "l-ok").await;
    let d = details(&h2, &p, &id).await;
    let path = format!("/api/v1/mfa/challenges/{id}/approve");
    let ok = send(
        &h2.app,
        p.request("POST", &path, &approve_body(&p, &d, number)),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
    let r = send(
        &h2.app,
        p.request("POST", &path, &approve_body(&p, &d, number)),
    )
    .await;
    let (s, c) = error_of(&r);
    seen.push(("consumed", s, c));

    let (id, number) = challenge(&h2, &p, "l-mis").await;
    let d = details(&h2, &p, &id).await;
    let wrong = d["candidate_numbers"]
        .as_array()
        .expect("3")
        .iter()
        .filter_map(Value::as_i64)
        .find(|n| *n != number)
        .expect("decoy");
    let path = format!("/api/v1/mfa/challenges/{id}/approve");
    let r = send(
        &h2.app,
        p.request("POST", &path, &approve_body(&p, &d, wrong)),
    )
    .await;
    let (s, c) = error_of(&r);
    seen.push(("mismatch", s, c));

    // another device in the body
    let (id, number) = challenge(&h2, &p, "l-dev").await;
    let d = details(&h2, &p, &id).await;
    let body =
        json!({ "device_id": "dev_other", "selected_number": number, "signature": p.answer(&d) });
    let r = send(
        &h2.app,
        p.request(
            "POST",
            &format!("/api/v1/mfa/challenges/{id}/approve"),
            body.to_string().as_bytes(),
        ),
    )
    .await;
    let (s, c) = error_of(&r);
    seen.push(("device_id of another phone", s, c));

    // invalid request
    let r = send(
        &h2.app,
        p.request(
            "PUT",
            &format!("/api/v1/devices/{}/push-token", p.id),
            json!({ "push_channel": "sms", "push_token": "t" })
                .to_string()
                .as_bytes(),
        ),
    )
    .await;
    let (s, c) = error_of(&r);
    seen.push(("invalid request", s, c));

    // rate limited: five wrong tokens from one address, the sixth is refused
    let mut last = None;
    for i in 0..6 {
        let body = json!({
            "enroll_token": "nope", "device_name": "x", "request_public_key": "a",
            "approval_public_key": "b", "key_algorithm": "ES256", "attestation_chain": [],
            "push_channel": "fcm", "push_token": format!("t{i}"),
        });
        // keys must be real for the failure to count, so use valid ones with a wrong token
        let mut body = body;
        body["request_public_key"] = json!(testkit::spki_b64(&testkit::fixed_key()));
        body["approval_public_key"] = json!(testkit::spki_b64(&testkit::fixed_key()));
        last = Some(
            send(
                &h2.app,
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/devices/register")
                    .body(Body::from(body.to_string()))
                    .expect("req"),
            )
            .await,
        );
    }
    let r = last.expect("six replies");
    assert!(
        r.headers.get("retry-after").is_some(),
        "429 needs Retry-After"
    );
    let retry: u64 = r.headers["retry-after"]
        .to_str()
        .expect("str")
        .parse()
        .expect("secs");
    assert!(retry > 0 && retry <= 900);
    let (s, c) = error_of(&r);
    seen.push(("rate limited", s, c));

    // revoked
    send(
        &h2.app,
        p.request("DELETE", &format!("/api/v1/devices/{}", p.id), b""),
    )
    .await;
    let r = send(&h2.app, p.request("GET", "/api/v1/devices", b"")).await;
    let (s, c) = error_of(&r);
    seen.push(("revoked", s, c));

    let expected: [(&str, u16, &str); 9] = [
        ("unknown challenge", 404, "RESOURCE_NOT_FOUND"),
        ("expired", 410, "CHALLENGE_EXPIRED"),
        ("consumed", 409, "CHALLENGE_ALREADY_CONSUMED"),
        ("mismatch", 409, "CHALLENGE_NUMBER_MISMATCH"),
        ("device_id of another phone", 403, "DEVICE_NOT_AUTHORIZED"),
        ("invalid request", 400, "INVALID_REQUEST"),
        ("rate limited", 429, "RATE_LIMITED"),
        ("revoked", 403, "DEVICE_REVOKED"),
        ("unauthenticated placeholder", 401, "UNAUTHENTICATED"),
    ];
    for (name, status, code) in &expected[..8] {
        let got = seen
            .iter()
            .find(|(n, _, _)| n == name)
            .unwrap_or_else(|| panic!("{name} not run"));
        assert_eq!((got.1.as_u16(), got.2.as_str()), (*status, *code), "{name}");
    }
}

#[tokio::test]
async fn body_over_64_kib_is_rejected_413() {
    let h = harness().await;
    let p = enroll(&h, "anna").await;
    let big = "a".repeat(64 * 1024 + 1);
    let r = send(
        &h.app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/devices/register")
            .body(Body::from(big.clone()))
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(r.body["error"]["code"], "INVALID_REQUEST");
    // authenticated routes too, even with a good signature over the whole body
    let body = format!(r#"{{"push_channel":"fcm","push_token":"{big}"}}"#);
    let r = send(
        &h.app,
        p.request(
            "PUT",
            &format!("/api/v1/devices/{}/push-token", p.id),
            body.as_bytes(),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    // exactly the limit still reaches the parser (and fails there, not on size)
    let r = send(
        &h.app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/devices/register")
            .body(Body::from("a".repeat(64 * 1024)))
            .expect("req"),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_json_fields_are_rejected() {
    let h = harness().await;
    let p = enroll(&h, "anna").await;
    let (id, number) = challenge(&h, &p, "l").await;
    let d = details(&h, &p, &id).await;
    let mut body: Value = serde_json::from_slice(&approve_body(&p, &d, number)).expect("json");
    body["extra"] = json!(true);
    let r = send(
        &h.app,
        p.request(
            "POST",
            &format!("/api/v1/mfa/challenges/{id}/approve"),
            body.to_string().as_bytes(),
        ),
    )
    .await;
    assert_eq!(
        error_of(&r),
        (StatusCode::BAD_REQUEST, "INVALID_REQUEST".into())
    );
    assert_eq!(
        h.st.mfa_challenge_status(&id).await.expect("s"),
        rostdav_app::ChallengeStatus::Pending
    );
    // registration too
    let r = send(
        &h.app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/devices/register")
            .body(Body::from(
                json!({ "enroll_token": "x", "extra": 1 }).to_string(),
            ))
            .expect("req"),
    )
    .await;
    assert_eq!(
        error_of(&r),
        (StatusCode::BAD_REQUEST, "INVALID_REQUEST".into())
    );
    // not JSON at all
    let r = send(
        &h.app,
        p.request(
            "PUT",
            &format!("/api/v1/devices/{}/push-token", p.id),
            b"not json",
        ),
    )
    .await;
    assert_eq!(
        error_of(&r),
        (StatusCode::BAD_REQUEST, "INVALID_REQUEST".into())
    );
    // a bad status filter
    let r = send(
        &h.app,
        p.request("GET", "/api/v1/mfa/challenges?status=approved", b""),
    )
    .await;
    assert_eq!(
        error_of(&r),
        (StatusCode::BAD_REQUEST, "INVALID_REQUEST".into())
    );
    let r = send(&h.app, p.request("GET", "/api/v1/mfa/challenges?x=1", b"")).await;
    assert_eq!(
        error_of(&r),
        (StatusCode::BAD_REQUEST, "INVALID_REQUEST".into())
    );
}

#[tokio::test]
async fn responses_contain_no_candidate_marker_and_no_internal_ids_of_other_users() {
    let h = harness().await;
    let anna = enroll(&h, "anna").await;
    let ben = enroll(&h, "ben").await;
    let (a_id, _) = challenge(&h, &anna, "la").await;
    let (b_id, _) = challenge(&h, &ben, "lb").await;

    let d = details(&h, &anna, &a_id).await;
    let mut keys: Vec<&str> = d
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    let spec = spec();
    let mut allowed: Vec<&str> = spec["components"]["schemas"]["ChallengeDetails"]["properties"]
        .as_object()
        .expect("props")
        .keys()
        .map(String::as_str)
        .collect();
    allowed.sort_unstable();
    assert!(
        keys.iter().all(|k| allowed.contains(k)),
        "{keys:?} vs {allowed:?}"
    );
    assert!(d["candidate_numbers"].is_array());

    // another user's challenge looks exactly like one that does not exist
    let other = send(
        &h.app,
        anna.request("GET", &format!("/api/v1/mfa/challenges/{b_id}"), b""),
    )
    .await;
    let none = send(
        &h.app,
        anna.request("GET", "/api/v1/mfa/challenges/ch_doesnotexist", b""),
    )
    .await;
    assert_eq!(other.status, StatusCode::NOT_FOUND);
    assert_eq!((other.status, &other.body), (none.status, &none.body));
    // no list, device list or audit view of anna names ben's ids
    let mut text = String::new();
    for path in ["/api/v1/mfa/challenges", "/api/v1/devices", "/api/v1/audit"] {
        let r = send(&h.app, anna.request("GET", path, b"")).await;
        text.push_str(&String::from_utf8_lossy(&r.raw));
    }
    for secret in [b_id.as_str(), ben.id.as_str()] {
        assert!(!text.contains(secret), "anna's responses mention {secret}");
    }
    // ben cannot revoke or change anna's phone
    let r = send(
        &h.app,
        ben.request("DELETE", &format!("/api/v1/devices/{}", anna.id), b""),
    )
    .await;
    assert_eq!(
        error_of(&r),
        (StatusCode::NOT_FOUND, "RESOURCE_NOT_FOUND".into())
    );
    let body = json!({ "push_channel": "fcm", "push_token": "evil" }).to_string();
    let r = send(
        &h.app,
        ben.request(
            "PUT",
            &format!("/api/v1/devices/{}/push-token", anna.id),
            body.as_bytes(),
        ),
    )
    .await;
    assert_eq!(
        error_of(&r),
        (StatusCode::FORBIDDEN, "DEVICE_NOT_AUTHORIZED".into())
    );
}

#[tokio::test]
async fn every_response_is_marked_not_cacheable() {
    let h = harness().await;
    let p = enroll(&h, "anna").await;
    for req in [
        p.request("GET", "/api/v1/devices", b""),
        p.request("GET", "/api/v1/mfa/challenges/ch_none", b""),
        Request::builder()
            .method("POST")
            .uri("/api/v1/devices/register")
            .body(Body::from("{}"))
            .expect("req"),
    ] {
        let r = send(&h.app, req).await;
        assert_eq!(
            r.headers.get("cache-control").and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }
}

#[tokio::test]
async fn error_bodies_never_echo_the_request() {
    let h = harness().await;
    let p = enroll(&h, "anna").await;
    let body =
        json!({ "push_channel": "fcm", "push_token": "super-secret-push-token-\n" }).to_string();
    let r = send(
        &h.app,
        p.request(
            "PUT",
            &format!("/api/v1/devices/{}/push-token", p.id),
            body.as_bytes(),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let text = String::from_utf8_lossy(&r.raw);
    assert!(!text.contains("super-secret"), "{text}");
}

#[tokio::test]
async fn deny_with_another_device_id_in_the_body_is_refused() {
    let h = harness().await;
    let p = enroll(&h, "anna").await;
    let (id, _) = challenge(&h, &p, "l").await;
    let d = details(&h, &p, &id).await;
    let body = json!({ "device_id": "dev_other", "signature": p.answer(&d) }).to_string();
    let r = send(
        &h.app,
        p.request(
            "POST",
            &format!("/api/v1/mfa/challenges/{id}/deny"),
            body.as_bytes(),
        ),
    )
    .await;
    assert_eq!(
        error_of(&r),
        (StatusCode::FORBIDDEN, "DEVICE_NOT_AUTHORIZED".into())
    );
    assert_eq!(
        h.st.mfa_challenge_status(&id).await.expect("s"),
        rostdav_app::ChallengeStatus::Pending
    );
}

#[tokio::test]
async fn the_device_list_tells_what_the_attestation_proved() {
    let h = harness().await;
    let p = enroll(&h, "anna").await;
    let r = send(&h.app, p.request("GET", "/api/v1/devices", b"")).await;
    let d = &r.body["devices"][0];
    // the test chain says TEE, not StrongBox
    assert_eq!(
        (d["hardware_backed"].clone(), d["strongbox"].clone()),
        (json!(true), json!(false))
    );
    assert_eq!(d["device_name"], "Pixel 8");
    assert_eq!(d["push_channel"], "fcm");
    assert_eq!(d["status"], "active");
}

#[tokio::test]
async fn register_with_an_unknown_field_is_rejected_and_keeps_the_token() {
    let h = harness().await;
    let principal = testkit::add_user(&h.st, "anna").await;
    let token =
        h.st.mfa_create_enroll_token(&principal)
            .await
            .expect("t")
            .token;
    let f = testkit::fixture(Opts {
        challenge: sha256(token.as_bytes()),
        ..live()
    });
    h.st.set_attestation_roots_for_tests(vec![f.root.clone()]);
    let mut body = json!({
        "enroll_token": token, "device_name": "P",
        "request_public_key": testkit::spki_b64(&testkit::fixed_key()),
        "approval_public_key": f.approval_spki, "key_algorithm": "ES256",
        "attestation_chain": f.chain, "push_channel": "fcm", "push_token": "t",
    });
    let post = |b: &Value| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/devices/register")
            .body(Body::from(b.to_string()))
            .expect("req")
    };
    body["extra"] = json!(1);
    let r = send(&h.app, post(&body)).await;
    assert_eq!(
        error_of(&r),
        (StatusCode::BAD_REQUEST, "INVALID_REQUEST".into())
    );
    // the request never reached the service: the token is still good
    body.as_object_mut().expect("object").remove("extra");
    let r = send(&h.app, post(&body)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
}
