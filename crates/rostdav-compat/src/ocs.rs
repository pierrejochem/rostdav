//! OCS endpoints: envelope, capabilities, user, app password sign-out.

use std::net::{IpAddr, Ipv4Addr};

use axum::extract::{Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rostdav_app::{AppState, Principal};
use rostdav_core::{ClientIp, Error};
use serde_json::{Value, json};

use crate::{CompatConfig, json_response};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Xml,
}

#[derive(serde::Deserialize, Default)]
pub struct FormatQuery {
    format: Option<String>,
}

struct Ocs {
    v2: bool,
    format: Format,
}

impl Ocs {
    fn new(version: &str, q: &FormatQuery, headers: &HeaderMap) -> Option<Self> {
        let v2 = match version {
            "v1.php" => false,
            "v2.php" => true,
            _ => return None,
        };
        let wants_json = q.format.as_deref() == Some("json")
            || (q.format.is_none()
                && headers
                    .get(header::ACCEPT)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|a| a.contains("application/json")));
        Some(Self {
            v2,
            format: if wants_json {
                Format::Json
            } else {
                Format::Xml
            },
        })
    }

    fn ok(&self, data: &Value) -> Response {
        let meta = if self.v2 {
            json!({"status": "ok", "statuscode": 200, "message": "OK"})
        } else {
            json!({"status": "ok", "statuscode": 100, "message": "OK", "totalitems": "", "itemsperpage": ""})
        };
        self.respond(StatusCode::OK, meta, data)
    }

    fn fail(&self, http: StatusCode, code: u16, message: &str) -> Response {
        let meta = json!({"status": "failure", "statuscode": code, "message": message});
        self.respond(http, meta, &json!([]))
    }

    fn respond(&self, http: StatusCode, meta: Value, data: &Value) -> Response {
        let mut r = match self.format {
            Format::Json => json_response(json!({"ocs": {"meta": meta, "data": data}})),
            Format::Xml => {
                let mut x = String::from("<?xml version=\"1.0\"?>\n<ocs>\n <meta>\n");
                if let Value::Object(m) = &meta {
                    for (k, v) in m {
                        xml_node(&mut x, k, v, 2);
                    }
                }
                x.push_str(" </meta>\n <data>\n");
                xml_children(&mut x, data, 2);
                x.push_str(" </data>\n</ocs>\n");
                let mut r = x.into_response();
                r.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/xml; charset=utf-8"),
                );
                r
            }
        };
        *r.status_mut() = http;
        r
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xml_scalar(v: &Value) -> String {
    match v {
        // PHP's XML conversion: true -> "1", false -> "".
        Value::Bool(true) => "1".into(),
        Value::Bool(false) | Value::Null => String::new(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => escape(s),
        _ => String::new(),
    }
}

fn xml_node(out: &mut String, key: &str, v: &Value, depth: usize) {
    let pad = " ".repeat(depth);
    match v {
        Value::Object(_) | Value::Array(_) => {
            let empty = matches!(v, Value::Array(a) if a.is_empty())
                || matches!(v, Value::Object(o) if o.is_empty());
            if empty {
                out.push_str(&format!("{pad}<{key}/>\n"));
            } else {
                out.push_str(&format!("{pad}<{key}>\n"));
                xml_children(out, v, depth + 1);
                out.push_str(&format!("{pad}</{key}>\n"));
            }
        }
        Value::Null => out.push_str(&format!("{pad}<{key}/>\n")),
        _ => out.push_str(&format!("{pad}<{key}>{}</{key}>\n", xml_scalar(v))),
    }
}

fn xml_children(out: &mut String, v: &Value, depth: usize) {
    match v {
        Value::Object(m) => {
            for (k, c) in m {
                xml_node(out, k, c, depth);
            }
        }
        // Lists use <element> items, as the reference server does.
        Value::Array(a) => {
            for c in a {
                xml_node(out, "element", c, depth);
            }
        }
        _ => {}
    }
}

fn client_ip(parts: &Parts) -> IpAddr {
    parts
        .extensions
        .get::<ClientIp>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0)
}

/// Common preamble: version, header check, authentication.
async fn guard(
    state: &AppState,
    version: &str,
    q: &FormatQuery,
    parts: &Parts,
) -> Result<(Ocs, Principal), Box<Response>> {
    let Some(ocs) = Ocs::new(version, q, &parts.headers) else {
        return Err(Box::new(StatusCode::NOT_FOUND.into_response()));
    };
    let has_header = parts
        .headers
        .get("ocs-apirequest")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
    if !has_header {
        let mut r = json_response(json!({"message": "CSRF check failed"}));
        *r.status_mut() = StatusCode::PRECONDITION_FAILED;
        return Err(Box::new(r));
    }
    let Some(auth) = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return Err(Box::new(ocs.fail(
            StatusCode::UNAUTHORIZED,
            997,
            "Current user is not logged in",
        )));
    };
    match state.authenticate_basic(auth, client_ip(parts)).await {
        Ok(p) => Ok((ocs, p)),
        Err(Error::RateLimited { retry_after_secs }) => {
            let mut r = ocs.fail(StatusCode::TOO_MANY_REQUESTS, 429, "Too many requests");
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                r.headers_mut().insert(header::RETRY_AFTER, v);
            }
            Err(Box::new(r))
        }
        Err(Error::Unauthenticated) => Err(Box::new(ocs.fail(
            StatusCode::UNAUTHORIZED,
            997,
            "Unauthorised",
        ))),
        Err(e) => {
            if e.is_internal() {
                tracing::error!(error = %e, "OCS authentication failed");
            }
            Err(Box::new(ocs.fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                996,
                "Internal server error",
            )))
        }
    }
}

pub async fn capabilities(
    State(state): State<AppState>,
    axum::Extension(cfg): axum::Extension<CompatConfig>,
    Path(version): Path<String>,
    Query(q): Query<FormatQuery>,
    parts: Parts,
) -> Response {
    let (ocs, _p) = match guard(&state, &version, &q, &parts).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let (major, minor, micro, short) = cfg.version_parts();
    // Only what Rostdav implements. Chunked upload, sharing, notifications,
    // versions and trash are deliberately absent (docs/compatibility.md).
    ocs.ok(&json!({
        "version": {
            "major": major, "minor": minor, "micro": micro,
            "string": short, "edition": "", "extendedSupport": false,
        },
        "capabilities": {
            "core": {
                "pollinterval": 60,
                "webdav-root": "remote.php/webdav",
            },
        },
    }))
}

pub async fn user(
    State(state): State<AppState>,
    Path(version): Path<String>,
    Query(q): Query<FormatQuery>,
    parts: Parts,
) -> Response {
    let (ocs, p) = match guard(&state, &version, &q, &parts).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let info = match state.user_info(&p).await {
        Ok(i) => i,
        Err(e) => {
            tracing::error!(error = %e, "user info failed");
            return ocs.fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                996,
                "Internal server error",
            );
        }
    };
    // -3 means "unlimited" in the reference server's quota block.
    let (free, total, relative) = match info.quota_total {
        Some(t) => {
            let rel = if t > 0 {
                (info.used as f64 / t as f64 * 100.0 * 100.0).round() / 100.0
            } else {
                0.0
            };
            ((t - info.used).max(0), t, rel)
        }
        None => (-3, -3, 0.0),
    };
    ocs.ok(&json!({
        "enabled": true,
        "id": info.id,
        "quota": {
            "free": free, "used": info.used, "total": total,
            "relative": relative, "quota": info.quota_total.unwrap_or(-3),
        },
        "email": null,
        "displayname": info.display_name,
        "display-name": info.display_name,
        "groups": if info.is_admin { json!(["admin"]) } else { json!([]) },
        "language": "en",
    }))
}

/// Sign-out: revokes the app password this request was authenticated with.
pub async fn revoke_app_password(
    State(state): State<AppState>,
    Path(version): Path<String>,
    Query(q): Query<FormatQuery>,
    parts: Parts,
) -> Response {
    let (ocs, p) = match guard(&state, &version, &q, &parts).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state.revoke_current_app_password(&p).await {
        Ok(()) => ocs.ok(&json!([])),
        Err(Error::BadRequest(m)) => ocs.fail(StatusCode::BAD_REQUEST, 400, m),
        Err(e) => {
            tracing::error!(error = %e, "revoking app password failed");
            ocs.fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                996,
                "Internal server error",
            )
        }
    }
}
