//! M11a: browser sessions, CSRF, security headers and the Files page (ADR 0006).

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rostdav::config::Config;
use tower::ServiceExt;

const PW: &str = "korrekt-pferd-batterie";
const HOST: &str = "files.test";

struct Env {
    app: Router,
    _dir: tempfile::TempDir,
}

async fn env() -> Env {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().join("data");
    let state = rostdav::build_state(&cfg).await.expect("state");
    for n in ["anna", "bob"] {
        state.add_user(n, PW, false).await.expect("user");
    }
    Env {
        app: rostdav::http::router_with(state, &rostdav::http::HttpOptions::from_config(&cfg)),
        _dir: dir,
    }
}

struct Res {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Res {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn h(&self, n: &str) -> &str {
        self.headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
    fn cookies(&self) -> Vec<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect()
    }
    /// `name=value` of a cookie set by this response.
    fn cookie(&self, name: &str) -> Option<String> {
        self.cookies()
            .into_iter()
            .find(|c| c.starts_with(&format!("{name}=")))
            .map(|c| c.split(';').next().unwrap_or("").to_owned())
    }
}

async fn send(e: &Env, method: &str, uri: &str, headers: &[(&str, &str)], body: Body) -> Res {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", HOST);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let r = e
        .app
        .clone()
        .oneshot(b.body(body).expect("request"))
        .await
        .expect("response");
    let (parts, body) = r.into_parts();
    Res {
        status: parts.status,
        headers: parts.headers,
        body: body.collect().await.expect("body").to_bytes().to_vec(),
    }
}

fn form(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| {
            format!(
                "{k}={}",
                percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn origin() -> String {
    format!("http://{HOST}")
}

async fn post_form(e: &Env, uri: &str, cookie: &str, fields: &[(&str, &str)]) -> Res {
    let o = origin();
    send(
        e,
        "POST",
        uri,
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", cookie),
            ("origin", &o),
        ],
        Body::from(form(fields)),
    )
    .await
}

fn extract_csrf(html: &str) -> String {
    let i = html.find("name=\"csrf\" value=\"").expect("csrf field") + 19;
    html[i..].split('"').next().expect("value").to_owned()
}

/// Signs in and returns the session cookie pair.
async fn login(e: &Env, user: &str) -> String {
    let page = send(e, "GET", "/login", &[], Body::empty()).await;
    assert_eq!(page.status, StatusCode::OK);
    let lc = page.cookie("rostdav_login").expect("login cookie");
    let csrf = extract_csrf(&page.text());
    let r = post_form(
        e,
        "/login",
        &lc,
        &[("csrf", &csrf), ("user", user), ("password", PW)],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    assert_eq!(r.h("location"), "/files");
    r.cookie("rostdav_session").expect("session cookie")
}

async fn get(e: &Env, uri: &str, cookie: &str) -> Res {
    send(e, "GET", uri, &[("cookie", cookie)], Body::empty()).await
}

async fn page_csrf(e: &Env, cookie: &str) -> String {
    extract_csrf(&get(e, "/files", cookie).await.text())
}

#[tokio::test]
async fn files_page_requires_sign_in() {
    let e = env().await;
    let r = send(&e, "GET", "/files", &[], Body::empty()).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.h("location"), "/login");
    let r = get(
        &e,
        "/files",
        "rostdav_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let r = send(&e, "GET", "/", &[], Body::empty()).await;
    assert_eq!(r.h("location"), "/files");
}

#[tokio::test]
async fn sign_in_rules_and_cookie_flags() {
    let e = env().await;
    let page = send(&e, "GET", "/login", &[], Body::empty()).await;
    let lc = page.cookie("rostdav_login").expect("cookie");
    let csrf = extract_csrf(&page.text());

    // wrong password
    let r = post_form(
        &e,
        "/login",
        &lc,
        &[("csrf", &csrf), ("user", "anna"), ("password", "nope")],
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.cookie("rostdav_session").is_none());
    // forged form value
    let r = post_form(
        &e,
        "/login",
        &lc,
        &[("csrf", "forged"), ("user", "anna"), ("password", PW)],
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // form value with a different cookie
    let other = send(&e, "GET", "/login", &[], Body::empty()).await;
    let r = post_form(
        &e,
        "/login",
        &other.cookie("rostdav_login").expect("c"),
        &[("csrf", &csrf), ("user", "anna"), ("password", PW)],
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // foreign origin
    let r = send(
        &e,
        "POST",
        "/login",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &lc),
            ("origin", "http://evil.test"),
        ],
        Body::from(form(&[("csrf", &csrf), ("user", "anna"), ("password", PW)])),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // no origin and no referer
    let r = send(
        &e,
        "POST",
        "/login",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &lc),
        ],
        Body::from(form(&[("csrf", &csrf), ("user", "anna"), ("password", PW)])),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // success; cookie flags
    let o = origin();
    let r = send(
        &e,
        "POST",
        "/login",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &lc),
            ("origin", &o),
            ("x-forwarded-proto", "https"),
        ],
        Body::from(form(&[("csrf", &csrf), ("user", "anna"), ("password", PW)])),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let c = r
        .cookies()
        .into_iter()
        .find(|c| c.starts_with("rostdav_session="))
        .expect("session");
    for flag in ["HttpOnly", "SameSite=Lax", "Secure", "Path=/"] {
        assert!(c.contains(flag), "{c}");
    }
    assert!(!c.contains("anna"));
}

#[tokio::test]
async fn pages_carry_security_headers_and_no_inline_style() {
    let e = env().await;
    let c = login(&e, "anna").await;
    for r in [
        get(&e, "/files", &c).await,
        send(&e, "GET", "/login", &[], Body::empty()).await,
    ] {
        let csp = r.h("content-security-policy");
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert!(csp.contains("style-src 'self'"));
        assert!(!csp.contains("unsafe-inline"));
        assert_eq!(r.h("x-frame-options"), "DENY");
        assert_eq!(r.h("x-content-type-options"), "nosniff");
        assert_eq!(r.h("cache-control"), "no-store");
        let html = r.text();
        assert!(!html.contains("<style"), "inline style block");
        assert!(!html.contains(" style="), "inline style attribute");
        assert!(!html.contains("<script"));
    }
    let css = send(&e, "GET", "/static/app.css", &[], Body::empty()).await;
    assert_eq!(css.status, StatusCode::OK);
    assert!(css.h("content-type").starts_with("text/css"));
    assert_eq!(
        send(&e, "GET", "/static/nope.css", &[], Body::empty())
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

fn multipart(parts: &[(&str, Option<&str>, &str)]) -> (String, Vec<u8>) {
    let boundary = "XBOUNDARYX";
    let mut b = String::new();
    for (name, file, content) in parts {
        b.push_str(&format!("--{boundary}\r\n"));
        match file {
            Some(f) => b.push_str(&format!(
                "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\nContent-Type: text/plain\r\n\r\n"
            )),
            None => b.push_str(&format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n")),
        }
        b.push_str(content);
        b.push_str("\r\n");
    }
    b.push_str(&format!("--{boundary}--\r\n"));
    (
        format!("multipart/form-data; boundary={boundary}"),
        b.into_bytes(),
    )
}

async fn upload(e: &Env, cookie: &str, parts: &[(&str, Option<&str>, &str)]) -> Res {
    let (ct, body) = multipart(parts);
    let o = origin();
    send(
        e,
        "POST",
        "/action/upload",
        &[("content-type", &ct), ("cookie", cookie), ("origin", &o)],
        Body::from(body),
    )
    .await
}

#[tokio::test]
async fn browse_upload_download_delete() {
    let e = env().await;
    let c = login(&e, "anna").await;
    let csrf = page_csrf(&e, &c).await;

    let r = post_form(
        &e,
        "/action/mkdir",
        &c,
        &[("csrf", &csrf), ("dir", ""), ("name", "Docs")],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.h("location"), "/files");
    // duplicate
    let r = post_form(
        &e,
        "/action/mkdir",
        &c,
        &[("csrf", &csrf), ("dir", ""), ("name", "Docs")],
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT);

    let r = upload(
        &e,
        &c,
        &[
            ("csrf", None, &csrf),
            ("dir", None, "Docs"),
            ("file", Some("hello.txt"), "hello world"),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    assert_eq!(r.h("location"), "/files/Docs");

    let list = get(&e, "/files/Docs", &c).await;
    assert_eq!(list.status, StatusCode::OK);
    assert!(list.text().contains("hello.txt"));
    assert!(list.text().contains("11 B"));
    assert!(get(&e, "/files", &c).await.text().contains("Docs/"));

    let d = get(&e, "/download/Docs/hello.txt", &c).await;
    assert_eq!(d.status, StatusCode::OK);
    assert_eq!(d.body, b"hello world");
    assert!(d.h("content-disposition").starts_with("attachment"));
    assert_eq!(d.h("content-type"), "application/octet-stream");
    assert_eq!(
        get(&e, "/download/Docs/missing.txt", &c).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&e, "/download/..%2Fx", &c).await.status,
        StatusCode::BAD_REQUEST
    );

    // delete asks first
    let q = get(&e, "/action/delete?path=Docs%2Fhello.txt", &c).await;
    assert_eq!(q.status, StatusCode::OK);
    assert!(q.text().contains("Delete “hello.txt”?"));
    let r = post_form(
        &e,
        "/action/delete",
        &c,
        &[("csrf", &csrf), ("path", "Docs/hello.txt")],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.h("location"), "/files/Docs");
    assert_eq!(
        get(&e, "/download/Docs/hello.txt", &c).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn csrf_and_origin_are_required_for_every_post() {
    let e = env().await;
    let ca = login(&e, "anna").await;
    let cb = login(&e, "bob").await;
    let csrf_a = page_csrf(&e, &ca).await;
    let csrf_b = page_csrf(&e, &cb).await;
    assert_ne!(csrf_a, csrf_b);
    let o = origin();

    for (uri, fields) in [
        ("/action/mkdir", vec![("dir", ""), ("name", "X")]),
        ("/action/delete", vec![("path", "X")]),
        ("/logout", vec![]),
    ] {
        // missing, forged and another session's token
        for bad in [None, Some("forged"), Some(csrf_b.as_str())] {
            let mut f = fields.clone();
            if let Some(b) = bad {
                f.push(("csrf", b));
            }
            let r = post_form(&e, uri, &ca, &f).await;
            assert!(
                r.status == StatusCode::FORBIDDEN || r.status == StatusCode::UNPROCESSABLE_ENTITY,
                "{uri} {bad:?} -> {}",
                r.status
            );
        }
        // right token, foreign origin
        let mut f = fields.clone();
        f.push(("csrf", &csrf_a));
        let r = send(
            &e,
            "POST",
            uri,
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("cookie", &ca),
                ("origin", "http://evil.test"),
            ],
            Body::from(form(&f)),
        )
        .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{uri}");
        // right token, no cookie: back to login
        let r = send(
            &e,
            "POST",
            uri,
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("origin", &o),
            ],
            Body::from(form(&f)),
        )
        .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{uri}");
    }
    // nothing was created
    assert!(!get(&e, "/files", &ca).await.text().contains(">X/<"));

    // upload: missing and foreign token
    let r = upload(
        &e,
        &ca,
        &[
            ("csrf", None, &csrf_b),
            ("dir", None, ""),
            ("file", Some("a.txt"), "x"),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = upload(&e, &ca, &[("dir", None, ""), ("file", Some("a.txt"), "x")]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(
        get(&e, "/download/a.txt", &ca).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn users_only_see_their_own_files() {
    let e = env().await;
    let ca = login(&e, "anna").await;
    let cb = login(&e, "bob").await;
    let csrf = page_csrf(&e, &ca).await;
    upload(
        &e,
        &ca,
        &[
            ("csrf", None, &csrf),
            ("dir", None, ""),
            ("file", Some("secret.txt"), "s"),
        ],
    )
    .await;
    assert_eq!(
        get(&e, "/download/secret.txt", &ca).await.status,
        StatusCode::OK
    );
    assert_eq!(
        get(&e, "/download/secret.txt", &cb).await.status,
        StatusCode::NOT_FOUND
    );
    assert!(!get(&e, "/files", &cb).await.text().contains("secret.txt"));
}

#[tokio::test]
async fn names_are_escaped_in_html() {
    let e = env().await;
    let c = login(&e, "anna").await;
    let csrf = page_csrf(&e, &c).await;
    let evil = "<img src=x onerror=alert(1)>";
    let r = post_form(
        &e,
        "/action/mkdir",
        &c,
        &[("csrf", &csrf), ("dir", ""), ("name", evil)],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let html = get(&e, "/files", &c).await.text();
    assert!(!html.contains(evil));
    assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    // and inside the folder page, in the breadcrumbs
    let uri = format!(
        "/files/{}",
        percent_encoding::utf8_percent_encode(evil, percent_encoding::NON_ALPHANUMERIC)
    );
    let html = get(&e, &uri, &c).await.text();
    assert!(!html.contains(evil));
}

#[tokio::test]
async fn sign_out_ends_the_session_and_cookie_is_not_accepted_elsewhere() {
    let e = env().await;
    let c = login(&e, "anna").await;
    let csrf = page_csrf(&e, &c).await;

    // the browser cookie does not authenticate WebDAV, OCS or the status of other APIs
    for (method, uri) in [
        ("PROPFIND", "/remote.php/dav/files/anna/"),
        ("GET", "/ocs/v2.php/cloud/user?format=json"),
    ] {
        let r = send(
            &e,
            method,
            uri,
            &[("cookie", &c), ("ocs-apirequest", "true")],
            Body::empty(),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{uri}");
    }

    let r = post_form(&e, "/logout", &c, &[("csrf", &csrf)]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.h("location"), "/login");
    assert!(
        r.cookies()
            .iter()
            .any(|c| c.starts_with("rostdav_session=;") && c.contains("Max-Age=0"))
    );
    let r = get(&e, "/files", &c).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.h("location"), "/login");
}

#[tokio::test]
async fn app_password_does_not_open_a_browser_session() {
    let e = env().await;
    let page = send(&e, "GET", "/login", &[], Body::empty()).await;
    let lc = page.cookie("rostdav_login").expect("cookie");
    let csrf = extract_csrf(&page.text());
    let r = post_form(
        &e,
        "/login",
        &lc,
        &[
            ("csrf", &csrf),
            ("user", "anna"),
            ("password", "x".repeat(72).as_str()),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn trash_page_restore_and_purge() {
    let e = env().await;
    let c = login(&e, "anna").await;
    let csrf = page_csrf(&e, &c).await;
    for n in ["a.txt", "b.txt"] {
        upload(
            &e,
            &c,
            &[
                ("csrf", None, &csrf),
                ("dir", None, ""),
                ("file", Some(n), "x"),
            ],
        )
        .await;
        let r = post_form(&e, "/action/delete", &c, &[("csrf", &csrf), ("path", n)]).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER);
    }
    let t = get(&e, "/trash", &c).await;
    assert_eq!(t.status, StatusCode::OK);
    let html = t.text();
    assert!(html.contains("a.txt") && html.contains("b.txt"));
    let entry = |name: &str| {
        let i = html
            .find(&format!("name=\"entry\" value=\"{name}.d"))
            .expect("entry")
            + 20;
        html[i..].split('"').next().expect("v").to_owned()
    };

    // restore
    let r = post_form(
        &e,
        "/trash/restore",
        &c,
        &[("csrf", &csrf), ("entry", &entry("a.txt"))],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(get(&e, "/download/a.txt", &c).await.status, StatusCode::OK);

    // permanent delete asks first, needs csrf
    assert!(
        get(&e, "/trash/delete?entry=x", &c)
            .await
            .text()
            .contains("cannot be undone")
    );
    let r = post_form(
        &e,
        "/trash/delete",
        &c,
        &[("csrf", "forged"), ("entry", &entry("b.txt"))],
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = post_form(
        &e,
        "/trash/delete",
        &c,
        &[("csrf", &csrf), ("entry", &entry("b.txt"))],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(
        get(&e, "/trash", &c)
            .await
            .text()
            .contains("The trash is empty.")
    );

    // other users have their own trash
    let cb = login(&e, "bob").await;
    assert!(
        get(&e, "/trash", &cb)
            .await
            .text()
            .contains("The trash is empty.")
    );
    let r = post_form(&e, "/trash/empty", &c, &[("csrf", "forged")]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn devices_page_create_revoke_and_sessions() {
    let e = env().await;
    let c = login(&e, "anna").await;
    let c2 = login(&e, "anna").await;
    let csrf = page_csrf(&e, &c).await;

    let r = post_form(
        &e,
        "/devices/create",
        &c,
        &[("csrf", "forged"), ("name", "phone")],
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = post_form(
        &e,
        "/devices/create",
        &c,
        &[("csrf", &csrf), ("name", "phone")],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let html = r.text();
    assert!(html.contains("shown only once"));
    let i = html.find("<code>").expect("token") + 6;
    let token = html[i..].split('<').next().expect("t").to_owned();
    assert_eq!(token.len(), 72);

    // the token is shown once only, and it works for WebDAV
    let list = get(&e, "/devices", &c).await.text();
    assert!(list.contains("phone") && !list.contains(&token));
    let basic = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(format!("anna:{token}"))
    };
    let dav = |auth: String| {
        let e = &e;
        async move {
            send(
                e,
                "PROPFIND",
                "/remote.php/dav/files/anna/",
                &[("authorization", &auth), ("depth", "0")],
                Body::empty(),
            )
            .await
            .status
        }
    };
    assert_eq!(
        dav(format!("Basic {basic}")).await,
        StatusCode::MULTI_STATUS
    );

    // revoke
    let id = list
        .split("name=\"id\" value=\"")
        .nth(1)
        .expect("id")
        .split('"')
        .next()
        .expect("v")
        .to_owned();
    let r = post_form(&e, "/devices/revoke", &c, &[("csrf", &csrf), ("id", &id)]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(
        dav(format!("Basic {basic}")).await,
        StatusCode::UNAUTHORIZED
    );

    // other browsers
    assert_eq!(get(&e, "/files", &c2).await.status, StatusCode::OK);
    let r = post_form(&e, "/devices/sign-out-others", &c, &[("csrf", &csrf)]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(get(&e, "/files", &c2).await.status, StatusCode::SEE_OTHER);
    assert_eq!(get(&e, "/files", &c).await.status, StatusCode::OK);
}

#[tokio::test]
async fn settings_theme_address_and_storage() {
    let e = env().await;
    let c = login(&e, "anna").await;
    let csrf = page_csrf(&e, &c).await;
    upload(
        &e,
        &c,
        &[
            ("csrf", None, &csrf),
            ("dir", None, ""),
            ("file", Some("a.txt"), "hello"),
        ],
    )
    .await;

    let s = get(&e, "/settings", &c).await;
    assert_eq!(s.status, StatusCode::OK);
    let html = s.text();
    assert!(html.contains("http://files.test/remote.php/dav/files/anna/"));
    assert!(html.contains("5 B"));
    assert!(!html.contains("data-theme"));

    assert_eq!(
        post_form(
            &e,
            "/settings/theme",
            &c,
            &[("csrf", "forged"), ("theme", "dark")]
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post_form(
            &e,
            "/settings/theme",
            &c,
            &[("csrf", &csrf), ("theme", "neon")]
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    let r = post_form(
        &e,
        "/settings/theme",
        &c,
        &[("csrf", &csrf), ("theme", "dark")],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(
        get(&e, "/files", &c)
            .await
            .text()
            .contains("data-theme=\"dark\"")
    );

    // the preference is per user
    let cb = login(&e, "bob").await;
    assert!(!get(&e, "/files", &cb).await.text().contains("data-theme"));
}
