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
    state: rostdav_app::AppState,
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
    state.add_user("root", PW, true).await.expect("admin");
    Env {
        app: rostdav::http::router_with(
            state.clone(),
            &rostdav::http::HttpOptions::from_config(&cfg),
        ),
        state,
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
        assert!(csp.contains("script-src 'self'"));
        assert!(!csp.contains("unsafe-inline"));
        assert_eq!(r.h("x-frame-options"), "DENY");
        assert_eq!(r.h("x-content-type-options"), "nosniff");
        assert_eq!(r.h("cache-control"), "no-store");
        // `no-referrer` would make browsers send `Origin: null` on form posts
        assert_eq!(r.h("referrer-policy"), "same-origin");
        let html = r.text();
        assert!(!html.contains("<style"), "inline style block");
        assert!(!html.contains(" style="), "inline style attribute");
        assert!(!html.contains("<script>"), "inline script");
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
    assert!(
        get(&e, "/files", &c)
            .await
            .text()
            .contains("<span>Docs</span>")
    );

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
    assert!(
        !get(&e, "/files", &ca)
            .await
            .text()
            .contains("<span>X</span>")
    );

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

/// anna shares `Pub` (with `f.txt` and `sub/g.txt`) as a link; returns the token.
async fn make_link(e: &Env, perms: i64, password: Option<&str>) -> String {
    let anna = e
        .state
        .authenticate("anna", PW, "192.0.2.9".parse().expect("ip"))
        .await
        .expect("auth");
    let c = login(e, "anna").await;
    let csrf = page_csrf(e, &c).await;
    post_form(
        e,
        "/action/mkdir",
        &c,
        &[("csrf", &csrf), ("dir", ""), ("name", "Pub")],
    )
    .await;
    post_form(
        e,
        "/action/mkdir",
        &c,
        &[("csrf", &csrf), ("dir", "Pub"), ("name", "sub")],
    )
    .await;
    upload(
        e,
        &c,
        &[
            ("csrf", None, &csrf),
            ("dir", None, "Pub"),
            ("file", Some("f.txt"), "file one"),
        ],
    )
    .await;
    upload(
        e,
        &c,
        &[
            ("csrf", None, &csrf),
            ("dir", None, "Pub/sub"),
            ("file", Some("g.txt"), "file two"),
        ],
    )
    .await;
    let v = e
        .state
        .share_create(
            &anna,
            rostdav_app::ShareCreate {
                path: Some(rostdav_core::LogicalPath::from_url_path("Pub").expect("path")),
                share_type: 3,
                permissions: Some(perms),
                password: password.map(str::to_owned),
                ..Default::default()
            },
        )
        .await
        .expect("share");
    v.share.token.expect("token")
}

#[tokio::test]
async fn public_link_page_lists_and_downloads() {
    let e = env().await;
    let t = make_link(&e, 1, None).await;
    let r = send(&e, "GET", &format!("/s/{t}"), &[], Body::empty()).await;
    assert_eq!(r.status, StatusCode::OK);
    let html = r.text();
    assert!(html.contains("f.txt") && html.contains("sub/"));
    assert!(
        !html.contains("type=\"file\""),
        "read-only link offers no upload"
    );
    assert!(
        r.h("content-security-policy")
            .contains("default-src 'none'")
    );
    let r = send(&e, "GET", &format!("/s/{t}?path=sub"), &[], Body::empty()).await;
    assert!(r.text().contains("g.txt"));
    let d = send(
        &e,
        "GET",
        &format!("/s/{t}/dl?path=sub%2Fg.txt"),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(d.status, StatusCode::OK);
    assert_eq!(d.body, b"file two");
    assert!(d.h("content-disposition").starts_with("attachment"));
    // no escape from the shared folder, no sign-in needed elsewhere
    for uri in [
        format!("/s/{t}?path=..%2Fsecret"),
        format!("/s/{t}/dl?path=..%2F..%2Fx"),
        format!("/s/{t}/dl?path=nope"),
    ] {
        let r = send(&e, "GET", &uri, &[], Body::empty()).await;
        assert!(
            r.status == StatusCode::BAD_REQUEST || r.status == StatusCode::NOT_FOUND,
            "{uri} {}",
            r.status
        );
    }
    // unknown and malformed tokens look alike
    for bad in ["aaaaaaaaaaaaaaa", "x", "a%2Fb"] {
        assert_eq!(
            send(&e, "GET", &format!("/s/{bad}"), &[], Body::empty())
                .await
                .status,
            StatusCode::NOT_FOUND
        );
    }
    // the cookie-less visitor cannot reach account pages
    assert_eq!(
        send(&e, "GET", "/files", &[], Body::empty()).await.status,
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn public_link_password_gate() {
    let e = env().await;
    let t = make_link(&e, 1, Some("open-sesame-please")).await;
    let r = send(&e, "GET", &format!("/s/{t}"), &[], Body::empty()).await;
    assert!(r.text().contains("Password required"));
    assert!(!r.text().contains("f.txt"));
    // downloads without the ticket bounce to the form
    let d = send(
        &e,
        "GET",
        &format!("/s/{t}/dl?path=f.txt"),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(d.status, StatusCode::SEE_OTHER);

    let lc = r.cookie("rostdav_login").expect("csrf cookie");
    let csrf = extract_csrf(&r.text());
    let uri = format!("/s/{t}/unlock");
    let bad = post_form(&e, &uri, &lc, &[("csrf", &csrf), ("password", "wrong")]).await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert!(bad.cookie("rostdav_link").is_none());
    assert_eq!(
        post_form(
            &e,
            &uri,
            &lc,
            &[("csrf", "forged"), ("password", "open-sesame-please")]
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let ok = post_form(
        &e,
        &uri,
        &lc,
        &[("csrf", &csrf), ("password", "open-sesame-please")],
    )
    .await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER);
    let c = ok
        .cookies()
        .into_iter()
        .find(|c| c.starts_with("rostdav_link="))
        .expect("ticket");
    assert!(
        c.contains("HttpOnly") && c.contains(&format!("Path=/s/{t}")),
        "{c}"
    );
    let ticket = c.split(';').next().expect("pair").to_owned();

    let r = send(
        &e,
        "GET",
        &format!("/s/{t}"),
        &[("cookie", &ticket)],
        Body::empty(),
    )
    .await;
    assert!(r.text().contains("f.txt"));
    let d = send(
        &e,
        "GET",
        &format!("/s/{t}/dl?path=f.txt"),
        &[("cookie", &ticket)],
        Body::empty(),
    )
    .await;
    assert_eq!(d.body, b"file one");

    // a ticket is bound to its link and cannot be forged
    let other = ticket.replace(&t, "AAAAAAAAAAAA");
    let r = send(
        &e,
        "GET",
        &format!("/s/{t}"),
        &[("cookie", &other)],
        Body::empty(),
    )
    .await;
    assert!(r.text().contains("Password required"));
    let forged = format!("rostdav_link={t}_9999999999.deadbeef");
    let r = send(
        &e,
        "GET",
        &format!("/s/{t}"),
        &[("cookie", &forged)],
        Body::empty(),
    )
    .await;
    assert!(r.text().contains("Password required"));
}

#[tokio::test]
async fn public_link_upload_rules() {
    let e = env().await;
    let t = make_link(&e, 5, None).await; // read + create
    let page = send(&e, "GET", &format!("/s/{t}"), &[], Body::empty()).await;
    assert!(page.text().contains("type=\"file\""));
    let lc = page.cookie("rostdav_login").expect("cookie");
    let csrf = extract_csrf(&page.text());
    let (ct, body) = multipart(&[
        ("csrf", None, &csrf),
        ("dir", None, ""),
        ("file", Some("new.txt"), "from visitor"),
    ]);
    let o = origin();
    let up = |body: Vec<u8>, cookie: String, origin: String| {
        let (e, ct, uri) = (&e, ct.clone(), format!("/s/{t}/upload"));
        async move {
            send(
                e,
                "POST",
                &uri,
                &[
                    ("content-type", &ct),
                    ("cookie", &cookie),
                    ("origin", &origin),
                ],
                Body::from(body),
            )
            .await
        }
    };
    assert_eq!(
        up(body.clone(), lc.clone(), "http://evil.test".into())
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let (_, forged) = multipart(&[
        ("csrf", None, "forged"),
        ("dir", None, ""),
        ("file", Some("new.txt"), "x"),
    ]);
    assert_eq!(
        up(forged, lc.clone(), o.clone()).await.status,
        StatusCode::FORBIDDEN
    );
    let r = up(body.clone(), lc.clone(), o.clone()).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    let d = send(
        &e,
        "GET",
        &format!("/s/{t}/dl?path=new.txt"),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(d.body, b"from visitor");
    // existing files are never replaced
    let (_, again) = multipart(&[
        ("csrf", None, &csrf),
        ("dir", None, ""),
        ("file", Some("f.txt"), "overwrite!"),
    ]);
    let r = up(again, lc.clone(), o.clone()).await;
    assert_ne!(r.status, StatusCode::SEE_OTHER);
    let d = send(
        &e,
        "GET",
        &format!("/s/{t}/dl?path=f.txt"),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(d.body, b"file one");

    // a read-only link refuses uploads
    let ro = {
        let anna = e
            .state
            .authenticate("anna", PW, "192.0.2.9".parse().expect("ip"))
            .await
            .expect("auth");
        let v = e
            .state
            .share_create(
                &anna,
                rostdav_app::ShareCreate {
                    path: Some(rostdav_core::LogicalPath::from_url_path("Pub/sub").expect("p")),
                    share_type: 3,
                    permissions: Some(1),
                    ..Default::default()
                },
            )
            .await
            .expect("share");
        v.share.token.expect("t")
    };
    let uri = format!("/s/{ro}/upload");
    let (_, body) = multipart(&[
        ("csrf", None, &csrf),
        ("dir", None, ""),
        ("file", Some("x.txt"), "x"),
    ]);
    let r = send(
        &e,
        "POST",
        &uri,
        &[("content-type", &ct), ("cookie", &lc), ("origin", &o)],
        Body::from(body),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let d = send(
        &e,
        "GET",
        &format!("/s/{ro}/dl?path=x.txt"),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(d.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn share_dialog_user_and_link() {
    let e = env().await;
    let ca = login(&e, "anna").await;
    let cb = login(&e, "bob").await;
    let csrf = page_csrf(&e, &ca).await;
    post_form(
        &e,
        "/action/mkdir",
        &ca,
        &[("csrf", &csrf), ("dir", ""), ("name", "Team")],
    )
    .await;
    upload(
        &e,
        &ca,
        &[
            ("csrf", None, &csrf),
            ("dir", None, "Team"),
            ("file", Some("n.txt"), "notes"),
        ],
    )
    .await;

    assert!(
        get(&e, "/share?path=Team", &ca)
            .await
            .text()
            .contains("Not shared yet.")
    );
    assert!(
        get(&e, "/files/Team", &ca)
            .await
            .text()
            .contains("/share?path=Team")
    );

    // csrf, unknown user
    let r = post_form(
        &e,
        "/share/user",
        &ca,
        &[
            ("csrf", "forged"),
            ("path", "Team"),
            ("user", "bob"),
            ("perms", "1"),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = post_form(
        &e,
        "/share/user",
        &ca,
        &[
            ("csrf", &csrf),
            ("path", "Team"),
            ("user", "nobody"),
            ("perms", "1"),
        ],
    )
    .await;
    assert!(r.status.is_client_error(), "{}", r.status);

    let r = post_form(
        &e,
        "/share/user",
        &ca,
        &[
            ("csrf", &csrf),
            ("path", "Team"),
            ("user", "bob"),
            ("perms", "1"),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    let page = get(&e, "/share?path=Team", &ca).await.text();
    assert!(page.contains("bob") && page.contains("View only"));
    // bob sees a read-only mount and has no Share button for it
    let fb = get(&e, "/files", &cb).await.text();
    assert!(fb.contains("<span>Team</span>"));
    assert!(!fb.contains("/share?path=Team"));
    assert_eq!(
        get(&e, "/download/Team/n.txt", &cb).await.status,
        StatusCode::OK
    );
    let csrf_b = page_csrf(&e, &cb).await;
    let r = upload(
        &e,
        &cb,
        &[
            ("csrf", None, &csrf_b),
            ("dir", None, "Team"),
            ("file", Some("x.txt"), "x"),
        ],
    )
    .await;
    assert_ne!(r.status, StatusCode::SEE_OTHER);
    // bob cannot manage anna's shares
    let r = get(&e, "/share?path=Team", &cb).await;
    assert!(r.status.is_client_error());

    // link with password and expiry
    let r = post_form(
        &e,
        "/share/link",
        &ca,
        &[
            ("csrf", &csrf),
            ("path", "Team"),
            ("perms", "1"),
            ("password", "open-sesame-please"),
            ("expire", "2999-01-01"),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    let page = get(&e, "/share?path=Team", &ca).await.text();
    assert!(page.contains("(password)") && page.contains("http://files.test/s/"));
    let i = page.find("http://files.test/s/").expect("url") + 20;
    let token = page[i..].split('<').next().expect("t").to_owned();
    assert!(
        send(&e, "GET", &format!("/s/{token}"), &[], Body::empty())
            .await
            .text()
            .contains("Password required")
    );
    // bad expiry date
    let r = post_form(
        &e,
        "/share/link",
        &ca,
        &[
            ("csrf", &csrf),
            ("path", "Team"),
            ("perms", "1"),
            ("password", ""),
            ("expire", "yesterday"),
        ],
    )
    .await;
    assert!(r.status.is_client_error());

    // stop sharing
    let page = get(&e, "/share?path=Team", &ca).await.text();
    let ids: Vec<String> = page
        .split("name=\"id\" value=\"")
        .skip(1)
        .map(|s| s.split('"').next().expect("id").to_owned())
        .collect();
    assert_eq!(ids.len(), 2);
    for id in &ids {
        let r = post_form(
            &e,
            "/share/delete",
            &ca,
            &[("csrf", &csrf), ("path", "Team"), ("id", id)],
        )
        .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER);
    }
    assert!(
        get(&e, "/share?path=Team", &ca)
            .await
            .text()
            .contains("Not shared yet.")
    );
    assert_eq!(
        get(&e, "/download/Team/n.txt", &cb).await.status,
        StatusCode::NOT_FOUND
    );
    // another user's share id cannot be removed
    let r = post_form(
        &e,
        "/share/delete",
        &cb,
        &[("csrf", &csrf_b), ("path", "Team"), ("id", &ids[0])],
    )
    .await;
    assert_ne!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn versions_panel_restore_and_delete() {
    let e = env().await;
    let c = login(&e, "anna").await;
    let csrf = page_csrf(&e, &c).await;
    for body in ["one", "second!", "third!!!"] {
        upload(
            &e,
            &c,
            &[
                ("csrf", None, &csrf),
                ("dir", None, ""),
                ("file", Some("doc.txt"), body),
            ],
        )
        .await;
        // distinct mtimes: versions are named by the time of the archived content
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    }
    let page = get(&e, "/versions?path=doc.txt", &c).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let html = page.text();
    assert!(html.contains("Current"));
    let times: Vec<String> = html
        .split("name=\"time\" value=\"")
        .skip(1)
        .step_by(2)
        .map(|s| s.split('"').next().expect("t").to_owned())
        .collect();
    assert_eq!(times.len(), 2, "{html}");

    // csrf
    let r = post_form(
        &e,
        "/versions/restore",
        &c,
        &[("csrf", "forged"), ("path", "doc.txt"), ("time", &times[0])],
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // restore the oldest version
    let oldest = times
        .iter()
        .min_by_key(|t| t.parse::<i64>().unwrap_or(0))
        .expect("t");
    let r = post_form(
        &e,
        "/versions/restore",
        &c,
        &[("csrf", &csrf), ("path", "doc.txt"), ("time", oldest)],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    assert_eq!(get(&e, "/download/doc.txt", &c).await.body, b"one");
    // delete an archived version
    let html = get(&e, "/versions?path=doc.txt", &c).await.text();
    let t = html
        .split("name=\"time\" value=\"")
        .nth(1)
        .expect("t")
        .split('"')
        .next()
        .expect("v")
        .to_owned();
    let r = post_form(
        &e,
        "/versions/delete",
        &c,
        &[("csrf", &csrf), ("path", "doc.txt"), ("time", &t)],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());

    // others cannot see them; folders have none
    let cb = login(&e, "bob").await;
    assert!(
        get(&e, "/versions?path=doc.txt", &cb)
            .await
            .status
            .is_client_error()
    );
    post_form(
        &e,
        "/action/mkdir",
        &c,
        &[("csrf", &csrf), ("dir", ""), ("name", "D")],
    )
    .await;
    assert!(
        get(&e, "/versions?path=D", &c)
            .await
            .status
            .is_client_error()
    );
}

#[tokio::test]
async fn files_filter_and_details() {
    let e = env().await;
    let c = login(&e, "anna").await;
    let csrf = page_csrf(&e, &c).await;
    for n in ["Report.txt", "photo.jpg"] {
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
    }
    let html = get(&e, "/files", &c).await.text();
    assert!(html.contains("Report.txt") && html.contains("photo.jpg"));
    assert!(!html.contains("File ID"), "details only for a selection");
    let html = get(&e, "/files?sel=Report.txt", &c).await.text();
    assert!(html.contains("File ID") && html.contains("ETag") && html.contains("Not shared yet."));
    assert!(html.contains("aria-current=\"true\""));
    assert!(html.contains("/download/Report.txt") && html.contains("/versions?path=Report.txt"));
    let html = get(&e, "/files?q=REPORT", &c).await.text();
    assert!(html.contains("Report.txt") && !html.contains("photo.jpg"));
    let html = get(&e, "/files?q=%3Cscript%3E", &c).await.text();
    assert!(!html.contains("<script>") && html.contains("&lt;script&gt;"));
}

async fn api(
    e: &Env,
    method: &str,
    uri: &str,
    cookie: &str,
    csrf: Option<&str>,
    body: Vec<u8>,
) -> Res {
    let o = origin();
    let mut h = vec![
        ("cookie", cookie),
        ("origin", o.as_str()),
        ("content-type", "application/octet-stream"),
    ];
    if let Some(c) = csrf {
        h.push(("x-csrf-token", c));
    }
    send(e, method, uri, &h, Body::from(body)).await
}

#[tokio::test]
async fn large_plain_upload_is_not_cut_at_the_framework_default() {
    let e = env().await;
    let c = login(&e, "anna").await;
    let csrf = page_csrf(&e, &c).await;
    let big = "x".repeat(3 * 1024 * 1024);
    let r = upload(
        &e,
        &c,
        &[
            ("csrf", None, &csrf),
            ("dir", None, ""),
            ("file", Some("big.bin"), &big),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    assert_eq!(get(&e, "/download/big.bin", &c).await.body.len(), big.len());
}

#[tokio::test]
async fn chunked_browser_upload_resume_and_rules() {
    let e = env().await;
    let c = login(&e, "anna").await;
    let cb = login(&e, "bob").await;
    let csrf = page_csrf(&e, &c).await;
    let csrf_b = page_csrf(&e, &cb).await;
    let up = "/web/upload/w-abc-11";

    // script is served with the right type, and the page loads it
    let js = send(&e, "GET", "/static/upload.js", &[], Body::empty()).await;
    assert!(js.h("content-type").starts_with("text/javascript"));
    assert!(!js.text().contains("innerHTML"));
    assert!(
        get(&e, "/files", &c)
            .await
            .text()
            .contains("src=\"/static/upload.js\"")
    );

    // unknown transfer
    assert_eq!(get(&e, up, &c).await.status, StatusCode::NOT_FOUND);
    // every write needs the header token and the same origin
    assert_eq!(
        api(&e, "POST", up, &c, None, vec![]).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api(&e, "POST", up, &c, Some("forged"), vec![]).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api(&e, "POST", up, &c, Some(&csrf_b), vec![]).await.status,
        StatusCode::FORBIDDEN
    );
    let r = send(
        &e,
        "POST",
        up,
        &[
            ("cookie", &c),
            ("origin", "http://evil.test"),
            ("x-csrf-token", &csrf),
        ],
        Body::empty(),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(get(&e, up, &c).await.status, StatusCode::NOT_FOUND);

    assert_eq!(
        api(&e, "POST", up, &c, Some(&csrf), vec![]).await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        api(
            &e,
            "PUT",
            &format!("{up}/000000"),
            &c,
            Some(&csrf),
            b"hello ".to_vec()
        )
        .await
        .status,
        StatusCode::OK
    );

    // resume: the server reports what it has
    let l = get(&e, up, &c).await;
    assert_eq!(l.status, StatusCode::OK);
    let j: serde_json::Value = serde_json::from_slice(&l.body).expect("json");
    assert_eq!(j["chunks"][0]["name"], "000000");
    assert_eq!(j["chunks"][0]["size"], 6);
    // another user neither sees nor changes the transfer
    assert_eq!(get(&e, up, &cb).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        api(
            &e,
            "PUT",
            &format!("{up}/000001"),
            &cb,
            Some(&csrf_b),
            b"x".to_vec()
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );

    assert_eq!(
        api(
            &e,
            "PUT",
            &format!("{up}/000001"),
            &c,
            Some(&csrf),
            b"world".to_vec()
        )
        .await
        .status,
        StatusCode::OK
    );
    assert_eq!(
        api(
            &e,
            "PUT",
            &format!("{up}/bad%2Fname"),
            &c,
            Some(&csrf),
            b"x".to_vec()
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );

    // finish: wrong total keeps the session, right total assembles
    let fin = |total: u64, name: &str| {
        serde_json::to_vec(&serde_json::json!({"dir": "", "name": name, "total": total}))
            .expect("json")
    };
    let finish = format!("{up}/finish");
    let jh = |body: Vec<u8>, tok: String| {
        let (e, c, f) = (&e, c.clone(), finish.clone());
        async move {
            send(
                e,
                "POST",
                &f,
                &[
                    ("cookie", &c),
                    ("origin", &origin()),
                    ("x-csrf-token", &tok),
                    ("content-type", "application/json"),
                ],
                Body::from(body),
            )
            .await
        }
    };
    assert_eq!(
        jh(fin(99, "r.txt"), csrf.clone()).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        jh(fin(11, "../r.txt"), csrf.clone()).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        jh(fin(11, "r.txt"), "forged".into()).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        jh(fin(11, "r.txt"), csrf.clone()).await.status,
        StatusCode::OK
    );
    assert_eq!(get(&e, "/download/r.txt", &c).await.body, b"hello world");
    assert_eq!(
        get(&e, up, &c).await.status,
        StatusCode::NOT_FOUND,
        "session removed after assembly"
    );

    // abort
    assert_eq!(
        api(&e, "POST", "/web/upload/w-x-1", &c, Some(&csrf), vec![])
            .await
            .status,
        StatusCode::CREATED
    );
    assert_eq!(
        api(&e, "DELETE", "/web/upload/w-x-1", &c, Some(&csrf), vec![])
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        get(&e, "/web/upload/w-x-1", &c).await.status,
        StatusCode::NOT_FOUND
    );

    // no session, no API
    let r = send(&e, "GET", up, &[], Body::empty()).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn admin_pages_are_for_administrators_only() {
    let e = env().await;
    let ca = login(&e, "anna").await;
    let csrf = page_csrf(&e, &ca).await;
    let root = login(&e, "root").await;

    // navigation entry only for admins
    assert!(
        !get(&e, "/files", &ca)
            .await
            .text()
            .contains("Administration")
    );
    assert!(
        get(&e, "/files", &root)
            .await
            .text()
            .contains("Administration")
    );
    assert!(get(&e, "/files", &root).await.text().contains(">Settings<"));

    for uri in [
        "/admin/users",
        "/admin/users/manage?name=bob",
        "/admin/users/delete?name=bob",
        "/admin/events",
        "/admin/status",
        "/admin/server",
    ] {
        assert_eq!(
            get(&e, uri, &ca).await.status,
            StatusCode::FORBIDDEN,
            "{uri}"
        );
        assert_eq!(
            send(&e, "GET", uri, &[], Body::empty()).await.status,
            StatusCode::SEE_OTHER,
            "{uri}"
        );
        assert_eq!(get(&e, uri, &root).await.status, StatusCode::OK, "{uri}");
    }
    // posts: even with a valid token of the normal user
    for (uri, fields) in [
        (
            "/admin/users/create",
            vec![("name", "evil"), ("password", PW), ("admin", "1")],
        ),
        ("/admin/users/role", vec![("name", "anna"), ("admin", "1")]),
        (
            "/admin/users/disabled",
            vec![("name", "bob"), ("disabled", "1")],
        ),
        ("/admin/users/quota", vec![("name", "bob"), ("quota", "1")]),
        (
            "/admin/users/password",
            vec![("name", "bob"), ("password", "hacked-hacked-hacked")],
        ),
        (
            "/admin/users/delete",
            vec![("name", "bob"), ("mode", "delete")],
        ),
        ("/admin/status/check", vec![]),
    ] {
        let mut f = fields.clone();
        f.push(("csrf", &csrf));
        assert_eq!(
            post_form(&e, uri, &ca, &f).await.status,
            StatusCode::FORBIDDEN,
            "{uri}"
        );
    }
    // nothing changed: bob still signs in with the old password, anna is no admin
    login(&e, "bob").await;
    assert_eq!(
        get(&e, "/admin/users", &ca).await.status,
        StatusCode::FORBIDDEN
    );
    // csrf for admins too
    let r = post_form(
        &e,
        "/admin/users/create",
        &root,
        &[("csrf", "forged"), ("name", "x"), ("password", PW)],
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_manages_users() {
    let e = env().await;
    let root = login(&e, "root").await;
    let csrf = page_csrf(&e, &root).await;

    // create; duplicates and weak passwords are refused
    let r = post_form(
        &e,
        "/admin/users/create",
        &root,
        &[("csrf", &csrf), ("name", "carl"), ("password", PW)],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    let list = get(&e, "/admin/users", &root).await.text();
    assert!(list.contains("carl") && list.contains("Active"));
    assert!(
        post_form(
            &e,
            "/admin/users/create",
            &root,
            &[("csrf", &csrf), ("name", "carl"), ("password", PW)]
        )
        .await
        .status
        .is_client_error()
    );
    assert!(
        post_form(
            &e,
            "/admin/users/create",
            &root,
            &[("csrf", &csrf), ("name", "dave"), ("password", "short")]
        )
        .await
        .status
        .is_client_error()
    );
    login(&e, "carl").await;

    // disabling ends the user's open session at once
    let cb = login(&e, "bob").await;
    assert_eq!(get(&e, "/files", &cb).await.status, StatusCode::OK);
    let r = post_form(
        &e,
        "/admin/users/disabled",
        &root,
        &[("csrf", &csrf), ("name", "bob"), ("disabled", "1")],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(get(&e, "/files", &cb).await.status, StatusCode::SEE_OTHER);
    assert!(
        get(&e, "/admin/users/manage?name=bob", &root)
            .await
            .text()
            .contains("Allow sign-in again")
    );
    post_form(
        &e,
        "/admin/users/disabled",
        &root,
        &[("csrf", &csrf), ("name", "bob"), ("disabled", "0")],
    )
    .await;
    login(&e, "bob").await;

    // quota
    let r = post_form(
        &e,
        "/admin/users/quota",
        &root,
        &[("csrf", &csrf), ("name", "carl"), ("quota", "1M")],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(
        get(&e, "/admin/users", &root)
            .await
            .text()
            .contains("1.0 MB")
    );
    assert!(
        post_form(
            &e,
            "/admin/users/quota",
            &root,
            &[("csrf", &csrf), ("name", "carl"), ("quota", "lots")]
        )
        .await
        .status
        .is_client_error()
    );
    assert!(
        post_form(
            &e,
            "/admin/users/quota",
            &root,
            &[("csrf", &csrf), ("name", "nobody"), ("quota", "1M")]
        )
        .await
        .status
        .is_client_error()
    );

    // password reset
    let r = post_form(
        &e,
        "/admin/users/password",
        &root,
        &[
            ("csrf", &csrf),
            ("name", "carl"),
            ("password", "brand-new-password-1"),
            ("revoke", "1"),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    let page = send(&e, "GET", "/login", &[], Body::empty()).await;
    let (lc, tok) = (
        page.cookie("rostdav_login").expect("c"),
        extract_csrf(&page.text()),
    );
    let ok = post_form(
        &e,
        "/login",
        &lc,
        &[
            ("csrf", &tok),
            ("user", "carl"),
            ("password", "brand-new-password-1"),
        ],
    )
    .await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER);
    let old = post_form(
        &e,
        "/login",
        &lc,
        &[("csrf", &tok), ("user", "carl"), ("password", PW)],
    )
    .await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED);

    // the last administrator and yourself are protected
    let r = post_form(
        &e,
        "/admin/users/role",
        &root,
        &[("csrf", &csrf), ("name", "root"), ("admin", "0")],
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = post_form(
        &e,
        "/admin/users/delete",
        &root,
        &[("csrf", &csrf), ("name", "root"), ("mode", "delete")],
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = post_form(
        &e,
        "/admin/users/disabled",
        &root,
        &[("csrf", &csrf), ("name", "root"), ("disabled", "1")],
    )
    .await;
    assert!(r.status.is_client_error(), "{}", r.status);
    assert_eq!(get(&e, "/files", &root).await.status, StatusCode::OK);
}

#[tokio::test]
async fn admin_deletes_user_with_transfer() {
    let e = env().await;
    let root = login(&e, "root").await;
    let csrf = page_csrf(&e, &root).await;
    let ca = login(&e, "anna").await;
    let csrf_a = page_csrf(&e, &ca).await;
    upload(
        &e,
        &ca,
        &[
            ("csrf", None, &csrf_a),
            ("dir", None, ""),
            ("file", Some("keep.txt"), "precious"),
        ],
    )
    .await;

    assert!(
        get(&e, "/admin/users/delete?name=anna", &root)
            .await
            .text()
            .contains("Delete “anna”?")
    );
    // transfer needs a receiver
    let r = post_form(
        &e,
        "/admin/users/delete",
        &root,
        &[
            ("csrf", &csrf),
            ("name", "anna"),
            ("mode", "transfer"),
            ("to", ""),
        ],
    )
    .await;
    assert!(r.status.is_client_error());
    let r = post_form(
        &e,
        "/admin/users/delete",
        &root,
        &[
            ("csrf", &csrf),
            ("name", "anna"),
            ("mode", "transfer"),
            ("to", "bob"),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    assert_eq!(
        get(&e, "/files", &ca).await.status,
        StatusCode::SEE_OTHER,
        "deleted user's session is gone"
    );
    let cb = login(&e, "bob").await;
    assert_eq!(
        get(&e, "/download/anna%20(transferred)/keep.txt", &cb)
            .await
            .body,
        b"precious"
    );
    assert!(
        !get(&e, "/admin/users", &root)
            .await
            .text()
            .contains(">anna<")
    );
}

#[tokio::test]
async fn admin_event_log_status_and_server() {
    let e = env().await;
    let root = login(&e, "root").await;
    let csrf = page_csrf(&e, &root).await;
    post_form(
        &e,
        "/admin/users/quota",
        &root,
        &[("csrf", &csrf), ("name", "bob"), ("quota", "2G")],
    )
    .await;

    let ev = get(&e, "/admin/events", &root).await.text();
    assert!(ev.contains("admin.user_quota_set") && ev.contains("root"));
    assert_eq!(
        get(&e, "/admin/events?days=0", &root).await.status,
        StatusCode::OK
    );
    assert_eq!(
        get(&e, "/admin/events?days=abc", &root).await.status,
        StatusCode::BAD_REQUEST
    );

    let st = get(&e, "/admin/status", &root).await.text();
    assert!(st.contains("Consistency check") && st.contains("Users"));
    let r = post_form(
        &e,
        "/admin/status/check",
        &root,
        &[("csrf", &csrf), ("checksums", "1")],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.text().contains("no problems"), "{}", r.text());
    assert_eq!(
        post_form(&e, "/admin/status/check", &root, &[("csrf", "forged")])
            .await
            .status,
        StatusCode::FORBIDDEN
    );

    let sv = get(&e, "/admin/server", &root).await.text();
    assert!(sv.contains("Versioning") && sv.contains("Trash retention"));
    // user-controlled text in the log is escaped
    post_form(
        &e,
        "/admin/users/create",
        &root,
        &[("csrf", &csrf), ("name", "<b>x</b>"), ("password", PW)],
    )
    .await;
    let ev = get(&e, "/admin/events", &root).await.text();
    assert!(!ev.contains("<b>x</b>"));
}

#[tokio::test]
async fn files_page_matches_the_design_parts() {
    let e = env().await;
    let c = login(&e, "anna").await;
    let csrf = page_csrf(&e, &c).await;
    post_form(
        &e,
        "/action/mkdir",
        &c,
        &[("csrf", &csrf), ("dir", ""), ("name", "Docs")],
    )
    .await;
    upload(
        &e,
        &c,
        &[
            ("csrf", None, &csrf),
            ("dir", None, "Docs"),
            ("file", Some("pic.png"), "img"),
        ],
    )
    .await;
    upload(
        &e,
        &c,
        &[
            ("csrf", None, &csrf),
            ("dir", None, "Docs"),
            ("file", Some("a.md"), "one"),
        ],
    )
    .await;
    upload(
        &e,
        &c,
        &[
            ("csrf", None, &csrf),
            ("dir", None, "Docs"),
            ("file", Some("a.md"), "second"),
        ],
    )
    .await;

    let html = get(&e, "/files/Docs", &c).await.text();
    assert!(
        html.contains("3 items") || html.contains("2 items"),
        "{html}"
    );
    assert!(html.contains("tile image") && html.contains("tile doc"));
    assert!(html.contains("Today, "), "friendly dates");
    assert!(
        html.contains("role=\"search\"")
            && html.contains("New folder")
            && html.contains("id=\"upload-form\"")
    );
    assert!(html.contains("id=\"upload-card\"") && html.contains(" hidden"));
    // storage meter in the sidebar: unlimited quota shows usage only
    assert!(html.contains("class=\"storage\"") && html.contains("used"));
    // no selection: the open folder is described
    assert!(html.contains("File ID") && html.contains("Folder"));

    // a selected file: versions with restore, shares, actions
    let html = get(&e, "/files/Docs?sel=a.md", &c).await.text();
    assert!(html.contains("Current version") && html.contains("action=\"/versions/restore\""));
    assert!(html.contains("Download") && html.contains("/share?path=Docs%2Fa.md"));
    // unknown selection falls back to the folder
    assert!(
        get(&e, "/files/Docs?sel=nope", &c)
            .await
            .text()
            .contains("Folder")
    );
    // names in selection and filter are escaped
    let html = get(
        &e,
        "/files/Docs?sel=%3Cimg%20src%3Dx%3E&q=%3Cimg%20src%3Dx%3E",
        &c,
    )
    .await
    .text();
    assert!(!html.contains("<img src=x>"));

    // shared items carry a chip
    let anna = e
        .state
        .authenticate("anna", PW, "192.0.2.9".parse().expect("ip"))
        .await
        .expect("auth");
    e.state
        .share_create(
            &anna,
            rostdav_app::ShareCreate {
                path: Some(rostdav_core::LogicalPath::from_url_path("Docs").expect("p")),
                share_type: 3,
                permissions: Some(1),
                ..Default::default()
            },
        )
        .await
        .expect("share");
    assert!(get(&e, "/files", &c).await.text().contains("Shared"));
    assert!(
        get(&e, "/files/Docs", &c)
            .await
            .text()
            .contains("Public link")
    );

    // limited quota: a real meter
    root_set_quota(&e, "anna", 1_000_000).await;
    let html = get(&e, "/files", &c).await.text();
    assert!(html.contains("<progress class=\"meter\""), "{html}");
}

async fn root_set_quota(e: &Env, user: &str, bytes: i64) {
    e.state.set_quota(user, Some(bytes)).await.expect("quota");
}
