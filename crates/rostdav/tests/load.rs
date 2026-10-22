//! Phase 5: load tests (large file, many small files, parallel uploads).
//!
//! They take a while and measure, so they are ignored by default:
//!
//! ```sh
//! cargo test --release -p rostdav --test load -- --ignored --nocapture --test-threads=1
//! ```
//!
//! They drive the real router in-process (no TCP, no TLS), so they show what the
//! application does, not what a network or a proxy adds. Sizes can be changed with
//! `LOAD_BIG_MB` (default 512), `LOAD_SMALL_FILES` (default 5000) and `LOAD_PARALLEL`
//! (default 32 uploads of 8 MiB).

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use rostdav::config::Config;
use tower::ServiceExt;

const PW: &str = "korrekt-pferd-batterie";

struct Env {
    app: Router,
    auth: String,
    _dir: tempfile::TempDir,
}

async fn env() -> Env {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().join("data");
    let state = rostdav::build_state(&cfg).await.expect("state");
    state.add_user("anna", PW, false).await.expect("user");
    let anna = state
        .authenticate("anna", PW, "192.0.2.9".parse().expect("ip"))
        .await
        .expect("auth");
    let app = state.device_create(&anna, "load").await.expect("device");
    Env {
        app: rostdav::http::router_with(state, &rostdav::http::HttpOptions::from_config(&cfg)),
        auth: format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("anna:{app}"))
        ),
        _dir: dir,
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Peak resident memory of this process in MiB (Linux).
fn peak_rss_mib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .map(str::to_owned)
        })
        .and_then(|l| {
            l.split_whitespace()
                .nth(1)
                .and_then(|n| n.parse::<u64>().ok())
        })
        .map_or(0, |kb| kb / 1024)
}

/// A request body of `total` bytes produced on the fly in 1 MiB pieces.
struct Gen {
    left: usize,
    seed: u8,
}

impl futures_core::Stream for Gen {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.left == 0 {
            return Poll::Ready(None);
        }
        let n = self.left.min(1 << 20);
        self.left -= n;
        let seed = self.seed;
        Poll::Ready(Some(Ok(Bytes::from(
            (0..n)
                .map(|i| (i as u8).wrapping_add(seed))
                .collect::<Vec<u8>>(),
        ))))
    }
}

async fn call(
    app: &Router,
    auth: &str,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Body,
) -> (StatusCode, Body) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "cloud.test")
        .header("authorization", auth);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let mut req = b.body(body).expect("req");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            4000,
        ))));
    let r = app.clone().oneshot(req).await.expect("resp");
    let (p, body) = r.into_parts();
    (p.status, body)
}

async fn drain(body: Body) -> usize {
    let mut n = 0;
    let mut b = body;
    while let Some(f) = b.frame().await {
        if let Ok(f) = f {
            n += f.data_ref().map_or(0, Bytes::len);
        }
    }
    n
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load test, see the module documentation"]
async fn large_file_is_streamed_in_constant_memory() {
    let e = env().await;
    let mb = env_usize("LOAD_BIG_MB", 512);
    let before = peak_rss_mib();
    let t = Instant::now();
    let (s, _) = call(
        &e.app,
        &e.auth,
        "PUT",
        "/remote.php/dav/files/anna/big.bin",
        &[],
        Body::from_stream(Gen {
            left: mb << 20,
            seed: 1,
        }),
    )
    .await;
    assert!(s.is_success(), "{s}");
    let up = t.elapsed();
    let t = Instant::now();
    let (s, body) = call(
        &e.app,
        &e.auth,
        "GET",
        "/remote.php/dav/files/anna/big.bin",
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let got = drain(body).await;
    let down = t.elapsed();
    assert_eq!(got, mb << 20);
    let after = peak_rss_mib();
    eprintln!(
        "LOAD large file {mb} MiB: upload {:.1} MiB/s ({up:?}), download {:.1} MiB/s ({down:?}), peak RSS {before} -> {after} MiB",
        mb as f64 / up.as_secs_f64(),
        mb as f64 / down.as_secs_f64()
    );
    // streaming: memory must not grow with the file (allow generous slack for buffers)
    assert!(
        after.saturating_sub(before) < 200,
        "memory grew by {} MiB for a {mb} MiB file",
        after - before
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load test, see the module documentation"]
async fn many_small_files() {
    let e = env().await;
    let n = env_usize("LOAD_SMALL_FILES", 5000);
    let (s, _) = call(
        &e.app,
        &e.auth,
        "MKCOL",
        "/remote.php/dav/files/anna/small",
        &[],
        Body::empty(),
    )
    .await;
    assert!(s.is_success());
    let t = Instant::now();
    for i in 0..n {
        let (s, _) = call(
            &e.app,
            &e.auth,
            "PUT",
            &format!("/remote.php/dav/files/anna/small/f{i:05}.txt"),
            &[],
            Body::from(format!("file number {i}")),
        )
        .await;
        assert!(s.is_success(), "{i}: {s}");
    }
    let put = t.elapsed();
    let t = Instant::now();
    let (s, body) = call(
        &e.app,
        &e.auth,
        "PROPFIND",
        "/remote.php/dav/files/anna/small/",
        &[("depth", "1")],
        Body::empty(),
    )
    .await;
    assert_eq!(s, StatusCode::MULTI_STATUS);
    let size = drain(body).await;
    let list = t.elapsed();
    let t = Instant::now();
    for i in (0..n).step_by(10) {
        let (s, body) = call(
            &e.app,
            &e.auth,
            "GET",
            &format!("/remote.php/dav/files/anna/small/f{i:05}.txt"),
            &[],
            Body::empty(),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        drain(body).await;
    }
    let get = t.elapsed();
    eprintln!(
        "LOAD {n} small files: PUT {:.0}/s ({put:?}), PROPFIND depth 1 {list:?} ({} KiB), GET {:.0}/s, peak RSS {} MiB",
        n as f64 / put.as_secs_f64(),
        size / 1024,
        (n / 10) as f64 / get.as_secs_f64(),
        peak_rss_mib()
    );
    assert!(list.as_secs() < 10, "listing {n} entries took {list:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load test, see the module documentation"]
async fn parallel_uploads_do_not_corrupt_each_other() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "error".into()))
        .with_test_writer()
        .try_init();
    let e = std::sync::Arc::new(env().await);
    let n = env_usize("LOAD_PARALLEL", 32);
    let t = Instant::now();
    let mut tasks = Vec::new();
    for i in 0..n {
        let e = e.clone();
        tasks.push(tokio::spawn(async move {
            // half as plain PUT, half chunked (1 MiB pieces)
            if i % 2 == 0 {
                let (s, _) = call(
                    &e.app,
                    &e.auth,
                    "PUT",
                    &format!("/remote.php/dav/files/anna/p{i}.bin"),
                    &[],
                    Body::from_stream(Gen {
                        left: 8 << 20,
                        seed: i as u8,
                    }),
                )
                .await;
                assert!(s.is_success(), "{i}: {s}");
            } else {
                let id = format!("t{i}");
                let (s, _) = call(
                    &e.app,
                    &e.auth,
                    "MKCOL",
                    &format!("/remote.php/dav/uploads/anna/{id}"),
                    &[],
                    Body::empty(),
                )
                .await;
                assert!(s.is_success());
                for c in 0..8 {
                    let (s, _) = call(
                        &e.app,
                        &e.auth,
                        "PUT",
                        &format!("/remote.php/dav/uploads/anna/{id}/{c:06}"),
                        &[],
                        Body::from_stream(Gen {
                            left: 1 << 20,
                            seed: i as u8,
                        }),
                    )
                    .await;
                    assert!(s.is_success(), "{i} chunk {c}: {s}");
                }
                let (s, _) = call(
                    &e.app,
                    &e.auth,
                    "MOVE",
                    &format!("/remote.php/dav/uploads/anna/{id}/.file"),
                    &[
                        (
                            "destination",
                            &format!("http://cloud.test/remote.php/dav/files/anna/p{i}.bin"),
                        ),
                        ("oc-total-length", &(8u64 << 20).to_string()),
                    ],
                    Body::empty(),
                )
                .await;
                assert!(s.is_success(), "{i} assemble: {s}");
            }
        }));
    }
    for t in tasks {
        t.await.expect("upload task");
    }
    let took = t.elapsed();
    // every file must be complete and have its own pattern (no mixing between uploads)
    for i in 0..n {
        let (s, body) = call(
            &e.app,
            &e.auth,
            "GET",
            &format!("/remote.php/dav/files/anna/p{i}.bin"),
            &[],
            Body::empty(),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let bytes = body.collect().await.expect("body").to_bytes();
        assert_eq!(bytes.len(), 8 << 20, "file {i}");
        // the generator restarts its pattern per 1 MiB piece, so check the first byte of each piece
        for piece in 0..8 {
            assert_eq!(bytes[piece << 20], i as u8, "file {i} piece {piece}");
        }
    }
    eprintln!(
        "LOAD {n} parallel uploads of 8 MiB ({} MiB in total): {took:?} ({:.1} MiB/s), peak RSS {} MiB",
        n * 8,
        (n * 8) as f64 / took.as_secs_f64(),
        peak_rss_mib()
    );
}
