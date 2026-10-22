use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use rostdav::config::Config;

#[derive(Parser)]
#[command(
    name = "rostdav",
    version,
    about = "Lean file server compatible with the Nextcloud apps"
)]
struct Cli {
    /// Path to the configuration file (default: ./rostdav.toml if present).
    #[arg(long, short, global = true, env = "ROSTDAV_CONFIG")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Starts the server.
    Serve,
    /// Administration: users, consistency check, import, event log.
    #[command(subcommand)]
    Admin(rostdav::cli::AdminCommand),
    /// Prints the effective configuration (without secrets).
    CheckConfig,
    /// Asks a running server whether it is ready (for container health checks). Exit code 0 = ready.
    Healthcheck,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load(cli.config.as_deref())?;

    match cli.command {
        Command::CheckConfig => {
            let mut shown = cfg.clone();
            if shown.security.totp_key.is_some() {
                shown.security.totp_key = Some("<set>".to_owned());
            }
            println!("{}", serde_json::to_string_pretty(&shown)?);
            Ok(())
        }
        Command::Healthcheck => healthcheck(&cfg).await,
        Command::Serve => serve(cfg).await,
        Command::Admin(cmd) => admin(cfg, cmd).await,
    }
}

async fn admin(cfg: Config, cmd: rostdav::cli::AdminCommand) -> anyhow::Result<()> {
    let state = rostdav::build_state(&cfg).await?;
    let code = rostdav::cli::run(
        &state,
        cmd,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )
    .await;
    state.shutdown().await;
    match code {
        Ok(0) => Ok(()),
        Ok(c) => std::process::exit(c),
        Err(e) => Err(e),
    }
}

async fn serve(cfg: Config) -> anyhow::Result<()> {
    rostdav::telemetry::init(&cfg.log);
    tracing::info!(
        version = rostdav_core::VERSION,
        "{} starting",
        rostdav_core::PRODUCT_NAME
    );

    let state = rostdav::build_state(&cfg).await?;
    let swept = state.sweep_tmp().await.context("cleaning up tmp/ failed")?;
    if swept > 0 {
        tracing::warn!(swept, "removed incomplete writes");
    }
    let app = rostdav::http::router_with(
        state.clone(),
        &rostdav::http::HttpOptions::from_config(&cfg),
    );

    spawn_garbage_collection(state.clone());

    let listener = tokio::net::TcpListener::bind(cfg.server.listen)
        .await
        .with_context(|| format!("could not bind address {}", cfg.server.listen))?;
    tracing::info!(listen = %cfg.server.listen, "ready");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server exited with error")?;

    state.shutdown().await;
    tracing::info!("stopped");
    Ok(())
}

/// Periodically removes blobs that no node references any more.
fn spawn_garbage_collection(state: rostdav_app::AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tick.tick().await;
            match state.collect_garbage().await {
                Ok(0) => {}
                Ok(n) => tracing::info!(removed = n, "unreferenced blobs removed"),
                Err(err) => tracing::warn!(error = %err, "garbage collection failed"),
            }
        }
    });
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "Ctrl-C handler failed");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => tracing::error!(error = %err, "SIGTERM handler failed"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown requested");
}

/// `GET /readyz` on the configured listen address (0.0.0.0 and :: mean "this machine").
async fn healthcheck(cfg: &Config) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut addr = cfg.server.listen;
    if addr.ip().is_unspecified() {
        addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
    }
    let work = async {
        let mut s = tokio::net::TcpStream::connect(addr).await?;
        s.write_all(b"GET /readyz HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut buf = Vec::new();
        s.take(4096).read_to_end(&mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    };
    let buf = tokio::time::timeout(std::time::Duration::from_secs(5), work)
        .await
        .context("timeout")?
        .context("no connection")?;
    let head = String::from_utf8_lossy(&buf);
    anyhow::ensure!(
        head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200"),
        "not ready: {}",
        head.lines().next().unwrap_or("")
    );
    Ok(())
}
