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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load(cli.config.as_deref())?;

    match cli.command {
        Command::CheckConfig => {
            println!("{}", serde_json::to_string_pretty(&cfg)?);
            Ok(())
        }
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
