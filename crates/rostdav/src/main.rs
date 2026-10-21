use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use rostdav::config::Config;

#[derive(Parser)]
#[command(
    name = "rostdav",
    version,
    about = "Schlanker, Nextcloud-App-kompatibler Dateiserver"
)]
struct Cli {
    /// Pfad zur Konfigurationsdatei (Standard: ./rostdav.toml, falls vorhanden).
    #[arg(long, short, global = true, env = "ROSTDAV_CONFIG")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Startet den Server.
    Serve,
    /// Gibt die wirksame Konfiguration aus (ohne Geheimnisse).
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
    }
}

async fn serve(cfg: Config) -> anyhow::Result<()> {
    rostdav::telemetry::init(&cfg.log);
    tracing::info!(
        version = rostdav_core::VERSION,
        "{} startet",
        rostdav_core::PRODUCT_NAME
    );

    let state = rostdav::build_state(&cfg).await?;
    let app = rostdav::http::router(state.clone());

    let listener = tokio::net::TcpListener::bind(cfg.server.listen)
        .await
        .with_context(|| format!("Adresse {} konnte nicht gebunden werden", cfg.server.listen))?;
    tracing::info!(listen = %cfg.server.listen, "bereit");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Server beendet mit Fehler")?;

    state.shutdown().await;
    tracing::info!("beendet");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "Ctrl-C-Handler fehlgeschlagen");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => tracing::error!(error = %err, "SIGTERM-Handler fehlgeschlagen"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("Herunterfahren angefordert");
}
