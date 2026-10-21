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
    /// Verwaltung (Benutzer).
    #[command(subcommand)]
    Admin(AdminCommand),
    /// Gibt die wirksame Konfiguration aus (ohne Geheimnisse).
    CheckConfig,
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Benutzerverwaltung.
    #[command(subcommand)]
    User(UserCommand),
}

#[derive(Subcommand)]
enum UserCommand {
    /// Legt einen Benutzer an. Das Passwort wird als eine Zeile von stdin gelesen
    /// (nie als Argument, damit es nicht in Prozesslisten oder der Shell-History landet).
    Add {
        name: String,
        /// Benutzer erhält Administratorrechte.
        #[arg(long)]
        admin: bool,
    },
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
        Command::Admin(AdminCommand::User(UserCommand::Add { name, admin })) => {
            user_add(cfg, &name, admin).await
        }
    }
}

async fn user_add(cfg: Config, name: &str, admin: bool) -> anyhow::Result<()> {
    use std::io::BufRead;

    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("Passwort konnte nicht von stdin gelesen werden")?;
    let password = line.trim_end_matches(['\r', '\n']);

    let state = rostdav::build_state(&cfg).await?;
    let result = state.add_user(name, password, admin).await;
    state.shutdown().await;
    let user = result.map_err(|e| anyhow::anyhow!("Benutzer nicht angelegt: {e}"))?;
    println!("Benutzer {} angelegt", user.name);
    Ok(())
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
