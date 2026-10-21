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
    /// Starts the server.
    Serve,
    /// Administration (users).
    #[command(subcommand)]
    Admin(AdminCommand),
    /// Prints the effective configuration (without secrets).
    CheckConfig,
}

#[derive(Subcommand)]
enum AdminCommand {
    /// User management.
    #[command(subcommand)]
    User(UserCommand),
}

#[derive(Subcommand)]
enum UserCommand {
    /// Creates a user. The password is read as one line from stdin
    /// (never as an argument, so it does not end up in process lists or shell history).
    Add {
        name: String,
        /// The user is granted administrator rights.
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
        .context("could not read password from stdin")?;
    let password = line.trim_end_matches(['\r', '\n']);

    let state = rostdav::build_state(&cfg).await?;
    let result = state.add_user(name, password, admin).await;
    state.shutdown().await;
    let user = result.map_err(|e| anyhow::anyhow!("user not created: {e}"))?;
    println!("user {} created", user.name);
    Ok(())
}

async fn serve(cfg: Config) -> anyhow::Result<()> {
    rostdav::telemetry::init(&cfg.log);
    tracing::info!(
        version = rostdav_core::VERSION,
        "{} starting",
        rostdav_core::PRODUCT_NAME
    );

    let state = rostdav::build_state(&cfg).await?;
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
