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

/// The words after `rostdav admin` on this process's command line (global options come first).
fn admin_words() -> Vec<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "admin" => break,
            "--config" | "-c" => {
                args.next();
            }
            _ => {}
        }
    }
    args.collect()
}

/// One line when typed at a terminal (a password), everything when piped.
fn read_stdin() -> anyhow::Result<String> {
    use std::io::{BufRead, IsTerminal, Read};
    let mut text = String::new();
    let mut stdin = std::io::stdin().lock();
    if stdin.is_terminal() {
        stdin.read_line(&mut text)?;
    } else {
        stdin.take(1 << 20).read_to_string(&mut text)?;
    }
    Ok(text)
}

async fn admin(cfg: Config, cmd: rostdav::cli::AdminCommand) -> anyhow::Result<()> {
    use std::io::Write;
    // A running server owns the database file; its admin socket does the work (ADR 0010).
    let socket = rostdav::admin_socket::path_for(&cfg.storage.data_dir);
    if socket.exists() {
        let cwd = std::env::current_dir().ok();
        // only a command that asks for a password reads (and waits for) standard input
        let input = if cmd.reads_stdin() {
            read_stdin()?
        } else {
            String::new()
        };
        let sent =
            rostdav::admin_socket::call(&socket, &admin_words(), &input, cwd.as_deref()).await;
        match sent {
            Ok(reply) => {
                std::io::stdout().write_all(reply.stdout.as_bytes())?;
                std::io::stderr().write_all(reply.stderr.as_bytes())?;
                if reply.code != 0 {
                    std::process::exit(reply.code);
                }
                return Ok(());
            }
            // nobody listens: a leftover from a crash, the database is free
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) => {}
            Err(e) => return Err(e).context("the running server did not take the command"),
        }
    }
    let state = match rostdav::build_state(&cfg).await {
        Ok(s) => s,
        Err(e) if format!("{e:?}").contains("locked by another process") => {
            anyhow::bail!(
                "the database is in use by a running server, and its admin socket ({}) is not there. \
                 Start the server of this version, or stop it and run the command again",
                socket.display()
            );
        }
        Err(e) => return Err(e),
    };
    let code = rostdav::cli::run(
        &state,
        cmd,
        &mut std::io::BufReader::new(std::io::stdin()),
        &mut std::io::stdout(),
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
    if let Err(err) = rostdav::admin_socket::serve(state.clone(), &cfg.storage.data_dir).await {
        tracing::warn!(error = %err, "no admin socket: `rostdav admin` needs the server stopped");
    }
    spawn_version_check(state.clone());
    spawn_indexer(state.clone());

    let listener = tokio::net::TcpListener::bind(cfg.server.listen)
        .await
        .with_context(|| format!("could not bind address {}", cfg.server.listen))?;
    tracing::info!(listen = %cfg.server.listen, "ready");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(state.clone()))
    .await
    .context("server exited with error")?;

    state.shutdown().await;
    tracing::info!("stopped");
    if state.restart_requested() {
        // an update was installed: a supervisor with `Restart=on-failure` starts the new program
        std::process::exit(rostdav_app::EXIT_FOR_RESTART);
    }
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

/// Keeps the search index in step with the files (ADR 0012): names first, then the text of
/// files a little at a time. Quick while there is work, a pass every 30 seconds otherwise.
fn spawn_indexer(state: rostdav_app::AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        loop {
            let pause = match state.indexer_pass().await {
                Ok(r) => {
                    if r.names_written + r.names_removed + r.texts_read > 0 {
                        tracing::info!(
                            names_written = r.names_written,
                            names_removed = r.names_removed,
                            texts_read = r.texts_read,
                            pending = r.pending,
                            "search index updated"
                        );
                    }
                    if r.pending > 0 { 1 } else { 30 }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "search indexer pass failed");
                    60
                }
            };
            tokio::time::sleep(std::time::Duration::from_secs(pause)).await;
        }
    });
}

/// The version check (ADR 0009): does nothing unless an administrator switched it on.
fn spawn_version_check(state: rostdav_app::AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            tick.tick().await;
            state.update_check_if_due().await;
        }
    });
}

async fn shutdown_signal(state: rostdav_app::AppState) {
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
        // an update was installed (the program file was replaced)
        () = state.restart_signal() => {},
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
