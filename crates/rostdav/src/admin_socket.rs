//! The admin socket: `rostdav admin …` while the server runs (ADR 0010).
//!
//! The database engine locks its file for one process, so a second process cannot open it. The
//! running server therefore listens on a Unix socket in the data directory; the command line
//! sends its arguments and one piece of standard input there, the server runs the very same
//! command code and answers with the output and the exit code. No network port is opened.
//!
//! Who may connect: the data directory must be closed to everybody but its owner (mode 0700),
//! the socket is mode 0600, and each connection's user ID must be the owner of the socket or
//! root. That is the same circle of people who could have opened the database directly.

use std::io::Cursor;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rostdav_app::AppState;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// A request is a command line and one line of input (a password): far below this.
const MAX_REQUEST: u64 = 1 << 20;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const PROTOCOL: u32 = 1;

#[derive(Serialize, Deserialize)]
struct Request {
    v: u32,
    /// The words after `rostdav admin`.
    args: Vec<String>,
    stdin: String,
    /// The caller's working directory, for relative paths.
    cwd: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Reply {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Where the socket of a server with this data directory is.
pub fn path_for(data_dir: &Path) -> PathBuf {
    data_dir.join("admin.sock")
}

/// Root and the owner of the socket (the user the server runs as) may use it.
pub fn peer_allowed(peer_uid: u32, owner_uid: u32) -> bool {
    peer_uid == 0 || peer_uid == owner_uid
}

/// Starts listening. Returns once the socket exists; connections are handled in the background.
/// An error means no socket (the server runs on; commands then need it stopped).
pub async fn serve(state: AppState, data_dir: &Path) -> anyhow::Result<()> {
    let mode = std::fs::metadata(data_dir)?.permissions().mode();
    anyhow::ensure!(
        mode & 0o077 == 0,
        "the data directory is accessible by other users (mode {:o}); not opening the admin socket",
        mode & 0o7777
    );
    let path = path_for(data_dir);
    if path.exists() {
        // a socket nobody listens on is left over from a crash
        anyhow::ensure!(
            UnixStream::connect(&path).await.is_err(),
            "another process listens on {}",
            path.display()
        );
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let owner = std::fs::metadata(&path)?.uid();
    tracing::info!(socket = %path.display(), "admin socket ready");
    tokio::spawn(async move {
        loop {
            let Ok((conn, _)) = listener.accept().await else {
                continue;
            };
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(err) = handle(conn, state, owner).await {
                    tracing::warn!(error = %err, "admin socket request failed");
                }
            });
        }
    });
    Ok(())
}

async fn handle(mut conn: UnixStream, state: AppState, owner: u32) -> anyhow::Result<()> {
    let peer = conn.peer_cred()?;
    if !peer_allowed(peer.uid(), owner) {
        tracing::warn!(uid = peer.uid(), "admin socket: connection refused");
        return Ok(());
    }
    let mut raw = Vec::new();
    let outcome = tokio::time::timeout(READ_TIMEOUT, async {
        (&mut conn)
            .take(MAX_REQUEST + 1)
            .read_to_end(&mut raw)
            .await
    })
    .await;
    let reply = match outcome {
        Err(_) => error_reply("the request did not arrive in time"),
        Ok(Err(e)) => error_reply(&format!("could not read the request: {e}")),
        Ok(Ok(_)) if raw.len() as u64 > MAX_REQUEST => error_reply("the request is too large"),
        Ok(Ok(_)) => match serde_json::from_slice::<Request>(&raw) {
            Ok(r) if r.v == PROTOCOL => {
                tracing::info!(uid = peer.uid(), "admin command over the socket");
                let cwd = r.cwd.map(PathBuf::from);
                let r = crate::cli::execute(
                    &state,
                    &r.args,
                    &mut Cursor::new(r.stdin.into_bytes()),
                    cwd.as_deref(),
                )
                .await;
                Reply {
                    code: r.code,
                    stdout: r.stdout,
                    stderr: r.stderr,
                }
            }
            Ok(_) => error_reply("this server speaks another version of the admin protocol"),
            Err(_) => error_reply("the request is not valid"),
        },
    };
    conn.write_all(&serde_json::to_vec(&reply)?).await?;
    conn.shutdown().await?;
    Ok(())
}

fn error_reply(text: &str) -> Reply {
    Reply {
        code: 1,
        stdout: String::new(),
        stderr: format!("Error: {text}\n"),
    }
}

/// Sends a command to the server that listens on `socket`.
pub async fn call(
    socket: &Path,
    args: &[String],
    stdin: &str,
    cwd: Option<&Path>,
) -> std::io::Result<Reply> {
    let mut conn = UnixStream::connect(socket).await?;
    let request = Request {
        v: PROTOCOL,
        args: args.to_vec(),
        stdin: stdin.to_owned(),
        cwd: cwd.map(|c| c.to_string_lossy().into_owned()),
    };
    conn.write_all(&serde_json::to_vec(&request).map_err(std::io::Error::other)?)
        .await?;
    conn.shutdown().await?;
    let mut raw = Vec::new();
    conn.take(64 << 20).read_to_end(&mut raw).await?;
    serde_json::from_slice(&raw).map_err(|_| {
        std::io::Error::other("the server did not answer (it may refuse this user, see its log)")
    })
}

#[cfg(test)]
mod tests {
    use super::peer_allowed;

    #[test]
    fn only_root_and_the_owner_may_connect() {
        assert!(peer_allowed(0, 10001));
        assert!(peer_allowed(10001, 10001));
        assert!(!peer_allowed(1000, 10001));
        assert!(!peer_allowed(10002, 10001));
        assert!(!peer_allowed(u32::MAX, 10001));
    }
}
