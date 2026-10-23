//! Installing an update from the web interface (ADR 0009).
//!
//! Only for a plain binary, never for a container image, and only with a signing key built in.
//! Everything that can be checked is checked *before* the program file is touched: the
//! administrator's password, the version (newer than the running one and the one the version
//! check found), the download address (built here, redirects only to GitHub's hosts), the
//! minisign signature, the new program's own `--version`, and a database backup. The swap is one
//! atomic `rename`; the old program stays as `<name>.previous`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rostdav_core::release::Version;
use rostdav_core::{Error, Result};
use serde_json::json;

use crate::AppState;
use crate::web::WebSession;

/// Where release files live. The path continues with `v<version>/<file>`.
pub(crate) const RELEASE_DOWNLOADS: &str =
    "https://github.com/pierrejochem/rostdav/releases/download";
/// The minisign public key of the release signing key. Without one the updater is off.
const PUBLIC_KEY: &str = include_str!("../update-key.pub");
/// GitHub serves release files from these hosts (after a redirect from `github.com`).
const TRUSTED_HOSTS: [&str; 3] = [
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];
const MAX_BINARY: u64 = 256 << 20;
const MAX_SIGNATURE: u64 = 8 << 10;
/// The server exits with this status after an update so that a supervisor (`Restart=on-failure`)
/// starts the new program.
pub const EXIT_FOR_RESTART: i32 = 75;

/// What the updater works with. Tests replace the parts that point outside.
pub(crate) struct UpdaterEnv {
    key: Option<String>,
    exe: Option<PathBuf>,
    base: String,
    container: bool,
    /// Tests only: plain HTTP and any host.
    relaxed: bool,
}

impl Default for UpdaterEnv {
    fn default() -> Self {
        Self {
            key: Some(PUBLIC_KEY.to_owned()),
            exe: std::env::current_exe().ok(),
            base: RELEASE_DOWNLOADS.to_owned(),
            container: std::env::var("RD_INSTALL").is_ok_and(|v| v == "container"),
            relaxed: false,
        }
    }
}

/// Whether, and if not why not, this server can install an update itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallSupport {
    Ready,
    /// Running from the container image: pull the new image instead.
    Container,
    /// This build has no update signing key.
    NoKey,
    /// No release file for this operating system or processor.
    UnsupportedPlatform,
    /// The program file's folder is not writable for the server's user.
    NotWritable,
}

/// The release file name part for this machine (`x86_64-unknown-linux-gnu`).
pub(crate) fn target() -> Option<&'static str> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    match std::env::consts::ARCH {
        "x86_64" => Some("x86_64-unknown-linux-gnu"),
        "aarch64" => Some("aarch64-unknown-linux-gnu"),
        _ => None,
    }
}

/// Checks `data` against the minisign signature text with the key text. Prehashed signatures
/// only (what `minisign -S -H` and the library write), no legacy ones.
pub(crate) fn verify_signature(key: &str, signature: &str, data: &[u8]) -> bool {
    // the key file has a comment line first; a file without a key line is "no key"
    let Ok(key) = minisign_verify::PublicKey::decode(key) else {
        return false;
    };
    let Ok(sig) = minisign_verify::Signature::decode(signature) else {
        return false;
    };
    key.verify(data, &sig, false).is_ok()
}

fn host_of(url: &str) -> Option<String> {
    let uri: ureq::http::Uri = url.parse().ok()?;
    uri.host().map(str::to_ascii_lowercase)
}

/// An `https` address on one of GitHub's hosts (exact names: `github.com.evil.example` is not one).
fn trusted(url: &str) -> bool {
    url.starts_with("https://") && host_of(url).is_some_and(|h| TRUSTED_HOSTS.contains(&h.as_str()))
}

/// One blocking download with at most three redirects, each checked against the allowed hosts.
fn download(url: &str, limit: u64, relaxed: bool) -> std::result::Result<Vec<u8>, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(300)))
        .max_redirects(0)
        .max_redirects_will_error(false)
        .https_only(!relaxed)
        .user_agent(format!("rostdav/{}", rostdav_core::VERSION))
        .build()
        .into();
    let mut current = url.to_owned();
    for _ in 0..4 {
        if !relaxed && !trusted(&current) {
            return Err("the download address is not one of GitHub's".to_owned());
        }
        let mut answer = agent.get(&current).call().map_err(|e| match e {
            ureq::Error::StatusCode(c) => format!("the server answered {c}"),
            other => other.to_string(),
        })?;
        let status = answer.status().as_u16();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let next = answer
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
                .ok_or("a redirect without an address")?;
            current = next;
            continue;
        }
        if status != 200 {
            return Err(format!("the server answered {status}"));
        }
        return answer
            .body_mut()
            .with_config()
            .limit(limit)
            .read_to_vec()
            .map_err(|e| e.to_string());
    }
    Err("too many redirects".to_owned())
}

/// Can the server create files next to its program file?
async fn dir_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".rostdav-write-test-{}", std::process::id()));
    match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .await
    {
        Ok(_) => {
            let _ = tokio::fs::remove_file(&probe).await;
            true
        }
        Err(_) => false,
    }
}

impl AppState {
    fn updater_env(&self) -> std::sync::MutexGuard<'_, UpdaterEnv> {
        self.inner
            .updater
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether this server could install an update now (administrators only).
    pub async fn update_install_support(
        &self,
        actor: &crate::admin::Actor<'_>,
    ) -> Result<InstallSupport> {
        actor.require_admin()?;
        Ok(self.install_support().await)
    }

    async fn install_support(&self) -> InstallSupport {
        let (container, has_key, exe) = {
            let e = self.updater_env();
            let key_ok = e
                .key
                .as_deref()
                .is_some_and(|k| minisign_verify::PublicKey::decode(k).is_ok());
            (e.container, key_ok, e.exe.clone())
        };
        if container {
            return InstallSupport::Container;
        }
        if !has_key {
            return InstallSupport::NoKey;
        }
        if target().is_none() && !self.updater_env().relaxed {
            return InstallSupport::UnsupportedPlatform;
        }
        match exe.as_deref().and_then(Path::parent) {
            Some(dir) if dir_writable(dir).await => InstallSupport::Ready,
            _ => InstallSupport::NotWritable,
        }
    }

    /// Whether an update was installed and the server has to be started again.
    pub fn restart_requested(&self) -> bool {
        self.inner
            .restart_requested
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Completes when an update was installed (the process then shuts down and exits with
    /// [`EXIT_FOR_RESTART`]).
    pub async fn restart_signal(&self) {
        self.inner.restart.notified().await;
    }

    /// Installs the newest release found by the version check. `password` is the signed-in
    /// administrator's account password. Returns the installed version.
    pub async fn update_install(
        &self,
        s: &WebSession,
        password: &str,
        ip: IpAddr,
    ) -> Result<String> {
        let p = &s.principal;
        let actor = crate::admin::Actor::User(p);
        actor.require_admin()?;
        let invalid = |m: &str| Error::Invalid(m.to_owned());
        match self.install_support().await {
            InstallSupport::Ready => {}
            InstallSupport::Container => {
                return Err(invalid(
                    "This server runs from a container image: pull the new image instead",
                ));
            }
            InstallSupport::NoKey => {
                return Err(invalid(
                    "This build has no update signing key, so it cannot install updates",
                ));
            }
            InstallSupport::UnsupportedPlatform => {
                return Err(invalid("There is no release file for this machine"));
            }
            InstallSupport::NotWritable => {
                return Err(invalid(
                    "The folder of the program file is not writable for the server",
                ));
            }
        }
        // the account password again (rate limited like a sign-in); an app password does not count
        if self
            .authenticate_with(&p.name, password, ip, false)
            .await
            .is_err()
        {
            return Err(invalid("The password is wrong"));
        }
        let status = self.update_status(&actor).await?;
        let Some(latest) = status.available() else {
            return Err(invalid("There is no newer version to install"));
        };
        let version = latest.version.clone();
        if version <= Version::current() {
            return Err(invalid("There is no newer version to install"));
        }
        if self
            .inner
            .installing
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(Error::Conflict("an update is already being installed"));
        }
        let result = self.install(&version, p.name.as_str(), ip).await;
        self.inner
            .installing
            .store(false, std::sync::atomic::Ordering::SeqCst);
        result.map(|()| version.to_string())
    }

    async fn install(&self, version: &Version, admin: &str, ip: IpAddr) -> Result<()> {
        let invalid = |m: String| Error::Invalid(m);
        let (key, exe, base, relaxed) = {
            let e = self.updater_env();
            (e.key.clone(), e.exe.clone(), e.base.clone(), e.relaxed)
        };
        let (Some(key), Some(exe)) = (key, exe) else {
            return Err(invalid("The updater is not set up".to_owned()));
        };
        let target = target().unwrap_or("test-target");
        let file = format!("rostdav-{version}-{target}");
        let url = format!("{base}/v{version}/{file}");
        let sig_url = format!("{url}.minisig");

        // 1. download both files
        tracing::info!(%version, "update: downloading");
        let (u1, u2) = (url.clone(), sig_url.clone());
        let fetched = tokio::task::spawn_blocking(move || {
            let bin = download(&u1, MAX_BINARY, relaxed)?;
            let sig = download(&u2, MAX_SIGNATURE, relaxed)?;
            Ok::<_, String>((bin, sig))
        })
        .await
        .map_err(Error::internal)?;
        let (binary, signature) =
            fetched.map_err(|e| invalid(format!("The download failed: {e}")))?;

        // 2. the signature, before anything is written
        let signature = String::from_utf8_lossy(&signature).into_owned();
        if !verify_signature(&key, &signature, &binary) {
            tracing::warn!(%version, "update: signature check failed, nothing installed");
            return Err(invalid(
                "The signature of the download is not valid. Nothing was installed".to_owned(),
            ));
        }

        // 3. the new program in the program's own folder (same file system: `rename` is atomic)
        let dir = exe
            .parent()
            .ok_or_else(|| invalid("The program file has no folder".to_owned()))?
            .to_path_buf();
        let name = exe
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "rostdav".to_owned());
        let staged = dir.join(format!(".{name}.update-{version}"));
        let io = |e: std::io::Error| Error::internal(e);
        let outcome = async {
            tokio::fs::write(&staged, &binary).await.map_err(io)?;
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
                    .await
                    .map_err(io)?;
            }
            // 4. it must say it is the version we think it is
            smoke_test(&staged, version).await?;
            // 5. the way back for an update that converts the database
            let backups = self.inner.store.root().join("backups");
            tokio::fs::create_dir_all(&backups).await.map_err(io)?;
            let copy = backups.join(format!("before-{version}.sqlite"));
            let _ = tokio::fs::remove_file(&copy).await;
            self.inner.db.backup_to(&copy).await.map_err(|e| {
                tracing::error!(error = %e, "update: database backup failed, nothing installed");
                invalid("The database backup failed. Nothing was installed".to_owned())
            })?;
            // 6. keep the old program, then replace it atomically
            let previous = dir.join(format!("{name}.previous"));
            let _ = tokio::fs::remove_file(&previous).await;
            if tokio::fs::hard_link(&exe, &previous).await.is_err() {
                tokio::fs::copy(&exe, &previous).await.map_err(io)?;
            }
            tokio::fs::rename(&staged, &exe).await.map_err(io)?;
            Ok::<(), Error>(())
        }
        .await;
        if outcome.is_err() {
            let _ = tokio::fs::remove_file(&staged).await;
        }
        outcome?;

        self.audit(
            admin,
            "admin.update_installed",
            "",
            Some(ip),
            json!({"from": rostdav_core::VERSION, "to": version.to_string()}),
        )
        .await;
        tracing::info!(%version, "update installed, restarting");
        self.inner
            .restart_requested
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.inner.restart.notify_one();
        Ok(())
    }

    /// Points the updater at a test setup: its key, the program file to replace, the download
    /// base address, and whether this runs as a container. Allows plain HTTP and any host.
    #[doc(hidden)]
    pub fn set_updater_for_tests(
        &self,
        key: Option<&str>,
        exe: &Path,
        base: &str,
        container: bool,
    ) {
        let mut e = self.updater_env();
        e.key = key.map(str::to_owned);
        e.exe = Some(exe.to_path_buf());
        e.base = base.to_owned();
        e.container = container;
        e.relaxed = true;
    }
}

/// Runs `<program> --version` and expects `rostdav <version>`.
async fn smoke_test(program: &Path, version: &Version) -> Result<()> {
    let run = tokio::process::Command::new(program)
        .arg("--version")
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .output();
    let out = match tokio::time::timeout(Duration::from_secs(15), run).await {
        Ok(Ok(o)) if o.status.success() => o,
        _ => {
            return Err(Error::Invalid(
                "The downloaded program does not start. Nothing was installed".to_owned(),
            ));
        }
    };
    let said = String::from_utf8_lossy(&out.stdout);
    if said.trim() != format!("rostdav {version}") {
        return Err(Error::Invalid(
            "The downloaded program reports another version than expected. Nothing was installed"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn trusted_for_tests(url: &str) -> bool {
    trusted(url)
}

#[cfg(test)]
pub(crate) async fn smoke_test_for_tests(program: &Path, version: &Version) -> Result<()> {
    smoke_test(program, version).await
}
