//! Optional two-factor authentication with TOTP (RFC 6238) and recovery codes (ADR 0007).
//!
//! The secret is encrypted with ChaCha20-Poly1305; the key lives outside the
//! database (key file or configuration). Codes and secrets are never logged.

use std::net::IpAddr;
use std::path::PathBuf;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::{Hmac, Mac};
use rostdav_core::{Error, Result};
use serde_json::json;
use sha1::Sha1;

use crate::AppState;
use crate::auth::{Principal, Scope, Via};
use crate::password::{hash_password, verify_password};
use crate::secrets::{mac, mac_eq, random_bytes};
use crate::web::WebSession;

/// Length of one TOTP step in seconds.
const STEP_SECS: u64 = 30;
/// Number of recovery codes handed out.
pub const RECOVERY_CODES: usize = 10;
/// How long a ticket from the password step is valid.
const TICKET_SECS: i64 = 300;
/// Setups that were not confirmed within this time are removed.
pub const PENDING_MAX_AGE_SECS: i64 = 3600;
/// Look-alike characters (0/o, 1/l/i) are left out of recovery codes.
const CODE_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// Where the key for the TOTP secrets comes from.
#[derive(Clone, Debug, Default)]
pub enum TotpKeySource {
    /// Two-factor authentication cannot be set up.
    #[default]
    None,
    /// Given in the configuration.
    Fixed([u8; 32]),
    /// A file with 32 random bytes; created (mode 0600) when the first setup starts.
    File(PathBuf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoFactorStatus {
    /// The server has a key and 2FA can be set up.
    pub available: bool,
    pub enabled: bool,
    pub recovery_left: i64,
}

#[derive(Clone, Debug)]
pub struct TwoFactorSetup {
    /// Base32, shown for manual entry.
    pub secret: String,
    pub uri: String,
    /// QR code of `uri` as an inline SVG.
    pub qr_svg: String,
}

/// Result of the password step of a browser sign-in.
#[derive(Debug)]
pub enum SignIn {
    /// No second factor: the session exists.
    Done {
        cookie: String,
        principal: Principal,
    },
    /// The password was right; the code is still needed.
    SecondFactor { ticket: String },
}

// ---- primitives ---------------------------------------------------------------------------

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub(crate) fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The 6-digit TOTP value for a counter (RFC 4226 dynamic truncation).
pub(crate) fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut m = <Hmac<Sha1> as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    m.update(&counter.to_be_bytes());
    let h = m.finalize().into_bytes();
    let off = usize::from(h[19] & 0x0f);
    let bin = (u32::from(h[off] & 0x7f) << 24)
        | (u32::from(h[off + 1]) << 16)
        | (u32::from(h[off + 2]) << 8)
        | u32::from(h[off + 3]);
    bin % 1_000_000
}

fn encrypt(key: &[u8; 32], user_id: i64, plain: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let nonce: [u8; 12] = random_bytes();
    let c = ChaCha20Poly1305::new(key.into());
    let ct = c
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plain,
                aad: &user_id.to_le_bytes(),
            },
        )
        .map_err(|_| Error::Unavailable)?;
    Ok((ct, nonce.to_vec()))
}

fn decrypt(key: &[u8; 32], user_id: i64, ct: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(Error::Unavailable);
    }
    ChaCha20Poly1305::new(key.into())
        .decrypt(
            &Nonce::try_from(nonce).map_err(|_| Error::Unavailable)?,
            Payload {
                msg: ct,
                aad: &user_id.to_le_bytes(),
            },
        )
        .map_err(|_| Error::Unavailable)
}

/// `xxxx-xxxx-xxxx` from 12 random characters without modulo bias.
fn new_recovery_code() -> String {
    let n = CODE_ALPHABET.len() as u8; // 31
    let limit = 255 - (255 % n);
    let mut chars = String::new();
    while chars.len() < 12 {
        for b in random_bytes::<32>() {
            if b < limit && chars.len() < 12 {
                chars.push(CODE_ALPHABET[usize::from(b % n)] as char);
            }
        }
    }
    format!("{}-{}-{}", &chars[..4], &chars[4..8], &chars[8..])
}

/// What the user typed, without spaces and dashes, in lower case.
fn normalize_code(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_lowercase()
}

fn now_step() -> i64 {
    i64::try_from(u64::try_from(crate::now_secs()).unwrap_or(0) / STEP_SECS).unwrap_or(0)
}

impl AppState {
    // ---- key ------------------------------------------------------------------------------

    pub fn two_factor_available(&self) -> bool {
        !matches!(self.cfg().security.totp_key, TotpKeySource::None)
    }

    /// The key for the secrets; with `create` a missing key file is created.
    async fn totp_key(&self, create: bool) -> Result<[u8; 32]> {
        match &self.cfg().security.totp_key {
            TotpKeySource::None => Err(Error::Unavailable),
            TotpKeySource::Fixed(k) => Ok(*k),
            TotpKeySource::File(path) => {
                match tokio::fs::read(path).await {
                    Ok(b) => return b.try_into().map_err(|_| Error::Unavailable),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {}
                    Err(e) => return Err(Error::internal(e)),
                }
                let key: [u8; 32] = random_bytes();
                let mut opts = tokio::fs::OpenOptions::new();
                opts.write(true).create_new(true).mode(0o600);
                match opts.open(path).await {
                    Ok(mut f) => {
                        use tokio::io::AsyncWriteExt;
                        f.write_all(&key).await.map_err(Error::internal)?;
                        f.sync_all().await.map_err(Error::internal)?;
                        Ok(key)
                    }
                    // another request created it first
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        let b = tokio::fs::read(path).await.map_err(Error::internal)?;
                        b.try_into().map_err(|_| Error::Unavailable)
                    }
                    Err(e) => Err(Error::internal(e)),
                }
            }
        }
    }

    async fn secret_of(&self, user_id: i64) -> Result<(Vec<u8>, bool, i64)> {
        let row = self
            .inner
            .db
            .totp_get(user_id)
            .await?
            .ok_or(Error::NotFound)?;
        let key = self.totp_key(false).await?;
        let secret = decrypt(&key, user_id, &row.secret_enc, &row.nonce)?;
        Ok((secret, row.enabled_at.is_some(), row.last_step))
    }

    // ---- status and setup -------------------------------------------------------------------

    pub async fn two_factor_status(&self, p: &Principal) -> Result<TwoFactorStatus> {
        Self::require_full(p)?;
        let enabled = self.inner.db.totp_enabled(p.user_id).await?;
        Ok(TwoFactorStatus {
            available: self.two_factor_available(),
            enabled,
            recovery_left: if enabled {
                self.inner.db.recovery_remaining(p.user_id).await?
            } else {
                0
            },
        })
    }

    /// Starts a setup (or shows the one in progress again).
    pub async fn two_factor_begin(&self, p: &Principal) -> Result<TwoFactorSetup> {
        Self::require_full(p)?;
        if self.inner.db.totp_enabled(p.user_id).await? {
            return Err(Error::Conflict("two-factor authentication is already on"));
        }
        let key = self.totp_key(true).await?;
        let fresh =
            |row: &rostdav_meta::TotpRow| crate::now_secs() - row.created_at < PENDING_MAX_AGE_SECS;
        let secret = match self.inner.db.totp_get(p.user_id).await? {
            Some(row) if fresh(&row) => decrypt(&key, p.user_id, &row.secret_enc, &row.nonce)?,
            _ => {
                let s: [u8; 20] = random_bytes();
                let (ct, nonce) = encrypt(&key, p.user_id, &s)?;
                self.inner
                    .db
                    .totp_put_pending(p.user_id, &ct, &nonce)
                    .await?;
                s.to_vec()
            }
        };
        let b32 = base32_encode(&secret);
        let label = percent_label(&p.name);
        let uri = format!(
            "otpauth://totp/Rostdav:{label}?secret={b32}&issuer=Rostdav&algorithm=SHA1&digits=6&period=30"
        );
        let qr_svg = qr_svg(&uri)?;
        Ok(TwoFactorSetup {
            secret: b32,
            uri,
            qr_svg,
        })
    }

    /// Switches 2FA on after a valid code; returns the recovery codes (shown once).
    pub async fn two_factor_confirm(
        &self,
        p: &Principal,
        code: &str,
        ip: IpAddr,
    ) -> Result<Vec<String>> {
        Self::require_full(p)?;
        self.totp_guard(p.user_id, ip)?;
        let (secret, enabled, last) = self.secret_of(p.user_id).await?;
        if enabled {
            return Err(Error::Conflict("two-factor authentication is already on"));
        }
        let Some(step) = matching_step(&secret, code, last) else {
            self.totp_failed(p, ip, "setup").await;
            return Err(Error::Unauthenticated);
        };
        let (codes, hashes) = self.new_recovery_set().await?;
        self.inner.db.totp_enable(p.user_id, step, &hashes).await?;
        self.inner
            .totp_limiter
            .clear(&format!("totp:{}", p.user_id));
        self.audit(&p.name, "auth.2fa_enabled", "", Some(ip), json!({}))
            .await;
        Ok(codes)
    }

    /// Turns 2FA off. Needs the account password and a current code (or recovery code).
    pub async fn two_factor_disable(
        &self,
        s: &WebSession,
        password: &str,
        code: &str,
        ip: IpAddr,
    ) -> Result<()> {
        let p = &s.principal;
        self.reauthenticate(p, password, code, ip).await?;
        self.inner.db.totp_delete(p.user_id).await?;
        self.audit(&p.name, "auth.2fa_disabled", "", Some(ip), json!({}))
            .await;
        Ok(())
    }

    /// New recovery codes (the old ones stop working). Same checks as disabling.
    pub async fn two_factor_regenerate(
        &self,
        s: &WebSession,
        password: &str,
        code: &str,
        ip: IpAddr,
    ) -> Result<Vec<String>> {
        let p = &s.principal;
        self.reauthenticate(p, password, code, ip).await?;
        let (codes, hashes) = self.new_recovery_set().await?;
        self.inner.db.recovery_replace(p.user_id, &hashes).await?;
        self.audit(
            &p.name,
            "auth.2fa_codes_regenerated",
            "",
            Some(ip),
            json!({}),
        )
        .await;
        Ok(codes)
    }

    async fn reauthenticate(
        &self,
        p: &Principal,
        password: &str,
        code: &str,
        ip: IpAddr,
    ) -> Result<()> {
        Self::require_full(p)?;
        if !self.inner.db.totp_enabled(p.user_id).await? {
            return Err(Error::Conflict("two-factor authentication is off"));
        }
        self.authenticate_with(&p.name, password, ip, false).await?;
        self.totp_guard(p.user_id, ip)?;
        if self.verify_second_factor(p.user_id, code).await? {
            self.inner
                .totp_limiter
                .clear(&format!("totp:{}", p.user_id));
            Ok(())
        } else {
            self.totp_failed(p, ip, "reauth").await;
            Err(Error::Unauthenticated)
        }
    }

    /// Administrator reset for a locked-out user: removes secret and codes, ends browser sessions.
    pub async fn user_reset_two_factor(
        &self,
        actor: &crate::admin::Actor<'_>,
        name: &str,
    ) -> Result<bool> {
        actor.require_admin()?;
        let u = self.target_user(name).await?;
        let was = self.inner.db.totp_delete(u.id).await?;
        self.inner.db.delete_user_sessions(u.id).await?;
        self.audit(
            &actor.name(),
            "admin.2fa_reset",
            &u.name,
            None,
            json!({"was_on": was}),
        )
        .await;
        Ok(was)
    }

    // ---- sign-in ---------------------------------------------------------------------------------

    /// Ticket after a correct password when a second factor is needed (ADR 0007).
    pub(crate) fn second_factor_ticket(&self, user_id: i64, flow: &str) -> String {
        let expiry = crate::now_secs() + TICKET_SECS;
        let sig = mac(
            &self.inner.server_key,
            &["2fa", &user_id.to_string(), &expiry.to_string(), flow],
        );
        format!("{user_id}.{expiry}.{sig}")
    }

    /// The user the ticket was issued for, if it is genuine, current and for this flow.
    pub(crate) fn second_factor_ticket_user(&self, ticket: &str, flow: &str) -> Option<i64> {
        let mut it = ticket.splitn(3, '.');
        let (uid, expiry, sig) = (it.next()?, it.next()?, it.next()?);
        let exp: i64 = expiry.parse().ok()?;
        let id: i64 = uid.parse().ok()?;
        let ok = exp > crate::now_secs()
            && mac_eq(
                &mac(&self.inner.server_key, &["2fa", uid, expiry, flow]),
                sig,
            );
        ok.then_some(id)
    }

    /// Whether a ticket from the password step of the web sign-in is genuine and current.
    pub fn web_ticket_valid(&self, ticket: &str) -> bool {
        self.second_factor_ticket_user(ticket, "").is_some()
    }

    /// Whether a user has two-factor authentication on (for the administration page).
    pub async fn user_two_factor_enabled(
        &self,
        actor: &crate::admin::Actor<'_>,
        name: &str,
    ) -> Result<bool> {
        actor.require_admin()?;
        let u = self.target_user(name).await?;
        self.inner.db.totp_enabled(u.id).await
    }

    /// Second step of a browser sign-in: the ticket and a code (or recovery code).
    pub async fn web_second_factor(
        &self,
        ticket: &str,
        code: &str,
        ip: IpAddr,
        user_agent: &str,
    ) -> Result<(String, Principal)> {
        let user_id = self
            .second_factor_ticket_user(ticket, "")
            .ok_or(Error::Unauthenticated)?;
        let p = self.second_factor_principal(user_id, code, ip).await?;
        let cookie = self.open_session(&p, ip, user_agent).await?;
        self.audit(
            &p.name,
            "auth.login",
            "web",
            Some(ip),
            json!({"second_factor": true}),
        )
        .await;
        Ok((cookie, p))
    }

    /// Checks the code for the user behind a ticket and returns their principal.
    pub(crate) async fn second_factor_principal(
        &self,
        user_id: i64,
        code: &str,
        ip: IpAddr,
    ) -> Result<Principal> {
        let u = self
            .inner
            .db
            .find_user_by_id(user_id)
            .await?
            .filter(|u| !u.disabled)
            .ok_or(Error::Unauthenticated)?;
        let p = Principal {
            user_id: u.id,
            name: u.name,
            is_admin: u.is_admin,
            via: Via::AccountPassword,
            scope: Scope::Full,
        };
        self.totp_guard(p.user_id, ip)?;
        if self.verify_second_factor(p.user_id, code).await? {
            self.inner
                .totp_limiter
                .clear(&format!("totp:{}", p.user_id));
            Ok(p)
        } else {
            self.totp_failed(&p, ip, "login").await;
            Err(Error::Unauthenticated)
        }
    }

    // ---- shared helpers -----------------------------------------------------------------------------

    /// Per-user and per-address block for code entry.
    fn totp_guard(&self, user_id: i64, ip: IpAddr) -> Result<()> {
        let retry = |s| Error::RateLimited {
            retry_after_secs: s,
        };
        self.inner
            .limiter
            .check(&format!("ip:{ip}"))
            .map_err(retry)?;
        self.inner
            .totp_limiter
            .check(&format!("totp:{user_id}"))
            .map_err(retry)
    }

    async fn totp_failed(&self, p: &Principal, ip: IpAddr, step: &str) {
        let by_user = self
            .inner
            .totp_limiter
            .record_failure(&format!("totp:{}", p.user_id));
        let by_ip = self.inner.limiter.record_failure(&format!("ip:{ip}"));
        self.audit(
            &p.name,
            "auth.login_failed",
            "",
            Some(ip),
            json!({"step": step, "second_factor": true}),
        )
        .await;
        if by_user || by_ip {
            self.audit(
                &p.name,
                "auth.locked",
                "",
                Some(ip),
                json!({"key": if by_user { "2fa" } else { "address" }}),
            )
            .await;
        }
    }

    /// A current TOTP code (single use) or an unused recovery code (single use).
    async fn verify_second_factor(&self, user_id: i64, input: &str) -> Result<bool> {
        let (secret, enabled, last) = self.secret_of(user_id).await?;
        if !enabled {
            return Ok(false);
        }
        let digits = input.trim().replace(' ', "");
        if digits.len() == 6 && digits.bytes().all(|b| b.is_ascii_digit()) {
            return match matching_step(&secret, &digits, last) {
                // `accept_step` is atomic: the same code cannot pass twice, even in parallel
                Some(step) => self.inner.db.totp_accept_step(user_id, step).await,
                None => Ok(false),
            };
        }
        let typed = normalize_code(input);
        if typed.len() != 12 {
            return Ok(false);
        }
        for (id, hash) in self.inner.db.recovery_unused(user_id).await? {
            let t = typed.clone();
            let ok = tokio::task::spawn_blocking(move || verify_password(&t, &hash))
                .await
                .map_err(Error::internal)?;
            if ok {
                return self.inner.db.recovery_use(id).await;
            }
        }
        Ok(false)
    }

    async fn new_recovery_set(&self) -> Result<(Vec<String>, Vec<String>)> {
        let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| new_recovery_code()).collect();
        let to_hash = codes.clone();
        let hashes = tokio::task::spawn_blocking(move || {
            to_hash
                .iter()
                .map(|c| hash_password(&normalize_code(c)))
                .collect::<Result<Vec<_>>>()
        })
        .await
        .map_err(Error::internal)??;
        Ok((codes, hashes))
    }

    /// Housekeeping: unconfirmed setups.
    pub(crate) async fn purge_two_factor(&self) -> Result<()> {
        self.inner
            .db
            .totp_purge_pending(PENDING_MAX_AGE_SECS)
            .await?;
        Ok(())
    }
}

/// The step (within ±1 of now, larger than `last`) whose code equals `code`.
fn matching_step(secret: &[u8], code: &str, last: i64) -> Option<i64> {
    let typed = code.trim().replace(' ', "");
    if typed.len() != 6 || !typed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = now_step();
    let mut found = None;
    // every candidate is compared (no early exit on the first match)
    for step in [now - 1, now, now + 1] {
        let want = format!("{:06}", hotp(secret, u64::try_from(step).unwrap_or(0)));
        if mac_eq(&want, &typed) && step > last {
            found = Some(found.map_or(step, |f: i64| f.max(step)));
        }
    }
    found
}

fn percent_label(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn qr_svg(uri: &str) -> Result<String> {
    let code = qrcode::QrCode::new(uri.as_bytes()).map_err(|_| Error::Unavailable)?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(220, 220)
        .quiet_zone(true)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    // drop the XML declaration: the SVG is embedded in HTML
    Ok(svg
        .split_once("?>")
        .map_or(svg.clone(), |(_, rest)| rest.trim_start().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6238_vectors() {
        // RFC 6238 appendix B, SHA-1, secret "12345678901234567890"; the 8-digit
        // values end in the 6 digits we use.
        let secret = b"12345678901234567890";
        for (t, expected) in [
            (59u64, 287_082u32),
            (1_111_111_109, 81_804),
            (1_111_111_111, 50_471),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
        ] {
            assert_eq!(hotp(secret, t / STEP_SECS), expected, "t={t}");
        }
    }

    #[test]
    fn base32_matches_rfc_4648() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn encryption_roundtrip_and_binding() {
        let key = [7u8; 32];
        let (ct, nonce) = encrypt(&key, 5, b"secret-bytes").expect("encrypt");
        assert_ne!(&ct[..12], b"secret-bytes");
        assert_eq!(
            decrypt(&key, 5, &ct, &nonce).expect("decrypt"),
            b"secret-bytes"
        );
        assert!(decrypt(&key, 6, &ct, &nonce).is_err(), "bound to the user");
        assert!(decrypt(&[8u8; 32], 5, &ct, &nonce).is_err(), "wrong key");
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(
            decrypt(&key, 5, &bad, &nonce).is_err(),
            "tampering is detected"
        );
    }

    #[test]
    fn recovery_codes_look_right_and_normalise() {
        let c = new_recovery_code();
        assert_eq!(c.len(), 14);
        assert!(
            c.split('-')
                .all(|g| g.len() == 4 && g.bytes().all(|b| CODE_ALPHABET.contains(&b))),
            "{c}"
        );
        assert_eq!(
            normalize_code(&format!(" {} ", c.to_uppercase())),
            c.replace('-', "")
        );
        assert_ne!(new_recovery_code(), new_recovery_code());
    }

    #[test]
    fn matching_step_window_and_replay() {
        let secret = b"12345678901234567890";
        let now = now_step();
        let code = |s: i64| format!("{:06}", hotp(secret, u64::try_from(s).expect("step")));
        assert_eq!(matching_step(secret, &code(now), 0), Some(now));
        assert_eq!(matching_step(secret, &code(now - 1), 0), Some(now - 1));
        assert_eq!(matching_step(secret, &code(now + 1), 0), Some(now + 1));
        assert_eq!(
            matching_step(secret, &code(now - 2), 0),
            None,
            "outside the window"
        );
        assert_eq!(matching_step(secret, &code(now + 2), 0), None);
        assert_eq!(matching_step(secret, &code(now), now), None, "already used");
        assert_eq!(
            matching_step(secret, &code(now - 1), now),
            None,
            "older than the last used"
        );
        for bad in ["", "12345", "1234567", "abcdef", "12 34 5"] {
            assert_eq!(matching_step(secret, bad, 0), None, "{bad}");
        }
    }

    #[test]
    fn otpauth_label_is_escaped_and_qr_is_svg() {
        assert_eq!(percent_label("anna.b-c_d"), "anna.b-c_d");
        assert_eq!(percent_label("a b:c/ü"), "a%20b%3Ac%2F%C3%BC");
        let svg = qr_svg("otpauth://totp/Rostdav:anna?secret=ABC").expect("qr");
        assert!(
            svg.starts_with("<svg") && !svg.contains("<?xml"),
            "{}",
            &svg[..40.min(svg.len())]
        );
        assert!(!svg.contains("style="), "no inline styles (CSP)");
    }

    // ---- service level ------------------------------------------------------------------

    use rostdav_meta::Db;
    use rostdav_storage::LocalStore;

    const PW: &str = "korrekt-pferd-batterie";
    const IP: &str = "192.0.2.10";

    async fn state(key: TotpKeySource) -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalStore::open(dir.path().join("data"))
            .await
            .expect("store");
        let db = Db::open(&Db::default_url(store.root())).await.expect("db");
        db.migrate().await.expect("migrate");
        let key = match key {
            TotpKeySource::File(_) => TotpKeySource::File(dir.path().join("totp.key")),
            other => other,
        };
        let st = AppState::new(db, store)
            .await
            .expect("state")
            .with_security(crate::SecurityOptions { totp_key: key });
        (dir, st)
    }

    fn ip() -> IpAddr {
        IP.parse().expect("ip")
    }

    async fn session_for(st: &AppState, user: &str) -> WebSession {
        let SignIn::Done { principal, .. } =
            st.web_sign_in(user, PW, ip(), "ua").await.expect("sign in")
        else {
            panic!("no second factor expected")
        };
        WebSession { id: 1, principal }
    }

    /// The code an authenticator app would show for a setup, and the base32 secret.
    fn current_code(setup: &TwoFactorSetup, offset: i64) -> String {
        let raw = decode_b32(&setup.secret);
        // one base step per test binary: a 30 s boundary in the middle of a test must not turn
        // "the same code again" into a new, valid code
        static BASE: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
        let base = *BASE.get_or_init(now_step);
        format!(
            "{:06}",
            hotp(&raw, u64::try_from(base + offset).expect("step"))
        )
    }

    fn decode_b32(s: &str) -> Vec<u8> {
        let (mut buf, mut bits, mut out) = (0u32, 0u32, Vec::new());
        for c in s.bytes() {
            let v = B32.iter().position(|b| *b == c).expect("base32") as u32;
            buf = (buf << 5) | v;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push(((buf >> bits) & 0xff) as u8);
            }
        }
        out
    }

    async fn enabled(st: &AppState, user: &str) -> (WebSession, TwoFactorSetup, Vec<String>) {
        st.add_user(user, PW, false).await.expect("user");
        let s = session_for(st, user).await;
        let setup = st.two_factor_begin(&s.principal).await.expect("begin");
        let codes = st
            .two_factor_confirm(&s.principal, &current_code(&setup, 0), ip())
            .await
            .expect("confirm");
        (s, setup, codes)
    }

    #[tokio::test]
    async fn without_a_key_two_factor_is_unavailable() {
        let (_d, st) = state(TotpKeySource::None).await;
        st.add_user("anna", PW, false).await.expect("user");
        let s = session_for(&st, "anna").await;
        assert!(
            !st.two_factor_status(&s.principal)
                .await
                .expect("status")
                .available
        );
        assert!(st.two_factor_begin(&s.principal).await.is_err());
    }

    #[tokio::test]
    async fn setup_login_second_step_and_replay() {
        let (dir, st) = state(TotpKeySource::File(PathBuf::new())).await;
        let (s, setup, codes) = enabled(&st, "anna").await;
        assert_eq!(codes.len(), RECOVERY_CODES);
        let status = st.two_factor_status(&s.principal).await.expect("status");
        assert!(status.enabled && status.recovery_left == 10);
        // the key file exists, is private and is not the secret
        let meta = std::fs::metadata(dir.path().join("totp.key")).expect("key file");
        assert_eq!(meta.len(), 32);
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
        // the database holds ciphertext only
        let row = st
            .inner
            .db
            .totp_get(s.principal.user_id)
            .await
            .expect("row")
            .expect("some");
        assert!(
            !row.secret_enc
                .windows(8)
                .any(|w| w == &decode_b32(&setup.secret)[..8])
        );
        // starting a setup while 2FA is on is refused
        assert!(st.two_factor_begin(&s.principal).await.is_err());

        // password step now needs a second step; no session exists yet
        let SignIn::SecondFactor { ticket } = st
            .web_sign_in("anna", PW, ip(), "ua")
            .await
            .expect("step 1")
        else {
            panic!("second factor expected")
        };
        // wrong code, replayed code (the one used for the setup), malformed ticket
        assert!(
            st.web_second_factor(&ticket, "000000", ip(), "ua")
                .await
                .is_err()
        );
        assert!(
            st.web_second_factor(&ticket, &current_code(&setup, 0), ip(), "ua")
                .await
                .is_err(),
            "setup code was used"
        );
        assert!(
            st.web_second_factor("garbage", "123456", ip(), "ua")
                .await
                .is_err()
        );
        let forged = ticket.replace(&format!("{}.", s.principal.user_id), "999.");
        assert!(
            st.web_second_factor(&forged, &current_code(&setup, 1), ip(), "ua")
                .await
                .is_err()
        );
        // the next step's code works once
        let (cookie, p) = st
            .web_second_factor(&ticket, &current_code(&setup, 1), ip(), "ua")
            .await
            .expect("step 2");
        assert_eq!(p.name, "anna");
        assert!(st.web_session(&cookie).await.expect("lookup").is_some());
        assert!(
            st.web_second_factor(&ticket, &current_code(&setup, 1), ip(), "ua")
                .await
                .is_err(),
            "same code twice"
        );
    }

    #[tokio::test]
    async fn ticket_expires_and_belongs_to_one_flow() {
        let (_d, st) = state(TotpKeySource::Fixed([3u8; 32])).await;
        let (s, _setup, _codes) = enabled(&st, "anna").await;
        let uid = s.principal.user_id;
        let t = st.second_factor_ticket(uid, "");
        assert_eq!(st.second_factor_ticket_user(&t, ""), Some(uid));
        assert_eq!(
            st.second_factor_ticket_user(&t, "flow-1"),
            None,
            "a web ticket is no flow ticket"
        );
        let f = st.second_factor_ticket(uid, "flow-1");
        assert_eq!(st.second_factor_ticket_user(&f, "flow-1"), Some(uid));
        assert_eq!(st.second_factor_ticket_user(&f, "flow-2"), None);
        assert_eq!(st.second_factor_ticket_user(&f, ""), None);
        // expired: same MAC construction with a past expiry is not accepted
        let past = format!(
            "{uid}.1.{}",
            mac(&st.inner.server_key, &["2fa", &uid.to_string(), "1", ""])
        );
        assert_eq!(st.second_factor_ticket_user(&past, ""), None);
    }

    #[tokio::test]
    async fn recovery_codes_work_once_and_count_down() {
        let (_d, st) = state(TotpKeySource::Fixed([4u8; 32])).await;
        let (s, _setup, codes) = enabled(&st, "anna").await;
        let SignIn::SecondFactor { ticket } = st
            .web_sign_in("anna", PW, ip(), "ua")
            .await
            .expect("step 1")
        else {
            panic!()
        };
        // typed with upper case and spaces instead of dashes
        let typed = codes[0].to_uppercase().replace('-', " ");
        st.web_second_factor(&ticket, &typed, ip(), "ua")
            .await
            .expect("recovery code");
        assert_eq!(
            st.two_factor_status(&s.principal)
                .await
                .expect("s")
                .recovery_left,
            9
        );
        assert!(
            st.web_second_factor(&ticket, &codes[0], ip(), "ua")
                .await
                .is_err(),
            "used code"
        );
        st.web_second_factor(&ticket, &codes[1], ip(), "ua")
            .await
            .expect("another code");
        assert!(
            st.web_second_factor(&ticket, "aaaa-bbbb-cccc", ip(), "ua")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn five_wrong_codes_lock_the_second_step() {
        let (_d, st) = state(TotpKeySource::Fixed([5u8; 32])).await;
        let (s, setup, _codes) = enabled(&st, "anna").await;
        let SignIn::SecondFactor { ticket } = st
            .web_sign_in("anna", PW, ip(), "ua")
            .await
            .expect("step 1")
        else {
            panic!()
        };
        for _ in 0..5 {
            assert!(matches!(
                st.web_second_factor(&ticket, "000000", ip(), "ua").await,
                Err(Error::Unauthenticated)
            ));
        }
        // locked: even the right code is refused now, with a retry time
        let r = st
            .web_second_factor(&ticket, &current_code(&setup, 1), ip(), "ua")
            .await;
        assert!(matches!(r, Err(Error::RateLimited { .. })), "{r:?}");
        // another user is not affected (different address, own counter)
        let (_s2, setup2, _c2) = enabled(&st, "bob").await;
        let SignIn::SecondFactor { ticket: t2 } = st
            .web_sign_in("bob", PW, "192.0.2.77".parse().expect("ip"), "ua")
            .await
            .expect("step 1")
        else {
            panic!()
        };
        st.web_second_factor(
            &t2,
            &current_code(&setup2, 1),
            "192.0.2.77".parse().expect("ip"),
            "ua",
        )
        .await
        .expect("bob signs in");
        drop(s);
    }

    #[tokio::test]
    async fn account_password_is_refused_for_dav_but_app_passwords_work() {
        let (_d, st) = state(TotpKeySource::Fixed([6u8; 32])).await;
        st.add_user("anna", PW, false).await.expect("user");
        let before = st.authenticate("anna", PW, ip()).await;
        assert!(
            before.is_ok(),
            "no 2FA yet: the account password works on WebDAV"
        );
        let s = session_for(&st, "anna").await;
        let app = st
            .device_create(&s.principal, "phone")
            .await
            .expect("device");
        let setup = st.two_factor_begin(&s.principal).await.expect("begin");
        // while the setup is only in progress nothing changes
        assert!(st.authenticate("anna", PW, ip()).await.is_ok());
        st.two_factor_confirm(&s.principal, &current_code(&setup, 0), ip())
            .await
            .expect("confirm");
        assert!(matches!(
            st.authenticate("anna", PW, ip()).await,
            Err(Error::Unauthenticated)
        ));
        assert!(
            st.authenticate("anna", &app, ip()).await.is_ok(),
            "app passwords bypass 2FA"
        );
        // the browser password step is unaffected by that rule
        assert!(matches!(
            st.web_sign_in("anna", PW, ip(), "ua").await,
            Ok(SignIn::SecondFactor { .. })
        ));
    }

    #[tokio::test]
    async fn disable_and_regenerate_need_password_and_code() {
        let (_d, st) = state(TotpKeySource::Fixed([8u8; 32])).await;
        let (s, setup, codes) = enabled(&st, "anna").await;
        // wrong password / wrong code: nothing changes
        assert!(
            st.two_factor_disable(&s, "wrong-password-1", &current_code(&setup, 1), ip())
                .await
                .is_err()
        );
        assert!(st.two_factor_disable(&s, PW, "000000", ip()).await.is_err());
        assert!(st.two_factor_status(&s.principal).await.expect("s").enabled);
        // regenerate with a recovery code: old codes stop working
        let new = st
            .two_factor_regenerate(&s, PW, &codes[0], ip())
            .await
            .expect("regenerate");
        assert_eq!(new.len(), 10);
        assert_ne!(new[0], codes[0]);
        let SignIn::SecondFactor { ticket } = st
            .web_sign_in("anna", PW, ip(), "ua")
            .await
            .expect("step 1")
        else {
            panic!()
        };
        assert!(
            st.web_second_factor(&ticket, &codes[1], ip(), "ua")
                .await
                .is_err(),
            "old code"
        );
        st.web_second_factor(&ticket, &new[1], ip(), "ua")
            .await
            .expect("new code");
        // disable with the current TOTP code
        st.two_factor_disable(&s, PW, &current_code(&setup, 1), ip())
            .await
            .expect("disable");
        assert!(!st.two_factor_status(&s.principal).await.expect("s").enabled);
        assert!(matches!(
            st.web_sign_in("anna", PW, ip(), "ua").await,
            Ok(SignIn::Done { .. })
        ));
        assert!(
            st.two_factor_disable(&s, PW, "123456", ip()).await.is_err(),
            "already off"
        );
    }

    #[tokio::test]
    async fn administrator_reset_and_events_without_secrets() {
        let (_d, st) = state(TotpKeySource::Fixed([9u8; 32])).await;
        let (s, setup, codes) = enabled(&st, "anna").await;
        st.add_user("root", PW, true).await.expect("admin");
        let admin = session_for(&st, "root").await;
        // a normal user cannot reset
        assert!(
            st.user_reset_two_factor(&crate::admin::Actor::User(&s.principal), "anna")
                .await
                .is_err()
        );
        assert!(
            st.user_reset_two_factor(&crate::admin::Actor::User(&admin.principal), "nobody")
                .await
                .is_err()
        );
        let was = st
            .user_reset_two_factor(&crate::admin::Actor::User(&admin.principal), "anna")
            .await
            .expect("reset");
        assert!(was);
        assert!(!st.two_factor_status(&s.principal).await.expect("s").enabled);
        assert!(matches!(
            st.web_sign_in("anna", PW, ip(), "ua").await,
            Ok(SignIn::Done { .. })
        ));
        // the event log records the actions and none of the secrets
        let ev = st
            .audit_events(&crate::admin::Actor::Cli, 0)
            .await
            .expect("events");
        let text = format!("{ev:?}");
        assert!(text.contains("auth.2fa_enabled") && text.contains("admin.2fa_reset"));
        assert!(
            !text.contains(&setup.secret)
                && !text.contains(&codes[0])
                && !text.contains(&current_code(&setup, 0))
        );
    }

    #[tokio::test]
    async fn login_flow_asks_for_the_code() {
        let (_d, st) = state(TotpKeySource::Fixed([1u8; 32])).await;
        let (_s, setup, _codes) = enabled(&st, "anna").await;
        let flow = st
            .start_login_flow("Nextcloud Android")
            .await
            .expect("flow");
        let login = flow.login_token.clone();
        let csrf = st.flow_csrf(&login, "allow");
        let crate::FlowStep::SecondFactor { ticket } = st
            .flow_allow(&login, &csrf, "anna", PW, ip())
            .await
            .expect("step 1")
        else {
            panic!("second factor expected")
        };
        // nothing granted yet
        assert!(
            st.poll_login_flow(&flow.poll_token)
                .await
                .expect("poll")
                .is_none()
        );
        // a web ticket does not work for the flow, a wrong code neither
        let web_ticket = st.second_factor_ticket(1, "");
        assert!(
            st.flow_second_factor(&login, &csrf, &web_ticket, &current_code(&setup, 1), ip())
                .await
                .is_err()
        );
        assert!(
            st.flow_second_factor(&login, &csrf, &ticket, "000000", ip())
                .await
                .is_err()
        );
        assert!(
            st.flow_second_factor(&login, "forged", &ticket, &current_code(&setup, 1), ip())
                .await
                .is_err()
        );
        st.flow_second_factor(&login, &csrf, &ticket, &current_code(&setup, 1), ip())
            .await
            .expect("granted");
        let granted = st
            .poll_login_flow(&flow.poll_token)
            .await
            .expect("poll")
            .expect("credentials");
        assert_eq!(granted.login_name, "anna");
    }
}
