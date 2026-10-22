# ADR 0007: Optional two-factor authentication (TOTP)

- Status: **Proposed** (approval point 3: change to authentication)
- Date: 2026-10-23
- Inputs: requirements in [instructions.md](../instructions.md) (P2, "Optional two-factor authentication"), [ADR 0003](0003-app-passwords-and-login-flow.md), [ADR 0006](0006-web-interface.md), the designs "Second factor" and the two-factor card on "Devices & security" in `design/mockups/web-ui/`.

## Context

Browser sign-in (web interface and the Login Flow v2 page) is protected by the account password only. Users who want more can add a time-based one-time password (TOTP, RFC 6238). Apps keep working unchanged because they sign in with app passwords, which bypass 2FA as in Nextcloud.

## Decision

### What the user gets

- Off by default. Devices & security › Two-factor authentication › Set up: the server creates a secret (160 bits), shows it as a QR code (`otpauth://totp/Rostdav:<user>?secret=…&issuer=Rostdav`) and as text. 2FA becomes active only after the user enters a valid code. At that moment ten recovery codes are shown once.
- Browser sign-in then has two steps. Step 1 is the existing form. If the password is right and 2FA is active, no session is created yet; the user gets a short-lived **ticket** and the page "Confirm your sign-in" (design: Second factor) asks for the six-digit code or, via a link, a recovery code. Only then is the session created. The Login Flow v2 page does the same before it grants the app password.
- Disabling 2FA and creating new recovery codes require the account password and a current code (or a recovery code).
- The page shows how many recovery codes are left.
- An administrator can reset 2FA for a locked-out user (web and `rostdav admin user reset-2fa <name>`); the user's browser sessions end, app passwords stay. Logged as `admin.2fa_reset`.

### Rules

- TOTP: HMAC-SHA1, 6 digits, 30 s step (what authenticator apps support), window ±1 step. Each code works once: the server stores the last accepted step per user and accepts only a larger one (replay protection).
- Recovery codes: ten random codes of 12 characters (`xxxx-xxxx-xxxx`, no look-alike characters), stored only as Argon2id hashes, each usable once.
- **Wrong codes** count like wrong passwords: five failures per user lock the second step for 15 minutes (existing limiter, key `totp:<user>`), plus the per-address limit. Codes and secrets are never logged.
- **Ticket:** stateless, `MAC(server_key, "2fa", user id, expiry, flow token or empty)` plus expiry 5 minutes, in an HttpOnly `SameSite=Lax` cookie `rostdav_2fa` (path `/login`). It proves "the password was right" and nothing else; it cannot be used on any other route. A ticket is not single-use by itself, but the code check is rate limited and a successful code is single-use.
- **Account password on WebDAV/OCS:** if 2FA is active for the user, Basic authentication with the *account password* is rejected there (401, same message as a wrong password); only app passwords are accepted. This is the switch ADR 0003 announced for M12.
- **Apps:** app passwords and Login Flow polling are unchanged. Nothing is added to the capabilities, so the Nextcloud apps do not start a 2FA flow of their own. Whether the real app copes with an account that has 2FA enabled is part of M6 (test with the emulator) and will be recorded in `docs/compatibility.md`; the reference server was not run with 2FA.

### Storage

- Migration `0009_two_factor.sql`: `totp(user_id PRIMARY KEY → users ON DELETE CASCADE, secret_enc BLOB NOT NULL, nonce BLOB NOT NULL, created_at, enabled_at NULL, last_step INTEGER NOT NULL DEFAULT 0)` and `recovery_codes(id, user_id → users ON DELETE CASCADE, code_hash TEXT NOT NULL, used_at NULL)`. A `totp` row without `enabled_at` is a setup in progress; it is replaced by the next setup and removed after 1 hour.
- The secret is encrypted with ChaCha20-Poly1305 (random 96-bit nonce, user id as associated data). The key is **not in the database**: 32 random bytes in the file `<data_dir>/totp.key` (mode 0600, created when the first setup starts), or from `ROSTDAV_SECURITY__TOTP_KEY` (base64) / `[security] totp_key_file` if configured. A copy of the database alone therefore does not reveal the secrets. The key file must be backed up with the data (documented in `docs/admin.md`); losing it disables 2FA for everyone (users can still sign in with the password after an administrator resets 2FA).

### Dependencies (justification)

- `chacha20poly1305` (RustCrypto, MIT/Apache): authenticated encryption of the secret.
- `hmac` + `sha1` (RustCrypto, MIT/Apache; already in the lock file through other crates): TOTP.
- `qrcode` (MIT/Apache, pure Rust): renders the QR code as inline SVG on the server, so no script and no external service is needed and the CSP stays as it is.
- Base32 (RFC 4648) for the secret is small enough to write ourselves.

### Out of scope

- "Require 2FA for everyone" and users being forced to set it up at the next sign-in (admin setting; later, with the retention rules in M13).
- WebAuthn / security keys, SMS, e-mail codes.
- Remembering a browser ("trust this device for 30 days").

## Consequences

- The sign-in is the most security-sensitive code; the acceptance criteria are tests for: no session before the code, wrong/expired/replayed code, rate limit and lock, recovery code single use, ticket forged/expired/for another user or flow, ticket not accepted elsewhere, password rejected on WebDAV/OCS with 2FA on and app password still accepted, disable/regenerate need password and code, admin reset, secrets absent from logs and database, Login Flow v2 with 2FA.
- Users who sign in to WebDAV clients with their account password (instead of an app password) will be locked out of those clients when they enable 2FA; the setup page says so.
- A lost key file or a lost authenticator without recovery codes needs an administrator.
