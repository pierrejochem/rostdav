# ADR 0003: App passwords, Login Flow v2 and brute-force protection

- Status: **Proposed** — implemented in M4 on the project owner's "go"; approval point 3 (authentication, token format) asks for review. Changing it later needs a new approval.
- Date: 2026-10-21

## Context

Nextcloud apps sign in through Login Flow v2 and afterwards send `username` + *app password* via HTTP Basic on every request (`docs/compatibility.md`, fixtures `02-login-flow-v2/`). Rostdav must create, check, list and revoke these passwords, show a login page for the flow, and resist password guessing.

## Decision

### App passwords

- 72 random characters `[A-Za-z0-9]` from the OS random source (rejection sampling, no modulo bias). Shown once, never stored in clear.
- Stored as `BLAKE3(token)` (hex) in `app_passwords.token_hash`, `UNIQUE`. The token has ~428 bits of entropy, so a fast hash is sufficient and allows an indexed lookup; Argon2 is reserved for human-chosen passwords. The lookup is by hash, so no secret-dependent comparison happens in application code.
- A Basic credential is accepted if (a) an app password of *that user* matches, else (b) the account password matches (Argon2id). Option (b) will be switchable per user when 2FA arrives (M12).
- `last_used_at` is updated at most once per minute per password.
- Revocation deletes the row; the next request fails with 401.

### Login Flow v2

- `POST /index.php/login/v2` (also `/login/v2`) creates a flow with two random 128-character tokens: the *poll token* (given to the app) and the *login token* (in the URL opened in the browser). Only their BLAKE3 hashes are stored. A flow expires after 20 minutes.
- Browser: `GET /login/v2/flow/{loginToken}` shows one page (design: `design/mockups/web-ui/Login.html`) with the client name, user name and password fields, "Sign in and allow access" and "Deny". `POST` to the same URL with the CSRF value checks the account password (rate limited; app passwords are not accepted here) and grants, or closes the flow on "Deny". The CSRF value is a BLAKE3 keyed hash (key = `settings.server_key`, 32 random bytes created on first start) over the purpose and the login token. No cookies or sessions exist yet (they arrive with the web UI, M11). Two-factor login (M12) will add a second step; its design (`Login2FA.dc.html`) will need a signed ticket then.
- On grant the app password is created; its clear value is kept in `login_flows.app_password` until the first successful poll (or expiry) and then deleted. While it is stored, anyone with read access to the database could use it; encrypting it with the server key is a possible hardening.
- `POST /login/v2/poll` with the poll token answers 404 while pending or unknown, and 200 `{server, loginName, appPassword}` once, then the flow is deleted.
- Pages send `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'`, `Cache-Control: no-store`.

### Brute-force protection

- In-memory sliding window per client IP and per user name: 10 failed credential checks in 15 minutes block further attempts for that key until the window ends (HTTP 429 with `Retry-After`). Successful logins clear the user key, not the IP key.
- **Amendment (Phase 5, found by the authorization matrix test):** the per-user block applies to the guessable secret only, the account password. An app password (428 bits, not guessable) is accepted even while the user key is blocked, and its success no longer clears the user key. Before, anyone could lock a victim's phone and sync clients out by guessing the account password ten times from different addresses, and a device syncing during an attack lifted the lock for the attacker. The per-address block still applies to every credential.
- Applies to Basic auth on WebDAV/OCS and the login form. The poll endpoint is not limited: its 128-character token cannot be guessed.
- The client IP is the socket peer unless that peer is listed in `server.trusted_proxies`; then the right-most `X-Forwarded-For` entry that is not a trusted proxy is used.
- State is lost on restart and not shared between instances; acceptable for a single-process server, revisit for PostgreSQL deployments.

## Consequences

- Revoking a device works immediately and is testable.
- A leaked database yields no usable app passwords except tokens of flows that were granted but not yet polled.
- Restarting the server resets rate limits.
