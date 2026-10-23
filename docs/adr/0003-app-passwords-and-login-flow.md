# ADR 0003: App passwords, Login Flow v2 and brute-force protection

- Status: **Accepted** by the project owner on 2026-10-23 (approval point 3), after the Phase 5 amendment and the review changes below. Changing it later needs a new approval.
- Date: 2026-10-21 (implemented in M4; amended in Phase 5 and on review)

## Context

Nextcloud apps sign in through Login Flow v2 and afterwards send `username` + *app password* via HTTP Basic on every request (`docs/compatibility.md`, fixtures `02-login-flow-v2/`). Rostdav must create, check, list and revoke these passwords, show a login page for the flow, and resist password guessing.

## Decision

### App passwords

- 72 random characters `[A-Za-z0-9]` from the OS random source (rejection sampling, no modulo bias). Shown once, never stored in clear.
- Stored as `BLAKE3(token)` (hex) in `app_passwords.token_hash`, `UNIQUE`. The token has ~428 bits of entropy, so a fast hash is sufficient and allows an indexed lookup; Argon2 is reserved for human-chosen passwords. The lookup is by hash, so no secret-dependent comparison happens in application code.
- A Basic credential is accepted if (a) an app password of *that user* matches, else (b) the account password matches (Argon2id). With two-factor on, (b) is refused for WebDAV/OCS and only app passwords work (ADR 0007).
- `last_used_at` is updated at most once per minute per password.
- Revocation deletes the row; the next request fails with 401.

### Login Flow v2

- `POST /index.php/login/v2` (also `/login/v2`) creates a flow with two random 128-character tokens: the *poll token* (given to the app) and the *login token* (in the URL opened in the browser). Only their BLAKE3 hashes are stored. A flow expires after 20 minutes.
- Browser: `GET /login/v2/flow/{loginToken}` shows one page (design: `design/mockups/web-ui/Login.html`) with the client name, user name and password fields, "Sign in and allow access" and "Deny". `POST` to the same URL with the CSRF value checks the account password (rate limited; app passwords are not accepted here) and grants, or closes the flow on "Deny". The CSRF value is a BLAKE3 keyed hash (key = `settings.server_key`, 32 random bytes created on first start) over the purpose and the login token. The flow page needs no cookie or session. With two-factor on, a second step asks for the code; the password step hands over a MAC-signed ticket (ADR 0007).
- On grant the app password is created; until the first successful poll (or expiry) it is kept in `login_flows.app_password` **encrypted**: ChaCha20-Poly1305 with a key derived from `settings.server_key` (BLAKE3 `derive_key`), a random nonce, and the poll token's hash as associated data. Stored as `base64(nonce ‖ ciphertext)`. The clear value exists only in memory and in the poll response. A read-only copy of the database yields no usable app password; a copy of the database plus the server key still does, until the flow is polled or expires.
- `POST /login/v2/poll` with the poll token answers 404 while pending or unknown, and 200 `{server, loginName, appPassword}` once, then the flow is deleted.
- `POST /login/v2` needs no sign-in, so at most 1000 flows may be open (not expired, not granted or polled); beyond that it answers 429 with `Retry-After: 60`. Expired flows are purged on every start. Trade-off: someone can fill the table for 20 minutes and keep new devices from starting a sign-in; existing sessions and app passwords are not affected. A per-address limit would need a schema change and was not worth it for a single-process server.
- Pages send `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'`, `Cache-Control: no-store`.

### Brute-force protection

- In-memory sliding window per client IP and per user name: 10 failed credential checks in 15 minutes block further attempts for that key until the window ends (HTTP 429 with `Retry-After`). Successful logins clear the user key, not the IP key.
- **Amendment (Phase 5, found by the authorization matrix test):** the per-user block applies to the guessable secret only, the account password. An app password (428 bits, not guessable) is accepted even while the user key is blocked, and its success no longer clears the user key. Before, anyone could lock a victim's phone and sync clients out by guessing the account password ten times from different addresses, and a device syncing during an attack lifted the lock for the attacker. The per-address block still applies to every credential.
- Applies to Basic auth on WebDAV/OCS and the login form. The poll endpoint is not limited: its 128-character token cannot be guessed.
- The client IP is the socket peer unless that peer is listed in `server.trusted_proxies`; then the right-most `X-Forwarded-For` entry that is not a trusted proxy is used.
- A blocked address is blocked for valid app passwords too (the address check runs first). Ten failures from a shared address (NAT) can therefore lock out that user's devices behind it for the rest of the window. Accepted: the address limit is the only defence against one source guessing across many user names.
- State is lost on restart and not shared between instances; acceptable for a single-process server, revisit for PostgreSQL deployments.

## Limits

- No limit on the number of app passwords per user. Each is one row; the user lists and revokes them in the web UI (Devices).
- The Login Flow page shows the app's whole User-Agent as the client name (bounded to 128 characters, HTML-escaped).

## Consequences

- Revoking a device works immediately and is testable.
- A leaked database yields no usable app passwords. Tokens of flows that were granted but not yet polled are encrypted; they are usable only together with the server key.
- Restarting the server resets rate limits.
