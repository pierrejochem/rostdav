# ADR 0014: Push sign-in approval with the RustMFA app

- Status: **Accepted** by the project owner on 2026-11-08 as proposed (approval point 3 granted)
- Date: 2026-11-08
- Inputs: [ADR 0003](0003-app-passwords-and-login-flow.md), [ADR 0007](0007-two-factor-authentication.md), [ADR 0008](0008-metadata-database-turso.md); the RustMFA design spec (`rostdav-mfa` repository, `docs/superpowers/specs/2026-11-08-rustmfa-android-design.md`), the machine-readable contract (`contract/openapi/rustmfa-v1.yaml`) and its test vectors (`contract/vectors/v1.json`).

## Context

Browser sign-in can already use a TOTP code as second factor (ADR 0007). The owner builds a self-hosted authenticator app, RustMFA (Android first), for this server only. The app should let a user approve a sign-in on the phone: the server sends a hint, the user compares a number and confirms with biometrics, the app returns a signed answer. Microsoft and Google Authenticator cannot do this for a custom server, so an own app and an own device API are needed.

This ADR covers the server side: devices, enrollment, challenges and the HTTP API. The sign-in pages, push delivery (FCM, later UnifiedPush) and the device pages of the web interface follow in a second step and amend this ADR if they need decisions not made here.

## Decision

### What the user gets

- A user enrolls a phone: in the web interface they create an enrollment QR code (single use, 5 minutes). The RustMFA app scans it and registers the phone. Several phones per user are possible. A phone can be revoked at any time, from the web interface or from another enrolled phone.
- A sign-in with a password-correct step 1 then offers "approve on your phone": the page shows a two-digit number; the app shows three numbers; the user picks the matching one and confirms with biometrics. A wrong number denies the request. A code from an authenticator app stays available as an alternative.
- Push is only a hint that a request is pending. Access is granted only after a valid signature over that one challenge.

### Rules

- **Device keys.** Each phone holds two ES256 (P-256) keys: a `request_key` that signs every API request, and a biometric-gated `approval_key` that signs challenge answers. The server stores only the public keys (base64 of the X.509 SubjectPublicKeyInfo DER).
- **Enrollment.** Enroll token: 256 random bits, stored only as a hash (`secrets::hash_token`), single use, 5 minutes, bound to the creating user. Registration uses the token and a **key attestation** chain for the approval key. The attestation challenge is the SHA-256 of the enroll token. By default the chain must verify to a pinned Google attestation root and show a hardware-backed key (TEE or StrongBox); software-only keys are rejected. `[mfa] attestation = "off"` allows custom ROMs and is documented with its trade-off. A token is consumed before the chain is checked, so a failed attempt burns the token.
- **Request authentication.** Header `Authorization: RustMFA-Sig device_id="…",ts="…",nonce="…",sig="…"`. Values are limited to `[A-Za-z0-9_-]` and 128 bytes. `sig` is a raw 64-byte R‖S signature, base64url, over `METHOD \n path-with-query \n ts \n nonce \n base64url(sha256(body))`. The server rejects a timestamp more than 60 seconds off and any nonce seen within 5 minutes for that device. A nonce is recorded only after the signature verified. Five failures per device in 15 minutes lock that device's requests for 15 minutes (existing limiter style). A success resets the count. A revoked phone gets `DEVICE_REVOKED` only after its signature verified, so someone without the key cannot learn that a device id was revoked; a disabled account is `UNAUTHENTICATED`.
- **Challenge.** Created in process by the sign-in code for one explicit device (the most recently seen active one). 90 seconds by default (`[mfa] challenge_ttl_seconds`, 10 to 300). Contains a 128-bit nonce, a two-digit number (10 to 99) and two decoys. The device receives the three candidates but never a marker of the right one.
- **Answer.** The approve and deny requests carry a raw R‖S signature by the `approval_key` over the canonical message `v1 \n challenge_id \n nonce \n login_id \n device_id \n expires_at \n audience` (exact format and test vectors in the contract). The server checks: device active and owner of the challenge; challenge pending and not expired; number matches (a mismatch resolves the challenge to `denied`); signature valid. Only then one conditional `UPDATE … WHERE status = 'pending' AND expires_at > now` consumes the challenge, so two simultaneous answers cannot both win. A bad signature never consumes a challenge.
- **No existence leaks.** Another user's challenge or device is `404`; another device of the same user is `403`.
- **Errors.** One format `{"error":{"code","message"}}`, codes as in the contract. No secrets, signatures, push tokens or keys in logs or errors.
- **Audit.** `mfa.device_registered`, `mfa.device_revoked`, `mfa.key_rotated`, `mfa.challenge_created`, `mfa.challenge_approved`, `mfa.challenge_denied`, `mfa.number_mismatch`, `mfa.challenge_expired`.
- **Join with ADR 0007.** A user has a second factor when TOTP is enabled **or** at least one active device exists. Step 2 accepts either. Rule of ADR 0007 extended accordingly: with a second factor active, Basic authentication with the account password on WebDAV and OCS is rejected, app passwords still work. This changes a rule of ADR 0007 and needs the same approval.

### Storage

Migration `0013_push_mfa.sql` with four `STRICT` tables, a plain index on every foreign key column (see the database notes in `CLAUDE.md`), cascading deletes from `users`:

- `mfa_devices(id, user_id, name, status active|revoked, request_pub, approval_pub, push_channel, push_token, hardware_backed, strongbox, created_at, last_seen_at, revoked_at)`
- `mfa_enroll_tokens(token_hash, user_id, expires_at, used_at)`
- `mfa_challenges(id, user_id, device_id, login_ref, nonce, number, candidates, audience, created_at, expires_at, status pending|approved|denied|expired, consumed_at)`
- `mfa_nonces(device_id, nonce, expires_at)`, purged opportunistically.

### Structure

- Logic in a `push_mfa` module of `rostdav-app`, reachable only through `AppState` methods; authorization stays in `rostdav-app`.
- HTTP API (10 device operations under `/api/v1`) in a new protocol crate `rostdav-mfa-api` that depends on `rostdav-app` and `rostdav-core` only. `architecture.md` gets the new row.
- The eleventh contract operation, the enroll-token route, lives in `rostdav-web` because it needs the session and CSRF protection.
- `PushChannel` trait in `rostdav-app`; delivery adapters follow in the second step.

### Dependencies (justification)

- `rustmfa-contract` (own crate, `rostdav-mfa` repository): signing formats and verification shared with the app and its test vectors. **Decision:** git dependency pinned by revision. Until that repository is published, development uses a local `[patch]` in an uncommitted `.cargo/config.toml`; the dependency is committed only once the repository exists.
  **Amendment 2026-11-08:** the owner chose a temporary path dependency on the sibling checkout (`../rostdav-mfa/contract/rustmfa-contract`, marked in `Cargo.toml`) for the development branch. It must become a git dependency pinned by revision before the branch is merged into `main`; until then the branch builds only next to that checkout.
- `x509-cert` and `der` (RustCrypto, MIT/Apache): parse the attestation chain and the Android key description.
- `ring` (already in the tree through the update check, ISC-style licence the policy allows): verifies the certificate signatures (RSA and ECDSA P-256/P-384). This avoids adding separate RSA and ECDSA crates, and `rcgen` is not needed: the tests build synthetic chains with `x509-cert` and sign them with `ring`.
- Android attestation roots are pinned in `push_mfa/google_roots.rs`. Source and check on 2026-11-08: the list at `https://android.googleapis.com/attestation/root` against the certificates on Google's key-attestation documentation page. Pinned are the two that both list:
  - RSA 4096, `serialNumber=f92009e853b6b045`, valid to 2042-03-15, SHA-256 `cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc`
  - ECDSA P-384, `CN=Key Attestation CA1`, valid to 2035-07-15, SHA-256 `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0`

  The documentation page lists three older roots (from 2016, 2019 and 2021) that the endpoint does not return. They are not pinned. A phone whose chain ends in one of them is rejected, and `attestation = "off"` is the way out until a release pins more roots.
- Google's attestation revocation list (`https://android.googleapis.com/attestation/status`) is not consulted: it needs a network request at registration. A revoked attestation key is therefore still accepted. Out of scope for now; the owner can revoke a device by hand.

### Out of scope

- FCM and UnifiedPush adapters, the sign-in page changes, the device pages in the web interface (second step).
- Number matching bypass, "remember this browser", approving sign-ins to other services.
- Attestation of key rotation beyond the rule below, remote attestation of boot state (`verifiedBootState`).
- Key rotation attestation: the rotation request carries a fresh attestation chain whose challenge is the SHA-256 of `"rotate:" + device_id + ":" + request_pub`.

## Consequences

- Sign-in is the most security-sensitive code. Acceptance criteria are tests for: concurrent approve (one winner), nonce replay and window, wrong device and wrong user, revoked device with a pending challenge, enroll token reuse/expiry/other user, software-only and wrong-challenge attestation, DER signature rejected, altered signed fields rejected, error table, no secrets in logs.
- Attestation logic is verified with synthetic chains first. A real-device chain fixture is added once the Android app exists, and recorded in `docs/compatibility.md`.
- A user whose only phone is lost can revoke it from the web interface after signing in with the password and a TOTP code, or needs an administrator if neither is available.
- Google's attestation roots rotate. A new root needs a release, and `attestation = "off"` is the escape hatch.
- Contract changes need coordinated releases of the server and the app. The versioned test vectors detect drift.
