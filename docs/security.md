# Security concept

Binding requirements: section 5 of the [instructions](instructions.md). Short version of the threat model: [architecture.md](architecture.md#threat-model-short-version-details-in-docssecuritymd).

## Trust boundaries

1. **Internet ↔ reverse proxy:** TLS, HSTS. Rostdav itself speaks only HTTP on localhost or an internal network.
2. **Reverse proxy ↔ Rostdav:** take client IP and scheme only from configured trusted proxies (not yet implemented, M4).
3. **Rostdav ↔ data directory:** service user only, mode 0700 (implemented in M0).
4. **User ↔ user:** strict separation of file areas, access only via shares.
5. **Rostdav ↔ GitHub (only if an administrator turned the version check on):** one HTTPS `GET` a day to the releases API, nothing else leaves the server. The request has no cookies and no data about users, files or the server, only `User-Agent: rostdav/<version>`. Certificates are checked against root certificates compiled into the program. The answer is size-limited (1 MiB), parsed as JSON and reduced to a version, a date, a link (must start with `https://github.com/pierrejochem/rostdav/`) and the notes, which are shown as text (restricted Markdown, no HTML). A failure is recorded and shown, nothing more. [ADR 0009](adr/0009-version-check-and-updater.md).

## Threats and mitigations

| ID | Threat | Mitigation | Status |
|---|---|---|---|
| S1 | Password guessing via WebDAV/OCS/login | Rate limit per IP and user, lockouts, app password requirement, 2FA (TOTP, ADR 0007: code entry limited to five failures per user and 15 minutes, secrets encrypted with a key outside the database) | M4, M12 implemented |
| S2 | Stolen app password | Revocable per device, last use visible, only hash stored | open (M4) |
| S3 | Session theft in the web interface | HttpOnly, Secure, SameSite=Lax, short lifetime, reissue after sign-in | open (M11) |
| T1 | Path Traversal | Physical paths independent of input, segment validation | open (M1) |
| T2 | `Destination` header pointing to a foreign host | Own host and base URL only | open (M2) |
| T3 | XXE / XML-Bomben | Parser without DTD/entities, size and depth limit | open (M2) |
| T4 | CSRF in the web interface | Token per session, POST only for changes | open (M11) |
| R1 | Unnoticed admin actions | Event log | open (M7) |
| I1 | Access to other users' file IDs | Authorization per node, negative tests | open (M2) |
| I2 | Internal details in errors | Generic responses, details only in the log with request ID | M0 for `/readyz` |
| I3 | Secrets in logs | `Authorization`/`Cookie` marked sensitive, spans without query | implemented in M0, smoke test verifies it |
| I4 | Guessable share links | ≥ 128 bits of randomness, only hash stored, optional password and expiry | open (M9) |
| D1 | Resource exhaustion | Body limits per route, `Depth: infinity` rejected, quota, timeouts | open (M2) |
| D2 | Orphaned uploads fill the disk | Expiry time, cleanup job | open (M5) |
| E1 | User calls an admin function | Role check in the service, not only in the UI | open (M7) |
| E2 | XSS via file names | Automatic escaping (askama), strict CSP | open (M11) |

## Cryptography

| Purpose | Method |
|---|---|
| Account passwords, link passwords | Argon2id (parameters configurable, defaults per OWASP recommendation at the time of implementation) |
| App passwords, session and link tokens | ≥ 128 bits from `getrandom`, stored as SHA-256, constant-time comparison |
| TOTP-Secrets | ChaCha20-Poly1305, key from environment/secret file |
| Recovery codes | Argon2id |
| Content checksums | BLAKE3 (not a security function, integrity only) |

## Verification

- `crates/rostdav/tests/authz_matrix.rs`: anonymous, wrong password, another user, a disabled user and a read-only public link try 26 doors (WebDAV new and legacy paths, traversal variants, chunked upload, versions, trashbin, OCS sharing, public.php) against one user's data; afterwards that data must be byte-identical. It found the lockout weakness described in ADR 0003 (amendment).

- `crates/rostdav/tests/robustness.rs`: 3500 seeded pseudo-random requests (traversal and encoding tricks on every WebDAV door, DOCTYPE/entity/nesting/attribute bombs and random bytes as XML, odd header values). Required: no 5xx, nothing slow, no entity expansion, nothing outside the data layout. Coverage-guided `cargo fuzz` targets live in `fuzz/` (own workspace, nightly toolchain, not part of `just check`): `paths` (names and logical paths), `dav_xml` (PROPFIND/PROPPATCH/REPORT bodies), `dav_headers_and_urls` (`Range`, request and `Destination` paths of every URL space), `tokens` (chunk and blob names). Run: `just fuzz <target> [seconds]`. First run: 30 s per target, about 3.3 million inputs in total, no panic or broken invariant. These are short runs; a longer run (hours) is the real test. Entry points are `rostdav_dav::fuzzing` (hidden from the docs).
- `crates/rostdav/tests/load.rs` (ignored by default, run with `--ignored`): a 512 MiB file, 5000 small files, 32 parallel uploads. It found a pool deadlock: `Db::resolve` held one database connection while asking the pool for a second, so with eight or more simultaneous requests every connection waited for another and the server answered 500 after 30 s (fixed; regression test `many_concurrent_resolves_do_not_deadlock`).

## Dependencies

- `cargo deny` in CI: security advisories, licenses, provenance.
- New dependencies only with a justification (commit or ADR).
- `unsafe_code = "forbid"` across the whole workspace.

## Reporting vulnerabilities

[Define a contact channel, e.g. the repository's GitHub Security Advisories.]
