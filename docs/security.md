# Security concept

Binding requirements: section 5 of the [instructions](instructions.md). Short version of the threat model: [architecture.md](architecture.md#threat-model-short-version-details-in-docssecuritymd).

## Trust boundaries

1. **Internet ↔ reverse proxy:** TLS, HSTS. Rostdav itself speaks only HTTP on localhost or an internal network.
2. **Reverse proxy ↔ Rostdav:** take client IP and scheme only from configured trusted proxies (not yet implemented, M4).
3. **Rostdav ↔ data directory:** service user only, mode 0700 (implemented in M0).
4. **User ↔ user:** strict separation of file areas, access only via shares.

## Threats and mitigations

| ID | Threat | Mitigation | Status |
|---|---|---|---|
| S1 | Password guessing via WebDAV/OCS/login | Rate limit per IP and user, lockouts, app password requirement, 2FA | open (M4, M12) |
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

## Dependencies

- `cargo deny` in CI: security advisories, licenses, provenance.
- New dependencies only with a justification (commit or ADR).
- `unsafe_code = "forbid"` across the whole workspace.

## Reporting vulnerabilities

[Define a contact channel, e.g. the repository's GitHub Security Advisories.]
