# ADR 0001: Technology stack

- Status: **Accepted** on 2026-10-21. The database engine named below (SQLite) was replaced by Turso Database on 2026-10-23: see [ADR 0008](0008-metadata-database-turso.md).
- Date: 2026-10-21

## Context

Rostdav is a lean file server that supports the unmodified Nextcloud apps. Requirements that influence the stack:

- Streaming of large files in both directions without buffering in memory
- Full control over WebDAV responses (Nextcloud properties `oc:`/`nc:`, headers such as `OC-FileId`, chunked upload v2)
- Security as a mandatory criterion (memory safety, secure defaults, small attack surface)
- Simple operation: one binary, one data directory, SQLite as the default
- Maintainability by a single developer, few dependencies

## Options considered

| Criterion | Rust (axum/tokio) | Kotlin (Spring Boot) | Go (net/http) |
|---|---|---|---|
| Streaming | Very good (tokio, `Body` streams, backpressure) | Good with WebFlux, more cumbersome with MVC | Very good (`io.Reader`) |
| Mature WebDAV building blocks | `dav-server` exists but is too rigid for Nextcloud extensions; XML with `quick-xml` is quite feasible | Hardly any maintained libraries (Milton etc.) | `x/net/webdav` exists, also hard to extend |
| Security | Memory-safe, no runtime reflection, small binary | Good frameworks, large dependency surface, reflection | Memory-safe, small dependency surface |
| Maintainability | High type safety, longer compile times | Very familiar to Spring developers, a lot of "magic" | Simple, but less expressive type system |
| Deployment size | One static binary, ~10–20 MB, low RAM usage | JVM, 200+ MB RAM when idle | One static binary, low RAM usage |
| Runs on Raspberry Pi / NAS | Very good | Possible, but heavy | Very good |

Also considered: **building on an existing project** (e.g. OxiCloud, Rust, MIT license, WebDAV present). Whether it supports the Nextcloud apps and how it implements metadata, file IDs and chunked upload has not been verified.

## Decision

**Rust** with the following building blocks (current stable version at project start in each case, pinned via `Cargo.lock`):

| Purpose | Crate | Rationale |
|---|---|---|
| Async runtime | `tokio` | De facto standard, file system and network streaming |
| HTTP | `axum` + `tower` / `tower-http` | Custom methods (PROPFIND, MKCOL, MOVE …) via `MethodFilter`/fallback, middleware as Tower layers |
| XML | `quick-xml` | Streaming parser and writer; DTD/entities are not resolved (XXE-safe) |
| Database | `sqlx` (SQLite, optionally PostgreSQL) | Compile-time checked queries, migrations |
| Passwords | `argon2` | Argon2id as required |
| TOTP | `totp-rs` | RFC 6238 |
| Encryption of secrets | `chacha20poly1305` | AEAD for TOTP secrets |
| Randomness | `rand` / `getrandom` | Tokens, app passwords |
| Unicode | `unicode-normalization` | NFC normalization of file names |
| Templates | `askama` | Compile-time templates, automatic HTML escaping |
| UI interactivity | `htmx` (a single static JS file, CSP-compatible) | Little custom JavaScript |
| Configuration | `figment` or `config` | File + environment variables with precedence |
| CLI | `clap` | `rostdav serve`, `rostdav admin …` |
| Logging | `tracing` + `tracing-subscriber` (JSON) | Structured logs, central redaction |
| Rate Limiting | `governor` | Brute-force protection per IP and user |
| Checksums | `blake3` | Fast content checksums |

**WebDAV is implemented in-house** (on `axum` + `quick-xml`), not via `dav-server`. Reason: Nextcloud compatibility requires stable file IDs from the database, custom properties, custom headers and the chunked upload flow. This fits poorly onto a file system trait. The set of methods (OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, DELETE, MOVE, COPY, later SEARCH) is manageable. As a safeguard, the WebDAV conformance suite **litmus** is run in CI.

## Consequences

- Positive: one binary, low resource usage, full control over the protocol, strong type safety at security boundaries.
- Negative: WebDAV protocol work is on us; longer compile times.
- Risk: deviations from the apps' expectations. Mitigation: contract tests against recordings of a real Nextcloud (see plan, milestone M5).

## Approval (2026-10-21)

1. Rust confirmed.
2. No spike on OxiCloud; Rostdav is developed independently.
3. License: MIT OR Apache-2.0 (dual license, customary in Rust).
4. Reference app: current stable Nextcloud Android app at the start of M3; the exact version is then entered in `docs/compatibility.md`.
