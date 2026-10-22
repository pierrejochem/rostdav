# Implementation plan

Prioritized by smallest testable benefit. Every milestone ends with green tests and a final report.

## Approval point 1 – done (2026-10-21)

- [x] Stack: Rust ([ADR 0001](adr/0001-technology-stack.md))
- [x] No OxiCloud spike
- [x] License: MIT OR Apache-2.0
- [x] Reference app: current stable Android version at the start of M3

## Phase 2: Minimal prototype (P0)

### M0 – Skeleton ✅ (2026-10-21)
- Cargo workspace with the crates from `docs/architecture.md`
- `rostdav serve`, configuration, structured logs, `/healthz`, `/readyz`
- CI: `cargo fmt --check`, `clippy -D warnings`, tests, `cargo deny` / `cargo audit`
- **Acceptance:** server starts, health endpoints respond, CI green

### M1 – Metadata and storage ✅ (2026-10-21)
- Approval point 2: schema per [ADR 0002](adr/0002-storage-model.md)
- Migrations, `BlobStore` with atomic placement, path validation and resolution
- `rostdav admin user add` (CLI), Argon2id
- **Acceptance:** unit tests for naming rules (incl. Unicode, `..`, percent-encoding); crash simulation between blob and commit leaves no inconsistent state

### M2 – WebDAV core ✅ (2026-10-21)
- Basic Auth with account password (app passwords follow in M4)
- OPTIONS, PROPFIND (Depth 0/1), GET/HEAD with Range, PUT (streaming), MKCOL, DELETE, MOVE, COPY
- ETag, Last-Modified, `If-Match`/`If-None-Match`, `Overwrite`, recursive folder ETags
- **Result:** `rclone` (copy up/down, check, moveto, purge, mkdir) verified manually; litmus `basic` 16/16 and `copymove` 13/13 pass (`scripts/litmus.sh`, CI job `litmus`). litmus `props` is not run: it needs PROPPATCH/dead properties, which are not implemented. `cadaver` (mkdir, put, get, ls, move, copy, delete) verified manually in Docker.
- **Acceptance:** integration tests of all methods incl. error cases; a second user demonstrably cannot access the first user's files; `rclone` and `cadaver` work; litmus basic tests run in CI

## Phase 3: App compatibility (P1)

### M3 – Reference recordings (server side done 2026-10-21; app side open)
- Nextcloud (same major version as emulated) in Docker, reference app in the Android emulator, record traffic with mitmproxy
- Flows: add server, Login Flow v2, open folder, upload small/large, download, rename, move, delete, sign out
- Sanitized fixtures to `tests/fixtures/nextcloud/`, findings with sources in `docs/compatibility.md`
- **Result so far:** Nextcloud 35.0.2 in Docker recorded with synthetic requests (`scripts/record_nextcloud.py`, ~110 fixtures, findings in `docs/compatibility.md`). Not done: capture of the real Android app via emulator + mitmproxy.
- **Acceptance:** every flow present as a fixture, open questions documented

### M4 – Sign-in like Nextcloud ✅ (2026-10-21; ADR 0003 awaits review)
- `status.php`, capabilities (implemented features only), OCS user endpoints
- Login Flow v2 incl. HTML sign-in page, app passwords (create, hash, revoke, last use)
- Rate limiting for all sign-in paths
- **Result:** implemented with contract tests against the fixtures (`crates/rostdav/tests/signin.rs`); design in [ADR 0003](adr/0003-app-passwords-and-login-flow.md), which still needs review (approval point 3). Real-app verification is part of M6.
- **Acceptance:** contract tests against fixtures green; revoking an app password results in 401

### M5 – Nextcloud WebDAV extensions ✅ (2026-10-22)
- `oc:`/`nc:` properties, upload headers (`X-OC-MTime`, `OC-Checksum`, `OC-FileId`, `OC-ETag`)
- Chunked upload v2, quota properties and HTTP 507
- Preview and avatar endpoints cleanly answered with 404
- **Result:** implemented and checked against the fixtures in `crates/rostdav/tests/nextcloud_dav.rs` (property sets, headers, Sabre error classes, name rules, chunk flow incl. a 105 MiB upload). Differences that remain are listed in `docs/compatibility.md`. Verified with the real app only in M6.
- **Acceptance:** contract tests green; upload > 100 MB via chunks

### M6 – End-to-end with the app
- Manual or automated test with the unmodified app (emulator)
- Capture deviations as reproducible tests and fix them
- **Acceptance:** acceptance list from section 6 of the instructions complete, test status in `docs/compatibility.md`

## Phase 4: Extensions (P2)

| # | Contents | Depends on |
|---|---|---|
| M7 ✅ | Admin CLI complete, event log (2026-10-22) | M4 |
| M8 ✅ | Versioning incl. versions DAV endpoint and restore (2026-10-22) | M5 |
| M9 ✅ | Shares: users, then public links (OCS Sharing API, mount points) (2026-10-22, [ADR 0004](adr/0004-shares-and-permissions.md)) | M5 |
| M10 ✅ | Trash (trashbin DAV endpoint) (2026-10-22, [ADR 0005](adr/0005-trash.md)) | M5 |
| M11 | Web interface: files, devices, settings, administration, light/dark ([ADR 0006](adr/0006-web-interface.md)). **11a ✅** (sign-in, Files, Trash, Devices, Settings, public link page); **11b (share dialog, versions panel, details, folder filter, chunked browser upload) ✅**; **11c administration (users, event log, status/fsck, server settings) ✅**, **11d: profile, change password, data export, languages (de/en) ✅** | M7–M10 |
| M12 ✅ | Optional two-factor authentication (TOTP + recovery codes; [ADR 0007](adr/0007-two-factor-authentication.md), 2026-10-22) | M11 |
| M13 | Retention rules, data export | M8, M10 |

## Phase 5: Hardening and delivery

- Security tests (authorization matrix, fuzzing of paths and XML with `cargo fuzz`), load tests (large files, many small files, parallel uploads)
- Container image, Compose example with reverse proxy, backup/restore test
- Operations documentation

## Biggest risks

| Risk | Impact | Mitigation |
|---|---|---|
| App expects undocumented behavior | Login or upload fails | Recordings early (M3) instead of assumptions |
| App rejects the reported version or changes requirements in updates | Compatibility breaks | Version configurable, pin app version, contract tests in CI |
| SQLite write lock with many parallel uploads | Wait times | Keep transactions short (step 3 only), PostgreSQL optional |
| Shares with mount points are complex | Permission errors | Dedicated authorization matrix tests, shares only after a stable base |
