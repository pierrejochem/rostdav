# Notes for Claude Code

The binding working rules are in [AGENTS.md](AGENTS.md). The full project instructions are in [docs/instructions.md](docs/instructions.md).

## Starting a session

1. Read `docs/plan.md`: which milestone is open, which approval point is pending?
2. `docs/architecture.md` and the ADRs under `docs/adr/` for module boundaries and the storage model.
3. Before making changes: `just check` must be green.

## Current state

- M0 complete (skeleton, configuration, logs, health endpoints, CI).
- Approval point 2 granted (ADR 0002 accepted). M1 complete (schema, BlobStore, naming rules, `admin user add`).
- M2 (WebDAV core) complete. M3: server side recorded (Nextcloud 35.0.2, synthetic requests), real-app capture open. M4 (sign-in) implemented; ADR 0003 (app passwords, Login Flow v2, rate limiting) is accepted (2026-10-23). M5 (Nextcloud WebDAV extensions, chunked upload v2) implemented. M7 (admin CLI, event log, fsck, import) implemented. M6 (real app on the Android emulator) is postponed to the end by the project owner. M8 (versioning), M9 (shares, ADR 0004 accepted) and M10 (trash, ADR 0005) implemented. M11 (web interface, ADR 0006 accepted): slice 11a implemented (sign-in, Files, Trash, Devices, Settings, public link page). 11b implemented (share dialog, versions panel, details, folder filter). Chunked browser upload done (JS not yet tested in a real browser). 11c implemented (administration pages). 11d done (profile, change password, data export, German/English). M11 complete. M12 (two-factor, ADR 0007 accepted) implemented. M13 (retention overview, `default_quota`, `upload_retention_hours`, streamed data export) done. Phase 5 done except coverage-guided fuzzing (authorization matrix, robustness tests, load tests, container image + Compose, backup/restore, operations docs). M6 complete for now (2026-10-23): verified with the real Android app (sign-in incl. 2FA, files, favorites, shares, public link, versions, trash, offline) and the desktop sync engine (`nextcloudcmd`); not tried: desktop GUI, iOS client. ADR 0003 accepted; cargo-fuzz targets in `fuzz/`. Web interface gaps from the mockups closed (maintenance mode, lockouts, shares, recent, sortable columns); left out: avatar upload, editable admin limits.

- About page, release notes, opt-in version check and the updater (ADR 0009) are built. The updater needs the maintainer's minisign key (`CONTRIBUTING.md`, "Release signing key"): until `crates/rostdav-app/update-key.pub` holds a key, it reports "no update signing key". The signing step of the release workflow has not run yet. Documentation site in `site/` (GitHub Pages, `just site`).

## Releases

`v0.1.0` is published (2026-10-23): tag push starts `.github/workflows/release.yml` (verify tag against `Cargo.toml` and `CHANGELOG.md`, tests; then per architecture amd64 and arm64: build the image, check it, take the binary out of it, push by digest; then one multi-arch tag set on ghcr.io; GitHub release with notes from `CHANGELOG.md`). The arm64 part is new since 0.1.0 and has not run yet: watch the first run after a tag push. To release: bump `version` in `Cargo.toml`, add a `## [x.y.z] - date` section to `CHANGELOG.md`, commit, `git tag -a vX.Y.Z`, push `main` and the tag. CI includes `cargo deny`; run it locally (`cargo install cargo-deny`) before a release. The history was rewritten once on 2026-10-23 to drop two commit trailers; `v0.1.0` was re-created on the new commit.

## Database

The metadata database is Turso Database (SQLite file format) behind `crates/rostdav-meta/src/sql.rs`, since 2026-10-23 ([ADR 0008](docs/adr/0008-metadata-database-turso.md)); `v0.2.0` is the last SQLite/sqlx version. Things that bit us and are guarded by tests: one writer (concurrent writers get `Busy`), cascades need a plain index on every foreign key column (`every_foreign_key_has_a_plain_index_for_cascades`), `PRAGMA foreign_key_check` does nothing (`fsck` checks it itself), `WITHOUT ROWID` cannot be written, and the planner does not use our partial unique index for lookups (`nodes_child_lookup`). Look at `EXPLAIN QUERY PLAN` after changing the schema.

## Commands

```sh
just check   # fmt --check, clippy -D warnings, test
just smoke   # start the process and verify health, log redaction, shutdown
just run     # start locally
```
