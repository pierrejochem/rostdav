# Notes for Claude Code

The binding working rules are in [AGENTS.md](AGENTS.md). The full project instructions are in [docs/instructions.md](docs/instructions.md).

## Starting a session

1. Read `docs/plan.md`: which milestone is open, which approval point is pending?
2. `docs/architecture.md` and the ADRs under `docs/adr/` for module boundaries and the storage model.
3. Before making changes: `just check` must be green.

## Current state

- M0 complete (skeleton, configuration, logs, health endpoints, CI).
- Approval point 2 granted (ADR 0002 accepted). M1 complete (schema, BlobStore, naming rules, `admin user add`).
- M2 (WebDAV core) complete. M3: server side recorded (Nextcloud 35.0.2, synthetic requests), real-app capture open. M4 (sign-in) implemented; ADR 0003 (app passwords, Login Flow v2, rate limiting) is **Proposed** and needs review (approval point 3). M5 (Nextcloud WebDAV extensions, chunked upload v2) implemented. M7 (admin CLI, event log, fsck, import) implemented. M6 (real app on the Android emulator) is postponed to the end by the project owner. M8 (versioning), M9 (shares, ADR 0004 accepted) and M10 (trash, ADR 0005) implemented. M11 (web interface, ADR 0006 accepted): slice 11a implemented (sign-in, Files, Trash, Devices, Settings, public link page). 11b implemented (share dialog, versions panel, details, folder filter). Chunked browser upload done (JS not yet tested in a real browser). 11c implemented (administration pages). 11d done (profile, change password, data export, German/English). M11 complete. M12 (two-factor, ADR 0007 accepted) implemented. M13 (retention overview, `default_quota`, `upload_retention_hours`, streamed data export) done. Phase 5 done except coverage-guided fuzzing (authorization matrix, robustness tests, load tests, container image + Compose, backup/restore, operations docs). M6 mostly verified with the real Android app (see `docs/plan.md` status); open: trash/versions/public link/offline in the app, ADR 0003 review, cargo-fuzz.

## Commands

```sh
just check   # fmt --check, clippy -D warnings, test
just smoke   # start the process and verify health, log redaction, shutdown
just run     # start locally
```
