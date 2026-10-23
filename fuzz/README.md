# Fuzz targets

`just fuzz <target> [seconds]` (cargo-fuzz, nightly). Four targets: see `fuzz_targets/`.

**Known problem (2026-10-23):** `cargo +nightly fuzz build` fails with nightly 1.101 (2026-10-12) because `branches` 0.4.6, a dependency of `turso_core` 0.8.3 (pinned exactly, [ADR 0008](../docs/adr/0008-metadata-database-turso.md)), calls `core::intrinsics::abort`, which that nightly no longer has. It is not a problem of this repository's code; the normal build on stable is not affected. Ways out: an older nightly (`cargo +nightly-YYYY-MM-DD fuzz build`; the date that still works is not known yet), or a newer Turso release that uses `branches` 0.5.
