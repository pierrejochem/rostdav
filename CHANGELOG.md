# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). What was tested with which client version is in [docs/compatibility.md](docs/compatibility.md); the design decisions are in [docs/adr/](docs/adr/).

## [0.2.0] - 2026-10-23

### Added

- Linux arm64: a `aarch64-unknown-linux-gnu` tarball and a multi-architecture container image (amd64 and arm64 under one tag). Both architectures are built on runners of their own kind; the tarball holds the binary from the image (built on Debian bookworm), so it runs wherever the image does.
- Profile pictures: upload a PNG or JPEG in Settings; the Nextcloud apps show it (`/index.php/avatar/<user>/<size>`, sign-in required, sent unscaled, 404 without a picture).
- Administrators can adjust the quota for new users, the expiry of unfinished uploads and the retention of versions, trash and event log in the web interface (Administration, Server). Settings given in the configuration file or an environment variable stay locked there ("set by configuration").
- Maintenance mode and sign-in lockouts: administrators can switch maintenance mode on (WebDAV and OCS answer 503 as Nextcloud does, `status.php` reports it) and lift sign-in blocks in Administration, Sign-in and maintenance.
- Web interface: a shares overview, a recent-files page, sortable file columns, and a "2FA" mark in the user list.

### Changed

- Login Flow: the app password is encrypted while it waits for the app to collect it, and at most 1000 flows can be open at once (ADR 0003, now accepted).
- Version 0.2.0 also updates `tokio` (1.54.1, fixes a yanked release and RUSTSEC-2026-0384) and `quick-xml` (0.42, fixes RUSTSEC-2026-0194 and 0195, both denial of service on XML input).

## [0.1.0] - 2026-10-23

First release: a single-binary file server with WebDAV that the unmodified Nextcloud apps can use.

### Added

- **Files**: multiple users with separate file areas, WebDAV (RFC 4918 class 1) under `/remote.php/dav/files/<user>/`, streaming of large files, range requests, content-addressed blob storage in the data directory, SQLite metadata (WAL).
- **Nextcloud compatibility**: `status.php`, OCS capabilities and user endpoints, the `oc:`/`nc:` WebDAV properties and upload headers, chunked upload v2, favorites (`oc:favorite`, `REPORT oc:filter-files`), quota, the connectivity probe `/index.php/204`.
- **Sign-in**: Login Flow v2 with a separate app password per device (ADR 0003), brute-force protection per address and per user, optional two-factor authentication with TOTP and recovery codes (ADR 0007).
- **Versions**: overwritten files keep versions, listed and restored through the Nextcloud versions endpoint; retention limits.
- **Shares and public links** (ADR 0004): sharing with users and by link with password, expiry and permissions (including upload-only); the `/s/<token>` page.
- **Trash** (ADR 0005): deleted files can be restored through the Nextcloud trashbin endpoint; retention.
- **Web interface** (ADR 0006), German and English, light and dark: files (search, sorting, details, chunked upload), recent files, shares overview, trash, devices and sessions, settings, profile, data export; administration of users, event log, status and consistency check, sign-in lockouts with unlock, maintenance mode.
- **Operations**: admin CLI (users, consistency check, import, backup, event log), container image and Compose file, health checks, JSON logs without secrets, documented backup and restore.
- **Tests**: contract tests against recordings of the Nextcloud 35.0.2 reference, an authorization matrix, robustness and load tests, coverage-guided fuzz targets in `fuzz/` (nightly, not part of `just check`).

### Verified with real clients

- Nextcloud Android 35.0.1 (emulator): sign-in (also with two-factor), files, favorites, shares, public link, versions, trash, offline and reconnect.
- Nextcloud desktop sync engine 4.0.6 (`nextcloudcmd`): two-way sync, chunked upload, rename, delete, versions.
- Not tried: the desktop GUI and the iOS client.

### Known limitations

- No previews, notifications, activities, end-to-end encryption, calendar or contacts (see [docs/compatibility.md](docs/compatibility.md)).
- Sign-in limits, session lifetimes and similar settings come from the configuration file and are shown read-only in the web interface.
- Sign-in blocks are kept in memory and end when the server restarts; one process, one SQLite database.
- No avatar upload.
