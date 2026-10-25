# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). What was tested with which client version is in [docs/compatibility.md](docs/compatibility.md); the design decisions are in [docs/adr/](docs/adr/).

## [Unreleased]

### Changed

- **Web interface, mobile first**: on phones the navigation is a tab bar at the bottom (Files, Recent, Shares, More) instead of a strip that scrolls sideways at the top; the new page "More" holds Search, Trash bin, Devices & security, Settings, About, Administration and Sign out. Upload and New folder are round buttons above the tab bar, and a selected file opens as a sheet from the bottom. File lists drop the size column on phones, and long values on the About page wrap instead of being cut off. Wide screens are unchanged.

## [0.9.0] - 2026-10-24

### Added

- **Search for the Nextcloud apps**: WebDAV `SEARCH` on `/remote.php/dav/` (`d:basicsearch`: name, type, size, date, favorite, folder, sorting, limit) and the unified search provider `files` (`/ocs/v2.php/search/providers/files/search`). Both only return what the user may read. Checked against 90 recordings of Nextcloud 35.0.2; the Android app's search (unified search) was seen working on the emulator, the iOS app was not tried. Differences are listed in `docs/compatibility.md`.

## [0.8.0] - 2026-10-24

### Added

- **Search in PDF and Office files**: the text of PDF, Word (`docx`, `doc`), Excel (`xlsx`, `xls`), PowerPoint (`pptx`, `ppt`) and OpenDocument (`odt`, `ods`, `odp`) files is found like the text of other files. The readers run in a separate short-lived process with a memory limit, a CPU limit and a time-out, so a damaged or hostile file cannot take the server down. On by default; Administration, Server, "Search PDF and Office files" switches it off (the stored texts are then removed). Files read before are read again once. [ADR 0013](docs/adr/0013-documents-in-search.md).

### Changed

- The minimum Rust version is 1.88 (the PDF reader needs it).

## [0.7.0] - 2026-10-24

### Added

- **Search** (`/search`, "Search" in the navigation): finds files and folders by name in everything you can reach, your own and what others shared with you, in all folders at once. You can limit it to a folder and to files or folders; results are paged and the best match comes first. When a folder filter finds nothing, it links to this search. 
- **Search in the text of files**: `/search` also finds files by the words in them (text files: txt, md, csv, json, xml, html, source code, …), shows where, with the words marked, and lists name hits first. Whole words only. A background indexer reads the files a little at a time into a search index of its own (`db/search.sqlite`, rebuildable, not in backups). On by default; Administration, Server can switch it off (the stored texts are then removed) and set the size limits. The index holds the text of files in plain form in the data directory, so it is as sensitive as the files. `rostdav admin search status|rebuild`. [ADR 0012](docs/adr/0012-search-index.md). PDF and Office files and the search of the Nextcloud apps follow.

### Fixed

- `rostdav admin …` commands that need no password (`user list`, `search status`, …) waited for a line of input when a server was running (since 0.4.1): in a terminal you had to press Enter, with an open pipe they never finished. Only `user add` and `user set-password` read standard input now.
- The admin socket was not created when the path of the data directory is long (a Unix socket address holds at most 107 bytes); the socket is now reached through the open directory, so any path works.

### Changed

- Names are compared the same way everywhere (the folder filter, the user list in the administration, the sharee search): case and accents do not matter, and an accented letter written as one character or as letter plus accent is the same. Before, `Café` typed with a combining accent did not find `Café`, and non-ASCII capitals were not folded in the sharee search. Sharee search with an empty text still lists everybody.

## [0.5.2] - 2026-10-24

### Fixed

- Menus of the web interface (account, New folder, Upload, Add user) now close like menus should: when you click elsewhere, press Esc (the focus goes back to the menu's button), move on with Tab, or open another menu. Before, they stayed open until their own button was clicked again, and several could be open at once.
- Web interface on a phone: the navigation was a panel as tall as the screen that pushed the content out of sight. It is now one row at the top that scrolls sideways and shows the current page; the account icon sits in its corner, and there is no empty gap under it. (The storage meter is only on the Settings page on a phone.)

## [0.5.1] - 2026-10-24

### Fixed

- File names with the characters U+007F and U+0080 to U+009F are accepted. Nextcloud forbids only the characters 0 to 31 (`FilenameValidator.php`), and real data directories contain such names (an emoji decoded as Latin-1); Rostdav refused them, so those files could not be imported or synced. Found with a real Nextcloud data directory.

## [0.5.0] - 2026-10-24

### Added

- `rostdav admin import-nextcloud <data-dir>`: imports a Nextcloud data directory ([ADR 0011](docs/adr/0011-nextcloud-data-import.md)). Every user's files with names and modification times, and the versions Nextcloud kept (`files_versions`), into the Rostdav user of the same name (`--map NC=USER` to rename, `--only` to pick). The directory is only read, so Nextcloud can keep running; the command can be repeated, `--update` replaces files that changed (the old content becomes a version), `--dry-run` writes nothing. Not imported, and listed in the output: the trash, group folders, external storage, shares, favorites and files encrypted by Nextcloud.

## [0.4.1] - 2026-10-24

### Fixed

- **`rostdav admin …` did not work while the server ran** (since 0.3.0, the Turso database locks its file for one process): adding the first user to a container, `admin backup` ("while the server runs"), `fsck` and the other commands failed with "File is locked by another process". The running server now listens on a Unix socket in the data directory (`admin.sock`, mode 0600, only root and the server's own user may connect) and the command line sends its command there ([ADR 0010](docs/adr/0010-admin-socket.md)). Without a running server the commands open the database directly, as before.

## [0.4.0] - 2026-10-23

### Added

- About page (`/about`, in the navigation under the account entries): version, licence, source code, and the release notes of every version. The notes are `CHANGELOG.md` compiled into the binary, so they work offline and describe exactly what is running; the running version is marked and open.
- Version check, off by default ([ADR 0009](docs/adr/0009-version-check-and-updater.md)): an administrator can switch it on (Administration, Server, "Updates"). Then the server asks the GitHub releases API once a day, and on "Check now", which version is the newest, and shows a newer one with its release notes. The request carries only `User-Agent: rostdav/<version>`: no user, file or server data. While the check is off, the server makes no outbound connection at all. A failed check is shown on the page and never affects serving files. This adds an HTTPS client (`ureq`, rustls, bundled root certificates) to the program.
- Installing an update from the web interface, for a plain binary only (a container image shows the steps to pull the new image). The administrator confirms with their password; the server downloads the release file from GitHub, checks its minisign signature against a key compiled into the program, runs it with `--version`, saves the database to `backups/before-<version>.sqlite`, keeps the old program as `rostdav.previous`, replaces its program file and exits with status 75 for the supervisor to restart it. It stays off until a signing key is built in. Releases now also carry the bare binaries (`rostdav-<version>-<target>`) with minisign signatures ([ADR 0009](docs/adr/0009-version-check-and-updater.md)).
- Documentation site with a user manual, an administrator guide and the reference documents at <https://pierrejochem.github.io/rostdav/> (built from `site/` and `docs/`, see `site/README.md`), `SECURITY.md`, and a social preview image in `assets/brand/`.

### Fixed

- The profile picture is now shown where a user appears as a round icon: the icon at the top right of every page, and the user list and user details in the administration (before, only the first letter was shown). The picture's address carries its version, so a new picture shows at once and not after the browser's cache has expired.

### Changed

- Dependencies: `hmac` 0.13, `sha1` 0.11, `chacha20poly1305` 0.11, `base64` 0.23, `ulid` 3, `tower-http` 0.7, and the transitive `ctutils` 0.4.5 (RUSTSEC-2026-0385, non-constant-time masks in 0.4.2). Secrets sealed by earlier versions still open (a test holds a value sealed by the old library). The Rust version needed to build is now 1.87 (was 1.85). Dependabot proposes updates from now on.
- Sign-in pages (sign-in, second factor, device connection): the full Rostdav logo from `assets/brand` (mark and wordmark, set in the page's own font) beside the form on a dark brand panel, with a short tagline; on phones the panel becomes a band above the form.

## [0.3.0] - 2026-10-23

### Added

- Files page: drag and drop of files and whole folders anywhere on the page (empty folders included), a "Choose a folder" button, and one progress bar for the whole batch. A file that cannot be stored (for example a refused name) is reported at the end; the rest of the batch still uploads.
- Profile picture: any picture can be chosen or dropped. The browser crops it to a square, shrinks it and re-encodes it so that it fits what the server stores (at most 256 KiB, 16 to 1024 pixels), and shows a preview before it is saved.
- File inputs are drop zones (Settings, Files), with sidebar icons for "Recent" and "Shares".

### Changed

- **Database engine: Turso Database instead of SQLite** ([ADR 0008](docs/adr/0008-metadata-database-turso.md)). Same file format and file name; no C library any more. Existing databases are converted on the first start (take a backup first). Small files are slower (about 245 uploads/s instead of 420, 660 downloads/s instead of 1100 in the load test), large files and listings are not; the binary grows from about 20 MB to 47 MB.
- `rostdav admin fsck` (and the status page) now also run the database's integrity check and look for rows whose parent row is gone.
- The page upload no longer probes every file with a request that answers 404 (it starts the transfer and reads it only when it exists).

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
