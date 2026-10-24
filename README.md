<p align="center"><img src="assets/brand/rostdav-logo-light.svg" alt="Rostdav" width="360"></p>

# Rostdav

A lean, self-hosted file server in Rust with WebDAV that works with the official Nextcloud apps.

Rostdav is one small program with one data folder: no PHP, no web server stack, no separate database server. Sign in from the Nextcloud Android app or the desktop client, sync and share files, restore older versions and deleted files, and manage users in a built-in web interface (light and dark, English and German). Free and open source (Apache-2.0 or MIT) for Linux on x86-64 and arm64, as a binary or a container image.

**[Documentation and user manual](https://pierrejochem.github.io/rostdav/)** · [Install](https://pierrejochem.github.io/rostdav/admin/deployment/) · [Releases](https://github.com/pierrejochem/rostdav/releases) · [Compatibility](https://pierrejochem.github.io/rostdav/reference/compatibility/)

[![CI](https://github.com/pierrejochem/rostdav/actions/workflows/ci.yml/badge.svg)](https://github.com/pierrejochem/rostdav/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/pierrejochem/rostdav)](https://github.com/pierrejochem/rostdav/releases) [![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](#license)

> Rostdav is not a Nextcloud product and is not affiliated with Nextcloud GmbH. It implements only the interfaces required for the supported features.

## Status

**Version 0.5.0.** Everything planned for the first release is implemented: WebDAV with the Nextcloud extensions, Login Flow v2 with app passwords, chunked upload, favorites, versions, shares and public links, trash, a German/English web interface with administration, optional two-factor authentication, and an admin CLI with backup. It was checked against recordings of Nextcloud 35.0.2 and used with the real Nextcloud Android app (35.0.1) and the desktop sync engine (4.0.6); the desktop GUI and the iOS client were not tried. Details: [docs/compatibility.md](docs/compatibility.md), [CHANGELOG.md](CHANGELOG.md), progress: [docs/plan.md](docs/plan.md).

## Quick start

```sh
# Install Rust from https://rustup.rs; rust-toolchain.toml selects the toolchain.
cargo run -p rostdav -- serve
curl http://127.0.0.1:8080/healthz      # {"status":"ok"}
curl http://127.0.0.1:8080/readyz       # {"status":"ok"}
```

Live development in Docker (rebuilds and restarts on every code change): `docker compose up --build`, then open <http://localhost:8080> (user `demo`, password `korrekt-pferd-batterie`; development only).

Production: [docs/deployment.md](docs/deployment.md) (released binary and container image, Compose with HTTPS proxy, backup/restore, upgrade). Releases: <https://github.com/pierrejochem/rostdav/releases>.

With [`just`](https://github.com/casey/just): `just run`, `just check`, `just smoke`. IDE setup and workflow: [CONTRIBUTING.md](CONTRIBUTING.md).

## Features

- Multiple users with separate file areas
- WebDAV for files and folders, streaming of large files, chunked upload
- Sign-in from the Nextcloud app via Login Flow v2 with a separate app password per device
- Versions, shares, trash
- Web interface with light and dark mode, administration, optional two-factor authentication
- Maintenance mode, event log, consistency check, backup and restore from the command line

What has actually been tested with which app version is documented in [docs/compatibility.md](docs/compatibility.md).

## Repository layout

```text
crates/
  rostdav-core/      Domain types, errors
  rostdav-meta/      Metadata database (Turso Database, SQLite file format; ADR 0008)
  rostdav-storage/   Blob storage in the data directory
  rostdav-app/       Services: identity, files, versions, shares, admin
  rostdav-dav/       WebDAV adapter
  rostdav-compat/    status.php, Capabilities, OCS, Login Flow v2
  rostdav-web/       Web interface (static/tokens.css: design tokens light/dark)
  rostdav/           Binary: configuration, router, CLI
docs/                Instructions, architecture, ADRs, plan, security, compatibility, operations
design/mockups/      Sources of the design canvases (logo, web UI)
assets/brand/        Logo, app icon, favicon as SVG
site/                Documentation site (Zola; GitHub Pages), user manual pages
scripts/             Smoke test, site-sync.py (copies docs/ into the site)
```

## Documentation

The same documents, with the user manual and screenshots, are published as a web site: <https://pierrejochem.github.io/rostdav/>. The site is built from `site/` and `docs/` (`just site`).

| Document | Contents |
|---|---|
| [docs/instructions.md](docs/instructions.md) | Full project instructions (requirements, priorities) |
| [docs/architecture.md](docs/architecture.md) | Modules, request handling, data model, threat model |
| [docs/adr/](docs/adr/) | Architecture decisions |
| [docs/plan.md](docs/plan.md) | Milestones and acceptance criteria |
| [docs/security.md](docs/security.md) | Security concept |
| [docs/compatibility.md](docs/compatibility.md) | Nextcloud compatibility with test status |
| [docs/api.md](docs/api.md) | Implemented endpoints |
| [docs/ui.md](docs/ui.md) | Web interface, design tokens, accessibility |
| [docs/admin.md](docs/admin.md) | Roles, CLI, event log |
| [docs/deployment.md](docs/deployment.md) | Configuration, operation, backup |
| [AGENTS.md](AGENTS.md) | Working rules for coding agents |

## License

Licensed under either of the following licenses, at your option:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

Unless explicitly stated otherwise, contributions are submitted under the same two licenses.
