<p align="center"><img src="assets/brand/rostdav-logo-light.svg" alt="Rostdav" width="360"></p>

# Rostdav

Schlanker, selbst gehosteter Dateiserver in Rust mit WebDAV, der mit den offiziellen Nextcloud-Apps genutzt werden kann.

> Rostdav ist kein Nextcloud-Produkt und nicht mit der Nextcloud GmbH verbunden. Es implementiert nur die Schnittstellen, die für die unterstützten Funktionen nötig sind.

## Status

**Phase 2, M0 abgeschlossen:** lauffähiges Gerüst (Konfiguration, Logging, Health-Endpunkte, CI), noch ohne Dateifunktionen. Nächster Schritt ist M1 nach Freigabe des Datenbankschemas. Fortschritt: [docs/plan.md](docs/plan.md).

## Schnellstart

```sh
# Rust über https://rustup.rs installieren; rust-toolchain.toml wählt die Toolchain.
cargo run -p rostdav -- serve
curl http://127.0.0.1:8080/healthz      # {"status":"ok"}
curl http://127.0.0.1:8080/readyz       # {"status":"ok"}
```

Mit [`just`](https://github.com/casey/just): `just run`, `just check`, `just smoke`. Einrichtung der IDE und Arbeitsablauf: [CONTRIBUTING.md](CONTRIBUTING.md).

## Geplante Funktionen

- Mehrere Benutzer mit getrennten Dateibereichen
- WebDAV für Dateien und Ordner, Streaming großer Dateien, Chunked Upload
- Anmeldung aus der Nextcloud-App über Login Flow v2 mit eigenem App-Passwort pro Gerät
- Versionen, Freigaben, Papierkorb
- Web-Oberfläche mit Hell- und Dunkelmodus, Administration, optionale Zwei-Faktor-Anmeldung

Was tatsächlich mit welcher App-Version getestet ist, steht in [docs/compatibility.md](docs/compatibility.md).

## Aufbau des Repositorys

```text
crates/
  rostdav-core/      Domänentypen, Fehler
  rostdav-meta/      Metadaten-Datenbank (SQLite, später optional PostgreSQL)
  rostdav-storage/   Blob-Speicher im Datenverzeichnis
  rostdav-app/       Dienste: Identity, Dateien, Versionen, Freigaben, Admin
  rostdav-dav/       WebDAV-Adapter
  rostdav-compat/    status.php, Capabilities, OCS, Login Flow v2
  rostdav-web/       Weboberfläche (static/tokens.css: Design-Tokens hell/dunkel)
  rostdav/           Binary: Konfiguration, Router, CLI
docs/                Anweisung, Architektur, ADRs, Plan, Sicherheit, Kompatibilität, Betrieb
design/mockups/      Quellen der Design-Canvases (Logo, Web-UI)
assets/brand/        Logo, App-Icon, Favicon als SVG
scripts/             Smoke-Test
```

## Dokumentation

| Dokument | Inhalt |
|---|---|
| [docs/anweisung.md](docs/anweisung.md) | Vollständige Projektanweisung (Anforderungen, Prioritäten) |
| [docs/architecture.md](docs/architecture.md) | Module, Anfrageverarbeitung, Datenmodell, Bedrohungsmodell |
| [docs/adr/](docs/adr/) | Architekturentscheidungen |
| [docs/plan.md](docs/plan.md) | Meilensteine und Abnahmekriterien |
| [docs/security.md](docs/security.md) | Sicherheitskonzept |
| [docs/compatibility.md](docs/compatibility.md) | Nextcloud-Kompatibilität mit Teststatus |
| [docs/api.md](docs/api.md) | Implementierte Endpunkte |
| [docs/ui.md](docs/ui.md) | Weboberfläche, Design-Tokens, Barrierefreiheit |
| [docs/admin.md](docs/admin.md) | Rollen, CLI, Ereignisprotokoll |
| [docs/deployment.md](docs/deployment.md) | Konfiguration, Betrieb, Backup |
| [AGENTS.md](AGENTS.md) | Arbeitsregeln für Coding-Agenten |

## Lizenz

Lizenziert unter einer der folgenden Lizenzen, nach Wahl:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

Beiträge werden, sofern nicht ausdrücklich anders angegeben, unter denselben beiden Lizenzen eingebracht.
