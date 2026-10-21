# Entwicklungsbefehle für Rostdav. `just` ohne Argument listet alle.

default:
    @just --list

# Server lokal starten (Pretty-Logs, Daten in ./data)
run *ARGS:
    ROSTDAV_LOG__FORMAT=pretty ROSTDAV_LOG__LEVEL=info,rostdav=debug cargo run -p rostdav -- serve {{ARGS}}

# Formatierung, Clippy und Tests – vor jedem Commit
check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace

# Code formatieren
fmt:
    cargo fmt --all

# Nur Tests
test *ARGS:
    cargo test --workspace {{ARGS}}

# Smoke-Test gegen das gebaute Debug-Binary
smoke:
    cargo build -p rostdav
    scripts/smoke.sh ./target/debug/rostdav

# Abhängigkeiten, Lizenzen, Sicherheitsmeldungen
deny:
    cargo deny check advisories licenses bans sources

# Wirksame Konfiguration anzeigen
config:
    cargo run -q -p rostdav -- check-config

# Lokale Daten löschen (fragt nach)
[confirm("Lokales ./data wirklich löschen?")]
clean-data:
    rm -rf ./data
