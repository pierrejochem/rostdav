# Development commands for Rostdav. `just` without arguments lists all.

default:
    @just --list

# Server lokal starten (Pretty-Logs, Daten in ./data)
run *ARGS:
    ROSTDAV_LOG__FORMAT=pretty ROSTDAV_LOG__LEVEL=info,rostdav=debug cargo run -p rostdav -- serve {{ARGS}}

# Formatting, Clippy and tests - before every commit
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

# Smoke test against the built debug binary
smoke:
    cargo build -p rostdav
    scripts/smoke.sh ./target/debug/rostdav

# Dependencies, licenses, security advisories
deny:
    cargo deny check advisories licenses bans sources

# Wirksame Konfiguration anzeigen
config:
    cargo run -q -p rostdav -- check-config

# Delete local data (asks for confirmation)
[confirm("Really delete local ./data?")]
clean-data:
    rm -rf ./data
