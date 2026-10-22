#!/bin/sh
# Starts the server and restarts it whenever source or static files change.
# On the first run a demo account is created. Development only.
set -eu

BIN=target/debug/rostdav
DEMO_USER="${DEMO_USER:-demo}"
DEMO_PASSWORD="${DEMO_PASSWORD:-korrekt-pferd-batterie}"

cargo build -p rostdav
if ! "$BIN" admin user list 2>/dev/null | grep -q "^$DEMO_USER\b"; then
    printf '%s\n' "$DEMO_PASSWORD" | "$BIN" admin user add "$DEMO_USER" --admin || true
fi

exec cargo watch \
    --why \
    -w crates -w Cargo.toml -w Cargo.lock \
    -x 'run -p rostdav -- serve'
