#!/usr/bin/env bash
# Runs the litmus WebDAV test suites `basic` and `copymove` against a fresh
# Rostdav instance. Requires `litmus` (apt install litmus).
# Usage: scripts/litmus.sh [path/to/rostdav]
set -euo pipefail

BIN="${1:-./target/debug/rostdav}"
PORT="${LITMUS_PORT:-18099}"
PASSWORD="litmus-test-password"
DIR="$(mktemp -d)"
trap 'kill "${PID:-0}" 2>/dev/null || true; rm -rf "$DIR"' EXIT

export ROSTDAV_STORAGE__DATA_DIR="$DIR/data"
export ROSTDAV_SERVER__LISTEN="127.0.0.1:$PORT"
printf '%s\n' "$PASSWORD" | "$BIN" admin user add litmus >/dev/null
"$BIN" serve >"$DIR/server.log" 2>&1 &
PID=$!

for _ in $(seq 50); do
  curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null && break
  sleep 0.2
done

TESTS="basic copymove" litmus "http://127.0.0.1:$PORT/remote.php/dav/files/litmus/" litmus "$PASSWORD"
