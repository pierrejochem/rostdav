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

# Known deviation: PUT into a missing parent answers 404 like Nextcloud
# (docs/compatibility.md), litmus `put_no_parent` wants 409. Any other failure
# is an error.
OUT="$DIR/litmus.out"
set +e
TESTS="basic copymove" litmus "http://127.0.0.1:$PORT/remote.php/dav/files/litmus/" litmus "$PASSWORD" 2>&1 | tee "$OUT"
STATUS=${PIPESTATUS[0]}
set -e
[ "$STATUS" -eq 0 ] && exit 0
if [ "$(grep -c ' FAIL' "$OUT")" -eq 1 ] && grep -q 'put_no_parent\.* FAIL' "$OUT"; then
  echo "litmus: only the known put_no_parent deviation failed"
  exit 0
fi
exit "$STATUS"
