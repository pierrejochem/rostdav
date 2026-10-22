#!/usr/bin/env bash
# Starts a built rostdav binary and checks health endpoints, log redaction
# and orderly shutdown. Usage: scripts/smoke.sh [path/to/binary]
set -euo pipefail

BIN="${1:-./target/debug/rostdav}"
PORT="${SMOKE_PORT:-18080}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

RUST_BACKTRACE=0 ROSTDAV_SERVER__LISTEN="127.0.0.1:$PORT" ROSTDAV_STORAGE__DATA_DIR="$WORK/data" \
  "$BIN" serve >"$WORK/log.txt" 2>&1 &
PID=$!

for _ in $(seq 1 50); do
  curl -s -o /dev/null "http://127.0.0.1:$PORT/healthz" && break
  sleep 0.1
done

fail() { echo "ERROR: $*"; cat "$WORK/log.txt"; kill "$PID" 2>/dev/null || true; exit 1; }

[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz")" = 200 ] || fail "healthz"
[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/readyz")" = 200 ] || fail "readyz"
ROSTDAV_SERVER__LISTEN="127.0.0.1:$PORT" "$BIN" healthcheck || fail "healthcheck subcommand"
curl -s -o /dev/null -H "Authorization: Basic c21va2U6c2VjcmV0" "http://127.0.0.1:$PORT/healthz?token=smoketoken"

kill -TERM "$PID"
wait "$PID" || fail "exit code after SIGTERM is not 0"

if ROSTDAV_SERVER__LISTEN="127.0.0.1:$PORT" "$BIN" healthcheck 2>/dev/null; then fail "healthcheck succeeds without a server"; fi
grep -q '"message":"stopped"' "$WORK/log.txt" || fail "no orderly shutdown in log"
grep -q '"path":"/healthz"' "$WORK/log.txt" || fail "requests are not logged"
if grep -q -e 'c21va2U6c2VjcmV0' -e 'smoketoken' "$WORK/log.txt"; then fail "secret in log"; fi
mode="$(stat -c %a "$WORK/data" 2>/dev/null || stat -f %Lp "$WORK/data")"  # GNU or macOS
[ "$mode" = 700 ] || fail "data directory is not 0700 (is $mode)"

echo "Smoke test passed"
