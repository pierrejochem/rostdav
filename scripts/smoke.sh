#!/usr/bin/env bash
# Startet ein gebautes rostdav-Binary, prüft Health-Endpunkte, Log-Schwärzung
# und geordnetes Herunterfahren. Aufruf: scripts/smoke.sh [pfad/zum/binary]
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

fail() { echo "FEHLER: $*"; cat "$WORK/log.txt"; kill "$PID" 2>/dev/null || true; exit 1; }

[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz")" = 200 ] || fail "healthz"
[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/readyz")" = 200 ] || fail "readyz"
curl -s -o /dev/null -H "Authorization: Basic c21va2U6c2VjcmV0" "http://127.0.0.1:$PORT/healthz?token=smoketoken"

kill -TERM "$PID"
wait "$PID" || fail "Exit-Code nach SIGTERM nicht 0"

grep -q '"message":"beendet"' "$WORK/log.txt" || fail "kein geordnetes Herunterfahren im Log"
grep -q '"path":"/healthz"' "$WORK/log.txt" || fail "Anfragen werden nicht geloggt"
if grep -q -e 'c21va2U6c2VjcmV0' -e 'smoketoken' "$WORK/log.txt"; then fail "Geheimnis im Log"; fi
mode="$(stat -c %a "$WORK/data" 2>/dev/null || stat -f %Lp "$WORK/data")"  # GNU bzw. macOS
[ "$mode" = 700 ] || fail "Datenverzeichnis nicht 0700 (ist $mode)"

echo "Smoke-Test bestanden"
