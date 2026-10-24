#!/usr/bin/env bash
# Pre-commit verification in the real container: build the production image, start it,
# check health, then run the Playwright UI checks (phone/tablet/desktop, light/dark).
# Usage: scripts/verify.sh   (needs docker, node, google-chrome)
set -euo pipefail

cd "$(dirname "$0")/.."
IMAGE="rostdav-verify:local"
NAME="rostdav-verify-$$"
PORT="${VERIFY_PORT:-18090}"
USER_NAME="verify"
PASSWORD="verify-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"  # throwaway, container only
OUT="scripts/verify/out"

for tool in docker node npm curl google-chrome; do
  command -v "$tool" >/dev/null || { echo "ERROR: $tool not found"; exit 1; }
done
docker info >/dev/null 2>&1 || { echo "ERROR: docker daemon not running"; exit 1; }

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker build -t "$IMAGE" .
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8080" "$IMAGE" >/dev/null

for _ in $(seq 1 100); do
  curl -sf "http://127.0.0.1:$PORT/readyz" >/dev/null && break
  sleep 0.2
done
curl -sf "http://127.0.0.1:$PORT/readyz" >/dev/null || { docker logs "$NAME"; echo "ERROR: container not ready"; exit 1; }
[ "$(docker inspect -f '{{.State.Running}}' "$NAME")" = true ] || { echo "ERROR: container stopped"; exit 1; }

printf '%s\n' "$PASSWORD" | docker exec -i "$NAME" rostdav admin user add "$USER_NAME" --admin >/dev/null

if docker logs "$NAME" 2>&1 | grep -q -e "$PASSWORD"; then echo "ERROR: password in container log"; exit 1; fi

(cd scripts/verify && npm ci --silent)
rm -rf "$OUT"; mkdir -p "$OUT"
node scripts/verify/check.mjs "http://127.0.0.1:$PORT" "$USER_NAME" "$PASSWORD" "$OUT" \
  || { echo "Screenshots: $OUT"; exit 1; }

echo "Verify passed (screenshots in $OUT)"
