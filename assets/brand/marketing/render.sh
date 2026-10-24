#!/usr/bin/env bash
# Render src/*.html to png/ (and the one-pager to PDF) with headless Chrome. Run build.py first.
set -euo pipefail
cd "$(dirname "$0")"
python3 build.py
for f in src/*.html; do
  n=$(basename "$f" .html)
  [ "$n" = one-pager ] && continue
  size=$(grep -oE 'html,body\{width:[0-9]+px;height:[0-9]+px' "$f" | grep -oE '[0-9]+' | paste -sd,)
  google-chrome --headless=new --no-sandbox --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --window-size="$size" --screenshot="$PWD/png/$n.png" "file://$PWD/$f" >/dev/null 2>&1
done
google-chrome --headless=new --no-sandbox --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="$PWD/one-pager.pdf" "file://$PWD/src/one-pager.html" >/dev/null 2>&1
ls png
