#!/usr/bin/env bash
set -e

echo "Building netwatch for $(uname -s)…"

pip install pyinstaller anthropic flask --quiet

pyinstaller \
  --onefile \
  --name netwatch \
  --icon icon.icns \
  --strip \
  --clean \
  netwatch.py

echo ""
echo "Done → dist/netwatch"
echo "Share that single file. Run with:  ./dist/netwatch"
