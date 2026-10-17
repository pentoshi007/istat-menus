#!/bin/bash
# One-step install for the patched iStat Menus build: extracts
# iStatMenus7.50.1-patched.zip (the self-contained deliverable: app +
# installer + signing assets) and runs its installer.
set -euo pipefail

DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
ZIP="$DIR/iStatMenus7.50.1-patched.zip"
WORK="$DIR/.bootstrap-extract"

[ "$(uname -s)" = "Darwin" ] || { echo "[!] This script must be run on macOS."; exit 1; }
[ -f "$ZIP" ] || { echo "[!] $ZIP not found - keep the repo contents together."; exit 1; }

echo "== iStat Menus 7.50.1 (patched) - bootstrap =="
rm -rf "$WORK"
mkdir -p "$WORK"
echo "[1/2] extracting deliverable ..."
ditto -x -k "$ZIP" "$WORK"
[ -f "$WORK/install.command" ] || { echo "[!] install.command missing inside $ZIP"; exit 1; }

echo "[2/2] running installer ..."
exec bash "$WORK/install.command"
