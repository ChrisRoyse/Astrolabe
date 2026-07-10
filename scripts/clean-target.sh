#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="$ROOT/target"

case "$TARGET_DIR" in
  "$ROOT"/target) ;;
  *)
    echo "ERROR: refusing to clean unexpected target path: $TARGET_DIR" >&2
    exit 2
    ;;
esac

if [[ -e "$TARGET_DIR" || -L "$TARGET_DIR" ]]; then
  rm -rf -- "$TARGET_DIR"
fi

if [[ -e "$TARGET_DIR" || -L "$TARGET_DIR" ]]; then
  echo "ERROR: target cleanup did not remove $TARGET_DIR" >&2
  exit 1
fi

echo "CLEANUP[ASTRO_TARGET]: $TARGET_DIR is absent"
