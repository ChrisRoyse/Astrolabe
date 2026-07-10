#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  echo "ERROR: python not found" >&2
  exit 1
fi

bash scripts/check-full.sh
cargo build --workspace --release
"$PYTHON_BIN" scripts/check-binary-size.py
exec bash "$ROOT/scripts/release-predicate.sh" "$@"
