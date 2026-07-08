#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "ERROR: python not found" >&2
  exit 127
fi

TARGET_ARGS=()
TARGET_DIR="$ROOT/target"
if [[ -n "${ASTROLABE_RUST_TARGET:-}" ]]; then
  TARGET_ARGS=(--target "$ASTROLABE_RUST_TARGET")
  TARGET_DIR="$ROOT/target/$ASTROLABE_RUST_TARGET"
fi

EXE=""
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;;
esac

cargo build -p astrolabe-server --bin astrolabe "${TARGET_ARGS[@]}"

CBM_BUILD_DIR="$ROOT/target/cbm-parity"
make -C "$ROOT/vendor/codebase-memory-mcp" \
  -f "$ROOT/patches/cbm/Makefile.cbm" \
  "BUILD_DIR=$CBM_BUILD_DIR" \
  cbm

UPSTREAM_BIN="$CBM_BUILD_DIR/codebase-memory-mcp$EXE"
if [[ ! -x "$UPSTREAM_BIN" && -x "$CBM_BUILD_DIR/codebase-memory-mcp" ]]; then
  UPSTREAM_BIN="$CBM_BUILD_DIR/codebase-memory-mcp"
fi

ASTROLABE_BIN="$TARGET_DIR/debug/astrolabe$EXE"
if [[ ! -x "$ASTROLABE_BIN" && -x "$TARGET_DIR/debug/astrolabe" ]]; then
  ASTROLABE_BIN="$TARGET_DIR/debug/astrolabe"
fi

"$PYTHON_BIN" scripts/check-mcp-parity.py \
  --upstream "$UPSTREAM_BIN" \
  --astrolabe "$ASTROLABE_BIN"
