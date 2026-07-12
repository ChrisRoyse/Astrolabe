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

# #189: this gate used to fork its own target/<triple>/debug tree whenever
# ASTROLABE_RUST_TARGET was set, which the Rust gate set to the host triple --
# so the parity binary was rebuilt from cold into a second artifact tree that
# shared nothing with the target/debug tree the aggregate had just built. The
# aggregate no longer passes a redundant --target on the native path (see
# scripts/ci-rust-gate.sh), so there is exactly ONE tree: target/debug. Resolve
# it directly rather than re-encoding the split here.
TARGET_DIR="$ROOT/target"

EXE=""
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;;
esac

cargo build -p astrolabe-server --bin astrolabe

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
