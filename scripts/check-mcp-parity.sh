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

# This gate is a DUAL-PATH CONSISTENCY check: it compares the astrolabe Rust host
# against the standalone C production binary built from the SAME owned CBM
# sources (with ASTRO_PROD_DEFS), so a divergence means the two code paths over
# one source base disagree — not that we drifted from an external upstream.
#
# #280: the CBM prod binary is the dominant cost of this gate. Build it through
# the shared cache helper, which restores a byte-identical binary from a
# gitignored cache keyed on (owned CBM subtree + patches/cbm Makefile/glue +
# toolchain identity) when nothing changed, and otherwise runs the same `make`
# and populates the cache. check-lowered-parity.py reuses this same BUILD_DIR
# (target/cbm-parity) so one build serves both parity gates within a run.
# Fail-closed: an ambiguous key => full build.
CBM_BUILD_DIR="$ROOT/target/cbm-parity"
bash "$ROOT/scripts/cbm-prod-build.sh" "$CBM_BUILD_DIR"

# PROD_BIN: the standalone production binary (same owned sources). Kept named
# UPSTREAM_BIN below only to avoid churning the arg wiring; it is NOT an external
# upstream — see the dual-path note above.
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
