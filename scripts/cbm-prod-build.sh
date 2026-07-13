#!/usr/bin/env bash
# Build (or restore from cache) the CBM production binary used by the byte-parity
# gates (scripts/check-mcp-parity.sh, scripts/check-lowered-parity.py). #280. It
# is built from the SAME owned CBM sources as libcbm, with ASTRO_PROD_DEFS
# selecting the production-side features (dual-path consistency check).
#
# The CBM prod build (`make ... cbm`, ~200 grammar translation units) is the
# single largest cost in check.sh (~320s of the 322.8s check-mcp-parity.sh gate,
# even with warm sccache C-object hits, because link/archive and the make graph
# dominate). Its output is a PURE FUNCTION of its inputs:
#
#   * vendor/codebase-memory-mcp -- the owned CBM sources (WORKING-TREE bytes,
#     including dirty/untracked edits; #286 made in-place editing normal).
#   * patches/cbm/**            -- Makefile.cbm (the -D flag wiring) + glue TUs.
#   * the C toolchain identity  -- CC/CXX/make versions.
#
# So a rebuild from an unchanged (sources + Makefile + toolchain) is provably
# identical input->output, and the built binary can be cached across runs (which
# each wipe target/) in a gitignored, non-launcher-owned cache. The parity
# harness still exercises the (cached or fresh) binary against the full corpus
# every run, so a cache hit never weakens the parity property.
#
# FAIL CLOSED: any ambiguity in computing the cache key (git unavailable, subtree
# not committed, hashing error) disables the cache and performs a full `make`
# build -- the current behavior. A cache is only ever consulted on an EXACT key
# match, so it can only make a run faster, never change what is verified.
#
# Usage: cbm-prod-build.sh <BUILD_DIR>
#   Ensures <BUILD_DIR>/codebase-memory-mcp[.exe] exists (from cache or a build).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BUILD_DIR="${1:?usage: cbm-prod-build.sh <BUILD_DIR>}"
mkdir -p "$BUILD_DIR"

EXE=""
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;;
esac

CC_BIN="${CC:-gcc}"
CXX_BIN="${CXX:-g++}"

# ── fail-closed cache key ───────────────────────────────────────────────────
# #280: content-exact over the WORKING TREE via the shared fingerprint engine
# (scripts/check-suite-impact.py, registry entry cbm-parity-binary). The former
# key used HEAD:vendor/... — sound only on a clean tree; with the parent trees
# owned first-class source (#286) a dirty vendor tree is normal, and a
# HEAD-keyed cache could restore a binary built from DIFFERENT bytes. The
# fingerprint hashes dirty/untracked working-tree bytes, closing that hole.
# Any fingerprint ambiguity => no key => full build (fail closed).
key=""
if command -v python >/dev/null 2>&1; then
  PY_BIN=python
elif command -v python3 >/dev/null 2>&1; then
  PY_BIN=python3
else
  PY_BIN=""
fi
if [[ -n "$PY_BIN" ]]; then
  key="$("$PY_BIN" "$ROOT/scripts/check-suite-impact.py" fingerprint cbm-parity-binary 2>/dev/null || true)"
  [[ "$key" =~ ^[0-9a-f]{64}$ ]] || key=""
fi

CACHE_ROOT="$ROOT/.astro-gate-cache/cbm-parity"
cached_bin=""
if [[ -n "$key" ]]; then
  cached_bin="$CACHE_ROOT/$key/codebase-memory-mcp$EXE"
  if [[ -f "$cached_bin" ]]; then
    cp -f "$cached_bin" "$BUILD_DIR/codebase-memory-mcp$EXE"
    echo "INFO[ASTRO_CBM_PARITY_BINARY_CACHED]: key=${key:0:12} (byte-identical to a build from the owned CBM sources + patches/cbm Makefile/glue + toolchain)"
    exit 0
  fi
  echo "INFO[ASTRO_CBM_PARITY_CACHE_MISS]: no cached CBM prod binary for key=${key:0:12} -> building"
else
  echo "INFO[ASTRO_CBM_PARITY_CACHE_UNAVAILABLE]: cache key inputs unreadable -> building (fail closed)"
fi

# ── build ───────────────────────────────────────────────────────────────────
make -C "$ROOT/vendor/codebase-memory-mcp" \
  -f "$ROOT/patches/cbm/Makefile.cbm" \
  "BUILD_DIR=$BUILD_DIR" \
  cbm

built="$BUILD_DIR/codebase-memory-mcp$EXE"
if [[ ! -f "$built" && -f "$BUILD_DIR/codebase-memory-mcp" ]]; then
  built="$BUILD_DIR/codebase-memory-mcp"
fi
if [[ ! -f "$built" ]]; then
  echo "ERROR[ASTRO_CBM_PROD_BUILD_MISSING]: make did not produce $BUILD_DIR/codebase-memory-mcp$EXE" >&2
  exit 1
fi

# Populate the cache for future runs (only when we have a sound key).
if [[ -n "$key" ]]; then
  mkdir -p "$CACHE_ROOT/$key"
  # Atomic-ish install so a concurrent reader never sees a half-copied binary.
  tmp_bin="$CACHE_ROOT/$key/.codebase-memory-mcp$EXE.tmp.$$"
  if cp -f "$built" "$tmp_bin" 2>/dev/null && mv -f "$tmp_bin" "$CACHE_ROOT/$key/codebase-memory-mcp$EXE" 2>/dev/null; then
    echo "INFO[ASTRO_CBM_PARITY_CACHE_STORE]: cached CBM prod binary (key=${key:0:12})"
  else
    rm -f "$tmp_bin" 2>/dev/null || true
    echo "WARN[ASTRO_CBM_PARITY_CACHE_STORE_FAILED]: could not populate cache (key=${key:0:12}); continuing"
  fi
fi
