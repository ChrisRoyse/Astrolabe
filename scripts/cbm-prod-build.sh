#!/usr/bin/env bash
# Build (or restore from cache) the upstream CBM production binary used by the
# byte-parity gates (scripts/check-mcp-parity.sh, scripts/check-lowered-parity.py). #280.
#
# The CBM prod build (`make ... cbm`, ~200 grammar translation units) is the
# single largest cost in check.sh (~320s of the 322.8s check-mcp-parity.sh gate,
# even with warm sccache C-object hits, because link/archive and the make graph
# dominate). Its output is a PURE FUNCTION of byte-pinned inputs:
#
#   * vendor/codebase-memory-mcp -- byte-pinned by scripts/verify-pins.sh
#     (unconditional, fail-closed, runs at the top of every aggregate), so the
#     committed subtree SHA fully identifies the C sources.
#   * patches/cbm/**            -- the Astrolabe overlay + Makefile.cbm.
#   * the C toolchain identity  -- CC/CXX version + host triple (ABI).
#
# So a rebuild from an unchanged (pin + overlay + toolchain) is provably
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
key=""
if command -v git >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1; then
  vendor_tree="$(git -C "$ROOT" rev-parse "HEAD:vendor/codebase-memory-mcp" 2>/dev/null || true)"
  if [[ -n "$vendor_tree" && -d "$ROOT/patches/cbm" ]]; then
    # Hash of every byte under patches/cbm (the overlay + Makefile.cbm).
    patches_hash="$(
      find "$ROOT/patches/cbm" -type f -print0 \
        | LC_ALL=C sort -z \
        | xargs -0 sha256sum \
        | sha256sum \
        | cut -d' ' -f1
    )" || patches_hash=""
    cc_id="$("$CC_BIN" -dumpversion 2>/dev/null || echo unknown)"
    cxx_id="$("$CXX_BIN" -dumpversion 2>/dev/null || echo unknown)"
    host_id="$(uname -sm 2>/dev/null || echo unknown)"
    if [[ -n "$patches_hash" ]]; then
      key="$(printf '%s|%s|%s|%s|%s' \
        "$vendor_tree" "$patches_hash" "$cc_id" "$cxx_id" "$host_id" \
        | sha256sum | cut -d' ' -f1)"
    fi
  fi
fi

CACHE_ROOT="$ROOT/.astro-gate-cache/cbm-parity"
cached_bin=""
if [[ -n "$key" ]]; then
  cached_bin="$CACHE_ROOT/$key/codebase-memory-mcp$EXE"
  if [[ -f "$cached_bin" ]]; then
    cp -f "$cached_bin" "$BUILD_DIR/codebase-memory-mcp$EXE"
    echo "INFO[ASTRO_CBM_PARITY_BINARY_CACHED]: key=${key:0:12} (byte-identical to a build from the pinned vendor subtree + patches/cbm overlay + toolchain)"
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
