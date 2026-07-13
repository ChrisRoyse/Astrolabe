#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CBM="$ROOT/vendor/codebase-memory-mcp"
HOST_OS="$(uname -s)"
CPPCHECK_COMMAND="${CPPCHECK:-cppcheck}"
FORMAT_TMP_PARENT="$ROOT/.tmp"
FORMAT_TMP_PARENT_EXISTED=0
FORMAT_WORKSPACE=""
if [[ -d "$FORMAT_TMP_PARENT" ]]; then
  FORMAT_TMP_PARENT_EXISTED=1
fi

cleanup_format_workspace() {
  local status=$?
  if [[ -n "$FORMAT_WORKSPACE" ]]; then
    rm -rf -- "$FORMAT_WORKSPACE"
  fi
  if [[ "$FORMAT_TMP_PARENT_EXISTED" -eq 0 ]]; then
    rmdir -- "$FORMAT_TMP_PARENT" 2>/dev/null || true
  fi
  return "$status"
}
trap cleanup_format_workspace EXIT

if command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  echo "ERROR: ASTRO_CBM_PYTHON_MISSING: python is required by the CBM cache-path gate." >&2
  echo "  remediation: install python (or python3) on PATH before running the CBM lint gate." >&2
  exit 1
fi

echo "=== CBM cache-path construction sites ==="
"$PYTHON_BIN" "$ROOT/scripts/check-cbm-cache-paths.py"

cd "$CBM"

echo "=== CBM no-skips policy ==="
bash scripts/check-no-test-skips.sh

if [[ "$HOST_OS" == "Linux" ]]; then
  echo "=== CBM clang-tidy ==="
  make -f Makefile.cbm lint-tidy CLANG_TIDY="${CLANG_TIDY:-clang-tidy}"
else
  # Hosted CI is banned (2026-07-11), so no CI job owns this gate and none may
  # be claimed. Astrolabe is Windows-only scope until the system is fully
  # operational natively; other platforms are a scheduled port phase at the end.
  # clang-tidy's analysis is platform-dependent, so this run has NO clang-tidy
  # coverage. Named, counted, never passing evidence. See
  # docs/port-phase-deferrals.md.
  echo "SKIP[ASTRO_CBM_CLANG_TIDY_LINUX_REQUIRED]: clang-tidy analysis is platform-dependent and this host is $HOST_OS; this run has NO clang-tidy coverage of the CBM C sources."
  echo "DEFERRED[ASTRO_PORT_PHASE]: CBM clang-tidy analysis is deferred to the port phase (Windows-only scope, owner directive 2026-07-11); tracked in #238. Not passing evidence; no CI job owns it."
  CPPCHECK_COMMAND="$CPPCHECK_COMMAND --platform=unix64"
  echo "INFO[ASTRO_CBM_CPPCHECK_LINUX_ABI]: cppcheck targets the unix64 ABI so its findings stay stable and comparable across hosts; this is an analyzer-ABI choice only, and it asserts no non-Windows coverage."
fi

echo "=== CBM cppcheck ==="
make -f Makefile.cbm lint-cppcheck CPPCHECK="$CPPCHECK_COMMAND"

# #250: static-analyze the Astrolabe-owned CBM C (patches/cbm/*.c). The vendored
# lint-cppcheck above only covers vendored sources; these Astrolabe-authored files
# are the new-code surface most worth analyzing. Same analyzer + ABI ($CPPCHECK_COMMAND
# already carries the unix64 platform flag on non-Linux) so findings stay comparable.
echo "=== CBM cppcheck (Astrolabe-owned C #250) ==="
make -f "$ROOT/patches/cbm/Makefile.cbm" lint-cppcheck-astrolabe CPPCHECK="$CPPCHECK_COMMAND"

echo "=== CBM clang-format ==="
mkdir -p "$FORMAT_TMP_PARENT"
FORMAT_WORKSPACE="$(mktemp -d "$FORMAT_TMP_PARENT/cbm-format.XXXXXX")"
# #286: the CBM sources are owned and edited in place, so lint-format-astrolabe
# format-checks them directly (as LINT_SRCS) plus the two Astrolabe-owned glue
# TUs (env_store_config.{c,h}) that still live outside the CBM src tree, fed via
# stdin with a vendor-relative assumed name so ./.clang-format applies. The
# spawn helper is handled by the same target's astro-lint-format-spawn prereq.
echo "INFO[ASTRO_CBM_FORMAT]: owned CBM sources format-checked in place (patches/cbm/Makefile.cbm: lint-format-astrolabe)"
make -f "$ROOT/patches/cbm/Makefile.cbm" lint-format-astrolabe \
  CLANG_FORMAT="${CLANG_FORMAT:-clang-format}" \
  BUILD_DIR="$FORMAT_WORKSPACE/build"

echo "=== CBM NOLINT whitelist ==="
make -f Makefile.cbm lint-no-suppress
