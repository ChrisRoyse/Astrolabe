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

cd "$CBM"

echo "=== CBM no-skips policy ==="
bash scripts/check-no-test-skips.sh

if [[ "$HOST_OS" == "Linux" ]]; then
  echo "=== CBM clang-tidy ==="
  make -f Makefile.cbm lint-tidy CLANG_TIDY="${CLANG_TIDY:-clang-tidy}"
else
  echo "SKIP[ASTRO_CBM_CLANG_TIDY_LINUX_REQUIRED]: clang-tidy is platform-dependent; required Linux CI job cbm lint / clang-tidy cppcheck format owns this gate"
  CPPCHECK_COMMAND="$CPPCHECK_COMMAND --platform=unix64"
  echo "INFO[ASTRO_CBM_CPPCHECK_LINUX_ABI]: cppcheck targets the required Linux CI unix64 ABI"
fi

echo "=== CBM cppcheck ==="
make -f Makefile.cbm lint-cppcheck CPPCHECK="$CPPCHECK_COMMAND"

echo "=== CBM clang-format ==="
mkdir -p "$FORMAT_TMP_PARENT"
FORMAT_WORKSPACE="$(mktemp -d "$FORMAT_TMP_PARENT/cbm-format.XXXXXX")"
echo "INFO[ASTRO_CBM_FORMAT_OVERLAY]: hash-checked graph-buffer overlay validates the pinned vendor source without mutation"
make -f "$ROOT/patches/cbm/Makefile.cbm" lint-format-astrolabe \
  CLANG_FORMAT="${CLANG_FORMAT:-clang-format}" \
  BUILD_DIR="$FORMAT_WORKSPACE/build" \
  ASTRO_FORMAT_OVERLAY_DIR="$FORMAT_WORKSPACE/overlay"

echo "=== CBM NOLINT whitelist ==="
make -f Makefile.cbm lint-no-suppress

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### CBM lint gate"
    echo
    echo "- check-no-test-skips passed."
    if [[ "$HOST_OS" == "Linux" ]]; then
      echo "- clang-tidy passed with WarningsAsErrors from .clang-tidy."
    else
      echo "- clang-tidy skipped locally; required Linux cbm lint CI owns that platform-dependent gate."
      echo "- cppcheck targets the required Linux CI unix64 ABI."
    fi
    echo "- cppcheck passed with the pinned upstream suppressions."
    echo "- clang-format --dry-run --Werror passed."
    echo "- NOLINT whitelist check passed."
  } >> "$GITHUB_STEP_SUMMARY"
fi
