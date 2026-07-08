#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CBM="$ROOT/vendor/codebase-memory-mcp"

cd "$CBM"

echo "=== CBM no-skips policy ==="
bash scripts/check-no-test-skips.sh

echo "=== CBM clang-tidy ==="
make -f Makefile.cbm lint-tidy CLANG_TIDY="${CLANG_TIDY:-clang-tidy}"

echo "=== CBM cppcheck ==="
make -f Makefile.cbm lint-cppcheck CPPCHECK="${CPPCHECK:-cppcheck}"

echo "=== CBM clang-format ==="
make -f Makefile.cbm lint-format CLANG_FORMAT="${CLANG_FORMAT:-clang-format}"

echo "=== CBM NOLINT whitelist ==="
make -f Makefile.cbm lint-no-suppress

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### CBM lint gate"
    echo
    echo "- check-no-test-skips passed."
    echo "- clang-tidy passed with WarningsAsErrors from .clang-tidy."
    echo "- cppcheck passed with the pinned upstream suppressions."
    echo "- clang-format --dry-run --Werror passed."
    echo "- NOLINT whitelist check passed."
  } >> "$GITHUB_STEP_SUMMARY"
fi
