#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: bash scripts/ci-cbm-test.sh <label> <cc> <cxx>" >&2
  exit 2
fi

LABEL="$1"
CC_BIN="$2"
CXX_BIN="$3"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CBM="$ROOT/vendor/codebase-memory-mcp"
LOG_DIR="$ROOT/target/ci-logs"
LOG="$LOG_DIR/cbm-${LABEL}.log"

mkdir -p "$LOG_DIR"

cd "$CBM"

case "$LABEL" in
  windows-*-mingw)
    if [[ -z "${MSYSTEM:-}" ]]; then
      echo "ERROR: Windows CBM gate must run under MSYS2/MinGW, not MSVC." >&2
      exit 1
    fi
    triple="$("$CC_BIN" -dumpmachine 2>/dev/null || true)"
    if [[ "$triple" != *mingw* && "$triple" != *w64* && "$triple" != *windows-gnu* ]]; then
      echo "ERROR: Windows CBM compiler is not a MinGW/GNU toolchain: ${triple:-unknown}" >&2
      exit 1
    fi
    ;;
esac

# Sanitizer availability is measured against the actual toolchain, never
# assumed. The pinned Makefile.cbm defaults to ASan+UBSan and documents
# `SANITIZE=` as the Windows disable override; MinGW-w64 GCC ships no
# sanitizer runtimes. A disabled run is named and counted, and Linux gates
# may never disable sanitizers because they own that coverage.
SANITIZE_OVERRIDES=()
PROBE_DIR="$LOG_DIR/cbm-sanitizer-probe-${LABEL}"
rm -rf -- "$PROBE_DIR"
mkdir -p "$PROBE_DIR"
printf 'int main(void) { return 0; }\n' > "$PROBE_DIR/probe.c"
if "$CC_BIN" -fsanitize=address,undefined -fno-omit-frame-pointer \
  "$PROBE_DIR/probe.c" -o "$PROBE_DIR/probe-bin" \
  > "$PROBE_DIR/probe.log" 2>&1; then
  echo "INFO[ASTRO_CBM_SANITIZERS_ACTIVE]: $CC_BIN links -fsanitize=address,undefined; running the CBM suite sanitized"
else
  if [[ "$LABEL" == linux-* ]]; then
    echo "ERROR: sanitizers are required on Linux CBM gates; $CC_BIN failed to link the sanitizer probe (log: $PROBE_DIR/probe.log)" >&2
    exit 1
  fi
  echo "SKIP[ASTRO_CBM_SANITIZERS_LINUX_REQUIRED]: $CC_BIN cannot link the sanitizer probe (no toolchain runtime); running the CBM suite with SANITIZE= per the pinned Makefile.cbm Windows override. Sanitizer coverage of the CBM C suite is owned by the required Linux CI jobs cbm tests / linux-x64-gcc and linux-x64-clang."
  SANITIZE_OVERRIDES+=("SANITIZE=")
fi

expected="$(
  find tests -path 'tests/repro' -prune -o -name '*.c' -print0 |
    xargs -0 grep -h -o 'RUN_TEST(' |
    wc -l |
    tr -d '[:space:]'
)"
if [[ ! "$expected" =~ ^[0-9]+$ || "$expected" -le 0 ]]; then
  echo "ERROR: failed to derive CBM expected test count from pinned source." >&2
  exit 1
fi

set +e
scripts/test.sh "CC=$CC_BIN" "CXX=$CXX_BIN" ${SANITIZE_OVERRIDES[@]+"${SANITIZE_OVERRIDES[@]}"} 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
set -e

summary="$(grep -E '[0-9]+ passed' "$LOG" | tail -n 1 || true)"
if [[ -z "$summary" ]]; then
  echo "ERROR: CBM test summary was not found in $LOG" >&2
  exit 1
fi

passed="$(sed -nE 's/.*[^0-9]([0-9]+) passed.*/\1/p' <<<"$summary")"
failed="$(sed -nE 's/.*[^0-9]([0-9]+) failed.*/\1/p' <<<"$summary")"
skipped="$(sed -nE 's/.*[^0-9]([0-9]+) skipped.*/\1/p' <<<"$summary")"
failed="${failed:-0}"
skipped="${skipped:-0}"

if [[ ! "$passed" =~ ^[0-9]+$ || ! "$failed" =~ ^[0-9]+$ || ! "$skipped" =~ ^[0-9]+$ ]]; then
  echo "ERROR: failed to parse CBM test summary: $summary" >&2
  exit 1
fi

total=$((passed + failed + skipped))
if [[ "$total" -ne "$expected" ]]; then
  echo "ERROR: CBM runtime test count $total does not match pinned-source expected count $expected." >&2
  exit 1
fi

bash "$ROOT/scripts/check-cbm-skip-count.sh" "$LABEL" "$skipped"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### CBM C test gate: $LABEL"
    echo
    echo "| Metric | Count |"
    echo "|---|---:|"
    echo "| Expected tests from pinned source | $expected |"
    echo "| Passed | $passed |"
    echo "| Failed | $failed |"
    echo "| Skipped | $skipped |"
    echo "| Runtime total | $total |"
    echo
    echo "Compiler: \`$CC_BIN\` / \`$CXX_BIN\`"
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [[ "$rc" -ne 0 ]]; then
  exit "$rc"
fi
if [[ "$failed" -ne 0 ]]; then
  exit 1
fi
