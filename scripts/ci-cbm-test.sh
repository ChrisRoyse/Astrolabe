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
  # Unsanitized GCC value-range analysis promotes alloc-size-larger-than to
  # a -Werror failure in pinned CBM sources that upstream compiles only
  # sanitized or with clang. The diagnostic is parameterized, so GCC has no
  # -Wno-error= form; disable it through the same documented make override
  # and announce the suppression, never silently.
  echo "INFO[ASTRO_CBM_UNSANITIZED_WERROR_DEMOTION]: -Wno-alloc-size-larger-than applied to the unsanitized CBM test build (GCC offers no -Wno-error= form for this parameterized diagnostic)"
  SANITIZE_OVERRIDES+=("SANITIZE=-Wno-alloc-size-larger-than")
fi

# The toolchain launcher confines TEMP/TMP to a child directory inside this
# repository, so a "non-git" CBM fixture would otherwise discover the outer
# Astrolabe .git and report is_git=true. Stop git upward discovery at the
# temp root; fixtures that create their own repositories are unaffected.
TMP_ROOT="${TMPDIR:-${TMP:-${TEMP:-}}}"
if [[ -n "$TMP_ROOT" ]]; then
  export GIT_CEILING_DIRECTORIES="${TMP_ROOT//\\//}"
fi

case "$LABEL" in
  windows-*-mingw)
    # Source-derived counting overstates native Windows: registrations
    # behind POSIX-only conditional compilation never build, and the
    # upstream incremental suite cannot set up (see the totals manifest).
    # Read the exact measured baseline instead, in the known-skips style.
    TOTALS_MANIFEST="$ROOT/ci/cbm-test-totals.md"
    if [[ ! -f "$TOTALS_MANIFEST" ]]; then
      echo "ERROR: ASTRO_CBM_TOTALS_MANIFEST_MISSING: $TOTALS_MANIFEST" >&2
      exit 1
    fi
    row="$(
      awk -F'|' -v target="$LABEL" '
        function trim(value) {
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
          return value
        }
        {
          system_name = trim($2)
          label = trim($3)
          if (system_name == "CBM" && label == target) {
            matches++
            expected = trim($4)
          }
        }
        END { printf "%d|%s\n", matches, expected }
      ' "$TOTALS_MANIFEST"
    )"
    matches="${row%%|*}"
    expected="${row#*|}"
    if [[ "$matches" != "1" ]]; then
      echo "ERROR: ASTRO_CBM_TOTALS_BASELINE_AMBIGUOUS: expected exactly one CBM row for $LABEL, found $matches" >&2
      exit 1
    fi
    ;;
  *)
    expected="$(
      find tests -path 'tests/repro' -prune -o -name '*.c' -print0 |
        xargs -0 grep -h -o 'RUN_TEST(' |
        wc -l |
        tr -d '[:space:]'
    )"
    ;;
esac
if [[ ! "$expected" =~ ^[0-9]+$ || "$expected" -le 0 ]]; then
  echo "ERROR: failed to derive CBM expected test count from pinned source." >&2
  exit 1
fi

set +e
scripts/test.sh "CC=$CC_BIN" "CXX=$CXX_BIN" ${SANITIZE_OVERRIDES[@]+"${SANITIZE_OVERRIDES[@]}"} 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
set -e

# Anchored: the unit-suite summary starts with its count; later harness
# steps (security-strings) print prefixed "N passed" lines that must not
# shadow it.
summary="$(grep -E '^[[:space:]]*[0-9]+ passed' "$LOG" | tail -n 1 || true)"
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

if [[ "$LABEL" == windows-*-mingw ]] && grep -q 'SETUP FAILED' "$LOG"; then
  # The upstream incremental suite's fixture clone builds its shell command
  # with POSIX single quoting and runs it through system(), which is cmd.exe
  # in a native Windows binary; the clone always fails there and upstream
  # treats that as a graceful suite skip that never registers its tests. The
  # totals baseline already excludes those registrations; this marker names
  # the degradation and its coverage owner.
  echo "SKIP[ASTRO_CBM_INCREMENTAL_LINUX_REQUIRED]: the upstream incremental suite cannot set up on native Windows (POSIX shell quoting through system()); its registrations are excluded from the ci/cbm-test-totals.md baseline. Incremental coverage is owned by the required Linux CI jobs cbm tests / linux-x64-gcc and linux-x64-clang."
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
