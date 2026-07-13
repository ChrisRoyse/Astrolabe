#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: bash scripts/ci-cbm-test.sh <label> <cc> <cxx>" >&2
  exit 2
fi

LABEL="$1"
# Backslashed Windows compiler paths survive quoted bash use but are mangled
# inside the pinned Makefile's $(shell echo | $(CC) ...) MinGW autodetection,
# which silently drops WIN32_LIBS from the link. Normalize to forward
# slashes; POSIX paths are unaffected.
CC_BIN="${2//\\//}"
CXX_BIN="${3//\\//}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CBM="$ROOT/vendor/codebase-memory-mcp"
# #280: phase evidence (tee'd log, hermeticity manifests, sanitizer probe)
# lives in a PID-scoped dir under .tmp, NOT under target/ — a concurrent or
# just-exited session's target/ cleanup must never be able to delete this
# phase's before-manifest mid-run (observed 2026-07-12: FileNotFoundError at
# the verify step after a green suite).
LOG_DIR="$ROOT/.tmp/cbm-phase-$$"
LOG="$LOG_DIR/cbm-${LABEL}.log"
mkdir -p "$LOG_DIR"
cleanup_phase_dir() { rm -rf -- "$LOG_DIR"; }
trap cleanup_phase_dir EXIT

if command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  echo "ERROR: ASTRO_CBM_PYTHON_MISSING: python is required by the CBM gate." >&2
  echo "  remediation: install python (or python3) on PATH before running the CBM gate." >&2
  exit 1
fi

# ── #280 suite impact gate: no suite runs when no code change impacts it ────
# Fail closed: only a byte-identical input set vs the last recorded GREEN run
# skips (exit 3); every other state — including any gate error — runs.
impact_rc=0
"$PYTHON_BIN" "$ROOT/scripts/check-suite-impact.py" should-run cbm-c-suite || impact_rc=$?
if [[ "$impact_rc" -eq 3 ]]; then
  echo "COUNTS[ASTRO_CBM_TESTS] label=$LABEL suite-skipped-unchanged (see SKIP[ASTRO_SUITE_UNCHANGED] above; recorded-green counts are in .astro-gate-cache/suite-green.json)"
  exit 0
fi

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
  # No CI job owns this (hosted CI is banned, 2026-07-11). MinGW-w64 GCC ships
  # no ASan/UBSan runtimes, so this run has NO sanitizer coverage of the CBM C
  # suite. Sanitized runs are port-phase work, not work we are deferring to a
  # nonexistent CI job. Named, counted, never passing evidence.
  echo "SKIP[ASTRO_CBM_SANITIZERS_LINUX_REQUIRED]: $CC_BIN cannot link the sanitizer probe (this toolchain ships no sanitizer runtime); running the CBM suite with SANITIZE= per the pinned Makefile.cbm Windows override. This run has NO ASan/UBSan/LSan coverage of the CBM C suite."
  echo "DEFERRED[ASTRO_PORT_PHASE]: sanitizer coverage of the CBM C suite is deferred to the port phase (Windows-only scope, owner directive 2026-07-11); tracked in #238. Not passing evidence; no CI job owns it."
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

# ── Hermetic CBM project store (#194/#232) ────────────────────────────────
#
# The CBM store has no registry table: a project is "registered" purely by the
# presence of `<slug>.db` in the resolved cache directory, so every fixture the
# suite indexes lands permanently in whatever store the library resolves.
#
# cbm_resolve_cache_dir() (src/foundation/platform.c:404) honours CBM_CACHE_DIR,
# but the vendored tests do NOT call it: they hand-build the same path from
# getenv("HOME") (tests/test_integration.c:116 and 20 sibling files). A
# CBM_CACHE_DIR redirect therefore moves the library's WRITE path away from the
# tests' READ path and regresses ~808 tests (reverted in de2fc30) — the env var
# was never the defect, the duplicated formula is.
#
# HOME is the one input BOTH halves read: cbm_get_home_dir()
# (platform.c:327) reads HOME first, then USERPROFILE. Redirecting HOME moves
# the library and the tests together, by construction. USERPROFILE follows it so
# the resolver cannot reach the operator's profile through the second branch, and
# CBM_CACHE_DIR is cleared so no split can be reintroduced from the environment.
# Native path form: the CBM test binaries are native Windows executables and
# read HOME with getenv(). An MSYS POSIX path (/c/...) would resolve against the
# current drive root inside them, so every path handed to a native child or to
# python is converted here, fail-closed.
to_native() {
  if [[ -n "${MSYSTEM:-}" ]]; then
    if ! command -v cygpath >/dev/null 2>&1; then
      echo "ERROR: ASTRO_CBM_CYGPATH_MISSING: cygpath is required to hand native Windows paths to the CBM test binaries." >&2
      echo "  remediation: run the CBM gate under Git for Windows bash (which ships cygpath), not a stripped POSIX shell." >&2
      exit 1
    fi
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

OPERATOR_HOME="${HOME:-${USERPROFILE:-}}"
if [[ -z "$OPERATOR_HOME" ]]; then
  echo "ERROR: ASTRO_CBM_OPERATOR_HOME_UNSET: neither HOME nor USERPROFILE is set, so the protected CBM store cannot be located." >&2
  echo "  remediation: export HOME (or USERPROFILE) before running the CBM gate." >&2
  exit 1
fi
# Whatever store this run WOULD have written to is the store that must come out
# byte-identical — including an inherited CBM_CACHE_DIR.
PROTECTED_CACHE="$(to_native "${CBM_CACHE_DIR:-$OPERATOR_HOME/.cache/codebase-memory-mcp}")"
NATIVE_ROOT="$(to_native "$ROOT")"
CBM_TEST_HOME="$NATIVE_ROOT/target/cbm-test-home"
RUN_SCOPED_CACHE="$CBM_TEST_HOME/.cache/codebase-memory-mcp"
BEFORE_MANIFEST="$(to_native "$LOG_DIR")/cbm-store-before-${LABEL}.manifest"
AFTER_MANIFEST="$(to_native "$LOG_DIR")/cbm-store-after-${LABEL}.manifest"

echo "=== CBM store hermeticity: protected-store snapshot (before) ==="
"$PYTHON_BIN" "$ROOT/scripts/check-cbm-cache-hermeticity.py" snapshot \
  --cache-dir "$PROTECTED_CACHE" --out "$BEFORE_MANIFEST"

rm -rf -- "$CBM_TEST_HOME"
mkdir -p "$RUN_SCOPED_CACHE"
# The suite's git fixtures must not depend on operator identity either; give the
# run-scoped HOME a deterministic global config instead of inheriting one.
cat > "$CBM_TEST_HOME/.gitconfig" <<'CBM_GITCONFIG'
[user]
	name = Astrolabe CBM Gate
	email = cbm-gate@astrolabe.invalid
[init]
	defaultBranch = main
CBM_GITCONFIG
export HOME="$CBM_TEST_HOME"
export USERPROFILE="$CBM_TEST_HOME"
unset CBM_CACHE_DIR
echo "INFO[ASTRO_CBM_RUN_SCOPED_STORE]: HOME/USERPROFILE redirected to $CBM_TEST_HOME for this phase; the library resolver and the vendored tests both derive the store from HOME, so they move together (no CBM_CACHE_DIR split)."

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

# The suite is only hermetic if BOTH halves hold: the protected store came out
# byte-identical, AND the run-scoped store actually received the writes. A suite
# that silently indexed nothing would satisfy the first alone.
echo "=== CBM store hermeticity: protected-store verification (after) ==="
"$PYTHON_BIN" "$ROOT/scripts/check-cbm-cache-hermeticity.py" verify \
  --cache-dir "$PROTECTED_CACHE" --before "$BEFORE_MANIFEST" --out "$AFTER_MANIFEST"

echo "=== CBM store hermeticity: run-scoped store received the writes ==="
# #280: the sharded runner gives each shard its own HOME under
# $CBM_TEST_HOME/shards/home-N, so store writes land in per-shard stores (plus
# possibly the base store, used by the post-shard watchdog/security steps).
# The honest requirement is unchanged — the suite must have written SOMEWHERE
# run-scoped — so require at least one non-empty run-scoped store.
stores_with_writes=0
for run_store in "$RUN_SCOPED_CACHE" "$CBM_TEST_HOME"/shards/home-*/.cache/codebase-memory-mcp; do
  [[ -d "$run_store" ]] || continue
  if "$PYTHON_BIN" "$ROOT/scripts/check-cbm-cache-hermeticity.py" require-writes \
    --cache-dir "$run_store" > "$LOG_DIR/require-writes.last" 2>&1; then
    stores_with_writes=$((stores_with_writes + 1))
  fi
done
if [[ "$stores_with_writes" -lt 1 ]]; then
  echo "ERROR: ASTRO_CBM_RUN_SCOPED_STORE_EMPTY: no run-scoped store (base or shard) received writes." >&2
  echo "  The suite indexed nothing into any redirected store, so a clean operator cache proves nothing." >&2
  echo "  remediation: confirm HOME/USERPROFILE reach the native test binaries (last probe output follows)." >&2
  cat "$LOG_DIR/require-writes.last" >&2 || true
  exit 1
fi
echo "CBM run-scoped stores with writes: $stores_with_writes"

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
  echo "SKIP[ASTRO_CBM_INCREMENTAL_LINUX_REQUIRED]: the upstream incremental suite cannot set up on native Windows (POSIX shell quoting through system()); its registrations are excluded from the ci/cbm-test-totals.md baseline. This run has NO incremental-suite coverage."
  echo "DEFERRED[ASTRO_PORT_PHASE]: CBM incremental-suite coverage is deferred to the port phase (Windows-only scope, owner directive 2026-07-11); tracked in #238. Not passing evidence; no CI job owns it."
fi

total=$((passed + failed + skipped))
if [[ "$total" -ne "$expected" ]]; then
  echo "ERROR: CBM runtime test count $total does not match pinned-source expected count $expected." >&2
  exit 1
fi

bash "$ROOT/scripts/check-cbm-skip-count.sh" "$LABEL" "$skipped"

# Counts go to stdout, which is the evidence stream (no hosted CI, no step summary).
echo "COUNTS[ASTRO_CBM_TESTS] label=$LABEL expected=$expected passed=$passed failed=$failed skipped=$skipped total=$total cc=$CC_BIN cxx=$CXX_BIN"

if [[ "$rc" -ne 0 ]]; then
  exit "$rc"
fi
if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

# #280: record this GREEN run's input fingerprint so an unchanged input set
# skips the suite next time (never weakens anything: any byte change, tool
# bump, or manifest ambiguity re-runs — see check-suite-impact.py).
"$PYTHON_BIN" "$ROOT/scripts/check-suite-impact.py" record-green cbm-c-suite \
  --note "label=$LABEL passed=$passed failed=$failed skipped=$skipped"
