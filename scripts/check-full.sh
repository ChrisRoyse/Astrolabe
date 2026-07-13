#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET_CLEANUP_OWNER="${ASTROLABE_TARGET_CLEANUP_OWNER:-check-full}"
case "$TARGET_CLEANUP_OWNER" in
  check-full)
    cleanup_target() {
      local status=$?
      if ! bash "$ROOT/scripts/clean-target.sh"; then
        return 1
      fi
      return "$status"
    }
    bash "$ROOT/scripts/clean-target.sh"
    trap cleanup_target EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    ;;
  check-release)
    ;;
  *)
    echo "ERROR: invalid ASTROLABE_TARGET_CLEANUP_OWNER: $TARGET_CLEANUP_OWNER" >&2
    exit 2
    ;;
esac

WORKSPACE_TEST_TIMEOUT_SECS="${ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS:-480}"
WORKSPACE_TEST_DEFERRED_EXIT=125

# #246: contain every phase's std::env::temp_dir() scratch to a run-scoped sandbox
# under target/ (cleaned with it) so no suite -- the portable workspace tests in
# check.sh, and the Calyx nextest in ci-rust-gate.sh -- leaks calyx-leapable-* dirs
# into the operator's real %TEMP%. The #237 no-escape gate resolves operator_temp via
# the OS known-folder (REAL_TEMP), not the env, so this contains honest writes WITHOUT
# blinding the gate to a test that bypasses the redirect. check.sh also sets this for
# its own standalone bracket; setting it here makes every child phase inherit it.
# The suite temp lives one level BELOW a dedicated ceiling dir (target/suite-tmp/tmp
# under ceiling target/suite-tmp). It is inside this git checkout, so
# std::env::temp_dir() resolves to a path *inside* the repo -- breaking tests that
# assume temp is outside a checkout (calyx-buildinfo compute_for_dir_outside_checkout_errors
# runs `git rev-parse HEAD` in env::temp_dir() and expects failure). target/ is
# git-ignored build output, so GIT_CEILING_DIRECTORIES tells git to stop its upward
# .git search at target/suite-tmp. The nesting matters: a ceiling only blocks a walk
# that crosses it FROM BELOW, so the temp must sit *under* the ceiling (git started
# in the ceiling dir itself still walks up). This isolates the temp: git from other
# target/ subtrees (release-predicate artifact commit stamping in
# target/hazard-suite-selftest/probe, target/astrolabe-release-predicate) and from
# the source tree still finds $ROOT/.git. Native Windows path form for git.exe.
AGG_SUITE_CEIL="$ROOT/target/suite-tmp"
AGG_SUITE_TMP="$AGG_SUITE_CEIL/tmp"
mkdir -p "$AGG_SUITE_TMP"
export TMP="$AGG_SUITE_TMP" TEMP="$AGG_SUITE_TMP" TMPDIR="$AGG_SUITE_TMP"
if command -v cygpath >/dev/null 2>&1; then
  export GIT_CEILING_DIRECTORIES="$(cygpath -m "$AGG_SUITE_CEIL")"
else
  export GIT_CEILING_DIRECTORIES="$AGG_SUITE_CEIL"
fi

if ! command -v rustc >/dev/null 2>&1; then
  echo "ERROR: rustc not found on PATH" >&2
  exit 1
fi

RUSTC_HOST="$(rustc -vV | sed -n 's/^host: //p')"
HOST_TARGET="${ASTROLABE_RUST_TARGET:-$RUSTC_HOST}"
if [[ -z "$RUSTC_HOST" || -z "$HOST_TARGET" ]]; then
  echo "ERROR: failed to derive the native Rust host target" >&2
  exit 1
fi
if [[ "$HOST_TARGET" != "$RUSTC_HOST" ]]; then
  echo "ERROR: check-full requires a native host toolchain; rustc host is $RUSTC_HOST but ASTROLABE_RUST_TARGET is $HOST_TARGET" >&2
  exit 1
fi

case "$HOST_TARGET" in
  x86_64-pc-windows-gnu)
    DEFAULT_LABEL="windows-x64-mingw"
    DEFAULT_CC="gcc"
    DEFAULT_CXX="g++"
    ;;
  *-pc-windows-msvc)
    echo "ERROR: native Windows checks require a GNU-host Rust toolchain; MSVC cannot link the MinGW libcbm archive" >&2
    exit 1
    ;;
  x86_64-unknown-linux-gnu)
    case "${CC:-cc}" in
      *clang*) DEFAULT_LABEL="linux-x64-clang" ;;
      *) DEFAULT_LABEL="linux-x64-gcc" ;;
    esac
    DEFAULT_CC="cc"
    DEFAULT_CXX="c++"
    ;;
  aarch64-apple-darwin)
    DEFAULT_LABEL="macos-arm64-clang"
    DEFAULT_CC="cc"
    DEFAULT_CXX="c++"
    ;;
  *)
    DEFAULT_LABEL="local-$HOST_TARGET"
    DEFAULT_CC="cc"
    DEFAULT_CXX="c++"
    ;;
esac

LABEL="${ASTROLABE_CHECK_LABEL:-$DEFAULT_LABEL}"
CC_BIN="${CC:-$DEFAULT_CC}"
CXX_BIN="${CXX:-$DEFAULT_CXX}"

echo "=== Portable Astrolabe aggregate (workspace test deadline: ${WORKSPACE_TEST_TIMEOUT_SECS}s) ==="
# #280 (owner directive 2026-07-12): check-full is the FULL TEST SUITE with a
# sub-3-minute (<180s) wall-clock benchmark. Suites are impact-gated — a suite
# runs only when its declared input set changed vs its last recorded green
# (scripts/check-suite-impact.py, fail-closed) — and the gate-tooling
# self-tests keep their change-gate. check-release.sh is the unabridged tier:
# it forces every suite and self-test (ASTRO_SUITE_GATE=all +
# ASTRO_GATE_SELFTESTS=all) and owns the lint/doc/Calyx phases tiered out of
# this gate (see the labels below).
CHECK_SH_STATUS_FILE="$ROOT/target/gate-logs/portable.exit"
run_portable_check() {
  local rc=0
  ASTROLABE_TARGET_CLEANUP_OWNER="$TARGET_CLEANUP_OWNER" \
    ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS="$WORKSPACE_TEST_TIMEOUT_SECS" \
    bash scripts/check.sh || rc=$?
  mkdir -p "$(dirname "$CHECK_SH_STATUS_FILE")"
  echo "$rc" > "$CHECK_SH_STATUS_FILE"
  return "$rc"
}

# ── #193: concurrent gate phases ────────────────────────────────────────────
#
# The phases below were strictly serial. The CBM C lint phase (cppcheck,
# clang-format over a hash-checked overlay, NOLINT grep) compiles nothing and
# writes no object into the vendor tree, so it is disjoint from the CBM C test
# phase (which owns vendor/build/c) and from the Rust phase (whose libcbm build
# lives in cbm-sys's OUT_DIR). Running it concurrently hides its whole wall clock
# inside the CBM test phase.
#
# The concurrency lives INSIDE this one launcher invocation: these are child
# processes of check-full.sh, never a second launcher, so the launcher's session
# lock (#186/#197) stays single-launcher by construction.
#
# WHY THE RUST PHASE IS *NOT* IN THIS GROUP (measured, not assumed): both
# scripts/ci-cbm-test.sh (the #194/#232 store-hermeticity gate) and the
# astrolabe-bridge `cbm_cache_dir` FSV test that runs inside the Rust phase's
# nextest assert EXCLUSIVE byte-identity of the operator's CBM store at
# $HOME/.cache/codebase-memory-mcp -- each snapshots it and requires it unchanged
# across its own run. Run concurrently, either can perturb (or create) that store
# while the other holds a snapshot, producing a FALSE RED that has nothing to do
# with the code under test. Weakening either assertion to permit concurrency
# would weaken a real gate, so the Rust phase stays serial until the bridge test
# is moved to a run-scoped store (filed separately; that change unlocks the much
# larger cbm-test || rust-gate overlap).
PHASE_LOG_DIR="$ROOT/target/gate-logs"
PHASE_PIDS=()
PHASE_NAMES=()
PHASE_STARTS=()

phase_now() { date +%s; }

# Each phase streams prefixed to stdout (so interleaved output stays attributable)
# and tees an unprefixed per-phase log under target/gate-logs/.
start_phase() {
  local name="$1"
  shift
  mkdir -p "$PHASE_LOG_DIR"
  echo "PHASE_START[$name]: $(date -u +%H:%M:%SZ) :: $*"
  (
    set +e
    "$@" 2>&1 | tee "$PHASE_LOG_DIR/$name.log" | sed -u "s/^/[$name] /"
    exit "${PIPESTATUS[0]}"
  ) &
  PHASE_PIDS+=("$!")
  PHASE_NAMES+=("$name")
  PHASE_STARTS+=("$(phase_now)")
}

# Waits for EVERY started phase before failing -- a phase that failed must not
# leave its siblings' cargo/make process trees running into target/ cleanup.
# A failure in ANY phase fails the aggregate, with the failing phase named.
wait_phases() {
  local failures=()
  local index name pid rc elapsed
  for index in "${!PHASE_PIDS[@]}"; do
    name="${PHASE_NAMES[$index]}"
    pid="${PHASE_PIDS[$index]}"
    rc=0
    wait "$pid" || rc=$?
    elapsed=$(($(phase_now) - PHASE_STARTS[index]))
    if [[ "$rc" -eq 0 ]]; then
      echo "PHASE_OK[$name]: ${elapsed}s"
    else
      echo "PHASE_FAIL[$name]: exit $rc after ${elapsed}s (log: $PHASE_LOG_DIR/$name.log)" >&2
      failures+=("$name(exit=$rc)")
    fi
  done
  PHASE_PIDS=()
  PHASE_NAMES=()
  PHASE_STARTS=()
  if [[ "${#failures[@]}" -gt 0 ]]; then
    echo "ERROR: ASTRO_GATE_PHASE_FAILED: ${failures[*]}" >&2
    return 1
  fi
  return 0
}

run_phase() {
  local name="$1"
  shift
  start_phase "$name" "$@"
  wait_phases
}

# #280 (owner directive 2026-07-12): the full TEST suite is two concurrent
# phases — the portable check.sh aggregate (workspace tests + binary-driving
# gates, impact-gated as workspace-block) and the CBM C suite (impact-gated as
# cbm-c-suite, incremental build + sharded run). They are store-disjoint: the
# #248 fix moved the astrolabe-bridge store-isolation tests onto per-run
# sandbox HOMEs, and every binary-driving check in check.sh runs against a
# run-scoped CBM_CACHE_DIR, so neither phase can perturb the operator store
# ci-cbm-test.sh snapshots. Rust is cargo into target/; CBM is make into
# vendor build dirs — no build-tree contention.
#
# The lint/doc/Calyx phases are NOT tests and are tiered to check-release
# (named, counted — never silent):
echo "SKIP[ASTRO_RELEASE_TIER_RUST_GATE]: owner=check-release (full-graph fmt, workspace clippy, full nextest re-run, doctests, Calyx nextest+doctests via scripts/ci-rust-gate.sh)"
echo "SKIP[ASTRO_RELEASE_TIER_CBM_LINT]: owner=check-release (cppcheck, clang-format, NOLINT whitelist, cache-path lint via scripts/ci-cbm-lint.sh)"

echo "=== Portable aggregate || CBM C runtime suite (concurrent) ==="
GATE_GROUP_START="$(phase_now)"
start_phase "portable" run_portable_check
start_phase "cbm-test" bash scripts/ci-cbm-test.sh "$LABEL" "$CC_BIN" "$CXX_BIN"
if ! wait_phases; then
  status=1
  if [[ -f "$CHECK_SH_STATUS_FILE" ]] && \
     [[ "$(cat "$CHECK_SH_STATUS_FILE" 2>/dev/null)" == "$WORKSPACE_TEST_DEFERRED_EXIT" ]]; then
    echo "DEFERRED[ASTRO_NATIVE_AGGREGATE]: workspace test deadline reached; downstream suites were not started"
    echo "CONTINUATION[ASTRO_NATIVE_AGGREGATE]: ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS=0 bash scripts/check-full.sh"
    status="$WORKSPACE_TEST_DEFERRED_EXIT"
  fi
  exit "$status"
fi
echo "PHASE_GROUP[portable+cbm-c]: $(($(phase_now) - GATE_GROUP_START))s wall clock for both phases"
