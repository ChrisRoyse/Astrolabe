#!/usr/bin/env bash
# test.sh — Clean build + run all C tests with ASan + UBSan.
#
# Usage:
#   scripts/test.sh                          # Auto-detect everything
#   scripts/test.sh --arch x86_64            # Force x86_64 build
#   scripts/test.sh CC=gcc-14 CXX=g++-14    # Override compiler
#
# This script is the SINGLE source of truth for running tests.
# Used identically in local development and CI workflows.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Parse --arch flag before sourcing env.sh
for arg in "$@"; do
    case "$arg" in
        --arch) :;; # next arg is the value, handled below
        arm64|x86_64)
            # Check if previous arg was --arch
            if [[ "${prev_arg:-}" == "--arch" ]]; then
                export CBM_ARCH="$arg"
            fi
            ;;
    esac
    prev_arg="$arg"
done

# Also support --arch=value
for arg in "$@"; do
    case "$arg" in
        --arch=*) export CBM_ARCH="${arg#--arch=}" ;;
    esac
done

# shellcheck source=env.sh
source "$ROOT/scripts/env.sh"

# Forward CC/CXX and collect make-passthrough args
MAKE_ARGS=""
for arg in "$@"; do
    case "$arg" in
        CC=*|CXX=*) export "${arg}" ;;
        --arch|--arch=*) ;; # already handled
        arm64|x86_64) ;; # already handled
        *=*) MAKE_ARGS="$MAKE_ARGS $arg" ;; # forward any VAR=VAL to make
    esac
done

print_env "test.sh"

# Verify compiler supports target arch
verify_compiler "$CC"

# #280: per-step wall-clock so the aggregate's timing surface can attribute
# the phase cost (clean/build/run/prod/watchdog) instead of one opaque total.
step_epoch() { date +%s; }
tstep_start="$(step_epoch)"
tstep() {
    local now
    now="$(step_epoch)"
    echo "STEP_TIME[cbm:$1]: $((now - tstep_start))s"
    tstep_start="$now"
}

# Step 1: Clean — ONLY when the build premise changed (#280). The per-TU
# object tree in build/c is mtime+depfile-correct (-MMD/-MP in Makefile.cbm),
# so an unchanged toolchain + flags premise makes a persistent build dir
# sound and a full clean pure waste (~230s of recompiles). The premise stamp
# is (compiler identities + Makefile.cbm bytes + the make args of this run);
# any mismatch or ambiguity cleans, fail closed. CBM_FORCE_CLEAN=1 forces it.
STAMP_FILE="build/c/.build-premise-stamp"
premise="$(
  {
    "$CC" --version 2>/dev/null | head -n 1 || echo cc-unknown
    "$CXX" --version 2>/dev/null | head -n 1 || echo cxx-unknown
    echo "args:$MAKE_ARGS $*"
    sha256sum Makefile.cbm 2>/dev/null || echo makefile-unknown
  } | sha256sum | cut -d' ' -f1
)"
if [ "${CBM_FORCE_CLEAN:-0}" = "1" ] || [ ! -f "$STAMP_FILE" ] \
  || [ "$(cat "$STAMP_FILE" 2>/dev/null)" != "$premise" ] \
  || printf '%s' "$premise" | grep -q "unknown"; then
    scripts/clean.sh
    mkdir -p build/c
    printf '%s' "$premise" > "$STAMP_FILE"
else
    echo "INFO[CBM_INCREMENTAL_BUILD]: build premise unchanged (stamp ${premise:0:12}) — reusing build/c object tree; make + depfiles own correctness"
    # Keep the fixture hygiene part of clean.sh even on incremental runs.
    find "$ROOT" -maxdepth 1 -type d \( -name 'cbm_*' -o -name 'cli-*' \) -exec rm -rf {} + 2>/dev/null || true
fi
tstep clean

# Step 2: Build the test runner (per-TU objects, parallel; Makefile applies
# $ARCHFLAGS on macOS).
make -j"$NPROC" -f Makefile.cbm build/c/test-runner $MAKE_ARGS
tstep build-test-runner

# Step 3: Run the suites in parallel shards (#280). The shard driver replays
# every suite's output, prints per-suite times, and emits the combined
# summary line last (the anchored count ci-cbm-test.sh parses).
bash scripts/test-shards.sh build/c/test-runner
tstep run-test-runner

# Step 4: C++ large-TU index-hang regression guard (#410). Runs the PROD binary
# in a subprocess with a wall-clock timeout — a hang must fail, not block the run.
# Opt-in via CBM_RUN_HANG_TEST=1 (it needs the prod binary, which the ASan unit
# run above does not build). Skipped by default so the fast unit run stays fast.
if [ "${CBM_RUN_HANG_TEST:-0}" = "1" ]; then
    echo "=== Step 4: C++ index-hang regression (#410) ==="
    bash "$ROOT/tests/test_cpp_index_hang.sh"
fi

# Step 5: Parent-death watchdog regression (#406/#407). Builds the prod stdio
# binary and verifies it self-exits when its launching parent is killed.
echo "=== Step 5: parent-death watchdog regression (#406/#407) ==="
make -j"$NPROC" -f Makefile.cbm cbm $MAKE_ARGS
tstep build-prod-cbm
bash "$ROOT/tests/test_parent_watchdog.sh"
tstep parent-watchdog

# Step 5b: worker-mode parent-death watchdog (#845). A supervised index worker
# (`cli --index-worker …`) whose supervisor dies must self-exit instead of
# indexing on as an orphan. Reuses the prod binary built in Step 5.
echo "=== Step 5b: worker-mode watchdog regression (#845) ==="
bash "$ROOT/tests/test_worker_watchdog.sh"
tstep worker-watchdog

# Step 6: security-strings URL allow-list regression. The MSYS2 CLANG64 toolchain
# bakes its package-tracker URL into the static Windows .exe; the binary string
# audit must allow-list it (Windows-only — Linux smoke never saw it).
echo "=== Step 6: security-strings allow-list regression ==="
bash "$ROOT/tests/test_security_strings_allowlist.sh"
tstep security-strings

echo "=== All tests passed ==="
