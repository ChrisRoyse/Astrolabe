#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: bash scripts/ci-rust-gate.sh <label> <rust-target>" >&2
  exit 2
fi

LABEL="$1"
TARGET_TRIPLE="$2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT/target/ci-logs"

mkdir -p "$LOG_DIR"

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo not found on PATH" >&2
  exit 127
fi
if ! command -v cargo-nextest >/dev/null 2>&1; then
  echo "ERROR: cargo-nextest not found on PATH" >&2
  exit 127
fi

if ! command -v python3 >/dev/null 2>&1 && command -v python >/dev/null 2>&1; then
  PY3_SHIM="$LOG_DIR/python3-shim"
  mkdir -p "$PY3_SHIM"
  cat > "$PY3_SHIM/python3" <<'SH'
#!/usr/bin/env bash
exec python "$@"
SH
  chmod +x "$PY3_SHIM/python3"
  export PATH="$PY3_SHIM:$PATH"
fi

RUSTC_HOST="$(rustc -vV | sed -n 's/^host: //p')"
if [[ -z "$RUSTC_HOST" ]]; then
  echo "ERROR: ci-rust-gate could not determine rustc host triple" >&2
  exit 1
fi

# #246: self-contain std::env::temp_dir() scratch to a run-scoped sandbox under
# target/ (cleaned with it) so this gate NEVER leaks calyx-* dirs into the
# operator's real %TEMP% -- on EVERY invocation path, not only when check-full.sh
# happened to export TMP first. The Calyx nextest and workspace doctest below create
# scratch dirs via std::env::temp_dir(), which honors TMP/TEMP/TMPDIR on Windows; run
# standalone (bash scripts/ci-rust-gate.sh <label> <target>) with no sandbox they land
# in the operator's real %TEMP% and (correctly) trip the #237 no-escape gate. Containment
# must be a property of this script, not an inherited convention. This mirrors check.sh's
# self-set sandbox at the SAME path, so when check-full.sh has already exported it the
# assignment is an idempotent no-op; standalone it closes the leak. The #237 gate resolves
# operator_temp via the OS known-folder (REAL_TEMP), not the env, so this contains honest
# writes without blinding the gate to a test that bypasses the redirect via an absolute
# path. Suite temp nests one level BELOW a dedicated ceiling (target/suite-tmp/tmp under
# ceiling target/suite-tmp): env::temp_dir() then resolves inside this checkout, so
# GIT_CEILING_DIRECTORIES stops git's upward .git search at the ceiling for the
# calyx-buildinfo test that runs `git rev-parse` in env::temp_dir() and expects failure.
# A ceiling only blocks a walk crossing it from below, so temp sits under it. Native path
# form for git.exe.
SUITE_CEIL="$ROOT/target/suite-tmp"
SUITE_TMP="$SUITE_CEIL/tmp"
mkdir -p "$SUITE_TMP"
export TMP="$SUITE_TMP" TEMP="$SUITE_TMP" TMPDIR="$SUITE_TMP"
if command -v cygpath >/dev/null 2>&1; then
  export GIT_CEILING_DIRECTORIES="$(cygpath -m "$SUITE_CEIL")"
else
  export GIT_CEILING_DIRECTORIES="$SUITE_CEIL"
fi

# ── #189: one artifact tree, never two ──────────────────────────────────────
#
# Cargo places artifacts in target/<triple>/debug when --target is passed and in
# target/debug when it is not -- EVEN WHEN the triple equals the host. The two
# trees share nothing (Cargo Book, "Build cache": "The directory layout depends
# on whether or not you are using the --target flag"). So passing an explicit
# --target equal to the host, while check.sh builds the implicit tree, forced a
# second from-cold compile of the whole workspace + the 8 Calyx path-deps +
# libcbm inside a single aggregate run -- the largest wall-clock cost in the
# local verification loop.
#
# Astrolabe is Windows-only scope and check-full.sh asserts HOST_TARGET ==
# RUSTC_HOST, so the requested target is ALWAYS the host. Drop --target entirely:
# every phase then shares one target/debug tree, and the Calyx sub-gate is pointed
# at that same tree instead of forking a third one under vendor/calyx/target.
#
# This is behavior-neutral: there is no .cargo/config.toml in this repository, so
# there are no [target.<triple>] rustflags that dropping --target could fail to
# apply. (Were any added, they would begin applying to build scripts and proc
# macros too -- see the Cargo Book note on build.rustflags.)
#
# A cross-target request is refused rather than silently producing non-native
# evidence: a build for another target exercises different code paths and cannot
# satisfy a Windows DoD.
if [[ "$TARGET_TRIPLE" != "$RUSTC_HOST" ]]; then
  echo "ERROR: ASTRO_RUST_GATE_CROSS_TARGET: requested target $TARGET_TRIPLE is not the rustc host $RUSTC_HOST." >&2
  echo "  message: this gate produces native evidence only; a cross-target build exercises different code paths." >&2
  echo "  remediation: run the gate on a host of that platform. Cross-platform evidence is DEFERRED[ASTRO_PORT_PHASE] (tracked in #238); see docs/port-phase-deferrals.md." >&2
  exit 1
fi
TARGET_SUBDIR="debug"
CALYX_TARGET_DIR_ARGS=(--target-dir "$ROOT/target")

# #189: enforce the single-tree invariant over the ambient environment for EVERY
# child gate this script spawns. check-full.sh:39 supports an inherited
# ASTROLABE_RUST_TARGET (asserted == host), and any child that reads it re-forks a
# second cold target/<triple>/debug tree -- the exact duplication this issue removes.
# check-mcp-parity.sh already resolves target/ directly, but check-single-mimalloc.sh
# (:22-24) still appends --target "$ASTROLABE_RUST_TARGET" when the var is set. Rather
# than patch each child, neutralize the variable once here: after the cross-target
# refusal above, the target is provably the host, so the forked tree would only rebuild
# identical objects. This unset is confined to this process and its children -- standalone
# `bash scripts/check-single-mimalloc.sh` (invoked directly with the env set) keeps its
# legitimate cross-target behavior; only the unified aggregate's children are pinned to
# the one target/debug tree. Defense-in-depth for present and future child gates.
unset ASTROLABE_RUST_TARGET

run_logged() {
  local name="$1"
  shift
  local log="$LOG_DIR/${name//[^A-Za-z0-9_.-]/_}.log"

  echo "=== $name ==="
  set +e
  "$@" 2>&1 | tee "$log"
  local rc=${PIPESTATUS[0]}
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "ERROR: $name failed; log: $log" >&2
    exit "$rc"
  fi
}

run_nextest() {
  local name="$1"
  local expected="$2"
  shift 2
  local log="$LOG_DIR/${name//[^A-Za-z0-9_.-]/_}.log"

  echo "=== $name ==="
  set +e
  "$@" 2>&1 | tee "$log"
  local rc=${PIPESTATUS[0]}
  set -e

  python3 - "$name" "$expected" "$log" <<'PY'
import pathlib
import re
import sys

name, expected, log_path = sys.argv[1], sys.argv[2], pathlib.Path(sys.argv[3])
text = log_path.read_text(errors="replace")
text = re.sub(r"\x1b\[[0-9;]*m", "", text)
summary = None
for line in text.splitlines():
    if "Summary" in line and "tests run:" in line:
        summary = line.strip()
if summary is None:
    print(f"ERROR: {name}: nextest summary not found in {log_path}", file=sys.stderr)
    sys.exit(1)
match = re.search(r"(\d+)\s+tests?\s+run:\s+(\d+)\s+passed", summary)
if not match:
    print(f"ERROR: {name}: could not parse nextest summary: {summary}", file=sys.stderr)
    sys.exit(1)
run_count = int(match.group(1))
passed = int(match.group(2))
if expected != "dynamic" and run_count != int(expected):
    print(
        f"ERROR: {name}: nextest ran {run_count} tests, expected {expected} at this pin",
        file=sys.stderr,
    )
    sys.exit(1)
if run_count != passed:
    print(f"ERROR: {name}: not all nextest tests passed: {summary}", file=sys.stderr)
    sys.exit(1)
# Counts go to stdout, which is the evidence stream. There is no hosted CI and
# therefore no step summary to write (#224).
print(summary)
PY

  if [[ "$rc" -ne 0 ]]; then
    exit "$rc"
  fi
}

run_cbm_sys_asan() {
  local name="cbm-sys-asan-$LABEL"
  local log="$LOG_DIR/${name//[^A-Za-z0-9_.-]/_}.log"

  echo "=== $name ==="
  set +e
  {
    env CC=clang CXX=clang++ CBM_SYS_ASAN=1 \
      cargo test -p cbm-sys --test fixtures --no-run ||
      exit $?

    local test_dir="$ROOT/target/$TARGET_SUBDIR/deps"
    local test_bin
    test_bin="$(
      find "$test_dir" -maxdepth 1 -type f -name 'fixtures-*' -perm -u+x -printf '%T@ %p\n' |
        sort -n |
        tail -n 1 |
        cut -d' ' -f2-
    )"
    if [[ -z "$test_bin" ]]; then
      echo "ERROR: cbm-sys ASan fixture binary not found in $test_dir" >&2
      exit 1
    fi

    local asan_lib
    asan_lib="$(clang -print-file-name=libasan.so)"
    if [[ -z "$asan_lib" || ! -f "$asan_lib" ]]; then
      echo "ERROR: clang did not resolve libasan.so" >&2
      exit 1
    fi

    env \
      LD_PRELOAD="$asan_lib" \
      ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
      LSAN_OPTIONS=exitcode=23 \
      "$test_bin" --nocapture
  } 2>&1 | tee "$log"
  local rc=${PIPESTATUS[0]}
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "ERROR: $name failed; log: $log" >&2
    exit "$rc"
  fi
}

run_astrolabe_bridge_asan() {
  local name="astrolabe-bridge-asan-$LABEL"
  local log="$LOG_DIR/${name//[^A-Za-z0-9_.-]/_}.log"

  echo "=== $name ==="
  set +e
  {
    env CC=clang CXX=clang++ CBM_SYS_ASAN=1 \
      cargo test -p astrolabe-bridge --lib --no-run ||
      exit $?

    local test_dir="$ROOT/target/$TARGET_SUBDIR/deps"
    local test_bin
    test_bin="$(
      find "$test_dir" -maxdepth 1 -type f -name 'astrolabe_bridge-*' -perm -u+x -printf '%T@ %p\n' |
        sort -n |
        tail -n 1 |
        cut -d' ' -f2-
    )"
    if [[ -z "$test_bin" ]]; then
      echo "ERROR: astrolabe-bridge ASan test binary not found in $test_dir" >&2
      exit 1
    fi

    local asan_lib
    asan_lib="$(clang -print-file-name=libasan.so)"
    if [[ -z "$asan_lib" || ! -f "$asan_lib" ]]; then
      echo "ERROR: clang did not resolve libasan.so" >&2
      exit 1
    fi

    env \
      LD_PRELOAD="$asan_lib" \
      ASAN_OPTIONS=verify_asan_link_order=0:detect_leaks=1:halt_on_error=1:abort_on_error=1 \
      LSAN_OPTIONS=exitcode=23 \
      "$test_bin" \
      create_use_drop_extracted_file_repeatedly \
      tool_runner_create_use_drop_repeatedly \
      --nocapture
  } 2>&1 | tee "$log"
  local rc=${PIPESTATUS[0]}
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "ERROR: $name failed; log: $log" >&2
    exit "$rc"
  fi
}

cd "$ROOT"
run_logged "astrolabe-fmt-$LABEL" python3 "$ROOT/scripts/native-cargo-fmt.py" --all -- --check
run_logged "astrolabe-clippy-$LABEL" cargo clippy --workspace --all-targets -- -D warnings
run_nextest "Astrolabe nextest $LABEL" dynamic cargo nextest run --workspace
run_logged "astrolabe-verify-chain-$LABEL" bash scripts/check-astrolabe-verify-chain.sh "$ROOT/target/$TARGET_SUBDIR/astrolabe"
run_logged "astrolabe-ingest-lscale-bench-$LABEL" bash scripts/bench-ingest-lscale.sh --ci-smoke
run_logged "libcbm-symbols-$LABEL" bash scripts/check-libcbm-symbols.sh
run_logged "single-mimalloc-$LABEL" bash scripts/check-single-mimalloc.sh
run_logged "mcp-parity-$LABEL" bash scripts/check-mcp-parity.sh
if [[ "$TARGET_TRIPLE" != *windows* ]]; then
  run_logged "astrolabe-watchdog-$LABEL" bash scripts/check-astrolabe-watchdog.sh "$ROOT/target/$TARGET_SUBDIR/astrolabe"
fi
if [[ "$TARGET_TRIPLE" == *linux-gnu ]]; then
  run_cbm_sys_asan
  run_astrolabe_bridge_asan
fi
run_logged "astrolabe-doctest-$LABEL" cargo test --workspace --doc

cd "$ROOT/vendor/calyx"
# The vendored scripts/cargo-fmt-workspace.sh mapfile-parses Windows python3
# output, which carries CRLF: every package name gains a trailing \r and
# `cargo fmt -p` refuses it ("is not a member of the workspace"). Vendor is
# pinned, so run our own Windows-safe batching formatter over the same Calyx
# workspace members instead (upstream fix tracked in ChrisRoyse/Calyx).
run_logged "calyx-fmt-$LABEL" python3 "$ROOT/scripts/native-cargo-fmt.py" --all --manifest-path "$ROOT/vendor/calyx/Cargo.toml" -- --check
run_logged "calyx-check-$LABEL" cargo check --workspace --all-targets "${CALYX_TARGET_DIR_ARGS[@]}"
# Vendored Calyx is pinned and never edited locally; at pin 6e0e344 the pinned
# 1.95 clippy fails -D warnings inside calyx-poly (newer lints firing on older
# code). Lint hygiene of the pinned tree is upstream-owned: tracked in
# Astrolabe #234, fix in ChrisRoyse/Calyx#824, retired by a lint-clean pin
# bump. Named skip, never pass evidence; the behavioral Calyx gates below
# (check/nextest/doctest) and all Astrolabe-crate clippy stay blocking.
echo "SKIP[ASTRO_CALYX_CLIPPY_VENDOR_PINNED]: vendored Calyx clippy is upstream-owned at the pin; tracked in #234 (upstream ChrisRoyse/Calyx#824)"
# calyx-poly's issue035 FSV test hard-depends on a machine-local Polymarket
# capture that no longer exists anywhere (its metadata.json sha256 cross-check
# makes the dataset unfabricatable). Excluded by name until upstream ships a
# fixture or a self-skip: tracked in Astrolabe #235, fix in ChrisRoyse/Calyx#825.
echo "SKIP[ASTRO_CALYX_ISSUE035_DATASET_LOCAL]: calyx-poly issue035 FSV needs the absent local capture; tracked in #235 (upstream ChrisRoyse/Calyx#825)"
run_nextest "Calyx nextest $LABEL" dynamic cargo nextest run --workspace "${CALYX_TARGET_DIR_ARGS[@]}" -E 'not test(issue035_historical_backfill_loader_fsv)'
run_logged "calyx-doctest-$LABEL" cargo test --workspace --doc "${CALYX_TARGET_DIR_ARGS[@]}"
