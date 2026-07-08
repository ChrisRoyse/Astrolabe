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
summary_file = pathlib.Path()
if "GITHUB_STEP_SUMMARY" in __import__("os").environ:
    summary_file = pathlib.Path(__import__("os").environ["GITHUB_STEP_SUMMARY"])
    with summary_file.open("a", encoding="utf-8") as handle:
        handle.write(f"### {name}\n\n")
        handle.write("| Metric | Count |\n")
        handle.write("|---|---:|\n")
        handle.write(f"| Tests run | {run_count} |\n")
        handle.write(f"| Tests passed | {passed} |\n")
        if expected != "dynamic":
            handle.write(f"| Expected at pin | {expected} |\n")
        handle.write("\n")
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
      cargo test -p cbm-sys --test fixtures --target "$TARGET_TRIPLE" --no-run ||
      exit $?

    local test_dir="$ROOT/target/$TARGET_TRIPLE/debug/deps"
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
      cargo test -p astrolabe-bridge --lib --target "$TARGET_TRIPLE" --no-run ||
      exit $?

    local test_dir="$ROOT/target/$TARGET_TRIPLE/debug/deps"
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
run_logged "astrolabe-fmt-$LABEL" cargo fmt --check --all
run_logged "astrolabe-clippy-$LABEL" cargo clippy --workspace --all-targets --target "$TARGET_TRIPLE" -- -D warnings
run_nextest "Astrolabe nextest $LABEL" dynamic cargo nextest run --workspace --target "$TARGET_TRIPLE"
run_logged "astrolabe-ingest-lscale-bench-$LABEL" bash scripts/bench-ingest-lscale.sh --ci-smoke
run_logged "libcbm-symbols-$LABEL" bash scripts/check-libcbm-symbols.sh
run_logged "single-mimalloc-$LABEL" env ASTROLABE_RUST_TARGET="$TARGET_TRIPLE" bash scripts/check-single-mimalloc.sh
run_logged "mcp-parity-$LABEL" env ASTROLABE_RUST_TARGET="$TARGET_TRIPLE" bash scripts/check-mcp-parity.sh
if [[ "$TARGET_TRIPLE" != *windows* ]]; then
  run_logged "astrolabe-watchdog-$LABEL" bash scripts/check-astrolabe-watchdog.sh "$ROOT/target/$TARGET_TRIPLE/debug/astrolabe"
fi
if [[ "$TARGET_TRIPLE" == *linux-gnu ]]; then
  run_cbm_sys_asan
  run_astrolabe_bridge_asan
fi
run_logged "astrolabe-doctest-$LABEL" cargo test --workspace --doc --target "$TARGET_TRIPLE"

cd "$ROOT/vendor/calyx"
bash scripts/cargo-fmt-workspace.sh --check
run_logged "calyx-check-$LABEL" cargo check --workspace --all-targets --target "$TARGET_TRIPLE"
run_logged "calyx-clippy-$LABEL" cargo clippy --workspace --all-targets --target "$TARGET_TRIPLE" -- -D warnings
run_nextest "Calyx nextest $LABEL" dynamic cargo nextest run --workspace --target "$TARGET_TRIPLE"
run_logged "calyx-doctest-$LABEL" cargo test --workspace --doc --target "$TARGET_TRIPLE"
