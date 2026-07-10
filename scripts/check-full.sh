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
if ASTROLABE_TARGET_CLEANUP_OWNER="$TARGET_CLEANUP_OWNER" \
  ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS="$WORKSPACE_TEST_TIMEOUT_SECS" \
  bash scripts/check.sh; then
  :
else
  status=$?
  if [[ "$status" -eq "$WORKSPACE_TEST_DEFERRED_EXIT" ]]; then
    echo "DEFERRED[ASTRO_NATIVE_AGGREGATE]: workspace test deadline reached; downstream suites were not started"
    echo "CONTINUATION[ASTRO_NATIVE_AGGREGATE]: ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS=0 bash scripts/check-full.sh"
  fi
  exit "$status"
fi

echo "=== Upstream CBM lint suite ==="
bash scripts/ci-cbm-lint.sh

echo "=== Upstream CBM runtime suite ==="
bash scripts/ci-cbm-test.sh "$LABEL" "$CC_BIN" "$CXX_BIN"

echo "=== Astrolabe and Calyx Rust suites ($HOST_TARGET) ==="
bash scripts/ci-rust-gate.sh "$LABEL" "$HOST_TARGET"
