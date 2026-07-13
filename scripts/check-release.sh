#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET_CLEANUP_OWNER="${ASTROLABE_TARGET_CLEANUP_OWNER:-check-release}"
if [[ "$TARGET_CLEANUP_OWNER" != "check-release" ]]; then
  echo "ERROR: invalid ASTROLABE_TARGET_CLEANUP_OWNER: $TARGET_CLEANUP_OWNER" >&2
  exit 2
fi

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

if command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  echo "ERROR: python not found" >&2
  exit 1
fi

ASTROLABE_TARGET_CLEANUP_OWNER=check-release bash scripts/check-full.sh
cargo build --workspace --release
"$PYTHON_BIN" scripts/check-binary-size.py
# #291: byte-level proof that the shipped release binaries carry no test-only
# failpoint marker (e.g. the calyx-aster crash-fsv env var). Runs on the real
# artifacts built just above, before the release predicate.
"$PYTHON_BIN" scripts/check-release-failpoint-strings.py
bash "$ROOT/scripts/release-predicate.sh" "$@"
