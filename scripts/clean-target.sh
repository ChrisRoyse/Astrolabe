#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="$ROOT/target"

case "$TARGET_DIR" in
  "$ROOT"/target) ;;
  *)
    echo "ERROR: refusing to clean unexpected target path: $TARGET_DIR" >&2
    exit 2
    ;;
esac

# #280: ASTROLABE_CONTIGUOUS_BATCH=1 = the CLAUDE.md "contiguous verification
# batch" carve-out — consecutive gate runs in one session keep target/ warm
# (a cold target/ costs ~143s of pure rebuild per aggregate against 6.6s of
# actual test execution). The batch owner still wipes at every batch boundary
# (turn end / pause / issue close / handoff): run this script with the
# variable unset. Default behavior (unset) is unchanged.
if [[ "${ASTROLABE_CONTIGUOUS_BATCH:-0}" == "1" ]]; then
  echo "CLEANUP[ASTRO_TARGET_BATCH_DEFERRED]: ASTROLABE_CONTIGUOUS_BATCH=1 -> target/ kept warm; the batch owner wipes it at the batch boundary"
  exit 0
fi

if [[ -e "$TARGET_DIR" || -L "$TARGET_DIR" ]]; then
  rm -rf -- "$TARGET_DIR"
fi

if [[ -e "$TARGET_DIR" || -L "$TARGET_DIR" ]]; then
  echo "ERROR: target cleanup did not remove $TARGET_DIR" >&2
  exit 1
fi

echo "CLEANUP[ASTRO_TARGET]: $TARGET_DIR is absent"
