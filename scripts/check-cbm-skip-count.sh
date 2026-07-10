#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: bash scripts/check-cbm-skip-count.sh <label> <actual-count> [manifest]" >&2
  exit 2
fi

LABEL="$1"
ACTUAL="$2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${3:-$ROOT/ci/known-skips.md}"

if [[ ! "$ACTUAL" =~ ^(0|[1-9][0-9]*)$ ]]; then
  echo "ERROR: ASTRO_CBM_SKIP_ACTUAL_INVALID: skip count must be a nonnegative integer: $ACTUAL" >&2
  exit 1
fi
if [[ ! -f "$MANIFEST" ]]; then
  echo "ERROR: ASTRO_CBM_SKIP_MANIFEST_MISSING: $MANIFEST" >&2
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
  ' "$MANIFEST"
)"

matches="${row%%|*}"
expected="${row#*|}"
if [[ "$matches" != "1" ]]; then
  echo "ERROR: ASTRO_CBM_SKIP_BASELINE_AMBIGUOUS: expected exactly one CBM row for $LABEL, found $matches" >&2
  exit 1
fi
if [[ ! "$expected" =~ ^(0|[1-9][0-9]*)$ ]]; then
  echo "ERROR: ASTRO_CBM_SKIP_BASELINE_INVALID: expected count for $LABEL is not a nonnegative integer: $expected" >&2
  exit 1
fi
if [[ "$ACTUAL" -ne "$expected" ]]; then
  echo "ERROR: ASTRO_CBM_SKIP_COUNT_MISMATCH: $LABEL expected $expected skipped tests, actual $ACTUAL" >&2
  exit 1
fi

echo "CBM skip count verified: label=$LABEL expected=$expected actual=$ACTUAL"
