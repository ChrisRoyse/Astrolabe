#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="${1:-}"
ALLOWED='^(cbm_|_*asan_|_*ubsan_|_*sanitizer_|_*lsan_|$)'

if [[ -z "$LIB" ]]; then
  py=""
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      py="$candidate"
      break
    fi
  done
  if [[ -n "$py" ]]; then
    LIB="$("$py" - "$ROOT" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
archives = list(root.glob("target/**/out/cbm-build/libcbm.a"))
if archives:
    print(max(archives, key=lambda p: p.stat().st_mtime))
PY
)"
  else
    LIB="$(find "$ROOT/target" -path '*/out/cbm-build/libcbm.a' -print -quit 2>/dev/null || true)"
  fi
fi
if [[ -z "$LIB" || ! -f "$LIB" ]]; then
  echo "ERROR: libcbm.a not found. Run `cargo test -p cbm-sys --no-run` first or pass the path." >&2
  exit 1
fi

if command -v readelf >/dev/null 2>&1; then
  bad="$(
    readelf -Ws "$LIB" 2>/dev/null |
      awk '$5 ~ /^(GLOBAL|WEAK)$/ && $7 != "UND" { print $8 }' |
      sed 's/^_//' |
      grep -Ev "$ALLOWED" || true
  )"
else
  tool=""
  for candidate in llvm-nm nm; do
    if command -v "$candidate" >/dev/null 2>&1; then
      tool="$candidate"
      break
    fi
  done
  if [[ -z "$tool" ]]; then
    echo "ERROR: neither readelf, llvm-nm, nor nm is available" >&2
    exit 1
  fi
  bad="$(
    "$tool" -g --defined-only "$LIB" |
      awk '{print $NF}' |
      sed 's/^_//' |
      grep -Ev "$ALLOWED" || true
  )"
fi

if [[ -n "$bad" ]]; then
  echo "ERROR: libcbm.a exposes non-cbm public symbols:" >&2
  echo "$bad" >&2
  exit 1
fi

echo "libcbm public symbols are cbm_-prefixed"
