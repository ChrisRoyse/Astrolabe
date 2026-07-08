#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

tool=""
for candidate in llvm-nm nm; do
  if command -v "$candidate" >/dev/null 2>&1; then
    tool="$candidate"
    break
  fi
done
if [[ -z "$tool" ]]; then
  echo "ERROR: neither llvm-nm nor nm is available" >&2
  exit 1
fi

if [[ "$#" -eq 0 ]]; then
  cargo_args=(-p astrolabe-bridge --lib --no-run)
  search_root="target"
  if [[ -n "${ASTROLABE_RUST_TARGET:-}" ]]; then
    cargo_args+=(--target "$ASTROLABE_RUST_TARGET")
    search_root="target/$ASTROLABE_RUST_TARGET"
  fi
  cargo test "${cargo_args[@]}" >/dev/null
  mapfile -t binaries < <(
    find "$search_root" -type f \( -name 'astrolabe_bridge-*' -o -name 'astrolabe_bridge-*.exe' \) \
      ! -name '*.d' -printf '%T@ %p\n' 2>/dev/null |
      sort -n |
      tail -n 1 |
      cut -d' ' -f2-
  )
else
  binaries=("$@")
fi

if [[ "${#binaries[@]}" -eq 0 || -z "${binaries[0]:-}" ]]; then
  echo "ERROR: no astrolabe_bridge test binary found" >&2
  exit 1
fi

count_symbol() {
  local binary="$1"
  local symbol="$2"
  {
    "$tool" --defined-only "$binary" 2>/dev/null |
      awk '{print $NF}' |
      sed 's/^_//' |
      grep -E "^${symbol}$" || true
  } |
    wc -l |
    tr -d '[:space:]'
}

for binary in "${binaries[@]}"; do
  if [[ ! -f "$binary" ]]; then
    echo "ERROR: binary not found: $binary" >&2
    exit 1
  fi
  mi_version_count="$(count_symbol "$binary" mi_version)"
  mi_malloc_count="$(count_symbol "$binary" mi_malloc)"
  cbm_version_count="$(count_symbol "$binary" cbm_mimalloc_version)"
  cbm_malloc_count="$(count_symbol "$binary" cbm_mimalloc_malloc)"

  if [[ "$mi_version_count" != "1" || "$mi_malloc_count" != "1" ]]; then
    echo "ERROR: expected exactly one raw mimalloc implementation in $binary" >&2
    echo "mi_version definitions: $mi_version_count" >&2
    echo "mi_malloc definitions: $mi_malloc_count" >&2
    exit 1
  fi
  if [[ "$cbm_version_count" != "1" || "$cbm_malloc_count" != "1" ]]; then
    echo "ERROR: expected exactly one cbm_mimalloc shim surface in $binary" >&2
    echo "cbm_mimalloc_version definitions: $cbm_version_count" >&2
    echo "cbm_mimalloc_malloc definitions: $cbm_malloc_count" >&2
    exit 1
  fi
done

echo "single vendored mimalloc implementation verified"
