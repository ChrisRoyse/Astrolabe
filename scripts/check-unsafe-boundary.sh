#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

missing=()
for crate_dir in crates/*; do
  [[ -d "$crate_dir" ]] || continue
  name="$(basename "$crate_dir")"
  case "$name" in
    astrolabe-bridge|cbm-sys)
      continue
      ;;
  esac
  lib="$crate_dir/src/lib.rs"
  if [[ ! -f "$lib" ]] || ! grep -q '#!\[forbid(unsafe_code)\]' "$lib"; then
    missing+=("$name")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'ERROR: non-FFI crates missing #![forbid(unsafe_code)]: %s\n' "${missing[*]}" >&2
  exit 1
fi

if rg -n '\bunsafe\b' crates --glob '*.rs' \
  --glob '!crates/cbm-sys/**' \
  --glob '!crates/astrolabe-bridge/**'; then
  echo "ERROR: unsafe Rust is confined to astrolabe-bridge and cbm-sys" >&2
  exit 1
fi

echo "unsafe Rust boundary verified"
