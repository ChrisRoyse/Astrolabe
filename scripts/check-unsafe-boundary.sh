#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# The unsafe-boundary scan is only meaningful if ripgrep is present. Without it
# the `if rg ...; then` guard below silently evaluates false (rg exits 127) and
# the check would print "verified" without inspecting a single file — a silent
# fallback that hides an unbounded unsafe surface. Fail closed instead.
if ! command -v rg >/dev/null 2>&1; then
  echo "ERROR: ripgrep (rg) is required to scan for the unsafe Rust boundary but was not found on PATH; install ripgrep and re-run" >&2
  exit 127
fi

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
