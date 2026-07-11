#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=python3
  else
    PYTHON_BIN=python
  fi
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

# Textual backstop to the compiler-enforced forbid(unsafe_code) attributes
# above. It scans the comment/string-blanked code view (rust_prod_lines), so
# prose in doc comments and deliberately dangerous string-literal corpora
# (e.g. the guard vulnerability patterns) are data, not violations — only an
# `unsafe` token in reachable code fails. A missing interpreter or module
# fails closed through set -e semantics below.
if ! "$PYTHON_BIN" - <<'PY'
import re
import sys
from pathlib import Path

sys.path.insert(0, "scripts")
import rust_prod_lines

pattern = re.compile(r"\bunsafe\b")
violations = []
for path in sorted(Path("crates").rglob("*.rs")):
    posix = path.as_posix()
    if posix.startswith("crates/cbm-sys/") or posix.startswith("crates/astrolabe-bridge/"):
        continue
    view = rust_prod_lines.code_view(path.read_text(encoding="utf-8"))
    for number, line in enumerate(view.split("\n"), start=1):
        if pattern.search(line):
            violations.append(f"{posix}:{number}:{line.strip()}")
for violation in violations:
    print(violation)
sys.exit(1 if violations else 0)
PY
then
  echo "ERROR: unsafe Rust is confined to astrolabe-bridge and cbm-sys" >&2
  exit 1
fi

echo "unsafe Rust boundary verified"
