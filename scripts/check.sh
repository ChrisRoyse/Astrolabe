#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v cargo >/dev/null 2>&1; then
  CARGO_BIN="cargo"
elif [[ -n "${USERPROFILE:-}" && -x "$USERPROFILE/.cargo/bin/cargo.exe" ]]; then
  CARGO_BIN="$USERPROFILE/.cargo/bin/cargo.exe"
elif [[ -n "${HOME:-}" && -x "$HOME/.cargo/bin/cargo" ]]; then
  CARGO_BIN="$HOME/.cargo/bin/cargo"
elif [[ -n "${HOME:-}" && -x "$HOME/.cargo/bin/cargo.exe" ]]; then
  CARGO_BIN="$HOME/.cargo/bin/cargo.exe"
else
  echo "ERROR: cargo not found on PATH, USERPROFILE/.cargo/bin, or HOME/.cargo/bin" >&2
  exit 1
fi

if command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  echo "ERROR: python not found" >&2
  exit 1
fi

bash scripts/verify-pins.sh
bash scripts/check-no-todo.sh
"$CARGO_BIN" metadata --format-version 1 >/dev/null
CARGO="$CARGO_BIN" "$PYTHON_BIN" scripts/check-calyx-path-deps.py
"$CARGO_BIN" build --workspace
"$CARGO_BIN" test --workspace
