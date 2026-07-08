#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if grep -RInE 'todo!|unimplemented!' crates; then
  echo "ERROR: reachable stubs must not use todo! or unimplemented!" >&2
  exit 1
fi

echo "no todo!/unimplemented! in crates/"
