#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f .gitmodules ]]; then
  echo "ERROR: submodules are forbidden for Astrolabe vendor parents" >&2
  exit 1
fi

if git ls-files -s vendor | awk '$1 == "160000" { found=1 } END { exit found ? 0 : 1 }'; then
  echo "ERROR: vendor contains a gitlink/submodule entry" >&2
  exit 1
fi

if find vendor -name .git -print -quit | grep -q .; then
  echo "ERROR: nested .git directory found under vendor/" >&2
  exit 1
fi

read_pin() {
  local path="$1"
  awk -F'|' -v target="\`$path\`" '
    $0 ~ target {
      value=$5
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      gsub(/`/, "", value)
      print value
    }
  ' VENDORED.md
}

verify_worktree() {
  local name="$1"
  local path="$2"
  local untracked

  if ! git diff --quiet -- "$path"; then
    echo "ERROR: ASTRO_VENDOR_WORKTREE_DIRTY: $name tracked files differ from the index" >&2
    echo "  path: $path" >&2
    git status --short --untracked-files=no -- "$path" >&2
    exit 1
  fi

  untracked="$(git ls-files --others --exclude-standard -- "$path")"
  if [[ -n "$untracked" ]]; then
    echo "ERROR: ASTRO_VENDOR_UNTRACKED: $name contains non-ignored untracked paths" >&2
    echo "  path: $path" >&2
    while IFS= read -r file; do
      printf '  %s\n' "$file" >&2
    done <<< "$untracked"
    exit 1
  fi
}

verify_tree() {
  local name="$1"
  local path="$2"
  local expected
  local root_tree
  local actual

  verify_worktree "$name" "$path"

  expected="$(read_pin "$path")"
  if [[ ! "$expected" =~ ^[0-9a-f]{40}$ ]]; then
    echo "ERROR: missing 40-hex tree pin for $name at $path in VENDORED.md" >&2
    exit 1
  fi

  root_tree="$(git write-tree)"
  actual="$(git rev-parse "${root_tree}:${path}")"
  if [[ "$actual" != "$expected" ]]; then
    echo "ERROR: $name tree pin mismatch" >&2
    echo "  path:     $path" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    exit 1
  fi

  echo "$name pin ok: $actual"
}

verify_tree "Calyx" "vendor/calyx"
verify_tree "codebase-memory-mcp" "vendor/codebase-memory-mcp"

echo "vendor pins verified"
