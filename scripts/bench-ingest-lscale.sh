#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ASTROLABE_LSCALE_OUT:-$ROOT/target/astrolabe-ingest-lscale-bench.json}"
TARGET_SECONDS="${ASTROLABE_LSCALE_TARGET_SECONDS:-300}"
mkdir -p "$(dirname "$OUT")"

write_summary() {
  local status="$1"
  local detail="$2"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "### Astrolabe ingest L-scale benchmark"
      echo
      echo "| Metric | Value |"
      echo "|---|---:|"
      echo "| Status | $status |"
      echo "| Target seconds | $TARGET_SECONDS |"
      echo "| Detail | $detail |"
      echo
    } >> "$GITHUB_STEP_SUMMARY"
  fi
}

if [[ "${1:-}" == "--ci-smoke" && -z "${ASTROLABE_LSCALE_SQLITE:-}" ]]; then
  cat > "$OUT" <<JSON
{"schema":"astrolabe-ingest-lscale-bench-v1","status":"skipped","reason":"ASTROLABE_LSCALE_SQLITE not set","target_seconds":$TARGET_SECONDS}
JSON
  write_summary "skipped" "ASTROLABE_LSCALE_SQLITE not set"
  cat "$OUT"
  exit 0
fi

SQLITE_PATH="${ASTROLABE_LSCALE_SQLITE:-${1:-}}"
PROJECT="${ASTROLABE_LSCALE_PROJECT:-${2:-}}"
COMMIT="${ASTROLABE_LSCALE_COMMIT:-${3:-lscale-bench}}"
PANEL_VERSION="${ASTROLABE_LSCALE_PANEL_VERSION:-${4:-7}}"

if [[ -z "$SQLITE_PATH" || -z "$PROJECT" ]]; then
  echo "usage: ASTROLABE_LSCALE_SQLITE=<dump.db> ASTROLABE_LSCALE_PROJECT=<project> bash scripts/bench-ingest-lscale.sh" >&2
  echo "   or: bash scripts/bench-ingest-lscale.sh <dump.db> <project> [commit] [panel-version]" >&2
  exit 2
fi
if [[ ! -f "$SQLITE_PATH" ]]; then
  echo "ERROR: SQLite input not found: $SQLITE_PATH" >&2
  exit 2
fi

cd "$ROOT"
tmp="$OUT.tmp"
cargo run -p astrolabe-ingest --release --example bench_sqlite_import -- \
  "$SQLITE_PATH" "$PROJECT" "$COMMIT" "$PANEL_VERSION" > "$tmp"
mv "$tmp" "$OUT"
cat "$OUT"
write_summary "recorded" "$OUT"
