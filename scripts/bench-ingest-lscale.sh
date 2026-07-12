#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ASTROLABE_LSCALE_OUT:-$ROOT/target/astrolabe-ingest-lscale-bench.json}"
TARGET_SECONDS="${ASTROLABE_LSCALE_TARGET_SECONDS:-300}"
mkdir -p "$(dirname "$OUT")"

# There is no hosted CI and therefore no step summary to write (#224): the
# invoking process's stdout IS the evidence stream. Emit a named, greppable line.
write_summary() {
  local status="$1"
  local detail="$2"
  echo "BENCH[astrolabe-ingest-lscale] status=$status target_seconds=$TARGET_SECONDS detail=$detail"
}

# Smoke mode (`--smoke`; `--ci-smoke` kept as a compatibility alias): when no
# corpus is supplied, generate the pinned deterministic smoke corpus and run the
# REAL bench against it. The former unconditional `status:"skipped"` exit-0
# branch was a permanent green no-op (issue #89); smoke now always measures.
if [[ "${1:-}" == "--smoke" || "${1:-}" == "--ci-smoke" ]]; then
  if [[ -z "${ASTROLABE_LSCALE_SQLITE:-}" ]]; then
    SMOKE_DB="$ROOT/target/astrolabe-lscale-smoke-corpus.db"
    SMOKE_NODES="${ASTROLABE_LSCALE_SMOKE_NODES:-400}"
    SMOKE_SEED="${ASTROLABE_LSCALE_SMOKE_SEED:-20260711}"
    echo "smoke mode: generating pinned corpus (nodes=$SMOKE_NODES seed=$SMOKE_SEED)" >&2
    cargo run -p astrolabe-ingest --release --example gen_lscale_smoke_corpus -- \
      "$SMOKE_DB" "$SMOKE_NODES" "$SMOKE_SEED"
    export ASTROLABE_LSCALE_SQLITE="$SMOKE_DB"
    export ASTROLABE_LSCALE_PROJECT="${ASTROLABE_LSCALE_PROJECT:-astrolabe-lscale-smoke}"
    # A smoke corpus is tiny; hold it to a much tighter budget than L-scale.
    export ASTROLABE_LSCALE_TARGET_SECONDS="${ASTROLABE_LSCALE_SMOKE_TARGET_SECONDS:-60}"
    TARGET_SECONDS="$ASTROLABE_LSCALE_TARGET_SECONDS"
  fi
  shift
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
