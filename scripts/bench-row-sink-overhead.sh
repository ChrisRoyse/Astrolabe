#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ASTROLABE_ROW_SINK_BENCH_OUT:-$ROOT/target/astrolabe-row-sink-overhead-bench.json}"
MODE="${ASTROLABE_ROW_SINK_BENCH_MODE:-full}"
REPEATS="${ASTROLABE_ROW_SINK_BENCH_REPEATS:-3}"
FILES="${ASTROLABE_ROW_SINK_BENCH_FILES:-12}"
CORPUS_CLASS="${ASTROLABE_ROW_SINK_BENCH_CORPUS_CLASS:-small}"
WRITE_RELEASE_ARTIFACT="${ASTROLABE_ROW_SINK_BENCH_WRITE_RELEASE_ARTIFACT:-0}"
ARTIFACT_DIR="${ASTROLABE_ROW_SINK_BENCH_ARTIFACT_DIR:-$ROOT/target/astrolabe-release-predicate}"

mkdir -p "$(dirname "$OUT")"

args=(--mode "$MODE" --repeats "$REPEATS" --files "$FILES" --corpus-class "$CORPUS_CLASS")
if [[ -n "${ASTROLABE_ROW_SINK_BENCH_GATE_RATIO:-}" ]]; then
  args+=(--gate-ratio "$ASTROLABE_ROW_SINK_BENCH_GATE_RATIO")
fi
if [[ -n "${ASTROLABE_ROW_SINK_BENCH_REPO:-}" ]]; then
  args+=(--repo "$ASTROLABE_ROW_SINK_BENCH_REPO")
fi
if [[ -n "${ASTROLABE_ROW_SINK_BENCH_PROJECT:-}" ]]; then
  args+=(--project "$ASTROLABE_ROW_SINK_BENCH_PROJECT")
fi

cd "$ROOT"
tmp="$OUT.tmp"
set +e
cargo run -p astrolabe-bridge --release --example bench_row_sink_overhead -- "${args[@]}" > "$tmp"
bench_rc=$?
set -e

if [[ -s "$tmp" ]]; then
  mv "$tmp" "$OUT"
else
  rm -f "$tmp"
fi

if [[ "$WRITE_RELEASE_ARTIFACT" == "1" || "$WRITE_RELEASE_ARTIFACT" == "true" ]]; then
  python3 scripts/write-bench-ratios-artifact.py \
    --source "$OUT" \
    --artifact-dir "$ARTIFACT_DIR" \
    --return-code "$bench_rc"
fi

if [[ -f "$OUT" ]]; then
  cat "$OUT"
fi

# There is no hosted CI and therefore no step summary to write (#224). The
# benchmark artifact above is cat'd to stdout, which IS the evidence stream.

exit "$bench_rc"
