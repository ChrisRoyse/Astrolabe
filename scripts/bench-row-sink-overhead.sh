#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ASTROLABE_ROW_SINK_BENCH_OUT:-$ROOT/target/astrolabe-row-sink-overhead-bench.json}"
MODE="${ASTROLABE_ROW_SINK_BENCH_MODE:-full}"
REPEATS="${ASTROLABE_ROW_SINK_BENCH_REPEATS:-3}"
FILES="${ASTROLABE_ROW_SINK_BENCH_FILES:-12}"
CORPUS_CLASS="${ASTROLABE_ROW_SINK_BENCH_CORPUS_CLASS:-small}"

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
cargo run -p astrolabe-bridge --release --example bench_row_sink_overhead -- "${args[@]}" > "$tmp"
mv "$tmp" "$OUT"
cat "$OUT"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  status="$(python3 - <<'PY' "$OUT"
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
print(data["status"])
PY
)"
  ratio="$(python3 - <<'PY' "$OUT"
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
print(f'{data["row_sink_overhead_ratio"]:.3f}')
PY
)"
  gate="$(python3 - <<'PY' "$OUT"
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
print(f'{data["gate"]["row_sink_overhead_max_ratio"]:.3f}')
PY
)"
  corpus_class="$(python3 - <<'PY' "$OUT"
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
print(data["corpus_class"])
PY
)"
  {
    echo "### Astrolabe row-sink overhead benchmark"
    echo
    echo "| Metric | Value |"
    echo "|---|---:|"
    echo "| Status | $status |"
    echo "| Mode | $MODE |"
    echo "| Corpus class | $corpus_class |"
    echo "| Repeats | $REPEATS |"
    echo "| Gate ratio | $gate |"
    echo "| Measured ratio | $ratio |"
    echo "| Artifact | $OUT |"
  } >> "$GITHUB_STEP_SUMMARY"
fi
