#!/usr/bin/env bash
# test-shards.sh — run the C test suites in parallel shards (#280).
#
# The serial test-runner walks ~90 suites in one process (~219s measured on 32
# threads, 2026-07-12). Suites are process-independent: each gets its own
# process here, grouped into N shards that run concurrently. Isolation per
# shard: HOME/USERPROFILE (the CBM store resolves from HOME — see
# ci-cbm-test.sh) and TMP/TEMP/TMPDIR. The CWD stays the repo root for every
# suite (fixtures live at fixed relative paths); fixed-name fixture dirs are
# suite-local, and a suite never spans shards, so shards do not collide.
#
# Honesty contract:
#   * Every suite's full output is replayed to stdout in canonical order.
#   * Per-suite wall clock is printed (SUITE_TIME) and persisted to
#     build/c/.suite-times.tsv for LPT balancing of the next run.
#   * A suite >60s prints SLOW_SUITE — under the #280 doctrine an individual
#     test >60s is a defect; a slow SUITE is the radar for finding it.
#   * The combined "<N> passed[, M failed][, K skipped]" line is printed LAST
#     so ci-cbm-test.sh's anchored summary grep keeps reading the true total.
#   * Any suite process exiting nonzero, or any suite log without a parsable
#     summary, fails the whole run (no silent shard loss). The exact-count
#     gate in ci-cbm-test.sh (sum == pinned total) backstops suite drift.
#
# Usage: test-shards.sh <path-to-test-runner>
#   CBM_TEST_SHARDS=N   override shard count (default: min(16, NPROC, #suites))

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUNNER="${1:?usage: test-shards.sh <path-to-test-runner>}"
if [[ ! -x "$RUNNER" && ! -f "$RUNNER.exe" ]]; then
  echo "ERROR[CBM_SHARDS_RUNNER_MISSING]: $RUNNER is not an executable test runner" >&2
  echo "  remediation: build it first (make -f Makefile.cbm build/c/test-runner)" >&2
  exit 1
fi

# Canonical suite list, extracted from the runner's own dispatch table so the
# driver can never silently drop a suite the runner knows about.
mapfile -t SUITES < <(
  grep -oE '^[[:space:]]*RUN_SELECTED_SUITE\([a-z0-9_]+\);' tests/test_main.c |
    sed -E 's/.*\(([a-z0-9_]+)\).*/\1/'
)
if [[ "${#SUITES[@]}" -lt 10 ]]; then
  echo "ERROR[CBM_SHARDS_SUITE_LIST]: extracted only ${#SUITES[@]} suites from tests/test_main.c" >&2
  echo "  remediation: the RUN_SELECTED_SUITE dispatch table moved or changed shape; fix this driver." >&2
  exit 1
fi

NPROC_LOCAL="${NPROC:-$(nproc 2>/dev/null || echo 8)}"
SHARDS="${CBM_TEST_SHARDS:-16}"
(( SHARDS > NPROC_LOCAL )) && SHARDS="$NPROC_LOCAL"
(( SHARDS > ${#SUITES[@]} )) && SHARDS="${#SUITES[@]}"
(( SHARDS < 1 )) && SHARDS=1

WORK="$ROOT/build/c/shards"
rm -rf -- "$WORK"
mkdir -p "$WORK"
TIMES_FILE="$ROOT/build/c/.suite-times.tsv"

# ── LPT partition: assign heaviest-first to the least-loaded shard ──────────
# Weights come from the previous run's measured durations (ms); a suite with
# no recorded time gets the median-ish default so it lands safely.
declare -A WEIGHT
if [[ -f "$TIMES_FILE" ]]; then
  while IFS=$'\t' read -r name ms; do
    [[ "$name" =~ ^[a-z0-9_]+$ && "$ms" =~ ^[0-9]+$ ]] && WEIGHT["$name"]="$ms"
  done < "$TIMES_FILE"
fi
DEFAULT_MS=2000

# Sort suites by weight desc (stable for equal weights).
mapfile -t ORDERED < <(
  for s in "${SUITES[@]}"; do
    printf '%012d\t%s\n' "${WEIGHT[$s]:-$DEFAULT_MS}" "$s"
  done | sort -r | cut -f2
)

declare -a SHARD_LOAD SHARD_LIST
for ((i = 0; i < SHARDS; i++)); do
  SHARD_LOAD[i]=0
  SHARD_LIST[i]=""
done
for s in "${ORDERED[@]}"; do
  best=0
  for ((i = 1; i < SHARDS; i++)); do
    (( SHARD_LOAD[i] < SHARD_LOAD[best] )) && best="$i"
  done
  SHARD_LIST[best]+="$s "
  (( SHARD_LOAD[best] += ${WEIGHT[$s]:-$DEFAULT_MS} )) || true
done

BASE_HOME="${HOME:?CBM shard driver requires the run-scoped HOME to be set}"
echo "INFO[CBM_SHARDS]: ${#SUITES[@]} suites across $SHARDS shards (base HOME=$BASE_HOME)"

# ── Run shards ───────────────────────────────────────────────────────────────
run_shard() {
  local idx="$1"
  # Shard homes live UNDER the run-scoped base HOME so every store write the
  # suite performs stays inside the one directory the hermeticity gate scans.
  local shard_home="$BASE_HOME/shards/home-$idx"
  # The shard temp sits INSIDE this repo, so a "non-git" fixture created there
  # would discover the outer .git and flip is_git=true (observed: three
  # git-context test failures in the first sharded run). Nest the temp one
  # level UNDER a per-shard ceiling dir and point GIT_CEILING_DIRECTORIES at
  # the ceiling — the same containment ci-cbm-test.sh establishes for the
  # launcher TMP, which the per-shard TMP override was silently discarding.
  local shard_ceil="$WORK/tmp-$idx"
  local shard_tmp="$shard_ceil/tmp"
  mkdir -p "$shard_home/.cache/codebase-memory-mcp" "$shard_tmp"
  local shard_ceil_native="$shard_ceil"
  if command -v cygpath >/dev/null 2>&1; then
    shard_ceil_native="$(cygpath -m "$shard_ceil")"
  fi
  if [[ -f "$BASE_HOME/.gitconfig" ]]; then
    cp -f "$BASE_HOME/.gitconfig" "$shard_home/.gitconfig"
  fi
  local suite start end rc
  for suite in ${SHARD_LIST[$idx]}; do
    start="$(date +%s%3N)"
    rc=0
    HOME="$shard_home" USERPROFILE="$shard_home" \
      TMP="$shard_tmp" TEMP="$shard_tmp" TMPDIR="$shard_tmp" \
      GIT_CEILING_DIRECTORIES="$shard_ceil_native" \
      "$RUNNER" "$suite" > "$WORK/log-$suite.txt" 2>&1 || rc=$?
    end="$(date +%s%3N)"
    printf '%s\t%s\t%s\n' "$suite" "$rc" "$((end - start))" >> "$WORK/result-$idx.tsv"
  done
}

for ((i = 0; i < SHARDS; i++)); do
  run_shard "$i" &
done
wait

# ── Aggregate: replay output canonically, sum counts, persist timings ───────
declare -A SUITE_RC SUITE_MS
for ((i = 0; i < SHARDS; i++)); do
  [[ -f "$WORK/result-$i.tsv" ]] || continue
  while IFS=$'\t' read -r name rc ms; do
    SUITE_RC["$name"]="$rc"
    SUITE_MS["$name"]="$ms"
  done < "$WORK/result-$i.tsv"
done

total_pass=0
total_fail=0
total_skip=0
hard_fail=0
: > "$TIMES_FILE.tmp"
for suite in "${SUITES[@]}"; do
  log="$WORK/log-$suite.txt"
  if [[ ! -f "$log" || -z "${SUITE_RC[$suite]:-}" ]]; then
    echo "ERROR[CBM_SHARDS_SUITE_LOST]: suite=$suite produced no result record" >&2
    hard_fail=1
    continue
  fi
  cat "$log"
  ms="${SUITE_MS[$suite]}"
  rc="${SUITE_RC[$suite]}"
  echo "SUITE_TIME[$suite]: ${ms}ms rc=$rc"
  printf '%s\t%s\n' "$suite" "$ms" >> "$TIMES_FILE.tmp"
  if (( ms > 60000 )); then
    echo "SLOW_SUITE[CBM]: $suite took ${ms}ms (>60s) — #280 doctrine: locate and delete/decompose the offending test(s)"
  fi
  summary="$(grep -E '^[[:space:]]*[0-9]+ passed' "$log" | tail -n 1 || true)"
  if [[ -z "$summary" ]]; then
    echo "ERROR[CBM_SHARDS_SUMMARY_MISSING]: suite=$suite log has no summary line (rc=$rc)" >&2
    hard_fail=1
    continue
  fi
  # Anchored at line start: a greedy `.*[^0-9]?` prefix lets the regex engine
  # eat leading digits and capture only the final digit (observed: 5764 -> 4).
  p="$(sed -nE 's/^[[:space:]]*([0-9]+) passed.*/\1/p' <<<"$summary")"
  f="$(sed -nE 's/.*[^0-9]([0-9]+) failed.*/\1/p' <<<"$summary")"
  k="$(sed -nE 's/.*[^0-9]([0-9]+) skipped.*/\1/p' <<<"$summary")"
  # Assignment form: `(( x += 0 ))` evaluates to 0 and aborts under set -e.
  total_pass=$((total_pass + ${p:-0}))
  total_fail=$((total_fail + ${f:-0}))
  total_skip=$((total_skip + ${k:-0}))
  if [[ "$rc" -ne 0 ]]; then
    echo "ERROR[CBM_SHARDS_SUITE_FAILED]: suite=$suite exit=$rc" >&2
    hard_fail=1
  fi
done
mv -f "$TIMES_FILE.tmp" "$TIMES_FILE"

# The combined summary MUST be the last "<N> passed" line on stdout:
# ci-cbm-test.sh anchors its count parse to the final such line.
printf '\n────────────────────────────────────────────\n'
if (( total_fail > 0 )); then
  printf '  %d passed, %d failed, %d skipped\n' "$total_pass" "$total_fail" "$total_skip"
else
  printf '  %d passed, %d skipped\n' "$total_pass" "$total_skip"
fi
printf '────────────────────────────────────────────\n\n'

if (( hard_fail != 0 || total_fail > 0 )); then
  exit 1
fi
exit 0
