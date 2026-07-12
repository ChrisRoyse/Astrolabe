#!/usr/bin/env bash
# Shared gate helpers for the portable aggregate (scripts/check.sh) — #280.
#
# Provides a permanent per-gate timing surface. Every gate the aggregate runs is
# wrapped by `gate <name> -- <command...>`, which times the command and prints
# exactly one greppable line per gate:
#
#     GATE_TIME[<name>]=<seconds>
#
# and, at the end of the run, a single total:
#
#     GATE_TIME_TOTAL=<seconds>
#
# Timing is emitted whether the gate passes OR fails (the `|| rc=$?` guard keeps
# `set -e` from aborting before the line prints); the caller's `set -e` still
# aborts on the non-zero return, so failure semantics are unchanged. Times are
# millisecond-resolution wall clock (GNU coreutils `date +%s%3N`, available in
# the pinned Git-for-Windows bash), formatted as whole-second.milliseconds so a
# sub-second Python gate still shows a real number instead of "0".
#
# This file only DEFINES helpers; it has no side effects when sourced, so it is
# safe under `set -euo pipefail`.

# Milliseconds since the epoch. GNU date supports %N; the pinned toolchain ships it.
_gate_now_ms() { date +%s%3N; }

# Format a millisecond count as "<secs>.<millis>" (e.g. 1234 -> "1.234").
_gate_fmt_secs() {
  local ms="$1"
  printf '%d.%03d' "$((ms / 1000))" "$((ms % 1000))"
}

# Start the aggregate-wide total timer. Call once, near the top of the run.
gate_time_init() {
  _GATE_TOTAL_START_MS="$(_gate_now_ms)"
}

# gate <name> -- <command> [args...]
#
# Runs the command, prints its GATE_TIME line, and propagates its exit code so a
# failing gate still aborts the `set -e` caller (after its timing line prints).
gate() {
  local name="$1"
  shift
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  local start_ms end_ms rc=0
  start_ms="$(_gate_now_ms)"
  "$@" || rc=$?
  end_ms="$(_gate_now_ms)"
  echo "GATE_TIME[$name]=$(_gate_fmt_secs "$((end_ms - start_ms))")"
  return "$rc"
}

# gate_group <name1> <command1> [<name2> <command2> ...]
#
# Runs a set of INDEPENDENT, read-only gates concurrently, then prints their
# captured output grouped and serialized in the given order, one GATE_TIME line
# per gate. Every gate is waited on (so a failure never leaves a sibling process
# tree running into target/ cleanup); the group returns the FIRST failure's exit
# code so the `set -e` caller aborts, with the failing gate named. Each command
# is a single string run via `bash -c`. Intended only for the vetted set of
# pure static analyzers (no shared writable state, no spawned binaries) — see
# scripts/check.sh. The set is small (~a dozen light processes), so all launch
# at once; that is the simplest robust pattern and needs no `wait -n`.
gate_group() {
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/gate-group.XXXXXX")"
  local -a gnames=() glogs=() gpids=() gstart=() gend=() grc=()
  local i=0
  while [[ $# -gt 0 ]]; do
    local name="$1" cmd="$2"
    shift 2
    gnames[i]="$name"
    glogs[i]="$tmp/$i.log"
    gstart[i]="$(_gate_now_ms)"
    bash -c "$cmd" >"${glogs[i]}" 2>&1 &
    gpids[i]=$!
    i=$((i + 1))
  done
  local n=$i j rc
  for ((j = 0; j < n; j++)); do
    rc=0
    wait "${gpids[j]}" || rc=$?
    gend[j]="$(_gate_now_ms)"
    grc[j]=$rc
  done
  local first_rc=0 first_name=""
  for ((j = 0; j < n; j++)); do
    if [[ "${grc[j]}" -eq 0 ]]; then
      echo "--- gate[${gnames[j]}] OK ---"
    else
      echo "--- gate[${gnames[j]}] FAIL(exit=${grc[j]}) ---"
    fi
    cat "${glogs[j]}"
    echo "GATE_TIME[${gnames[j]}]=$(_gate_fmt_secs "$((gend[j] - gstart[j]))")"
    if [[ "${grc[j]}" -ne 0 && -z "$first_name" ]]; then
      first_name="${gnames[j]}"
      first_rc="${grc[j]}"
    fi
  done
  rm -rf "$tmp"
  if [[ -n "$first_name" ]]; then
    echo "ERROR[ASTRO_GATE_GROUP_FAILED]: $first_name exited $first_rc" >&2
    return "$first_rc"
  fi
  return 0
}

# Emit the run-wide total. Call once, at the very end of a successful run.
gate_time_total() {
  if [[ -z "${_GATE_TOTAL_START_MS:-}" ]]; then
    echo "GATE_TIME_TOTAL=unknown (gate_time_init was not called)"
    return 0
  fi
  local now_ms
  now_ms="$(_gate_now_ms)"
  echo "GATE_TIME_TOTAL=$(_gate_fmt_secs "$((now_ms - _GATE_TOTAL_START_MS))")"
}
