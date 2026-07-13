#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# #280: per-gate timing surface + parallel/gate-group helpers. Sourcing has no
# side effects, so it is safe before the cleanup trap is armed.
# shellcheck source=scripts/gate-lib.sh
source "$ROOT/scripts/gate-lib.sh"
gate_time_init

TARGET_CLEANUP_OWNER="${ASTROLABE_TARGET_CLEANUP_OWNER:-check}"
case "$TARGET_CLEANUP_OWNER" in
  check)
    cleanup_target() {
      local status=$?
      if ! bash "$ROOT/scripts/clean-target.sh"; then
        return 1
      fi
      return "$status"
    }
    bash "$ROOT/scripts/clean-target.sh"
    trap cleanup_target EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    ;;
  check-full|check-release)
    ;;
  *)
    echo "ERROR: invalid ASTROLABE_TARGET_CLEANUP_OWNER: $TARGET_CLEANUP_OWNER" >&2
    exit 2
    ;;
esac

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

# ── #280: gate-tooling self-tests (change-gated + parallel) ──────────────────
#
# These test-*.py scripts are META-TESTS of the gate tooling: they drive a gate
# script/patch-applier with fixtures and assert it fails/passes closed. They
# verify the tooling, not the product, so scripts/run-gate-selftests.py runs
# each only when its dependency fingerprint changed vs the recorded-green
# manifest (.astro-gate-cache/), and runs the eligible ones in bounded parallel.
# It fails closed: an absent/corrupt manifest, or a self-test whose pass/fail
# depends on live host state, runs unconditionally. check-full.sh /
# check-release.sh export ASTRO_GATE_SELFTESTS=all so the aggregate always runs
# every one; this change-gate is a Tier-1-only optimization. The driver prints
# its own GATE_TIME[selftest:<name>] lines and a GATE_TIME[gate-selftests] total.
#
# Every name is listed here (not hidden behind a manifest) so the gate-wiring
# contract can still see each test-*.py wired into the aggregate.
ASTRO_GATE_SELFTESTS_LIST=(
  scripts/test-cbm-skip-count.py
  scripts/test-cbm-lint-platform.py
  scripts/test-cbm-cache-guards.py
  scripts/test-check-libcbm-symbols.py
  scripts/test-parity-corpus-contract.py
  scripts/test-native-cargo-fmt.py
  scripts/test-check-no-mocks.py
  scripts/test-gate-wiring.py
  scripts/test-degradation-labels.py
  scripts/test-check-workspace-tests.py
  scripts/test-verify-chain-native-path.py
  scripts/test-native-binary-resolution.py
  scripts/test-installer-roundtrip-fixture.py
  scripts/test-egress-platform.py
  scripts/test-release-predicate.py
  scripts/test-check-hazard-suite.py
  scripts/test-check-no-escape.py
  scripts/test-no-escape-attribution.py
  scripts/test-cbm-spawn-fsv.py
  scripts/test-cbm-env-contract.py
  scripts/test-bench-ratios-artifact.py
  scripts/test-windows-gnu-toolchain-contract.py
  scripts/test-native-aggregate-wrapper.py
  scripts/test-check-hook-contracts.py
  scripts/test-cbm-overlay-sources.py
  scripts/test-check-suite-impact.py
  scripts/test-check-release-failpoint-strings.py
)
# The mechanism ITSELF (fail-closed change-gating) is proven by an unconditional
# meta-meta-test that must always run — never routed through the change-gate.
gate gate-selftests-mechanism -- "$PYTHON_BIN" scripts/test-run-gate-selftests.py
ASTRO_GATE_PYTHON="$PYTHON_BIN" ASTRO_GATE_ROOT="$ROOT" \
  "$PYTHON_BIN" scripts/run-gate-selftests.py "${ASTRO_GATE_SELFTESTS_LIST[@]}"

# ── #280: independent read-only static gates (bounded parallel, serialized) ──
#
# Each of these is a pure static analyzer: it scans repo bytes, spawns no
# binary, and writes no shared state (verified in #280). They are mutually
# independent, so gate_group runs them concurrently and prints their captured
# output grouped + serialized with one GATE_TIME line each, failing closed on
# the first failure.
gate_group \
  check-no-mocks        "\"$PYTHON_BIN\" scripts/check-no-mocks.py" \
  check-gate-wiring     "\"$PYTHON_BIN\" scripts/check-gate-wiring.py" \
  check-degradation-labels "\"$PYTHON_BIN\" scripts/check-degradation-labels.py" \
  check-shadow-parity-selftest "\"$PYTHON_BIN\" scripts/check-shadow-parity.py --selftest" \
  check-cbm-env-contract "\"$PYTHON_BIN\" scripts/check-cbm-env-contract.py" \
  check-license-notices "\"$PYTHON_BIN\" scripts/check-license-notices.py" \
  check-redaction-writers "\"$PYTHON_BIN\" scripts/check-redaction-writers.py" \
  check-shell-arg-audit "\"$PYTHON_BIN\" scripts/check-shell-arg-audit.py" \
  check-cbm-native-build-contract "\"$PYTHON_BIN\" scripts/check-cbm-native-build-contract.py" \
  check-windows-gnu-toolchain-contract "\"$PYTHON_BIN\" scripts/check-windows-gnu-toolchain-contract.py" \
  check-native-aggregate-wrapper "\"$PYTHON_BIN\" scripts/check-native-aggregate-wrapper.py" \
  check-allocator-contract "\"$PYTHON_BIN\" scripts/check-allocator-contract.py"

# ── Serial gates that spawn tools or touch process/lock state (kept serial) ──
gate no-todo -- bash scripts/check-no-todo.sh
gate unsafe-boundary -- bash scripts/check-unsafe-boundary.sh
gate hazard-suite -- "$PYTHON_BIN" scripts/check-hazard-suite.py
# #247/#197: native FSV of the shared launcher session-lock helper -- proves a live
# foreign lock owner is refused and never stopped (fixture locks, not the live workspace).
gate launcher-lock -- bash scripts/check-launcher-lock.sh
# #279: native FSV of the no-escape attribution recorder's causal owned-path probe --
# proves owned_paths is populated by attributing a held-open store file to its holder pid
# (Restart-Manager backed, real handles), so an our-tree store write REDs the run-wide verify.
gate attribution-owned-probe -- bash scripts/check-attribution-owned-probe.sh
# #301: native FSV of the attribution manifest lifecycle -- proves dead-PID manifests are
# swept at startup, a live-PID (concurrent session) manifest is inviolable (#197), and a
# run removes its own manifest + .tmp sibling on exit (fixture dirs, not the live .tmp).
gate attribution-manifest -- bash scripts/check-attribution-manifest.sh

# ── #291 suite impact gate: the astrolabe-ingest crash-FSV cluster ───────────
#
# #291: the child-process crash-recovery FSV tests in
# crates/astrolabe-ingest/src/ledger_verify.rs (kill_after_wal_append /
# kill_after_mvcc_commit / kill_after_checkpoint + their crash_*_child helpers)
# arm calyx-aster's `crash-fsv` failpoints. That failpoint must never reach a
# shipped binary, so it is an OPT-IN feature (astrolabe-ingest/crash-fsv-tests,
# NOT default) rather than a [dev-dependencies] feature Cargo would unify into
# every dev-target build — including the optimized `--example` builds the lscale
# bench compiles, where the #276 build-time guard correctly refuses
# feature+release (that unification was the release-gate RED this fixes). The
# default `nextest --workspace` above runs WITHOUT the feature, so it no longer
# covers this cluster; this named suite restores its coverage, built in the
# DEBUG profile so the #276 release guard stays silent. Impact-gated on the same
# fail-closed contract as every suite: byte-identical inputs vs the last green =>
# SKIP (the gate prints the counted label); ANY other state (including gate
# ambiguity) => RUN. check-release.sh sets ASTRO_SUITE_GATE=all so the release
# tier always runs it. The tests spawn child processes that create scratch under
# std::env::temp_dir(); point that at the run-scoped suite sandbox under target/
# (cleaned with the run) so nothing lands in the operator's real %TEMP%
# (workspace-block re-exports the same path when it runs).
CRASH_FSV_IMPACT_RC=0
"$PYTHON_BIN" scripts/check-suite-impact.py should-run crash-fsv || CRASH_FSV_IMPACT_RC=$?
if [[ "$CRASH_FSV_IMPACT_RC" -eq 3 ]]; then
  echo "  skipped suite: astrolabe-ingest crash-FSV cluster (kill_after_* / crash_*_child)"
else
  CRASH_FSV_CEIL="$ROOT/target/suite-tmp"
  CRASH_FSV_TMP="$CRASH_FSV_CEIL/tmp"
  mkdir -p "$CRASH_FSV_TMP"
  export TMP="$CRASH_FSV_TMP" TEMP="$CRASH_FSV_TMP" TMPDIR="$CRASH_FSV_TMP"
  gate crash-fsv -- "$CARGO_BIN" test -p astrolabe-ingest --features crash-fsv-tests -- kill_ crash_
  # Suite passed -> record its green so an unchanged input set skips next run.
  "$PYTHON_BIN" scripts/check-suite-impact.py record-green crash-fsv --note "check.sh crash-fsv cluster"
fi

# ── #280 suite impact gate: the workspace block ──────────────────────────────
#
# Doctrine (owner directive 2026-07-12): no test suite runs when no code change
# impacts it. Everything from the cargo-metadata resolve through the no-escape
# verify — the workspace tests, the binary-driving checks, the parity gates and
# the release artifacts — is one "workspace-block" suite whose declared input
# set (crates/, vendor/calyx, vendor/codebase-memory-mcp via libcbm, patches/cbm,
# cargo manifests, the driving gate scripts, the toolchain identities) is
# fingerprinted by scripts/check-suite-impact.py. Byte-identical inputs vs the
# last recorded GREEN run => the whole block skips with the counted label the
# gate prints; ANY other state (including any gate ambiguity) runs it all.
# check-release.sh sets ASTRO_SUITE_GATE=all so the release tier always runs.
WORKSPACE_IMPACT_RC=0
"$PYTHON_BIN" scripts/check-suite-impact.py should-run workspace-block || WORKSPACE_IMPACT_RC=$?
if [[ "$WORKSPACE_IMPACT_RC" -eq 3 ]]; then
  echo "  skipped block: cargo metadata/fmt, workspace tests, server bins, verify-chain, mimalloc, mcp-parity, rapid-init, cli-parity, compat-shim, installer, hooks, manifest, lowered/shadow parity, artifacts, cross-process, watchdog, egress, no-escape bracket"
else

# Resolve workspace metadata once per aggregate run (#192) and hand the JSON
# to every downstream consumer via ASTRO_CARGO_METADATA_JSON. Consumers filter
# to workspace_members, so the full resolve here (which also validates the
# lockfile for the --offline resolves below) matches their former --no-deps
# view. The cache lives under target/, owned by this run's cleanup.
mkdir -p "$ROOT/target"
ASTRO_CARGO_METADATA_JSON="$ROOT/target/astro-cargo-metadata.json"
gate cargo-metadata -- bash -c "\"$CARGO_BIN\" metadata --format-version 1 > \"$ASTRO_CARGO_METADATA_JSON\""
export ASTRO_CARGO_METADATA_JSON
# #280: fmt only the workspace-local crates. The owned vendor/ tree is
# full-graph-formatted by the Rust gate (scripts/ci-rust-gate.sh runs
# native-cargo-fmt.py --all in check-full), so re-checking vendor fmt every
# Tier-1 run is redundant work removed, not coverage lost.
echo "INFO[ASTRO_FMT_VENDOR_EXCLUDED]: vendor/ full-graph fmt runs in check-full via ci-rust-gate.sh"
gate fmt-workspace -- "$PYTHON_BIN" scripts/native-cargo-fmt.py --all --workspace-only -- --check
gate calyx-path-deps -- env CARGO="$CARGO_BIN" "$PYTHON_BIN" scripts/check-calyx-path-deps.py
# #237: snapshot the protected roots BEFORE the build/test phase can touch them.
gate no-escape-snapshot -- "$PYTHON_BIN" scripts/check-no-escape.py snapshot --out "$ROOT/target/no-escape-before.json"
# #246: give the suite a run-scoped scratch sandbox. The workspace tests (notably
# the Calyx integration tests) create scratch dirs via std::env::temp_dir(), which
# honors TMP/TEMP/TMPDIR on Windows; without an explicit sandbox they land in the
# operator's real %TEMP% and (correctly) trip the #237 no-escape gate. The gate that
# brackets this phase only *catches* escapes -- it never established a sandbox to
# escape from, so containment cannot depend on the launcher having redirected TMP
# (it demonstrably did not reach the cargo-test child processes). Point env::temp_dir
# at a dir under target/ (cleaned with it). The gate resolves operator_temp via the
# OS known-folder (REAL_TEMP), not the env, so this contains honest writes WITHOUT
# blinding the gate to any test that bypasses the redirect via an absolute path.
# Suite temp sits one level below a dedicated ceiling (target/suite-tmp/tmp under
# ceiling target/suite-tmp). It is inside this git checkout, so env::temp_dir()
# resolves inside the repo -- breaking tests that assume temp is outside a checkout
# (calyx-buildinfo compute_for_dir_outside_checkout_errors runs `git rev-parse` in
# env::temp_dir() and expects failure). target/ is git-ignored build output;
# GIT_CEILING_DIRECTORIES stops git's upward .git search at target/suite-tmp. The
# temp must nest UNDER the ceiling (a ceiling only blocks a walk crossing it from
# below), which also keeps git from other target/ subtrees (release-artifact commit
# stamping) and the source tree resolving $ROOT/.git normally. Native path for git.exe.
SUITE_CEIL="$ROOT/target/suite-tmp"
SUITE_TMP="$SUITE_CEIL/tmp"
mkdir -p "$SUITE_TMP"
export TMP="$SUITE_TMP" TEMP="$SUITE_TMP" TMPDIR="$SUITE_TMP"
if command -v cygpath >/dev/null 2>&1; then
  export GIT_CEILING_DIRECTORIES="$(cygpath -m "$SUITE_CEIL")"
else
  export GIT_CEILING_DIRECTORIES="$SUITE_CEIL"
fi
# #280: the standalone `cargo build --workspace` that used to precede the test
# phase was redundant -- `cargo test --workspace` (and the bounded
# check-workspace-tests.py runner) build a SUPERSET of the same targets,
# including both bin targets of astrolabe-server (astrolabe,
# codebase-memory-mcp; neither is behind required-features or test=false). The
# build is replaced by the test phase plus a fail-closed assertion (below) that
# the binaries the downstream checks consume were actually produced.
#
# #280 + #264 fast test tier: the workspace-test phase runs the nextest `fast`
# profile. Since the >60s tests were DELETED under the #280 sub-3-minute owner
# directive (2026-07-12: no individual test may take >60s), the fast profile
# carries NO filter and equals full workspace test coverage — per-test process
# parallelism, every test. The only remaining tier-out is the doctests, owned
# by check-release (ci-rust-gate.sh runs `cargo test --workspace --doc`).
# Fail-safe: if cargo-nextest is absent, run the full `cargo test --workspace`
# (more coverage, no tiering) rather than skipping silently.
WORKSPACE_TEST_MODE="cargo-test"
if command -v cargo-nextest >/dev/null 2>&1; then
  WORKSPACE_TEST_MODE="nextest-fast"
  echo "INFO[ASTRO_FAST_TIER_FULL_COVERAGE]: nextest fast profile == full workspace test set (the >60s tests were deleted under #280; .config/nextest.toml [profile.fast] carries no filter)"
  echo "SKIP[ASTRO_FAST_TIER_DOCTESTS]: owner=check-release (ci-rust-gate.sh runs cargo test --workspace --doc)"
else
  echo "INFO[ASTRO_FAST_TIER_NO_NEXTEST]: cargo-nextest not found -> running full cargo test --workspace (fail-safe: more coverage, no tiering)"
fi
if [[ -n "${ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS+x}" ]]; then
  WS_ARGS=(--cargo "$CARGO_BIN" --timeout-secs "$ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS")
  if [[ "$WORKSPACE_TEST_MODE" == "nextest-fast" ]]; then
    WS_ARGS+=(--nextest-profile fast)
  fi
  if gate workspace-test -- "$PYTHON_BIN" scripts/check-workspace-tests.py "${WS_ARGS[@]}"; then
    :
  else
    status=$?
    if [[ "$status" -eq 125 ]]; then
      echo "DEFERRED[ASTRO_WORKSPACE_TEST_TIMEOUT]: portable runtime checks were not started"
    fi
    exit "$status"
  fi
else
  if [[ "$WORKSPACE_TEST_MODE" == "nextest-fast" ]]; then
    gate workspace-test -- "$CARGO_BIN" nextest run --profile fast --workspace
  else
    gate workspace-test -- "$CARGO_BIN" test --workspace
  fi
fi
# #280: nextest builds test binaries, not necessarily the [[bin]] targets the
# downstream parity/shim checks consume. Guarantee both astrolabe-server bins
# (astrolabe, codebase-memory-mcp) with a targeted build -- cheap after the test
# compile warmed the dependency graph, and the replacement for the dropped ~129s
# full `cargo build --workspace`. The fail-closed assertion below is the backstop.
build_gate_binaries() {
  # Server bins + every binary a downstream gate invokes via cargo, built with
  # the gates' EXACT invocation shapes: a combined `-p A -p B` build resolves
  # a unified feature set that differs from each gate's solo command, so the
  # gates recompiled shared deps behind the cargo lock anyway (measured:
  # verify-chain 2m07s inside the group). Identical commands => the group's
  # cargo calls are warm no-ops.
  "$CARGO_BIN" build -p astrolabe-server --bins
  "$CARGO_BIN" build -p astrolabe-ingest --example build_verify_fixture
  "$CARGO_BIN" build -p astrolabe-lower --example lower_cbm_sqlite
  "$CARGO_BIN" test -p astrolabe-bridge --lib --no-run
}
gate build-gate-binaries -- build_gate_binaries
# #280: fail closed if the test phase did not produce the binaries the
# downstream binary-driving checks consume. This is the guard that lets us drop
# the redundant standalone build: unknown/missing => hard error, never a silent
# skip.
assert_debug_binaries() {
  local missing=()
  local bin
  for bin in astrolabe codebase-memory-mcp; do
    if [[ ! -x "$ROOT/target/debug/$bin" && ! -f "$ROOT/target/debug/$bin.exe" ]]; then
      missing+=("$bin")
    fi
  done
  if [[ "${#missing[@]}" -gt 0 ]]; then
    echo "ERROR[ASTRO_DEBUG_BINARY_MISSING]: the test + \`cargo build -p astrolabe-server --bins\` phase did not produce: ${missing[*]}" >&2
    echo "  remediation: a bin target may have gained required-features or test=false;" >&2
    echo "  fix the bin build above before the downstream binary checks depend on it." >&2
    return 1
  fi
  echo "INFO[ASTRO_DEBUG_BINARIES_PRESENT]: target/debug/{astrolabe,codebase-memory-mcp} produced by the test phase"
}
gate assert-debug-binaries -- assert_debug_binaries
# #240/#246/#248: the binary-driving checks below run the astrolabe /
# codebase-memory-mcp binaries and, without an explicit store, resolve
# CBM_CACHE_DIR->HOME->USERPROFILE to the operator's REAL
# ~/.cache/codebase-memory-mcp -- opening _config.db (the migration dial) there and
# churning its WAL sidecars, which the #237 no-escape gate (correctly) flags as an
# escape of the exclusive cbm_project_store_home_cache root. Point every downstream
# check at a run-scoped store under target/ so none touches the operator's real store
# (check-*.py that already set their own CBM_CACHE_DIR override this per-subprocess).
# Set AFTER the workspace test so the cbm-sys/bridge tests -- which assert real-store
# behavior and include $HOME-hardcoded CBM cases -- run unaffected.
CBM_STORE_SANDBOX="$ROOT/target/cbm-store-sandbox"
mkdir -p "$CBM_STORE_SANDBOX"
# The native astrolabe/codebase-memory-mcp binaries need a Windows path here. Git
# Bash auto-mangles TMP/TEMP/TMPDIR for native children but NOT CBM_CACHE_DIR, so an
# MSYS "/c/..." value would reach the binary verbatim and be rejected/misresolved --
# convert to the mixed "C:/..." form (as check-astrolabe-verify-chain.sh does).
if command -v cygpath >/dev/null 2>&1; then
  CBM_STORE_SANDBOX="$(cygpath -m "$CBM_STORE_SANDBOX")"
fi
export CBM_CACHE_DIR="$CBM_STORE_SANDBOX"
# #280: prefetch the CBM parity prod binary ONCE (content-keyed cache; warm
# hit is a copy). mcp-parity and the backgrounded lowered-parity both consume
# target/cbm-parity, so neither pays the build and they can overlap safely.
gate cbm-prod-binary -- bash scripts/cbm-prod-build.sh "$ROOT/target/cbm-parity"
# #280: the lowered-parity harness (~98s, self-contained: its own mkdtemp
# fixture/caches, per-subprocess CBM_CACHE_DIR, no writes to this run's shared
# CBM_STORE_SANDBOX) overlaps the whole binary-gate phase instead of
# extending it. Launched right after the cbm-prod-binary prefetch (its
# upstream binary resolve is a cache hit) and collected before
# shadow-parity (gate lowered-parity), where a failure still aborts the
# aggregate with the harness output attached.
LOWERED_PARITY_LOG="$ROOT/target/gate-logs/lowered-parity.log"
mkdir -p "$ROOT/target/gate-logs"
LOWERED_PARITY_ARGS=(scripts/check-lowered-parity.py)
if [[ "${ASTROLABE_CHECK_UI_SMOKE:-0}" == "1" ]]; then
  LOWERED_PARITY_ARGS+=(--ui-smoke)
fi
"$PYTHON_BIN" "${LOWERED_PARITY_ARGS[@]}" > "$LOWERED_PARITY_LOG" 2>&1 &
LOWERED_PARITY_PID=$!
# A gate failure between launch and collect aborts via set -e; the EXIT trap
# must reap the background harness so no orphan writes into target/ during
# cleanup. Composes with (never replaces) the owner=check target cleanup.
kill_lowered_parity() {
  kill "$LOWERED_PARITY_PID" 2>/dev/null || true
  wait "$LOWERED_PARITY_PID" 2>/dev/null || true
}
if [[ "$TARGET_CLEANUP_OWNER" == "check" ]]; then
  cleanup_check_and_bg() {
    local status=$?
    kill_lowered_parity
    if ! bash "$ROOT/scripts/clean-target.sh"; then
      return 1
    fi
    return "$status"
  }
  trap cleanup_check_and_bg EXIT
else
  cleanup_bg_only() {
    local status=$?
    kill_lowered_parity
    return "$status"
  }
  trap cleanup_bg_only EXIT
fi
lowered_parity_wait() {
  local rc=0
  wait "$LOWERED_PARITY_PID" || rc=$?
  cat "$LOWERED_PARITY_LOG"
  if [[ "$rc" -ne 0 ]]; then
    echo "ERROR[ASTRO_LOWERED_PARITY_FAILED]: check-lowered-parity.py exited $rc (output above)" >&2
  fi
  return "$rc"
}
# #6 (item 2): CBM's own MCP protocol suite (vendored test_mcp_rapid_init.py) must pass
# against the astrolabe binary UNMODIFIED -- spawn it, send initialize +
# notifications/initialized + tools/list with no delays, require the id:1 and id:2
# responses (tools present) within the timeout. Pass an absolute NATIVE path: Windows
# CreateProcess cannot resolve a relative/forward-slash binary path even when
# os.path.isfile accepts it. Inherits the sandboxed CBM_CACHE_DIR set above.
astro_mcp_bin="$ROOT/target/debug/astrolabe"
[[ -f "$astro_mcp_bin" ]] || astro_mcp_bin="${astro_mcp_bin}.exe"
if command -v cygpath >/dev/null 2>&1; then astro_mcp_bin="$(cygpath -w "$astro_mcp_bin")"; fi
echo "=== CBM MCP protocol suite (test_mcp_rapid_init.py) vs astrolabe (#6) ==="
# #280: every gate below is a SELF-ISOLATED consumer of the built binaries —
# each sets its own CBM_CACHE_DIR and its own temp fixture root (audited
# 2026-07-13), so none can perturb another through shared state. gate_group
# runs them concurrently (wall clock = the slowest member, not the sum) with
# grouped, serialized output and fail-closed first-failure semantics. The two
# cargo-invoking members (single-mimalloc, mcp-parity) serialize on cargo's
# own build lock, which only costs them a wait.
# Per-member run-scoped stores: a SHARED sandbox store serializes every
# spawned binary on one _config.db (SQLite locking false-failed mcp-parity and
# compat-shim under concurrency, 2026-07-13). Members that set their own
# per-check store keep it; the env value here is the fallback resolver target.
for member_store in verify-chain single-mimalloc mcp-parity mcp-rapid-init   cli-parity compat-shim installer-roundtrip hook-contracts server-manifest   cross-process-vault cross-process-servers watchdog; do
  mkdir -p "$ROOT/target/cbm-store-sandbox/$member_store"
done
GSTORE="$CBM_STORE_SANDBOX"
# #292 RESOLVED (root cause, 2026-07-13): the "rc=1 under concurrent load /
# clean-log silent exit" family was installer-roundtrip's `install -y --force`
# executing CBM's cbm_kill_other_instances(), which force-killed EVERY process
# named codebase-memory-mcp.exe host-wide (taskkill /F /FI IMAGENAME) — the
# shim, the parity prod binary, and the backgrounded lowered-parity harness's
# one-shot CLI all died with exit 1 and no output whenever they overlapped the
# installer's kill window. The kill is now identity-attributed to the exact
# install-target binary (vendor/codebase-memory-mcp/src/cli/cli.c), the
# installer gate carries both-ways kill-scope controls, and the formerly
# serialized members (mcp-parity, compat-shim, cross-process-*) return to the
# concurrent group below.
gate_group   verify-chain          "CBM_CACHE_DIR=\"$GSTORE/verify-chain\" bash scripts/check-astrolabe-verify-chain.sh \"$ROOT/target/debug/astrolabe\""   single-mimalloc       "CBM_CACHE_DIR=\"$GSTORE/single-mimalloc\" bash scripts/check-single-mimalloc.sh"   mcp-rapid-init        "CBM_CACHE_DIR=\"$GSTORE/mcp-rapid-init\" \"$PYTHON_BIN\" vendor/codebase-memory-mcp/scripts/test_mcp_rapid_init.py \"$astro_mcp_bin\""   cli-parity            "CBM_CACHE_DIR=\"$GSTORE/cli-parity\" \"$PYTHON_BIN\" scripts/check-cli-parity.py --astrolabe \"$ROOT/target/debug/astrolabe\""   installer-roundtrip   "CBM_CACHE_DIR=\"$GSTORE/installer-roundtrip\" \"$PYTHON_BIN\" scripts/check-installer-roundtrip.py --astrolabe \"$ROOT/target/debug/astrolabe\" --shim \"$ROOT/target/debug/codebase-memory-mcp\""   hook-contracts        "CBM_CACHE_DIR=\"$GSTORE/hook-contracts\" \"$PYTHON_BIN\" scripts/check-hook-contracts.py --astrolabe \"$ROOT/target/debug/astrolabe\" --shim \"$ROOT/target/debug/codebase-memory-mcp\""   server-manifest       "CBM_CACHE_DIR=\"$GSTORE/server-manifest\" \"$PYTHON_BIN\" scripts/check-server-manifest.py"   watchdog              "CBM_CACHE_DIR=\"$GSTORE/watchdog\" bash scripts/check-astrolabe-watchdog.sh \"$ROOT/target/debug/astrolabe\""   mcp-parity            "CBM_CACHE_DIR=\"$GSTORE/mcp-parity\" bash scripts/check-mcp-parity.sh"   cross-process-vault   "CBM_CACHE_DIR=\"$GSTORE/cross-process-vault\" \"$PYTHON_BIN\" scripts/check-cross-process-vault.py"   cross-process-servers "CBM_CACHE_DIR=\"$GSTORE/cross-process-servers\" \"$PYTHON_BIN\" scripts/check-cross-process-servers.py"   compat-shim           "CBM_CACHE_DIR=\"$GSTORE/compat-shim\" \"$PYTHON_BIN\" scripts/check-compat-shim.py --astrolabe \"$ROOT/target/debug/astrolabe\" --shim \"$ROOT/target/debug/codebase-memory-mcp\""
# Collect the backgrounded lowered-parity harness (launched above, after
# mcp-rapid-init). GATE_TIME here is the RESIDUAL wait — the harness ran
# concurrently under the gates in between.
gate lowered-parity -- lowered_parity_wait
gate shadow-parity -- "$PYTHON_BIN" scripts/check-shadow-parity.py --write-release-artifact
# #88: predicate artifacts are written ONLY after their attested tests have run
# (cargo test + workspace test above), stamped with commit + UTC timestamp so a
# run that dies in the build/test phase leaves no fresh 'pass' artifact behind.
gate license-notices-artifact -- "$PYTHON_BIN" scripts/check-license-notices.py --write-release-artifact
gate hazard-suite-artifact -- "$PYTHON_BIN" scripts/check-hazard-suite.py --write-release-artifact --cargo "$CARGO_BIN"
gate egress-deny -- "$PYTHON_BIN" scripts/check-egress-deny.py --allow-unsupported-platform --astrolabe "$ROOT/target/debug/astrolabe"
# #237: re-read the protected roots AFTER the full suite and fail closed if any
# test escaped its sandbox (added/modified/removed entry outside the run sandbox).
gate no-escape-verify -- "$PYTHON_BIN" scripts/check-no-escape.py verify --before "$ROOT/target/no-escape-before.json" --out "$ROOT/target/no-escape-after.json"

# #280: every gate in the block passed — record the green fingerprint so an
# unchanged input set skips the block next run (fail-closed; see the gate).
"$PYTHON_BIN" scripts/check-suite-impact.py record-green workspace-block --note "check.sh workspace block"

fi  # end #280 workspace-block impact gate

gate_time_total
