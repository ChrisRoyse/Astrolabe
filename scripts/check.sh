#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

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

bash scripts/verify-pins.sh
"$PYTHON_BIN" scripts/test-verify-pins.py
"$PYTHON_BIN" scripts/test-cbm-skip-count.py
"$PYTHON_BIN" scripts/test-cbm-lint-platform.py
"$PYTHON_BIN" scripts/test-cbm-format-overlay.py
"$PYTHON_BIN" scripts/test-cbm-cache-guards.py
"$PYTHON_BIN" scripts/test-check-libcbm-symbols.py
"$PYTHON_BIN" scripts/test-parity-corpus-contract.py
"$PYTHON_BIN" scripts/test-native-cargo-fmt.py
bash scripts/check-no-todo.sh
"$PYTHON_BIN" scripts/check-no-mocks.py
"$PYTHON_BIN" scripts/test-check-no-mocks.py
bash scripts/check-unsafe-boundary.sh
"$PYTHON_BIN" scripts/check-gate-wiring.py
"$PYTHON_BIN" scripts/test-gate-wiring.py
"$PYTHON_BIN" scripts/check-degradation-labels.py
"$PYTHON_BIN" scripts/test-degradation-labels.py
"$PYTHON_BIN" scripts/test-check-workspace-tests.py
"$PYTHON_BIN" scripts/test-verify-chain-native-path.py
"$PYTHON_BIN" scripts/test-native-binary-resolution.py
"$PYTHON_BIN" scripts/test-installer-roundtrip-fixture.py
"$PYTHON_BIN" scripts/test-egress-platform.py
"$PYTHON_BIN" scripts/test-release-predicate.py
"$PYTHON_BIN" scripts/test-check-hazard-suite.py
"$PYTHON_BIN" scripts/test-check-no-escape.py
"$PYTHON_BIN" scripts/test-cbm-spawn-patch.py
"$PYTHON_BIN" scripts/test-cbm-spawn-fsv.py
"$PYTHON_BIN" scripts/test-cbm-env-store-patch.py
"$PYTHON_BIN" scripts/test-cbm-env-contract.py
"$PYTHON_BIN" scripts/check-cbm-env-contract.py
"$PYTHON_BIN" scripts/test-bench-ratios-artifact.py
"$PYTHON_BIN" scripts/check-license-notices.py
"$PYTHON_BIN" scripts/check-redaction-writers.py
"$PYTHON_BIN" scripts/check-shell-arg-audit.py
"$PYTHON_BIN" scripts/check-hazard-suite.py
"$PYTHON_BIN" scripts/test-cbm-mem-pressure-patch.py
"$PYTHON_BIN" scripts/check-cbm-native-build-contract.py
"$PYTHON_BIN" scripts/check-windows-gnu-toolchain-contract.py
"$PYTHON_BIN" scripts/test-windows-gnu-toolchain-contract.py
# #247/#197: native FSV of the shared launcher session-lock helper -- proves a live
# foreign lock owner is refused and never stopped (fixture locks, not the live workspace).
bash scripts/check-launcher-lock.sh
"$PYTHON_BIN" scripts/check-native-aggregate-wrapper.py
"$PYTHON_BIN" scripts/test-native-aggregate-wrapper.py
"$PYTHON_BIN" scripts/check-allocator-contract.py
# Resolve workspace metadata once per aggregate run (#192) and hand the JSON
# to every downstream consumer via ASTRO_CARGO_METADATA_JSON. Consumers filter
# to workspace_members, so the full resolve here (which also validates the
# lockfile for the --offline resolves below) matches their former --no-deps
# view. The cache lives under target/, owned by this run's cleanup.
mkdir -p "$ROOT/target"
ASTRO_CARGO_METADATA_JSON="$ROOT/target/astro-cargo-metadata.json"
"$CARGO_BIN" metadata --format-version 1 >"$ASTRO_CARGO_METADATA_JSON"
export ASTRO_CARGO_METADATA_JSON
"$PYTHON_BIN" scripts/native-cargo-fmt.py --all -- --check
CARGO="$CARGO_BIN" "$PYTHON_BIN" scripts/check-calyx-path-deps.py
# #237: snapshot the protected roots BEFORE the build/test phase can touch them.
"$PYTHON_BIN" scripts/check-no-escape.py snapshot --out "$ROOT/target/no-escape-before.json"
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
"$CARGO_BIN" build --workspace
if [[ -n "${ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS+x}" ]]; then
  if "$PYTHON_BIN" scripts/check-workspace-tests.py \
    --cargo "$CARGO_BIN" \
    --timeout-secs "$ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS"; then
    :
  else
    status=$?
    if [[ "$status" -eq 125 ]]; then
      echo "DEFERRED[ASTRO_WORKSPACE_TEST_TIMEOUT]: portable runtime checks were not started"
    fi
    exit "$status"
  fi
else
  "$CARGO_BIN" test --workspace
fi
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
bash scripts/check-astrolabe-verify-chain.sh "$ROOT/target/debug/astrolabe"
bash scripts/check-single-mimalloc.sh
bash scripts/check-mcp-parity.sh
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
"$PYTHON_BIN" vendor/codebase-memory-mcp/scripts/test_mcp_rapid_init.py "$astro_mcp_bin"
"$PYTHON_BIN" scripts/check-cli-parity.py --astrolabe "$ROOT/target/debug/astrolabe"
"$PYTHON_BIN" scripts/check-compat-shim.py --astrolabe "$ROOT/target/debug/astrolabe" --shim "$ROOT/target/debug/codebase-memory-mcp"
"$PYTHON_BIN" scripts/check-installer-roundtrip.py --astrolabe "$ROOT/target/debug/astrolabe" --shim "$ROOT/target/debug/codebase-memory-mcp"
"$PYTHON_BIN" scripts/check-hook-contracts.py --astrolabe "$ROOT/target/debug/astrolabe" --shim "$ROOT/target/debug/codebase-memory-mcp"
"$PYTHON_BIN" scripts/check-server-manifest.py
if [[ "${ASTROLABE_CHECK_UI_SMOKE:-0}" == "1" ]]; then
  "$PYTHON_BIN" scripts/check-lowered-parity.py --ui-smoke
else
  "$PYTHON_BIN" scripts/check-lowered-parity.py
fi
"$PYTHON_BIN" scripts/check-shadow-parity.py --write-release-artifact
# #88: predicate artifacts are written ONLY after their attested tests have run
# (cargo build + workspace test above), stamped with commit + UTC timestamp so a
# run that dies in the build/test phase leaves no fresh 'pass' artifact behind.
"$PYTHON_BIN" scripts/check-license-notices.py --write-release-artifact
"$PYTHON_BIN" scripts/check-hazard-suite.py --write-release-artifact --cargo "$CARGO_BIN"
"$PYTHON_BIN" scripts/check-cross-process-vault.py
"$PYTHON_BIN" scripts/check-cross-process-servers.py
bash scripts/check-astrolabe-watchdog.sh "$ROOT/target/debug/astrolabe"
"$PYTHON_BIN" scripts/check-egress-deny.py --allow-unsupported-platform --astrolabe "$ROOT/target/debug/astrolabe"
# #237: re-read the protected roots AFTER the full suite and fail closed if any
# test escaped its sandbox (added/modified/removed entry outside the run sandbox).
"$PYTHON_BIN" scripts/check-no-escape.py verify --before "$ROOT/target/no-escape-before.json" --out "$ROOT/target/no-escape-after.json"
