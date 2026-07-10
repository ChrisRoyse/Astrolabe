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
"$PYTHON_BIN" scripts/test-check-libcbm-symbols.py
"$PYTHON_BIN" scripts/test-parity-corpus-contract.py
"$PYTHON_BIN" scripts/test-native-cargo-fmt.py
bash scripts/check-no-todo.sh
bash scripts/check-unsafe-boundary.sh
"$PYTHON_BIN" scripts/check-gate-wiring.py
"$PYTHON_BIN" scripts/test-gate-wiring.py
"$PYTHON_BIN" scripts/test-check-workspace-tests.py
"$PYTHON_BIN" scripts/test-verify-chain-native-path.py
"$PYTHON_BIN" scripts/test-egress-platform.py
"$PYTHON_BIN" scripts/test-release-predicate.py
"$PYTHON_BIN" scripts/test-bench-ratios-artifact.py
"$PYTHON_BIN" scripts/check-license-notices.py --write-release-artifact
"$PYTHON_BIN" scripts/check-redaction-writers.py
"$PYTHON_BIN" scripts/check-shell-arg-audit.py
"$PYTHON_BIN" scripts/check-hazard-suite.py --write-release-artifact
"$PYTHON_BIN" scripts/test-cbm-mem-pressure-patch.py
"$PYTHON_BIN" scripts/check-cbm-native-build-contract.py
"$PYTHON_BIN" scripts/check-windows-gnu-toolchain-contract.py
"$PYTHON_BIN" scripts/check-allocator-contract.py
"$CARGO_BIN" metadata --format-version 1 >/dev/null
"$PYTHON_BIN" scripts/native-cargo-fmt.py --all -- --check
CARGO="$CARGO_BIN" "$PYTHON_BIN" scripts/check-calyx-path-deps.py
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
bash scripts/check-astrolabe-verify-chain.sh "$ROOT/target/debug/astrolabe"
bash scripts/check-single-mimalloc.sh
bash scripts/check-mcp-parity.sh
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
"$PYTHON_BIN" scripts/check-cross-process-vault.py
"$PYTHON_BIN" scripts/check-cross-process-servers.py
bash scripts/check-astrolabe-watchdog.sh "$ROOT/target/debug/astrolabe"
"$PYTHON_BIN" scripts/check-egress-deny.py --allow-unsupported-platform --astrolabe "$ROOT/target/debug/astrolabe"
