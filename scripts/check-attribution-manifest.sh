#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# #301: native FSV of the no-escape attribution manifest lifecycle (scripts/attribution-manifest.ps1).
# Proves the load-bearing hygiene properties with a real spawned process: the dead-PID
# startup sweep removes stale manifests, a LIVE-PID manifest is inviolable (never removed,
# #197), this run's own manifest is skipped, and exit removal deletes a run's own manifest
# plus its .tmp sibling idempotently without throwing. Fixture directories only, never the
# live workspace .tmp. Pure PowerShell, needs no astrolabe binary.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    if command -v powershell.exe >/dev/null 2>&1; then PS_EXE=powershell.exe; else PS_EXE=pwsh.exe; fi
    "$PS_EXE" -NoProfile -ExecutionPolicy Bypass \
      -File "$(cygpath -w "$ROOT/scripts/test-attribution-manifest.ps1")"
    exit $?
    ;;
esac

# The native Windows launcher's attribution-manifest lifecycle has no meaning off Windows.
# Per the Windows-only directive this is a deferred port-phase concern, disclosed not silent.
echo "DEFERRED[ASTRO_PORT_PHASE]: attribution-manifest FSV is native-Windows only (scripts/test-attribution-manifest.ps1); not run on $(uname -s). Tracked in #238; not passing evidence."
exit 0
