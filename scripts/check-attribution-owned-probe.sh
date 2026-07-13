#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# #279: native FSV of the no-escape attribution recorder's causal owned-path probe.
# The probe (AstroTreeRecorder.ProbeOwnedStorePaths, Add-Typed straight out of
# scripts/windows-gnu-toolchain.ps1) uses the Windows Restart Manager to attribute a
# protected CBM-store file to the process that holds it open. The harness holds a real
# fixture store file open in a known pid and asserts the probe attributes it to that pid
# and NOT to a foreign pid -- proving owned_paths is populated CAUSALLY, so an our-tree
# store write REDs the run-wide no-escape verify (the #246 backstop #278 deferred here).
# It is a pure PowerShell + .NET Add-Type test needing no astrolabe binary.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    if command -v powershell.exe >/dev/null 2>&1; then PS_EXE=powershell.exe; else PS_EXE=pwsh.exe; fi
    "$PS_EXE" -NoProfile -ExecutionPolicy Bypass \
      -File "$(cygpath -w "$ROOT/scripts/test-attribution-owned-probe.ps1")"
    exit $?
    ;;
esac

# The Restart-Manager owned-path probe is a native-Windows launcher concern with no meaning
# off Windows. Per the Windows-only directive this is a deferred port-phase concern.
echo "DEFERRED[ASTRO_PORT_PHASE]: owned-path probe FSV is native-Windows only (scripts/test-attribution-owned-probe.ps1); not run on $(uname -s). Tracked in #238; not passing evidence."
exit 0
