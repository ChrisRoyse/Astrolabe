#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# #247/#197: the launcher session-lock semantics live in one audited, dot-sourceable
# place (scripts/launcher-lock.ps1). This gate runs its native FSV harness
# (scripts/test-launcher-lock.ps1) which spawns a real foreign process, writes fixture
# locks (never the live workspace lock), and reads OS liveness back before/after to prove
# the load-bearing safety property: a live foreign lock owner is REFUSED and NEVER stopped,
# a dead-pid lock is stale-removed, and a malformed lock fails closed as UNREADABLE.
# It is a pure PowerShell test needing no astrolabe binary, so it delegates directly.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    if command -v powershell.exe >/dev/null 2>&1; then PS_EXE=powershell.exe; else PS_EXE=pwsh.exe; fi
    "$PS_EXE" -NoProfile -ExecutionPolicy Bypass \
      -File "$(cygpath -w "$ROOT/scripts/test-launcher-lock.ps1")"
    exit $?
    ;;
esac

# The native Windows launcher and its PowerShell lock helper have no meaning off Windows.
# Per the Windows-only directive this is a deferred port-phase concern, disclosed not silent.
echo "DEFERRED[ASTRO_PORT_PHASE]: launcher-lock FSV is native-Windows only (scripts/test-launcher-lock.ps1); not run on $(uname -s). Tracked in #238; not passing evidence."
exit 0
