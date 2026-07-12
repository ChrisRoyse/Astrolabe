<#
.SYNOPSIS
    FSV for the shared launcher session-lock semantics (#247, #197).

.DESCRIPTION
    Proves the load-bearing safety property: a launcher lock naming a LIVE foreign PID is
    REFUSED (ASTRO_LAUNCHER_LOCK_HELD) and that PID is provably never stopped. No mocks -- a
    real sleeper process is spawned and its OS liveness is read back before and after.

    Every case runs against an ISOLATED fixture lock in a run-scoped temp dir, never the live
    workspace lock (#197: FSV of lock semantics uses isolated fixture roots).

    Three edge cases (each prints before/after state):
      1. live foreign pid  -> HELD, refuse, sleeper still alive, lock file untouched
      2. dead pid          -> stale, removed, returns claimable
      3. malformed pid     -> UNREADABLE, refuse, lock file untouched
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "launcher-lock.ps1")

$fixtureRoot = Join-Path $env:TEMP ("astro-launcher-lock-fixture-{0}-{1}" -f $PID, ([guid]::NewGuid().ToString('N').Substring(0, 8)))
New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null

$failures = @()
function Check([bool]$Condition, [string]$What) {
    if ($Condition) { Write-Output "  PASS  $What" } else { Write-Output "  FAIL  $What"; $script:failures += $What }
}
function Test-Alive([int]$ProcId) { $null -ne (Get-Process -Id $ProcId -ErrorAction SilentlyContinue) }
function Write-Lock([string]$Path, $PidValue) {
    [ordered]@{ pid = $PidValue; started = (Get-Date).ToString('o'); command = 'fixture' } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $Path -Encoding UTF8
}

$sleeper = $null
try {
    # --- Case 1: a LIVE foreign pid must be refused and never stopped --------------------
    Write-Output "CASE 1: live foreign lock owner -> HELD, never stopped"
    $sleeper = Start-Process -FilePath "ping" -ArgumentList "-n", "60", "127.0.0.1" `
        -PassThru -WindowStyle Hidden
    $lock1 = Join-Path $fixtureRoot "held.lock"
    Write-Lock -Path $lock1 -PidValue $sleeper.Id
    $before = Test-Alive $sleeper.Id
    Write-Output "  before: sleeper pid=$($sleeper.Id) alive=$before ; lock exists=$([bool](Test-Path $lock1))"
    $threw = $false; $msg = ""
    try { Assert-AstroLauncherLockClaimable -LockPath $lock1 }
    catch { $threw = $true; $msg = "$($_.Exception.Message)" }
    $after = Test-Alive $sleeper.Id
    Write-Output "  after : threw=$threw ; sleeper alive=$after ; lock still exists=$([bool](Test-Path $lock1))"
    Check $threw "a live foreign lock is refused (throws)"
    Check ($msg -like "*ASTRO_LAUNCHER_LOCK_HELD*") "the refusal carries the ASTRO_LAUNCHER_LOCK_HELD code"
    Check $after "the live foreign PID is NEVER stopped (still alive after the check)"
    Check (Test-Path $lock1) "a live foreign lock file is NOT removed"

    # --- Case 2: a dead pid is a stale lock, removed, claimable --------------------------
    Write-Output "CASE 2: dead pid -> stale, removed, claimable"
    $shortLived = Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "exit", "0" -PassThru -WindowStyle Hidden
    $shortLived.WaitForExit()
    $deadPid = $shortLived.Id
    $lock2 = Join-Path $fixtureRoot "stale.lock"
    Write-Lock -Path $lock2 -PidValue $deadPid
    Write-Output "  before: dead pid=$deadPid alive=$(Test-Alive $deadPid) ; lock exists=$([bool](Test-Path $lock2))"
    $threw2 = $false
    try { Assert-AstroLauncherLockClaimable -LockPath $lock2 } catch { $threw2 = $true }
    Write-Output "  after : threw=$threw2 ; lock still exists=$([bool](Test-Path $lock2))"
    Check (-not $threw2) "a stale (dead-pid) lock is claimable (does not throw)"
    Check (-not (Test-Path $lock2)) "the stale lock file is removed"

    # --- Case 3: a malformed pid fails closed as UNREADABLE ------------------------------
    Write-Output "CASE 3: malformed pid -> UNREADABLE, refuse"
    $lock3 = Join-Path $fixtureRoot "unreadable.lock"
    Write-Lock -Path $lock3 -PidValue "not-a-pid"
    Write-Output "  before: lock exists=$([bool](Test-Path $lock3)) (pid field = 'not-a-pid')"
    $threw3 = $false; $msg3 = ""
    try { Assert-AstroLauncherLockClaimable -LockPath $lock3 } catch { $threw3 = $true; $msg3 = "$($_.Exception.Message)" }
    Write-Output "  after : threw=$threw3 ; lock still exists=$([bool](Test-Path $lock3))"
    Check $threw3 "a malformed-pid lock is refused (throws)"
    Check ($msg3 -like "*ASTRO_LAUNCHER_LOCK_UNREADABLE*") "the refusal carries the ASTRO_LAUNCHER_LOCK_UNREADABLE code"
    Check (Test-Path $lock3) "a malformed lock file is NOT removed (operator must inspect)"

    if ($failures.Count -eq 0) {
        Write-Output "LAUNCHER_LOCK_TEST[PASS]: live foreign PIDs are never stopped; stale removed; malformed fails closed"
        exit 0
    }
    Write-Output "LAUNCHER_LOCK_TEST[FAIL]: $($failures.Count) assertion(s) failed"
    exit 1
}
finally {
    if ($sleeper -and (Test-Alive $sleeper.Id)) { Stop-Process -Id $sleeper.Id -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
