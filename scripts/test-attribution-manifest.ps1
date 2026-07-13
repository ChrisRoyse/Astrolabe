<#
.SYNOPSIS
    FSV for the no-escape attribution manifest lifecycle (#301).

.DESCRIPTION
    Proves the two load-bearing properties of scripts/attribution-manifest.ps1, with no
    mocks -- a real sleeper process is spawned and its OS liveness is read back:

      * STARTUP SWEEP removes ONLY dead-PID manifests. A manifest naming a LIVE process
        (a concurrent launcher session) is inviolable and never removed (#197); this
        run's own PID manifest is skipped; a manifest whose name carries no readable PID
        is swept. This is the "kill mid-run, relaunch -> stale swept, live survives" DoD
        (#301): the live sleeper stands in for the surviving concurrent run.
      * EXIT REMOVAL deletes a run's own manifest and its atomic-rename .tmp sibling on
        every path, idempotently and without throwing (the launcher finally must not
        throw, #239).

    Every case runs against an ISOLATED fixture directory in a run-scoped temp dir, never
    the live workspace .tmp (#197: FSV of these semantics uses isolated fixture roots).
    Every assertion is an independent readback of the fixture directory on disk.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "attribution-manifest.ps1")

$fixtureRoot = Join-Path $env:TEMP ("astro-attribution-manifest-fixture-{0}-{1}" -f $PID, ([guid]::NewGuid().ToString('N').Substring(0, 8)))
New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null

$failures = @()
function Check([bool]$Condition, [string]$What) {
    if ($Condition) { Write-Output "  PASS  $What" } else { Write-Output "  FAIL  $What"; $script:failures += $What }
}
function Test-Alive([int]$ProcId) { $null -ne (Get-Process -Id $ProcId -ErrorAction SilentlyContinue) }
function New-Manifest([string]$Directory, $PidToken, [switch]$WithTmp) {
    $name = "no-escape-attribution-$PidToken.json"
    $path = Join-Path $Directory $name
    Set-Content -LiteralPath $path -Value '{"schema":"astrolabe.no_escape_attribution.v1"}' -Encoding UTF8
    if ($WithTmp) { Set-Content -LiteralPath "$path.tmp" -Value '{}' -Encoding UTF8 }
    return $path
}
function Listing([string]$Directory) {
    if (-not (Test-Path -LiteralPath $Directory)) { return @() }
    return @(Get-ChildItem -LiteralPath $Directory -File | Select-Object -ExpandProperty Name | Sort-Object)
}

$sleeper = $null
try {
    # --- Case 1: startup sweep -- dead swept, LIVE kept, self skipped, no-pid swept -----
    Write-Output "CASE 1: startup sweep classifies by live PID (dead swept, live inviolable)"
    $sleeper = Start-Process -FilePath "ping" -ArgumentList "-n", "60", "127.0.0.1" -PassThru -WindowStyle Hidden
    $livePid = $sleeper.Id

    # A dead PID: spawn-and-wait so the PID is provably gone.
    $shortLived = Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "exit", "0" -PassThru -WindowStyle Hidden
    $shortLived.WaitForExit()
    $deadPid = $shortLived.Id

    $deadManifest = New-Manifest $fixtureRoot $deadPid -WithTmp
    $liveManifest = New-Manifest $fixtureRoot $livePid
    $selfManifest = New-Manifest $fixtureRoot $PID
    $nopidManifest = Join-Path $fixtureRoot "no-escape-attribution-notapid.json"
    Set-Content -LiteralPath $nopidManifest -Value '{}' -Encoding UTF8

    Write-Output "  before: $(Listing $fixtureRoot -join ', ')"
    Write-Output "  live sleeper pid=$livePid alive=$(Test-Alive $livePid); dead pid=$deadPid alive=$(Test-Alive $deadPid)"

    $result = Clear-DeadAttributionManifests -Directory $fixtureRoot -SelfPid $PID

    Write-Output "  after : $(Listing $fixtureRoot -join ', ')"
    Write-Output "  sweep : removed=$($result.Removed.Count) kept=$($result.Kept.Count) skipped=$($result.Skipped.Count)"

    Check (-not (Test-Path -LiteralPath $deadManifest)) "a dead-PID manifest is swept"
    Check (-not (Test-Path -LiteralPath "$deadManifest.tmp")) "the dead-PID manifest's .tmp sibling is swept too"
    Check (Test-Path -LiteralPath $liveManifest) "a LIVE-PID manifest is NEVER removed (concurrent session inviolable, #197)"
    Check (Test-Alive $livePid) "the live PID is never stopped by the sweep"
    Check (Test-Path -LiteralPath $selfManifest) "this run's own-PID manifest is skipped by the sweep"
    Check (-not (Test-Path -LiteralPath $nopidManifest)) "a manifest with no readable PID in its name is swept"

    # --- Case 2: exit removal is idempotent and non-throwing ----------------------------
    Write-Output "CASE 2: exit removal deletes own manifest + .tmp, idempotent, non-throwing"
    $ownManifest = New-Manifest $fixtureRoot 777777 -WithTmp
    Write-Output "  before: exists=$([bool](Test-Path $ownManifest)) tmp=$([bool](Test-Path "$ownManifest.tmp"))"
    $removed1 = Remove-AstroAttributionManifest -Path $ownManifest
    Write-Output "  after : exists=$([bool](Test-Path $ownManifest)) tmp=$([bool](Test-Path "$ownManifest.tmp")); removed=$($removed1.Count)"
    Check (-not (Test-Path -LiteralPath $ownManifest)) "exit removal deletes the manifest"
    Check (-not (Test-Path -LiteralPath "$ownManifest.tmp")) "exit removal deletes the .tmp sibling"
    Check ($removed1.Count -eq 2) "exit removal reports both removed paths"

    $threw = $false
    try { $removed2 = @(Remove-AstroAttributionManifest -Path $ownManifest) } catch { $threw = $true }
    Check (-not $threw) "a second removal of an already-gone manifest does not throw (idempotent)"
    Check ($removed2.Count -eq 0) "the idempotent removal reports nothing removed"

    # --- Case 3: an empty / absent directory sweeps cleanly -----------------------------
    Write-Output "CASE 3: sweeping an absent directory is a clean no-op"
    $absentDir = Join-Path $fixtureRoot "does-not-exist"
    $threw3 = $false
    try { $r3 = Clear-DeadAttributionManifests -Directory $absentDir -SelfPid $PID } catch { $threw3 = $true }
    Check (-not $threw3) "sweeping an absent directory does not throw"
    Check ($r3.Removed.Count -eq 0) "an absent directory removes nothing"

    if ($failures.Count -eq 0) {
        Write-Output "ATTRIBUTION_MANIFEST_TEST[PASS]: dead-PID manifests swept; live-PID manifests inviolable; own-manifest exit removal idempotent"
        exit 0
    }
    Write-Output "ATTRIBUTION_MANIFEST_TEST[FAIL]: $($failures.Count) assertion(s) failed"
    exit 1
}
finally {
    if ($sleeper -and (Test-Alive $sleeper.Id)) { Stop-Process -Id $sleeper.Id -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
