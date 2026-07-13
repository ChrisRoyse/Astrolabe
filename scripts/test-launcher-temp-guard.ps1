<#
.SYNOPSIS
    FSV harness for the #320 liveness-gated launcher cleanup (isolated fixture root).

.DESCRIPTION
    Exercises the real helper functions against a fresh isolated fixture directory (NEVER the
    live workspace .tmp -- #197 rule 5), using REAL spawned/killed processes and reading back
    on-disk directory + manifest state as evidence. Covers:

      1. Get-AstroAttributionTreePids: open (end=null) vs closed intervals, malformed input.
      2. Get-AstroLiveAttributedPids: real live child included, self excluded, dead excluded.
      3. Clear-DeadLauncherTempDirs: the #320 core -- a dead-launcher TEMP dir whose DETACHED
         child is still alive is KEPT; once the child dies the NEXT sweep reaps it. Live
         concurrent launcher kept; own dir skipped.
      4. Clear-DeadAttributionManifests (#320 upgrade): a dead-launcher manifest with a live
         child is kept; with no live child it is removed (#301 behaviour preserved).
      5. Edge triad: empty manifest, self-only manifest, invalid-JSON manifest.

    Exit 0 on all-pass, 1 on any failure (prints FAIL lines). No cargo/toolchain needed.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "attribution-manifest.ps1")
. (Join-Path $PSScriptRoot "launcher-temp-guard.ps1")

$script:Failures = 0
function Assert-True {
    param([bool]$Condition, [string]$Label)
    if ($Condition) { Write-Host "PASS: $Label" }
    else { Write-Host "FAIL: $Label"; $script:Failures++ }
}

function New-DeadPid {
    # A guaranteed-dead pid: spawn a trivial process, kill it, confirm it is gone.
    $p = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "exit" -PassThru -WindowStyle Hidden
    $deadPid = $p.Id
    try { Wait-Process -Id $deadPid -Timeout 5 -ErrorAction SilentlyContinue } catch {}
    try { Stop-Process -Id $deadPid -Force -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 200
    return $deadPid
}

function New-LiveChild {
    # A real, long-lived child process whose pid we control. Returns the Process object.
    return Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-NoProfile", "-Command", "Start-Sleep -Seconds 300" `
        -PassThru -WindowStyle Hidden
}

function Write-Manifest {
    param([string]$Path, [hashtable]$PidToLastEnd)
    # $PidToLastEnd: pid(int) -> last interval end (int or $null for OPEN).
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{"schema":"astrolabe.no_escape_attribution.v1","pid_intervals":{')
    $first = $true
    foreach ($k in $PidToLastEnd.Keys) {
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        $end = $PidToLastEnd[$k]
        $endJson = if ($null -eq $end) { "null" } else { "$end" }
        [void]$sb.Append("`"$k`":[[100,$endJson]]")
    }
    [void]$sb.Append('}}')
    Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8
}

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("astro-320-fsv-" + $PID + "-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
$liveChildren = @()
Write-Host "FIXTURE ROOT: $fixtureRoot"
try {
    $tmpDir = Join-Path $fixtureRoot ".tmp"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    # ---- 1. Get-AstroAttributionTreePids parsing --------------------------------------
    $m1 = Join-Path $tmpDir "parse-test.json"
    Write-Manifest -Path $m1 -PidToLastEnd ([ordered]@{ 111 = $null; 222 = 900; 333 = $null })
    $parsed = Get-AstroAttributionTreePids -ManifestPath $m1
    Assert-True ($parsed.Readable) "parse: readable manifest"
    Assert-True (($parsed.OpenPids -contains 111) -and ($parsed.OpenPids -contains 333)) "parse: open (null-end) pids detected"
    Assert-True (-not ($parsed.OpenPids -contains 222)) "parse: closed-interval pid excluded"

    # ---- 5. Edge triad (do it early; pure parsing) ------------------------------------
    $empty = Join-Path $tmpDir "empty.json"; Set-Content -LiteralPath $empty -Value "" -Encoding UTF8
    Assert-True (-not (Get-AstroAttributionTreePids -ManifestPath $empty).Readable) "edge: empty manifest -> not readable"
    $missing = Join-Path $tmpDir "does-not-exist.json"
    Assert-True (-not (Get-AstroAttributionTreePids -ManifestPath $missing).Readable) "edge: missing manifest -> not readable"
    $bad = Join-Path $tmpDir "bad.json"; Set-Content -LiteralPath $bad -Value "{not valid json,,}" -Encoding UTF8
    Assert-True (-not (Get-AstroAttributionTreePids -ManifestPath $bad).Readable) "edge: invalid JSON -> not readable (no throw)"

    # ---- 2. Get-AstroLiveAttributedPids: real live child, self excluded ---------------
    $child = New-LiveChild; $liveChildren += $child
    $childPid = $child.Id
    $selfOnly = Join-Path $tmpDir "self-only.json"
    Write-Manifest -Path $selfOnly -PidToLastEnd ([ordered]@{ $PID = $null })
    $selfGate = Get-AstroLiveAttributedPids -ManifestPath $selfOnly -SelfPid $PID
    Assert-True ($selfGate.LivePids.Count -eq 0) "gate: self pid excluded (boundary)"

    $liveM = Join-Path $tmpDir "live-child.json"
    Write-Manifest -Path $liveM -PidToLastEnd ([ordered]@{ $PID = $null; $childPid = $null })
    $liveGate = Get-AstroLiveAttributedPids -ManifestPath $liveM -SelfPid $PID
    Assert-True ($liveGate.LivePids -contains $childPid) "gate: real live detached child detected (defer decision = true)"
    Assert-True (-not ($liveGate.LivePids -contains $PID)) "gate: self not reported live"

    # ---- 3. Clear-DeadLauncherTempDirs: THE #320 CORE ---------------------------------
    $deadLauncherPid = New-DeadPid
    Assert-True (-not (Test-AstroPidAlive -OwnerPid $deadLauncherPid)) "setup: dead launcher pid confirmed dead"

    # TEMP dir named by the DEAD launcher pid, with a manifest naming the ALIVE detached child.
    $hazardDir = Join-Path $tmpDir ("windows-gnu-toolchain-" + $deadLauncherPid)
    New-Item -ItemType Directory -Path $hazardDir -Force | Out-Null
    $fixtureFile = Join-Path $hazardDir "running-test-fixture.db"
    Set-Content -LiteralPath $fixtureFile -Value "in-use" -Encoding UTF8
    $hazardManifest = Join-Path $tmpDir ("no-escape-attribution-" + $deadLauncherPid + ".json")
    Write-Manifest -Path $hazardManifest -PidToLastEnd ([ordered]@{ $deadLauncherPid = $null; $childPid = $null })

    # Own dir (must be skipped) + a live concurrent launcher dir (must be kept).
    $ownDir = Join-Path $tmpDir ("windows-gnu-toolchain-" + $PID)
    New-Item -ItemType Directory -Path $ownDir -Force | Out-Null
    $liveLauncher = New-LiveChild; $liveChildren += $liveLauncher
    $liveLauncherDir = Join-Path $tmpDir ("windows-gnu-toolchain-" + $liveLauncher.Id)
    New-Item -ItemType Directory -Path $liveLauncherDir -Force | Out-Null

    $sweep1 = Clear-DeadLauncherTempDirs -Directory $tmpDir -SelfPid $PID
    # READBACK: the hazard dir and its fixture file MUST still exist while the child is alive.
    Assert-True (Test-Path -LiteralPath $hazardDir) "reap-guard: dead-launcher dir with LIVE child KEPT (readback: dir exists)"
    Assert-True (Test-Path -LiteralPath $fixtureFile) "reap-guard: live child's fixture file NOT ripped (readback: file exists)"
    Assert-True ($sweep1.Kept -contains $hazardDir) "reap-guard: hazard dir reported Kept"
    Assert-True (Test-Path -LiteralPath $ownDir) "reap-guard: own dir skipped (readback: exists)"
    Assert-True ($sweep1.Skipped -contains $ownDir) "reap-guard: own dir reported Skipped"
    Assert-True (Test-Path -LiteralPath $liveLauncherDir) "reap-guard: live concurrent launcher dir kept (readback: exists)"

    # ---- 4. Clear-DeadAttributionManifests (#320 upgrade) while child still alive ------
    $swManifest1 = Clear-DeadAttributionManifests -Directory $tmpDir -SelfPid $PID
    Assert-True (Test-Path -LiteralPath $hazardManifest) "manifest-guard: dead-launcher manifest with LIVE child KEPT (readback: exists)"
    Assert-True ($swManifest1.Kept -contains $hazardManifest) "manifest-guard: hazard manifest reported Kept"

    # ---- Now kill the detached child and re-sweep: everything dead -> reaped -----------
    Stop-Process -Id $childPid -Force -ErrorAction SilentlyContinue
    try { Wait-Process -Id $childPid -Timeout 10 -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 400
    Assert-True (-not (Test-AstroPidAlive -OwnerPid $childPid)) "setup: detached child confirmed dead"

    $swManifest2 = Clear-DeadAttributionManifests -Directory $tmpDir -SelfPid $PID
    Assert-True (-not (Test-Path -LiteralPath $hazardManifest)) "manifest-guard: whole tree dead -> manifest reaped (readback: gone)"

    $sweep2 = Clear-DeadLauncherTempDirs -Directory $tmpDir -SelfPid $PID
    Assert-True (-not (Test-Path -LiteralPath $hazardDir)) "reap: whole tree dead -> hazard dir reaped (readback: gone)"
    Assert-True ($sweep2.Removed -contains $hazardDir) "reap: hazard dir reported Removed"
    Assert-True (Test-Path -LiteralPath $ownDir) "reap: own dir still skipped"
    Assert-True (Test-Path -LiteralPath $liveLauncherDir) "reap: live concurrent launcher dir still kept"
}
finally {
    foreach ($c in $liveChildren) {
        try { Stop-Process -Id $c.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($script:Failures -gt 0) {
    Write-Host "RESULT: $script:Failures FAILURE(S)"
    exit 1
}
Write-Host "RESULT: ALL PASS"
exit 0
