<#
.SYNOPSIS
    FSV for the #279 causal owned-path probe in the no-escape attribution recorder.

.DESCRIPTION
    The CBM store files are not pid-named, so the no-escape gate can only attribute an
    our-tree store write to this run via the launcher's owned-path probe. That probe
    (AstroTreeRecorder.ProbeOwnedStorePaths) uses the Windows Restart Manager to ask
    which process currently holds each protected store file open, and records the files
    held by a tree pid into owned_paths.

    This is the standing control that the probe is CAUSAL and REAL (no mocks): a fixture
    store file is held open by a KNOWN pid (this process), and the probe must attribute
    it to that pid and NOT to a foreign pid. Every assertion is an independent readback.

    The recorder C# is Add-Typed straight out of scripts/windows-gnu-toolchain.ps1 (the
    same source the launcher compiles) so this test exercises the shipped code, not a copy.

    Cases:
      1. fixture store file held open by THIS pid, probe with treePids=@(this) -> attributed
      2. same open file, probe with a FOREIGN pid set -> NOT attributed
      3. handle closed -> file no longer held -> probe returns empty
      4. non-existent / empty store root -> empty (probe ran, nothing owned; not a failure)
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$launcher = Join-Path $scriptRoot "windows-gnu-toolchain.ps1"

# Extract the recorder C# here-string ($AstroTreeRecorderSource = @' ... '@) from the
# launcher and Add-Type it, so we test the SHIPPED source, never a divergent copy.
$launcherText = Get-Content -LiteralPath $launcher -Raw
$marker = "`$AstroTreeRecorderSource = @'"
$startIdx = $launcherText.IndexOf($marker)
if ($startIdx -lt 0) { throw "could not find `$AstroTreeRecorderSource here-string in $launcher" }
$bodyStart = $launcherText.IndexOf("`n", $startIdx) + 1
$endIdx = $launcherText.IndexOf("`n'@", $bodyStart)
if ($endIdx -lt 0) { throw "could not find the closing '@ of the recorder here-string" }
$recorderSource = $launcherText.Substring($bodyStart, $endIdx - $bodyStart)
if (-not ([System.Management.Automation.PSTypeName]'AstroTreeRecorder').Type) {
    Add-Type -TypeDefinition $recorderSource -Language CSharp -ErrorAction Stop
}

$failures = @()
function Check([bool]$Condition, [string]$What) {
    if ($Condition) { Write-Output "  PASS  $What" } else { Write-Output "  FAIL  $What"; $script:failures += $What }
}

$fixtureRoot = Join-Path $env:TEMP ("astro-owned-probe-fixture-{0}-{1}" -f $PID, ([guid]::NewGuid().ToString('N').Substring(0, 8)))
New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
$storeRoot = Join-Path $fixtureRoot "cbm-store"
New-Item -ItemType Directory -Path $storeRoot -Force | Out-Null
$storeFile = Join-Path $storeRoot "_config.db"
Set-Content -LiteralPath $storeFile -Value "operator store baseline" -Encoding UTF8

$handle = $null
try {
    Write-Output "CASE 1: fixture store file held open by THIS pid -> attributed to this pid"
    # Hold a real OS handle open in THIS process (a known tree pid = $PID).
    $handle = [System.IO.File]::Open($storeFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
    $owned = [AstroTreeRecorder]::ProbeOwnedStorePaths([int[]]@($PID), [string[]]@($storeRoot))
    Write-Output "  probe(treePids=@($PID)) -> [$($owned -join '; ')]"
    Check ($owned -contains $storeFile) "the open store file is attributed to its holder pid ($PID)"

    Write-Output "CASE 2: same open file, probe with a FOREIGN pid set -> NOT attributed"
    # A pid guaranteed not to be this process. Pick a definitely-absent high pid.
    $foreignPid = 1
    while ($foreignPid -eq $PID -or ($null -ne (Get-Process -Id $foreignPid -ErrorAction SilentlyContinue))) { $foreignPid += 2 }
    $ownedForeign = [AstroTreeRecorder]::ProbeOwnedStorePaths([int[]]@($foreignPid), [string[]]@($storeRoot))
    Write-Output "  probe(treePids=@($foreignPid)) -> [$($ownedForeign -join '; ')]"
    Check (-not ($ownedForeign -contains $storeFile)) "a foreign-pid probe does NOT attribute the file (causal, not name-based)"

    Write-Output "CASE 3: handle closed -> file no longer held -> probe returns empty"
    $handle.Dispose(); $handle = $null
    # RM may briefly report the handle post-close; retry a few times for determinism.
    $ownedClosed = $null
    for ($i = 0; $i -lt 10; $i++) {
        $ownedClosed = [AstroTreeRecorder]::ProbeOwnedStorePaths([int[]]@($PID), [string[]]@($storeRoot))
        if (-not ($ownedClosed -contains $storeFile)) { break }
        Start-Sleep -Milliseconds 100
    }
    Write-Output "  probe after close -> [$($ownedClosed -join '; ')]"
    Check (-not ($ownedClosed -contains $storeFile)) "a store file with no open handle is not attributed"

    Write-Output "CASE 4: absent store root -> empty result (probe ran, owned nothing; not a failure)"
    $absent = Join-Path $fixtureRoot "does-not-exist"
    $ownedAbsent = [AstroTreeRecorder]::ProbeOwnedStorePaths([int[]]@($PID), [string[]]@($absent))
    Check ($ownedAbsent.Count -eq 0) "an absent store root yields an empty owned set, no throw"

    if ($failures.Count -eq 0) {
        Write-Output "OWNED_PROBE_TEST[PASS]: the owned-path probe is causal (attributes only the holder pid, RM-backed, real handles)"
        exit 0
    }
    Write-Output "OWNED_PROBE_TEST[FAIL]: $($failures.Count) assertion(s) failed"
    exit 1
}
finally {
    if ($null -ne $handle) { $handle.Dispose() }
    if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
