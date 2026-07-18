<#
.SYNOPSIS
    Shared, dot-sourceable lifecycle for no-escape attribution manifests (#301).

.DESCRIPTION
    The launcher writes a per-run process-tree attribution manifest at
    .tmp/no-escape-attribution-<PID>.json (#278). Nothing removed it, so 49 stale
    dead-PID manifests accumulated in the workspace .tmp (#301). This helper is the
    single audited place that removes a run's own manifest on exit and sweeps stale
    dead-PID manifests at startup.

    Like the launcher-lock helper (#197/#247), it NEVER stops a process and treats a
    LIVE-PID manifest as inviolable: the startup sweep probes the exact recorded PID
    with Get-Process -Id and deletes ONLY manifests whose PID is dead (or whose name
    carries no readable PID). A future stale-manifest consumer (#293) can then trust
    the .tmp manifest corpus. The current run's own manifest is never swept.

    Both the launcher and its manual FSV (exercised against isolated fixture dirs -- never
    the live .tmp) route through these functions.
#>

# .tmp basename shape the launcher writes: no-escape-attribution-<PID>.json (+ its
# <name>.tmp atomic-rename sibling). One regex is the single source of truth for the
# name<->PID mapping the sweep depends on.
$script:AstroAttributionManifestPattern = 'no-escape-attribution-*.json'
$script:AstroAttributionManifestPidRegex = '^no-escape-attribution-(?<pid>\d+)\.json$'

function Remove-AstroAttributionManifest {
    # RAII exit cleanup: remove a run's own manifest and its atomic-rename sibling.
    # Idempotent and non-throwing -- it runs in the launcher's finally, which must never
    # throw (a throw there destroys the child's exit-code contract, #239). Returns the
    # list of paths it actually removed (for evidence).
    param([Parameter(Mandatory)][string]$Path)

    $removed = @()
    foreach ($candidate in @($Path, "$Path.tmp")) {
        if (Test-Path -LiteralPath $candidate) {
            try {
                Remove-Item -LiteralPath $candidate -Force -ErrorAction Stop
                $removed += $candidate
            }
            catch {
                # Non-fatal: report via the return value, never throw from cleanup.
            }
        }
    }
    return $removed
}

function Test-AstroPidAlive {
    # Liveness probe of the EXACT recorded pid only -- never a by-name sweep (#197).
    param([Parameter(Mandatory)][int]$OwnerPid)
    return ($null -ne (Get-Process -Id $OwnerPid -ErrorAction SilentlyContinue))
}

function Get-AstroAttributionTreePids {
    # Parse an attribution manifest (#278 schema astrolabe.no_escape_attribution.v1) and
    # return the OPEN-interval tree pids -- pids the recorder recorded and never observed
    # exit. Each pid maps to a list of [start,end] instance intervals; a last interval whose
    # end is JSON null means the instance had NOT exited when the manifest was flushed, i.e.
    # an open window. A pid whose last interval is CLOSED is excluded (the recorder saw it
    # die; a now-live same pid is OS pid-reuse by an unrelated process, not our child).
    # Returns { Readable = $true|$false; OpenPids = @(int) }. Readable=$false on a missing,
    # empty, malformed, or schema-less manifest (the caller decides how to treat that).
    param([Parameter(Mandatory)][string]$ManifestPath)

    $open = @()
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        return [pscustomobject]@{ Readable = $false; OpenPids = $open }
    }
    $raw = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return [pscustomobject]@{ Readable = $false; OpenPids = $open }
    }
    $doc = $null
    try { $doc = ConvertFrom-Json -InputObject $raw } catch { $doc = $null }
    if ($null -eq $doc -or -not $doc.PSObject.Properties['pid_intervals']) {
        return [pscustomobject]@{ Readable = $false; OpenPids = $open }
    }
    foreach ($prop in $doc.pid_intervals.PSObject.Properties) {
        $ownerPid = 0
        if (-not [int]::TryParse($prop.Name, [ref]$ownerPid)) { continue }
        $spans = @($prop.Value)
        if ($spans.Count -eq 0) { continue }
        $last = @($spans[$spans.Count - 1])
        # [start, end]; end == $null (JSON null) is an OPEN window.
        if ($last.Count -ge 2 -and $null -eq $last[1]) {
            $open += $ownerPid
        }
    }
    return [pscustomobject]@{ Readable = $true; OpenPids = @($open | Sort-Object -Unique) }
}

function Get-AstroCleanupProtectionClass {
    # #539: every live attributed process protects launcher-owned state by default. The
    # sole exception is the detached MSVC telemetry uploader, which consumes no build
    # inputs but can idle indefinitely after its compiler parent exits. It is
    # non-protecting only when every identity predicate below succeeds. Classification is
    # read-only and never stops or changes a process; an unreadable predicate protects.
    param([Parameter(Mandatory)][int]$OwnerPid)

    try {
        $row = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $OwnerPid" -ErrorAction Stop
        if ($null -eq $row) {
            return [pscustomobject]@{ Protection = 'not_required'; ImagePath = $null; Reason = 'process exited before classification' }
        }
        $imagePath = [string]$row.ExecutablePath
        if ([string]::IsNullOrWhiteSpace($imagePath)) {
            return [pscustomobject]@{ Protection = 'unevaluable'; ImagePath = $null; Reason = 'image path unreadable' }
        }
        if ([IO.Path]::GetFileName($imagePath) -notlike 'VCTIP.exe') {
            return [pscustomobject]@{ Protection = 'required'; ImagePath = $imagePath; Reason = 'not the MSVC telemetry uploader' }
        }
        if ($imagePath -notmatch '\\VC\\Tools\\MSVC\\[^\\]+\\bin\\Host[^\\]+\\[^\\]+\\VCTIP\.EXE$') {
            return [pscustomobject]@{ Protection = 'required'; ImagePath = $imagePath; Reason = 'VCTIP name outside an MSVC toolset host-tools directory' }
        }

        $commandLine = [string]$row.CommandLine
        if ([string]::IsNullOrWhiteSpace($commandLine)) {
            return [pscustomobject]@{ Protection = 'unevaluable'; ImagePath = $imagePath; Reason = 'command line unreadable' }
        }
        $trimmed = $commandLine.Trim()
        $bareToken = $null
        $remainder = $null
        if ($trimmed.StartsWith('"')) {
            $closing = $trimmed.IndexOf('"', 1)
            if ($closing -gt 0) {
                $bareToken = $trimmed.Substring(1, $closing - 1)
                $remainder = $trimmed.Substring($closing + 1)
            }
        }
        else {
            $firstSpace = $trimmed.IndexOf(' ')
            if ($firstSpace -lt 0) {
                $bareToken = $trimmed
                $remainder = ''
            }
            else {
                $bareToken = $trimmed.Substring(0, $firstSpace)
                $remainder = $trimmed.Substring($firstSpace)
            }
        }
        if ($null -eq $bareToken -or -not [string]::IsNullOrWhiteSpace($remainder)) {
            return [pscustomobject]@{ Protection = 'required'; ImagePath = $imagePath; Reason = 'VCTIP was invoked with arguments' }
        }
        if ([IO.Path]::GetFileName($bareToken.Trim()) -notlike 'VCTIP.exe') {
            return [pscustomobject]@{ Protection = 'required'; ImagePath = $imagePath; Reason = 'command line does not name VCTIP' }
        }

        $ambientModulePath = $env:PSModulePath
        try {
            $env:PSModulePath = Join-Path $PSHOME 'Modules'
            $securityManifest = Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
            Import-Module -Name $securityManifest -ErrorAction Stop
            $signature = Get-AuthenticodeSignature -LiteralPath $imagePath -ErrorAction Stop
        }
        finally {
            $env:PSModulePath = $ambientModulePath
        }
        if ($signature.Status.ToString() -cne 'Valid' -or $null -eq $signature.SignerCertificate) {
            return [pscustomobject]@{ Protection = 'required'; ImagePath = $imagePath; Reason = "image signature status $($signature.Status)" }
        }
        if ($signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
            return [pscustomobject]@{ Protection = 'required'; ImagePath = $imagePath; Reason = 'image signer is not Microsoft Corporation' }
        }
        return [pscustomobject]@{ Protection = 'not_required'; ImagePath = $imagePath; Reason = 'Microsoft-signed no-argument MSVC toolset VCTIP telemetry uploader (#539)' }
    }
    catch {
        return [pscustomobject]@{ Protection = 'unevaluable'; ImagePath = $null; Reason = "classification failed: $($_.Exception.Message)" }
    }
}

function Get-AstroLiveAttributedPids {
    # #320 cleanup gate: which recorded attributed tree pids are BOTH still open in the
    # manifest AND alive per the OS, EXCLUDING $SelfPid. A non-empty result means a detached
    # child of the run this manifest describes is still executing, so the run's working tree
    # (target/, its TEMP child, its lock, this manifest) MUST NOT be torn down out from under
    # it. Combining "open interval" with "OS-alive" is precise: the recorder never saw the
    # pid exit AND a process with that pid currently exists -- pid-reuse of a closed interval
    # is excluded by the open-interval filter, an OS-dead open pid is excluded by the probe.
    # #539: LivePids contains only cleanup-protecting processes. A live process classified
    # not_required is reported separately and never stopped. An unevaluable process stays
    # protecting, so failed classification cannot authorize cleanup.
    # Returns { ManifestReadable; LivePids; NonProtecting }.
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][int]$SelfPid
    )

    $parsed = Get-AstroAttributionTreePids -ManifestPath $ManifestPath
    $live = @()
    $nonProtecting = @()
    foreach ($candidate in $parsed.OpenPids) {
        if ($candidate -eq $SelfPid) { continue }
        if (-not (Test-AstroPidAlive -OwnerPid $candidate)) { continue }
        $class = Get-AstroCleanupProtectionClass -OwnerPid $candidate
        if ($class.Protection -eq 'not_required') {
            $nonProtecting += [pscustomobject]@{ Pid = $candidate; ImagePath = $class.ImagePath; Reason = $class.Reason }
        }
        else {
            $live += $candidate
        }
    }
    return [pscustomobject]@{
        ManifestReadable = $parsed.Readable
        LivePids = @($live | Sort-Object -Unique)
        NonProtecting = @($nonProtecting | Sort-Object -Property Pid -Unique)
    }
}

function Clear-DeadAttributionManifests {
    # Startup sweep: remove attribution manifests in $Directory whose embedded PID is a
    # DEAD process, guarded exactly like the #197 dead-PID lock rule -- probe the exact
    # PID first, and NEVER remove a manifest naming a live PID (a concurrent launcher
    # session's manifest is inviolable). $SelfPid (this run's own PID) is always skipped.
    # A manifest whose name carries no readable PID is swept (it can bind to nothing) and
    # reported. Returns { Removed = @(paths); Kept = @(paths); Skipped = @(paths) }.
    param(
        [Parameter(Mandatory)][string]$Directory,
        [int]$SelfPid = $PID
    )

    $removed = @()
    $kept = @()
    $skipped = @()
    if (-not (Test-Path -LiteralPath $Directory)) {
        return [pscustomobject]@{ Removed = $removed; Kept = $kept; Skipped = $skipped }
    }
    $candidates = Get-ChildItem -LiteralPath $Directory -Filter $script:AstroAttributionManifestPattern -File -ErrorAction SilentlyContinue
    foreach ($file in $candidates) {
        $match = [regex]::Match($file.Name, $script:AstroAttributionManifestPidRegex)
        if (-not $match.Success) {
            # No readable PID in the name: it can bind to no live run, so it is stale by
            # construction. Remove it (and any .tmp sibling) and report.
            $removed += @(Remove-AstroAttributionManifest -Path $file.FullName)
            continue
        }
        $ownerPid = [int]$match.Groups['pid'].Value
        if ($ownerPid -eq $SelfPid) {
            $skipped += $file.FullName  # our own run's manifest, never sweep it
            continue
        }
        if (Test-AstroPidAlive -OwnerPid $ownerPid) {
            $kept += $file.FullName     # a live (concurrent) session owns it: inviolable (#197)
            continue
        }
        # #320: the LAUNCHER pid is dead, but a DETACHED child of that run (a different pid --
        # a cargo/rustc/test grandchild that outlived the owner pwsh) may still be executing
        # with its working tree under the sibling TEMP child dir. Removing the manifest now
        # would blind the TEMP-dir reaper (Clear-DeadLauncherTempDirs) to those live children
        # and let it rip a live process's fixtures out mid-run. Keep the manifest -- like the
        # TEMP dir and lock -- until the WHOLE process tree is dead. Probes exact pids only.
        $liveChildren = @((Get-AstroLiveAttributedPids -ManifestPath $file.FullName -SelfPid $SelfPid).LivePids |
            Where-Object { $_ -ne $ownerPid })
        if ($liveChildren.Count -gt 0) {
            $kept += $file.FullName
            continue
        }
        $removed += (Remove-AstroAttributionManifest -Path $file.FullName)
    }
    return [pscustomobject]@{ Removed = $removed; Kept = $kept; Skipped = $skipped }
}
