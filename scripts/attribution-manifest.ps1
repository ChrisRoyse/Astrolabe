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

    Both the launcher and its FSV test (scripts/test-attribution-manifest.ps1, against
    isolated fixture dirs -- never the live .tmp) route through these functions.
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
        $removed += (Remove-AstroAttributionManifest -Path $file.FullName)
    }
    return [pscustomobject]@{ Removed = $removed; Kept = $kept; Skipped = $skipped }
}
