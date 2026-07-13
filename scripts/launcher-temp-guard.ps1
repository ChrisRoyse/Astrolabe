<#
.SYNOPSIS
    Shared, dot-sourceable liveness-gated reaper for the launcher's per-run TEMP child
    directories (.tmp/windows-gnu-toolchain-<pid>) (#320).

.DESCRIPTION
    The launcher confines each run's child TEMP/TMP/TMPDIR to a per-run child directory
    .tmp/windows-gnu-toolchain-<launcher-pid> and, on a normal exit, removes it in its
    finally block. #320: when the owner pwsh dies while a DETACHED cargo/rustc/test
    grandchild it spawned is still executing, the run's finally now DEFERS all cleanup
    (see windows-gnu-toolchain.ps1) so the live child keeps its working tree. This helper
    is the second half of that contract: the NEXT launcher start reaps the leftover TEMP
    child directories, but ONLY once the WHOLE process tree of the owning run is dead.

    Like the launcher-lock (#197/#247) and attribution-manifest (#301) helpers, it NEVER
    stops a process and treats any still-live run as inviolable. It probes exact pids only
    (never a by-name sweep): the TEMP dir's embedded LAUNCHER pid AND -- because the dir is
    named by the launcher pid yet a detached child is a DIFFERENT pid -- the attributed
    child pids recorded in the sibling attribution manifest (Get-AstroLiveAttributedPids,
    from attribution-manifest.ps1). A directory is reaped only when the launcher pid is dead
    AND no attributed child is alive.

    Depends on attribution-manifest.ps1 (Get-AstroLiveAttributedPids, Test-AstroPidAlive);
    both are dot-sourced by the launcher and by the FSV harness before this runs. Resolution
    is late-bound in PowerShell, so dot-source order does not matter as long as both files
    are loaded before Clear-DeadLauncherTempDirs is called.
#>

# .tmp basename shape the launcher writes for each run's TEMP child. One regex is the single
# source of truth for the name<->launcher-pid mapping the reaper depends on.
$script:AstroLauncherTempPidRegex = '^windows-gnu-toolchain-(?<pid>\d+)$'
# Sibling attribution manifest naming (#278/#301), keyed on the SAME launcher pid, so the
# reaper can find a TEMP dir's recorded child pids without re-deriving the schema.
$script:AstroAttributionManifestNameFormat = 'no-escape-attribution-{0}.json'

function Clear-DeadLauncherTempDirs {
    # Startup sweep (#320): remove per-run TEMP child dirs whose owning run is COMPLETELY
    # dead. For each .tmp/windows-gnu-toolchain-<pid>:
    #   * $SelfPid (this run's own dir)                      -> Skipped (never reap our own)
    #   * launcher pid ALIVE (a concurrent session)          -> Kept (inviolable, #197)
    #   * launcher pid dead, a recorded child still ALIVE    -> Kept (the #320 detached-child
    #                                                           hazard: its fixtures live here)
    #   * launcher pid dead, no live child                   -> Removed (safe to reap)
    # A locked/racing removal is caught and reported as Kept, never thrown -- callers run this
    # at startup and in cleanup paths that must not fault. Returns
    # { Removed = @(paths); Kept = @(paths); Skipped = @(paths) }.
    param(
        [Parameter(Mandatory)][string]$Directory,
        [int]$SelfPid = $PID
    )

    $removed = @()
    $kept = @()
    $skipped = @()
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        return [pscustomobject]@{ Removed = $removed; Kept = $kept; Skipped = $skipped }
    }
    $candidates = Get-ChildItem -LiteralPath $Directory -Directory -ErrorAction SilentlyContinue
    foreach ($dir in $candidates) {
        $match = [regex]::Match($dir.Name, $script:AstroLauncherTempPidRegex)
        if (-not $match.Success) {
            continue  # not a launcher TEMP child (e.g. a foreign dir) -- never touch it
        }
        $ownerPid = [int]$match.Groups['pid'].Value
        if ($ownerPid -eq $SelfPid) {
            $skipped += $dir.FullName
            continue
        }
        if (Test-AstroPidAlive -OwnerPid $ownerPid) {
            $kept += $dir.FullName     # a live (concurrent) launcher session owns it (#197)
            continue
        }
        # Launcher pid dead -> require every attributed child to be dead too before reaping,
        # because this dir is named by the launcher pid yet a DETACHED child (a different pid)
        # may still hold a fixture under it (the #320 hazard). The child pids live in the
        # sibling attribution manifest, keyed on the same launcher pid.
        $manifestPath = Join-Path $Directory ([string]::Format($script:AstroAttributionManifestNameFormat, $ownerPid))
        $liveChildren = @()
        if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
            $liveChildren = @((Get-AstroLiveAttributedPids -ManifestPath $manifestPath -SelfPid $SelfPid).LivePids |
                Where-Object { $_ -ne $ownerPid })
        }
        if ($liveChildren.Count -gt 0) {
            $kept += $dir.FullName
            continue
        }
        try {
            Remove-Item -LiteralPath $dir.FullName -Recurse -Force -ErrorAction Stop
            $removed += $dir.FullName
        }
        catch {
            # Locked/racing removal: leave the dir, report it Kept, never throw from a sweep.
            $kept += $dir.FullName
        }
    }
    return [pscustomobject]@{ Removed = $removed; Kept = $kept; Skipped = $skipped }
}
