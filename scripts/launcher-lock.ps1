<#
.SYNOPSIS
    Shared, dot-sourceable launcher session-lock semantics (#197, #247).

.DESCRIPTION
    The single audited place that reads the launcher session lock and decides whether a
    workspace is claimable. It is the process-lifecycle analog of the #237 no-escape gate:
    containment by construction, not convention.

    Critically, it NEVER stops a process. A live *foreign* lock owner is REFUSED with a named
    fail-closed boundary (the caller waits for the lock to release) -- never killed, and never
    via a host-wide by-name sweep. The only process inspection is `Get-Process -Id <ownerPid>`
    for a liveness probe of the exact recorded PID. This is what makes it safe under the
    multi-session lock discipline (#197): a session's cleanup can never stomp another live
    session's PIDs, because this code path has no capability to stop any PID at all.

    Both the launcher (against the workspace lock) and its tests (against isolated fixture
    locks, never the live workspace -- #197) route through these functions.
#>

function Read-AstroLauncherLock {
    # Classify a launcher lock file without mutating anything or stopping any process.
    # Returns { State = absent|stale|held|unreadable; OwnerPid; Command; Started }.
    #   absent     -- no lock file
    #   unreadable -- present but names no positive-integer pid (fail-closed, #186/#197)
    #   held       -- names a pid that is a LIVE process (a foreign session owns it)
    #   stale      -- names a pid that is no longer a live process
    param([Parameter(Mandatory)][string]$LockPath)

    if (-not (Test-Path -LiteralPath $LockPath)) {
        return [pscustomobject]@{ State = 'absent'; OwnerPid = $null; Command = $null; Started = $null }
    }

    $raw = Get-Content -LiteralPath $LockPath -Raw -ErrorAction SilentlyContinue
    $state = $null
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
        try { $state = ConvertFrom-Json -InputObject $raw } catch { $state = $null }
    }

    # Fail-closed schema validation: the pid must parse as a positive integer. A malformed pid
    # (clobbered or truncated manifest) surfaces as the named UNREADABLE boundary, never as an
    # unnamed cast exception.
    $ownerPid = $null
    if ($null -ne $state -and $state.PSObject.Properties['pid']) {
        $parsed = 0
        if ([int]::TryParse([string]$state.pid, [ref]$parsed) -and $parsed -gt 0) {
            $ownerPid = $parsed
        }
    }
    if ($null -eq $ownerPid) {
        return [pscustomobject]@{ State = 'unreadable'; OwnerPid = $null; Command = $null; Started = $null }
    }

    $command = if ($state.PSObject.Properties['command']) { $state.command } else { 'unknown' }
    $started = if ($state.PSObject.Properties['started']) { $state.started } else { 'unknown' }
    # Liveness probe of the EXACT recorded pid only -- never a by-name sweep.
    $holder = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
    $liveState = if ($null -ne $holder) { 'held' } else { 'stale' }
    return [pscustomobject]@{ State = $liveState; OwnerPid = $ownerPid; Command = $command; Started = $started }
}

function Assert-AstroLauncherLockClaimable {
    # Decide whether the workspace is claimable, fail-closed. Behaviour:
    #   absent     -> return (claimable)
    #   unreadable -> throw ASTRO_LAUNCHER_LOCK_UNREADABLE (never guess; operator removes it)
    #   held       -> throw ASTRO_LAUNCHER_LOCK_HELD (a LIVE foreign session; NEVER stop it)
    #   stale      -> remove the dead-pid lock and return (claimable)
    # It never stops a process under any branch.
    param([Parameter(Mandatory)][string]$LockPath)

    $lock = Read-AstroLauncherLock -LockPath $LockPath
    switch ($lock.State) {
        'absent' { return }
        'unreadable' {
            throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_UNREADABLE]: launcher lock exists but names no readable pid; verify no toolchain session is live, then remove it manually: $LockPath"
        }
        'held' {
            throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_HELD]: another launcher session owns this workspace (pid=$($lock.OwnerPid), started=$($lock.Started), command=$($lock.Command)); never stop or clean a live session's run - wait for the lock to release: $LockPath"
        }
        'stale' {
            Write-Output "LAUNCHER_LOCK[ASTRO_LAUNCHER_LOCK_STALE]: removing lock left by dead pid $($lock.OwnerPid)"
            Remove-Item -LiteralPath $LockPath -Force
            return
        }
        default {
            throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_UNREADABLE]: launcher lock classified as unexpected state '$($lock.State)': $LockPath"
        }
    }
}
