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
    # Returns { State = absent|stale|held|unreadable; OwnerPid; Issue; Command; Started }.
    #   absent     -- no lock file
    #   unreadable -- present but violates the required owner schema (fail-closed, #186/#197/#317)
    #   held       -- names a pid that is a LIVE process (a foreign session owns it)
    #   stale      -- names a pid that is no longer a live process
    param([Parameter(Mandatory)][string]$LockPath)

    if (-not (Test-Path -LiteralPath $LockPath)) {
        return [pscustomobject]@{ State = 'absent'; OwnerPid = $null; Issue = $null; Command = $null; Started = $null }
    }

    $raw = Get-Content -LiteralPath $LockPath -Raw -ErrorAction SilentlyContinue
    $state = $null
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
        try { $state = ConvertFrom-Json -InputObject $raw } catch { $state = $null }
    }

    # Fail-closed schema validation: PID and driving issue are positive integers,
    # start time is an ISO timestamp, and command is non-empty. A clobbered,
    # truncated, or legacy ownerless manifest is unreadable, never guessed.
    $ownerPid = $null
    if ($null -ne $state -and $state.PSObject.Properties['pid']) {
        $parsed = 0
        if ([int]::TryParse([string]$state.pid, [ref]$parsed) -and $parsed -gt 0) {
            $ownerPid = $parsed
        }
    }
    $issue = $null
    if ($null -ne $state -and $state.PSObject.Properties['issue']) {
        $parsedIssue = 0
        if ([int]::TryParse([string]$state.issue, [ref]$parsedIssue) -and $parsedIssue -gt 0) {
            $issue = $parsedIssue
        }
    }
    $command = if ($null -ne $state -and $state.PSObject.Properties['command']) { [string]$state.command } else { $null }
    $started = if ($null -ne $state -and $state.PSObject.Properties['started']) { [string]$state.started } else { $null }
    $parsedStarted = [DateTimeOffset]::MinValue
    $startedIsValid = -not [string]::IsNullOrWhiteSpace($started) -and
        [DateTimeOffset]::TryParse($started, [ref]$parsedStarted)
    if ($null -eq $ownerPid -or $null -eq $issue -or
        [string]::IsNullOrWhiteSpace($command) -or -not $startedIsValid) {
        return [pscustomobject]@{ State = 'unreadable'; OwnerPid = $ownerPid; Issue = $issue; Command = $command; Started = $started }
    }
    # Liveness probe of the EXACT recorded pid only -- never a by-name sweep.
    $holder = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
    $liveState = if ($null -ne $holder) { 'held' } else { 'stale' }
    return [pscustomobject]@{ State = $liveState; OwnerPid = $ownerPid; Issue = $issue; Command = $command; Started = $started }
}

function Assert-AstroLauncherLockClaimable {
    # Decide whether the workspace is claimable, fail-closed. Behaviour:
    #   absent     -> return (claimable)
    #   unreadable -> refuse with the named UNREADABLE boundary (never guess; operator removes it)
    #   held       -> refuse with the named HELD boundary (a LIVE foreign session; NEVER stop it)
    #   stale      -> remove the dead-pid lock and return (claimable)
    # It never stops a process under any branch.
    param([Parameter(Mandatory)][string]$LockPath)

    $lock = Read-AstroLauncherLock -LockPath $LockPath
    switch ($lock.State) {
        'absent' { return }
        'unreadable' {
            throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_UNREADABLE]: launcher lock schema is unreadable (required: positive pid, positive issue, ISO started, non-empty command); verify no toolchain session is live, post PID-probe evidence to the owning issue when identifiable, then remove it manually: $LockPath"
        }
        'held' {
            throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_HELD]: another launcher session owns this workspace (pid=$($lock.OwnerPid), issue=#$($lock.Issue), started=$($lock.Started), command=$($lock.Command)); never stop or clean a live session's run - wait for the lock to release: $LockPath"
        }
        'stale' {
            Write-Output "LAUNCHER_LOCK[ASTRO_LAUNCHER_LOCK_STALE]: removing lock for issue #$($lock.Issue) left by dead pid $($lock.OwnerPid)"
            Remove-Item -LiteralPath $LockPath -Force
            return
        }
        default {
            throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_UNREADABLE]: launcher lock classified as unexpected state '$($lock.State)': $LockPath"
        }
    }
}
