<#
.SYNOPSIS
    Fixed Task Scheduler action for one exact Astrolabe detached launcher run.

.DESCRIPTION
    Reads one immutable intent/task chain, publishes its exact identity, creates the
    canonical launcher boundary through the retained native spawn helper, proves the live
    v3 launcher lease and parent relationship, waits the exact boundary handle, then
    persists completion and exact task cleanup readback.

.NOTES
    This file is invoked only by scripts/detach-run.ps1. Refs #616.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$earlyRunDirectory = [IO.Path]::GetFullPath($RunDirectory)
if (-not [IO.Directory]::Exists($earlyRunDirectory)) {
    throw "DETACH_RUNNER[ASTRO_DETACH_RUN_DIRECTORY_MISSING]: {code=ASTRO_DETACH_RUN_DIRECTORY_MISSING; message=`"bound run directory is missing: $earlyRunDirectory`"; remediation=`"preserve task state and inspect the immutable action definition`"}"
}
$env:TEMP = $earlyRunDirectory
$env:TMP = $earlyRunDirectory
$env:TMPDIR = $earlyRunDirectory

$protocolPath = Join-Path $PSScriptRoot 'detach-protocol.ps1'
$spawnPath = Join-Path $PSScriptRoot 'detach-spawn.ps1'
. $protocolPath
. $spawnPath

$run = Assert-AstroDetachedRunDirectory $RunDirectory
$logPath = Join-Path $run 'launcher.log'
$chain = $null
$lease = $null
$taskService = $null
$taskName = $null
$taskXmlSha256 = $null
$taskCleanupAttempted = $false
$terminalWritten = $false
$exitCode = 70

function Get-DetachedFileEvidence {
    param([Parameter(Mandatory)][string]$Path)

    $snapshot = Read-AstroDetachedOrdinaryFile $Path
    return [ordered]@{
        path = $snapshot.Path
        sha256 = $snapshot.Sha256
        bytes = $snapshot.Length
    }
}

function Get-DetachedPathAbsence {
    param([Parameter(Mandatory)][string]$Path)

    return [ordered]@{
        path = [IO.Path]::GetFullPath($Path)
        file_exists = [IO.File]::Exists($Path)
        directory_exists = [IO.Directory]::Exists($Path)
    }
}

try {
    $intent = Read-AstroDetachedRecord `
        -RunDirectory $run `
        -Name '000-intent.json' `
        -ExpectedSchema 'astrolabe.detached.intent.v1' `
        -ExpectedSequence 0
    $taskRecord = Read-AstroDetachedRecord `
        -RunDirectory $run `
        -Name '001-task.json' `
        -ExpectedSchema 'astrolabe.detached.task.v1' `
        -ExpectedSequence 1
    Assert-AstroDetachedRecordLink $intent $taskRecord
    $chain = $taskRecord

    $intentPayload = $intent.Payload
    $taskPayload = $taskRecord.Payload
    if ([int]$intentPayload.issue -le 0 -or
        [string]$intentPayload.run_id -cne [IO.Path]::GetFileName($run) -or
        [string]$intentPayload.repository_root -cne $script:AstroDetachedCanonicalRoot) {
        throw 'intent issue/run/root binding is invalid'
    }
    $taskName = [string]$intentPayload.task_name
    $taskXmlSha256 = [string]$taskPayload.task.xml_sha256

    foreach ($binding in @(
            @{ Path = $protocolPath; Expected = [string]$intentPayload.protocol_sha256 },
            @{ Path = $spawnPath; Expected = [string]$intentPayload.spawn_sha256 },
            @{ Path = $PSCommandPath; Expected = [string]$intentPayload.runner_sha256 },
            @{
                Path = Join-Path $PSScriptRoot 'windows-gnu-toolchain.ps1'
                Expected = [string]$intentPayload.launcher_sha256
            }
        )) {
        $actual = (Get-FileHash -LiteralPath $binding.Path -Algorithm SHA256).Hash.
            ToLowerInvariant()
        if ($actual -cne $binding.Expected) {
            throw "bound script hash changed before detached runner execution: $($binding.Path) expected=$($binding.Expected) observed=$actual"
        }
    }

    $taskService = Get-AstroDetachedTaskService
    $liveTask = Get-AstroDetachedRegisteredTask `
        -TaskService $taskService `
        -TaskName $taskName
    $liveTaskSnapshot = Get-AstroDetachedTaskSnapshot $liveTask
    if ($liveTaskSnapshot.xml_sha256 -cne $taskXmlSha256) {
        throw "registered task XML differs from the immutable task record before runner acceptance"
    }

    $runnerIdentity = Get-AstroDetachedCurrentIdentity
    $runnerRecord = Write-AstroDetachedRecord `
        -RunDirectory $run `
        -Name '002-runner.json' `
        -Schema 'astrolabe.detached.runner.v1' `
        -Sequence 2 `
        -PreviousName $chain.Name `
        -PreviousSha256 $chain.Sha256 `
        -Payload ([ordered]@{
            identity = $runnerIdentity
            role = 'task-runner'
            task_name = $taskName
            task_xml_sha256 = $taskXmlSha256
            task_session_id = $runnerIdentity.session_id
            task_logon_type = [string]$intentPayload.task_logon_type
        })
    $chain = Read-AstroDetachedRecord `
        -RunDirectory $run `
        -Name $runnerRecord.Name `
        -ExpectedSchema 'astrolabe.detached.runner.v1' `
        -ExpectedSequence 2
    Assert-AstroDetachedRecordLink $taskRecord $chain

    $launcherPath = [string]$intentPayload.launcher_path
    $launcherArguments = @(
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $launcherPath,
        '-Issue',
        ([string]$intentPayload.issue)
    )
    if ([string]$intentPayload.command_mode -ceq 'single') {
        $launcherArguments += @(
            '-Command',
            [string]$intentPayload.command,
            '-CommandArgsJson',
            [string]$intentPayload.command_args_json
        )
    }
    elseif ([string]$intentPayload.command_mode -ceq 'batch') {
        $launcherArguments += @(
            '-BatchCommandsJson',
            [string]$intentPayload.batch_commands_json
        )
    }
    else {
        throw "unsupported detached command mode '$($intentPayload.command_mode)'"
    }

    $lease = Start-AstroDetachedProcessRetained `
        -FilePath ([string]$intentPayload.powershell_path) `
        -ArgumentList ([string[]]$launcherArguments) `
        -LogFile $logPath `
        -WorkingDirectory $script:AstroDetachedCanonicalRoot
    $boundaryRecord = Write-AstroDetachedRecord `
        -RunDirectory $run `
        -Name '003-boundary.json' `
        -Schema 'astrolabe.detached.boundary.v1' `
        -Sequence 3 `
        -PreviousName $chain.Name `
        -PreviousSha256 $chain.Sha256 `
        -Payload ([ordered]@{
            identity = [ordered]@{
                pid = [int]$lease.ProcessId
                process_start_utc_ticks = [long]$lease.ProcessStartUtcTicks
                process_started_utc = [string]$lease.ProcessStartedUtc
                session_id = [int]$lease.SessionId
            }
            role = 'launcher-boundary'
            application_path = [string]$lease.ApplicationPath
            command_line = [string]$lease.CommandLine
            log_path = $logPath
        })
    $chain = Read-AstroDetachedRecord `
        -RunDirectory $run `
        -Name $boundaryRecord.Name `
        -ExpectedSchema 'astrolabe.detached.boundary.v1' `
        -ExpectedSequence 3

    $lockPath = Join-Path `
        (Join-Path $script:AstroDetachedCanonicalRoot '.tmp') `
        'astrolabe-launcher.lock'
    $deadline = [DateTime]::UtcNow.AddSeconds(
        [int]$intentPayload.launcher_lease_wait_seconds
    )
    $lock = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $lock = Read-AstroLauncherLock $lockPath
        if ($lock.State -ceq 'held') {
            break
        }
        if ($lock.State -notin @('absent', 'transition', 'held')) {
            throw "authoritative launcher lock entered preserving state '$($lock.State)' during readiness"
        }
        Start-Sleep -Milliseconds 100
    }
    if ($null -eq $lock -or $lock.State -cne 'held') {
        $observed = if ($null -eq $lock) { 'not-read' } else { $lock.State }
        throw "DETACH_RUNNER[ASTRO_DETACH_LEASE_TIMEOUT]: {code=ASTRO_DETACH_LEASE_TIMEOUT; message=`"authoritative held launcher lease was not observed within $($intentPayload.launcher_lease_wait_seconds) seconds; final_state=$observed`"; remediation=`"preserve this run; inspect launcher.log, exact child identity, and canonical protocol state`"}"
    }
    if ([int]$lock.Issue -ne [int]$intentPayload.issue) {
        throw "authoritative held launcher issue differs from immutable intent: expected=$($intentPayload.issue) observed=$($lock.Issue)"
    }

    $ownerProcess = Get-Process -Id ([int]$lock.OwnerPid) -ErrorAction Stop
    $ownerSession = [int]$ownerProcess.SessionId
    $ownerProbe = Get-AstroDetachedProcessProbe `
        -ProcessId ([int]$lock.OwnerPid) `
        -ProcessStartUtcTicks ([long]$lock.OwnerProcessStartUtcTicks) `
        -SessionId $ownerSession
    if ($ownerProbe.state -cne 'exact-live') {
        throw "authoritative launcher owner is not exact-live: $($ownerProbe.state)"
    }
    $ownerParent = Get-AstroDetachedParentIdentity `
        -ChildProcessId ([int]$lock.OwnerPid) `
        -ChildProcessStartUtcTicks ([long]$lock.OwnerProcessStartUtcTicks) `
        -ChildSessionId $ownerSession
    if ([int]$ownerParent.pid -ne [int]$lease.ProcessId -or
        [long]$ownerParent.process_start_utc_ticks -ne
            [long]$lease.ProcessStartUtcTicks -or
        [int]$ownerParent.session_id -ne [int]$lease.SessionId) {
        throw "authoritative launcher owner parent is not the exact retained boundary process"
    }

    $workRecord = Write-AstroDetachedRecord `
        -RunDirectory $run `
        -Name '004-work.json' `
        -Schema 'astrolabe.detached.work.v1' `
        -Sequence 4 `
        -PreviousName $chain.Name `
        -PreviousSha256 $chain.Sha256 `
        -Payload ([ordered]@{
            identity = [ordered]@{
                pid = [int]$lock.OwnerPid
                process_start_utc_ticks = [long]$lock.OwnerProcessStartUtcTicks
                process_started_utc = [string]$lock.OwnerProcessStarted
                session_id = $ownerSession
            }
            role = 'authoritative-launcher-owner'
            exact_parent_identity = $ownerParent
            boundary_identity = $boundaryRecord.Payload.identity
            issue = [int]$lock.Issue
        })
    $chain = Read-AstroDetachedRecord `
        -RunDirectory $run `
        -Name $workRecord.Name `
        -ExpectedSchema 'astrolabe.detached.work.v1' `
        -ExpectedSequence 4

    $lockBytes = Get-AstroDetachedUtf8Bytes ([string]$lock.RawJson)
    $leaseRecord = Write-AstroDetachedRecord `
        -RunDirectory $run `
        -Name '005-launcher-lease.json' `
        -Schema 'astrolabe.detached.launcher-lease.v1' `
        -Sequence 5 `
        -PreviousName $chain.Name `
        -PreviousSha256 $chain.Sha256 `
        -Payload ([ordered]@{
            lock_path = $lockPath
            lock_state = [string]$lock.State
            lock_schema = [string]$lock.Schema
            lock_sha256 = [string]$lock.Sha256
            lock_bytes = [long]$lock.Length
            lock_json_sha256 = Get-AstroDetachedSha256Bytes $lockBytes
            lock_json_base64 = [Convert]::ToBase64String($lockBytes)
            issue = [int]$lock.Issue
            owner_identity = $workRecord.Payload.identity
            protocol_authority_path = [string]$lock.ProtocolAuthorityPath
            protocol_authority_sha256 = [string]$lock.ProtocolAuthoritySha256
            workspace_root = [string]$lock.WorkspaceRoot
        })
    $chain = Read-AstroDetachedRecord `
        -RunDirectory $run `
        -Name $leaseRecord.Name `
        -ExpectedSchema 'astrolabe.detached.launcher-lease.v1' `
        -ExpectedSequence 5

    $exitCode = [int]$lease.Wait()
    $lease.Dispose()
    $lease = $null

    $finalLock = Read-AstroLauncherLock $lockPath
    $boundaryProbe = Get-AstroDetachedProcessProbe `
        -ProcessId ([int]$boundaryRecord.Payload.identity.pid) `
        -ProcessStartUtcTicks (
            [long]$boundaryRecord.Payload.identity.process_start_utc_ticks
        ) `
        -SessionId ([int]$boundaryRecord.Payload.identity.session_id)
    $workProbe = Get-AstroDetachedProcessProbe `
        -ProcessId ([int]$workRecord.Payload.identity.pid) `
        -ProcessStartUtcTicks (
            [long]$workRecord.Payload.identity.process_start_utc_ticks
        ) `
        -SessionId ([int]$workRecord.Payload.identity.session_id)
    $targetState = Get-DetachedPathAbsence (
        Join-Path $script:AstroDetachedCanonicalRoot 'target'
    )
    $calyxTargetState = Get-DetachedPathAbsence (
        Join-Path (Join-Path $script:AstroDetachedCanonicalRoot 'calyx') 'target'
    )
    if ($finalLock.State -cne 'absent' -or
        $targetState.file_exists -or
        $targetState.directory_exists -or
        $calyxTargetState.file_exists -or
        $calyxTargetState.directory_exists -or
        $boundaryProbe.state -notin @('absent', 'exact-exited') -or
        $workProbe.state -notin @('absent', 'exact-exited', 'reused')) {
        throw "terminal launcher state is not clean/exact after retained boundary wait: lock=$($finalLock.State) boundary=$($boundaryProbe.state) work=$($workProbe.state)"
    }
    $logEvidence = Get-DetachedFileEvidence $logPath
    $completionRecord = Write-AstroDetachedRecord `
        -RunDirectory $run `
        -Name '006-completion.json' `
        -Schema 'astrolabe.detached.completion.v1' `
        -Sequence 6 `
        -PreviousName $chain.Name `
        -PreviousSha256 $chain.Sha256 `
        -Payload ([ordered]@{
            outcome = if ($exitCode -eq 0) { 'success' } else { 'child-nonzero' }
            child_exit_code = $exitCode
            boundary_probe = $boundaryProbe
            work_probe = $workProbe
            launcher_lock_state = [string]$finalLock.State
            canonical_target = $targetState
            calyx_target = $calyxTargetState
            launcher_log = $logEvidence
        })
    $chain = Read-AstroDetachedRecord `
        -RunDirectory $run `
        -Name $completionRecord.Name `
        -ExpectedSchema 'astrolabe.detached.completion.v1' `
        -ExpectedSequence 6
    $terminalWritten = $true

    $taskCleanupAttempted = $true
    $removedTask = Remove-AstroDetachedTaskExact `
        -TaskService $taskService `
        -TaskName $taskName `
        -ExpectedXmlSha256 $taskXmlSha256
    $cleanupRecord = Write-AstroDetachedRecord `
        -RunDirectory $run `
        -Name '007-cleanup.json' `
        -Schema 'astrolabe.detached.cleanup.v1' `
        -Sequence 7 `
        -PreviousName $chain.Name `
        -PreviousSha256 $chain.Sha256 `
        -Payload ([ordered]@{
            task_name = $taskName
            task_xml_sha256 = [string]$removedTask.xml_sha256
            task_absent = $true
            runner_identity = $runnerIdentity
            protocol_artifacts_preserved = $true
        })
    [void](Read-AstroDetachedRecord `
        -RunDirectory $run `
        -Name $cleanupRecord.Name `
        -ExpectedSchema 'astrolabe.detached.cleanup.v1' `
        -ExpectedSequence 7)
}
catch {
    $faultMessage = $_.Exception.Message
    if ($null -ne $lease) {
        try {
            $waitedExit = [int]$lease.Wait()
            $lease.Dispose()
            $lease = $null
            $faultMessage += " | retained launcher boundary later exited $waitedExit"
        }
        catch {
            $faultMessage += " | retained launcher boundary wait failed: $($_.Exception.Message)"
        }
    }
    try {
        ("DETACH_RUNNER_FAULT: " + $faultMessage) |
            Out-File -LiteralPath $logPath -Append -Encoding utf8
    }
    catch {
        # The durable fault record below is authoritative; log append failure is included there.
        $faultMessage += " | launcher.log append also failed: $($_.Exception.Message)"
    }
    try {
        if ($null -ne $chain) {
            $faultSequence = [int]$chain.Sequence + 1
            $faultName = '{0:d3}-fault.json' -f $faultSequence
            $fault = Write-AstroDetachedRecord `
                -RunDirectory $run `
                -Name $faultName `
                -Schema 'astrolabe.detached.fault.v1' `
                -Sequence $faultSequence `
                -PreviousName $chain.Name `
                -PreviousSha256 $chain.Sha256 `
                -Payload ([ordered]@{
                    code = 'ASTRO_DETACH_RUNNER_FAULT'
                    message = $faultMessage
                    remediation =
                        'preserve this run directory and inspect every exact record, launcher.log, task, and canonical launcher state'
                    terminal_record_previously_written = $terminalWritten
                    task_cleanup_attempted = [bool]$taskCleanupAttempted
                    task_cleanup_retried = $false
                })
            $chain = Read-AstroDetachedRecord `
                -RunDirectory $run `
                -Name $fault.Name `
                -ExpectedSchema 'astrolabe.detached.fault.v1' `
                -ExpectedSequence $faultSequence
        }
    }
    catch {
        try {
            ("DETACH_RUNNER_RECORD_FAULT: " + $_.Exception.Message) |
                Out-File -LiteralPath $logPath -Append -Encoding utf8
        }
        catch {
            Write-Error (
                'DETACH_RUNNER_FATAL_RECORD_AND_LOG_FAULT: ' +
                $_.Exception.Message
            )
        }
    }
    if ($null -ne $taskService -and
        -not [string]::IsNullOrWhiteSpace($taskName) -and
        $taskXmlSha256 -cmatch '^[0-9a-f]{64}$' -and
        -not $taskCleanupAttempted) {
        try {
            $registered = Get-AstroDetachedRegisteredTask `
                -TaskService $taskService `
                -TaskName $taskName `
                -AllowAbsent
            if ($null -ne $registered) {
                $taskCleanupAttempted = $true
                [void](Remove-AstroDetachedTaskExact `
                    -TaskService $taskService `
                    -TaskName $taskName `
                    -ExpectedXmlSha256 $taskXmlSha256)
            }
            if ($null -ne $chain) {
                $cleanupSequence = [int]$chain.Sequence + 1
                $cleanupName = '{0:d3}-cleanup.json' -f $cleanupSequence
                [void](Write-AstroDetachedRecord `
                    -RunDirectory $run `
                    -Name $cleanupName `
                    -Schema 'astrolabe.detached.cleanup.v1' `
                    -Sequence $cleanupSequence `
                    -PreviousName $chain.Name `
                    -PreviousSha256 $chain.Sha256 `
                    -Payload ([ordered]@{
                        task_name = $taskName
                        task_xml_sha256 = $taskXmlSha256
                        task_absent = $true
                        cleanup_after_fault = $true
                        protocol_artifacts_preserved = $true
                    }))
            }
        }
        catch {
            $cleanupFaultMessage = $_.Exception.Message
            try {
                if ($null -ne $chain) {
                    $cleanupFaultSequence = [int]$chain.Sequence + 1
                    $cleanupFaultName =
                        '{0:d3}-cleanup-fault.json' -f $cleanupFaultSequence
                    [void](Write-AstroDetachedRecord `
                        -RunDirectory $run `
                        -Name $cleanupFaultName `
                        -Schema 'astrolabe.detached.fault.v1' `
                        -Sequence $cleanupFaultSequence `
                        -PreviousName $chain.Name `
                        -PreviousSha256 $chain.Sha256 `
                        -Payload ([ordered]@{
                            code = 'ASTRO_DETACH_TASK_CLEANUP_FAULT'
                            message = $cleanupFaultMessage
                            remediation =
                                'preserve the unchanged task and run directory; inspect exact XML/process state before any recovery'
                            task_cleanup_attempted = $taskCleanupAttempted
                            task_cleanup_retried = $false
                        }))
                }
                else {
                    throw 'no validated predecessor exists for cleanup-fault record'
                }
            }
            catch {
                try {
                    (
                        'DETACH_RUNNER_CLEANUP_AND_RECORD_FAULT: ' +
                        $cleanupFaultMessage +
                        ' | record failure: ' +
                        $_.Exception.Message
                    ) | Out-File -LiteralPath $logPath -Append -Encoding utf8
                }
                catch {
                    Write-Error (
                        'DETACH_RUNNER_FATAL_CLEANUP_RECORD_LOG_FAULT: ' +
                        $_.Exception.Message
                    )
                }
            }
        }
    }
    $exitCode = 70
}
finally {
    if ($null -ne $lease) {
        $lease.Dispose()
    }
}

exit $exitCode
