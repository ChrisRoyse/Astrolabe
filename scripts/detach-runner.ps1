<#
.SYNOPSIS
    Fixed Task Scheduler action for one exact Astrolabe detached launcher run.

.DESCRIPTION
    Reads one immutable intent/task chain, publishes its exact identity, creates the
    canonical launcher boundary through the retained native spawn helper, proves the live
    v3 launcher lease and parent relationship, waits the exact boundary handle, then
    persists completion and exact task cleanup readback.

.NOTES
    This file is invoked only by scripts/detach-run.ps1. Refs #616, #1065.
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
$protocolPath = Join-Path $PSScriptRoot 'detach-protocol.ps1'
$strictJsonPath = Join-Path $PSScriptRoot 'detach-strict-json.ps1'
$compilerStatePath = Join-Path $PSScriptRoot 'detach-compiler-state.ps1'
$lockHelperPath = Join-Path $PSScriptRoot 'launcher-lock.ps1'
$spawnPath = Join-Path $PSScriptRoot 'detach-spawn.ps1'
. $protocolPath
$modulePathPolicy = Initialize-AstroDetachedPowerShellModulePath `
    -Role 'runner'
. $compilerStatePath

$run = Assert-AstroDetachedRunDirectory $RunDirectory
$logPath = Join-Path $run 'launcher.log'
$chain = $null
$lease = $null
$taskService = $null
$taskName = $null
$taskXmlSha256 = $null
$taskCleanupAttempted = $false
$taskPreservationRequired = $false
$terminalWritten = $false
$priorityPolicy = $null
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
    $priorityPolicy = Resolve-AstroDetachedPriorityPolicy -Name 'production'
    try {
        $intentPriority = $intentPayload.PSObject.Properties['priority_policy']
        $taskPriority = $taskPayload.PSObject.Properties['priority_policy']
        if ($null -eq $intentPriority -or $null -eq $taskPriority) {
            throw "priority policy is missing from intent or task record"
        }
        Assert-AstroDetachedPriorityPolicyBinding `
            -Candidate $intentPriority.Value `
            -Expected $priorityPolicy `
            -Context 'intent'
        Assert-AstroDetachedPriorityPolicyBinding `
            -Candidate $taskPriority.Value `
            -Expected $priorityPolicy `
            -Context 'task record'
    }
    catch {
        $taskPreservationRequired = $true
        throw "DETACH_RUNNER[ASTRO_DETACH_PRIORITY_BINDING_INVALID]: {code=ASTRO_DETACH_PRIORITY_BINDING_INVALID; message=`"$($_.Exception.Message)`"; remediation=`"preserve task/run/process state and inspect the immutable chain; never infer or substitute priority`"}"
    }
    $taskName = [string]$intentPayload.task_name
    $taskXmlSha256 = [string]$taskPayload.task.xml_sha256
    $runnerIdentity = Get-AstroDetachedCurrentIdentity
    if ($runnerIdentity.priority_class -cne
            [string]$priorityPolicy.process_priority_class -or
        $runnerIdentity.base_priority -ne
            [int]$priorityPolicy.process_base_priority) {
        $taskPreservationRequired = $true
        throw "DETACH_RUNNER[ASTRO_DETACH_RUNNER_PRIORITY_MISMATCH]: {code=ASTRO_DETACH_RUNNER_PRIORITY_MISMATCH; message=`"task runner priority differs from the immutable policy: expected=$($priorityPolicy.process_priority_class)/$($priorityPolicy.process_base_priority) observed=$($runnerIdentity.priority_class)/$($runnerIdentity.base_priority)`"; remediation=`"preserve task/run/process state and inspect Task Scheduler policy inheritance; do not reprioritize the live generation`"}"
    }
    $bootstrapStart = Read-AstroDetachedBootstrapRecord `
        -RunDirectory $run `
        -Name 'bootstrap-start.json'
    $bootstrapValues = $bootstrapStart.Values
    $bootstrapSnapshot = Read-AstroDetachedOrdinaryFile (
        [string]$intentPayload.bootstrap_path
    )
    $powershellSnapshot = Read-AstroDetachedOrdinaryFile (
        [string]$intentPayload.powershell_path
    )
    $runnerSnapshot = Read-AstroDetachedOrdinaryFile $PSCommandPath
    if ($bootstrapValues.bootstrap_path -cne
            [string]$intentPayload.bootstrap_path -or
        $bootstrapValues.bootstrap_sha256 -cne
            [string]$intentPayload.bootstrap_sha256 -or
        $bootstrapValues.bootstrap_bytes -ne
            [long]$intentPayload.bootstrap_bytes -or
        $bootstrapSnapshot.Sha256 -cne
            [string]$intentPayload.bootstrap_sha256 -or
        $bootstrapSnapshot.Length -ne [long]$intentPayload.bootstrap_bytes -or
        $powershellSnapshot.Sha256 -cne
            [string]$intentPayload.powershell_sha256 -or
        $bootstrapValues.powershell_path -cne
            [string]$intentPayload.powershell_path -or
        $bootstrapValues.powershell_sha256 -cne
            [string]$intentPayload.powershell_sha256 -or
        $runnerSnapshot.Sha256 -cne [string]$intentPayload.runner_sha256 -or
        $bootstrapValues.runner_path -cne $PSCommandPath -or
        $bootstrapValues.runner_sha256 -cne
            [string]$intentPayload.runner_sha256 -or
        $bootstrapValues.working_directory -cne
            $script:AstroDetachedCanonicalRoot -or
        $bootstrapValues.creation_flags -ne 134743552 -or
        $bootstrapValues.startup_show_window -ne 0 -or
        $bootstrapValues.runner_log_path -cne
            (Join-Path $run 'bootstrap-runner.log') -or
        [string]$taskPayload.task.action_path -cne
            [string]$intentPayload.bootstrap_path -or
        [string]$taskPayload.task.action_arguments -cne
            [string]$intentPayload.bootstrap_action_arguments -or
        [bool]$taskPayload.task.hidden) {
        throw "DETACH_RUNNER[ASTRO_DETACH_BOOTSTRAP_BINDING_INVALID]: {code=ASTRO_DETACH_BOOTSTRAP_BINDING_INVALID; message=`"bootstrap start/artifact/task bindings do not equal the immutable intent and physical bytes`"; remediation=`"preserve the task/run/process and inspect the first mismatching path, hash, size, flag, or setting`"}"
    }
    $bootstrapProbe = Get-AstroDetachedProcessProbe `
        -ProcessId ([int]$bootstrapValues.bootstrap_pid) `
        -ProcessStartUtcTicks (
            [long]$bootstrapValues.bootstrap_start_utc_ticks
        ) `
        -SessionId ([int]$bootstrapValues.bootstrap_session_id) `
        -ExpectedPriorityClass (
            [string]$priorityPolicy.process_priority_class
        ) `
        -ExpectedBasePriority ([int]$priorityPolicy.process_base_priority)
    if ($bootstrapProbe.state -cne 'exact-live') {
        if ($bootstrapProbe.state -ceq 'priority-mismatch') {
            $taskPreservationRequired = $true
        }
        throw "DETACH_RUNNER[ASTRO_DETACH_BOOTSTRAP_NOT_LIVE]: {code=ASTRO_DETACH_BOOTSTRAP_NOT_LIVE; message=`"bootstrap is not exact-live during runner admission: $($bootstrapProbe.state)`"; remediation=`"preserve the run/task bytes and inspect process ancestry without restarting`"}"
    }
    $runnerParent = Get-AstroDetachedParentIdentity `
        -ChildProcessId ([int]$runnerIdentity.pid) `
        -ChildProcessStartUtcTicks (
            [long]$runnerIdentity.process_start_utc_ticks
        ) `
        -ChildSessionId ([int]$runnerIdentity.session_id)
    if ($runnerParent.pid -ne [int]$bootstrapValues.bootstrap_pid -or
        $runnerParent.process_start_utc_ticks -ne
            [long]$bootstrapValues.bootstrap_start_utc_ticks -or
        $runnerParent.session_id -ne
            [int]$bootstrapValues.bootstrap_session_id) {
        throw "DETACH_RUNNER[ASTRO_DETACH_BOOTSTRAP_PARENT_INVALID]: {code=ASTRO_DETACH_BOOTSTRAP_PARENT_INVALID; message=`"runner parent is not the exact bootstrap generation`"; remediation=`"preserve every byte and inspect the recorded exact process tree; do not accept the runner`"}"
    }

    foreach ($binding in @(
            @{ Path = $protocolPath; Expected = [string]$intentPayload.protocol_sha256 },
            @{ Path = $strictJsonPath; Expected = [string]$intentPayload.strict_json_sha256 },
            @{ Path = $compilerStatePath; Expected = [string]$intentPayload.compiler_state_sha256 },
            @{ Path = $lockHelperPath; Expected = [string]$intentPayload.launcher_lock_sha256 },
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

    $compilerState = $null
    $compilerEvidence = $null
    try {
        $compilerState = Start-AstroDetachedCompilerScope `
            -RunDirectory $run `
            -Role runner `
            -Issue ([int]$intentPayload.issue)
        . $lockHelperPath
        . $spawnPath
        $compilerEvidence = Complete-AstroDetachedCompilerScope $compilerState
    }
    catch {
        $compilerFailure = $_
        if ($null -ne $compilerState) {
            try {
                [void](Write-AstroDetachedCompilerFault `
                    -State $compilerState `
                    -Code 'ASTRO_DETACH_RUNNER_COMPILER_FAILED' `
                    -Message $compilerFailure.Exception.Message `
                    -Remediation 'preserve the run/compiler state and task; inspect immutable compiler evidence before tracker-bound recovery' `
                    -Stage 'runner-import-or-cleanup')
            }
            catch {
                throw "DETACH_RUNNER[ASTRO_DETACH_COMPILER_FAULT_PUBLISH_FAILED]: {code=ASTRO_DETACH_COMPILER_FAULT_PUBLISH_FAILED; message=`"runner compiler failed ('$($compilerFailure.Exception.Message)') and its durable fault also failed ('$($_.Exception.Message)')`"; remediation=`"preserve all run/task/compiler bytes and inspect both failures`"}"
            }
        }
        throw "DETACH_RUNNER[ASTRO_DETACH_RUNNER_COMPILER_FAILED]: {code=ASTRO_DETACH_RUNNER_COMPILER_FAILED; message=`"$($compilerFailure.Exception.Message)`"; remediation=`"preserve run and task state; inspect compiler-state records`"}"
    }

    $taskService = Get-AstroDetachedTaskService
    $liveTask = Get-AstroDetachedRegisteredTask `
        -TaskService $taskService `
        -TaskName $taskName
    $liveTaskSnapshot = Get-AstroDetachedTaskSnapshot $liveTask
    if (-not $liveTaskSnapshot.xml_priority_present -or
        $liveTaskSnapshot.scheduler_priority -ne
            [int]$priorityPolicy.scheduler_priority -or
        $liveTaskSnapshot.xml_priority -ne
            [int]$priorityPolicy.scheduler_priority) {
        $taskPreservationRequired = $true
        throw "DETACH_RUNNER[ASTRO_DETACH_TASK_PRIORITY_MISMATCH]: {code=ASTRO_DETACH_TASK_PRIORITY_MISMATCH; message=`"live task priority differs from the immutable policy`"; remediation=`"preserve the exact task/run/process state and inspect Task Scheduler normalization without reprioritizing it`"}"
    }
    if ($liveTaskSnapshot.xml_sha256 -cne $taskXmlSha256 -or
        $liveTaskSnapshot.action_path -cne
            [string]$intentPayload.bootstrap_path -or
        $liveTaskSnapshot.action_arguments -cne
            [string]$intentPayload.bootstrap_action_arguments -or
        $liveTaskSnapshot.hidden) {
        throw "registered task XML differs from the immutable task record before runner acceptance"
    }

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
            priority_policy = $priorityPolicy
            psmodulepath_policy = $modulePathPolicy
            bootstrap = [ordered]@{
                identity = [ordered]@{
                    pid = [int]$bootstrapValues.bootstrap_pid
                    process_start_utc_ticks =
                        [long]$bootstrapValues.bootstrap_start_utc_ticks
                    session_id = [int]$bootstrapValues.bootstrap_session_id
                }
                exact_parent = $runnerParent
                probe = $bootstrapProbe
                start_path = $bootstrapStart.Path
                start_sha256 = $bootstrapStart.Sha256
                start_bytes = [long]$bootstrapStart.Length
                path = $bootstrapValues.bootstrap_path
                sha256 = $bootstrapValues.bootstrap_sha256
                bytes = [long]$bootstrapValues.bootstrap_bytes
                pe_subsystem = [int]$intentPayload.bootstrap_subsystem
                pe_subsystem_name =
                    [string]$intentPayload.bootstrap_subsystem_name
                creation_flags = [long]$bootstrapValues.creation_flags
                startup_show_window =
                    [int]$bootstrapValues.startup_show_window
                runner_log_path = $bootstrapValues.runner_log_path
            }
            compiler = [ordered]@{
                intent_path = $compilerEvidence.Intent.Path
                intent_sha256 = $compilerEvidence.Intent.Sha256
                authorization_path = $compilerEvidence.Authorization.Path
                authorization_sha256 = $compilerEvidence.Authorization.Sha256
                renamed_path = $compilerEvidence.Renamed.Path
                renamed_sha256 = $compilerEvidence.Renamed.Sha256
                completion_path = $compilerEvidence.Completion.Path
                completion_sha256 = $compilerEvidence.Completion.Sha256
                scope_path = $compilerEvidence.ScopePath
                scope_file_id = $compilerEvidence.ScopeFileId
                inventory_sha256 = $compilerEvidence.InventorySha256
                scope_state = $compilerEvidence.ScopeState
                tombstone_state = $compilerEvidence.TombstoneState
            }
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
    $boundaryProbe = Get-AstroDetachedProcessProbe `
        -ProcessId ([int]$lease.ProcessId) `
        -ProcessStartUtcTicks ([long]$lease.ProcessStartUtcTicks) `
        -SessionId ([int]$lease.SessionId) `
        -ExpectedPriorityClass (
            [string]$priorityPolicy.process_priority_class
        ) `
        -ExpectedBasePriority ([int]$priorityPolicy.process_base_priority)
    if ($boundaryProbe.state -cne 'exact-live') {
        if ($boundaryProbe.state -ceq 'priority-mismatch') {
            $taskPreservationRequired = $true
        }
        throw "DETACH_RUNNER[ASTRO_DETACH_BOUNDARY_PRIORITY_MISMATCH]: {code=ASTRO_DETACH_BOUNDARY_PRIORITY_MISMATCH; message=`"launcher boundary is not exact-live at the declared priority: $($boundaryProbe.state)`"; remediation=`"preserve the retained process/run/task and inspect priority inheritance; do not reprioritize or retry`"}"
    }
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
                priority_class = [string]$boundaryProbe.observed_priority_class
                base_priority = [int]$boundaryProbe.observed_base_priority
            }
            role = 'launcher-boundary'
            priority_policy = $priorityPolicy
            priority_probe = $boundaryProbe
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
        -SessionId $ownerSession `
        -ExpectedPriorityClass (
            [string]$priorityPolicy.process_priority_class
        ) `
        -ExpectedBasePriority ([int]$priorityPolicy.process_base_priority)
    if ($ownerProbe.state -cne 'exact-live') {
        if ($ownerProbe.state -ceq 'priority-mismatch') {
            $taskPreservationRequired = $true
        }
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
                priority_class = [string]$ownerProbe.observed_priority_class
                base_priority = [int]$ownerProbe.observed_base_priority
            }
            role = 'authoritative-launcher-owner'
            priority_policy = $priorityPolicy
            priority_probe = $ownerProbe
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
            priority_policy = $priorityPolicy
            owner_priority_probe = $ownerProbe
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
        -SessionId ([int]$boundaryRecord.Payload.identity.session_id) `
        -ExpectedPriorityClass (
            [string]$priorityPolicy.process_priority_class
        ) `
        -ExpectedBasePriority ([int]$priorityPolicy.process_base_priority)
    $workProbe = Get-AstroDetachedProcessProbe `
        -ProcessId ([int]$workRecord.Payload.identity.pid) `
        -ProcessStartUtcTicks (
            [long]$workRecord.Payload.identity.process_start_utc_ticks
        ) `
        -SessionId ([int]$workRecord.Payload.identity.session_id) `
        -ExpectedPriorityClass (
            [string]$priorityPolicy.process_priority_class
        ) `
        -ExpectedBasePriority ([int]$priorityPolicy.process_base_priority)
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
            priority_policy = $priorityPolicy
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
            priority_policy = $priorityPolicy
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
                    priority_policy = $priorityPolicy
                    task_preservation_required = $taskPreservationRequired
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
        -not $taskCleanupAttempted -and
        -not $taskPreservationRequired) {
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
                        priority_policy = $priorityPolicy
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
