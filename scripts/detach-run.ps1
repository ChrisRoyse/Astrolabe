<#
.SYNOPSIS
    Start one issue-bound native launcher through an exact Task Scheduler boundary.

.DESCRIPTION
    Creates one fresh repository-local run directory, persists immutable intent and exact
    task-definition readback, starts a create-only GUID task, then reports readiness only
    after an independent authoritative launcher-lock read proves that the durable work
    identity is the live v3 lease owner.

    This command never overwrites state or tasks, never deletes/stops work on readiness
    timeout, and never infers ownership from a numeric PID.

.NOTES
    Production uses an explicit InteractiveToken principal. S4U is accepted only with
    -AllowS4UIsolatedLocalFsv and is never selected as a fallback. Refs #616.
#>

[CmdletBinding()]
param(
    [int]$Issue = 0,
    [string]$Command = '',
    [string]$CommandArgsJson = '[]',
    [string]$BatchCommandsJson = '',
    [int]$ReadinessWaitSeconds = 0,
    [int]$LauncherLeaseWaitSeconds = 0,
    [string]$RunId = '',
    [ValidateSet('InteractiveToken', 'S4U')]
    [string]$TaskLogonType = 'InteractiveToken',
    [switch]$AllowS4UIsolatedLocalFsv,

    # Retired v1 surface: retained only so callers receive a structured refusal instead
    # of PowerShell's ambiguous unknown-parameter/binding behavior.
    [string]$WorkScript = '',
    [string]$WorkArgsJson = '',
    [string]$LogFile = '',
    [string]$RunPidFile = '',
    [string]$DoneFile = '',
    [string]$TaskName = '',
    [int]$PidWaitSeconds = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$observerStartedUtcTicks = [DateTime]::UtcNow.Ticks

$bootstrapTemp = 'C:\code\Astrolabe\.tmp'
if (-not [IO.Directory]::Exists($bootstrapTemp)) {
    throw "DETACH_RUN[ASTRO_DETACH_TMP_MISSING]: {code=ASTRO_DETACH_TMP_MISSING; message=`"canonical repository .tmp directory is missing`"; remediation=`"restore the canonical workspace layout before detached execution`"}"
}
$env:TEMP = $bootstrapTemp
$env:TMP = $bootstrapTemp
$env:TMPDIR = $bootstrapTemp

$protocolPath = Join-Path $PSScriptRoot 'detach-protocol.ps1'
$spawnPath = Join-Path $PSScriptRoot 'detach-spawn.ps1'
$runnerPath = Join-Path $PSScriptRoot 'detach-runner.ps1'
$launcherPath = Join-Path $PSScriptRoot 'windows-gnu-toolchain.ps1'
. $protocolPath
. $spawnPath

function ConvertFrom-AstroDetachedCommandPlan {
    param(
        [AllowEmptyString()][string]$SingleCommand,
        [Parameter(Mandatory)][string]$SingleArgsJson,
        [AllowEmptyString()][string]$BatchJson
    )

    if (-not [string]::IsNullOrWhiteSpace($BatchJson)) {
        if (-not [string]::IsNullOrWhiteSpace($SingleCommand) -or
            $SingleArgsJson -cne '[]') {
            throw "DETACH_RUN[ASTRO_DETACH_ARGUMENT_CONFLICT]: {code=ASTRO_DETACH_ARGUMENT_CONFLICT; message=`"BatchCommandsJson is mutually exclusive with Command and CommandArgsJson`"; remediation=`"pass one single command or one explicit nested-array batch`"}"
        }
        try {
            $envelope = ConvertFrom-Json `
                -InputObject ('{"value":' + $BatchJson + '}')
            if (@($envelope.PSObject.Properties.Name).Count -ne 1 -or
                @($envelope.PSObject.Properties.Name)[0] -cne 'value') {
                throw 'JSON escaped the single-value envelope'
            }
            $parsed = $envelope.value
        }
        catch {
            throw "DETACH_RUN[ASTRO_DETACH_BATCH_JSON_INVALID]: {code=ASTRO_DETACH_BATCH_JSON_INVALID; message=`"BatchCommandsJson is not valid JSON: $($_.Exception.Message)`"; remediation=`"pass a JSON array containing at least two nonempty command string arrays`"}"
        }
        if ($parsed -isnot [Collections.IEnumerable] -or $parsed -is [string]) {
            throw "DETACH_RUN[ASTRO_DETACH_BATCH_SHAPE_INVALID]: {code=ASTRO_DETACH_BATCH_SHAPE_INVALID; message=`"BatchCommandsJson root must be an array`"; remediation=`"pass a nested JSON string-array batch`"}"
        }
        $entries = @($parsed)
        if ($entries.Count -lt 2) {
            throw "DETACH_RUN[ASTRO_DETACH_BATCH_CARDINALITY_INVALID]: {code=ASTRO_DETACH_BATCH_CARDINALITY_INVALID; message=`"batch requires at least two commands; observed $($entries.Count)`"; remediation=`"use Command for one command or supply two or more batch entries`"}"
        }
        for ($index = 0; $index -lt $entries.Count; $index++) {
            if ($entries[$index] -isnot [Collections.IEnumerable] -or
                $entries[$index] -is [string]) {
                throw "DETACH_RUN[ASTRO_DETACH_BATCH_ENTRY_INVALID]: {code=ASTRO_DETACH_BATCH_ENTRY_INVALID; message=`"batch entry $index is not a JSON string array`"; remediation=`"represent every command as [command,arg1,...]`"}"
            }
            $values = @($entries[$index])
            if ($values.Count -eq 0) {
                throw "DETACH_RUN[ASTRO_DETACH_BATCH_ENTRY_EMPTY]: {code=ASTRO_DETACH_BATCH_ENTRY_EMPTY; message=`"batch entry $index is empty`"; remediation=`"supply a nonblank command as its first element`"}"
            }
            foreach ($value in $values) {
                if ($value -isnot [string]) {
                    throw "DETACH_RUN[ASTRO_DETACH_BATCH_ENTRY_NONSTRING]: {code=ASTRO_DETACH_BATCH_ENTRY_NONSTRING; message=`"batch entry $index contains a non-string value`"; remediation=`"use only JSON strings`"}"
                }
            }
            if ([string]::IsNullOrWhiteSpace([string]$values[0])) {
                throw "DETACH_RUN[ASTRO_DETACH_BATCH_COMMAND_BLANK]: {code=ASTRO_DETACH_BATCH_COMMAND_BLANK; message=`"batch entry $index command is blank`"; remediation=`"supply a nonblank executable name`"}"
            }
        }
        return [ordered]@{
            mode = 'batch'
            command = ''
            command_args_json = '[]'
            batch_commands_json = $BatchJson
        }
    }

    if ([string]::IsNullOrWhiteSpace($SingleCommand)) {
        throw "DETACH_RUN[ASTRO_DETACH_COMMAND_REQUIRED]: {code=ASTRO_DETACH_COMMAND_REQUIRED; message=`"one nonblank Command or BatchCommandsJson is required`"; remediation=`"supply the real native launcher work explicitly`"}"
    }
    try {
        $envelope = ConvertFrom-Json `
            -InputObject ('{"value":' + $SingleArgsJson + '}')
        if (@($envelope.PSObject.Properties.Name).Count -ne 1 -or
            @($envelope.PSObject.Properties.Name)[0] -cne 'value') {
            throw 'JSON escaped the single-value envelope'
        }
        $parsed = $envelope.value
    }
    catch {
        throw "DETACH_RUN[ASTRO_DETACH_COMMAND_JSON_INVALID]: {code=ASTRO_DETACH_COMMAND_JSON_INVALID; message=`"CommandArgsJson is not valid JSON: $($_.Exception.Message)`"; remediation=`"pass one JSON string array`"}"
    }
    if ($parsed -isnot [Collections.IEnumerable] -or $parsed -is [string]) {
        throw "DETACH_RUN[ASTRO_DETACH_COMMAND_SHAPE_INVALID]: {code=ASTRO_DETACH_COMMAND_SHAPE_INVALID; message=`"CommandArgsJson root must be a JSON string array`"; remediation=`"pass [] or one array of strings`"}"
    }
    foreach ($value in @($parsed)) {
        if ($value -isnot [string]) {
            throw "DETACH_RUN[ASTRO_DETACH_COMMAND_NONSTRING]: {code=ASTRO_DETACH_COMMAND_NONSTRING; message=`"CommandArgsJson contains a non-string value`"; remediation=`"use only JSON strings`"}"
        }
    }
    return [ordered]@{
        mode = 'single'
        command = $SingleCommand
        command_args_json = $SingleArgsJson
        batch_commands_json = ''
    }
}

function Get-AstroDetachedScriptBinding {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.File]::Exists($full)) {
        throw "required detached protocol script is missing: $full"
    }
    return [ordered]@{
        path = $full
        sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.
            ToLowerInvariant()
    }
}

function Write-AstroDetachedPrestartFault {
    param(
        [Parameter(Mandatory)]$PreviousRecord,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Remediation,
        [Parameter(Mandatory)][string]$Stage,
        [Parameter(Mandatory)][string]$HResult,
        [bool]$TaskCreated,
        [bool]$TaskRemoved
    )

    $sequence = [int]$PreviousRecord.Sequence + 1
    $name = '{0:d3}-fault.json' -f $sequence
    return Write-AstroDetachedRecord `
        -RunDirectory $runDirectory `
        -Name $name `
        -Schema 'astrolabe.detached.fault.v1' `
        -Sequence $sequence `
        -PreviousName $PreviousRecord.Name `
        -PreviousSha256 $PreviousRecord.Sha256 `
        -Payload ([ordered]@{
            code = $Code
            message = $Message
            remediation = $Remediation
            stage = $Stage
            hresult = $HResult
            task_created = $TaskCreated
            task_removed = $TaskRemoved
        })
}

if (-not [string]::IsNullOrEmpty($WorkScript) -or
    -not [string]::IsNullOrEmpty($WorkArgsJson) -or
    -not [string]::IsNullOrEmpty($LogFile) -or
    -not [string]::IsNullOrEmpty($RunPidFile) -or
    -not [string]::IsNullOrEmpty($DoneFile) -or
    -not [string]::IsNullOrEmpty($TaskName) -or
    $PidWaitSeconds -ne 0) {
    throw "DETACH_RUN[ASTRO_DETACH_LEGACY_SURFACE_REFUSED]: {code=ASTRO_DETACH_LEGACY_SURFACE_REFUSED; message=`"caller-selected scripts, sentinels, logs, task names, and PID-only readiness are retired`"; remediation=`"pass Issue plus Command/CommandArgsJson or BatchCommandsJson and explicit ReadinessWaitSeconds/LauncherLeaseWaitSeconds budgets`"}"
}
if ($Issue -le 0) {
    throw "DETACH_RUN[ASTRO_DETACH_ISSUE_INVALID]: {code=ASTRO_DETACH_ISSUE_INVALID; message=`"Issue must be a positive integer`"; remediation=`"bind the detached launcher to its driving GitHub issue`"}"
}
if ($ReadinessWaitSeconds -le 0) {
    throw "DETACH_RUN[ASTRO_DETACH_READINESS_WAIT_INVALID]: {code=ASTRO_DETACH_READINESS_WAIT_INVALID; message=`"ReadinessWaitSeconds must be explicitly positive`"; remediation=`"choose and pass the observed startup budget for this run`"}"
}
if ($LauncherLeaseWaitSeconds -le 0) {
    throw "DETACH_RUN[ASTRO_DETACH_LEASE_WAIT_INVALID]: {code=ASTRO_DETACH_LEASE_WAIT_INVALID; message=`"LauncherLeaseWaitSeconds must be explicitly positive`"; remediation=`"pass the separately observed budget for native launcher lease publication`"}"
}
if ($TaskLogonType -ceq 'S4U' -and -not $AllowS4UIsolatedLocalFsv) {
    throw "DETACH_RUN[ASTRO_DETACH_S4U_REQUIRES_ISOLATED_FSV]: {code=ASTRO_DETACH_S4U_REQUIRES_ISOLATED_FSV; message=`"S4U has no network/EFS access and is forbidden for production`"; remediation=`"use InteractiveToken, or explicitly add AllowS4UIsolatedLocalFsv only for a local isolated protocol FSV`"}"
}
if ($TaskLogonType -ceq 'InteractiveToken' -and $AllowS4UIsolatedLocalFsv) {
    throw "DETACH_RUN[ASTRO_DETACH_S4U_SWITCH_CONFLICT]: {code=ASTRO_DETACH_S4U_SWITCH_CONFLICT; message=`"AllowS4UIsolatedLocalFsv was supplied with InteractiveToken`"; remediation=`"remove the switch or explicitly select S4U for isolated local FSV`"}"
}
if ([IO.Path]::GetFullPath((Get-Location).Path).TrimEnd('\') -cne
    $script:AstroDetachedCanonicalRoot) {
    throw "DETACH_RUN[ASTRO_DETACH_ROOT_INVALID]: {code=ASTRO_DETACH_ROOT_INVALID; message=`"detach-run must execute from C:\code\Astrolabe`"; remediation=`"change to the canonical checkout and retry`"}"
}

$plan = ConvertFrom-AstroDetachedCommandPlan `
    -SingleCommand $Command `
    -SingleArgsJson $CommandArgsJson `
    -BatchJson $BatchCommandsJson
if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = [Guid]::NewGuid().ToString('N')
}
elseif ($RunId -cnotmatch '^[0-9a-f]{32}$') {
    throw "DETACH_RUN[ASTRO_DETACH_RUN_ID_INVALID]: {code=ASTRO_DETACH_RUN_ID_INVALID; message=`"RunId must be 32 lowercase hexadecimal characters`"; remediation=`"omit it for a fresh GUID or pass one canonical GUID N value`"}"
}

$bindings = [ordered]@{
    protocol = Get-AstroDetachedScriptBinding $protocolPath
    spawn = Get-AstroDetachedScriptBinding $spawnPath
    runner = Get-AstroDetachedScriptBinding $runnerPath
    launcher = Get-AstroDetachedScriptBinding $launcherPath
}
$powershellPath = Join-Path `
    ([Environment]::SystemDirectory) `
    'WindowsPowerShell\v1.0\powershell.exe'
if (-not [IO.File]::Exists($powershellPath)) {
    throw "DETACH_RUN[ASTRO_DETACH_SYSTEM_POWERSHELL_MISSING]: {code=ASTRO_DETACH_SYSTEM_POWERSHELL_MISSING; message=`"absolute System32 Windows PowerShell is missing: $powershellPath`"; remediation=`"repair the supported Windows runtime before detached execution`"}"
}

$runDirectory = New-AstroDetachedRunDirectory $RunId
$taskNameExact = "Astrolabe.Detached.$RunId"
$principal = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$principalSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$creatorIdentity = Get-AstroDetachedCurrentIdentity
$intentRecord = Write-AstroDetachedRecord `
    -RunDirectory $runDirectory `
    -Name '000-intent.json' `
    -Schema 'astrolabe.detached.intent.v1' `
    -Sequence 0 `
    -Payload ([ordered]@{
        issue = $Issue
        run_id = $RunId
        repository_root = $script:AstroDetachedCanonicalRoot
        creator_identity = $creatorIdentity
        command_mode = $plan.mode
        command = $plan.command
        command_args_json = $plan.command_args_json
        batch_commands_json = $plan.batch_commands_json
        readiness_wait_seconds = $ReadinessWaitSeconds
        readiness_observer_started_utc_ticks = $observerStartedUtcTicks
        readiness_observer_started_utc =
            ConvertTo-AstroDetachedUtcIso $observerStartedUtcTicks
        launcher_lease_wait_seconds = $LauncherLeaseWaitSeconds
        task_name = $taskNameExact
        task_logon_type = $TaskLogonType
        s4u_isolated_local_fsv = [bool]$AllowS4UIsolatedLocalFsv
        principal_user_id = $principal
        principal_sid = $principalSid
        powershell_path = $powershellPath
        protocol_path = $bindings.protocol.path
        protocol_sha256 = $bindings.protocol.sha256
        spawn_path = $bindings.spawn.path
        spawn_sha256 = $bindings.spawn.sha256
        runner_path = $bindings.runner.path
        runner_sha256 = $bindings.runner.sha256
        launcher_path = $bindings.launcher.path
        launcher_sha256 = $bindings.launcher.sha256
    })

$taskService = $null
$registered = $null
$taskSnapshot = $null
$taskRecord = $null
$taskCreated = $false
$taskStarted = $false
$prestartStage = 'task-service-connect'
try {
    $taskService = Get-AstroDetachedTaskService
    $actionValues = @(
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $runnerPath,
        '-RunDirectory',
        $runDirectory
    )
    $actionArguments = (
        $actionValues |
            ForEach-Object { [AstroDetachV2]::QuoteArgument([string]$_) }
    ) -join ' '
    $prestartStage = 'task-create'
    $registered = Register-AstroDetachedTaskCreateOnly `
        -TaskService $taskService `
        -TaskName $taskNameExact `
        -PrincipalUserId $principal `
        -LogonType $TaskLogonType `
        -ActionPath $powershellPath `
        -ActionArguments $actionArguments `
        -WorkingDirectory $script:AstroDetachedCanonicalRoot `
        -Description "Astrolabe issue #$Issue detached launcher run $RunId"
    $taskCreated = $true
    $prestartStage = 'task-first-readback'
    $taskSnapshot = Get-AstroDetachedTaskSnapshot $registered
    $expectedLogon = if ($TaskLogonType -ceq 'InteractiveToken') { 3 } else { 2 }
    if ($taskSnapshot.path -cne "\$taskNameExact" -or
        $taskSnapshot.name -cne $taskNameExact -or
        -not $taskSnapshot.enabled -or
        [string]::IsNullOrWhiteSpace($taskSnapshot.principal_user_id) -or
        $taskSnapshot.principal_sid -cne $principalSid -or
        $taskSnapshot.principal_logon_type -ne $expectedLogon -or
        $taskSnapshot.principal_run_level -ne 0 -or
        $taskSnapshot.action_count -ne 1 -or
        $taskSnapshot.action_path -cne $powershellPath -or
        $taskSnapshot.action_arguments -cne $actionArguments -or
        $taskSnapshot.action_working_directory -cne
            $script:AstroDetachedCanonicalRoot -or
        -not $taskSnapshot.allow_demand_start -or
        $taskSnapshot.disallow_start_on_batteries -or
        $taskSnapshot.stop_if_going_on_batteries -or
        $taskSnapshot.execution_time_limit -cne 'PT0S' -or
        $taskSnapshot.multiple_instances -ne 2 -or
        $taskSnapshot.start_when_available -or
        $taskSnapshot.wake_to_run) {
        throw "DETACH_RUN[ASTRO_DETACH_TASK_READBACK_MISMATCH]: {code=ASTRO_DETACH_TASK_READBACK_MISMATCH; message=`"registered task principal/action/settings differ from the requested exact definition`"; remediation=`"preserve the readback and inspect Task Scheduler policy normalization`"}"
    }
    $taskRecord = Write-AstroDetachedRecord `
        -RunDirectory $runDirectory `
        -Name '001-task.json' `
        -Schema 'astrolabe.detached.task.v1' `
        -Sequence 1 `
        -PreviousName $intentRecord.Name `
        -PreviousSha256 $intentRecord.Sha256 `
        -Payload ([ordered]@{
            task = $taskSnapshot
            definition_read_back_before_start = $true
            registrar_identity = Get-AstroDetachedCurrentIdentity
        })
    $prestartStage = 'task-second-readback'
    $taskReadback = Get-AstroDetachedTaskSnapshot (
        Get-AstroDetachedRegisteredTask `
            -TaskService $taskService `
            -TaskName $taskNameExact
    )
    if ($taskReadback.xml_sha256 -cne $taskSnapshot.xml_sha256) {
            throw "DETACH_RUN[ASTRO_DETACH_TASK_SECOND_READBACK_CHANGED]: {code=ASTRO_DETACH_TASK_SECOND_READBACK_CHANGED; message=`"task XML changed between independent pre-start reads`"; remediation=`"preserve state and inspect task mutation policy`"}"
    }
    $prestartStage = 'task-start'
    [void]$registered.Run($null)
    $taskStarted = $true
    $prestartStage = 'started'
}
catch {
    $original = $_.Exception.Message
    $prestartHResult = '0x{0:x8}' -f (
        $_.Exception.HResult -band 0xffffffffL
    )
    $prestartCode = 'ASTRO_DETACH_PRESTART_FAULT'
    $prestartRemediation =
        'preserve the run directory and any existing task; inspect the exact create/readback failure'
    if ($TaskLogonType -ceq 'S4U' -and
        $prestartStage -ceq 'task-create' -and
        $prestartHResult -ceq '0x80070005') {
        $prestartCode = 'ASTRO_DETACH_S4U_REGISTRATION_DENIED'
        $prestartRemediation =
            'run isolated-local S4U FSV only from a same-principal Windows token authorized for noninteractive task registration and Log on as a batch job; do not switch logon modes'
    }
    $removed = $false
    $cleanupError = $null
    if ($taskCreated -and -not $taskStarted) {
        try {
            [void](Remove-AstroDetachedTaskExact `
                -TaskService $taskService `
                -TaskName $taskNameExact `
                -ExpectedXmlSha256 $taskSnapshot.xml_sha256)
            $removed = $true
        }
        catch {
            $cleanupError = $_.Exception.Message
        }
    }
    $predecessor = if ($null -ne $taskRecord) {
        Read-AstroDetachedRecord `
            -RunDirectory $runDirectory `
            -Name $taskRecord.Name `
            -ExpectedSequence 1
    }
    else {
        $intentRecord
    }
    try {
        $faultRecord = Write-AstroDetachedPrestartFault `
            -PreviousRecord $predecessor `
            -Code $prestartCode `
            -Message $original `
            -Remediation $prestartRemediation `
            -Stage $prestartStage `
            -HResult $prestartHResult `
            -TaskCreated $taskCreated `
            -TaskRemoved $removed
        if ($removed) {
            $faultReadback = Read-AstroDetachedRecord `
                -RunDirectory $runDirectory `
                -Name $faultRecord.Name `
                -ExpectedSequence $faultRecord.Sequence
            $cleanupSequence = [int]$faultReadback.Sequence + 1
            $cleanupName = '{0:d3}-cleanup.json' -f $cleanupSequence
            [void](Write-AstroDetachedRecord `
                -RunDirectory $runDirectory `
                -Name $cleanupName `
                -Schema 'astrolabe.detached.cleanup.v1' `
                -Sequence $cleanupSequence `
                -PreviousName $faultReadback.Name `
                -PreviousSha256 $faultReadback.Sha256 `
                -Payload ([ordered]@{
                    task_name = $taskNameExact
                    task_xml_sha256 = $taskSnapshot.xml_sha256
                    task_absent = $true
                    cleanup_after_prestart_fault = $true
                    task_cleanup_retried = $false
                }))
        }
    }
    catch {
        $original += " | fault/cleanup record write failed: $($_.Exception.Message)"
    }
    if ($null -ne $cleanupError) {
        throw "DETACH_RUN[ASTRO_DETACH_PRESTART_CLEANUP_FAILED]: {code=ASTRO_DETACH_PRESTART_CLEANUP_FAILED; message=`"$original; exact cleanup also failed: $cleanupError`"; remediation=`"preserve the task and run directory and inspect both exact states`"}"
    }
    if ($prestartCode -ceq 'ASTRO_DETACH_S4U_REGISTRATION_DENIED') {
        throw "DETACH_RUN[$prestartCode]: {code=$prestartCode; stage=$prestartStage; hresult=$prestartHResult; message=`"$original`"; remediation=`"$prestartRemediation`"}"
    }
    throw $original
}

$deadline = [DateTime]::new(
    $observerStartedUtcTicks,
    [DateTimeKind]::Utc
).AddSeconds($ReadinessWaitSeconds)
$recordNames = @(
    '000-intent.json',
    '001-task.json',
    '002-runner.json',
    '003-boundary.json',
    '004-work.json',
    '005-launcher-lease.json'
)
$lastLock = $null
while ([DateTime]::UtcNow -lt $deadline) {
    if ([IO.File]::Exists((Join-Path $runDirectory '005-launcher-lease.json'))) {
        $records = @()
        for ($index = 0; $index -lt $recordNames.Count; $index++) {
            $record = Read-AstroDetachedRecord `
                -RunDirectory $runDirectory `
                -Name $recordNames[$index] `
                -ExpectedSequence $index
            if ($index -gt 0) {
                Assert-AstroDetachedRecordLink $records[$index - 1] $record
            }
            $records += $record
        }
        $runnerRecord = $records[2]
        $boundaryRecord = $records[3]
        $workRecord = $records[4]
        $leaseRecord = $records[5]
        $liveTaskReadback = Get-AstroDetachedTaskSnapshot (
            Get-AstroDetachedRegisteredTask `
                -TaskService $taskService `
                -TaskName $taskNameExact
        )
        if ($liveTaskReadback.xml_sha256 -cne $taskSnapshot.xml_sha256) {
            throw "DETACH_RUN[ASTRO_DETACH_LIVE_TASK_CHANGED]: {code=ASTRO_DETACH_LIVE_TASK_CHANGED; message=`"task XML changed before readiness acceptance`"; remediation=`"preserve task/run state and inspect the mutation`"}"
        }
        $lastLock = Read-AstroLauncherLock (
            Join-Path `
                (Join-Path $script:AstroDetachedCanonicalRoot '.tmp') `
                'astrolabe-launcher.lock'
        )
        if ($lastLock.State -cne 'held' -or
            [int]$lastLock.Issue -ne $Issue -or
            [int]$lastLock.OwnerPid -ne [int]$workRecord.Payload.identity.pid -or
            [long]$lastLock.OwnerProcessStartUtcTicks -ne
                [long]$workRecord.Payload.identity.process_start_utc_ticks -or
            [string]$lastLock.Sha256 -cne
                [string]$leaseRecord.Payload.lock_sha256) {
            throw "DETACH_RUN[ASTRO_DETACH_LIVE_LEASE_CHANGED]: {code=ASTRO_DETACH_LIVE_LEASE_CHANGED; message=`"authoritative live lock no longer equals the durable work/lease identity`"; remediation=`"preserve all state and inspect the exact process/lock probes`"}"
        }
        $runnerProbe = Get-AstroDetachedProcessProbe `
            -ProcessId ([int]$runnerRecord.Payload.identity.pid) `
            -ProcessStartUtcTicks (
                [long]$runnerRecord.Payload.identity.process_start_utc_ticks
            ) `
            -SessionId ([int]$runnerRecord.Payload.identity.session_id)
        $workProbe = Get-AstroDetachedProcessProbe `
            -ProcessId ([int]$workRecord.Payload.identity.pid) `
            -ProcessStartUtcTicks (
                [long]$workRecord.Payload.identity.process_start_utc_ticks
            ) `
            -SessionId ([int]$workRecord.Payload.identity.session_id)
        if ($runnerProbe.state -cne 'exact-live' -or
            $workProbe.state -cne 'exact-live') {
            throw "DETACH_RUN[ASTRO_DETACH_READY_OWNER_NOT_LIVE]: {code=ASTRO_DETACH_READY_OWNER_NOT_LIVE; message=`"runner/work probes are not both exact-live: runner=$($runnerProbe.state), work=$($workProbe.state)`"; remediation=`"read terminal records instead of claiming live readiness`"}"
        }
        $result = [ordered]@{
            schema = 'astrolabe.detached.start-result.v1'
            run_id = $RunId
            run_directory = $runDirectory
            issue = $Issue
            task_name = $taskNameExact
            task_xml_sha256 = $taskSnapshot.xml_sha256
            task_principal_user_id = $taskSnapshot.principal_user_id
            task_principal_sid = $taskSnapshot.principal_sid
            task_logon_type = $TaskLogonType
            task_action_path = $taskSnapshot.action_path
            task_session_id = [int]$runnerRecord.Payload.identity.session_id
            runner_identity = $runnerRecord.Payload.identity
            launcher_boundary_identity = $boundaryRecord.Payload.identity
            work_launcher_identity = $workRecord.Payload.identity
            authoritative_lock_sha256 = [string]$lastLock.Sha256
            lifecycle_head_name = $leaseRecord.Name
            lifecycle_head_sha256 = $leaseRecord.Sha256
            launcher_log = Join-Path $runDirectory 'launcher.log'
        }
        Write-Output (
            'DETACH_RUN[ASTRO_DETACH_STARTED]: ' +
            ($result | ConvertTo-Json -Depth 8 -Compress)
        )
        exit 0
    }
    $fault = Get-ChildItem `
        -LiteralPath $runDirectory `
        -Filter '*-fault.json' `
        -File `
        -ErrorAction Stop |
        Sort-Object Name |
        Select-Object -First 1
    if ($null -ne $fault) {
        throw "DETACH_RUN[ASTRO_DETACH_RUNNER_FAULT_RECORDED]: {code=ASTRO_DETACH_RUNNER_FAULT_RECORDED; message=`"detached runner persisted a fault record: $($fault.FullName)`"; remediation=`"read the immutable fault chain and launcher.log; do not infer readiness`"}"
    }
    $lastLock = Read-AstroLauncherLock (
        Join-Path `
            (Join-Path $script:AstroDetachedCanonicalRoot '.tmp') `
            'astrolabe-launcher.lock'
    )
    Start-Sleep -Milliseconds 100
}

$existing = Get-ChildItem -LiteralPath $runDirectory -File |
    Sort-Object Name |
    ForEach-Object {
        $snapshot = Read-AstroDetachedOrdinaryFile $_.FullName
        [ordered]@{
            name = $_.Name
            sha256 = $snapshot.Sha256
            bytes = $snapshot.Length
        }
    }
$taskAtTimeout = Get-AstroDetachedRegisteredTask `
    -TaskService $taskService `
    -TaskName $taskNameExact `
    -AllowAbsent
$taskAtTimeoutSnapshot = if ($null -eq $taskAtTimeout) {
    $null
}
else {
    Get-AstroDetachedTaskSnapshot $taskAtTimeout
}
$chainHead = Read-AstroDetachedRecord `
    -RunDirectory $runDirectory `
    -Name '001-task.json' `
    -ExpectedSchema 'astrolabe.detached.task.v1' `
    -ExpectedSequence 1
$timeoutRecord = Write-AstroDetachedRecord `
    -RunDirectory $runDirectory `
    -Name '900-readiness-timeout.json' `
    -Schema 'astrolabe.detached.readiness-timeout.v1' `
    -Sequence 2 `
    -PreviousName $chainHead.Name `
    -PreviousSha256 $chainHead.Sha256 `
    -Payload ([ordered]@{
        code = 'ASTRO_DETACH_READINESS_TIMEOUT'
        waited_seconds = $ReadinessWaitSeconds
        observer_started_utc_ticks = $observerStartedUtcTicks
        observer_started_utc =
            ConvertTo-AstroDetachedUtcIso $observerStartedUtcTicks
        observer_deadline_utc_ticks = $deadline.Ticks
        observer_deadline_utc =
            ConvertTo-AstroDetachedUtcIso $deadline.Ticks
        observed_utc_ticks = [DateTime]::UtcNow.Ticks
        launcher_lock_state = if ($null -eq $lastLock) {
            'not-read'
        }
        else {
            [string]$lastLock.State
        }
        launcher_lock_owner_pid = if ($null -eq $lastLock -or
            $lastLock.State -cne 'held') {
            $null
        }
        else {
            [int]$lastLock.OwnerPid
        }
        launcher_lock_owner_process_start_utc_ticks =
            if ($null -eq $lastLock -or $lastLock.State -cne 'held') {
                $null
            }
            else {
                [long]$lastLock.OwnerProcessStartUtcTicks
            }
        task_snapshot = $taskAtTimeoutSnapshot
        existing_files_before_timeout_record = $existing
        action = 'preserved-without-task-delete-or-process-stop'
    })
throw "DETACH_RUN[ASTRO_DETACH_READINESS_TIMEOUT]: {code=ASTRO_DETACH_READINESS_TIMEOUT; message=`"readiness was not proven within $ReadinessWaitSeconds seconds; exact observation=$($timeoutRecord.Path)`"; remediation=`"preserve the live task/process/run state and inspect the immutable observation plus subsequent lifecycle records`"}"
