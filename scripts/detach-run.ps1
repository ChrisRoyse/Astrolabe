<#
.SYNOPSIS
    Start one issue-bound native launcher through an exact Task Scheduler boundary.

.DESCRIPTION
    Creates one fresh repository-local run directory, persists immutable intent and exact
    task-definition readback, starts a create-only GUID task, then reports readiness only
    after an independent authoritative launcher-lock read proves that the durable work
    identity is the live v3 lease owner. Coordinator and runner native imports compile only
    inside exact owner-bound run children and publish durable cleanup or fault evidence.

    This command never overwrites state or tasks, never deletes/stops work on readiness
    timeout, and never infers ownership from a numeric PID.

.NOTES
    Production uses an explicit InteractiveToken principal. S4U is accepted only with
    -AllowS4UIsolatedLocalFsv and is never selected as a fallback. Refs #616, #1065.
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
    [AllowEmptyString()][string]$PriorityPolicy = 'production',
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

$protocolPath = Join-Path $PSScriptRoot 'detach-protocol.ps1'
$strictJsonPath = Join-Path $PSScriptRoot 'detach-strict-json.ps1'
$compilerStatePath = Join-Path $PSScriptRoot 'detach-compiler-state.ps1'
$lockHelperPath = Join-Path $PSScriptRoot 'launcher-lock.ps1'
$spawnPath = Join-Path $PSScriptRoot 'detach-spawn.ps1'
$runnerPath = Join-Path $PSScriptRoot 'detach-runner.ps1'
$bootstrapSourcePath = Join-Path $PSScriptRoot 'detach-bootstrap.cs'
$launcherPath = Join-Path $PSScriptRoot 'windows-gnu-toolchain.ps1'
. $protocolPath
$modulePathPolicy = Initialize-AstroDetachedPowerShellModulePath `
    -Role 'coordinator'
. $compilerStatePath

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

function Get-AstroDetachedPeSnapshot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$ProtectedHandle
    )

    $snapshot = Read-AstroDetachedOrdinaryFile $Path
    $bytes = $snapshot.Bytes
    if ($bytes.Length -lt 256 -or
        $bytes[0] -ne 0x4d -or
        $bytes[1] -ne 0x5a) {
        throw "DETACH_RUN[ASTRO_DETACH_BOOTSTRAP_PE_DOS_INVALID]: {code=ASTRO_DETACH_BOOTSTRAP_PE_DOS_INVALID; message=`"compiled bootstrap lacks one bounded MZ header: $Path`"; remediation=`"preserve the compiler output/log and inspect the exact compiler invocation`"}"
    }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($peOffset -lt 0x40 -or $peOffset -gt ($bytes.Length - 96) -or
        $bytes[$peOffset] -ne 0x50 -or
        $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0 -or
        $bytes[$peOffset + 3] -ne 0) {
        throw "DETACH_RUN[ASTRO_DETACH_BOOTSTRAP_PE_SIGNATURE_INVALID]: {code=ASTRO_DETACH_BOOTSTRAP_PE_SIGNATURE_INVALID; message=`"compiled bootstrap lacks one in-range PE signature: $Path`"; remediation=`"preserve the compiler output/log and inspect the exact compiler invocation`"}"
    }
    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    $sectionCount = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
    $timeDateStamp = [BitConverter]::ToUInt32($bytes, $peOffset + 8)
    $optionalBytes = [BitConverter]::ToUInt16($bytes, $peOffset + 20)
    $characteristics = [BitConverter]::ToUInt16($bytes, $peOffset + 22)
    $optionalOffset = $peOffset + 24
    if ($optionalBytes -lt 70 -or
        $optionalOffset + $optionalBytes -gt $bytes.Length) {
        throw "DETACH_RUN[ASTRO_DETACH_BOOTSTRAP_PE_OPTIONAL_INVALID]: {code=ASTRO_DETACH_BOOTSTRAP_PE_OPTIONAL_INVALID; message=`"compiled bootstrap optional header is out of range: offset=$optionalOffset bytes=$optionalBytes length=$($bytes.Length)`"; remediation=`"preserve the compiler output/log and inspect the exact compiler invocation`"}"
    }
    $magic = [BitConverter]::ToUInt16($bytes, $optionalOffset)
    $subsystem = [BitConverter]::ToUInt16($bytes, $optionalOffset + 68)
    $isExecutable = ($characteristics -band 0x0002) -ne 0
    $isDll = ($characteristics -band 0x2000) -ne 0
    if ($machine -ne 0x8664 -or
        $sectionCount -le 0 -or
        $magic -ne 0x020b -or
        $subsystem -ne 2 -or
        -not $isExecutable -or
        $isDll) {
        throw "DETACH_RUN[ASTRO_DETACH_BOOTSTRAP_PE_POLICY_INVALID]: {code=ASTRO_DETACH_BOOTSTRAP_PE_POLICY_INVALID; message=`"compiled bootstrap is not one x64 PE32+ Windows GUI executable: machine=0x$($machine.ToString('x4')) sections=$sectionCount magic=0x$($magic.ToString('x4')) subsystem=$subsystem characteristics=0x$($characteristics.ToString('x4'))`"; remediation=`"preserve the output and correct the checked compiler target/options before task creation`"}"
    }
    $fileId = [AstroLauncherLockNative]::GetFileIdentity($ProtectedHandle)
    return [ordered]@{
        path = $snapshot.Path
        sha256 = $snapshot.Sha256
        bytes = [long]$snapshot.Length
        file_id = $fileId
        dos_magic = 'MZ'
        pe_signature = 'PE00'
        pe_offset = $peOffset
        machine = ('0x{0:x4}' -f $machine)
        section_count = [int]$sectionCount
        time_date_stamp = [uint32]$timeDateStamp
        optional_header_bytes = [int]$optionalBytes
        optional_header_magic = ('0x{0:x4}' -f $magic)
        subsystem = [int]$subsystem
        subsystem_name = 'IMAGE_SUBSYSTEM_WINDOWS_GUI'
        characteristics = ('0x{0:x4}' -f $characteristics)
        executable_image = $isExecutable
        dll = $isDll
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
$priorityPolicyResolved = Resolve-AstroDetachedPriorityPolicy `
    -Name $PriorityPolicy

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

$runDirectory = New-AstroDetachedRunDirectory $RunId
$powershellPath = Join-Path `
    ([Environment]::SystemDirectory) `
    'WindowsPowerShell\v1.0\powershell.exe'
$dotnetPath = 'C:\Program Files\dotnet\dotnet.exe'
$roslynVersion = '10.0.100'
$roslynCscPath = Join-Path `
    'C:\Program Files\dotnet\sdk' `
    "$roslynVersion\Roslyn\bincore\csc.dll"
$frameworkReferenceRoot =
    'C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8'
$frameworkReferencePaths = @(
    Join-Path $frameworkReferenceRoot 'mscorlib.dll'
    Join-Path $frameworkReferenceRoot 'System.dll'
    Join-Path $frameworkReferenceRoot 'System.Core.dll'
)
foreach ($requiredFile in @(
        $powershellPath,
        $dotnetPath,
        $roslynCscPath,
        $bootstrapSourcePath
    ) + $frameworkReferencePaths) {
    if (-not [IO.File]::Exists($requiredFile)) {
        throw "DETACH_RUN[ASTRO_DETACH_BOOTSTRAP_INPUT_MISSING]: {code=ASTRO_DETACH_BOOTSTRAP_INPUT_MISSING; message=`"required windowless-bootstrap input is missing: $requiredFile`"; remediation=`"restore the checked-in source or supported native Windows runtime before detached execution`"}"
    }
}
$bootstrapPath = Join-Path $runDirectory 'detach-bootstrap.exe'
$bootstrapCompilerLogPath = Join-Path $runDirectory 'bootstrap-compiler.log'
foreach ($outputPath in @($bootstrapPath, $bootstrapCompilerLogPath)) {
    if ([IO.File]::Exists($outputPath) -or [IO.Directory]::Exists($outputPath)) {
        throw "DETACH_RUN[ASTRO_DETACH_BOOTSTRAP_OUTPUT_COLLISION]: {code=ASTRO_DETACH_BOOTSTRAP_OUTPUT_COLLISION; message=`"bootstrap output is not absent: $outputPath`"; remediation=`"preserve the fresh-run collision and investigate run-directory admission; do not overwrite it`"}"
    }
}
$compilerState = $null
$compilerEvidence = $null
$compilerProcessRecord = $null
$compilerArtifactRecord = $null
$bootstrapArtifactLease = $null
$compilerProcessLease = $null
$bootstrapSourceLease = $null
$dotnetSourceLease = $null
$roslynSourceLease = $null
$frameworkReferenceLeases = @()
try {
    $compilerState = Start-AstroDetachedCompilerScope `
        -RunDirectory $runDirectory `
        -Role coordinator `
        -Issue $Issue
    . $lockHelperPath
    . $spawnPath

    $bootstrapSourceLease =
        [AstroLauncherLockNative]::OpenExactProtectedReadFile(
            $bootstrapSourcePath
        )
    $dotnetSourceLease =
        [AstroLauncherLockNative]::OpenProtectedOrdinaryReadFile($dotnetPath)
    $roslynSourceLease =
        [AstroLauncherLockNative]::OpenProtectedOrdinaryReadFile($roslynCscPath)
    foreach ($referencePath in $frameworkReferencePaths) {
        $frameworkReferenceLeases +=
            [AstroLauncherLockNative]::OpenProtectedOrdinaryReadFile(
                $referencePath
            )
    }
    $bootstrapSource = Read-AstroDetachedOrdinaryFile $bootstrapSourcePath
    $dotnetSource = Read-AstroDetachedOrdinaryFile $dotnetPath
    $roslynSource = Read-AstroDetachedOrdinaryFile $roslynCscPath
    $frameworkReferences = @(
        $frameworkReferencePaths |
            ForEach-Object { Read-AstroDetachedOrdinaryFile $_ }
    )
    $compilerArguments = @(
        'exec',
        $roslynCscPath,
        '/nologo',
        '/noconfig',
        '/nostdlib+',
        '/target:winexe',
        '/platform:x64',
        '/optimize+',
        '/debug-',
        '/deterministic+',
        '/checked+',
        '/warn:4',
        '/warnaserror+',
        '/langversion:7.3',
        "/pathmap:$script:AstroDetachedCanonicalRoot=/_/Astrolabe",
        "/reference:$($frameworkReferencePaths[0])",
        "/reference:$($frameworkReferencePaths[1])",
        "/reference:$($frameworkReferencePaths[2])",
        "/out:$bootstrapPath",
        $bootstrapSourcePath
    )
    $compilerProcessLease = Start-AstroDetachedProcessRetained `
        -FilePath $dotnetPath `
        -ArgumentList ([string[]]$compilerArguments) `
        -LogFile $bootstrapCompilerLogPath `
        -WorkingDirectory $script:AstroDetachedCanonicalRoot
    $compilerProcess = [ordered]@{
        pid = [int]$compilerProcessLease.ProcessId
        process_start_utc_ticks =
            [long]$compilerProcessLease.ProcessStartUtcTicks
        process_started_utc = [string]$compilerProcessLease.ProcessStartedUtc
        session_id = [int]$compilerProcessLease.SessionId
        application_path = [string]$compilerProcessLease.ApplicationPath
        command_line = [string]$compilerProcessLease.CommandLine
    }
    $compilerExitCode = [int]$compilerProcessLease.Wait()
    $compilerProcessLease.Dispose()
    $compilerProcessLease = $null
    $compilerLog = Read-AstroDetachedOrdinaryFile $bootstrapCompilerLogPath
    $bootstrapSourceReadback = Read-AstroDetachedOrdinaryFile $bootstrapSourcePath
    $dotnetSourceReadback = Read-AstroDetachedOrdinaryFile $dotnetPath
    $roslynSourceReadback = Read-AstroDetachedOrdinaryFile $roslynCscPath
    $frameworkReferenceReadbacks = @(
        $frameworkReferencePaths |
            ForEach-Object { Read-AstroDetachedOrdinaryFile $_ }
    )
    if ($bootstrapSourceReadback.Sha256 -cne $bootstrapSource.Sha256 -or
        $bootstrapSourceReadback.Length -ne $bootstrapSource.Length -or
        $dotnetSourceReadback.Sha256 -cne $dotnetSource.Sha256 -or
        $dotnetSourceReadback.Length -ne $dotnetSource.Length -or
        $roslynSourceReadback.Sha256 -cne $roslynSource.Sha256 -or
        $roslynSourceReadback.Length -ne $roslynSource.Length) {
        throw "DETACH_RUN[ASTRO_DETACH_BOOTSTRAP_COMPILER_INPUT_CHANGED]: {code=ASTRO_DETACH_BOOTSTRAP_COMPILER_INPUT_CHANGED; message=`"compiler source or executable changed across exact retained execution`"; remediation=`"preserve all run/compiler bytes and inspect the recorded file identities and hashes`"}"
    }
    for ($referenceIndex = 0;
        $referenceIndex -lt $frameworkReferences.Count;
        $referenceIndex++) {
        if ($frameworkReferenceReadbacks[$referenceIndex].Sha256 -cne
                $frameworkReferences[$referenceIndex].Sha256 -or
            $frameworkReferenceReadbacks[$referenceIndex].Length -ne
                $frameworkReferences[$referenceIndex].Length) {
            throw "DETACH_RUN[ASTRO_DETACH_BOOTSTRAP_REFERENCE_CHANGED]: {code=ASTRO_DETACH_BOOTSTRAP_REFERENCE_CHANGED; message=`"framework reference changed across exact retained compilation: $($frameworkReferences[$referenceIndex].Path)`"; remediation=`"preserve all run/compiler bytes and inspect the exact file identity and hash`"}"
        }
    }
    if ($compilerExitCode -ne 0) {
        $compilerProcessRecord = Write-AstroDetachedCompilerRecord `
            -RunDirectory $runDirectory `
            -Role coordinator `
            -Stage process `
            -Payload ([ordered]@{
                issue = $Issue
                source = [ordered]@{
                    path = $bootstrapSource.Path
                    sha256 = $bootstrapSource.Sha256
                    bytes = [long]$bootstrapSource.Length
                    file_id = [AstroLauncherLockNative]::GetFileIdentity(
                        $bootstrapSourceLease
                    )
                }
                compiler = [ordered]@{
                    host_path = $dotnetSource.Path
                    host_sha256 = $dotnetSource.Sha256
                    roslyn_version = $roslynVersion
                    roslyn_path = $roslynSource.Path
                    roslyn_sha256 = $roslynSource.Sha256
                    process = $compilerProcess
                    arguments = [string[]]$compilerArguments
                    exit_code = $compilerExitCode
                    log_path = $compilerLog.Path
                    log_sha256 = $compilerLog.Sha256
                    log_bytes = [long]$compilerLog.Length
                }
                outcome = 'known-compiler-nonzero'
                artifact_admitted = $false
                policy = [ordered]@{
                    retry_or_fallback = $false
                    exact_owner_cleanup_before_outer_failure = $true
                    unknown_fault_preservation_unchanged = $true
                }
            })
        $compilerEvidence = Complete-AstroDetachedCompilerScope $compilerState
        throw "DETACH_RUN[ASTRO_DETACH_BOOTSTRAP_COMPILE_FAILED]: {code=ASTRO_DETACH_BOOTSTRAP_COMPILE_FAILED; message=`"exact csc child exited $compilerExitCode; log=$bootstrapCompilerLogPath sha256=$($compilerLog.Sha256); process_record=$($compilerProcessRecord.Path) sha256=$($compilerProcessRecord.Sha256)`"; remediation=`"the exact live owner removed its compiler scope; preserve the run records/log and fix the reported source error before creating a fresh run`"}"
    }
    $bootstrapArtifactLease =
        [AstroLauncherLockNative]::OpenExactProtectedReadFile($bootstrapPath)
    $bootstrapPe = Get-AstroDetachedPeSnapshot `
        -Path $bootstrapPath `
        -ProtectedHandle $bootstrapArtifactLease
    $compilerArtifactRecord = Write-AstroDetachedCompilerRecord `
        -RunDirectory $runDirectory `
        -Role coordinator `
        -Stage artifact `
        -Payload ([ordered]@{
            issue = $Issue
            source = [ordered]@{
                path = $bootstrapSource.Path
                sha256 = $bootstrapSource.Sha256
                bytes = [long]$bootstrapSource.Length
                file_id = [AstroLauncherLockNative]::GetFileIdentity(
                    $bootstrapSourceLease
                )
            }
            compiler = [ordered]@{
                host_path = $dotnetSource.Path
                host_sha256 = $dotnetSource.Sha256
                host_bytes = [long]$dotnetSource.Length
                host_file_id = [AstroLauncherLockNative]::GetFileIdentity(
                    $dotnetSourceLease
                )
                roslyn_version = $roslynVersion
                roslyn_path = $roslynSource.Path
                roslyn_sha256 = $roslynSource.Sha256
                roslyn_bytes = [long]$roslynSource.Length
                roslyn_file_id = [AstroLauncherLockNative]::GetFileIdentity(
                    $roslynSourceLease
                )
                framework_reference_root = $frameworkReferenceRoot
                framework_references = @(
                    for ($referenceIndex = 0;
                        $referenceIndex -lt $frameworkReferences.Count;
                        $referenceIndex++) {
                        [ordered]@{
                            path = $frameworkReferences[$referenceIndex].Path
                            sha256 =
                                $frameworkReferences[$referenceIndex].Sha256
                            bytes = [long](
                                $frameworkReferences[$referenceIndex].Length
                            )
                            file_id =
                                [AstroLauncherLockNative]::GetFileIdentity(
                                    $frameworkReferenceLeases[$referenceIndex]
                                )
                        }
                    }
                )
                process = $compilerProcess
                arguments = [string[]]$compilerArguments
                exit_code = $compilerExitCode
                log_path = $compilerLog.Path
                log_sha256 = $compilerLog.Sha256
                log_bytes = [long]$compilerLog.Length
            }
            artifact = $bootstrapPe
            policy = [ordered]@{
                compile_count = 1
                process_count = 1
                output_publication = 'fresh-run-direct-create'
                task_admission = 'x64-pe32-plus-windows-gui-only'
                retained_artifact_lease = $true
                retry_or_fallback = $false
            }
        })
    $compilerEvidence = Complete-AstroDetachedCompilerScope $compilerState
}
catch {
    $compilerFailure = $_
    $compilerWaitFailure = $null
    if ($null -ne $compilerProcessLease) {
        try {
            [void]$compilerProcessLease.Wait()
        }
        catch {
            $compilerWaitFailure = $_.Exception.Message
        }
        $compilerProcessLease.Dispose()
        $compilerProcessLease = $null
    }
    if ($null -ne $bootstrapArtifactLease) {
        $bootstrapArtifactLease.Dispose()
        $bootstrapArtifactLease = $null
    }
    $compilerFailureMessage = $compilerFailure.Exception.Message
    if ($null -ne $compilerWaitFailure) {
        $compilerFailureMessage +=
            " | exact compiler cleanup wait also failed: $compilerWaitFailure"
    }
    if ($null -ne $compilerState) {
        $compilerScopeTerminal = $null -ne $compilerEvidence -and
            [string]$compilerEvidence.ScopeState -ceq 'absent' -and
            [string]$compilerEvidence.TombstoneState -ceq 'absent'
        $compilerFaultRemediation = if ($compilerScopeTerminal) {
            'compiler scope reached exact-owner terminal absence; preserve the ' +
            'run records/log and fix the reported compiler error before a fresh run'
        }
        else {
            'preserve the run and compiler scope; inspect the immutable ' +
            'compiler intent/fault before tracker-bound recovery'
        }
        try {
            [void](Write-AstroDetachedCompilerFault `
                -State $compilerState `
                -Code 'ASTRO_DETACH_COORDINATOR_COMPILER_FAILED' `
                -Message $compilerFailureMessage `
                -Remediation $compilerFaultRemediation `
                -Stage 'coordinator-import-or-cleanup')
        }
        catch {
            throw "DETACH_RUN[ASTRO_DETACH_COMPILER_FAULT_PUBLISH_FAILED]: {code=ASTRO_DETACH_COMPILER_FAULT_PUBLISH_FAILED; message=`"coordinator compiler failed ('$($compilerFailure.Exception.Message)') and its durable fault also failed ('$($_.Exception.Message)')`"; remediation=`"preserve every run/compiler byte and inspect both failures before recovery`"}"
        }
    }
    throw "DETACH_RUN[ASTRO_DETACH_COORDINATOR_COMPILER_FAILED]: {code=ASTRO_DETACH_COORDINATOR_COMPILER_FAILED; message=`"$compilerFailureMessage`"; remediation=`"preserve the run and inspect compiler-state records; do not create or start a task`"}"
}
finally {
    foreach ($referenceLease in $frameworkReferenceLeases) {
        $referenceLease.Dispose()
    }
    if ($null -ne $roslynSourceLease) { $roslynSourceLease.Dispose() }
    if ($null -ne $dotnetSourceLease) { $dotnetSourceLease.Dispose() }
    if ($null -ne $bootstrapSourceLease) { $bootstrapSourceLease.Dispose() }
}

try {
$bindings = [ordered]@{
    protocol = Get-AstroDetachedScriptBinding $protocolPath
    strict_json = Get-AstroDetachedScriptBinding $strictJsonPath
    compiler_state = Get-AstroDetachedScriptBinding $compilerStatePath
    launcher_lock = Get-AstroDetachedScriptBinding $lockHelperPath
    spawn = Get-AstroDetachedScriptBinding $spawnPath
    runner = Get-AstroDetachedScriptBinding $runnerPath
    bootstrap_source = Get-AstroDetachedScriptBinding $bootstrapSourcePath
    launcher = Get-AstroDetachedScriptBinding $launcherPath
}
if ($bindings.bootstrap_source.sha256 -cne $bootstrapSource.Sha256) {
    throw "DETACH_RUN[ASTRO_DETACH_BOOTSTRAP_SOURCE_CHANGED_AFTER_COMPILE]: {code=ASTRO_DETACH_BOOTSTRAP_SOURCE_CHANGED_AFTER_COMPILE; message=`"checked-in bootstrap source changed after the retained compiler child: compiled=$($bootstrapSource.Sha256) observed=$($bindings.bootstrap_source.sha256)`"; remediation=`"preserve the compiled artifact/evidence and start no task from an output whose source binding changed`"}"
}
$powershellBinding = Get-AstroDetachedScriptBinding $powershellPath
$actionValues = @(
    '--run-directory', $runDirectory,
    '--run-id', $RunId,
    '--powershell-path', $powershellPath,
    '--powershell-sha256', $powershellBinding.sha256,
    '--runner-path', $runnerPath,
    '--runner-sha256', $bindings.runner.sha256,
    '--bootstrap-path', $bootstrapPath,
    '--bootstrap-sha256', $bootstrapPe.sha256,
    '--working-directory', $script:AstroDetachedCanonicalRoot
)
$actionArguments = (
    $actionValues |
        ForEach-Object { [AstroDetachV2]::QuoteArgument([string]$_) }
) -join ' '

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
        priority_policy = $priorityPolicyResolved
        s4u_isolated_local_fsv = [bool]$AllowS4UIsolatedLocalFsv
        principal_user_id = $principal
        principal_sid = $principalSid
        powershell_path = $powershellPath
        powershell_sha256 = $powershellBinding.sha256
        psmodulepath_policy = $modulePathPolicy
        protocol_path = $bindings.protocol.path
        protocol_sha256 = $bindings.protocol.sha256
        strict_json_path = $bindings.strict_json.path
        strict_json_sha256 = $bindings.strict_json.sha256
        compiler_state_path = $bindings.compiler_state.path
        compiler_state_sha256 = $bindings.compiler_state.sha256
        launcher_lock_path = $bindings.launcher_lock.path
        launcher_lock_sha256 = $bindings.launcher_lock.sha256
        spawn_path = $bindings.spawn.path
        spawn_sha256 = $bindings.spawn.sha256
        runner_path = $bindings.runner.path
        runner_sha256 = $bindings.runner.sha256
        bootstrap_source_path = $bindings.bootstrap_source.path
        bootstrap_source_sha256 = $bindings.bootstrap_source.sha256
        bootstrap_path = $bootstrapPe.path
        bootstrap_sha256 = $bootstrapPe.sha256
        bootstrap_bytes = $bootstrapPe.bytes
        bootstrap_file_id = $bootstrapPe.file_id
        bootstrap_subsystem = $bootstrapPe.subsystem
        bootstrap_subsystem_name = $bootstrapPe.subsystem_name
        bootstrap_compiler_artifact_path = $compilerArtifactRecord.Path
        bootstrap_compiler_artifact_sha256 = $compilerArtifactRecord.Sha256
        bootstrap_action_arguments = $actionArguments
        launcher_path = $bindings.launcher.path
        launcher_sha256 = $bindings.launcher.sha256
        coordinator_compiler = [ordered]@{
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

$taskService = $null
$registered = $null
$taskSnapshot = $null
$taskRecord = $null
$taskCreated = $false
$taskStarted = $false
$preserveTaskOnPriorityMismatch = $false
$prestartStage = 'task-service-connect'
try {
    $taskService = Get-AstroDetachedTaskService
    $prestartStage = 'task-create'
    $registered = Register-AstroDetachedTaskCreateOnly `
        -TaskService $taskService `
        -TaskName $taskNameExact `
        -PrincipalUserId $principal `
        -LogonType $TaskLogonType `
        -ActionPath $bootstrapPath `
        -ActionArguments $actionArguments `
        -WorkingDirectory $script:AstroDetachedCanonicalRoot `
        -Description "Astrolabe issue #$Issue detached launcher run $RunId" `
        -SchedulerPriority ([int]$priorityPolicyResolved.scheduler_priority)
    $taskCreated = $true
    $prestartStage = 'task-first-readback'
    $taskSnapshot = Get-AstroDetachedTaskSnapshot $registered
    $expectedLogon = if ($TaskLogonType -ceq 'InteractiveToken') { 3 } else { 2 }
    if (-not $taskSnapshot.xml_priority_present -or
        $taskSnapshot.scheduler_priority -ne
            [int]$priorityPolicyResolved.scheduler_priority -or
        $taskSnapshot.xml_priority -ne
            [int]$priorityPolicyResolved.scheduler_priority) {
        $preserveTaskOnPriorityMismatch = $true
        throw "DETACH_RUN[ASTRO_DETACH_TASK_PRIORITY_MISMATCH]: {code=ASTRO_DETACH_TASK_PRIORITY_MISMATCH; message=`"registered task priority differs from the named policy: expected=$($priorityPolicyResolved.scheduler_priority) com=$($taskSnapshot.scheduler_priority) xml=$($taskSnapshot.xml_priority) explicit=$($taskSnapshot.xml_priority_present)`"; remediation=`"preserve the exact task and run directory; inspect Task Scheduler normalization without reprioritizing the live definition`"}"
    }
    if ($taskSnapshot.path -cne "\$taskNameExact" -or
        $taskSnapshot.name -cne $taskNameExact -or
        -not $taskSnapshot.enabled -or
        [string]::IsNullOrWhiteSpace($taskSnapshot.principal_user_id) -or
        $taskSnapshot.principal_sid -cne $principalSid -or
        $taskSnapshot.principal_logon_type -ne $expectedLogon -or
        $taskSnapshot.principal_run_level -ne 0 -or
        $taskSnapshot.action_count -ne 1 -or
        $taskSnapshot.action_path -cne $bootstrapPath -or
        $taskSnapshot.action_arguments -cne $actionArguments -or
        $taskSnapshot.action_working_directory -cne
            $script:AstroDetachedCanonicalRoot -or
        $taskSnapshot.hidden -or
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
            priority_policy = $priorityPolicyResolved
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
    if ($taskCreated -and -not $taskStarted -and
        -not $preserveTaskOnPriorityMismatch) {
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
        foreach ($priorityBinding in @(
                @{
                    Candidate = $runnerRecord.Payload.priority_policy
                    Context = 'runner record'
                },
                @{
                    Candidate = $boundaryRecord.Payload.priority_policy
                    Context = 'boundary record'
                },
                @{
                    Candidate = $workRecord.Payload.priority_policy
                    Context = 'work record'
                },
                @{
                    Candidate = $leaseRecord.Payload.priority_policy
                    Context = 'launcher-lease record'
                }
            )) {
            Assert-AstroDetachedPriorityPolicyBinding `
                -Candidate $priorityBinding.Candidate `
                -Expected $priorityPolicyResolved `
                -Context $priorityBinding.Context
        }
        $bootstrapStart = Read-AstroDetachedBootstrapRecord `
            -RunDirectory $runDirectory `
            -Name 'bootstrap-start.json'
        $bootstrapValues = $bootstrapStart.Values
        if ($bootstrapValues.bootstrap_path -cne $bootstrapPath -or
            $bootstrapValues.bootstrap_sha256 -cne $bootstrapPe.sha256 -or
            $bootstrapValues.bootstrap_bytes -ne $bootstrapPe.bytes -or
            $bootstrapValues.powershell_path -cne $powershellPath -or
            $bootstrapValues.powershell_sha256 -cne
                $powershellBinding.sha256 -or
            $bootstrapValues.runner_path -cne $runnerPath -or
            $bootstrapValues.runner_sha256 -cne $bindings.runner.sha256 -or
            $bootstrapValues.working_directory -cne
                $script:AstroDetachedCanonicalRoot -or
            $bootstrapValues.creation_flags -ne 134743552 -or
            $bootstrapValues.startup_show_window -ne 0 -or
            $bootstrapValues.runner_log_path -cne
                (Join-Path $runDirectory 'bootstrap-runner.log')) {
            throw "DETACH_RUN[ASTRO_DETACH_BOOTSTRAP_START_MISMATCH]: {code=ASTRO_DETACH_BOOTSTRAP_START_MISMATCH; message=`"bootstrap start record differs from the retained artifact/task intent`"; remediation=`"preserve the run/task/process bytes and inspect the exact binding that changed`"}"
        }
        $liveTaskReadback = Get-AstroDetachedTaskSnapshot (
            Get-AstroDetachedRegisteredTask `
                -TaskService $taskService `
                -TaskName $taskNameExact
        )
        if ($liveTaskReadback.xml_sha256 -cne $taskSnapshot.xml_sha256 -or
            -not $liveTaskReadback.xml_priority_present -or
            $liveTaskReadback.scheduler_priority -ne
                [int]$priorityPolicyResolved.scheduler_priority -or
            $liveTaskReadback.xml_priority -ne
                [int]$priorityPolicyResolved.scheduler_priority) {
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
            -SessionId ([int]$runnerRecord.Payload.identity.session_id) `
            -ExpectedPriorityClass (
                [string]$priorityPolicyResolved.process_priority_class
            ) `
            -ExpectedBasePriority (
                [int]$priorityPolicyResolved.process_base_priority
            )
        $bootstrapProbe = Get-AstroDetachedProcessProbe `
            -ProcessId ([int]$bootstrapValues.bootstrap_pid) `
            -ProcessStartUtcTicks (
                [long]$bootstrapValues.bootstrap_start_utc_ticks
            ) `
            -SessionId ([int]$bootstrapValues.bootstrap_session_id) `
            -ExpectedPriorityClass (
                [string]$priorityPolicyResolved.process_priority_class
            ) `
            -ExpectedBasePriority (
                [int]$priorityPolicyResolved.process_base_priority
            )
        $boundaryProbe = Get-AstroDetachedProcessProbe `
            -ProcessId ([int]$boundaryRecord.Payload.identity.pid) `
            -ProcessStartUtcTicks (
                [long]$boundaryRecord.Payload.identity.process_start_utc_ticks
            ) `
            -SessionId ([int]$boundaryRecord.Payload.identity.session_id) `
            -ExpectedPriorityClass (
                [string]$priorityPolicyResolved.process_priority_class
            ) `
            -ExpectedBasePriority (
                [int]$priorityPolicyResolved.process_base_priority
            )
        $workProbe = Get-AstroDetachedProcessProbe `
            -ProcessId ([int]$workRecord.Payload.identity.pid) `
            -ProcessStartUtcTicks (
                [long]$workRecord.Payload.identity.process_start_utc_ticks
            ) `
            -SessionId ([int]$workRecord.Payload.identity.session_id) `
            -ExpectedPriorityClass (
                [string]$priorityPolicyResolved.process_priority_class
            ) `
            -ExpectedBasePriority (
                [int]$priorityPolicyResolved.process_base_priority
            )
        if ($bootstrapProbe.state -cne 'exact-live' -or
            $runnerProbe.state -cne 'exact-live' -or
            $boundaryProbe.state -cne 'exact-live' -or
            $workProbe.state -cne 'exact-live') {
            throw "DETACH_RUN[ASTRO_DETACH_READY_OWNER_NOT_LIVE]: {code=ASTRO_DETACH_READY_OWNER_NOT_LIVE; message=`"bootstrap/runner/boundary/work probes are not all exact-live with the declared priority: bootstrap=$($bootstrapProbe.state), runner=$($runnerProbe.state), boundary=$($boundaryProbe.state), work=$($workProbe.state)`"; remediation=`"read terminal records instead of claiming live readiness; preserve any priority mismatch`"}"
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
            priority_policy = $priorityPolicyResolved
            task_scheduler_priority = $taskSnapshot.scheduler_priority
            task_xml_priority = $taskSnapshot.xml_priority
            task_session_id = [int]$runnerRecord.Payload.identity.session_id
            bootstrap_identity = [ordered]@{
                pid = [int]$bootstrapValues.bootstrap_pid
                process_start_utc_ticks =
                    [long]$bootstrapValues.bootstrap_start_utc_ticks
                session_id = [int]$bootstrapValues.bootstrap_session_id
            }
            bootstrap_start_path = $bootstrapStart.Path
            bootstrap_start_sha256 = $bootstrapStart.Sha256
            runner_identity = $runnerRecord.Payload.identity
            runner_priority_probe = $runnerProbe
            launcher_boundary_identity = $boundaryRecord.Payload.identity
            launcher_boundary_priority_probe = $boundaryProbe
            work_launcher_identity = $workRecord.Payload.identity
            work_launcher_priority_probe = $workProbe
            authoritative_lock_sha256 = [string]$lastLock.Sha256
            lifecycle_head_name = $leaseRecord.Name
            lifecycle_head_sha256 = $leaseRecord.Sha256
            launcher_log = Join-Path $runDirectory 'launcher.log'
        }
        Write-Output (
            'DETACH_RUN[ASTRO_DETACH_STARTED]: ' +
            ($result | ConvertTo-Json -Depth 8 -Compress)
        )
        $bootstrapArtifactLease.Dispose()
        $bootstrapArtifactLease = $null
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
        if ($fault.Name -ceq 'bootstrap-fault.json') {
            $bootstrapFault = Read-AstroDetachedBootstrapRecord `
                -RunDirectory $runDirectory `
                -Name 'bootstrap-fault.json'
            throw "DETACH_RUN[ASTRO_DETACH_BOOTSTRAP_FAULT_RECORDED]: {code=$($bootstrapFault.Values.code); stage=$($bootstrapFault.Values.stage); native_error=$($bootstrapFault.Values.native_error); message=`"$($bootstrapFault.Values.message)`"; remediation=`"$($bootstrapFault.Values.remediation)`"}"
        }
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
}
finally {
    if ($null -ne $bootstrapArtifactLease) {
        $bootstrapArtifactLease.Dispose()
        $bootstrapArtifactLease = $null
    }
}
