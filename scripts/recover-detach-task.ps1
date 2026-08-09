<#
.SYNOPSIS
    Tracker-bound recovery of one stranded detached scheduled task.

.DESCRIPTION
    Prepare binds one exact append-only detached run chain, registered-task XML and
    runtime state, every recorded process generation, launcher/target absence, the
    current principal, and the recovery implementation without granting deletion
    authority. Recover verifies the owner-authored tracker line twice, positively
    acquires the canonical launcher mutex, repeats every physical probe, durably
    finalizes the exact Task Scheduler deletion, removes only that XML-bound task,
    independently reads absence through a fresh Task Scheduler service, appends one
    terminal record to the existing run chain, and completes the recovery transaction.

    A recovery interrupted after finalization resumes only the same immutable
    transaction. It never retries an ordinary launcher, stops a process, infers an
    owner from a numeric PID, rewrites a record, or treats an API return as proof.
    Refs #1066.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Prepare', 'Recover')]
    [string]$Operation,
    [Parameter(Mandatory)][int]$Issue,
    [Parameter(Mandatory)][string]$RunId,
    [string]$TransactionId = '',
    [string]$ExpectedProbeSha256 = '',
    [string]$TrackerCommentUrl = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$protocolPath = Join-Path $PSScriptRoot 'detach-protocol.ps1'
$strictJsonPath = Join-Path $PSScriptRoot 'detach-strict-json.ps1'
$lockHelperPath = Join-Path $PSScriptRoot 'launcher-lock.ps1'
. $protocolPath

$script:AstroTaskRecoveryMaximumBytes = 8MB
$script:AstroTaskRecoveryTransaction = $null
$script:AstroTaskRecoveryWritingFault = $false

function Get-AstroTaskRecoveryPrincipal {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return [ordered]@{
        name = [string]$identity.Name
        sid = [string]$identity.User.Value
        process = Get-AstroDetachedCurrentIdentity
    }
}

function Get-AstroTaskRecoveryScriptBinding {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.File]::Exists($full)) {
        throw "bound recovery dependency is missing: $full"
    }
    return [ordered]@{
        path = $full
        sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.
            ToLowerInvariant()
    }
}

function Write-AstroTaskRecoveryDurableJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Document
    )

    $bytes = Get-AstroDetachedUtf8Bytes (
        $Document | ConvertTo-Json -Depth 64 -Compress
    )
    if ($bytes.Length -gt $script:AstroTaskRecoveryMaximumBytes) {
        throw "task-recovery record exceeds maximum bytes: $Path / $($bytes.Length)"
    }
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    $readback = Read-AstroDetachedOrdinaryFile $Path
    $expected = Get-AstroDetachedSha256Bytes $bytes
    if ($readback.Length -ne $bytes.Length -or
        $readback.Sha256 -cne $expected) {
        throw "task-recovery durable readback differs after create-new write: $Path"
    }
    return [pscustomobject]@{
        Path = $readback.Path
        Sha256 = $readback.Sha256
        Length = $readback.Length
        Document = $Document
    }
}

function Write-AstroTaskRecoveryAuxRecord {
    param(
        [Parameter(Mandatory)][string]$TransactionDirectory,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Payload
    )

    $transaction = Assert-AstroDetachedOrdinaryDirectory $TransactionDirectory
    if ([IO.Path]::GetFileName($transaction) -cnotmatch
            '^task-recovery-[0-9a-f]{32}\.dir$' -or
        $Name -cnotmatch '^[a-z0-9.-]+\.json$') {
        throw "task-recovery auxiliary path is noncanonical: $transaction / $Name"
    }
    $payloadBytes = Get-AstroDetachedUtf8Bytes (
        $Payload | ConvertTo-Json -Depth 64 -Compress
    )
    $document = [ordered]@{
        schema = 'astrolabe.detached-task-recovery-aux.v1'
        run_id = $RunId
        transaction_id = $TransactionId
        name = $Name
        written_utc_ticks = [DateTime]::UtcNow.Ticks
        writer = Get-AstroDetachedCurrentIdentity
        payload_sha256 = Get-AstroDetachedSha256Bytes $payloadBytes
        payload_bytes = [long]$payloadBytes.Length
        payload_json_base64 = [Convert]::ToBase64String($payloadBytes)
    }
    return Write-AstroTaskRecoveryDurableJson `
        -Path (Join-Path $transaction $Name) `
        -Document $document
}

function Fail-AstroTaskRecovery {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Remediation
    )

    $document = [ordered]@{
        schema = 'astrolabe.detached-task-recovery-error.v1'
        code = $Code
        message = $Message
        remediation = $Remediation
    }
    [Console]::Error.WriteLine(($document | ConvertTo-Json -Compress))
    if ($null -ne $script:AstroTaskRecoveryTransaction -and
        -not $script:AstroTaskRecoveryWritingFault) {
        $script:AstroTaskRecoveryWritingFault = $true
        try {
            $name = 'fault.{0}.pid-{1}.json' -f
                [DateTime]::UtcNow.Ticks, $PID
            [void](Write-AstroTaskRecoveryAuxRecord `
                -TransactionDirectory $script:AstroTaskRecoveryTransaction `
                -Name $name `
                -Payload ([ordered]@{
                    operation = $Operation
                    issue = $Issue
                    run_id = $RunId
                    transaction_id = $TransactionId
                    code = $Code
                    message = $Message
                    remediation = $Remediation
                }))
        }
        catch {
            [Console]::Error.WriteLine(
                'ASTRO_DETACHED_TASK_RECOVERY_FAULT_RECORD_FAILED: ' +
                $_.Exception.Message
            )
        }
        finally {
            $script:AstroTaskRecoveryWritingFault = $false
        }
    }
    $exception = [InvalidOperationException]::new($Message)
    $exception.Data['AstroCode'] = $Code
    $exception.Data['AstroRemediation'] = $Remediation
    throw $exception
}

function Get-AstroTaskRecoveryRunDirectory {
    if ($RunId -cnotmatch '^[0-9a-f]{32}$') {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_RUN_ID_INVALID' `
            "run ID must be 32 lowercase hexadecimal characters: '$RunId'" `
            'pass the exact stranded detached run ID'
    }
    return Assert-AstroDetachedRunDirectory (
        Join-Path $script:AstroDetachedStateRoot $RunId
    )
}

function Get-AstroTaskRecoveryTransactionDirectory {
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)][string]$Id,
        [switch]$AllowCreate
    )

    if ($Id -cnotmatch '^[0-9a-f]{32}$') {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_TRANSACTION_INVALID' `
            "transaction ID is not a canonical GUID N value: '$Id'" `
            'pass the exact transaction ID printed by Prepare'
    }
    $run = Assert-AstroDetachedRunDirectory $RunDirectory
    $leaf = "task-recovery-$Id.dir"
    $path = [IO.Path]::GetFullPath((Join-Path $run $leaf))
    if ([IO.Path]::GetDirectoryName($path).TrimEnd('\', '/') -cne $run -or
        [IO.Path]::GetFileName($path) -cne $leaf) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_TRANSACTION_ESCAPE' `
            "transaction escaped the exact run: $path" `
            'preserve the run and use only the canonical transaction binding'
    }
    if ($AllowCreate) {
        [void](New-AstroDetachedDirectoryNoReplace $path)
    }
    return Assert-AstroDetachedOrdinaryDirectory $path
}

function Write-AstroTaskRecoveryRecord {
    param(
        [Parameter(Mandatory)][string]$TransactionDirectory,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Sequence,
        [AllowEmptyString()][string]$PreviousName = '',
        [AllowEmptyString()][string]$PreviousSha256 = '',
        [Parameter(Mandatory)]$Payload
    )

    $transaction = Assert-AstroDetachedOrdinaryDirectory $TransactionDirectory
    if ([IO.Path]::GetFileName($transaction) -cnotmatch
            '^task-recovery-[0-9a-f]{32}\.dir$' -or
        $Name -cnotmatch '^[0-9]{3}-[a-z0-9-]+\.json$' -or
        $Sequence -lt 0 -or
        -not $Name.StartsWith(
            ('{0:d3}-' -f $Sequence),
            [StringComparison]::Ordinal
        ) -or
        ($Sequence -eq 0 -and
            (-not [string]::IsNullOrEmpty($PreviousName) -or
             -not [string]::IsNullOrEmpty($PreviousSha256))) -or
        ($Sequence -gt 0 -and
            ($PreviousName -cnotmatch '^[0-9]{3}-[a-z0-9-]+\.json$' -or
             $PreviousSha256 -cnotmatch '^[0-9a-f]{64}$'))) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_RECORD_BINDING_INVALID' `
            "record path/link is invalid: $transaction / $Name / $Sequence" `
            'preserve the transaction and use canonical append-only links'
    }
    $payloadBytes = Get-AstroDetachedUtf8Bytes (
        $Payload | ConvertTo-Json -Depth 64 -Compress
    )
    $writer = Get-AstroDetachedCurrentIdentity
    $document = [ordered]@{
        schema = 'astrolabe.detached-task-recovery-record.v1'
        run_id = $RunId
        transaction_id = $TransactionId
        sequence = $Sequence
        name = $Name
        written_utc_ticks = [DateTime]::UtcNow.Ticks
        writer_pid = [int]$writer.pid
        writer_process_start_utc_ticks =
            [long]$writer.process_start_utc_ticks
        writer_session_id = [int]$writer.session_id
        previous_name = $PreviousName
        previous_sha256 = $PreviousSha256
        payload_sha256 = Get-AstroDetachedSha256Bytes $payloadBytes
        payload_bytes = [long]$payloadBytes.Length
        payload_json_base64 = [Convert]::ToBase64String($payloadBytes)
    }
    $written = Write-AstroTaskRecoveryDurableJson `
        -Path (Join-Path $transaction $Name) `
        -Document $document
    return [pscustomobject]@{
        Name = $Name
        Path = $written.Path
        Sequence = $Sequence
        Sha256 = $written.Sha256
        Length = $written.Length
        Document = [pscustomobject]$document
        Payload = $Payload
    }
}

function Read-AstroTaskRecoveryRecord {
    param(
        [Parameter(Mandatory)][string]$TransactionDirectory,
        [Parameter(Mandatory)][string]$Name,
        [AllowEmptyString()][string]$ExpectedSha256 = ''
    )

    $transaction = Assert-AstroDetachedOrdinaryDirectory $TransactionDirectory
    if ($Name -cnotmatch '^[0-9]{3}-[a-z0-9-]+\.json$') {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_RECORD_NAME_INVALID' `
            "record name is noncanonical: $Name" `
            'pass an exact recovery record name'
    }
    $snapshot = Read-AstroDetachedOrdinaryFile (Join-Path $transaction $Name)
    if (-not [string]::IsNullOrEmpty($ExpectedSha256) -and
        $snapshot.Sha256 -cne $ExpectedSha256) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_RECORD_HASH_DRIFT' `
            "record hash differs: $Name expected=$ExpectedSha256 observed=$($snapshot.Sha256)" `
            'preserve every transaction byte and pass the exact Prepare result'
    }
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString(
            $snapshot.Bytes
        )
        $strict = ConvertFrom-AstroStrictFlatJsonObject -Json $text
        $required = @(
            'schema',
            'run_id',
            'transaction_id',
            'sequence',
            'name',
            'written_utc_ticks',
            'writer_pid',
            'writer_process_start_utc_ticks',
            'writer_session_id',
            'previous_name',
            'previous_sha256',
            'payload_sha256',
            'payload_bytes',
            'payload_json_base64'
        )
        $names = @($strict.Names)
        if ($names.Count -ne $required.Count) {
            throw 'record property count differs from the exact v1 envelope'
        }
        for ($index = 0; $index -lt $required.Count; $index++) {
            if ([string]$names[$index] -cne $required[$index]) {
                throw "record property order differs at index $index"
            }
        }
        foreach ($propertyName in @(
                'schema', 'run_id', 'transaction_id', 'name',
                'previous_name', 'previous_sha256', 'payload_sha256',
                'payload_json_base64'
            )) {
            if ($strict.Properties[$propertyName].Kind -cne 'string') {
                throw "record property '$propertyName' is not a string"
            }
        }
        foreach ($propertyName in @(
                'sequence', 'written_utc_ticks', 'writer_pid',
                'writer_process_start_utc_ticks', 'writer_session_id',
                'payload_bytes'
            )) {
            if ($strict.Properties[$propertyName].Kind -cne 'integer') {
                throw "record property '$propertyName' is not an integer"
            }
        }
        $document = [pscustomobject]@{
            schema = [string]$strict.Properties['schema'].Value
            run_id = [string]$strict.Properties['run_id'].Value
            transaction_id =
                [string]$strict.Properties['transaction_id'].Value
            sequence = [int64]::Parse(
                [string]$strict.Properties['sequence'].Raw,
                [Globalization.CultureInfo]::InvariantCulture
            )
            name = [string]$strict.Properties['name'].Value
            written_utc_ticks = [int64]::Parse(
                [string]$strict.Properties['written_utc_ticks'].Raw,
                [Globalization.CultureInfo]::InvariantCulture
            )
            writer_pid = [int64]::Parse(
                [string]$strict.Properties['writer_pid'].Raw,
                [Globalization.CultureInfo]::InvariantCulture
            )
            writer_process_start_utc_ticks = [int64]::Parse(
                [string]$strict.Properties[
                    'writer_process_start_utc_ticks'
                ].Raw,
                [Globalization.CultureInfo]::InvariantCulture
            )
            writer_session_id = [int64]::Parse(
                [string]$strict.Properties['writer_session_id'].Raw,
                [Globalization.CultureInfo]::InvariantCulture
            )
            previous_name =
                [string]$strict.Properties['previous_name'].Value
            previous_sha256 =
                [string]$strict.Properties['previous_sha256'].Value
            payload_sha256 =
                [string]$strict.Properties['payload_sha256'].Value
            payload_bytes = [int64]::Parse(
                [string]$strict.Properties['payload_bytes'].Raw,
                [Globalization.CultureInfo]::InvariantCulture
            )
            payload_json_base64 =
                [string]$strict.Properties['payload_json_base64'].Value
        }
        $payloadBytes = [Convert]::FromBase64String(
            [string]$document.payload_json_base64
        )
        $payload = ConvertFrom-Json -InputObject (
            [Text.UTF8Encoding]::new($false, $true).GetString($payloadBytes)
        )
    }
    catch {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_RECORD_DECODE_FAILED' `
            "record decode failed for $Name`: $($_.Exception.Message)" `
            'preserve the transaction and inspect its exact bytes'
    }
    if ([string]$document.schema -cne
            'astrolabe.detached-task-recovery-record.v1' -or
        [string]$document.run_id -cne $RunId -or
        [string]$document.transaction_id -cne $TransactionId -or
        [string]$document.name -cne $Name -or
        [int64]$document.sequence -lt 0 -or
        -not $Name.StartsWith(
            ('{0:d3}-' -f [int64]$document.sequence),
            [StringComparison]::Ordinal
        ) -or
        [int64]$document.written_utc_ticks -le 0 -or
        [int64]$document.writer_pid -le 0 -or
        [int64]$document.writer_pid -gt [int]::MaxValue -or
        [int64]$document.writer_process_start_utc_ticks -le 0 -or
        [int64]$document.writer_session_id -lt 0 -or
        [int64]$document.writer_session_id -gt [int]::MaxValue -or
        ([int64]$document.sequence -eq 0 -and
            (-not [string]::IsNullOrEmpty(
                [string]$document.previous_name
            ) -or
             -not [string]::IsNullOrEmpty(
                [string]$document.previous_sha256
            ))) -or
        ([int64]$document.sequence -gt 0 -and
            ([string]$document.previous_name -cnotmatch
                '^[0-9]{3}-[a-z0-9-]+\.json$' -or
             [string]$document.previous_sha256 -cnotmatch
                '^[0-9a-f]{64}$')) -or
        [int64]$document.payload_bytes -ne $payloadBytes.Length -or
        [string]$document.payload_sha256 -cne
            (Get-AstroDetachedSha256Bytes $payloadBytes)) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_RECORD_INVALID' `
            "record identity/payload validation failed: $Name" `
            'preserve the transaction and inspect schema/hash drift'
    }
    return [pscustomobject]@{
        Name = $Name
        Path = $snapshot.Path
        Sequence = [int]$document.sequence
        Sha256 = $snapshot.Sha256
        Length = $snapshot.Length
        Document = $document
        Payload = $payload
    }
}

function Assert-AstroTaskRecoveryRecordLink {
    param(
        [Parameter(Mandatory)]$Previous,
        [Parameter(Mandatory)]$Current
    )

    if ($Current.Sequence -ne ($Previous.Sequence + 1) -or
        [string]$Current.Document.previous_name -cne $Previous.Name -or
        [string]$Current.Document.previous_sha256 -cne $Previous.Sha256) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_RECORD_LINK_DRIFT' `
            "recovery record link differs: $($Previous.Name) -> $($Current.Name)" `
            'preserve every transaction byte and inspect the immutable chain'
    }
}

function Get-AstroTaskRecoveryMainChain {
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [switch]$AllowRecovered
    )

    $files = @(
        Get-ChildItem -LiteralPath $RunDirectory -File -Force |
            Where-Object { $_.Name -cmatch '^[0-9]{3}-[a-z0-9-]+\.json$' } |
            Sort-Object Name
    )
    if ($files.Count -lt 6) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_CHAIN_INCOMPLETE' `
            "run has fewer than the required six lifecycle records: $RunDirectory" `
            'preserve the run; recovery requires the exact chain through launcher lease'
    }
    $records = @()
    for ($index = 0; $index -lt $files.Count; $index++) {
        $expectedPrefix = '{0:d3}-' -f $index
        if (-not $files[$index].Name.StartsWith(
                $expectedPrefix,
                [StringComparison]::Ordinal
            )) {
            Fail-AstroTaskRecovery `
                'ASTRO_DETACHED_TASK_RECOVERY_CHAIN_GAP' `
                "main chain is noncontiguous at sequence $index" `
                'preserve every run byte and inspect duplicate/gapped records'
        }
        $record = Read-AstroDetachedRecord `
            -RunDirectory $RunDirectory `
            -Name $files[$index].Name `
            -ExpectedSequence $index
        if ($records.Count -gt 0) {
            Assert-AstroDetachedRecordLink $records[-1] $record
        }
        $records += ,$record
    }
    $requiredSchemas = @(
        'astrolabe.detached.intent.v1',
        'astrolabe.detached.task.v1',
        'astrolabe.detached.runner.v1',
        'astrolabe.detached.boundary.v1',
        'astrolabe.detached.work.v1',
        'astrolabe.detached.launcher-lease.v1'
    )
    for ($index = 0; $index -lt $requiredSchemas.Count; $index++) {
        if ($records[$index].Schema -cne $requiredSchemas[$index]) {
            Fail-AstroTaskRecovery `
                'ASTRO_DETACHED_TASK_RECOVERY_CHAIN_SCHEMA_INVALID' `
                "sequence $index schema differs: $($records[$index].Schema)" `
                'preserve the run and recover only a canonical detached lifecycle'
        }
    }
    $terminal = $null
    if ($records[-1].Schema -ceq 'astrolabe.detached.task-recovery.v1') {
        if (-not $AllowRecovered) {
            Fail-AstroTaskRecovery `
                'ASTRO_DETACHED_TASK_RECOVERY_ALREADY_TERMINAL' `
                'run already has a terminal task-recovery record' `
                'read the existing recovery transaction instead of preparing another'
        }
        $terminal = $records[-1]
        $records = @($records[0..($records.Count - 2)])
    }
    if ($records[-1].Sequence -lt 5 -or $records[-1].Sequence -gt 998 -or
        @($records | Where-Object {
                $_.Schema -ceq 'astrolabe.detached.cleanup.v1'
            }).Count -ne 0) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_CHAIN_NOT_RECOVERABLE' `
            "run chain is not a stranded pre-cleanup lifecycle: $($records[-1].Name) / $($records[-1].Schema)" `
            'preserve the run and use its owning terminal/cleanup protocol'
    }
    return [pscustomobject]@{
        Records = $records
        Head = $records[-1]
        Intent = $records[0]
        Task = $records[1]
        Runner = $records[2]
        Boundary = $records[3]
        Work = $records[4]
        Lease = $records[5]
        Terminal = $terminal
    }
}

function Get-AstroTaskRecoveryProcessBindings {
    param([Parameter(Mandatory)]$Chain)

    $bindings = New-Object System.Collections.Generic.List[object]
    $bindings.Add([pscustomobject]@{
        role = 'coordinator'
        identity = $Chain.Intent.Payload.creator_identity
    })
    $bindings.Add([pscustomobject]@{
        role = 'runner'
        identity = $Chain.Runner.Payload.identity
    })
    $bindings.Add([pscustomobject]@{
        role = 'boundary'
        identity = $Chain.Boundary.Payload.identity
    })
    $bindings.Add([pscustomobject]@{
        role = 'work'
        identity = $Chain.Work.Payload.identity
    })
    $bindings.Add([pscustomobject]@{
        role = 'lease-owner'
        identity = $Chain.Lease.Payload.owner_identity
    })
    if ($null -ne $Chain.Runner.Payload.PSObject.Properties['bootstrap'] -and
        $null -ne $Chain.Runner.Payload.bootstrap -and
        $null -ne $Chain.Runner.Payload.bootstrap.identity) {
        $bindings.Add([pscustomobject]@{
            role = 'bootstrap'
            identity = $Chain.Runner.Payload.bootstrap.identity
        })
    }
    return $bindings.ToArray()
}

function Get-AstroTaskRecoveryProcessProbes {
    param([Parameter(Mandatory)]$Bindings)

    $probes = New-Object System.Collections.Generic.List[object]
    foreach ($binding in @($Bindings)) {
        $identity = $binding.identity
        if ($null -eq $identity -or [int]$identity.pid -le 0 -or
            [long]$identity.process_start_utc_ticks -le 0 -or
            [int]$identity.session_id -lt 0) {
            Fail-AstroTaskRecovery `
                'ASTRO_DETACHED_TASK_RECOVERY_PROCESS_BINDING_INVALID' `
                "recorded process identity is invalid for role $($binding.role)" `
                'preserve the run and inspect its exact lifecycle records'
        }
        $probe = Get-AstroDetachedProcessProbe `
            -ProcessId ([int]$identity.pid) `
            -ProcessStartUtcTicks ([long]$identity.process_start_utc_ticks) `
            -SessionId ([int]$identity.session_id)
        $probes.Add([pscustomobject]@{
            role = [string]$binding.role
            probe = $probe
        })
    }
    return $probes.ToArray()
}

function Assert-AstroTaskRecoveryProcessesInactive {
    param([Parameter(Mandatory)]$Probes)

    foreach ($row in @($Probes)) {
        if ([string]$row.probe.state -ceq 'exact-live' -or
            [string]$row.probe.state -ceq 'unevaluable') {
            Fail-AstroTaskRecovery `
                'ASTRO_DETACHED_TASK_RECOVERY_PROCESS_NOT_INACTIVE' `
                "recorded $($row.role) process is $($row.probe.state): pid=$($row.probe.pid)" `
                'preserve the task and run until every exact generation is inactive'
        }
    }
}

function Get-AstroTaskRecoveryTaskProbe {
    param([switch]$AllowAbsent)

    $service = Get-AstroDetachedTaskService
    $name = "Astrolabe.Detached.$RunId"
    $registered = Get-AstroDetachedRegisteredTask `
        -TaskService $service `
        -TaskName $name `
        -AllowAbsent
    if ($null -eq $registered) {
        if ($AllowAbsent) {
            return [ordered]@{
                state = 'absent'
                task_name = $name
                snapshot = $null
                snapshot_sha256 = $null
                running_instance_count = 0
            }
        }
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_TASK_ABSENT' `
            "bound task is absent before finalization: $name" `
            'preserve the run; deletion requires the exact registered task'
    }
    $snapshot = Get-AstroDetachedTaskSnapshot $registered
    $instances = $registered.GetInstances(0)
    $snapshotBytes = Get-AstroDetachedUtf8Bytes (
        $snapshot | ConvertTo-Json -Depth 32 -Compress
    )
    return [ordered]@{
        state = 'present'
        task_name = $name
        snapshot = $snapshot
        snapshot_sha256 = Get-AstroDetachedSha256Bytes $snapshotBytes
        running_instance_count = [int]$instances.Count
    }
}

function Assert-AstroTaskRecoveryTaskRecoverable {
    param(
        [Parameter(Mandatory)]$Probe,
        [Parameter(Mandatory)][string]$ExpectedXmlSha256
    )

    if ([string]$Probe.state -cne 'present' -or
        [string]$Probe.snapshot.name -cne "Astrolabe.Detached.$RunId" -or
        [string]$Probe.snapshot.path -cne "\Astrolabe.Detached.$RunId" -or
        [string]$Probe.snapshot.xml_sha256 -cne $ExpectedXmlSha256 -or
        [int]$Probe.running_instance_count -ne 0 -or
        @([int]1, [int]3) -cnotcontains
            [int]$Probe.snapshot.scheduler_state) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_TASK_NOT_RECOVERABLE' `
            ("task state/identity differs: state=$($Probe.state) " +
             "scheduler=$($Probe.snapshot.scheduler_state) " +
             "instances=$($Probe.running_instance_count) " +
             "expected_xml=$ExpectedXmlSha256 " +
             "observed_xml=$($Probe.snapshot.xml_sha256)") `
            'preserve the task/run and inspect exact XML, state, and instances'
    }
}

function Assert-AstroTaskRecoveryTaskProbeEqual {
    param(
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)]$Actual
    )

    if ([string]$Actual.state -cne [string]$Expected.state -or
        [string]$Actual.snapshot_sha256 -cne
            [string]$Expected.snapshot_sha256 -or
        [int]$Actual.running_instance_count -ne
            [int]$Expected.running_instance_count) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_TASK_DRIFT' `
            'task snapshot or running-instance count changed between exact reads' `
            'preserve the task/run and prepare a fresh transaction after stability'
    }
}

function Get-AstroTaskRecoveryProtocolState {
    $root = $script:AstroDetachedCanonicalRoot
    $lockPath = Join-Path (Join-Path $root '.tmp') 'astrolabe-launcher.lock'
    $lock = Read-AstroLauncherLock $lockPath
    return [ordered]@{
        observed_utc_ticks = [DateTime]::UtcNow.Ticks
        launcher_lock = [ordered]@{
            path = $lockPath
            state = [string]$lock.State
            validation_error = [string]$lock.ValidationError
            read_error = [string]$lock.ReadError
            transition_paths = [string[]]@($lock.TransitionPaths)
        }
        target = Get-AstroPathEntryState (Join-Path $root 'target')
        calyx_target = Get-AstroPathEntryState (Join-Path $root 'calyx\target')
        git_index_lock = Get-AstroPathEntryState (
            Join-Path $root '.git\index.lock'
        )
    }
}

function Assert-AstroTaskRecoveryProtocolAbsent {
    param([Parameter(Mandatory)]$State)

    if ([string]$State.launcher_lock.state -cne 'absent' -or
        [string]$State.target.State -cne 'absent' -or
        [string]$State.calyx_target.State -cne 'absent' -or
        [string]$State.git_index_lock.State -cne 'absent') {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_PROTOCOL_NOT_ABSENT' `
            ("launcher/target state is not terminal: lock=$($State.launcher_lock.state) " +
             "target=$($State.target.State) calyx=$($State.calyx_target.State) " +
             "git=$($State.git_index_lock.State)") `
            'preserve the task/run and complete or recover active launcher state first'
    }
}

function Import-AstroTaskRecoveryNativeScoped {
    param(
        [Parameter(Mandatory)][string]$TransactionDirectory,
        [Parameter(Mandatory)]
        [ValidateSet('prepare', 'recover')]
        [string]$RecoveryRole
    )

    $owner = Get-AstroDetachedCurrentIdentity
    $prefix = 'native-{0}.pid-{1}.ticks-{2}' -f
        $RecoveryRole, $owner.pid, $owner.process_start_utc_ticks
    $scope = Join-Path $TransactionDirectory "$prefix.dir"
    $tombstone = Join-Path $TransactionDirectory "$prefix.tombstone"
    [void](New-AstroDetachedDirectoryNoReplace $scope)
    $intent = Write-AstroTaskRecoveryAuxRecord `
        -TransactionDirectory $TransactionDirectory `
        -Name "$prefix.intent.json" `
        -Payload ([ordered]@{
            stage = 'intent'
            issue = $Issue
            exact_owner = $owner
            scope_path = $scope
            policy = 'compiler-temp-exact-scope-only'
        })
    $before = [ordered]@{
        TEMP = [string]$env:TEMP
        TMP = [string]$env:TMP
        TMPDIR = [string]$env:TMPDIR
    }
    $env:TEMP = $scope
    $env:TMP = $scope
    $env:TMPDIR = $scope
    try {
        . $lockHelperPath
    }
    catch {
        [void](Write-AstroTaskRecoveryAuxRecord `
            -TransactionDirectory $TransactionDirectory `
            -Name "$prefix.import-fault.json" `
            -Payload ([ordered]@{
                stage = 'import'
                issue = $Issue
                exact_owner = $owner
                scope_path = $scope
                code = 'ASTRO_DETACHED_TASK_RECOVERY_NATIVE_IMPORT_FAILED'
                message = $_.Exception.Message
            }))
        throw
    }
    finally {
        $env:TEMP = [string]$before.TEMP
        $env:TMP = [string]$before.TMP
        $env:TMPDIR = [string]$before.TMPDIR
    }
    $sourceHandle = $null
    $parentHandle = $null
    try {
        $first = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $scope
        $second = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $scope
        if ($first.schema -cne $second.schema -or
            $first.encoding -cne $second.encoding -or
            $first.entry_count -ne $second.entry_count -or
            $first.sha256 -cne $second.sha256) {
            throw 'native compiler scope changed between exact inventories'
        }
        $rootRows = @(
            $second.entries |
                Where-Object { [string]$_.relative_path -ceq '.' }
        )
        if ($rootRows.Count -ne 1) {
            throw 'native compiler inventory lacks exactly one root entry'
        }
        $sourceHandle =
            [AstroLauncherLockNative]::OpenExactDeleteDirectory($scope)
        $parentHandle =
            [AstroLauncherLockNative]::OpenExactRenameDirectory(
                $TransactionDirectory
            )
        $fileId = [AstroLauncherLockNative]::GetFileIdentity($sourceHandle)
        if ($fileId -cne [string]$rootRows[0].file_id) {
            throw 'native compiler scope FILE_ID changed after inventory'
        }
        $authorization = Write-AstroTaskRecoveryAuxRecord `
            -TransactionDirectory $TransactionDirectory `
            -Name "$prefix.authorization.json" `
            -Payload ([ordered]@{
                stage = 'authorization'
                issue = $Issue
                exact_owner = $owner
                intent_sha256 = $intent.Sha256
                scope_path = $scope
                scope_file_id = $fileId
                tombstone_path = $tombstone
                inventory_schema = $second.schema
                inventory_encoding = $second.encoding
                inventory_sha256 = $second.sha256
                inventory_entry_count = $second.entry_count
            })
        [AstroLauncherLockNative]::RenameDirectoryHandleNoReplace(
            $sourceHandle,
            $parentHandle,
            "$prefix.tombstone"
        )
        $finalPath = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($sourceHandle)
        )
        if ([AstroLauncherLockNative]::GetFileIdentity($sourceHandle) -cne
                $fileId -or
            -not [string]::Equals(
                [IO.Path]::GetFullPath($finalPath).TrimEnd('\', '/'),
                [IO.Path]::GetFullPath($tombstone).TrimEnd('\', '/'),
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            (Get-AstroPathEntryState $scope).State -cne 'absent') {
            throw 'native compiler handle-rename readback failed'
        }
    }
    catch {
        try {
            [void](Write-AstroTaskRecoveryAuxRecord `
                -TransactionDirectory $TransactionDirectory `
                -Name "$prefix.cleanup-fault.json" `
                -Payload ([ordered]@{
                    stage = 'cleanup'
                    issue = $Issue
                    exact_owner = $owner
                    scope_path = $scope
                    tombstone_path = $tombstone
                    code = 'ASTRO_DETACHED_TASK_RECOVERY_NATIVE_CLEANUP_FAILED'
                    message = $_.Exception.Message
                }))
        }
        catch {
            [Console]::Error.WriteLine(
                'ASTRO_DETACHED_TASK_RECOVERY_CLEANUP_FAULT_RECORD_FAILED: ' +
                $_.Exception.Message
            )
        }
        throw
    }
    finally {
        if ($null -ne $parentHandle) { $parentHandle.Dispose() }
        if ($null -ne $sourceHandle) { $sourceHandle.Dispose() }
    }
    $tombstoneInventory =
        Get-AstroOrdinaryDirectoryTreeInventoryLongPath $tombstone
    if ($tombstoneInventory.sha256 -cne $second.sha256 -or
        $tombstoneInventory.entry_count -ne $second.entry_count) {
        throw 'native compiler tombstone inventory drifted before deletion'
    }
    Remove-AstroOrdinaryDirectoryTreeLongPath `
        -LiteralPath $tombstone `
        -ExpectedInventorySchema ([string]$second.schema) `
        -ExpectedInventoryEncoding ([string]$second.encoding) `
        -ExpectedInventorySha256 ([string]$second.sha256)
    if ((Get-AstroPathEntryState $scope).State -cne 'absent' -or
        (Get-AstroPathEntryState $tombstone).State -cne 'absent') {
        throw 'native compiler scope did not reach terminal absence'
    }
    $completion = Write-AstroTaskRecoveryAuxRecord `
        -TransactionDirectory $TransactionDirectory `
        -Name "$prefix.completion.json" `
        -Payload ([ordered]@{
            stage = 'completion'
            issue = $Issue
            exact_owner = $owner
            intent_sha256 = $intent.Sha256
            authorization_sha256 = $authorization.Sha256
            scope_path = $scope
            scope_file_id = $fileId
            scope_state = 'absent'
            tombstone_path = $tombstone
            tombstone_state = 'absent'
            inventory_sha256 = $second.sha256
        })
    return [ordered]@{
        intent_sha256 = $intent.Sha256
        authorization_sha256 = $authorization.Sha256
        completion_sha256 = $completion.Sha256
        scope_path = $scope
        scope_file_id = $fileId
        inventory_sha256 = $second.sha256
        inventory_entry_count = $second.entry_count
        scope_state = 'absent'
        tombstone_state = 'absent'
    }
}

function Get-AstroTaskRecoveryTrackerLine {
    param([Parameter(Mandatory)]$Probe)

    return 'ASTRO_DETACHED_TASK_RECOVERY_V1 issue={0} run_id={1} transaction={2} probe_sha256={3} chain_head={4} chain_sha256={5} task_name={6} task_xml_sha256={7} action=delete-exact-registered-task-append-terminal-recovery' -f
        $Issue,
        $RunId,
        $TransactionId,
        $Probe.Sha256,
        $Probe.Payload.chain_head_name,
        $Probe.Payload.chain_head_sha256,
        $Probe.Payload.task.task_name,
        $Probe.Payload.task.snapshot.xml_sha256
}

function Invoke-AstroTaskRecoveryGhRead {
    param([Parameter(Mandatory)][long]$CommentId)

    $gh = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $gh) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_GH_MISSING' `
            'authenticated GitHub CLI is unavailable' `
            'restore GitHub access; local recovery never trusts an unverified URL'
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $gh.Source
    $start.Arguments =
        "api repos/ChrisRoyse/Astrolabe/issues/comments/$CommentId"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'Process.Start returned false' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            try {
                $process.Kill()
            }
            catch {
                [Console]::Error.WriteLine(
                    'ASTRO_DETACHED_TASK_RECOVERY_GH_KILL_FAILED: ' +
                    $_.Exception.Message
                )
            }
            throw 'bounded GitHub read timed out after 30000 ms'
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "gh exited $($process.ExitCode): $stderr"
        }
        return $stdout | ConvertFrom-Json
    }
    catch {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_GH_READ_FAILED' `
            $_.Exception.Message `
            'repair authenticated GitHub access; no task mutation is authorized'
    }
    finally {
        $process.Dispose()
    }
}

function Read-AstroTaskRecoveryTrackerEvidence {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)]$Probe
    )

    $pattern = '^https://github\.com/ChrisRoyse/Astrolabe/issues/' +
        [Regex]::Escape([string]$Issue) + '#issuecomment-([0-9]+)$'
    $match = [Regex]::Match($Url, $pattern)
    if (-not $match.Success) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_TRACKER_URL_INVALID' `
            "tracker URL is not an exact comment on issue #$Issue`: $Url" `
            'pass the exact owner-authored authorization comment URL'
    }
    $commentId = [long]::Parse(
        $match.Groups[1].Value,
        [Globalization.CultureInfo]::InvariantCulture
    )
    $comment = Invoke-AstroTaskRecoveryGhRead $commentId
    if ([string]$comment.html_url -cne $Url -or
        [string]$comment.author_association -cne 'OWNER') {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_TRACKER_AUTHORITY_INVALID' `
            "tracker URL/owner association differs: $($comment.html_url) / $($comment.author_association)" `
            'use an exact owner-authored issue comment'
    }
    $line = Get-AstroTaskRecoveryTrackerLine $Probe
    if (-not (@([string]$comment.body -split "`r?`n") -ccontains $line)) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_TRACKER_LINE_MISSING' `
            "tracker comment lacks exact authorization: $line" `
            'post the exact Prepare-produced line without changing any field'
    }
    return [ordered]@{
        url = $Url
        comment_id = $commentId
        updated_at = [string]$comment.updated_at
        body_sha256 = Get-AstroDetachedSha256Bytes (
            Get-AstroDetachedUtf8Bytes ([string]$comment.body)
        )
        authorization_line = $line
    }
}

function Assert-AstroTaskRecoveryScriptBindings {
    param([Parameter(Mandatory)]$Bindings)

    foreach ($binding in @(
            @{ Path = $protocolPath; Expected = [string]$Bindings.protocol.sha256 },
            @{ Path = $strictJsonPath; Expected = [string]$Bindings.strict_json.sha256 },
            @{ Path = $lockHelperPath; Expected = [string]$Bindings.launcher_lock.sha256 },
            @{ Path = $PSCommandPath; Expected = [string]$Bindings.recovery_script.sha256 }
        )) {
        $actual = (Get-FileHash -LiteralPath $binding.Path -Algorithm SHA256).
            Hash.ToLowerInvariant()
        if ($actual -cne $binding.Expected) {
            Fail-AstroTaskRecovery `
                'ASTRO_DETACHED_TASK_RECOVERY_SCRIPT_DRIFT' `
                "bound script changed: $($binding.Path) expected=$($binding.Expected) observed=$actual" `
                'preserve the transaction and use a fresh Prepare transaction'
        }
    }
}

function Assert-AstroTaskRecoverySourceBinding {
    param(
        [Parameter(Mandatory)]$Chain,
        [Parameter(Mandatory)]$Probe
    )

    if ([int]$Chain.Intent.Payload.issue -ne $Issue -or
        [string]$Chain.Head.Name -cne
            [string]$Probe.Payload.chain_head_name -or
        [string]$Chain.Head.Sha256 -cne
            [string]$Probe.Payload.chain_head_sha256 -or
        [string]$Chain.Task.Sha256 -cne
            [string]$Probe.Payload.task_record_sha256 -or
        [string]$Chain.Task.Payload.task.xml_sha256 -cne
            [string]$Probe.Payload.expected_task_xml_sha256) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_SOURCE_DRIFT' `
            'source issue, chain head, task record, or expected XML changed' `
            'preserve all state and prepare a fresh transaction'
    }
}

function Get-AstroTaskRecoveryCompleteResult {
    param(
        [Parameter(Mandatory)][string]$TransactionDirectory,
        [Parameter(Mandatory)]$Probe
    )

    $authorization = Read-AstroTaskRecoveryRecord `
        $TransactionDirectory '001-authorization.json'
    $finalization = Read-AstroTaskRecoveryRecord `
        $TransactionDirectory '002-finalization.json'
    $removal = Read-AstroTaskRecoveryRecord `
        $TransactionDirectory '003-removal.json'
    $completion = Read-AstroTaskRecoveryRecord `
        $TransactionDirectory '004-completion.json'
    Assert-AstroTaskRecoveryRecordLink $Probe $authorization
    Assert-AstroTaskRecoveryRecordLink $authorization $finalization
    Assert-AstroTaskRecoveryRecordLink $finalization $removal
    Assert-AstroTaskRecoveryRecordLink $removal $completion
    $tracker = Read-AstroTaskRecoveryTrackerEvidence `
        $TrackerCommentUrl $Probe
    if ([string]$authorization.Payload.tracker.body_sha256 -cne
            [string]$tracker.body_sha256) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_COMPLETED_TRACKER_DRIFT' `
            'completed authorization differs from the current tracker comment' `
            'preserve the transaction and inspect tracker mutation'
    }
    $chain = Get-AstroTaskRecoveryMainChain `
        -RunDirectory (Get-AstroTaskRecoveryRunDirectory) `
        -AllowRecovered
    Assert-AstroTaskRecoverySourceBinding $chain $Probe
    if ($null -eq $chain.Terminal -or
        [string]$chain.Terminal.Sha256 -cne
            [string]$completion.Payload.terminal_record_sha256 -or
        [string]$chain.Terminal.Payload.transaction_id -cne $TransactionId -or
        [string]$chain.Terminal.Payload.probe_sha256 -cne $Probe.Sha256) {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_COMPLETED_TERMINAL_DRIFT' `
            'main terminal recovery record differs from transaction completion' `
            'preserve every byte and inspect the two append-only chains'
    }
    $task = Get-AstroTaskRecoveryTaskProbe -AllowAbsent
    if ([string]$task.state -cne 'absent') {
        Fail-AstroTaskRecovery `
            'ASTRO_DETACHED_TASK_RECOVERY_COMPLETED_TASK_RECREATED' `
            'completed recovery task is physically present again' `
            'preserve all state and inspect the recreated Task Scheduler entry'
    }
    return [ordered]@{
        schema = 'astrolabe.detached-task-recovery-complete.v1'
        issue = $Issue
        run_id = $RunId
        transaction_id = $TransactionId
        transaction_path = $TransactionDirectory
        probe_sha256 = $Probe.Sha256
        authorization_sha256 = $authorization.Sha256
        finalization_sha256 = $finalization.Sha256
        removal_sha256 = $removal.Sha256
        completion_sha256 = $completion.Sha256
        terminal_record_name = $chain.Terminal.Name
        terminal_record_sha256 = $chain.Terminal.Sha256
        task_state = $task.state
        completed_readback = $true
    }
}

if ($Issue -le 0) {
    Fail-AstroTaskRecovery `
        'ASTRO_DETACHED_TASK_RECOVERY_ISSUE_INVALID' `
        'Issue must be a positive integer' `
        'pass the exact source tracker issue number'
}
if ([IO.Path]::GetFullPath((Get-Location).Path).TrimEnd('\') -cne
    $script:AstroDetachedCanonicalRoot) {
    Fail-AstroTaskRecovery `
        'ASTRO_DETACHED_TASK_RECOVERY_ROOT_INVALID' `
        "recovery must execute from $script:AstroDetachedCanonicalRoot" `
        'change to the canonical checkout before invoking recovery'
}

$runDirectory = Get-AstroTaskRecoveryRunDirectory

switch ($Operation) {
    'Prepare' {
        if ([string]::IsNullOrWhiteSpace($TransactionId)) {
            $TransactionId = [Guid]::NewGuid().ToString('N')
        }
        $chain = Get-AstroTaskRecoveryMainChain $runDirectory
        if ([int]$chain.Intent.Payload.issue -ne $Issue) {
            Fail-AstroTaskRecovery `
                'ASTRO_DETACHED_TASK_RECOVERY_SOURCE_ISSUE_INVALID' `
                "run source issue is $($chain.Intent.Payload.issue), not #$Issue" `
                'authorize recovery on the exact issue stored by the run intent'
        }
        $principal = Get-AstroTaskRecoveryPrincipal
        if ([string]$principal.sid -cne
            [string]$chain.Intent.Payload.principal_sid) {
            Fail-AstroTaskRecovery `
                'ASTRO_DETACHED_TASK_RECOVERY_PRINCIPAL_INVALID' `
                'current principal SID differs from the immutable run intent' `
                'run recovery as the same Windows principal that created the task'
        }
        $transaction = Get-AstroTaskRecoveryTransactionDirectory `
            $runDirectory $TransactionId -AllowCreate
        $script:AstroTaskRecoveryTransaction = $transaction
        $native = Import-AstroTaskRecoveryNativeScoped `
            $transaction prepare
        # Import-AstroTaskRecoveryNativeScoped owns the only Add-Type execution and
        # its compiler scratch. Dot-source once more at script scope after the type
        # exists so the helper functions survive the importing function's scope.
        . $lockHelperPath
        $processBindings = Get-AstroTaskRecoveryProcessBindings $chain
        $processFirst = Get-AstroTaskRecoveryProcessProbes $processBindings
        Assert-AstroTaskRecoveryProcessesInactive $processFirst
        $taskFirst = Get-AstroTaskRecoveryTaskProbe
        $expectedXml = [string]$chain.Task.Payload.task.xml_sha256
        Assert-AstroTaskRecoveryTaskRecoverable $taskFirst $expectedXml
        $protocolFirst = Get-AstroTaskRecoveryProtocolState
        Assert-AstroTaskRecoveryProtocolAbsent $protocolFirst
        $taskSecond = Get-AstroTaskRecoveryTaskProbe
        Assert-AstroTaskRecoveryTaskRecoverable $taskSecond $expectedXml
        Assert-AstroTaskRecoveryTaskProbeEqual $taskFirst $taskSecond
        $processSecond = Get-AstroTaskRecoveryProcessProbes $processBindings
        Assert-AstroTaskRecoveryProcessesInactive $processSecond
        $protocolSecond = Get-AstroTaskRecoveryProtocolState
        Assert-AstroTaskRecoveryProtocolAbsent $protocolSecond
        $bindings = [ordered]@{
            protocol = Get-AstroTaskRecoveryScriptBinding $protocolPath
            strict_json = Get-AstroTaskRecoveryScriptBinding $strictJsonPath
            launcher_lock = Get-AstroTaskRecoveryScriptBinding $lockHelperPath
            recovery_script = Get-AstroTaskRecoveryScriptBinding $PSCommandPath
        }
        $probe = Write-AstroTaskRecoveryRecord `
            $transaction '000-probe.json' 0 -Payload ([ordered]@{
                issue = $Issue
                run_id = $RunId
                transaction_id = $TransactionId
                principal = $principal
                chain_head_name = $chain.Head.Name
                chain_head_sequence = $chain.Head.Sequence
                chain_head_sha256 = $chain.Head.Sha256
                chain_record_count = $chain.Records.Count
                task_record_name = $chain.Task.Name
                task_record_sha256 = $chain.Task.Sha256
                expected_task_xml_sha256 = $expectedXml
                task = $taskSecond
                process_bindings = $processBindings
                process_probe_first = $processFirst
                process_probe_second = $processSecond
                protocol_first = $protocolFirst
                protocol_second = $protocolSecond
                script_bindings = $bindings
                native_compiler = $native
                destructive_authority = 'none'
                cost = [ordered]@{
                    explicit_run_count = 1
                    explicit_task_count = 1
                    chain_record_count = $chain.Records.Count
                    task_scheduler_folder_scan = $false
                    workspace_scan = $false
                    retry_count = 0
                }
            })
        $line = Get-AstroTaskRecoveryTrackerLine $probe
        [ordered]@{
            schema = 'astrolabe.detached-task-recovery-prepare-result.v1'
            issue = $Issue
            run_id = $RunId
            transaction_id = $TransactionId
            transaction_path = $transaction
            probe_path = $probe.Path
            probe_sha256 = $probe.Sha256
            chain_head_name = $chain.Head.Name
            chain_head_sha256 = $chain.Head.Sha256
            task_name = $taskSecond.task_name
            task_xml_sha256 = $taskSecond.snapshot.xml_sha256
            tracker_authorization_line = $line
            next = 'post the exact line on the source issue, then invoke Recover'
        } | ConvertTo-Json -Depth 32
        break
    }
    'Recover' {
        if ($TransactionId -cnotmatch '^[0-9a-f]{32}$' -or
            $ExpectedProbeSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]::IsNullOrWhiteSpace($TrackerCommentUrl)) {
            Fail-AstroTaskRecovery `
                'ASTRO_DETACHED_TASK_RECOVERY_ARGUMENT_INVALID' `
                'Recover requires exact transaction, probe hash, and tracker URL' `
                'pass the immutable values printed by Prepare'
        }
        $transaction = Get-AstroTaskRecoveryTransactionDirectory `
            $runDirectory $TransactionId
        $script:AstroTaskRecoveryTransaction = $transaction
        $probe = Read-AstroTaskRecoveryRecord `
            $transaction '000-probe.json' $ExpectedProbeSha256
        if ($probe.Sequence -ne 0 -or
            [int]$probe.Payload.issue -ne $Issue -or
            [string]$probe.Payload.run_id -cne $RunId) {
            Fail-AstroTaskRecovery `
                'ASTRO_DETACHED_TASK_RECOVERY_PROBE_BINDING_INVALID' `
                'probe sequence/issue/run binding differs' `
                'preserve state and pass the exact Prepare result'
        }
        Assert-AstroTaskRecoveryScriptBindings `
            $probe.Payload.script_bindings
        $principal = Get-AstroTaskRecoveryPrincipal
        if ([string]$principal.sid -cne
            [string]$probe.Payload.principal.sid) {
            Fail-AstroTaskRecovery `
                'ASTRO_DETACHED_TASK_RECOVERY_PRINCIPAL_INVALID' `
                'Recover principal differs from Prepare principal' `
                'run Recover as the exact same Windows principal'
        }
        $completionPath = Join-Path $transaction '004-completion.json'
        if ([IO.File]::Exists($completionPath)) {
            Get-AstroTaskRecoveryCompleteResult $transaction $probe |
                ConvertTo-Json -Depth 32
            return
        }
        $native = Import-AstroTaskRecoveryNativeScoped `
            $transaction recover
        # The scoped import above already loaded the native type and durably removed
        # its exact compiler scratch. This script-scope pass defines functions only.
        . $lockHelperPath
        $trackerFirst = Read-AstroTaskRecoveryTrackerEvidence `
            $TrackerCommentUrl $probe
        $launcherLockPath = Join-Path (
            Join-Path $script:AstroDetachedCanonicalRoot '.tmp'
        ) 'astrolabe-launcher.lock'
        $mutexLease = Enter-AstroLauncherLockMutex $launcherLockPath
        if (-not $mutexLease.Acquired) {
            Exit-AstroLauncherLockMutex $mutexLease
            Fail-AstroTaskRecovery `
                'ASTRO_DETACHED_TASK_RECOVERY_MUTEX_CONTENDED' `
                "canonical launcher mutex is held: $($mutexLease.Name)" `
                'preserve state and invoke Recover only after the active owner exits'
        }
        try {
            $chain = Get-AstroTaskRecoveryMainChain `
                -RunDirectory $runDirectory `
                -AllowRecovered
            Assert-AstroTaskRecoverySourceBinding $chain $probe
            $processFirst = Get-AstroTaskRecoveryProcessProbes `
                $probe.Payload.process_bindings
            Assert-AstroTaskRecoveryProcessesInactive $processFirst
            $protocolFirst = Get-AstroTaskRecoveryProtocolState
            Assert-AstroTaskRecoveryProtocolAbsent $protocolFirst
            $authorizationPath = Join-Path `
                $transaction '001-authorization.json'
            $finalizationPath = Join-Path `
                $transaction '002-finalization.json'
            $removalPath = Join-Path $transaction '003-removal.json'
            if ([IO.File]::Exists($authorizationPath)) {
                $authorization = Read-AstroTaskRecoveryRecord `
                    $transaction '001-authorization.json'
                Assert-AstroTaskRecoveryRecordLink $probe $authorization
                if ([string]$authorization.Payload.tracker.body_sha256 -cne
                        [string]$trackerFirst.body_sha256) {
                    Fail-AstroTaskRecovery `
                        'ASTRO_DETACHED_TASK_RECOVERY_AUTHORIZATION_DRIFT' `
                        'existing authorization differs from probe/tracker' `
                        'preserve transaction and task state'
                }
            }
            else {
                $taskFirst = Get-AstroTaskRecoveryTaskProbe
                Assert-AstroTaskRecoveryTaskRecoverable `
                    $taskFirst `
                    ([string]$probe.Payload.expected_task_xml_sha256)
                Assert-AstroTaskRecoveryTaskProbeEqual `
                    $probe.Payload.task $taskFirst
                $taskSecond = Get-AstroTaskRecoveryTaskProbe
                Assert-AstroTaskRecoveryTaskRecoverable `
                    $taskSecond `
                    ([string]$probe.Payload.expected_task_xml_sha256)
                Assert-AstroTaskRecoveryTaskProbeEqual $taskFirst $taskSecond
                $processSecond = Get-AstroTaskRecoveryProcessProbes `
                    $probe.Payload.process_bindings
                Assert-AstroTaskRecoveryProcessesInactive $processSecond
                $protocolSecond = Get-AstroTaskRecoveryProtocolState
                Assert-AstroTaskRecoveryProtocolAbsent $protocolSecond
                $trackerSecond = Read-AstroTaskRecoveryTrackerEvidence `
                    $TrackerCommentUrl $probe
                if ([string]$trackerSecond.body_sha256 -cne
                        [string]$trackerFirst.body_sha256 -or
                    [string]$trackerSecond.updated_at -cne
                        [string]$trackerFirst.updated_at) {
                    Fail-AstroTaskRecovery `
                        'ASTRO_DETACHED_TASK_RECOVERY_TRACKER_CHANGED' `
                        'tracker authorization changed between exact reads' `
                        'preserve state and obtain a fresh stable owner comment'
                }
                $authorization = Write-AstroTaskRecoveryRecord `
                    $transaction '001-authorization.json' 1 `
                    $probe.Name $probe.Sha256 ([ordered]@{
                        issue = $Issue
                        run_id = $RunId
                        transaction_id = $TransactionId
                        exact_recovery_owner = $principal
                        probe_sha256 = $probe.Sha256
                        tracker = $trackerSecond
                        mutex = [ordered]@{
                            name = $mutexLease.Name
                            acquired = [bool]$mutexLease.Acquired
                            was_abandoned = [bool]$mutexLease.WasAbandoned
                            created_new = [bool]$mutexLease.CreatedNew
                            root = $mutexLease.Root
                            root_final_path = $mutexLease.RootFinalPath
                            root_identity = $mutexLease.RootIdentity
                        }
                        task_probe_first = $taskFirst
                        task_probe_second = $taskSecond
                        process_probe_first = $processFirst
                        process_probe_second = $processSecond
                        protocol_first = $protocolFirst
                        protocol_second = $protocolSecond
                        native_compiler = $native
                        deletion_operation =
                            'TaskFolder.DeleteTask(exact-name, flags=0)'
                        interruption_policy =
                            'resume-only-this-immutable-finalized-transaction'
                    })
            }
            if ([IO.File]::Exists($finalizationPath)) {
                $finalization = Read-AstroTaskRecoveryRecord `
                    $transaction '002-finalization.json'
                Assert-AstroTaskRecoveryRecordLink `
                    $authorization $finalization
            }
            else {
                $taskBeforeFinalization = Get-AstroTaskRecoveryTaskProbe
                Assert-AstroTaskRecoveryTaskRecoverable `
                    $taskBeforeFinalization `
                    ([string]$probe.Payload.expected_task_xml_sha256)
                Assert-AstroTaskRecoveryTaskProbeEqual `
                    $probe.Payload.task $taskBeforeFinalization
                $processBeforeFinalization =
                    Get-AstroTaskRecoveryProcessProbes `
                        $probe.Payload.process_bindings
                Assert-AstroTaskRecoveryProcessesInactive `
                    $processBeforeFinalization
                $protocolBeforeFinalization =
                    Get-AstroTaskRecoveryProtocolState
                Assert-AstroTaskRecoveryProtocolAbsent `
                    $protocolBeforeFinalization
                $finalization = Write-AstroTaskRecoveryRecord `
                    $transaction '002-finalization.json' 2 `
                    $authorization.Name $authorization.Sha256 ([ordered]@{
                        issue = $Issue
                        run_id = $RunId
                        transaction_id = $TransactionId
                        probe_sha256 = $probe.Sha256
                        authorization_sha256 = $authorization.Sha256
                        task = $taskBeforeFinalization
                        process_probe = $processBeforeFinalization
                        protocol = $protocolBeforeFinalization
                        deletion_authority =
                            'only-the-bound-task-name-with-this-exact-xml-sha256'
                    })
            }
            if ([IO.File]::Exists($removalPath)) {
                $removal = Read-AstroTaskRecoveryRecord `
                    $transaction '003-removal.json'
                Assert-AstroTaskRecoveryRecordLink $finalization $removal
            }
            else {
                $preDelete = Get-AstroTaskRecoveryTaskProbe -AllowAbsent
                $resumedAfterFinalization =
                    [string]$preDelete.state -ceq 'absent'
                $removedSnapshot = $null
                if (-not $resumedAfterFinalization) {
                    Assert-AstroTaskRecoveryTaskRecoverable `
                        $preDelete `
                        ([string]$probe.Payload.expected_task_xml_sha256)
                    $service = Get-AstroDetachedTaskService
                    $removedSnapshot = Remove-AstroDetachedTaskExact `
                        -TaskService $service `
                        -TaskName ([string]$probe.Payload.task.task_name) `
                        -ExpectedXmlSha256 (
                            [string]$probe.Payload.expected_task_xml_sha256
                        )
                }
                $absenceFirst = Get-AstroTaskRecoveryTaskProbe -AllowAbsent
                $absenceSecond = Get-AstroTaskRecoveryTaskProbe -AllowAbsent
                if ([string]$absenceFirst.state -cne 'absent' -or
                    [string]$absenceSecond.state -cne 'absent') {
                    Fail-AstroTaskRecovery `
                        'ASTRO_DETACHED_TASK_RECOVERY_DELETE_READBACK_FAILED' `
                        'fresh Task Scheduler reads did not both prove task absence' `
                        'preserve transaction/run state and inspect Task Scheduler'
                }
                $removal = Write-AstroTaskRecoveryRecord `
                    $transaction '003-removal.json' 3 `
                    $finalization.Name $finalization.Sha256 ([ordered]@{
                        issue = $Issue
                        run_id = $RunId
                        transaction_id = $TransactionId
                        probe_sha256 = $probe.Sha256
                        authorization_sha256 = $authorization.Sha256
                        finalization_sha256 = $finalization.Sha256
                        expected_task_xml_sha256 =
                            $probe.Payload.expected_task_xml_sha256
                        removed_snapshot = $removedSnapshot
                        resumed_after_finalization =
                            $resumedAfterFinalization
                        absence_readback_first = $absenceFirst
                        absence_readback_second = $absenceSecond
                        task_state = 'absent'
                    })
            }
            $chain = Get-AstroTaskRecoveryMainChain `
                -RunDirectory $runDirectory `
                -AllowRecovered
            Assert-AstroTaskRecoverySourceBinding $chain $probe
            if ($null -eq $chain.Terminal) {
                $terminalName = '{0:d3}-task-recovery.json' -f
                    ($chain.Head.Sequence + 1)
                $terminal = Write-AstroDetachedRecord `
                    -RunDirectory $runDirectory `
                    -Name $terminalName `
                    -Schema 'astrolabe.detached.task-recovery.v1' `
                    -Sequence ($chain.Head.Sequence + 1) `
                    -PreviousName $chain.Head.Name `
                    -PreviousSha256 $chain.Head.Sha256 `
                    -Payload ([ordered]@{
                        issue = $Issue
                        source_issue = $chain.Intent.Payload.issue
                        run_id = $RunId
                        task_name = $probe.Payload.task.task_name
                        task_xml_sha256 =
                            $probe.Payload.expected_task_xml_sha256
                        task_absent = $true
                        transaction_id = $TransactionId
                        probe_sha256 = $probe.Sha256
                        authorization_sha256 = $authorization.Sha256
                        finalization_sha256 = $finalization.Sha256
                        removal_sha256 = $removal.Sha256
                        tracker_url = $TrackerCommentUrl
                        protocol_artifacts_preserved = $true
                        source_of_truth = $transaction
                    })
                $terminal = Read-AstroDetachedRecord `
                    -RunDirectory $runDirectory `
                    -Name $terminal.Name `
                    -ExpectedSchema 'astrolabe.detached.task-recovery.v1' `
                    -ExpectedSequence $terminal.Sequence
            }
            else {
                $terminal = $chain.Terminal
                if ([string]$terminal.Payload.transaction_id -cne
                        $TransactionId -or
                    [string]$terminal.Payload.probe_sha256 -cne
                        $probe.Sha256 -or
                    [string]$terminal.Payload.removal_sha256 -cne
                        $removal.Sha256) {
                    Fail-AstroTaskRecovery `
                        'ASTRO_DETACHED_TASK_RECOVERY_TERMINAL_DRIFT' `
                        'existing main terminal record differs from this transaction' `
                        'preserve both chains and inspect interrupted recovery state'
                }
            }
            $taskTerminal = Get-AstroTaskRecoveryTaskProbe -AllowAbsent
            $protocolTerminal = Get-AstroTaskRecoveryProtocolState
            Assert-AstroTaskRecoveryProtocolAbsent $protocolTerminal
            if ([string]$taskTerminal.state -cne 'absent') {
                Fail-AstroTaskRecovery `
                    'ASTRO_DETACHED_TASK_RECOVERY_TERMINAL_TASK_PRESENT' `
                    'task is present after the main terminal record' `
                    'preserve all state and inspect task recreation'
            }
            if ([IO.File]::Exists($completionPath)) {
                $completion = Read-AstroTaskRecoveryRecord `
                    $transaction '004-completion.json'
            }
            else {
                $completion = Write-AstroTaskRecoveryRecord `
                    $transaction '004-completion.json' 4 `
                    $removal.Name $removal.Sha256 ([ordered]@{
                        issue = $Issue
                        run_id = $RunId
                        transaction_id = $TransactionId
                        probe_sha256 = $probe.Sha256
                        authorization_sha256 = $authorization.Sha256
                        finalization_sha256 = $finalization.Sha256
                        removal_sha256 = $removal.Sha256
                        terminal_record_name = $terminal.Name
                        terminal_record_sha256 = $terminal.Sha256
                        task = $taskTerminal
                        protocol = $protocolTerminal
                        task_state = 'absent'
                        source_of_truth = $transaction
                    })
            }
            [ordered]@{
                schema = 'astrolabe.detached-task-recovery-complete.v1'
                issue = $Issue
                run_id = $RunId
                transaction_id = $TransactionId
                transaction_path = $transaction
                probe_sha256 = $probe.Sha256
                authorization_sha256 = $authorization.Sha256
                finalization_sha256 = $finalization.Sha256
                removal_sha256 = $removal.Sha256
                completion_sha256 = $completion.Sha256
                terminal_record_name = $terminal.Name
                terminal_record_sha256 = $terminal.Sha256
                task_state = $taskTerminal.state
                completed_readback = $true
            } | ConvertTo-Json -Depth 32
        }
        finally {
            Exit-AstroLauncherLockMutex $mutexLease
        }
        break
    }
}
