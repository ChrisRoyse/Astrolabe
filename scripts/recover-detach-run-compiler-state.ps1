<#
.SYNOPSIS
    Tracker-bound recovery of one modern run-local detached compiler scope.

.DESCRIPTION
    Prepare binds an exact detached run, immutable compiler intent/fault records,
    the dead owner generation, stable FILE_ID/security/content evidence, and
    protocol absence without granting destructive authority. Recover verifies an
    owner-authored tracker line twice while holding the canonical launcher mutex,
    re-probes all bound state, handle-renames only the exact compiler scope into
    the transaction, and deletes only its finalized ordinary inventory. Every
    recovery record remains append-only inside the owning detached run. Legacy
    opaque direct-.tmp compiler state remains owned by
    recover-detach-compiler-state.ps1. Refs #1068.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Prepare', 'Recover')]
    [string]$Operation,
    [Parameter(Mandatory)][int]$Issue,
    [Parameter(Mandatory)][string]$RunId,
    [Parameter(Mandatory)]
    [ValidateSet('coordinator', 'runner')]
    [string]$Role,
    [string]$TransactionId = '',
    [string]$ExpectedProbeSha256 = '',
    [string]$TrackerCommentUrl = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$protocolPath = Join-Path $PSScriptRoot 'detach-protocol.ps1'
$strictJsonPath = Join-Path $PSScriptRoot 'detach-strict-json.ps1'
$compilerStatePath = Join-Path $PSScriptRoot 'detach-compiler-state.ps1'
$lockHelperPath = Join-Path $PSScriptRoot 'launcher-lock.ps1'
. $protocolPath

$script:AstroModernRecoveryMaximumBytes = 8MB

function Fail-AstroModernRecovery {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Remediation
    )

    $document = [ordered]@{
        schema = 'astrolabe.detached-modern-compiler-recovery-error.v1'
        code = $Code
        message = $Message
        remediation = $Remediation
    }
    [Console]::Error.WriteLine(($document | ConvertTo-Json -Compress))
    $exception = [InvalidOperationException]::new($Message)
    $exception.Data['AstroCode'] = $Code
    $exception.Data['AstroRemediation'] = $Remediation
    throw $exception
}

function Get-AstroModernRecoveryPrincipal {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return [ordered]@{
        name = [string]$identity.Name
        sid = [string]$identity.User.Value
        process = Get-AstroDetachedCurrentIdentity
    }
}

function Get-AstroModernRecoveryScriptBinding {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.File]::Exists($full)) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_SCRIPT_MISSING' `
            "bound recovery dependency is missing: $full" `
            'restore the exact tracked script before preparing recovery'
    }
    return [ordered]@{
        path = $full
        sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.
            ToLowerInvariant()
    }
}

function Get-AstroModernRecoveryRunDirectory {
    if ($RunId -cnotmatch '^[0-9a-f]{32}$') {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_RUN_ID_INVALID' `
            "run ID must be 32 lowercase hexadecimal characters: '$RunId'" `
            'pass the exact owning detached run ID'
    }
    $path = Join-Path $script:AstroDetachedStateRoot $RunId
    return Assert-AstroDetachedRunDirectory $path
}

function Get-AstroModernRecoveryTransactionDirectory {
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)][string]$Id,
        [switch]$AllowCreate
    )

    if ($Id -cnotmatch '^[0-9a-f]{32}$') {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_TRANSACTION_INVALID' `
            "transaction ID is not a canonical GUID N value: '$Id'" `
            'pass the exact transaction ID printed by Prepare'
    }
    $run = Assert-AstroDetachedRunDirectory $RunDirectory
    $leaf = "compiler-recovery-$Role-$Id.dir"
    $path = [IO.Path]::GetFullPath((Join-Path $run $leaf))
    if ([IO.Path]::GetDirectoryName($path).TrimEnd('\', '/') -cne $run -or
        [IO.Path]::GetFileName($path) -cne $leaf) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_TRANSACTION_ESCAPE' `
            "transaction escaped the exact run: $path" `
            'preserve the run and use only the canonical transaction binding'
    }
    if ($AllowCreate) {
        [void](New-AstroDetachedDirectoryNoReplace $path)
    }
    return Assert-AstroDetachedOrdinaryDirectory $path
}

function Write-AstroModernRecoveryRecord {
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
            ('^compiler-recovery-' + [Regex]::Escape($Role) +
             '-[0-9a-f]{32}\.dir$') -or
        $Name -cnotmatch '^[0-9]{3}-[a-z0-9-]+\.json$') {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_RECORD_PATH_INVALID' `
            "invalid transaction/record binding: $transaction / $Name" `
            'preserve the transaction and use canonical append-only names'
    }
    if (($Sequence -eq 0 -and
            (-not [string]::IsNullOrEmpty($PreviousName) -or
             -not [string]::IsNullOrEmpty($PreviousSha256))) -or
        ($Sequence -gt 0 -and
            ($PreviousName -cnotmatch '^[0-9]{3}-[a-z0-9-]+\.json$' -or
             $PreviousSha256 -cnotmatch '^[0-9a-f]{64}$'))) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_RECORD_LINK_INVALID' `
            "invalid predecessor for sequence $Sequence / $Name" `
            'preserve the transaction and bind the exact previous record'
    }
    $payloadBytes = Get-AstroDetachedUtf8Bytes (
        $Payload | ConvertTo-Json -Depth 64 -Compress
    )
    $writer = Get-AstroDetachedCurrentIdentity
    $document = [ordered]@{
        schema = 'astrolabe.detached-modern-compiler-recovery-record.v1'
        run_id = $RunId
        role = $Role
        transaction_id = ([IO.Path]::GetFileName($transaction) -replace
            ("^compiler-recovery-$Role-"), '' -replace '\.dir$', '')
        sequence = $Sequence
        name = $Name
        written_utc_ticks = [DateTime]::UtcNow.Ticks
        writer = $writer
        previous_name = $PreviousName
        previous_sha256 = $PreviousSha256
        payload_sha256 = Get-AstroDetachedSha256Bytes $payloadBytes
        payload_bytes = [long]$payloadBytes.Length
        payload_json_base64 = [Convert]::ToBase64String($payloadBytes)
    }
    $bytes = Get-AstroDetachedUtf8Bytes (
        $document | ConvertTo-Json -Depth 12 -Compress
    )
    if ($bytes.Length -gt $script:AstroModernRecoveryMaximumBytes) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_RECORD_TOO_LARGE' `
            "$Name exceeds $script:AstroModernRecoveryMaximumBytes bytes" `
            'preserve the transaction and inspect the unexpected inventory size'
    }
    $path = Join-Path $transaction $Name
    $stream = [IO.File]::Open(
        $path,
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
    $snapshot = Read-AstroDetachedOrdinaryFile `
        $path $script:AstroModernRecoveryMaximumBytes
    $hash = Get-AstroDetachedSha256Bytes $bytes
    if ($snapshot.Length -ne $bytes.Length -or $snapshot.Sha256 -cne $hash) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_RECORD_READBACK' `
            "record readback differs after create-new write: $path" `
            'preserve the transaction bytes and investigate storage state'
    }
    return [pscustomobject]@{
        Name = $Name
        Path = $path
        Sequence = $Sequence
        Sha256 = $hash
        Length = $snapshot.Length
        Payload = $Payload
    }
}

function Read-AstroModernRecoveryRecord {
    param(
        [Parameter(Mandatory)][string]$TransactionDirectory,
        [Parameter(Mandatory)][string]$Name,
        [AllowEmptyString()][string]$ExpectedSha256 = ''
    )

    $transaction = Assert-AstroDetachedOrdinaryDirectory $TransactionDirectory
    $path = Join-Path $transaction $Name
    $snapshot = Read-AstroDetachedOrdinaryFile `
        $path $script:AstroModernRecoveryMaximumBytes
    if (-not [string]::IsNullOrEmpty($ExpectedSha256) -and
        $snapshot.Sha256 -cne $ExpectedSha256) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_RECORD_HASH_MISMATCH' `
            "$Name hash differs: expected=$ExpectedSha256 observed=$($snapshot.Sha256)" `
            'preserve every byte and pass the exact independently read hash'
    }
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString(
            $snapshot.Bytes
        )
        $document = ConvertFrom-Json -InputObject $text
        $required = @(
            'schema', 'run_id', 'role', 'transaction_id', 'sequence', 'name',
            'written_utc_ticks', 'writer', 'previous_name', 'previous_sha256',
            'payload_sha256', 'payload_bytes', 'payload_json_base64'
        )
        $names = @($document.PSObject.Properties.Name)
        if ($names.Count -ne $required.Count) {
            throw 'record property count differs'
        }
        for ($index = 0; $index -lt $required.Count; $index++) {
            if ([string]$names[$index] -cne $required[$index]) {
                throw "record property order differs at $index"
            }
        }
        if ([string]$document.schema -cne
                'astrolabe.detached-modern-compiler-recovery-record.v1' -or
            [string]$document.run_id -cne $RunId -or
            [string]$document.role -cne $Role -or
            [string]$document.transaction_id -cne $TransactionId -or
            [string]$document.name -cne $Name) {
            throw 'record schema/run/role/transaction/name binding differs'
        }
        $payloadBytes = [Convert]::FromBase64String(
            [string]$document.payload_json_base64
        )
        if ([long]$document.payload_bytes -ne $payloadBytes.Length -or
            [string]$document.payload_sha256 -cne
                (Get-AstroDetachedSha256Bytes $payloadBytes)) {
            throw 'payload byte count or hash differs'
        }
        $payloadText = [Text.UTF8Encoding]::new($false, $true).GetString(
            $payloadBytes
        )
        $payload = ConvertFrom-Json -InputObject $payloadText
    }
    catch {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_RECORD_INVALID' `
            "$Name decode failed: $($_.Exception.Message)" `
            'preserve the transaction; never recover from malformed evidence'
    }
    return [pscustomobject]@{
        Name = $Name
        Path = $path
        Sequence = [int]$document.sequence
        Sha256 = $snapshot.Sha256
        Length = $snapshot.Length
        Document = $document
        Payload = $payload
    }
}

function Write-AstroModernRecoveryAuxRecord {
    param(
        [Parameter(Mandatory)][string]$TransactionDirectory,
        [Parameter(Mandatory)][string]$Leaf,
        [Parameter(Mandatory)]$Payload
    )

    if ($Leaf -cnotmatch
            '^native-(prepare|recover)\.pid-[0-9]+\.ticks-[0-9]+\.(intent|authorization|completion|fault)\.json$') {
        throw "invalid modern-recovery compiler record leaf: $Leaf"
    }
    $path = Join-Path $TransactionDirectory $Leaf
    $bytes = Get-AstroDetachedUtf8Bytes (
        ([ordered]@{
            schema = 'astrolabe.detached-modern-recovery-native.v1'
            run_id = $RunId
            role = $Role
            transaction_id = $TransactionId
            written_utc_ticks = [DateTime]::UtcNow.Ticks
            payload = $Payload
        } | ConvertTo-Json -Depth 48 -Compress)
    )
    $stream = [IO.File]::Open(
        $path,
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
    $snapshot = Read-AstroDetachedOrdinaryFile $path
    if ($snapshot.Sha256 -cne (Get-AstroDetachedSha256Bytes $bytes)) {
        throw "native compiler record readback differs: $path"
    }
    return [pscustomobject]@{
        Path = $path
        Sha256 = $snapshot.Sha256
        Length = $snapshot.Length
    }
}

function Get-AstroModernRecoveryPathEntryState {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    try {
        $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
        return [pscustomobject]@{
            State = 'present'
            Attributes = [uint32]$item.Attributes
            Error = $null
        }
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'PathNotFound,*' -or
            $_.FullyQualifiedErrorId -like 'ItemNotFound,*' -or
            $_.Exception -is [IO.FileNotFoundException] -or
            $_.Exception -is [IO.DirectoryNotFoundException]) {
            return [pscustomobject]@{
                State = 'absent'
                Attributes = $null
                Error = $null
            }
        }
        return [pscustomobject]@{
            State = 'unevaluable'
            Attributes = $null
            Error = "$($_.FullyQualifiedErrorId): $($_.Exception.Message)"
        }
    }
}

function Import-AstroModernRecoveryNativeScoped {
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
    $intent = Write-AstroModernRecoveryAuxRecord `
        $TransactionDirectory "$prefix.intent.json" ([ordered]@{
            stage = 'intent'
            issue = $Issue
            exact_owner = $owner
            principal = Get-AstroModernRecoveryPrincipal
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
        $failure = $_
        [void](Write-AstroModernRecoveryAuxRecord `
            $TransactionDirectory "$prefix.fault.json" ([ordered]@{
                stage = 'import'
                issue = $Issue
                exact_owner = $owner
                scope_path = $scope
                code = 'ASTRO_DETACHED_MODERN_RECOVERY_NATIVE_IMPORT_FAILED'
                message = $failure.Exception.Message
                remediation = 'preserve the transaction and native compiler scope'
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
            throw 'native compiler scope inventory changed between observations'
        }
        $root = @(
            $second.entries |
                Where-Object { [string]$_.relative_path -ceq '.' }
        )
        if ($root.Count -ne 1) {
            throw 'native compiler inventory lacks exactly one root entry'
        }
        $sourceHandle =
            [AstroLauncherLockNative]::OpenExactDeleteDirectory($scope)
        $parentHandle =
            [AstroLauncherLockNative]::OpenExactRenameDirectory(
                $TransactionDirectory
            )
        $fileId = [AstroLauncherLockNative]::GetFileIdentity($sourceHandle)
        if ($fileId -cne [string]$root[0].file_id) {
            throw 'native compiler scope FILE_ID changed after inventory'
        }
        $authorization = Write-AstroModernRecoveryAuxRecord `
            $TransactionDirectory "$prefix.authorization.json" ([ordered]@{
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
        $final = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($sourceHandle)
        )
        if ([AstroLauncherLockNative]::GetFileIdentity($sourceHandle) -cne
                $fileId -or
            -not [string]::Equals(
                [IO.Path]::GetFullPath($final).TrimEnd('\', '/'),
                [IO.Path]::GetFullPath($tombstone).TrimEnd('\', '/'),
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            (Get-AstroModernRecoveryPathEntryState $scope).State -cne
                'absent') {
            throw 'native compiler handle-rename readback failed'
        }
    }
    catch {
        $failure = $_
        try {
            [void](Write-AstroModernRecoveryAuxRecord `
                $TransactionDirectory "$prefix.fault.json" ([ordered]@{
                    stage = 'cleanup'
                    issue = $Issue
                    exact_owner = $owner
                    scope_path = $scope
                    tombstone_path = $tombstone
                    code = 'ASTRO_DETACHED_MODERN_RECOVERY_NATIVE_CLEANUP_FAILED'
                    message = $failure.Exception.Message
                    remediation = 'preserve transaction/native compiler bytes'
                }))
        }
        catch {}
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
    if ((Get-AstroModernRecoveryPathEntryState $scope).State -cne 'absent' -or
        (Get-AstroModernRecoveryPathEntryState $tombstone).State -cne
            'absent') {
        throw 'native compiler scope did not reach terminal absence'
    }
    $completion = Write-AstroModernRecoveryAuxRecord `
        $TransactionDirectory "$prefix.completion.json" ([ordered]@{
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
        intent_path = $intent.Path
        intent_sha256 = $intent.Sha256
        authorization_path = $authorization.Path
        authorization_sha256 = $authorization.Sha256
        completion_path = $completion.Path
        completion_sha256 = $completion.Sha256
        scope_path = $scope
        scope_file_id = $fileId
        inventory_sha256 = $second.sha256
        inventory_entry_count = $second.entry_count
        scope_state = 'absent'
        tombstone_state = 'absent'
    }
}

function Read-AstroModernCompilerStateRecord {
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)]
        [ValidateSet(
            'intent', 'process', 'artifact', 'authorization', 'renamed',
            'completion', 'fault'
        )]
        [string]$Stage,
        [switch]$AllowAbsent,
        [AllowEmptyString()][string]$ExpectedSha256 = ''
    )

    $path = Join-Path $RunDirectory "compiler-$Role-$Stage.json"
    if (-not [IO.File]::Exists($path)) {
        if ($AllowAbsent) { return $null }
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_COMPILER_RECORD_MISSING' `
            "required compiler record is absent: $path" `
            'preserve the run and recover only a complete intent/fault pair'
    }
    $snapshot = Read-AstroDetachedOrdinaryFile $path
    if (-not [string]::IsNullOrEmpty($ExpectedSha256) -and
        $snapshot.Sha256 -cne $ExpectedSha256) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_COMPILER_RECORD_DRIFT' `
            "$Stage hash differs: expected=$ExpectedSha256 observed=$($snapshot.Sha256)" `
            'preserve every run byte and restart with a fresh recovery probe'
    }
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString(
            $snapshot.Bytes
        )
        $document = ConvertFrom-Json -InputObject $text
        if ([string]$document.schema -cne
                'astrolabe.detached.compiler-state.v1' -or
            [string]$document.run_id -cne $RunId -or
            [string]$document.role -cne $Role -or
            [string]$document.stage -cne $Stage) {
            throw 'compiler record schema/run/role/stage binding differs'
        }
        $payloadBytes = Get-AstroDetachedUtf8Bytes (
            $document.payload | ConvertTo-Json -Depth 40 -Compress
        )
        if ([long]$document.payload_bytes -ne $payloadBytes.Length -or
            [string]$document.payload_sha256 -cne
                (Get-AstroDetachedSha256Bytes $payloadBytes)) {
            throw 'compiler payload hash/length differs'
        }
    }
    catch {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_COMPILER_RECORD_INVALID' `
            "$Stage record decode failed: $($_.Exception.Message)" `
            'preserve the run; never recover from malformed compiler evidence'
    }
    return [pscustomobject]@{
        Path = $path
        Sha256 = $snapshot.Sha256
        Length = $snapshot.Length
        Document = $document
        Payload = $document.payload
    }
}

function Get-AstroModernRecoveryCompilerBinding {
    param([Parameter(Mandatory)][string]$RunDirectory)

    $intent = Read-AstroModernCompilerStateRecord $RunDirectory intent
    $fault = Read-AstroModernCompilerStateRecord $RunDirectory fault
    $sourceIssue = [int]$intent.Payload.issue
    if ($sourceIssue -le 0 -or
        [int]$fault.Payload.issue -ne $sourceIssue -or
        [string]$fault.Payload.intent_sha256 -cne $intent.Sha256) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_INTENT_FAULT_BINDING_INVALID' `
            'compiler intent/fault issue or hash binding differs' `
            'preserve the run and bind recovery to its exact driving issue'
    }
    $owner = $intent.Payload.exact_owner
    if ([int]$owner.pid -le 0 -or
        [long]$owner.process_start_utc_ticks -le 0 -or
        [int]$owner.session_id -lt 0) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_OWNER_INVALID' `
            'compiler intent lacks a complete exact owner generation' `
            'preserve the state; numeric PID alone never grants recovery authority'
    }
    $expectedLeaf = 'compiler-state-{0}.pid-{1}.ticks-{2}.dir' -f
        $Role, $owner.pid, $owner.process_start_utc_ticks
    $expectedScope = [IO.Path]::GetFullPath(
        (Join-Path $RunDirectory $expectedLeaf)
    ).TrimEnd('\', '/')
    $expectedTombstone = [IO.Path]::GetFullPath(
        (Join-Path $RunDirectory ($expectedLeaf -replace '\.dir$', '.tombstone'))
    ).TrimEnd('\', '/')
    if ([string]$intent.Payload.scope_leaf -cne $expectedLeaf -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$intent.Payload.scope_path).
                TrimEnd('\', '/'),
            $expectedScope,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$fault.Payload.scope_path).
                TrimEnd('\', '/'),
            $expectedScope,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$fault.Payload.tombstone_path).
                TrimEnd('\', '/'),
            $expectedTombstone,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_SCOPE_BINDING_INVALID' `
            'compiler scope path/leaf differs from exact intent owner generation' `
            'preserve every byte; never infer or repair a scope pathname'
    }
    $authorization = Read-AstroModernCompilerStateRecord `
        $RunDirectory authorization -AllowAbsent
    $renamed = Read-AstroModernCompilerStateRecord `
        $RunDirectory renamed -AllowAbsent
    $completion = Read-AstroModernCompilerStateRecord `
        $RunDirectory completion -AllowAbsent
    return [ordered]@{
        intent = $intent
        fault = $fault
        authorization = $authorization
        renamed = $renamed
        completion = $completion
        source_issue = $sourceIssue
        owner = $owner
        principal = $intent.Payload.principal
        scope_path = $expectedScope
        tombstone_path = $expectedTombstone
    }
}

function Assert-AstroModernRecoveryOwnerInactive {
    param([Parameter(Mandatory)]$Probe)

    if ([string]$Probe.state -ceq 'exact-live' -or
        [string]$Probe.state -ceq 'unevaluable') {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_OWNER_NOT_INACTIVE' `
            "compiler owner probe is $($Probe.state): pid=$($Probe.pid) / $($Probe.error)" `
            'preserve all state until the exact owner generation is conclusively inactive'
    }
}

function Get-AstroModernRecoveryProtocolState {
    $root = $script:AstroDetachedCanonicalRoot
    $tmp = Join-Path $root '.tmp'
    $taskService = Get-AstroDetachedTaskService
    $task = Get-AstroDetachedRegisteredTask `
        -TaskService $taskService `
        -TaskName "Astrolabe.Detached.$RunId" `
        -AllowAbsent
    $reserved = @(
        Get-ChildItem -LiteralPath $tmp -Force -ErrorAction Stop |
            Where-Object {
                $_.Name -like 'astrolabe-launcher.lock*' -or
                $_.Name -like 'no-escape-attribution-v3.*' -or
                $_.Name -like 'windows-gnu-toolchain-v2.*'
            } |
            Sort-Object Name |
            ForEach-Object { [IO.Path]::GetFullPath($_.FullName) }
    )
    return [ordered]@{
        observed_utc_ticks = [DateTime]::UtcNow.Ticks
        target_state = (
            Get-AstroModernRecoveryPathEntryState (Join-Path $root 'target')
        ).State
        calyx_target_state = (
            Get-AstroModernRecoveryPathEntryState (
                Join-Path $root 'calyx\target'
            )
        ).State
        git_index_lock_state = (
            Get-AstroModernRecoveryPathEntryState (
                Join-Path $root '.git\index.lock'
            )
        ).State
        exact_task_state = if ($null -eq $task) { 'absent' } else { 'present' }
        reserved_active_paths = [string[]]$reserved
        reserved_active_count = $reserved.Count
    }
}

function Assert-AstroModernRecoveryProtocolAbsent {
    param([Parameter(Mandatory)]$State)

    if ([string]$State.target_state -cne 'absent' -or
        [string]$State.calyx_target_state -cne 'absent' -or
        [string]$State.git_index_lock_state -cne 'absent' -or
        [string]$State.exact_task_state -cne 'absent' -or
        [int]$State.reserved_active_count -ne 0) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_PROTOCOL_NOT_ABSENT' `
            ("protocol is not terminal: target=$($State.target_state) " +
             "calyx_target=$($State.calyx_target_state) " +
             "git_lock=$($State.git_index_lock_state) " +
             "task=$($State.exact_task_state) " +
             "reserved=$($State.reserved_active_count)") `
            'preserve compiler state and complete the active protocol before recovery'
    }
}

function Get-AstroModernRecoveryTargetState {
    param(
        [Parameter(Mandatory)][string]$ScopePath,
        [Parameter(Mandatory)][string]$CompilerTombstonePath,
        [Parameter(Mandatory)][string]$RecoveryTombstonePath
    )

    return [ordered]@{
        scope = Get-AstroModernRecoveryPathEntryState $ScopePath
        compiler_tombstone =
            Get-AstroModernRecoveryPathEntryState $CompilerTombstonePath
        recovery_tombstone =
            Get-AstroModernRecoveryPathEntryState $RecoveryTombstonePath
    }
}

function Get-AstroModernRecoverySecuritySnapshot {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $acl = Get-Acl -LiteralPath $full -ErrorAction Stop
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group -bor
        [Security.AccessControl.AccessControlSections]::Access
    $sddl = $acl.GetSecurityDescriptorSddlForm($sections)
    return [ordered]@{
        path = $full
        owner = [string]$acl.Owner
        group = [string]$acl.Group
        access_sddl = $sddl
        access_sddl_sha256 = Get-AstroDetachedSha256Bytes (
            Get-AstroDetachedUtf8Bytes $sddl
        )
    }
}

function Get-AstroModernRecoveryTargetProbe {
    param([Parameter(Mandatory)][string]$Path)

    $full = Assert-AstroDetachedOrdinaryDirectory $Path
    $first = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $full
    $second = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $full
    if ($first.schema -cne $second.schema -or
        $first.encoding -cne $second.encoding -or
        $first.entry_count -ne $second.entry_count -or
        $first.sha256 -cne $second.sha256) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_TARGET_UNSTABLE' `
            'compiler target inventory changed between exact observations' `
            'preserve the target and prepare a fresh transaction only after it is stable'
    }
    $roots = @(
        $second.entries |
            Where-Object { [string]$_.relative_path -ceq '.' }
    )
    if ($roots.Count -ne 1) {
        throw 'compiler target inventory lacks exactly one root entry'
    }
    $handle = $null
    try {
        $handle = [AstroLauncherLockNative]::OpenExactDeleteDirectory($full)
        $fileId = [AstroLauncherLockNative]::GetFileIdentity($handle)
        $final = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($handle)
        )
        $final = [IO.Path]::GetFullPath($final).TrimEnd('\', '/')
        $securityFirst = Get-AstroModernRecoverySecuritySnapshot $full
        $securitySecond = Get-AstroModernRecoverySecuritySnapshot $full
        if ($fileId -cne [string]$roots[0].file_id -or
            -not [string]::Equals(
                $final,
                $full,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            $securityFirst.access_sddl_sha256 -cne
                $securitySecond.access_sddl_sha256) {
            throw 'retained compiler target identity/path/security changed'
        }
    }
    finally {
        if ($null -ne $handle) { $handle.Dispose() }
    }
    $third = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $full
    if ($third.sha256 -cne $second.sha256 -or
        $third.entry_count -ne $second.entry_count) {
        throw 'compiler target inventory changed across retained observation'
    }
    $entries = @(
        foreach ($entry in @($third.entries)) {
            [ordered]@{
                relative_path = [string]$entry.relative_path
                kind = [string]$entry.kind
                attributes = [uint32]$entry.attributes
                file_id = [string]$entry.file_id
                bytes = if ($null -eq $entry.bytes) { $null } else {
                    [uint64]$entry.bytes
                }
                sha256 = if ($null -eq $entry.sha256) { $null } else {
                    [string]$entry.sha256
                }
            }
        }
    )
    return [ordered]@{
        path = $full
        file_id = $fileId
        final_path = $final
        security = $securitySecond
        security_sddl_sha256 = $securitySecond.access_sddl_sha256
        inventory = [ordered]@{
            schema = [string]$third.schema
            encoding = [string]$third.encoding
            entry_count = [int]$third.entry_count
            canonical_bytes_length = [uint64]$third.canonical_bytes_length
            sha256 = [string]$third.sha256
            entries = $entries
        }
        first_equals_second_equals_third = $true
    }
}

function Get-AstroModernRecoveryTrackerLine {
    param([Parameter(Mandatory)]$ProbeRecord)

    return 'ASTRO_DETACHED_RUN_COMPILER_RECOVERY_V1 issue={0} source_issue={1} run_id={2} role={3} transaction={4} probe_sha256={5} intent_sha256={6} fault_sha256={7} scope_file_id={8} inventory_sha256={9} action=handle-rename-delete-exact-inventory' -f
        $Issue,
        $ProbeRecord.Payload.source_issue,
        $RunId,
        $Role,
        $TransactionId,
        $ProbeRecord.Sha256,
        $ProbeRecord.Payload.intent_sha256,
        $ProbeRecord.Payload.fault_sha256,
        $ProbeRecord.Payload.target.file_id,
        $ProbeRecord.Payload.target.inventory.sha256
}

function Invoke-AstroModernRecoveryGhRead {
    param([Parameter(Mandatory)][long]$CommentId)

    $gh = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $gh) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_GH_MISSING' `
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
            try { $process.Kill() } catch {}
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
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_GH_READ_FAILED' `
            $_.Exception.Message `
            'repair authenticated GitHub access; no target mutation is authorized'
    }
    finally {
        $process.Dispose()
    }
}

function Read-AstroModernRecoveryTrackerEvidence {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)]$ProbeRecord
    )

    $pattern = '^https://github\.com/ChrisRoyse/Astrolabe/issues/' +
        [Regex]::Escape([string]$Issue) + '#issuecomment-([0-9]+)$'
    $match = [Regex]::Match($Url, $pattern)
    if (-not $match.Success) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_TRACKER_URL_INVALID' `
            "tracker URL is not an exact comment on issue #$Issue`: $Url" `
            'pass the exact URL returned for the owner-authored authorization comment'
    }
    $commentId = [long]::Parse(
        $match.Groups[1].Value,
        [Globalization.CultureInfo]::InvariantCulture
    )
    $comment = Invoke-AstroModernRecoveryGhRead $commentId
    if ([string]$comment.html_url -cne $Url -or
        [string]$comment.author_association -cne 'OWNER') {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_TRACKER_AUTHORITY_INVALID' `
            "tracker URL/owner association differs: $($comment.html_url) / $($comment.author_association)" `
            'use an exact owner-authored issue comment'
    }
    $line = Get-AstroModernRecoveryTrackerLine $ProbeRecord
    if (-not (@([string]$comment.body -split "`r?`n") -ccontains $line)) {
        Fail-AstroModernRecovery `
            'ASTRO_DETACHED_MODERN_RECOVERY_TRACKER_LINE_MISSING' `
            "tracker comment lacks the exact authorization line: $line" `
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

function Assert-AstroModernRecoveryScriptBindings {
    param([Parameter(Mandatory)]$Bindings)

    foreach ($binding in @(
            @{ Path = $protocolPath; Expected = [string]$Bindings.protocol.sha256 },
            @{ Path = $strictJsonPath; Expected = [string]$Bindings.strict_json.sha256 },
            @{ Path = $compilerStatePath; Expected = [string]$Bindings.compiler_state.sha256 },
            @{ Path = $lockHelperPath; Expected = [string]$Bindings.launcher_lock.sha256 },
            @{ Path = $PSCommandPath; Expected = [string]$Bindings.recovery_script.sha256 }
        )) {
        $actual = (Get-FileHash -LiteralPath $binding.Path -Algorithm SHA256).
            Hash.ToLowerInvariant()
        if ($actual -cne $binding.Expected) {
            Fail-AstroModernRecovery `
                'ASTRO_DETACHED_MODERN_RECOVERY_SCRIPT_DRIFT' `
                "bound script changed: $($binding.Path) expected=$($binding.Expected) observed=$actual" `
                'preserve the transaction and use a fresh Prepare transaction'
        }
    }
}

if ($Issue -le 0) {
    Fail-AstroModernRecovery `
        'ASTRO_DETACHED_MODERN_RECOVERY_ISSUE_INVALID' `
        'Issue must be a positive integer' `
        'pass the exact driving tracker issue number'
}
if ([IO.Path]::GetFullPath((Get-Location).Path).TrimEnd('\') -cne
    $script:AstroDetachedCanonicalRoot) {
    Fail-AstroModernRecovery `
        'ASTRO_DETACHED_MODERN_RECOVERY_ROOT_INVALID' `
        "recovery must execute from $script:AstroDetachedCanonicalRoot" `
        'change to the canonical checkout before retrying'
}

$runDirectory = Get-AstroModernRecoveryRunDirectory

switch ($Operation) {
    'Prepare' {
        if ([string]::IsNullOrWhiteSpace($TransactionId)) {
            $TransactionId = [Guid]::NewGuid().ToString('N')
        }
        $compiler = Get-AstroModernRecoveryCompilerBinding $runDirectory
        $principal = Get-AstroModernRecoveryPrincipal
        if ([string]$principal.sid -cne [string]$compiler.principal.sid) {
            Fail-AstroModernRecovery `
                'ASTRO_DETACHED_MODERN_RECOVERY_PRINCIPAL_INVALID' `
                "current principal SID differs from compiler intent: $($principal.sid) / $($compiler.principal.sid)" `
                'run recovery as the same principal that created the compiler scope'
        }
        if ($null -ne $compiler.completion) {
            Fail-AstroModernRecovery `
                'ASTRO_DETACHED_MODERN_RECOVERY_ALREADY_COMPLETE' `
                'compiler completion already exists; dead-owner recovery is not applicable' `
                'inspect normal compiler completion instead of recovering it'
        }
        $transaction = Get-AstroModernRecoveryTransactionDirectory `
            $runDirectory $TransactionId -AllowCreate
        $nativeCompiler = Import-AstroModernRecoveryNativeScoped `
            $transaction prepare
        . $lockHelperPath
        $protocolFirst = Get-AstroModernRecoveryProtocolState
        Assert-AstroModernRecoveryProtocolAbsent $protocolFirst
        $ownerFirst = Get-AstroDetachedProcessProbe `
            -ProcessId ([int]$compiler.owner.pid) `
            -ProcessStartUtcTicks ([long]$compiler.owner.process_start_utc_ticks) `
            -SessionId ([int]$compiler.owner.session_id)
        Assert-AstroModernRecoveryOwnerInactive $ownerFirst
        $states = Get-AstroModernRecoveryTargetState `
            $compiler.scope_path `
            $compiler.tombstone_path `
            (Join-Path $transaction 'recovered-compiler-state.tombstone')
        $scopePresent = [string]$states.scope.State -ceq 'present'
        $compilerTombstonePresent =
            [string]$states.compiler_tombstone.State -ceq 'present'
        if ($scopePresent -eq $compilerTombstonePresent -or
            [string]$states.recovery_tombstone.State -cne 'absent') {
            Fail-AstroModernRecovery `
                'ASTRO_DETACHED_MODERN_RECOVERY_TARGET_STATE_INVALID' `
                ("expected exactly one compiler source and no recovery tombstone; " +
                 "scope=$($states.scope.State) compiler_tombstone=$($states.compiler_tombstone.State) " +
                 "recovery_tombstone=$($states.recovery_tombstone.State)") `
                'preserve all paths and inspect the interrupted compiler lifecycle'
        }
        $targetKind = if ($scopePresent) { 'scope' } else {
            'compiler-tombstone'
        }
        $targetPath = if ($scopePresent) { $compiler.scope_path } else {
            $compiler.tombstone_path
        }
        $target = Get-AstroModernRecoveryTargetProbe $targetPath
        $ownerSecond = Get-AstroDetachedProcessProbe `
            -ProcessId ([int]$compiler.owner.pid) `
            -ProcessStartUtcTicks ([long]$compiler.owner.process_start_utc_ticks) `
            -SessionId ([int]$compiler.owner.session_id)
        Assert-AstroModernRecoveryOwnerInactive $ownerSecond
        $protocolSecond = Get-AstroModernRecoveryProtocolState
        Assert-AstroModernRecoveryProtocolAbsent $protocolSecond
        $bindings = [ordered]@{
            protocol = Get-AstroModernRecoveryScriptBinding $protocolPath
            strict_json = Get-AstroModernRecoveryScriptBinding $strictJsonPath
            compiler_state =
                Get-AstroModernRecoveryScriptBinding $compilerStatePath
            launcher_lock = Get-AstroModernRecoveryScriptBinding $lockHelperPath
            recovery_script =
                Get-AstroModernRecoveryScriptBinding $PSCommandPath
        }
        $probe = Write-AstroModernRecoveryRecord `
            $transaction '000-probe.json' 0 -Payload ([ordered]@{
                issue = $Issue
                source_issue = $compiler.source_issue
                run_id = $RunId
                role = $Role
                transaction_id = $TransactionId
                principal = $principal
                intent_path = $compiler.intent.Path
                intent_sha256 = $compiler.intent.Sha256
                fault_path = $compiler.fault.Path
                fault_sha256 = $compiler.fault.Sha256
                optional_authorization_sha256 = if (
                    $null -eq $compiler.authorization
                ) { $null } else { $compiler.authorization.Sha256 }
                optional_renamed_sha256 = if ($null -eq $compiler.renamed) {
                    $null
                } else { $compiler.renamed.Sha256 }
                exact_owner = $compiler.owner
                owner_probe_first = $ownerFirst
                owner_probe_second = $ownerSecond
                source_scope_path = $compiler.scope_path
                source_compiler_tombstone_path = $compiler.tombstone_path
                target_kind = $targetKind
                target = $target
                protocol_first = $protocolFirst
                protocol_second = $protocolSecond
                script_bindings = $bindings
                native_compiler = $nativeCompiler
                destructive_authority = 'none'
                cost = [ordered]@{
                    explicit_scope_count = 1
                    inventory_entry_count = $target.inventory.entry_count
                    inventory_canonical_bytes =
                        $target.inventory.canonical_bytes_length
                    workspace_scan = $false
                    per_entry_process_spawn = $false
                }
            })
        $line = Get-AstroModernRecoveryTrackerLine $probe
        [ordered]@{
            schema = 'astrolabe.detached-modern-compiler-recovery-prepare-result.v1'
            issue = $Issue
            source_issue = $compiler.source_issue
            run_id = $RunId
            role = $Role
            transaction_id = $TransactionId
            transaction_path = $transaction
            probe_path = $probe.Path
            probe_sha256 = $probe.Sha256
            target_path = $target.path
            target_file_id = $target.file_id
            inventory_sha256 = $target.inventory.sha256
            inventory_entry_count = $target.inventory.entry_count
            tracker_authorization_line = $line
            next = 'post the exact line on the driving issue, then invoke Recover'
        } | ConvertTo-Json -Depth 24
        break
    }
    'Recover' {
        if ($TransactionId -cnotmatch '^[0-9a-f]{32}$' -or
            $ExpectedProbeSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]::IsNullOrWhiteSpace($TrackerCommentUrl)) {
            Fail-AstroModernRecovery `
                'ASTRO_DETACHED_MODERN_RECOVERY_ARGUMENT_INVALID' `
                'Recover requires exact transaction, probe hash, and tracker URL' `
                'pass the immutable values printed by Prepare'
        }
        $transaction = Get-AstroModernRecoveryTransactionDirectory `
            $runDirectory $TransactionId
        $probe = Read-AstroModernRecoveryRecord `
            $transaction '000-probe.json' $ExpectedProbeSha256
        if ($probe.Sequence -ne 0 -or
            [int]$probe.Payload.issue -ne $Issue -or
            [string]$probe.Payload.run_id -cne $RunId -or
            [string]$probe.Payload.role -cne $Role) {
            Fail-AstroModernRecovery `
                'ASTRO_DETACHED_MODERN_RECOVERY_PROBE_BINDING_INVALID' `
                'probe sequence/issue/run/role binding differs' `
                'preserve state and pass the exact Prepare result'
        }
        Assert-AstroModernRecoveryScriptBindings `
            $probe.Payload.script_bindings
        $principal = Get-AstroModernRecoveryPrincipal
        if ([string]$principal.sid -cne [string]$probe.Payload.principal.sid) {
            Fail-AstroModernRecovery `
                'ASTRO_DETACHED_MODERN_RECOVERY_PRINCIPAL_INVALID' `
                'Recover principal differs from Prepare principal' `
                'run Recover as the exact same Windows principal'
        }
        $existingCompletionPath = Join-Path $transaction '003-completion.json'
        if ([IO.File]::Exists($existingCompletionPath)) {
            $tracker = Read-AstroModernRecoveryTrackerEvidence `
                $TrackerCommentUrl $probe
            $compiler = Get-AstroModernRecoveryCompilerBinding $runDirectory
            if ([int]$compiler.source_issue -ne
                    [int]$probe.Payload.source_issue -or
                $compiler.intent.Sha256 -cne
                    [string]$probe.Payload.intent_sha256 -or
                $compiler.fault.Sha256 -cne
                    [string]$probe.Payload.fault_sha256) {
                Fail-AstroModernRecovery `
                    'ASTRO_DETACHED_MODERN_RECOVERY_SOURCE_RECORD_DRIFT' `
                    'compiler intent/fault differs during completed readback' `
                    'preserve transaction state and investigate source record drift'
            }
            $authorization = Read-AstroModernRecoveryRecord `
                $transaction '001-authorization.json'
            $finalization = Read-AstroModernRecoveryRecord `
                $transaction '002-finalization.json'
            $completion = Read-AstroModernRecoveryRecord `
                $transaction '003-completion.json'
            if ($authorization.Sequence -ne 1 -or
                $authorization.Document.previous_name -cne $probe.Name -or
                $authorization.Document.previous_sha256 -cne $probe.Sha256 -or
                $finalization.Sequence -ne 2 -or
                $finalization.Document.previous_name -cne
                    $authorization.Name -or
                $finalization.Document.previous_sha256 -cne
                    $authorization.Sha256 -or
                $completion.Sequence -ne 3 -or
                $completion.Document.previous_name -cne $finalization.Name -or
                $completion.Document.previous_sha256 -cne
                    $finalization.Sha256 -or
                [string]$authorization.Payload.tracker.body_sha256 -cne
                    $tracker.body_sha256) {
                Fail-AstroModernRecovery `
                    'ASTRO_DETACHED_MODERN_RECOVERY_COMPLETED_CHAIN_INVALID' `
                    'completed recovery record chain or tracker binding differs' `
                    'preserve every transaction byte and inspect the immutable chain'
            }
            $recoveryTombstone = Join-Path `
                $transaction 'recovered-compiler-state.tombstone'
            $terminal = Get-AstroModernRecoveryTargetState `
                ([string]$probe.Payload.source_scope_path) `
                ([string]$probe.Payload.source_compiler_tombstone_path) `
                $recoveryTombstone
            if ([string]$terminal.scope.State -cne 'absent' -or
                [string]$terminal.compiler_tombstone.State -cne 'absent' -or
                [string]$terminal.recovery_tombstone.State -cne 'absent') {
                Fail-AstroModernRecovery `
                    'ASTRO_DETACHED_MODERN_RECOVERY_COMPLETED_STATE_DRIFT' `
                    'completed recovery has a non-absent source or tombstone' `
                    'preserve all state and investigate namespace recreation'
            }
            [ordered]@{
                schema =
                    'astrolabe.detached-modern-compiler-recovery-complete.v1'
                issue = $Issue
                source_issue = $compiler.source_issue
                run_id = $RunId
                role = $Role
                transaction_id = $TransactionId
                transaction_path = $transaction
                probe_sha256 = $probe.Sha256
                authorization_sha256 = $authorization.Sha256
                finalization_sha256 = $finalization.Sha256
                completion_path = $completion.Path
                completion_sha256 = $completion.Sha256
                target_file_id = $probe.Payload.target.file_id
                inventory_sha256 = $probe.Payload.target.inventory.sha256
                inventory_entry_count =
                    $probe.Payload.target.inventory.entry_count
                terminal = $terminal
                completed_readback = $true
                native_compiler_spawned = $false
            } | ConvertTo-Json -Depth 24
            return
        }
        $nativeCompiler = Import-AstroModernRecoveryNativeScoped `
            $transaction recover
        . $lockHelperPath
        $trackerFirst = Read-AstroModernRecoveryTrackerEvidence `
            $TrackerCommentUrl $probe
        $launcherLockPath = Join-Path (
            Join-Path $script:AstroDetachedCanonicalRoot '.tmp'
        ) 'astrolabe-launcher.lock'
        $mutexLease = Enter-AstroLauncherLockMutex $launcherLockPath
        if (-not $mutexLease.Acquired) {
            $contendedMutexName = [string]$mutexLease.Name
            Exit-AstroLauncherLockMutex $mutexLease
            Fail-AstroModernRecovery `
                'ASTRO_DETACHED_MODERN_RECOVERY_MUTEX_CONTENDED' `
                "canonical launcher mutex is held: $contendedMutexName" `
                'preserve state and invoke Recover only after the active owner exits'
        }
        try {
            $compiler = Get-AstroModernRecoveryCompilerBinding $runDirectory
            if ([int]$compiler.source_issue -ne
                    [int]$probe.Payload.source_issue -or
                $compiler.intent.Sha256 -cne
                    [string]$probe.Payload.intent_sha256 -or
                $compiler.fault.Sha256 -cne
                    [string]$probe.Payload.fault_sha256) {
                Fail-AstroModernRecovery `
                    'ASTRO_DETACHED_MODERN_RECOVERY_SOURCE_RECORD_DRIFT' `
                    'compiler intent/fault hashes differ from Prepare' `
                    'preserve all state and start a fresh transaction'
            }
            $ownerFirst = Get-AstroDetachedProcessProbe `
                -ProcessId ([int]$compiler.owner.pid) `
                -ProcessStartUtcTicks (
                    [long]$compiler.owner.process_start_utc_ticks
                ) `
                -SessionId ([int]$compiler.owner.session_id)
            Assert-AstroModernRecoveryOwnerInactive $ownerFirst
            $protocolFirst = Get-AstroModernRecoveryProtocolState
            Assert-AstroModernRecoveryProtocolAbsent $protocolFirst

            $authorizationPath = Join-Path $transaction '001-authorization.json'
            if ([IO.File]::Exists($authorizationPath)) {
                $authorization = Read-AstroModernRecoveryRecord `
                    $transaction '001-authorization.json'
                if ($authorization.Sequence -ne 1 -or
                    [string]$authorization.Payload.probe_sha256 -cne
                        $probe.Sha256 -or
                    [string]$authorization.Payload.tracker.body_sha256 -cne
                        $trackerFirst.body_sha256) {
                    Fail-AstroModernRecovery `
                        'ASTRO_DETACHED_MODERN_RECOVERY_AUTHORIZATION_DRIFT' `
                        'existing authorization differs from probe/tracker' `
                        'preserve transaction and target bytes'
                }
            }
            else {
                $target = Get-AstroModernRecoveryTargetProbe `
                    ([string]$probe.Payload.target.path)
                if ([string]$target.file_id -cne
                        [string]$probe.Payload.target.file_id -or
                    [string]$target.security_sddl_sha256 -cne
                        [string]$probe.Payload.target.security_sddl_sha256 -or
                    [string]$target.inventory.sha256 -cne
                        [string]$probe.Payload.target.inventory.sha256 -or
                    [int]$target.inventory.entry_count -ne
                        [int]$probe.Payload.target.inventory.entry_count) {
                    Fail-AstroModernRecovery `
                        'ASTRO_DETACHED_MODERN_RECOVERY_TARGET_DRIFT' `
                        'compiler target identity/security/inventory differs from Prepare' `
                        'preserve every byte and start a fresh transaction'
                }
                $ownerSecond = Get-AstroDetachedProcessProbe `
                    -ProcessId ([int]$compiler.owner.pid) `
                    -ProcessStartUtcTicks (
                        [long]$compiler.owner.process_start_utc_ticks
                    ) `
                    -SessionId ([int]$compiler.owner.session_id)
                Assert-AstroModernRecoveryOwnerInactive $ownerSecond
                $protocolSecond = Get-AstroModernRecoveryProtocolState
                Assert-AstroModernRecoveryProtocolAbsent $protocolSecond
                $trackerSecond = Read-AstroModernRecoveryTrackerEvidence `
                    $TrackerCommentUrl $probe
                if ($trackerSecond.body_sha256 -cne
                        $trackerFirst.body_sha256 -or
                    $trackerSecond.updated_at -cne $trackerFirst.updated_at) {
                    Fail-AstroModernRecovery `
                        'ASTRO_DETACHED_MODERN_RECOVERY_TRACKER_CHANGED' `
                        'tracker authorization changed between exact reads' `
                        'preserve state and obtain a fresh stable owner comment'
                }
                $authorization = Write-AstroModernRecoveryRecord `
                    $transaction '001-authorization.json' 1 `
                    $probe.Name $probe.Sha256 ([ordered]@{
                        issue = $Issue
                        source_issue = $compiler.source_issue
                        run_id = $RunId
                        role = $Role
                        transaction_id = $TransactionId
                        exact_recovery_owner = $principal
                        probe_sha256 = $probe.Sha256
                        tracker = $trackerSecond
                        owner_probe_first = $ownerFirst
                        owner_probe_second = $ownerSecond
                        protocol_first = $protocolFirst
                        protocol_second = $protocolSecond
                        target_reprobe = $target
                        native_compiler = $nativeCompiler
                        launcher_mutex = [ordered]@{
                            name = [string]$mutexLease.Name
                            acquired = [bool]$mutexLease.Acquired
                            was_abandoned = [bool]$mutexLease.WasAbandoned
                            created_new = [bool]$mutexLease.CreatedNew
                            root = [string]$mutexLease.Root
                            root_final_path =
                                [string]$mutexLease.RootFinalPath
                            root_identity =
                                [string]$mutexLease.RootIdentity
                        }
                        namespace_operation =
                            'same-volume-handle-no-replace-rename'
                        deletion_operation =
                            'exact-finalized-ordinary-inventory-only'
                        interruption_policy =
                            'resume-this-immutable-transaction'
                    })
            }

            $recoveryTombstone = Join-Path `
                $transaction 'recovered-compiler-state.tombstone'
            $finalizationPath = Join-Path `
                $transaction '002-finalization.json'
            $completionPath = Join-Path $transaction '003-completion.json'
            $states = Get-AstroModernRecoveryTargetState `
                ([string]$probe.Payload.source_scope_path) `
                ([string]$probe.Payload.source_compiler_tombstone_path) `
                $recoveryTombstone
            $scopePresent = [string]$states.scope.State -ceq 'present'
            $compilerTombstonePresent =
                [string]$states.compiler_tombstone.State -ceq 'present'
            $recoveryTombstonePresent =
                [string]$states.recovery_tombstone.State -ceq 'present'
            $allNamespacePathsAbsent = -not $scopePresent -and
                -not $compilerTombstonePresent -and
                -not $recoveryTombstonePresent
            if ($allNamespacePathsAbsent -and
                [IO.File]::Exists($finalizationPath)) {
                $finalization = Read-AstroModernRecoveryRecord `
                    $transaction '002-finalization.json'
                if ($finalization.Sequence -ne 2 -or
                    [string]$finalization.Payload.authorization_sha256 -cne
                        $authorization.Sha256) {
                    Fail-AstroModernRecovery `
                        'ASTRO_DETACHED_MODERN_RECOVERY_FINALIZATION_DRIFT' `
                        'existing finalization differs from authorization' `
                        'preserve transaction bytes and investigate chain drift'
                }
                $terminal = $states
                $completion = Write-AstroModernRecoveryRecord `
                    $transaction '003-completion.json' 3 `
                    $finalization.Name $finalization.Sha256 ([ordered]@{
                        issue = $Issue
                        source_issue = $compiler.source_issue
                        run_id = $RunId
                        role = $Role
                        transaction_id = $TransactionId
                        probe_sha256 = $probe.Sha256
                        authorization_sha256 = $authorization.Sha256
                        finalization_sha256 = $finalization.Sha256
                        target_file_id = $probe.Payload.target.file_id
                        inventory_sha256 =
                            $probe.Payload.target.inventory.sha256
                        terminal = $terminal
                        all_source_and_tombstone_states = 'absent'
                        resumed_after_finalized_deletion = $true
                        source_of_truth = $transaction
                    })
                [ordered]@{
                    schema =
                        'astrolabe.detached-modern-compiler-recovery-complete.v1'
                    issue = $Issue
                    source_issue = $compiler.source_issue
                    run_id = $RunId
                    role = $Role
                    transaction_id = $TransactionId
                    transaction_path = $transaction
                    probe_sha256 = $probe.Sha256
                    authorization_sha256 = $authorization.Sha256
                    finalization_sha256 = $finalization.Sha256
                    completion_path = $completion.Path
                    completion_sha256 = $completion.Sha256
                    target_file_id = $probe.Payload.target.file_id
                    inventory_sha256 =
                        $probe.Payload.target.inventory.sha256
                    inventory_entry_count =
                        $probe.Payload.target.inventory.entry_count
                    terminal = $terminal
                    resumed_after_finalized_deletion = $true
                } | ConvertTo-Json -Depth 24
                return
            }
            if ($recoveryTombstonePresent) {
                if ($scopePresent -or $compilerTombstonePresent) {
                    Fail-AstroModernRecovery `
                        'ASTRO_DETACHED_MODERN_RECOVERY_RESUME_STATE_INVALID' `
                        'recovery tombstone and original source coexist' `
                        'preserve all paths and inspect interrupted namespace state'
                }
            }
            elseif ($scopePresent -eq $compilerTombstonePresent) {
                Fail-AstroModernRecovery `
                    'ASTRO_DETACHED_MODERN_RECOVERY_SOURCE_STATE_INVALID' `
                    'expected exactly one original compiler source before rename' `
                    'preserve all paths and inspect source/tombstone state'
            }

            if (-not $recoveryTombstonePresent) {
                $sourcePath = if ($scopePresent) {
                    [string]$probe.Payload.source_scope_path
                }
                else {
                    [string]$probe.Payload.source_compiler_tombstone_path
                }
                if (-not [string]::Equals(
                        [IO.Path]::GetFullPath($sourcePath).TrimEnd('\', '/'),
                        [IO.Path]::GetFullPath(
                            [string]$probe.Payload.target.path
                        ).TrimEnd('\', '/'),
                        [StringComparison]::OrdinalIgnoreCase
                    )) {
                    Fail-AstroModernRecovery `
                        'ASTRO_DETACHED_MODERN_RECOVERY_SOURCE_KIND_DRIFT' `
                        'present original source differs from the probed target path' `
                        'preserve state and start a fresh transaction'
                }
                $sourceHandle = $null
                $parentHandle = $null
                try {
                    $sourceHandle =
                        [AstroLauncherLockNative]::OpenExactDeleteDirectory(
                            $sourcePath
                        )
                    $parentHandle =
                        [AstroLauncherLockNative]::OpenExactRenameDirectory(
                            $transaction
                        )
                    if ([AstroLauncherLockNative]::GetFileIdentity(
                            $sourceHandle
                        ) -cne [string]$probe.Payload.target.file_id) {
                        throw 'source FILE_ID differs immediately before rename'
                    }
                    [AstroLauncherLockNative]::RenameDirectoryHandleNoReplace(
                        $sourceHandle,
                        $parentHandle,
                        'recovered-compiler-state.tombstone'
                    )
                    $final = ConvertFrom-AstroNativeFinalPath (
                        [AstroLauncherLockNative]::GetFileFinalPath($sourceHandle)
                    )
                    if ([AstroLauncherLockNative]::GetFileIdentity(
                            $sourceHandle
                        ) -cne [string]$probe.Payload.target.file_id -or
                        -not [string]::Equals(
                            [IO.Path]::GetFullPath($final).TrimEnd('\', '/'),
                            [IO.Path]::GetFullPath($recoveryTombstone).
                                TrimEnd('\', '/'),
                            [StringComparison]::OrdinalIgnoreCase
                        )) {
                        throw 'retained post-rename identity/path differs'
                    }
                }
                finally {
                    if ($null -ne $parentHandle) { $parentHandle.Dispose() }
                    if ($null -ne $sourceHandle) { $sourceHandle.Dispose() }
                }
            }
            $postRename = Get-AstroModernRecoveryTargetState `
                ([string]$probe.Payload.source_scope_path) `
                ([string]$probe.Payload.source_compiler_tombstone_path) `
                $recoveryTombstone
            if ([string]$postRename.scope.State -cne 'absent' -or
                [string]$postRename.compiler_tombstone.State -cne 'absent' -or
                [string]$postRename.recovery_tombstone.State -cne 'present') {
                Fail-AstroModernRecovery `
                    'ASTRO_DETACHED_MODERN_RECOVERY_RENAME_READBACK' `
                    'source/tombstone states differ after handle-bound rename' `
                    'preserve the transaction tombstone and immutable authorization'
            }
            $tombstoneProbe = Get-AstroModernRecoveryTargetProbe `
                $recoveryTombstone
            if ([string]$tombstoneProbe.file_id -cne
                    [string]$probe.Payload.target.file_id -or
                [string]$tombstoneProbe.inventory.sha256 -cne
                    [string]$probe.Payload.target.inventory.sha256) {
                Fail-AstroModernRecovery `
                    'ASTRO_DETACHED_MODERN_RECOVERY_TOMBSTONE_DRIFT' `
                    'recovery tombstone differs from the authorized target' `
                    'preserve the tombstone and all authorization evidence'
            }
            if ([IO.File]::Exists($finalizationPath)) {
                $finalization = Read-AstroModernRecoveryRecord `
                    $transaction '002-finalization.json'
                if ($finalization.Sequence -ne 2 -or
                    [string]$finalization.Payload.authorization_sha256 -cne
                        $authorization.Sha256) {
                    Fail-AstroModernRecovery `
                        'ASTRO_DETACHED_MODERN_RECOVERY_FINALIZATION_DRIFT' `
                        'existing finalization differs from authorization' `
                        'preserve transaction and tombstone bytes'
                }
            }
            else {
                $finalization = Write-AstroModernRecoveryRecord `
                    $transaction '002-finalization.json' 2 `
                    $authorization.Name $authorization.Sha256 ([ordered]@{
                        issue = $Issue
                        source_issue = $compiler.source_issue
                        run_id = $RunId
                        role = $Role
                        transaction_id = $TransactionId
                        probe_sha256 = $probe.Sha256
                        authorization_sha256 = $authorization.Sha256
                        source_scope_path =
                            $probe.Payload.source_scope_path
                        source_compiler_tombstone_path =
                            $probe.Payload.source_compiler_tombstone_path
                        source_states = [ordered]@{
                            scope = $postRename.scope.State
                            compiler_tombstone =
                                $postRename.compiler_tombstone.State
                        }
                        recovery_tombstone_path = $recoveryTombstone
                        recovery_tombstone_file_id = $tombstoneProbe.file_id
                        inventory_schema =
                            $tombstoneProbe.inventory.schema
                        inventory_encoding =
                            $tombstoneProbe.inventory.encoding
                        inventory_sha256 =
                            $tombstoneProbe.inventory.sha256
                        inventory_entry_count =
                            $tombstoneProbe.inventory.entry_count
                        deletion_authority =
                            'only-this-finalized-tombstone-inventory'
                    })
            }

            $tombstoneState =
                Get-AstroModernRecoveryPathEntryState $recoveryTombstone
            if ([string]$tombstoneState.State -ceq 'present') {
                $inventory =
                    Get-AstroOrdinaryDirectoryTreeInventoryLongPath `
                        $recoveryTombstone
                if ([string]$inventory.sha256 -cne
                    [string]$finalization.Payload.inventory_sha256) {
                    Fail-AstroModernRecovery `
                        'ASTRO_DETACHED_MODERN_RECOVERY_DELETE_INVENTORY_DRIFT' `
                        'finalized tombstone inventory changed before deletion' `
                        'preserve the tombstone and immutable finalization'
                }
                Remove-AstroOrdinaryDirectoryTreeLongPath `
                    -LiteralPath $recoveryTombstone `
                    -ExpectedInventorySchema (
                        [string]$finalization.Payload.inventory_schema
                    ) `
                    -ExpectedInventoryEncoding (
                        [string]$finalization.Payload.inventory_encoding
                    ) `
                    -ExpectedInventorySha256 (
                        [string]$finalization.Payload.inventory_sha256
                    )
            }
            elseif ([string]$tombstoneState.State -cne 'absent') {
                Fail-AstroModernRecovery `
                    'ASTRO_DETACHED_MODERN_RECOVERY_TOMBSTONE_UNEVALUABLE' `
                    "recovery tombstone state is $($tombstoneState.State)" `
                    'preserve the transaction and repair exact namespace observation'
            }
            $terminal = Get-AstroModernRecoveryTargetState `
                ([string]$probe.Payload.source_scope_path) `
                ([string]$probe.Payload.source_compiler_tombstone_path) `
                $recoveryTombstone
            if ([string]$terminal.scope.State -cne 'absent' -or
                [string]$terminal.compiler_tombstone.State -cne 'absent' -or
                [string]$terminal.recovery_tombstone.State -cne 'absent') {
                Fail-AstroModernRecovery `
                    'ASTRO_DETACHED_MODERN_RECOVERY_TERMINAL_STATE_INVALID' `
                    'one or more exact source/tombstone paths are not absent' `
                    'preserve the transaction and inspect exact terminal states'
            }
            if ([IO.File]::Exists($completionPath)) {
                $completion = Read-AstroModernRecoveryRecord `
                    $transaction '003-completion.json'
            }
            else {
                $completion = Write-AstroModernRecoveryRecord `
                    $transaction '003-completion.json' 3 `
                    $finalization.Name $finalization.Sha256 ([ordered]@{
                        issue = $Issue
                        source_issue = $compiler.source_issue
                        run_id = $RunId
                        role = $Role
                        transaction_id = $TransactionId
                        probe_sha256 = $probe.Sha256
                        authorization_sha256 = $authorization.Sha256
                        finalization_sha256 = $finalization.Sha256
                        target_file_id = $probe.Payload.target.file_id
                        inventory_sha256 =
                            $probe.Payload.target.inventory.sha256
                        terminal = $terminal
                        all_source_and_tombstone_states = 'absent'
                        source_of_truth = $transaction
                    })
            }
            [ordered]@{
                schema = 'astrolabe.detached-modern-compiler-recovery-complete.v1'
                issue = $Issue
                source_issue = $compiler.source_issue
                run_id = $RunId
                role = $Role
                transaction_id = $TransactionId
                transaction_path = $transaction
                probe_sha256 = $probe.Sha256
                authorization_sha256 = $authorization.Sha256
                finalization_sha256 = $finalization.Sha256
                completion_path = $completion.Path
                completion_sha256 = $completion.Sha256
                target_file_id = $probe.Payload.target.file_id
                inventory_sha256 = $probe.Payload.target.inventory.sha256
                inventory_entry_count =
                    $probe.Payload.target.inventory.entry_count
                terminal = $terminal
            } | ConvertTo-Json -Depth 24
        }
        finally {
            Exit-AstroLauncherLockMutex $mutexLease
        }
        break
    }
}
