<#
.SYNOPSIS
    Tracker-bound recovery of exact opaque detached-compiler directories.

.DESCRIPTION
    Prepare creates a normal-token transaction without reading protected targets.
    Probe requires the same principal under an elevated token, confines its own
    Add-Type compilation, and publishes two equal handle-bound FILE_ID/security/
    content inventories. Recover re-verifies an owner-authored GitHub comment and
    the target state twice, writes durable authorization, handle-renames each exact
    source into the transaction, and deletes only finalized ordinary inventories.
    Interrupted Recover calls resume from the immutable authorization/finalization
    records. No ACL mutation, PID inference, or pathname-only deletion is allowed.
    Refs #717.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Prepare', 'Probe', 'Recover')]
    [string]$Operation,
    [Parameter(Mandatory)][string]$Issue,
    [string]$TransactionId = '',
    [string]$TargetNamesJson = '[]',
    [string]$ExpectedIntentSha256 = '',
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

$script:AstroRecoveryRoot = Join-Path `
    (Join-Path $script:AstroDetachedCanonicalRoot '.tmp') `
    'detached-compiler-recovery'
$script:AstroRecoveryMaximumBytes = 8MB

function Fail-AstroRecovery {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Remediation
    )
    $document = [ordered]@{
        schema = 'astrolabe.detached-compiler-recovery-error.v1'
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

function ConvertTo-AstroRecoveryPositiveInt {
    param([string]$Value, [string]$Name)
    $parsed = 0
    if (-not [int]::TryParse(
            $Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsed
        ) -or $parsed -le 0) {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_ARGUMENT_INVALID' `
            "$Name must be a positive invariant integer; received '$Value'" `
            'pass the exact driving issue number'
    }
    return $parsed
}

function Get-AstroRecoveryPrincipal {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $integritySids = @(
        $identity.Groups |
            ForEach-Object { $_.Value } |
            Where-Object { $_ -cmatch '^S-1-16-[0-9]+$' } |
            Sort-Object -Unique
    )
    return [ordered]@{
        name = [string]$identity.Name
        sid = [string]$identity.User.Value
        is_elevated_administrator = [bool]$principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
        integrity_sids = [string[]]$integritySids
        process = Get-AstroDetachedCurrentIdentity
    }
}

function Get-AstroRecoveryScriptBinding {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.File]::Exists($full)) {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_SCRIPT_MISSING' `
            "bound recovery dependency is missing: $full" `
            'restore the exact tracked script before starting a recovery transaction'
    }
    return [ordered]@{
        path = $full
        sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.
            ToLowerInvariant()
    }
}

function ConvertFrom-AstroRecoveryTargetNames {
    param([Parameter(Mandatory)][string]$Json)
    try {
        $envelope = ConvertFrom-Json -InputObject ('{"value":' + $Json + '}')
        $values = @($envelope.value)
    }
    catch {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_TARGET_JSON_INVALID' `
            $_.Exception.Message `
            'pass a JSON array of exact direct .tmp leaf names'
    }
    if ($values.Count -lt 1 -or $values.Count -gt 32) {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_TARGET_COUNT_INVALID' `
            "target count must be 1..32; observed $($values.Count)" `
            'enumerate only the exact opaque compiler directories authorized by the issue'
    }
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    [string[]]$names = @(
        foreach ($value in $values) {
            if ($value -isnot [string] -or
                [string]$value -cnotmatch '^[a-z0-9]{8}$' -or
                -not $seen.Add([string]$value)) {
                Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_TARGET_NAME_INVALID' `
                    "target names must be unique eight-character lowercase ASCII leaves; observed '$value'" `
                    'pass the exact CodeDOM directory names from the tracker evidence'
            }
            [string]$value
        }
    )
    [Array]::Sort($names, [StringComparer]::Ordinal)
    return ,$names
}

function Initialize-AstroRecoveryRoot {
    $tmp = Assert-AstroDetachedOrdinaryDirectory (
        Join-Path $script:AstroDetachedCanonicalRoot '.tmp'
    )
    if (-not [IO.Directory]::Exists($script:AstroRecoveryRoot)) {
        try {
            [void](New-AstroDetachedDirectoryNoReplace $script:AstroRecoveryRoot)
        }
        catch {
            if (-not [IO.Directory]::Exists($script:AstroRecoveryRoot)) { throw }
        }
    }
    $root = Assert-AstroDetachedOrdinaryDirectory $script:AstroRecoveryRoot
    if ([IO.Path]::GetDirectoryName($root).TrimEnd('\', '/') -cne $tmp) {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_ROOT_ESCAPE' `
            "recovery root escaped canonical .tmp: $root" `
            'preserve the namespace and restore the canonical recovery root'
    }
    return $root
}

function Get-AstroRecoveryTransactionDirectory {
    param([Parameter(Mandatory)][string]$Id)
    if ($Id -cnotmatch '^[0-9a-f]{32}$') {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_TRANSACTION_INVALID' `
            "transaction id is not a canonical GUID N value: '$Id'" `
            'pass the exact transaction id printed by Prepare'
    }
    return [IO.Path]::GetFullPath((Join-Path (Initialize-AstroRecoveryRoot) $Id))
}

function Write-AstroRecoveryRecord {
    param(
        [Parameter(Mandatory)][string]$TransactionDirectory,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Sequence,
        [AllowEmptyString()][string]$PreviousName = '',
        [AllowEmptyString()][string]$PreviousSha256 = '',
        [Parameter(Mandatory)]$Payload
    )
    $transaction = Assert-AstroDetachedOrdinaryDirectory $TransactionDirectory
    if ([IO.Path]::GetDirectoryName($transaction).TrimEnd('\', '/') -cne
            (Initialize-AstroRecoveryRoot) -or
        [IO.Path]::GetFileName($transaction) -cnotmatch '^[0-9a-f]{32}$' -or
        $Name -cnotmatch '^[0-9]{3}-[a-z0-9-]+\.json$') {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_RECORD_PATH_INVALID' `
            "invalid transaction/record path binding: $transaction / $Name" `
            'preserve the transaction and use only canonical append-only record names'
    }
    if (($Sequence -eq 0 -and
            (-not [string]::IsNullOrEmpty($PreviousName) -or
             -not [string]::IsNullOrEmpty($PreviousSha256))) -or
        ($Sequence -gt 0 -and
            ($PreviousName -cnotmatch '^[0-9]{3}-[a-z0-9-]+\.json$' -or
             $PreviousSha256 -cnotmatch '^[0-9a-f]{64}$'))) {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_RECORD_LINK_INVALID' `
            "invalid predecessor for sequence $Sequence / $Name" `
            'preserve the transaction and link only the exact prior immutable record'
    }
    $payloadBytes = Get-AstroDetachedUtf8Bytes (
        $Payload | ConvertTo-Json -Depth 64 -Compress
    )
    $writer = Get-AstroDetachedCurrentIdentity
    $document = [ordered]@{
        schema = 'astrolabe.detached-compiler-recovery-record.v1'
        transaction_id = [IO.Path]::GetFileName($transaction)
        sequence = $Sequence
        name = $Name
        written_utc_ticks = [DateTime]::UtcNow.Ticks
        writer_pid = $writer.pid
        writer_process_start_utc_ticks = $writer.process_start_utc_ticks
        writer_session_id = $writer.session_id
        previous_name = $PreviousName
        previous_sha256 = $PreviousSha256
        payload_sha256 = Get-AstroDetachedSha256Bytes $payloadBytes
        payload_bytes = [long]$payloadBytes.Length
        payload_json_base64 = [Convert]::ToBase64String($payloadBytes)
    }
    $bytes = Get-AstroDetachedUtf8Bytes (
        $document | ConvertTo-Json -Compress
    )
    if ($bytes.Length -gt $script:AstroRecoveryMaximumBytes) {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_RECORD_TOO_LARGE' `
            "$Name exceeds $script:AstroRecoveryMaximumBytes bytes" `
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
    finally { $stream.Dispose() }
    $snapshot = Read-AstroDetachedOrdinaryFile $path $script:AstroRecoveryMaximumBytes
    $hash = Get-AstroDetachedSha256Bytes $bytes
    if ($snapshot.Sha256 -cne $hash -or $snapshot.Length -ne $bytes.Length) {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_RECORD_READBACK' `
            "record readback differs after durable create-new write: $path" `
            'preserve the transaction bytes and inspect the storage fault'
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

function Get-AstroRecoveryStrictValue {
    param($Strict, [string]$Name, [string]$Kind)
    if (-not $Strict.Properties.ContainsKey($Name)) {
        throw "missing recovery record property '$Name'"
    }
    $entry = $Strict.Properties[$Name]
    if ([string]$entry.Kind -cne $Kind) {
        throw "recovery record property '$Name' must be $Kind"
    }
    return $entry.Value
}

function Read-AstroRecoveryRecord {
    param(
        [Parameter(Mandatory)][string]$TransactionDirectory,
        [Parameter(Mandatory)][string]$Name,
        [AllowEmptyString()][string]$ExpectedSha256 = ''
    )
    $path = Join-Path $TransactionDirectory $Name
    $snapshot = Read-AstroDetachedOrdinaryFile $path $script:AstroRecoveryMaximumBytes
    if (-not [string]::IsNullOrEmpty($ExpectedSha256) -and
        $snapshot.Sha256 -cne $ExpectedSha256) {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_RECORD_HASH_MISMATCH' `
            "$Name hash differs: expected=$ExpectedSha256 observed=$($snapshot.Sha256)" `
            'preserve every byte and pass the exact independently read record hash'
    }
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($snapshot.Bytes)
        $strict = ConvertFrom-AstroStrictFlatJsonObject $text
        $required = @(
            'schema','transaction_id','sequence','name','written_utc_ticks',
            'writer_pid','writer_process_start_utc_ticks','writer_session_id',
            'previous_name','previous_sha256','payload_sha256','payload_bytes',
            'payload_json_base64'
        )
        if (@($strict.Names).Count -ne $required.Count) {
            throw 'record property count differs'
        }
        for ($index = 0; $index -lt $required.Count; $index++) {
            if ([string]$strict.Names[$index] -cne $required[$index]) {
                throw "record property order differs at $index"
            }
        }
        if ([string](Get-AstroRecoveryStrictValue $strict schema string) -cne
            'astrolabe.detached-compiler-recovery-record.v1' -or
            [string](Get-AstroRecoveryStrictValue $strict name string) -cne $Name -or
            [string](Get-AstroRecoveryStrictValue $strict transaction_id string) -cne
                [IO.Path]::GetFileName($TransactionDirectory)) {
            throw 'record schema/name/transaction binding differs'
        }
        $sequence = [int]::Parse(
            [string](Get-AstroRecoveryStrictValue $strict sequence integer),
            [Globalization.CultureInfo]::InvariantCulture
        )
        $payloadHash = [string](
            Get-AstroRecoveryStrictValue $strict payload_sha256 string
        )
        $payloadLength = [long]::Parse(
            [string](Get-AstroRecoveryStrictValue $strict payload_bytes integer),
            [Globalization.CultureInfo]::InvariantCulture
        )
        $payloadBytes = [Convert]::FromBase64String(
            [string](Get-AstroRecoveryStrictValue $strict payload_json_base64 string)
        )
        if ($payloadBytes.Length -ne $payloadLength -or
            (Get-AstroDetachedSha256Bytes $payloadBytes) -cne $payloadHash) {
            throw 'payload length/hash differs'
        }
        $payloadText = [Text.UTF8Encoding]::new(
            $false, $true
        ).GetString($payloadBytes)
        $payload = ConvertFrom-Json -InputObject $payloadText
    }
    catch {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_RECORD_INVALID' `
            "$Name strict decode failed: $($_.Exception.Message)" `
            'preserve the transaction; never recover from malformed durable evidence'
    }
    return [pscustomobject]@{
        Name = $Name
        Path = $path
        Sequence = $sequence
        Sha256 = $snapshot.Sha256
        Length = $snapshot.Length
        Payload = $payload
    }
}

function Write-AstroRecoveryCompilerAuxRecord {
    param(
        [string]$TransactionDirectory,
        [string]$Leaf,
        $Payload
    )
    if ($Leaf -cnotmatch '^compiler-(probe|recover)\.pid-[0-9]+\.ticks-[0-9]+\.(intent|authorization|completion|fault)\.json$') {
        throw "invalid compiler auxiliary record leaf: $Leaf"
    }
    $path = Join-Path $TransactionDirectory $Leaf
    $bytes = Get-AstroDetachedUtf8Bytes (
        ([ordered]@{
            schema = 'astrolabe.detached-compiler-recovery-native.v1'
            transaction_id = [IO.Path]::GetFileName($TransactionDirectory)
            written_utc_ticks = [DateTime]::UtcNow.Ticks
            payload = $Payload
        } | ConvertTo-Json -Depth 48 -Compress)
    )
    $stream = [IO.File]::Open(
        $path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    $snapshot = Read-AstroDetachedOrdinaryFile $path
    if ($snapshot.Sha256 -cne (Get-AstroDetachedSha256Bytes $bytes)) {
        throw "compiler auxiliary record readback differs: $path"
    }
    return [pscustomobject]@{ Path=$path; Sha256=$snapshot.Sha256; Length=$snapshot.Length }
}

function Import-AstroRecoveryNativeScoped {
    param(
        [Parameter(Mandatory)][string]$TransactionDirectory,
        [Parameter(Mandatory)][ValidateSet('probe','recover')][string]$Role,
        [Parameter(Mandatory)][int]$IssueValue
    )
    $owner = Get-AstroDetachedCurrentIdentity
    $principal = Get-AstroRecoveryPrincipal
    $prefix = 'compiler-{0}.pid-{1}.ticks-{2}' -f
        $Role, $owner.pid, $owner.process_start_utc_ticks
    $scopeLeaf = "$prefix.dir"
    $scope = Join-Path $TransactionDirectory $scopeLeaf
    [void](New-AstroDetachedDirectoryNoReplace $scope)
    $intent = Write-AstroRecoveryCompilerAuxRecord `
        $TransactionDirectory "$prefix.intent.json" ([ordered]@{
            stage='intent'; issue=$IssueValue; role=$Role; exact_owner=$owner
            principal=$principal; scope_path=$scope
            policy='compiler-temp-exact-scope-only'
        })
    $env:TEMP = $scope
    $env:TMP = $scope
    $env:TMPDIR = $scope
    try {
        . $lockHelperPath
    }
    catch {
        $failure = $_
        $env:TEMP = $TransactionDirectory
        $env:TMP = $TransactionDirectory
        $env:TMPDIR = $TransactionDirectory
        [void](Write-AstroRecoveryCompilerAuxRecord `
            $TransactionDirectory "$prefix.fault.json" ([ordered]@{
                stage='import'; issue=$IssueValue; role=$Role; exact_owner=$owner
                scope_path=$scope; code='ASTRO_DETACHED_RECOVERY_NATIVE_IMPORT_FAILED'
                message=$failure.Exception.Message
                remediation='preserve scope and transaction for tracker-bound recovery'
            }))
        throw
    }
    $env:TEMP = $TransactionDirectory
    $env:TMP = $TransactionDirectory
    $env:TMPDIR = $TransactionDirectory

    $sourceHandle = $null
    $parentHandle = $null
    $tombstoneLeaf = "$prefix.tombstone"
    $tombstone = Join-Path $TransactionDirectory $tombstoneLeaf
    $first = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $scope
    $second = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $scope
    if ($first.sha256 -cne $second.sha256 -or
        $first.entry_count -ne $second.entry_count) {
        throw 'recovery compiler scope inventory changed between observations'
    }
    $expectedRootFileId = [string]@(
        $second.entries | Where-Object { $_.relative_path -ceq '.' }
    )[0].file_id
    try {
        $sourceHandle = [AstroLauncherLockNative]::OpenExactDeleteDirectory($scope)
        $parentHandle = [AstroLauncherLockNative]::OpenExactRenameDirectory(
            $TransactionDirectory
        )
        $fileId = [AstroLauncherLockNative]::GetFileIdentity($sourceHandle)
        if ($fileId -cne $expectedRootFileId) {
            throw 'recovery compiler scope FILE_ID changed after double inventory'
        }
        $authorization = Write-AstroRecoveryCompilerAuxRecord `
            $TransactionDirectory "$prefix.authorization.json" ([ordered]@{
                stage='authorization'; issue=$IssueValue; role=$Role
                exact_owner=$owner; intent_sha256=$intent.Sha256
                scope_path=$scope; scope_file_id=$fileId
                tombstone_path=$tombstone
                inventory_schema=$second.schema
                inventory_encoding=$second.encoding
                inventory_sha256=$second.sha256
                inventory_entry_count=$second.entry_count
            })
        [AstroLauncherLockNative]::RenameDirectoryHandleNoReplace(
            $sourceHandle, $parentHandle, $tombstoneLeaf
        )
        $renamedId = [AstroLauncherLockNative]::GetFileIdentity($sourceHandle)
        $renamedPath = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($sourceHandle)
        )
        if ($renamedId -cne $fileId -or
            -not [string]::Equals(
                [IO.Path]::GetFullPath($renamedPath).TrimEnd('\','/'),
                [IO.Path]::GetFullPath($tombstone).TrimEnd('\','/'),
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            (Get-AstroPathEntryState $scope).State -cne 'absent') {
            throw 'recovery compiler scope handle-rename readback failed'
        }
    }
    catch {
        $failure = $_
        try {
            [void](Write-AstroRecoveryCompilerAuxRecord `
                $TransactionDirectory "$prefix.fault.json" ([ordered]@{
                    stage='cleanup'; issue=$IssueValue; role=$Role
                    exact_owner=$owner; scope_path=$scope
                    tombstone_path=$tombstone
                    code='ASTRO_DETACHED_RECOVERY_NATIVE_CLEANUP_FAILED'
                    message=$failure.Exception.Message
                    remediation='preserve scope/tombstone and immutable records'
                }))
        } catch {}
        throw
    }
    finally {
        if ($null -ne $parentHandle) { $parentHandle.Dispose() }
        if ($null -ne $sourceHandle) { $sourceHandle.Dispose() }
    }
    $tombstoneInventory =
        Get-AstroOrdinaryDirectoryTreeInventoryLongPath $tombstone
    if ($tombstoneInventory.sha256 -cne $second.sha256) {
        throw 'recovery compiler tombstone inventory drifted before deletion'
    }
    Remove-AstroOrdinaryDirectoryTreeLongPath `
        -LiteralPath $tombstone `
        -ExpectedInventorySchema ([string]$second.schema) `
        -ExpectedInventoryEncoding ([string]$second.encoding) `
        -ExpectedInventorySha256 ([string]$second.sha256)
    if ((Get-AstroPathEntryState $scope).State -cne 'absent' -or
        (Get-AstroPathEntryState $tombstone).State -cne 'absent') {
        throw 'recovery compiler scope did not reach terminal absence'
    }
    $completion = Write-AstroRecoveryCompilerAuxRecord `
        $TransactionDirectory "$prefix.completion.json" ([ordered]@{
            stage='completion'; issue=$IssueValue; role=$Role
            exact_owner=$owner; intent_sha256=$intent.Sha256
            authorization_sha256=$authorization.Sha256
            scope_path=$scope; scope_file_id=$fileId; scope_state='absent'
            tombstone_path=$tombstone; tombstone_state='absent'
            inventory_sha256=$second.sha256
        })
    return [ordered]@{
        intent_path=$intent.Path; intent_sha256=$intent.Sha256
        authorization_path=$authorization.Path
        authorization_sha256=$authorization.Sha256
        completion_path=$completion.Path; completion_sha256=$completion.Sha256
        scope_path=$scope; scope_file_id=$fileId
        inventory_sha256=$second.sha256
        scope_state='absent'; tombstone_state='absent'
    }
}

function Get-AstroRecoveryTargetProbe {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\','/')
    $inventoryFirst = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $full
    $inventorySecond = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $full
    if ($inventorySecond.sha256 -cne $inventoryFirst.sha256 -or
        $inventorySecond.entry_count -ne $inventoryFirst.entry_count) {
        throw 'target content changed between first and second exact inventories'
    }
    $expectedRootFileId = [string]@(
        $inventorySecond.entries |
            Where-Object { [string]$_.relative_path -ceq '.' }
    )[0].file_id
    $handle = $null
    try {
        $handle = [AstroLauncherLockNative]::OpenExactRecoveryDirectory($full)
        $fileId = [AstroLauncherLockNative]::GetFileIdentity($handle)
        if ($fileId -cne $expectedRootFileId) {
            throw 'target FILE_ID changed after the double inventory'
        }
        $final = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($handle)
        )
        $final = [IO.Path]::GetFullPath($final).TrimEnd('\','/')
        if (-not [string]::Equals(
                $full, $final, [StringComparison]::OrdinalIgnoreCase
            )) { throw "retained target final path differs: $final" }
        $sddlFirst = [AstroLauncherLockNative]::GetExactSecurityDescriptorSddl(
            $handle
        )
        $sddlSecond = [AstroLauncherLockNative]::GetExactSecurityDescriptorSddl(
            $handle
        )
        $fileIdSecond = [AstroLauncherLockNative]::GetFileIdentity($handle)
        if ($fileIdSecond -cne $fileId -or $sddlSecond -cne $sddlFirst) {
            throw 'FILE_ID/security changed between retained observations'
        }
        $info = [IO.DirectoryInfo]::new($full)
    }
    finally { if ($null -ne $handle) { $handle.Dispose() } }
    $inventoryThird = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $full
    $thirdRootFileId = [string]@(
        $inventoryThird.entries |
            Where-Object { [string]$_.relative_path -ceq '.' }
    )[0].file_id
    if ($inventoryThird.sha256 -cne $inventorySecond.sha256 -or
        $inventoryThird.entry_count -ne $inventorySecond.entry_count -or
        $thirdRootFileId -cne $fileId) {
        throw 'target content/identity changed across the retained security observation'
    }
    $entryEvidence = @(
        foreach ($entry in @($inventoryThird.entries)) {
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
        name = [IO.Path]::GetFileName($full)
        path = $full
        file_id = $fileId
        final_path = $final
        creation_utc = $info.CreationTimeUtc.ToString('o')
        last_write_utc = $info.LastWriteTimeUtc.ToString('o')
        attributes = [uint32]$info.Attributes
        security_sddl = $sddlSecond
        security_sddl_sha256 = Get-AstroDetachedSha256Bytes (
            Get-AstroDetachedUtf8Bytes $sddlSecond
        )
        inventory = [ordered]@{
            schema = [string]$inventoryThird.schema
            encoding = [string]$inventoryThird.encoding
            entry_count = [int]$inventoryThird.entry_count
            canonical_bytes_length =
                [uint64]$inventoryThird.canonical_bytes_length
            sha256 = [string]$inventoryThird.sha256
            entries = $entryEvidence
        }
        first_equals_second_equals_third = $true
    }
}

function Get-AstroRecoveryTargetsSha256 {
    param([Parameter(Mandatory)]$Targets)
    $lines = @(
        $Targets |
            Sort-Object name |
            ForEach-Object {
                '{0}|{1}|{2}|{3}' -f $_.name, $_.file_id,
                    $_.security_sddl_sha256, $_.inventory.sha256
            }
    )
    return Get-AstroDetachedSha256Bytes (
        Get-AstroDetachedUtf8Bytes (($lines -join "`n") + "`n")
    )
}

function Get-AstroRecoveryProtocolState {
    $tmp = Join-Path $script:AstroDetachedCanonicalRoot '.tmp'
    $paths = [ordered]@{
        target = Join-Path $script:AstroDetachedCanonicalRoot 'target'
        launcher_lock = Join-Path $tmp 'astrolabe-launcher.lock'
        launcher_transitions = Join-Path $tmp 'launcher-transitions'
        attribution = Join-Path $tmp 'attribution'
    }
    $result = [ordered]@{}
    foreach ($entry in $paths.GetEnumerator()) {
        $state = Get-AstroPathEntryState ([string]$entry.Value)
        $result[$entry.Key] = [ordered]@{
            path = [IO.Path]::GetFullPath([string]$entry.Value)
            state = [string]$state.State
            error = $state.Error
        }
    }
    return $result
}

function Assert-AstroRecoveryProtocolAbsent {
    param($State)
    foreach ($name in @('target','launcher_lock','launcher_transitions','attribution')) {
        if ([string]$State.$name.state -cne 'absent') {
            Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_PROTOCOL_NOT_ABSENT' `
                "$name is $($State.$name.state): $($State.$name.path) / $($State.$name.error)" `
                'preserve all state and complete the owning launcher protocol before recovery'
        }
    }
}

function Invoke-AstroRecoveryGhRead {
    param([Parameter(Mandatory)][long]$CommentId)
    $gh = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $gh) {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_GH_MISSING' `
            'authenticated GitHub CLI is unavailable' `
            'restore gh authentication; local recovery never trusts an unverified URL'
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
            throw 'bounded 30000-ms gh read timed out'
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "gh exited $($process.ExitCode): $stderr"
        }
        return $stdout | ConvertFrom-Json
    }
    catch {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_GH_READ_FAILED' `
            $_.Exception.Message `
            'repair authenticated GitHub access; no target mutation is authorized'
    }
    finally { $process.Dispose() }
}

function Read-AstroRecoveryTrackerEvidence {
    param(
        [string]$Url,
        [int]$IssueValue,
        [string]$Transaction,
        [string]$IntentSha256,
        [string]$ProbeSha256,
        [string]$TargetsSha256
    )
    $pattern = '^https://github\.com/ChrisRoyse/Astrolabe/issues/' +
        [Regex]::Escape([string]$IssueValue) + '#issuecomment-([0-9]+)$'
    $match = [Regex]::Match($Url, $pattern)
    if (-not $match.Success) {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_TRACKER_URL_INVALID' `
            "tracker URL is not an exact comment on issue #$IssueValue`: $Url" `
            'pass the html_url returned for the exact owner-authored evidence comment'
    }
    $commentId = [long]::Parse(
        $match.Groups[1].Value,
        [Globalization.CultureInfo]::InvariantCulture
    )
    $comment = Invoke-AstroRecoveryGhRead $commentId
    if ([string]$comment.html_url -cne $Url -or
        [string]$comment.author_association -cne 'OWNER') {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_TRACKER_AUTHORITY_INVALID' `
            "tracker comment URL/owner association differs (url=$($comment.html_url), association=$($comment.author_association))" `
            'use an exact owner-authored issue comment'
    }
    $line = 'ASTRO_DETACHED_COMPILER_RECOVERY_V1 issue={0} transaction={1} intent_sha256={2} probe_sha256={3} targets_sha256={4} action=handle-rename-delete-exact-inventories' -f
        $IssueValue,$Transaction,$IntentSha256,$ProbeSha256,$TargetsSha256
    if (-not (@([string]$comment.body -split "`r?`n") -ccontains $line)) {
        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_TRACKER_LINE_MISSING' `
            "tracker comment lacks the exact machine-readable authorization line: $line" `
            'post the exact Probe-produced line without editing any hash or identifier'
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

function Assert-AstroRecoveryScriptBindings {
    param($Intent)
    foreach ($binding in @(
            @{Path=$protocolPath;Expected=[string]$Intent.protocol_sha256},
            @{Path=$strictJsonPath;Expected=[string]$Intent.strict_json_sha256},
            @{Path=$compilerStatePath;Expected=[string]$Intent.compiler_state_sha256},
            @{Path=$lockHelperPath;Expected=[string]$Intent.launcher_lock_sha256},
            @{Path=$PSCommandPath;Expected=[string]$Intent.recovery_script_sha256}
        )) {
        $actual = (Get-FileHash -LiteralPath $binding.Path -Algorithm SHA256).Hash.
            ToLowerInvariant()
        if ($actual -cne $binding.Expected) {
            Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_SCRIPT_DRIFT' `
                "bound script changed: $($binding.Path) expected=$($binding.Expected) observed=$actual" `
                'preserve the transaction and execute the exact bytes bound by Prepare'
        }
    }
}

$issueValue = ConvertTo-AstroRecoveryPositiveInt $Issue Issue
if ([IO.Path]::GetFullPath((Get-Location).Path).TrimEnd('\') -cne
    $script:AstroDetachedCanonicalRoot) {
    Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_ROOT_INVALID' `
        "recovery must execute from $script:AstroDetachedCanonicalRoot" `
        'change to the canonical checkout before retrying'
}

switch ($Operation) {
    'Prepare' {
        $principal = Get-AstroRecoveryPrincipal
        if ([bool]$principal.is_elevated_administrator) {
            Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_PREPARE_ELEVATED' `
                'Prepare must bind the normal same-principal token, but this token is elevated' `
                'run Prepare from the normal authenticated operator session'
        }
        [string[]]$targetNames = ConvertFrom-AstroRecoveryTargetNames $TargetNamesJson
        if ([string]::IsNullOrWhiteSpace($TransactionId)) {
            $TransactionId = [Guid]::NewGuid().ToString('N')
        }
        $transaction = Get-AstroRecoveryTransactionDirectory $TransactionId
        [void](New-AstroDetachedDirectoryNoReplace $transaction)
        $tmp = Join-Path $script:AstroDetachedCanonicalRoot '.tmp'
        $normalObservations = @(
            foreach ($name in $targetNames) {
                $path = Join-Path $tmp $name
                $info = [IO.DirectoryInfo]::new($path)
                $aclState = try {
                    [void](Get-Acl -LiteralPath $path -ErrorAction Stop)
                    'readable'
                } catch { 'access-denied-or-unevaluable: ' + $_.Exception.Message }
                $inventoryState = try {
                    [void]@([IO.Directory]::GetFileSystemEntries($path))
                    'readable'
                } catch { 'access-denied-or-unevaluable: ' + $_.Exception.Message }
                $attributes = try { [uint32]$info.Attributes } catch { $null }
                $creationUtc = try {
                    $info.CreationTimeUtc.ToString('o')
                } catch { $null }
                [ordered]@{
                    name=$name; path=[IO.Path]::GetFullPath($path)
                    exists=[IO.Directory]::Exists($path)
                    attributes=$attributes
                    creation_utc=$creationUtc
                    acl_state=$aclState; inventory_state=$inventoryState
                }
            }
        )
        $intent = Write-AstroRecoveryRecord `
            $transaction '000-intent.json' 0 -Payload ([ordered]@{
                issue=$issueValue; transaction_id=$TransactionId
                created_utc=[DateTime]::UtcNow.ToString('o')
                normal_principal=$principal
                target_names=[string[]]$targetNames
                target_paths=@($normalObservations|ForEach-Object{$_.path})
                normal_token_observations=$normalObservations
                protocol_path=(Get-AstroRecoveryScriptBinding $protocolPath).path
                protocol_sha256=(Get-AstroRecoveryScriptBinding $protocolPath).sha256
                strict_json_path=(Get-AstroRecoveryScriptBinding $strictJsonPath).path
                strict_json_sha256=(Get-AstroRecoveryScriptBinding $strictJsonPath).sha256
                compiler_state_path=(Get-AstroRecoveryScriptBinding $compilerStatePath).path
                compiler_state_sha256=(Get-AstroRecoveryScriptBinding $compilerStatePath).sha256
                launcher_lock_path=(Get-AstroRecoveryScriptBinding $lockHelperPath).path
                launcher_lock_sha256=(Get-AstroRecoveryScriptBinding $lockHelperPath).sha256
                recovery_script_path=(Get-AstroRecoveryScriptBinding $PSCommandPath).path
                recovery_script_sha256=(Get-AstroRecoveryScriptBinding $PSCommandPath).sha256
                destructive_authority='none'
                next_operation='same-principal-elevated-probe'
            })
        [ordered]@{
            schema='astrolabe.detached-compiler-recovery-prepare-result.v1'
            transaction_id=$TransactionId; transaction_path=$transaction
            intent_path=$intent.Path; intent_sha256=$intent.Sha256
            normal_principal_sid=$principal.sid
            targets=[string[]]$targetNames
            next='run Probe from a same-principal elevated Windows PowerShell token'
        } | ConvertTo-Json -Depth 12
        break
    }
    'Probe' {
        $transaction = Get-AstroRecoveryTransactionDirectory $TransactionId
        $intent = Read-AstroRecoveryRecord `
            $transaction '000-intent.json' $ExpectedIntentSha256
        if ($intent.Sequence -ne 0 -or
            [int]$intent.Payload.issue -ne $issueValue) {
            Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_INTENT_BINDING_INVALID' `
                'intent sequence/issue differs from the requested recovery' `
                'pass the exact Prepare transaction and driving issue'
        }
        Assert-AstroRecoveryScriptBindings $intent.Payload
        $principal = Get-AstroRecoveryPrincipal
        if (-not [bool]$principal.is_elevated_administrator -or
            [string]$principal.sid -cne
                [string]$intent.Payload.normal_principal.sid) {
            Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_ELEVATED_PRINCIPAL_INVALID' `
                "Probe requires elevated same principal SID=$($intent.Payload.normal_principal.sid); observed SID=$($principal.sid) elevated=$($principal.is_elevated_administrator)" `
                'use UAC elevation of the exact normal principal bound by Prepare'
        }
        $nativeCompiler = Import-AstroRecoveryNativeScoped `
            $transaction probe $issueValue
        # Dot-sourcing inside the scoped import intentionally limits helper
        # functions to that function scope. The native type is now resident, so
        # this script-scope import publishes the helpers without recompilation.
        . $lockHelperPath
        $protocolBefore = Get-AstroRecoveryProtocolState
        $targets = @(
            foreach ($path in @($intent.Payload.target_paths)) {
                Get-AstroRecoveryTargetProbe ([string]$path)
            }
        )
        $targetsSha256 = Get-AstroRecoveryTargetsSha256 $targets
        $probe = Write-AstroRecoveryRecord `
            $transaction '001-probe.json' 1 $intent.Name $intent.Sha256 `
            ([ordered]@{
                issue=$issueValue; transaction_id=$TransactionId
                elevated_principal=$principal
                creator_attribution=[ordered]@{
                    state='legacy-process-generation-unavailable'
                    observed_elevated_host_pid=35696
                    observed_elevated_host_process_start_utc_ticks=$null
                    evidence='Synapse CF_TIMELINE exact UAC interval plus two three-import timestamp bursts'
                    inference_policy='never-authorize-from-pid-or-inferred-ticks'
                }
                native_compiler=$nativeCompiler
                protocol_state_before=$protocolBefore
                targets=$targets; targets_sha256=$targetsSha256
                destructive_authority='none'
            })
        $line = 'ASTRO_DETACHED_COMPILER_RECOVERY_V1 issue={0} transaction={1} intent_sha256={2} probe_sha256={3} targets_sha256={4} action=handle-rename-delete-exact-inventories' -f
            $issueValue,$TransactionId,$intent.Sha256,$probe.Sha256,$targetsSha256
        [ordered]@{
            schema='astrolabe.detached-compiler-recovery-probe-result.v1'
            transaction_id=$TransactionId; probe_path=$probe.Path
            probe_sha256=$probe.Sha256; targets_sha256=$targetsSha256
            target_count=$targets.Count; target_evidence=$targets
            tracker_authorization_line=$line
            next='post the exact line on the driving issue, then invoke Recover with that comment URL'
        } | ConvertTo-Json -Depth 48
        break
    }
    'Recover' {
        $transaction = Get-AstroRecoveryTransactionDirectory $TransactionId
        $intent = Read-AstroRecoveryRecord `
            $transaction '000-intent.json' $ExpectedIntentSha256
        $probe = Read-AstroRecoveryRecord `
            $transaction '001-probe.json' $ExpectedProbeSha256
        if ($probe.Sequence -ne 1 -or $probe.Payload.transaction_id -cne
            $TransactionId -or $probe.Payload.targets_sha256 -cnotmatch
            '^[0-9a-f]{64}$') {
            Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_PROBE_BINDING_INVALID' `
                'probe transaction/sequence/targets digest is invalid' `
                'preserve all state and pass the exact immutable Probe record'
        }
        Assert-AstroRecoveryScriptBindings $intent.Payload
        $principal = Get-AstroRecoveryPrincipal
        if (-not [bool]$principal.is_elevated_administrator -or
            [string]$principal.sid -cne
                [string]$intent.Payload.normal_principal.sid) {
            Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_ELEVATED_PRINCIPAL_INVALID' `
                'Recover is not executing as the elevated principal bound by Prepare' `
                'use UAC elevation of the exact normal principal'
        }
        $nativeCompiler = Import-AstroRecoveryNativeScoped `
            $transaction recover $issueValue
        . $lockHelperPath
        $trackerFirst = Read-AstroRecoveryTrackerEvidence `
            $TrackerCommentUrl $issueValue $TransactionId $intent.Sha256 `
            $probe.Sha256 ([string]$probe.Payload.targets_sha256)
        $protocolFirst = Get-AstroRecoveryProtocolState
        Assert-AstroRecoveryProtocolAbsent $protocolFirst

        $authorizationPath = Join-Path $transaction '002-authorization.json'
        if ([IO.File]::Exists($authorizationPath)) {
            $authorization = Read-AstroRecoveryRecord `
                $transaction '002-authorization.json'
            if ($authorization.Sequence -ne 2 -or
                $authorization.Payload.probe_sha256 -cne $probe.Sha256 -or
                $authorization.Payload.tracker.body_sha256 -cne
                    $trackerFirst.body_sha256) {
                Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_AUTHORIZATION_DRIFT' `
                    'existing recovery authorization differs from probe/tracker' `
                    'preserve transaction and targets; never replace authorization'
            }
        }
        else {
            $reprobes = @(
                foreach ($expected in @($probe.Payload.targets)) {
                    $observed = Get-AstroRecoveryTargetProbe ([string]$expected.path)
                    if ($observed.file_id -cne [string]$expected.file_id -or
                        $observed.security_sddl_sha256 -cne
                            [string]$expected.security_sddl_sha256 -or
                        $observed.inventory.sha256 -cne
                            [string]$expected.inventory.sha256) {
                        Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_TARGET_DRIFT' `
                            "target drifted since Probe: $($expected.path)" `
                            'preserve all source bytes and run a fresh Prepare/Probe transaction'
                    }
                    $observed
                }
            )
            if ((Get-AstroRecoveryTargetsSha256 $reprobes) -cne
                [string]$probe.Payload.targets_sha256) {
                Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_TARGET_DIGEST_DRIFT' `
                    're-probed target digest differs immediately before authorization' `
                    'preserve sources and run a fresh transaction'
            }
            $trackerSecond = Read-AstroRecoveryTrackerEvidence `
                $TrackerCommentUrl $issueValue $TransactionId $intent.Sha256 `
                $probe.Sha256 ([string]$probe.Payload.targets_sha256)
            if ($trackerSecond.body_sha256 -cne $trackerFirst.body_sha256 -or
                $trackerSecond.updated_at -cne $trackerFirst.updated_at) {
                Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_TRACKER_CHANGED' `
                    'tracker authorization changed between exact reads' `
                    'preserve all state and obtain a fresh stable owner comment'
            }
            $protocolSecond = Get-AstroRecoveryProtocolState
            Assert-AstroRecoveryProtocolAbsent $protocolSecond
            $authorization = Write-AstroRecoveryRecord `
                $transaction '002-authorization.json' 2 $probe.Name $probe.Sha256 `
                ([ordered]@{
                    issue=$issueValue; transaction_id=$TransactionId
                    exact_recovery_owner=$principal
                    intent_sha256=$intent.Sha256; probe_sha256=$probe.Sha256
                    targets_sha256=$probe.Payload.targets_sha256
                    tracker=$trackerSecond
                    protocol_first=$protocolFirst; protocol_second=$protocolSecond
                    reprobes=$reprobes; native_compiler=$nativeCompiler
                    namespace_operation='same-volume-handle-no-replace-rename'
                    deletion_operation='exact-finalized-ordinary-inventory-only'
                    interruption_policy='resume-this-immutable-transaction'
                })
        }

        $tombstonesRoot = Join-Path $transaction 'tombstones'
        if (-not [IO.Directory]::Exists($tombstonesRoot)) {
            [void](New-AstroDirectoryNoClobberLongPath $tombstonesRoot)
        }
        $tombstonesRoot = Assert-AstroDetachedOrdinaryDirectory $tombstonesRoot
        $finalizationPath = Join-Path $transaction '003-finalization.json'
        if (-not [IO.File]::Exists($finalizationPath)) {
            $renamed = [Collections.Generic.List[object]]::new()
            $parentHandle = [AstroLauncherLockNative]::OpenExactRenameDirectory(
                $tombstonesRoot
            )
            try {
                foreach ($expected in @($probe.Payload.targets)) {
                    $source = [string]$expected.path
                    $destinationLeaf = 'legacy-' + [string]$expected.name + '.dir'
                    $destination = Join-Path $tombstonesRoot $destinationLeaf
                    $sourceState = Get-AstroPathEntryState $source
                    $destinationState = Get-AstroPathEntryState $destination
                    $handle = $null
                    try {
                        if ($sourceState.State -ceq 'present' -and
                            $destinationState.State -ceq 'absent') {
                            $handle = [AstroLauncherLockNative]::OpenExactRecoveryDirectory(
                                $source
                            )
                            if ([AstroLauncherLockNative]::GetFileIdentity($handle) -cne
                                [string]$expected.file_id) {
                                throw 'source FILE_ID differs before rename'
                            }
                            [AstroLauncherLockNative]::RenameDirectoryHandleNoReplace(
                                $handle,$parentHandle,$destinationLeaf
                            )
                        }
                        elseif ($sourceState.State -ceq 'absent' -and
                            $destinationState.State -ceq 'present') {
                            $handle = [AstroLauncherLockNative]::OpenExactRecoveryDirectory(
                                $destination
                            )
                        }
                        else {
                            throw "invalid resumable source/tombstone states: source=$($sourceState.State) tombstone=$($destinationState.State)"
                        }
                        $fileId = [AstroLauncherLockNative]::GetFileIdentity($handle)
                        $final = ConvertFrom-AstroNativeFinalPath (
                            [AstroLauncherLockNative]::GetFileFinalPath($handle)
                        )
                        $sddl = [AstroLauncherLockNative]::GetExactSecurityDescriptorSddl(
                            $handle
                        )
                        if ($fileId -cne [string]$expected.file_id -or
                            (Get-AstroDetachedSha256Bytes (
                                Get-AstroDetachedUtf8Bytes $sddl
                            )) -cne [string]$expected.security_sddl_sha256 -or
                            (Get-AstroPathEntryState $source).State -cne 'absent' -or
                            -not [string]::Equals(
                                [IO.Path]::GetFullPath($final).TrimEnd('\','/'),
                                [IO.Path]::GetFullPath($destination).TrimEnd('\','/'),
                                [StringComparison]::OrdinalIgnoreCase
                            )) {
                            throw "renamed target readback differs: $source -> $destination"
                        }
                    }
                    finally { if ($null -ne $handle) { $handle.Dispose() } }
                    $inventory = Get-AstroOrdinaryDirectoryTreeInventoryLongPath (
                        $destination
                    )
                    if ($inventory.sha256 -cne
                        [string]$expected.inventory.sha256) {
                        throw "renamed target inventory differs: $source -> $destination"
                    }
                    $renamed.Add([ordered]@{
                        name=$expected.name; source_path=$source
                        source_state='absent'; tombstone_path=$destination
                        tombstone_file_id=$fileId
                        security_sddl_sha256=$expected.security_sddl_sha256
                        inventory_schema=$expected.inventory.schema
                        inventory_encoding=$expected.inventory.encoding
                        inventory_sha256=$expected.inventory.sha256
                        inventory_entry_count=$expected.inventory.entry_count
                    })
                }
            }
            finally { $parentHandle.Dispose() }
            $finalization = Write-AstroRecoveryRecord `
                $transaction '003-finalization.json' 3 `
                $authorization.Name $authorization.Sha256 ([ordered]@{
                    issue=$issueValue; transaction_id=$TransactionId
                    authorization_sha256=$authorization.Sha256
                    targets_sha256=$probe.Payload.targets_sha256
                    renamed=@($renamed)
                    all_sources_state='absent'
                    deletion_authority='only-these-finalized-tombstone-inventories'
                })
        }
        else {
            $finalization = Read-AstroRecoveryRecord `
                $transaction '003-finalization.json'
            if ($finalization.Sequence -ne 3 -or
                $finalization.Payload.authorization_sha256 -cne
                    $authorization.Sha256) {
                Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_FINALIZATION_DRIFT' `
                    'existing finalization differs from immutable authorization' `
                    'preserve all tombstones and transaction records'
            }
        }

        foreach ($entry in @($finalization.Payload.renamed)) {
            $sourceState = Get-AstroPathEntryState ([string]$entry.source_path)
            if ($sourceState.State -cne 'absent') {
                Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_SOURCE_REAPPEARED' `
                    "finalized source is not absent: $($entry.source_path)" `
                    'preserve all state; investigate namespace recreation'
            }
            $tombstoneState = Get-AstroPathEntryState ([string]$entry.tombstone_path)
            if ($tombstoneState.State -ceq 'present') {
                $inventory = Get-AstroOrdinaryDirectoryTreeInventoryLongPath (
                    [string]$entry.tombstone_path
                )
                if ($inventory.sha256 -cne [string]$entry.inventory_sha256) {
                    Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_TOMBSTONE_DRIFT' `
                        "finalized tombstone inventory drifted: $($entry.tombstone_path)" `
                        'preserve all tombstones and transaction evidence'
                }
                Remove-AstroOrdinaryDirectoryTreeLongPath `
                    -LiteralPath ([string]$entry.tombstone_path) `
                    -ExpectedInventorySchema ([string]$entry.inventory_schema) `
                    -ExpectedInventoryEncoding ([string]$entry.inventory_encoding) `
                    -ExpectedInventorySha256 ([string]$entry.inventory_sha256)
            }
            elseif ($tombstoneState.State -cne 'absent') {
                Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_TOMBSTONE_UNEVALUABLE' `
                    "tombstone state is $($tombstoneState.State): $($entry.tombstone_path)" `
                    'preserve all state and repair exact namespace observation'
            }
        }
        $terminal = @(
            foreach ($entry in @($finalization.Payload.renamed)) {
                [ordered]@{
                    name=$entry.name; source_path=$entry.source_path
                    source_state=(Get-AstroPathEntryState ([string]$entry.source_path)).State
                    tombstone_path=$entry.tombstone_path
                    tombstone_state=(Get-AstroPathEntryState ([string]$entry.tombstone_path)).State
                }
            }
        )
        if (@($terminal|Where-Object{
                    $_.source_state -cne 'absent' -or
                    $_.tombstone_state -cne 'absent'
                }).Count -ne 0) {
            Fail-AstroRecovery 'ASTRO_DETACHED_RECOVERY_TERMINAL_STATE_INVALID' `
                'one or more exact source/tombstone paths did not reach absence' `
                'preserve the transaction and inspect terminal path states'
        }
        $completionPath = Join-Path $transaction '004-completion.json'
        if ([IO.File]::Exists($completionPath)) {
            $completion = Read-AstroRecoveryRecord `
                $transaction '004-completion.json'
        }
        else {
            $completion = Write-AstroRecoveryRecord `
                $transaction '004-completion.json' 4 `
                $finalization.Name $finalization.Sha256 ([ordered]@{
                    issue=$issueValue; transaction_id=$TransactionId
                    authorization_sha256=$authorization.Sha256
                    finalization_sha256=$finalization.Sha256
                    targets_sha256=$probe.Payload.targets_sha256
                    terminal=$terminal
                    source_of_truth=$transaction
                    all_sources_state='absent'; all_tombstones_state='absent'
                })
        }
        [ordered]@{
            schema='astrolabe.detached-compiler-recovery-complete.v1'
            transaction_id=$TransactionId; transaction_path=$transaction
            intent_sha256=$intent.Sha256; probe_sha256=$probe.Sha256
            authorization_sha256=$authorization.Sha256
            finalization_sha256=$finalization.Sha256
            completion_path=$completion.Path
            completion_sha256=$completion.Sha256
            targets_sha256=$probe.Payload.targets_sha256
            terminal=$terminal
        } | ConvertTo-Json -Depth 32
        break
    }
}
