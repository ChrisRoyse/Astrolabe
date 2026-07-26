<#
.SYNOPSIS
    Append-only launcher TEMP/attribution archive transaction (#620).

.DESCRIPTION
    Destructive recursive TEMP cleanup cannot atomically bind every authorized
    metadata class to FileDispositionInfo.  This module therefore never deletes
    launcher TEMP or attribution evidence.  It publishes a durable authorization
    record whose snapshots are diagnostic observations and never deletion
    authority, moves the complete TEMP directory and exact manifest by
    retained-handle no-replace rename into one generation-bound transaction
    directory, then publishes a durable completion record and independently reads
    the archive back. Completion explicitly classifies stable, changed-preserved,
    and opaque-preserved state at every public transaction cut.

    A fault at any cut preserves every source or archive byte.  The transaction
    directory is append-only evidence and is never removed by ordinary launcher
    startup or cleanup.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Command Open-AstroLauncherPinnedDirectoryLease -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'launcher-lock.ps1')
}
if (-not (Get-Command Get-AstroAttributionManifestProbe -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'attribution-manifest.ps1')
}
if (-not (Get-Command Get-AstroLauncherTempTreeSnapshot -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'launcher-temp-guard.ps1')
}

$script:AstroLauncherStateArchiveDirectoryName = 'launcher-state-archive'
$script:AstroLauncherStateArchiveRecordMaximumBytes = 1048576

function Get-AstroLauncherTempArchiveSnapshot {
    param([Parameter(Mandatory)]$Lease)

    if ($null -eq $Lease -or $null -eq $Lease.Handle -or
        $Lease.Handle.IsInvalid -or $Lease.Handle.IsClosed) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TEMP_HANDLE_INVALID]: archive snapshot requires one retained directory handle'
    }
    $fileId = [AstroLauncherTempNative]::GetExactDirectoryIdentity($Lease.Handle)
    $finalPath = [IO.Path]::GetFullPath(
        [AstroLauncherTempNative]::GetExactDirectoryFinalPath($Lease.Handle)
    ).TrimEnd('\', '/')
    $rootState = [AstroLauncherTempNative]::CaptureExactRootState($Lease.Handle)
    [string[]]$entries = @()
    $inventoryState = 'exact'
    $inventoryError = $null
    $inventorySha256 = $null
    $observationInventorySha256 = $null
    try {
        [string[]]$entries = @(
            [AstroLauncherTempNative]::CaptureExactTreeEntries($Lease.Handle)
        )
        $observationBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            $rootState + "`n" + ($entries -join "`n")
        )
        $observationInventorySha256 = Get-AstroByteSha256 $observationBytes
        $authorizationState =
            [AstroLauncherTempNative]::GetExactTreeAuthorizationState(
                $rootState,
                $entries
            )
        $authorizationBytes =
            [Text.UTF8Encoding]::new($false, $true).GetBytes(
                $authorizationState
            )
        $inventorySha256 = Get-AstroByteSha256 $authorizationBytes
    }
    catch {
        # Archive correctness is the retained root's same-volume namespace move,
        # not a destructive decision derived from child interpretation.  Reparse,
        # sparse, encrypted, compressed, privilege-denied, or otherwise opaque
        # children remain physically inside the moved directory.  Label the exact
        # observation deficit; never follow a reparse target and never delete.
        $inventoryState = 'opaque-preserved'
        $inventoryError = $_.Exception.Message
        [string[]]$entries = @()
    }
    return [pscustomobject]@{
        Path = $Lease.Path
        RootFileId = $fileId
        RootFinalPath = $finalPath
        RootState = $rootState
        InventoryState = $inventoryState
        InventoryError = $inventoryError
        EntryCount = if ($inventoryState -ceq 'exact') {
            $entries.Count
        } else { $null }
        InventorySha256 = $inventorySha256
        ObservationInventorySha256 = if ($inventoryState -ceq 'exact') {
            $observationInventorySha256
        } else { $null }
        Entries = $entries
        InventoryAuthorizationScope =
            'exact FILE_ID/path/link-count/short-name/creation-write-change-time/attributes/bytes/security/EA-object/streams; observer-neutral LastAccessTime excluded; raw observation retained separately'
    }
}

function ConvertTo-AstroLauncherTempArchiveSnapshotRecord {
    param([Parameter(Mandatory)]$Snapshot)

    return [ordered]@{
        path = $Snapshot.Path
        root_file_id = $Snapshot.RootFileId
        root_final_path = $Snapshot.RootFinalPath
        root_state = $Snapshot.RootState
        inventory_state = $Snapshot.InventoryState
        inventory_error = $Snapshot.InventoryError
        entry_count = $Snapshot.EntryCount
        inventory_sha256 = $Snapshot.InventorySha256
        inventory_observation_sha256 = $Snapshot.ObservationInventorySha256
        inventory_authorization_scope = $Snapshot.InventoryAuthorizationScope
    }
}

function Compare-AstroLauncherTempArchiveSnapshots {
    param(
        [Parameter(Mandatory)]$Before,
        [Parameter(Mandatory)]$After,
        [ValidateSet('same-namespace', 'exact-rename')]
        [string]$ComparisonMode = 'same-namespace'
    )

    if ($Before.RootFileId -cne $After.RootFileId) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TEMP_IDENTITY_CHANGED]: retained TEMP FILE_ID changed between observations'
    }
    $rootStateRawEqual = $Before.RootState -ceq $After.RootState
    $rootStateEqual = if ($ComparisonMode -ceq 'exact-rename') {
        [AstroLauncherTempNative]::ExactRootStateEqualAcrossRename(
            [string]$Before.RootState,
            [string]$After.RootState
        )
    }
    else {
        [AstroLauncherTempNative]::ExactRootStateEqualIgnoringLastAccessTime(
            [string]$Before.RootState,
            [string]$After.RootState
        )
    }
    $bothInventoriesExact =
        $Before.InventoryState -ceq 'exact' -and
        $After.InventoryState -ceq 'exact'
    $inventoryEqual = if ($bothInventoriesExact) {
        $Before.EntryCount -eq $After.EntryCount -and
        [AstroLauncherTempNative]::
            ExactTreeEntriesEqualIgnoringLastAccessTime(
                [string[]]$Before.Entries,
                [string[]]$After.Entries
            )
    } else { $null }
    $integrityState = if (-not $rootStateEqual -or
        ($bothInventoriesExact -and -not $inventoryEqual)) {
        'changed-preserved'
    }
    elseif ($bothInventoriesExact) {
        'stable-exact'
    }
    else {
        'opaque-preserved'
    }

    return [ordered]@{
        state = $integrityState
        comparison_mode = $ComparisonMode
        root_file_id_equal = $true
        root_state_equal = $rootStateEqual
        root_state_raw_equal = $rootStateRawEqual
        inventory_comparison = if ($bothInventoriesExact) {
            if ($inventoryEqual) { 'equal-normalized' } else { 'changed' }
        } else { 'unavailable' }
        inventory_sha256_equal = if ($bothInventoriesExact) {
            $Before.InventorySha256 -ceq $After.InventorySha256
        } else { $null }
        inventory_observation_sha256_equal = if ($bothInventoriesExact) {
            $Before.ObservationInventorySha256 -ceq
                $After.ObservationInventorySha256
        } else { $null }
        before_inventory_state = $Before.InventoryState
        before_entry_count = $Before.EntryCount
        before_inventory_sha256 = $Before.InventorySha256
        before_inventory_observation_sha256 =
            $Before.ObservationInventorySha256
        after_inventory_state = $After.InventoryState
        after_entry_count = $After.EntryCount
        after_inventory_sha256 = $After.InventorySha256
        after_inventory_observation_sha256 =
            $After.ObservationInventorySha256
    }
}

function Open-AstroLauncherTempArchiveLease {
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)]$Evidence,
        [Parameter(Mandatory)]$DirectoryLease
    )

    if ($null -eq $Record -or -not $Record.Valid -or
        $Record.Kind -cne 'temp' -or
        $null -eq $Evidence -or -not $Evidence.Valid -or
        $Evidence.OwnerProbe.State -notin @('absent', 'pid-reused') -or
        $Evidence.JobObjectProbe.State -cne 'absent') {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TEMP_AUTHORITY_INVALID]: one exact dead complete-pair record is required'
    }
    if ($Record.Name.LauncherPid -ne $Evidence.Parsed.LauncherPid -or
        $Record.Name.LauncherProcessStartUtcTicks -ne
            $Evidence.Parsed.LauncherProcessStartUtcTicks -or
        $Record.Name.LauncherLockSha256 -cne
            $Evidence.Parsed.LauncherLockSha256 -or
        $Record.ExpectedTempPath -cne $Evidence.ExpectedTempPath) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_PAIR_GENERATION_MISMATCH]: TEMP and evidence bind different generations'
    }
    $parent = Assert-AstroLauncherPinnedDirectoryLease $DirectoryLease
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($Record.Path).TrimEnd('\', '/'),
            $parent.Path,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TEMP_PARENT_MISMATCH]: TEMP is not a direct child of the retained protocol directory'
    }
    $handle = $null
    try {
        $handle = [AstroLauncherTempNative]::OpenExactDirectoryMutation(
            $Record.Path
        )
        $lease = [pscustomobject]@{
            Authority = 'tracker-archive-retained-v1'
            OriginalPath = [IO.Path]::GetFullPath($Record.Path).TrimEnd('\', '/')
            Path = [IO.Path]::GetFullPath($Record.Path).TrimEnd('\', '/')
            Kind = 'temp'
            Record = $Record
            Evidence = $Evidence
            Handle = $handle
            SafeFileHandle = $handle
            RootFileId = [AstroLauncherTempNative]::GetExactDirectoryIdentity($handle)
            Snapshot = $null
            DispositionSet = $false
            Disposed = $false
        }
        if ($lease.RootFileId -cne $Record.FileId) {
            throw "TEMP FILE_ID changed between classification and archive lease (expected=$($Record.FileId), observed=$($lease.RootFileId))"
        }
        $first = Get-AstroLauncherTempArchiveSnapshot $lease
        if (-not [string]::Equals(
                $first.RootFinalPath,
                $lease.Path,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "retained TEMP resolves to a different final path ('$($lease.Path)' -> '$($first.RootFinalPath)')"
        }
        $ownerFinal = Get-AstroAttributionOwnerGenerationProbe `
            $Evidence.Parsed.LauncherPid `
            $Evidence.Parsed.LauncherProcessStartUtcTicks
        $jobFinal = Get-AstroLauncherJobObjectProbe `
            $Evidence.Parsed.JobObjectName
        if ($ownerFinal.State -notin @('absent', 'pid-reused') -or
            $jobFinal.State -cne 'absent') {
            throw "owner/Job state changed while retaining TEMP (owner=$($ownerFinal.State), job=$($jobFinal.State), pids=$(@($jobFinal.ProcessIds) -join ','))"
        }
        $second = Get-AstroLauncherTempArchiveSnapshot $lease
        if ($second.RootFileId -cne $first.RootFileId -or
            -not [string]::Equals(
                $second.RootFinalPath,
                $first.RootFinalPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw 'TEMP root identity/final path changed across archive authority probes'
        }
        $lease.Snapshot = $second
        return $lease
    }
    catch {
        if ($null -ne $handle) { $handle.Dispose() }
        throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TEMP_LEASE_FAILED]: path=$($Record.Path); $($_.Exception.Message)"
    }
}

function New-AstroLauncherStateArchiveNonce {
    $bytes = New-Object byte[] 16
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

function ConvertTo-AstroLauncherStateArchiveJsonBytes {
    param([Parameter(Mandatory)]$Value)

    $json = ($Value | ConvertTo-Json -Depth 32 -Compress) + "`n"
    return [Text.UTF8Encoding]::new($false, $true).GetBytes($json)
}

function Write-AstroLauncherStateArchiveRecord {
    param(
        [Parameter(Mandatory)]$TransactionDirectoryLease,
        [Parameter(Mandatory)][string]$Leaf,
        [Parameter(Mandatory)]$Value
    )

    $directory = Assert-AstroLauncherPinnedDirectoryLease (
        $TransactionDirectoryLease
    )
    if ([string]::IsNullOrEmpty($Leaf) -or
        [IO.Path]::GetFileName($Leaf) -cne $Leaf -or
        $Leaf -notmatch '^[a-z][a-z0-9.-]{0,127}\.json$') {
        throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_RECORD_LEAF_INVALID]: '$Leaf'"
    }
    $path = [IO.Path]::GetFullPath((Join-Path $directory.Path $Leaf))
    $state = Get-AstroPathEntryState $path
    if ($state.State -ne 'absent') {
        throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_RECORD_COLLISION]: state=$($state.State); error=$($state.Error); path=$path"
    }
    [byte[]]$bytes = ConvertTo-AstroLauncherStateArchiveJsonBytes $Value
    if ($bytes.Length -le 1 -or
        $bytes.Length -gt $script:AstroLauncherStateArchiveRecordMaximumBytes) {
        throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_RECORD_SIZE_INVALID]: bytes=$($bytes.Length); path=$path"
    }

    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $path),
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

    $handle = $null
    try {
        $handle = [AstroLauncherLockNative]::OpenExactRenameSource($path)
        $snapshot = Get-AstroExactRetainedFileSnapshot `
            -Handle $handle `
            -ExpectedPath $path `
            -MaximumBytes $script:AstroLauncherStateArchiveRecordMaximumBytes
        if ($snapshot.Length -ne $bytes.Length -or
            [Convert]::ToBase64String($snapshot.Bytes) -cne
                [Convert]::ToBase64String($bytes)) {
            throw 'durable archive record readback differs from the bytes written'
        }
        $parsed = [Text.UTF8Encoding]::new($false, $true).GetString(
            $snapshot.Bytes
        ) | ConvertFrom-Json
        if ($null -eq $parsed -or -not $parsed.PSObject.Properties['schema']) {
            throw 'durable archive record is not a schema-directed JSON object'
        }
        return [pscustomobject]@{
            Path = $path
            Leaf = $Leaf
            FileId = $snapshot.FileId
            Length = $snapshot.Length
            Sha256 = $snapshot.Sha256
            Bytes = $snapshot.Bytes
            Parsed = $parsed
            Handle = $handle
            SafeFileHandle = $handle
        }
    }
    catch {
        if ($null -ne $handle) {
            $handle.Dispose()
        }
        throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_RECORD_READBACK_FAILED]: path=$path; $($_.Exception.Message)"
    }
}

function Open-AstroAttributionArchiveLease {
    param(
        [Parameter(Mandatory)]$ManifestProbe,
        [Parameter(Mandatory)][ValidateSet('live-owner', 'tracker-reclaim')]
        [string]$AuthorityMode,
        [AllowNull()][byte[]]$ExpectedBytes,
        [switch]$TrackerEvidenceVerified
    )

    if ($null -eq $ManifestProbe -or -not $ManifestProbe.Valid -or
        $ManifestProbe.Kind -cne 'manifest') {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_MANIFEST_UNEVALUABLE]: one strict final-manifest probe is required'
    }
    if ($AuthorityMode -ceq 'live-owner') {
        if ($ManifestProbe.Parsed.SchemaVersion -ne 3 -or
            -not $ManifestProbe.Parsed.KillOnJobCloseBound -or
            $ManifestProbe.OwnerProbe.State -cne 'exact-live' -or
            $ManifestProbe.Parsed.LauncherPid -ne $PID) {
            throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_LIVE_AUTHORITY_INVALID]: live archive requires the exact self-owned v3 KILL_ON_JOB_CLOSE manifest'
        }
        [int[]]$jobPids = @($ManifestProbe.JobObjectProbe.ProcessIds)
        if ($ManifestProbe.JobObjectProbe.State -cne 'observed' -or
            $jobPids.Count -ne 1 -or $jobPids[0] -ne $PID) {
            throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_LIVE_JOB_OCCUPIED]: state=$($ManifestProbe.JobObjectProbe.State); pids=$($jobPids -join ',')"
        }
        if ($null -eq $ExpectedBytes -or $ExpectedBytes.Length -eq 0 -or
            $ManifestProbe.Snapshot.Length -ne $ExpectedBytes.Length -or
            [Convert]::ToBase64String($ManifestProbe.Snapshot.Bytes) -cne
                [Convert]::ToBase64String($ExpectedBytes)) {
            throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_MANIFEST_PRODUCER_READBACK_MISMATCH]: final manifest differs from recorder readback'
        }
    }
    else {
        if (-not $TrackerEvidenceVerified -or
            $ManifestProbe.OwnerProbe.State -notin @('absent', 'pid-reused') -or
            $ManifestProbe.JobObjectProbe.State -cne 'absent') {
            throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TRACKER_AUTHORITY_INVALID]: verified=$([bool]$TrackerEvidenceVerified); owner=$($ManifestProbe.OwnerProbe.State); job=$($ManifestProbe.JobObjectProbe.State)"
        }
    }

    $path = [IO.Path]::GetFullPath($ManifestProbe.Path)
    $handle = $null
    try {
        $handle = [AstroLauncherLockNative]::OpenExactRenameSource($path)
        $snapshot = Get-AstroExactRetainedFileSnapshot `
            -Handle $handle `
            -ExpectedPath $path `
            -MaximumBytes $script:AstroAttributionManifestMaxBytes
        Assert-AstroAttributionRetainedProtocolPath `
            $snapshot $ManifestProbe.Name.Leaf `
            'manifest retained for append-only archive'
        if ($snapshot.FileId -cne $ManifestProbe.Snapshot.FileId -or
            $snapshot.Length -ne $ManifestProbe.Snapshot.Length -or
            $snapshot.Sha256 -cne $ManifestProbe.Snapshot.Sha256 -or
            [Convert]::ToBase64String($snapshot.Bytes) -cne
                [Convert]::ToBase64String($ManifestProbe.Snapshot.Bytes)) {
            throw 'manifest changed between strict classification and archive lease'
        }
        $parsed = Convert-AstroAttributionBytesToState `
            -Bytes $snapshot.Bytes `
            -ExpectedLauncherPid $ManifestProbe.Name.LauncherPid `
            -ExpectedLauncherProcessStartUtcTicks `
                $ManifestProbe.Name.LauncherProcessStartUtcTicks `
            -ExpectedLauncherLockSha256 $ManifestProbe.Name.LauncherLockSha256 `
            -Path $path
        if (-not $parsed.Valid) {
            throw $parsed.Error
        }
        return [pscustomobject]@{
            AuthorityMode = $AuthorityMode
            OriginalPath = $path
            Path = $path
            Handle = $handle
            SafeFileHandle = $handle
            Snapshot = $snapshot
            Parsed = $parsed
            ManifestProbe = $ManifestProbe
            Archived = $false
        }
    }
    catch {
        if ($null -ne $handle) {
            $handle.Dispose()
        }
        throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_MANIFEST_LEASE_FAILED]: path=$path; $($_.Exception.Message)"
    }
}

function Start-AstroLauncherStateArchiveTransaction {
    param(
        [Parameter(Mandatory)][string]$ProtocolDirectory,
        [Parameter(Mandatory)]$ProtocolDirectoryLease,
        [Parameter(Mandatory)]$TempLease,
        [Parameter(Mandatory)]$ManifestLease,
        [Parameter(Mandatory)][ValidateSet('live-owner', 'tracker-reclaim')]
        [string]$AuthorityMode,
        [Parameter(Mandatory)][int]$DrivingIssue,
        [AllowEmptyString()][string]$TrackerCommentUrl = ''
    )

    if ($DrivingIssue -le 0) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_ISSUE_INVALID]: driving issue must be positive'
    }
    if ($AuthorityMode -ceq 'tracker-reclaim' -and
        [string]::IsNullOrWhiteSpace($TrackerCommentUrl)) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TRACKER_URL_REQUIRED]: explicit recovery requires its exact evidence-comment URL'
    }
    $expectedTempAuthority = if ($AuthorityMode -ceq 'live-owner') {
        'live-owner-retained-v1'
    } else { 'tracker-archive-retained-v1' }
    if (-not $TempLease.PSObject.Properties['Authority'] -or
        $TempLease.Authority -cne $expectedTempAuthority) {
        throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TEMP_AUTHORITY_MODE_MISMATCH]: expected=$expectedTempAuthority"
    }
    $protocol = Assert-AstroLauncherPinnedDirectoryLease $ProtocolDirectoryLease
    $protocolFull = [IO.Path]::GetFullPath($ProtocolDirectory).TrimEnd('\', '/')
    if (-not [string]::Equals(
            $protocol.Path,
            $protocolFull,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_PROTOCOL_DIRECTORY_DRIFT]: retained protocol directory differs from requested path'
    }
    if ($TempLease.Record.Name.LauncherPid -ne
            $ManifestLease.Parsed.LauncherPid -or
        $TempLease.Record.Name.LauncherProcessStartUtcTicks -ne
            $ManifestLease.Parsed.LauncherProcessStartUtcTicks -or
        $TempLease.Record.Name.LauncherLockSha256 -cne
            $ManifestLease.Parsed.LauncherLockSha256) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_PAIR_GENERATION_MISMATCH]: TEMP and manifest bind different launcher generations'
    }
    $tempBefore = Get-AstroLauncherTempArchiveSnapshot $TempLease
    if ($tempBefore.RootFileId -cne $TempLease.RootFileId) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TEMP_IDENTITY_DRIFT]: TEMP FILE_ID changed before authorization'
    }
    $manifestBefore = Get-AstroExactRetainedFileSnapshot `
        -Handle $ManifestLease.Handle `
        -ExpectedPath $ManifestLease.Path `
        -MaximumBytes $script:AstroAttributionManifestMaxBytes
    if ($manifestBefore.FileId -cne $ManifestLease.Snapshot.FileId -or
        $manifestBefore.Sha256 -cne $ManifestLease.Snapshot.Sha256 -or
        $manifestBefore.Length -ne $ManifestLease.Snapshot.Length) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_MANIFEST_DRIFT]: manifest changed before authorization'
    }

    $archiveRoot = [IO.Path]::GetFullPath((
        Join-Path $protocol.Path $script:AstroLauncherStateArchiveDirectoryName
    ))
    $archiveRootState = Get-AstroPathEntryState $archiveRoot
    if ($archiveRootState.State -eq 'absent') {
        New-AstroDirectoryLongPath $archiveRoot | Out-Null
    }
    elseif ($archiveRootState.State -ne 'present' -or
        ($archiveRootState.Attributes -band [IO.FileAttributes]::Directory) -eq 0) {
        throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_ROOT_UNEVALUABLE]: state=$($archiveRootState.State); error=$($archiveRootState.Error); path=$archiveRoot"
    }
    $archiveRootLease = Open-AstroLauncherPinnedDirectoryLease $archiveRoot
    $transactionDirectoryLease = $null
    $authorizationLease = $null
    try {
        $archiveRootReadback = Assert-AstroLauncherPinnedDirectoryLease $archiveRootLease
        $nonce = New-AstroLauncherStateArchiveNonce
        $leaf = 'transaction.v1.pid-{0}.ticks-{1}.lock-sha256-{2}.nonce-{3}.dir' -f
            $ManifestLease.Parsed.LauncherPid,
            $ManifestLease.Parsed.LauncherProcessStartUtcTicks,
            $ManifestLease.Parsed.LauncherLockSha256,
            $nonce
        $transactionPath = [IO.Path]::GetFullPath((Join-Path $archiveRoot $leaf))
        $transactionState = Get-AstroPathEntryState $transactionPath
        if ($transactionState.State -ne 'absent') {
            throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TRANSACTION_COLLISION]: state=$($transactionState.State); error=$($transactionState.Error); path=$transactionPath"
        }
        New-AstroDirectoryNoClobberLongPath $transactionPath | Out-Null
        $transactionDirectoryLease = Open-AstroLauncherPinnedDirectoryLease (
            $transactionPath
        )
        $transactionReadback = Assert-AstroLauncherPinnedDirectoryLease (
            $transactionDirectoryLease
        )
        $transactionId = [Guid]::NewGuid().ToString('N')
        $tempDestination = [IO.Path]::GetFullPath((
            Join-Path $transactionPath 'temp.dir'
        ))
        $manifestDestination = [IO.Path]::GetFullPath((
            Join-Path $transactionPath 'manifest.json'
        ))
        $authorization = [ordered]@{
            schema = 'astrolabe.launcher-state-archive.authorization.v2'
            transaction_id = $transactionId
            created_utc = [DateTime]::UtcNow.ToString('O')
            authority = [ordered]@{
                mode = $AuthorityMode
                driving_issue = $DrivingIssue
                tracker_comment_url = $TrackerCommentUrl
            }
            policy = [ordered]@{
                destructive_authority = 'none'
                snapshot_role = 'diagnostic-observation-only'
                namespace_operation =
                    'same-volume-retained-handle-no-replace-rename'
                concurrent_change_policy = 'preserve-and-classify'
                ambiguous_state_policy = 'preserve-and-report'
            }
            generation = [ordered]@{
                launcher_pid = $ManifestLease.Parsed.LauncherPid
                launcher_process_start_utc_ticks =
                    $ManifestLease.Parsed.LauncherProcessStartUtcTicks
                launcher_lock_sha256 =
                    $ManifestLease.Parsed.LauncherLockSha256
                manifest_schema_version = $ManifestLease.Parsed.SchemaVersion
                job_object_name = $ManifestLease.Parsed.JobObjectName
                job_limit_flags = $ManifestLease.Parsed.JobLimitFlags
            }
            archive = [ordered]@{
                root_path = $archiveRootReadback.Path
                root_file_id = $archiveRootReadback.FileId
                transaction_path = $transactionReadback.Path
                transaction_file_id = $transactionReadback.FileId
                temp_destination = $tempDestination
                manifest_destination = $manifestDestination
            }
            source = [ordered]@{
                temp = [ordered]@{
                    path = $TempLease.OriginalPath
                    current_path = $TempLease.Path
                    root_file_id = $tempBefore.RootFileId
                    root_final_path = $tempBefore.RootFinalPath
                    root_state = $tempBefore.RootState
                    inventory_state = $tempBefore.InventoryState
                    inventory_error = $tempBefore.InventoryError
                    entry_count = $tempBefore.EntryCount
                    inventory_sha256 = $tempBefore.InventorySha256
                }
                manifest = [ordered]@{
                    path = $ManifestLease.OriginalPath
                    file_id = $manifestBefore.FileId
                    bytes = $manifestBefore.Length
                    sha256 = $manifestBefore.Sha256
                }
            }
        }
        $authorizationLease = Write-AstroLauncherStateArchiveRecord `
            -TransactionDirectoryLease $transactionDirectoryLease `
            -Leaf 'authorization.json' `
            -Value $authorization
        return [pscustomobject]@{
            TransactionId = $transactionId
            AuthorityMode = $AuthorityMode
            DrivingIssue = $DrivingIssue
            TrackerCommentUrl = $TrackerCommentUrl
            ProtocolDirectory = $protocol.Path
            ArchiveRoot = $archiveRoot
            ArchiveRootLease = $archiveRootLease
            TransactionPath = $transactionPath
            TransactionDirectoryLease = $transactionDirectoryLease
            TempDestination = $tempDestination
            ManifestDestination = $manifestDestination
            TempLease = $TempLease
            ManifestLease = $ManifestLease
            TempBefore = $tempBefore
            ManifestBefore = $manifestBefore
            AuthorizationLease = $authorizationLease
            TempMoved = $false
            TempMoveBefore = $null
            TempAfter = $null
            ManifestMoved = $false
            ManifestAfter = $null
            CompletionLease = $null
            Completed = $false
        }
    }
    catch {
        if ($null -ne $authorizationLease -and
            -not $authorizationLease.Handle.IsClosed) {
            $authorizationLease.Handle.Dispose()
        }
        if ($null -ne $transactionDirectoryLease -and
            -not $transactionDirectoryLease.SafeFileHandle.IsClosed) {
            $transactionDirectoryLease.SafeFileHandle.Dispose()
        }
        if ($null -ne $archiveRootLease -and
            -not $archiveRootLease.SafeFileHandle.IsClosed) {
            $archiveRootLease.SafeFileHandle.Dispose()
        }
        throw
    }
}

function Move-AstroLauncherStateArchiveTemp {
    param([Parameter(Mandatory)]$Transaction)

    if ($Transaction.TempMoved) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TEMP_ALREADY_MOVED]: transaction already moved TEMP'
    }
    foreach ($path in @($Transaction.TempDestination)) {
        $state = Get-AstroPathEntryState $path
        if ($state.State -ne 'absent') {
            throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TEMP_DESTINATION_COLLISION]: state=$($state.State); error=$($state.Error); path=$path"
        }
    }
    $before = Get-AstroLauncherTempArchiveSnapshot $Transaction.TempLease
    if ($before.RootFileId -cne $Transaction.TempBefore.RootFileId) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TEMP_IDENTITY_DRIFT]: TEMP FILE_ID changed before archive rename'
    }
    $Transaction.TempMoveBefore = $before
    [AstroLauncherTempNative]::RenameExactDirectoryNoReplace(
        $Transaction.TempLease.Handle,
        $Transaction.TransactionDirectoryLease.SafeFileHandle,
        'temp.dir'
    )
    $source = $Transaction.TempLease.Path
    $Transaction.TempLease.Path = $Transaction.TempDestination
    $after = Get-AstroLauncherTempArchiveSnapshot $Transaction.TempLease
    if ($after.RootFileId -cne $before.RootFileId -or
        -not [string]::Equals(
            $after.RootFinalPath,
            $Transaction.TempDestination,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TEMP_RENAME_READBACK_INVALID]: retained TEMP identity/final path changed'
    }
    $sourceState = Get-AstroPathEntryState $source
    if ($sourceState.State -ne 'absent') {
        throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TEMP_SOURCE_REMAINS]: state=$($sourceState.State); error=$($sourceState.Error); path=$source"
    }
    $Transaction.TempMoved = $true
    $Transaction.TempAfter = $after
    $integrity = Compare-AstroLauncherTempArchiveSnapshots `
        -Before $Transaction.TempBefore `
        -After $after `
        -ComparisonMode exact-rename
    return [pscustomobject]@{
        State = 'archived'
        SourcePath = $source
        DestinationPath = $Transaction.TempDestination
        RootFileId = $after.RootFileId
        InventoryState = $after.InventoryState
        InventoryError = $after.InventoryError
        EntryCount = $after.EntryCount
        InventorySha256 = $after.InventorySha256
        IntegrityState = $integrity.state
        SourcePathState = $sourceState.State
    }
}

function Move-AstroLauncherStateArchiveManifest {
    param([Parameter(Mandatory)]$Transaction)

    if (-not $Transaction.TempMoved) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_ORDER_INVALID]: TEMP must be archived before its manifest'
    }
    if ($Transaction.ManifestMoved) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_MANIFEST_ALREADY_MOVED]: transaction already moved manifest'
    }
    $destinationState = Get-AstroPathEntryState $Transaction.ManifestDestination
    if ($destinationState.State -ne 'absent') {
        throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_MANIFEST_DESTINATION_COLLISION]: state=$($destinationState.State); error=$($destinationState.Error); path=$($Transaction.ManifestDestination)"
    }
    $before = Get-AstroExactRetainedFileSnapshot `
        -Handle $Transaction.ManifestLease.Handle `
        -ExpectedPath $Transaction.ManifestLease.Path `
        -MaximumBytes $script:AstroAttributionManifestMaxBytes
    if ($before.FileId -cne $Transaction.ManifestBefore.FileId -or
        $before.Length -ne $Transaction.ManifestBefore.Length -or
        $before.Sha256 -cne $Transaction.ManifestBefore.Sha256 -or
        [Convert]::ToBase64String($before.Bytes) -cne
            [Convert]::ToBase64String($Transaction.ManifestBefore.Bytes)) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_MANIFEST_CHANGED]: retained manifest changed before archive rename'
    }
    [AstroLauncherLockNative]::RenameFileHandleNoReplace(
        $Transaction.ManifestLease.Handle,
        $Transaction.TransactionDirectoryLease.SafeFileHandle,
        'manifest.json'
    )
    $source = $Transaction.ManifestLease.Path
    $Transaction.ManifestLease.Path = $Transaction.ManifestDestination
    [AstroLauncherLockNative]::FlushExactFile($Transaction.ManifestLease.Handle)
    $after = Get-AstroExactRetainedFileSnapshot `
        -Handle $Transaction.ManifestLease.Handle `
        -ExpectedPath $Transaction.ManifestDestination `
        -MaximumBytes $script:AstroAttributionManifestMaxBytes
    if ($after.FileId -cne $before.FileId -or
        $after.Length -ne $before.Length -or
        $after.Sha256 -cne $before.Sha256 -or
        [Convert]::ToBase64String($after.Bytes) -cne
            [Convert]::ToBase64String($before.Bytes)) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_MANIFEST_RENAME_READBACK_INVALID]: archived manifest differs from retained source bytes'
    }
    $sourceState = Get-AstroPathEntryState $source
    if ($sourceState.State -ne 'absent') {
        throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_MANIFEST_SOURCE_REMAINS]: state=$($sourceState.State); error=$($sourceState.Error); path=$source"
    }
    $Transaction.ManifestMoved = $true
    $Transaction.ManifestAfter = $after
    return [pscustomobject]@{
        State = 'archived'
        SourcePath = $source
        DestinationPath = $Transaction.ManifestDestination
        FileId = $after.FileId
        Length = $after.Length
        Sha256 = $after.Sha256
        SourcePathState = $sourceState.State
    }
}

function Complete-AstroLauncherStateArchiveTransaction {
    param([Parameter(Mandatory)]$Transaction)

    if (-not $Transaction.TempMoved -or -not $Transaction.ManifestMoved) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_INCOMPLETE]: both retained sources must be archived before completion'
    }
    if ($null -eq $Transaction.TempMoveBefore -or
        $null -eq $Transaction.TempAfter) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_TEMP_OBSERVATIONS_MISSING]: archive completion requires pre-rename and post-rename TEMP observations'
    }
    $tempAfter = Get-AstroLauncherTempArchiveSnapshot $Transaction.TempLease
    $manifestAfter = Get-AstroExactRetainedFileSnapshot `
        -Handle $Transaction.ManifestLease.Handle `
        -ExpectedPath $Transaction.ManifestDestination `
        -MaximumBytes $script:AstroAttributionManifestMaxBytes
    if ($tempAfter.RootFileId -cne $Transaction.TempBefore.RootFileId -or
        $manifestAfter.FileId -cne $Transaction.ManifestBefore.FileId -or
        $manifestAfter.Length -ne $Transaction.ManifestBefore.Length -or
        $manifestAfter.Sha256 -cne $Transaction.ManifestBefore.Sha256) {
        throw 'LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_FINAL_IDENTITY_INVALID]: final retained archive differs from authorization identities'
    }
    foreach ($source in @(
            $Transaction.TempLease.OriginalPath,
            $Transaction.ManifestLease.OriginalPath
        )) {
        $state = Get-AstroPathEntryState $source
        if ($state.State -ne 'absent') {
            throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_SOURCE_RECREATED]: state=$($state.State); error=$($state.Error); path=$source"
        }
    }
    $authorizationToRename = Compare-AstroLauncherTempArchiveSnapshots `
        -Before $Transaction.TempBefore `
        -After $Transaction.TempMoveBefore
    $renameOperation = Compare-AstroLauncherTempArchiveSnapshots `
        -Before $Transaction.TempMoveBefore `
        -After $Transaction.TempAfter `
        -ComparisonMode exact-rename
    $renameToCompletion = Compare-AstroLauncherTempArchiveSnapshots `
        -Before $Transaction.TempAfter `
        -After $tempAfter
    $authorizationToCompletion = Compare-AstroLauncherTempArchiveSnapshots `
        -Before $Transaction.TempBefore `
        -After $tempAfter `
        -ComparisonMode exact-rename
    $tempIntegrityState = if (@(
            $authorizationToRename,
            $renameOperation,
            $renameToCompletion,
            $authorizationToCompletion
        ) | Where-Object { $_.state -ceq 'changed-preserved' }) {
        'changed-preserved'
    }
    elseif (@(
            $authorizationToRename,
            $renameOperation,
            $renameToCompletion,
            $authorizationToCompletion
        ) | Where-Object { $_.state -ceq 'opaque-preserved' }) {
        'opaque-preserved'
    }
    else {
        'stable-exact'
    }
    $completion = [ordered]@{
        schema = 'astrolabe.launcher-state-archive.completion.v2'
        transaction_id = $Transaction.TransactionId
        completed_utc = [DateTime]::UtcNow.ToString('O')
        policy = [ordered]@{
            destructive_authority = 'none'
            snapshot_role = 'diagnostic-observation-only'
            namespace_operation =
                'same-volume-retained-handle-no-replace-rename'
            concurrent_change_policy = 'preserve-and-classify'
            ambiguous_state_policy = 'preserve-and-report'
        }
        authorization = [ordered]@{
            path = $Transaction.AuthorizationLease.Path
            file_id = $Transaction.AuthorizationLease.FileId
            bytes = $Transaction.AuthorizationLease.Length
            sha256 = $Transaction.AuthorizationLease.Sha256
        }
        temp_integrity = [ordered]@{
            state = $tempIntegrityState
            observations = [ordered]@{
                authorization = ConvertTo-AstroLauncherTempArchiveSnapshotRecord `
                    $Transaction.TempBefore
                rename_before = ConvertTo-AstroLauncherTempArchiveSnapshotRecord `
                    $Transaction.TempMoveBefore
                rename_after = ConvertTo-AstroLauncherTempArchiveSnapshotRecord `
                    $Transaction.TempAfter
                completion = ConvertTo-AstroLauncherTempArchiveSnapshotRecord `
                    $tempAfter
            }
            comparisons = [ordered]@{
                authorization_to_rename = $authorizationToRename
                rename_operation = $renameOperation
                rename_to_completion = $renameToCompletion
                authorization_to_completion = $authorizationToCompletion
            }
        }
        terminal = [ordered]@{
            temp_source_state = 'absent'
            manifest_source_state = 'absent'
            temp = [ordered]@{
                path = $Transaction.TempDestination
                root_file_id = $tempAfter.RootFileId
                root_final_path = $tempAfter.RootFinalPath
                root_state = $tempAfter.RootState
                inventory_state = $tempAfter.InventoryState
                inventory_error = $tempAfter.InventoryError
                entry_count = $tempAfter.EntryCount
                inventory_sha256 = $tempAfter.InventorySha256
            }
            manifest = [ordered]@{
                path = $Transaction.ManifestDestination
                file_id = $manifestAfter.FileId
                bytes = $manifestAfter.Length
                sha256 = $manifestAfter.Sha256
            }
        }
    }
    $completionLease = Write-AstroLauncherStateArchiveRecord `
        -TransactionDirectoryLease $Transaction.TransactionDirectoryLease `
        -Leaf 'completion.json' `
        -Value $completion
    $Transaction.CompletionLease = $completionLease
    $Transaction.Completed = $true
    return [pscustomobject]@{
        State = 'complete'
        TransactionId = $Transaction.TransactionId
        TransactionPath = $Transaction.TransactionPath
        AuthorizationPath = $Transaction.AuthorizationLease.Path
        AuthorizationFileId = $Transaction.AuthorizationLease.FileId
        AuthorizationSha256 = $Transaction.AuthorizationLease.Sha256
        CompletionPath = $completionLease.Path
        CompletionFileId = $completionLease.FileId
        CompletionSha256 = $completionLease.Sha256
        TempArchivePath = $Transaction.TempDestination
        TempRootFileId = $tempAfter.RootFileId
        TempInventoryState = $tempAfter.InventoryState
        TempInventoryError = $tempAfter.InventoryError
        TempEntryCount = $tempAfter.EntryCount
        TempInventorySha256 = $tempAfter.InventorySha256
        TempIntegrityState = $tempIntegrityState
        TempAuthorizationToRenameState = $authorizationToRename.state
        TempRenameOperationState = $renameOperation.state
        TempRenameToCompletionState = $renameToCompletion.state
        TempAuthorizationToCompletionState =
            $authorizationToCompletion.state
        ManifestArchivePath = $Transaction.ManifestDestination
        ManifestFileId = $manifestAfter.FileId
        ManifestLength = $manifestAfter.Length
        ManifestSha256 = $manifestAfter.Sha256
        TempSourceState = 'absent'
        ManifestSourceState = 'absent'
    }
}

function Close-AstroLauncherStateArchiveTransaction {
    param([Parameter(Mandatory)]$Transaction)

    $errors = New-Object System.Collections.Generic.List[string]
    $completionLease = if (
        $Transaction.PSObject.Properties['CompletionLease']
    ) {
        $Transaction.CompletionLease
    } else { $null }
    foreach ($lease in @(
            $completionLease,
            $Transaction.AuthorizationLease,
            $Transaction.ManifestLease
        )) {
        if ($null -ne $lease -and $null -ne $lease.Handle -and
            -not $lease.Handle.IsClosed) {
            try { $lease.Handle.Dispose() }
            catch { $errors.Add($_.Exception.Message) }
        }
    }
    if ($null -ne $Transaction.TempLease.Handle -and
        -not $Transaction.TempLease.Handle.IsClosed) {
        try { Close-AstroLauncherTempMutationLease $Transaction.TempLease }
        catch { $errors.Add($_.Exception.Message) }
    }
    foreach ($lease in @(
            $Transaction.TransactionDirectoryLease,
            $Transaction.ArchiveRootLease
        )) {
        if ($null -ne $lease -and $null -ne $lease.SafeFileHandle -and
            -not $lease.SafeFileHandle.IsClosed) {
            try { $lease.SafeFileHandle.Dispose() }
            catch { $errors.Add($_.Exception.Message) }
        }
    }
    if ($errors.Count -gt 0) {
        throw "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_ARCHIVE_HANDLE_RELEASE_FAILED]: $($errors -join '; ')"
    }
}
