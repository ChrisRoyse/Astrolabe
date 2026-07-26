<#
.SYNOPSIS
    Tracker-authorized archive of one conclusively foreign launcher-reserved directory.

.DESCRIPTION
    A manual FSV fixture can accidentally claim the launcher's reserved top-level
    TEMP namespace without ever becoming a launcher generation. Ordinary launcher
    admission must keep refusing that malformed entry. This command is the separate
    recovery transaction: it proves the entry is foreign, empty, ordinary, stable,
    and tracker-bound, retains its exact FILE_ID, and moves that same directory
    object into the append-only launcher-state archive by handle.

    It never accepts a canonical launcher generation, never deletes source/archive
    bytes, and never weakens the ordinary reserved-name classifier.

.NOTES
    Refs #750. Manual recovery tooling; this is not a test or gate.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Inspect', 'Archive')]
    [string]$Operation,
    [string]$Root = '',
    [Parameter(Mandatory)][string]$SourcePath,
    [string]$ExpectedIssue = '',
    [string]$ExpectedProducerIssue = '',
    [string]$ExpectedSourceFileId = '',
    [string]$ExpectedInventorySha256 = '',
    [string]$ProvenanceArgsPath = '',
    [string]$ExpectedProvenanceArgsSha256 = '',
    [string]$ProvenanceClosurePath = '',
    [string]$ExpectedProvenanceClosureSha256 = '',
    [string]$TrackerCommentUrl = '',
    [switch]$AllowIsolatedFixture
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

. (Join-Path $PSScriptRoot 'launcher-lock.ps1')
. (Join-Path $PSScriptRoot 'attribution-manifest.ps1')
. (Join-Path $PSScriptRoot 'launcher-temp-guard.ps1')
. (Join-Path $PSScriptRoot 'launcher-state-archive.ps1')

function Fail-AstroForeignArchive {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Remediation
    )

    $errorRecord = [ordered]@{
        schema = 'astrolabe.foreign-reserved-state-archive-error.v1'
        code = $Code
        message = $Message
        remediation = $Remediation
    }
    [Console]::Error.WriteLine(($errorRecord | ConvertTo-Json -Compress))
    $exception = [InvalidOperationException]::new($Message)
    $exception.Data['AstroCode'] = $Code
    $exception.Data['AstroRemediation'] = $Remediation
    throw $exception
}

function ConvertTo-AstroForeignPositiveInt {
    param([string]$Value, [string]$Name)

    $parsed = 0
    if (-not [int]::TryParse(
            $Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsed
        ) -or $parsed -le 0) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_ARGUMENT_INVALID' `
            "$Name must be one positive invariant integer; received '$Value'" `
            'pass the exact positive issue number from the tracker'
    }
    return $parsed
}

function Invoke-AstroForeignGhJson {
    param([Parameter(Mandatory)][string]$ApiPath)

    $gh = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $gh) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_GH_MISSING' `
            'authenticated GitHub CLI is unavailable' `
            'install/authenticate gh and retry without changing local state'
    }
    $process = $null
    try {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $gh.Source
        $start.Arguments = 'api ' + $ApiPath
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.EnvironmentVariables['NO_COLOR'] = '1'
        $start.EnvironmentVariables['GH_FORCE_TTY'] = '0'
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        if (-not $process.Start()) {
            throw 'Process.Start returned false'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            try { $process.Kill() } catch {}
            throw 'gh read exceeded the 30000 ms bounded timeout'
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "gh exited $($process.ExitCode): $stderr"
        }
        return $stdout | ConvertFrom-Json
    }
    catch {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_GH_READ_FAILED' `
            $_.Exception.Message `
            'repair authenticated github.com access; the failed read grants no local mutation authority'
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Read-AstroForeignTrackerEvidence {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][int]$Issue,
        [Parameter(Mandatory)][int]$ProducerIssue,
        [Parameter(Mandatory)][string]$ExpectedRoot,
        [Parameter(Mandatory)][string]$ExpectedSource,
        [Parameter(Mandatory)][string]$ExpectedFileId,
        [Parameter(Mandatory)][string]$ExpectedInventory,
        [Parameter(Mandatory)][string]$ExpectedArgsPath,
        [Parameter(Mandatory)][string]$ExpectedArgsSha256,
        [Parameter(Mandatory)][string]$ExpectedClosurePath,
        [Parameter(Mandatory)][string]$ExpectedClosureSha256,
        [Parameter(Mandatory)][string]$ExpectedTransactionPath
    )

    $match = [Regex]::Match(
        $Url,
        '^https://github\.com/(?<owner>[^/]+)/(?<repo>[^/]+)/issues/(?<issue>[1-9][0-9]*)#issuecomment-(?<comment>[1-9][0-9]*)\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success -or [int]$match.Groups['issue'].Value -ne $Issue) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_TRACKER_URL_INVALID' `
            "tracker URL is not one exact issue-comment URL for #${Issue}: $Url" `
            'pass the fresh owner-authored evidence-comment URL from the driving issue'
    }
    $api = 'repos/{0}/{1}/issues/comments/{2}' -f
        $match.Groups['owner'].Value,
        $match.Groups['repo'].Value,
        $match.Groups['comment'].Value
    $comment = Invoke-AstroForeignGhJson $api
    if ([string]$comment.html_url -cne $Url -or
        [string]$comment.author_association -cne 'OWNER') {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_TRACKER_IDENTITY_INVALID' `
            "GitHub readback does not bind the exact owner-authored URL (url='$($comment.html_url)', association='$($comment.author_association)')" `
            'use a repository-owner evidence comment and its exact canonical URL'
    }

    $prefix = 'ASTRO_FOREIGN_RESERVED_STATE_ARCHIVE_EVIDENCE '
    [string[]]$lines = @([string]$comment.body -split "`r?`n")
    [string[]]$markers = @($lines | Where-Object {
            $_.StartsWith($prefix, [StringComparison]::Ordinal)
        })
    if ($markers.Count -ne 1) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_TRACKER_EVIDENCE_INVALID' `
            "tracker comment must contain exactly one '$prefix' line; observed $($markers.Count)" `
            'post one fresh canonical machine-readable evidence object'
    }

    $json = $markers[0].Substring($prefix.Length)
    try {
        $node = Read-AstroAttributionJsonValueNode $json 0 0 '$'
        $end = Get-AstroJsonNextTokenIndex $json $node.NextIndex
        if ($end -ne $json.Length -or
            (ConvertTo-AstroAttributionCanonicalJsonNode $node) -cne $json) {
            throw 'evidence JSON must be one exact canonical minified object'
        }
        $fields = @(
            'schema',
            'issue',
            'producer_issue',
            'root',
            'source_path',
            'source_file_id',
            'source_inventory_sha256',
            'source_entry_count',
            'provenance_args_path',
            'provenance_args_sha256',
            'provenance_closure_path',
            'provenance_closure_sha256',
            'transaction_path',
            'active_lock_state',
            'transition_state',
            'target_state'
        )
        Assert-AstroAttributionExactObjectFields $node $fields '$'
        $p = $node.Properties
        $actual = [ordered]@{
            schema = ConvertFrom-AstroAttributionStringNode $p['schema'] '$.schema' -Nonblank
            issue = [int](ConvertFrom-AstroAttributionUnsignedNode $p['issue'] '$.issue' ([uint64][int]::MaxValue) -Positive)
            producer_issue = [int](ConvertFrom-AstroAttributionUnsignedNode $p['producer_issue'] '$.producer_issue' ([uint64][int]::MaxValue) -Positive)
            root = ConvertFrom-AstroAttributionAbsolutePathNode $p['root'] '$.root'
            source_path = ConvertFrom-AstroAttributionAbsolutePathNode $p['source_path'] '$.source_path'
            source_file_id = ConvertFrom-AstroAttributionStringNode $p['source_file_id'] '$.source_file_id' -Nonblank
            source_inventory_sha256 = ConvertFrom-AstroAttributionStringNode $p['source_inventory_sha256'] '$.source_inventory_sha256' -Nonblank
            source_entry_count = [int](ConvertFrom-AstroAttributionUnsignedNode $p['source_entry_count'] '$.source_entry_count' ([uint64][int]::MaxValue))
            provenance_args_path = ConvertFrom-AstroAttributionAbsolutePathNode $p['provenance_args_path'] '$.provenance_args_path'
            provenance_args_sha256 = ConvertFrom-AstroAttributionStringNode $p['provenance_args_sha256'] '$.provenance_args_sha256' -Nonblank
            provenance_closure_path = ConvertFrom-AstroAttributionAbsolutePathNode $p['provenance_closure_path'] '$.provenance_closure_path'
            provenance_closure_sha256 = ConvertFrom-AstroAttributionStringNode $p['provenance_closure_sha256'] '$.provenance_closure_sha256' -Nonblank
            transaction_path = ConvertFrom-AstroAttributionAbsolutePathNode $p['transaction_path'] '$.transaction_path'
            active_lock_state = ConvertFrom-AstroAttributionStringNode $p['active_lock_state'] '$.active_lock_state' -Nonblank
            transition_state = ConvertFrom-AstroAttributionStringNode $p['transition_state'] '$.transition_state' -Nonblank
            target_state = ConvertFrom-AstroAttributionStringNode $p['target_state'] '$.target_state' -Nonblank
        }
    }
    catch {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_TRACKER_EVIDENCE_INVALID' `
            $_.Exception.Message `
            'post one fresh exact ordered canonical evidence object'
    }

    if ($actual.schema -cne 'astrolabe.foreign-reserved-state-archive-evidence.v1' -or
        $actual.issue -ne $Issue -or
        $actual.producer_issue -ne $ProducerIssue -or
        -not [string]::Equals($actual.root, $ExpectedRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($actual.source_path, $ExpectedSource, [StringComparison]::OrdinalIgnoreCase) -or
        $actual.source_file_id -cne $ExpectedFileId -or
        $actual.source_inventory_sha256 -cne $ExpectedInventory -or
        $actual.source_entry_count -ne 0 -or
        -not [string]::Equals($actual.provenance_args_path, $ExpectedArgsPath, [StringComparison]::OrdinalIgnoreCase) -or
        $actual.provenance_args_sha256 -cne $ExpectedArgsSha256 -or
        -not [string]::Equals($actual.provenance_closure_path, $ExpectedClosurePath, [StringComparison]::OrdinalIgnoreCase) -or
        $actual.provenance_closure_sha256 -cne $ExpectedClosureSha256 -or
        -not [string]::Equals($actual.transaction_path, $ExpectedTransactionPath, [StringComparison]::OrdinalIgnoreCase) -or
        $actual.active_lock_state -cne 'absent' -or
        $actual.transition_state -cne 'clear' -or
        $actual.target_state -cne 'absent') {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_TRACKER_EVIDENCE_MISMATCH' `
            'tracker evidence differs from the exact command and retained physical state' `
            're-read physical state and post a fresh evidence object containing every exact field'
    }

    return [pscustomobject]@{
        Url = $Url
        CommentId = [long]$match.Groups['comment'].Value
        Author = [string]$comment.user.login
        Evidence = $actual
    }
}

function Get-AstroForeignProtocolState {
    param([string]$RootPath, [string]$LockPath)

    $active = Get-AstroPathEntryState $LockPath
    $transitions = Get-AstroLauncherLockTransitions $LockPath
    $target = Get-AstroPathEntryState (Join-Path $RootPath 'target')
    return [pscustomobject]@{
        Active = $active
        Transitions = $transitions
        Target = $target
    }
}

function Assert-AstroForeignProtocolAbsent {
    param([Parameter(Mandatory)]$State)

    if ($State.Active.State -ne 'absent' -or
        $State.Transitions.State -ne 'clear' -or
        $State.Target.State -ne 'absent') {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_PROTOCOL_BUSY' `
            "active=$($State.Active.State); transitions=$($State.Transitions.State); transition_paths=$(@($State.Transitions.Paths) -join '; '); target=$($State.Target.State)" `
            'preserve every byte and retry only after active/transition/target state is authoritatively absent'
    }
}

function Get-AstroForeignTransactionPath {
    param(
        [string]$ProtocolPath,
        [int]$Issue,
        [string]$OriginalSourcePath,
        [string]$FileId,
        [string]$InventorySha256
    )

    $identityBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        $OriginalSourcePath.ToLowerInvariant() + "`n" + $FileId + "`n" +
        $InventorySha256
    )
    $identitySha256 = Get-AstroByteSha256 $identityBytes
    $archiveRoot = [IO.Path]::GetFullPath((
        Join-Path $ProtocolPath 'launcher-state-archive'
    ))
    $leaf = 'foreign-reserved.v1.issue-{0}.identity-sha256-{1}.dir' -f
        $Issue,
        $identitySha256
    return [pscustomobject]@{
        ArchiveRoot = $archiveRoot
        IdentitySha256 = $identitySha256
        TransactionPath = [IO.Path]::GetFullPath((Join-Path $archiveRoot $leaf))
    }
}

function Open-AstroForeignEvidenceFile {
    param([string]$Path, [string]$ExpectedSha256, [string]$Description)

    $handle = $null
    try {
        $handle = [AstroLauncherLockNative]::OpenExactProtectedReadFile($Path)
        $snapshot = Get-AstroExactRetainedFileSnapshot `
            -Handle $handle `
            -ExpectedPath $Path `
            -MaximumBytes 1048576
        if ($snapshot.Sha256 -cne $ExpectedSha256) {
            throw "$Description SHA-256 changed (expected=$ExpectedSha256, observed=$($snapshot.Sha256))"
        }
        return [pscustomobject]@{
            Description = $Description
            Path = $Path
            Snapshot = $snapshot
            Handle = $handle
        }
    }
    catch {
        if ($null -ne $handle) { $handle.Dispose() }
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_PROVENANCE_MISMATCH' `
            $_.Exception.Message `
            'preserve the reserved entry and bind recovery only to unchanged producer evidence'
    }
}

function Read-AstroForeignArchiveRecord {
    param([string]$Path)

    $handle = $null
    try {
        $handle = [AstroLauncherLockNative]::OpenExactProtectedReadFile($Path)
        $snapshot = Get-AstroExactRetainedFileSnapshot `
            -Handle $handle `
            -ExpectedPath $Path `
            -MaximumBytes 1048576
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($snapshot.Bytes)
        $parsed = $text | ConvertFrom-Json
        if ($null -eq $parsed -or -not $parsed.PSObject.Properties['schema']) {
            throw 'record is not a schema-directed JSON object'
        }
        return [pscustomobject]@{
            Path = $Path
            Snapshot = $snapshot
            Parsed = $parsed
            Handle = $handle
        }
    }
    catch {
        if ($null -ne $handle) { $handle.Dispose() }
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_RECORD_UNREADABLE' `
            "path=$Path; $($_.Exception.Message)" `
            'preserve the transaction and inspect its exact immutable record bytes'
    }
}

function Get-AstroForeignArchiveRecordSnapshot {
    param([Parameter(Mandatory)]$Lease)

    if ($Lease.PSObject.Properties['Snapshot']) {
        return $Lease.Snapshot
    }
    foreach ($name in @('FileId', 'Length', 'Sha256')) {
        if (-not $Lease.PSObject.Properties[$name]) {
            throw "foreign archive record lease lacks '$name' readback"
        }
    }
    return [pscustomobject]@{
        FileId = $Lease.FileId
        Length = $Lease.Length
        Sha256 = $Lease.Sha256
    }
}

$canonicalRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\', '/')
$rootFull = if ([string]::IsNullOrWhiteSpace($Root)) {
    $canonicalRoot
} else {
    [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
}
if ([string]::Equals($rootFull, $canonicalRoot, [StringComparison]::OrdinalIgnoreCase)) {
    Assert-AstroLauncherRootCanonical $rootFull
}
else {
    $fixtureBase = [IO.Path]::GetFullPath((
        Join-Path $canonicalRoot '.tmp\manual-fsv\issue750'
    )).TrimEnd('\', '/')
    if (-not $AllowIsolatedFixture -or
        -not ($rootFull + '\').StartsWith(
            $fixtureBase + '\',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_ROOT_INVALID' `
            "root is neither canonical nor an explicit #750 isolated fixture: $rootFull" `
            'use the canonical checkout; manual refusal probes may use only -AllowIsolatedFixture below .tmp\manual-fsv\issue750'
    }
}

$protocol = [IO.Path]::GetFullPath((Join-Path $rootFull '.tmp')).TrimEnd('\', '/')
$sourceOriginal = [IO.Path]::GetFullPath($SourcePath).TrimEnd('\', '/')
if (-not [string]::Equals(
        [IO.Path]::GetDirectoryName($sourceOriginal).TrimEnd('\', '/'),
        $protocol,
        [StringComparison]::OrdinalIgnoreCase
    )) {
    Fail-AstroForeignArchive `
        'ASTRO_FOREIGN_ARCHIVE_SOURCE_PATH_ESCAPE' `
        "source must be one direct child of the exact protocol directory: $sourceOriginal" `
        'pass only the independently inventoried foreign reserved entry'
}

$tempName = ConvertFrom-AstroLauncherTempName $sourceOriginal
$cleanupName = ConvertFrom-AstroLauncherTempCleanupName $sourceOriginal
if (-not $tempName.Candidate -and -not $cleanupName.Candidate) {
    Fail-AstroForeignArchive `
        'ASTRO_FOREIGN_ARCHIVE_SOURCE_NOT_RESERVED' `
        "source does not use a launcher-reserved prefix: $sourceOriginal" `
        'this command archives only conclusively foreign objects that block the reserved namespace'
}
if ($tempName.Valid -or $cleanupName.Valid) {
    Fail-AstroForeignArchive `
        'ASTRO_FOREIGN_ARCHIVE_CANONICAL_GENERATION_REFUSED' `
        "source is a canonical launcher generation/tombstone and is not foreign: $sourceOriginal" `
        'use the exact owner/Job/manifest-bound launcher generation recovery procedure'
}

if ($Operation -ceq 'Archive') {
    $issueValue = ConvertTo-AstroForeignPositiveInt $ExpectedIssue 'ExpectedIssue'
    $producerIssueValue = ConvertTo-AstroForeignPositiveInt `
        $ExpectedProducerIssue `
        'ExpectedProducerIssue'
    if ($ExpectedSourceFileId -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$' -or
        $ExpectedInventorySha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedProvenanceArgsSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedProvenanceClosureSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]::IsNullOrWhiteSpace($TrackerCommentUrl)) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_ARGUMENT_INVALID' `
            'Archive requires canonical lowercase FILE_ID/hashes and one tracker comment URL' `
            'copy the exact values from a fresh Inspect result and producer-evidence readback'
    }
}
else {
    $issueValue = if ([string]::IsNullOrWhiteSpace($ExpectedIssue)) {
        750
    } else {
        ConvertTo-AstroForeignPositiveInt $ExpectedIssue 'ExpectedIssue'
    }
    $producerIssueValue = $null
    if (-not [string]::IsNullOrEmpty($ExpectedSourceFileId) -and
        $ExpectedSourceFileId -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$') {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_ARGUMENT_INVALID' `
            'ExpectedSourceFileId is not one canonical lowercase FILE_ID' `
            'copy the exact FILE_ID from a prior Inspect result'
    }
}

$lockPath = Join-Path $protocol 'astrolabe-launcher.lock'
$mutex = $null
$protocolLease = $null
$sourceHandle = $null
$provenanceArgsLease = $null
$provenanceClosureLease = $null
$archiveRootLease = $null
$transactionLease = $null
$authorizationLease = $null
$completionLease = $null
try {
    $mutex = Enter-AstroLauncherLockMutex $lockPath
    if (-not $mutex.Acquired) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_MUTEX_HELD' `
            "launcher protocol mutex is owned by another process: $($mutex.Name)" `
            'preserve the entry and retry only after the exact live owner exits'
    }
    $protocolStateFirst = Get-AstroForeignProtocolState $rootFull $lockPath
    Assert-AstroForeignProtocolAbsent $protocolStateFirst

    $protocolState = Get-AstroPathEntryState $protocol
    if ($protocolState.State -ne 'present' -or
        ($protocolState.Attributes -band [IO.FileAttributes]::Directory) -eq 0) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_PROTOCOL_DIRECTORY_INVALID' `
            "protocol directory is not one ordinary present directory (state=$($protocolState.State), error=$($protocolState.Error)): $protocol" `
            'preserve every byte and repair only the exact protocol-directory state'
    }
    $protocolLease = Open-AstroLauncherPinnedDirectoryLease $protocol

    $transactionInfo = $null
    $archivedSource = $null
    $sourceState = Get-AstroPathEntryState $sourceOriginal
    if ($Operation -ceq 'Archive') {
        $transactionInfo = Get-AstroForeignTransactionPath `
            $protocol $issueValue $sourceOriginal $ExpectedSourceFileId `
            $ExpectedInventorySha256
        $archivedSource = [IO.Path]::GetFullPath((
            Join-Path $transactionInfo.TransactionPath 'preserved-source.dir'
        )).TrimEnd('\', '/')
    }

    $currentSource = $sourceOriginal
    if ($Operation -ceq 'Archive' -and $sourceState.State -eq 'absent') {
        $archivedState = Get-AstroPathEntryState $archivedSource
        if ($archivedState.State -ne 'present') {
            Fail-AstroForeignArchive `
                'ASTRO_FOREIGN_ARCHIVE_SOURCE_ABSENT' `
                "neither original nor deterministic archived source is present (archive_state=$($archivedState.State), error=$($archivedState.Error))" `
                'preserve the transaction and inspect the exact deterministic archive path'
        }
        $currentSource = $archivedSource
    }
    elseif ($sourceState.State -ne 'present') {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_SOURCE_UNEVALUABLE' `
            "source state is '$($sourceState.State)' ($($sourceState.Error)): $sourceOriginal" `
            'preserve every byte and retry only after the exact path is evaluable'
    }
    elseif ($Operation -ceq 'Archive' -and
        (Get-AstroPathEntryState $archivedSource).State -ne 'absent') {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_DUPLICATE_SOURCE' `
            'both original and deterministic archived source paths are present' `
            'preserve both objects; never infer which FILE_ID is authoritative'
    }

    $sourceHandle = if ($Operation -ceq 'Archive') {
        [AstroLauncherTempNative]::OpenExactDirectoryMutation($currentSource)
    } else {
        [AstroLauncherTempNative]::OpenExactDirectoryIdentity($currentSource)
    }
    $sourceLease = [pscustomobject]@{
        OriginalPath = $sourceOriginal
        Path = $currentSource
        Handle = $sourceHandle
        SafeFileHandle = $sourceHandle
    }
    $snapshotFirst = Get-AstroLauncherTempArchiveSnapshot $sourceLease
    $snapshotSecond = Get-AstroLauncherTempArchiveSnapshot $sourceLease
    $snapshotComparison = Compare-AstroLauncherTempArchiveSnapshots `
        $snapshotFirst $snapshotSecond
    if ($snapshotComparison.state -cne 'stable-exact' -or
        $snapshotSecond.InventoryState -cne 'exact') {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_SOURCE_UNSTABLE' `
            "retained source is not stable/exact (state=$($snapshotComparison.state), inventory=$($snapshotSecond.InventoryState), error=$($snapshotSecond.InventoryError))" `
            'preserve the exact object and resolve the inventory/metadata drift before retrying'
    }
    if (-not [string]::IsNullOrEmpty($ExpectedSourceFileId) -and
        $snapshotSecond.RootFileId -cne $ExpectedSourceFileId) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_SOURCE_IDENTITY_MISMATCH' `
            "source FILE_ID changed (expected=$ExpectedSourceFileId, observed=$($snapshotSecond.RootFileId))" `
            'preserve the replacement and post evidence only for the independently observed exact object'
    }

    if ($Operation -ceq 'Inspect') {
        $inspectTransaction = Get-AstroForeignTransactionPath `
            $protocol $issueValue $sourceOriginal $snapshotSecond.RootFileId `
            $snapshotSecond.InventorySha256
        [ordered]@{
            schema = 'astrolabe.foreign-reserved-state-inspection.v1'
            root = $rootFull
            source_path = $sourceOriginal
            source_current_path = $currentSource
            source_file_id = $snapshotSecond.RootFileId
            source_root_state = $snapshotSecond.RootState
            source_inventory_state = $snapshotSecond.InventoryState
            source_entry_count = $snapshotSecond.EntryCount
            source_inventory_sha256 = $snapshotSecond.InventorySha256
            source_inventory_observation_sha256 =
                $snapshotSecond.ObservationInventorySha256
            source_inventory_authorization_scope =
                $snapshotSecond.InventoryAuthorizationScope
            transaction_path = $inspectTransaction.TransactionPath
            active_lock_state = $protocolStateFirst.Active.State
            transition_state = $protocolStateFirst.Transitions.State
            target_state = $protocolStateFirst.Target.State
        } | ConvertTo-Json -Depth 8 -Compress
        return
    }

    $sourceAlreadyArchived = -not [string]::Equals(
        $currentSource,
        $sourceOriginal,
        [StringComparison]::OrdinalIgnoreCase
    )
    if ($snapshotSecond.RootFileId -cne $ExpectedSourceFileId -or
        (-not $sourceAlreadyArchived -and
            $snapshotSecond.InventorySha256 -cne $ExpectedInventorySha256)) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_SOURCE_SNAPSHOT_MISMATCH' `
            "source snapshot differs from command authority (file_id=$($snapshotSecond.RootFileId), inventory=$($snapshotSecond.InventorySha256))" `
            'preserve the object and post fresh evidence only for its current exact state'
    }
    if ($snapshotSecond.EntryCount -ne 0) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_SOURCE_NOT_EMPTY' `
            "foreign reserved entry contains $($snapshotSecond.EntryCount) classified descendant(s)" `
            'preserve the complete tree; this recovery transaction accepts only the independently proven empty FSV fixture'
    }

    $argsFull = [IO.Path]::GetFullPath($ProvenanceArgsPath)
    $closureFull = [IO.Path]::GetFullPath($ProvenanceClosurePath)
    $provenanceArgsLease = Open-AstroForeignEvidenceFile `
        $argsFull $ExpectedProvenanceArgsSha256 'producer args'
    $provenanceClosureLease = Open-AstroForeignEvidenceFile `
        $closureFull $ExpectedProvenanceClosureSha256 'producer closure'

    $trackerFirst = Read-AstroForeignTrackerEvidence `
        $TrackerCommentUrl $issueValue $producerIssueValue $rootFull `
        $sourceOriginal $ExpectedSourceFileId $ExpectedInventorySha256 `
        $argsFull $ExpectedProvenanceArgsSha256 $closureFull `
        $ExpectedProvenanceClosureSha256 $transactionInfo.TransactionPath
    $protocolStateProbeOne = Get-AstroForeignProtocolState $rootFull $lockPath
    Assert-AstroForeignProtocolAbsent $protocolStateProbeOne
    Start-Sleep -Milliseconds 1000
    $protocolStateProbeTwo = Get-AstroForeignProtocolState $rootFull $lockPath
    Assert-AstroForeignProtocolAbsent $protocolStateProbeTwo

    $archiveRootState = Get-AstroPathEntryState $transactionInfo.ArchiveRoot
    if ($archiveRootState.State -eq 'absent') {
        New-AstroDirectoryLongPath $transactionInfo.ArchiveRoot | Out-Null
    }
    elseif ($archiveRootState.State -ne 'present' -or
        ($archiveRootState.Attributes -band [IO.FileAttributes]::Directory) -eq 0) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_ROOT_UNEVALUABLE' `
            "archive root state=$($archiveRootState.State); error=$($archiveRootState.Error); path=$($transactionInfo.ArchiveRoot)" `
            'preserve every byte and repair only the exact append-only archive root'
    }
    $archiveRootLease = Open-AstroLauncherPinnedDirectoryLease `
        $transactionInfo.ArchiveRoot

    $transactionState = Get-AstroPathEntryState $transactionInfo.TransactionPath
    if ($transactionState.State -eq 'absent') {
        New-AstroDirectoryNoClobberLongPath $transactionInfo.TransactionPath |
            Out-Null
    }
    elseif ($transactionState.State -ne 'present' -or
        ($transactionState.Attributes -band [IO.FileAttributes]::Directory) -eq 0) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_TRANSACTION_UNEVALUABLE' `
            "transaction state=$($transactionState.State); error=$($transactionState.Error); path=$($transactionInfo.TransactionPath)" `
            'preserve every byte and inspect the deterministic transaction path'
    }
    $transactionLease = Open-AstroLauncherPinnedDirectoryLease `
        $transactionInfo.TransactionPath

    $authorizationPath = Join-Path `
        $transactionInfo.TransactionPath `
        'authorization.json'
    $authorizationState = Get-AstroPathEntryState $authorizationPath
    if ($authorizationState.State -eq 'absent') {
        if (-not [string]::Equals(
                $currentSource,
                $sourceOriginal,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-AstroForeignArchive `
                'ASTRO_FOREIGN_ARCHIVE_AUTHORIZATION_MISSING' `
                'source is already archived but its create-before-rename authorization record is absent' `
                'preserve the transaction; never reconstruct authority after namespace mutation'
        }
        $authorization = [ordered]@{
            schema = 'astrolabe.foreign-reserved-state-archive.authorization.v1'
            created_utc = [DateTime]::UtcNow.ToString('O')
            authority = [ordered]@{
                driving_issue = $issueValue
                producer_issue = $producerIssueValue
                tracker_comment_url = $TrackerCommentUrl
                tracker_comment_id = $trackerFirst.CommentId
                tracker_author = $trackerFirst.Author
            }
            policy = [ordered]@{
                destructive_authority = 'none'
                namespace_operation =
                    'same-volume-retained-handle-no-replace-rename'
                accepted_source =
                    'foreign-empty-ordinary-reserved-prefix-directory'
                canonical_generation_policy = 'refuse'
                nonempty_or_opaque_policy = 'preserve-and-refuse'
            }
            source = [ordered]@{
                original_path = $sourceOriginal
                current_path = $currentSource
                root_file_id = $snapshotSecond.RootFileId
                root_state = $snapshotSecond.RootState
                inventory_state = $snapshotSecond.InventoryState
                entry_count = $snapshotSecond.EntryCount
                inventory_sha256 = $snapshotSecond.InventorySha256
                inventory_observation_sha256 =
                    $snapshotSecond.ObservationInventorySha256
                inventory_authorization_scope =
                    $snapshotSecond.InventoryAuthorizationScope
            }
            provenance = [ordered]@{
                args_path = $argsFull
                args_file_id = $provenanceArgsLease.Snapshot.FileId
                args_bytes = $provenanceArgsLease.Snapshot.Length
                args_sha256 = $provenanceArgsLease.Snapshot.Sha256
                closure_path = $closureFull
                closure_file_id = $provenanceClosureLease.Snapshot.FileId
                closure_bytes = $provenanceClosureLease.Snapshot.Length
                closure_sha256 = $provenanceClosureLease.Snapshot.Sha256
            }
            archive = [ordered]@{
                transaction_path = $transactionInfo.TransactionPath
                identity_sha256 = $transactionInfo.IdentitySha256
                source_destination = $archivedSource
            }
            preconditions = [ordered]@{
                active_lock_state = $protocolStateProbeTwo.Active.State
                transition_state = $protocolStateProbeTwo.Transitions.State
                target_state = $protocolStateProbeTwo.Target.State
            }
        }
        $authorizationLease = Write-AstroLauncherStateArchiveRecord `
            -TransactionDirectoryLease $transactionLease `
            -Leaf 'authorization.json' `
            -Value $authorization
    }
    elseif ($authorizationState.State -eq 'present') {
        $authorizationLease = Read-AstroForeignArchiveRecord $authorizationPath
        $a = $authorizationLease.Parsed
        if ([string]$a.schema -cne
                'astrolabe.foreign-reserved-state-archive.authorization.v1' -or
            [int]$a.authority.driving_issue -ne $issueValue -or
            [int]$a.authority.producer_issue -ne $producerIssueValue -or
            [string]$a.authority.tracker_comment_url -cne $TrackerCommentUrl -or
            -not [string]::Equals([string]$a.source.original_path, $sourceOriginal, [StringComparison]::OrdinalIgnoreCase) -or
            [string]$a.source.root_file_id -cne $ExpectedSourceFileId -or
            [int]$a.source.entry_count -ne 0 -or
            [string]$a.source.inventory_sha256 -cne $ExpectedInventorySha256 -or
            [string]$a.source.inventory_observation_sha256 -cnotmatch
                '^[0-9a-f]{64}$' -or
            [string]$a.provenance.args_sha256 -cne $ExpectedProvenanceArgsSha256 -or
            [string]$a.provenance.closure_sha256 -cne $ExpectedProvenanceClosureSha256 -or
            -not [string]::Equals([string]$a.archive.transaction_path, $transactionInfo.TransactionPath, [StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals([string]$a.archive.source_destination, $archivedSource, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-AstroForeignArchive `
                'ASTRO_FOREIGN_ARCHIVE_AUTHORIZATION_MISMATCH' `
                'existing deterministic authorization record differs from the exact recovery request' `
                'preserve the append-only transaction and inspect its immutable authorization bytes'
        }
    }
    else {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_AUTHORIZATION_UNEVALUABLE' `
            "authorization state=$($authorizationState.State); error=$($authorizationState.Error)" `
            'preserve the deterministic transaction and inspect its exact record state'
    }
    $authorizationSnapshot = Get-AstroForeignArchiveRecordSnapshot `
        $authorizationLease
    if ($sourceAlreadyArchived) {
        $authorizedSourceSnapshot = [pscustomobject]@{
            RootFileId = [string]$authorizationLease.Parsed.source.root_file_id
            RootState = [string]$authorizationLease.Parsed.source.root_state
            InventoryState = [string]$authorizationLease.Parsed.source.inventory_state
            InventoryError = $null
            EntryCount = [int]$authorizationLease.Parsed.source.entry_count
            InventorySha256 = [string]$authorizationLease.Parsed.source.inventory_sha256
            ObservationInventorySha256 =
                [string]$authorizationLease.Parsed.source.inventory_observation_sha256
            InventoryAuthorizationScope =
                [string]$authorizationLease.Parsed.source.inventory_authorization_scope
            Entries = [string[]]@()
        }
        $resumeComparison = Compare-AstroLauncherTempArchiveSnapshots `
            $authorizedSourceSnapshot $snapshotSecond `
            -ComparisonMode exact-rename
        if ($resumeComparison.state -cne 'stable-exact') {
            Fail-AstroForeignArchive `
                'ASTRO_FOREIGN_ARCHIVE_RESUME_SOURCE_CHANGED' `
                "archived retained source differs from its create-before-rename authorization (state=$($resumeComparison.state))" `
                'preserve the interrupted transaction; never reconstruct or replace its authorized source identity'
        }
    }

    $trackerFinal = Read-AstroForeignTrackerEvidence `
        $TrackerCommentUrl $issueValue $producerIssueValue $rootFull `
        $sourceOriginal $ExpectedSourceFileId $ExpectedInventorySha256 `
        $argsFull $ExpectedProvenanceArgsSha256 $closureFull `
        $ExpectedProvenanceClosureSha256 $transactionInfo.TransactionPath
    $protocolStateFinal = Get-AstroForeignProtocolState $rootFull $lockPath
    Assert-AstroForeignProtocolAbsent $protocolStateFinal
    if ($trackerFinal.CommentId -ne $trackerFirst.CommentId) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_FINAL_AUTHORITY_CHANGED' `
            'tracker evidence identity changed during transaction authorization' `
            'preserve the transaction and inspect exact tracker/local state'
    }

    $beforeMove = Get-AstroLauncherTempArchiveSnapshot $sourceLease
    if ($beforeMove.RootFileId -cne $ExpectedSourceFileId -or
        $beforeMove.EntryCount -ne 0 -or
        (-not $sourceAlreadyArchived -and
            $beforeMove.InventorySha256 -cne $ExpectedInventorySha256)) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_SOURCE_CHANGED_BEFORE_RENAME' `
            'retained source changed after durable authorization' `
            'preserve the authorization and exact source; do not publish completion'
    }

    if ([string]::Equals(
            $currentSource,
            $sourceOriginal,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        [AstroLauncherTempNative]::RenameExactDirectoryNoReplace(
            $sourceHandle,
            $transactionLease.SafeFileHandle,
            'preserved-source.dir'
        )
        $sourceLease.Path = $archivedSource
        $currentSource = $archivedSource
    }
    $afterMove = Get-AstroLauncherTempArchiveSnapshot $sourceLease
    $renameComparison = Compare-AstroLauncherTempArchiveSnapshots `
        $beforeMove $afterMove `
        -ComparisonMode exact-rename
    $directState = Get-AstroPathEntryState $sourceOriginal
    if ($renameComparison.state -cne 'stable-exact' -or
        $afterMove.RootFileId -cne $ExpectedSourceFileId -or
        $afterMove.EntryCount -ne 0 -or
        $directState.State -ne 'absent' -or
        -not [string]::Equals(
            $afterMove.RootFinalPath,
            $archivedSource,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_RENAME_READBACK_INVALID' `
            "comparison=$($renameComparison.state); file_id=$($afterMove.RootFileId); entries=$($afterMove.EntryCount); source=$($directState.State); final_path=$($afterMove.RootFinalPath)" `
            'preserve the complete transaction and inspect exact retained-handle/archive state'
    }

    $completionPath = Join-Path $transactionInfo.TransactionPath 'completion.json'
    $completionState = Get-AstroPathEntryState $completionPath
    if ($completionState.State -eq 'absent') {
        $completion = [ordered]@{
            schema = 'astrolabe.foreign-reserved-state-archive.completion.v1'
            completed_utc = [DateTime]::UtcNow.ToString('O')
            driving_issue = $issueValue
            producer_issue = $producerIssueValue
            tracker_comment_url = $TrackerCommentUrl
            authorization = [ordered]@{
                path = $authorizationLease.Path
                file_id = $authorizationSnapshot.FileId
                bytes = $authorizationSnapshot.Length
                sha256 = $authorizationSnapshot.Sha256
            }
            source = [ordered]@{
                original_path = $sourceOriginal
                original_state = $directState.State
                archive_path = $archivedSource
                root_file_id = $afterMove.RootFileId
                root_state = $afterMove.RootState
                entry_count = $afterMove.EntryCount
                inventory_sha256 = $afterMove.InventorySha256
                inventory_observation_sha256 =
                    $afterMove.ObservationInventorySha256
                integrity = $renameComparison
            }
            terminal = [ordered]@{
                active_lock_state = $protocolStateFinal.Active.State
                transition_state = $protocolStateFinal.Transitions.State
                target_state = $protocolStateFinal.Target.State
            }
        }
        $completionLease = Write-AstroLauncherStateArchiveRecord `
            -TransactionDirectoryLease $transactionLease `
            -Leaf 'completion.json' `
            -Value $completion
    }
    elseif ($completionState.State -eq 'present') {
        $completionLease = Read-AstroForeignArchiveRecord $completionPath
        $c = $completionLease.Parsed
        if ([string]$c.schema -cne
                'astrolabe.foreign-reserved-state-archive.completion.v1' -or
            [string]$c.authorization.sha256 -cne $authorizationSnapshot.Sha256 -or
            [string]$c.source.root_file_id -cne $ExpectedSourceFileId -or
            [int]$c.source.entry_count -ne 0 -or
            [string]$c.source.inventory_sha256 -cne $afterMove.InventorySha256 -or
            [string]$c.source.inventory_observation_sha256 -cnotmatch
                '^[0-9a-f]{64}$' -or
            [string]$c.source.original_state -cne 'absent') {
            Fail-AstroForeignArchive `
                'ASTRO_FOREIGN_ARCHIVE_COMPLETION_MISMATCH' `
                'existing completion record differs from retained terminal state' `
                'preserve the complete transaction and inspect exact immutable completion bytes'
        }
    }
    else {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_COMPLETION_UNEVALUABLE' `
            "completion state=$($completionState.State); error=$($completionState.Error)" `
            'preserve the complete transaction and inspect exact record state'
    }
    $completionSnapshot = Get-AstroForeignArchiveRecordSnapshot $completionLease

    $terminalSnapshot = Get-AstroLauncherTempArchiveSnapshot $sourceLease
    $terminalProtocol = Get-AstroForeignProtocolState $rootFull $lockPath
    Assert-AstroForeignProtocolAbsent $terminalProtocol
    $terminalTemps = Get-AstroReservedLauncherTempEntries $protocol
    if ((Get-AstroPathEntryState $sourceOriginal).State -ne 'absent' -or
        $terminalSnapshot.RootFileId -cne $ExpectedSourceFileId -or
        $terminalSnapshot.EntryCount -ne 0 -or
        @($terminalTemps.Records | Where-Object { -not $_.Valid }).Count -ne 0) {
        Fail-AstroForeignArchive `
            'ASTRO_FOREIGN_ARCHIVE_TERMINAL_READBACK_INVALID' `
            "source=$((Get-AstroPathEntryState $sourceOriginal).State); file_id=$($terminalSnapshot.RootFileId); entries=$($terminalSnapshot.EntryCount); malformed_remaining=$(@($terminalTemps.Records | Where-Object { -not $_.Valid }).Count)" `
            'preserve the archive and resolve only the exact terminal protocol mismatch'
    }

    [ordered]@{
        schema = 'astrolabe.foreign-reserved-state-archive-result.v1'
        driving_issue = $issueValue
        producer_issue = $producerIssueValue
        tracker_comment_url = $TrackerCommentUrl
        source_path = $sourceOriginal
        source_state = 'absent'
        source_file_id = $terminalSnapshot.RootFileId
        source_entry_count = $terminalSnapshot.EntryCount
        source_inventory_sha256 = $terminalSnapshot.InventorySha256
        archive_path = $archivedSource
        transaction_path = $transactionInfo.TransactionPath
        authorization_path = $authorizationLease.Path
        authorization_sha256 = $authorizationSnapshot.Sha256
        completion_path = $completionLease.Path
        completion_sha256 = $completionSnapshot.Sha256
        active_lock_state = $terminalProtocol.Active.State
        transition_state = $terminalProtocol.Transitions.State
        target_state = $terminalProtocol.Target.State
        malformed_reserved_entries_remaining = 0
    } | ConvertTo-Json -Depth 8 -Compress
}
finally {
    foreach ($lease in @(
            $completionLease,
            $authorizationLease,
            $provenanceClosureLease,
            $provenanceArgsLease
        )) {
        if ($null -ne $lease -and $null -ne $lease.Handle -and
            -not $lease.Handle.IsClosed) {
            $lease.Handle.Dispose()
        }
    }
    if ($null -ne $sourceHandle -and -not $sourceHandle.IsClosed) {
        $sourceHandle.Dispose()
    }
    foreach ($lease in @($transactionLease, $archiveRootLease, $protocolLease)) {
        if ($null -ne $lease -and $null -ne $lease.SafeFileHandle -and
            -not $lease.SafeFileHandle.IsClosed) {
            $lease.SafeFileHandle.Dispose()
        }
    }
    if ($null -ne $mutex) {
        Exit-AstroLauncherLockMutex $mutex
    }
}
