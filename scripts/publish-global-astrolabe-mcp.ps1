<#
.SYNOPSIS
    Publish one verified Astrolabe MCP compatibility shim as an immutable global generation.

.DESCRIPTION
    The native build target is disposable launcher-owned state. This command accepts only a
    content-addressed native-fsv-artifact.v2 receipt plus a verified native-fsv-run.v2 record
    created under the same live issue-owned launcher generation. It copies the exact staged
    artifact into a fresh generation beneath the user's Astrolabe program directory, flushes
    every new file, and publishes the complete directory with MoveFileExW write-through and
    no replacement.

    Existing generations are never reused or replaced. Client configuration is deliberately a
    separate transaction: Codex and Claude Code must be switched to the exact published path
    only after this command's independent readback succeeds.

.NOTES
    Manual FSV/publication tooling for #751. This is not a test or a fallback installer.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$NativeFsvReceiptPath,
    [Parameter(Mandatory)][string]$NativeFsvRunRecordPath,
    [Parameter(Mandatory)][int]$Issue,
    [Parameter(Mandatory)][string]$ExpectedTreeSha,
    [string]$InstallRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

. (Join-Path $PSScriptRoot 'launcher-lock.ps1')

function Fail-AstroGlobalPublish {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Remediation
    )

    $exception = [InvalidOperationException]::new($Message)
    $exception.Data['AstroCode'] = $Code
    $exception.Data['AstroRemediation'] = $Remediation
    throw $exception
}

function Path-WithTrailingSeparator {
    param([Parameter(Mandatory)][string]$Path)

    return [IO.Path]::GetFullPath($Path).TrimEnd('\', '/') +
        [IO.Path]::DirectorySeparatorChar
}

function Assert-PathWithin {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith(
            (Path-WithTrailingSeparator $Root),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-AstroGlobalPublish $Code `
            "$Description '$full' escapes required root '$([IO.Path]::GetFullPath($Root))'" `
            'pass the exact workspace-local native-FSV record produced by this repository'
    }
    return $full
}

function Assert-OrdinaryEntry {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description,
        [switch]$AllowAbsent
    )

    $state = Get-AstroPathEntryState $Path
    if ($state.State -ceq 'absent' -and $AllowAbsent) { return }
    if ($state.State -cne 'present') {
        Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_PATH_UNEVALUABLE' `
            "$Description is not an evaluable present ordinary entry: $Path (state=$($state.State); error=$($state.Error))" `
            'repair the exact path or use a fresh ordinary local directory before publishing'
    }
    if (($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_REPARSE_REFUSED' `
            "$Description is a reparse point: $Path" `
            'use ordinary local files and directories for global publication state'
    }
}

function File-Sha256 {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([Convert]::ToHexString($hasher.ComputeHash($stream))).ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

function File-Identity {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        return [AstroLauncherLockNative]::GetFileIdentity($stream.SafeFileHandle)
    }
    finally { $stream.Dispose() }
}

function Write-NewDurableUtf8 {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Content)
    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
}

function Copy-NewDurableFile {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )

    $input = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Source),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $output = [IO.File]::Open(
            (ConvertTo-AstroExtendedLengthPath $Destination),
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $input.CopyTo($output)
            $output.Flush($true)
        }
        finally { $output.Dispose() }
    }
    finally { $input.Dispose() }
}

function Test-DescendantOf {
    param(
        [Parameter(Mandatory)][int]$CandidatePid,
        [Parameter(Mandatory)][int]$AncestorPid
    )

    $seen = @{}
    $current = $CandidatePid
    while ($current -gt 0 -and -not $seen.ContainsKey($current)) {
        if ($current -eq $AncestorPid) { return $true }
        $seen[$current] = $true
        $row = Get-CimInstance Win32_Process -Filter "ProcessId=$current" -ErrorAction Stop
        if ($null -eq $row) { return $false }
        $current = [int]$row.ParentProcessId
    }
    return $false
}

function Assert-ExactProcessIdentityRecord {
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][int]$ExpectedPid,
        [Parameter(Mandatory)][long]$ExpectedProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$Description
    )

    if ($null -eq $Record -or
        -not $Record.PSObject.Properties['pid'] -or
        -not $Record.PSObject.Properties['process_start_utc_ticks'] -or
        [int]$Record.pid -ne $ExpectedPid -or
        [long]$Record.process_start_utc_ticks -ne
            $ExpectedProcessStartUtcTicks) {
        Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_OWNER_MISMATCH' `
            "$Description does not name launcher owner ($ExpectedPid,$ExpectedProcessStartUtcTicks)" `
            'stage, run, and publish the artifact inside one exact launcher generation'
    }
}

if ($Issue -le 0) {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_ISSUE_INVALID' `
        "Issue must be positive; received $Issue" `
        'pass the active GitHub issue number'
}
if ($ExpectedTreeSha -cnotmatch '^[0-9a-fA-F]{40}$') {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_TREE_INVALID' `
        "ExpectedTreeSha is not a full Git object id: '$ExpectedTreeSha'" `
        'pass the exact clean commit used by the native launcher'
}
$ExpectedTreeSha = $ExpectedTreeSha.ToLowerInvariant()

$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$evidenceRoot = Join-Path $workspace '.tmp\native-fsv-artifacts'
$launcherLockPath = Join-Path $workspace '.tmp\astrolabe-launcher.lock'

if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_USERPROFILE_MISSING' `
        'USERPROFILE is absent; global Codex and Claude Code config identities are undefined' `
        'run from the intended interactive Windows user profile'
}

if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_LOCALAPPDATA_MISSING' `
            'LOCALAPPDATA is absent; the global Astrolabe program root is undefined' `
            'run from the intended interactive Windows user profile'
    }
    $InstallRoot = Join-Path $env:LOCALAPPDATA 'Programs\Astrolabe'
}
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)

$launcher = Read-AstroLauncherLock -LockPath $launcherLockPath
if ($launcher.State -cne 'held' -or
    [int]$launcher.Issue -ne $Issue -or
    [string]$launcher.HeadSha -cne $ExpectedTreeSha) {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_LAUNCHER_INVALID' `
        "launcher does not hold issue #$Issue at tree $ExpectedTreeSha (state=$($launcher.State); issue=$($launcher.Issue); head=$($launcher.HeadSha); pid=$($launcher.OwnerPid); ticks=$($launcher.OwnerProcessStartUtcTicks))" `
        'publish synchronously inside the exact issue-owned native launcher generation'
}
$launcherProbe = Get-AstroExactProcessIdentityProbe `
    -Pid ([int]$launcher.OwnerPid) `
    -ProcessStartUtcTicks ([long]$launcher.OwnerProcessStartUtcTicks)
if ($launcherProbe.State -cne 'exact-live') {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_LAUNCHER_IDENTITY' `
        "launcher owner is not exact-live: $($launcherProbe | ConvertTo-Json -Depth 6 -Compress)" `
        'preserve all state and recover the launcher generation through its tracker-bound protocol'
}
if (-not (Test-DescendantOf -CandidatePid $PID -AncestorPid ([int]$launcher.OwnerPid))) {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_CALLER_NOT_OWNED' `
        "publisher PID $PID is not a descendant of launcher PID $($launcher.OwnerPid)" `
        'invoke publication synchronously from the launcher-owned batch'
}
try {
    $launcherRootIdentity =
        [AstroLauncherLockNative]::GetDirectoryIdentity($workspace)
    $launcherJobName = Get-AstroLauncherTreeJobObjectName `
        -RootIdentity $launcherRootIdentity `
        -LauncherPid ([int]$launcher.OwnerPid) `
        -LauncherProcessStartUtcTicks `
            ([long]$launcher.OwnerProcessStartUtcTicks) `
        -LauncherLeaseStartUtcTicks ([long]$launcher.LeaseStartUtcTicks) `
        -LauncherLockSha256 ([string]$launcher.Sha256)
    $launcherJobProbe = Get-AstroLauncherJobObjectProbe -Name $launcherJobName
}
catch {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_JOB_UNEVALUABLE' `
        "could not derive and query the exact launcher Job Object: $($_.Exception.Message)" `
        'preserve all state and repair exact launcher Job attribution before publication'
}
$launcherJobMembers = [int[]]@(
    $launcherJobProbe.ProcessIds | Sort-Object -Unique
)
if ($launcherJobProbe.State -cne 'observed' -or
    $launcherJobMembers -notcontains [int]$launcher.OwnerPid -or
    $launcherJobMembers -notcontains $PID) {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_JOB_MISMATCH' `
        "exact launcher Job does not contain launcher PID $($launcher.OwnerPid) and publisher PID $PID (name=$launcherJobName; state=$($launcherJobProbe.State); members=$($launcherJobMembers -join ','); error=$($launcherJobProbe.Error))" `
        'invoke publication only as a non-breakaway descendant of the exact launcher owner'
}

$receiptPath = Assert-PathWithin `
    $NativeFsvReceiptPath $evidenceRoot `
    'ASTRO_GLOBAL_PUBLISH_RECEIPT_ESCAPE' 'native-FSV receipt'
$runPath = Assert-PathWithin `
    $NativeFsvRunRecordPath $evidenceRoot `
    'ASTRO_GLOBAL_PUBLISH_RUN_ESCAPE' 'native-FSV run record'
Assert-OrdinaryEntry $receiptPath 'native-FSV receipt'
Assert-OrdinaryEntry $runPath 'native-FSV run record'

$nativeReceiptRaw = Read-AstroUtf8FileLongPath $receiptPath
$nativeRunRaw = Read-AstroUtf8FileLongPath $runPath
$nativeReceipt = $nativeReceiptRaw | ConvertFrom-Json
$nativeRun = $nativeRunRaw | ConvertFrom-Json
$nativeReceiptSha = File-Sha256 $receiptPath
$nativeRunSha = File-Sha256 $runPath

if ([string]$nativeReceipt.schema -cne 'astrolabe.native-fsv-artifact.v2' -or
    [int]$nativeReceipt.issue -ne $Issue -or
    [string]$nativeReceipt.tree_sha -cne $ExpectedTreeSha) {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_RECEIPT_INVALID' `
        'native-FSV receipt schema, issue, or tree does not match publication authority' `
        'pass the exact receipt emitted by native-fsv-artifact.ps1 in this launcher generation'
}
Assert-ExactProcessIdentityRecord `
    $nativeReceipt.owners.launcher `
    ([int]$launcher.OwnerPid) `
    ([long]$launcher.OwnerProcessStartUtcTicks) `
    'native-FSV receipt launcher identity'
if ([string]$nativeRun.schema -cne 'astrolabe.native-fsv-run.v2' -or
    [string]$nativeRun.verdict -cne 'verified' -or
    [int]$nativeRun.issue -ne $Issue -or
    [string]$nativeRun.receipt_path -cne $receiptPath -or
    [string]$nativeRun.receipt.sha256_after -cne $nativeReceiptSha -or
    [int]$nativeRun.process.exit_code -ne 0) {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_RUN_INVALID' `
        'native-FSV run is not one verified zero-exit execution of the exact supplied receipt' `
        'run the staged artifact through native-fsv-run.ps1 and pass its exact terminal record'
}
Assert-ExactProcessIdentityRecord `
    $nativeRun.launcher `
    ([int]$launcher.OwnerPid) `
    ([long]$launcher.OwnerProcessStartUtcTicks) `
    'native-FSV run launcher identity'
if ([string]$nativeRun.launcher_lease.sha256_after -cne
        [string]$launcher.Sha256 -or
    [bool]$nativeRun.launcher_lease.stable -ne $true -or
    [bool]$nativeRun.repository.stable -ne $true -or
    [string]$nativeReceipt.repository.head_sha -cne $ExpectedTreeSha -or
    [string]$nativeRun.repository.before.head_sha -cne $ExpectedTreeSha -or
    [string]$nativeRun.repository.after.head_sha -cne $ExpectedTreeSha -or
    [string]$nativeReceipt.repository.status_sha256 -cne
        [string]$launcher.StatusSha256 -or
    [string]$nativeRun.repository.before.status_sha256 -cne
        [string]$launcher.StatusSha256 -or
    [string]$nativeRun.repository.after.status_sha256 -cne
        [string]$launcher.StatusSha256 -or
    [string]$nativeReceipt.repository.diff_sha256 -cne
        [string]$launcher.DiffSha256 -or
    [string]$nativeRun.repository.before.diff_sha256 -cne
        [string]$launcher.DiffSha256 -or
    [string]$nativeRun.repository.after.diff_sha256 -cne
        [string]$launcher.DiffSha256) {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_PROVENANCE_MISMATCH' `
        'native-FSV repository or launcher-lease provenance differs from the live frozen launcher generation' `
        'preserve the session and repeat build, stage, run, and publication in one frozen launcher generation'
}

$artifactPath = [IO.Path]::GetFullPath([string]$nativeReceipt.artifact.path)
$sessionRoot = Split-Path -Parent $receiptPath
[void](Assert-PathWithin `
        $artifactPath $sessionRoot `
        'ASTRO_GLOBAL_PUBLISH_ARTIFACT_ESCAPE' 'staged artifact')
[void](Assert-PathWithin `
        $runPath $sessionRoot `
        'ASTRO_GLOBAL_PUBLISH_RUN_SESSION_MISMATCH' 'native-FSV run record')
Assert-OrdinaryEntry $artifactPath 'staged artifact'

$artifactHashBefore = File-Sha256 $artifactPath
$artifactLength = [uint64](Get-AstroFileLengthLongPath $artifactPath)
if ($artifactHashBefore -cne [string]$nativeReceipt.artifact.sha256 -or
    $artifactHashBefore -cne [string]$nativeRun.artifact.sha256 -or
    [string]$nativeRun.artifact.path -cne $artifactPath -or
    [bool]$nativeRun.artifact.stable -ne $true -or
    $artifactLength -ne [uint64]$nativeReceipt.artifact.bytes -or
    $artifactLength -ne [uint64]$nativeRun.artifact.bytes) {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_ARTIFACT_DRIFT' `
        'staged artifact bytes do not match the native receipt and verified run record' `
        'preserve the FSV session and investigate artifact drift before publication'
}
if ([IO.Path]::GetFileName($artifactPath) -cne 'codebase-memory-mcp.exe') {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_ARTIFACT_NAME' `
        "expected the fused compatibility shim codebase-memory-mcp.exe, got '$artifactPath'" `
        'build and stage astrolabe-server --bin codebase-memory-mcp'
}

Assert-OrdinaryEntry $InstallRoot 'global Astrolabe install root' -AllowAbsent
New-AstroDirectoryLongPath $InstallRoot | Out-Null
Assert-OrdinaryEntry $InstallRoot 'global Astrolabe install root'
$generationsRoot = Join-Path $InstallRoot 'generations'
Assert-OrdinaryEntry $generationsRoot 'global generations root' -AllowAbsent
New-AstroDirectoryLongPath $generationsRoot | Out-Null
Assert-OrdinaryEntry $generationsRoot 'global generations root'

$generationName = "$ExpectedTreeSha-$artifactHashBefore"
$generationPath = Join-Path $generationsRoot $generationName
if (Test-AstroPathLongPath -LiteralPath $generationPath) {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_GENERATION_EXISTS' `
        "immutable global generation already exists: $generationPath" `
        'inspect and use the existing exact receipt, or publish a different tree/artifact generation'
}

$publishingPath = Join-Path $generationsRoot (
    ".$generationName.publishing-$PID-" + [Guid]::NewGuid().ToString('N')
)
New-AstroDirectoryNoClobberLongPath $publishingPath | Out-Null
Assert-OrdinaryEntry $publishingPath 'global publication stage'

$publishedArtifact = Join-Path $publishingPath 'codebase-memory-mcp.exe'
Copy-NewDurableFile $artifactPath $publishedArtifact
$artifactHashAfter = File-Sha256 $artifactPath
$publishedHash = File-Sha256 $publishedArtifact
$publishedLength = [uint64](Get-AstroFileLengthLongPath $publishedArtifact)
if ($artifactHashAfter -cne $artifactHashBefore -or
    $publishedHash -cne $artifactHashBefore -or
    $publishedLength -ne $artifactLength) {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_COPY_MISMATCH' `
        "artifact changed during copy (before=$artifactHashBefore; after=$artifactHashAfter; published=$publishedHash; source_bytes=$artifactLength; published_bytes=$publishedLength; stage=$publishingPath)" `
        'preserve the publication stage and native-FSV session for diagnosis'
}
Set-AstroFileReadOnlyLongPath -LiteralPath $publishedArtifact -ReadOnly $true

$finalArtifact = Join-Path $generationPath 'codebase-memory-mcp.exe'
$finalReceipt = Join-Path $generationPath 'publication.json'
$codexConfigPath = if ([string]::IsNullOrWhiteSpace($env:CODEX_HOME)) {
    Join-Path $env:USERPROFILE '.codex\config.toml'
} else {
    Join-Path $env:CODEX_HOME 'config.toml'
}
$claudeUserConfigPath = Join-Path $env:USERPROFILE '.claude.json'
$publication = [ordered]@{
    schema = 'astrolabe.global-mcp-publication.v1'
    issue = $Issue
    published_at_utc = [DateTime]::UtcNow.ToString('o')
    tree_sha = $ExpectedTreeSha
    launcher = [ordered]@{
        pid = [int]$launcher.OwnerPid
        process_start_utc_ticks = [long]$launcher.OwnerProcessStartUtcTicks
        lease_start_utc_ticks = [long]$launcher.LeaseStartUtcTicks
        launcher_lock_sha256 = [string]$launcher.Sha256
        job_object_name = $launcherJobName
    }
    native_fsv = [ordered]@{
        receipt_path = $receiptPath
        receipt_sha256 = $nativeReceiptSha
        run_record_path = $runPath
        run_record_sha256 = $nativeRunSha
        run_verdict = [string]$nativeRun.verdict
        process = $nativeRun.process.identity
    }
    artifact = [ordered]@{
        source_path = $artifactPath
        installed_path = $finalArtifact
        bytes = $artifactLength
        sha256 = $artifactHashBefore
        read_only = $true
    }
    generation = [ordered]@{
        root = $generationPath
        id = $generationName
        publication = 'MoveFileExW(MOVEFILE_WRITE_THROUGH,no-replace)'
        same_volume = $true
    }
    client_configuration = [ordered]@{
        server_name = 'astrolabe'
        command = $finalArtifact
        arguments = @()
        codex = [ordered]@{
            config_path = [IO.Path]::GetFullPath($codexConfigPath)
            required = $true
        }
        claude_code = [ordered]@{
            scope = 'user'
            config_readback_path =
                [IO.Path]::GetFullPath($claudeUserConfigPath)
        }
        legacy_server_name = 'codebase-memory-mcp'
        legacy_configured_fallback_permitted = $false
    }
}
$stageReceipt = Join-Path $publishingPath 'publication.json'
Write-NewDurableUtf8 $stageReceipt ($publication | ConvertTo-Json -Depth 15)
Set-AstroFileReadOnlyLongPath -LiteralPath $stageReceipt -ReadOnly $true

[AstroLauncherLockNative]::MoveFileWriteThroughNoReplace(
    $publishingPath,
    $generationPath
)

if (Test-AstroPathLongPath -LiteralPath $publishingPath) {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_STAGE_REMAINS' `
        "publication stage still exists after MoveFileExW: $publishingPath" `
        'preserve both paths and inspect the exact namespace state'
}
Assert-OrdinaryEntry $generationPath 'published global generation'
Assert-OrdinaryEntry $finalArtifact 'published global artifact'
Assert-OrdinaryEntry $finalReceipt 'published global receipt'

$persistedReceipt = Read-AstroUtf8FileLongPath $finalReceipt | ConvertFrom-Json
$finalHash = File-Sha256 $finalArtifact
$finalLength = [uint64](Get-AstroFileLengthLongPath $finalArtifact)
$finalIdentity = File-Identity $finalArtifact
$finalReceiptHash = File-Sha256 $finalReceipt
$finalArtifactInfo = Get-AstroFileInfoLongPath $finalArtifact
$finalReceiptInfo = Get-AstroFileInfoLongPath $finalReceipt
if ([string]$persistedReceipt.schema -cne 'astrolabe.global-mcp-publication.v1' -or
    [string]$persistedReceipt.tree_sha -cne $ExpectedTreeSha -or
    [string]$persistedReceipt.artifact.installed_path -cne $finalArtifact -or
    [string]$persistedReceipt.client_configuration.command -cne
        $finalArtifact -or
    [string]$persistedReceipt.client_configuration.server_name -cne
        'astrolabe' -or
    [bool]$persistedReceipt.client_configuration.codex.required -ne $true -or
    [string]$persistedReceipt.artifact.sha256 -cne $finalHash -or
    [uint64]$persistedReceipt.artifact.bytes -ne $finalLength -or
    -not $finalArtifactInfo.IsReadOnly -or
    -not $finalReceiptInfo.IsReadOnly -or
    $finalHash -cne $artifactHashBefore -or
    $finalLength -ne $artifactLength) {
    Fail-AstroGlobalPublish 'ASTRO_GLOBAL_PUBLISH_READBACK_MISMATCH' `
        "published generation readback differs from authority: $generationPath" `
        'preserve the immutable generation and investigate the exact receipt/artifact mismatch'
}

[ordered]@{
    code = 'ASTRO_GLOBAL_MCP_PUBLISHED'
    issue = $Issue
    tree_sha = $ExpectedTreeSha
    generation_path = $generationPath
    artifact = [ordered]@{
        path = $finalArtifact
        bytes = $finalLength
        sha256 = $finalHash
        file_id = $finalIdentity
        read_only = $finalArtifactInfo.IsReadOnly
    }
    receipt = [ordered]@{
        path = $finalReceipt
        bytes = [uint64](Get-AstroFileLengthLongPath $finalReceipt)
        sha256 = $finalReceiptHash
        read_only = $finalReceiptInfo.IsReadOnly
    }
    source_stage_absent = -not (Test-AstroPathLongPath -LiteralPath $publishingPath)
} | ConvertTo-Json -Depth 10 -Compress | Write-Output
