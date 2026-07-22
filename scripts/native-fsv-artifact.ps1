<#
.SYNOPSIS
    Content-addressed promotion and lifecycle management for native FSV artifacts (#596).

.DESCRIPTION
    Cargo's target directory is disposable launcher-owned build state. A native artifact that
    will be exercised after it is built must therefore be promoted, byte-for-byte, into a fresh
    workspace-local evidence directory before target cleanup. Promotion is fail-closed:

      * the source must live below an owned Cargo target root;
      * the source bytes are hashed before and after copying;
      * the staged bytes are flushed to disk and independently re-hashed;
      * a provenance receipt binds issue, tree SHA, source, staged path, length, and SHA-256;
      * the complete staging directory is published with one same-volume, write-through,
        no-clobber rename;
      * reuse, drift, path escape, and partial publication are structured failures.

    The companion native-fsv-run.ps1 holds a Windows handle that denies delete/rename while
    the artifact is executing. Cleanup refuses any live FSV lock or live recorded child.

.NOTES
    Refs #596, #424, #197. Manual FSV tooling; this is not a test or a gate.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Stage', 'Inspect', 'Cleanup', 'Abandon', 'Quarantine')]
    [string]$Operation,

    [string]$SourcePath = '',
    [string]$ReceiptPath = '',
    [string]$RunRecordPath = '',
    [int]$Issue = 0,
    [string]$TreeSha = '',
    [string]$SessionId = '',
    [string]$AbandonRecordPath = '',
    [string]$RecoveryRecordPath = '',
    [string]$LiveStatePath = '',
    [string]$ReasonCode = '',
    [string]$ReasonMessage = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

. (Join-Path $PSScriptRoot 'launcher-lock.ps1')

function Fail-Astro {
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
    return ([IO.Path]::GetFullPath($Path).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar)
}

function Assert-PathWithin {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )
    $full = [IO.Path]::GetFullPath($Path)
    $rootPrefix = Path-WithTrailingSeparator $Root
    if (-not $full.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Fail-Astro $Code "$Description '$full' escapes required root '$($rootPrefix.TrimEnd('\'))'" `
            "use a fresh path below the required workspace-local root"
    }
    return $full
}

function Assert-NotReparseEntry {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Astro 'ASTRO_FSV_REPARSE_ENTRY_REFUSED' "$Description is a reparse point: $Path" `
            'use ordinary workspace-local files and directories; evidence paths may not redirect elsewhere'
    }
}

function File-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($stream)) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

function String-Sha256 {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))) -replace '-', '').ToLowerInvariant()
    }
    finally { $hasher.Dispose() }
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

function Get-RepoState {
    param(
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)][string]$Workspace
    )
    $head = (& $GitExe -C $Workspace rev-parse HEAD).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
        Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' 'git rev-parse HEAD failed during artifact promotion' `
            'repair repository state before staging evidence'
    }
    $status = (& $GitExe -C $Workspace status --porcelain) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' 'git status --porcelain failed during artifact promotion' `
            'repair repository state before staging evidence'
    }
    $diff = (& $GitExe -C $Workspace diff --binary HEAD) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' 'git diff --binary HEAD failed during artifact promotion' `
            'repair repository state before staging evidence'
    }
    return [ordered]@{
        head_sha = $head
        status_sha256 = String-Sha256 $status
        diff_sha256 = String-Sha256 $diff
    }
}

function Write-NewDurableUtf8 {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )
    $encoding = [Text.UTF8Encoding]::new($false)
    $bytes = $encoding.GetBytes($Content)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Copy-FileDurable {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )
    $input = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $input.CopyTo($output)
        $output.Flush($true)
    }
    finally {
        $output.Dispose()
        $input.Dispose()
    }
}

if (-not ([Management.Automation.PSTypeName]'AstroFsvPublish').Type) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class AstroFsvPublish {
    const uint MOVEFILE_WRITE_THROUGH = 0x00000008;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool MoveFileExW(string existingName, string newName, uint flags);

    public static void PublishDirectory(string source, string destination) {
        if (!MoveFileExW(source, destination, MOVEFILE_WRITE_THROUGH))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "write-through no-clobber evidence-directory publication failed");
    }
}
'@
}

function Read-Receipt {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$EvidenceRoot
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_REQUIRED' 'ReceiptPath is required for this operation' `
            'pass the receipt.json path emitted by the Stage operation'
    }
    $full = Assert-PathWithin $Path $EvidenceRoot 'ASTRO_FSV_RECEIPT_ESCAPE' 'receipt path'
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_MISSING' "evidence receipt does not exist: $full" `
            'stage the native artifact first and pass its exact persisted receipt path'
    }
    try { $receipt = Get-Content -LiteralPath $full -Raw | ConvertFrom-Json }
    catch {
        Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' "parse evidence receipt '$full' failed: $($_.Exception.Message)" `
            'discard the incomplete evidence session and stage the artifact again'
    }
    if ($receipt.schema -ne 'astrolabe.native-fsv-artifact.v1' -or
        -not $receipt.artifact -or -not $receipt.artifact.path -or
        [string]::IsNullOrWhiteSpace([string]$receipt.artifact.sha256)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' "evidence receipt '$full' violates the required schema" `
            'discard the invalid session and stage the artifact again'
    }
    return [pscustomobject]@{ Path = $full; Receipt = $receipt }
}

function Inspect-ReceiptArtifact {
    param(
        [Parameter(Mandatory)]$ReceiptState,
        [Parameter(Mandatory)][string]$EvidenceRoot
    )
    $receipt = $ReceiptState.Receipt
    $sessionDirectory = [IO.Path]::GetFullPath((Split-Path -Parent $ReceiptState.Path))
    Assert-NotReparseEntry $ReceiptState.Path 'evidence receipt'
    Assert-NotReparseEntry $sessionDirectory 'evidence session directory'
    if ([string]$receipt.tree_sha -notmatch '^[0-9a-f]{40}$' -or
        [string]$receipt.artifact.sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$receipt.session_id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$' -or
        [int]$receipt.issue -le 0) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' "evidence receipt '$($ReceiptState.Path)' contains invalid identity fields" `
            'discard the invalid session and stage the artifact again'
    }
    $expectedSession = Join-Path (Join-Path (Join-Path $EvidenceRoot ([string]$receipt.tree_sha)) `
        ([string]$receipt.artifact.sha256)) ([string]$receipt.session_id)
    if (-not [string]::Equals($sessionDirectory, [IO.Path]::GetFullPath($expectedSession), [StringComparison]::OrdinalIgnoreCase)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_PATH_MISMATCH' `
            "receipt path '$sessionDirectory' does not match its tree/hash/session identity '$expectedSession'" `
            'discard the cross-session or relocated receipt and stage a fresh artifact'
    }
    $artifact = Assert-PathWithin ([string]$receipt.artifact.path) $sessionDirectory `
        'ASTRO_FSV_ARTIFACT_ESCAPE' 'staged artifact path'
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_ARTIFACT_MISSING' "staged native artifact is absent: $artifact" `
            'treat this evidence session as invalid and stage a fresh artifact'
    }
    Assert-NotReparseEntry $artifact 'staged native artifact'
    $item = Get-Item -LiteralPath $artifact
    $hash = File-Sha256 $artifact
    if ([uint64]$item.Length -ne [uint64]$receipt.artifact.bytes -or
        $hash -cne ([string]$receipt.artifact.sha256).ToLowerInvariant()) {
        Fail-Astro 'ASTRO_FSV_ARTIFACT_DRIFT' `
            "staged artifact bytes drifted: expected bytes=$($receipt.artifact.bytes) sha256=$($receipt.artifact.sha256), observed bytes=$($item.Length) sha256=$hash" `
            'discard the evidence session, identify the writer, and rebuild from a frozen tree'
    }
    return [ordered]@{
        receipt_path = $ReceiptState.Path
        session_directory = $sessionDirectory
        artifact_path = $artifact
        bytes = [uint64]$item.Length
        sha256 = $hash
        read_only = [bool]($item.Attributes -band [IO.FileAttributes]::ReadOnly)
        tree_sha = [string]$receipt.tree_sha
        issue = [int]$receipt.issue
        session_id = [string]$receipt.session_id
    }
}

function Assert-FsvLockAbsent {
    param([Parameter(Mandatory)][string]$LockPath)
    if (-not (Test-Path -LiteralPath $LockPath)) { return }
    $rawLock = Get-Content -LiteralPath $LockPath -Raw -ErrorAction SilentlyContinue
    $lockState = $null
    try { $lockState = $rawLock | ConvertFrom-Json } catch { }
    $ownerPid = 0
    $ownerPids = New-Object System.Collections.Generic.List[int]
    if ($null -ne $lockState -and $lockState.PSObject.Properties['pid'] -and
        [int]::TryParse([string]$lockState.pid, [ref]$ownerPid) -and $ownerPid -gt 0) {
        $ownerPids.Add($ownerPid)
    }
    if ($null -ne $lockState -and $lockState.PSObject.Properties['owner_pids']) {
        foreach ($candidate in @($lockState.owner_pids)) {
            $parsed = 0
            if ([int]::TryParse([string]$candidate, [ref]$parsed) -and $parsed -gt 0 -and -not $ownerPids.Contains($parsed)) {
                $ownerPids.Add($parsed)
            }
        }
    }
    if ($null -ne $lockState -and $lockState.PSObject.Properties['child_pid']) {
        $parsedChild = 0
        if ([int]::TryParse([string]$lockState.child_pid, [ref]$parsedChild) -and $parsedChild -gt 0 -and -not $ownerPids.Contains($parsedChild)) {
            $ownerPids.Add($parsedChild)
        }
    }
    $liveOwnerPids = @($ownerPids | Where-Object { $null -ne (Get-Process -Id $_ -ErrorAction SilentlyContinue) })
    $code = if ($liveOwnerPids.Count -gt 0) { 'ASTRO_FSV_CLEANUP_LIVE_LOCK' } else { 'ASTRO_FSV_CLEANUP_STALE_LOCK' }
    Fail-Astro $code "FSV lock exists at $LockPath (owner_pids=$($ownerPids -join ',') live_pids=$($liveOwnerPids -join ',')); lifecycle mutation refused" `
        'never remove a live lock; for a stale lock, post exact PID-probe evidence to the driving issue before removing it'
}

function Read-PositivePid {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Field,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )
    if (-not $Object.PSObject.Properties[$Field]) {
        Fail-Astro $Code "$Description has no required $Field" 'preserve the session and investigate its incomplete process provenance'
    }
    $parsedPid = 0
    if (-not [int]::TryParse([string]$Object.$Field, [ref]$parsedPid) -or $parsedPid -le 0) {
        Fail-Astro $Code "$Description $Field is not a positive PID" 'preserve the session and investigate its incomplete process provenance'
    }
    return $parsedPid
}

function Get-SessionFileInventory {
    param([Parameter(Mandatory)][string]$Session)
    $inventory = @()
    foreach ($entry in @(Get-ChildItem -LiteralPath $Session -Force | Sort-Object Name)) {
        Assert-NotReparseEntry $entry.FullName "evidence session entry '$($entry.Name)'"
        if (-not $entry.PSIsContainer -and -not (Test-Path -LiteralPath $entry.FullName -PathType Leaf)) {
            Fail-Astro 'ASTRO_FSV_QUARANTINE_ENTRY_INVALID' "evidence session entry is not an ordinary file: $($entry.FullName)" 'preserve the session and investigate its filesystem identity'
        }
        if ($entry.PSIsContainer) {
            Fail-Astro 'ASTRO_FSV_QUARANTINE_DIRECTORY_REFUSED' "evidence session contains a nested directory: $($entry.FullName)" 'preserve the session; recovery inventory accepts only ordinary files in the exact session root'
        }
        $inventory += [ordered]@{
            name = $entry.Name
            path = [IO.Path]::GetFullPath($entry.FullName)
            bytes = [uint64]$entry.Length
            sha256 = File-Sha256 $entry.FullName
            attributes = $entry.Attributes.ToString()
            read_only = [bool]($entry.Attributes -band [IO.FileAttributes]::ReadOnly)
        }
    }
    return $inventory
}

$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$evidenceRoot = Join-Path $workspace '.tmp\native-fsv-artifacts'
$abandonRoot = Join-Path $workspace '.tmp\native-fsv-abandon-records'
$recoveryRoot = Join-Path $workspace '.tmp\native-fsv-recovery-records'
$fsvLock = Join-Path (Join-Path $workspace '.tmp') 'astrolabe-fsv.lock'
$launcherLockPath = Join-Path (Join-Path $workspace '.tmp') 'astrolabe-launcher.lock'
$gitExe = 'C:\Program Files\Git\bin\git.exe'

try {
    switch ($Operation) {
        'Stage' {
            if ($Issue -le 0) {
                Fail-Astro 'ASTRO_FSV_ISSUE_INVALID' "Issue must be a positive integer; received $Issue" `
                    'pass the driving GitHub issue number'
            }
            if ($TreeSha -notmatch '^[0-9a-fA-F]{40}$') {
                Fail-Astro 'ASTRO_FSV_TREE_SHA_INVALID' "TreeSha is not a full Git object id: '$TreeSha'" `
                    'pass the exact full commit SHA reported by git rev-parse HEAD'
            }
            $TreeSha = $TreeSha.ToLowerInvariant()
            if ($SessionId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') {
                Fail-Astro 'ASTRO_FSV_SESSION_ID_INVALID' "SessionId contains unsupported characters or length: '$SessionId'" `
                    'use 1-96 ASCII letters, digits, dot, underscore, or hyphen, beginning with a letter or digit'
            }
            if ([string]::IsNullOrWhiteSpace($SourcePath)) {
                Fail-Astro 'ASTRO_FSV_SOURCE_REQUIRED' 'SourcePath is required for Stage' `
                    'pass the exact native artifact emitted below the launcher-owned target root'
            }
            $source = [IO.Path]::GetFullPath($SourcePath)
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_SOURCE_MISSING' "native build artifact does not exist: $source" `
                    'build the real native artifact successfully before staging it'
            }
            Assert-NotReparseEntry $source 'native build artifact'
            $source = (Resolve-Path -LiteralPath $source -ErrorAction Stop).Path
            $ownedTargets = @(
                (Join-Path $workspace 'target'),
                (Join-Path $workspace 'calyx\target')
            )
            $sourceOwned = $false
            foreach ($owned in $ownedTargets) {
                $prefix = Path-WithTrailingSeparator $owned
                if ($source.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                    $sourceOwned = $true
                    break
                }
            }
            if (-not $sourceOwned) {
                Fail-Astro 'ASTRO_FSV_SOURCE_OUTSIDE_TARGET' `
                    "native artifact '$source' is outside the launcher-owned Cargo target roots" `
                    'stage only a real artifact emitted under workspace target/ by the native launcher'
            }
            if (-not (Test-Path -LiteralPath $gitExe -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_GIT_MISSING' "required native Git executable is absent: $gitExe" `
                    'restore the canonical Git for Windows installation before staging evidence'
            }
            $launcherOwner = Read-AstroLauncherLock -LockPath $launcherLockPath
            $launcherPid = if ($null -ne $launcherOwner.OwnerPid) {
                [int]$launcherOwner.OwnerPid
            } else {
                0
            }
            if ($launcherOwner.State -ne 'held' -or
                $launcherOwner.Issue -ne $Issue -or
                [string]$launcherOwner.HeadSha -cne $TreeSha) {
                Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_INVALID' `
                    "launcher protocol does not name the exact live issue #$Issue process identity for tree $TreeSha (state=$($launcherOwner.State), pid=$launcherPid, process_start_utc_ticks=$($launcherOwner.OwnerProcessStartUtcTicks), read_error=$($launcherOwner.ReadError), validation_error=$($launcherOwner.ValidationError))" `
                    'start artifact promotion through the native launcher with the same issue and tree'
            }
            if (-not (Test-DescendantOf -CandidatePid $PID -AncestorPid $launcherPid)) {
                Fail-Astro 'ASTRO_FSV_PROMOTER_NOT_OWNED' "promoter PID $PID is not a descendant of launcher PID $launcherPid" `
                    'invoke Stage synchronously from the launcher-owned child process'
            }
            $repoState = Get-RepoState -GitExe $gitExe -Workspace $workspace
            if ($repoState.head_sha -cne $TreeSha) {
                Fail-Astro 'ASTRO_FSV_TREE_MISMATCH' "current HEAD '$($repoState.head_sha)' does not match requested evidence tree '$TreeSha'" `
                    'freeze the checkout, rebuild, and stage with the exact current full commit SHA'
            }
            $tracked = (& $gitExe -C $workspace status --porcelain --untracked-files=no) -join "`n"
            if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace($tracked)) {
                Fail-Astro 'ASTRO_FSV_TREE_DIRTY' "tracked checkout is not clean at artifact promotion: $tracked" `
                    'commit the implementation and rebuild from a clean frozen tree'
            }
            if ([string]$launcherOwner.StatusSha256 -cne [string]$repoState.status_sha256 -or
                [string]$launcherOwner.DiffSha256 -cne [string]$repoState.diff_sha256) {
                Fail-Astro 'ASTRO_FSV_LAUNCHER_TREE_DRIFT' `
                    'repository status/diff fingerprints differ from the launcher acquisition state' `
                    'discard this build, restore the frozen checkout, and rebuild from a fresh launcher lease'
            }

            $sourceHashBefore = File-Sha256 $source
            $sourceItem = Get-Item -LiteralPath $source
            $hashParent = Join-Path (Join-Path $evidenceRoot $TreeSha) $sourceHashBefore
            $finalDirectory = Join-Path $hashParent $SessionId
            if (Test-Path -LiteralPath $finalDirectory) {
                Fail-Astro 'ASTRO_FSV_STAGE_REUSE_REFUSED' "evidence session already exists: $finalDirectory" `
                    'use a fresh SessionId; evidence sessions are immutable and never overwritten'
            }
            Assert-NotReparseEntry (Join-Path $workspace '.tmp') 'workspace temporary directory'
            Assert-NotReparseEntry $evidenceRoot 'evidence root'
            Assert-NotReparseEntry (Join-Path $evidenceRoot $TreeSha) 'evidence tree directory'
            Assert-NotReparseEntry $hashParent 'evidence hash directory'
            New-Item -ItemType Directory -Path $hashParent -Force | Out-Null
            Assert-NotReparseEntry $hashParent 'evidence hash directory'
            $publishingDirectory = Join-Path $hashParent (".$SessionId.publishing-$PID-" + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $publishingDirectory -ErrorAction Stop | Out-Null
            $published = $false
            try {
                $artifactName = [IO.Path]::GetFileName($source)
                $staged = Join-Path $publishingDirectory $artifactName
                Copy-FileDurable $source $staged
                $sourceHashAfter = File-Sha256 $source
                $stagedHash = File-Sha256 $staged
                $stagedItem = Get-Item -LiteralPath $staged
                if ($sourceHashBefore -cne $sourceHashAfter -or $sourceHashBefore -cne $stagedHash -or
                    [uint64]$sourceItem.Length -ne [uint64]$stagedItem.Length) {
                    Fail-Astro 'ASTRO_FSV_STAGE_COPY_MISMATCH' `
                        "source/staged bytes changed during promotion: source_before=$sourceHashBefore source_after=$sourceHashAfter staged=$stagedHash" `
                        'discard the partial publication, stop the writer, and rebuild from a frozen tree'
                }
                $stagedItem.IsReadOnly = $true
                $finalArtifact = Join-Path $finalDirectory $artifactName
                $receipt = [ordered]@{
                    schema = 'astrolabe.native-fsv-artifact.v1'
                    issue = $Issue
                    session_id = $SessionId
                    tree_sha = $TreeSha
                    promoted_at_utc = [DateTime]::UtcNow.ToString('o')
                    promoter_pid = $PID
                    launcher_pid = $launcherPid
                    repository = $repoState
                    source = [ordered]@{ path = $source; bytes = [uint64]$sourceItem.Length; sha256 = $sourceHashBefore }
                    artifact = [ordered]@{ path = $finalArtifact; bytes = [uint64]$stagedItem.Length; sha256 = $stagedHash; read_only = $true }
                    publication = [ordered]@{ method = 'MoveFileExW(MOVEFILE_WRITE_THROUGH,no-replace)'; same_volume = $true }
                }
                $receiptJson = $receipt | ConvertTo-Json -Depth 12
                Write-NewDurableUtf8 (Join-Path $publishingDirectory 'receipt.json') $receiptJson
                [AstroFsvPublish]::PublishDirectory($publishingDirectory, $finalDirectory)
                $published = $true
                Assert-NotReparseEntry $finalDirectory 'published evidence session directory'
            }
            finally {
                if (-not $published -and (Test-Path -LiteralPath $publishingDirectory)) {
                    Remove-Item -LiteralPath $publishingDirectory -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            $receiptState = Read-Receipt (Join-Path $finalDirectory 'receipt.json') $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            [ordered]@{ operation = 'stage'; receipt = $receiptState.Receipt; readback = $inspection } |
                ConvertTo-Json -Depth 15 -Compress | Write-Output
        }
        'Inspect' {
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            [ordered]@{ operation = 'inspect'; readback = $inspection } |
                ConvertTo-Json -Depth 12 -Compress | Write-Output
        }
        'Abandon' {
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            Assert-FsvLockAbsent $fsvLock
            $launcherProtocolState = Read-AstroLauncherLock -LockPath $launcherLockPath
            if ($launcherProtocolState.State -ne 'absent') {
                Fail-Astro 'ASTRO_FSV_ABANDON_LAUNCHER_LOCK' `
                    "launcher protocol state is '$($launcherProtocolState.State)' at $launcherLockPath; never-run session abandonment requires authoritative absence (transitions=$(@($launcherProtocolState.TransitionPaths) -join '; '), read_error=$($launcherProtocolState.ReadError), validation_error=$($launcherProtocolState.ValidationError))" `
                    'wait for a live owner to finish, or use the tracker-bound explicit reclaim command for stale/unreadable/transition state; then independently prove every receipt owner dead'
            }
            if ($ReasonCode -notmatch '^[A-Z][A-Z0-9_]{2,95}$') {
                Fail-Astro 'ASTRO_FSV_ABANDON_REASON_INVALID' "ReasonCode is not a structured upper-case code: '$ReasonCode'" `
                    'pass a stable code such as ASTRO_FSV_ORCHESTRATION_FAILED'
            }
            if ([string]::IsNullOrWhiteSpace($ReasonMessage)) {
                Fail-Astro 'ASTRO_FSV_ABANDON_REASON_INVALID' 'ReasonMessage is required and may not be blank' `
                    'describe the exact pre-run failure whose persisted evidence authorizes abandonment'
            }
            if ([string]::IsNullOrWhiteSpace($AbandonRecordPath)) {
                Fail-Astro 'ASTRO_FSV_ABANDON_RECORD_REQUIRED' 'AbandonRecordPath is required for Abandon' `
                    "use a fresh JSON path below $abandonRoot; the record persists after session removal"
            }
            $abandonRecord = Assert-PathWithin $AbandonRecordPath $abandonRoot `
                'ASTRO_FSV_ABANDON_RECORD_ESCAPE' 'abandonment record path'
            if (Test-Path -LiteralPath $abandonRecord) {
                Fail-Astro 'ASTRO_FSV_ABANDON_RECORD_REUSE_REFUSED' "abandonment record already exists: $abandonRecord" `
                    'use one fresh append-only record path for each never-run evidence session'
            }
            $receipt = $receiptState.Receipt
            $ownerPids = New-Object System.Collections.Generic.List[int]
            foreach ($field in @('launcher_pid', 'promoter_pid')) {
                if (-not $receipt.PSObject.Properties[$field]) {
                    Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' "receipt has no $field required for abandonment" `
                        'preserve the session and investigate its incomplete provenance'
                }
                $parsedPid = 0
                if (-not [int]::TryParse([string]$receipt.$field, [ref]$parsedPid) -or $parsedPid -le 0) {
                    Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' "receipt $field is not a positive PID" `
                        'preserve the session and investigate its incomplete provenance'
                }
                if (-not $ownerPids.Contains($parsedPid)) { $ownerPids.Add($parsedPid) }
            }
            $liveOwnerPids = @($ownerPids | Where-Object { $null -ne (Get-Process -Id $_ -ErrorAction SilentlyContinue) })
            if ($liveOwnerPids.Count -gt 0) {
                Fail-Astro 'ASTRO_FSV_ABANDON_LIVE_OWNER' `
                    "never-run session still names live receipt owner PID(s): $($liveOwnerPids -join ',')" `
                    'wait for every exact receipt owner to exit naturally; never abandon a live session'
            }
            $session = [IO.Path]::GetFullPath($inspection.session_directory)
            $allowedEntries = @(
                [IO.Path]::GetFullPath($receiptState.Path),
                [IO.Path]::GetFullPath($inspection.artifact_path)
            )
            $unexpectedEntries = @(
                Get-ChildItem -LiteralPath $session -Force |
                    Where-Object {
                        $full = [IO.Path]::GetFullPath($_.FullName)
                        -not ($allowedEntries -contains $full)
                    } |
                    ForEach-Object { $_.FullName }
            )
            if ($unexpectedEntries.Count -gt 0 -or @(Get-ChildItem -LiteralPath $session -Force).Count -ne 2) {
                Fail-Astro 'ASTRO_FSV_ABANDON_NONPRISTINE' `
                    "session contains state beyond its never-run artifact and receipt: $($unexpectedEntries -join ', ')" `
                    'preserve the session; inspect the partial/live run state and use Cleanup only with a valid bound run record'
            }
            Assert-NotReparseEntry $abandonRoot 'abandonment record root'
            $recordParent = Split-Path -Parent $abandonRecord
            Assert-NotReparseEntry $recordParent 'abandonment record parent'
            New-Item -ItemType Directory -Path $recordParent -Force | Out-Null
            Assert-NotReparseEntry $recordParent 'abandonment record parent'
            $currentRepository = Get-RepoState -GitExe $gitExe -Workspace $workspace
            $record = [ordered]@{
                schema = 'astrolabe.native-fsv-abandon.v1'
                verdict = 'abandoned-before-run'
                issue = [int]$inspection.issue
                recorded_at_utc = [DateTime]::UtcNow.ToString('o')
                receipt_path = $receiptState.Path
                session_directory = $session
                artifact = [ordered]@{
                    path = $inspection.artifact_path
                    bytes = [uint64]$inspection.bytes
                    sha256 = $inspection.sha256
                }
                staged_repository = $receipt.repository
                current_repository = $currentRepository
                receipt_owner_pids = @($ownerPids | ForEach-Object { [int]$_ })
                owner_pids_live = @()
                failure = [ordered]@{
                    code = $ReasonCode
                    message = $ReasonMessage
                }
            }
            Write-NewDurableUtf8 $abandonRecord ($record | ConvertTo-Json -Depth 15)
            $persistedRecord = Get-Content -LiteralPath $abandonRecord -Raw | ConvertFrom-Json
            if ($persistedRecord.schema -ne 'astrolabe.native-fsv-abandon.v1' -or
                [string]$persistedRecord.artifact.sha256 -cne [string]$inspection.sha256 -or
                [string]$persistedRecord.failure.code -cne $ReasonCode) {
                Fail-Astro 'ASTRO_FSV_ABANDON_RECORD_INVALID' `
                    "persisted abandonment record readback does not bind the session: $abandonRecord" `
                    'preserve both session and record and investigate the durable-write mismatch'
            }
            $recordHash = File-Sha256 $abandonRecord
            $before = [ordered]@{
                session = $session
                exists = $true
                artifact_sha256 = $inspection.sha256
                receipt_owner_pids = @($ownerPids | ForEach-Object { [int]$_ })
                owner_pids_live = @()
            }
            $artifactItem = Get-Item -LiteralPath $inspection.artifact_path
            $artifactItem.IsReadOnly = $false
            Remove-Item -LiteralPath $session -Recurse -Force
            if (Test-Path -LiteralPath $session) {
                Fail-Astro 'ASTRO_FSV_ABANDON_FAILED' "evidence session remains after abandonment: $session" `
                    'preserve the external abandonment record and inspect open handles before retrying exact cleanup'
            }
            foreach ($parent in @((Split-Path -Parent $session), (Split-Path -Parent (Split-Path -Parent $session)))) {
                if ((Test-Path -LiteralPath $parent -PathType Container) -and
                    @(Get-ChildItem -LiteralPath $parent -Force).Count -eq 0) {
                    Remove-Item -LiteralPath $parent -Force
                }
            }
            [ordered]@{
                operation = 'abandon'
                record_path = $abandonRecord
                record_sha256 = $recordHash
                record = $persistedRecord
                before = $before
                after = [ordered]@{ session = $session; exists = $false }
            } | ConvertTo-Json -Depth 18 -Compress | Write-Output
        }
        'Quarantine' {
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            Assert-FsvLockAbsent $fsvLock
            $launcherProtocolState = Read-AstroLauncherLock -LockPath $launcherLockPath
            if ($launcherProtocolState.State -ne 'absent') {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_LAUNCHER_LOCK' `
                    "launcher protocol state is '$($launcherProtocolState.State)' at $launcherLockPath; terminal-session quarantine requires authoritative absence (transitions=$(@($launcherProtocolState.TransitionPaths) -join '; '), read_error=$($launcherProtocolState.ReadError), validation_error=$($launcherProtocolState.ValidationError))" `
                    'wait for a live owner to finish, or archive stale/unreadable/transition state through scripts\reclaim-launcher-lock.ps1 with exact tracker evidence before quarantine'
            }
            if ($ReasonCode -notmatch '^[A-Z][A-Z0-9_]{2,95}$') {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_REASON_INVALID' "ReasonCode is not a structured upper-case code: '$ReasonCode'" `
                    'pass the exact stable failure code that left the terminal partial session'
            }
            if ([string]::IsNullOrWhiteSpace($ReasonMessage)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_REASON_INVALID' 'ReasonMessage is required and may not be blank' `
                    'describe the exact terminal runner failure that prevented a valid run record'
            }
            if ([string]::IsNullOrWhiteSpace($RecoveryRecordPath)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_RECORD_REQUIRED' 'RecoveryRecordPath is required for Quarantine' `
                    "use a fresh JSON path below $recoveryRoot; the record persists after exact session removal"
            }
            $recoveryRecord = Assert-PathWithin $RecoveryRecordPath $recoveryRoot `
                'ASTRO_FSV_QUARANTINE_RECORD_ESCAPE' 'recovery record path'
            if (Test-Path -LiteralPath $recoveryRecord) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_RECORD_REUSE_REFUSED' "recovery record already exists: $recoveryRecord" `
                    'use one fresh append-only recovery record path for each terminal partial session'
            }
            if ([string]::IsNullOrWhiteSpace($LiveStatePath)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_LIVE_STATE_REQUIRED' 'LiveStatePath is required for Quarantine' `
                    'pass the exact live-state JSON published by native-fsv-run.ps1 for this session'
            }
            $liveStateFile = Assert-PathWithin $LiveStatePath $inspection.session_directory `
                'ASTRO_FSV_QUARANTINE_LIVE_STATE_ESCAPE' 'live-state path'
            if (-not (Test-Path -LiteralPath $liveStateFile -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_LIVE_STATE_MISSING' "live-state file does not exist: $liveStateFile" `
                    'pristine never-run sessions use Abandon; preserve any unexplained nonpristine session'
            }
            Assert-NotReparseEntry $liveStateFile 'native FSV live-state file'
            try { $liveState = Get-Content -LiteralPath $liveStateFile -Raw | ConvertFrom-Json }
            catch {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_LIVE_STATE_INVALID' "parse live-state '$liveStateFile' failed: $($_.Exception.Message)" `
                    'preserve the session and investigate its incomplete process provenance'
            }
            if ($liveState.schema -ne 'astrolabe.native-fsv-live.v1' -or
                [int]$liveState.issue -ne [int]$inspection.issue -or
                [string]$liveState.tree_sha -cne [string]$inspection.tree_sha -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$liveState.artifact.path), $inspection.artifact_path, [StringComparison]::OrdinalIgnoreCase) -or
                [uint64]$liveState.artifact.bytes -ne [uint64]$inspection.bytes -or
                [string]$liveState.artifact.sha256 -cne [string]$inspection.sha256) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_LIVE_STATE_INVALID' `
                    "live-state '$liveStateFile' is not bound to the staged issue/tree/artifact" `
                    'preserve the session and investigate the cross-session or incomplete provenance'
            }
            $receipt = $receiptState.Receipt
            $ownerPids = New-Object System.Collections.Generic.List[int]
            foreach ($owner in @(
                [ordered]@{ object = $receipt; field = 'launcher_pid'; description = 'artifact receipt' },
                [ordered]@{ object = $receipt; field = 'promoter_pid'; description = 'artifact receipt' },
                [ordered]@{ object = $liveState; field = 'launcher_pid'; description = 'runner live state' },
                [ordered]@{ object = $liveState; field = 'runner_pid'; description = 'runner live state' },
                [ordered]@{ object = $liveState; field = 'child_pid'; description = 'runner live state' }
            )) {
                $ownerPid = Read-PositivePid $owner.object $owner.field `
                    'ASTRO_FSV_QUARANTINE_OWNER_INVALID' $owner.description
                if (-not $ownerPids.Contains($ownerPid)) { $ownerPids.Add($ownerPid) }
            }
            if ([int]$receipt.launcher_pid -ne [int]$liveState.launcher_pid) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_OWNER_MISMATCH' `
                    "receipt launcher PID $($receipt.launcher_pid) differs from runner live-state launcher PID $($liveState.launcher_pid)" `
                    'preserve the session and investigate the cross-lease provenance'
            }
            $liveOwnerPids = @($ownerPids | Where-Object { $null -ne (Get-Process -Id $_ -ErrorAction SilentlyContinue) })
            if ($liveOwnerPids.Count -gt 0) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_LIVE_OWNER' `
                    "terminal partial session still names live owner PID(s): $($liveOwnerPids -join ',')" `
                    'wait for every exact owner to exit naturally; never quarantine a live session'
            }
            if ([string]::IsNullOrWhiteSpace($RunRecordPath)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_RUN_RECORD_PATH_REQUIRED' 'RunRecordPath is required for Quarantine' `
                    'pass the exact run-record path that the failed runner was required to publish'
            }
            $expectedRunRecord = Assert-PathWithin $RunRecordPath $inspection.session_directory `
                'ASTRO_FSV_QUARANTINE_RUN_RECORD_ESCAPE' 'expected run-record path'
            $runRecordState = 'missing'
            if (Test-Path -LiteralPath $expectedRunRecord -PathType Leaf) {
                Assert-NotReparseEntry $expectedRunRecord 'native FSV run record'
                $runRecordState = 'invalid'
                try {
                    $candidateRecord = Get-Content -LiteralPath $expectedRunRecord -Raw | ConvertFrom-Json
                    if ($candidateRecord.schema -eq 'astrolabe.native-fsv-run.v1' -and
                        [int]$candidateRecord.issue -eq [int]$inspection.issue -and
                        [string]::Equals([IO.Path]::GetFullPath([string]$candidateRecord.receipt_path), $receiptState.Path, [StringComparison]::OrdinalIgnoreCase) -and
                        [string]::Equals([IO.Path]::GetFullPath([string]$candidateRecord.artifact.path), $inspection.artifact_path, [StringComparison]::OrdinalIgnoreCase) -and
                        [string]$candidateRecord.artifact.sha256 -ceq [string]$inspection.sha256) {
                        Fail-Astro 'ASTRO_FSV_QUARANTINE_VALID_RUN_RECORD' `
                            "session has a valid bound run record at $expectedRunRecord" `
                            'use Cleanup for a completed real run; Quarantine is only for terminal partial state'
                    }
                }
                catch {
                    if ($_.Exception.Data.Contains('AstroCode')) { throw }
                }
            }
            $session = [IO.Path]::GetFullPath($inspection.session_directory)
            $inventory = @(Get-SessionFileInventory $session)
            if ($inventory.Count -lt 4) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_NONPARTIAL' `
                    "session inventory has only $($inventory.Count) files; no terminal partial-run state is proven" `
                    'use Abandon only for a pristine two-file never-run session; otherwise preserve and investigate the incomplete state'
            }
            $inventoryPaths = @($inventory | ForEach-Object { [string]$_.path })
            foreach ($requiredPath in @($receiptState.Path, $inspection.artifact_path, $liveStateFile)) {
                if (-not ($inventoryPaths -contains [IO.Path]::GetFullPath($requiredPath))) {
                    Fail-Astro 'ASTRO_FSV_QUARANTINE_INVENTORY_INVALID' `
                        "session inventory omitted required path $requiredPath" `
                        'preserve the session and investigate its filesystem identity'
                }
            }
            $outputInventory = @($inventory | Where-Object {
                [string]$_.path -cne [string]$receiptState.Path -and
                [string]$_.path -cne [string]$inspection.artifact_path -and
                [string]$_.path -cne [string]$liveStateFile -and
                [string]$_.path -cne [string]$expectedRunRecord
            })
            if ($outputInventory.Count -eq 0) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_OUTPUT_EVIDENCE_MISSING' `
                    'terminal partial session contains no child output file beyond receipt/artifact/live state' `
                    'preserve the session; no real child-output state exists to distinguish it from incomplete staging'
            }
            Assert-NotReparseEntry $recoveryRoot 'recovery record root'
            $recordParent = Split-Path -Parent $recoveryRecord
            New-Item -ItemType Directory -Path $recordParent -Force | Out-Null
            Assert-NotReparseEntry $recordParent 'recovery record parent'
            $currentRepository = Get-RepoState -GitExe $gitExe -Workspace $workspace
            $record = [ordered]@{
                schema = 'astrolabe.native-fsv-recovery.v1'
                verdict = 'quarantined-unverified-run'
                issue = [int]$inspection.issue
                recorded_at_utc = [DateTime]::UtcNow.ToString('o')
                receipt_path = $receiptState.Path
                session_directory = $session
                expected_run_record_path = $expectedRunRecord
                expected_run_record_state = $runRecordState
                live_state_path = $liveStateFile
                artifact = [ordered]@{
                    path = $inspection.artifact_path
                    bytes = [uint64]$inspection.bytes
                    sha256 = $inspection.sha256
                }
                staged_repository = $receipt.repository
                current_repository = $currentRepository
                source_of_truth = [ordered]@{
                    fsv_lock = $fsvLock
                    fsv_lock_exists = $false
                    launcher_lock = $launcherLockPath
                    launcher_lock_exists = $false
                    launcher_protocol_state = $launcherProtocolState.State
                    session_files = $inventory
                }
                owner_pids = @($ownerPids | ForEach-Object { [int]$_ })
                owner_pids_live = @()
                failure = [ordered]@{
                    code = $ReasonCode
                    message = $ReasonMessage
                }
            }
            Write-NewDurableUtf8 $recoveryRecord ($record | ConvertTo-Json -Depth 20)
            $persistedRecord = Get-Content -LiteralPath $recoveryRecord -Raw | ConvertFrom-Json
            if ($persistedRecord.schema -ne 'astrolabe.native-fsv-recovery.v1' -or
                $persistedRecord.verdict -ne 'quarantined-unverified-run' -or
                [string]$persistedRecord.artifact.sha256 -cne [string]$inspection.sha256 -or
                [string]$persistedRecord.failure.code -cne $ReasonCode -or
                @($persistedRecord.source_of_truth.session_files).Count -ne $inventory.Count) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_RECORD_INVALID' `
                    "persisted recovery record readback does not bind the terminal session: $recoveryRecord" `
                    'preserve both session and record and investigate the durable-write mismatch'
            }
            $recordHash = File-Sha256 $recoveryRecord
            $before = [ordered]@{
                session = $session
                exists = $true
                artifact_sha256 = $inspection.sha256
                file_count = $inventory.Count
                owner_pids = @($ownerPids | ForEach-Object { [int]$_ })
                owner_pids_live = @()
            }
            foreach ($entry in @(Get-ChildItem -LiteralPath $session -File -Force)) {
                if ($entry.IsReadOnly) { $entry.IsReadOnly = $false }
            }
            Remove-Item -LiteralPath $session -Recurse -Force
            if (Test-Path -LiteralPath $session) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_FAILED' "evidence session remains after quarantine: $session" `
                    'preserve the external recovery record and inspect open handles before retrying exact cleanup'
            }
            foreach ($parent in @((Split-Path -Parent $session), (Split-Path -Parent (Split-Path -Parent $session)))) {
                if ((Test-Path -LiteralPath $parent -PathType Container) -and
                    @(Get-ChildItem -LiteralPath $parent -Force).Count -eq 0) {
                    Remove-Item -LiteralPath $parent -Force
                }
            }
            [ordered]@{
                operation = 'quarantine'
                record_path = $recoveryRecord
                record_sha256 = $recordHash
                record = $persistedRecord
                before = $before
                after = [ordered]@{ session = $session; exists = $false }
            } | ConvertTo-Json -Depth 22 -Compress | Write-Output
        }
        'Cleanup' {
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            Assert-FsvLockAbsent $fsvLock
            if ([string]::IsNullOrWhiteSpace($RunRecordPath)) {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_REQUIRED' 'RunRecordPath is required for Cleanup' `
                    'pass the persisted run record written by native-fsv-run.ps1 after the real process exited'
            }
            $runRecord = Assert-PathWithin $RunRecordPath $inspection.session_directory `
                'ASTRO_FSV_RUN_RECORD_ESCAPE' 'run record path'
            if (-not (Test-Path -LiteralPath $runRecord -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_MISSING' "run record does not exist: $runRecord" `
                    'complete the real staged-artifact run and persist its readback before cleanup'
            }
            try { $record = Get-Content -LiteralPath $runRecord -Raw | ConvertFrom-Json }
            catch {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_INVALID' "parse run record '$runRecord' failed: $($_.Exception.Message)" `
                    'preserve the evidence directory and investigate the incomplete run'
            }
            if ($record.schema -ne 'astrolabe.native-fsv-run.v1' -or
                [int]$record.issue -ne [int]$inspection.issue -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$record.receipt_path), $receiptState.Path, [StringComparison]::OrdinalIgnoreCase) -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$record.artifact.path), $inspection.artifact_path, [StringComparison]::OrdinalIgnoreCase) -or
                [string]$record.artifact.sha256 -cne [string]$inspection.sha256) {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_INVALID' "run record '$runRecord' is not bound to the staged artifact" `
                    'preserve the evidence directory and investigate the provenance mismatch'
            }
            $childPid = 0
            if (-not [int]::TryParse([string]$record.process.pid, [ref]$childPid) -or $childPid -le 0) {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_INVALID' "run record '$runRecord' has no valid child PID" `
                    'preserve the evidence directory and investigate the incomplete run'
            }
            if ($null -ne (Get-Process -Id $childPid -ErrorAction SilentlyContinue)) {
                Fail-Astro 'ASTRO_FSV_CLEANUP_LIVE_PROCESS' "recorded native process PID $childPid is still live" `
                    'wait for the exact recorded process to exit; never clean a live process artifact'
            }
            $session = [IO.Path]::GetFullPath($inspection.session_directory)
            $before = [ordered]@{ session = $session; exists = Test-Path -LiteralPath $session; artifact_sha256 = $inspection.sha256; child_pid = $childPid; child_live = $false }
            $artifactItem = Get-Item -LiteralPath $inspection.artifact_path
            $artifactItem.IsReadOnly = $false
            Remove-Item -LiteralPath $session -Recurse -Force
            if (Test-Path -LiteralPath $session) {
                Fail-Astro 'ASTRO_FSV_CLEANUP_FAILED' "evidence session remains after cleanup: $session" `
                    'inspect open handles and remove the exact session only after every owner PID is dead'
            }
            foreach ($parent in @((Split-Path -Parent $session), (Split-Path -Parent (Split-Path -Parent $session)))) {
                if ((Test-Path -LiteralPath $parent -PathType Container) -and
                    @(Get-ChildItem -LiteralPath $parent -Force).Count -eq 0) {
                    Remove-Item -LiteralPath $parent -Force
                }
            }
            [ordered]@{ operation = 'cleanup'; before = $before; after = [ordered]@{ session = $session; exists = $false } } |
                ConvertTo-Json -Depth 10 -Compress | Write-Output
        }
    }
}
catch {
    $failure = $_
    $code = if ($failure.Exception.Data.Contains('AstroCode')) { [string]$failure.Exception.Data['AstroCode'] } else { 'ASTRO_FSV_ARTIFACT_INTERNAL' }
    $remediation = if ($failure.Exception.Data.Contains('AstroRemediation')) { [string]$failure.Exception.Data['AstroRemediation'] } else { 'preserve the evidence state, inspect the full error, repair the root cause, and retry from a fresh session' }
    [Console]::Error.WriteLine(([ordered]@{
        code = $code
        message = $failure.Exception.Message
        remediation = $remediation
        exception_type = $failure.Exception.GetType().FullName
        script_stack_trace = $failure.ScriptStackTrace
        invocation = $failure.InvocationInfo.PositionMessage
    } | ConvertTo-Json -Compress))
    exit 1
}
