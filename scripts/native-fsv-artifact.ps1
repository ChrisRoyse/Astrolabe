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
    [ValidateSet('Stage', 'Inspect', 'Cleanup')]
    [string]$Operation,

    [string]$SourcePath = '',
    [string]$ReceiptPath = '',
    [string]$RunRecordPath = '',
    [int]$Issue = 0,
    [string]$TreeSha = '',
    [string]$SessionId = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

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
    param([Parameter(Mandatory)][string]$Value)
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

$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$evidenceRoot = Join-Path $workspace '.tmp\native-fsv-artifacts'
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
            if (-not (Test-Path -LiteralPath $launcherLockPath -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_REQUIRED' "live launcher lock is absent: $launcherLockPath" `
                    'invoke Stage synchronously from the issue-owned native launcher process'
            }
            try { $launcherLock = Get-Content -LiteralPath $launcherLockPath -Raw | ConvertFrom-Json }
            catch {
                Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_INVALID' "launcher lock is unreadable: $($_.Exception.Message)" `
                    'preserve state and repair the launcher lock before staging evidence'
            }
            $launcherPid = 0
            if (-not [int]::TryParse([string]$launcherLock.pid, [ref]$launcherPid) -or
                $launcherPid -le 0 -or [int]$launcherLock.issue -ne $Issue -or
                [string]$launcherLock.head_sha -cne $TreeSha -or
                $null -eq (Get-Process -Id $launcherPid -ErrorAction SilentlyContinue)) {
                Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_INVALID' `
                    "launcher lock does not name a live issue #$Issue owner for tree $TreeSha" `
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
            if ([string]$launcherLock.status_sha256 -cne [string]$repoState.status_sha256 -or
                [string]$launcherLock.diff_sha256 -cne [string]$repoState.diff_sha256) {
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
        'Cleanup' {
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            if (Test-Path -LiteralPath $fsvLock) {
                $rawLock = Get-Content -LiteralPath $fsvLock -Raw -ErrorAction SilentlyContinue
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
                Fail-Astro $code "FSV lock exists at $fsvLock (owner_pids=$($ownerPids -join ',') live_pids=$($liveOwnerPids -join ',')); cleanup refused" `
                    'never remove a live lock; for a stale lock, post exact PID-probe evidence to the driving issue before removing it'
            }
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
    $code = if ($_.Exception.Data.Contains('AstroCode')) { [string]$_.Exception.Data['AstroCode'] } else { 'ASTRO_FSV_ARTIFACT_INTERNAL' }
    $remediation = if ($_.Exception.Data.Contains('AstroRemediation')) { [string]$_.Exception.Data['AstroRemediation'] } else { 'preserve the evidence state, inspect the full error, repair the root cause, and retry from a fresh session' }
    [Console]::Error.WriteLine(([ordered]@{ code = $code; message = $_.Exception.Message; remediation = $remediation } | ConvertTo-Json -Compress))
    exit 1
}
