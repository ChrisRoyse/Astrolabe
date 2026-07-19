<#
.SYNOPSIS
    Execute a promoted native FSV artifact under a live launcher lease (#596).

.DESCRIPTION
    Verifies the content-addressed receipt, requires this runner to be a descendant of the
    live launcher-lock owner, acquires a dedicated JSON FSV lock, and opens the artifact with
    FileShare.Read (intentionally omitting FILE_SHARE_WRITE and FILE_SHARE_DELETE). The handle
    remains open for the complete child lifetime, so Windows refuses artifact mutation,
    rename, and directory cleanup while the real process is running.

    Before returning, it independently reads back the artifact hash, output hashes, the
    retained Windows process handle's kernel exit code (cross-checked against Process.ExitCode),
    and Git tree state into a durable run record. No CPU fallback, output substitution, retry,
    or mock behavior exists here.

.NOTES
    Refs #600, #596, #424, #197. Manual FSV tooling; this is not a test or a gate.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ReceiptPath,
    [Parameter(Mandatory)][string]$ArgumentsJson,
    [Parameter(Mandatory)][string]$StandardOutputPath,
    [Parameter(Mandatory)][string]$StandardErrorPath,
    [Parameter(Mandatory)][string]$RunRecordPath,
    [Parameter(Mandatory)][string]$LiveStatePath,
    [Parameter(Mandatory)][int]$Issue
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Fail-Astro {
    param([string]$Code, [string]$Message, [string]$Remediation)
    $exception = [InvalidOperationException]::new($Message)
    $exception.Data['AstroCode'] = $Code
    $exception.Data['AstroRemediation'] = $Remediation
    throw $exception
}

function Path-WithTrailingSeparator([string]$Path) {
    return ([IO.Path]::GetFullPath($Path).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar)
}

function Assert-PathWithin([string]$Path, [string]$Root, [string]$Code, [string]$Description) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith((Path-WithTrailingSeparator $Root), [StringComparison]::OrdinalIgnoreCase)) {
        Fail-Astro $Code "$Description '$full' escapes required root '$Root'" 'use a fresh path inside the staged evidence session'
    }
    return $full
}

function Assert-NotReparseEntry([string]$Path, [string]$Description) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Astro 'ASTRO_FSV_REPARSE_ENTRY_REFUSED' "$Description is a reparse point: $Path" 'use ordinary workspace-local evidence paths that cannot redirect elsewhere'
    }
}

function File-Sha256([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hasher.ComputeHash($stream)) -replace '-', '').ToLowerInvariant() }
    finally { $hasher.Dispose(); $stream.Dispose() }
}

function String-Sha256([AllowEmptyString()][string]$Value) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))) -replace '-', '').ToLowerInvariant()
    }
    finally { $hasher.Dispose() }
}

function Observe-ExitedProcessCode(
    [Diagnostics.Process]$Process,
    [Microsoft.Win32.SafeHandles.SafeProcessHandle]$RetainedHandle
) {
    $Process.Refresh()
    if (-not $Process.HasExited) {
        Fail-Astro 'ASTRO_FSV_CHILD_STILL_LIVE' "native child PID $($Process.Id) is still live after the runner wait completed" 'preserve the FSV lock and wait for the exact recorded child to exit naturally'
    }
    try {
        [uint32]$kernelCode = [AstroFsvAtomicFile]::ReadTerminatedProcessExitCode($RetainedHandle)
    }
    catch {
        Fail-Astro 'ASTRO_FSV_CHILD_EXIT_UNREADABLE' "kernel32!GetExitCodeProcess failed for retained native child PID $($Process.Id): $($_.Exception.Message)" 'preserve the session and process handle evidence; repair process-exit observation before rerunning'
    }
    $componentSignedCode = $null
    $componentCode = $null
    $componentError = $null
    try {
        $componentSignedCode = [int32]$Process.ExitCode
        $componentCode = [BitConverter]::ToUInt32(
            [BitConverter]::GetBytes($componentSignedCode),
            0
        )
    }
    catch {
        $componentError = $_.Exception.Message
    }
    return [ordered]@{
        exit_code = $kernelCode
        primary_source = 'kernel32!GetExitCodeProcess(retained_process_handle)'
        process_component_exit_code_signed = $componentSignedCode
        process_component_exit_code = $componentCode
        process_component_error = Failure-Text $componentError
        sources_agree = $null -ne $componentCode -and $componentCode -eq $kernelCode
    }
}

function Failure-Text($Value) {
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text
}

function Write-NewDurableUtf8([string]$Path, [string]$Content) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Content)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Publish-NewFile([string]$Path, [string]$Content) {
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $stage = Join-Path $parent ('.' + [IO.Path]::GetFileName($Path) + ".publishing-$PID-" + [guid]::NewGuid().ToString('N'))
    try {
        Write-NewDurableUtf8 $stage $Content
        [AstroFsvAtomicFile]::PublishNoClobber($stage, $Path)
    }
    catch {
        Remove-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Get-RepoState([string]$GitExe, [string]$Workspace) {
    $head = (& $GitExe -C $Workspace rev-parse HEAD).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0) { Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' 'git rev-parse HEAD failed' 'repair repository state before evidence execution' }
    $status = (& $GitExe -C $Workspace status --porcelain) -join "`n"
    if ($LASTEXITCODE -ne 0) { Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' 'git status failed' 'repair repository state before evidence execution' }
    $diff = (& $GitExe -C $Workspace diff --binary HEAD) -join "`n"
    if ($LASTEXITCODE -ne 0) { Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' 'git diff HEAD failed' 'repair repository state before evidence execution' }
    return [ordered]@{ head_sha = $head; status_sha256 = String-Sha256 $status; diff_sha256 = String-Sha256 $diff }
}

if (-not ([Management.Automation.PSTypeName]'AstroFsvAtomicFile').Type) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class AstroFsvAtomicFile {
    const uint MOVEFILE_REPLACE_EXISTING = 0x00000001;
    const uint MOVEFILE_WRITE_THROUGH = 0x00000008;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint OPEN_EXISTING = 3;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const uint STILL_ACTIVE = 259;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool MoveFileExW(string existingName, string newName, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    public static void PublishNoClobber(string source, string destination) {
        Move(source, destination, MOVEFILE_WRITE_THROUGH);
    }

    public static void ReplaceOwned(string source, string destination) {
        Move(source, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }

    static void Move(string source, string destination, uint flags) {
        if (!MoveFileExW(source, destination, flags))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "atomic write-through publication failed");
    }

    public static SafeFileHandle OpenDirectoryWithoutDeleteShare(string path) {
        SafeFileHandle handle = CreateFileW(path, 0, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "open evidence directory lease failed");
        return handle;
    }

    public static uint ReadTerminatedProcessExitCode(SafeProcessHandle process) {
        if (process == null || process.IsInvalid || process.IsClosed)
            throw new InvalidOperationException("retained native process handle is invalid or closed");
        uint exitCode;
        if (!GetExitCodeProcess(process, out exitCode))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess failed");
        if (exitCode == STILL_ACTIVE)
            throw new InvalidOperationException("retained native process handle still reports STILL_ACTIVE");
        return exitCode;
    }
}
'@
}

function Test-DescendantOf([int]$CandidatePid, [int]$AncestorPid) {
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

function ConvertTo-WindowsCommandLineArgument([string]$Argument) {
    if ($Argument.Length -gt 0 -and $Argument -notmatch '[\s"]') { return $Argument }
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) { [void]$builder.Append(('\' * ($backslashes * 2))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertFrom-FlatStringArrayJson([string]$Json) {
    if ([string]::IsNullOrWhiteSpace($Json)) {
        Fail-Astro 'ASTRO_FSV_ARGUMENTS_INVALID' 'ArgumentsJson is empty' 'pass a JSON array containing only strings; use [] for zero arguments'
    }

    # ConvertFrom-Json normally enumerates a top-level JSON array, collapsing []
    # to $null and a single item to a scalar. Parse through an object envelope so
    # the array identity and cardinality survive on Windows PowerShell 5.1 and
    # PowerShell 7. Random property names make injected sibling properties
    # observable rather than allowing trailing JSON to escape the array contract.
    $argumentProperty = "arguments_$([Guid]::NewGuid().ToString('N'))"
    $sentinelProperty = "sentinel_$([Guid]::NewGuid().ToString('N'))"
    $envelopeJson = '{"' + $argumentProperty + '":' + $Json + ',"' + $sentinelProperty + '":true}'
    try { $envelope = ConvertFrom-Json -InputObject $envelopeJson }
    catch {
        Fail-Astro 'ASTRO_FSV_ARGUMENTS_INVALID' "ArgumentsJson is invalid: $($_.Exception.Message)" 'pass a flat JSON array containing only strings'
    }

    $properties = @($envelope.PSObject.Properties)
    $argumentEntry = $envelope.PSObject.Properties[$argumentProperty]
    $sentinelEntry = $envelope.PSObject.Properties[$sentinelProperty]
    if ($properties.Count -ne 2 -or $null -eq $argumentEntry -or $null -eq $sentinelEntry -or
        $sentinelEntry.Value -isnot [bool] -or -not [bool]$sentinelEntry.Value) {
        Fail-Astro 'ASTRO_FSV_ARGUMENTS_INVALID' 'ArgumentsJson contains data outside its top-level value' 'pass exactly one flat JSON array containing only strings'
    }

    $rawArguments = $argumentEntry.Value
    if ($rawArguments -isnot [Array]) {
        Fail-Astro 'ASTRO_FSV_ARGUMENTS_INVALID' 'ArgumentsJson top-level value is not an array' 'pass a flat JSON array containing only strings; use [] for zero arguments'
    }
    $values = [string[]]::new($rawArguments.Count)
    for ($index = 0; $index -lt $rawArguments.Count; $index++) {
        if ($rawArguments[$index] -isnot [string]) {
            Fail-Astro 'ASTRO_FSV_ARGUMENTS_INVALID' "ArgumentsJson item $index is not a string" 'pass a flat JSON array containing only strings'
        }
        $values[$index] = [string]$rawArguments[$index]
    }
    return [pscustomobject]@{
        Count = [int]$values.Length
        Values = $values
    }
}

$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$evidenceRoot = Join-Path $workspace '.tmp\native-fsv-artifacts'
$launcherLockPath = Join-Path (Join-Path $workspace '.tmp') 'astrolabe-launcher.lock'
$fsvLockPath = Join-Path (Join-Path $workspace '.tmp') 'astrolabe-fsv.lock'
$gitExe = 'C:\Program Files\Git\bin\git.exe'
$artifactHandle = $null
$receiptHandle = $null
$launcherLockHandle = $null
$directoryHandle = $null
$fsvLockOwned = $false
$child = $null
$childStartedAtUtc = $null
$childExitedAtUtc = $null
$childExitCode = $null
$childExitObservation = $null
$childExitObservationError = $null
$childProcessHandle = $null
$artifact = $null
$artifactHashBefore = $null
$receiptFull = $null
$runRecordWritten = $false
$runRecordAuthorized = $false
$arguments = [string[]]::new(0)
$argumentCount = 0

try {
    if ($Issue -le 0) { Fail-Astro 'ASTRO_FSV_ISSUE_INVALID' 'Issue must be positive' 'pass the driving GitHub issue number' }
    if (-not (Test-Path -LiteralPath $gitExe -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_GIT_MISSING' "required native Git executable is absent: $gitExe" 'restore the canonical Git for Windows installation'
    }
    $receiptFull = Assert-PathWithin $ReceiptPath $evidenceRoot 'ASTRO_FSV_RECEIPT_ESCAPE' 'receipt path'
    if (-not (Test-Path -LiteralPath $receiptFull -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_MISSING' "receipt does not exist: $receiptFull" 'stage the native artifact first'
    }
    try { $receipt = Get-Content -LiteralPath $receiptFull -Raw | ConvertFrom-Json }
    catch { Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' "parse receipt failed: $($_.Exception.Message)" 'stage a fresh native artifact' }
    if ($receipt.schema -ne 'astrolabe.native-fsv-artifact.v1' -or [int]$receipt.issue -ne $Issue) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' "receipt schema/issue does not match issue #$Issue" 'pass the exact receipt emitted for this driving issue'
    }
    if ([string]$receipt.tree_sha -notmatch '^[0-9a-f]{40}$' -or
        [string]$receipt.artifact.sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$receipt.session_id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') {
        Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' 'receipt contains invalid tree/hash/session identity fields' 'discard the invalid session and stage a fresh artifact'
    }
    $sessionDirectory = Split-Path -Parent $receiptFull
    $expectedSessionDirectory = Join-Path (Join-Path (Join-Path $evidenceRoot ([string]$receipt.tree_sha)) `
        ([string]$receipt.artifact.sha256)) ([string]$receipt.session_id)
    if (-not [string]::Equals([IO.Path]::GetFullPath($sessionDirectory), [IO.Path]::GetFullPath($expectedSessionDirectory), [StringComparison]::OrdinalIgnoreCase)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_PATH_MISMATCH' 'receipt path does not match its tree/hash/session identity' 'discard the relocated receipt and stage a fresh artifact'
    }
    Assert-NotReparseEntry $receiptFull 'evidence receipt'
    Assert-NotReparseEntry $sessionDirectory 'evidence session directory'
    $artifact = Assert-PathWithin ([string]$receipt.artifact.path) $sessionDirectory 'ASTRO_FSV_ARTIFACT_ESCAPE' 'artifact path'
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_ARTIFACT_MISSING' "staged artifact is absent: $artifact" 'stage a fresh native artifact'
    }
    Assert-NotReparseEntry $artifact 'staged native artifact'
    foreach ($pair in @(
        @($StandardOutputPath, 'stdout'), @($StandardErrorPath, 'stderr'),
        @($RunRecordPath, 'run record'), @($LiveStatePath, 'live state')
    )) {
        $resolved = Assert-PathWithin ([string]$pair[0]) $sessionDirectory 'ASTRO_FSV_OUTPUT_ESCAPE' ([string]$pair[1])
        if (Test-Path -LiteralPath $resolved) {
            Fail-Astro 'ASTRO_FSV_OUTPUT_REUSE_REFUSED' "$($pair[1]) already exists: $resolved" 'use fresh output paths; FSV state is append-only and never overwritten'
        }
    }
    $StandardOutputPath = [IO.Path]::GetFullPath($StandardOutputPath)
    $StandardErrorPath = [IO.Path]::GetFullPath($StandardErrorPath)
    $RunRecordPath = [IO.Path]::GetFullPath($RunRecordPath)
    $LiveStatePath = [IO.Path]::GetFullPath($LiveStatePath)
    $runRecordAuthorized = $true

    if (-not (Test-Path -LiteralPath $launcherLockPath -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_REQUIRED' "live launcher lock is absent: $launcherLockPath" 'run native-fsv-run.ps1 as a child of scripts/windows-gnu-toolchain.ps1'
    }
    try { $launcherLock = Get-Content -LiteralPath $launcherLockPath -Raw | ConvertFrom-Json }
    catch { Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_INVALID' "launcher lock is unreadable: $($_.Exception.Message)" 'preserve state and repair the launcher lock before running evidence' }
    $launcherPid = 0
    if (-not [int]::TryParse([string]$launcherLock.pid, [ref]$launcherPid) -or $launcherPid -le 0 -or
        [int]$launcherLock.issue -ne $Issue -or $null -eq (Get-Process -Id $launcherPid -ErrorAction SilentlyContinue)) {
        Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_INVALID' "launcher lock does not name a live owner for issue #$Issue" 'start the FSV through the native launcher with the same driving issue'
    }
    if (-not (Test-DescendantOf $PID $launcherPid)) {
        Fail-Astro 'ASTRO_FSV_RUNNER_NOT_OWNED' "runner PID $PID is not a descendant of launcher PID $launcherPid" 'invoke this runner synchronously from the launcher-owned child process'
    }

    $beforeRepo = Get-RepoState $gitExe $workspace
    if ($beforeRepo.head_sha -cne ([string]$receipt.tree_sha).ToLowerInvariant()) {
        Fail-Astro 'ASTRO_FSV_TREE_MISMATCH' "current HEAD $($beforeRepo.head_sha) differs from staged tree $($receipt.tree_sha)" 'discard the session and rebuild from the current frozen tree'
    }
    if ($null -eq $receipt.repository -or
        [string]$receipt.repository.status_sha256 -cne [string]$beforeRepo.status_sha256 -or
        [string]$receipt.repository.diff_sha256 -cne [string]$beforeRepo.diff_sha256 -or
        [string]$launcherLock.head_sha -cne [string]$beforeRepo.head_sha -or
        [string]$launcherLock.status_sha256 -cne [string]$beforeRepo.status_sha256 -or
        [string]$launcherLock.diff_sha256 -cne [string]$beforeRepo.diff_sha256) {
        Fail-Astro 'ASTRO_FSV_REPOSITORY_IDENTITY_MISMATCH' 'receipt, live launcher lock, and current repository fingerprints do not identify the same frozen state' 'discard the artifact and rebuild under a fresh immutable launcher lease'
    }
    $artifactHashBefore = File-Sha256 $artifact
    $receiptHashBefore = File-Sha256 $receiptFull
    $launcherLockHashBefore = File-Sha256 $launcherLockPath
    $artifactItem = Get-Item -LiteralPath $artifact
    if ($artifactHashBefore -cne ([string]$receipt.artifact.sha256).ToLowerInvariant() -or
        [uint64]$artifactItem.Length -ne [uint64]$receipt.artifact.bytes) {
        Fail-Astro 'ASTRO_FSV_ARTIFACT_DRIFT' 'staged artifact hash/length differs from its receipt before launch' 'discard the session, identify the writer, and rebuild'
    }

    $argumentVector = ConvertFrom-FlatStringArrayJson $ArgumentsJson
    $argumentCount = [int]$argumentVector.Count
    $arguments = [string[]]@($argumentVector.Values)
    if ($arguments.Length -ne $argumentCount) {
        Fail-Astro 'ASTRO_FSV_ARGUMENTS_INVALID' 'ArgumentsJson cardinality changed during parsing' 'preserve the invocation and investigate the PowerShell JSON runtime'
    }
    $argumentLine = if ($argumentCount -gt 0) {
        (@($arguments | ForEach-Object { ConvertTo-WindowsCommandLineArgument ([string]$_) }) -join ' ')
    } else {
        $null
    }

    # FileShare.Read intentionally omits write/delete sharing. Microsoft documents that a
    # subsequent delete/rename open then fails until this handle is closed.
    $directoryHandle = [AstroFsvAtomicFile]::OpenDirectoryWithoutDeleteShare($sessionDirectory)
    $artifactHandle = [IO.File]::Open($artifact, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $receiptHandle = [IO.File]::Open($receiptFull, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $launcherLockHandle = [IO.File]::Open($launcherLockPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $lockStage = "$fsvLockPath.$PID.tmp"
    $lockManifest = [ordered]@{
        pid = $PID
        issue = $Issue
        started = [DateTime]::UtcNow.ToString('o')
        command = if ($argumentCount -gt 0) { "$artifact $argumentLine" } else { $artifact }
        argument_count = $argumentCount
        arguments = @($arguments)
        tree_sha = [string]$receipt.tree_sha
        artifact_path = $artifact
        artifact_sha256 = $artifactHashBefore
        launcher_pid = $launcherPid
        owner_pids = @($launcherPid, $PID)
        child_pid = $null
        phase = 'claimed'
    }
    Write-NewDurableUtf8 $lockStage ($lockManifest | ConvertTo-Json -Depth 10 -Compress)
    try { [AstroFsvAtomicFile]::PublishNoClobber($lockStage, $fsvLockPath) }
    catch {
        Remove-Item -LiteralPath $lockStage -Force -ErrorAction SilentlyContinue
        Fail-Astro 'ASTRO_FSV_LOCK_HELD' "FSV lock could not be claimed without clobbering: $fsvLockPath" 'wait for the live owner or post dead-owner evidence before removing a stale lock'
    }
    $fsvLockOwned = $true

    $startProcessParameters = @{
        FilePath = $artifact
        RedirectStandardOutput = $StandardOutputPath
        RedirectStandardError = $StandardErrorPath
        WindowStyle = 'Hidden'
        PassThru = $true
    }
    if ($argumentCount -gt 0) {
        $startProcessParameters.ArgumentList = $argumentLine
    }
    $child = Start-Process @startProcessParameters
    $childProcessHandle = $child.SafeHandle
    if ($null -eq $childProcessHandle -or $childProcessHandle.IsInvalid -or $childProcessHandle.IsClosed) {
        Fail-Astro 'ASTRO_FSV_CHILD_HANDLE_UNAVAILABLE' "native child PID $($child.Id) did not expose a retained process handle" 'preserve the session and repair native process launch before rerunning'
    }
    $childStartedAtUtc = [DateTime]::UtcNow.ToString('o')
    $ownedLock = Get-Content -LiteralPath $fsvLockPath -Raw | ConvertFrom-Json
    if ([int]$ownedLock.pid -ne $PID -or [string]$ownedLock.artifact_sha256 -cne $artifactHashBefore) {
        Fail-Astro 'ASTRO_FSV_LOCK_IDENTITY_CHANGED' 'FSV lock identity changed before child PID publication' 'preserve state and investigate the competing writer'
    }
    $lockManifest.child_pid = $child.Id
    $lockManifest.owner_pids = @($launcherPid, $PID, $child.Id)
    $lockManifest.phase = 'running'
    $lockUpdateStage = "$fsvLockPath.$PID.running.tmp"
    Write-NewDurableUtf8 $lockUpdateStage ($lockManifest | ConvertTo-Json -Depth 10 -Compress)
    try { [AstroFsvAtomicFile]::ReplaceOwned($lockUpdateStage, $fsvLockPath) }
    catch {
        Remove-Item -LiteralPath $lockUpdateStage -Force -ErrorAction SilentlyContinue
        Fail-Astro 'ASTRO_FSV_LOCK_UPDATE_FAILED' "publishing child PID $($child.Id) into the FSV lock failed: $($_.Exception.Message)" 'preserve state and investigate the lock writer'
    }
    $publishedLock = Get-Content -LiteralPath $fsvLockPath -Raw | ConvertFrom-Json
    if ([int]$publishedLock.child_pid -ne $child.Id -or [string]$publishedLock.phase -cne 'running') {
        Fail-Astro 'ASTRO_FSV_LOCK_UPDATE_FAILED' 'FSV lock child-PID readback does not match the real process' 'preserve state and investigate the durable lock write'
    }
    $liveState = [ordered]@{
        schema = 'astrolabe.native-fsv-live.v1'
        runner_pid = $PID
        launcher_pid = $launcherPid
        child_pid = $child.Id
        issue = $Issue
        tree_sha = [string]$receipt.tree_sha
        artifact = [ordered]@{ path = $artifact; bytes = [uint64]$artifactItem.Length; sha256 = $artifactHashBefore }
        started_at_utc = $childStartedAtUtc
        argument_count = $argumentCount
        arguments = @($arguments)
    }
    Publish-NewFile $LiveStatePath ($liveState | ConvertTo-Json -Depth 10)
    $child.WaitForExit()
    $child.Refresh()
    $childExitedAtUtc = [DateTime]::UtcNow.ToString('o')
    $childExitObservation = Observe-ExitedProcessCode $child $childProcessHandle
    $childExitCode = [uint32]$childExitObservation.exit_code

    $artifactHashAfter = File-Sha256 $artifact
    $receiptHashAfter = File-Sha256 $receiptFull
    $launcherLockHashAfter = File-Sha256 $launcherLockPath
    $afterRepo = Get-RepoState $gitExe $workspace
    $stdoutHash = File-Sha256 $StandardOutputPath
    $stderrHash = File-Sha256 $StandardErrorPath
    $treeStable = $beforeRepo.head_sha -ceq $afterRepo.head_sha -and
        $beforeRepo.status_sha256 -ceq $afterRepo.status_sha256 -and
        $beforeRepo.diff_sha256 -ceq $afterRepo.diff_sha256
    $artifactStable = $artifactHashBefore -ceq $artifactHashAfter -and
        [uint64](Get-Item -LiteralPath $artifact).Length -eq [uint64]$receipt.artifact.bytes
    $receiptStable = $receiptHashBefore -ceq $receiptHashAfter
    $launcherLeaseStable = $launcherLockHashBefore -ceq $launcherLockHashAfter
    $verdict = if ($childExitCode -eq 0 -and [bool]$childExitObservation.sources_agree -and
        $treeStable -and $artifactStable -and $receiptStable -and $launcherLeaseStable) {
        'verified'
    } else {
        'failed'
    }
    $record = [ordered]@{
        schema = 'astrolabe.native-fsv-run.v1'
        verdict = $verdict
        issue = $Issue
        receipt_path = $receiptFull
        runner = [ordered]@{ pid = $PID; launcher_pid = $launcherPid }
        process = [ordered]@{
            pid = $child.Id
            exit_code = $childExitCode
            exit_code_observation = $childExitObservation
            started_at = $childStartedAtUtc
            exited_at = $childExitedAtUtc
            timestamp_basis = 'runner-observed-utc'
        }
        artifact = [ordered]@{ path = $artifact; bytes = [uint64](Get-Item -LiteralPath $artifact).Length; sha256 = $artifactHashAfter; stable = $artifactStable; delete_share_denied_for_run = $true }
        receipt = [ordered]@{ path = $receiptFull; sha256_before = $receiptHashBefore; sha256_after = $receiptHashAfter; stable = $receiptStable }
        launcher_lease = [ordered]@{ path = $launcherLockPath; sha256_before = $launcherLockHashBefore; sha256_after = $launcherLockHashAfter; stable = $launcherLeaseStable }
        argument_count = $argumentCount
        arguments = @($arguments)
        stdout = [ordered]@{ path = $StandardOutputPath; bytes = [uint64](Get-Item -LiteralPath $StandardOutputPath).Length; sha256 = $stdoutHash }
        stderr = [ordered]@{ path = $StandardErrorPath; bytes = [uint64](Get-Item -LiteralPath $StandardErrorPath).Length; sha256 = $stderrHash }
        repository = [ordered]@{ before = $beforeRepo; after = $afterRepo; stable = $treeStable }
    }
    Write-NewDurableUtf8 $RunRecordPath ($record | ConvertTo-Json -Depth 15)
    $runRecordWritten = $true
    $persistedRecord = Get-Content -LiteralPath $RunRecordPath -Raw | ConvertFrom-Json
    $persistedArguments = @($persistedRecord.arguments)
    $argumentsMatch = [int]$persistedRecord.argument_count -eq $argumentCount -and
        $persistedArguments.Count -eq $argumentCount
    if ($argumentsMatch) {
        for ($index = 0; $index -lt $argumentCount; $index++) {
            if ($persistedArguments[$index] -isnot [string] -or
                -not [string]::Equals([string]$persistedArguments[$index], $arguments[$index], [StringComparison]::Ordinal)) {
                $argumentsMatch = $false
                break
            }
        }
    }
    if ([uint64]$persistedRecord.process.exit_code -ne [uint64]$childExitCode -or
        [string]$persistedRecord.process.exit_code_observation.primary_source -cne [string]$childExitObservation.primary_source -or
        [bool]$persistedRecord.process.exit_code_observation.sources_agree -ne [bool]$childExitObservation.sources_agree -or
        [string]$persistedRecord.artifact.sha256 -cne $artifactHashAfter -or
        -not $argumentsMatch) {
        Fail-Astro 'ASTRO_FSV_RUN_READBACK_FAILED' 'persisted run record does not match the observed process/artifact state' 'preserve the session and investigate the failed durable write'
    }
    $record | ConvertTo-Json -Depth 15 -Compress | Write-Output
    if (-not $treeStable) { Fail-Astro 'ASTRO_FSV_TREE_MUTATED' 'repository state changed during the native FSV run' 'discard the evidence, freeze the checkout, rebuild, and rerun' }
    if (-not $artifactStable) { Fail-Astro 'ASTRO_FSV_ARTIFACT_DRIFT' 'staged artifact changed during the native FSV run' 'preserve state, identify the writer, rebuild, and rerun' }
    if (-not $receiptStable) { Fail-Astro 'ASTRO_FSV_RECEIPT_DRIFT' 'artifact receipt changed during the native FSV run' 'preserve state, identify the writer, rebuild, and rerun' }
    if (-not $launcherLeaseStable) { Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_DRIFT' 'launcher lock changed during the native FSV run' 'discard the evidence and investigate the lease writer' }
    if (-not [bool]$childExitObservation.sources_agree) {
        Fail-Astro 'ASTRO_FSV_CHILD_EXIT_OBSERVATION_MISMATCH' "kernel32 exit code $childExitCode disagrees with Process.ExitCode $($childExitObservation.process_component_exit_code) for native child PID $($child.Id)" 'preserve the run record and repair process-component exit observation; never infer success from a disagreeing source'
    }
    if ($childExitCode -ne 0) { exit 1 }
}
catch {
    $failure = $_
    if ($null -ne $child) {
        try {
            if (-not $child.HasExited) {
                [Console]::Error.WriteLine("NATIVE_FSV[ASTRO_FSV_FAILURE_WAITING_FOR_CHILD]: runner failed after real child PID $($child.Id) started; waiting for that exact process to exit naturally before releasing its immutable artifact lease")
                $child.WaitForExit()
                $child.Refresh()
            }
            if ($child.HasExited) {
                if ($null -eq $childExitedAtUtc) {
                    $childExitedAtUtc = [DateTime]::UtcNow.ToString('o')
                }
                if ($null -eq $childExitCode) {
                    try {
                        $childExitObservation = Observe-ExitedProcessCode $child $childProcessHandle
                        $childExitCode = [uint32]$childExitObservation.exit_code
                    }
                    catch { $childExitObservationError = $_.Exception.Message }
                }
            }
        }
        catch {
            [Console]::Error.WriteLine("NATIVE_FSV[ASTRO_FSV_CHILD_LIVENESS_UNEVALUABLE]: could not prove real child termination: $($_.Exception.Message); preserving the FSV lock fail-closed")
        }
    }
    $code = if ($failure.Exception.Data.Contains('AstroCode')) { [string]$failure.Exception.Data['AstroCode'] } else { 'ASTRO_FSV_RUN_INTERNAL' }
    $remediation = if ($failure.Exception.Data.Contains('AstroRemediation')) { [string]$failure.Exception.Data['AstroRemediation'] } else { 'preserve the evidence state, inspect the full error, repair the root cause, and retry from a fresh session' }
    if ($runRecordAuthorized -and -not $runRecordWritten -and $null -ne $child -and $child.HasExited -and
        -not (Test-Path -LiteralPath $RunRecordPath)) {
        try {
            $failureArtifactHash = if (Test-Path -LiteralPath $artifact -PathType Leaf) { File-Sha256 $artifact } else { $null }
            $failureRecord = [ordered]@{
                schema = 'astrolabe.native-fsv-run.v1'
                verdict = 'failed'
                issue = $Issue
                receipt_path = $receiptFull
                process = [ordered]@{
                    pid = $child.Id
                    exit_code = $childExitCode
                    exit_code_observation = $childExitObservation
                    exit_code_observation_error = Failure-Text $childExitObservationError
                    started_at = $childStartedAtUtc
                    exited_at = $childExitedAtUtc
                    timestamp_basis = 'runner-observed-utc'
                }
                artifact = [ordered]@{
                    path = $artifact
                    bytes = if (Test-Path -LiteralPath $artifact -PathType Leaf) { [uint64](Get-Item -LiteralPath $artifact).Length } else { 0 }
                    sha256 = $failureArtifactHash
                    stable = $false
                }
                argument_count = $argumentCount
                arguments = @($arguments)
                stdout = [ordered]@{
                    path = $StandardOutputPath
                    bytes = if (Test-Path -LiteralPath $StandardOutputPath -PathType Leaf) { [uint64](Get-Item -LiteralPath $StandardOutputPath).Length } else { 0 }
                    sha256 = if (Test-Path -LiteralPath $StandardOutputPath -PathType Leaf) { File-Sha256 $StandardOutputPath } else { $null }
                }
                stderr = [ordered]@{
                    path = $StandardErrorPath
                    bytes = if (Test-Path -LiteralPath $StandardErrorPath -PathType Leaf) { [uint64](Get-Item -LiteralPath $StandardErrorPath).Length } else { 0 }
                    sha256 = if (Test-Path -LiteralPath $StandardErrorPath -PathType Leaf) { File-Sha256 $StandardErrorPath } else { $null }
                }
                failure = [ordered]@{
                    code = $code
                    message = $failure.Exception.Message
                    remediation = $remediation
                    exception_type = $failure.Exception.GetType().FullName
                    script_stack_trace = Failure-Text $failure.ScriptStackTrace
                    invocation = Failure-Text $failure.InvocationInfo.PositionMessage
                }
            }
            Write-NewDurableUtf8 $RunRecordPath ($failureRecord | ConvertTo-Json -Depth 15)
            $runRecordWritten = $true
        }
        catch {
            [Console]::Error.WriteLine("NATIVE_FSV[ASTRO_FSV_FAILURE_RECORD_WRITE_FAILED]: could not persist the failure record: $($_.Exception.Message)")
        }
    }
    [Console]::Error.WriteLine(([ordered]@{ code = $code; message = $failure.Exception.Message; remediation = $remediation; run_record_written = $runRecordWritten } | ConvertTo-Json -Compress))
    exit 1
}
finally {
    if ($null -ne $launcherLockHandle) { $launcherLockHandle.Dispose() }
    if ($null -ne $receiptHandle) { $receiptHandle.Dispose() }
    if ($null -ne $artifactHandle) { $artifactHandle.Dispose() }
    if ($null -ne $directoryHandle) { $directoryHandle.Dispose() }
    $childStillLive = $false
    if ($null -ne $child) {
        try { $childStillLive = -not $child.HasExited }
        catch { $childStillLive = $true }
    }
    if ($fsvLockOwned -and -not $childStillLive -and (Test-Path -LiteralPath $fsvLockPath)) {
        $owned = $false
        try {
            $lock = Get-Content -LiteralPath $fsvLockPath -Raw | ConvertFrom-Json
            $owned = [int]$lock.pid -eq $PID -and [string]$lock.artifact_sha256 -ceq $artifactHashBefore
        }
        catch { $owned = $false }
        if ($owned) { Remove-Item -LiteralPath $fsvLockPath -Force }
        else { [Console]::Error.WriteLine('NATIVE_FSV[ASTRO_FSV_LOCK_IDENTITY_CHANGED]: refusing to remove FSV lock whose identity changed while the runner was live') }
    }
    elseif ($fsvLockOwned -and $childStillLive) {
        [Console]::Error.WriteLine('NATIVE_FSV[ASTRO_FSV_LOCK_PRESERVED_LIVE_CHILD]: preserving the FSV lock because the recorded real child is still live')
    }
}
