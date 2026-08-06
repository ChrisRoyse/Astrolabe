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
    the artifact is executing. Every owner is a strict PID/process-start identity. Lifecycle
    removal refuses exact-live and unevaluable generations, records PID reuse without treating
    it as ownership, and accepts legacy PID-only state only through a tracker-bound migration.

.NOTES
    Refs #612, #596, #424, #197. Manual FSV tooling; this is not a test or a gate.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Stage', 'Inspect', 'Cleanup', 'Abandon', 'PreAdmissionAbandon', 'Quarantine', 'QuarantineTerminalPartial', 'MigrateLegacy', 'RetireLock', 'RetireTerminalPartialLock', 'RetireInterruptedV2Lock')]
    [string]$Operation,

    [string]$SourcePath = '',
    [string]$ReceiptPath = '',
    [string]$RunRecordPath = '',
    [int]$Issue = 0,
    [string]$TreeSha = '',
    [string]$SessionId = '',
    [string]$AbandonRecordPath = '',
    [string]$RecoveryRecordPath = '',
    [string]$MigrationRecordPath = '',
    [string]$LockRetirementRecordPath = '',
    [string]$LauncherRecoveryCompletionPath = '',
    [string]$TargetRecoveryCompletionPath = '',
    [string[]]$LauncherArchiveCompletionPaths = @(),
    [ValidateSet('DeadOwnerRecoveryV1', 'NormalLiveOwnerCleanupV1')]
    [string]$LauncherTerminalChainKind = 'DeadOwnerRecoveryV1',
    [string]$LauncherNormalArchiveCompletionPath = '',
    [string]$LiveStatePath = '',
    [string]$StandardOutputPath = '',
    [string]$StandardErrorPath = '',
    [string]$PreAdmissionDirectoryPath = '',
    [string]$TrackerCommentUrl = '',
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

function Assert-DirectSessionChildPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SessionDirectory,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    $full = Assert-PathWithin $Path $SessionDirectory $Code $Description
    if (-not [string]::Equals(
            [IO.Path]::GetFullPath((Split-Path -Parent $full)),
            [IO.Path]::GetFullPath($SessionDirectory),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-Astro $Code `
            "$Description must be a direct child of staged session '$SessionDirectory': $full" `
            'bind one fresh direct session-root path; never infer nested pre-admission state'
    }
    return $full
}

function Assert-NotReparseEntry {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )
    $state = Get-AstroPathEntryState $Path
    if ($state.State -ceq 'absent') { return }
    if ($state.State -cne 'present') {
        Fail-Astro 'ASTRO_FSV_PATH_UNEVALUABLE' `
            "$Description presence/attributes are unevaluable: $Path ($($state.Error))" `
            'repair filesystem access before mutating evidence state'
    }
    if (($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Astro 'ASTRO_FSV_REPARSE_ENTRY_REFUSED' "$Description is a reparse point: $Path" `
            'use ordinary workspace-local files and directories; evidence paths may not redirect elsewhere'
    }
}

function File-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    $handle = [AstroLauncherLockNative]::OpenExactProtectedReadFile(
        [IO.Path]::GetFullPath($Path)
    )
    try {
        return [AstroLauncherLockNative]::ComputeExactFileSha256($handle)
    }
    finally {
        $handle.Dispose()
    }
}

function Source-File-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    $handle = [AstroLauncherLockNative]::OpenProtectedOrdinaryReadFile(
        [IO.Path]::GetFullPath($Path)
    )
    try {
        return [AstroLauncherLockNative]::ComputeOrdinaryFileSha256($handle)
    }
    finally {
        $handle.Dispose()
    }
}

function Get-AstroFsvExactFileIdentity {
    param([Parameter(Mandatory)][string]$Path)

    $handle = [AstroLauncherLockNative]::OpenExactClassifierReadFile(
        [IO.Path]::GetFullPath($Path)
    )
    try { return [AstroLauncherLockNative]::GetFileIdentity($handle) }
    finally { $handle.Dispose() }
}

function String-Sha256 {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))) -replace '-', '').ToLowerInvariant()
    }
    finally { $hasher.Dispose() }
}

function ByteArray-Sha256 {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Value)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($Value)) -replace '-', '').ToLowerInvariant()
    }
    finally { $hasher.Dispose() }
}

function ConvertTo-AstroNativeCommandLineArgument {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    # ProcessStartInfo.ArgumentList is unavailable in the Windows PowerShell 5.1
    # Task Scheduler boundary. Build one Windows command line using the inverse of
    # CommandLineToArgvW's backslash/quote rules so every native Git argument keeps
    # its exact byte sequence rather than relying on shell tokenization.
    if ($Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }

    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append('\', ($slashes * 2) + 1)
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) {
            [void]$builder.Append('\', $slashes)
            $slashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($slashes -gt 0) {
        [void]$builder.Append('\', $slashes * 2)
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-GitRawCapture {
    param(
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)][string]$Workspace,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Description
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $GitExe
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    [string[]]$nativeArguments = @(
        '-C',
        [IO.Path]::GetFullPath($Workspace).TrimEnd('\', '/')
    ) + @($Arguments)
    $start.Arguments = [string]::Join(
        ' ',
        @($nativeArguments | ForEach-Object {
            ConvertTo-AstroNativeCommandLineArgument -Value ([string]$_)
        })
    )
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $stdout = [IO.MemoryStream]::new()
    try {
        if (-not $process.Start()) {
            Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' "$Description did not start during artifact promotion" `
                'repair native Git before staging evidence'
        }
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            try { $process.Kill() } catch {}
            Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' "$Description exceeded the 30000 ms bounded timeout during artifact promotion" `
                'repair native Git or repository state before staging evidence'
        }
        [void]$stdoutTask.GetAwaiter().GetResult()
        return [pscustomobject]@{
            ExitCode = [int]$process.ExitCode
            Bytes = [byte[]]$stdout.ToArray()
            Stderr = $stderrTask.GetAwaiter().GetResult()
        }
    }
    finally {
        $stdout.Dispose()
        $process.Dispose()
    }
}

function Read-GitStatusFingerprint {
    param(
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)][string]$Workspace
    )
    $status = Invoke-GitRawCapture `
        -GitExe $GitExe `
        -Workspace $Workspace `
        -Arguments @(
            '-c',
            'core.quotepath=false',
            'status',
            '--porcelain=v1',
            '-z',
            '--untracked-files=normal'
        ) `
        -Description 'git status --porcelain=v1 -z --untracked-files=normal'
    if ($status.ExitCode -ne 0) {
        Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' "git status --porcelain=v1 -z failed during artifact promotion (exit=$($status.ExitCode), stderr=$($status.Stderr))" `
            'repair repository state before staging evidence'
    }
    try {
        $statusText = [Text.UTF8Encoding]::new($false, $true).GetString($status.Bytes)
    }
    catch {
        Fail-Astro 'ASTRO_FSV_GIT_STATUS_UTF8_INVALID' "Git status emitted bytes that are not strict UTF-8 during artifact promotion: $($_.Exception.Message)" `
            'rename the unsupported Windows worktree path before staging evidence'
    }
    if ($status.Bytes.Length -gt 0 -and
        $status.Bytes[$status.Bytes.Length - 1] -ne 0) {
        Fail-Astro 'ASTRO_FSV_GIT_STATUS_TERMINAL_NUL_MISSING' `
            'nonempty Git porcelain-v1 -z output lacks its terminal NUL during artifact promotion' `
            'repair or replace the native Git executable before staging evidence'
    }
    $parts = @($statusText.Split([char]0))
    $records = if ($statusText.Length -eq 0) {
        @()
    }
    else {
        @($parts[0..($parts.Count - 2)])
    }
    return [ordered]@{
        sha256 = ByteArray-Sha256 $status.Bytes
        records = [string[]]$records
    }
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
    $status = Read-GitStatusFingerprint -GitExe $GitExe -Workspace $Workspace
    $diff = Invoke-GitRawCapture `
        -GitExe $GitExe `
        -Workspace $Workspace `
        -Arguments @('diff', '--binary', 'HEAD') `
        -Description 'git diff --binary HEAD'
    if ($diff.ExitCode -ne 0) {
        Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' "git diff --binary HEAD failed during artifact promotion (exit=$($diff.ExitCode), stderr=$($diff.Stderr))" `
            'repair repository state before staging evidence'
    }
    return [ordered]@{
        head_sha = $head
        status_sha256 = [string]$status.sha256
        status_records = [string[]]$status.records
        diff_sha256 = ByteArray-Sha256 $diff.Bytes
    }
}

function Write-NewDurableUtf8 {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )
    $encoding = [Text.UTF8Encoding]::new($false)
    $bytes = $encoding.GetBytes($Content)
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
    finally {
        $stream.Dispose()
    }
}

function Copy-FileDurable {
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

    static string Extended(string path) {
        string full = System.IO.Path.GetFullPath(path);
        if (full.StartsWith(@"\\?\", StringComparison.Ordinal))
            return full;
        if (full.StartsWith(@"\\", StringComparison.Ordinal))
            return @"\\?\UNC\" + full.Substring(2);
        return @"\\?\" + full;
    }

    public static void PublishDirectory(string source, string destination) {
        if (!MoveFileExW(Extended(source), Extended(destination),
                MOVEFILE_WRITE_THROUGH)) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "MoveFileExW write-through no-clobber evidence-directory publication failed " +
                "(native_error=" + error + "; source=" + source +
                "; destination=" + destination + ")");
        }
    }

    public static void PublishFile(string source, string destination) {
        if (!MoveFileExW(Extended(source), Extended(destination),
                MOVEFILE_WRITE_THROUGH)) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "MoveFileExW write-through no-clobber protocol-file publication failed " +
                "(native_error=" + error + "; source=" + source +
                "; destination=" + destination + ")");
        }
    }
}
'@
}

function Get-AstroFsvProtocolStableProjection {
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][string]$CodePrefix
    )

    $schema = [string]$Record.schema
    switch ($schema) {
        'astrolabe.native-fsv-partial-lock-retirement.authorization.v1' {
            return [ordered]@{
                schema = $Record.schema; phase = $Record.phase; issue = $Record.issue
                tracker = $Record.tracker; fsv_lock = $Record.fsv_lock
                authorization_record_path = $Record.authorization_record_path
                completion_record_path = $Record.completion_record_path
                lifecycle_transition_path = $Record.lifecycle_transition_path
                receipt_path = $Record.receipt_path
                receipt_sha256 = $Record.receipt_sha256
                session_directory = $Record.session_directory
                artifact = $Record.artifact
                expected_controls = $Record.expected_controls
                outputs = $Record.outputs
                session_inventory = $Record.session_inventory
                launcher_recovery_chain = $Record.launcher_recovery_chain
                launcher_job_name = $Record.launcher_job.name
                owner_identities = $Record.owners.identities
                failure = $Record.failure
            }
        }
        'astrolabe.native-fsv-partial-lock-retirement.authorization.v2' {
            return [ordered]@{
                schema = $Record.schema; phase = $Record.phase; issue = $Record.issue
                tracker = $Record.tracker; fsv_lock = $Record.fsv_lock
                authorization_record_path = $Record.authorization_record_path
                completion_record_path = $Record.completion_record_path
                lifecycle_transition_path = $Record.lifecycle_transition_path
                receipt_path = $Record.receipt_path
                receipt_sha256 = $Record.receipt_sha256
                session_directory = $Record.session_directory
                artifact = $Record.artifact
                expected_controls = $Record.expected_controls
                outputs = $Record.outputs
                session_inventory = $Record.session_inventory
                launcher_terminal_chain = $Record.launcher_terminal_chain
                launcher_job_name = $Record.launcher_job.name
                owner_identities = $Record.owners.identities
                failure = $Record.failure
            }
        }
        'astrolabe.native-fsv-partial-lock-retirement.completion.v1' {
            return [ordered]@{
                schema = $Record.schema; phase = $Record.phase; issue = $Record.issue
                authorization = $Record.authorization; source = $Record.source
                archive = $Record.archive; session = $Record.session
            }
        }
        'astrolabe.native-fsv-interrupted-v2-lock-retirement.authorization.v1' {
            return [ordered]@{
                schema = $Record.schema; phase = $Record.phase; issue = $Record.issue
                tracker = $Record.tracker; fsv_lock = $Record.fsv_lock
                authorization_record_path = $Record.authorization_record_path
                completion_record_path = $Record.completion_record_path
                lifecycle_transition_path = $Record.lifecycle_transition_path
                receipt_path = $Record.receipt_path
                receipt_sha256 = $Record.receipt_sha256
                session_directory = $Record.session_directory
                artifact = $Record.artifact
                expected_controls = $Record.expected_controls
                live_state = $Record.live_state
                outputs = $Record.outputs
                session_inventory = $Record.session_inventory
                launcher_recovery_chain = $Record.launcher_recovery_chain
                launcher_job_name = $Record.launcher_job.name
                owner_identities = $Record.owners.identities
                failure = $Record.failure
            }
        }
        'astrolabe.native-fsv-interrupted-v2-lock-retirement.completion.v1' {
            return [ordered]@{
                schema = $Record.schema; phase = $Record.phase; issue = $Record.issue
                authorization = $Record.authorization; source = $Record.source
                archive = $Record.archive; session = $Record.session
            }
        }
        'astrolabe.native-fsv-terminal-partial-quarantine.authorization.v1' {
            return [ordered]@{
                schema = $Record.schema; phase = $Record.phase; issue = $Record.issue
                tracker = $Record.tracker; retirement = $Record.retirement
                receipt_path = $Record.receipt_path
                receipt_sha256 = $Record.receipt_sha256
                session_directory = $Record.session_directory
                session_tombstone_path = $Record.session_tombstone_path
                lifecycle_transition_path = $Record.lifecycle_transition_path
                authorization_record_path = $Record.authorization_record_path
                artifact = $Record.artifact
                expected_controls = $Record.expected_controls
                outputs = $Record.outputs
                session_inventory = $Record.session_inventory
                source_fsv_lock = $Record.source_of_truth.fsv_lock
                source_launcher_protocol = $Record.source_of_truth.launcher_protocol
                source_launcher_job_name = $Record.source_of_truth.launcher_job.name
                owner_identities = $Record.owners.identities
                failure = $Record.failure
                completion_record_path = $Record.completion_record_path
            }
        }
        'astrolabe.native-fsv-terminal-partial-quarantine.authorization.v2' {
            return [ordered]@{
                schema = $Record.schema; phase = $Record.phase; issue = $Record.issue
                tracker = $Record.tracker; retirement = $Record.retirement
                receipt_path = $Record.receipt_path
                receipt_sha256 = $Record.receipt_sha256
                session_directory = $Record.session_directory
                session_tombstone_path = $Record.session_tombstone_path
                lifecycle_transition_path = $Record.lifecycle_transition_path
                authorization_record_path = $Record.authorization_record_path
                artifact = $Record.artifact
                expected_controls = $Record.expected_controls
                outputs = $Record.outputs
                session_inventory = $Record.session_inventory
                source_fsv_lock = $Record.source_of_truth.fsv_lock
                source_launcher_protocol = $Record.source_of_truth.launcher_protocol
                source_launcher_job_name = $Record.source_of_truth.launcher_job.name
                owner_identities = $Record.owners.identities
                failure = $Record.failure
                completion_record_path = $Record.completion_record_path
            }
        }
        'astrolabe.native-fsv-terminal-partial-quarantine.completion.v1' {
            return [ordered]@{
                schema = $Record.schema; phase = $Record.phase; issue = $Record.issue
                authorization = $Record.authorization
                retirement_completion = $Record.retirement_completion
                session = $Record.session; tombstone = $Record.tombstone
                fsv_lock = $Record.fsv_lock
            }
        }
        default {
            Fail-Astro "${CodePrefix}_STAGE_SCHEMA_UNSUPPORTED" `
                "protocol publication has no stable projection for schema '$schema'" `
                'preserve the stage and add an exact schema-specific recovery projection'
        }
    }
}

function Publish-NewAstroFsvProtocolRecord {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$CodePrefix,
        [string]$StageDirectory = ''
    )

    $parent = Split-Path -Parent $Path
    New-AstroDirectoryLongPath $parent | Out-Null
    Assert-NotReparseEntry $parent "$CodePrefix record parent"
    if (Test-AstroPathLongPath -LiteralPath $Path) {
        Fail-Astro "${CodePrefix}_REUSE_REFUSED" `
            "protocol record already exists: $Path" `
            'resume the exact bound transaction; never overwrite an append-only protocol record'
    }
    $stageParent = if ([string]::IsNullOrWhiteSpace($StageDirectory)) {
        $parent
    } else {
        [IO.Path]::GetFullPath($StageDirectory)
    }
    New-AstroDirectoryLongPath $stageParent | Out-Null
    Assert-NotReparseEntry $stageParent "$CodePrefix publication-stage parent"
    $stage = Join-Path $stageParent (
        '.' + [IO.Path]::GetFileName($Path) + '.publishing.v1.json'
    )
    $published = $false
    $createdStage = $false
    try {
        $json = $Value | ConvertTo-Json -Depth 40
        $expectedBytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
        $expectedSha256 = Get-AstroByteSha256 $expectedBytes
        $stageState = Get-AstroFsvStrictPathState `
            $stage file "${CodePrefix}_STAGE_INVALID" `
            "$CodePrefix deterministic publication stage"
        if ($stageState.state -ceq 'absent') {
            Write-NewDurableUtf8 $stage $json
            $createdStage = $true
        }
        try { $stageReadback = Read-AstroUtf8FileLongPath $stage | ConvertFrom-Json }
        catch {
            Fail-Astro "${CodePrefix}_STAGE_INVALID" `
                "durable protocol stage cannot be parsed: $stage ($($_.Exception.Message))" `
                'preserve the stage and investigate the exact write/readback failure'
        }
        if ([string]$stageReadback.schema -cne [string]$Value.schema) {
            Fail-Astro "${CodePrefix}_STAGE_INVALID" `
                "durable protocol stage schema changed during readback: $stage" `
                'preserve the stage and investigate the exact write/readback failure'
        }
        $stageSha256 = File-Sha256 $stage
        if ($createdStage -and $stageSha256 -cne $expectedSha256) {
            Fail-Astro "${CodePrefix}_STAGE_INVALID" `
                "durable publication stage does not equal the requested exact bytes: $stage" `
                'preserve the stage and investigate durable-write drift'
        }
        if (-not $createdStage) {
            $stagedProjection = Get-AstroFsvProtocolStableProjection `
                $stageReadback $CodePrefix | ConvertTo-Json -Depth 40 -Compress
            $requestedProjection = Get-AstroFsvProtocolStableProjection `
                $Value $CodePrefix | ConvertTo-Json -Depth 40 -Compress
            if ($stagedProjection -cne $requestedProjection) {
                Fail-Astro "${CodePrefix}_STAGE_MISMATCH" `
                    "surviving deterministic stage is not the requested stable transaction: $stage" `
                    'preserve the stage and resume only the exact transaction whose stable bindings created it'
            }
        }
        [AstroFsvPublish]::PublishFile($stage, $Path)
        $published = $true
        $finalSha256 = File-Sha256 $Path
        if ($finalSha256 -cne $stageSha256) {
            Fail-Astro "${CodePrefix}_PUBLICATION_INVALID" `
                "published protocol record differs from its durable stage: $Path" `
                'preserve both namespaces and investigate the atomic publication boundary'
        }
        return [ordered]@{
            path = [IO.Path]::GetFullPath($Path)
            sha256 = $finalSha256
            value = Read-AstroUtf8FileLongPath $Path | ConvertFrom-Json
        }
    }
    finally {
        if ($createdStage -and -not $published -and
            (Test-AstroPathLongPath -LiteralPath $stage -PathType Leaf)) {
            # A caught failure removes only the exact stage created by this live
            # publisher. A hard-death stage is deterministic, blocks admission,
            # and is republished only by the byte-identical resumed transaction.
            Remove-AstroFileLongPath $stage
        }
    }
}

function Read-AstroFsvProcessIdentity {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    if ($null -eq $Object) {
        Fail-Astro $Code "$Description is absent" `
            'preserve the session and investigate its incomplete process provenance'
    }
    $properties = @($Object.PSObject.Properties | ForEach-Object Name)
    $required = @('pid', 'process_start_utc_ticks', 'process_started_utc')
    if ($properties.Count -ne $required.Count -or
        @($required | Where-Object { $properties -notcontains $_ }).Count -ne 0) {
        Fail-Astro $Code `
            "$Description must contain exactly pid, process_start_utc_ticks, process_started_utc" `
            'preserve the session; legacy, partial, and extended authority records require explicit schema handling'
    }
    $parsedPid = 0
    $parsedTicks = 0L
    if (-not [int]::TryParse(
            [string]$Object.pid,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsedPid
        ) -or $parsedPid -le 0 -or
        -not [long]::TryParse(
            [string]$Object.process_start_utc_ticks,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsedTicks
        ) -or $parsedTicks -le 0 -or
        $parsedTicks -gt [DateTime]::MaxValue.Ticks) {
        Fail-Astro $Code "$Description has an invalid PID or process-start UTC ticks" `
            'preserve the session and investigate its incomplete process provenance'
    }
    $expectedIso = ConvertTo-AstroProcessStartUtcIso $parsedTicks
    $startedValue = $Object.process_started_utc
    $startedMatches = if ($startedValue -is [DateTime]) {
        $startedValue.ToUniversalTime().Ticks -eq $parsedTicks
    }
    elseif ($startedValue -is [DateTimeOffset]) {
        $startedValue.UtcDateTime.Ticks -eq $parsedTicks
    }
    else {
        [string]::Equals(
            [string]$startedValue,
            $expectedIso,
            [StringComparison]::Ordinal
        )
    }
    if (-not $startedMatches) {
        Fail-Astro $Code `
            "$Description process_started_utc does not resolve to its exact UTC ticks" `
            'preserve the session and investigate identity byte drift'
    }
    return New-AstroProcessIdentityRecord $parsedPid $parsedTicks
}

function New-AstroFsvOwnerBinding {
    param(
        [Parameter(Mandatory)][string]$Role,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)]$Identity
    )

    return [pscustomobject]@{
        Role = $Role
        Source = $Source
        Identity = $Identity
    }
}

function Test-AstroFsvIdentityEqual {
    param(
        [Parameter(Mandatory)]$Left,
        [Parameter(Mandatory)]$Right
    )

    return [int]$Left.pid -eq [int]$Right.pid -and
        [long]$Left.process_start_utc_ticks -eq
            [long]$Right.process_start_utc_ticks
}

function Read-AstroFsvV3ProcessEntries {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]$Entries,
        [Parameter(Mandatory)][int]$ResidentCount,
        [Parameter(Mandatory)][int]$ProcessCount,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )
    if ($ResidentCount -lt 2 -or $ResidentCount -gt 16 -or
        $ProcessCount -lt 0 -or $ProcessCount -gt ($ResidentCount + 1) -or
        $Entries -isnot [Array] -or $Entries.Count -ne $ProcessCount) {
        Fail-Astro $Code `
            "$Description has invalid v3 resident/process cardinality (resident_count=$ResidentCount; process_count=$ProcessCount; entries=$($Entries.Count))" `
            'preserve the session and investigate incomplete multi-process provenance'
    }
    $roleOrdinals = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $identities = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $result = New-Object System.Collections.Generic.List[object]
    foreach ($entry in $Entries) {
        if ($null -eq $entry -or
            -not $entry.PSObject.Properties['role'] -or
            -not $entry.PSObject.Properties['ordinal'] -or
            -not $entry.PSObject.Properties['identity']) {
            Fail-Astro $Code "$Description contains a process entry without role/ordinal/identity" `
                'preserve the session and investigate incomplete multi-process provenance'
        }
        $role = [string]$entry.role
        $ordinal = [int]$entry.ordinal
        $validRole = ($role -ceq 'indexer' -and $ordinal -eq 0) -or
            ($role -ceq 'resident' -and $ordinal -ge 1 -and
                $ordinal -le $ResidentCount)
        $identity = Read-AstroFsvProcessIdentity $entry.identity $Code `
            "$Description $role/$ordinal identity"
        $roleOrdinal = "$role/$ordinal"
        $identityKey = "$($identity.pid)/$($identity.process_start_utc_ticks)"
        if (-not $validRole -or -not $roleOrdinals.Add($roleOrdinal) -or
            -not $identities.Add($identityKey)) {
            Fail-Astro $Code `
                "$Description contains an invalid or duplicate role/process generation (role=$role; ordinal=$ordinal; identity=$identityKey)" `
                'preserve the session and investigate incomplete multi-process provenance'
        }
        $result.Add([pscustomobject][ordered]@{
            role = $role
            ordinal = $ordinal
            identity = $identity
        })
    }
    if ($ProcessCount -eq ($ResidentCount + 1) -and
        (@($result | Where-Object role -ceq 'indexer').Count -ne 1 -or
         @($result | Where-Object role -ceq 'resident').Count -ne $ResidentCount)) {
        Fail-Astro $Code "$Description complete v3 process set has invalid role cardinality" `
            'preserve the session and investigate incomplete multi-process provenance'
    }
    return ,([object[]]@($result | Sort-Object role, ordinal))
}

function Read-AstroFsvTerminalPartialPreLiveProcesses {
    param(
        [Parameter(Mandatory)]$LockState,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    $residentCount = [int]$LockState.resident_count
    $processCount = [int]$LockState.process_count
    $processes = Read-AstroFsvV3ProcessEntries `
        $LockState.owners.processes $residentCount $processCount $Code $Description
    $phase = [string]$LockState.phase
    if ($phase -ceq 'creating') {
        if ($processCount -lt 1 -or $processCount -gt $residentCount -or
            @($processes | Where-Object { [string]$_.role -cne 'resident' }).Count -ne 0) {
            Fail-Astro $Code `
                "$Description creating phase does not contain one contiguous resident prefix" `
                'preserve the terminal-partial lock and investigate its publisher'
        }
        for ($ordinal = 1; $ordinal -le $processCount; $ordinal++) {
            if (@($processes | Where-Object {
                        [string]$_.role -ceq 'resident' -and
                        [int]$_.ordinal -eq $ordinal
                    }).Count -ne 1) {
                Fail-Astro $Code `
                    "$Description creating phase omits resident ordinal $ordinal" `
                    'preserve the terminal-partial lock and investigate its publisher'
            }
        }
    }
    elseif ($phase -ceq 'suspended') {
        if ($processCount -ne ($residentCount + 1) -or
            @($processes | Where-Object { [string]$_.role -ceq 'resident' }).Count -ne
                $residentCount -or
            @($processes | Where-Object {
                    [string]$_.role -ceq 'indexer' -and [int]$_.ordinal -eq 0
                }).Count -ne 1) {
            Fail-Astro $Code `
                "$Description suspended phase is not the complete resident-plus-indexer set" `
                'preserve the terminal-partial lock and investigate its publisher'
        }
    }
    else {
        Fail-Astro $Code `
            "$Description phase '$phase' is not a terminal-partial pre-live phase" `
            'use Abandon for claimed state and normal Cleanup/Quarantine for a published live generation'
    }
    return ,([object[]]$processes)
}

function Test-AstroFsvV3ProcessEntriesEqual {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Left,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Right
    )
    if ($Left.Count -ne $Right.Count) { return $false }
    for ($index = 0; $index -lt $Left.Count; $index++) {
        if ([string]$Left[$index].role -cne [string]$Right[$index].role -or
            [int]$Left[$index].ordinal -ne [int]$Right[$index].ordinal -or
            -not (Test-AstroFsvIdentityEqual `
                $Left[$index].identity $Right[$index].identity)) {
            return $false
        }
    }
    return $true
}

function Add-AstroFsvV3ProcessBindings {
    param(
        [Parameter(Mandatory)]$Bindings,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Processes,
        [Parameter(Mandatory)][string]$Source
    )
    foreach ($process in $Processes) {
        $Bindings.Add((New-AstroFsvOwnerBinding `
            ("{0}-{1}" -f $process.role,$process.ordinal) `
            $Source $process.identity))
    }
}

function Get-AstroFsvOwnerProbes {
    param([Parameter(Mandatory)][object[]]$Bindings)

    $probes = foreach ($binding in $Bindings) {
        $identity = $binding.Identity
        $probe = Get-AstroExactProcessIdentityProbe `
            -Pid ([int]$identity.pid) `
            -ProcessStartUtcTicks ([long]$identity.process_start_utc_ticks)
        [ordered]@{
            role = [string]$binding.Role
            source = [string]$binding.Source
            identity = $identity
            state = $probe.State
            numeric_pid_live = $probe.NumericPidLive
            exact_owner_live = $probe.ExactOwnerLive
            pid_reused = $probe.PidReused
            observed_process_start_utc_ticks =
                $probe.ObservedProcessStartUtcTicks
            observed_process_started_utc =
                $probe.ObservedProcessStartedUtc
            observed_at_utc = $probe.ObservedAtUtc
            error = $probe.Error
        }
    }
    return @($probes)
}

function Assert-AstroFsvOwnersInactive {
    param(
        [Parameter(Mandatory)][object[]]$Bindings,
        [Parameter(Mandatory)][string]$CodePrefix,
        [Parameter(Mandatory)][string]$Description
    )

    $probes = @(Get-AstroFsvOwnerProbes $Bindings)
    $live = @($probes | Where-Object { $_.state -ceq 'exact-live' })
    if ($live.Count -gt 0) {
        Fail-Astro "${CodePrefix}_LIVE_OWNER" `
            "$Description retains exact-live owner(s): $($live | ConvertTo-Json -Depth 8 -Compress)" `
            'wait for every exact recorded process generation to exit naturally'
    }
    $unevaluable = @($probes | Where-Object { $_.state -ceq 'unevaluable' })
    if ($unevaluable.Count -gt 0) {
        Fail-Astro "${CodePrefix}_OWNER_UNEVALUABLE" `
            "$Description has unevaluable owner state: $($unevaluable | ConvertTo-Json -Depth 8 -Compress)" `
            'preserve every byte and retry only when exact process identity is readable'
    }
    return $probes
}

function Assert-AstroFsvPersistedOwnerEnvelope {
    param(
        [Parameter(Mandatory)]$Owners,
        [Parameter(Mandatory)][object[]]$ExpectedBindings,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    if ($null -eq $Owners -or
        -not $Owners.PSObject.Properties['identities'] -or
        -not $Owners.PSObject.Properties['initial_probes'] -or
        -not $Owners.PSObject.Properties['final_probes']) {
        Fail-Astro $Code `
            "$Description omits its identities or authorization probes" `
            'preserve both session and external record and investigate the durable-write mismatch'
    }
    $persistedIdentities = @($Owners.identities)
    $initialProbes = @($Owners.initial_probes)
    $finalProbes = @($Owners.final_probes)
    if ($persistedIdentities.Count -ne $ExpectedBindings.Count -or
        $initialProbes.Count -ne $ExpectedBindings.Count -or
        $finalProbes.Count -ne $ExpectedBindings.Count) {
        Fail-Astro $Code `
            "$Description owner/probe cardinality differs from the authorization set" `
            'preserve both session and external record and investigate the durable-write mismatch'
    }
    for ($index = 0; $index -lt $ExpectedBindings.Count; $index++) {
        $expected = $ExpectedBindings[$index]
        $persisted = $persistedIdentities[$index]
        $persistedIdentity = Read-AstroFsvProcessIdentity `
            $persisted.identity $Code `
            "$Description persisted owner identity $index"
        if ([string]$persisted.role -cne [string]$expected.Role -or
            [string]$persisted.source -cne [string]$expected.Source -or
            -not (Test-AstroFsvIdentityEqual `
                $persistedIdentity $expected.Identity)) {
            Fail-Astro $Code `
                "$Description persisted owner identity $index differs from the authorization set" `
                'preserve both session and external record and investigate the durable-write mismatch'
        }
        foreach ($probeSet in @($initialProbes, $finalProbes)) {
            $persistedProbe = $probeSet[$index]
            $probeIdentity = Read-AstroFsvProcessIdentity `
                $persistedProbe.identity $Code `
                "$Description persisted owner probe identity $index"
            if ([string]$persistedProbe.role -cne
                    [string]$expected.Role -or
                [string]$persistedProbe.source -cne
                    [string]$expected.Source -or
                -not (Test-AstroFsvIdentityEqual `
                    $probeIdentity $expected.Identity) -or
                [string]$persistedProbe.state -notin
                    @('absent', 'pid-reused')) {
                Fail-Astro $Code `
                    "$Description persisted owner probe $index differs from its inactive authorization" `
                    'preserve both session and external record and investigate the durable-write mismatch'
            }
        }
    }
}

function Get-AstroCurrentProcessIdentity {
    param(
        [Parameter(Mandatory)]
        [Alias('Pid')]
        [int]$ProcessId,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    $probe = Get-AstroProcessIdentityProbe -OwnerPid $ProcessId
    if ($probe.State -cne 'observed') {
        Fail-Astro $Code `
            "$Description process identity is '$($probe.State)': $($probe.Error)" `
            'preserve state and retry only when the live process creation time is readable'
    }
    return New-AstroProcessIdentityRecord `
        $ProcessId ([long]$probe.ProcessStartUtcTicks)
}

function Invoke-AstroFsvGhJson {
    param([Parameter(Mandatory)][string]$ApiPath)

    $gh = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $gh) {
        Fail-Astro 'ASTRO_FSV_MIGRATION_GH_MISSING' `
            'authenticated GitHub CLI is unavailable' `
            'restore authenticated gh access; no legacy session bytes were authorized for removal'
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
        Fail-Astro 'ASTRO_FSV_MIGRATION_GH_READ_FAILED' `
            $_.Exception.Message `
            'repair authenticated GitHub access; no legacy session bytes were authorized for removal'
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Read-AstroFsvExactJsonFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-AstroPathLongPath -LiteralPath $full -PathType Leaf)) {
        Fail-Astro $Code "$Description is absent: $full" `
            'preserve the lifecycle state and supply the exact durable record path'
    }
    Assert-NotReparseEntry $full $Description
    try { $value = Read-AstroUtf8FileLongPath $full | ConvertFrom-Json }
    catch {
        Fail-Astro $Code "$Description is unreadable: $full ($($_.Exception.Message))" `
            'preserve the lifecycle state and investigate the exact durable bytes'
    }
    return [ordered]@{
        path = $full
        bytes = [uint64](Get-AstroFileInfoLongPath $full).Length
        sha256 = File-Sha256 $full
        value = $value
    }
}

function Get-AstroFsvStrictPathState {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('file', 'directory')][string]$ExpectedKind,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )
    $full = [IO.Path]::GetFullPath($Path)
    $state = Get-AstroPathEntryState $full
    if ($state.State -ceq 'absent') {
        return [ordered]@{ path = $full; state = 'absent'; attributes = $null }
    }
    if ($state.State -cne 'present') {
        Fail-Astro $Code "$Description is unevaluable: $full ($($state.Error))" `
            'preserve every namespace and repair the exact filesystem probe failure'
    }
    if (($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Astro $Code "$Description is a reparse point: $full" `
            'preserve the namespace object; lifecycle authority requires an ordinary entry'
    }
    $isDirectory = ($state.Attributes -band [IO.FileAttributes]::Directory) -ne 0
    if (($ExpectedKind -ceq 'directory') -ne $isDirectory) {
        Fail-Astro $Code "$Description is present with the wrong entry kind: $full" `
            'preserve the namespace and investigate the unexpected file/directory collision'
    }
    return [ordered]@{
        path = $full
        state = 'present'
        attributes = [uint32]$state.Attributes
    }
}

function ConvertFrom-AstroFsvPersistedInventoryEntries {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]$Entries,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    if ($Entries -isnot [Array]) {
        Fail-Astro $Code "$Description entries are not an array" `
            'preserve the transition and investigate malformed inventory authority'
    }
    $expectedFields = @(
        'relative_path', 'kind', 'file_id', 'attributes', 'bytes', 'sha256'
    )
    $typed = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $Entries.Count; $index++) {
        $entry = $Entries[$index]
        if ($null -eq $entry) {
            Fail-Astro $Code "$Description entry $index is null" `
                'preserve the transition and investigate malformed inventory authority'
        }
        $actualFields = @($entry.PSObject.Properties | ForEach-Object Name)
        if ($actualFields.Count -ne $expectedFields.Count -or
            @($expectedFields | Where-Object { $actualFields -cnotcontains $_ }).Count -ne 0) {
            Fail-Astro $Code "$Description entry $index has a noncanonical field set" `
                'preserve the transition and investigate malformed inventory authority'
        }
        $attributesText = [Convert]::ToString(
            $entry.attributes, [Globalization.CultureInfo]::InvariantCulture
        )
        [uint64]$attributesWide = 0
        if ($entry.attributes -isnot [sbyte] -and
            $entry.attributes -isnot [byte] -and
            $entry.attributes -isnot [int16] -and
            $entry.attributes -isnot [uint16] -and
            $entry.attributes -isnot [int32] -and
            $entry.attributes -isnot [uint32] -and
            $entry.attributes -isnot [int64] -and
            $entry.attributes -isnot [uint64]) {
            Fail-Astro $Code "$Description entry $index attributes are not an integral JSON value" `
                'preserve the transition and investigate malformed inventory authority'
        }
        if ($attributesText -cnotmatch '^(0|[1-9][0-9]{0,9})$' -or
            -not [uint64]::TryParse(
                $attributesText,
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$attributesWide
            ) -or $attributesWide -gt [uint32]::MaxValue) {
            Fail-Astro $Code "$Description entry $index attributes exceed UInt32" `
                'preserve the transition and investigate malformed inventory authority'
        }
        $typedBytes = $null
        if ($null -ne $entry.bytes) {
            $bytesText = [Convert]::ToString(
                $entry.bytes, [Globalization.CultureInfo]::InvariantCulture
            )
            [uint64]$bytesWide = 0
            if (($entry.bytes -isnot [sbyte] -and
                    $entry.bytes -isnot [byte] -and
                    $entry.bytes -isnot [int16] -and
                    $entry.bytes -isnot [uint16] -and
                    $entry.bytes -isnot [int32] -and
                    $entry.bytes -isnot [uint32] -and
                    $entry.bytes -isnot [int64] -and
                    $entry.bytes -isnot [uint64]) -or
                $bytesText -cnotmatch '^(0|[1-9][0-9]{0,19})$' -or
                -not [uint64]::TryParse(
                    $bytesText,
                    [Globalization.NumberStyles]::None,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [ref]$bytesWide
                )) {
                Fail-Astro $Code "$Description entry $index bytes are not UInt64" `
                    'preserve the transition and investigate malformed inventory authority'
            }
            $typedBytes = [uint64]$bytesWide
        }
        $typed.Add([ordered]@{
            relative_path = $entry.relative_path
            kind = $entry.kind
            file_id = $entry.file_id
            attributes = [uint32]$attributesWide
            bytes = $typedBytes
            sha256 = $entry.sha256
        })
    }
    return ,([object[]]$typed.ToArray())
}

function Assert-AstroFsvPersistedAbsentJobProbe {
    param(
        [Parameter(Mandatory)]$Probe,
        [Parameter(Mandatory)][string]$ExpectedName,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )
    $expectedFields = @(
        'Name', 'State', 'ProcessIds', 'NativeErrorCode',
        'NumberOfAssignedProcesses', 'NumberOfProcessIdsInList', 'Error'
    )
    $actualFields = if ($null -eq $Probe) { @() } else {
        @($Probe.PSObject.Properties | ForEach-Object Name)
    }
    if ($null -eq $Probe -or
        $actualFields.Count -ne $expectedFields.Count -or
        @($expectedFields | Where-Object { $actualFields -cnotcontains $_ }).Count -ne 0 -or
        [string]$Probe.Name -cne $ExpectedName -or
        [string]$Probe.State -cne 'absent' -or
        @($Probe.ProcessIds).Count -ne 0 -or
        [int]$Probe.NativeErrorCode -ne 2 -or
        [uint64]$Probe.NumberOfAssignedProcesses -ne 0 -or
        [uint64]$Probe.NumberOfProcessIdsInList -ne 0 -or
        $null -ne $Probe.Error) {
        Fail-Astro $Code "$Description is not an exact absent Job probe for '$ExpectedName'" `
            'preserve the transaction and investigate malformed durable Job evidence'
    }
}

function Assert-AstroFsvPersistedRecoveryJobProbes {
    param(
        [Parameter(Mandatory)]$Persisted,
        [Parameter(Mandatory)]$LauncherRecoveryChain,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )
    $initial = @($Persisted.initial)
    $final = @($Persisted.final)
    $archives = @($LauncherRecoveryChain.archives)
    if ($initial.Count -ne $archives.Count -or $final.Count -ne $archives.Count) {
        Fail-Astro $Code "$Description Job-probe cardinality differs from the recovery chain" `
            'preserve the transaction and investigate malformed durable Job evidence'
    }
    for ($index = 0; $index -lt $archives.Count; $index++) {
        $name = [string]$archives[$index].job_name
        Assert-AstroFsvPersistedAbsentJobProbe `
            $initial[$index] $name $Code "$Description initial probe $index"
        Assert-AstroFsvPersistedAbsentJobProbe `
            $final[$index] $name $Code "$Description final probe $index"
    }
}

function Assert-AstroFsvLinkedFile {
    param(
        [Parameter(Mandatory)]$Link,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )
    if ($null -eq $Link -or
        -not $Link.PSObject.Properties['path'] -or
        -not $Link.PSObject.Properties['sha256']) {
        Fail-Astro $Code "$Description link is missing path/SHA-256" `
            'preserve the record chain and investigate the malformed durable link'
    }
    $record = Read-AstroFsvExactJsonFile `
        -Path ([string]$Link.path) -Code $Code -Description $Description
    if ([string]$record.sha256 -cne [string]$Link.sha256) {
        Fail-Astro $Code "$Description SHA-256 differs from its durable link" `
            'preserve the complete record chain and investigate byte drift'
    }
    if ($Link.PSObject.Properties['bytes'] -and
        [uint64]$Link.bytes -ne [uint64]$record.bytes) {
        Fail-Astro $Code "$Description byte count differs from its durable link" `
            'preserve the complete record chain and investigate byte drift'
    }
    return $record
}

function Read-AstroFsvLauncherRecoveryChain {
    param(
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][string]$Workspace,
        [Parameter(Mandatory)][string]$LauncherRecoveryPath,
        [Parameter(Mandatory)][string]$TargetRecoveryPath,
        [Parameter(Mandatory)][string[]]$ArchiveCompletionPaths
    )
    $code = 'ASTRO_FSV_PARTIAL_LOCK_LAUNCHER_RECOVERY_INVALID'
    if ([string]::IsNullOrWhiteSpace($LauncherRecoveryPath) -or
        [string]::IsNullOrWhiteSpace($TargetRecoveryPath) -or
        $ArchiveCompletionPaths.Count -eq 0) {
        Fail-Astro $code `
            'launcher-lock, target-recovery, and launcher-pair completion paths are all required' `
            'supply the exact durable completion chain that made target and launcher protocol absent'
    }
    $tmpRoot = Join-Path $Workspace '.tmp'
    $launcherPath = Assert-PathWithin $LauncherRecoveryPath $tmpRoot $code `
        'launcher-lock recovery completion path'
    $targetPath = Assert-PathWithin $TargetRecoveryPath $tmpRoot $code `
        'target recovery completion path'
    $launcher = Read-AstroFsvExactJsonFile $launcherPath $code `
        'launcher-lock recovery completion'
    if ([string]$launcher.value.schema -cne
            'astrolabe.launcher-lock-recovery.completion.v6' -or
        [string]$launcher.value.phase -cne
            'source-archive-committed-marker-archive-authorized' -or
        [string]$launcher.value.expected_final_protocol.active_state -cne 'absent' -or
        @($launcher.value.expected_final_protocol.transition_paths).Count -ne 0) {
        Fail-Astro $code 'launcher-lock recovery completion is not terminal protocol absence' `
            'complete the exact launcher recovery before FSV lifecycle recovery'
    }
    $launcherAuthorization = Assert-AstroFsvLinkedFile `
        -Link $launcher.value.authorization -Code $code `
        -Description 'launcher-lock recovery authorization'
    $target = Read-AstroFsvExactJsonFile $targetPath $code `
        'preserved-target recovery completion'
    if ([string]$target.value.schema -cne
            'astrolabe.preserved-target-recovery.completion.v1' -or
        [string]$target.value.phase -cne 'complete-target-absent' -or
        [string]$target.value.target.state -cne 'absent' -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$target.value.target.path),
            (Join-Path $Workspace 'target'),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-Astro $code 'preserved-target recovery completion does not bind canonical target absence' `
            'complete hash-bound target recovery before FSV lifecycle recovery'
    }
    $targetAuthorization = Assert-AstroFsvLinkedFile `
        -Link $target.value.authorization -Code $code `
        -Description 'preserved-target recovery authorization'
    [void](Assert-AstroFsvLinkedFile `
        -Link $target.value.finalization -Code $code `
        -Description 'preserved-target recovery finalization')
    if ([string]$targetAuthorization.value.schema -cne
            'astrolabe.preserved-target-recovery.authorization.v1' -or
        [int]$targetAuthorization.value.owner.issue -ne $ExpectedIssue -or
        [string]$targetAuthorization.value.prior_recovery_transaction_id -cne
            [string]$launcher.value.transaction_id) {
        Fail-Astro $code 'target recovery does not descend from the exact launcher recovery/issue' `
            'supply the target-recovery completion authorized by this launcher-lock recovery'
    }
    $rootIdentity = [AstroLauncherLockNative]::GetDirectoryIdentity($Workspace)
    if ([string]$launcherAuthorization.value.mutex.root_identity -cne $rootIdentity) {
        Fail-Astro $code 'launcher recovery workspace identity differs from the canonical retained root' `
            'preserve all records and use only the canonical checkout that authored them'
    }
    $requiredGenerations = @{}
    $launcherEvidence = $launcherAuthorization.value.tracker.evidence
    foreach ($generation in @(
        [ordered]@{
            pid = [int]$launcherEvidence.expected_pid
            ticks = [long]$launcherEvidence.expected_owner_process_start_utc_ticks
            lock_sha256 = [string]$launcherEvidence.lock_sha256
        },
        [ordered]@{
            pid = [int]$targetAuthorization.value.owner.pid
            ticks = [long]$targetAuthorization.value.owner.owner_process_start_utc_ticks
            lock_sha256 = [string]$targetAuthorization.value.owner.launcher_lock_sha256
        }
    )) {
        $key = "$($generation.pid)|$($generation.ticks)|$($generation.lock_sha256)"
        $requiredGenerations[$key] = $generation
    }
    $archives = [Collections.Generic.List[object]]::new()
    $observedGenerations = @{}
    foreach ($archiveInput in @($ArchiveCompletionPaths)) {
        $archivePath = Assert-PathWithin $archiveInput $tmpRoot $code `
            'launcher-pair archive completion path'
        $archive = Read-AstroFsvExactJsonFile $archivePath $code `
            'launcher-pair archive completion'
        if ([string]$archive.value.schema -cne
                'astrolabe.launcher-state-archive.completion.v2' -or
            [string]$archive.value.temp_integrity.state -cne 'stable-exact' -or
            [string]$archive.value.terminal.temp_source_state -cne 'absent' -or
            [string]$archive.value.terminal.manifest_source_state -cne 'absent') {
            Fail-Astro $code 'launcher-pair archive completion is not stable exact source absence' `
                'complete exact launcher pair archival before FSV lifecycle recovery'
        }
        $archiveAuthorization = Assert-AstroFsvLinkedFile `
            -Link $archive.value.authorization -Code $code `
            -Description 'launcher-pair archive authorization'
        $manifest = Read-AstroFsvExactJsonFile `
            -Path ([string]$archive.value.terminal.manifest.path) -Code $code `
            -Description 'archived launcher attribution manifest'
        if ([string]$manifest.sha256 -cne
                [string]$archive.value.terminal.manifest.sha256 -or
            [string]$archiveAuthorization.value.schema -cne
                'astrolabe.launcher-state-archive.authorization.v2' -or
            [int]$archiveAuthorization.value.authority.driving_issue -ne $ExpectedIssue) {
            Fail-Astro $code 'launcher-pair archive authorization/manifest chain is inconsistent' `
                'preserve the archive and supply only its exact completion record'
        }
        $generation = $archiveAuthorization.value.generation
        $key = "$([int]$generation.launcher_pid)|$([long]$generation.launcher_process_start_utc_ticks)|$([string]$generation.launcher_lock_sha256)"
        if ($observedGenerations.ContainsKey($key)) {
            Fail-Astro $code "duplicate launcher archive generation supplied: $key" `
                'supply each exact required launcher generation once'
        }
        $derivedJob = Get-AstroLauncherTreeJobObjectName `
            -RootIdentity $rootIdentity `
            -LauncherPid ([int]$generation.launcher_pid) `
            -LauncherProcessStartUtcTicks ([long]$generation.launcher_process_start_utc_ticks) `
            -LauncherLeaseStartUtcTicks ([long]$manifest.value.launcher_lease_start_utc_ticks) `
            -LauncherLockSha256 ([string]$generation.launcher_lock_sha256)
        if ([string]$manifest.value.schema -cne 'astrolabe.no_escape_attribution.v3' -or
            [string]$manifest.value.job_object_name -cne $derivedJob -or
            [string]$generation.job_object_name -cne $derivedJob -or
            [int]$manifest.value.launcher_pid -ne [int]$generation.launcher_pid -or
            [long]$manifest.value.launcher_process_start_utc_ticks -ne
                [long]$generation.launcher_process_start_utc_ticks -or
            [string]$manifest.value.launcher_lock_sha256 -cne
                [string]$generation.launcher_lock_sha256) {
            Fail-Astro $code 'archived launcher manifest does not reproduce its deterministic Job/generation' `
                'preserve the archive and investigate the malformed generation binding'
        }
        $sourceTempPresent = Test-AstroPathLongPath -LiteralPath `
            ([string]$archiveAuthorization.value.source.temp.path)
        $sourceManifestPresent = Test-AstroPathLongPath -LiteralPath `
            ([string]$archiveAuthorization.value.source.manifest.path)
        if ($sourceTempPresent -or $sourceManifestPresent) {
            Fail-Astro $code 'a launcher pair archive source namespace has reappeared' `
                'preserve all state and reconcile the unexpected source before FSV recovery'
        }
        $observedGenerations[$key] = $true
        $archives.Add([ordered]@{
            completion = $archive
            authorization = $archiveAuthorization
            manifest = $manifest
            generation_key = $key
            job_name = $derivedJob
        })
    }
    if ($observedGenerations.Count -ne $requiredGenerations.Count -or
        @($requiredGenerations.Keys | Where-Object {
                -not $observedGenerations.ContainsKey($_)
            }).Count -ne 0) {
        Fail-Astro $code 'launcher archive set does not equal the exact recovery generation set' `
            'supply the original dead generation and every launcher generation used by target recovery'
    }
    if (Test-AstroPathLongPath -LiteralPath (Join-Path $Workspace 'target')) {
        Fail-Astro $code 'canonical target exists after its bound recovery completion' `
            'preserve it and complete the tracker-bound target lifecycle before FSV recovery'
    }
    $launcherProtocol = Read-AstroLauncherLock `
        -LockPath (Join-Path $tmpRoot 'astrolabe-launcher.lock')
    if ($launcherProtocol.State -ne 'absent') {
        Fail-Astro $code "launcher protocol is '$($launcherProtocol.State)' after recovery" `
            'complete the exact launcher lifecycle before FSV recovery'
    }
    return [ordered]@{
        kind = 'DeadOwnerRecoveryV1'
        launcher_recovery = $launcher
        launcher_recovery_authorization = $launcherAuthorization
        target_recovery = $target
        target_recovery_authorization = $targetAuthorization
        archives = [object[]]$archives.ToArray()
        required_generations = $requiredGenerations
        root_identity = $rootIdentity
    }
}

function Read-AstroFsvLauncherNormalCleanupChain {
    param(
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][string]$Workspace,
        [Parameter(Mandatory)][string]$ArchiveCompletionPath
    )

    $code = 'ASTRO_FSV_PARTIAL_LOCK_NORMAL_CLEANUP_INVALID'
    if ([string]::IsNullOrWhiteSpace($ArchiveCompletionPath)) {
        Fail-Astro $code `
            'normal live-owner cleanup requires its exact launcher archive completion path' `
            'supply the completion from the exact live-owner launcher generation'
    }
    $tmpRoot = Join-Path $Workspace '.tmp'
    $completionPath = Assert-PathWithin $ArchiveCompletionPath $tmpRoot $code `
        'normal live-owner launcher archive completion'
    $completion = Read-AstroFsvExactJsonFile $completionPath $code `
        'normal live-owner launcher archive completion'
    if ([string]$completion.value.schema -cne
            'astrolabe.launcher-state-archive.completion.v2' -or
        [string]$completion.value.temp_integrity.state -cne 'stable-exact' -or
        [string]$completion.value.terminal.temp_source_state -cne 'absent' -or
        [string]$completion.value.terminal.manifest_source_state -cne 'absent' -or
        [string]$completion.value.terminal.temp.inventory_state -cne 'exact') {
        Fail-Astro $code `
            'launcher archive completion is not one stable exact terminal live-owner archive' `
            'preserve the FSV generation and supply its exact completed launcher archive'
    }
    $authorization = Assert-AstroFsvLinkedFile `
        -Link $completion.value.authorization -Code $code `
        -Description 'normal live-owner launcher archive authorization'
    if ([string]$authorization.value.schema -cne
            'astrolabe.launcher-state-archive.authorization.v2' -or
        [string]$authorization.value.transaction_id -cne
            [string]$completion.value.transaction_id -or
        [string]$authorization.value.authority.mode -cne 'live-owner' -or
        [int]$authorization.value.authority.driving_issue -ne $ExpectedIssue -or
        -not [string]::IsNullOrEmpty(
            [string]$authorization.value.authority.tracker_comment_url) -or
        [string]$authorization.value.policy.destructive_authority -cne 'none' -or
        [string]$authorization.value.policy.snapshot_role -cne
            'diagnostic-observation-only' -or
        [string]$authorization.value.policy.namespace_operation -cne
            'same-volume-retained-handle-no-replace-rename' -or
        [string]$authorization.value.policy.concurrent_change_policy -cne
            'preserve-and-classify' -or
        [string]$authorization.value.policy.ambiguous_state_policy -cne
            'preserve-and-report' -or
        [string]$completion.value.policy.destructive_authority -cne 'none' -or
        [string]$completion.value.policy.snapshot_role -cne
            'diagnostic-observation-only' -or
        [string]$completion.value.policy.namespace_operation -cne
            'same-volume-retained-handle-no-replace-rename' -or
        [string]$completion.value.policy.concurrent_change_policy -cne
            'preserve-and-classify' -or
        [string]$completion.value.policy.ambiguous_state_policy -cne
            'preserve-and-report') {
        Fail-Astro $code `
            'launcher archive authorization is not the exact normal live-owner generation' `
            'preserve the chain and reject tracker-reclaim or mixed-issue archive authority'
    }

    $transactionDirectory = [IO.Path]::GetFullPath(
        (Split-Path -Parent $completion.path)
    )
    $archiveRoot = [IO.Path]::GetFullPath(
        (Join-Path $tmpRoot 'launcher-state-archive')
    )
    if (-not [string]::Equals(
            (Split-Path -Parent $authorization.path),
            $transactionDirectory,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath(
                [string]$authorization.value.archive.root_path),
            $archiveRoot,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath(
                [string]$authorization.value.archive.transaction_path),
            $transactionDirectory,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string][AstroLauncherLockNative]::GetDirectoryIdentity($archiveRoot) -cne
            [string]$authorization.value.archive.root_file_id -or
        [string][AstroLauncherLockNative]::GetDirectoryIdentity(
            $transactionDirectory) -cne
            [string]$authorization.value.archive.transaction_file_id -or
        [IO.Path]::GetFileName($authorization.path) -cne 'authorization.json' -or
        [IO.Path]::GetFileName($completion.path) -cne 'completion.json' -or
        [string](Get-AstroFsvExactFileIdentity $authorization.path) -cne
            [string]$completion.value.authorization.file_id) {
        Fail-Astro $code `
            'launcher archive authorization path/FILE_ID is not the exact transaction child' `
            'preserve the archive and investigate namespace or hard-link drift'
    }
    foreach ($comparisonName in @(
            'authorization_to_rename', 'rename_operation',
            'rename_to_completion', 'authorization_to_completion'
        )) {
        if ([string]$completion.value.temp_integrity.comparisons.$comparisonName.state -cne
            'stable-exact') {
            Fail-Astro $code `
                "launcher archive TEMP comparison '$comparisonName' is not stable-exact" `
                'preserve the archive and investigate the exact retained-handle rename chain'
        }
    }
    $archiveTemp = Assert-PathWithin `
        ([string]$completion.value.terminal.temp.path) $transactionDirectory $code `
        'archived normal live-owner TEMP root'
    $archiveManifestPath = Assert-PathWithin `
        ([string]$completion.value.terminal.manifest.path) $transactionDirectory $code `
        'archived normal live-owner attribution manifest'
    foreach ($pair in @(
            @([string]$authorization.value.archive.transaction_path,
                $transactionDirectory),
            @([string]$authorization.value.archive.temp_destination, $archiveTemp),
            @([string]$authorization.value.archive.manifest_destination,
                $archiveManifestPath)
        )) {
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath([string]$pair[0]),
                [IO.Path]::GetFullPath([string]$pair[1]),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro $code `
                'launcher archive authorization destinations differ from completion namespaces' `
                'preserve the archive and investigate the mixed transaction'
        }
    }
    $archiveTempState = Get-AstroFsvStrictPathState `
        $archiveTemp directory $code 'archived normal live-owner TEMP root'
    if ($archiveTempState.state -cne 'present' -or
        [string][AstroLauncherLockNative]::GetDirectoryIdentity($archiveTemp) -cne
            [string]$completion.value.terminal.temp.root_file_id -or
        [string]$authorization.value.source.temp.root_file_id -cne
            [string]$completion.value.terminal.temp.root_file_id) {
        Fail-Astro $code `
            'archived normal live-owner TEMP root identity differs from its durable chain' `
            'preserve the archive and investigate namespace or FILE_ID drift'
    }
    if (-not (Get-Command Get-AstroLauncherTempArchiveSnapshot `
            -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'launcher-state-archive.ps1')
    }
    $archiveTempLease = $null
    try {
        $archiveTempLease = Open-AstroLauncherPinnedDirectoryLease `
            -DirectoryPath $archiveTemp
        $physicalTemp = Get-AstroLauncherTempArchiveSnapshot $archiveTempLease
    }
    finally {
        if ($null -ne $archiveTempLease) {
            $archiveTempLease.SafeFileHandle.Dispose()
        }
    }
    if ([string]$physicalTemp.RootFileId -cne
            [string]$completion.value.terminal.temp.root_file_id -or
        [string]$physicalTemp.InventoryState -cne 'exact' -or
        [int]$physicalTemp.EntryCount -ne
            [int]$completion.value.terminal.temp.entry_count -or
        [string]$physicalTemp.InventorySha256 -cne
            [string]$completion.value.terminal.temp.inventory_sha256) {
        Fail-Astro $code `
            'physical archived TEMP inventory differs from its terminal completion' `
            'preserve the archive and investigate post-completion child drift'
    }
    $manifest = Read-AstroFsvExactJsonFile $archiveManifestPath $code `
        'archived normal live-owner attribution manifest'
    if ([string]$manifest.sha256 -cne
            [string]$completion.value.terminal.manifest.sha256 -or
        [uint64]$manifest.bytes -ne
            [uint64]$completion.value.terminal.manifest.bytes -or
        [string]$manifest.sha256 -cne
            [string]$authorization.value.source.manifest.sha256 -or
        [uint64]$manifest.bytes -ne
            [uint64]$authorization.value.source.manifest.bytes -or
        [string](Get-AstroFsvExactFileIdentity $archiveManifestPath) -cne
            [string]$completion.value.terminal.manifest.file_id -or
        [string]$completion.value.terminal.manifest.file_id -cne
            [string]$authorization.value.source.manifest.file_id) {
        Fail-Astro $code `
            'archived attribution manifest bytes differ from authorization/completion' `
            'preserve the archive and investigate attribution drift'
    }
    $generation = $authorization.value.generation
    $rootIdentity = [AstroLauncherLockNative]::GetDirectoryIdentity($Workspace)
    $derivedJob = Get-AstroLauncherTreeJobObjectName `
        -RootIdentity $rootIdentity `
        -LauncherPid ([int]$generation.launcher_pid) `
        -LauncherProcessStartUtcTicks `
            ([long]$generation.launcher_process_start_utc_ticks) `
        -LauncherLeaseStartUtcTicks `
            ([long]$manifest.value.launcher_lease_start_utc_ticks) `
        -LauncherLockSha256 ([string]$generation.launcher_lock_sha256)
    if ([string]$manifest.value.schema -cne
            'astrolabe.no_escape_attribution.v3' -or
        [int]$generation.manifest_schema_version -ne 3 -or
        [uint32]$generation.job_limit_flags -ne
            [uint32]$manifest.value.job_limit_flags -or
        [int]$manifest.value.launcher_pid -ne [int]$generation.launcher_pid -or
        [long]$manifest.value.launcher_process_start_utc_ticks -ne
            [long]$generation.launcher_process_start_utc_ticks -or
        [string]$manifest.value.launcher_lock_sha256 -cne
            [string]$generation.launcher_lock_sha256 -or
        [string]$manifest.value.job_object_name -cne $derivedJob -or
        [string]$generation.job_object_name -cne $derivedJob) {
        Fail-Astro $code `
            'normal live-owner archive does not reproduce one deterministic launcher generation' `
            'preserve the archive and investigate malformed attribution'
    }
    foreach ($source in @(
            [string]$authorization.value.source.temp.path,
            [string]$authorization.value.source.manifest.path
        )) {
        if (Test-AstroPathLongPath -LiteralPath $source) {
            Fail-Astro $code `
                "normal live-owner archive source namespace reappeared: $source" `
                'preserve all state and reconcile the source before FSV recovery'
        }
    }

    $ownershipPath = Join-Path $archiveTemp 'target-ownership.manifest.v1.json'
    $finalizationPath = Join-Path $archiveTemp 'target-cleanup.finalization.v1.json'
    $targetCompletionPath = Join-Path $archiveTemp 'target-cleanup.completion.v1.json'
    $ownership = Read-AstroFsvExactJsonFile $ownershipPath $code `
        'archived live-owner target ownership manifest'
    $finalization = Read-AstroFsvExactJsonFile $finalizationPath $code `
        'archived live-owner target cleanup finalization'
    $targetCompletion = Read-AstroFsvExactJsonFile $targetCompletionPath $code `
        'archived live-owner target cleanup completion'
    $sourceTemp = [IO.Path]::GetFullPath(
        [string]$authorization.value.source.temp.path
    )
    foreach ($pair in @(
            @([string]$finalization.value.ownership_manifest.path,
                (Join-Path $sourceTemp 'target-ownership.manifest.v1.json')),
            @([string]$targetCompletion.value.finalization.path,
                (Join-Path $sourceTemp 'target-cleanup.finalization.v1.json'))
        )) {
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath([string]$pair[0]),
                [IO.Path]::GetFullPath([string]$pair[1]),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro $code `
                'archived target cleanup links do not descend from the exact source TEMP' `
                'preserve the archive and investigate relocated or mixed-generation records'
        }
    }
    $canonicalTarget = [IO.Path]::GetFullPath((Join-Path $Workspace 'target'))
    $ownershipRoots = @($ownership.value.roots)
    $finalizationRoots = @($finalization.value.roots)
    $completionRoots = @($targetCompletion.value.roots)
    if ([string]$ownership.value.schema -cne
            'astrolabe.launcher-target-ownership.v1' -or
        [string]$finalization.value.schema -cne
            'astrolabe.launcher-target-cleanup-finalization.v1' -or
        [string]$finalization.value.phase -cne
            'exact-inventory-finalized-before-handle-rename' -or
        [string]$targetCompletion.value.schema -cne
            'astrolabe.launcher-target-cleanup-completion.v1' -or
        [string]$targetCompletion.value.phase -cne
            'complete-all-exact-target-names-absent' -or
        [string]$ownership.value.ownership_id -cne
            [string]$finalization.value.ownership_id -or
        [string]$ownership.value.ownership_id -cne
            [string]$targetCompletion.value.ownership_id -or
        [string]$finalization.value.ownership_manifest.sha256 -cne
            [string]$ownership.sha256 -or
        [string]$targetCompletion.value.finalization.sha256 -cne
            [string]$finalization.sha256 -or
        $ownershipRoots.Count -ne 1 -or $finalizationRoots.Count -ne 1 -or
        $completionRoots.Count -ne 1) {
        Fail-Astro $code `
            'archived target cleanup manifest/finalization/completion chain is malformed' `
            'preserve the archive and investigate the exact target cleanup records'
    }
    foreach ($owner in @(
            $ownership.value.owner,
            $finalization.value.owner,
            $targetCompletion.value.owner
        )) {
        if ([int]$owner.pid -ne [int]$generation.launcher_pid -or
            [long]$owner.owner_process_start_utc_ticks -ne
                [long]$generation.launcher_process_start_utc_ticks -or
            [int]$owner.issue -ne $ExpectedIssue -or
            [string]$owner.launcher_lock_sha256 -cne
                [string]$generation.launcher_lock_sha256) {
            Fail-Astro $code `
                'archived target cleanup owner differs from the live-owner archive generation' `
                'preserve the archive and investigate mixed owner authority'
        }
    }
    $cleanupTransitionPath = Assert-PathWithin `
        ([string]$finalization.value.owner.cleanup_transition_path) $tmpRoot $code `
        'normal live-owner target cleanup transition'
    $cleanupTransitionLeaf = [IO.Path]::GetFileName($cleanupTransitionPath)
    $cleanupTransitionPrefix = 'astrolabe-launcher.lock.cleanup.v2.pid-{0}.issue-{1}.ticks-{2}.sha256-{3}.' -f
        [int]$generation.launcher_pid,
        $ExpectedIssue,
        [long]$generation.launcher_process_start_utc_ticks,
        [string]$generation.launcher_lock_sha256
    if (-not $cleanupTransitionLeaf.StartsWith(
            $cleanupTransitionPrefix, [StringComparison]::Ordinal) -or
        $cleanupTransitionLeaf.Substring($cleanupTransitionPrefix.Length) -cnotmatch
            '^[0-9a-f]{32}$' -or
        [string]$finalization.value.owner.cleanup_transition_sha256 -cne
            [string]$generation.launcher_lock_sha256 -or
        [string]::IsNullOrWhiteSpace(
            [string]$finalization.value.owner.cleanup_transition_file_id) -or
        (Test-AstroPathLongPath -LiteralPath $cleanupTransitionPath)) {
        Fail-Astro $code `
            'archived target finalization does not bind the exact absent launcher cleanup transition generation' `
            'preserve the archive and investigate mixed or incomplete launcher cleanup authority'
    }
    if ([string]$ownership.value.owner.job_object_name -cne $derivedJob -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$ownershipRoots[0].path),
            $canonicalTarget,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$finalizationRoots[0].source_path),
            $canonicalTarget,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$completionRoots[0].source_path),
            $canonicalTarget,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$ownershipRoots[0].root_file_id -cne
            [string]$finalizationRoots[0].root_file_id -or
        [string]$completionRoots[0].prior_root_file_id -cne
            [string]$finalizationRoots[0].root_file_id -or
        [string]$completionRoots[0].prior_exact_inventory_sha256 -cne
            [string]$finalizationRoots[0].exact_inventory_sha256 -or
        [uint64]$completionRoots[0].prior_entry_count -ne
            [uint64]$finalizationRoots[0].entry_count -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath(
                [string]$completionRoots[0].tombstone_path),
            [IO.Path]::GetFullPath(
                [string]$finalizationRoots[0].tombstone_path),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$completionRoots[0].source_state -cne 'absent' -or
        [string]$completionRoots[0].tombstone_state -cne 'absent') {
        Fail-Astro $code `
            'archived target cleanup root identity/inventory/terminal absence chain differs' `
            'preserve the archive and investigate the exact target generation'
    }
    if ((Test-AstroPathLongPath -LiteralPath $canonicalTarget) -or
        (Test-AstroPathLongPath -LiteralPath `
            ([string]$completionRoots[0].tombstone_path))) {
        Fail-Astro $code `
            'canonical target or its exact cleanup tombstone is present after normal cleanup' `
            'preserve all state and complete the exact launcher lifecycle'
    }
    $launcherProtocol = Read-AstroLauncherLock `
        -LockPath (Join-Path $tmpRoot 'astrolabe-launcher.lock')
    if ($launcherProtocol.State -ne 'absent') {
        Fail-Astro $code `
            "launcher protocol is '$($launcherProtocol.State)' after normal cleanup" `
            'complete the exact launcher lifecycle before FSV recovery'
    }
    try {
        $publishedAt = [DateTimeOffset]::Parse(
            [string]$ownership.value.published_at_utc,
            [Globalization.CultureInfo]::InvariantCulture)
        $finalizedAt = [DateTimeOffset]::Parse(
            [string]$finalization.value.recorded_at_utc,
            [Globalization.CultureInfo]::InvariantCulture)
        $targetCompletedAt = [DateTimeOffset]::Parse(
            [string]$targetCompletion.value.completed_at_utc,
            [Globalization.CultureInfo]::InvariantCulture)
        $archiveAuthorizedAt = [DateTimeOffset]::Parse(
            [string]$authorization.value.created_utc,
            [Globalization.CultureInfo]::InvariantCulture)
        $archiveCompletedAt = [DateTimeOffset]::Parse(
            [string]$completion.value.completed_utc,
            [Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        Fail-Astro $code `
            "normal cleanup chain contains a malformed timestamp: $($_.Exception.Message)" `
            'preserve every record and investigate its durable chronology'
    }
    if ($publishedAt -gt $finalizedAt -or $finalizedAt -gt $targetCompletedAt -or
        $targetCompletedAt -gt $archiveAuthorizedAt -or
        $archiveAuthorizedAt -gt $archiveCompletedAt) {
        Fail-Astro $code `
            'normal cleanup chronology is not ownership <= finalization <= target completion <= archive authorization <= archive completion' `
            'preserve every record and investigate mixed-generation chronology'
    }

    $archive = [ordered]@{
        completion = $completion
        authorization = $authorization
        manifest = $manifest
        generation_key = "$([int]$generation.launcher_pid)|$([long]$generation.launcher_process_start_utc_ticks)|$([string]$generation.launcher_lock_sha256)"
        job_name = $derivedJob
    }
    return [ordered]@{
        kind = 'NormalLiveOwnerCleanupV1'
        archives = [object[]]@($archive)
        required_generations = @{
            $archive.generation_key = [ordered]@{
                pid = [int]$generation.launcher_pid
                ticks = [long]$generation.launcher_process_start_utc_ticks
                lock_sha256 = [string]$generation.launcher_lock_sha256
            }
        }
        root_identity = $rootIdentity
        normal_cleanup = [ordered]@{
            archive_completion = [ordered]@{
                path = $completion.path; bytes = $completion.bytes; sha256 = $completion.sha256
            }
            archive_authorization = [ordered]@{
                path = $authorization.path; bytes = $authorization.bytes; sha256 = $authorization.sha256
            }
            attribution_manifest = [ordered]@{
                path = $manifest.path; bytes = $manifest.bytes; sha256 = $manifest.sha256
            }
            target_ownership_manifest = [ordered]@{
                path = $ownership.path; bytes = $ownership.bytes; sha256 = $ownership.sha256
            }
            target_cleanup_finalization = [ordered]@{
                path = $finalization.path; bytes = $finalization.bytes; sha256 = $finalization.sha256
            }
            target_cleanup_completion = [ordered]@{
                path = $targetCompletion.path; bytes = $targetCompletion.bytes
                sha256 = $targetCompletion.sha256
            }
            generation = [ordered]@{
                launcher_pid = [int]$generation.launcher_pid
                launcher_process_start_utc_ticks =
                    [long]$generation.launcher_process_start_utc_ticks
                launcher_lock_sha256 = [string]$generation.launcher_lock_sha256
                job_object_name = $derivedJob
            }
            target = [ordered]@{
                path = $canonicalTarget
                prior_root_file_id = [string]$completionRoots[0].prior_root_file_id
                prior_exact_inventory_sha256 =
                    [string]$completionRoots[0].prior_exact_inventory_sha256
                prior_entry_count = [uint64]$completionRoots[0].prior_entry_count
                tombstone_path = [string]$completionRoots[0].tombstone_path
                source_state = 'absent'; tombstone_state = 'absent'
            }
        }
    }
}

function ConvertTo-AstroFsvNormalCleanupTerminalChainRecord {
    param([Parameter(Mandatory)]$Chain)

    if ([string]$Chain.kind -cne 'NormalLiveOwnerCleanupV1') {
        Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_NORMAL_CLEANUP_INVALID' `
            'normal cleanup record conversion received a different terminal-chain kind' `
            'preserve state and use the explicit matching terminal-chain path'
    }
    return [ordered]@{
        schema = 'astrolabe.native-fsv-launcher-terminal-chain.v1'
        kind = 'NormalLiveOwnerCleanupV1'
        archive_completion = $Chain.normal_cleanup.archive_completion
        archive_authorization = $Chain.normal_cleanup.archive_authorization
        attribution_manifest = $Chain.normal_cleanup.attribution_manifest
        target_ownership_manifest = $Chain.normal_cleanup.target_ownership_manifest
        target_cleanup_finalization = $Chain.normal_cleanup.target_cleanup_finalization
        target_cleanup_completion = $Chain.normal_cleanup.target_cleanup_completion
        generation = $Chain.normal_cleanup.generation
        target = $Chain.normal_cleanup.target
    }
}

function Assert-AstroFsvPersistedNormalCleanupTerminalChain {
    param(
        [Parameter(Mandatory)]$Persisted,
        [Parameter(Mandatory)]$Physical,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    $expected = ConvertTo-AstroFsvNormalCleanupTerminalChainRecord $Physical
    $persistedText = $Persisted | ConvertTo-Json -Depth 20 -Compress
    $expectedText = $expected | ConvertTo-Json -Depth 20 -Compress
    if ($persistedText -cne $expectedText) {
        Fail-Astro $Code `
            "$Description differs from the exact normal live-owner cleanup chain" `
            'preserve every record and investigate terminal-chain drift'
    }
}

function Read-AstroFsvLauncherTerminalChainFromInputs {
    param(
        [Parameter(Mandatory)][ValidateSet(
            'DeadOwnerRecoveryV1', 'NormalLiveOwnerCleanupV1')]
        [string]$Kind,
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][string]$Workspace,
        [AllowEmptyString()][string]$LauncherRecoveryPath = '',
        [AllowEmptyString()][string]$TargetRecoveryPath = '',
        [string[]]$ArchiveCompletionPaths = @(),
        [AllowEmptyString()][string]$NormalArchiveCompletionPath = ''
    )

    if ($Kind -ceq 'DeadOwnerRecoveryV1') {
        if (-not [string]::IsNullOrWhiteSpace($NormalArchiveCompletionPath)) {
            Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TERMINAL_CHAIN_MIXED' `
                'dead-owner recovery cannot also consume a normal live-owner archive parameter' `
                'select exactly one explicit launcher terminal-chain kind'
        }
        return Read-AstroFsvLauncherRecoveryChain `
            -ExpectedIssue $ExpectedIssue -Workspace $Workspace `
            -LauncherRecoveryPath $LauncherRecoveryPath `
            -TargetRecoveryPath $TargetRecoveryPath `
            -ArchiveCompletionPaths $ArchiveCompletionPaths
    }
    if (-not [string]::IsNullOrWhiteSpace($LauncherRecoveryPath) -or
        -not [string]::IsNullOrWhiteSpace($TargetRecoveryPath) -or
        $ArchiveCompletionPaths.Count -ne 0) {
        Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TERMINAL_CHAIN_MIXED' `
            'normal live-owner cleanup cannot consume dead-owner recovery records' `
            'select exactly one explicit launcher terminal-chain kind'
    }
    return Read-AstroFsvLauncherNormalCleanupChain `
        -ExpectedIssue $ExpectedIssue -Workspace $Workspace `
        -ArchiveCompletionPath $NormalArchiveCompletionPath
}

function Test-AstroFsvLauncherTerminalChainEqual {
    param(
        [Parameter(Mandatory)]$First,
        [Parameter(Mandatory)]$Second
    )

    if ([string]$First.kind -cne [string]$Second.kind -or
        @($First.archives).Count -ne @($Second.archives).Count) {
        return $false
    }
    if ([string]$First.kind -ceq 'DeadOwnerRecoveryV1') {
        if ([string]$First.launcher_recovery.sha256 -cne
                [string]$Second.launcher_recovery.sha256 -or
            [string]$First.target_recovery.sha256 -cne
                [string]$Second.target_recovery.sha256) {
            return $false
        }
    }
    else {
        $firstRecord = ConvertTo-AstroFsvNormalCleanupTerminalChainRecord $First
        $secondRecord = ConvertTo-AstroFsvNormalCleanupTerminalChainRecord $Second
        if (($firstRecord | ConvertTo-Json -Depth 20 -Compress) -cne
            ($secondRecord | ConvertTo-Json -Depth 20 -Compress)) {
            return $false
        }
    }
    for ($index = 0; $index -lt @($First.archives).Count; $index++) {
        if ([string]$First.archives[$index].completion.sha256 -cne
            [string]$Second.archives[$index].completion.sha256) {
            return $false
        }
    }
    return $true
}

function Assert-AstroFsvPersistedDeadOwnerRecoveryTerminalChain {
    param(
        [Parameter(Mandatory)]$Persisted,
        [Parameter(Mandatory)]$Physical,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    if ([string]$Physical.kind -cne 'DeadOwnerRecoveryV1' -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$Persisted.launcher_recovery_completion.path),
            [IO.Path]::GetFullPath([string]$Physical.launcher_recovery.path),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$Persisted.target_recovery_completion.path),
            [IO.Path]::GetFullPath([string]$Physical.target_recovery.path),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$Persisted.launcher_recovery_completion.sha256 -cne
            [string]$Physical.launcher_recovery.sha256 -or
        [string]$Persisted.target_recovery_completion.sha256 -cne
            [string]$Physical.target_recovery.sha256 -or
        @($Persisted.launcher_archive_completions).Count -ne
            @($Physical.archives).Count) {
        Fail-Astro $Code `
            "$Description differs from the exact dead-owner recovery chain" `
            'preserve every record and investigate terminal-chain drift'
    }
    for ($index = 0; $index -lt @($Physical.archives).Count; $index++) {
        $persistedArchive = $Persisted.launcher_archive_completions[$index]
        $physicalArchive = $Physical.archives[$index].completion
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath([string]$persistedArchive.path),
                [IO.Path]::GetFullPath([string]$physicalArchive.path),
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            [string]$persistedArchive.sha256 -cne [string]$physicalArchive.sha256) {
            Fail-Astro $Code `
                "$Description archive differs at index $index" `
                'preserve every record and investigate terminal-chain drift'
        }
    }
}

function Read-AstroFsvLauncherTerminalChainFromRetirementAuthorization {
    param(
        [Parameter(Mandatory)]$Authorization,
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][string]$Workspace,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    $schema = [string]$Authorization.schema
    if ($schema -ceq 'astrolabe.native-fsv-partial-lock-retirement.authorization.v1') {
        $persisted = $Authorization.launcher_recovery_chain
        $physical = Read-AstroFsvLauncherRecoveryChain `
            -ExpectedIssue $ExpectedIssue -Workspace $Workspace `
            -LauncherRecoveryPath ([string]$persisted.launcher_recovery_completion.path) `
            -TargetRecoveryPath ([string]$persisted.target_recovery_completion.path) `
            -ArchiveCompletionPaths ([string[]]@(
                $persisted.launcher_archive_completions | ForEach-Object {
                    [string]$_.path
                }))
        Assert-AstroFsvPersistedDeadOwnerRecoveryTerminalChain `
            -Persisted $persisted -Physical $physical -Code $Code `
            -Description $Description
        return $physical
    }
    if ($schema -ceq 'astrolabe.native-fsv-partial-lock-retirement.authorization.v2') {
        $persisted = $Authorization.launcher_terminal_chain
        if ([string]$persisted.schema -cne
                'astrolabe.native-fsv-launcher-terminal-chain.v1' -or
            [string]$persisted.kind -cne 'NormalLiveOwnerCleanupV1') {
            Fail-Astro $Code `
                "$Description does not name the exact normal live-owner terminal-chain schema/kind" `
                'preserve every record and investigate malformed terminal-chain authority'
        }
        $physical = Read-AstroFsvLauncherNormalCleanupChain `
            -ExpectedIssue $ExpectedIssue -Workspace $Workspace `
            -ArchiveCompletionPath ([string]$persisted.archive_completion.path)
        Assert-AstroFsvPersistedNormalCleanupTerminalChain `
            -Persisted $persisted -Physical $physical -Code $Code `
            -Description $Description
        return $physical
    }
    Fail-Astro $Code `
        "$Description uses unsupported retirement authorization schema '$schema'" `
        'preserve every record and resume only a supported exact terminal-chain generation'
}

function Read-AstroFsvLegacyTrackerEvidence {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][string]$ExpectedReceiptPath,
        [Parameter(Mandatory)][string]$ExpectedReceiptSha256,
        [Parameter(Mandatory)][string]$ExpectedSessionDirectory,
        [Parameter(Mandatory)][string]$ExpectedInventorySchema,
        [Parameter(Mandatory)][string]$ExpectedInventoryEncoding,
        [Parameter(Mandatory)][int]$ExpectedInventoryEntryCount,
        [Parameter(Mandatory)][uint64]$ExpectedInventoryCanonicalByteCount,
        [Parameter(Mandatory)][string]$ExpectedInventorySha256,
        [Parameter(Mandatory)][int[]]$ExpectedNumericOwnerPids,
        [Parameter(Mandatory)][string]$ExpectedMigrationRecordPath
    )

    $match = [Regex]::Match(
        $Url,
        '^https://github\.com/(?<owner>[^/]+)/(?<repo>[^/]+)/issues/(?<issue>[1-9][0-9]*)#issuecomment-(?<comment>[1-9][0-9]*)\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success -or
        [int]$match.Groups['issue'].Value -ne $ExpectedIssue) {
        Fail-Astro 'ASTRO_FSV_MIGRATION_TRACKER_URL_INVALID' `
            "tracker URL is not an exact issue-comment URL for #${ExpectedIssue}: $Url" `
            'post one fresh owner-authored evidence comment on the exact driving issue'
    }
    $api = 'repos/{0}/{1}/issues/comments/{2}' -f
        $match.Groups['owner'].Value,
        $match.Groups['repo'].Value,
        $match.Groups['comment'].Value
    $comment = Invoke-AstroFsvGhJson $api
    if ([string]$comment.html_url -cne $Url -or
        [string]$comment.author_association -cne 'OWNER') {
        Fail-Astro 'ASTRO_FSV_MIGRATION_TRACKER_IDENTITY_INVALID' `
            'GitHub readback does not bind the exact owner-authored comment URL' `
            'use the canonical html_url of a repository-owner evidence comment'
    }
    $prefix = 'ASTRO_FSV_LEGACY_MIGRATION_EVIDENCE '
    [string[]]$markers = @(
        [string]$comment.body -split "`r?`n" |
            Where-Object {
                $_.StartsWith($prefix, [StringComparison]::Ordinal)
            }
    )
    if ($markers.Count -ne 1) {
        Fail-Astro 'ASTRO_FSV_MIGRATION_TRACKER_EVIDENCE_INVALID' `
            "tracker comment must contain exactly one '$prefix' line" `
            'post one fresh machine-readable legacy migration evidence object'
    }
    try {
        $evidence = $markers[0].Substring($prefix.Length) | ConvertFrom-Json
    }
    catch {
        Fail-Astro 'ASTRO_FSV_MIGRATION_TRACKER_EVIDENCE_INVALID' `
            "tracker evidence JSON is invalid: $($_.Exception.Message)" `
            'post one fresh exact JSON evidence object'
    }
    $expectedFields = @(
        'schema',
        'issue',
        'receipt_path',
        'receipt_sha256',
        'session_directory',
        'inventory_schema',
        'inventory_encoding',
        'inventory_entry_count',
        'inventory_canonical_byte_count',
        'inventory_sha256',
        'legacy_numeric_owner_pids',
        'numeric_owner_probe_state',
        'migration_record_path',
        'authorized_action'
    )
    $actualFields = @($evidence.PSObject.Properties | ForEach-Object Name)
    if ($actualFields.Count -ne $expectedFields.Count -or
        @($expectedFields | Where-Object { $actualFields -notcontains $_ }).Count -ne 0) {
        Fail-Astro 'ASTRO_FSV_MIGRATION_TRACKER_EVIDENCE_INVALID' `
            'tracker evidence fields differ from the exact legacy migration contract' `
            'post a fresh object containing exactly the documented fields'
    }
    $actualPids = [int[]]@(
        @($evidence.legacy_numeric_owner_pids) |
            ForEach-Object { [int]$_ } |
            Sort-Object -Unique
    )
    $expectedPids = [int[]]@($ExpectedNumericOwnerPids | Sort-Object -Unique)
    if ($evidence.schema -cne
            'astrolabe.native-fsv-legacy-migration-evidence.v2' -or
        [int]$evidence.issue -ne $ExpectedIssue -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$evidence.receipt_path),
            [IO.Path]::GetFullPath($ExpectedReceiptPath),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$evidence.receipt_sha256 -cne $ExpectedReceiptSha256 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$evidence.session_directory),
            [IO.Path]::GetFullPath($ExpectedSessionDirectory),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$evidence.inventory_schema -cne
            $ExpectedInventorySchema -or
        [string]$evidence.inventory_encoding -cne
            $ExpectedInventoryEncoding -or
        [int]$evidence.inventory_entry_count -ne
            $ExpectedInventoryEntryCount -or
        [uint64]$evidence.inventory_canonical_byte_count -ne
            $ExpectedInventoryCanonicalByteCount -or
        [string]$evidence.inventory_sha256 -cne $ExpectedInventorySha256 -or
        ($actualPids -join ',') -cne ($expectedPids -join ',') -or
        [string]$evidence.numeric_owner_probe_state -cne 'all-absent' -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$evidence.migration_record_path),
            [IO.Path]::GetFullPath($ExpectedMigrationRecordPath),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$evidence.authorized_action -cne
            'remove-legacy-session-without-inventing-process-start-ticks') {
        Fail-Astro 'ASTRO_FSV_MIGRATION_TRACKER_EVIDENCE_MISMATCH' `
            'tracker evidence differs from the exact local legacy session binding' `
            're-read physical state and post a fresh exact evidence object'
    }
    return [ordered]@{
        url = $Url
        comment_id = [long]$match.Groups['comment'].Value
        author = [string]$comment.user.login
        evidence = $evidence
    }
}

function Read-AstroFsvPreAdmissionTrackerEvidence {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][string]$ExpectedReceiptPath,
        [Parameter(Mandatory)][string]$ExpectedReceiptSha256,
        [Parameter(Mandatory)][string]$ExpectedArtifactPath,
        [Parameter(Mandatory)][string]$ExpectedArtifactSha256,
        [Parameter(Mandatory)][string]$ExpectedSessionDirectory,
        [Parameter(Mandatory)][string]$ExpectedPreAdmissionDirectory,
        [Parameter(Mandatory)][string]$ExpectedStandardOutputPath,
        [Parameter(Mandatory)][string]$ExpectedStandardErrorPath,
        [Parameter(Mandatory)][string]$ExpectedRunRecordPath,
        [Parameter(Mandatory)][string]$ExpectedLiveStatePath,
        [Parameter(Mandatory)][string]$ExpectedInventorySchema,
        [Parameter(Mandatory)][string]$ExpectedInventoryEncoding,
        [Parameter(Mandatory)][int]$ExpectedInventoryEntryCount,
        [Parameter(Mandatory)][uint64]$ExpectedInventoryCanonicalByteCount,
        [Parameter(Mandatory)][string]$ExpectedInventorySha256,
        [Parameter(Mandatory)][string]$ExpectedRecoveryRecordPath,
        [Parameter(Mandatory)][string]$ExpectedReasonCode
    )

    $match = [Regex]::Match(
        $Url,
        '^https://github\.com/(?<owner>[^/]+)/(?<repo>[^/]+)/issues/(?<issue>[1-9][0-9]*)#issuecomment-(?<comment>[1-9][0-9]*)\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success -or [int]$match.Groups['issue'].Value -ne $ExpectedIssue) {
        Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_TRACKER_URL_INVALID' `
            "tracker URL is not an exact issue-comment URL for #${ExpectedIssue}: $Url" `
            'post one fresh owner-authored evidence comment on the exact driving issue'
    }
    $comment = Invoke-AstroFsvGhJson ('repos/{0}/{1}/issues/comments/{2}' -f $match.Groups['owner'].Value, $match.Groups['repo'].Value, $match.Groups['comment'].Value)
    if ([string]$comment.html_url -cne $Url -or [string]$comment.author_association -cne 'OWNER') {
        Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_TRACKER_IDENTITY_INVALID' `
            'GitHub readback does not bind the exact owner-authored comment URL' `
            'use the canonical html_url of a repository-owner evidence comment'
    }
    $prefix = 'ASTRO_FSV_PRE_ADMISSION_ABANDON_EVIDENCE '
    [string[]]$markers = @([string]$comment.body -split "`r?`n" | Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) })
    if ($markers.Count -ne 1) {
        Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_TRACKER_EVIDENCE_INVALID' `
            "tracker comment must contain exactly one '$prefix' line" `
            'post one fresh machine-readable pre-admission abandonment evidence object'
    }
    try { $evidence = $markers[0].Substring($prefix.Length) | ConvertFrom-Json }
    catch {
        Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_TRACKER_EVIDENCE_INVALID' `
            "tracker evidence JSON is invalid: $($_.Exception.Message)" `
            'post one fresh exact JSON evidence object'
    }
    $expectedFields = @(
        'schema', 'issue', 'receipt_path', 'receipt_sha256', 'artifact_path', 'artifact_sha256',
        'session_directory', 'pre_admission_directory', 'standard_output_path', 'standard_error_path',
        'run_record_path', 'live_state_path', 'standard_output_state', 'standard_error_state',
        'run_record_state', 'live_state_state', 'inventory_schema', 'inventory_encoding',
        'inventory_entry_count', 'inventory_canonical_byte_count', 'inventory_sha256',
        'receipt_owner_probe_state', 'recovery_record_path', 'reason_code', 'authorized_action'
    )
    $actualFields = @($evidence.PSObject.Properties | ForEach-Object Name)
    if ($actualFields.Count -ne $expectedFields.Count -or @($expectedFields | Where-Object { $actualFields -notcontains $_ }).Count -ne 0) {
        Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_TRACKER_EVIDENCE_INVALID' `
            'tracker evidence fields differ from the exact pre-admission abandonment contract' `
            'post a fresh object containing exactly the documented fields'
    }
    $expectedPaths = @(
        @('receipt_path', $ExpectedReceiptPath), @('artifact_path', $ExpectedArtifactPath),
        @('session_directory', $ExpectedSessionDirectory), @('pre_admission_directory', $ExpectedPreAdmissionDirectory),
        @('standard_output_path', $ExpectedStandardOutputPath), @('standard_error_path', $ExpectedStandardErrorPath),
        @('run_record_path', $ExpectedRunRecordPath), @('live_state_path', $ExpectedLiveStatePath),
        @('recovery_record_path', $ExpectedRecoveryRecordPath)
    )
    foreach ($pair in $expectedPaths) {
        if (-not [string]::Equals([IO.Path]::GetFullPath([string]$evidence.($pair[0])), [IO.Path]::GetFullPath([string]$pair[1]), [StringComparison]::OrdinalIgnoreCase)) {
            Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_TRACKER_EVIDENCE_MISMATCH' `
                "tracker evidence path differs for $($pair[0])" `
                're-read physical state and post a fresh exact evidence object'
        }
    }
    if ($evidence.schema -cne 'astrolabe.native-fsv-pre-admission-abandon-evidence.v1' -or
        [int]$evidence.issue -ne $ExpectedIssue -or
        [string]$evidence.receipt_sha256 -cne $ExpectedReceiptSha256 -or
        [string]$evidence.artifact_sha256 -cne $ExpectedArtifactSha256 -or
        [string]$evidence.standard_output_state -cne 'absent' -or
        [string]$evidence.standard_error_state -cne 'absent' -or
        [string]$evidence.run_record_state -cne 'absent' -or
        [string]$evidence.live_state_state -cne 'absent' -or
        [string]$evidence.inventory_schema -cne $ExpectedInventorySchema -or
        [string]$evidence.inventory_encoding -cne $ExpectedInventoryEncoding -or
        [int]$evidence.inventory_entry_count -ne $ExpectedInventoryEntryCount -or
        [uint64]$evidence.inventory_canonical_byte_count -ne $ExpectedInventoryCanonicalByteCount -or
        [string]$evidence.inventory_sha256 -cne $ExpectedInventorySha256 -or
        [string]$evidence.receipt_owner_probe_state -cne 'all-inactive' -or
        [string]$evidence.reason_code -cne $ExpectedReasonCode -or
        [string]$evidence.authorized_action -cne 'remove-exact-pre-admission-session-without-child-or-live-state') {
        Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_TRACKER_EVIDENCE_MISMATCH' `
            'tracker evidence differs from the exact local pre-admission session binding' `
            're-read physical state and post a fresh exact evidence object'
    }
    return [ordered]@{ url = $Url; comment_id = [long]$match.Groups['comment'].Value; author = [string]$comment.user.login; evidence = $evidence }
}

function Read-AstroFsvPartialLockTrackerEvidence {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][string]$ExpectedLockPath,
        [Parameter(Mandatory)][string]$ExpectedLockSha256,
        [Parameter(Mandatory)][string]$ExpectedReceiptPath,
        [Parameter(Mandatory)][string]$ExpectedReceiptSha256,
        [Parameter(Mandatory)][string]$ExpectedArtifactPath,
        [Parameter(Mandatory)][string]$ExpectedArtifactSha256,
        [Parameter(Mandatory)][string]$ExpectedSessionDirectory,
        [Parameter(Mandatory)][string]$ExpectedStandardOutputPath,
        [Parameter(Mandatory)][string]$ExpectedStandardOutputSha256,
        [Parameter(Mandatory)][string]$ExpectedStandardErrorPath,
        [Parameter(Mandatory)][string]$ExpectedStandardErrorSha256,
        [Parameter(Mandatory)][string]$ExpectedRunRecordPath,
        [Parameter(Mandatory)][string]$ExpectedLiveStatePath,
        [Parameter(Mandatory)][string]$ExpectedInventorySchema,
        [Parameter(Mandatory)][string]$ExpectedInventoryEncoding,
        [Parameter(Mandatory)][int]$ExpectedInventoryEntryCount,
        [Parameter(Mandatory)][uint64]$ExpectedInventoryCanonicalByteCount,
        [Parameter(Mandatory)][string]$ExpectedInventorySha256,
        [Parameter(Mandatory)][string]$ExpectedRecoveryRecordPath,
        [Parameter(Mandatory)][string]$ExpectedLockArchivePath,
        [Parameter(Mandatory)][string]$ExpectedCompletionRecordPath,
        [Parameter(Mandatory)][string]$ExpectedLifecycleTransitionPath,
        [AllowEmptyString()][string]$ExpectedLauncherRecoveryCompletionPath = '',
        [AllowEmptyString()][string]$ExpectedLauncherRecoveryCompletionSha256 = '',
        [AllowEmptyString()][string]$ExpectedTargetRecoveryCompletionPath = '',
        [AllowEmptyString()][string]$ExpectedTargetRecoveryCompletionSha256 = '',
        [string[]]$ExpectedLauncherArchiveCompletionPaths = @(),
        [string[]]$ExpectedLauncherArchiveCompletionSha256s = @(),
        [ValidateSet('DeadOwnerRecoveryV1', 'NormalLiveOwnerCleanupV1')]
        [string]$ExpectedLauncherTerminalChainKind = 'DeadOwnerRecoveryV1',
        [AllowNull()]$ExpectedLauncherNormalChainRecord = $null,
        [Parameter(Mandatory)][string]$ExpectedReasonCode
    )

    $match = [Regex]::Match(
        $Url,
        '^https://github\.com/(?<owner>[^/]+)/(?<repo>[^/]+)/issues/(?<issue>[1-9][0-9]*)#issuecomment-(?<comment>[1-9][0-9]*)\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success -or [int]$match.Groups['issue'].Value -ne $ExpectedIssue) {
        Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TRACKER_URL_INVALID' `
            "tracker URL is not an exact issue-comment URL for #${ExpectedIssue}: $Url" `
            'post one fresh owner-authored evidence comment on the exact driving issue'
    }
    $comment = Invoke-AstroFsvGhJson ('repos/{0}/{1}/issues/comments/{2}' -f `
            $match.Groups['owner'].Value, $match.Groups['repo'].Value, `
            $match.Groups['comment'].Value)
    if ([string]$comment.html_url -cne $Url -or
        [string]$comment.author_association -cne 'OWNER') {
        Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TRACKER_IDENTITY_INVALID' `
            'GitHub readback does not bind the exact owner-authored comment URL' `
            'use the canonical html_url of a repository-owner evidence comment'
    }
    $prefix = 'ASTRO_FSV_PARTIAL_LOCK_RETIREMENT_EVIDENCE '
    [string[]]$markers = @([string]$comment.body -split "`r?`n" |
            Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) })
    if ($markers.Count -ne 1) {
        Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TRACKER_EVIDENCE_INVALID' `
            "tracker comment must contain exactly one '$prefix' line" `
            'post one fresh machine-readable partial-lock retirement evidence object'
    }
    try { $evidence = $markers[0].Substring($prefix.Length) | ConvertFrom-Json }
    catch {
        Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TRACKER_EVIDENCE_INVALID' `
            "tracker evidence JSON is invalid: $($_.Exception.Message)" `
            'post one fresh exact JSON evidence object'
    }
    $commonFields = @(
        'schema', 'issue', 'lock_path', 'lock_sha256', 'receipt_path',
        'receipt_sha256', 'artifact_path', 'artifact_sha256', 'session_directory',
        'standard_output_path', 'standard_output_sha256', 'standard_error_path',
        'standard_error_sha256', 'run_record_path', 'run_record_state',
        'live_state_path', 'live_state_state', 'inventory_schema',
        'inventory_encoding', 'inventory_entry_count',
        'inventory_canonical_byte_count', 'inventory_sha256', 'owner_probe_state',
        'job_probe_state', 'recovery_record_path', 'lock_archive_path',
        'completion_record_path', 'lifecycle_transition_path',
        'reason_code', 'authorized_action'
    )
    $expectedFields = if ($ExpectedLauncherTerminalChainKind -ceq
            'DeadOwnerRecoveryV1') {
        @($commonFields + @(
                'launcher_recovery_completion_path',
                'launcher_recovery_completion_sha256',
                'target_recovery_completion_path',
                'target_recovery_completion_sha256',
                'launcher_archive_completion_paths',
                'launcher_archive_completion_sha256s'
            ))
    }
    else {
        @($commonFields + @(
                'launcher_terminal_chain_kind',
                'launcher_archive_completion_path',
                'launcher_archive_completion_sha256',
                'launcher_archive_authorization_path',
                'launcher_archive_authorization_sha256',
                'launcher_attribution_manifest_path',
                'launcher_attribution_manifest_sha256',
                'launcher_target_ownership_manifest_path',
                'launcher_target_ownership_manifest_sha256',
                'launcher_target_cleanup_finalization_path',
                'launcher_target_cleanup_finalization_sha256',
                'launcher_target_cleanup_completion_path',
                'launcher_target_cleanup_completion_sha256'
            ))
    }
    $actualFields = @($evidence.PSObject.Properties | ForEach-Object Name)
    if ($actualFields.Count -ne $expectedFields.Count -or
        @($expectedFields | Where-Object { $actualFields -notcontains $_ }).Count -ne 0) {
        Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TRACKER_EVIDENCE_INVALID' `
            'tracker evidence fields differ from the exact partial-lock retirement contract' `
            'post a fresh object containing exactly the documented fields'
    }
    $expectedPaths = @(
        @('lock_path', $ExpectedLockPath), @('receipt_path', $ExpectedReceiptPath),
        @('artifact_path', $ExpectedArtifactPath),
        @('session_directory', $ExpectedSessionDirectory),
        @('standard_output_path', $ExpectedStandardOutputPath),
        @('standard_error_path', $ExpectedStandardErrorPath),
        @('run_record_path', $ExpectedRunRecordPath),
        @('live_state_path', $ExpectedLiveStatePath),
        @('recovery_record_path', $ExpectedRecoveryRecordPath),
        @('lock_archive_path', $ExpectedLockArchivePath),
        @('completion_record_path', $ExpectedCompletionRecordPath),
        @('lifecycle_transition_path', $ExpectedLifecycleTransitionPath)
    )
    if ($ExpectedLauncherTerminalChainKind -ceq 'DeadOwnerRecoveryV1') {
        $expectedPaths += @(
            @('launcher_recovery_completion_path',
                $ExpectedLauncherRecoveryCompletionPath),
            @('target_recovery_completion_path',
                $ExpectedTargetRecoveryCompletionPath)
        )
    }
    else {
        if ($null -eq $ExpectedLauncherNormalChainRecord) {
            Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TRACKER_EVIDENCE_INVALID' `
                'normal cleanup tracker validation lacks its exact terminal-chain record' `
                're-read the physical normal cleanup chain before tracker validation'
        }
        $expectedPaths += @(
            @('launcher_archive_completion_path',
                [string]$ExpectedLauncherNormalChainRecord.archive_completion.path),
            @('launcher_archive_authorization_path',
                [string]$ExpectedLauncherNormalChainRecord.archive_authorization.path),
            @('launcher_attribution_manifest_path',
                [string]$ExpectedLauncherNormalChainRecord.attribution_manifest.path),
            @('launcher_target_ownership_manifest_path',
                [string]$ExpectedLauncherNormalChainRecord.target_ownership_manifest.path),
            @('launcher_target_cleanup_finalization_path',
                [string]$ExpectedLauncherNormalChainRecord.target_cleanup_finalization.path),
            @('launcher_target_cleanup_completion_path',
                [string]$ExpectedLauncherNormalChainRecord.target_cleanup_completion.path)
        )
    }
    foreach ($pair in $expectedPaths) {
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath([string]$evidence.($pair[0])),
                [IO.Path]::GetFullPath([string]$pair[1]),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TRACKER_EVIDENCE_MISMATCH' `
                "tracker evidence path differs for $($pair[0])" `
                're-read physical state and post a fresh exact evidence object'
        }
    }
    if ($ExpectedLauncherTerminalChainKind -ceq 'DeadOwnerRecoveryV1') {
        $trackerArchivePaths = @($evidence.launcher_archive_completion_paths)
        $trackerArchiveHashes = @($evidence.launcher_archive_completion_sha256s)
        if ($trackerArchivePaths.Count -ne
                $ExpectedLauncherArchiveCompletionPaths.Count -or
            $trackerArchiveHashes.Count -ne
                $ExpectedLauncherArchiveCompletionSha256s.Count) {
            Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TRACKER_EVIDENCE_MISMATCH' `
                'tracker launcher-archive completion arrays have the wrong cardinality' `
                're-read the exact recovery chain and post one fresh evidence object'
        }
        for ($index = 0; $index -lt $trackerArchivePaths.Count; $index++) {
            if (-not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$trackerArchivePaths[$index]),
                    [IO.Path]::GetFullPath(
                        [string]$ExpectedLauncherArchiveCompletionPaths[$index]),
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                [string]$trackerArchiveHashes[$index] -cne
                    [string]$ExpectedLauncherArchiveCompletionSha256s[$index]) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TRACKER_EVIDENCE_MISMATCH' `
                    "tracker launcher-archive completion binding differs at index $index" `
                    're-read the exact recovery chain and post one fresh evidence object'
            }
        }
    }
    $expectedEvidenceSchema = if ($ExpectedLauncherTerminalChainKind -ceq
            'DeadOwnerRecoveryV1') {
        'astrolabe.native-fsv-partial-lock-retirement-evidence.v1'
    } else { 'astrolabe.native-fsv-partial-lock-retirement-evidence.v2' }
    $chainMismatch = if ($ExpectedLauncherTerminalChainKind -ceq
            'DeadOwnerRecoveryV1') {
        [string]$evidence.launcher_recovery_completion_sha256 -cne
            $ExpectedLauncherRecoveryCompletionSha256 -or
        [string]$evidence.target_recovery_completion_sha256 -cne
            $ExpectedTargetRecoveryCompletionSha256
    }
    else {
        [string]$evidence.launcher_terminal_chain_kind -cne
            'NormalLiveOwnerCleanupV1' -or
        [string]$evidence.launcher_archive_completion_sha256 -cne
            [string]$ExpectedLauncherNormalChainRecord.archive_completion.sha256 -or
        [string]$evidence.launcher_archive_authorization_sha256 -cne
            [string]$ExpectedLauncherNormalChainRecord.archive_authorization.sha256 -or
        [string]$evidence.launcher_attribution_manifest_sha256 -cne
            [string]$ExpectedLauncherNormalChainRecord.attribution_manifest.sha256 -or
        [string]$evidence.launcher_target_ownership_manifest_sha256 -cne
            [string]$ExpectedLauncherNormalChainRecord.target_ownership_manifest.sha256 -or
        [string]$evidence.launcher_target_cleanup_finalization_sha256 -cne
            [string]$ExpectedLauncherNormalChainRecord.target_cleanup_finalization.sha256 -or
        [string]$evidence.launcher_target_cleanup_completion_sha256 -cne
            [string]$ExpectedLauncherNormalChainRecord.target_cleanup_completion.sha256
    }
    if ([string]$evidence.schema -cne $expectedEvidenceSchema -or
        [int]$evidence.issue -ne $ExpectedIssue -or
        [string]$evidence.lock_sha256 -cne $ExpectedLockSha256 -or
        [string]$evidence.receipt_sha256 -cne $ExpectedReceiptSha256 -or
        [string]$evidence.artifact_sha256 -cne $ExpectedArtifactSha256 -or
        [string]$evidence.standard_output_sha256 -cne
            $ExpectedStandardOutputSha256 -or
        [string]$evidence.standard_error_sha256 -cne
            $ExpectedStandardErrorSha256 -or
        [string]$evidence.run_record_state -cne 'absent' -or
        [string]$evidence.live_state_state -cne 'absent' -or
        [string]$evidence.inventory_schema -cne $ExpectedInventorySchema -or
        [string]$evidence.inventory_encoding -cne $ExpectedInventoryEncoding -or
        [int]$evidence.inventory_entry_count -ne $ExpectedInventoryEntryCount -or
        [uint64]$evidence.inventory_canonical_byte_count -ne
            $ExpectedInventoryCanonicalByteCount -or
        [string]$evidence.inventory_sha256 -cne $ExpectedInventorySha256 -or
        [string]$evidence.owner_probe_state -cne 'all-inactive' -or
        [string]$evidence.job_probe_state -cne 'absent' -or
        $chainMismatch -or
        [string]$evidence.reason_code -cne $ExpectedReasonCode -or
        [string]$evidence.authorized_action -cne
            'archive-exact-terminal-partial-v3-fsv-lock-only') {
        Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TRACKER_EVIDENCE_MISMATCH' `
            'tracker evidence differs from the exact local partial-lock binding' `
            're-read physical state and post a fresh exact evidence object'
    }
    return [ordered]@{
        url = $Url
        comment_id = [long]$match.Groups['comment'].Value
        author = [string]$comment.user.login
        created_at = [string]$comment.created_at
        evidence = $evidence
    }
}

function Read-AstroFsvInterruptedV2LockTrackerEvidence {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][string]$ExpectedLockPath,
        [Parameter(Mandatory)][string]$ExpectedLockSha256,
        [Parameter(Mandatory)][string]$ExpectedReceiptPath,
        [Parameter(Mandatory)][string]$ExpectedReceiptSha256,
        [Parameter(Mandatory)][string]$ExpectedArtifactPath,
        [Parameter(Mandatory)][string]$ExpectedArtifactSha256,
        [Parameter(Mandatory)][string]$ExpectedSessionDirectory,
        [Parameter(Mandatory)][string]$ExpectedLiveStatePath,
        [Parameter(Mandatory)][string]$ExpectedLiveStateSha256,
        [Parameter(Mandatory)][string]$ExpectedStandardOutputPath,
        [Parameter(Mandatory)][string]$ExpectedStandardOutputSha256,
        [Parameter(Mandatory)][string]$ExpectedStandardErrorPath,
        [Parameter(Mandatory)][string]$ExpectedStandardErrorSha256,
        [Parameter(Mandatory)][string]$ExpectedRunRecordPath,
        [Parameter(Mandatory)][string]$ExpectedInventorySchema,
        [Parameter(Mandatory)][string]$ExpectedInventoryEncoding,
        [Parameter(Mandatory)][int]$ExpectedInventoryEntryCount,
        [Parameter(Mandatory)][uint64]$ExpectedInventoryCanonicalByteCount,
        [Parameter(Mandatory)][string]$ExpectedInventorySha256,
        [Parameter(Mandatory)]$ExpectedLauncherIdentity,
        [Parameter(Mandatory)]$ExpectedRunnerIdentity,
        [Parameter(Mandatory)]$ExpectedChildIdentity,
        [Parameter(Mandatory)][string]$ExpectedLauncherJobName,
        [Parameter(Mandatory)][string]$ExpectedRecoveryRecordPath,
        [Parameter(Mandatory)][string]$ExpectedLockArchivePath,
        [Parameter(Mandatory)][string]$ExpectedCompletionRecordPath,
        [Parameter(Mandatory)][string]$ExpectedLifecycleTransitionPath,
        [Parameter(Mandatory)][string]$ExpectedLauncherRecoveryCompletionPath,
        [Parameter(Mandatory)][string]$ExpectedLauncherRecoveryCompletionSha256,
        [Parameter(Mandatory)][string]$ExpectedTargetRecoveryCompletionPath,
        [Parameter(Mandatory)][string]$ExpectedTargetRecoveryCompletionSha256,
        [Parameter(Mandatory)][string[]]$ExpectedLauncherArchiveCompletionPaths,
        [Parameter(Mandatory)][string[]]$ExpectedLauncherArchiveCompletionSha256s,
        [Parameter(Mandatory)][string]$ExpectedReasonCode
    )

    $code = 'ASTRO_FSV_INTERRUPTED_V2_TRACKER_EVIDENCE'
    $match = [Regex]::Match(
        $Url,
        '^https://github\.com/(?<owner>[^/]+)/(?<repo>[^/]+)/issues/(?<issue>[1-9][0-9]*)#issuecomment-(?<comment>[1-9][0-9]*)\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success -or [int]$match.Groups['issue'].Value -ne $ExpectedIssue) {
        Fail-Astro "${code}_URL_INVALID" `
            "tracker URL is not an exact issue-comment URL for #${ExpectedIssue}: $Url" `
            'post one fresh owner-authored evidence comment on the exact driving issue'
    }
    $comment = Invoke-AstroFsvGhJson ('repos/{0}/{1}/issues/comments/{2}' -f `
            $match.Groups['owner'].Value, $match.Groups['repo'].Value,
            $match.Groups['comment'].Value)
    if ([string]$comment.html_url -cne $Url -or
        [string]$comment.author_association -cne 'OWNER') {
        Fail-Astro "${code}_IDENTITY_INVALID" `
            'GitHub readback does not bind the exact owner-authored comment URL' `
            'use the canonical html_url of a repository-owner evidence comment'
    }
    $prefix = 'ASTRO_FSV_INTERRUPTED_V2_LOCK_RETIREMENT_EVIDENCE '
    [string[]]$markers = @([string]$comment.body -split "`r?`n" |
            Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) })
    if ($markers.Count -ne 1) {
        Fail-Astro "${code}_INVALID" `
            "tracker comment must contain exactly one '$prefix' line" `
            'post one fresh machine-readable interrupted-v2 retirement evidence object'
    }
    try { $evidence = $markers[0].Substring($prefix.Length) | ConvertFrom-Json }
    catch {
        Fail-Astro "${code}_INVALID" `
            "tracker evidence JSON is invalid: $($_.Exception.Message)" `
            'post one fresh exact JSON evidence object'
    }
    $expectedFields = @(
        'schema', 'issue', 'lock_path', 'lock_sha256', 'receipt_path',
        'receipt_sha256', 'artifact_path', 'artifact_sha256', 'session_directory',
        'live_state_path', 'live_state_sha256', 'live_state_state',
        'standard_output_path', 'standard_output_sha256', 'standard_error_path',
        'standard_error_sha256', 'run_record_path', 'run_record_state',
        'inventory_schema', 'inventory_encoding', 'inventory_entry_count',
        'inventory_canonical_byte_count', 'inventory_sha256', 'launcher_identity',
        'runner_identity', 'child_identity', 'launcher_job_name',
        'owner_probe_state', 'job_probe_state', 'recovery_record_path',
        'lock_archive_path', 'completion_record_path', 'lifecycle_transition_path',
        'launcher_recovery_completion_path', 'launcher_recovery_completion_sha256',
        'target_recovery_completion_path', 'target_recovery_completion_sha256',
        'launcher_archive_completion_paths', 'launcher_archive_completion_sha256s',
        'reason_code', 'authorized_action'
    )
    $actualFields = @($evidence.PSObject.Properties | ForEach-Object Name)
    if ($actualFields.Count -ne $expectedFields.Count -or
        @($expectedFields | Where-Object { $actualFields -notcontains $_ }).Count -ne 0) {
        Fail-Astro "${code}_INVALID" `
            'tracker evidence fields differ from the exact interrupted-v2 contract' `
            'post a fresh object containing exactly the documented fields'
    }
    foreach ($pair in @(
            @('lock_path', $ExpectedLockPath),
            @('receipt_path', $ExpectedReceiptPath),
            @('artifact_path', $ExpectedArtifactPath),
            @('session_directory', $ExpectedSessionDirectory),
            @('live_state_path', $ExpectedLiveStatePath),
            @('standard_output_path', $ExpectedStandardOutputPath),
            @('standard_error_path', $ExpectedStandardErrorPath),
            @('run_record_path', $ExpectedRunRecordPath),
            @('recovery_record_path', $ExpectedRecoveryRecordPath),
            @('lock_archive_path', $ExpectedLockArchivePath),
            @('completion_record_path', $ExpectedCompletionRecordPath),
            @('lifecycle_transition_path', $ExpectedLifecycleTransitionPath),
            @('launcher_recovery_completion_path',
                $ExpectedLauncherRecoveryCompletionPath),
            @('target_recovery_completion_path',
                $ExpectedTargetRecoveryCompletionPath)
        )) {
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath([string]$evidence.($pair[0])),
                [IO.Path]::GetFullPath([string]$pair[1]),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro "${code}_MISMATCH" `
                "tracker evidence path differs for $($pair[0])" `
                're-read physical state and post a fresh exact evidence object'
        }
    }
    $trackerArchivePaths = @($evidence.launcher_archive_completion_paths)
    $trackerArchiveHashes = @($evidence.launcher_archive_completion_sha256s)
    if ($trackerArchivePaths.Count -ne $ExpectedLauncherArchiveCompletionPaths.Count -or
        $trackerArchiveHashes.Count -ne
            $ExpectedLauncherArchiveCompletionSha256s.Count) {
        Fail-Astro "${code}_MISMATCH" `
            'tracker launcher-archive completion arrays have the wrong cardinality' `
            're-read the exact recovery chain and post one fresh evidence object'
    }
    for ($index = 0; $index -lt $trackerArchivePaths.Count; $index++) {
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath([string]$trackerArchivePaths[$index]),
                [IO.Path]::GetFullPath(
                    [string]$ExpectedLauncherArchiveCompletionPaths[$index]),
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            [string]$trackerArchiveHashes[$index] -cne
                [string]$ExpectedLauncherArchiveCompletionSha256s[$index]) {
            Fail-Astro "${code}_MISMATCH" `
                "tracker launcher-archive completion differs at index $index" `
                're-read the exact recovery chain and post one fresh evidence object'
        }
    }
    foreach ($identityPair in @(
            @('launcher_identity', $ExpectedLauncherIdentity),
            @('runner_identity', $ExpectedRunnerIdentity),
            @('child_identity', $ExpectedChildIdentity)
        )) {
        $trackerIdentity = Read-AstroFsvProcessIdentity `
            $evidence.($identityPair[0]) "${code}_MISMATCH" `
            "tracker $($identityPair[0])"
        if (-not (Test-AstroFsvIdentityEqual $trackerIdentity $identityPair[1])) {
            Fail-Astro "${code}_MISMATCH" `
                "tracker $($identityPair[0]) differs from physical state" `
                're-read the exact owner generations and post fresh evidence'
        }
    }
    if ([string]$evidence.schema -cne
            'astrolabe.native-fsv-interrupted-v2-lock-retirement-evidence.v1' -or
        [int]$evidence.issue -ne $ExpectedIssue -or
        [string]$evidence.lock_sha256 -cne $ExpectedLockSha256 -or
        [string]$evidence.receipt_sha256 -cne $ExpectedReceiptSha256 -or
        [string]$evidence.artifact_sha256 -cne $ExpectedArtifactSha256 -or
        [string]$evidence.live_state_sha256 -cne $ExpectedLiveStateSha256 -or
        [string]$evidence.live_state_state -cne 'present' -or
        [string]$evidence.standard_output_sha256 -cne
            $ExpectedStandardOutputSha256 -or
        [string]$evidence.standard_error_sha256 -cne
            $ExpectedStandardErrorSha256 -or
        [string]$evidence.run_record_state -cne 'absent' -or
        [string]$evidence.inventory_schema -cne $ExpectedInventorySchema -or
        [string]$evidence.inventory_encoding -cne $ExpectedInventoryEncoding -or
        [int]$evidence.inventory_entry_count -ne $ExpectedInventoryEntryCount -or
        [uint64]$evidence.inventory_canonical_byte_count -ne
            $ExpectedInventoryCanonicalByteCount -or
        [string]$evidence.inventory_sha256 -cne $ExpectedInventorySha256 -or
        [string]$evidence.launcher_job_name -cne $ExpectedLauncherJobName -or
        [string]$evidence.owner_probe_state -cne 'all-inactive' -or
        [string]$evidence.job_probe_state -cne 'absent' -or
        [string]$evidence.launcher_recovery_completion_sha256 -cne
            $ExpectedLauncherRecoveryCompletionSha256 -or
        [string]$evidence.target_recovery_completion_sha256 -cne
            $ExpectedTargetRecoveryCompletionSha256 -or
        [string]$evidence.reason_code -cne $ExpectedReasonCode -or
        [string]$evidence.authorized_action -cne
            'archive-exact-interrupted-v2-fsv-lock-only') {
        Fail-Astro "${code}_MISMATCH" `
            'tracker evidence differs from the exact local interrupted-v2 binding' `
            're-read physical state and post a fresh exact evidence object'
    }
    return [ordered]@{
        url = $Url
        comment_id = [long]$match.Groups['comment'].Value
        author = [string]$comment.user.login
        created_at = [string]$comment.created_at
        evidence = $evidence
    }
}

function Read-AstroFsvTerminalPartialQuarantineTrackerEvidence {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][string]$ExpectedRetirementCompletionPath,
        [Parameter(Mandatory)][string]$ExpectedRetirementCompletionSha256,
        [Parameter(Mandatory)][string]$ExpectedReceiptPath,
        [Parameter(Mandatory)][string]$ExpectedReceiptSha256,
        [Parameter(Mandatory)][string]$ExpectedArtifactPath,
        [Parameter(Mandatory)][string]$ExpectedArtifactSha256,
        [Parameter(Mandatory)][string]$ExpectedSessionDirectory,
        [Parameter(Mandatory)][string]$ExpectedStandardOutputPath,
        [Parameter(Mandatory)][string]$ExpectedStandardOutputSha256,
        [Parameter(Mandatory)][string]$ExpectedStandardErrorPath,
        [Parameter(Mandatory)][string]$ExpectedStandardErrorSha256,
        [Parameter(Mandatory)][string]$ExpectedRunRecordPath,
        [Parameter(Mandatory)][string]$ExpectedLiveStatePath,
        [Parameter(Mandatory)][string]$ExpectedInventorySchema,
        [Parameter(Mandatory)][string]$ExpectedInventoryEncoding,
        [Parameter(Mandatory)][int]$ExpectedInventoryEntryCount,
        [Parameter(Mandatory)][uint64]$ExpectedInventoryCanonicalByteCount,
        [Parameter(Mandatory)][string]$ExpectedInventorySha256,
        [Parameter(Mandatory)][string]$ExpectedRecoveryRecordPath,
        [Parameter(Mandatory)][string]$ExpectedCompletionRecordPath,
        [Parameter(Mandatory)][string]$ExpectedLifecycleTransitionPath,
        [Parameter(Mandatory)][string]$ExpectedSessionTombstonePath,
        [Parameter(Mandatory)][string]$ExpectedReasonCode
    )

    $match = [Regex]::Match(
        $Url,
        '^https://github\.com/(?<owner>[^/]+)/(?<repo>[^/]+)/issues/(?<issue>[1-9][0-9]*)#issuecomment-(?<comment>[1-9][0-9]*)\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success -or [int]$match.Groups['issue'].Value -ne $ExpectedIssue) {
        Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_TRACKER_URL_INVALID' `
            "tracker URL is not an exact issue-comment URL for #${ExpectedIssue}: $Url" `
            'post one fresh owner-authored evidence comment on the exact driving issue'
    }
    $comment = Invoke-AstroFsvGhJson ('repos/{0}/{1}/issues/comments/{2}' -f `
            $match.Groups['owner'].Value, $match.Groups['repo'].Value, `
            $match.Groups['comment'].Value)
    if ([string]$comment.html_url -cne $Url -or
        [string]$comment.author_association -cne 'OWNER') {
        Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_TRACKER_IDENTITY_INVALID' `
            'GitHub readback does not bind the exact owner-authored comment URL' `
            'use the canonical html_url of a repository-owner evidence comment'
    }
    $prefix = 'ASTRO_FSV_TERMINAL_PARTIAL_QUARANTINE_EVIDENCE '
    [string[]]$markers = @([string]$comment.body -split "`r?`n" |
            Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) })
    if ($markers.Count -ne 1) {
        Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_TRACKER_EVIDENCE_INVALID' `
            "tracker comment must contain exactly one '$prefix' line" `
            'post one fresh machine-readable terminal-partial quarantine evidence object'
    }
    try { $evidence = $markers[0].Substring($prefix.Length) | ConvertFrom-Json }
    catch {
        Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_TRACKER_EVIDENCE_INVALID' `
            "tracker evidence JSON is invalid: $($_.Exception.Message)" `
            'post one fresh exact JSON evidence object'
    }
    $expectedFields = @(
        'schema', 'issue', 'retirement_completion_path',
        'retirement_completion_sha256', 'receipt_path', 'receipt_sha256',
        'artifact_path', 'artifact_sha256', 'session_directory',
        'standard_output_path', 'standard_output_sha256', 'standard_error_path',
        'standard_error_sha256', 'run_record_path', 'run_record_state',
        'live_state_path', 'live_state_state', 'inventory_schema',
        'inventory_encoding', 'inventory_entry_count',
        'inventory_canonical_byte_count', 'inventory_sha256', 'owner_probe_state',
        'job_probe_state', 'recovery_record_path', 'completion_record_path',
        'lifecycle_transition_path', 'session_tombstone_path',
        'reason_code', 'authorized_action'
    )
    $actualFields = @($evidence.PSObject.Properties | ForEach-Object Name)
    if ($actualFields.Count -ne $expectedFields.Count -or
        @($expectedFields | Where-Object { $actualFields -notcontains $_ }).Count -ne 0) {
        Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_TRACKER_EVIDENCE_INVALID' `
            'tracker evidence fields differ from the exact terminal-partial quarantine contract' `
            'post a fresh object containing exactly the documented fields'
    }
    $expectedPaths = @(
        @('retirement_completion_path', $ExpectedRetirementCompletionPath),
        @('receipt_path', $ExpectedReceiptPath),
        @('artifact_path', $ExpectedArtifactPath),
        @('session_directory', $ExpectedSessionDirectory),
        @('standard_output_path', $ExpectedStandardOutputPath),
        @('standard_error_path', $ExpectedStandardErrorPath),
        @('run_record_path', $ExpectedRunRecordPath),
        @('live_state_path', $ExpectedLiveStatePath),
        @('recovery_record_path', $ExpectedRecoveryRecordPath),
        @('completion_record_path', $ExpectedCompletionRecordPath),
        @('lifecycle_transition_path', $ExpectedLifecycleTransitionPath),
        @('session_tombstone_path', $ExpectedSessionTombstonePath)
    )
    foreach ($pair in $expectedPaths) {
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath([string]$evidence.($pair[0])),
                [IO.Path]::GetFullPath([string]$pair[1]),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_TRACKER_EVIDENCE_MISMATCH' `
                "tracker evidence path differs for $($pair[0])" `
                're-read physical state and post a fresh exact evidence object'
        }
    }
    if ([string]$evidence.schema -cne
            'astrolabe.native-fsv-terminal-partial-quarantine-evidence.v1' -or
        [int]$evidence.issue -ne $ExpectedIssue -or
        [string]$evidence.retirement_completion_sha256 -cne
            $ExpectedRetirementCompletionSha256 -or
        [string]$evidence.receipt_sha256 -cne $ExpectedReceiptSha256 -or
        [string]$evidence.artifact_sha256 -cne $ExpectedArtifactSha256 -or
        [string]$evidence.standard_output_sha256 -cne
            $ExpectedStandardOutputSha256 -or
        [string]$evidence.standard_error_sha256 -cne
            $ExpectedStandardErrorSha256 -or
        [string]$evidence.run_record_state -cne 'absent' -or
        [string]$evidence.live_state_state -cne 'absent' -or
        [string]$evidence.inventory_schema -cne $ExpectedInventorySchema -or
        [string]$evidence.inventory_encoding -cne $ExpectedInventoryEncoding -or
        [int]$evidence.inventory_entry_count -ne $ExpectedInventoryEntryCount -or
        [uint64]$evidence.inventory_canonical_byte_count -ne
            $ExpectedInventoryCanonicalByteCount -or
        [string]$evidence.inventory_sha256 -cne $ExpectedInventorySha256 -or
        [string]$evidence.owner_probe_state -cne 'all-inactive' -or
        [string]$evidence.job_probe_state -cne 'absent' -or
        [string]$evidence.reason_code -cne $ExpectedReasonCode -or
        [string]$evidence.authorized_action -cne
            'quarantine-exact-terminal-partial-session-after-lock-retirement') {
        Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_TRACKER_EVIDENCE_MISMATCH' `
            'tracker evidence differs from the exact local terminal-partial session binding' `
            're-read physical state and post a fresh exact evidence object'
    }
    return [ordered]@{
        url = $Url
        comment_id = [long]$match.Groups['comment'].Value
        author = [string]$comment.user.login
        created_at = [string]$comment.created_at
        evidence = $evidence
    }
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
    if (-not (Test-AstroPathLongPath -LiteralPath $full -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_MISSING' "evidence receipt does not exist: $full" `
            'stage the native artifact first and pass its exact persisted receipt path'
    }
    try { $receipt = Read-AstroUtf8FileLongPath $full | ConvertFrom-Json }
    catch {
        Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' "parse evidence receipt '$full' failed: $($_.Exception.Message)" `
            'discard the incomplete evidence session and stage the artifact again'
    }
    if ($receipt.schema -eq 'astrolabe.native-fsv-artifact.v1') {
        Fail-Astro 'ASTRO_FSV_RECEIPT_LEGACY_MIGRATION_REQUIRED' `
            "evidence receipt '$full' uses legacy PID-only schema v1" `
            'preserve the session and use MigrateLegacy with a fresh owner-authored tracker evidence comment; never infer missing process generations'
    }
    if ($receipt.schema -ne 'astrolabe.native-fsv-artifact.v2' -or
        -not $receipt.PSObject.Properties['owners'] -or
        -not $receipt.owners.PSObject.Properties['launcher'] -or
        -not $receipt.owners.PSObject.Properties['promoter'] -or
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
    $launcherIdentity = Read-AstroFsvProcessIdentity `
        -Object $receipt.owners.launcher `
        -Code 'ASTRO_FSV_RECEIPT_INVALID' `
        -Description 'artifact receipt launcher identity'
    $promoterIdentity = Read-AstroFsvProcessIdentity `
        -Object $receipt.owners.promoter `
        -Code 'ASTRO_FSV_RECEIPT_INVALID' `
        -Description 'artifact receipt promoter identity'
    $expectedSession = Join-Path (Join-Path (Join-Path $EvidenceRoot ([string]$receipt.tree_sha)) `
        ([string]$receipt.artifact.sha256)) ([string]$receipt.session_id)
    if (-not [string]::Equals($sessionDirectory, [IO.Path]::GetFullPath($expectedSession), [StringComparison]::OrdinalIgnoreCase)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_PATH_MISMATCH' `
            "receipt path '$sessionDirectory' does not match its tree/hash/session identity '$expectedSession'" `
            'discard the cross-session or relocated receipt and stage a fresh artifact'
    }
    $artifact = Assert-PathWithin ([string]$receipt.artifact.path) $sessionDirectory `
        'ASTRO_FSV_ARTIFACT_ESCAPE' 'staged artifact path'
    if (-not (Test-AstroPathLongPath -LiteralPath $artifact -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_ARTIFACT_MISSING' "staged native artifact is absent: $artifact" `
            'treat this evidence session as invalid and stage a fresh artifact'
    }
    Assert-NotReparseEntry $artifact 'staged native artifact'
    $item = Get-AstroFileInfoLongPath $artifact
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
        owners = [ordered]@{
            launcher = $launcherIdentity
            promoter = $promoterIdentity
        }
        owner_probes = @(
            Get-AstroFsvOwnerProbes @(
                New-AstroFsvOwnerBinding `
                    'launcher' 'artifact receipt' $launcherIdentity
                New-AstroFsvOwnerBinding `
                    'promoter' 'artifact receipt' $promoterIdentity
            )
        )
    }
}

function Assert-FsvLockAbsent {
    param([Parameter(Mandatory)][string]$LockPath)
    if (-not (Test-AstroPathLongPath -LiteralPath $LockPath)) { return }
    try {
        $lockState = Read-AstroUtf8FileLongPath $LockPath | ConvertFrom-Json
    }
    catch {
        Fail-Astro 'ASTRO_FSV_LOCK_INVALID' `
            "FSV lock exists but is unreadable at ${LockPath}: $($_.Exception.Message)" `
            'preserve the lock and session; repair or tracker-migrate the exact legacy state without inferring ownership'
    }
    if ($lockState.schema -notin @(
            'astrolabe.native-fsv-lock.v2',
            'astrolabe.native-fsv-lock.v3'
        )) {
        Fail-Astro 'ASTRO_FSV_LOCK_LEGACY_OR_UNKNOWN' `
            "FSV lock exists with unsupported schema '$($lockState.schema)' at $LockPath" `
            'preserve the lock and session; PID-only state has no destructive authority'
    }
    if (-not $lockState.PSObject.Properties['owners'] -or
        -not $lockState.owners.PSObject.Properties['launcher'] -or
        -not $lockState.owners.PSObject.Properties['runner']) {
        Fail-Astro 'ASTRO_FSV_LOCK_INVALID' `
            "FSV lock omits the required launcher, runner, or child identity field at $LockPath" `
            'preserve the lock and session; incomplete exact ownership has no destructive authority'
    }
    $bindings = New-Object System.Collections.Generic.List[object]
    foreach ($role in @('launcher', 'runner')) {
        $identity = Read-AstroFsvProcessIdentity $lockState.owners.$role `
            'ASTRO_FSV_LOCK_INVALID' "FSV lock $role identity"
        $bindings.Add((New-AstroFsvOwnerBinding $role 'FSV lock' $identity))
    }
    if ([string]$lockState.schema -ceq 'astrolabe.native-fsv-lock.v2') {
        if (-not $lockState.owners.PSObject.Properties['child']) {
            Fail-Astro 'ASTRO_FSV_LOCK_INVALID' `
                "v2 FSV lock omits its child field at $LockPath" `
                'preserve the lock/session; incomplete exact ownership has no destructive authority'
        }
        if ($null -ne $lockState.owners.child) {
            $identity = Read-AstroFsvProcessIdentity $lockState.owners.child `
                'ASTRO_FSV_LOCK_INVALID' 'FSV lock child identity'
            $bindings.Add((New-AstroFsvOwnerBinding 'child' 'FSV lock' $identity))
        }
    }
    else {
        if (-not $lockState.PSObject.Properties['resident_count'] -or
            -not $lockState.PSObject.Properties['process_count'] -or
            -not $lockState.owners.PSObject.Properties['processes']) {
            Fail-Astro 'ASTRO_FSV_LOCK_INVALID' `
                "v3 FSV lock omits its process array/cardinality at $LockPath" `
                'preserve the lock/session; incomplete exact ownership has no destructive authority'
        }
        $processes = Read-AstroFsvV3ProcessEntries `
            $lockState.owners.processes ([int]$lockState.resident_count) `
            ([int]$lockState.process_count) `
            'ASTRO_FSV_LOCK_INVALID' 'FSV-lock v3 process set'
        Add-AstroFsvV3ProcessBindings $bindings $processes 'FSV lock'
    }
    $probes = @(
        Get-AstroFsvOwnerProbes ([object[]]$bindings.ToArray())
    )
    $states = @($probes | ForEach-Object { $_.state })
    $code = if ($states -contains 'exact-live') {
        'ASTRO_FSV_CLEANUP_LIVE_LOCK'
    }
    elseif ($states -contains 'unevaluable') {
        'ASTRO_FSV_CLEANUP_UNEVALUABLE_LOCK'
    }
    else {
        'ASTRO_FSV_CLEANUP_STALE_LOCK'
    }
    Fail-Astro $code `
        "FSV lock exists at $LockPath; lifecycle mutation refused; exact_probes=$($probes | ConvertTo-Json -Depth 8 -Compress)" `
        'never remove or bypass an FSV lock; resolve it through its exact tracker-bound lifecycle'
}

function Get-SessionFileInventory {
    param([Parameter(Mandatory)][string]$Session)
    $inventory = @()
    foreach ($entry in @(Get-AstroDirectoryEntriesLongPath $Session)) {
        Assert-NotReparseEntry $entry.FullName "evidence session entry '$($entry.Name)'"
        if (-not $entry.PSIsContainer -and
            -not (Test-AstroPathLongPath -LiteralPath $entry.FullName -PathType Leaf)) {
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

function Read-AstroFsvInterruptedV2PhysicalState {
    param(
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [Parameter(Mandatory)][string]$ReceiptInputPath,
        [Parameter(Mandatory)]$LockState,
        [Parameter(Mandatory)][string]$LockSha256,
        [Parameter(Mandatory)][string]$LiveStateInputPath,
        [Parameter(Mandatory)][string]$StandardOutputInputPath,
        [Parameter(Mandatory)][string]$StandardErrorInputPath,
        [Parameter(Mandatory)][string]$RunRecordInputPath,
        [Parameter(Mandatory)]$LauncherRecoveryChain
    )

    $code = 'ASTRO_FSV_INTERRUPTED_V2_STATE_INVALID'
    $receiptState = Read-Receipt $ReceiptInputPath $EvidenceRoot
    $inspection = Inspect-ReceiptArtifact $receiptState $EvidenceRoot
    if ([int]$inspection.issue -ne $ExpectedIssue) {
        Fail-Astro $code `
            "requested issue #$ExpectedIssue differs from receipt issue #$($inspection.issue)" `
            'select only the exact interrupted session bound to the driving issue'
    }
    $lockFields = @($LockState.PSObject.Properties | ForEach-Object Name)
    $expectedLockFields = @(
        'schema', 'issue', 'started', 'command', 'argument_count', 'arguments',
        'argument_source', 'tree_sha', 'artifact_path', 'artifact_sha256',
        'owners', 'launcher_job', 'phase'
    )
    $lockOwnerFields = if ($LockState.PSObject.Properties['owners']) {
        @($LockState.owners.PSObject.Properties | ForEach-Object Name)
    } else { @() }
    $lockJobFields = if ($LockState.PSObject.Properties['launcher_job']) {
        @($LockState.launcher_job.PSObject.Properties | ForEach-Object Name)
    } else { @() }
    if ($lockFields.Count -ne $expectedLockFields.Count -or
        @($expectedLockFields | Where-Object { $lockFields -notcontains $_ }).Count -ne 0 -or
        [string]$LockState.schema -cne 'astrolabe.native-fsv-lock.v2' -or
        [string]$LockState.phase -cne 'running' -or
        [int]$LockState.issue -ne $ExpectedIssue -or
        [string]$LockState.tree_sha -cne [string]$inspection.tree_sha -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$LockState.artifact_path),
            $inspection.artifact_path,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$LockState.artifact_sha256 -cne [string]$inspection.sha256 -or
        [string]::IsNullOrWhiteSpace([string]$LockState.command) -or
        [int]$LockState.argument_count -ne @($LockState.arguments).Count -or
        -not $LockState.PSObject.Properties['owners'] -or
        $lockOwnerFields.Count -ne 3 -or
        @('launcher', 'runner', 'child' | Where-Object {
                $lockOwnerFields -notcontains $_
            }).Count -ne 0 -or
        -not $LockState.owners.PSObject.Properties['launcher'] -or
        -not $LockState.owners.PSObject.Properties['runner'] -or
        -not $LockState.owners.PSObject.Properties['child'] -or
        -not $LockState.PSObject.Properties['launcher_job'] -or
        $lockJobFields.Count -ne 2 -or
        @('name', 'members' | Where-Object {
                $lockJobFields -notcontains $_
            }).Count -ne 0 -or
        -not $LockState.launcher_job.PSObject.Properties['name'] -or
        -not $LockState.launcher_job.PSObject.Properties['members']) {
        Fail-Astro $code `
            'source lock is not one complete running v2 generation bound to the selected artifact' `
            'preserve mixed, incomplete, completed, and non-v2 state'
    }
    $lockLauncher = Read-AstroFsvProcessIdentity $LockState.owners.launcher `
        $code 'interrupted v2 lock launcher identity'
    $lockRunner = Read-AstroFsvProcessIdentity $LockState.owners.runner `
        $code 'interrupted v2 lock runner identity'
    $lockChild = Read-AstroFsvProcessIdentity $LockState.owners.child `
        $code 'interrupted v2 lock child identity'
    if (-not (Test-AstroFsvIdentityEqual $lockLauncher $inspection.owners.launcher)) {
        Fail-Astro $code `
            'receipt and interrupted v2 lock launcher generations differ' `
            'preserve the cross-generation state and investigate its publisher'
    }
    $matchingLauncherArchive = @($LauncherRecoveryChain.archives | Where-Object {
            [int]$_.authorization.value.generation.launcher_pid -eq
                [int]$lockLauncher.pid -and
            [long]$_.authorization.value.generation.launcher_process_start_utc_ticks -eq
                [long]$lockLauncher.process_start_utc_ticks
        })
    $jobName = [string]$LockState.launcher_job.name
    if ($matchingLauncherArchive.Count -ne 1 -or
        $jobName -cne [string]$matchingLauncherArchive[0].job_name) {
        Fail-Astro $code `
            'interrupted v2 lock Job/launcher generation is not the exact archived launcher generation' `
            'supply the exact launcher recovery, target recovery, and pair archive chain'
    }
    [int[]]$jobMembers = @($LockState.launcher_job.members)
    if ($jobMembers.Count -ne @($jobMembers | Sort-Object -Unique).Count -or
        $jobMembers -contains 0 -or
        $jobMembers -notcontains [int]$lockLauncher.pid -or
        $jobMembers -notcontains [int]$lockRunner.pid) {
        Fail-Astro $code `
            'interrupted v2 lock launcher Job membership is malformed' `
            'preserve the generation and investigate its original attribution'
    }

    $session = [IO.Path]::GetFullPath($inspection.session_directory)
    $liveStatePath = Assert-DirectSessionChildPath $LiveStateInputPath $session `
        $code 'live-state path'
    $stdoutPath = Assert-DirectSessionChildPath $StandardOutputInputPath $session `
        $code 'standard-output path'
    $stderrPath = Assert-DirectSessionChildPath $StandardErrorInputPath $session `
        $code 'standard-error path'
    $runRecordPath = Assert-DirectSessionChildPath $RunRecordInputPath $session `
        $code 'expected run-record path'
    $claimedPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($claimedPath in @(
            $receiptState.Path, $inspection.artifact_path, $liveStatePath,
            $stdoutPath, $stderrPath, $runRecordPath
        )) {
        if (-not $claimedPaths.Add([IO.Path]::GetFullPath($claimedPath))) {
            Fail-Astro $code `
                "interrupted receipt/artifact/live/output/run paths collide: $claimedPath" `
                'preserve the session and bind six pairwise-distinct direct paths'
        }
    }
    if (-not (Test-AstroPathLongPath -LiteralPath $liveStatePath -PathType Leaf) -or
        -not (Test-AstroPathLongPath -LiteralPath $stdoutPath -PathType Leaf) -or
        -not (Test-AstroPathLongPath -LiteralPath $stderrPath -PathType Leaf)) {
        Fail-Astro $code `
            'live state and both output files must physically exist' `
            'preserve the session; a complete interrupted child publication is not proven'
    }
    if (Test-AstroPathLongPath -LiteralPath $runRecordPath) {
        Fail-Astro $code `
            'expected run record is present' `
            'use completed-run RetireLock/Cleanup for valid terminal state; preserve malformed state'
    }
    foreach ($path in @($liveStatePath, $stdoutPath, $stderrPath)) {
        Assert-NotReparseEntry $path 'interrupted v2 session control/output file'
    }
    try { $liveState = Read-AstroUtf8FileLongPath $liveStatePath | ConvertFrom-Json }
    catch {
        Fail-Astro $code `
            "parse live state '$liveStatePath' failed: $($_.Exception.Message)" `
            'preserve the exact session and investigate its incomplete provenance'
    }
    $liveFields = @($liveState.PSObject.Properties | ForEach-Object Name)
    $expectedLiveFields = @(
        'schema', 'owners', 'launcher_job', 'issue', 'tree_sha', 'artifact',
        'started_at_utc', 'argument_count', 'arguments', 'argument_source'
    )
    $liveOwnerFields = if ($liveState.PSObject.Properties['owners']) {
        @($liveState.owners.PSObject.Properties | ForEach-Object Name)
    } else { @() }
    $liveJobFields = if ($liveState.PSObject.Properties['launcher_job']) {
        @($liveState.launcher_job.PSObject.Properties | ForEach-Object Name)
    } else { @() }
    $liveArtifactFields = if ($liveState.PSObject.Properties['artifact']) {
        @($liveState.artifact.PSObject.Properties | ForEach-Object Name)
    } else { @() }
    if ($liveFields.Count -ne $expectedLiveFields.Count -or
        @($expectedLiveFields | Where-Object { $liveFields -notcontains $_ }).Count -ne 0 -or
        $liveOwnerFields.Count -ne 3 -or
        @('launcher', 'runner', 'child' | Where-Object {
                $liveOwnerFields -notcontains $_
            }).Count -ne 0 -or
        $liveJobFields.Count -ne 2 -or
        @('name', 'members_before' | Where-Object {
                $liveJobFields -notcontains $_
            }).Count -ne 0 -or
        $liveArtifactFields.Count -ne 3 -or
        @('path', 'bytes', 'sha256' | Where-Object {
                $liveArtifactFields -notcontains $_
            }).Count -ne 0 -or
        [string]$liveState.schema -cne 'astrolabe.native-fsv-live.v2' -or
        [int]$liveState.issue -ne $ExpectedIssue -or
        [string]$liveState.tree_sha -cne [string]$inspection.tree_sha -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$liveState.artifact.path),
            $inspection.artifact_path,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [uint64]$liveState.artifact.bytes -ne [uint64]$inspection.bytes -or
        [string]$liveState.artifact.sha256 -cne [string]$inspection.sha256 -or
        [string]$liveState.launcher_job.name -cne $jobName -or
        (@($liveState.launcher_job.members_before) |
            Sort-Object | ConvertTo-Json -Compress) -cne
            (@($LockState.launcher_job.members) |
                Sort-Object | ConvertTo-Json -Compress) -or
        [int]$liveState.argument_count -ne [int]$LockState.argument_count -or
        ($liveState.arguments | ConvertTo-Json -Depth 10 -Compress) -cne
            ($LockState.arguments | ConvertTo-Json -Depth 10 -Compress) -or
        ($liveState.argument_source | ConvertTo-Json -Depth 10 -Compress) -cne
            ($LockState.argument_source | ConvertTo-Json -Depth 10 -Compress)) {
        Fail-Astro $code `
            'live state is not the exact child publication bound to the running v2 lock' `
            'preserve the cross-generation or drifted state'
    }
    $liveLauncher = Read-AstroFsvProcessIdentity $liveState.owners.launcher `
        $code 'interrupted v2 live launcher identity'
    $liveRunner = Read-AstroFsvProcessIdentity $liveState.owners.runner `
        $code 'interrupted v2 live runner identity'
    $liveChild = Read-AstroFsvProcessIdentity $liveState.owners.child `
        $code 'interrupted v2 live child identity'
    if (-not (Test-AstroFsvIdentityEqual $liveLauncher $lockLauncher) -or
        -not (Test-AstroFsvIdentityEqual $liveRunner $lockRunner) -or
        -not (Test-AstroFsvIdentityEqual $liveChild $lockChild)) {
        Fail-Astro $code `
            'v2 live-state owner generations differ from the source lock' `
            'preserve the session and investigate cross-run provenance'
    }

    $sessionFiles = @(Get-SessionFileInventory $session)
    $sessionTree = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $session
    $allowedPaths = @(
        [IO.Path]::GetFullPath($receiptState.Path),
        [IO.Path]::GetFullPath($inspection.artifact_path),
        [IO.Path]::GetFullPath($liveStatePath),
        [IO.Path]::GetFullPath($stdoutPath),
        [IO.Path]::GetFullPath($stderrPath)
    )
    $inventoryPaths = @($sessionFiles | ForEach-Object { [IO.Path]::GetFullPath([string]$_.path) })
    if ($sessionFiles.Count -ne 5 -or
        [int]$sessionTree.entry_count -ne ($sessionFiles.Count + 1) -or
        [string]$sessionTree.entries[0].relative_path -cne '.' -or
        [string]$sessionTree.entries[0].kind -cne 'directory' -or
        @($inventoryPaths | Where-Object { $allowedPaths -notcontains $_ }).Count -ne 0 -or
        @($allowedPaths | Where-Object { $inventoryPaths -notcontains $_ }).Count -ne 0) {
        Fail-Astro $code `
            'interrupted v2 session inventory is not exactly artifact/receipt/live/stdout/stderr' `
            'preserve any missing, unexpected, nested, or mixed-generation state'
    }

    $ownerBindingList = [Collections.Generic.List[object]]::new()
    foreach ($binding in @(
            New-AstroFsvOwnerBinding 'launcher' 'artifact receipt' $inspection.owners.launcher
            New-AstroFsvOwnerBinding 'promoter' 'artifact receipt' $inspection.owners.promoter
            New-AstroFsvOwnerBinding 'launcher' 'interrupted v2 lock' $lockLauncher
            New-AstroFsvOwnerBinding 'runner' 'interrupted v2 lock' $lockRunner
            New-AstroFsvOwnerBinding 'child' 'interrupted v2 lock' $lockChild
            New-AstroFsvOwnerBinding 'launcher' 'interrupted v2 live state' $liveLauncher
            New-AstroFsvOwnerBinding 'runner' 'interrupted v2 live state' $liveRunner
            New-AstroFsvOwnerBinding 'child' 'interrupted v2 live state' $liveChild
        )) { $ownerBindingList.Add($binding) }
    foreach ($archive in $LauncherRecoveryChain.archives) {
        $generation = $archive.authorization.value.generation
        $archiveIdentity = New-AstroProcessIdentityRecord `
            ([int]$generation.launcher_pid) `
            ([long]$generation.launcher_process_start_utc_ticks)
        $ownerBindingList.Add((New-AstroFsvOwnerBinding `
                    'launcher' 'launcher recovery/archive chain' $archiveIdentity))
    }
    return [ordered]@{
        receipt_state = $receiptState
        receipt_sha256 = File-Sha256 $receiptState.Path
        inspection = $inspection
        lock_state = $LockState
        lock_sha256 = $LockSha256
        lock_launcher = $lockLauncher
        lock_runner = $lockRunner
        lock_child = $lockChild
        launcher_job_name = $jobName
        live_state_path = $liveStatePath
        live_state = $liveState
        live_state_sha256 = File-Sha256 $liveStatePath
        stdout_path = $stdoutPath
        stdout_sha256 = File-Sha256 $stdoutPath
        stderr_path = $stderrPath
        stderr_sha256 = File-Sha256 $stderrPath
        run_record_path = $runRecordPath
        session_directory = $session
        session_files = $sessionFiles
        session_tree = $sessionTree
        owner_bindings = [object[]]$ownerBindingList.ToArray()
    }
}

function Get-AstroFsvSessionOwnerBindings {
    param(
        [Parameter(Mandatory)]$ReceiptState,
        [Parameter(Mandatory)]$Inspection,
        [Parameter(Mandatory)][string]$RunRecordPath,
        [Parameter(Mandatory)]$RunRecord
    )

    $bindings = New-Object System.Collections.Generic.List[object]
    $bindings.Add((New-AstroFsvOwnerBinding `
                'launcher' 'artifact receipt' $Inspection.owners.launcher))
    $bindings.Add((New-AstroFsvOwnerBinding `
                'promoter' 'artifact receipt' $Inspection.owners.promoter))
    $runLauncher = Read-AstroFsvProcessIdentity $RunRecord.launcher `
        'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
        'run-record launcher identity'
    $runRunner = Read-AstroFsvProcessIdentity $RunRecord.runner `
        'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
        'run-record runner identity'
    if (-not (Test-AstroFsvIdentityEqual `
            $Inspection.owners.launcher $runLauncher)) {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "run-record launcher generation differs from its receipt: $RunRecordPath" `
            'preserve the complete session and investigate cross-lease provenance'
    }
    $bindings.Add((New-AstroFsvOwnerBinding `
                'launcher' $RunRecordPath $runLauncher))
    $bindings.Add((New-AstroFsvOwnerBinding `
                'runner' $RunRecordPath $runRunner))
    $runVersion = $null
    $runChild = $null
    $runProcesses = [object[]]@()
    $residentCount = 0
    $processCount = 0
    if ([string]$RunRecord.schema -ceq 'astrolabe.native-fsv-run.v2') {
        if (-not $RunRecord.PSObject.Properties['process'] -or
            -not $RunRecord.process.PSObject.Properties['identity']) {
            Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
                "v2 run record omits its exact child identity: $RunRecordPath" `
                'preserve the complete session and investigate its partial durable state'
        }
        $runVersion = 2
        $runChild = Read-AstroFsvProcessIdentity $RunRecord.process.identity `
            'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            'run-record child identity'
        $bindings.Add((New-AstroFsvOwnerBinding `
                    'child' $RunRecordPath $runChild))
    }
    elseif ([string]$RunRecord.schema -ceq 'astrolabe.native-fsv-run.v3') {
        if (-not $RunRecord.PSObject.Properties['resident_count'] -or
            -not $RunRecord.PSObject.Properties['process_count'] -or
            -not $RunRecord.PSObject.Properties['processes']) {
            Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
                "v3 run record omits its process-array cardinality: $RunRecordPath" `
                'preserve the complete session and investigate its partial durable state'
        }
        $runVersion = 3
        $residentCount = [int]$RunRecord.resident_count
        $processCount = [int]$RunRecord.process_count
        $runProcesses = Read-AstroFsvV3ProcessEntries `
            $RunRecord.processes $residentCount $processCount `
            'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' 'run-record v3 process set'
        Add-AstroFsvV3ProcessBindings $bindings $runProcesses $RunRecordPath
    }
    else {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "run-record schema is unsupported: $($RunRecord.schema)" `
            'preserve the complete session and use an explicitly supported lifecycle schema'
    }

    if (-not $RunRecord.PSObject.Properties['live_state'] -or
        -not $RunRecord.live_state.PSObject.Properties['path'] -or
        -not $RunRecord.live_state.PSObject.Properties['published'] -or
        -not $RunRecord.live_state.PSObject.Properties['bytes'] -or
        -not $RunRecord.live_state.PSObject.Properties['sha256']) {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "run record omits its exact live-state publication binding: $RunRecordPath" `
            'preserve the complete session and investigate its partial durable state'
    }
    $liveStatePath = Assert-PathWithin `
        ([string]$RunRecord.live_state.path) `
        $Inspection.session_directory `
        'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
        'run-record live-state path'
    if (-not [bool]$RunRecord.live_state.published) {
        if (Test-AstroPathLongPath -LiteralPath $liveStatePath) {
            Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
                "run record says its live state was not published, but the path exists: $liveStatePath" `
                'preserve the complete session and investigate the contradictory durable state'
        }
        if ([uint64]$RunRecord.live_state.bytes -ne 0 -or
            $null -ne $RunRecord.live_state.sha256) {
            Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
                "unpublished live-state binding carries bytes or a hash: $RunRecordPath" `
                'preserve the complete session and investigate the contradictory durable state'
        }
        return [object[]]$bindings.ToArray()
    }
    if (-not (Test-AstroPathLongPath `
            -LiteralPath $liveStatePath -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "run record binds a published live state that is absent: $liveStatePath" `
            'preserve the complete session and investigate its missing durable state'
    }
    $liveStateItem = Get-AstroFileInfoLongPath $liveStatePath
    $liveStateHash = File-Sha256 $liveStatePath
    if ([uint64]$RunRecord.live_state.bytes -ne
            [uint64]$liveStateItem.Length -or
        [string]$RunRecord.live_state.sha256 -cne $liveStateHash) {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "run-record live-state bytes drifted: $liveStatePath" `
            'preserve the complete session and investigate the durable-state writer'
    }
    Assert-NotReparseEntry $liveStatePath 'native FSV live-state record'
    try {
        $liveRecord = Read-AstroUtf8FileLongPath $liveStatePath |
            ConvertFrom-Json
    }
    catch {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "live-state record is unreadable: ${liveStatePath}: $($_.Exception.Message)" `
            'preserve the complete session and investigate its partial durable state'
    }
    $expectedLiveSchema = if ($runVersion -eq 2) {
        'astrolabe.native-fsv-live.v2'
    } else {
        'astrolabe.native-fsv-live.v3'
    }
    if ($liveRecord.schema -cne $expectedLiveSchema -or
        -not $liveRecord.PSObject.Properties['owners'] -or
        -not $liveRecord.owners.PSObject.Properties['launcher'] -or
        -not $liveRecord.owners.PSObject.Properties['runner'] -or
        -not $liveRecord.PSObject.Properties['artifact'] -or
        -not $liveRecord.artifact.PSObject.Properties['path'] -or
        -not $liveRecord.artifact.PSObject.Properties['sha256']) {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "live-state record omits required exact ownership or artifact binding: $liveStatePath" `
            'preserve the complete session and investigate its partial durable state'
    }
    if ([int]$liveRecord.issue -ne [int]$Inspection.issue -or
        [string]$liveRecord.tree_sha -cne [string]$Inspection.tree_sha -or
        [string]$liveRecord.artifact.sha256 -cne [string]$Inspection.sha256 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$liveRecord.artifact.path),
            [IO.Path]::GetFullPath($Inspection.artifact_path),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "live-state record is not bound to this session: $liveStatePath" `
            'preserve the complete session and investigate cross-session provenance'
    }
    $liveLauncher = Read-AstroFsvProcessIdentity `
        $liveRecord.owners.launcher `
        'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
        'live-state launcher identity'
    $liveRunner = Read-AstroFsvProcessIdentity `
        $liveRecord.owners.runner `
        'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
        'live-state runner identity'
    if (-not (Test-AstroFsvIdentityEqual $runLauncher $liveLauncher) -or
        -not (Test-AstroFsvIdentityEqual $runRunner $liveRunner)) {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "live-state owner generations differ from the exact run record: $liveStatePath" `
            'preserve the complete session and investigate cross-run provenance'
    }
    foreach ($binding in @(
            (New-AstroFsvOwnerBinding 'launcher' $liveStatePath $liveLauncher),
            (New-AstroFsvOwnerBinding 'runner' $liveStatePath $liveRunner)
        )) {
        $bindings.Add($binding)
    }
    if ($runVersion -eq 2) {
        if (-not $liveRecord.owners.PSObject.Properties['child']) {
            Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
                "v2 live state omits its exact child identity: $liveStatePath" `
                'preserve the complete session and investigate its partial durable state'
        }
        $liveChild = Read-AstroFsvProcessIdentity `
            $liveRecord.owners.child `
            'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            'live-state child identity'
        if (-not (Test-AstroFsvIdentityEqual $runChild $liveChild)) {
            Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
                "v2 live-state child generation differs from the run record: $liveStatePath" `
                'preserve the complete session and investigate cross-run provenance'
        }
        $bindings.Add((New-AstroFsvOwnerBinding `
                    'child' $liveStatePath $liveChild))
    }
    else {
        if (-not $liveRecord.PSObject.Properties['resident_count'] -or
            -not $liveRecord.PSObject.Properties['process_count'] -or
            -not $liveRecord.owners.PSObject.Properties['processes'] -or
            [int]$liveRecord.resident_count -ne $residentCount -or
            [int]$liveRecord.process_count -ne $processCount) {
            Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
                "v3 live-state process cardinality differs from its run record: $liveStatePath" `
                'preserve the complete session and investigate cross-run provenance'
        }
        $liveProcesses = Read-AstroFsvV3ProcessEntries `
            $liveRecord.owners.processes $residentCount $processCount `
            'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' 'live-state v3 process set'
        if (-not (Test-AstroFsvV3ProcessEntriesEqual `
                $runProcesses $liveProcesses)) {
            Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
                "v3 live-state process generations differ from the run record: $liveStatePath" `
                'preserve the complete session and investigate cross-run provenance'
        }
        Add-AstroFsvV3ProcessBindings $bindings $liveProcesses $liveStatePath
    }
    return [object[]]$bindings.ToArray()
}

function Remove-EmptyEvidenceParents {
    param([Parameter(Mandatory)][string]$Session)

    foreach ($parent in @(
            (Split-Path -Parent $Session),
            (Split-Path -Parent (Split-Path -Parent $Session))
        )) {
        if ((Test-AstroPathLongPath -LiteralPath $parent -PathType Container) -and
            @(Get-AstroDirectoryEntriesLongPath $parent).Count -eq 0) {
            Remove-AstroEmptyDirectoryLongPath $parent
        }
    }
}

function Invoke-AstroFsvPartialLockRetirementResume {
    param(
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][string]$Workspace,
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [Parameter(Mandatory)][string]$RecoveryRoot,
        [Parameter(Mandatory)][string]$FsvLockPath,
        [Parameter(Mandatory)][string]$LifecycleTransitionPath,
        [Parameter(Mandatory)][string]$ReceiptInputPath,
        [Parameter(Mandatory)][string]$RecoveryInputPath,
        [Parameter(Mandatory)][string]$StandardOutputInputPath,
        [Parameter(Mandatory)][string]$StandardErrorInputPath,
        [Parameter(Mandatory)][string]$RunRecordInputPath,
        [Parameter(Mandatory)][string]$LiveStateInputPath,
        [Parameter(Mandatory)][string]$TrackerUrl,
        [Parameter(Mandatory)][string]$FailureCode,
        [Parameter(Mandatory)][string]$FailureMessage,
        [Parameter(Mandatory)][AllowEmptyString()]
        [string]$LauncherRecoveryInputPath,
        [Parameter(Mandatory)][AllowEmptyString()]
        [string]$TargetRecoveryInputPath,
        [Parameter(Mandatory)][AllowEmptyCollection()]
        [string[]]$ArchiveCompletionInputPaths,
        [Parameter(Mandatory)][ValidateSet(
            'DeadOwnerRecoveryV1', 'NormalLiveOwnerCleanupV1')]
        [string]$LauncherTerminalChainKind,
        [AllowEmptyString()][string]$NormalArchiveCompletionInputPath = ''
    )
    $code = 'ASTRO_FSV_PARTIAL_LOCK_RESUME_INVALID'
    $authorizationPath = Assert-PathWithin $RecoveryInputPath $RecoveryRoot $code `
        'partial-lock retirement authorization path'
    $archivePath = $authorizationPath + '.lock.bin'
    $completionPath = $authorizationPath + '.completed.json'
    $transitionPresent = (Get-AstroFsvStrictPathState `
            $LifecycleTransitionPath file $code 'canonical FSV lifecycle transition').state -ceq
        'present'
    $authorizationPresent = (Get-AstroFsvStrictPathState `
            $authorizationPath file $code 'partial-lock authorization archive').state -ceq
        'present'
    $archivePresent = (Get-AstroFsvStrictPathState `
            $archivePath file $code 'archived terminal-partial FSV lock').state -ceq
        'present'
    $completionPresent = (Get-AstroFsvStrictPathState `
            $completionPath file $code 'partial-lock retirement completion').state -ceq
        'present'
    if ($transitionPresent -and $authorizationPresent) {
        Fail-Astro $code 'canonical transition and archived authorization are both present' `
            'preserve both namespaces and investigate the interrupted no-replace archive'
    }
    if (-not $transitionPresent -and -not $authorizationPresent) {
        Fail-Astro $code 'resume state lacks both canonical transition and authorization' `
            'preserve archive/completion bytes and restore only through their exact authored transition'
    }
    $activeAuthorizationPath = if ($transitionPresent) {
        $LifecycleTransitionPath
    } else { $authorizationPath }
    $authorization = Read-AstroFsvExactJsonFile `
        $activeAuthorizationPath $code 'terminal-partial lock retirement authorization'
    $value = $authorization.value
    foreach ($pair in @(
            @([string]$value.authorization_record_path, $authorizationPath),
            @([string]$value.lifecycle_transition_path, $LifecycleTransitionPath),
            @([string]$value.completion_record_path, $completionPath),
            @([string]$value.fsv_lock.path, $FsvLockPath),
            @([string]$value.fsv_lock.archive_path, $archivePath),
            @([string]$value.receipt_path, [IO.Path]::GetFullPath($ReceiptInputPath)),
            @([string]$value.outputs.stdout.path, [IO.Path]::GetFullPath($StandardOutputInputPath)),
            @([string]$value.outputs.stderr.path, [IO.Path]::GetFullPath($StandardErrorInputPath)),
            @([string]$value.expected_controls.run_record_path, [IO.Path]::GetFullPath($RunRecordInputPath)),
            @([string]$value.expected_controls.live_state_path, [IO.Path]::GetFullPath($LiveStateInputPath))
        )) {
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath([string]$pair[0]),
                [IO.Path]::GetFullPath([string]$pair[1]),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro $code 'resume arguments differ from the durable authorization path family' `
                'resume only with the exact paths bound by the canonical transition'
        }
    }
    $expectedAuthorizationSchema = if ($LauncherTerminalChainKind -ceq
        'NormalLiveOwnerCleanupV1') {
        'astrolabe.native-fsv-partial-lock-retirement.authorization.v2'
    } else {
        'astrolabe.native-fsv-partial-lock-retirement.authorization.v1'
    }
    if ([string]$value.schema -cne $expectedAuthorizationSchema -or
        [string]$value.phase -cne 'authorized-exact-terminal-partial-lock' -or
        [int]$value.issue -ne $ExpectedIssue -or
        [string]$value.failure.code -cne $FailureCode -or
        [string]$value.failure.message -cne $FailureMessage -or
        [string]$value.tracker.url -cne $TrackerUrl -or
        [string]$value.expected_controls.run_record_state -cne 'absent' -or
        [string]$value.expected_controls.live_state_state -cne 'absent') {
        Fail-Astro $code 'durable retirement authorization differs from the requested transaction' `
            'preserve every byte and resume only the exact tracker-bound transaction'
    }
    $chain = Read-AstroFsvLauncherTerminalChainFromInputs `
        -Kind $LauncherTerminalChainKind `
        -ExpectedIssue $ExpectedIssue -Workspace $Workspace `
        -LauncherRecoveryPath $LauncherRecoveryInputPath `
        -TargetRecoveryPath $TargetRecoveryInputPath `
        -ArchiveCompletionPaths $ArchiveCompletionInputPaths `
        -NormalArchiveCompletionPath $NormalArchiveCompletionInputPath
    if ($LauncherTerminalChainKind -ceq 'DeadOwnerRecoveryV1') {
        Assert-AstroFsvPersistedDeadOwnerRecoveryTerminalChain `
            -Persisted $value.launcher_recovery_chain -Physical $chain `
            -Code $code -Description 'durable launcher recovery chain'
    }
    else {
        Assert-AstroFsvPersistedNormalCleanupTerminalChain `
            -Persisted $value.launcher_terminal_chain -Physical $chain `
            -Code $code -Description 'durable launcher terminal chain'
    }
    $receiptState = Read-Receipt $ReceiptInputPath $EvidenceRoot
    $inspection = Inspect-ReceiptArtifact $receiptState $EvidenceRoot
    $session = [IO.Path]::GetFullPath($inspection.session_directory)
    if ([int]$inspection.issue -ne $ExpectedIssue -or
        [string]$value.receipt_sha256 -cne (File-Sha256 $receiptState.Path) -or
        [string]$value.artifact.sha256 -cne [string]$inspection.sha256 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$value.session_directory),
            $session,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-Astro $code 'receipt/artifact/session differ from durable retirement authorization' `
            'preserve the transaction and investigate evidence drift'
    }
    $stdoutPath = [IO.Path]::GetFullPath($StandardOutputInputPath)
    $stderrPath = [IO.Path]::GetFullPath($StandardErrorInputPath)
    $runPath = [IO.Path]::GetFullPath($RunRecordInputPath)
    $livePath = [IO.Path]::GetFullPath($LiveStateInputPath)
    if (-not (Test-AstroPathLongPath -LiteralPath $stdoutPath -PathType Leaf) -or
        -not (Test-AstroPathLongPath -LiteralPath $stderrPath -PathType Leaf) -or
        (File-Sha256 $stdoutPath) -cne [string]$value.outputs.stdout.sha256 -or
        (File-Sha256 $stderrPath) -cne [string]$value.outputs.stderr.sha256 -or
        (Test-AstroPathLongPath -LiteralPath $runPath) -or
        (Test-AstroPathLongPath -LiteralPath $livePath)) {
        Fail-Astro $code 'terminal-partial output/control state drifted during retirement' `
            'preserve the transaction and investigate the changed session'
    }
    $sessionTree = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $session
    if ([string]$sessionTree.schema -cne [string]$value.session_inventory.schema -or
        [string]$sessionTree.encoding -cne [string]$value.session_inventory.encoding -or
        [int]$sessionTree.entry_count -ne [int]$value.session_inventory.entry_count -or
        [uint64]$sessionTree.canonical_bytes_length -ne
            [uint64]$value.session_inventory.canonical_bytes_length -or
        [string]$sessionTree.sha256 -cne [string]$value.session_inventory.sha256) {
        Fail-Astro $code 'session inventory drifted during terminal-partial lock retirement' `
            'preserve the complete transaction and investigate the changed entry'
    }
    $lockReadPath = if (Test-AstroPathLongPath -LiteralPath $FsvLockPath -PathType Leaf) {
        $FsvLockPath
    } elseif ($archivePresent) { $archivePath } else { '' }
    if ([string]::IsNullOrEmpty($lockReadPath) -or
        (File-Sha256 $lockReadPath) -cne [string]$value.fsv_lock.sha256) {
        Fail-Astro $code 'neither exact source nor exact archived FSV lock is available' `
            'preserve all records and investigate the interrupted archive transition'
    }
    try { $lockState = Read-AstroUtf8FileLongPath $lockReadPath | ConvertFrom-Json }
    catch {
        Fail-Astro $code 'bound FSV lock bytes are not valid JSON' `
            'preserve the source/archive and investigate its exact bytes'
    }
    if ([string]$lockState.schema -cne 'astrolabe.native-fsv-lock.v3' -or
        [string]$lockState.mode -cne 'resident-cohort' -or
        [int]$lockState.issue -ne $ExpectedIssue -or
        [int]$lockState.process_count -le 0 -or
        [string]$lockState.artifact_sha256 -cne [string]$inspection.sha256) {
        Fail-Astro $code 'bound FSV lock is not the authorized terminal-partial v3 cohort' `
            'preserve the source/archive and investigate malformed authority'
    }
    $lockLauncher = Read-AstroFsvProcessIdentity $lockState.owners.launcher $code `
        'resumed FSV-lock launcher identity'
    $lockRunner = Read-AstroFsvProcessIdentity $lockState.owners.runner $code `
        'resumed FSV-lock runner identity'
    $lockProcesses = Read-AstroFsvTerminalPartialPreLiveProcesses `
        -LockState $lockState -Code $code `
        -Description 'resumed FSV-lock process set'
    $authorizedLockState = $value.fsv_lock.state
    $authorizedLockLauncher = Read-AstroFsvProcessIdentity `
        $authorizedLockState.owners.launcher $code `
        'authorized embedded FSV-lock launcher identity'
    $authorizedLockRunner = Read-AstroFsvProcessIdentity `
        $authorizedLockState.owners.runner $code `
        'authorized embedded FSV-lock runner identity'
    $authorizedLockProcesses = Read-AstroFsvTerminalPartialPreLiveProcesses `
        -LockState $authorizedLockState -Code $code `
        -Description 'authorized embedded FSV-lock process set'
    if ([string]$authorizedLockState.schema -cne [string]$lockState.schema -or
        [string]$authorizedLockState.mode -cne [string]$lockState.mode -or
        [int]$authorizedLockState.issue -ne [int]$lockState.issue -or
        [string]$authorizedLockState.started -cne [string]$lockState.started -or
        [int]$authorizedLockState.resident_count -ne [int]$lockState.resident_count -or
        [int]$authorizedLockState.process_count -ne [int]$lockState.process_count -or
        [string]$authorizedLockState.tree_sha -cne [string]$lockState.tree_sha -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$authorizedLockState.artifact_path),
            [IO.Path]::GetFullPath([string]$lockState.artifact_path),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$authorizedLockState.artifact_sha256 -cne
            [string]$lockState.artifact_sha256 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$authorizedLockState.cohort_plan.path),
            [IO.Path]::GetFullPath([string]$lockState.cohort_plan.path),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$authorizedLockState.cohort_plan.sha256 -cne
            [string]$lockState.cohort_plan.sha256 -or
        [string]$authorizedLockState.launcher_job.name -cne
            [string]$lockState.launcher_job.name -or
        (@($authorizedLockState.launcher_job.members) -join ',') -cne
            (@($lockState.launcher_job.members) -join ',') -or
        [string]$authorizedLockState.phase -cne [string]$lockState.phase -or
        -not (Test-AstroFsvIdentityEqual $authorizedLockLauncher $lockLauncher) -or
        -not (Test-AstroFsvIdentityEqual $authorizedLockRunner $lockRunner) -or
        -not (Test-AstroFsvV3ProcessEntriesEqual `
            $authorizedLockProcesses $lockProcesses)) {
        Fail-Astro $code 'embedded authorized FSV-lock state differs from archived lock bytes' `
            'preserve the transaction and investigate malformed durable authorization'
    }
    $cohortPlanPath = Assert-PathWithin `
        ([string]$lockState.cohort_plan.path) $Workspace $code `
        'resumed terminal-partial cohort plan'
    $cohortPlanState = Get-AstroFsvStrictPathState `
        $cohortPlanPath file $code 'resumed terminal-partial cohort plan'
    if ($cohortPlanState.state -cne 'present' -or
        (File-Sha256 $cohortPlanPath) -cne [string]$lockState.cohort_plan.sha256) {
        Fail-Astro $code 'terminal-partial cohort plan is absent or hash-mismatched' `
            'preserve the transaction and investigate the external plan bytes'
    }
    $ownerBindingList = [Collections.Generic.List[object]]::new()
    foreach ($binding in @(
            New-AstroFsvOwnerBinding 'launcher' 'artifact receipt' $inspection.owners.launcher
            New-AstroFsvOwnerBinding 'promoter' 'artifact receipt' $inspection.owners.promoter
            New-AstroFsvOwnerBinding 'launcher' 'partial FSV lock' $lockLauncher
            New-AstroFsvOwnerBinding 'runner' 'partial FSV lock' $lockRunner
        )) { $ownerBindingList.Add($binding) }
    Add-AstroFsvV3ProcessBindings $ownerBindingList $lockProcesses 'partial FSV lock'
    foreach ($archive in $chain.archives) {
        $generation = $archive.authorization.value.generation
        $ownerBindingList.Add((New-AstroFsvOwnerBinding 'launcher' `
                'launcher recovery/archive chain' `
                (New-AstroProcessIdentityRecord ([int]$generation.launcher_pid) `
                    ([long]$generation.launcher_process_start_utc_ticks))))
    }
    $ownerBindings = [object[]]$ownerBindingList.ToArray()
    $initialOwnerProbes = @(Assert-AstroFsvOwnersInactive `
            -Bindings $ownerBindings -CodePrefix 'ASTRO_FSV_PARTIAL_LOCK' `
            -Description 'resumed terminal-partial lock retirement')
    $initialJobProbes = [Collections.Generic.List[object]]::new()
    foreach ($archive in $chain.archives) {
        $probe = Get-AstroLauncherJobObjectProbe -Name ([string]$archive.job_name)
        if ($probe.State -cne 'absent') {
            Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_JOB_PRESENT' `
                "resumed launcher Job is '$($probe.State)': $($archive.job_name)" `
                'preserve the transaction while the exact Job exists'
        }
        $initialJobProbes.Add($probe)
    }
    $matchingArchive = @($chain.archives | Where-Object {
            [int]$_.authorization.value.generation.launcher_pid -eq [int]$lockLauncher.pid -and
            [long]$_.authorization.value.generation.launcher_process_start_utc_ticks -eq
                [long]$lockLauncher.process_start_utc_ticks
        })
    if ($matchingArchive.Count -ne 1 -or
        [string]$lockState.launcher_job.name -cne [string]$matchingArchive[0].job_name) {
        Fail-Astro $code 'archived lock Job does not equal its deterministic launcher archive Job' `
            'preserve the transaction and investigate malformed attribution'
    }
    Assert-AstroFsvPersistedOwnerEnvelope `
        -Owners $value.owners -ExpectedBindings $ownerBindings -Code $code `
        -Description 'resumed terminal-partial lock-retirement authorization'
    if ([string]$value.launcher_job.name -cne [string]$lockState.launcher_job.name) {
        Fail-Astro $code 'persisted primary launcher Job name differs from the archived lock' `
            'preserve the transaction and investigate malformed durable Job evidence'
    }
    Assert-AstroFsvPersistedAbsentJobProbe `
        $value.launcher_job.initial_probe ([string]$lockState.launcher_job.name) `
        $code 'persisted primary launcher initial probe'
    Assert-AstroFsvPersistedAbsentJobProbe `
        $value.launcher_job.final_probe ([string]$lockState.launcher_job.name) `
        $code 'persisted primary launcher final probe'
    $persistedTerminalJobProbes = if ($LauncherTerminalChainKind -ceq
        'NormalLiveOwnerCleanupV1') {
        $value.terminal_launcher_job_probes
    } else {
        $value.recovery_launcher_job_probes
    }
    Assert-AstroFsvPersistedRecoveryJobProbes `
        -Persisted $persistedTerminalJobProbes `
        -LauncherRecoveryChain $chain -Code $code `
        -Description 'persisted terminal-launcher'
    $chainArchivePaths = [string[]]@($chain.archives | ForEach-Object {
            [string]$_.completion.path
        })
    $chainArchiveHashes = [string[]]@($chain.archives | ForEach-Object {
            [string]$_.completion.sha256
        })
    $deadLauncherRecoveryPath = if ($LauncherTerminalChainKind -ceq
        'DeadOwnerRecoveryV1') { [string]$chain.launcher_recovery.path } else { '' }
    $deadLauncherRecoveryHash = if ($LauncherTerminalChainKind -ceq
        'DeadOwnerRecoveryV1') { [string]$chain.launcher_recovery.sha256 } else { '' }
    $deadTargetRecoveryPath = if ($LauncherTerminalChainKind -ceq
        'DeadOwnerRecoveryV1') { [string]$chain.target_recovery.path } else { '' }
    $deadTargetRecoveryHash = if ($LauncherTerminalChainKind -ceq
        'DeadOwnerRecoveryV1') { [string]$chain.target_recovery.sha256 } else { '' }
    $normalTerminalRecord = if ($LauncherTerminalChainKind -ceq
        'NormalLiveOwnerCleanupV1') {
        ConvertTo-AstroFsvNormalCleanupTerminalChainRecord $chain
    } else { $null }
    $trackerReadback = Read-AstroFsvPartialLockTrackerEvidence `
        -Url $TrackerUrl -ExpectedIssue $ExpectedIssue `
        -ExpectedLockPath $FsvLockPath `
        -ExpectedLockSha256 ([string]$value.fsv_lock.sha256) `
        -ExpectedReceiptPath $receiptState.Path `
        -ExpectedReceiptSha256 ([string]$value.receipt_sha256) `
        -ExpectedArtifactPath $inspection.artifact_path `
        -ExpectedArtifactSha256 $inspection.sha256 `
        -ExpectedSessionDirectory $session `
        -ExpectedStandardOutputPath $stdoutPath `
        -ExpectedStandardOutputSha256 ([string]$value.outputs.stdout.sha256) `
        -ExpectedStandardErrorPath $stderrPath `
        -ExpectedStandardErrorSha256 ([string]$value.outputs.stderr.sha256) `
        -ExpectedRunRecordPath $runPath -ExpectedLiveStatePath $livePath `
        -ExpectedInventorySchema ([string]$sessionTree.schema) `
        -ExpectedInventoryEncoding ([string]$sessionTree.encoding) `
        -ExpectedInventoryEntryCount ([int]$sessionTree.entry_count) `
        -ExpectedInventoryCanonicalByteCount `
            ([uint64]$sessionTree.canonical_bytes_length) `
        -ExpectedInventorySha256 ([string]$sessionTree.sha256) `
        -ExpectedRecoveryRecordPath $authorizationPath `
        -ExpectedLockArchivePath $archivePath `
        -ExpectedCompletionRecordPath $completionPath `
        -ExpectedLifecycleTransitionPath $LifecycleTransitionPath `
        -ExpectedLauncherRecoveryCompletionPath $deadLauncherRecoveryPath `
        -ExpectedLauncherRecoveryCompletionSha256 $deadLauncherRecoveryHash `
        -ExpectedTargetRecoveryCompletionPath $deadTargetRecoveryPath `
        -ExpectedTargetRecoveryCompletionSha256 $deadTargetRecoveryHash `
        -ExpectedLauncherArchiveCompletionPaths $chainArchivePaths `
        -ExpectedLauncherArchiveCompletionSha256s $chainArchiveHashes `
        -ExpectedLauncherTerminalChainKind $LauncherTerminalChainKind `
        -ExpectedLauncherNormalChainRecord $normalTerminalRecord `
        -ExpectedReasonCode $FailureCode
    if ([long]$trackerReadback.comment_id -ne [long]$value.tracker.comment_id -or
        [string]$trackerReadback.author -cne [string]$value.tracker.author -or
        [string]$trackerReadback.created_at -cne [string]$value.tracker.created_at) {
        Fail-Astro $code 'persisted tracker identity differs from fresh GitHub readback' `
            'preserve the transaction and investigate edited or cross-generation authority'
    }
    $sourcePresent = (Get-AstroFsvStrictPathState `
            $FsvLockPath file $code 'source terminal-partial FSV lock').state -ceq
        'present'
    if ($sourcePresent -and $archivePresent) {
        Fail-Astro $code 'source and archive FSV lock are both present' `
            'preserve both namespaces and investigate the interrupted no-replace move'
    }
    if ($transitionPresent -and $sourcePresent -and -not $archivePresent) {
        if ($completionPresent) {
            Fail-Astro $code 'completion exists before the authorized source lock was archived' `
                'preserve the inconsistent transaction and investigate publication order'
        }
        Move-AstroFileWriteThroughNoReplace -Source $FsvLockPath -Destination $archivePath
        $sourcePresent = (Get-AstroFsvStrictPathState `
                $FsvLockPath file $code 'source terminal-partial FSV lock').state -ceq
            'present'
        $archivePresent = (Get-AstroFsvStrictPathState `
                $archivePath file $code 'archived terminal-partial FSV lock').state -ceq
            'present'
    }
    if ($sourcePresent -or -not $archivePresent -or
        (File-Sha256 $archivePath) -cne [string]$value.fsv_lock.sha256) {
        Fail-Astro $code 'lock archive state is not exact source-absent/archive-equal' `
            'preserve all bytes and resume only after investigating namespace drift'
    }
    $finalOwnerProbes = @(Assert-AstroFsvOwnersInactive `
            -Bindings $ownerBindings -CodePrefix 'ASTRO_FSV_PARTIAL_LOCK' `
            -Description 'resumed terminal-partial lock finalization')
    $finalJobProbes = [Collections.Generic.List[object]]::new()
    foreach ($archive in $chain.archives) {
        $probe = Get-AstroLauncherJobObjectProbe -Name ([string]$archive.job_name)
        if ($probe.State -cne 'absent') {
            Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_JOB_PRESENT' `
                "resumed launcher Job changed to '$($probe.State)': $($archive.job_name)" `
                'preserve the transaction while the exact Job exists'
        }
        $finalJobProbes.Add($probe)
    }
    $launcherState = Read-AstroLauncherLock `
        -LockPath (Join-Path (Join-Path $Workspace '.tmp') 'astrolabe-launcher.lock')
    if ($launcherState.State -ne 'absent' -or
        (Test-AstroPathLongPath -LiteralPath (Join-Path $Workspace 'target')) -or
        (Get-AstroOrdinaryDirectoryTreeInventoryLongPath $session).sha256 -cne
            [string]$sessionTree.sha256) {
        Fail-Astro $code 'launcher/target/session state changed before resumed completion' `
            'preserve the transaction and investigate physical state drift'
    }
    $authorizationSha256 = [string]$authorization.sha256
    if (-not $completionPresent) {
        if (-not $transitionPresent) {
            Fail-Astro $code 'archived authorization exists without its required completion' `
                'preserve the inconsistent transaction; only the canonical transition may finalize it'
        }
        $completion = [ordered]@{
            schema = 'astrolabe.native-fsv-partial-lock-retirement.completion.v1'
            phase = 'complete-lock-archived-source-absent'
            issue = $ExpectedIssue
            completed_at_utc = [DateTime]::UtcNow.ToString('o')
            authorization = [ordered]@{ path = $authorizationPath; sha256 = $authorizationSha256 }
            source = [ordered]@{
                path = $FsvLockPath; state = 'absent'
                prior_sha256 = [string]$value.fsv_lock.sha256
            }
            archive = [ordered]@{
                path = $archivePath
                bytes = [uint64](Get-AstroFileInfoLongPath $archivePath).Length
                sha256 = File-Sha256 $archivePath
            }
            session = [ordered]@{
                path = $session
                inventory_schema = [string]$sessionTree.schema
                inventory_encoding = [string]$sessionTree.encoding
                inventory_entry_count = [int]$sessionTree.entry_count
                inventory_canonical_byte_count = [uint64]$sessionTree.canonical_bytes_length
                inventory_sha256 = [string]$sessionTree.sha256
            }
        }
        $completionRecord = Publish-NewAstroFsvProtocolRecord `
            -Path $completionPath -Value $completion `
            -CodePrefix 'ASTRO_FSV_PARTIAL_LOCK_COMPLETION'
        $completionPresent = $true
    }
    else {
        $completionRecord = Read-AstroFsvExactJsonFile `
            $completionPath $code 'terminal-partial lock retirement completion'
    }
    $completionValue = $completionRecord.value
    if ([string]$completionValue.schema -cne
            'astrolabe.native-fsv-partial-lock-retirement.completion.v1' -or
        [string]$completionValue.phase -cne 'complete-lock-archived-source-absent' -or
        [int]$completionValue.issue -ne $ExpectedIssue -or
        [string]$completionValue.authorization.sha256 -cne $authorizationSha256 -or
        [string]$completionValue.source.state -cne 'absent' -or
        [string]$completionValue.source.prior_sha256 -cne
            [string]$value.fsv_lock.sha256 -or
        [uint64]$completionValue.archive.bytes -ne
            [uint64](Get-AstroFileInfoLongPath $archivePath).Length -or
        [string]$completionValue.archive.sha256 -cne [string]$value.fsv_lock.sha256 -or
        [string]$completionValue.session.inventory_schema -cne
            [string]$sessionTree.schema -or
        [string]$completionValue.session.inventory_encoding -cne
            [string]$sessionTree.encoding -or
        [int]$completionValue.session.inventory_entry_count -ne
            [int]$sessionTree.entry_count -or
        [uint64]$completionValue.session.inventory_canonical_byte_count -ne
            [uint64]$sessionTree.canonical_bytes_length -or
        [string]$completionValue.session.inventory_sha256 -cne
            [string]$sessionTree.sha256 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$completionValue.authorization.path),
            $authorizationPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$completionValue.source.path),
            $FsvLockPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$completionValue.archive.path),
            $archivePath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$completionValue.session.path),
            $session,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-Astro $code 'retirement completion does not exactly link authorization/source/archive/session' `
            'preserve the complete record chain and investigate malformed completion bytes'
    }
    if ($transitionPresent) {
        Move-AstroFileWriteThroughNoReplace `
            -Source $LifecycleTransitionPath -Destination $authorizationPath
        $transitionPresent = $false
        $authorizationPresent = $true
    }
    if ((Get-AstroFsvStrictPathState `
            $LifecycleTransitionPath file $code 'canonical FSV lifecycle transition').state -cne
            'absent' -or
        (Get-AstroFsvStrictPathState `
            $FsvLockPath file $code 'source terminal-partial FSV lock').state -cne
            'absent' -or
        (Get-AstroFsvStrictPathState `
            $authorizationPath file $code 'partial-lock authorization archive').state -cne
            'present' -or
        (File-Sha256 $authorizationPath) -cne $authorizationSha256 -or
        (File-Sha256 $archivePath) -cne [string]$value.fsv_lock.sha256) {
        Fail-Astro $code 'terminal retirement readback is not transition-absent/source-absent/archive-equal' `
            'preserve all protocol records and inspect physical state'
    }
    return [ordered]@{
        operation = 'retire-terminal-partial-lock'
        resumed = $true
        authorization_path = $authorizationPath
        authorization_sha256 = $authorizationSha256
        completion_path = $completionPath
        completion_sha256 = File-Sha256 $completionPath
        authorization = $value
        completion = $completionValue
        owner_probes = [ordered]@{ initial = $initialOwnerProbes; final = $finalOwnerProbes }
        job_probes = [ordered]@{
            initial = [object[]]$initialJobProbes.ToArray()
            final = [object[]]$finalJobProbes.ToArray()
        }
        after = [ordered]@{
            lifecycle_transition_state = 'absent'
            fsv_lock_state = 'absent'
            lock_archive_sha256 = [string]$value.fsv_lock.sha256
            session_inventory_sha256 = [string]$sessionTree.sha256
        }
    }
}

function Assert-AstroFsvAuthorizedInventorySubset {
    param(
        [Parameter(Mandatory)]$AuthorizedEntries,
        [Parameter(Mandatory)]$CurrentInventory,
        [Parameter(Mandatory)][string]$Code
    )
    $authorized = @{}
    foreach ($entry in @($AuthorizedEntries)) {
        $key = ([string]$entry.relative_path).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($key) -or $authorized.ContainsKey($key)) {
            Fail-Astro $Code 'authorized tombstone inventory has an empty/duplicate relative path' `
                'preserve the tombstone and investigate malformed authorization bytes'
        }
        $authorized[$key] = $entry
    }
    if (-not $authorized.ContainsKey('.')) {
        Fail-Astro $Code 'authorized tombstone inventory lacks its root entry' `
            'preserve the tombstone and investigate malformed authorization bytes'
    }
    $currentKeys = @{}
    foreach ($entry in @($CurrentInventory.entries)) {
        $key = ([string]$entry.relative_path).ToLowerInvariant()
        if (-not $authorized.ContainsKey($key) -or $currentKeys.ContainsKey($key)) {
            Fail-Astro $Code "tombstone contains an unauthorized/duplicate entry: $($entry.relative_path)" `
                'preserve the tombstone; never delete an entry outside the durable authorization'
        }
        $expected = $authorized[$key]
        if ([string]$entry.kind -cne [string]$expected.kind -or
            [string]$entry.file_id -cne [string]$expected.file_id -or
            [uint32]$entry.attributes -ne [uint32]$expected.attributes -or
            ([string]$entry.kind -ceq 'file' -and
                ([uint64]$entry.bytes -ne [uint64]$expected.bytes -or
                    [string]$entry.sha256 -cne [string]$expected.sha256))) {
            Fail-Astro $Code "tombstone entry identity/bytes drifted: $($entry.relative_path)" `
                'preserve the tombstone and investigate the exact changed entry'
        }
        $currentKeys[$key] = $true
    }
    if (-not $currentKeys.ContainsKey('.')) {
        Fail-Astro $Code 'present tombstone inventory lacks its root entry' `
            'preserve the namespace and investigate the unevaluable directory state'
    }
    foreach ($key in @($currentKeys.Keys | Where-Object { $_ -ne '.' })) {
        $parent = [IO.Path]::GetDirectoryName($key)
        while (-not [string]::IsNullOrEmpty($parent)) {
            $parentKey = $parent.ToLowerInvariant()
            if (-not $currentKeys.ContainsKey($parentKey)) {
                Fail-Astro $Code "tombstone inventory lacks parent closure for '$key'" `
                    'preserve the namespace and investigate malformed tree state'
            }
            $parent = [IO.Path]::GetDirectoryName($parent)
        }
    }
}

function Get-AstroFsvRetirementDerivedOwners {
    param(
        [Parameter(Mandatory)]$RetirementAuthorization,
        [Parameter(Mandatory)]$Inspection,
        [Parameter(Mandatory)]$LauncherRecoveryChain,
        [Parameter(Mandatory)][string]$Code
    )
    $lockState = $RetirementAuthorization.fsv_lock.state
    $lockLauncher = Read-AstroFsvProcessIdentity $lockState.owners.launcher $Code `
        'archived FSV-lock launcher identity'
    $lockRunner = Read-AstroFsvProcessIdentity $lockState.owners.runner $Code `
        'archived FSV-lock runner identity'
    if (-not (Test-AstroFsvIdentityEqual $lockLauncher $Inspection.owners.launcher)) {
        Fail-Astro $Code 'archived FSV lock and receipt launcher generations differ' `
            'preserve the cross-generation state and investigate its publisher'
    }
    $lockProcesses = Read-AstroFsvV3ProcessEntries `
        $lockState.owners.processes ([int]$lockState.resident_count) `
        ([int]$lockState.process_count) $Code 'archived FSV-lock process set'
    $bindings = [Collections.Generic.List[object]]::new()
    foreach ($binding in @(
            New-AstroFsvOwnerBinding 'launcher' 'artifact receipt' $Inspection.owners.launcher
            New-AstroFsvOwnerBinding 'promoter' 'artifact receipt' $Inspection.owners.promoter
            New-AstroFsvOwnerBinding 'launcher' 'partial FSV lock' $lockLauncher
            New-AstroFsvOwnerBinding 'runner' 'partial FSV lock' $lockRunner
        )) { $bindings.Add($binding) }
    Add-AstroFsvV3ProcessBindings $bindings $lockProcesses 'partial FSV lock'
    foreach ($archive in $LauncherRecoveryChain.archives) {
        $generation = $archive.authorization.value.generation
        $bindings.Add((New-AstroFsvOwnerBinding 'launcher' `
                'launcher recovery/archive chain' `
                (New-AstroProcessIdentityRecord ([int]$generation.launcher_pid) `
                    ([long]$generation.launcher_process_start_utc_ticks))))
    }
    $matchingArchive = @($LauncherRecoveryChain.archives | Where-Object {
            [int]$_.authorization.value.generation.launcher_pid -eq [int]$lockLauncher.pid -and
            [long]$_.authorization.value.generation.launcher_process_start_utc_ticks -eq
                [long]$lockLauncher.process_start_utc_ticks
        })
    if ($matchingArchive.Count -ne 1 -or
        [string]$lockState.launcher_job.name -cne [string]$matchingArchive[0].job_name) {
        Fail-Astro $Code 'archived FSV-lock Job does not equal its deterministic launcher Job' `
            'preserve the record chain and investigate malformed attribution'
    }
    return [object[]]$bindings.ToArray()
}

function Assert-AstroFsvRecoveryJobsAbsent {
    param(
        [Parameter(Mandatory)]$LauncherRecoveryChain,
        [Parameter(Mandatory)][string]$CodePrefix,
        [Parameter(Mandatory)][string]$Description
    )
    $probes = [Collections.Generic.List[object]]::new()
    foreach ($archive in $LauncherRecoveryChain.archives) {
        $probe = Get-AstroLauncherJobObjectProbe -Name ([string]$archive.job_name)
        if ($probe.State -cne 'absent') {
            Fail-Astro "${CodePrefix}_JOB_PRESENT" `
                "$Description Job is '$($probe.State)': $($archive.job_name)" `
                'preserve the session while any exact launcher Job generation exists'
        }
        $probes.Add($probe)
    }
    return [object[]]$probes.ToArray()
}

function Invoke-AstroFsvTerminalPartialQuarantineResume {
    param(
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][string]$Workspace,
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [Parameter(Mandatory)][string]$RecoveryRoot,
        [Parameter(Mandatory)][string]$FsvLockPath,
        [Parameter(Mandatory)][string]$LifecycleTransitionPath,
        [Parameter(Mandatory)][string]$RecoveryInputPath,
        [Parameter(Mandatory)][string]$RetirementCompletionInputPath,
        [Parameter(Mandatory)][string]$TrackerUrl,
        [Parameter(Mandatory)][string]$FailureCode,
        [Parameter(Mandatory)][string]$FailureMessage
    )
    $code = 'ASTRO_FSV_TERMINAL_PARTIAL_RESUME_INVALID'
    $authorizationPath = Assert-PathWithin $RecoveryInputPath $RecoveryRoot $code `
        'terminal-partial quarantine authorization path'
    $completionPath = $authorizationPath + '.completed.json'
    $tombstonePath = $authorizationPath + '.session.dir'
    $transitionState = Get-AstroFsvStrictPathState `
        $LifecycleTransitionPath file $code 'canonical FSV lifecycle transition'
    $authorizationState = Get-AstroFsvStrictPathState `
        $authorizationPath file $code 'quarantine authorization archive'
    $completionState = Get-AstroFsvStrictPathState `
        $completionPath file $code 'quarantine completion'
    $tombstoneState = Get-AstroFsvStrictPathState `
        $tombstonePath directory $code 'quarantine session tombstone'
    $transitionPresent = $transitionState.state -ceq 'present'
    $authorizationPresent = $authorizationState.state -ceq 'present'
    $completionPresent = $completionState.state -ceq 'present'
    $tombstonePresent = $tombstoneState.state -ceq 'present'
    if ($transitionPresent -and $authorizationPresent) {
        Fail-Astro $code 'canonical transition and archived quarantine authorization are both present' `
            'preserve both namespaces and investigate the interrupted authorization archive'
    }
    if (-not $transitionPresent -and -not $authorizationPresent) {
        Fail-Astro $code 'quarantine resume state lacks transition/authorization authority' `
            'preserve tombstone/completion bytes and restore only through their exact transaction'
    }
    $activeAuthorizationPath = if ($transitionPresent) {
        $LifecycleTransitionPath
    } else { $authorizationPath }
    $authorization = Read-AstroFsvExactJsonFile `
        $activeAuthorizationPath $code 'terminal-partial quarantine authorization'
    $value = $authorization.value
    foreach ($pair in @(
            @([string]$value.authorization_record_path, $authorizationPath),
            @([string]$value.lifecycle_transition_path, $LifecycleTransitionPath),
            @([string]$value.completion_record_path, $completionPath),
            @([string]$value.session_tombstone_path, $tombstonePath),
            @([string]$value.retirement.completion_path,
                [IO.Path]::GetFullPath($RetirementCompletionInputPath))
        )) {
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath([string]$pair[0]),
                [IO.Path]::GetFullPath([string]$pair[1]),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro $code 'quarantine resume arguments differ from durable path bindings' `
                'resume only the exact transition-bound quarantine transaction'
        }
    }
    if ([string]$value.schema -cnotin @(
            'astrolabe.native-fsv-terminal-partial-quarantine.authorization.v1',
            'astrolabe.native-fsv-terminal-partial-quarantine.authorization.v2') -or
        [string]$value.phase -cne 'authorized-exact-terminal-partial-session' -or
        [int]$value.issue -ne $ExpectedIssue -or
        [string]$value.failure.code -cne $FailureCode -or
        [string]$value.failure.message -cne $FailureMessage -or
        [string]$value.tracker.url -cne $TrackerUrl) {
        Fail-Astro $code 'durable quarantine authorization differs from requested transaction' `
            'preserve all state and resume only the exact tracker-bound transaction'
    }
    $sessionPath = Assert-PathWithin `
        ([string]$value.session_directory) $EvidenceRoot $code `
        'authorized terminal-partial session'
    $requiredSessionPaths = @(
        Assert-DirectSessionChildPath ([string]$value.receipt_path) $sessionPath `
            $code 'authorized receipt path'
        Assert-DirectSessionChildPath ([string]$value.artifact.path) $sessionPath `
            $code 'authorized artifact path'
        Assert-DirectSessionChildPath ([string]$value.outputs.stdout.path) $sessionPath `
            $code 'authorized standard-output path'
        Assert-DirectSessionChildPath ([string]$value.outputs.stderr.path) $sessionPath `
            $code 'authorized standard-error path'
    )
    [void](Assert-DirectSessionChildPath `
        ([string]$value.expected_controls.run_record_path) $sessionPath $code `
        'authorized expected run-record path')
    [void](Assert-DirectSessionChildPath `
        ([string]$value.expected_controls.live_state_path) $sessionPath $code `
        'authorized expected live-state path')
    $distinctPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($path in @(
            $requiredSessionPaths +
            @([string]$value.expected_controls.run_record_path,
                [string]$value.expected_controls.live_state_path)
        )) {
        if (-not $distinctPaths.Add([IO.Path]::GetFullPath($path))) {
            Fail-Astro $code 'authorized receipt/artifact/output/control paths collide' `
                'preserve the transition and investigate malformed path authority'
        }
    }
    $authorizedEntries = ConvertFrom-AstroFsvPersistedInventoryEntries `
        -Entries $value.session_inventory.entries -Code $code `
        -Description 'authorized terminal-partial session inventory'
    [byte[]]$authorizedCanonicalBytes =
        ConvertTo-AstroOrdinaryTreeInventoryCanonicalBytes `
            -Schema ([string]$value.session_inventory.schema) `
            -Encoding ([string]$value.session_inventory.encoding) `
            -Records $authorizedEntries
    if ($authorizedEntries.Count -ne
            [int]$value.session_inventory.entry_count -or
        [uint64]$authorizedCanonicalBytes.Length -ne
            [uint64]$value.session_inventory.canonical_bytes_length -or
        (Get-AstroByteSha256 $authorizedCanonicalBytes) -cne
            [string]$value.session_inventory.sha256) {
        Fail-Astro $code 'authorized session entries do not reproduce inventory count/bytes/SHA-256' `
            'preserve the transition and investigate malformed deletion authority'
    }
    $authorizedRoot = @($authorizedEntries | Where-Object {
            [string]$_.relative_path -ceq '.' -and [string]$_.kind -ceq 'directory'
        })
    if ($authorizedRoot.Count -ne 1) {
        Fail-Astro $code 'authorized session inventory does not contain one ordinary root' `
            'preserve the transition and investigate malformed deletion authority'
    }
    $authorizedAbsolutePaths = @(
        $authorizedEntries | Where-Object {
            [string]$_.relative_path -cne '.'
        } | ForEach-Object {
            [IO.Path]::GetFullPath((Join-Path $sessionPath ([string]$_.relative_path)))
        }
    )
    if (@($requiredSessionPaths | Where-Object {
                $authorizedAbsolutePaths -notcontains [IO.Path]::GetFullPath($_)
            }).Count -ne 0) {
        Fail-Astro $code 'authorized inventory omits receipt/artifact/output source-of-truth files' `
            'preserve the transition and investigate malformed deletion authority'
    }
    $retirementCompletion = Read-AstroFsvExactJsonFile `
        ([string]$value.retirement.completion_path) $code `
        'terminal-partial lock retirement completion'
    $retirementAuthorization = Read-AstroFsvExactJsonFile `
        ([string]$value.retirement.authorization_path) $code `
        'terminal-partial lock retirement authorization'
    $lockArchiveState = Get-AstroFsvStrictPathState `
        ([string]$value.retirement.lock_archive_path) file $code `
        'phase-one archived terminal-partial FSV lock'
    if ($lockArchiveState.state -cne 'present') {
        Fail-Astro $code 'phase-one archived FSV lock is absent' `
            'preserve the quarantine transition and restore only its exact record chain'
    }
    if ([string]$retirementCompletion.sha256 -cne
            [string]$value.retirement.completion_sha256 -or
        [string]$retirementAuthorization.sha256 -cne
            [string]$value.retirement.authorization_sha256 -or
        [string]$retirementCompletion.value.authorization.sha256 -cne
            [string]$retirementAuthorization.sha256 -or
        [string]$retirementCompletion.value.archive.sha256 -cne
            [string]$value.retirement.lock_archive_sha256 -or
        (File-Sha256 ([string]$value.retirement.lock_archive_path)) -cne
            [string]$value.retirement.lock_archive_sha256) {
        Fail-Astro $code 'phase-one completion/authorization/archive chain drifted' `
            'preserve the quarantine transaction and investigate the exact changed record'
    }
    $phaseOneValue = $retirementAuthorization.value
    $phaseOneCompletion = $retirementCompletion.value
    foreach ($pair in @(
            @([string]$phaseOneCompletion.authorization.path,
                [string]$retirementAuthorization.path),
            @([string]$phaseOneCompletion.source.path, $FsvLockPath),
            @([string]$phaseOneCompletion.archive.path,
                [string]$value.retirement.lock_archive_path),
            @([string]$phaseOneValue.fsv_lock.path, $FsvLockPath),
            @([string]$phaseOneValue.fsv_lock.archive_path,
                [string]$value.retirement.lock_archive_path),
            @([string]$phaseOneCompletion.session.path,
                [string]$phaseOneValue.session_directory),
            @([string]$value.retirement.authorization_path,
                [string]$retirementAuthorization.path),
            @([string]$value.receipt_path, [string]$phaseOneValue.receipt_path),
            @([string]$value.session_directory,
                [string]$phaseOneValue.session_directory),
            @([string]$value.artifact.path, [string]$phaseOneValue.artifact.path),
            @([string]$value.outputs.stdout.path,
                [string]$phaseOneValue.outputs.stdout.path),
            @([string]$value.outputs.stderr.path,
                [string]$phaseOneValue.outputs.stderr.path),
            @([string]$value.expected_controls.run_record_path,
                [string]$phaseOneValue.expected_controls.run_record_path),
            @([string]$value.expected_controls.live_state_path,
                [string]$phaseOneValue.expected_controls.live_state_path)
        )) {
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath([string]$pair[0]),
                [IO.Path]::GetFullPath([string]$pair[1]),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro $code 'phase-one and phase-two path bindings differ' `
                'preserve the quarantine transition and investigate mixed-generation authority'
        }
    }
    $expectedPhaseTwoSchema = if ([string]$phaseOneValue.schema -ceq
        'astrolabe.native-fsv-partial-lock-retirement.authorization.v2') {
        'astrolabe.native-fsv-terminal-partial-quarantine.authorization.v2'
    } elseif ([string]$phaseOneValue.schema -ceq
        'astrolabe.native-fsv-partial-lock-retirement.authorization.v1') {
        'astrolabe.native-fsv-terminal-partial-quarantine.authorization.v1'
    } else { '' }
    if ([string]::IsNullOrEmpty($expectedPhaseTwoSchema) -or
        [string]$value.schema -cne $expectedPhaseTwoSchema -or
        [string]$phaseOneValue.phase -cne
            'authorized-exact-terminal-partial-lock' -or
        [int]$phaseOneValue.issue -ne $ExpectedIssue -or
        [string]$phaseOneValue.fsv_lock.state.schema -cne
            'astrolabe.native-fsv-lock.v3' -or
        [string]$phaseOneValue.fsv_lock.state.mode -cne 'resident-cohort' -or
        [string]$phaseOneCompletion.schema -cne
            'astrolabe.native-fsv-partial-lock-retirement.completion.v1' -or
        [string]$phaseOneCompletion.phase -cne
            'complete-lock-archived-source-absent' -or
        [int]$phaseOneCompletion.issue -ne $ExpectedIssue -or
        [string]$phaseOneCompletion.source.state -cne 'absent' -or
        [string]$phaseOneCompletion.source.prior_sha256 -cne
            [string]$phaseOneValue.fsv_lock.sha256 -or
        [uint64]$phaseOneCompletion.archive.bytes -ne
            [uint64](Get-AstroFileInfoLongPath `
                ([string]$value.retirement.lock_archive_path)).Length -or
        [string]$phaseOneCompletion.archive.sha256 -cne
            [string]$phaseOneValue.fsv_lock.sha256 -or
        [string]$phaseOneCompletion.session.inventory_schema -cne
            [string]$phaseOneValue.session_inventory.schema -or
        [string]$phaseOneCompletion.session.inventory_encoding -cne
            [string]$phaseOneValue.session_inventory.encoding -or
        [int]$phaseOneCompletion.session.inventory_entry_count -ne
            [int]$phaseOneValue.session_inventory.entry_count -or
        [uint64]$phaseOneCompletion.session.inventory_canonical_byte_count -ne
            [uint64]$phaseOneValue.session_inventory.canonical_bytes_length -or
        [string]$phaseOneCompletion.session.inventory_sha256 -cne
            [string]$phaseOneValue.session_inventory.sha256 -or
        [string]$value.receipt_sha256 -cne [string]$phaseOneValue.receipt_sha256 -or
        [uint64]$value.artifact.bytes -ne [uint64]$phaseOneValue.artifact.bytes -or
        [string]$value.artifact.sha256 -cne [string]$phaseOneValue.artifact.sha256 -or
        [string]$value.outputs.stdout.sha256 -cne
            [string]$phaseOneValue.outputs.stdout.sha256 -or
        [uint64]$value.outputs.stdout.bytes -ne
            [uint64]$phaseOneValue.outputs.stdout.bytes -or
        [string]$value.outputs.stderr.sha256 -cne
            [string]$phaseOneValue.outputs.stderr.sha256 -or
        [uint64]$value.outputs.stderr.bytes -ne
            [uint64]$phaseOneValue.outputs.stderr.bytes -or
        [string]$value.expected_controls.run_record_state -cne 'absent' -or
        [string]$value.expected_controls.live_state_state -cne 'absent' -or
        [string]$phaseOneValue.expected_controls.run_record_state -cne 'absent' -or
        [string]$phaseOneValue.expected_controls.live_state_state -cne 'absent' -or
        [string]$value.session_inventory.schema -cne
            [string]$phaseOneValue.session_inventory.schema -or
        [string]$value.session_inventory.encoding -cne
            [string]$phaseOneValue.session_inventory.encoding -or
        [int]$value.session_inventory.entry_count -ne
            [int]$phaseOneValue.session_inventory.entry_count -or
        [uint64]$value.session_inventory.canonical_bytes_length -ne
            [uint64]$phaseOneValue.session_inventory.canonical_bytes_length -or
        [string]$value.session_inventory.sha256 -cne
            [string]$phaseOneValue.session_inventory.sha256) {
        Fail-Astro $code 'phase-one completion/authorization and phase-two authority differ' `
            'preserve every byte and investigate malformed or mixed-generation state'
    }
    $chain = Read-AstroFsvLauncherTerminalChainFromRetirementAuthorization `
        -Authorization $phaseOneValue -ExpectedIssue $ExpectedIssue `
        -Workspace $Workspace -Code $code `
        -Description 'phase-one launcher terminal chain'
    $inspection = [ordered]@{
        owners = [ordered]@{
            launcher = $retirementAuthorization.value.fsv_lock.state.owners.launcher
            promoter = $retirementAuthorization.value.owners.identities |
                Where-Object role -eq 'promoter' | Select-Object -First 1 |
                ForEach-Object identity
        }
    }
    if ($null -eq $inspection.owners.promoter) {
        Fail-Astro $code 'phase-one authorization lacks the receipt promoter identity' `
            'preserve the transaction and investigate malformed owner state'
    }
    $ownerBindings = Get-AstroFsvRetirementDerivedOwners `
        -RetirementAuthorization $retirementAuthorization.value `
        -Inspection $inspection -LauncherRecoveryChain $chain -Code $code
    Assert-AstroFsvPersistedOwnerEnvelope `
        -Owners $retirementAuthorization.value.owners `
        -ExpectedBindings $ownerBindings -Code $code `
        -Description 'phase-one derived terminal-partial owner envelope'
    Assert-AstroFsvPersistedOwnerEnvelope `
        -Owners $value.owners -ExpectedBindings $ownerBindings -Code $code `
        -Description 'phase-two terminal-partial quarantine owner envelope'
    $primaryJobName = [string]$phaseOneValue.launcher_job.name
    if ([string]$value.source_of_truth.launcher_job.name -cne $primaryJobName) {
        Fail-Astro $code 'phase-two primary launcher Job differs from phase one' `
            'preserve the transaction and investigate mixed-generation Job authority'
    }
    foreach ($probe in @(
            $phaseOneValue.launcher_job.initial_probe,
            $phaseOneValue.launcher_job.final_probe,
            $value.source_of_truth.launcher_job.initial_probe,
            $value.source_of_truth.launcher_job.final_probe
        )) {
        Assert-AstroFsvPersistedAbsentJobProbe `
            $probe $primaryJobName $code 'persisted terminal-partial primary Job probe'
    }
    $phaseOneTerminalJobProbes = if ([string]$phaseOneValue.schema -ceq
        'astrolabe.native-fsv-partial-lock-retirement.authorization.v2') {
        $phaseOneValue.terminal_launcher_job_probes
    } else { $phaseOneValue.recovery_launcher_job_probes }
    $phaseTwoTerminalJobProbes = if ([string]$value.schema -ceq
        'astrolabe.native-fsv-terminal-partial-quarantine.authorization.v2') {
        $value.source_of_truth.terminal_launcher_jobs
    } else { $value.source_of_truth.recovery_launcher_jobs }
    Assert-AstroFsvPersistedRecoveryJobProbes `
        -Persisted $phaseOneTerminalJobProbes `
        -LauncherRecoveryChain $chain -Code $code `
        -Description 'phase-one persisted terminal-launcher'
    Assert-AstroFsvPersistedRecoveryJobProbes `
        -Persisted $phaseTwoTerminalJobProbes `
        -LauncherRecoveryChain $chain -Code $code `
        -Description 'phase-two persisted terminal-launcher'
    $trackerReadback = Read-AstroFsvTerminalPartialQuarantineTrackerEvidence `
        -Url $TrackerUrl -ExpectedIssue $ExpectedIssue `
        -ExpectedRetirementCompletionPath ([string]$retirementCompletion.path) `
        -ExpectedRetirementCompletionSha256 ([string]$retirementCompletion.sha256) `
        -ExpectedReceiptPath ([string]$value.receipt_path) `
        -ExpectedReceiptSha256 ([string]$value.receipt_sha256) `
        -ExpectedArtifactPath ([string]$value.artifact.path) `
        -ExpectedArtifactSha256 ([string]$value.artifact.sha256) `
        -ExpectedSessionDirectory $sessionPath `
        -ExpectedStandardOutputPath ([string]$value.outputs.stdout.path) `
        -ExpectedStandardOutputSha256 ([string]$value.outputs.stdout.sha256) `
        -ExpectedStandardErrorPath ([string]$value.outputs.stderr.path) `
        -ExpectedStandardErrorSha256 ([string]$value.outputs.stderr.sha256) `
        -ExpectedRunRecordPath ([string]$value.expected_controls.run_record_path) `
        -ExpectedLiveStatePath ([string]$value.expected_controls.live_state_path) `
        -ExpectedInventorySchema ([string]$value.session_inventory.schema) `
        -ExpectedInventoryEncoding ([string]$value.session_inventory.encoding) `
        -ExpectedInventoryEntryCount ([int]$value.session_inventory.entry_count) `
        -ExpectedInventoryCanonicalByteCount `
            ([uint64]$value.session_inventory.canonical_bytes_length) `
        -ExpectedInventorySha256 ([string]$value.session_inventory.sha256) `
        -ExpectedRecoveryRecordPath $authorizationPath `
        -ExpectedCompletionRecordPath $completionPath `
        -ExpectedLifecycleTransitionPath $LifecycleTransitionPath `
        -ExpectedSessionTombstonePath $tombstonePath `
        -ExpectedReasonCode $FailureCode
    if ([long]$trackerReadback.comment_id -ne [long]$value.tracker.comment_id -or
        [string]$trackerReadback.author -cne [string]$value.tracker.author -or
        [string]$trackerReadback.created_at -cne [string]$value.tracker.created_at -or
        [long]$trackerReadback.comment_id -eq [long]$phaseOneValue.tracker.comment_id) {
        Fail-Astro $code 'phase-two tracker identity differs from fresh GitHub readback or phase one' `
            'preserve the transaction and investigate stale or cross-generation authority'
    }
    try {
        $trackerCreated = [DateTimeOffset]::Parse(
            [string]$trackerReadback.created_at,
            [Globalization.CultureInfo]::InvariantCulture
        )
        $phaseOneCompleted = [DateTimeOffset]::Parse(
            [string]$phaseOneCompletion.completed_at_utc,
            [Globalization.CultureInfo]::InvariantCulture
        )
    }
    catch {
        Fail-Astro $code `
            "phase timestamp is malformed (tracker='$($trackerReadback.created_at)'; completion='$($phaseOneCompletion.completed_at_utc)'): $($_.Exception.Message)" `
            'preserve the transaction and investigate malformed durable timestamp authority'
    }
    if ($trackerCreated -le $phaseOneCompleted) {
        Fail-Astro $code 'phase-two tracker is not provably later than phase-one completion' `
            'post a fresh owner comment after the completed phase-one timestamp'
    }
    $initialOwnerProbes = @(Assert-AstroFsvOwnersInactive `
            -Bindings $ownerBindings -CodePrefix 'ASTRO_FSV_TERMINAL_PARTIAL' `
            -Description 'resumed terminal-partial quarantine')
    $initialJobProbes = @(Assert-AstroFsvRecoveryJobsAbsent `
            -LauncherRecoveryChain $chain -CodePrefix 'ASTRO_FSV_TERMINAL_PARTIAL' `
            -Description 'resumed terminal-partial quarantine')
    $launcherStateBeforeMutation = Read-AstroLauncherLock `
        -LockPath (Join-Path (Join-Path $Workspace '.tmp') 'astrolabe-launcher.lock')
    $fsvStateBeforeMutation = Get-AstroFsvStrictPathState `
        $FsvLockPath file $code 'active native-FSV lock'
    if ($launcherStateBeforeMutation.State -ne 'absent' -or
        $fsvStateBeforeMutation.state -cne 'absent' -or
        (Test-AstroPathLongPath -LiteralPath (Join-Path $Workspace 'target'))) {
        Fail-Astro $code 'launcher/FSV/target state is not absent before quarantine mutation' `
            'preserve the old session while any newer build or FSV generation exists'
    }
    $sourceState = Get-AstroFsvStrictPathState `
        $sessionPath directory $code 'authorized terminal-partial session'
    $sourcePresent = $sourceState.state -ceq 'present'
    if ($sourcePresent -and $tombstonePresent) {
        Fail-Astro $code 'source session and quarantine tombstone are both present' `
            'preserve both namespaces and investigate the interrupted no-replace rename'
    }
    if ($completionPresent -and ($sourcePresent -or $tombstonePresent)) {
        Fail-Astro $code 'quarantine completion exists while source/tombstone remains' `
            'preserve the inconsistent state and investigate transaction ordering'
    }
    if ($sourcePresent) {
        if (-not $transitionPresent -or $completionPresent) {
            Fail-Astro $code 'source session remains without an active quarantine transition' `
                'preserve the session and investigate the inconsistent transaction'
        }
        $sourceInventory = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $sessionPath
        if ([string]$sourceInventory.sha256 -cne [string]$value.session_inventory.sha256) {
            Fail-Astro $code 'source session drifted before resumed tombstone rename' `
                'preserve the session and investigate the changed entry'
        }
        $destinationParent = Split-Path -Parent $tombstonePath
        New-AstroDirectoryLongPath $destinationParent | Out-Null
        $sourceHandle = $null
        $destinationHandle = $null
        try {
            $sourceHandle = [AstroLauncherLockNative]::OpenExactDeleteDirectory($sessionPath)
            $destinationHandle =
                [AstroLauncherLockNative]::OpenExactRenameDirectory($destinationParent)
            $sourceFileId = [AstroLauncherLockNative]::GetFileIdentity($sourceHandle)
            if ([string]$sourceFileId -cne
                [string](@($authorizedEntries | Where-Object {
                            [string]$_.relative_path -ceq '.'
                        })[0].file_id)) {
                Fail-Astro $code 'source session root FILE_ID differs from authorization' `
                    'preserve the session and investigate namespace replacement'
            }
            [AstroLauncherLockNative]::RenameDirectoryHandleNoReplace(
                $sourceHandle,
                $destinationHandle,
                [IO.Path]::GetFileName($tombstonePath)
            )
            $renamedPath = ConvertFrom-AstroNativeFinalPath (
                [AstroLauncherLockNative]::GetFileFinalPath($sourceHandle)
            )
            if (-not [string]::Equals(
                    [IO.Path]::GetFullPath($renamedPath),
                    $tombstonePath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                [string][AstroLauncherLockNative]::GetFileIdentity($sourceHandle) -cne
                    [string]$sourceFileId) {
                Fail-Astro $code 'handle-bound session rename did not preserve exact root identity' `
                    'preserve the tombstone and investigate the namespace transition'
            }
        }
        finally {
            if ($null -ne $destinationHandle) { $destinationHandle.Dispose() }
            if ($null -ne $sourceHandle) { $sourceHandle.Dispose() }
        }
        $sourcePresent = (Get-AstroFsvStrictPathState `
                $sessionPath directory $code 'authorized terminal-partial session').state -ceq
            'present'
        $tombstonePresent = (Get-AstroFsvStrictPathState `
                $tombstonePath directory $code 'quarantine session tombstone').state -ceq
            'present'
    }
    if ($sourcePresent) {
        Fail-Astro $code 'quarantine source/tombstone transition is incomplete or unevaluable' `
            'preserve all state and inspect the exact source/tombstone namespaces'
    }
    while ($tombstonePresent) {
        $currentInventory = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $tombstonePath
        Assert-AstroFsvAuthorizedInventorySubset `
            -AuthorizedEntries $authorizedEntries `
            -CurrentInventory $currentInventory -Code $code
        Remove-AstroOrdinaryDirectoryTreeLongPath `
            -LiteralPath $tombstonePath `
            -ExpectedInventorySchema ([string]$currentInventory.schema) `
            -ExpectedInventoryEncoding ([string]$currentInventory.encoding) `
            -ExpectedInventorySha256 ([string]$currentInventory.sha256)
        $tombstonePresent = (Get-AstroFsvStrictPathState `
                $tombstonePath directory $code 'quarantine session tombstone').state -ceq
            'present'
    }
    $finalOwnerProbes = @(Assert-AstroFsvOwnersInactive `
            -Bindings $ownerBindings -CodePrefix 'ASTRO_FSV_TERMINAL_PARTIAL' `
            -Description 'resumed terminal-partial quarantine finalization')
    $finalJobProbes = @(Assert-AstroFsvRecoveryJobsAbsent `
            -LauncherRecoveryChain $chain -CodePrefix 'ASTRO_FSV_TERMINAL_PARTIAL' `
            -Description 'resumed terminal-partial quarantine finalization')
    $launcherState = Read-AstroLauncherLock `
        -LockPath (Join-Path (Join-Path $Workspace '.tmp') 'astrolabe-launcher.lock')
    if ($launcherState.State -ne 'absent' -or
        (Test-AstroPathLongPath -LiteralPath $FsvLockPath) -or
        (Test-AstroPathLongPath -LiteralPath $sessionPath) -or
        (Test-AstroPathLongPath -LiteralPath $tombstonePath)) {
        Fail-Astro $code 'launcher/FSV/source/tombstone state is not terminal absence' `
            'preserve the recovery chain and investigate physical state'
    }
    $authorizationSha256 = [string]$authorization.sha256
    if (-not $completionPresent) {
        if (-not $transitionPresent) {
            Fail-Astro $code 'archived quarantine authorization lacks its completion' `
                'preserve the inconsistent record chain; only the canonical transition may finalize it'
        }
        $completion = [ordered]@{
            schema = 'astrolabe.native-fsv-terminal-partial-quarantine.completion.v1'
            phase = 'complete-session-and-tombstone-absent'
            issue = $ExpectedIssue
            completed_at_utc = [DateTime]::UtcNow.ToString('o')
            authorization = [ordered]@{ path = $authorizationPath; sha256 = $authorizationSha256 }
            retirement_completion = [ordered]@{
                path = [string]$retirementCompletion.path
                sha256 = [string]$retirementCompletion.sha256
            }
            session = [ordered]@{
                path = $sessionPath; state = 'absent'
                prior_inventory_sha256 = [string]$value.session_inventory.sha256
            }
            tombstone = [ordered]@{ path = $tombstonePath; state = 'absent' }
            fsv_lock = [ordered]@{ path = $FsvLockPath; state = 'absent' }
        }
        $completionRecord = Publish-NewAstroFsvProtocolRecord `
            -Path $completionPath -Value $completion `
            -CodePrefix 'ASTRO_FSV_TERMINAL_PARTIAL_COMPLETION'
        $completionPresent = $true
    }
    else {
        $completionRecord = Read-AstroFsvExactJsonFile `
            $completionPath $code 'terminal-partial quarantine completion'
    }
    $completionValue = $completionRecord.value
    if ([string]$completionValue.schema -cne
            'astrolabe.native-fsv-terminal-partial-quarantine.completion.v1' -or
        [string]$completionValue.phase -cne 'complete-session-and-tombstone-absent' -or
        [int]$completionValue.issue -ne $ExpectedIssue -or
        [string]$completionValue.authorization.sha256 -cne $authorizationSha256 -or
        [string]$completionValue.retirement_completion.sha256 -cne
            [string]$retirementCompletion.sha256 -or
        [string]$completionValue.session.prior_inventory_sha256 -cne
            [string]$value.session_inventory.sha256 -or
        [string]$completionValue.session.state -cne 'absent' -or
        [string]$completionValue.tombstone.state -cne 'absent' -or
        [string]$completionValue.fsv_lock.state -cne 'absent' -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$completionValue.authorization.path),
            $authorizationPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$completionValue.retirement_completion.path),
            [string]$retirementCompletion.path,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$completionValue.session.path),
            $sessionPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$completionValue.tombstone.path),
            $tombstonePath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$completionValue.fsv_lock.path),
            $FsvLockPath,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-Astro $code 'quarantine completion does not hash-link terminal source/tombstone absence' `
            'preserve the complete record chain and investigate malformed completion bytes'
    }
    if ($transitionPresent) {
        Move-AstroFileWriteThroughNoReplace `
            -Source $LifecycleTransitionPath -Destination $authorizationPath
    }
    if ((Get-AstroFsvStrictPathState `
            $LifecycleTransitionPath file $code 'canonical FSV lifecycle transition').state -cne
            'absent' -or
        (Get-AstroFsvStrictPathState `
            $sessionPath directory $code 'authorized terminal-partial session').state -cne
            'absent' -or
        (Get-AstroFsvStrictPathState `
            $tombstonePath directory $code 'quarantine session tombstone').state -cne
            'absent' -or
        (Get-AstroFsvStrictPathState `
            $FsvLockPath file $code 'active native-FSV lock').state -cne 'absent' -or
        (File-Sha256 $authorizationPath) -cne $authorizationSha256) {
        Fail-Astro $code 'quarantine terminal readback differs from completion' `
            'preserve every recovery record and inspect physical state'
    }
    return [ordered]@{
        operation = 'quarantine-terminal-partial'
        resumed = $true
        authorization_path = $authorizationPath
        authorization_sha256 = $authorizationSha256
        completion_path = $completionPath
        completion_sha256 = File-Sha256 $completionPath
        authorization = $value
        completion = $completionValue
        owner_probes = [ordered]@{ initial = $initialOwnerProbes; final = $finalOwnerProbes }
        job_probes = [ordered]@{ initial = $initialJobProbes; final = $finalJobProbes }
        after = [ordered]@{
            lifecycle_transition_state = 'absent'
            session_state = 'absent'
            tombstone_state = 'absent'
            fsv_lock_state = 'absent'
        }
    }
}

function Invoke-AstroFsvInterruptedV2LockRetirementResume {
    param(
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][string]$Workspace,
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [Parameter(Mandatory)][string]$RecoveryRoot,
        [Parameter(Mandatory)][string]$FsvLockPath,
        [Parameter(Mandatory)][string]$LifecycleTransitionPath,
        [Parameter(Mandatory)][string]$ReceiptInputPath,
        [Parameter(Mandatory)][string]$RecoveryInputPath,
        [Parameter(Mandatory)][string]$StandardOutputInputPath,
        [Parameter(Mandatory)][string]$StandardErrorInputPath,
        [Parameter(Mandatory)][string]$RunRecordInputPath,
        [Parameter(Mandatory)][string]$LiveStateInputPath,
        [Parameter(Mandatory)][string]$TrackerUrl,
        [Parameter(Mandatory)][string]$FailureCode,
        [Parameter(Mandatory)][string]$FailureMessage,
        [Parameter(Mandatory)][string]$LauncherRecoveryInputPath,
        [Parameter(Mandatory)][string]$TargetRecoveryInputPath,
        [Parameter(Mandatory)][string[]]$ArchiveCompletionInputPaths
    )

    $code = 'ASTRO_FSV_INTERRUPTED_V2_RESUME_INVALID'
    $authorizationPath = Assert-PathWithin $RecoveryInputPath $RecoveryRoot $code `
        'interrupted-v2 retirement authorization path'
    $archivePath = $authorizationPath + '.lock.bin'
    $completionPath = $authorizationPath + '.completed.json'
    $transitionPresent = (Get-AstroFsvStrictPathState `
            $LifecycleTransitionPath file $code 'canonical FSV lifecycle transition').state -ceq
        'present'
    $authorizationPresent = (Get-AstroFsvStrictPathState `
            $authorizationPath file $code 'interrupted-v2 authorization archive').state -ceq
        'present'
    if ($transitionPresent -and $authorizationPresent) {
        Fail-Astro $code 'canonical transition and authorization archive are both present' `
            'preserve both namespaces and investigate the interrupted no-replace archive'
    }
    if (-not $transitionPresent -and -not $authorizationPresent) {
        Fail-Astro $code 'resume state lacks both canonical transition and authorization' `
            'preserve archive/completion bytes and restore only through their authored transition'
    }
    $activeAuthorizationPath = if ($transitionPresent) {
        $LifecycleTransitionPath
    } else { $authorizationPath }
    $authorizationRecord = Read-AstroFsvExactJsonFile `
        $activeAuthorizationPath $code 'interrupted-v2 retirement authorization'
    $authorization = $authorizationRecord.value
    if ([string]$authorization.schema -cne
            'astrolabe.native-fsv-interrupted-v2-lock-retirement.authorization.v1' -or
        [string]$authorization.phase -cne 'authorized-exact-interrupted-v2-lock' -or
        [int]$authorization.issue -ne $ExpectedIssue -or
        [string]$authorization.tracker.url -cne $TrackerUrl -or
        [string]$authorization.failure.code -cne $FailureCode -or
        [string]$authorization.failure.message -cne $FailureMessage) {
        Fail-Astro $code `
            'surviving authorization is not the requested interrupted-v2 transaction' `
            'preserve it and resume only with its exact issue/tracker/reason binding'
    }
    foreach ($pair in @(
            @([string]$authorization.authorization_record_path, $authorizationPath),
            @([string]$authorization.completion_record_path, $completionPath),
            @([string]$authorization.lifecycle_transition_path, $LifecycleTransitionPath),
            @([string]$authorization.fsv_lock.path, $FsvLockPath),
            @([string]$authorization.fsv_lock.archive_path, $archivePath),
            @([string]$authorization.receipt_path, $ReceiptInputPath),
            @([string]$authorization.live_state.path, $LiveStateInputPath),
            @([string]$authorization.outputs.stdout.path, $StandardOutputInputPath),
            @([string]$authorization.outputs.stderr.path, $StandardErrorInputPath),
            @([string]$authorization.expected_controls.run_record_path,
                $RunRecordInputPath)
        )) {
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath([string]$pair[0]),
                [IO.Path]::GetFullPath([string]$pair[1]),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro $code 'surviving authorization path binding differs from this request' `
                'preserve the transaction and pass its exact original paths'
        }
    }
    $launcherChain = Read-AstroFsvLauncherRecoveryChain `
        -ExpectedIssue $ExpectedIssue -Workspace $Workspace `
        -LauncherRecoveryPath $LauncherRecoveryInputPath `
        -TargetRecoveryPath $TargetRecoveryInputPath `
        -ArchiveCompletionPaths $ArchiveCompletionInputPaths
    Assert-AstroFsvPersistedDeadOwnerRecoveryTerminalChain `
        -Persisted $authorization.launcher_recovery_chain `
        -Physical $launcherChain -Code $code `
        -Description 'interrupted-v2 persisted launcher recovery chain'
    $launcherProtocol = Read-AstroLauncherLock `
        -LockPath (Join-Path (Join-Path $Workspace '.tmp') 'astrolabe-launcher.lock')
    if ($launcherProtocol.State -ne 'absent') {
        Fail-Astro $code `
            "launcher protocol is '$($launcherProtocol.State)' during interrupted-v2 resume" `
            'complete the exact launcher terminal lifecycle before resuming FSV recovery'
    }
    $state = Read-AstroFsvInterruptedV2PhysicalState `
        -ExpectedIssue $ExpectedIssue -EvidenceRoot $EvidenceRoot `
        -ReceiptInputPath $ReceiptInputPath -LockState $authorization.fsv_lock.state `
        -LockSha256 ([string]$authorization.fsv_lock.sha256) `
        -LiveStateInputPath $LiveStateInputPath `
        -StandardOutputInputPath $StandardOutputInputPath `
        -StandardErrorInputPath $StandardErrorInputPath `
        -RunRecordInputPath $RunRecordInputPath `
        -LauncherRecoveryChain $launcherChain
    if ([string]$authorization.receipt_sha256 -cne [string]$state.receipt_sha256 -or
        [string]$authorization.artifact.sha256 -cne
            [string]$state.inspection.sha256 -or
        [string]$authorization.live_state.sha256 -cne
            [string]$state.live_state_sha256 -or
        [string]$authorization.outputs.stdout.sha256 -cne
            [string]$state.stdout_sha256 -or
        [string]$authorization.outputs.stderr.sha256 -cne
            [string]$state.stderr_sha256 -or
        [string]$authorization.session_inventory.sha256 -cne
            [string]$state.session_tree.sha256 -or
        [string]$authorization.launcher_job.name -cne
            [string]$state.launcher_job_name) {
        Fail-Astro $code 'session bytes differ from the durable interrupted-v2 authorization' `
            'preserve every byte and investigate post-authorization drift'
    }
    Assert-AstroFsvPersistedOwnerEnvelope `
        -Owners $authorization.owners -ExpectedBindings $state.owner_bindings `
        -Code $code -Description 'persisted interrupted-v2 owner envelope'
    Assert-AstroFsvPersistedAbsentJobProbe `
        $authorization.launcher_job.initial_probe $state.launcher_job_name $code `
        'persisted interrupted-v2 initial Job probe'
    Assert-AstroFsvPersistedAbsentJobProbe `
        $authorization.launcher_job.final_probe $state.launcher_job_name $code `
        'persisted interrupted-v2 final Job probe'
    Assert-AstroFsvPersistedRecoveryJobProbes `
        -Persisted $authorization.recovery_launcher_job_probes `
        -LauncherRecoveryChain $launcherChain -Code $code `
        -Description 'persisted interrupted-v2 recovery-chain'

    $archivePaths = @($ArchiveCompletionInputPaths | ForEach-Object {
            [IO.Path]::GetFullPath($_)
        })
    $archiveHashes = @($archivePaths | ForEach-Object { File-Sha256 $_ })
    $tracker = Read-AstroFsvInterruptedV2LockTrackerEvidence `
        -Url $TrackerUrl -ExpectedIssue $ExpectedIssue `
        -ExpectedLockPath $FsvLockPath `
        -ExpectedLockSha256 ([string]$authorization.fsv_lock.sha256) `
        -ExpectedReceiptPath $state.receipt_state.Path `
        -ExpectedReceiptSha256 $state.receipt_sha256 `
        -ExpectedArtifactPath $state.inspection.artifact_path `
        -ExpectedArtifactSha256 $state.inspection.sha256 `
        -ExpectedSessionDirectory $state.session_directory `
        -ExpectedLiveStatePath $state.live_state_path `
        -ExpectedLiveStateSha256 $state.live_state_sha256 `
        -ExpectedStandardOutputPath $state.stdout_path `
        -ExpectedStandardOutputSha256 $state.stdout_sha256 `
        -ExpectedStandardErrorPath $state.stderr_path `
        -ExpectedStandardErrorSha256 $state.stderr_sha256 `
        -ExpectedRunRecordPath $state.run_record_path `
        -ExpectedInventorySchema $state.session_tree.schema `
        -ExpectedInventoryEncoding $state.session_tree.encoding `
        -ExpectedInventoryEntryCount ([int]$state.session_tree.entry_count) `
        -ExpectedInventoryCanonicalByteCount `
            ([uint64]$state.session_tree.canonical_bytes_length) `
        -ExpectedInventorySha256 $state.session_tree.sha256 `
        -ExpectedLauncherIdentity $state.lock_launcher `
        -ExpectedRunnerIdentity $state.lock_runner `
        -ExpectedChildIdentity $state.lock_child `
        -ExpectedLauncherJobName $state.launcher_job_name `
        -ExpectedRecoveryRecordPath $authorizationPath `
        -ExpectedLockArchivePath $archivePath `
        -ExpectedCompletionRecordPath $completionPath `
        -ExpectedLifecycleTransitionPath $LifecycleTransitionPath `
        -ExpectedLauncherRecoveryCompletionPath $LauncherRecoveryInputPath `
        -ExpectedLauncherRecoveryCompletionSha256 `
            (File-Sha256 $LauncherRecoveryInputPath) `
        -ExpectedTargetRecoveryCompletionPath $TargetRecoveryInputPath `
        -ExpectedTargetRecoveryCompletionSha256 `
            (File-Sha256 $TargetRecoveryInputPath) `
        -ExpectedLauncherArchiveCompletionPaths $archivePaths `
        -ExpectedLauncherArchiveCompletionSha256s $archiveHashes `
        -ExpectedReasonCode $FailureCode
    if ([long]$authorization.tracker.comment_id -ne [long]$tracker.comment_id) {
        Fail-Astro $code 'surviving authorization tracker identity differs on readback' `
            'preserve the transaction and investigate issue-comment drift'
    }

    $initialOwnerProbes = @(Assert-AstroFsvOwnersInactive `
            -Bindings $state.owner_bindings `
            -CodePrefix 'ASTRO_FSV_INTERRUPTED_V2_RESUME' `
            -Description 'interrupted-v2 retirement resume')
    $jobProbeFirst = Get-AstroLauncherJobObjectProbe `
        -Name $state.launcher_job_name
    if ($jobProbeFirst.State -cne 'absent') {
        Fail-Astro $code `
            "interrupted-v2 launcher Job is '$($jobProbeFirst.State)' during resume" `
            'preserve every byte until the exact deterministic Job is absent'
    }
    $sourcePresent = (Get-AstroFsvStrictPathState `
            $FsvLockPath file $code 'interrupted v2 FSV lock source').state -ceq 'present'
    $archivePresent = (Get-AstroFsvStrictPathState `
            $archivePath file $code 'interrupted v2 FSV lock archive').state -ceq 'present'
    if ($sourcePresent -eq $archivePresent) {
        Fail-Astro $code `
            'exactly one of interrupted-v2 lock source/archive must exist before completion' `
            'preserve ambiguous namespace state and investigate the publication boundary'
    }
    if ($sourcePresent) {
        if ((File-Sha256 $FsvLockPath) -cne
            [string]$authorization.fsv_lock.sha256) {
            Fail-Astro $code 'source lock bytes changed after authorization' `
                'preserve source and authorization; investigate the competing writer'
        }
        Move-AstroFileWriteThroughNoReplace `
            -Source $FsvLockPath -Destination $archivePath
    }
    if ((Test-AstroPathLongPath -LiteralPath $FsvLockPath) -or
        -not (Test-AstroPathLongPath -LiteralPath $archivePath -PathType Leaf) -or
        (File-Sha256 $archivePath) -cne [string]$authorization.fsv_lock.sha256) {
        Fail-Astro $code 'lock archive does not prove source absence and byte equality' `
            'preserve authorization/archive state and inspect the filesystem transition'
    }
    $finalOwnerProbes = @(Assert-AstroFsvOwnersInactive `
            -Bindings $state.owner_bindings `
            -CodePrefix 'ASTRO_FSV_INTERRUPTED_V2_RESUME' `
            -Description 'interrupted-v2 retirement resume final authorization')
    $jobProbeSecond = Get-AstroLauncherJobObjectProbe `
        -Name $state.launcher_job_name
    if ($jobProbeSecond.State -cne 'absent') {
        Fail-Astro $code `
            "interrupted-v2 launcher Job became '$($jobProbeSecond.State)'" `
            'preserve authorization/archive state and investigate generation reappearance'
    }
    $completionState = Get-AstroFsvStrictPathState `
        $completionPath file $code 'interrupted-v2 retirement completion'
    if ($completionState.state -ceq 'absent') {
        $completion = [ordered]@{
            schema = 'astrolabe.native-fsv-interrupted-v2-lock-retirement.completion.v1'
            phase = 'complete-lock-archived-source-absent'
            issue = $ExpectedIssue
            completed_at_utc = [DateTime]::UtcNow.ToString('o')
            authorization = [ordered]@{
                path = $authorizationPath; sha256 = $authorizationRecord.sha256
            }
            source = [ordered]@{
                path = $FsvLockPath; state = 'absent'
                prior_sha256 = [string]$authorization.fsv_lock.sha256
            }
            archive = [ordered]@{
                path = $archivePath
                bytes = [uint64](Get-AstroFileInfoLongPath $archivePath).Length
                sha256 = File-Sha256 $archivePath
            }
            session = [ordered]@{
                path = $state.session_directory; state = 'present-unchanged'
                inventory_schema = [string]$state.session_tree.schema
                inventory_encoding = [string]$state.session_tree.encoding
                inventory_entry_count = [int]$state.session_tree.entry_count
                inventory_canonical_byte_count =
                    [uint64]$state.session_tree.canonical_bytes_length
                inventory_sha256 = [string]$state.session_tree.sha256
            }
            resumption = [ordered]@{
                owner_probes = [ordered]@{
                    initial = $initialOwnerProbes; final = $finalOwnerProbes
                }
                job_probes = [ordered]@{
                    initial = $jobProbeFirst; final = $jobProbeSecond
                }
            }
        }
        $completionRecord = Publish-NewAstroFsvProtocolRecord `
            -Path $completionPath -Value $completion `
            -CodePrefix 'ASTRO_FSV_INTERRUPTED_V2_COMPLETION'
    }
    else {
        $completionRecord = Read-AstroFsvExactJsonFile `
            $completionPath $code 'interrupted-v2 retirement completion'
    }
    $completionValue = $completionRecord.value
    if ([string]$completionValue.schema -cne
            'astrolabe.native-fsv-interrupted-v2-lock-retirement.completion.v1' -or
        [string]$completionValue.phase -cne 'complete-lock-archived-source-absent' -or
        [int]$completionValue.issue -ne $ExpectedIssue -or
        [string]$completionValue.authorization.sha256 -cne
            [string]$authorizationRecord.sha256 -or
        [string]$completionValue.source.state -cne 'absent' -or
        [string]$completionValue.source.prior_sha256 -cne
            [string]$authorization.fsv_lock.sha256 -or
        [string]$completionValue.archive.sha256 -cne
            [string]$authorization.fsv_lock.sha256 -or
        [string]$completionValue.session.state -cne 'present-unchanged' -or
        [string]$completionValue.session.inventory_sha256 -cne
            [string]$state.session_tree.sha256) {
        Fail-Astro $code 'completion does not hash-link source absence and unchanged session' `
            'preserve the complete record chain and investigate malformed completion bytes'
    }
    if ($transitionPresent) {
        Move-AstroFileWriteThroughNoReplace `
            -Source $LifecycleTransitionPath -Destination $authorizationPath
    }
    if ((Test-AstroPathLongPath -LiteralPath $LifecycleTransitionPath) -or
        (File-Sha256 $authorizationPath) -cne [string]$authorizationRecord.sha256 -or
        (Test-AstroPathLongPath -LiteralPath $FsvLockPath) -or
        (File-Sha256 $archivePath) -cne [string]$authorization.fsv_lock.sha256 -or
        (File-Sha256 $state.live_state_path) -cne [string]$state.live_state_sha256 -or
        (Get-AstroOrdinaryDirectoryTreeInventoryLongPath `
            $state.session_directory).sha256 -cne [string]$state.session_tree.sha256) {
        Fail-Astro $code 'terminal readback differs from interrupted-v2 completion' `
            'preserve every recovery record and inspect physical state'
    }
    return [ordered]@{
        operation = 'retire-interrupted-v2-lock'
        authorization_path = $authorizationPath
        authorization_sha256 = File-Sha256 $authorizationPath
        completion_path = $completionPath
        completion_sha256 = File-Sha256 $completionPath
        authorization = Read-AstroUtf8FileLongPath $authorizationPath | ConvertFrom-Json
        completion = Read-AstroUtf8FileLongPath $completionPath | ConvertFrom-Json
        owner_probes = [ordered]@{
            initial = $initialOwnerProbes; final = $finalOwnerProbes
        }
        job_probes = [ordered]@{
            initial = $jobProbeFirst; final = $jobProbeSecond
        }
        after = [ordered]@{
            fsv_lock_state = 'absent'; archive_state = 'present-exact'
            session_state = 'present-unchanged'; lifecycle_transition_state = 'absent'
        }
    }
}

$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$evidenceRoot = Join-Path $workspace '.tmp\native-fsv-artifacts'
$abandonRoot = Join-Path $workspace '.tmp\native-fsv-abandon-records'
$recoveryRoot = Join-Path $workspace '.tmp\native-fsv-recovery-records'
$migrationRoot = Join-Path $workspace '.tmp\native-fsv-legacy-migration-records'
$fsvLock = Join-Path (Join-Path $workspace '.tmp') 'astrolabe-fsv.lock'
$fsvLifecycleTransition = Join-Path (Join-Path $workspace '.tmp') `
    'astrolabe-fsv-lifecycle.transition.v1.json'
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
            if (-not (Test-AstroPathLongPath -LiteralPath $source -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_SOURCE_MISSING' "native build artifact does not exist: $source" `
                    'build the real native artifact successfully before staging it'
            }
            Assert-NotReparseEntry $source 'native build artifact'
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
            if (-not (Test-AstroPathLongPath -LiteralPath $gitExe -PathType Leaf)) {
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
            $launcherIdentity = New-AstroProcessIdentityRecord `
                $launcherPid ([long]$launcherOwner.OwnerProcessStartUtcTicks)
            $launcherIdentityProbe = Get-AstroExactProcessIdentityProbe `
                -Pid $launcherPid `
                -ProcessStartUtcTicks (
                    [long]$launcherOwner.OwnerProcessStartUtcTicks
                )
            if ($launcherIdentityProbe.State -cne 'exact-live') {
                Fail-Astro 'ASTRO_FSV_LAUNCHER_IDENTITY_DRIFT' `
                    "launcher identity changed before Stage owner capture: $($launcherIdentityProbe | ConvertTo-Json -Depth 6 -Compress)" `
                    'preserve target and protocol state; only the exact live launcher may stage an artifact'
            }
            if (-not (Test-DescendantOf -CandidatePid $PID -AncestorPid $launcherPid)) {
                Fail-Astro 'ASTRO_FSV_PROMOTER_NOT_OWNED' "promoter PID $PID is not a descendant of launcher PID $launcherPid" `
                    'invoke Stage synchronously from the launcher-owned child process'
            }
            $promoterIdentity = Get-AstroCurrentProcessIdentity `
                -Pid $PID `
                -Code 'ASTRO_FSV_PROMOTER_IDENTITY_UNEVALUABLE' `
                -Description 'artifact promoter'
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
                    "repository status/diff fingerprints differ from the launcher acquisition state (expected_status_sha256=$($launcherOwner.StatusSha256), actual_status_sha256=$($repoState.status_sha256), expected_diff_sha256=$($launcherOwner.DiffSha256), actual_diff_sha256=$($repoState.diff_sha256))" `
                    'discard this build, restore the frozen checkout, and rebuild from a fresh launcher lease'
            }

            $sourceHashBefore = Source-File-Sha256 $source
            $sourceItem = Get-AstroFileInfoLongPath $source
            $hashParent = Join-Path (Join-Path $evidenceRoot $TreeSha) $sourceHashBefore
            $finalDirectory = Join-Path $hashParent $SessionId
            if (Test-AstroPathLongPath -LiteralPath $finalDirectory) {
                Fail-Astro 'ASTRO_FSV_STAGE_REUSE_REFUSED' "evidence session already exists: $finalDirectory" `
                    'use a fresh SessionId; evidence sessions are immutable and never overwritten'
            }
            Assert-NotReparseEntry (Join-Path $workspace '.tmp') 'workspace temporary directory'
            Assert-NotReparseEntry $evidenceRoot 'evidence root'
            Assert-NotReparseEntry (Join-Path $evidenceRoot $TreeSha) 'evidence tree directory'
            Assert-NotReparseEntry $hashParent 'evidence hash directory'
            New-AstroDirectoryLongPath $hashParent | Out-Null
            Assert-NotReparseEntry $hashParent 'evidence hash directory'
            $publishingDirectory = Join-Path $hashParent (".$SessionId.publishing-$PID-" + [guid]::NewGuid().ToString('N'))
            New-AstroDirectoryNoClobberLongPath $publishingDirectory | Out-Null
            $published = $false
            try {
                $artifactName = [IO.Path]::GetFileName($source)
                $staged = Join-Path $publishingDirectory $artifactName
                Copy-FileDurable $source $staged
                $sourceHashAfter = Source-File-Sha256 $source
                $stagedHash = File-Sha256 $staged
                $stagedItem = Get-AstroFileInfoLongPath $staged
                if ($sourceHashBefore -cne $sourceHashAfter -or $sourceHashBefore -cne $stagedHash -or
                    [uint64]$sourceItem.Length -ne [uint64]$stagedItem.Length) {
                    Fail-Astro 'ASTRO_FSV_STAGE_COPY_MISMATCH' `
                        "source/staged bytes changed during promotion: source_before=$sourceHashBefore source_after=$sourceHashAfter staged=$stagedHash" `
                        'discard the partial publication, stop the writer, and rebuild from a frozen tree'
                }
                Set-AstroFileReadOnlyLongPath -LiteralPath $staged -ReadOnly $true
                $finalArtifact = Join-Path $finalDirectory $artifactName
                $receipt = [ordered]@{
                    schema = 'astrolabe.native-fsv-artifact.v2'
                    issue = $Issue
                    session_id = $SessionId
                    tree_sha = $TreeSha
                    promoted_at_utc = [DateTime]::UtcNow.ToString('o')
                    owners = [ordered]@{
                        launcher = $launcherIdentity
                        promoter = $promoterIdentity
                    }
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
                if (-not $published -and
                    (Test-AstroPathLongPath -LiteralPath $publishingDirectory)) {
                    Remove-AstroOrdinaryFlatDirectoryLongPath $publishingDirectory
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
        'RetireTerminalPartialLock' {
            if ($Issue -le 0) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_ISSUE_INVALID' `
                    'Issue must be positive for terminal-partial FSV lock retirement' `
                    'pass the exact issue bound by the staged artifact and FSV lock'
            }
            if ([string]::IsNullOrWhiteSpace($TrackerCommentUrl)) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TRACKER_REQUIRED' `
                    'TrackerCommentUrl is required for terminal-partial FSV lock retirement' `
                    'post a fresh owner-authored comment binding every exact source-of-truth path and hash'
            }
            if ($ReasonCode -notmatch '^[A-Z][A-Z0-9_]{2,95}$' -or
                [string]::IsNullOrWhiteSpace($ReasonMessage)) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_REASON_INVALID' `
                    'RetireTerminalPartialLock requires a structured ReasonCode and nonblank ReasonMessage' `
                    'describe the exact runner failure that prevented run/live publication'
            }
            if ([string]::IsNullOrWhiteSpace($RecoveryRecordPath)) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_RECORD_REQUIRED' `
                    'RecoveryRecordPath is required for terminal-partial FSV lock retirement' `
                    "use one fresh JSON path below $recoveryRoot"
            }
            $fsvLifecycleMutex = Enter-AstroFsvLifecycleMutex -WorkspaceRoot $workspace
            if (-not $fsvLifecycleMutex.Acquired) {
                Exit-AstroFsvLifecycleMutex $fsvLifecycleMutex
                Fail-Astro 'ASTRO_FSV_LIFECYCLE_MUTEX_HELD' `
                    "native-FSV lifecycle mutex is held: $($fsvLifecycleMutex.Name)" `
                    'wait for the exact active claim/recovery transaction to publish durable state'
            }
            # Global order for cross-protocol recovery is native-FSV lifecycle
            # mutex first, launcher-lock mutex second. Launcher admission holds
            # only the latter during its short claim, so contention refuses and
            # releases rather than waiting into a lock cycle.
            $launcherCoordinationMutex = Enter-AstroLauncherLockMutex `
                -LockPath $launcherLockPath
            if (-not $launcherCoordinationMutex.Acquired) {
                $mutexName = [string]$launcherCoordinationMutex.Name
                Exit-AstroLauncherLockMutex $launcherCoordinationMutex
                Exit-AstroFsvLifecycleMutex $fsvLifecycleMutex
                Fail-Astro 'ASTRO_FSV_LAUNCHER_MUTEX_HELD' `
                    "launcher-lock coordination mutex is held: $mutexName" `
                    'wait for launcher claim/recovery coordination to finish, then resume the exact FSV transaction'
            }
            try {
            $resumeAuthorizationPath = Assert-PathWithin `
                $RecoveryRecordPath $recoveryRoot `
                'ASTRO_FSV_PARTIAL_LOCK_RECORD_ESCAPE' 'retirement record path'
            $resumeArchivePath = $resumeAuthorizationPath + '.lock.bin'
            $resumeCompletionPath = $resumeAuthorizationPath + '.completed.json'
            if ((Test-AstroPathLongPath -LiteralPath $fsvLifecycleTransition) -or
                (Test-AstroPathLongPath -LiteralPath $resumeAuthorizationPath) -or
                (Test-AstroPathLongPath -LiteralPath $resumeArchivePath) -or
                (Test-AstroPathLongPath -LiteralPath $resumeCompletionPath)) {
                $resumeResult = Invoke-AstroFsvPartialLockRetirementResume `
                    -ExpectedIssue $Issue -Workspace $workspace `
                    -EvidenceRoot $evidenceRoot -RecoveryRoot $recoveryRoot `
                    -FsvLockPath $fsvLock `
                    -LifecycleTransitionPath $fsvLifecycleTransition `
                    -ReceiptInputPath $ReceiptPath `
                    -RecoveryInputPath $RecoveryRecordPath `
                    -StandardOutputInputPath $StandardOutputPath `
                    -StandardErrorInputPath $StandardErrorPath `
                    -RunRecordInputPath $RunRecordPath `
                    -LiveStateInputPath $LiveStatePath `
                    -TrackerUrl $TrackerCommentUrl `
                    -FailureCode $ReasonCode -FailureMessage $ReasonMessage `
                    -LauncherRecoveryInputPath $LauncherRecoveryCompletionPath `
                    -TargetRecoveryInputPath $TargetRecoveryCompletionPath `
                    -ArchiveCompletionInputPaths $LauncherArchiveCompletionPaths `
                    -LauncherTerminalChainKind $LauncherTerminalChainKind `
                    -NormalArchiveCompletionInputPath `
                        $LauncherNormalArchiveCompletionPath
                $resumeResult | ConvertTo-Json -Depth 40 -Compress | Write-Output
                return
            }
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            if ([int]$inspection.issue -ne $Issue) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_ISSUE_MISMATCH' `
                    "requested issue #$Issue differs from receipt issue #$($inspection.issue)" `
                    'retire state only through the exact issue named by its receipt and lock'
            }
            $launcherRecoveryChain = Read-AstroFsvLauncherTerminalChainFromInputs `
                -Kind $LauncherTerminalChainKind `
                -ExpectedIssue $Issue -Workspace $workspace `
                -LauncherRecoveryPath $LauncherRecoveryCompletionPath `
                -TargetRecoveryPath $TargetRecoveryCompletionPath `
                -ArchiveCompletionPaths $LauncherArchiveCompletionPaths `
                -NormalArchiveCompletionPath $LauncherNormalArchiveCompletionPath
            $launcherProtocolState = Read-AstroLauncherLock -LockPath $launcherLockPath
            if ($launcherProtocolState.State -ne 'absent') {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_LAUNCHER_LOCK' `
                    "launcher protocol is '$($launcherProtocolState.State)'; terminal-partial FSV lock retirement requires authoritative absence" `
                    'complete the exact launcher terminal lifecycle before retiring any FSV lock'
            }
            if (-not (Test-AstroPathLongPath -LiteralPath $fsvLock -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_ABSENT' `
                    "FSV lock is already absent: $fsvLock" `
                    'do not manufacture retirement evidence for an absent lock'
            }
            Assert-NotReparseEntry $fsvLock 'terminal-partial native FSV lock'
            $lockShaBefore = File-Sha256 $fsvLock
            try { $lockState = Read-AstroUtf8FileLongPath $fsvLock | ConvertFrom-Json }
            catch {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_INVALID' `
                    "FSV lock is unreadable: ${fsvLock}: $($_.Exception.Message)" `
                    'preserve the lock and investigate its exact bytes'
            }
            $lockFields = @($lockState.PSObject.Properties | ForEach-Object Name)
            $expectedLockFields = @(
                'schema', 'mode', 'issue', 'started', 'resident_count',
                'process_count', 'tree_sha', 'artifact_path', 'artifact_sha256',
                'cohort_plan', 'owners', 'launcher_job', 'phase'
            )
            if ($lockFields.Count -ne $expectedLockFields.Count -or
                @($expectedLockFields | Where-Object {
                        $lockFields -notcontains $_
                    }).Count -ne 0 -or
                [string]$lockState.schema -cne 'astrolabe.native-fsv-lock.v3' -or
                [string]$lockState.mode -cne 'resident-cohort' -or
                [int]$lockState.issue -ne $Issue -or
                [string]$lockState.tree_sha -cne [string]$inspection.tree_sha -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$lockState.artifact_path),
                    $inspection.artifact_path,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                [string]$lockState.artifact_sha256 -cne [string]$inspection.sha256 -or
                -not $lockState.PSObject.Properties['owners'] -or
                -not $lockState.owners.PSObject.Properties['launcher'] -or
                -not $lockState.owners.PSObject.Properties['runner'] -or
                -not $lockState.owners.PSObject.Properties['processes'] -or
                -not $lockState.PSObject.Properties['resident_count'] -or
                -not $lockState.PSObject.Properties['process_count'] -or
                -not $lockState.PSObject.Properties['launcher_job'] -or
                -not $lockState.launcher_job.PSObject.Properties['name'] -or
                -not $lockState.launcher_job.PSObject.Properties['members'] -or
                -not $lockState.PSObject.Properties['cohort_plan'] -or
                -not $lockState.cohort_plan.PSObject.Properties['path'] -or
                -not $lockState.cohort_plan.PSObject.Properties['sha256'] -or
                [string]$lockState.phase -cnotin @('creating', 'suspended')) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_INVALID' `
                    'FSV lock is not one complete v3 cohort authority bound to the selected issue/tree/artifact' `
                    'preserve the lock and session; mixed or incomplete authority cannot retire state'
            }
            $lockLauncher = Read-AstroFsvProcessIdentity $lockState.owners.launcher `
                'ASTRO_FSV_PARTIAL_LOCK_INVALID' 'partial FSV-lock launcher identity'
            $lockRunner = Read-AstroFsvProcessIdentity $lockState.owners.runner `
                'ASTRO_FSV_PARTIAL_LOCK_INVALID' 'partial FSV-lock runner identity'
            try {
                $lockStarted = [DateTimeOffset]::Parse(
                    [string]$lockState.started,
                    [Globalization.CultureInfo]::InvariantCulture
                )
            }
            catch {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_INVALID' `
                    'FSV lock started timestamp is not a valid UTC timestamp' `
                    'preserve the malformed lock and investigate its publisher'
            }
            if (-not (Test-AstroFsvIdentityEqual `
                    $lockLauncher $inspection.owners.launcher)) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_OWNER_MISMATCH' `
                    'receipt and FSV-lock launcher generations differ' `
                    'preserve the cross-generation state and investigate its publisher'
            }
            $lockProcesses = Read-AstroFsvTerminalPartialPreLiveProcesses `
                -LockState $lockState -Code 'ASTRO_FSV_PARTIAL_LOCK_INVALID' `
                -Description 'partial FSV-lock process set'
            $cohortPlanPath = Assert-PathWithin `
                ([string]$lockState.cohort_plan.path) $workspace `
                'ASTRO_FSV_PARTIAL_LOCK_INVALID' 'partial FSV-lock cohort plan'
            if (-not (Test-AstroPathLongPath -LiteralPath $cohortPlanPath -PathType Leaf) -or
                (File-Sha256 $cohortPlanPath) -cne
                    [string]$lockState.cohort_plan.sha256) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_INVALID' `
                    'FSV lock cohort plan is absent or differs from its bound SHA-256' `
                    'preserve the lock/session and investigate plan drift'
            }
            [int[]]$jobMembers = @($lockState.launcher_job.members)
            if ($jobMembers.Count -ne @($jobMembers | Sort-Object -Unique).Count -or
                $jobMembers -contains 0 -or
                $jobMembers -notcontains [int]$lockLauncher.pid -or
                $jobMembers -notcontains [int]$lockRunner.pid) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_INVALID' `
                    'FSV lock initial launcher Job membership does not contain launcher and runner' `
                    'preserve the lock/session and investigate malformed cohort attribution'
            }
            $matchingLauncherArchive = @($launcherRecoveryChain.archives | Where-Object {
                    [int]$_.authorization.value.generation.launcher_pid -eq
                        [int]$lockLauncher.pid -and
                    [long]$_.authorization.value.generation.launcher_process_start_utc_ticks -eq
                        [long]$lockLauncher.process_start_utc_ticks
                })
            if ($matchingLauncherArchive.Count -ne 1 -or
                [string]$lockState.launcher_job.name -cne
                    [string]$matchingLauncherArchive[0].job_name) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_LAUNCHER_RECOVERY_INVALID' `
                    'FSV lock Job/launcher generation is not the exact archived launcher generation' `
                    'preserve the lock and supply its exact launcher recovery/archive chain'
            }
            $ownerBindingList = New-Object System.Collections.Generic.List[object]
            foreach ($binding in @(
                New-AstroFsvOwnerBinding `
                    'launcher' 'artifact receipt' $inspection.owners.launcher
                New-AstroFsvOwnerBinding `
                    'promoter' 'artifact receipt' $inspection.owners.promoter
                New-AstroFsvOwnerBinding `
                    'launcher' 'partial FSV lock' $lockLauncher
                New-AstroFsvOwnerBinding `
                    'runner' 'partial FSV lock' $lockRunner
            )) { $ownerBindingList.Add($binding) }
            Add-AstroFsvV3ProcessBindings $ownerBindingList $lockProcesses `
                'partial FSV lock'
            foreach ($archive in $launcherRecoveryChain.archives) {
                $archiveGeneration = $archive.authorization.value.generation
                $archiveIdentity = New-AstroProcessIdentityRecord `
                    ([int]$archiveGeneration.launcher_pid) `
                    ([long]$archiveGeneration.launcher_process_start_utc_ticks)
                $ownerBindingList.Add((New-AstroFsvOwnerBinding `
                        'launcher' 'launcher recovery/archive chain' $archiveIdentity))
            }
            $ownerBindings = [object[]]$ownerBindingList.ToArray()
            $session = [IO.Path]::GetFullPath($inspection.session_directory)
            $stdoutPath = Assert-DirectSessionChildPath $StandardOutputPath $session `
                'ASTRO_FSV_PARTIAL_LOCK_OUTPUT_PATH_INVALID' 'standard-output path'
            $stderrPath = Assert-DirectSessionChildPath $StandardErrorPath $session `
                'ASTRO_FSV_PARTIAL_LOCK_OUTPUT_PATH_INVALID' 'standard-error path'
            $expectedRunRecord = Assert-DirectSessionChildPath $RunRecordPath $session `
                'ASTRO_FSV_PARTIAL_LOCK_RUN_PATH_INVALID' 'expected run-record path'
            $expectedLiveState = Assert-DirectSessionChildPath $LiveStatePath $session `
                'ASTRO_FSV_PARTIAL_LOCK_LIVE_PATH_INVALID' 'expected live-state path'
            $claimedPaths = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::OrdinalIgnoreCase
            )
            foreach ($claimedPath in @(
                    $receiptState.Path, $inspection.artifact_path, $stdoutPath,
                    $stderrPath, $expectedRunRecord, $expectedLiveState
                )) {
                if (-not $claimedPaths.Add([IO.Path]::GetFullPath($claimedPath))) {
                    Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_PATH_COLLISION' `
                        "terminal-partial receipt/artifact/output/control paths collide: $claimedPath" `
                        'preserve the session and bind six pairwise-distinct direct paths'
                }
            }
            if (-not (Test-AstroPathLongPath -LiteralPath $stdoutPath -PathType Leaf) -or
                -not (Test-AstroPathLongPath -LiteralPath $stderrPath -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_OUTPUT_MISSING' `
                    'both explicit child output paths must physically exist' `
                    'preserve the session; no exact terminal partial output family is proven'
            }
            foreach ($path in @($stdoutPath, $stderrPath)) {
                Assert-NotReparseEntry $path 'terminal-partial native FSV output'
            }
            if ((Test-AstroPathLongPath -LiteralPath $expectedRunRecord) -or
                (Test-AstroPathLongPath -LiteralPath $expectedLiveState)) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_CONTROL_STATE_PRESENT' `
                    'RetireTerminalPartialLock requires both exact expected run and live-state paths to be absent' `
                    'use RetireLock for a completed bound run; preserve malformed mixed state'
            }
            $stdoutSha256 = File-Sha256 $stdoutPath
            $stderrSha256 = File-Sha256 $stderrPath
            $stdoutBytes = [uint64](Get-AstroFileInfoLongPath $stdoutPath).Length
            $stderrBytes = [uint64](Get-AstroFileInfoLongPath $stderrPath).Length
            if (($stdoutBytes + $stderrBytes) -eq 0) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_OUTPUT_EMPTY' `
                    'both child output files are empty; real child execution is not physically proven' `
                    'preserve the ambiguous session and investigate its process chronology'
            }
            $sessionFiles = @(Get-SessionFileInventory $session)
            $sessionTree = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $session
            if ($sessionFiles.Count -lt 4) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_INVENTORY_INVALID' `
                    "session inventory has only $($sessionFiles.Count) files" `
                    'preserve ambiguous state that lacks receipt/artifact/output evidence'
            }
            $requiredPaths = @(
                $receiptState.Path, $inspection.artifact_path, $stdoutPath, $stderrPath
            ) | ForEach-Object { [IO.Path]::GetFullPath($_) }
            $inventoryPaths = @($sessionFiles | ForEach-Object { [string]$_.path })
            if (@($requiredPaths | Where-Object { $inventoryPaths -notcontains $_ }).Count -ne 0) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_INVENTORY_INVALID' `
                    'session inventory omits one or more required receipt/artifact/output paths' `
                    'preserve the session and investigate its exact filesystem identity'
            }
            $receiptSha256 = File-Sha256 $receiptState.Path
            $initialOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_PARTIAL_LOCK' `
                    -Description 'terminal-partial FSV lock retirement'
            )
            $jobName = [string]$lockState.launcher_job.name
            $jobProbeFirst = Get-AstroLauncherJobObjectProbe -Name $jobName
            if ($jobProbeFirst.State -cne 'absent') {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_JOB_PRESENT' `
                    "launcher Job is '$($jobProbeFirst.State)': $jobName" `
                    'preserve the lock/session until the exact deterministic Job is absent'
            }
            $recoveryJobProbesFirst = [Collections.Generic.List[object]]::new()
            foreach ($archive in $launcherRecoveryChain.archives) {
                $probe = Get-AstroLauncherJobObjectProbe -Name ([string]$archive.job_name)
                if ($probe.State -cne 'absent') {
                    Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_JOB_PRESENT' `
                        "recovery launcher Job is '$($probe.State)': $($archive.job_name)" `
                        'preserve the lock/session while any recovery launcher generation exists'
                }
                $recoveryJobProbesFirst.Add($probe)
            }
            $recoveryRecord = Assert-PathWithin $RecoveryRecordPath $recoveryRoot `
                'ASTRO_FSV_PARTIAL_LOCK_RECORD_ESCAPE' 'retirement record path'
            if ((Get-AstroFsvStrictPathState `
                    $recoveryRecord file `
                    'ASTRO_FSV_PARTIAL_LOCK_RECORD_REUSE_REFUSED' `
                    'partial-lock authorization archive').state -cne 'absent') {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_RECORD_REUSE_REFUSED' `
                    "retirement record already exists: $recoveryRecord" `
                    'use one fresh append-only record path per partial-lock generation'
            }
            $lockArchivePath = $recoveryRecord + '.lock.bin'
            $completionRecordPath = $recoveryRecord + '.completed.json'
            if ((Get-AstroFsvStrictPathState `
                    $lockArchivePath file `
                    'ASTRO_FSV_PARTIAL_LOCK_RECORD_REUSE_REFUSED' `
                    'partial-lock archive').state -cne 'absent' -or
                (Get-AstroFsvStrictPathState `
                    $completionRecordPath file `
                    'ASTRO_FSV_PARTIAL_LOCK_RECORD_REUSE_REFUSED' `
                    'partial-lock completion').state -cne 'absent' -or
                (Get-AstroFsvStrictPathState `
                    $fsvLifecycleTransition file `
                    'ASTRO_FSV_PARTIAL_LOCK_RECORD_REUSE_REFUSED' `
                    'canonical FSV lifecycle transition').state -cne 'absent') {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_RECORD_REUSE_REFUSED' `
                    'derived lock archive, completion, or canonical lifecycle transition already exists' `
                    'use one fresh append-only recovery record path per partial-lock generation'
            }
            $archiveCompletionPaths = [string[]]@(
                $launcherRecoveryChain.archives | ForEach-Object {
                    [string]$_.completion.path
                }
            )
            $archiveCompletionHashes = [string[]]@(
                $launcherRecoveryChain.archives | ForEach-Object {
                    [string]$_.completion.sha256
                }
            )
            $deadLauncherRecoveryPath = if ($LauncherTerminalChainKind -ceq
                'DeadOwnerRecoveryV1') {
                [string]$launcherRecoveryChain.launcher_recovery.path
            } else { '' }
            $deadLauncherRecoveryHash = if ($LauncherTerminalChainKind -ceq
                'DeadOwnerRecoveryV1') {
                [string]$launcherRecoveryChain.launcher_recovery.sha256
            } else { '' }
            $deadTargetRecoveryPath = if ($LauncherTerminalChainKind -ceq
                'DeadOwnerRecoveryV1') {
                [string]$launcherRecoveryChain.target_recovery.path
            } else { '' }
            $deadTargetRecoveryHash = if ($LauncherTerminalChainKind -ceq
                'DeadOwnerRecoveryV1') {
                [string]$launcherRecoveryChain.target_recovery.sha256
            } else { '' }
            $normalTerminalRecord = if ($LauncherTerminalChainKind -ceq
                'NormalLiveOwnerCleanupV1') {
                ConvertTo-AstroFsvNormalCleanupTerminalChainRecord $launcherRecoveryChain
            } else { $null }
            $tracker = Read-AstroFsvPartialLockTrackerEvidence `
                -Url $TrackerCommentUrl -ExpectedIssue $Issue `
                -ExpectedLockPath $fsvLock -ExpectedLockSha256 $lockShaBefore `
                -ExpectedReceiptPath $receiptState.Path `
                -ExpectedReceiptSha256 $receiptSha256 `
                -ExpectedArtifactPath $inspection.artifact_path `
                -ExpectedArtifactSha256 $inspection.sha256 `
                -ExpectedSessionDirectory $session `
                -ExpectedStandardOutputPath $stdoutPath `
                -ExpectedStandardOutputSha256 $stdoutSha256 `
                -ExpectedStandardErrorPath $stderrPath `
                -ExpectedStandardErrorSha256 $stderrSha256 `
                -ExpectedRunRecordPath $expectedRunRecord `
                -ExpectedLiveStatePath $expectedLiveState `
                -ExpectedInventorySchema ([string]$sessionTree.schema) `
                -ExpectedInventoryEncoding ([string]$sessionTree.encoding) `
                -ExpectedInventoryEntryCount ([int]$sessionTree.entry_count) `
                -ExpectedInventoryCanonicalByteCount `
                    ([uint64]$sessionTree.canonical_bytes_length) `
                -ExpectedInventorySha256 ([string]$sessionTree.sha256) `
                -ExpectedRecoveryRecordPath $recoveryRecord `
                -ExpectedLockArchivePath $lockArchivePath `
                -ExpectedCompletionRecordPath $completionRecordPath `
                -ExpectedLifecycleTransitionPath $fsvLifecycleTransition `
                -ExpectedLauncherRecoveryCompletionPath $deadLauncherRecoveryPath `
                -ExpectedLauncherRecoveryCompletionSha256 $deadLauncherRecoveryHash `
                -ExpectedTargetRecoveryCompletionPath $deadTargetRecoveryPath `
                -ExpectedTargetRecoveryCompletionSha256 $deadTargetRecoveryHash `
                -ExpectedLauncherArchiveCompletionPaths $archiveCompletionPaths `
                -ExpectedLauncherArchiveCompletionSha256s $archiveCompletionHashes `
                -ExpectedLauncherTerminalChainKind $LauncherTerminalChainKind `
                -ExpectedLauncherNormalChainRecord $normalTerminalRecord `
                -ExpectedReasonCode $ReasonCode
            try {
                $trackerCreated = [DateTimeOffset]::Parse(
                    [string]$tracker.created_at,
                    [Globalization.CultureInfo]::InvariantCulture
                )
            }
            catch {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TRACKER_STALE' `
                    "tracker timestamp is malformed ('$($tracker.created_at)'): $($_.Exception.Message)" `
                    'preserve the lock and post no retirement transition'
            }
            $lockStartedSecond = [DateTimeOffset]::new(
                $lockStarted.Year, $lockStarted.Month, $lockStarted.Day,
                $lockStarted.Hour, $lockStarted.Minute, $lockStarted.Second,
                [TimeSpan]::Zero
            )
            if ($trackerCreated -lt $lockStartedSecond) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_TRACKER_STALE' `
                    'partial-lock tracker comment predates the exact terminal-partial generation' `
                    'post one fresh owner-authored comment after reading the preserved state'
            }
            $finalOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_PARTIAL_LOCK' `
                    -Description 'terminal-partial FSV lock final authorization'
            )
            $jobProbeSecond = Get-AstroLauncherJobObjectProbe -Name $jobName
            $recoveryJobProbesSecond = [Collections.Generic.List[object]]::new()
            foreach ($archive in $launcherRecoveryChain.archives) {
                $probe = Get-AstroLauncherJobObjectProbe -Name ([string]$archive.job_name)
                if ($probe.State -cne 'absent') {
                    Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_JOB_PRESENT' `
                        "recovery launcher Job changed to '$($probe.State)': $($archive.job_name)" `
                        'preserve the lock/session while any recovery launcher generation exists'
                }
                $recoveryJobProbesSecond.Add($probe)
            }
            $launcherRecoveryChainFinal = Read-AstroFsvLauncherTerminalChainFromInputs `
                -Kind $LauncherTerminalChainKind `
                -ExpectedIssue $Issue -Workspace $workspace `
                -LauncherRecoveryPath $LauncherRecoveryCompletionPath `
                -TargetRecoveryPath $TargetRecoveryCompletionPath `
                -ArchiveCompletionPaths $LauncherArchiveCompletionPaths `
                -NormalArchiveCompletionPath $LauncherNormalArchiveCompletionPath
            $terminalChainStable = Test-AstroFsvLauncherTerminalChainEqual `
                $launcherRecoveryChainFinal $launcherRecoveryChain
            $launcherProtocolFinal = Read-AstroLauncherLock -LockPath $launcherLockPath
            $finalTree = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $session
            $cohortPlanFinalState = Get-AstroFsvStrictPathState `
                $cohortPlanPath file 'ASTRO_FSV_PARTIAL_LOCK_STATE_DRIFT' `
                'terminal-partial cohort plan after tracker authorization'
            if ($jobProbeSecond.State -cne 'absent' -or
                $launcherProtocolFinal.State -ne 'absent' -or
                $cohortPlanFinalState.state -cne 'present' -or
                (File-Sha256 $cohortPlanPath) -cne
                    [string]$lockState.cohort_plan.sha256 -or
                (File-Sha256 $fsvLock) -cne $lockShaBefore -or
                (File-Sha256 $receiptState.Path) -cne $receiptSha256 -or
                (File-Sha256 $inspection.artifact_path) -cne $inspection.sha256 -or
                (File-Sha256 $stdoutPath) -cne $stdoutSha256 -or
                (File-Sha256 $stderrPath) -cne $stderrSha256 -or
                (Test-AstroPathLongPath -LiteralPath $expectedRunRecord) -or
                (Test-AstroPathLongPath -LiteralPath $expectedLiveState) -or
                -not $terminalChainStable -or
                [string]$finalTree.schema -cne [string]$sessionTree.schema -or
                [string]$finalTree.encoding -cne [string]$sessionTree.encoding -or
                [int]$finalTree.entry_count -ne [int]$sessionTree.entry_count -or
                [uint64]$finalTree.canonical_bytes_length -ne
                    [uint64]$sessionTree.canonical_bytes_length -or
                [string]$finalTree.sha256 -cne [string]$sessionTree.sha256) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_STATE_DRIFT' `
                    'lock/session/owner/Job/launcher state changed after tracker authorization' `
                    'preserve every byte and post fresh evidence for the current exact state'
            }
            $currentRepository = Get-RepoState -GitExe $gitExe -Workspace $workspace
            $recordParent = Split-Path -Parent $recoveryRecord
            New-AstroDirectoryLongPath $recordParent | Out-Null
            Assert-NotReparseEntry $recordParent 'partial-lock retirement record parent'
            $retirementSchema = if ($LauncherTerminalChainKind -ceq
                'NormalLiveOwnerCleanupV1') {
                'astrolabe.native-fsv-partial-lock-retirement.authorization.v2'
            } else {
                'astrolabe.native-fsv-partial-lock-retirement.authorization.v1'
            }
            $retirement = [ordered]@{
                schema = $retirementSchema
                phase = 'authorized-exact-terminal-partial-lock'
                issue = $Issue
                recorded_at_utc = [DateTime]::UtcNow.ToString('o')
                tracker = $tracker
                fsv_lock = [ordered]@{
                    path = $fsvLock
                    sha256 = $lockShaBefore
                    state = $lockState
                    archive_path = $lockArchivePath
                }
                lifecycle_transition_path = $fsvLifecycleTransition
                authorization_record_path = $recoveryRecord
                completion_record_path = $completionRecordPath
                receipt_path = $receiptState.Path
                receipt_sha256 = $receiptSha256
                session_directory = $session
                artifact = [ordered]@{
                    path = $inspection.artifact_path
                    bytes = [uint64]$inspection.bytes
                    sha256 = $inspection.sha256
                }
                expected_controls = [ordered]@{
                    run_record_path = $expectedRunRecord
                    run_record_state = 'absent'
                    live_state_path = $expectedLiveState
                    live_state_state = 'absent'
                }
                outputs = [ordered]@{
                    stdout = [ordered]@{
                        path = $stdoutPath; bytes = $stdoutBytes; sha256 = $stdoutSha256
                    }
                    stderr = [ordered]@{
                        path = $stderrPath; bytes = $stderrBytes; sha256 = $stderrSha256
                    }
                }
                session_inventory = [ordered]@{
                    schema = [string]$sessionTree.schema
                    encoding = [string]$sessionTree.encoding
                    entry_count = [int]$sessionTree.entry_count
                    canonical_bytes_length = [uint64]$sessionTree.canonical_bytes_length
                    sha256 = [string]$sessionTree.sha256
                    files = $sessionFiles
                    entries = [object[]]$sessionTree.entries
                }
                launcher_protocol_state = $launcherProtocolFinal.State
                launcher_job = [ordered]@{
                    name = $jobName
                    initial_probe = $jobProbeFirst
                    final_probe = $jobProbeSecond
                }
                staged_repository = $receiptState.Receipt.repository
                current_repository = $currentRepository
                owners = [ordered]@{
                    identities = @($ownerBindings | ForEach-Object {
                            [ordered]@{
                                role = $_.Role; source = $_.Source; identity = $_.Identity
                            }
                        })
                    initial_probes = $initialOwnerProbes
                    final_probes = $finalOwnerProbes
                }
                failure = [ordered]@{ code = $ReasonCode; message = $ReasonMessage }
            }
            if ($LauncherTerminalChainKind -ceq 'DeadOwnerRecoveryV1') {
                $retirement.launcher_recovery_chain = [ordered]@{
                    launcher_recovery_completion = [ordered]@{
                        path = [string]$launcherRecoveryChain.launcher_recovery.path
                        sha256 = [string]$launcherRecoveryChain.launcher_recovery.sha256
                    }
                    target_recovery_completion = [ordered]@{
                        path = [string]$launcherRecoveryChain.target_recovery.path
                        sha256 = [string]$launcherRecoveryChain.target_recovery.sha256
                    }
                    launcher_archive_completions = @(
                        for ($archiveIndex = 0;
                            $archiveIndex -lt $archiveCompletionPaths.Count;
                            $archiveIndex++) {
                            [ordered]@{
                                path = $archiveCompletionPaths[$archiveIndex]
                                sha256 = $archiveCompletionHashes[$archiveIndex]
                            }
                        }
                    )
                }
                $retirement.recovery_launcher_job_probes = [ordered]@{
                    initial = [object[]]$recoveryJobProbesFirst.ToArray()
                    final = [object[]]$recoveryJobProbesSecond.ToArray()
                }
            }
            else {
                $retirement.launcher_terminal_chain = $normalTerminalRecord
                $retirement.terminal_launcher_job_probes = [ordered]@{
                    initial = [object[]]$recoveryJobProbesFirst.ToArray()
                    final = [object[]]$recoveryJobProbesSecond.ToArray()
                }
            }
            $transitionPublication = Publish-NewAstroFsvProtocolRecord `
                -Path $fsvLifecycleTransition -Value $retirement `
                -CodePrefix 'ASTRO_FSV_PARTIAL_LOCK_AUTHORIZATION' `
                -StageDirectory $recordParent
            $persisted = $transitionPublication.value
            if ([string]$persisted.schema -cne $retirementSchema -or
                [string]$persisted.phase -cne
                    'authorized-exact-terminal-partial-lock' -or
                [string]$persisted.fsv_lock.sha256 -cne $lockShaBefore -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$persisted.fsv_lock.archive_path),
                    $lockArchivePath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                [string]$persisted.receipt_sha256 -cne $receiptSha256 -or
                [string]$persisted.artifact.sha256 -cne $inspection.sha256 -or
                [string]$persisted.session_inventory.sha256 -cne
                    [string]$sessionTree.sha256 -or
                [string]$persisted.failure.code -cne $ReasonCode -or
                [string]$persisted.tracker.url -cne $TrackerCommentUrl) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_RECORD_INVALID' `
                    'persisted retirement record differs from the exact authorization state' `
                    'preserve both lock and record and investigate the durable-write mismatch'
            }
            Assert-AstroFsvPersistedOwnerEnvelope `
                -Owners $persisted.owners -ExpectedBindings $ownerBindings `
                -Code 'ASTRO_FSV_PARTIAL_LOCK_RECORD_INVALID' `
                -Description 'persisted terminal-partial lock retirement'
            foreach ($pair in @(
                    @([string]$persisted.authorization_record_path, $recoveryRecord),
                    @([string]$persisted.lifecycle_transition_path,
                        $fsvLifecycleTransition),
                    @([string]$persisted.completion_record_path,
                        $completionRecordPath),
                    @([string]$persisted.fsv_lock.path, $fsvLock),
                    @([string]$persisted.fsv_lock.archive_path, $lockArchivePath),
                    @([string]$persisted.receipt_path, $receiptState.Path),
                    @([string]$persisted.session_directory, $session),
                    @([string]$persisted.artifact.path, $inspection.artifact_path),
                    @([string]$persisted.outputs.stdout.path, $stdoutPath),
                    @([string]$persisted.outputs.stderr.path, $stderrPath),
                    @([string]$persisted.expected_controls.run_record_path,
                        $expectedRunRecord),
                    @([string]$persisted.expected_controls.live_state_path,
                        $expectedLiveState)
                )) {
                if (-not [string]::Equals(
                        [IO.Path]::GetFullPath([string]$pair[0]),
                        [IO.Path]::GetFullPath([string]$pair[1]),
                        [StringComparison]::OrdinalIgnoreCase
                    )) {
                    Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_RECORD_INVALID' `
                        'persisted retirement path binding differs from the authorized state' `
                        'preserve the lock and transition; no archive authority was established'
                }
            }
            if ($LauncherTerminalChainKind -ceq 'DeadOwnerRecoveryV1') {
                Assert-AstroFsvPersistedDeadOwnerRecoveryTerminalChain `
                    -Persisted $persisted.launcher_recovery_chain `
                    -Physical $launcherRecoveryChainFinal `
                    -Code 'ASTRO_FSV_PARTIAL_LOCK_RECORD_INVALID' `
                    -Description 'persisted launcher recovery chain'
            }
            else {
                Assert-AstroFsvPersistedNormalCleanupTerminalChain `
                    -Persisted $persisted.launcher_terminal_chain `
                    -Physical $launcherRecoveryChainFinal `
                    -Code 'ASTRO_FSV_PARTIAL_LOCK_RECORD_INVALID' `
                    -Description 'persisted launcher terminal chain'
            }
            Assert-AstroFsvPersistedAbsentJobProbe `
                $persisted.launcher_job.initial_probe $jobName `
                'ASTRO_FSV_PARTIAL_LOCK_RECORD_INVALID' `
                'persisted primary launcher initial probe'
            Assert-AstroFsvPersistedAbsentJobProbe `
                $persisted.launcher_job.final_probe $jobName `
                'ASTRO_FSV_PARTIAL_LOCK_RECORD_INVALID' `
                'persisted primary launcher final probe'
            $persistedTerminalJobProbes = if ($LauncherTerminalChainKind -ceq
                'NormalLiveOwnerCleanupV1') {
                $persisted.terminal_launcher_job_probes
            } else {
                $persisted.recovery_launcher_job_probes
            }
            Assert-AstroFsvPersistedRecoveryJobProbes `
                -Persisted $persistedTerminalJobProbes `
                -LauncherRecoveryChain $launcherRecoveryChainFinal `
                -Code 'ASTRO_FSV_PARTIAL_LOCK_RECORD_INVALID' `
                -Description 'persisted terminal-launcher'
            $persistedLockProcesses = Read-AstroFsvTerminalPartialPreLiveProcesses `
                -LockState $persisted.fsv_lock.state `
                -Code 'ASTRO_FSV_PARTIAL_LOCK_RECORD_INVALID' `
                -Description 'persisted embedded FSV-lock process set'
            $persistedLockLauncher = Read-AstroFsvProcessIdentity `
                $persisted.fsv_lock.state.owners.launcher `
                'ASTRO_FSV_PARTIAL_LOCK_RECORD_INVALID' `
                'persisted embedded FSV-lock launcher identity'
            $persistedLockRunner = Read-AstroFsvProcessIdentity `
                $persisted.fsv_lock.state.owners.runner `
                'ASTRO_FSV_PARTIAL_LOCK_RECORD_INVALID' `
                'persisted embedded FSV-lock runner identity'
            if ([string]$persisted.launcher_job.name -cne $jobName -or
                -not (Test-AstroFsvIdentityEqual `
                    $persistedLockLauncher $lockLauncher) -or
                -not (Test-AstroFsvIdentityEqual `
                    $persistedLockRunner $lockRunner) -or
                -not (Test-AstroFsvV3ProcessEntriesEqual `
                    $persistedLockProcesses $lockProcesses) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath(
                        [string]$persisted.fsv_lock.state.cohort_plan.path),
                    $cohortPlanPath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                [string]$persisted.fsv_lock.state.cohort_plan.sha256 -cne
                    [string]$lockState.cohort_plan.sha256) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_RECORD_INVALID' `
                    'persisted embedded FSV-lock provenance differs from physical lock bytes' `
                    'preserve the lock and transition; no archive authority was established'
            }
            $recordSha256 = [string]$transitionPublication.sha256
            if ((File-Sha256 $fsvLock) -cne $lockShaBefore) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_STATE_DRIFT' `
                    'FSV lock bytes changed after durable retirement publication' `
                    'preserve the lock and record and investigate the competing writer'
            }
            Move-AstroFileWriteThroughNoReplace `
                -Source $fsvLock -Destination $lockArchivePath
            if ((Test-AstroPathLongPath -LiteralPath $fsvLock) -or
                -not (Test-AstroPathLongPath -LiteralPath $lockArchivePath -PathType Leaf) -or
                (File-Sha256 $lockArchivePath) -cne $lockShaBefore) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_ARCHIVE_FAILED' `
                    'exact lock archive did not publish source-absence and byte-equality' `
                    'preserve authorization/archive state and inspect the exact filesystem transition'
            }
            $archiveBytes = [uint64](Get-AstroFileInfoLongPath $lockArchivePath).Length
            $completion = [ordered]@{
                schema = 'astrolabe.native-fsv-partial-lock-retirement.completion.v1'
                phase = 'complete-lock-archived-source-absent'
                issue = $Issue
                completed_at_utc = [DateTime]::UtcNow.ToString('o')
                authorization = [ordered]@{
                    path = $recoveryRecord; sha256 = $recordSha256
                }
                source = [ordered]@{
                    path = $fsvLock; state = 'absent'; prior_sha256 = $lockShaBefore
                }
                archive = [ordered]@{
                    path = $lockArchivePath
                    bytes = $archiveBytes
                    sha256 = File-Sha256 $lockArchivePath
                }
                session = [ordered]@{
                    path = $session
                    inventory_schema = [string]$sessionTree.schema
                    inventory_encoding = [string]$sessionTree.encoding
                    inventory_entry_count = [int]$sessionTree.entry_count
                    inventory_canonical_byte_count =
                        [uint64]$sessionTree.canonical_bytes_length
                    inventory_sha256 = [string]$sessionTree.sha256
                }
            }
            $completionPublication = Publish-NewAstroFsvProtocolRecord `
                -Path $completionRecordPath -Value $completion `
                -CodePrefix 'ASTRO_FSV_PARTIAL_LOCK_COMPLETION'
            $persistedCompletion = $completionPublication.value
            if ([string]$persistedCompletion.schema -cne
                    'astrolabe.native-fsv-partial-lock-retirement.completion.v1' -or
                [string]$persistedCompletion.phase -cne
                    'complete-lock-archived-source-absent' -or
                [int]$persistedCompletion.issue -ne $Issue -or
                [string]$persistedCompletion.authorization.sha256 -cne
                    $recordSha256 -or
                [string]$persistedCompletion.source.state -cne 'absent' -or
                [string]$persistedCompletion.source.prior_sha256 -cne
                    $lockShaBefore -or
                [uint64]$persistedCompletion.archive.bytes -ne $archiveBytes -or
                [string]$persistedCompletion.archive.sha256 -cne $lockShaBefore -or
                [string]$persistedCompletion.session.inventory_schema -cne
                    [string]$sessionTree.schema -or
                [string]$persistedCompletion.session.inventory_encoding -cne
                    [string]$sessionTree.encoding -or
                [int]$persistedCompletion.session.inventory_entry_count -ne
                    [int]$sessionTree.entry_count -or
                [uint64]$persistedCompletion.session.inventory_canonical_byte_count -ne
                    [uint64]$sessionTree.canonical_bytes_length -or
                [string]$persistedCompletion.session.inventory_sha256 -cne
                    [string]$sessionTree.sha256 -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$persistedCompletion.authorization.path),
                    $recoveryRecord,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$persistedCompletion.source.path),
                    $fsvLock,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$persistedCompletion.archive.path),
                    $lockArchivePath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$persistedCompletion.session.path),
                    $session,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                (Test-AstroPathLongPath -LiteralPath $fsvLock) -or
                (File-Sha256 $lockArchivePath) -cne $lockShaBefore) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_COMPLETION_INVALID' `
                    'persisted completion does not bind the archived exact lock and unchanged session' `
                    'preserve authorization/archive/completion bytes and investigate durable publication'
            }
            Move-AstroFileWriteThroughNoReplace `
                -Source $fsvLifecycleTransition -Destination $recoveryRecord
            if ((Test-AstroPathLongPath -LiteralPath $fsvLifecycleTransition) -or
                (File-Sha256 $recoveryRecord) -cne $recordSha256) {
                Fail-Astro 'ASTRO_FSV_PARTIAL_LOCK_AUTHORIZATION_ARCHIVE_FAILED' `
                    'canonical transition did not archive to the exact authorization record' `
                    'preserve transition/authorization/completion state and resume the same transaction'
            }
            $completionSha256 = File-Sha256 $completionRecordPath
            [ordered]@{
                operation = 'retire-terminal-partial-lock'
                authorization_path = $recoveryRecord
                authorization_sha256 = $recordSha256
                completion_path = $completionRecordPath
                completion_sha256 = $completionSha256
                authorization = $persisted
                completion = $persistedCompletion
                before = [ordered]@{
                    fsv_lock = $fsvLock; exists = $true; sha256 = $lockShaBefore
                }
                after = [ordered]@{
                    fsv_lock = $fsvLock
                    exists = $false
                    archive_path = $lockArchivePath
                    archive_sha256 = $lockShaBefore
                }
            } | ConvertTo-Json -Depth 30 -Compress | Write-Output
            }
            finally {
                try { Exit-AstroLauncherLockMutex $launcherCoordinationMutex }
                finally { Exit-AstroFsvLifecycleMutex $fsvLifecycleMutex }
            }
        }
        'RetireInterruptedV2Lock' {
            if ($Issue -le 0) {
                Fail-Astro 'ASTRO_FSV_INTERRUPTED_V2_ISSUE_INVALID' `
                    'Issue must be positive for interrupted-v2 lock retirement' `
                    'pass the exact issue bound by the staged artifact and FSV lock'
            }
            if ([string]::IsNullOrWhiteSpace($TrackerCommentUrl)) {
                Fail-Astro 'ASTRO_FSV_INTERRUPTED_V2_TRACKER_REQUIRED' `
                    'TrackerCommentUrl is required for interrupted-v2 lock retirement' `
                    'post a fresh owner-authored comment binding every physical path and hash'
            }
            if ($ReasonCode -notmatch '^[A-Z][A-Z0-9_]{2,95}$' -or
                [string]::IsNullOrWhiteSpace($ReasonMessage)) {
                Fail-Astro 'ASTRO_FSV_INTERRUPTED_V2_REASON_INVALID' `
                    'RetireInterruptedV2Lock requires a structured code and nonblank message' `
                    'describe the exact interruption that prevented terminal run publication'
            }
            if ([string]::IsNullOrWhiteSpace($RecoveryRecordPath) -or
                [string]::IsNullOrWhiteSpace($ReceiptPath) -or
                [string]::IsNullOrWhiteSpace($LiveStatePath) -or
                [string]::IsNullOrWhiteSpace($RunRecordPath) -or
                [string]::IsNullOrWhiteSpace($StandardOutputPath) -or
                [string]::IsNullOrWhiteSpace($StandardErrorPath) -or
                [string]::IsNullOrWhiteSpace($LauncherRecoveryCompletionPath) -or
                [string]::IsNullOrWhiteSpace($TargetRecoveryCompletionPath) -or
                $LauncherArchiveCompletionPaths.Count -eq 0) {
                Fail-Astro 'ASTRO_FSV_INTERRUPTED_V2_PATH_REQUIRED' `
                    'session paths and the complete dead-owner launcher recovery chain are required' `
                    'bind every member of the exact interrupted-v2 physical state'
            }
            $fsvLifecycleMutex = Enter-AstroFsvLifecycleMutex -WorkspaceRoot $workspace
            if (-not $fsvLifecycleMutex.Acquired) {
                Exit-AstroFsvLifecycleMutex $fsvLifecycleMutex
                Fail-Astro 'ASTRO_FSV_LIFECYCLE_MUTEX_HELD' `
                    "native-FSV lifecycle mutex is held: $($fsvLifecycleMutex.Name)" `
                    'wait for the exact active claim/recovery transaction to publish durable state'
            }
            $launcherCoordinationMutex = Enter-AstroLauncherLockMutex `
                -LockPath $launcherLockPath
            if (-not $launcherCoordinationMutex.Acquired) {
                $mutexName = [string]$launcherCoordinationMutex.Name
                Exit-AstroLauncherLockMutex $launcherCoordinationMutex
                Exit-AstroFsvLifecycleMutex $fsvLifecycleMutex
                Fail-Astro 'ASTRO_FSV_LAUNCHER_MUTEX_HELD' `
                    "launcher-lock coordination mutex is held: $mutexName" `
                    'wait for launcher coordination to finish, then resume the exact transaction'
            }
            try {
                $authorizationPath = Assert-PathWithin `
                    $RecoveryRecordPath $recoveryRoot `
                    'ASTRO_FSV_INTERRUPTED_V2_RECORD_ESCAPE' `
                    'interrupted-v2 retirement authorization path'
                $lockArchivePath = $authorizationPath + '.lock.bin'
                $completionRecordPath = $authorizationPath + '.completed.json'
                if ((Test-AstroPathLongPath -LiteralPath $fsvLifecycleTransition) -or
                    (Test-AstroPathLongPath -LiteralPath $authorizationPath) -or
                    (Test-AstroPathLongPath -LiteralPath $lockArchivePath) -or
                    (Test-AstroPathLongPath -LiteralPath $completionRecordPath)) {
                    $resumeResult = Invoke-AstroFsvInterruptedV2LockRetirementResume `
                        -ExpectedIssue $Issue -Workspace $workspace `
                        -EvidenceRoot $evidenceRoot -RecoveryRoot $recoveryRoot `
                        -FsvLockPath $fsvLock `
                        -LifecycleTransitionPath $fsvLifecycleTransition `
                        -ReceiptInputPath $ReceiptPath `
                        -RecoveryInputPath $RecoveryRecordPath `
                        -StandardOutputInputPath $StandardOutputPath `
                        -StandardErrorInputPath $StandardErrorPath `
                        -RunRecordInputPath $RunRecordPath `
                        -LiveStateInputPath $LiveStatePath `
                        -TrackerUrl $TrackerCommentUrl `
                        -FailureCode $ReasonCode -FailureMessage $ReasonMessage `
                        -LauncherRecoveryInputPath $LauncherRecoveryCompletionPath `
                        -TargetRecoveryInputPath $TargetRecoveryCompletionPath `
                        -ArchiveCompletionInputPaths $LauncherArchiveCompletionPaths
                    $resumeResult | ConvertTo-Json -Depth 40 -Compress | Write-Output
                    return
                }
                $launcherChain = Read-AstroFsvLauncherRecoveryChain `
                    -ExpectedIssue $Issue -Workspace $workspace `
                    -LauncherRecoveryPath $LauncherRecoveryCompletionPath `
                    -TargetRecoveryPath $TargetRecoveryCompletionPath `
                    -ArchiveCompletionPaths $LauncherArchiveCompletionPaths
                $launcherProtocol = Read-AstroLauncherLock -LockPath $launcherLockPath
                if ($launcherProtocol.State -ne 'absent') {
                    Fail-Astro 'ASTRO_FSV_INTERRUPTED_V2_LAUNCHER_LOCK' `
                        "launcher protocol is '$($launcherProtocol.State)'" `
                        'complete the exact launcher lifecycle before retiring the FSV lock'
                }
                if (-not (Test-AstroPathLongPath -LiteralPath $fsvLock -PathType Leaf)) {
                    Fail-Astro 'ASTRO_FSV_INTERRUPTED_V2_LOCK_ABSENT' `
                        "FSV lock is already absent: $fsvLock" `
                        'do not manufacture interrupted-v2 evidence for an absent lock'
                }
                Assert-NotReparseEntry $fsvLock 'interrupted v2 native-FSV lock'
                $lockSha256 = File-Sha256 $fsvLock
                try { $lockState = Read-AstroUtf8FileLongPath $fsvLock | ConvertFrom-Json }
                catch {
                    Fail-Astro 'ASTRO_FSV_INTERRUPTED_V2_LOCK_INVALID' `
                        "FSV lock is unreadable: $($_.Exception.Message)" `
                        'preserve the exact lock bytes and investigate its publisher'
                }
                $state = Read-AstroFsvInterruptedV2PhysicalState `
                    -ExpectedIssue $Issue -EvidenceRoot $evidenceRoot `
                    -ReceiptInputPath $ReceiptPath -LockState $lockState `
                    -LockSha256 $lockSha256 -LiveStateInputPath $LiveStatePath `
                    -StandardOutputInputPath $StandardOutputPath `
                    -StandardErrorInputPath $StandardErrorPath `
                    -RunRecordInputPath $RunRecordPath `
                    -LauncherRecoveryChain $launcherChain
                $initialOwnerProbes = @(Assert-AstroFsvOwnersInactive `
                        -Bindings $state.owner_bindings `
                        -CodePrefix 'ASTRO_FSV_INTERRUPTED_V2' `
                        -Description 'interrupted-v2 lock retirement')
                $jobProbeFirst = Get-AstroLauncherJobObjectProbe `
                    -Name $state.launcher_job_name
                if ($jobProbeFirst.State -cne 'absent') {
                    Fail-Astro 'ASTRO_FSV_INTERRUPTED_V2_JOB_PRESENT' `
                        "deterministic launcher Job is '$($jobProbeFirst.State)'" `
                        'preserve every byte until the exact Job is absent'
                }
                $recoveryJobProbesFirst = [Collections.Generic.List[object]]::new()
                foreach ($archive in $launcherChain.archives) {
                    $probe = Get-AstroLauncherJobObjectProbe `
                        -Name ([string]$archive.job_name)
                    if ($probe.State -cne 'absent') {
                        Fail-Astro 'ASTRO_FSV_INTERRUPTED_V2_JOB_PRESENT' `
                            "recovery-chain Job '$($archive.job_name)' is '$($probe.State)'" `
                            'preserve every byte until every exact launcher Job is absent'
                    }
                    $recoveryJobProbesFirst.Add($probe)
                }
                $archivePaths = @($LauncherArchiveCompletionPaths | ForEach-Object {
                        [IO.Path]::GetFullPath($_)
                    })
                $archiveHashes = @($archivePaths | ForEach-Object { File-Sha256 $_ })
                $tracker = Read-AstroFsvInterruptedV2LockTrackerEvidence `
                    -Url $TrackerCommentUrl -ExpectedIssue $Issue `
                    -ExpectedLockPath $fsvLock -ExpectedLockSha256 $lockSha256 `
                    -ExpectedReceiptPath $state.receipt_state.Path `
                    -ExpectedReceiptSha256 $state.receipt_sha256 `
                    -ExpectedArtifactPath $state.inspection.artifact_path `
                    -ExpectedArtifactSha256 $state.inspection.sha256 `
                    -ExpectedSessionDirectory $state.session_directory `
                    -ExpectedLiveStatePath $state.live_state_path `
                    -ExpectedLiveStateSha256 $state.live_state_sha256 `
                    -ExpectedStandardOutputPath $state.stdout_path `
                    -ExpectedStandardOutputSha256 $state.stdout_sha256 `
                    -ExpectedStandardErrorPath $state.stderr_path `
                    -ExpectedStandardErrorSha256 $state.stderr_sha256 `
                    -ExpectedRunRecordPath $state.run_record_path `
                    -ExpectedInventorySchema $state.session_tree.schema `
                    -ExpectedInventoryEncoding $state.session_tree.encoding `
                    -ExpectedInventoryEntryCount ([int]$state.session_tree.entry_count) `
                    -ExpectedInventoryCanonicalByteCount `
                        ([uint64]$state.session_tree.canonical_bytes_length) `
                    -ExpectedInventorySha256 $state.session_tree.sha256 `
                    -ExpectedLauncherIdentity $state.lock_launcher `
                    -ExpectedRunnerIdentity $state.lock_runner `
                    -ExpectedChildIdentity $state.lock_child `
                    -ExpectedLauncherJobName $state.launcher_job_name `
                    -ExpectedRecoveryRecordPath $authorizationPath `
                    -ExpectedLockArchivePath $lockArchivePath `
                    -ExpectedCompletionRecordPath $completionRecordPath `
                    -ExpectedLifecycleTransitionPath $fsvLifecycleTransition `
                    -ExpectedLauncherRecoveryCompletionPath `
                        $LauncherRecoveryCompletionPath `
                    -ExpectedLauncherRecoveryCompletionSha256 `
                        (File-Sha256 $LauncherRecoveryCompletionPath) `
                    -ExpectedTargetRecoveryCompletionPath `
                        $TargetRecoveryCompletionPath `
                    -ExpectedTargetRecoveryCompletionSha256 `
                        (File-Sha256 $TargetRecoveryCompletionPath) `
                    -ExpectedLauncherArchiveCompletionPaths $archivePaths `
                    -ExpectedLauncherArchiveCompletionSha256s $archiveHashes `
                    -ExpectedReasonCode $ReasonCode

                $launcherChainFinal = Read-AstroFsvLauncherRecoveryChain `
                    -ExpectedIssue $Issue -Workspace $workspace `
                    -LauncherRecoveryPath $LauncherRecoveryCompletionPath `
                    -TargetRecoveryPath $TargetRecoveryCompletionPath `
                    -ArchiveCompletionPaths $LauncherArchiveCompletionPaths
                $launcherProtocolFinal = Read-AstroLauncherLock -LockPath $launcherLockPath
                if ($launcherProtocolFinal.State -ne 'absent' -or
                    (File-Sha256 $fsvLock) -cne $lockSha256) {
                    Fail-Astro 'ASTRO_FSV_INTERRUPTED_V2_STATE_DRIFT' `
                        'launcher protocol or source lock changed before final authorization' `
                        'preserve every byte and investigate the competing generation'
                }
                $stateFinal = Read-AstroFsvInterruptedV2PhysicalState `
                    -ExpectedIssue $Issue -EvidenceRoot $evidenceRoot `
                    -ReceiptInputPath $ReceiptPath -LockState $lockState `
                    -LockSha256 $lockSha256 -LiveStateInputPath $LiveStatePath `
                    -StandardOutputInputPath $StandardOutputPath `
                    -StandardErrorInputPath $StandardErrorPath `
                    -RunRecordInputPath $RunRecordPath `
                    -LauncherRecoveryChain $launcherChainFinal
                if ([string]$stateFinal.session_tree.sha256 -cne
                    [string]$state.session_tree.sha256) {
                    Fail-Astro 'ASTRO_FSV_INTERRUPTED_V2_STATE_DRIFT' `
                        'session inventory changed before final authorization' `
                        'preserve every byte and investigate the competing writer'
                }
                $finalOwnerProbes = @(Assert-AstroFsvOwnersInactive `
                        -Bindings $stateFinal.owner_bindings `
                        -CodePrefix 'ASTRO_FSV_INTERRUPTED_V2' `
                        -Description 'interrupted-v2 final authorization')
                $jobProbeSecond = Get-AstroLauncherJobObjectProbe `
                    -Name $stateFinal.launcher_job_name
                if ($jobProbeSecond.State -cne 'absent') {
                    Fail-Astro 'ASTRO_FSV_INTERRUPTED_V2_JOB_PRESENT' `
                        "deterministic launcher Job became '$($jobProbeSecond.State)'" `
                        'preserve every byte and investigate generation reappearance'
                }
                $recoveryJobProbesSecond = [Collections.Generic.List[object]]::new()
                foreach ($archive in $launcherChainFinal.archives) {
                    $probe = Get-AstroLauncherJobObjectProbe `
                        -Name ([string]$archive.job_name)
                    if ($probe.State -cne 'absent') {
                        Fail-Astro 'ASTRO_FSV_INTERRUPTED_V2_JOB_PRESENT' `
                            "recovery-chain Job '$($archive.job_name)' became '$($probe.State)'" `
                            'preserve every byte and investigate generation reappearance'
                    }
                    $recoveryJobProbesSecond.Add($probe)
                }
                Assert-NotReparseEntry $recoveryRoot 'native-FSV recovery root'
                $recordParent = Split-Path -Parent $authorizationPath
                New-AstroDirectoryLongPath $recordParent | Out-Null
                Assert-NotReparseEntry $recordParent 'interrupted-v2 record parent'
                $currentRepository = Get-RepoState -GitExe $gitExe -Workspace $workspace
                $authorization = [ordered]@{
                    schema = 'astrolabe.native-fsv-interrupted-v2-lock-retirement.authorization.v1'
                    phase = 'authorized-exact-interrupted-v2-lock'
                    issue = $Issue
                    authorized_at_utc = [DateTime]::UtcNow.ToString('o')
                    tracker = [ordered]@{
                        url = $TrackerCommentUrl
                        comment_id = [long]$tracker.comment_id
                        author = [string]$tracker.author
                        created_at = [string]$tracker.created_at
                    }
                    authorization_record_path = $authorizationPath
                    completion_record_path = $completionRecordPath
                    lifecycle_transition_path = $fsvLifecycleTransition
                    fsv_lock = [ordered]@{
                        path = $fsvLock; sha256 = $lockSha256
                        archive_path = $lockArchivePath; state = $lockState
                    }
                    receipt_path = $state.receipt_state.Path
                    receipt_sha256 = $state.receipt_sha256
                    session_directory = $state.session_directory
                    artifact = [ordered]@{
                        path = $state.inspection.artifact_path
                        bytes = [uint64]$state.inspection.bytes
                        sha256 = $state.inspection.sha256
                    }
                    expected_controls = [ordered]@{
                        run_record_path = $state.run_record_path
                        run_record_state = 'absent'
                    }
                    live_state = [ordered]@{
                        path = $state.live_state_path; state = 'present'
                        sha256 = $state.live_state_sha256
                    }
                    outputs = [ordered]@{
                        stdout = [ordered]@{
                            path = $state.stdout_path; sha256 = $state.stdout_sha256
                            bytes = [uint64](Get-AstroFileInfoLongPath $state.stdout_path).Length
                        }
                        stderr = [ordered]@{
                            path = $state.stderr_path; sha256 = $state.stderr_sha256
                            bytes = [uint64](Get-AstroFileInfoLongPath $state.stderr_path).Length
                        }
                    }
                    session_inventory = [ordered]@{
                        schema = [string]$state.session_tree.schema
                        encoding = [string]$state.session_tree.encoding
                        entry_count = [int]$state.session_tree.entry_count
                        canonical_bytes_length =
                            [uint64]$state.session_tree.canonical_bytes_length
                        sha256 = [string]$state.session_tree.sha256
                        files = $state.session_files
                        entries = [object[]]$state.session_tree.entries
                    }
                    launcher_protocol_state = $launcherProtocolFinal.State
                    launcher_job = [ordered]@{
                        name = $state.launcher_job_name
                        initial_probe = $jobProbeFirst; final_probe = $jobProbeSecond
                    }
                    launcher_recovery_chain = [ordered]@{
                        launcher_recovery_completion = [ordered]@{
                            path = [string]$launcherChainFinal.launcher_recovery.path
                            sha256 = [string]$launcherChainFinal.launcher_recovery.sha256
                        }
                        target_recovery_completion = [ordered]@{
                            path = [string]$launcherChainFinal.target_recovery.path
                            sha256 = [string]$launcherChainFinal.target_recovery.sha256
                        }
                        launcher_archive_completions = @(
                            foreach ($archivePath in $archivePaths) {
                                [ordered]@{
                                    path = $archivePath; sha256 = File-Sha256 $archivePath
                                }
                            }
                        )
                    }
                    recovery_launcher_job_probes = [ordered]@{
                        initial = [object[]]$recoveryJobProbesFirst.ToArray()
                        final = [object[]]$recoveryJobProbesSecond.ToArray()
                    }
                    staged_repository = $state.receipt_state.Receipt.repository
                    current_repository = $currentRepository
                    owners = [ordered]@{
                        identities = @($state.owner_bindings | ForEach-Object {
                                [ordered]@{
                                    role = $_.Role; source = $_.Source; identity = $_.Identity
                                }
                            })
                        initial_probes = $initialOwnerProbes
                        final_probes = $finalOwnerProbes
                    }
                    failure = [ordered]@{
                        code = $ReasonCode; message = $ReasonMessage
                    }
                }
                $publication = Publish-NewAstroFsvProtocolRecord `
                    -Path $fsvLifecycleTransition -Value $authorization `
                    -CodePrefix 'ASTRO_FSV_INTERRUPTED_V2_AUTHORIZATION' `
                    -StageDirectory $recordParent
                if ([string]$publication.value.fsv_lock.sha256 -cne $lockSha256 -or
                    [string]$publication.value.session_inventory.sha256 -cne
                        [string]$state.session_tree.sha256) {
                    Fail-Astro 'ASTRO_FSV_INTERRUPTED_V2_RECORD_INVALID' `
                        'published authorization differs from physical source state' `
                        'preserve transition and source lock; investigate durable publication'
                }
                $result = Invoke-AstroFsvInterruptedV2LockRetirementResume `
                    -ExpectedIssue $Issue -Workspace $workspace `
                    -EvidenceRoot $evidenceRoot -RecoveryRoot $recoveryRoot `
                    -FsvLockPath $fsvLock `
                    -LifecycleTransitionPath $fsvLifecycleTransition `
                    -ReceiptInputPath $ReceiptPath `
                    -RecoveryInputPath $RecoveryRecordPath `
                    -StandardOutputInputPath $StandardOutputPath `
                    -StandardErrorInputPath $StandardErrorPath `
                    -RunRecordInputPath $RunRecordPath `
                    -LiveStateInputPath $LiveStatePath `
                    -TrackerUrl $TrackerCommentUrl `
                    -FailureCode $ReasonCode -FailureMessage $ReasonMessage `
                    -LauncherRecoveryInputPath $LauncherRecoveryCompletionPath `
                    -TargetRecoveryInputPath $TargetRecoveryCompletionPath `
                    -ArchiveCompletionInputPaths $LauncherArchiveCompletionPaths
                $result | ConvertTo-Json -Depth 40 -Compress | Write-Output
            }
            finally {
                try { Exit-AstroLauncherLockMutex $launcherCoordinationMutex }
                finally { Exit-AstroFsvLifecycleMutex $fsvLifecycleMutex }
            }
        }
        'RetireLock' {
            if ($Issue -le 0) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_ISSUE_INVALID' `
                    'Issue must be positive for stale FSV lock retirement' `
                    'pass the driving GitHub issue number'
            }
            if ([string]::IsNullOrWhiteSpace($TrackerCommentUrl)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_TRACKER_REQUIRED' `
                    'TrackerCommentUrl is required for stale FSV lock retirement' `
                    'post a GitHub issue comment binding the exact lock/run/session state before mutation'
            }
            if ($ReasonCode -notmatch '^[A-Z][A-Z0-9_]{2,95}$') {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_REASON_INVALID' `
                    "ReasonCode is not a structured upper-case code: '$ReasonCode'" `
                    'pass the exact stable failure code that left the stale FSV lock'
            }
            if ([string]::IsNullOrWhiteSpace($ReasonMessage)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_REASON_INVALID' `
                    'ReasonMessage is required and may not be blank' `
                    'describe the exact stale-lock condition being retired'
            }
            if ([string]::IsNullOrWhiteSpace($RecoveryRecordPath)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_RECORD_REQUIRED' `
                    'RecoveryRecordPath is required for RetireLock' `
                    "use a fresh JSON path below $recoveryRoot; the record persists after exact lock removal"
            }
            if ([string]::IsNullOrWhiteSpace($RunRecordPath)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_REQUIRED' `
                    'RunRecordPath is required for RetireLock' `
                    'pass the exact run record written by native-fsv-run.ps1'
            }
            if ([string]::IsNullOrWhiteSpace($LiveStatePath)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_LIVE_STATE_REQUIRED' `
                    'LiveStatePath is required for RetireLock' `
                    'pass the exact live-state record written by native-fsv-run.ps1'
            }
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            $launcherProtocolState =
                Read-AstroLauncherLock -LockPath $launcherLockPath
            if ($launcherProtocolState.State -ne 'absent') {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_LAUNCHER_LOCK' `
                    "launcher protocol is '$($launcherProtocolState.State)'; stale-lock retirement requires authoritative absence (transitions=$(@($launcherProtocolState.TransitionPaths) -join '; '), read_error=$($launcherProtocolState.ReadError), validation_error=$($launcherProtocolState.ValidationError))" `
                    'wait for the exact launcher generation to finish or recover it through the launcher protocol before retiring the FSV lock'
            }
            if (-not (Test-AstroPathLongPath -LiteralPath $fsvLock -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_ABSENT' `
                    "FSV lock is already absent: $fsvLock" `
                    'do not manufacture retirement evidence for an absent lock'
            }
            Assert-NotReparseEntry $fsvLock 'native FSV lock'
            $lockShaBefore = File-Sha256 $fsvLock
            try {
                $lockState = Read-AstroUtf8FileLongPath $fsvLock | ConvertFrom-Json
            }
            catch {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_INVALID_LOCK' `
                    "FSV lock is unreadable: ${fsvLock}: $($_.Exception.Message)" `
                    'preserve the lock and investigate its exact bytes'
            }
            $lockSchemaSupported = [string]$lockState.schema -in @(
                'astrolabe.native-fsv-lock.v2',
                'astrolabe.native-fsv-lock.v3'
            )
            if (-not $lockSchemaSupported -or
                [int]$lockState.issue -ne [int]$inspection.issue -or
                [string]$lockState.tree_sha -cne [string]$inspection.tree_sha -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$lockState.artifact_path), $inspection.artifact_path, [StringComparison]::OrdinalIgnoreCase) -or
                [string]$lockState.artifact_sha256 -cne [string]$inspection.sha256 -or
                -not $lockState.PSObject.Properties['owners'] -or
                -not $lockState.owners.PSObject.Properties['launcher'] -or
                -not $lockState.owners.PSObject.Properties['runner']) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_INVALID_LOCK' `
                    "FSV lock is not bound to the selected issue/tree/artifact: $fsvLock" `
                    'preserve the lock and session; retry with the exact receipt/run/live-state binding'
            }
            $lockLauncher = Read-AstroFsvProcessIdentity $lockState.owners.launcher `
                'ASTRO_FSV_LOCK_RETIRE_INVALID_LOCK' 'FSV lock launcher identity'
            $lockRunner = Read-AstroFsvProcessIdentity $lockState.owners.runner `
                'ASTRO_FSV_LOCK_RETIRE_INVALID_LOCK' 'FSV lock runner identity'
            $lockChild = $null
            $lockProcesses = [object[]]@()
            $lockResidentCount = 0
            $lockProcessCount = 0
            if ([string]$lockState.schema -ceq 'astrolabe.native-fsv-lock.v2') {
                if (-not $lockState.owners.PSObject.Properties['child']) {
                    Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_INVALID_LOCK' `
                        'v2 FSV lock omits its child identity' `
                        'preserve the lock/session and investigate incomplete ownership state'
                }
                $lockChild = Read-AstroFsvProcessIdentity $lockState.owners.child `
                    'ASTRO_FSV_LOCK_RETIRE_INVALID_LOCK' 'FSV lock child identity'
            }
            else {
                if (-not $lockState.PSObject.Properties['resident_count'] -or
                    -not $lockState.PSObject.Properties['process_count'] -or
                    -not $lockState.owners.PSObject.Properties['processes']) {
                    Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_INVALID_LOCK' `
                        'v3 FSV lock omits resident/process cardinality' `
                        'preserve the lock/session and investigate incomplete ownership state'
                }
                $lockResidentCount = [int]$lockState.resident_count
                $lockProcessCount = [int]$lockState.process_count
                $lockProcesses = Read-AstroFsvV3ProcessEntries `
                    $lockState.owners.processes $lockResidentCount $lockProcessCount `
                    'ASTRO_FSV_LOCK_RETIRE_INVALID_LOCK' 'v3 FSV-lock process set'
            }
            $runRecord = Assert-PathWithin $RunRecordPath $inspection.session_directory `
                'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_ESCAPE' 'run record path'
            if (-not (Test-AstroPathLongPath -LiteralPath $runRecord -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_MISSING' `
                    "run record does not exist: $runRecord" `
                    'preserve the lock and session; retry only with a completed run record'
            }
            try {
                $record = Read-AstroUtf8FileLongPath $runRecord | ConvertFrom-Json
            }
            catch {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_INVALID' `
                    "parse run record '$runRecord' failed: $($_.Exception.Message)" `
                    'preserve the lock and session; investigate the incomplete run'
            }
            if ($record.schema -notin @(
                    'astrolabe.native-fsv-run.v2',
                    'astrolabe.native-fsv-run.v3'
                ) -or
                [int]$record.issue -ne [int]$inspection.issue -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$record.receipt_path), $receiptState.Path, [StringComparison]::OrdinalIgnoreCase) -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$record.artifact.path), $inspection.artifact_path, [StringComparison]::OrdinalIgnoreCase) -or
                [string]$record.artifact.sha256 -cne [string]$inspection.sha256) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_INVALID' `
                    "run record '$runRecord' is not bound to the selected receipt/artifact" `
                    'preserve the lock and session; retry with the exact completed run record'
            }
            $explicitLiveState = Assert-PathWithin $LiveStatePath $inspection.session_directory `
                'ASTRO_FSV_LOCK_RETIRE_LIVE_STATE_ESCAPE' 'live-state path'
            if (-not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$record.live_state.path),
                    $explicitLiveState,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_LIVE_STATE_MISMATCH' `
                    "explicit live-state path does not match run-record binding: $explicitLiveState" `
                    'preserve the lock and session; pass the exact live-state path named by the run record'
            }
            $sessionBindings = @(
                Get-AstroFsvSessionOwnerBindings `
                    -ReceiptState $receiptState `
                    -Inspection $inspection `
                    -RunRecordPath $runRecord `
                    -RunRecord $record
            )
            $runRunner = Read-AstroFsvProcessIdentity $record.runner `
                'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_INVALID' 'run-record runner identity'
            if (-not (Test-AstroFsvIdentityEqual $lockLauncher $inspection.owners.launcher) -or
                -not (Test-AstroFsvIdentityEqual $lockRunner $runRunner)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_OWNER_MISMATCH' `
                    'FSV lock owner generations differ from the selected receipt/run/live-state records' `
                    'preserve the lock and session; retry with the exact bound artifacts'
            }
            $ownerBindings = New-Object System.Collections.Generic.List[object]
            foreach ($binding in $sessionBindings) { $ownerBindings.Add($binding) }
            $ownerBindings.Add((New-AstroFsvOwnerBinding 'launcher' $fsvLock $lockLauncher))
            $ownerBindings.Add((New-AstroFsvOwnerBinding 'runner' $fsvLock $lockRunner))
            if ([string]$lockState.schema -ceq 'astrolabe.native-fsv-lock.v2') {
                if ([string]$record.schema -cne 'astrolabe.native-fsv-run.v2') {
                    Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_OWNER_MISMATCH' `
                        'v2 FSV lock is paired with a non-v2 run record' `
                        'preserve the lock/session and pass the exact bound lifecycle records'
                }
                $runChild = Read-AstroFsvProcessIdentity $record.process.identity `
                    'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_INVALID' `
                    'run-record child identity'
                if (-not (Test-AstroFsvIdentityEqual $lockChild $runChild)) {
                    Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_OWNER_MISMATCH' `
                        'v2 FSV-lock child generation differs from its run record' `
                        'preserve the lock/session and pass the exact bound lifecycle records'
                }
                $ownerBindings.Add((New-AstroFsvOwnerBinding `
                            'child' $fsvLock $lockChild))
            }
            else {
                if ([string]$record.schema -cne 'astrolabe.native-fsv-run.v3' -or
                    [int]$record.resident_count -ne $lockResidentCount -or
                    [int]$record.process_count -ne $lockProcessCount) {
                    Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_OWNER_MISMATCH' `
                        'v3 FSV-lock cardinality differs from its run record' `
                        'preserve the lock/session and pass the exact bound lifecycle records'
                }
                $runProcesses = Read-AstroFsvV3ProcessEntries `
                    $record.processes $lockResidentCount $lockProcessCount `
                    'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_INVALID' `
                    'v3 run-record process set'
                if (-not (Test-AstroFsvV3ProcessEntriesEqual `
                        $lockProcesses $runProcesses)) {
                    Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_OWNER_MISMATCH' `
                        'v3 FSV-lock process generations differ from its run record' `
                        'preserve the lock/session and pass the exact bound lifecycle records'
                }
                Add-AstroFsvV3ProcessBindings $ownerBindings $lockProcesses $fsvLock
            }
            $initialOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings ([object[]]$ownerBindings.ToArray()) `
                    -CodePrefix 'ASTRO_FSV_LOCK_RETIRE' `
                    -Description 'stale FSV lock retirement'
            )
            $recoveryRecord = Assert-PathWithin $RecoveryRecordPath $recoveryRoot `
                'ASTRO_FSV_LOCK_RETIRE_RECORD_ESCAPE' 'retirement record path'
            if (Test-AstroPathLongPath -LiteralPath $recoveryRecord) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_RECORD_REUSE_REFUSED' `
                    "retirement record already exists: $recoveryRecord" `
                    'use one fresh append-only recovery record path for each stale lock retirement'
            }
            Assert-NotReparseEntry $recoveryRoot 'recovery record root'
            $recordParent = Split-Path -Parent $recoveryRecord
            New-AstroDirectoryLongPath $recordParent | Out-Null
            Assert-NotReparseEntry $recordParent 'retirement record parent'
            $currentRepository = Get-RepoState -GitExe $gitExe -Workspace $workspace
            $finalOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings ([object[]]$ownerBindings.ToArray()) `
                    -CodePrefix 'ASTRO_FSV_LOCK_RETIRE' `
                    -Description 'stale FSV lock retirement final authorization'
            )
            $retirement = [ordered]@{
                schema = 'astrolabe.native-fsv-lock-retirement.v1'
                verdict = 'retired-stale-lock'
                issue = [int]$inspection.issue
                recorded_at_utc = [DateTime]::UtcNow.ToString('o')
                tracker_comment_url = $TrackerCommentUrl
                fsv_lock = [ordered]@{
                    path = $fsvLock
                    sha256 = $lockShaBefore
                    state = $lockState
                }
                receipt_path = $receiptState.Path
                session_directory = $inspection.session_directory
                run_record_path = $runRecord
                run_record_sha256 = File-Sha256 $runRecord
                live_state_path = $explicitLiveState
                live_state_sha256 = File-Sha256 $explicitLiveState
                artifact = [ordered]@{
                    path = $inspection.artifact_path
                    bytes = [uint64]$inspection.bytes
                    sha256 = $inspection.sha256
                }
                launcher_protocol_state = $launcherProtocolState.State
                staged_repository = $receiptState.Receipt.repository
                current_repository = $currentRepository
                owners = [ordered]@{
                    identities = @($ownerBindings.ToArray() | ForEach-Object {
                            [ordered]@{
                                role = $_.Role
                                source = $_.Source
                                identity = $_.Identity
                            }
                        })
                    initial_probes = $initialOwnerProbes
                    final_probes = $finalOwnerProbes
                }
                failure = [ordered]@{
                    code = $ReasonCode
                    message = $ReasonMessage
                }
            }
            Write-NewDurableUtf8 $recoveryRecord ($retirement | ConvertTo-Json -Depth 24)
            $persistedRetirement =
                Read-AstroUtf8FileLongPath $recoveryRecord | ConvertFrom-Json
            if ($persistedRetirement.schema -ne 'astrolabe.native-fsv-lock-retirement.v1' -or
                [string]$persistedRetirement.fsv_lock.sha256 -cne $lockShaBefore -or
                [string]$persistedRetirement.artifact.sha256 -cne [string]$inspection.sha256 -or
                [string]$persistedRetirement.failure.code -cne $ReasonCode) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_RECORD_INVALID' `
                    "persisted retirement record readback does not bind the stale lock: $recoveryRecord" `
                    'preserve both lock and record and investigate the durable-write mismatch'
            }
            Assert-AstroFsvPersistedOwnerEnvelope `
                -Owners $persistedRetirement.owners `
                -ExpectedBindings ([object[]]$ownerBindings.ToArray()) `
                -Code 'ASTRO_FSV_LOCK_RETIRE_RECORD_INVALID' `
                -Description 'persisted stale-lock retirement record'
            Remove-AstroFileLongPath $fsvLock
            if (Test-AstroPathLongPath -LiteralPath $fsvLock) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_DELETE_FAILED' `
                    "FSV lock remains after exact retirement delete: $fsvLock" `
                    'preserve the recovery record and inspect open handles before retrying'
            }
            [ordered]@{
                operation = 'retire-lock'
                record_path = $recoveryRecord
                record_sha256 = File-Sha256 $recoveryRecord
                record = $persistedRetirement
                before = [ordered]@{
                    fsv_lock = $fsvLock
                    exists = $true
                    sha256 = $lockShaBefore
                    owners = $retirement.owners
                }
                after = [ordered]@{ fsv_lock = $fsvLock; exists = $false }
            } | ConvertTo-Json -Depth 26 -Compress | Write-Output
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
            if (Test-AstroPathLongPath -LiteralPath $abandonRecord) {
                Fail-Astro 'ASTRO_FSV_ABANDON_RECORD_REUSE_REFUSED' "abandonment record already exists: $abandonRecord" `
                    'use one fresh append-only record path for each never-run evidence session'
            }
            $receipt = $receiptState.Receipt
            $ownerBindings = @(
                New-AstroFsvOwnerBinding `
                    'launcher' 'artifact receipt' $inspection.owners.launcher
                New-AstroFsvOwnerBinding `
                    'promoter' 'artifact receipt' $inspection.owners.promoter
            )
            $initialOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_ABANDON' `
                    -Description 'never-run evidence session'
            )
            $session = [IO.Path]::GetFullPath($inspection.session_directory)
            $allowedEntries = @(
                [IO.Path]::GetFullPath($receiptState.Path),
                [IO.Path]::GetFullPath($inspection.artifact_path)
            )
            $sessionEntries = @(Get-AstroDirectoryEntriesLongPath $session)
            $unexpectedEntries = @($sessionEntries | Where-Object {
                $full = [IO.Path]::GetFullPath($_.FullName)
                -not ($allowedEntries -contains $full)
            } | ForEach-Object { $_.FullName })
            if ($unexpectedEntries.Count -gt 0 -or $sessionEntries.Count -ne 2) {
                Fail-Astro 'ASTRO_FSV_ABANDON_NONPRISTINE' `
                    "session contains state beyond its never-run artifact and receipt: $($unexpectedEntries -join ', ')" `
                    'preserve the session; inspect the partial/live run state and use Cleanup only with a valid bound run record'
            }
            Assert-NotReparseEntry $abandonRoot 'abandonment record root'
            $recordParent = Split-Path -Parent $abandonRecord
            Assert-NotReparseEntry $recordParent 'abandonment record parent'
            New-AstroDirectoryLongPath $recordParent | Out-Null
            Assert-NotReparseEntry $recordParent 'abandonment record parent'
            $currentRepository = Get-RepoState -GitExe $gitExe -Workspace $workspace
            $finalOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_ABANDON' `
                    -Description 'never-run evidence session final authorization'
            )
            $record = [ordered]@{
                schema = 'astrolabe.native-fsv-abandon.v2'
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
                owners = [ordered]@{
                    identities = @($ownerBindings | ForEach-Object {
                            [ordered]@{
                                role = $_.Role
                                source = $_.Source
                                identity = $_.Identity
                            }
                        })
                    initial_probes = $initialOwnerProbes
                    final_probes = $finalOwnerProbes
                }
                failure = [ordered]@{
                    code = $ReasonCode
                    message = $ReasonMessage
                }
            }
            Write-NewDurableUtf8 $abandonRecord ($record | ConvertTo-Json -Depth 15)
            $persistedRecord =
                Read-AstroUtf8FileLongPath $abandonRecord | ConvertFrom-Json
            if ($persistedRecord.schema -ne 'astrolabe.native-fsv-abandon.v2' -or
                [string]$persistedRecord.artifact.sha256 -cne [string]$inspection.sha256 -or
                [string]$persistedRecord.failure.code -cne $ReasonCode) {
                Fail-Astro 'ASTRO_FSV_ABANDON_RECORD_INVALID' `
                    "persisted abandonment record readback does not bind the session: $abandonRecord" `
                    'preserve both session and record and investigate the durable-write mismatch'
            }
            Assert-AstroFsvPersistedOwnerEnvelope `
                -Owners $persistedRecord.owners `
                -ExpectedBindings $ownerBindings `
                -Code 'ASTRO_FSV_ABANDON_RECORD_INVALID' `
                -Description 'persisted abandonment record'
            $recordHash = File-Sha256 $abandonRecord
            $before = [ordered]@{
                session = $session
                exists = $true
                artifact_sha256 = $inspection.sha256
                owners = $record.owners
            }
            Set-AstroFileReadOnlyLongPath `
                -LiteralPath $inspection.artifact_path -ReadOnly $false
            Remove-AstroOrdinaryFlatDirectoryLongPath $session
            if (Test-AstroPathLongPath -LiteralPath $session) {
                Fail-Astro 'ASTRO_FSV_ABANDON_FAILED' "evidence session remains after abandonment: $session" `
                    'preserve the external abandonment record and inspect open handles before retrying exact cleanup'
            }
            Remove-EmptyEvidenceParents $session
            [ordered]@{
                operation = 'abandon'
                record_path = $abandonRecord
                record_sha256 = $recordHash
                record = $persistedRecord
                before = $before
                after = [ordered]@{ session = $session; exists = $false }
            } | ConvertTo-Json -Depth 18 -Compress | Write-Output
        }
        'PreAdmissionAbandon' {
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            Assert-FsvLockAbsent $fsvLock
            $launcherProtocolState = Read-AstroLauncherLock -LockPath $launcherLockPath
            if ($launcherProtocolState.State -ne 'absent') {
                Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_LAUNCHER_LOCK' `
                    "launcher protocol state is '$($launcherProtocolState.State)'; pre-admission abandonment requires authoritative absence" `
                    'wait for a live owner to finish or recover the exact launcher generation before session removal'
            }
            if ($ReasonCode -notmatch '^[A-Z][A-Z0-9_]{2,95}$' -or
                [string]::IsNullOrWhiteSpace($ReasonMessage)) {
                Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_REASON_INVALID' `
                    'PreAdmissionAbandon requires a stable upper-case ReasonCode and nonblank ReasonMessage' `
                    'describe the exact pre-admission runner refusal before requesting tracker authorization'
            }
            if ([string]::IsNullOrWhiteSpace($PreAdmissionDirectoryPath) -or
                [string]::IsNullOrWhiteSpace($StandardOutputPath) -or
                [string]::IsNullOrWhiteSpace($StandardErrorPath) -or
                [string]::IsNullOrWhiteSpace($RunRecordPath) -or
                [string]::IsNullOrWhiteSpace($LiveStatePath)) {
                Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_PATH_REQUIRED' `
                    'PreAdmissionAbandon requires the exact empty directory plus all four intended direct runner output paths' `
                    'bind the exact pre-admission refusal paths; do not infer child or runner state'
            }
            if ([string]::IsNullOrWhiteSpace($RecoveryRecordPath)) {
                Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_RECORD_REQUIRED' `
                    'RecoveryRecordPath is required for PreAdmissionAbandon' `
                    "use a fresh JSON path below $recoveryRoot; the record persists after exact session removal"
            }
            $session = [IO.Path]::GetFullPath($inspection.session_directory)
            $preAdmissionDirectory = Assert-DirectSessionChildPath `
                $PreAdmissionDirectoryPath $session `
                'ASTRO_FSV_PRE_ADMISSION_DIRECTORY_ESCAPE' 'pre-admission evidence directory'
            $standardOutput = Assert-DirectSessionChildPath `
                $StandardOutputPath $session `
                'ASTRO_FSV_PRE_ADMISSION_OUTPUT_ESCAPE' 'standard output path'
            $standardError = Assert-DirectSessionChildPath `
                $StandardErrorPath $session `
                'ASTRO_FSV_PRE_ADMISSION_OUTPUT_ESCAPE' 'standard error path'
            $runRecord = Assert-DirectSessionChildPath `
                $RunRecordPath $session `
                'ASTRO_FSV_PRE_ADMISSION_OUTPUT_ESCAPE' 'run record path'
            $liveState = Assert-DirectSessionChildPath `
                $LiveStatePath $session `
                'ASTRO_FSV_PRE_ADMISSION_OUTPUT_ESCAPE' 'live state path'
            $claimedPaths = @(
                [IO.Path]::GetFullPath($receiptState.Path),
                [IO.Path]::GetFullPath($inspection.artifact_path),
                $preAdmissionDirectory, $standardOutput, $standardError, $runRecord, $liveState
            )
            if (@($claimedPaths | Sort-Object -Unique).Count -ne $claimedPaths.Count) {
                Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_PATH_COLLISION' `
                    'pre-admission directory, receipt, artifact, and four runner output paths must be distinct' `
                    'bind seven distinct direct children of the selected evidence session'
            }
            if (-not (Test-AstroPathLongPath -LiteralPath $preAdmissionDirectory -PathType Container)) {
                Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_DIRECTORY_MISSING' `
                    "exact pre-admission evidence directory is absent: $preAdmissionDirectory" `
                    'use Abandon for a pristine session; this lifecycle consumes only the observed empty-directory state'
            }
            Assert-NotReparseEntry $preAdmissionDirectory 'pre-admission evidence directory'
            $preAdmissionEntries = @(Get-AstroDirectoryEntriesLongPath $preAdmissionDirectory)
            if ($preAdmissionEntries.Count -ne 0) {
                Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_DIRECTORY_NONEMPTY' `
                    "pre-admission evidence directory contains $($preAdmissionEntries.Count) entry or entries" `
                    'preserve every byte; any nested output might belong to a real child or incomplete runner'
            }
            foreach ($outputPath in @($standardOutput, $standardError, $runRecord, $liveState)) {
                Assert-NotReparseEntry $outputPath 'pre-admission runner output path'
                if (Test-AstroPathLongPath -LiteralPath $outputPath) {
                    Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_RUN_STATE_PRESENT' `
                        "pre-admission session contains an expected runner output or control path: $outputPath" `
                        'preserve the session; a real runner state must use Cleanup or Quarantine only'
                }
            }
            $allowedRootEntries = @(
                [IO.Path]::GetFullPath($receiptState.Path),
                [IO.Path]::GetFullPath($inspection.artifact_path),
                $preAdmissionDirectory
            )
            $rootEntries = @(Get-AstroDirectoryEntriesLongPath $session)
            $unexpectedRootEntries = @($rootEntries | Where-Object {
                    $full = [IO.Path]::GetFullPath($_.FullName)
                    -not ($allowedRootEntries -contains $full)
                })
            if ($rootEntries.Count -ne 3 -or $unexpectedRootEntries.Count -ne 0) {
                Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_SESSION_SHAPE_INVALID' `
                    "session is not the exact receipt/artifact/one-empty-directory pre-admission shape: $($rootEntries.FullName -join '; ')" `
                    'preserve every byte; unknown state might belong to a real child or incomplete runner'
            }
            $recoveryRecord = Assert-PathWithin $RecoveryRecordPath $recoveryRoot `
                'ASTRO_FSV_PRE_ADMISSION_RECORD_ESCAPE' 'pre-admission recovery record path'
            if (Test-AstroPathLongPath -LiteralPath $recoveryRecord) {
                Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_RECORD_REUSE_REFUSED' `
                    "pre-admission recovery record already exists: $recoveryRecord" `
                    'use one fresh append-only recovery record path for the exact session'
            }
            $ownerBindings = @(
                New-AstroFsvOwnerBinding 'launcher' 'artifact receipt' $inspection.owners.launcher
                New-AstroFsvOwnerBinding 'promoter' 'artifact receipt' $inspection.owners.promoter
            )
            $initialOwnerProbes = @(Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_PRE_ADMISSION' `
                    -Description 'pre-admission evidence session')
            $initialTree = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $session
            $receiptHash = File-Sha256 $receiptState.Path
            $artifactHash = File-Sha256 $inspection.artifact_path
            Assert-NotReparseEntry $recoveryRoot 'pre-admission recovery record root'
            $recordParent = Split-Path -Parent $recoveryRecord
            $tracker = Read-AstroFsvPreAdmissionTrackerEvidence `
                -Url $TrackerCommentUrl `
                -ExpectedIssue ([int]$inspection.issue) `
                -ExpectedReceiptPath $receiptState.Path `
                -ExpectedReceiptSha256 $receiptHash `
                -ExpectedArtifactPath $inspection.artifact_path `
                -ExpectedArtifactSha256 $artifactHash `
                -ExpectedSessionDirectory $session `
                -ExpectedPreAdmissionDirectory $preAdmissionDirectory `
                -ExpectedStandardOutputPath $standardOutput `
                -ExpectedStandardErrorPath $standardError `
                -ExpectedRunRecordPath $runRecord `
                -ExpectedLiveStatePath $liveState `
                -ExpectedInventorySchema ([string]$initialTree.schema) `
                -ExpectedInventoryEncoding ([string]$initialTree.encoding) `
                -ExpectedInventoryEntryCount ([int]$initialTree.entry_count) `
                -ExpectedInventoryCanonicalByteCount ([uint64]$initialTree.canonical_bytes_length) `
                -ExpectedInventorySha256 ([string]$initialTree.sha256) `
                -ExpectedRecoveryRecordPath $recoveryRecord `
                -ExpectedReasonCode $ReasonCode
            New-AstroDirectoryLongPath $recordParent | Out-Null
            Assert-NotReparseEntry $recordParent 'pre-admission recovery record parent'
            $finalTree = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $session
            if ([string]$finalTree.schema -cne [string]$initialTree.schema -or
                [string]$finalTree.encoding -cne [string]$initialTree.encoding -or
                [int]$finalTree.entry_count -ne [int]$initialTree.entry_count -or
                [uint64]$finalTree.canonical_bytes_length -ne [uint64]$initialTree.canonical_bytes_length -or
                [string]$finalTree.sha256 -cne [string]$initialTree.sha256 -or
                (File-Sha256 $receiptState.Path) -cne $receiptHash -or
                (File-Sha256 $inspection.artifact_path) -cne $artifactHash) {
                Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_SESSION_DRIFT' `
                    'pre-admission session inventory or immutable receipt/artifact bytes changed after tracker authorization' `
                    'preserve the session and post fresh evidence for its current exact state'
            }
            $finalOwnerProbes = @(Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_PRE_ADMISSION' `
                    -Description 'pre-admission evidence session final authorization')
            $record = [ordered]@{
                schema = 'astrolabe.native-fsv-pre-admission-abandon.v1'
                verdict = 'abandoned-pre-admission-nonpristine'
                issue = [int]$inspection.issue
                recorded_at_utc = [DateTime]::UtcNow.ToString('o')
                tracker = $tracker
                receipt_path = $receiptState.Path
                receipt_sha256 = $receiptHash
                session_directory = $session
                pre_admission_directory = $preAdmissionDirectory
                runner_paths = [ordered]@{
                    standard_output = $standardOutput
                    standard_error = $standardError
                    run_record = $runRecord
                    live_state = $liveState
                    all_absent = $true
                }
                artifact = [ordered]@{ path = $inspection.artifact_path; bytes = [uint64]$inspection.bytes; sha256 = $artifactHash }
                inventory = [ordered]@{
                    schema = [string]$finalTree.schema
                    encoding = [string]$finalTree.encoding
                    entry_count = [int]$finalTree.entry_count
                    canonical_byte_count = [uint64]$finalTree.canonical_bytes_length
                    sha256 = [string]$finalTree.sha256
                }
                source_of_truth = [ordered]@{
                    fsv_lock = [ordered]@{ path = $fsvLock; exists = $false }
                    launcher_protocol = [ordered]@{ path = $launcherLockPath; state = $launcherProtocolState.State }
                }
                owners = [ordered]@{
                    identities = @($ownerBindings | ForEach-Object { [ordered]@{ role = $_.Role; source = $_.Source; identity = $_.Identity } })
                    initial_probes = $initialOwnerProbes
                    final_probes = $finalOwnerProbes
                }
                failure = [ordered]@{ code = $ReasonCode; message = $ReasonMessage }
            }
            Write-NewDurableUtf8 $recoveryRecord ($record | ConvertTo-Json -Depth 20)
            $persistedRecord = Read-AstroUtf8FileLongPath $recoveryRecord | ConvertFrom-Json
            if ($persistedRecord.schema -cne 'astrolabe.native-fsv-pre-admission-abandon.v1' -or
                $persistedRecord.verdict -cne 'abandoned-pre-admission-nonpristine' -or
                [string]$persistedRecord.receipt_sha256 -cne $receiptHash -or
                [string]$persistedRecord.artifact.sha256 -cne $artifactHash -or
                [string]$persistedRecord.inventory.sha256 -cne [string]$finalTree.sha256 -or
                [string]$persistedRecord.failure.code -cne $ReasonCode -or
                -not [bool]$persistedRecord.runner_paths.all_absent) {
                Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_RECORD_INVALID' `
                    "persisted pre-admission recovery record readback does not bind the exact session: $recoveryRecord" `
                    'preserve both session and recovery record and investigate the durable-write mismatch'
            }
            Assert-AstroFsvPersistedOwnerEnvelope `
                -Owners $persistedRecord.owners `
                -ExpectedBindings $ownerBindings `
                -Code 'ASTRO_FSV_PRE_ADMISSION_RECORD_INVALID' `
                -Description 'persisted pre-admission recovery record'
            $recordHash = File-Sha256 $recoveryRecord
            $before = [ordered]@{ session = $session; exists = $true; inventory_sha256 = [string]$finalTree.sha256; owners = $record.owners }
            Remove-AstroOrdinaryDirectoryTreeLongPath `
                -LiteralPath $session `
                -ExpectedInventorySchema ([string]$finalTree.schema) `
                -ExpectedInventoryEncoding ([string]$finalTree.encoding) `
                -ExpectedInventorySha256 ([string]$finalTree.sha256)
            if (Test-AstroPathLongPath -LiteralPath $session) {
                Fail-Astro 'ASTRO_FSV_PRE_ADMISSION_DELETE_FAILED' `
                    "evidence session remains after pre-admission abandonment: $session" `
                    'preserve the external recovery record and inspect exact filesystem state before retrying'
            }
            Remove-EmptyEvidenceParents $session
            [ordered]@{
                operation = 'pre-admission-abandon'
                record_path = $recoveryRecord
                record_sha256 = $recordHash
                record = $persistedRecord
                before = $before
                after = [ordered]@{ session = $session; exists = $false }
            } | ConvertTo-Json -Depth 24 -Compress | Write-Output
        }
        'QuarantineTerminalPartial' {
            if ($Issue -le 0) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_ISSUE_INVALID' `
                    'Issue must be positive for terminal-partial quarantine' `
                    'pass the exact issue bound by the staged artifact and retirement completion'
            }
            if ([string]::IsNullOrWhiteSpace($TrackerCommentUrl)) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_TRACKER_REQUIRED' `
                    'TrackerCommentUrl is required for terminal-partial quarantine' `
                    'post a fresh owner-authored comment after lock retirement completes'
            }
            if ($ReasonCode -notmatch '^[A-Z][A-Z0-9_]{2,95}$' -or
                [string]::IsNullOrWhiteSpace($ReasonMessage)) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_REASON_INVALID' `
                    'QuarantineTerminalPartial requires a structured ReasonCode and nonblank ReasonMessage' `
                    'describe the exact failure that left this terminal-partial session'
            }
            if ([string]::IsNullOrWhiteSpace($RecoveryRecordPath) -or
                [string]::IsNullOrWhiteSpace($LockRetirementRecordPath)) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_REQUIRED' `
                    'RecoveryRecordPath and LockRetirementRecordPath are required' `
                    'pass one fresh quarantine authorization path and the exact completed lock-retirement record'
            }
            $fsvLifecycleMutex = Enter-AstroFsvLifecycleMutex -WorkspaceRoot $workspace
            if (-not $fsvLifecycleMutex.Acquired) {
                Exit-AstroFsvLifecycleMutex $fsvLifecycleMutex
                Fail-Astro 'ASTRO_FSV_LIFECYCLE_MUTEX_HELD' `
                    "native-FSV lifecycle mutex is held: $($fsvLifecycleMutex.Name)" `
                    'wait for the exact active claim/recovery transaction to publish durable state'
            }
            $launcherCoordinationMutex = Enter-AstroLauncherLockMutex `
                -LockPath $launcherLockPath
            if (-not $launcherCoordinationMutex.Acquired) {
                $mutexName = [string]$launcherCoordinationMutex.Name
                Exit-AstroLauncherLockMutex $launcherCoordinationMutex
                Exit-AstroFsvLifecycleMutex $fsvLifecycleMutex
                Fail-Astro 'ASTRO_FSV_LAUNCHER_MUTEX_HELD' `
                    "launcher-lock coordination mutex is held: $mutexName" `
                    'wait for launcher claim/recovery coordination to finish, then resume the exact FSV transaction'
            }
            try {
            $resumeAuthorizationPath = Assert-PathWithin `
                $RecoveryRecordPath $recoveryRoot `
                'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_ESCAPE' `
                'terminal-partial quarantine authorization path'
            $resumeCompletionPath = $resumeAuthorizationPath + '.completed.json'
            $resumeTombstonePath = $resumeAuthorizationPath + '.session.dir'
            if ((Test-AstroPathLongPath -LiteralPath $fsvLifecycleTransition) -or
                (Test-AstroPathLongPath -LiteralPath $resumeAuthorizationPath) -or
                (Test-AstroPathLongPath -LiteralPath $resumeCompletionPath) -or
                (Test-AstroPathLongPath -LiteralPath $resumeTombstonePath)) {
                $resumeResult = Invoke-AstroFsvTerminalPartialQuarantineResume `
                    -ExpectedIssue $Issue -Workspace $workspace `
                    -EvidenceRoot $evidenceRoot -RecoveryRoot $recoveryRoot `
                    -FsvLockPath $fsvLock `
                    -LifecycleTransitionPath $fsvLifecycleTransition `
                    -RecoveryInputPath $RecoveryRecordPath `
                    -RetirementCompletionInputPath $LockRetirementRecordPath `
                    -TrackerUrl $TrackerCommentUrl `
                    -FailureCode $ReasonCode -FailureMessage $ReasonMessage
                $resumeResult | ConvertTo-Json -Depth 40 -Compress | Write-Output
                return
            }
            Assert-FsvLockAbsent $fsvLock
            $launcherProtocolInitial = Read-AstroLauncherLock -LockPath $launcherLockPath
            if ($launcherProtocolInitial.State -ne 'absent') {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_LAUNCHER_LOCK' `
                    "launcher protocol is '$($launcherProtocolInitial.State)'" `
                    'complete exact launcher recovery before quarantining any FSV session'
            }
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            if ([int]$inspection.issue -ne $Issue) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_ISSUE_MISMATCH' `
                    "requested issue #$Issue differs from receipt issue #$($inspection.issue)" `
                    'quarantine only through the exact issue named by the receipt'
            }
            $retirementCompletionPath = Assert-PathWithin `
                $LockRetirementRecordPath $recoveryRoot `
                'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_ESCAPE' `
                'lock-retirement completion path'
            if (-not (Test-AstroPathLongPath `
                    -LiteralPath $retirementCompletionPath -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_MISSING' `
                    "lock-retirement completion is absent: $retirementCompletionPath" `
                    'complete RetireTerminalPartialLock before session quarantine'
            }
            Assert-NotReparseEntry $retirementCompletionPath `
                'terminal-partial lock-retirement completion'
            $retirementCompletionSha256 = File-Sha256 $retirementCompletionPath
            try {
                $retirementCompletion =
                    Read-AstroUtf8FileLongPath $retirementCompletionPath |
                        ConvertFrom-Json
            }
            catch {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_INVALID' `
                    "lock-retirement completion is unreadable: $($_.Exception.Message)" `
                    'preserve the session and retirement state'
            }
            if ([string]$retirementCompletion.schema -cne
                    'astrolabe.native-fsv-partial-lock-retirement.completion.v1' -or
                [string]$retirementCompletion.phase -cne
                    'complete-lock-archived-source-absent' -or
                [int]$retirementCompletion.issue -ne $Issue -or
                [string]$retirementCompletion.source.state -cne 'absent' -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$retirementCompletion.source.path),
                    $fsvLock,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_INVALID' `
                    'lock-retirement completion does not prove the exact terminal phase' `
                    'preserve the session and pass only the completed phase-one record'
            }
            $retirementAuthorizationPath = Assert-PathWithin `
                ([string]$retirementCompletion.authorization.path) `
                $recoveryRoot `
                'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_ESCAPE' `
                'lock-retirement authorization path'
            if (-not (Test-AstroPathLongPath `
                    -LiteralPath $retirementAuthorizationPath -PathType Leaf) -or
                (File-Sha256 $retirementAuthorizationPath) -cne
                    [string]$retirementCompletion.authorization.sha256) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_INVALID' `
                    'lock-retirement authorization is absent or hash-mismatched' `
                    'preserve all state and investigate the external recovery record'
            }
            try {
                $retirementAuthorization =
                    Read-AstroUtf8FileLongPath $retirementAuthorizationPath |
                        ConvertFrom-Json
            }
            catch {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_INVALID' `
                    "lock-retirement authorization is unreadable: $($_.Exception.Message)" `
                    'preserve all state and investigate the external recovery record'
            }
            if ([string]$retirementAuthorization.schema -cnotin @(
                    'astrolabe.native-fsv-partial-lock-retirement.authorization.v1',
                    'astrolabe.native-fsv-partial-lock-retirement.authorization.v2') -or
                [string]$retirementAuthorization.phase -cne
                    'authorized-exact-terminal-partial-lock' -or
                [int]$retirementAuthorization.issue -ne $Issue -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath(
                        [string]$retirementAuthorization.receipt_path),
                    $receiptState.Path,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                [string]$retirementAuthorization.receipt_sha256 -cne
                    (File-Sha256 $receiptState.Path) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath(
                        [string]$retirementAuthorization.session_directory),
                    $inspection.session_directory,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath(
                        [string]$retirementAuthorization.artifact.path),
                    $inspection.artifact_path,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                [string]$retirementAuthorization.artifact.sha256 -cne
                    $inspection.sha256 -or
                [string]$retirementAuthorization.fsv_lock.state.schema -cne
                    'astrolabe.native-fsv-lock.v3' -or
                [string]$retirementAuthorization.fsv_lock.state.mode -cne
                    'resident-cohort') {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_INVALID' `
                    'lock-retirement authorization is not bound to this receipt/artifact/session' `
                    'preserve mixed-generation state and investigate its publisher'
            }
            $lockArchivePath = Assert-PathWithin `
                ([string]$retirementAuthorization.fsv_lock.archive_path) `
                $recoveryRoot `
                'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_ESCAPE' `
                'archived FSV-lock path'
            if (-not (Test-AstroPathLongPath -LiteralPath $lockArchivePath -PathType Leaf) -or
                (File-Sha256 $lockArchivePath) -cne
                    [string]$retirementAuthorization.fsv_lock.sha256 -or
                (File-Sha256 $lockArchivePath) -cne
                    [string]$retirementCompletion.archive.sha256) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_INVALID' `
                    'archived FSV-lock bytes are absent or hash-mismatched' `
                    'preserve every byte and investigate the phase-one archive'
            }
            if (-not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$retirementCompletion.authorization.path),
                    $retirementAuthorizationPath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$retirementCompletion.archive.path),
                    $lockArchivePath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$retirementCompletion.session.path),
                    [IO.Path]::GetFullPath([string]$retirementAuthorization.session_directory),
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                [string]$retirementCompletion.session.inventory_schema -cne
                    [string]$retirementAuthorization.session_inventory.schema -or
                [string]$retirementCompletion.session.inventory_encoding -cne
                    [string]$retirementAuthorization.session_inventory.encoding -or
                [int]$retirementCompletion.session.inventory_entry_count -ne
                    [int]$retirementAuthorization.session_inventory.entry_count -or
                [uint64]$retirementCompletion.session.inventory_canonical_byte_count -ne
                    [uint64]$retirementAuthorization.session_inventory.canonical_bytes_length -or
                [string]$retirementCompletion.session.inventory_sha256 -cne
                    [string]$retirementAuthorization.session_inventory.sha256) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_INVALID' `
                    'phase-one completion paths/inventory do not exactly link authorization/archive/session' `
                    'preserve every record and investigate the malformed chain'
            }
            $launcherRecoveryChain =
                Read-AstroFsvLauncherTerminalChainFromRetirementAuthorization `
                    -Authorization $retirementAuthorization -ExpectedIssue $Issue `
                    -Workspace $workspace `
                    -Code 'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_INVALID' `
                    -Description 'phase-one launcher terminal chain'
            $ownerBindings = Get-AstroFsvRetirementDerivedOwners `
                -RetirementAuthorization $retirementAuthorization `
                -Inspection $inspection -LauncherRecoveryChain $launcherRecoveryChain `
                -Code 'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_INVALID'
            Assert-AstroFsvPersistedOwnerEnvelope `
                -Owners $retirementAuthorization.owners `
                -ExpectedBindings $ownerBindings `
                -Code 'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_INVALID' `
                -Description 'terminal-partial lock-retirement authorization'
            $session = [IO.Path]::GetFullPath($inspection.session_directory)
            $stdoutPath = Assert-DirectSessionChildPath $StandardOutputPath $session `
                'ASTRO_FSV_TERMINAL_PARTIAL_OUTPUT_PATH_INVALID' 'standard-output path'
            $stderrPath = Assert-DirectSessionChildPath $StandardErrorPath $session `
                'ASTRO_FSV_TERMINAL_PARTIAL_OUTPUT_PATH_INVALID' 'standard-error path'
            $expectedRunRecord = Assert-DirectSessionChildPath $RunRecordPath $session `
                'ASTRO_FSV_TERMINAL_PARTIAL_RUN_PATH_INVALID' 'expected run-record path'
            $expectedLiveState = Assert-DirectSessionChildPath $LiveStatePath $session `
                'ASTRO_FSV_TERMINAL_PARTIAL_LIVE_PATH_INVALID' 'expected live-state path'
            foreach ($pair in @(
                @($stdoutPath, $retirementAuthorization.outputs.stdout.path),
                @($stderrPath, $retirementAuthorization.outputs.stderr.path),
                @($expectedRunRecord, $retirementAuthorization.expected_controls.run_record_path),
                @($expectedLiveState, $retirementAuthorization.expected_controls.live_state_path)
            )) {
                if (-not [string]::Equals(
                        [IO.Path]::GetFullPath([string]$pair[0]),
                        [IO.Path]::GetFullPath([string]$pair[1]),
                        [StringComparison]::OrdinalIgnoreCase
                    )) {
                    Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_RETIREMENT_INVALID' `
                        'explicit output/control paths differ from phase-one authorization' `
                        'preserve the session and use the exact phase-one path bindings'
                }
            }
            if (-not (Test-AstroPathLongPath -LiteralPath $stdoutPath -PathType Leaf) -or
                -not (Test-AstroPathLongPath -LiteralPath $stderrPath -PathType Leaf) -or
                (File-Sha256 $stdoutPath) -cne
                    [string]$retirementAuthorization.outputs.stdout.sha256 -or
                (File-Sha256 $stderrPath) -cne
                    [string]$retirementAuthorization.outputs.stderr.sha256 -or
                (Test-AstroPathLongPath -LiteralPath $expectedRunRecord) -or
                (Test-AstroPathLongPath -LiteralPath $expectedLiveState)) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_SESSION_DRIFT' `
                    'output/control family changed after lock retirement' `
                    'preserve the session and post no quarantine authorization'
            }
            $sessionTree = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $session
            if ([string]$sessionTree.schema -cne
                    [string]$retirementAuthorization.session_inventory.schema -or
                [string]$sessionTree.encoding -cne
                    [string]$retirementAuthorization.session_inventory.encoding -or
                [int]$sessionTree.entry_count -ne
                    [int]$retirementAuthorization.session_inventory.entry_count -or
                [uint64]$sessionTree.canonical_bytes_length -ne
                    [uint64]$retirementAuthorization.session_inventory.canonical_bytes_length -or
                [string]$sessionTree.sha256 -cne
                    [string]$retirementAuthorization.session_inventory.sha256) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_SESSION_DRIFT' `
                    'complete session inventory changed after lock retirement' `
                    'preserve the session and post fresh evidence only after investigation'
            }
            $initialOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_TERMINAL_PARTIAL' `
                    -Description 'terminal-partial quarantine'
            )
            $jobName = [string]$retirementAuthorization.launcher_job.name
            $jobProbeFirst = Get-AstroLauncherJobObjectProbe -Name $jobName
            if ($jobProbeFirst.State -cne 'absent') {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_JOB_PRESENT' `
                    "launcher Job is '$($jobProbeFirst.State)': $jobName" `
                    'preserve the session while any recorded Job generation exists'
            }
            $recoveryJobProbesFirst = @(Assert-AstroFsvRecoveryJobsAbsent `
                    -LauncherRecoveryChain $launcherRecoveryChain `
                    -CodePrefix 'ASTRO_FSV_TERMINAL_PARTIAL' `
                    -Description 'terminal-partial quarantine')
            $recoveryRecord = Assert-PathWithin $RecoveryRecordPath $recoveryRoot `
                'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_ESCAPE' `
                'terminal-partial quarantine authorization path'
            $completionRecordPath = $recoveryRecord + '.completed.json'
            $sessionTombstonePath = $recoveryRecord + '.session.dir'
            if ((Get-AstroFsvStrictPathState `
                    $recoveryRecord file `
                    'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_REUSE_REFUSED' `
                    'quarantine authorization archive').state -cne 'absent' -or
                (Get-AstroFsvStrictPathState `
                    $completionRecordPath file `
                    'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_REUSE_REFUSED' `
                    'quarantine completion').state -cne 'absent' -or
                (Get-AstroFsvStrictPathState `
                    $sessionTombstonePath directory `
                    'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_REUSE_REFUSED' `
                    'quarantine session tombstone').state -cne 'absent' -or
                (Get-AstroFsvStrictPathState `
                    $fsvLifecycleTransition file `
                    'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_REUSE_REFUSED' `
                    'canonical FSV lifecycle transition').state -cne 'absent') {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_REUSE_REFUSED' `
                    'quarantine authorization/completion/tombstone/transition path already exists' `
                    'use one fresh append-only recovery path per session'
            }
            $receiptSha256 = File-Sha256 $receiptState.Path
            $tracker = Read-AstroFsvTerminalPartialQuarantineTrackerEvidence `
                -Url $TrackerCommentUrl -ExpectedIssue $Issue `
                -ExpectedRetirementCompletionPath $retirementCompletionPath `
                -ExpectedRetirementCompletionSha256 $retirementCompletionSha256 `
                -ExpectedReceiptPath $receiptState.Path `
                -ExpectedReceiptSha256 $receiptSha256 `
                -ExpectedArtifactPath $inspection.artifact_path `
                -ExpectedArtifactSha256 $inspection.sha256 `
                -ExpectedSessionDirectory $session `
                -ExpectedStandardOutputPath $stdoutPath `
                -ExpectedStandardOutputSha256 `
                    ([string]$retirementAuthorization.outputs.stdout.sha256) `
                -ExpectedStandardErrorPath $stderrPath `
                -ExpectedStandardErrorSha256 `
                    ([string]$retirementAuthorization.outputs.stderr.sha256) `
                -ExpectedRunRecordPath $expectedRunRecord `
                -ExpectedLiveStatePath $expectedLiveState `
                -ExpectedInventorySchema ([string]$sessionTree.schema) `
                -ExpectedInventoryEncoding ([string]$sessionTree.encoding) `
                -ExpectedInventoryEntryCount ([int]$sessionTree.entry_count) `
                -ExpectedInventoryCanonicalByteCount `
                    ([uint64]$sessionTree.canonical_bytes_length) `
                -ExpectedInventorySha256 ([string]$sessionTree.sha256) `
                -ExpectedRecoveryRecordPath $recoveryRecord `
                -ExpectedCompletionRecordPath $completionRecordPath `
                -ExpectedLifecycleTransitionPath $fsvLifecycleTransition `
                -ExpectedSessionTombstonePath $sessionTombstonePath `
                -ExpectedReasonCode $ReasonCode
            if ([long]$tracker.comment_id -eq
                [long]$retirementAuthorization.tracker.comment_id) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_TRACKER_STALE' `
                    'quarantine tracker reuses the phase-one owner comment' `
                    'post a distinct second-phase comment that binds the completed phase-one hash'
            }
            try {
                $trackerCreated = [DateTimeOffset]::Parse(
                    [string]$tracker.created_at,
                    [Globalization.CultureInfo]::InvariantCulture
                )
                $retirementCompleted = [DateTimeOffset]::Parse(
                    [string]$retirementCompletion.completed_at_utc,
                    [Globalization.CultureInfo]::InvariantCulture
                )
            }
            catch {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_TRACKER_STALE' `
                    "phase timestamp is malformed (tracker='$($tracker.created_at)'; completion='$($retirementCompletion.completed_at_utc)'): $($_.Exception.Message)" `
                    'preserve the session and investigate malformed durable timestamp authority'
            }
            if ($trackerCreated -le $retirementCompleted) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_TRACKER_STALE' `
                    'quarantine tracker is not provably later than phase-one completion' `
                    'post a fresh second-phase comment that binds the completed phase-one hash'
            }
            $finalOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_TERMINAL_PARTIAL' `
                    -Description 'terminal-partial quarantine final authorization'
            )
            $jobProbeSecond = Get-AstroLauncherJobObjectProbe -Name $jobName
            $recoveryJobProbesSecond = @(Assert-AstroFsvRecoveryJobsAbsent `
                    -LauncherRecoveryChain $launcherRecoveryChain `
                    -CodePrefix 'ASTRO_FSV_TERMINAL_PARTIAL' `
                    -Description 'terminal-partial quarantine final authorization')
            $launcherRecoveryChainFinal =
                Read-AstroFsvLauncherTerminalChainFromRetirementAuthorization `
                    -Authorization $retirementAuthorization -ExpectedIssue $Issue `
                    -Workspace $workspace `
                    -Code 'ASTRO_FSV_TERMINAL_PARTIAL_LAUNCHER_RECOVERY_DRIFT' `
                    -Description 'phase-one launcher terminal chain final readback'
            if (-not (Test-AstroFsvLauncherTerminalChainEqual `
                    $launcherRecoveryChainFinal $launcherRecoveryChain)) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_LAUNCHER_RECOVERY_DRIFT' `
                    'launcher terminal chain changed after tracker authorization' `
                    'preserve the session and post no quarantine transition'
            }
            $launcherProtocolFinal = Read-AstroLauncherLock -LockPath $launcherLockPath
            $finalTree = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $session
            if ($jobProbeSecond.State -cne 'absent' -or
                $launcherProtocolFinal.State -ne 'absent' -or
                (Test-AstroPathLongPath -LiteralPath (Join-Path $workspace 'target')) -or
                (Test-AstroPathLongPath -LiteralPath $fsvLock) -or
                (File-Sha256 $retirementCompletionPath) -cne
                    $retirementCompletionSha256 -or
                (File-Sha256 $lockArchivePath) -cne
                    [string]$retirementAuthorization.fsv_lock.sha256 -or
                (File-Sha256 $receiptState.Path) -cne $receiptSha256 -or
                (File-Sha256 $inspection.artifact_path) -cne $inspection.sha256 -or
                (File-Sha256 $stdoutPath) -cne
                    [string]$retirementAuthorization.outputs.stdout.sha256 -or
                (File-Sha256 $stderrPath) -cne
                    [string]$retirementAuthorization.outputs.stderr.sha256 -or
                (Test-AstroPathLongPath -LiteralPath $expectedRunRecord) -or
                (Test-AstroPathLongPath -LiteralPath $expectedLiveState) -or
                [string]$finalTree.schema -cne [string]$sessionTree.schema -or
                [string]$finalTree.encoding -cne [string]$sessionTree.encoding -or
                [int]$finalTree.entry_count -ne [int]$sessionTree.entry_count -or
                [uint64]$finalTree.canonical_bytes_length -ne
                    [uint64]$sessionTree.canonical_bytes_length -or
                [string]$finalTree.sha256 -cne [string]$sessionTree.sha256) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_SESSION_DRIFT' `
                    'retirement/session/owner/Job/launcher state changed after tracker authorization' `
                    'preserve every byte and post fresh evidence for the current exact state'
            }
            $sessionFiles = @(Get-SessionFileInventory $session)
            $currentRepository = Get-RepoState -GitExe $gitExe -Workspace $workspace
            $recordParent = Split-Path -Parent $recoveryRecord
            New-AstroDirectoryLongPath $recordParent | Out-Null
            Assert-NotReparseEntry $recordParent `
                'terminal-partial quarantine record parent'
            $normalTerminalChain = [string]$retirementAuthorization.schema -ceq
                'astrolabe.native-fsv-partial-lock-retirement.authorization.v2'
            $phaseTwoAuthorizationSchema = if ($normalTerminalChain) {
                'astrolabe.native-fsv-terminal-partial-quarantine.authorization.v2'
            }
            else {
                'astrolabe.native-fsv-terminal-partial-quarantine.authorization.v1'
            }
            $phaseTwoTerminalJobsField = if ($normalTerminalChain) {
                'terminal_launcher_jobs'
            }
            else { 'recovery_launcher_jobs' }
            $sourceOfTruth = [ordered]@{
                fsv_lock = [ordered]@{ path = $fsvLock; state = 'absent' }
                launcher_protocol = [ordered]@{
                    path = $launcherLockPath; state = $launcherProtocolFinal.State
                }
                launcher_job = [ordered]@{
                    name = $jobName
                    initial_probe = $jobProbeFirst
                    final_probe = $jobProbeSecond
                }
            }
            $sourceOfTruth[$phaseTwoTerminalJobsField] = [ordered]@{
                initial = $recoveryJobProbesFirst
                final = $recoveryJobProbesSecond
            }
            $authorization = [ordered]@{
                schema = $phaseTwoAuthorizationSchema
                phase = 'authorized-exact-terminal-partial-session'
                issue = $Issue
                recorded_at_utc = [DateTime]::UtcNow.ToString('o')
                tracker = $tracker
                retirement = [ordered]@{
                    completion_path = $retirementCompletionPath
                    completion_sha256 = $retirementCompletionSha256
                    authorization_path = $retirementAuthorizationPath
                    authorization_sha256 =
                        [string]$retirementCompletion.authorization.sha256
                    lock_archive_path = $lockArchivePath
                    lock_archive_sha256 =
                        [string]$retirementAuthorization.fsv_lock.sha256
                }
                receipt_path = $receiptState.Path
                receipt_sha256 = $receiptSha256
                session_directory = $session
                session_tombstone_path = $sessionTombstonePath
                lifecycle_transition_path = $fsvLifecycleTransition
                authorization_record_path = $recoveryRecord
                artifact = [ordered]@{
                    path = $inspection.artifact_path
                    bytes = [uint64]$inspection.bytes
                    sha256 = $inspection.sha256
                }
                expected_controls = [ordered]@{
                    run_record_path = $expectedRunRecord
                    run_record_state = 'absent'
                    live_state_path = $expectedLiveState
                    live_state_state = 'absent'
                }
                outputs = $retirementAuthorization.outputs
                session_inventory = [ordered]@{
                    schema = [string]$finalTree.schema
                    encoding = [string]$finalTree.encoding
                    entry_count = [int]$finalTree.entry_count
                    canonical_bytes_length = [uint64]$finalTree.canonical_bytes_length
                    sha256 = [string]$finalTree.sha256
                    files = $sessionFiles
                    entries = [object[]]$finalTree.entries
                }
                source_of_truth = $sourceOfTruth
                staged_repository = $receiptState.Receipt.repository
                current_repository = $currentRepository
                owners = [ordered]@{
                    identities = @($ownerBindings | ForEach-Object {
                            [ordered]@{
                                role = $_.Role; source = $_.Source; identity = $_.Identity
                            }
                        })
                    initial_probes = $initialOwnerProbes
                    final_probes = $finalOwnerProbes
                }
                failure = [ordered]@{ code = $ReasonCode; message = $ReasonMessage }
                completion_record_path = $completionRecordPath
            }
            $transitionPublication = Publish-NewAstroFsvProtocolRecord `
                -Path $fsvLifecycleTransition -Value $authorization `
                -CodePrefix 'ASTRO_FSV_TERMINAL_PARTIAL_AUTHORIZATION' `
                -StageDirectory $recordParent
            $persistedAuthorization = $transitionPublication.value
            if ([string]$persistedAuthorization.schema -cne
                    $phaseTwoAuthorizationSchema -or
                [string]$persistedAuthorization.phase -cne
                    'authorized-exact-terminal-partial-session' -or
                [string]$persistedAuthorization.retirement.completion_sha256 -cne
                    $retirementCompletionSha256 -or
                [string]$persistedAuthorization.session_inventory.sha256 -cne
                    [string]$finalTree.sha256 -or
                [string]$persistedAuthorization.artifact.sha256 -cne
                    $inspection.sha256 -or
                [string]$persistedAuthorization.failure.code -cne $ReasonCode -or
                [string]$persistedAuthorization.tracker.url -cne $TrackerCommentUrl) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_INVALID' `
                    'persisted quarantine authorization differs from exact state' `
                    'preserve both session and record and investigate durable publication'
            }
            Assert-AstroFsvPersistedOwnerEnvelope `
                -Owners $persistedAuthorization.owners `
                -ExpectedBindings $ownerBindings `
                -Code 'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_INVALID' `
                -Description 'persisted terminal-partial quarantine authorization'
            Assert-AstroFsvPersistedAbsentJobProbe `
                $persistedAuthorization.source_of_truth.launcher_job.initial_probe `
                $jobName 'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_INVALID' `
                'persisted terminal-partial primary Job initial probe'
            Assert-AstroFsvPersistedAbsentJobProbe `
                $persistedAuthorization.source_of_truth.launcher_job.final_probe `
                $jobName 'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_INVALID' `
                'persisted terminal-partial primary Job final probe'
            Assert-AstroFsvPersistedRecoveryJobProbes `
                -Persisted `
                    $persistedAuthorization.source_of_truth.$phaseTwoTerminalJobsField `
                -LauncherRecoveryChain $launcherRecoveryChainFinal `
                -Code 'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_INVALID' `
                -Description 'persisted terminal-partial recovery-launcher'
            $persistedAuthorizedEntries = ConvertFrom-AstroFsvPersistedInventoryEntries `
                -Entries $persistedAuthorization.session_inventory.entries `
                -Code 'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_INVALID' `
                -Description 'persisted terminal-partial session inventory'
            [byte[]]$persistedAuthorizedBytes =
                ConvertTo-AstroOrdinaryTreeInventoryCanonicalBytes `
                    -Schema ([string]$persistedAuthorization.session_inventory.schema) `
                    -Encoding ([string]$persistedAuthorization.session_inventory.encoding) `
                    -Records $persistedAuthorizedEntries
            if ([string]$persistedAuthorization.session_inventory.schema -cne
                    [string]$finalTree.schema -or
                [string]$persistedAuthorization.session_inventory.encoding -cne
                    [string]$finalTree.encoding -or
                [int]$persistedAuthorization.session_inventory.entry_count -ne
                    [int]$finalTree.entry_count -or
                [uint64]$persistedAuthorization.session_inventory.canonical_bytes_length -ne
                    [uint64]$finalTree.canonical_bytes_length -or
                $persistedAuthorizedEntries.Count -ne [int]$finalTree.entry_count -or
                [uint64]$persistedAuthorizedBytes.Length -ne
                    [uint64]$finalTree.canonical_bytes_length -or
                (Get-AstroByteSha256 $persistedAuthorizedBytes) -cne
                    [string]$finalTree.sha256) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_RECORD_INVALID' `
                    'persisted deletion entries do not reproduce the authorized physical inventory' `
                    'preserve the session and transition; no deletion authority was established'
            }
            $authorizationSha256 = [string]$transitionPublication.sha256
            if ((Get-AstroOrdinaryDirectoryTreeInventoryLongPath $session).sha256 -cne
                    [string]$finalTree.sha256) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_SESSION_DRIFT' `
                    'session inventory changed after durable quarantine authorization' `
                    'preserve the session and authorization record'
            }
            $sourceHandle = $null
            $destinationHandle = $null
            try {
                $sourceHandle = [AstroLauncherLockNative]::OpenExactDeleteDirectory($session)
                $destinationHandle =
                    [AstroLauncherLockNative]::OpenExactRenameDirectory($recordParent)
                $sourceFileId = [AstroLauncherLockNative]::GetFileIdentity($sourceHandle)
                $authorizedRoot = @($persistedAuthorizedEntries | Where-Object {
                        [string]$_.relative_path -ceq '.'
                    })
                if ($authorizedRoot.Count -ne 1 -or
                    [string]$authorizedRoot[0].file_id -cne [string]$sourceFileId) {
                    Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_SESSION_DRIFT' `
                        'session root FILE_ID differs from its durable authorization' `
                        'preserve the session and investigate namespace replacement'
                }
                [AstroLauncherLockNative]::RenameDirectoryHandleNoReplace(
                    $sourceHandle,
                    $destinationHandle,
                    [IO.Path]::GetFileName($sessionTombstonePath)
                )
                $renamedPath = ConvertFrom-AstroNativeFinalPath (
                    [AstroLauncherLockNative]::GetFileFinalPath($sourceHandle)
                )
                if (-not [string]::Equals(
                        [IO.Path]::GetFullPath($renamedPath),
                        $sessionTombstonePath,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    [string][AstroLauncherLockNative]::GetFileIdentity($sourceHandle) -cne
                        [string]$sourceFileId) {
                    Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_QUARANTINE_FAILED' `
                        'handle-bound session rename did not preserve exact root identity' `
                        'preserve the tombstone and investigate the namespace transition'
                }
            }
            finally {
                if ($null -ne $destinationHandle) { $destinationHandle.Dispose() }
                if ($null -ne $sourceHandle) { $sourceHandle.Dispose() }
            }
            if ((Test-AstroPathLongPath -LiteralPath $session) -or
                -not (Test-AstroPathLongPath -LiteralPath $sessionTombstonePath -PathType Container)) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_QUARANTINE_FAILED' `
                    'session-to-tombstone transition did not publish exact source absence' `
                    'preserve the transition and inspect both namespaces'
            }
            $tombstoneInventory =
                Get-AstroOrdinaryDirectoryTreeInventoryLongPath $sessionTombstonePath
            Assert-AstroFsvAuthorizedInventorySubset `
                -AuthorizedEntries $persistedAuthorizedEntries `
                -CurrentInventory $tombstoneInventory `
                -Code 'ASTRO_FSV_TERMINAL_PARTIAL_SESSION_DRIFT'
            Remove-AstroOrdinaryDirectoryTreeLongPath `
                -LiteralPath $sessionTombstonePath `
                -ExpectedInventorySchema ([string]$tombstoneInventory.schema) `
                -ExpectedInventoryEncoding ([string]$tombstoneInventory.encoding) `
                -ExpectedInventorySha256 ([string]$tombstoneInventory.sha256)
            if ((Test-AstroPathLongPath -LiteralPath $session) -or
                (Test-AstroPathLongPath -LiteralPath $sessionTombstonePath)) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_QUARANTINE_FAILED' `
                    'session or tombstone remains after identity-bound removal' `
                    'preserve the canonical transition and resume the exact transaction'
            }
            $completion = [ordered]@{
                schema = 'astrolabe.native-fsv-terminal-partial-quarantine.completion.v1'
                phase = 'complete-session-and-tombstone-absent'
                issue = $Issue
                completed_at_utc = [DateTime]::UtcNow.ToString('o')
                authorization = [ordered]@{
                    path = $recoveryRecord; sha256 = $authorizationSha256
                }
                retirement_completion = [ordered]@{
                    path = $retirementCompletionPath
                    sha256 = $retirementCompletionSha256
                }
                session = [ordered]@{
                    path = $session
                    state = 'absent'
                    prior_inventory_sha256 = [string]$finalTree.sha256
                }
                tombstone = [ordered]@{
                    path = $sessionTombstonePath
                    state = 'absent'
                }
                fsv_lock = [ordered]@{ path = $fsvLock; state = 'absent' }
            }
            $completionPublication = Publish-NewAstroFsvProtocolRecord `
                -Path $completionRecordPath -Value $completion `
                -CodePrefix 'ASTRO_FSV_TERMINAL_PARTIAL_COMPLETION'
            $persistedCompletion = $completionPublication.value
            if ([string]$persistedCompletion.schema -cne
                    'astrolabe.native-fsv-terminal-partial-quarantine.completion.v1' -or
                [string]$persistedCompletion.phase -cne
                    'complete-session-and-tombstone-absent' -or
                [int]$persistedCompletion.issue -ne $Issue -or
                [string]$persistedCompletion.authorization.sha256 -cne
                    $authorizationSha256 -or
                [string]$persistedCompletion.retirement_completion.sha256 -cne
                    $retirementCompletionSha256 -or
                [string]$persistedCompletion.session.prior_inventory_sha256 -cne
                    [string]$finalTree.sha256 -or
                [string]$persistedCompletion.session.state -cne 'absent' -or
                [string]$persistedCompletion.tombstone.state -cne 'absent' -or
                [string]$persistedCompletion.fsv_lock.state -cne 'absent' -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$persistedCompletion.authorization.path),
                    $recoveryRecord,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$persistedCompletion.retirement_completion.path),
                    $retirementCompletionPath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$persistedCompletion.session.path),
                    $session,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$persistedCompletion.tombstone.path),
                    $sessionTombstonePath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$persistedCompletion.fsv_lock.path),
                    $fsvLock,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                (Test-AstroPathLongPath -LiteralPath $session) -or
                (Test-AstroPathLongPath -LiteralPath $sessionTombstonePath) -or
                (Test-AstroPathLongPath -LiteralPath $fsvLock)) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_COMPLETION_INVALID' `
                    'persisted completion does not prove session and FSV-lock absence' `
                    'preserve all recovery records and inspect physical state'
            }
            Move-AstroFileWriteThroughNoReplace `
                -Source $fsvLifecycleTransition -Destination $recoveryRecord
            if ((Test-AstroPathLongPath -LiteralPath $fsvLifecycleTransition) -or
                (File-Sha256 $recoveryRecord) -cne $authorizationSha256) {
                Fail-Astro 'ASTRO_FSV_TERMINAL_PARTIAL_AUTHORIZATION_ARCHIVE_FAILED' `
                    'canonical quarantine transition did not archive to the authorization record' `
                    'preserve transition/authorization/completion state and resume the same transaction'
            }
            Remove-EmptyEvidenceParents $session
            [ordered]@{
                operation = 'quarantine-terminal-partial'
                authorization_path = $recoveryRecord
                authorization_sha256 = $authorizationSha256
                completion_path = $completionRecordPath
                completion_sha256 = File-Sha256 $completionRecordPath
                authorization = $persistedAuthorization
                completion = $persistedCompletion
                before = [ordered]@{
                    session = $session
                    exists = $true
                    inventory_sha256 = [string]$finalTree.sha256
                }
                after = [ordered]@{ session = $session; exists = $false }
            } | ConvertTo-Json -Depth 28 -Compress | Write-Output
            }
            finally {
                try { Exit-AstroLauncherLockMutex $launcherCoordinationMutex }
                finally { Exit-AstroFsvLifecycleMutex $fsvLifecycleMutex }
            }
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
            if (Test-AstroPathLongPath -LiteralPath $recoveryRecord) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_RECORD_REUSE_REFUSED' "recovery record already exists: $recoveryRecord" `
                    'use one fresh append-only recovery record path for each terminal partial session'
            }
            if ([string]::IsNullOrWhiteSpace($LiveStatePath)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_LIVE_STATE_REQUIRED' 'LiveStatePath is required for Quarantine' `
                    'pass the exact live-state JSON published by native-fsv-run.ps1 for this session'
            }
            $liveStateFile = Assert-PathWithin $LiveStatePath $inspection.session_directory `
                'ASTRO_FSV_QUARANTINE_LIVE_STATE_ESCAPE' 'live-state path'
            if (-not (Test-AstroPathLongPath -LiteralPath $liveStateFile -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_LIVE_STATE_MISSING' "live-state file does not exist: $liveStateFile" `
                    'pristine never-run sessions use Abandon; preserve any unexplained nonpristine session'
            }
            Assert-NotReparseEntry $liveStateFile 'native FSV live-state file'
            try {
                $liveState =
                    Read-AstroUtf8FileLongPath $liveStateFile | ConvertFrom-Json
            }
            catch {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_LIVE_STATE_INVALID' "parse live-state '$liveStateFile' failed: $($_.Exception.Message)" `
                    'preserve the session and investigate its incomplete process provenance'
            }
            $liveSchemaSupported = [string]$liveState.schema -in @(
                'astrolabe.native-fsv-live.v2',
                'astrolabe.native-fsv-live.v3'
            )
            if (-not $liveSchemaSupported -or
                -not $liveState.PSObject.Properties['owners'] -or
                -not $liveState.owners.PSObject.Properties['launcher'] -or
                -not $liveState.owners.PSObject.Properties['runner'] -or
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
            $liveLauncherIdentity = Read-AstroFsvProcessIdentity `
                $liveState.owners.launcher `
                'ASTRO_FSV_QUARANTINE_OWNER_INVALID' `
                'runner live-state launcher identity'
            $liveRunnerIdentity = Read-AstroFsvProcessIdentity `
                $liveState.owners.runner `
                'ASTRO_FSV_QUARANTINE_OWNER_INVALID' `
                'runner live-state runner identity'
            if (-not (Test-AstroFsvIdentityEqual `
                    $inspection.owners.launcher $liveLauncherIdentity)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_OWNER_MISMATCH' `
                    'receipt and runner live-state launcher generations differ' `
                    'preserve the session and investigate the cross-lease provenance'
            }
            $ownerBindingList = New-Object System.Collections.Generic.List[object]
            foreach ($binding in @(
                New-AstroFsvOwnerBinding `
                    'launcher' 'artifact receipt' $inspection.owners.launcher
                New-AstroFsvOwnerBinding `
                    'promoter' 'artifact receipt' $inspection.owners.promoter
                New-AstroFsvOwnerBinding `
                    'launcher' 'runner live state' $liveLauncherIdentity
                New-AstroFsvOwnerBinding `
                    'runner' 'runner live state' $liveRunnerIdentity
            )) { $ownerBindingList.Add($binding) }
            if ([string]$liveState.schema -ceq 'astrolabe.native-fsv-live.v2') {
                if (-not $liveState.owners.PSObject.Properties['child']) {
                    Fail-Astro 'ASTRO_FSV_QUARANTINE_OWNER_INVALID' `
                        'v2 runner live state omits its child identity' `
                        'preserve the session and investigate incomplete process provenance'
                }
                $liveChildIdentity = Read-AstroFsvProcessIdentity `
                    $liveState.owners.child `
                    'ASTRO_FSV_QUARANTINE_OWNER_INVALID' `
                    'runner live-state child identity'
                $ownerBindingList.Add((New-AstroFsvOwnerBinding `
                            'child' 'runner live state' $liveChildIdentity))
            }
            else {
                if (-not $liveState.PSObject.Properties['resident_count'] -or
                    -not $liveState.PSObject.Properties['process_count'] -or
                    -not $liveState.owners.PSObject.Properties['processes']) {
                    Fail-Astro 'ASTRO_FSV_QUARANTINE_OWNER_INVALID' `
                        'v3 runner live state omits resident/process cardinality' `
                        'preserve the session and investigate incomplete process provenance'
                }
                $liveProcesses = Read-AstroFsvV3ProcessEntries `
                    $liveState.owners.processes ([int]$liveState.resident_count) `
                    ([int]$liveState.process_count) `
                    'ASTRO_FSV_QUARANTINE_OWNER_INVALID' `
                    'runner v3 live-state process set'
                Add-AstroFsvV3ProcessBindings $ownerBindingList $liveProcesses `
                    'runner live state'
            }
            $ownerBindings = [object[]]$ownerBindingList.ToArray()
            $initialOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_QUARANTINE' `
                    -Description 'terminal partial evidence session'
            )
            if ([string]::IsNullOrWhiteSpace($RunRecordPath)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_RUN_RECORD_PATH_REQUIRED' 'RunRecordPath is required for Quarantine' `
                    'pass the exact run-record path that the failed runner was required to publish'
            }
            $expectedRunRecord = Assert-PathWithin $RunRecordPath $inspection.session_directory `
                'ASTRO_FSV_QUARANTINE_RUN_RECORD_ESCAPE' 'expected run-record path'
            $runRecordState = 'missing'
            if (Test-AstroPathLongPath -LiteralPath $expectedRunRecord -PathType Leaf) {
                Assert-NotReparseEntry $expectedRunRecord 'native FSV run record'
                $runRecordState = 'invalid'
                try {
                    $candidateRecord =
                        Read-AstroUtf8FileLongPath $expectedRunRecord |
                            ConvertFrom-Json
                    $candidateProcessEnvelopeValid = $false
                    if ([string]$candidateRecord.schema -ceq
                            'astrolabe.native-fsv-run.v2') {
                        $candidateProcessEnvelopeValid =
                            $null -ne $candidateRecord.PSObject.Properties['process'] -and
                            $null -ne $candidateRecord.process.PSObject.Properties['identity']
                    }
                    elseif ([string]$candidateRecord.schema -ceq
                            'astrolabe.native-fsv-run.v3') {
                        try {
                            [void](Read-AstroFsvV3ProcessEntries `
                                $candidateRecord.processes `
                                ([int]$candidateRecord.resident_count) `
                                ([int]$candidateRecord.process_count) `
                                'ASTRO_FSV_QUARANTINE_CANDIDATE_INVALID' `
                                'candidate v3 run-record process set')
                            $candidateProcessEnvelopeValid = $true
                        }
                        catch { $candidateProcessEnvelopeValid = $false }
                    }
                    if ($candidateRecord.schema -in @(
                            'astrolabe.native-fsv-run.v2',
                            'astrolabe.native-fsv-run.v3'
                        ) -and $candidateProcessEnvelopeValid -and
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
            New-AstroDirectoryLongPath $recordParent | Out-Null
            Assert-NotReparseEntry $recordParent 'recovery record parent'
            $currentRepository = Get-RepoState -GitExe $gitExe -Workspace $workspace
            $finalOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_QUARANTINE' `
                    -Description 'terminal partial evidence session final authorization'
            )
            $record = [ordered]@{
                schema = 'astrolabe.native-fsv-recovery.v2'
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
                owners = [ordered]@{
                    identities = @($ownerBindings | ForEach-Object {
                            [ordered]@{
                                role = $_.Role
                                source = $_.Source
                                identity = $_.Identity
                            }
                        })
                    initial_probes = $initialOwnerProbes
                    final_probes = $finalOwnerProbes
                }
                failure = [ordered]@{
                    code = $ReasonCode
                    message = $ReasonMessage
                }
            }
            Write-NewDurableUtf8 $recoveryRecord ($record | ConvertTo-Json -Depth 20)
            $persistedRecord =
                Read-AstroUtf8FileLongPath $recoveryRecord | ConvertFrom-Json
            if ($persistedRecord.schema -ne 'astrolabe.native-fsv-recovery.v2' -or
                $persistedRecord.verdict -ne 'quarantined-unverified-run' -or
                [string]$persistedRecord.artifact.sha256 -cne [string]$inspection.sha256 -or
                [string]$persistedRecord.failure.code -cne $ReasonCode -or
                @($persistedRecord.source_of_truth.session_files).Count -ne $inventory.Count) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_RECORD_INVALID' `
                    "persisted recovery record readback does not bind the terminal session: $recoveryRecord" `
                    'preserve both session and record and investigate the durable-write mismatch'
            }
            Assert-AstroFsvPersistedOwnerEnvelope `
                -Owners $persistedRecord.owners `
                -ExpectedBindings $ownerBindings `
                -Code 'ASTRO_FSV_QUARANTINE_RECORD_INVALID' `
                -Description 'persisted recovery record'
            $recordHash = File-Sha256 $recoveryRecord
            $before = [ordered]@{
                session = $session
                exists = $true
                artifact_sha256 = $inspection.sha256
                file_count = $inventory.Count
                owners = $record.owners
            }
            Remove-AstroOrdinaryFlatDirectoryLongPath $session
            if (Test-AstroPathLongPath -LiteralPath $session) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_FAILED' "evidence session remains after quarantine: $session" `
                    'preserve the external recovery record and inspect open handles before retrying exact cleanup'
            }
            Remove-EmptyEvidenceParents $session
            [ordered]@{
                operation = 'quarantine'
                record_path = $recoveryRecord
                record_sha256 = $recordHash
                record = $persistedRecord
                before = $before
                after = [ordered]@{ session = $session; exists = $false }
            } | ConvertTo-Json -Depth 22 -Compress | Write-Output
        }
        'MigrateLegacy' {
            if ($Issue -le 0) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_ISSUE_INVALID' `
                    'Issue must be positive for legacy migration' `
                    'pass the exact driving GitHub issue number'
            }
            Assert-FsvLockAbsent $fsvLock
            $launcherProtocolState =
                Read-AstroLauncherLock -LockPath $launcherLockPath
            if ($launcherProtocolState.State -ne 'absent') {
                Fail-Astro 'ASTRO_FSV_MIGRATION_LAUNCHER_LOCK' `
                    "launcher protocol is '$($launcherProtocolState.State)'; legacy migration requires authoritative absence" `
                    'wait for or tracker-reclaim the exact launcher state before migration'
            }
            if ([string]::IsNullOrWhiteSpace($ReceiptPath)) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECEIPT_REQUIRED' `
                    'ReceiptPath is required for MigrateLegacy' `
                    'pass the exact legacy v1 receipt inside the staged session'
            }
            $legacyReceiptPath = Assert-PathWithin `
                $ReceiptPath $evidenceRoot `
                'ASTRO_FSV_MIGRATION_RECEIPT_ESCAPE' `
                'legacy receipt path'
            if (-not (Test-AstroPathLongPath `
                    -LiteralPath $legacyReceiptPath -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECEIPT_MISSING' `
                    "legacy receipt is absent: $legacyReceiptPath" `
                    'preserve surrounding state and pass the exact persisted receipt'
            }
            try {
                $legacyReceipt =
                    Read-AstroUtf8FileLongPath $legacyReceiptPath |
                        ConvertFrom-Json
            }
            catch {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECEIPT_INVALID' `
                    "legacy receipt parse failed: $($_.Exception.Message)" `
                    'preserve the session; malformed state is not migration-authorizing'
            }
            if ($legacyReceipt.schema -ne
                    'astrolabe.native-fsv-artifact.v1' -or
                [int]$legacyReceipt.issue -ne $Issue -or
                [string]$legacyReceipt.tree_sha -cnotmatch '^[0-9a-f]{40}$' -or
                [string]$legacyReceipt.artifact.sha256 -cnotmatch
                    '^[0-9a-f]{64}$' -or
                [string]$legacyReceipt.session_id -cnotmatch
                    '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECEIPT_INVALID' `
                    'receipt is not the exact supported legacy v1 shape/issue' `
                    'preserve the session; only valid v1 state has this explicit migration path'
            }
            $legacySession =
                [IO.Path]::GetFullPath((Split-Path -Parent $legacyReceiptPath))
            $expectedLegacySession = Join-Path (
                Join-Path (
                    Join-Path $evidenceRoot ([string]$legacyReceipt.tree_sha)
                ) ([string]$legacyReceipt.artifact.sha256)
            ) ([string]$legacyReceipt.session_id)
            if (-not [string]::Equals(
                    $legacySession,
                    [IO.Path]::GetFullPath($expectedLegacySession),
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECEIPT_INVALID' `
                    'legacy receipt path differs from its tree/hash/session identity' `
                    'preserve relocated or cross-session state for investigation'
            }
            Assert-NotReparseEntry $legacySession 'legacy evidence session'
            $legacyArtifact = Assert-PathWithin `
                ([string]$legacyReceipt.artifact.path) `
                $legacySession `
                'ASTRO_FSV_MIGRATION_ARTIFACT_ESCAPE' `
                'legacy artifact path'
            if (-not (Test-AstroPathLongPath `
                    -LiteralPath $legacyArtifact -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_ARTIFACT_MISSING' `
                    "legacy artifact is absent: $legacyArtifact" `
                    'preserve the session; incomplete legacy state is not migration-authorizing'
            }
            $legacyArtifactItem = Get-AstroFileInfoLongPath $legacyArtifact
            $legacyArtifactHash = File-Sha256 $legacyArtifact
            if ([uint64]$legacyArtifactItem.Length -ne
                    [uint64]$legacyReceipt.artifact.bytes -or
                $legacyArtifactHash -cne
                    [string]$legacyReceipt.artifact.sha256) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_ARTIFACT_DRIFT' `
                    'legacy artifact bytes differ from the receipt' `
                    'preserve the drifted session and investigate its writer'
            }
            $legacyPids =
                New-Object System.Collections.Generic.List[int]
            foreach ($field in @('launcher_pid', 'promoter_pid')) {
                $parsedPid = 0
                if (-not $legacyReceipt.PSObject.Properties[$field] -or
                    -not [int]::TryParse(
                        [string]$legacyReceipt.$field,
                        [Globalization.NumberStyles]::None,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [ref]$parsedPid
                    ) -or $parsedPid -le 0) {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_RECEIPT_INVALID' `
                        "legacy receipt $field is absent or invalid" `
                        'preserve the session; missing legacy numeric ownership cannot be inferred'
                }
                if (-not $legacyPids.Contains($parsedPid)) {
                    $legacyPids.Add($parsedPid)
                }
            }
            $legacySessionEntries =
                @(Get-AstroDirectoryEntriesLongPath $legacySession)
            $legacyControlPaths = @(
                $legacyReceiptPath,
                $legacyArtifact
            )
            $legacyAdditionalEntries = @(
                $legacySessionEntries |
                    Where-Object {
                        [IO.Path]::GetFullPath($_.FullName) -notin
                            $legacyControlPaths
                    }
            )
            if ($legacyAdditionalEntries.Count -gt 0) {
                if ([string]::IsNullOrWhiteSpace($RunRecordPath) -or
                    [string]::IsNullOrWhiteSpace($LiveStatePath)) {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_CONTROL_PATH_REQUIRED' `
                        'nonpristine legacy sessions require explicit RunRecordPath and LiveStatePath bindings' `
                        'pass the exact two v1 control records; ordinary JSON output is never inferred to be authority'
                }
                $legacyRunPath = Assert-PathWithin `
                    $RunRecordPath $legacySession `
                    'ASTRO_FSV_MIGRATION_CONTROL_PATH_ESCAPE' `
                    'legacy run-record path'
                $legacyLivePath = Assert-PathWithin `
                    $LiveStatePath $legacySession `
                    'ASTRO_FSV_MIGRATION_CONTROL_PATH_ESCAPE' `
                    'legacy live-state path'
                if (-not (Test-AstroPathLongPath `
                        -LiteralPath $legacyRunPath -PathType Leaf) -or
                    -not (Test-AstroPathLongPath `
                        -LiteralPath $legacyLivePath -PathType Leaf) -or
                    [string]::Equals(
                        $legacyRunPath,
                        $legacyLivePath,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    $legacyControlPaths -contains $legacyRunPath -or
                    $legacyControlPaths -contains $legacyLivePath) {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_CONTROL_PATH_INVALID' `
                        'legacy run/live control paths are absent, duplicate, or overlap receipt/artifact state' `
                        'preserve the session and pass two exact distinct persisted v1 control files'
                }
                try {
                    $legacyRun =
                        Read-AstroUtf8FileLongPath $legacyRunPath |
                        ConvertFrom-Json
                    $legacyLive =
                        Read-AstroUtf8FileLongPath $legacyLivePath |
                        ConvertFrom-Json
                }
                catch {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_SESSION_INVALID' `
                        "explicit legacy run/live control state is unreadable: $($_.Exception.Message)" `
                        'preserve malformed legacy state; migration requires a complete inventory'
                }
                if ($legacyRun.schema -ne 'astrolabe.native-fsv-run.v1' -or
                    $legacyLive.schema -ne
                        'astrolabe.native-fsv-live.v1' -or
                    -not $legacyRun.PSObject.Properties['runner'] -or
                    -not $legacyRun.PSObject.Properties['process'] -or
                    -not $legacyRun.PSObject.Properties['receipt_path'] -or
                    -not $legacyRun.PSObject.Properties['artifact'] -or
                    -not $legacyRun.artifact.PSObject.Properties['path'] -or
                    -not $legacyRun.artifact.PSObject.Properties['sha256'] -or
                    -not $legacyLive.PSObject.Properties['artifact'] -or
                    -not $legacyLive.artifact.PSObject.Properties['path'] -or
                    -not $legacyLive.artifact.PSObject.Properties['sha256'] -or
                    [int]$legacyRun.issue -ne $Issue -or
                    [int]$legacyLive.issue -ne $Issue -or
                    [string]$legacyRun.artifact.sha256 -cne
                        [string]$legacyReceipt.artifact.sha256 -or
                    [string]$legacyLive.artifact.sha256 -cne
                        [string]$legacyReceipt.artifact.sha256 -or
                    -not [string]::Equals(
                        [IO.Path]::GetFullPath(
                            [string]$legacyRun.receipt_path
                        ),
                        $legacyReceiptPath,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    -not [string]::Equals(
                        [IO.Path]::GetFullPath(
                            [string]$legacyRun.artifact.path
                        ),
                        $legacyArtifact,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    -not [string]::Equals(
                        [IO.Path]::GetFullPath(
                            [string]$legacyLive.artifact.path
                        ),
                        $legacyArtifact,
                        [StringComparison]::OrdinalIgnoreCase
                    )) {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_SESSION_INVALID' `
                        'explicit legacy run/live records are incomplete or not bound to the receipt/artifact' `
                        'preserve unknown, partial, or mixed-session state for investigation'
                }
                $pidValues = @(
                    $legacyLive.launcher_pid,
                    $legacyLive.runner_pid,
                    $legacyLive.child_pid,
                    $legacyRun.runner.pid,
                    $legacyRun.runner.launcher_pid,
                    $legacyRun.process.pid
                )
                if ($legacyRun.PSObject.Properties['launcher_lease']) {
                    $pidValues += @(
                        $legacyRun.launcher_lease.owner_pid
                    )
                }
                foreach ($value in @($pidValues)) {
                    $parsedPid = 0
                    if (-not [int]::TryParse(
                            [string]$value,
                            [Globalization.NumberStyles]::None,
                            [Globalization.CultureInfo]::InvariantCulture,
                            [ref]$parsedPid
                        ) -or $parsedPid -le 0) {
                        Fail-Astro 'ASTRO_FSV_MIGRATION_SESSION_INVALID' `
                            'legacy run/live owner PID is absent or invalid' `
                            'preserve incomplete legacy ownership state'
                    }
                    if (-not $legacyPids.Contains($parsedPid)) {
                        $legacyPids.Add($parsedPid)
                    }
                }
                if ([int]$legacyLive.launcher_pid -ne
                        [int]$legacyReceipt.launcher_pid -or
                    [int]$legacyRun.runner.launcher_pid -ne
                        [int]$legacyLive.launcher_pid -or
                    [int]$legacyRun.runner.pid -ne
                        [int]$legacyLive.runner_pid -or
                    [int]$legacyRun.process.pid -ne
                        [int]$legacyLive.child_pid -or
                    ($legacyRun.PSObject.Properties['launcher_lease'] -and
                        [int]$legacyRun.launcher_lease.owner_pid -ne
                            [int]$legacyLive.launcher_pid)) {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_SESSION_INVALID' `
                        'legacy receipt, live state, and run record disagree on numeric ownership' `
                        'preserve cross-generation or contradictory legacy state for investigation'
                }
            }
            $legacyInventory = @(Get-SessionFileInventory $legacySession)
            try {
                $legacyTree =
                    Get-AstroOrdinaryDirectoryTreeInventoryLongPath `
                        $legacySession
            }
            catch {
                Fail-Astro 'ASTRO_FSV_MIGRATION_INVENTORY_INVALID' `
                    "legacy session canonical inventory failed without mutation: $($_.Exception.Message)" `
                    'preserve every session byte and investigate the exact ordinary-tree state'
            }
            $legacyInventorySchema = [string]$legacyTree.schema
            $legacyInventoryEncoding = [string]$legacyTree.encoding
            $legacyInventorySha256 = [string]$legacyTree.sha256
            $legacyReceiptSha256 = File-Sha256 $legacyReceiptPath
            $initialLegacyProbes = foreach ($legacyPid in $legacyPids) {
                $probe =
                    Get-AstroProcessIdentityProbe -OwnerPid $legacyPid
                if ($probe.State -ceq 'unevaluable') {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_OWNER_UNEVALUABLE' `
                        "legacy numeric PID $legacyPid is unevaluable: $($probe.Error)" `
                        'preserve every session byte and retry only when PID state is readable'
                }
                if ($probe.State -cne 'absent') {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_PID_OCCUPIED' `
                        "legacy numeric PID $legacyPid is occupied; v1 cannot distinguish the original owner from reuse" `
                        'wait until every legacy numeric PID is completely absent'
                }
                [ordered]@{
                    pid = $legacyPid
                    state = 'absent'
                    observed_at_utc = [DateTime]::UtcNow.ToString('o')
                }
            }
            if ([string]::IsNullOrWhiteSpace($MigrationRecordPath)) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECORD_REQUIRED' `
                    'MigrationRecordPath is required for MigrateLegacy' `
                    "use a fresh JSON path below $migrationRoot"
            }
            $migrationRecord = Assert-PathWithin `
                $MigrationRecordPath $migrationRoot `
                'ASTRO_FSV_MIGRATION_RECORD_ESCAPE' `
                'legacy migration record path'
            if (Test-AstroPathLongPath -LiteralPath $migrationRecord) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECORD_REUSE_REFUSED' `
                    "migration record already exists: $migrationRecord" `
                    'use one fresh append-only record path per legacy session'
            }
            if ($ReasonCode -notmatch '^[A-Z][A-Z0-9_]{2,95}$' -or
                [string]::IsNullOrWhiteSpace($ReasonMessage)) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_REASON_INVALID' `
                    'MigrateLegacy requires a structured ReasonCode and nonblank ReasonMessage' `
                    'describe why this exact legacy session must be retired'
            }
            $tracker = Read-AstroFsvLegacyTrackerEvidence `
                -Url $TrackerCommentUrl `
                -ExpectedIssue $Issue `
                -ExpectedReceiptPath $legacyReceiptPath `
                -ExpectedReceiptSha256 $legacyReceiptSha256 `
                -ExpectedSessionDirectory $legacySession `
                -ExpectedInventorySchema $legacyInventorySchema `
                -ExpectedInventoryEncoding $legacyInventoryEncoding `
                -ExpectedInventoryEntryCount `
                    ([int]$legacyTree.entry_count) `
                -ExpectedInventoryCanonicalByteCount `
                    ([uint64]$legacyTree.canonical_bytes_length) `
                -ExpectedInventorySha256 $legacyInventorySha256 `
                -ExpectedNumericOwnerPids ([int[]]$legacyPids.ToArray()) `
                -ExpectedMigrationRecordPath $migrationRecord
            try {
                $finalLegacyTree =
                    Get-AstroOrdinaryDirectoryTreeInventoryLongPath `
                        $legacySession
            }
            catch {
                Fail-Astro 'ASTRO_FSV_MIGRATION_SESSION_DRIFT' `
                    "legacy session final canonical inventory failed without mutation: $($_.Exception.Message)" `
                    'preserve the session and post fresh evidence for its current exact tree'
            }
            if ([string]$finalLegacyTree.schema -cne
                    $legacyInventorySchema -or
                [string]$finalLegacyTree.encoding -cne
                    $legacyInventoryEncoding -or
                [string]$finalLegacyTree.sha256 -cne
                    $legacyInventorySha256 -or
                [uint64]$finalLegacyTree.canonical_bytes_length -ne
                    [uint64]$legacyTree.canonical_bytes_length -or
                [int]$finalLegacyTree.entry_count -ne
                    [int]$legacyTree.entry_count -or
                (File-Sha256 $legacyReceiptPath) -cne
                    $legacyReceiptSha256) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_SESSION_DRIFT' `
                    'legacy session inventory changed after tracker authorization' `
                    'preserve the session and post fresh evidence for its current bytes'
            }
            $finalLegacyProbes = foreach ($legacyPid in $legacyPids) {
                $probe =
                    Get-AstroProcessIdentityProbe -OwnerPid $legacyPid
                if ($probe.State -cne 'absent') {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_OWNER_CHANGED' `
                        "legacy numeric PID $legacyPid changed to '$($probe.State)' before removal" `
                        'preserve the session and repeat tracker authorization only after every numeric PID is absent'
                }
                [ordered]@{
                    pid = $legacyPid
                    state = 'absent'
                    observed_at_utc = [DateTime]::UtcNow.ToString('o')
                }
            }
            $recordParent = Split-Path -Parent $migrationRecord
            New-AstroDirectoryLongPath $recordParent | Out-Null
            Assert-NotReparseEntry $recordParent `
                'legacy migration record parent'
            $migration = [ordered]@{
                schema = 'astrolabe.native-fsv-legacy-migration.v2'
                verdict = 'legacy-session-removed-without-identity-inference'
                issue = $Issue
                recorded_at_utc = [DateTime]::UtcNow.ToString('o')
                receipt_path = $legacyReceiptPath
                receipt_sha256 = $legacyReceiptSha256
                session_directory = $legacySession
                inventory = $legacyInventory
                inventory_schema = $legacyInventorySchema
                inventory_encoding = $legacyInventoryEncoding
                inventory_entry_count = [int]$legacyTree.entry_count
                inventory_canonical_byte_count =
                    [uint64]$legacyTree.canonical_bytes_length
                inventory_sha256 = $legacyInventorySha256
                legacy_numeric_owner_pids =
                    [int[]]@($legacyPids | Sort-Object -Unique)
                initial_numeric_owner_probes = @($initialLegacyProbes)
                final_numeric_owner_probes = @($finalLegacyProbes)
                tracker = $tracker
                failure = [ordered]@{
                    code = $ReasonCode
                    message = $ReasonMessage
                }
            }
            Write-NewDurableUtf8 `
                $migrationRecord ($migration | ConvertTo-Json -Depth 22)
            $persistedMigration =
                Read-AstroUtf8FileLongPath $migrationRecord |
                    ConvertFrom-Json
            if ($persistedMigration.schema -ne
                    'astrolabe.native-fsv-legacy-migration.v2' -or
                [string]$persistedMigration.receipt_sha256 -cne
                    $legacyReceiptSha256 -or
                [string]$persistedMigration.inventory_schema -cne
                    $legacyInventorySchema -or
                [string]$persistedMigration.inventory_encoding -cne
                    $legacyInventoryEncoding -or
                [int]$persistedMigration.inventory_entry_count -ne
                    [int]$legacyTree.entry_count -or
                [uint64]$persistedMigration.inventory_canonical_byte_count -ne
                    [uint64]$legacyTree.canonical_bytes_length -or
                [string]$persistedMigration.inventory_sha256 -cne
                    $legacyInventorySha256 -or
                [string]$persistedMigration.tracker.url -cne
                    $TrackerCommentUrl) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECORD_INVALID' `
                    'persisted migration record does not bind the authorized legacy session' `
                    'preserve both session and external record for investigation'
            }
            $migrationRecordSha256 = File-Sha256 $migrationRecord
            Set-AstroFileReadOnlyLongPath `
                -LiteralPath $legacyArtifact -ReadOnly $false
            Remove-AstroOrdinaryFlatDirectoryLongPath $legacySession
            if (Test-AstroPathLongPath -LiteralPath $legacySession) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_REMOVE_FAILED' `
                    "legacy session remains after migration: $legacySession" `
                    'preserve the external record and inspect exact filesystem handles'
            }
            Remove-EmptyEvidenceParents $legacySession
            [ordered]@{
                operation = 'migrate-legacy'
                record_path = $migrationRecord
                record_sha256 = $migrationRecordSha256
                record = $persistedMigration
                before = [ordered]@{
                    session = $legacySession
                    exists = $true
                    receipt_sha256 = $legacyReceiptSha256
                    inventory_schema = $legacyInventorySchema
                    inventory_encoding = $legacyInventoryEncoding
                    inventory_entry_count = [int]$legacyTree.entry_count
                    inventory_canonical_byte_count =
                        [uint64]$legacyTree.canonical_bytes_length
                    inventory_sha256 = $legacyInventorySha256
                }
                after = [ordered]@{
                    session = $legacySession
                    exists = $false
                }
            } | ConvertTo-Json -Depth 24 -Compress | Write-Output
        }
        'Cleanup' {
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            Assert-FsvLockAbsent $fsvLock
            $launcherProtocolState =
                Read-AstroLauncherLock -LockPath $launcherLockPath
            if ($launcherProtocolState.State -ne 'absent') {
                Fail-Astro 'ASTRO_FSV_CLEANUP_LAUNCHER_LOCK' `
                    "launcher protocol is '$($launcherProtocolState.State)'; completed-session cleanup requires authoritative absence (transitions=$(@($launcherProtocolState.TransitionPaths) -join '; '), read_error=$($launcherProtocolState.ReadError), validation_error=$($launcherProtocolState.ValidationError))" `
                    'wait for the exact launcher generation to exit and finish its protocol cleanup'
            }
            if ([string]::IsNullOrWhiteSpace($RunRecordPath)) {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_REQUIRED' 'RunRecordPath is required for Cleanup' `
                    'pass the persisted run record written by native-fsv-run.ps1 after the real process exited'
            }
            $runRecord = Assert-PathWithin $RunRecordPath $inspection.session_directory `
                'ASTRO_FSV_RUN_RECORD_ESCAPE' 'run record path'
            if (-not (Test-AstroPathLongPath -LiteralPath $runRecord -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_MISSING' "run record does not exist: $runRecord" `
                    'complete the real staged-artifact run and persist its readback before cleanup'
            }
            try {
                $record = Read-AstroUtf8FileLongPath $runRecord | ConvertFrom-Json
            }
            catch {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_INVALID' "parse run record '$runRecord' failed: $($_.Exception.Message)" `
                    'preserve the evidence directory and investigate the incomplete run'
            }
            if (-not $record.PSObject.Properties['launcher'] -or
                -not $record.PSObject.Properties['runner'] -or
                -not $record.PSObject.Properties['artifact'] -or
                -not $record.artifact.PSObject.Properties['path'] -or
                -not $record.artifact.PSObject.Properties['sha256'] -or
                -not $record.PSObject.Properties['receipt_path']) {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_INVALID' `
                    "run record '$runRecord' omits required exact ownership or artifact binding" `
                    'preserve the evidence directory and investigate the incomplete run'
            }
            $supportedRunSchema = [string]$record.schema -in @(
                'astrolabe.native-fsv-run.v2',
                'astrolabe.native-fsv-run.v3'
            )
            $processEnvelopeValid = if ([string]$record.schema -ceq
                    'astrolabe.native-fsv-run.v2') {
                $record.PSObject.Properties['process'] -and
                    $record.process.PSObject.Properties['identity']
            }
            elseif ([string]$record.schema -ceq
                    'astrolabe.native-fsv-run.v3') {
                $record.PSObject.Properties['resident_count'] -and
                    $record.PSObject.Properties['process_count'] -and
                    $record.PSObject.Properties['processes']
            }
            else { $false }
            if (-not $supportedRunSchema -or -not $processEnvelopeValid -or
                [int]$record.issue -ne [int]$inspection.issue -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$record.receipt_path), $receiptState.Path, [StringComparison]::OrdinalIgnoreCase) -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$record.artifact.path), $inspection.artifact_path, [StringComparison]::OrdinalIgnoreCase) -or
                [string]$record.artifact.sha256 -cne [string]$inspection.sha256) {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_INVALID' "run record '$runRecord' is not bound to the staged artifact" `
                    'preserve the evidence directory and investigate the provenance mismatch'
            }
            $ownerBindings = @(
                Get-AstroFsvSessionOwnerBindings `
                    -ReceiptState $receiptState `
                    -Inspection $inspection `
                    -RunRecordPath $runRecord `
                    -RunRecord $record
            )
            $initialOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_CLEANUP' `
                    -Description 'completed evidence session'
            )
            $session = [IO.Path]::GetFullPath($inspection.session_directory)
            try {
                $initialTree =
                    Get-AstroOrdinaryDirectoryTreeInventoryLongPath $session
            }
            catch {
                Fail-Astro 'ASTRO_FSV_CLEANUP_TREE_INVALID' `
                    "completed evidence tree preflight failed without mutation: $($_.Exception.Message)" `
                    'preserve every session byte; remove reparses/foreign writers only through an explicitly authorized recovery lifecycle'
            }
            $finalOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_CLEANUP' `
                    -Description 'completed evidence session final authorization'
            )
            try {
                $finalTree =
                    Get-AstroOrdinaryDirectoryTreeInventoryLongPath $session
            }
            catch {
                Fail-Astro 'ASTRO_FSV_CLEANUP_TREE_INVALID' `
                    "completed evidence tree final preflight failed without mutation: $($_.Exception.Message)" `
                    'preserve every session byte and investigate the exact filesystem state before retrying'
            }
            if ([string]$initialTree.schema -cne
                    [string]$finalTree.schema -or
                [string]$initialTree.encoding -cne
                    [string]$finalTree.encoding -or
                [string]$initialTree.sha256 -cne
                    [string]$finalTree.sha256 -or
                [uint64]$initialTree.canonical_bytes_length -ne
                    [uint64]$finalTree.canonical_bytes_length -or
                [int]$initialTree.entry_count -ne
                    [int]$finalTree.entry_count) {
                Fail-Astro 'ASTRO_FSV_CLEANUP_TREE_DRIFT' `
                    "completed evidence tree changed between authorization reads (initial_schema=$($initialTree.schema), final_schema=$($finalTree.schema), initial_encoding=$($initialTree.encoding), final_encoding=$($finalTree.encoding), initial_canonical_bytes=$($initialTree.canonical_bytes_length), final_canonical_bytes=$($finalTree.canonical_bytes_length), initial_sha256=$($initialTree.sha256), final_sha256=$($finalTree.sha256), initial_entries=$($initialTree.entry_count), final_entries=$($finalTree.entry_count))" `
                    'preserve every session byte; stop the writer and retry only after the exact tree is stable'
            }
            $before = [ordered]@{
                session = $session
                exists = Test-AstroPathLongPath -LiteralPath $session
                artifact_sha256 = $inspection.sha256
                tree = [ordered]@{
                    schema = [string]$finalTree.schema
                    encoding = [string]$finalTree.encoding
                    entry_count = [int]$finalTree.entry_count
                    canonical_byte_count =
                        [uint64]$finalTree.canonical_bytes_length
                    inventory_sha256 = [string]$finalTree.sha256
                }
                owners = [ordered]@{
                    identities = @($ownerBindings | ForEach-Object {
                            [ordered]@{
                                role = $_.Role
                                source = $_.Source
                                identity = $_.Identity
                            }
                        })
                    initial_probes = $initialOwnerProbes
                    final_probes = $finalOwnerProbes
                }
            }
            try {
                Remove-AstroOrdinaryDirectoryTreeLongPath `
                    -LiteralPath $session `
                    -ExpectedInventorySchema ([string]$finalTree.schema) `
                    -ExpectedInventoryEncoding ([string]$finalTree.encoding) `
                    -ExpectedInventorySha256 ([string]$finalTree.sha256)
            }
            catch {
                Fail-Astro 'ASTRO_FSV_CLEANUP_TREE_DELETE_FAILED' `
                    "exact completed evidence-tree deletion failed: $($_.Exception.Message)" `
                    'preserve all remaining state; inspect the exact error and retry Cleanup only after any foreign handle or namespace drift is resolved'
            }
            if (Test-AstroPathLongPath -LiteralPath $session) {
                Fail-Astro 'ASTRO_FSV_CLEANUP_FAILED' "evidence session remains after cleanup: $session" `
                    'inspect open handles and retry only after every exact owner generation is dead'
            }
            Remove-EmptyEvidenceParents $session
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
