<#
.SYNOPSIS
    Explicit hash-bound reconciliation transaction for one legacy CBM store.

.DESCRIPTION
    The source DB/WAL/SHM family is opened by exact Windows handles that deny
    writers and namespace changes, hashed, and renamed without replacement into
    a tracker-bound archive directory.  Append-only transition records and
    independent post-rename identity/hash readback make partial completion
    diagnosable.  Only after the legacy source paths are proven absent is the
    supplied real codebase-memory binary allowed to index the canonical source
    repository under the explicit stable project alias.

    ArchiveAliasAgainstCanonical instead requires an already accepted,
    root-derived canonical family. It verifies and hashes both families,
    requires the real list_projects surface to report exactly one canonical
    project plus one exact legacy identity conflict, archives only the legacy
    family, and then independently proves the canonical family and discovery
    state unchanged through an exact FILE_ID/length/hash release-query-reacquire
    chain. ResumeReindex
    revalidates a completed immutable archive and its hash-linked journal, then
    creates one append-only attempt without repeating or reversing the archive
    transition.

    This command never upgrades, deletes, or silently rebuilds a legacy store in
    place.  A failed archive or reindex leaves its transaction directory and
    exact fault record intact for investigation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$Issue,

    [Parameter(Mandatory)]
    [ValidateSet(
        'ArchiveAndReindex',
        'ArchiveAliasAgainstCanonical',
        'ResumeReindex',
        'RecoverInterruptedResume'
    )]
    [string]$Operation,

    [Parameter(Mandatory)]
    [string]$LegacyDbPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedDbSha256,

    [ValidatePattern('^$|^[0-9a-fA-F]{64}$')]
    [string]$ExpectedCanonicalDbSha256 = '',

    [Parameter(Mandatory)]
    [string]$RepositoryPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^(?!\.)(?!.*\.\.)[A-Za-z0-9_.-]+$')]
    [string]$Project,

    [Parameter(Mandatory)]
    [string]$BinaryPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedBinarySha256,

    [Parameter(Mandatory)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$ExpectedSchemaVersion,

    [ValidateRange(60, 86400)]
    [int]$ReindexTimeoutSeconds = 14400,

    [string]$InterruptedAttemptPrefix = '',

    [string]$ExpectedInterruptedIntentSha256 = '',

    [string]$ExpectedJournalTailSha256 = '',

    [string]$LauncherRecoveryCompletionPath = '',

    [string]$ExpectedLauncherRecoveryCompletionSha256 = '',

    [string]$RecoveryTrackerCommentUrl = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Throw-CbmMigrationError {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Remediation
    )
    throw "CBM_STORE_MIGRATION[$Code]: {code=$Code; message=$Message; remediation=$Remediation}"
}

if (-not $IsWindows) {
    Throw-CbmMigrationError `
        -Code 'CBM_STORE_MIGRATION_WINDOWS_REQUIRED' `
        -Message 'exact handle-bound store-family archival is implemented for native Windows' `
        -Remediation 'run this transaction from the canonical native Windows checkout'
}

$nativeSource = @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class CbmStoreMigrationNative {
    const uint GENERIC_READ = 0x80000000;
    const uint DELETE = 0x00010000;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint OPEN_EXISTING = 3;
    const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
    const int FILE_RENAME_INFO_CLASS = 3;
    const uint MOVEFILE_WRITE_THROUGH = 0x00000008;

    [StructLayout(LayoutKind.Sequential)]
    struct FILETIME { public uint Low; public uint High; }

    [StructLayout(LayoutKind.Sequential)]
    struct BY_HANDLE_FILE_INFORMATION {
        public uint Attributes;
        public FILETIME CreationTime;
        public FILETIME LastAccessTime;
        public FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle file,
        out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle file,
        StringBuilder path, uint chars, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle file, int cls,
        IntPtr info, uint bytes);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool MoveFileExW(string source, string destination, uint flags);

    static string Extended(string path) {
        string full = Path.GetFullPath(path);
        if (full.StartsWith("\\\\?\\", StringComparison.Ordinal)) return full;
        if (full.StartsWith("\\\\", StringComparison.Ordinal))
            return "\\\\?\\UNC\\" + full.Substring(2);
        return "\\\\?\\" + full;
    }

    public static string Normal(string path) {
        if (path.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
            return "\\\\" + path.Substring(8);
        if (path.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase))
            return path.Substring(4);
        return path;
    }

    public static SafeFileHandle OpenGuard(string path) {
        SafeFileHandle handle = CreateFileW(Extended(path), GENERIC_READ | DELETE,
            FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN,
            IntPtr.Zero);
        if (handle.IsInvalid) {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error,
                "exclusive exact store-family handle open failed; native_error=" + error);
        }
        return handle;
    }

    public static string FinalPath(SafeFileHandle handle) {
        StringBuilder buffer = new StringBuilder(32768);
        uint chars = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (chars == 0 || chars >= (uint)buffer.Capacity)
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "GetFinalPathNameByHandleW failed");
        return Normal(buffer.ToString());
    }

    public static string FileId(SafeFileHandle handle) {
        BY_HANDLE_FILE_INFORMATION info;
        if (!GetFileInformationByHandle(handle, out info))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "GetFileInformationByHandle failed");
        ulong index = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
        return info.VolumeSerialNumber.ToString("x8") + ":" + index.ToString("x16");
    }

    public static void RenameNoReplace(SafeFileHandle handle, string destination) {
        byte[] name = Encoding.Unicode.GetBytes(Extended(destination));
        int rootOffset = IntPtr.Size == 8 ? 8 : 4;
        int lengthOffset = rootOffset + IntPtr.Size;
        int nameOffset = lengthOffset + 4;
        int raw = checked(nameOffset + name.Length + 2);
        int size = checked(((raw + IntPtr.Size - 1) / IntPtr.Size) * IntPtr.Size);
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try {
            for (int i = 0; i < size; i++) Marshal.WriteByte(buffer, i, 0);
            Marshal.WriteInt32(buffer, 0, 0);
            Marshal.WriteIntPtr(buffer, rootOffset, IntPtr.Zero);
            Marshal.WriteInt32(buffer, lengthOffset, name.Length);
            Marshal.Copy(name, 0, IntPtr.Add(buffer, nameOffset), name.Length);
            if (!SetFileInformationByHandle(handle, FILE_RENAME_INFO_CLASS,
                                             buffer, (uint)size)) {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error,
                    "exact handle-bound no-replace archive rename failed; native_error=" + error);
            }
        } finally {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static void PublishNoReplace(string source, string destination) {
        if (!MoveFileExW(Extended(source), Extended(destination), MOVEFILE_WRITE_THROUGH)) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "durable no-replace record publication failed; native_error=" + error);
        }
    }
}
'@

$script:nativeInteropReady = $false

function Write-InitialDurableJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth 12 -Compress)
    )
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::Read)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Initialize-CbmMigrationNative {
    param(
        [Parameter(Mandatory)][string]$TransactionPath,
        [Parameter(Mandatory)][string]$CompilerScope,
        [string]$RecordPrefix = 'compiler'
    )
    [IO.Directory]::CreateDirectory($CompilerScope) | Out-Null
    $owner = Get-Process -Id $PID -ErrorAction Stop
    $identity = [ordered]@{
        pid = $PID
        process_start_utc_ticks = $owner.StartTime.ToUniversalTime().Ticks
    }
    $intentPath = [IO.Path]::Combine($TransactionPath, "$RecordPrefix-intent.json")
    Write-InitialDurableJson -Path $intentPath -Value ([ordered]@{
        schema = 1
        issue = $Issue
        purpose = 'compile Win32 exact-handle migration interop'
        owner = $identity
        compiler_scope = $CompilerScope
        source_sha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                [Text.UTF8Encoding]::new($false).GetBytes($nativeSource)
            )
        ).ToLowerInvariant()
        created_utc = [DateTime]::UtcNow.ToString('o')
    })

    $savedTemp = $env:TEMP
    $savedTmp = $env:TMP
    $savedTmpDir = $env:TMPDIR
    try {
        $env:TEMP = $CompilerScope
        $env:TMP = $CompilerScope
        $env:TMPDIR = $CompilerScope
        Add-Type -TypeDefinition $nativeSource -Language CSharp
        $script:nativeInteropReady = $true
    }
    catch {
        Write-InitialDurableJson `
            -Path ([IO.Path]::Combine($TransactionPath, "$RecordPrefix-fault.json")) `
            -Value ([ordered]@{
                schema = 1
                issue = $Issue
                owner = $identity
                compiler_scope = $CompilerScope
                fault_utc = [DateTime]::UtcNow.ToString('o')
                message = $_.Exception.Message
                remediation = 'preserve the transaction and compiler scope; repair the native interop compiler failure before retrying'
            })
        throw
    }
    finally {
        $env:TEMP = $savedTemp
        $env:TMP = $savedTmp
        $env:TMPDIR = $savedTmpDir
    }

    $inventory = @(Get-ChildItem -LiteralPath $CompilerScope -Recurse -Force -File |
        Sort-Object FullName | ForEach-Object {
            [ordered]@{
                relative_path = [IO.Path]::GetRelativePath($CompilerScope, $_.FullName)
                length = $_.Length
                sha256 = Get-FileSha256 -Path $_.FullName
            }
        })
    Write-InitialDurableJson `
        -Path ([IO.Path]::Combine($TransactionPath, "$RecordPrefix-completion.json")) `
        -Value ([ordered]@{
            schema = 1
            issue = $Issue
            owner = $identity
            compiler_scope = $CompilerScope
            completed_utc = [DateTime]::UtcNow.ToString('o')
            inventory = $inventory
            native_interop_ready = $true
        })
}

function Get-CanonicalExistingPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('File', 'Directory')][string]$Kind
    )
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
    catch {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_INPUT_UNRESOLVABLE' `
            -Message "$Kind input is absent or unreadable: $Path; detail=$($_.Exception.Message)" `
            -Remediation 'pass an existing exact path and retry without changing archived state'
    }
    if ($Kind -eq 'File' -and -not ($item -is [IO.FileInfo])) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_NOT_FILE' `
            -Message "path is not a file: $Path" -Remediation 'pass the exact legacy DB or binary file'
    }
    if ($Kind -eq 'Directory' -and -not ($item -is [IO.DirectoryInfo])) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_NOT_DIRECTORY' `
            -Message "path is not a directory: $Path" -Remediation 'pass the canonical repository directory'
    }
    return [IO.Path]::GetFullPath($item.FullName).TrimEnd('\', '/')
}

function Get-FileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read -bor [IO.FileShare]::Delete
    )
    try {
        $digest = [Security.Cryptography.SHA256]::HashData($stream)
        return [Convert]::ToHexString($digest).ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
    }
}

function New-FamilyGuardRecord {
    param([Parameter(Mandatory)][string]$Path)
    $handle = [CbmStoreMigrationNative]::OpenGuard($Path)
    try {
        $final = [IO.Path]::GetFullPath([CbmStoreMigrationNative]::FinalPath($handle))
        if (-not [string]::Equals($final, [IO.Path]::GetFullPath($Path),
                                 [StringComparison]::OrdinalIgnoreCase)) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_SOURCE_PATH_DRIFT' `
                -Message "retained source path changed: expected=$Path observed=$final" `
                -Remediation 'preserve every path and investigate namespace drift'
        }
        return [pscustomobject]@{
            SourcePath = $Path
            Handle = $handle
            FileId = [CbmStoreMigrationNative]::FileId($handle)
            Length = (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).Length
            Sha256 = Get-FileSha256 -Path $Path
        }
    }
    catch {
        $handle.Dispose()
        throw
    }
}

function Write-DurableUtf8 {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )
    if (Test-Path -LiteralPath $Path) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECORD_EXISTS' `
            -Message "durable record already exists: $Path" `
            -Remediation 'inspect the existing transaction; never overwrite migration evidence'
    }
    $scratch = "$Path.scratch-$PID-$([Guid]::NewGuid().ToString('N'))"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
    $stream = [IO.File]::Open($scratch, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::Read)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    [CbmStoreMigrationNative]::PublishNoReplace($scratch, $Path)
}

function Write-DurableJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )
    Write-DurableUtf8 -Path $Path -Text ($Value | ConvertTo-Json -Depth 12 -Compress)
}

function Add-JournalRecord {
    param(
        [Parameter(Mandatory)][string]$JournalPath,
        [Parameter(Mandatory)][string]$PreviousSha256,
        [Parameter(Mandatory)][string]$Event,
        [Parameter(Mandatory)]$Data
    )
    $payload = [ordered]@{
        schema = 1
        previous_record_sha256 = $PreviousSha256
        event = $Event
        utc = [DateTime]::UtcNow.ToString('o')
        data = $Data
    }
    $payloadText = $payload | ConvertTo-Json -Depth 12 -Compress
    $recordSha = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($payloadText))
    ).ToLowerInvariant()
    $record = [ordered]@{ payload = $payload; payload_sha256 = $recordSha }
    $line = ($record | ConvertTo-Json -Depth 14 -Compress) + "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($line)
    $stream = [IO.File]::Open($JournalPath, [IO.FileMode]::Append, [IO.FileAccess]::Write,
        [IO.FileShare]::Read)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    return $recordSha
}

function Get-ValidatedJournal {
    param([Parameter(Mandatory)][string]$JournalPath)
    if (-not (Test-Path -LiteralPath $JournalPath -PathType Leaf)) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_JOURNAL_MISSING' `
            -Message "transaction journal is absent: $JournalPath" `
            -Remediation 'preserve the transaction; resume requires the complete original hash chain'
    }
    $lines = @([IO.File]::ReadAllLines($JournalPath) | Where-Object { $_.Length -gt 0 })
    if ($lines.Count -eq 0) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_JOURNAL_EMPTY' `
            -Message "transaction journal has no records: $JournalPath" `
            -Remediation 'preserve the transaction and investigate missing durable transition records'
    }
    $records = [Collections.Generic.List[object]]::new()
    $previous = '0' * 64
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $document = $null
        try {
            $document = [Text.Json.JsonDocument]::Parse($lines[$i])
            $record = $lines[$i] | ConvertFrom-Json -Depth 30
        }
        catch {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_JOURNAL_INVALID' `
                -Message "journal record $i is not valid JSON: $($_.Exception.Message)" `
                -Remediation 'preserve the transaction and investigate journal corruption'
        }
        if ($null -eq $record.payload -or
            [string]$record.payload.previous_record_sha256 -cne $previous -or
            [string]$record.payload_sha256 -cnotmatch '^[0-9a-f]{64}$') {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_JOURNAL_CHAIN_INVALID' `
                -Message "journal record $i does not bind the preceding record" `
                -Remediation 'preserve the transaction and compare the append-only journal to its issue evidence'
        }
        $payloadText = $document.RootElement.GetProperty('payload').GetRawText()
        $computed = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                [Text.UTF8Encoding]::new($false).GetBytes($payloadText)
            )
        ).ToLowerInvariant()
        if ($computed -cne [string]$record.payload_sha256) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_JOURNAL_HASH_INVALID' `
                -Message "journal record $i hash=$($record.payload_sha256) computed=$computed" `
                -Remediation 'preserve the transaction and investigate journal byte or schema drift'
        }
        $document.Dispose()
        $records.Add($record)
        $previous = $computed
    }
    return [pscustomobject]@{ Records = @($records); TailSha256 = $previous }
}

function Read-CbmMigrationJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Purpose
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_RECORD_MISSING' `
            -Message "$Purpose is absent: $Path" `
            -Remediation 'preserve the transaction and pass only the exact immutable recovery evidence'
    }
    try {
        return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -Depth 100
    }
    catch {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_RECORD_INVALID' `
            -Message "$Purpose is not valid JSON: $Path; detail=$($_.Exception.Message)" `
            -Remediation 'preserve the exact bytes and investigate the malformed recovery evidence'
    }
}

function Read-CbmRecoveryTrackerEvidence {
    param(
        [Parameter(Mandatory)][string]$CommentUrl,
        [Parameter(Mandatory)][int]$OwningIssue,
        [Parameter(Mandatory)][string]$ExpectedEvidenceLine
    )
    $pattern = '^https://github\.com/ChrisRoyse/Astrolabe/issues/' +
        [Regex]::Escape([string]$OwningIssue) + '#issuecomment-(?<id>[1-9][0-9]*)$'
    if ($CommentUrl -cnotmatch $pattern) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_TRACKER_URL_INVALID' `
            -Message "tracker URL is not an exact comment on owning issue #$OwningIssue`: $CommentUrl" `
            -Remediation 'post the exact recovery marker on the owning migration issue and pass its canonical URL'
    }
    [long]$commentId = $Matches['id']
    $gh = Get-Command gh.exe -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $gh) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_GH_MISSING' `
            -Message 'gh.exe is unavailable for the mandatory independent tracker read' `
            -Remediation 'install and authenticate GitHub CLI, then retry without changing migration state'
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $gh.Source
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.ArgumentList.Add('api')
    $start.ArgumentList.Add("repos/ChrisRoyse/Astrolabe/issues/comments/$commentId")
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_GH_START_FAILED' `
            -Message "could not start gh.exe for tracker comment $commentId" `
            -Remediation 'inspect GitHub CLI execution policy and retry without changing migration state'
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(60000)) {
        try {
            $process.Kill($true)
            $process.WaitForExit()
        }
        catch {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_GH_TIMEOUT_UNTERMINATED' `
                -Message "tracker read exceeded 60000 ms and owned gh process could not be terminated: pid=$($process.Id); detail=$($_.Exception.Message)" `
                -Remediation 'preserve migration state and inspect the exact owned GitHub CLI process generation'
        }
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_GH_TIMEOUT' `
            -Message "tracker read exceeded 60000 ms: comment=$commentId" `
            -Remediation 'preserve migration state and restore bounded GitHub API access before retrying'
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_GH_FAILED' `
            -Message "gh api failed for tracker comment $commentId (exit=$($process.ExitCode)): $($stderr.Trim())" `
            -Remediation 'restore authenticated GitHub access and retry without changing migration state'
    }
    try {
        $comment = $stdout | ConvertFrom-Json -Depth 30
    }
    catch {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_TRACKER_INVALID' `
            -Message "GitHub comment response is not valid JSON: $($_.Exception.Message)" `
            -Remediation 'preserve migration state and investigate the GitHub API response'
    }
    $expectedApiIssue = "https://api.github.com/repos/ChrisRoyse/Astrolabe/issues/$OwningIssue"
    if ([long]$comment.id -ne $commentId -or [string]$comment.html_url -cne $CommentUrl -or
        [string]$comment.issue_url -cne $expectedApiIssue -or
        [string]$comment.user.login -cne 'ChrisRoyse' -or
        [string]$comment.author_association -cne 'OWNER') {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_TRACKER_IDENTITY_MISMATCH' `
            -Message 'tracker response does not bind the exact repository owner, issue, comment id, and canonical URL' `
            -Remediation 'use one owner-authored comment on the owning migration issue'
    }
    $markerPrefix = 'CBM_STORE_MIGRATION_INTERRUPTION_RECOVERY '
    $markerLines = @(([string]$comment.body -split "`r?`n") | Where-Object {
        $_.StartsWith($markerPrefix, [StringComparison]::Ordinal)
    })
    if ($markerLines.Count -ne 1 -or $markerLines[0] -cne $ExpectedEvidenceLine) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_TRACKER_EVIDENCE_MISMATCH' `
            -Message "tracker comment must contain exactly one byte-exact recovery marker; found=$($markerLines.Count)" `
            -Remediation 'post the generated exact marker without editing or duplicating it'
    }
    $bodyBytes = [Text.UTF8Encoding]::new($false).GetBytes([string]$comment.body)
    return [pscustomobject]@{
        Url = $CommentUrl
        Id = $commentId
        UpdatedAt = [string]$comment.updated_at
        BodySha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($bodyBytes)
        ).ToLowerInvariant()
    }
}

function Assert-CbmRecoveredAttemptTerminal {
    param(
        [Parameter(Mandatory)][string]$TransactionPath,
        [Parameter(Mandatory)][string]$AttemptPrefix,
        [Parameter(Mandatory)][string]$IntentSha256,
        [Parameter(Mandatory)]$JournalState
    )
    $authorizationPath = [IO.Path]::Combine(
        $TransactionPath, "$AttemptPrefix-interruption-recovery.authorization.json")
    $faultPath = [IO.Path]::Combine($TransactionPath, "$AttemptPrefix-fault.json")
    $completionPath = [IO.Path]::Combine(
        $TransactionPath, "$AttemptPrefix-interruption-recovery.completion.json")
    $authorization = Read-CbmMigrationJson -Path $authorizationPath `
        -Purpose "$AttemptPrefix recovery authorization"
    $fault = Read-CbmMigrationJson -Path $faultPath -Purpose "$AttemptPrefix recovered fault"
    $completion = Read-CbmMigrationJson -Path $completionPath `
        -Purpose "$AttemptPrefix recovery completion"
    $authorizationSha = Get-FileSha256 -Path $authorizationPath
    $faultSha = Get-FileSha256 -Path $faultPath
    if ($authorization.schema -ne 1 -or $authorization.status -cne 'authorized' -or
        $authorization.issue -ne $Issue -or $authorization.attempt_prefix -cne $AttemptPrefix -or
        [string]$authorization.intent_sha256 -cne $IntentSha256 -or
        $fault.schema -ne 1 -or $fault.status -cne 'fault' -or $fault.issue -ne $Issue -or
        $fault.fault_kind -cne 'interrupted_resume_recovered' -or
        $fault.attempt_prefix -cne $AttemptPrefix -or
        [string]$fault.intent_sha256 -cne $IntentSha256 -or
        [string]$fault.recovery_authorization_sha256 -cne $authorizationSha -or
        [string]$fault.launcher_recovery_completion_sha256 -cne
            [string]$authorization.launcher_recovery_completion_sha256 -or
        [string]$fault.migration_script_sha256 -cne
            [string]$authorization.migration_script_sha256 -or
        [string]$fault.launcher_lock_helper_sha256 -cne
            [string]$authorization.launcher_lock_helper_sha256 -or
        $completion.schema -ne 1 -or $completion.status -cne 'interruption_recovered' -or
        $completion.issue -ne $Issue -or $completion.attempt_prefix -cne $AttemptPrefix -or
        $completion.transaction_path -cne $TransactionPath -or
        [string]$completion.intent_sha256 -cne $IntentSha256 -or
        [string]$completion.recovery_authorization_sha256 -cne $authorizationSha -or
        [string]$completion.recovered_fault_sha256 -cne $faultSha -or
        [string]$completion.launcher_recovery_completion_sha256 -cne
            [string]$authorization.launcher_recovery_completion_sha256 -or
        [string]$completion.migration_script_sha256 -cne
            [string]$authorization.migration_script_sha256 -or
        [string]$completion.launcher_lock_helper_sha256 -cne
            [string]$authorization.launcher_lock_helper_sha256) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_TERMINAL_INVALID' `
            -Message "$AttemptPrefix recovery authorization, fault, and completion do not cross-bind exactly" `
            -Remediation 'preserve every record and investigate the interrupted recovery protocol'
    }
    $matches = @($JournalState.Records | Where-Object {
        $_.payload.event -ceq 'resume_interruption_recovered' -and
        $_.payload.data.attempt_prefix -ceq $AttemptPrefix -and
        $_.payload.data.intent_sha256 -ceq $IntentSha256 -and
        $_.payload.data.recovery_authorization_sha256 -ceq $authorizationSha -and
        $_.payload.data.recovered_fault_sha256 -ceq $faultSha -and
        $_.payload.data.launcher_recovery_completion_sha256 -ceq
            [string]$authorization.launcher_recovery_completion_sha256 -and
        $_.payload.data.migration_script_sha256 -ceq
            [string]$authorization.migration_script_sha256 -and
        $_.payload.data.launcher_lock_helper_sha256 -ceq
            [string]$authorization.launcher_lock_helper_sha256
    })
    if ($matches.Count -ne 1 -or
        [string]$completion.final_journal_record_sha256 -cne
            [string]$matches[0].payload_sha256) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_JOURNAL_UNBOUND' `
            -Message "$AttemptPrefix recovery terminal records are not bound by exactly one journal event" `
            -Remediation 'preserve the transaction and investigate the interrupted recovery journal phase'
    }
}

function Write-CbmRecoveryDurableJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )
    if (Test-Path -LiteralPath $Path) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_RECORD_EXISTS' `
            -Message "recovery record already exists: $Path" `
            -Remediation 'read and validate the immutable existing phase record; never overwrite it'
    }
    $scratch = "$Path.scratch-$PID-$([Guid]::NewGuid().ToString('N'))"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth 20 -Compress)
    )
    $stream = [IO.File]::Open($scratch, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::Read)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    Move-AstroFileWriteThroughNoReplace -Source $scratch -Destination $Path
}

function Invoke-CbmInterruptedResumeRecovery {
    param(
        [Parameter(Mandatory)][string]$TransactionPath,
        [Parameter(Mandatory)][string]$JournalPath,
        [Parameter(Mandatory)]$JournalState,
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string[]]$TargetFamilyPaths
    )
    if ($InterruptedAttemptPrefix -cnotmatch '^resume-(?<number>[0-9]{3})$' -or
        [int]$Matches['number'] -lt 1 -or
        $ExpectedInterruptedIntentSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
        $ExpectedJournalTailSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
        [string]::IsNullOrWhiteSpace($LauncherRecoveryCompletionPath) -or
        $ExpectedLauncherRecoveryCompletionSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
        [string]::IsNullOrWhiteSpace($RecoveryTrackerCommentUrl)) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_INPUT_INVALID' `
            -Message 'interrupted recovery requires one canonical attempt prefix, exact hashes, one launcher completion path, and one tracker comment URL' `
            -Remediation 'measure every immutable input and pass all explicit recovery bindings'
    }
    $intentExpectedSha = $ExpectedInterruptedIntentSha256.ToLowerInvariant()
    $journalExpectedTail = $ExpectedJournalTailSha256.ToLowerInvariant()
    $launcherExpectedSha = $ExpectedLauncherRecoveryCompletionSha256.ToLowerInvariant()
    $targetMembers = @($TargetFamilyPaths | Where-Object { Test-Path -LiteralPath $_ })
    if ($targetMembers.Count -ne 0) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_TARGET_EXISTS' `
            -Message "canonical target family exists during recovery: $($targetMembers -join ', ')" `
            -Remediation 'preserve the target and investigate whether the interrupted child published real state'
    }

    $attemptIntentPath = [IO.Path]::Combine(
        $TransactionPath, "$InterruptedAttemptPrefix-intent.json")
    $attemptIntent = Read-CbmMigrationJson -Path $attemptIntentPath `
        -Purpose "$InterruptedAttemptPrefix intent"
    $intentSha = Get-FileSha256 -Path $attemptIntentPath
    $archiveCompletePath = [IO.Path]::Combine($TransactionPath, 'archive-complete.json')
    if ($intentSha -cne $intentExpectedSha -or $attemptIntent.schema -ne 1 -or
        $attemptIntent.operation -cne 'ResumeReindex' -or $attemptIntent.issue -ne $Issue -or
        $attemptIntent.project -cne $Project -or
        -not [string]::Equals([string]$attemptIntent.repository_path, $Repository,
            [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$attemptIntent.transaction_path, $TransactionPath,
            [StringComparison]::OrdinalIgnoreCase) -or
        [string]$attemptIntent.archive_complete_sha256 -cne
            (Get-FileSha256 -Path $archiveCompletePath) -or
        $attemptIntent.expected_schema_version -ne $ExpectedSchemaVersion) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_INTENT_MISMATCH' `
            -Message "$InterruptedAttemptPrefix intent does not bind the exact immutable migration identity" `
            -Remediation 'preserve the transaction and use the exact interrupted intent named in tracker evidence'
    }
    $attemptNumbers = @(Get-ChildItem -LiteralPath $TransactionPath -File -Force |
        ForEach-Object {
            if ($_.Name -cmatch '^resume-(\d{3})-intent\.json$') { [int]$Matches[1] }
        })
    $interruptedNumber = [int]($InterruptedAttemptPrefix.Substring(7))
    if ($attemptNumbers.Count -eq 0 -or
        [int](($attemptNumbers | Measure-Object -Maximum).Maximum) -ne $interruptedNumber) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_NOT_LATEST_ATTEMPT' `
            -Message "$InterruptedAttemptPrefix is not the latest durable resume intent" `
            -Remediation 'never recover an older attempt after a later attempt has been published'
    }

    $intentJournalMatches = @($JournalState.Records | Where-Object {
        [string]$_.payload_sha256 -ceq $journalExpectedTail -and
        $_.payload.event -ceq 'resume_intent_published' -and
        $_.payload.data.issue -eq $Issue -and
        $_.payload.data.transaction_path -ceq $TransactionPath -and
        $_.payload.data.created_utc -ceq $attemptIntent.created_utc
    })
    if ($intentJournalMatches.Count -ne 1) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_JOURNAL_INTENT_UNBOUND' `
            -Message 'expected journal tail is not the unique interrupted resume-intent event' `
            -Remediation 'pass the payload SHA-256 of the exact resume_intent_published record'
    }
    $recordAfterIntent = @($JournalState.Records | Where-Object {
        $_.payload.previous_record_sha256 -ceq $journalExpectedTail
    })
    if ($recordAfterIntent.Count -gt 1 -or
        ($recordAfterIntent.Count -eq 1 -and
            $recordAfterIntent[0].payload.event -cne 'resume_interruption_recovered')) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_JOURNAL_ADVANCED' `
            -Message 'journal contains an unexpected event after the interrupted intent' `
            -Remediation 'preserve the journal and investigate the competing migration writer'
    }

    $launcherCompletion = Get-CanonicalExistingPath `
        -Path $LauncherRecoveryCompletionPath -Kind File
    $allowedRecoveryRoot = [IO.Path]::Combine($Repository, '.tmp', 'lock-recovery').TrimEnd('\') + '\'
    if (-not $launcherCompletion.StartsWith($allowedRecoveryRoot,
            [StringComparison]::OrdinalIgnoreCase)) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_LAUNCHER_PATH_INVALID' `
            -Message "launcher recovery completion is outside repository authority: $launcherCompletion" `
            -Remediation 'pass the exact supported launcher recovery completion under .tmp\\lock-recovery'
    }
    $launcherSha = Get-FileSha256 -Path $launcherCompletion
    $launcherRecord = Read-CbmMigrationJson -Path $launcherCompletion `
        -Purpose 'launcher recovery completion'
    $pidProbe = $launcherRecord.post_publication_pid_probe
    $attributionProbe = $launcherRecord.post_publication_attribution_probe
    $jobProbeRecord = $attributionProbe.exact_job_object_probe
    if ($launcherSha -cne $launcherExpectedSha -or
        $launcherRecord.schema -cne 'astrolabe.launcher-lock-recovery.completion.v6' -or
        $pidProbe.state -cne 'absent' -or [bool]$pidProbe.legacy_pid_only -or
        [int]$pidProbe.pid -le 0 -or [long]$pidProbe.owner_process_start_utc_ticks -le 0 -or
        $attributionProbe.exact_job_object_name -cnotmatch
            '^Global\\Astrolabe\.LauncherTree\.[0-9a-f]{64}$' -or
        $jobProbeRecord.state -cne 'absent' -or @($jobProbeRecord.process_ids).Count -ne 0 -or
        $launcherRecord.expected_final_protocol.active_state -cne 'absent' -or
        @($launcherRecord.expected_final_protocol.transition_paths).Count -ne 0) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_LAUNCHER_COMPLETION_INVALID' `
            -Message 'launcher completion does not prove exact owner/Job absence and an empty launcher namespace' `
            -Remediation 'use the exact successful v6 launcher recovery completion and measured hash'
    }

    $scriptPath = Get-CanonicalExistingPath -Path $PSCommandPath -Kind File
    $expectedScriptPath = [IO.Path]::Combine(
        $Repository, 'scripts', 'migrate-cbm-store.ps1')
    $launcherHelperPath = Get-CanonicalExistingPath `
        -Path ([IO.Path]::Combine($Repository, 'scripts', 'launcher-lock.ps1')) -Kind File
    if (-not [string]::Equals($scriptPath, $expectedScriptPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_SCRIPT_PATH_INVALID' `
            -Message "recovery script is not the repository-owned canonical path: $scriptPath" `
            -Remediation 'run the exact repository scripts\\migrate-cbm-store.ps1 bytes'
    }
    $scriptSha = Get-FileSha256 -Path $scriptPath
    $launcherHelperSha = Get-FileSha256 -Path $launcherHelperPath
    if (('AstroLauncherLockNative' -as [type]) -or
        (Get-Command Get-AstroLauncherJobObjectProbe -ErrorAction SilentlyContinue) -or
        (Get-Command Read-AstroLauncherLock -ErrorAction SilentlyContinue)) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_HELPER_PRELOADED' `
            -Message 'launcher-lock native type or query functions were loaded before exact helper import' `
            -Remediation 'run recovery in a fresh PowerShell process so only the hash-bound helper defines authority'
    }
    . $launcherHelperPath
    $ownerProbe = Get-AstroExactProcessIdentityProbe `
        -ProcessId ([int]$pidProbe.pid) `
        -ProcessStartUtcTicks ([long]$pidProbe.owner_process_start_utc_ticks)
    $jobProbe = Get-AstroLauncherJobObjectProbe `
        -Name ([string]$attributionProbe.exact_job_object_name)
    $launcherLockPath = [IO.Path]::Combine($Repository, '.tmp', 'astrolabe-launcher.lock')
    $launcherState = Read-AstroLauncherLock -LockPath $launcherLockPath
    if ($ownerProbe.State -cnotin @('absent', 'pid-reused') -or
        $jobProbe.State -cne 'absent' -or @($jobProbe.ProcessIds).Count -ne 0 -or
        $launcherState.State -cne 'absent' -or @($launcherState.TransitionPaths).Count -ne 0) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_LAUNCHER_NOT_QUIESCENT' `
            -Message "launcher is not quiescent: owner=$($ownerProbe.State), job=$($jobProbe.State), active=$($launcherState.State), transitions=$(@($launcherState.TransitionPaths).Count)" `
            -Remediation 'recover the exact live or interrupted launcher protocol before migration recovery'
    }

    $evidence = [ordered]@{
        schema = 1
        issue = $Issue
        transaction_path = $TransactionPath
        attempt_prefix = $InterruptedAttemptPrefix
        intent_sha256 = $intentSha
        journal_tail_sha256 = $journalExpectedTail
        launcher_recovery_completion_path = $launcherCompletion
        launcher_recovery_completion_sha256 = $launcherSha
        migration_script_path = $scriptPath
        migration_script_sha256 = $scriptSha
        launcher_lock_helper_path = $launcherHelperPath
        launcher_lock_helper_sha256 = $launcherHelperSha
        owner_pid = [int]$pidProbe.pid
        owner_process_start_utc_ticks = [long]$pidProbe.owner_process_start_utc_ticks
        job_object_name = [string]$attributionProbe.exact_job_object_name
    }
    $evidenceLine = 'CBM_STORE_MIGRATION_INTERRUPTION_RECOVERY ' +
        ($evidence | ConvertTo-Json -Compress)
    $trackerFirst = Read-CbmRecoveryTrackerEvidence `
        -CommentUrl $RecoveryTrackerCommentUrl -OwningIssue $Issue `
        -ExpectedEvidenceLine $evidenceLine

    $authorizationPath = [IO.Path]::Combine(
        $TransactionPath, "$InterruptedAttemptPrefix-interruption-recovery.authorization.json")
    $faultPath = [IO.Path]::Combine($TransactionPath, "$InterruptedAttemptPrefix-fault.json")
    $completionPath = [IO.Path]::Combine(
        $TransactionPath, "$InterruptedAttemptPrefix-interruption-recovery.completion.json")
    $authorizationValue = [ordered]@{
        schema = 1
        status = 'authorized'
        issue = $Issue
        authorized_utc = [DateTime]::UtcNow.ToString('o')
        transaction_path = $TransactionPath
        attempt_prefix = $InterruptedAttemptPrefix
        intent_path = $attemptIntentPath
        intent_sha256 = $intentSha
        journal_tail_before_sha256 = $journalExpectedTail
        launcher_recovery_completion_path = $launcherCompletion
        launcher_recovery_completion_sha256 = $launcherSha
        migration_script_path = $scriptPath
        migration_script_sha256 = $scriptSha
        launcher_lock_helper_path = $launcherHelperPath
        launcher_lock_helper_sha256 = $launcherHelperSha
        tracker = [ordered]@{
            url = $trackerFirst.Url
            comment_id = $trackerFirst.Id
            updated_at = $trackerFirst.UpdatedAt
            body_sha256 = $trackerFirst.BodySha256
        }
        owner_probe_before = $ownerProbe
        job_probe_before = $jobProbe
        launcher_state_before = [ordered]@{
            state = $launcherState.State
            transition_paths = @($launcherState.TransitionPaths)
        }
    }
    if (-not (Test-Path -LiteralPath $authorizationPath)) {
        Write-CbmRecoveryDurableJson -Path $authorizationPath -Value $authorizationValue
    }
    $authorization = Read-CbmMigrationJson -Path $authorizationPath `
        -Purpose "$InterruptedAttemptPrefix recovery authorization"
    $authorizationSha = Get-FileSha256 -Path $authorizationPath
    if ($authorization.schema -ne 1 -or $authorization.status -cne 'authorized' -or
        $authorization.issue -ne $Issue -or
        $authorization.transaction_path -cne $TransactionPath -or
        $authorization.attempt_prefix -cne $InterruptedAttemptPrefix -or
        [string]$authorization.intent_sha256 -cne $intentSha -or
        [string]$authorization.journal_tail_before_sha256 -cne $journalExpectedTail -or
        [string]$authorization.launcher_recovery_completion_path -cne $launcherCompletion -or
        [string]$authorization.launcher_recovery_completion_sha256 -cne $launcherSha -or
        [string]$authorization.migration_script_path -cne $scriptPath -or
        [string]$authorization.migration_script_sha256 -cne $scriptSha -or
        [string]$authorization.launcher_lock_helper_path -cne $launcherHelperPath -or
        [string]$authorization.launcher_lock_helper_sha256 -cne $launcherHelperSha -or
        [string]$authorization.tracker.url -cne $trackerFirst.Url -or
        [long]$authorization.tracker.comment_id -ne $trackerFirst.Id -or
        [string]$authorization.tracker.updated_at -cne $trackerFirst.UpdatedAt -or
        [string]$authorization.tracker.body_sha256 -cne $trackerFirst.BodySha256) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_AUTHORIZATION_CONFLICT' `
            -Message 'recovery authorization does not exactly match immutable inputs and tracker bytes' `
            -Remediation 'preserve all phase records and investigate the conflicting recovery invocation'
    }

    $trackerSecond = Read-CbmRecoveryTrackerEvidence `
        -CommentUrl $RecoveryTrackerCommentUrl -OwningIssue $Issue `
        -ExpectedEvidenceLine $evidenceLine
    $ownerSecond = Get-AstroExactProcessIdentityProbe `
        -ProcessId ([int]$pidProbe.pid) `
        -ProcessStartUtcTicks ([long]$pidProbe.owner_process_start_utc_ticks)
    $jobSecond = Get-AstroLauncherJobObjectProbe `
        -Name ([string]$attributionProbe.exact_job_object_name)
    $launcherSecond = Read-AstroLauncherLock -LockPath $launcherLockPath
    if ($trackerSecond.UpdatedAt -cne $trackerFirst.UpdatedAt -or
        $trackerSecond.BodySha256 -cne $trackerFirst.BodySha256 -or
        $ownerSecond.State -cnotin @('absent', 'pid-reused') -or
        $jobSecond.State -cne 'absent' -or @($jobSecond.ProcessIds).Count -ne 0 -or
        $launcherSecond.State -cne 'absent' -or @($launcherSecond.TransitionPaths).Count -ne 0 -or
        (Get-FileSha256 -Path $attemptIntentPath) -cne $intentSha -or
        (Get-FileSha256 -Path $launcherCompletion) -cne $launcherSha -or
        (Get-FileSha256 -Path $scriptPath) -cne $scriptSha -or
        (Get-FileSha256 -Path $launcherHelperPath) -cne $launcherHelperSha) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_AUTHORITY_DRIFT' `
            -Message 'tracker, owner, Job Object, launcher namespace, intent, or launcher completion changed across authorization' `
            -Remediation 'preserve the authorization and investigate the exact state change before any terminal record'
    }

    if (-not (Test-Path -LiteralPath $faultPath)) {
        Write-CbmRecoveryDurableJson -Path $faultPath -Value ([ordered]@{
            schema = 1
            issue = $Issue
            status = 'fault'
            fault_kind = 'interrupted_resume_recovered'
            fault_utc = [DateTime]::UtcNow.ToString('o')
            attempt_prefix = $InterruptedAttemptPrefix
            intent_sha256 = $intentSha
            recovery_authorization_sha256 = $authorizationSha
            launcher_recovery_completion_sha256 = $launcherSha
            migration_script_sha256 = $scriptSha
            launcher_lock_helper_sha256 = $launcherHelperSha
            message = 'the exact resume process generation ended before its ordinary catch could publish a terminal fault'
            remediation = 'resume only after recovery completion and journal readback agree'
        })
    }
    $fault = Read-CbmMigrationJson -Path $faultPath `
        -Purpose "$InterruptedAttemptPrefix recovered fault"
    $faultSha = Get-FileSha256 -Path $faultPath
    if ($fault.schema -ne 1 -or $fault.issue -ne $Issue -or $fault.status -cne 'fault' -or
        $fault.fault_kind -cne 'interrupted_resume_recovered' -or
        $fault.attempt_prefix -cne $InterruptedAttemptPrefix -or
        [string]$fault.intent_sha256 -cne $intentSha -or
        [string]$fault.recovery_authorization_sha256 -cne $authorizationSha -or
        [string]$fault.launcher_recovery_completion_sha256 -cne $launcherSha -or
        [string]$fault.migration_script_sha256 -cne $scriptSha -or
        [string]$fault.launcher_lock_helper_sha256 -cne $launcherHelperSha) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_FAULT_CONFLICT' `
            -Message 'recovered-fault record does not exactly bind the authorization and intent' `
            -Remediation 'preserve all records and investigate the conflicting terminal fault'
    }

    $recoveryJournalData = [ordered]@{
        attempt_prefix = $InterruptedAttemptPrefix
        intent_sha256 = $intentSha
        recovery_authorization_sha256 = $authorizationSha
        recovered_fault_sha256 = $faultSha
        launcher_recovery_completion_sha256 = $launcherSha
        migration_script_sha256 = $scriptSha
        launcher_lock_helper_sha256 = $launcherHelperSha
    }
    $journalCurrent = Get-ValidatedJournal -JournalPath $JournalPath
    if ($journalCurrent.TailSha256 -ceq $journalExpectedTail) {
        $recoveryJournalTail = Add-JournalRecord -JournalPath $JournalPath `
            -PreviousSha256 $journalExpectedTail -Event 'resume_interruption_recovered' `
            -Data $recoveryJournalData
    }
    else {
        $tailRecord = $journalCurrent.Records[-1]
        if ($tailRecord.payload.event -cne 'resume_interruption_recovered' -or
            $tailRecord.payload.previous_record_sha256 -cne $journalExpectedTail -or
            $tailRecord.payload.data.attempt_prefix -cne $InterruptedAttemptPrefix -or
            $tailRecord.payload.data.intent_sha256 -cne $intentSha -or
            $tailRecord.payload.data.recovery_authorization_sha256 -cne $authorizationSha -or
            $tailRecord.payload.data.recovered_fault_sha256 -cne $faultSha -or
            $tailRecord.payload.data.launcher_recovery_completion_sha256 -cne $launcherSha -or
            $tailRecord.payload.data.migration_script_sha256 -cne $scriptSha -or
            $tailRecord.payload.data.launcher_lock_helper_sha256 -cne $launcherHelperSha) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_JOURNAL_CONFLICT' `
                -Message 'journal advanced without the exact idempotent recovery event' `
                -Remediation 'preserve the journal and investigate the competing migration writer'
        }
        $recoveryJournalTail = [string]$tailRecord.payload_sha256
    }

    if (-not (Test-Path -LiteralPath $completionPath)) {
        Write-CbmRecoveryDurableJson -Path $completionPath -Value ([ordered]@{
            schema = 1
            issue = $Issue
            status = 'interruption_recovered'
            completed_utc = [DateTime]::UtcNow.ToString('o')
            transaction_path = $TransactionPath
            attempt_prefix = $InterruptedAttemptPrefix
            intent_sha256 = $intentSha
            recovery_authorization_sha256 = $authorizationSha
            recovered_fault_sha256 = $faultSha
            launcher_recovery_completion_sha256 = $launcherSha
            migration_script_sha256 = $scriptSha
            launcher_lock_helper_sha256 = $launcherHelperSha
            final_journal_record_sha256 = $recoveryJournalTail
        })
    }
    $finalJournal = Get-ValidatedJournal -JournalPath $JournalPath
    Assert-CbmRecoveredAttemptTerminal -TransactionPath $TransactionPath `
        -AttemptPrefix $InterruptedAttemptPrefix -IntentSha256 $intentSha `
        -JournalState $finalJournal
    if ($finalJournal.TailSha256 -cne $recoveryJournalTail) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RECOVERY_FINAL_TAIL_DRIFT' `
            -Message 'journal advanced after interruption-recovery completion' `
            -Remediation 'preserve all state and investigate the competing migration writer'
    }
    [ordered]@{
        schema = 1
        status = 'interruption_recovered'
        issue = $Issue
        transaction_path = $TransactionPath
        attempt_prefix = $InterruptedAttemptPrefix
        intent_sha256 = $intentSha
        authorization_sha256 = $authorizationSha
        recovered_fault_sha256 = $faultSha
        completion_sha256 = Get-FileSha256 -Path $completionPath
        final_journal_record_sha256 = $finalJournal.TailSha256
        launcher_owner_state = $ownerSecond.State
        launcher_job_state = $jobSecond.State
        launcher_protocol_state = $launcherSecond.State
    } | ConvertTo-Json -Depth 8 -Compress
}

function Invoke-CbmTool {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$ArgsPath,
        [Parameter(Mandatory)][string]$StdoutPath,
        [Parameter(Mandatory)][string]$StderrPath,
        [Parameter(Mandatory)][int]$TimeoutSeconds,
        [Parameter(Mandatory)][string]$CacheDirectory
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment['CBM_CACHE_DIR'] = $CacheDirectory
    $start.ArgumentList.Add('cli')
    $start.ArgumentList.Add('--json')
    $start.ArgumentList.Add($Tool)
    $start.ArgumentList.Add('--args-file')
    $start.ArgumentList.Add($ArgsPath)
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_CHILD_START_FAILED' `
            -Message "could not start $Tool" -Remediation 'inspect the binary path and Windows process policy'
    }
    $identity = [ordered]@{
        pid = $process.Id
        process_start_utc_ticks = $process.StartTime.ToUniversalTime().Ticks
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_CHILD_TIMEOUT' `
            -Message "$Tool remained live as pid=$($identity.pid), start_ticks=$($identity.process_start_utc_ticks)" `
            -Remediation 'preserve the transaction and exact live child; investigate it without PID-only termination'
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    Write-DurableUtf8 -Path $StdoutPath -Text $stdout
    Write-DurableUtf8 -Path $StderrPath -Text $stderr
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        Identity = $identity
        StdoutSha256 = Get-FileSha256 -Path $StdoutPath
        StderrSha256 = Get-FileSha256 -Path $StderrPath
    }
}

function Read-CbmToolPayload {
    param(
        [Parameter(Mandatory)][string]$StdoutPath,
        [Parameter(Mandatory)][string]$Purpose
    )
    try {
        $outer = Get-Content -Raw -LiteralPath $StdoutPath |
            ConvertFrom-Json -AsHashtable -Depth 100
        if (-not $outer.ContainsKey('content') -or @($outer['content']).Count -lt 1 -or
            -not $outer['content'][0].ContainsKey('text')) {
            throw 'MCP response omitted content[0].text'
        }
        return [string]$outer['content'][0]['text'] |
            ConvertFrom-Json -AsHashtable -Depth 100
    }
    catch {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_TOOL_RESPONSE_INVALID' `
            -Message "$Purpose response is not one complete MCP JSON payload: $($_.Exception.Message)" `
            -Remediation 'preserve the transaction and inspect the exact persisted stdout/stderr bytes'
    }
}

$transactionPath = $null
$transactionOwned = $false
$attemptPrefix = $null
$faultRecordPath = $null
$guards = [Collections.Generic.List[object]]::new()
$targetRecords = [Collections.Generic.List[object]]::new()
$preflightRun = $null
$postflightRun = $null
$mutexMaterial = (
    [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($LegacyDbPath)).TrimEnd('\', '/') +
    '|' + $Project
).ToUpperInvariant()
$mutexDigest = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData(
        [Text.UTF8Encoding]::new($false).GetBytes($mutexMaterial)
    )
).ToLowerInvariant()
$migrationMutex = [Threading.Mutex]::new($false, "Global\Astrolabe.CbmStoreMigration.$mutexDigest")
$migrationMutexHeld = $false
try {
    try {
        $migrationMutexHeld = $migrationMutex.WaitOne(0)
    }
    catch [Threading.AbandonedMutexException] {
        $migrationMutexHeld = $true
    }
    if (-not $migrationMutexHeld) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_TRANSACTION_HELD' `
            -Message "another process holds the exact store migration mutex: $mutexMaterial" `
            -Remediation 'inspect the live migration owner and retry only after its exact process generation exits'
    }
}
catch {
    $migrationMutex.Dispose()
    throw
}
try {
    $repository = Get-CanonicalExistingPath -Path $RepositoryPath -Kind Directory
    $binary = Get-CanonicalExistingPath -Path $BinaryPath -Kind File
    $newArchiveOperation = $Operation -in @(
        'ArchiveAndReindex',
        'ArchiveAliasAgainstCanonical'
    )
    if ($newArchiveOperation) {
        $legacy = Get-CanonicalExistingPath -Path $LegacyDbPath -Kind File
    }
    else {
        $legacyParent = Get-CanonicalExistingPath `
            -Path ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($LegacyDbPath))) `
            -Kind Directory
        $legacy = [IO.Path]::Combine($legacyParent, [IO.Path]::GetFileName($LegacyDbPath))
    }
    if ([IO.Path]::GetExtension($legacy) -cne '.db') {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_DB_SUFFIX_INVALID' `
            -Message "legacy source is not a .db file: $legacy" `
            -Remediation 'pass the exact primary SQLite database path, not a sidecar'
    }
    $expectedDb = $ExpectedDbSha256.ToLowerInvariant()
    $expectedCanonicalDb = $ExpectedCanonicalDbSha256.ToLowerInvariant()
    $expectedBinary = $ExpectedBinarySha256.ToLowerInvariant()
    $binarySha = Get-FileSha256 -Path $binary
    if ($binarySha -cne $expectedBinary) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_BINARY_HASH_MISMATCH' `
            -Message "binary sha256=$binarySha expected=$expectedBinary path=$binary" `
            -Remediation 'use the exact reviewed native artifact and pass its measured SHA-256'
    }

    $cache = [IO.Path]::GetDirectoryName($legacy).TrimEnd('\', '/')
    $target = [IO.Path]::Combine($cache, "$Project.db")
    if ([string]::Equals($legacy, $target, [StringComparison]::OrdinalIgnoreCase)) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_SOURCE_IS_TARGET' `
            -Message 'legacy source already occupies the canonical alias path' `
            -Remediation 'preserve it and use a distinct stable project alias or archive source path'
    }
    $targetFamilyPaths = @($target, "$target-wal", "$target-shm")
    $existingTargetMembers = @($targetFamilyPaths | Where-Object { Test-Path -LiteralPath $_ })
    if ($Operation -eq 'ArchiveAndReindex' -and $existingTargetMembers.Count -ne 0) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_TARGET_EXISTS' `
            -Message "canonical target family already exists: $($existingTargetMembers -join ', ')" `
            -Remediation 'inspect and verify every existing target-family member; this transaction never overwrites any of them'
    }
    if ($Operation -eq 'ArchiveAliasAgainstCanonical') {
        if ($expectedCanonicalDb -notmatch '^[0-9a-f]{64}$') {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_CANONICAL_HASH_REQUIRED' `
                -Message 'ArchiveAliasAgainstCanonical requires ExpectedCanonicalDbSha256' `
                -Remediation 'independently hash the accepted canonical primary DB and pass its exact lowercase SHA-256'
        }
        if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_CANONICAL_TARGET_MISSING' `
                -Message "accepted canonical primary DB is absent: $target" `
                -Remediation 'preserve the legacy family and establish one verified root-derived canonical family first'
        }
    }

    $transactionId = if ($Operation -eq 'ArchiveAliasAgainstCanonical') {
        "issue-$Issue-$expectedDb-$Project-against-$expectedCanonicalDb"
    }
    else {
        "issue-$Issue-$expectedDb-$Project"
    }
    $archiveRoot = [IO.Path]::Combine($cache, 'archive', 'cbm-store-migrations')
    $transactionPath = [IO.Path]::Combine($archiveRoot, $transactionId)
    if ($newArchiveOperation) {
        [IO.Directory]::CreateDirectory($archiveRoot) | Out-Null
        if (Test-Path -LiteralPath $transactionPath) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_TRANSACTION_EXISTS' `
                -Message "transaction already exists: $transactionPath" `
                -Remediation 'inspect the existing immutable transaction and resume only through a reviewed recovery operation'
        }
        [IO.Directory]::CreateDirectory($transactionPath) | Out-Null
        $transactionOwned = $true
        $faultRecordPath = [IO.Path]::Combine($transactionPath, 'fault.json')
        Initialize-CbmMigrationNative -TransactionPath $transactionPath `
            -CompilerScope ([IO.Path]::Combine($transactionPath, 'compiler-scope'))

    if ($Operation -eq 'ArchiveAliasAgainstCanonical') {
        # The real product verifies the complete source families first. This
        # operation then accepts only a quiescent sidecar-free generation, so
        # exact primary DB hashes bind all persistent SQLite state when the
        # no-write/no-delete-share handles are acquired immediately afterward.
        $preflightArgs = [IO.Path]::Combine($transactionPath, 'preflight-list-args.json')
        Write-DurableJson -Path $preflightArgs -Value ([ordered]@{})
        $preflightStdout = [IO.Path]::Combine($transactionPath, 'preflight-list.stdout.json')
        $preflightStderr = [IO.Path]::Combine($transactionPath, 'preflight-list.stderr.log')
        $preflightRun = Invoke-CbmTool -Executable $binary -Tool 'list_projects' `
            -ArgsPath $preflightArgs -StdoutPath $preflightStdout -StderrPath $preflightStderr `
            -TimeoutSeconds $ReindexTimeoutSeconds -CacheDirectory $cache
        if ($preflightRun.ExitCode -ne 0) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_PREFLIGHT_LIST_FAILED' `
                -Message "real list_projects exited $($preflightRun.ExitCode) before archival" `
                -Remediation 'preserve both families and inspect the persisted preflight response'
        }
        $preflightPayload = Read-CbmToolPayload -StdoutPath $preflightStdout `
            -Purpose 'preflight list_projects'
        $canonicalRows = @($preflightPayload['projects'] | Where-Object {
            [string]$_['name'] -ceq $Project -and
            [string]::Equals(
                [IO.Path]::GetFullPath([string]$_['db_path']),
                $target,
                [StringComparison]::OrdinalIgnoreCase
            ) -and [string]$_['db_sha256'] -ceq $expectedCanonicalDb -and
            [string]::Equals(
                [IO.Path]::GetFullPath([string]$_['canonical_root']).TrimEnd('\', '/'),
                $repository.TrimEnd('\', '/'),
                [StringComparison]::OrdinalIgnoreCase
            )
        })
        $legacyConflicts = @($preflightPayload['project_identity_conflicts'] |
            Where-Object {
                [string]::Equals(
                    [IO.Path]::GetFullPath([string]$_['legacy_db_path']),
                    $legacy,
                    [StringComparison]::OrdinalIgnoreCase
                ) -and [string]$_['legacy_db_sha256'] -ceq $expectedDb -and
                [string]$_['canonical_project'] -ceq $Project -and
                [string]::Equals(
                    [IO.Path]::GetFullPath([string]$_['canonical_db_path']),
                    $target,
                    [StringComparison]::OrdinalIgnoreCase
                ) -and
                [string]::Equals(
                    [IO.Path]::GetFullPath([string]$_['canonical_root']).TrimEnd('\', '/'),
                    $repository.TrimEnd('\', '/'),
                    [StringComparison]::OrdinalIgnoreCase
                )
            })
        if ($canonicalRows.Count -ne 1 -or $legacyConflicts.Count -ne 1) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_PREFLIGHT_IDENTITY_MISMATCH' `
                -Message "expected one accepted canonical row and one exact legacy conflict; canonical=$($canonicalRows.Count) conflict=$($legacyConflicts.Count)" `
                -Remediation 'preserve both families; reconcile product discovery output with the reviewed paths, roots, and hashes'
        }
        foreach ($sidecarPath in @("$target-wal", "$target-shm", "$legacy-wal", "$legacy-shm")) {
            if (Test-Path -LiteralPath $sidecarPath) {
                Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_ALIAS_FAMILY_NOT_QUIESCENT' `
                    -Message "ArchiveAliasAgainstCanonical requires a sidecar-free generation; present=$sidecarPath" `
                    -Remediation 'close every client, complete a normal SQLite checkpoint/close, then retry only after DB/WAL/SHM state is independently read back'
            }
        }

        $targetPrimary = New-FamilyGuardRecord -Path $target
        $guards.Add($targetPrimary)
        $targetRecords.Add($targetPrimary)
        foreach ($sidecarPath in @("$target-wal", "$target-shm")) {
            if (Test-Path -LiteralPath $sidecarPath) {
                Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_CANONICAL_FAMILY_CHANGED' `
                    -Message "canonical sidecar appeared before exact target freeze completed: $sidecarPath" `
                    -Remediation 'preserve both families and retry only after the exact writer generation is absent'
            }
        }
        if ($targetPrimary.Sha256 -cne $expectedCanonicalDb) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_CANONICAL_HASH_MISMATCH' `
                -Message "canonical db sha256=$($targetPrimary.Sha256) expected=$expectedCanonicalDb" `
                -Remediation 're-read the accepted canonical family and pass its exact current primary DB hash'
        }
    }

    # Guard the primary first. Denying FILE_SHARE_WRITE makes an existing or
    # newly starting SQLite writer incompatible before sidecar membership is
    # stated, so the DB/WAL/SHM family cannot legitimately change underneath
    # the inventory.
    $legacyPrimary = New-FamilyGuardRecord -Path $legacy
    $guards.Add($legacyPrimary)
    foreach ($suffix in @('-wal', '-shm')) {
        $sidecar = $legacy + $suffix
        if (Test-Path -LiteralPath $sidecar) {
            if ($Operation -eq 'ArchiveAliasAgainstCanonical') {
                Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_ALIAS_FAMILY_CHANGED' `
                    -Message "legacy sidecar appeared after quiescent preflight: $sidecar" `
                    -Remediation 'preserve both families and retry only after the exact writer generation is absent'
            }
            $guards.Add((New-FamilyGuardRecord -Path $sidecar))
        }
    }
    if ($legacyPrimary.Sha256 -cne $expectedDb) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_DB_HASH_MISMATCH' `
            -Message "legacy db sha256=$($legacyPrimary.Sha256) expected=$expectedDb" `
            -Remediation 're-read the issue authorization and pass the exact current source hash'
    }

    $journal = [IO.Path]::Combine($transactionPath, 'journal.ndjson')
    $members = @($guards | Where-Object {
        -not $targetRecords.Contains($_)
    } | ForEach-Object {
        [ordered]@{
            source_path = $_.SourcePath
            archive_path = [IO.Path]::Combine($transactionPath, [IO.Path]::GetFileName($_.SourcePath))
            file_id = $_.FileId
            length = $_.Length
            sha256 = $_.Sha256
        }
    })
    $intent = [ordered]@{
        schema = 1
        operation = $Operation
        issue = $Issue
        created_utc = [DateTime]::UtcNow.ToString('o')
        project = $Project
        repository_path = $repository
        canonical_target_db_path = $target
        binary_path = $binary
        binary_sha256 = $binarySha
        expected_schema_version = $ExpectedSchemaVersion
        source_family = $members
        canonical_target_family_preflight = @($targetRecords | ForEach-Object {
            [ordered]@{
                path = $_.SourcePath
                file_id = $_.FileId
                length = $_.Length
                sha256 = $_.Sha256
            }
        })
    }
    Write-DurableJson -Path ([IO.Path]::Combine($transactionPath, 'intent.json')) -Value $intent
    $previous = Add-JournalRecord -JournalPath $journal -PreviousSha256 ('0' * 64) `
        -Event 'intent_published' -Data $intent

    if ($Operation -eq 'ArchiveAliasAgainstCanonical') {
        $previous = Add-JournalRecord -JournalPath $journal -PreviousSha256 $previous `
            -Event 'alias_preflight_verified' -Data ([ordered]@{
                process = $preflightRun.Identity
                exit_code = $preflightRun.ExitCode
                stdout_sha256 = $preflightRun.StdoutSha256
                stderr_sha256 = $preflightRun.StderrSha256
                canonical = $canonicalRows[0]
                legacy_conflict = $legacyConflicts[0]
            })
    }

    # The primary DB is renamed first so the active cache namespace stops
    # advertising it before sidecars move.  All family guards remain live for
    # the complete transition, so no SQLite writer can observe a split family.
    foreach ($guard in @($guards | Where-Object {
        -not $targetRecords.Contains($_)
    })) {
        $destination = [IO.Path]::Combine($transactionPath, [IO.Path]::GetFileName($guard.SourcePath))
        [CbmStoreMigrationNative]::RenameNoReplace($guard.Handle, $destination)
        $afterPath = [IO.Path]::GetFullPath([CbmStoreMigrationNative]::FinalPath($guard.Handle))
        $afterId = [CbmStoreMigrationNative]::FileId($guard.Handle)
        $afterSha = Get-FileSha256 -Path $destination
        if (-not [string]::Equals($afterPath, $destination,
                                 [StringComparison]::OrdinalIgnoreCase) -or
            $afterId -cne $guard.FileId -or $afterSha -cne $guard.Sha256 -or
            (Test-Path -LiteralPath $guard.SourcePath)) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RENAME_READBACK_FAILED' `
                -Message "archive rename readback disagreed for $($guard.SourcePath)" `
                -Remediation 'preserve the transaction and inspect exact source/archive identities and hashes'
        }
        $previous = Add-JournalRecord -JournalPath $journal -PreviousSha256 $previous `
            -Event 'family_member_archived' -Data ([ordered]@{
                source_path = $guard.SourcePath
                archive_path = $destination
                file_id = $afterId
                length = $guard.Length
                sha256 = $afterSha
                source_absent = $true
            })
    }
    $archiveReadback = @($members | ForEach-Object {
        if (Test-Path -LiteralPath $_.source_path) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_SOURCE_REAPPEARED' `
                -Message "archived source path reappeared: $($_.source_path)" `
                -Remediation 'stop before reindex and investigate the foreign writer'
        }
        $archiveSha = Get-FileSha256 -Path $_.archive_path
        if ($archiveSha -cne $_.sha256) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_ARCHIVE_HASH_DRIFT' `
                -Message "archive hash drift: $($_.archive_path)" `
                -Remediation 'preserve every byte and investigate storage corruption'
        }
        [ordered]@{
            source_path = $_.source_path
            source_absent = $true
            archive_path = $_.archive_path
            length = (Get-Item -LiteralPath $_.archive_path).Length
            sha256 = $archiveSha
        }
    })
    $archiveComplete = [ordered]@{
        schema = 1
        issue = $Issue
        status = 'archive_complete'
        completed_utc = [DateTime]::UtcNow.ToString('o')
        final_journal_record_sha256 = $previous
        members = $archiveReadback
    }
    Write-DurableJson -Path ([IO.Path]::Combine($transactionPath, 'archive-complete.json')) `
        -Value $archiveComplete

    if ($Operation -eq 'ArchiveAliasAgainstCanonical') {
        $canonicalBeforePostflight = [ordered]@{
            path = $targetPrimary.SourcePath
            file_id = $targetPrimary.FileId
            length = $targetPrimary.Length
            sha256 = $targetPrimary.Sha256
        }
        $targetPrimary.Handle.Dispose()
        [void]$guards.Remove($targetPrimary)
        $targetRecords.Clear()

        $postflightArgs = [IO.Path]::Combine($transactionPath, 'postflight-list-args.json')
        Write-DurableJson -Path $postflightArgs -Value ([ordered]@{})
        $postflightStdout = [IO.Path]::Combine($transactionPath, 'postflight-list.stdout.json')
        $postflightStderr = [IO.Path]::Combine($transactionPath, 'postflight-list.stderr.log')
        $postflightRun = Invoke-CbmTool -Executable $binary -Tool 'list_projects' `
            -ArgsPath $postflightArgs -StdoutPath $postflightStdout `
            -StderrPath $postflightStderr -TimeoutSeconds $ReindexTimeoutSeconds `
            -CacheDirectory $cache
        if ($postflightRun.ExitCode -ne 0) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_POSTFLIGHT_LIST_FAILED' `
                -Message "real list_projects exited $($postflightRun.ExitCode) after archival" `
                -Remediation 'preserve the completed archive and accepted canonical family; inspect the persisted postflight response'
        }
        $postflightPayload = Read-CbmToolPayload -StdoutPath $postflightStdout `
            -Purpose 'postflight list_projects'
        $postCanonicalRows = @($postflightPayload['projects'] | Where-Object {
            [string]$_['name'] -ceq $Project -and
            [string]::Equals(
                [IO.Path]::GetFullPath([string]$_['db_path']),
                $target,
                [StringComparison]::OrdinalIgnoreCase
            ) -and [string]$_['db_sha256'] -ceq $expectedCanonicalDb -and
            [string]::Equals(
                [IO.Path]::GetFullPath([string]$_['canonical_root']).TrimEnd('\', '/'),
                $repository.TrimEnd('\', '/'),
                [StringComparison]::OrdinalIgnoreCase
            )
        })
        $remainingLegacyConflicts = @($postflightPayload['project_identity_conflicts'] |
            Where-Object {
                [string]::Equals(
                    [IO.Path]::GetFullPath([string]$_['legacy_db_path']),
                    $legacy,
                    [StringComparison]::OrdinalIgnoreCase
                )
            })
        if ($postCanonicalRows.Count -ne 1 -or $remainingLegacyConflicts.Count -ne 0 -or
            (Test-Path -LiteralPath $legacy)) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_POSTFLIGHT_IDENTITY_MISMATCH' `
                -Message "expected one unchanged canonical row, no legacy conflict, and absent legacy path; canonical=$($postCanonicalRows.Count) conflict=$($remainingLegacyConflicts.Count) legacy_present=$(Test-Path -LiteralPath $legacy)" `
                -Remediation 'preserve every archive/canonical byte and inspect the postflight namespace and discovery response'
        }

        foreach ($sidecarPath in @("$target-wal", "$target-shm")) {
            if (Test-Path -LiteralPath $sidecarPath) {
                Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_CANONICAL_NOT_QUIESCENT' `
                    -Message "canonical sidecar appeared during postflight readback: $sidecarPath" `
                    -Remediation 'preserve the completed archive and canonical family; inspect the exact client generation before any further reconciliation'
            }
        }
        $targetPrimary = New-FamilyGuardRecord -Path $target
        $guards.Add($targetPrimary)
        $targetRecords.Add($targetPrimary)
        if ($targetPrimary.FileId -cne $canonicalBeforePostflight.file_id -or
            $targetPrimary.Length -ne $canonicalBeforePostflight.length -or
            $targetPrimary.Sha256 -cne $canonicalBeforePostflight.sha256) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_CANONICAL_POSTFLIGHT_DRIFT' `
                -Message 'canonical FILE_ID/length/hash changed across independent product postflight' `
                -Remediation 'preserve the archive and canonical family; inspect the exact namespace/content transition'
        }

        $targetFamilyReadback = @($targetRecords | ForEach-Object {
            $currentSha = Get-FileSha256 -Path $_.SourcePath
            $currentItem = Get-Item -LiteralPath $_.SourcePath -Force
            $currentFinal = [IO.Path]::GetFullPath(
                [CbmStoreMigrationNative]::FinalPath($_.Handle)
            )
            $currentId = [CbmStoreMigrationNative]::FileId($_.Handle)
            if (-not [string]::Equals(
                    $currentFinal,
                    $_.SourcePath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or $currentId -cne $_.FileId -or
                $currentItem.Length -ne $_.Length -or $currentSha -cne $_.Sha256) {
                Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_CANONICAL_READBACK_DRIFT' `
                    -Message "accepted canonical family changed during alias archival: $($_.SourcePath)" `
                    -Remediation 'preserve the archive and canonical family; inspect exact FILE_ID/length/hash drift'
            }
            [ordered]@{
                path = $_.SourcePath
                file_id = $currentId
                length = $currentItem.Length
                sha256 = $currentSha
            }
        })
        $finalArchiveReadback = @($archiveReadback | ForEach-Object {
            if (Test-Path -LiteralPath $_.source_path) {
                Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_SOURCE_REAPPEARED' `
                    -Message "archived alias source reappeared: $($_.source_path)" `
                    -Remediation 'preserve both families and investigate the foreign writer'
            }
            $archiveSha = Get-FileSha256 -Path $_.archive_path
            if ($archiveSha -cne $_.sha256) {
                Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_ARCHIVE_HASH_DRIFT' `
                    -Message "archived alias bytes drifted: $($_.archive_path)" `
                    -Remediation 'preserve every byte and investigate storage corruption'
            }
            [ordered]@{
                source_path = $_.source_path
                source_absent = $true
                archive_path = $_.archive_path
                length = (Get-Item -LiteralPath $_.archive_path -Force).Length
                sha256 = $archiveSha
            }
        })
        $previous = Add-JournalRecord -JournalPath $journal -PreviousSha256 $previous `
            -Event 'alias_postflight_verified' -Data ([ordered]@{
                process = $postflightRun.Identity
                exit_code = $postflightRun.ExitCode
                stdout_sha256 = $postflightRun.StdoutSha256
                stderr_sha256 = $postflightRun.StderrSha256
                canonical = $postCanonicalRows[0]
                legacy_source_absent = $true
                canonical_family = $targetFamilyReadback
                archived_source_family = $finalArchiveReadback
            })
        $complete = [ordered]@{
            schema = 1
            issue = $Issue
            status = 'complete'
            operation = $Operation
            completed_utc = [DateTime]::UtcNow.ToString('o')
            project = $Project
            repository_path = $repository
            archived_source_family = $finalArchiveReadback
            canonical_target = $postCanonicalRows[0]
            canonical_target_family = $targetFamilyReadback
            preflight_process = $preflightRun.Identity
            preflight_exit_code = $preflightRun.ExitCode
            preflight_stdout_sha256 = $preflightRun.StdoutSha256
            preflight_stderr_sha256 = $preflightRun.StderrSha256
            postflight_process = $postflightRun.Identity
            postflight_exit_code = $postflightRun.ExitCode
            postflight_stdout_sha256 = $postflightRun.StdoutSha256
            postflight_stderr_sha256 = $postflightRun.StderrSha256
            final_journal_record_sha256 = $previous
        }
        Write-DurableJson -Path ([IO.Path]::Combine($transactionPath, 'completion.json')) `
            -Value $complete
        foreach ($guard in $guards) {
            $guard.Handle.Dispose()
        }
        $guards.Clear()
        $complete | ConvertTo-Json -Depth 12 -Compress
        return
    }

    }
    else {
        if (-not (Test-Path -LiteralPath $transactionPath -PathType Container)) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_TRANSACTION_MISSING' `
                -Message "reviewed archive transaction is absent: $transactionPath" `
                -Remediation 'pass the exact issue, source hash, legacy path, and project of the completed archive'
        }
        if (Test-Path -LiteralPath ([IO.Path]::Combine($transactionPath, 'completion.json'))) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_ALREADY_COMPLETE' `
                -Message "transaction already has immutable completion: $transactionPath" `
                -Remediation 'verify the existing completion and canonical target; never run the reindex again'
        }
        $intentPath = [IO.Path]::Combine($transactionPath, 'intent.json')
        $archiveCompletePath = [IO.Path]::Combine($transactionPath, 'archive-complete.json')
        $initialFaultPath = [IO.Path]::Combine($transactionPath, 'fault.json')
        foreach ($required in @($intentPath, $archiveCompletePath, $initialFaultPath)) {
            if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
                Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RESUME_RECORD_MISSING' `
                    -Message "required immutable resume record is absent: $required" `
                    -Remediation 'preserve the transaction; resume only a fully recorded archive fault'
            }
        }
        try {
            $intent = Get-Content -Raw -LiteralPath $intentPath | ConvertFrom-Json -Depth 30
            $archiveComplete = Get-Content -Raw -LiteralPath $archiveCompletePath |
                ConvertFrom-Json -Depth 30
            $initialFault = Get-Content -Raw -LiteralPath $initialFaultPath |
                ConvertFrom-Json -Depth 30
        }
        catch {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RESUME_RECORD_INVALID' `
                -Message "immutable resume record is not valid JSON: $($_.Exception.Message)" `
                -Remediation 'preserve the transaction and compare its record hashes to the issue evidence'
        }
        if (@($intent.source_family).Count -ne @($archiveComplete.members).Count -or
            @($intent.source_family).Count -eq 0) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_ARCHIVE_MEMBERSHIP_INVALID' `
                -Message 'intent and archive-complete family cardinalities differ or are empty' `
                -Remediation 'preserve the transaction and investigate partial archive publication'
        }
        $sameLegacy = [string]::Equals([string]$intent.source_family[0].source_path, $legacy,
            [StringComparison]::OrdinalIgnoreCase)
        if ($intent.schema -ne 1 -or $intent.operation -cne 'ArchiveAndReindex' -or
            $intent.issue -ne $Issue -or $intent.project -cne $Project -or
            -not [string]::Equals([string]$intent.repository_path, $repository,
                [StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals([string]$intent.canonical_target_db_path, $target,
                [StringComparison]::OrdinalIgnoreCase) -or
            $intent.expected_schema_version -ne $ExpectedSchemaVersion -or -not $sameLegacy -or
            [string]$intent.source_family[0].sha256 -cne $expectedDb -or
            $archiveComplete.schema -ne 1 -or $archiveComplete.issue -ne $Issue -or
            $archiveComplete.status -cne 'archive_complete' -or
            $initialFault.schema -ne 1 -or $initialFault.issue -ne $Issue -or
            $initialFault.status -cne 'fault') {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RESUME_IDENTITY_MISMATCH' `
                -Message 'issue/source/project/repository/schema records do not bind the requested archive' `
                -Remediation 'use the exact inputs from immutable intent.json; never retarget an archive transaction'
        }
        $archiveReadback = @()
        foreach ($member in @($intent.source_family)) {
            $completed = @($archiveComplete.members | Where-Object {
                [string]::Equals([string]$_.source_path, [string]$member.source_path,
                    [StringComparison]::OrdinalIgnoreCase) -and
                [string]::Equals([string]$_.archive_path, [string]$member.archive_path,
                    [StringComparison]::OrdinalIgnoreCase)
            })
            if ($completed.Count -ne 1 -or (Test-Path -LiteralPath $member.source_path) -or
                -not (Test-Path -LiteralPath $member.archive_path -PathType Leaf)) {
                Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_ARCHIVE_STATE_INVALID' `
                    -Message "source/archive namespace readback failed for $($member.source_path)" `
                    -Remediation 'preserve every byte; repair no state until the archive discrepancy is understood'
            }
            $archiveItem = Get-Item -LiteralPath $member.archive_path -Force
            $archiveSha = Get-FileSha256 -Path $member.archive_path
            if ($archiveItem.Length -ne $member.length -or $archiveSha -cne $member.sha256 -or
                $completed[0].length -ne $member.length -or
                [string]$completed[0].sha256 -cne [string]$member.sha256 -or
                -not [bool]$completed[0].source_absent) {
                Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_ARCHIVE_HASH_DRIFT' `
                    -Message "archived member identity/hash drifted: $($member.archive_path)" `
                    -Remediation 'preserve the transaction and investigate storage corruption'
            }
            $archiveReadback += [ordered]@{
                source_path = [string]$member.source_path
                source_absent = $true
                archive_path = [string]$member.archive_path
                length = $archiveItem.Length
                sha256 = $archiveSha
            }
        }
        $journal = [IO.Path]::Combine($transactionPath, 'journal.ndjson')
        $journalState = Get-ValidatedJournal -JournalPath $journal
        if (@($journalState.Records | Where-Object {
            [string]$_.payload_sha256 -ceq [string]$archiveComplete.final_journal_record_sha256
        }).Count -ne 1) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_ARCHIVE_JOURNAL_UNBOUND' `
                -Message 'archive-complete final journal hash is absent or duplicated in the journal chain' `
                -Remediation 'preserve the transaction and compare journal/archive-complete hashes to the issue evidence'
        }
        $previous = $journalState.TailSha256
        if ($Operation -ceq 'RecoverInterruptedResume') {
            Invoke-CbmInterruptedResumeRecovery `
                -TransactionPath $transactionPath -JournalPath $journal `
                -JournalState $journalState -Repository $repository `
                -TargetFamilyPaths $targetFamilyPaths
            return
        }
        $attemptNumbers = @(Get-ChildItem -LiteralPath $transactionPath -File -Force |
            ForEach-Object {
                if ($_.Name -cmatch '^resume-(\d{3})-intent\.json$') { [int]$Matches[1] }
            })
        foreach ($priorNumber in $attemptNumbers) {
            $priorPrefix = 'resume-{0:D3}' -f $priorNumber
            $priorIntentPath = [IO.Path]::Combine(
                $transactionPath, "$priorPrefix-intent.json")
            $priorFaultPath = [IO.Path]::Combine(
                $transactionPath, "$priorPrefix-fault.json")
            if (-not (Test-Path -LiteralPath $priorFaultPath -PathType Leaf)) {
                Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RESUME_INTERRUPTED' `
                    -Message "prior resume attempt lacks a terminal fault record: $priorPrefix" `
                    -Remediation 'preserve the transaction and run RecoverInterruptedResume only after tracker-bound exact-generation recovery'
            }
            $priorFault = Read-CbmMigrationJson -Path $priorFaultPath `
                -Purpose "$priorPrefix terminal fault"
            if ($priorFault.schema -ne 1 -or $priorFault.issue -ne $Issue -or
                $priorFault.status -cne 'fault') {
                Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RESUME_FAULT_INVALID' `
                    -Message "prior resume attempt has an invalid terminal fault: $priorPrefix" `
                    -Remediation 'preserve the transaction and investigate the malformed attempt terminal state'
            }
            $faultKindProperty = $priorFault.PSObject.Properties['fault_kind']
            if ($null -ne $faultKindProperty -and
                [string]$faultKindProperty.Value -ceq 'interrupted_resume_recovered') {
                Assert-CbmRecoveredAttemptTerminal -TransactionPath $transactionPath `
                    -AttemptPrefix $priorPrefix `
                    -IntentSha256 (Get-FileSha256 -Path $priorIntentPath) `
                    -JournalState $journalState
            }
        }
        $attemptNumber = if ($attemptNumbers.Count -eq 0) { 1 } else {
            [int](($attemptNumbers | Measure-Object -Maximum).Maximum) + 1
        }
        if ($attemptNumber -gt 999) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_RESUME_ATTEMPT_LIMIT' `
                -Message 'transaction already contains 999 append-only resume attempts' `
                -Remediation 'preserve the transaction and open a dedicated recovery issue before any further attempt'
        }
        $attemptPrefix = 'resume-{0:D3}' -f $attemptNumber
        $attemptIntent = [ordered]@{
            schema = 1
            operation = 'ResumeReindex'
            issue = $Issue
            created_utc = [DateTime]::UtcNow.ToString('o')
            project = $Project
            repository_path = $repository
            canonical_target_db_path = $target
            transaction_path = $transactionPath
            archive_complete_sha256 = Get-FileSha256 -Path $archiveCompletePath
            journal_tail_before_sha256 = $previous
            binary_path = $binary
            binary_sha256 = $binarySha
            expected_schema_version = $ExpectedSchemaVersion
        }
        Write-InitialDurableJson `
            -Path ([IO.Path]::Combine($transactionPath, "$attemptPrefix-intent.json")) `
            -Value $attemptIntent
        $transactionOwned = $true
        $faultRecordPath = [IO.Path]::Combine($transactionPath, "$attemptPrefix-fault.json")
        Initialize-CbmMigrationNative -TransactionPath $transactionPath `
            -CompilerScope ([IO.Path]::Combine($transactionPath, "$attemptPrefix-compiler-scope")) `
            -RecordPrefix "$attemptPrefix-compiler"
        $previous = Add-JournalRecord -JournalPath $journal -PreviousSha256 $previous `
            -Event 'resume_intent_published' -Data $attemptIntent
    }

    $existingTargetMembers = @($targetFamilyPaths | Where-Object { Test-Path -LiteralPath $_ })
    if ($existingTargetMembers.Count -ne 0) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_TARGET_APPEARED' `
            -Message "canonical target family appeared after archive: $($existingTargetMembers -join ', ')" `
            -Remediation 'preserve the complete archive and inspect the foreign target-family writer before reindexing'
    }

    $recordStem = if ($attemptPrefix) { "$attemptPrefix-" } else { '' }
    $argsPath = [IO.Path]::Combine($transactionPath, "${recordStem}reindex-args.json")
    Write-DurableJson -Path $argsPath -Value ([ordered]@{
        repo_path = $repository
        name = $Project
        mode = 'fast'
        persistence = $false
    })
    $run = Invoke-CbmTool -Executable $binary -Tool 'index_repository' -ArgsPath $argsPath `
        -StdoutPath ([IO.Path]::Combine($transactionPath, "${recordStem}reindex.stdout.json")) `
        -StderrPath ([IO.Path]::Combine($transactionPath, "${recordStem}reindex.stderr.log")) `
        -TimeoutSeconds $ReindexTimeoutSeconds -CacheDirectory $cache
    $previous = Add-JournalRecord -JournalPath $journal -PreviousSha256 $previous `
        -Event $(if ($attemptPrefix) { 'resume_reindex_process_exited' } else {
            'reindex_process_exited'
        }) -Data ([ordered]@{
            process = $run.Identity
            exit_code = $run.ExitCode
            stdout_sha256 = $run.StdoutSha256
            stderr_sha256 = $run.StderrSha256
        })
    if ($run.ExitCode -ne 0) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_REINDEX_FAILED' `
            -Message "real index_repository exited $($run.ExitCode); archive is complete at $transactionPath" `
            -Remediation 'inspect the persisted stdout/stderr and retry from the canonical repository without restoring the legacy family'
    }
    if (-not (Test-Path -LiteralPath $target)) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_TARGET_MISSING' `
            -Message "index_repository reported success but target is absent: $target" `
            -Remediation 'inspect the persisted child response and cache path resolution'
    }

    # A successful index return is not query admission. Start a fresh real
    # process so the newly published exact alias must independently pass the
    # schema, internal project identity, and live-root provenance boundary.
    $admissionArgsPath = [IO.Path]::Combine($transactionPath,
        "${recordStem}admission-args.json")
    Write-DurableJson -Path $admissionArgsPath -Value ([ordered]@{
        project = $Project
        name_pattern = '.*'
        limit = 1
    })
    $admission = Invoke-CbmTool -Executable $binary -Tool 'search_graph' `
        -ArgsPath $admissionArgsPath `
        -StdoutPath ([IO.Path]::Combine($transactionPath, "${recordStem}admission.stdout.json")) `
        -StderrPath ([IO.Path]::Combine($transactionPath, "${recordStem}admission.stderr.log")) `
        -TimeoutSeconds $ReindexTimeoutSeconds -CacheDirectory $cache
    $previous = Add-JournalRecord -JournalPath $journal -PreviousSha256 $previous `
        -Event $(if ($attemptPrefix) { 'resume_query_admission_process_exited' } else {
            'query_admission_process_exited'
        }) -Data ([ordered]@{
            process = $admission.Identity
            exit_code = $admission.ExitCode
            stdout_sha256 = $admission.StdoutSha256
            stderr_sha256 = $admission.StderrSha256
        })
    if ($admission.ExitCode -ne 0) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_QUERY_ADMISSION_FAILED' `
            -Message "fresh-process search_graph exited $($admission.ExitCode); target=$target" `
            -Remediation 'preserve the archive and target families; inspect the persisted admission response and exact provenance refusal'
    }

    # Freeze the complete newly indexed family before declaring its bytes. The
    # DB guard is acquired first so WAL/SHM membership cannot legitimately
    # change while those sidecars are inventoried.
    $targetPrimary = New-FamilyGuardRecord -Path $target
    $guards.Add($targetPrimary)
    $targetRecords.Add($targetPrimary)
    foreach ($sidecarPath in @("$target-wal", "$target-shm")) {
        if (Test-Path -LiteralPath $sidecarPath) {
            $record = New-FamilyGuardRecord -Path $sidecarPath
            $guards.Add($record)
            $targetRecords.Add($record)
        }
    }
    $targetFamilyReadback = @($targetRecords | ForEach-Object {
        [ordered]@{
            path = $_.SourcePath
            file_id = $_.FileId
            length = $_.Length
            sha256 = $_.Sha256
        }
    })

    $finalArchiveReadback = @($archiveReadback | ForEach-Object {
        if (Test-Path -LiteralPath $_.source_path) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_SOURCE_REAPPEARED' `
                -Message "archived source path reappeared after reindex: $($_.source_path)" `
                -Remediation 'preserve both families and investigate the foreign writer before accepting completion'
        }
        $archiveSha = Get-FileSha256 -Path $_.archive_path
        if ($archiveSha -cne $_.sha256) {
            Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_ARCHIVE_HASH_DRIFT' `
                -Message "archive hash drift after reindex: $($_.archive_path)" `
                -Remediation 'preserve every byte and investigate storage corruption'
        }
        [ordered]@{
            source_path = $_.source_path
            source_absent = $true
            archive_path = $_.archive_path
            length = (Get-Item -LiteralPath $_.archive_path -Force).Length
            sha256 = $archiveSha
        }
    })

    $header = [byte[]]::new(100)
    $headerStream = [IO.File]::Open($target, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read -bor [IO.FileShare]::Delete)
    try {
        $headerBytes = 0
        while ($headerBytes -lt $header.Length) {
            $read = $headerStream.Read($header, $headerBytes, $header.Length - $headerBytes)
            if ($read -eq 0) {
                break
            }
            $headerBytes += $read
        }
    }
    finally {
        $headerStream.Dispose()
    }
    if ($headerBytes -lt 100) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_TARGET_HEADER_SHORT' `
            -Message "canonical target is shorter than a SQLite header: $headerBytes bytes" `
            -Remediation 'preserve the target and inspect the failed publication'
    }
    $sqliteMagic = [Text.Encoding]::ASCII.GetString($header, 0, 16)
    if ($sqliteMagic -cne "SQLite format 3`0") {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_TARGET_FORMAT_INVALID' `
            -Message "canonical target header is not SQLite format 3: $target" `
            -Remediation 'preserve the target and inspect the index publication and persisted child output'
    }
    $userVersion = ([uint32]$header[60] -shl 24) -bor
        ([uint32]$header[61] -shl 16) -bor
        ([uint32]$header[62] -shl 8) -bor [uint32]$header[63]
    if ($userVersion -ne $ExpectedSchemaVersion) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_TARGET_SCHEMA_MISMATCH' `
            -Message "canonical target user_version=$userVersion expected=$ExpectedSchemaVersion path=$target" `
            -Remediation 'preserve the target and child output; use a binary whose schema contract matches the reviewed source'
    }
    $complete = [ordered]@{
        schema = 1
        issue = $Issue
        status = 'complete'
        operation = $Operation
        attempt_prefix = $attemptPrefix
        completed_utc = [DateTime]::UtcNow.ToString('o')
        project = $Project
        repository_path = $repository
        archived_source_family = $finalArchiveReadback
        canonical_target = [ordered]@{
            path = $target
            length = $targetRecords[0].Length
            sha256 = $targetRecords[0].Sha256
            sqlite_user_version = $userVersion
        }
        canonical_target_family = $targetFamilyReadback
        reindex_process = $run.Identity
        reindex_exit_code = $run.ExitCode
        reindex_stdout_sha256 = $run.StdoutSha256
        reindex_stderr_sha256 = $run.StderrSha256
        admission_process = $admission.Identity
        admission_exit_code = $admission.ExitCode
        admission_stdout_sha256 = $admission.StdoutSha256
        admission_stderr_sha256 = $admission.StderrSha256
        final_journal_record_sha256 = $previous
    }
    Write-DurableJson -Path ([IO.Path]::Combine($transactionPath, 'completion.json')) -Value $complete
    foreach ($guard in $guards) {
        $guard.Handle.Dispose()
    }
    $guards.Clear()
    $complete | ConvertTo-Json -Depth 12 -Compress
}
catch {
    foreach ($guard in $guards) {
        if ($null -ne $guard.Handle) {
            $guard.Handle.Dispose()
        }
    }
    if ($transactionOwned -and $transactionPath -and (Test-Path -LiteralPath $transactionPath)) {
        $faultPath = if ($faultRecordPath) {
            $faultRecordPath
        }
        else {
            [IO.Path]::Combine($transactionPath, 'fault.json')
        }
        if (-not (Test-Path -LiteralPath $faultPath)) {
            try {
                $fault = [ordered]@{
                    schema = 1
                    issue = $Issue
                    status = 'fault'
                    fault_utc = [DateTime]::UtcNow.ToString('o')
                    message = $_.Exception.Message
                    remediation = 'preserve the complete transaction and inspect intent, journal, source paths, archive paths, and child output before any retry'
                }
                if ($script:nativeInteropReady) {
                    Write-DurableJson -Path $faultPath -Value $fault
                }
                else {
                    Write-InitialDurableJson -Path $faultPath -Value $fault
                }
            }
            catch {
                Write-Error "CBM_STORE_MIGRATION[CBM_STORE_MIGRATION_FAULT_RECORD_FAILED]: $($_.Exception.Message)"
            }
        }
    }
    throw
}
finally {
    if ($migrationMutexHeld) {
        $migrationMutex.ReleaseMutex()
    }
    $migrationMutex.Dispose()
}
