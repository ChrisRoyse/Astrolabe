<#
.SYNOPSIS
    Explicit hash-bound archive and reindex transaction for one legacy CBM store.

.DESCRIPTION
    The source DB/WAL/SHM family is opened by exact Windows handles that deny
    writers and namespace changes, hashed, and renamed without replacement into
    a tracker-bound archive directory.  Append-only transition records and
    independent post-rename identity/hash readback make partial completion
    diagnosable.  Only after the legacy source paths are proven absent is the
    supplied real codebase-memory binary allowed to index the canonical source
    repository under the explicit stable project alias.

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
    [ValidateSet('ArchiveAndReindex')]
    [string]$Operation,

    [Parameter(Mandatory)]
    [string]$LegacyDbPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedDbSha256,

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
    [int]$ReindexTimeoutSeconds = 14400
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
        [Parameter(Mandatory)][string]$CompilerScope
    )
    [IO.Directory]::CreateDirectory($CompilerScope) | Out-Null
    $owner = Get-Process -Id $PID -ErrorAction Stop
    $identity = [ordered]@{
        pid = $PID
        process_start_utc_ticks = $owner.StartTime.ToUniversalTime().Ticks
    }
    $intentPath = [IO.Path]::Combine($TransactionPath, 'compiler-intent.json')
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
            -Path ([IO.Path]::Combine($TransactionPath, 'compiler-fault.json')) `
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
        -Path ([IO.Path]::Combine($TransactionPath, 'compiler-completion.json')) `
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
        [Parameter(Mandatory)][string]$Text
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

function Invoke-CbmTool {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$ArgsPath,
        [Parameter(Mandatory)][string]$StdoutPath,
        [Parameter(Mandatory)][string]$StderrPath,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
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

$transactionPath = $null
$transactionOwned = $false
$guards = [Collections.Generic.List[object]]::new()
$targetRecords = [Collections.Generic.List[object]]::new()
try {
    $legacy = Get-CanonicalExistingPath -Path $LegacyDbPath -Kind File
    $repository = Get-CanonicalExistingPath -Path $RepositoryPath -Kind Directory
    $binary = Get-CanonicalExistingPath -Path $BinaryPath -Kind File
    if ([IO.Path]::GetExtension($legacy) -cne '.db') {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_DB_SUFFIX_INVALID' `
            -Message "legacy source is not a .db file: $legacy" `
            -Remediation 'pass the exact primary SQLite database path, not a sidecar'
    }
    $expectedDb = $ExpectedDbSha256.ToLowerInvariant()
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
    if ($existingTargetMembers.Count -ne 0) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_TARGET_EXISTS' `
            -Message "canonical target family already exists: $($existingTargetMembers -join ', ')" `
            -Remediation 'inspect and verify every existing target-family member; this transaction never overwrites any of them'
    }

    $transactionId = "issue-$Issue-$expectedDb-$Project"
    $archiveRoot = [IO.Path]::Combine($cache, 'archive', 'cbm-store-migrations')
    [IO.Directory]::CreateDirectory($archiveRoot) | Out-Null
    $transactionPath = [IO.Path]::Combine($archiveRoot, $transactionId)
    if (Test-Path -LiteralPath $transactionPath) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_TRANSACTION_EXISTS' `
            -Message "transaction already exists: $transactionPath" `
            -Remediation 'inspect the existing immutable transaction and resume only through a reviewed recovery operation'
    }
    [IO.Directory]::CreateDirectory($transactionPath) | Out-Null
    $transactionOwned = $true
    Initialize-CbmMigrationNative -TransactionPath $transactionPath `
        -CompilerScope ([IO.Path]::Combine($transactionPath, 'compiler-scope'))

    # Guard the primary first. Denying FILE_SHARE_WRITE makes an existing or
    # newly starting SQLite writer incompatible before sidecar membership is
    # stated, so the DB/WAL/SHM family cannot legitimately change underneath
    # the inventory.
    $guards.Add((New-FamilyGuardRecord -Path $legacy))
    foreach ($suffix in @('-wal', '-shm')) {
        $sidecar = $legacy + $suffix
        if (Test-Path -LiteralPath $sidecar) {
            $guards.Add((New-FamilyGuardRecord -Path $sidecar))
        }
    }
    if ($guards[0].Sha256 -cne $expectedDb) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_DB_HASH_MISMATCH' `
            -Message "legacy db sha256=$($guards[0].Sha256) expected=$expectedDb" `
            -Remediation 're-read the issue authorization and pass the exact current source hash'
    }

    $journal = [IO.Path]::Combine($transactionPath, 'journal.ndjson')
    $members = @($guards | ForEach-Object {
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
    }
    Write-DurableJson -Path ([IO.Path]::Combine($transactionPath, 'intent.json')) -Value $intent
    $previous = Add-JournalRecord -JournalPath $journal -PreviousSha256 ('0' * 64) `
        -Event 'intent_published' -Data $intent

    # The primary DB is renamed first so the active cache namespace stops
    # advertising it before sidecars move.  All family guards remain live for
    # the complete transition, so no SQLite writer can observe a split family.
    foreach ($guard in $guards) {
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

    $existingTargetMembers = @($targetFamilyPaths | Where-Object { Test-Path -LiteralPath $_ })
    if ($existingTargetMembers.Count -ne 0) {
        Throw-CbmMigrationError -Code 'CBM_STORE_MIGRATION_TARGET_APPEARED' `
            -Message "canonical target family appeared after archive: $($existingTargetMembers -join ', ')" `
            -Remediation 'preserve the complete archive and inspect the foreign target-family writer before reindexing'
    }

    $argsPath = [IO.Path]::Combine($transactionPath, 'reindex-args.json')
    Write-DurableJson -Path $argsPath -Value ([ordered]@{
        repo_path = $repository
        name = $Project
        mode = 'fast'
        persistence = $false
    })
    $run = Invoke-CbmTool -Executable $binary -Tool 'index_repository' -ArgsPath $argsPath `
        -StdoutPath ([IO.Path]::Combine($transactionPath, 'reindex.stdout.json')) `
        -StderrPath ([IO.Path]::Combine($transactionPath, 'reindex.stderr.log')) `
        -TimeoutSeconds $ReindexTimeoutSeconds
    $previous = Add-JournalRecord -JournalPath $journal -PreviousSha256 $previous `
        -Event 'reindex_process_exited' -Data ([ordered]@{
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
    $admissionArgsPath = [IO.Path]::Combine($transactionPath, 'admission-args.json')
    Write-DurableJson -Path $admissionArgsPath -Value ([ordered]@{
        project = $Project
        name_pattern = '.*'
        limit = 1
    })
    $admission = Invoke-CbmTool -Executable $binary -Tool 'search_graph' `
        -ArgsPath $admissionArgsPath `
        -StdoutPath ([IO.Path]::Combine($transactionPath, 'admission.stdout.json')) `
        -StderrPath ([IO.Path]::Combine($transactionPath, 'admission.stderr.log')) `
        -TimeoutSeconds $ReindexTimeoutSeconds
    $previous = Add-JournalRecord -JournalPath $journal -PreviousSha256 $previous `
        -Event 'query_admission_process_exited' -Data ([ordered]@{
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
        $faultPath = [IO.Path]::Combine($transactionPath, 'fault.json')
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
