<#
.SYNOPSIS
    Execute a promoted native FSV artifact under a live launcher lease (#596).

.DESCRIPTION
    Verifies the content-addressed receipt, requires this runner to be a descendant of the
    live launcher-lock owner, acquires a dedicated JSON FSV lock, and opens the artifact with
    FileShare.Read (intentionally omitting FILE_SHARE_WRITE and FILE_SHARE_DELETE). The handle
    remains open for the complete child lifetime, so Windows refuses artifact mutation,
    rename, and directory cleanup while the real process is running.

    Before returning, it independently reads back the artifact hash, output hashes, and the
    kernel exit code through both the original PROCESS_INFORMATION process handle and a
    separately duplicated handle to that exact kernel object. It also records Git tree state
    into a durable run record. No PID-reopened process authority, CPU fallback, output
    substitution, retry, or mock behavior exists here.

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

. (Join-Path $PSScriptRoot 'launcher-lock.ps1')

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
    $state = Get-AstroPathEntryState $Path
    if ($state.State -ceq 'absent') { return }
    if ($state.State -cne 'present') {
        Fail-Astro 'ASTRO_FSV_PATH_UNEVALUABLE' `
            "$Description presence/attributes are unevaluable: $Path ($($state.Error))" `
            'repair filesystem access before executing evidence state'
    }
    if (($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Astro 'ASTRO_FSV_REPARSE_ENTRY_REFUSED' "$Description is a reparse point: $Path" 'use ordinary workspace-local evidence paths that cannot redirect elsewhere'
    }
}

function File-Sha256([string]$Path) {
    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hasher.ComputeHash($stream)) -replace '-', '').ToLowerInvariant() }
    finally { $hasher.Dispose(); $stream.Dispose() }
}

function File-Sha256UnderCleanupLease([string]$Path) {
    # The retained cleanup-readiness lease requests read/write/delete access while
    # sharing reads only. This independent reader must therefore share all access
    # requested by that existing lease while itself requesting only read access.
    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    )
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
    [AstroFsvCreatedProcess]$Process
) {
    if (-not $Process.HasExited) {
        Fail-Astro 'ASTRO_FSV_CHILD_STILL_LIVE' "native child PID $($Process.Id) is still live after the runner wait completed" 'preserve the FSV lock and wait for the exact recorded child to exit naturally'
    }
    try {
        [uint32]$kernelCode =
            [AstroFsvAtomicFile]::ReadTerminatedProcessExitCode($Process.ProcessHandle)
        [uint32]$duplicateCode =
            [AstroFsvAtomicFile]::ReadTerminatedProcessExitCode($Process.ObservationHandle)
    }
    catch {
        Fail-Astro 'ASTRO_FSV_CHILD_EXIT_UNREADABLE' "kernel32!GetExitCodeProcess failed for an exact retained handle to native child PID $($Process.Id): $($_.Exception.Message)" 'preserve the session and both exact process-handle observations; repair process-exit observation before rerunning'
    }
    return [ordered]@{
        exit_code = $kernelCode
        primary_source = 'kernel32!GetExitCodeProcess(PROCESS_INFORMATION.hProcess)'
        exact_duplicate_source = 'kernel32!GetExitCodeProcess(DuplicateHandle(PROCESS_INFORMATION.hProcess))'
        exact_duplicate_exit_code = $duplicateCode
        sources_agree = $duplicateCode -eq $kernelCode
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
    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Publish-NewFile([string]$Path, [string]$Content) {
    $parent = Split-Path -Parent $Path
    if (-not (Test-AstroPathLongPath -LiteralPath $parent -PathType Container)) {
        New-AstroDirectoryLongPath $parent | Out-Null
    }
    $stage = Join-Path $parent ('.' + [IO.Path]::GetFileName($Path) + ".publishing-$PID-" + [guid]::NewGuid().ToString('N'))
    try {
        Write-NewDurableUtf8 $stage $Content
        [AstroFsvAtomicFile]::PublishNoClobber($stage, $Path)
    }
    catch {
        if (Test-AstroPathLongPath -LiteralPath $stage -PathType Leaf) {
            Remove-AstroFileLongPath $stage
        }
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
using System.Text;
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

    static string Extended(string path) {
        string full = System.IO.Path.GetFullPath(path);
        if (full.StartsWith(@"\\?\", StringComparison.Ordinal))
            return full;
        if (full.StartsWith(@"\\", StringComparison.Ordinal))
            return @"\\?\UNC\" + full.Substring(2);
        return @"\\?\" + full;
    }

    public static void PublishNoClobber(string source, string destination) {
        Move(source, destination, MOVEFILE_WRITE_THROUGH);
    }

    public static void ReplaceOwned(string source, string destination) {
        Move(source, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }

    static void Move(string source, string destination, uint flags) {
        if (!MoveFileExW(Extended(source), Extended(destination), flags)) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "MoveFileExW atomic write-through publication failed " +
                "(native_error=" + error + "; flags=" + flags +
                "; source=" + source + "; destination=" + destination + ")");
        }
    }

    public static SafeFileHandle OpenDirectoryWithoutDeleteShare(string path) {
        SafeFileHandle handle = CreateFileW(Extended(path), 0, FILE_SHARE_READ,
            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (handle.IsInvalid) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "CreateFileW evidence-directory lease failed (native_error=" +
                error + "; path=" + path + ")");
        }
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

public sealed class AstroFsvCreatedProcess : IDisposable {
    const uint STILL_ACTIVE = 259;
    const uint WAIT_OBJECT_0 = 0;
    const uint WAIT_TIMEOUT = 258;
    const uint WAIT_FAILED = 0xFFFFFFFF;
    const uint INFINITE = 0xFFFFFFFF;
    const uint DUPLICATE_SAME_ACCESS = 0x00000002;
    const uint DUPLICATE_FAILURE_EXIT_CODE = 0xA57F0002;
    const uint DUPLICATE_FAILURE_WAIT_MS = 30000;

    IntPtr threadHandle;
    bool disposed;

    internal AstroFsvCreatedProcess(IntPtr processHandle, IntPtr primaryThreadHandle, uint processId) {
        ProcessHandle = new SafeProcessHandle(processHandle, true);
        threadHandle = primaryThreadHandle;
        ProcessId = processId;
        try {
            SafeProcessHandle duplicate;
            IntPtr current = GetCurrentProcess();
            if (!DuplicateHandle(
                current,
                ProcessHandle,
                current,
                out duplicate,
                0,
                false,
                DUPLICATE_SAME_ACCESS)) {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error,
                    "DuplicateHandle failed for exact created native child process " +
                    "(native_error=" + error + "; pid=" + ProcessId + ")");
            }
            ObservationHandle = duplicate;
        }
        catch (Exception duplicateFailure) {
            Exception cleanupFailure = null;
            try {
                if (!TerminateProcess(ProcessHandle, DUPLICATE_FAILURE_EXIT_CODE)) {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error,
                        "TerminateProcess failed after exact process-handle duplication failure " +
                        "(native_error=" + error + "; pid=" + ProcessId + ")");
                }
                uint cleanupWait = WaitForExactHandle(
                    ProcessHandle,
                    DUPLICATE_FAILURE_WAIT_MS,
                    "primary process handle after duplication failure");
                if (cleanupWait == WAIT_TIMEOUT) {
                    throw new TimeoutException(
                        "timed out waiting for exact suspended child cleanup after " +
                        "process-handle duplication failure (pid=" + ProcessId +
                        "; timeout_ms=" + DUPLICATE_FAILURE_WAIT_MS + ")");
                }
            }
            catch (Exception cleanup) {
                cleanupFailure = cleanup;
            }
            if (threadHandle != IntPtr.Zero) {
                if (!CloseHandle(threadHandle) && cleanupFailure == null) {
                    int error = Marshal.GetLastWin32Error();
                    cleanupFailure = new Win32Exception(error,
                        "CloseHandle failed for primary thread after process-handle duplication failure " +
                        "(native_error=" + error + "; pid=" + ProcessId + ")");
                }
                threadHandle = IntPtr.Zero;
            }
            ProcessHandle.Dispose();
            if (cleanupFailure != null) {
                throw new InvalidOperationException(
                    duplicateFailure.Message +
                    "; exact suspended-child cleanup also failed: " +
                    cleanupFailure.Message,
                    duplicateFailure);
            }
            throw;
        }
    }

    public SafeProcessHandle ProcessHandle { get; private set; }
    public SafeProcessHandle ObservationHandle { get; private set; }
    public uint ProcessId { get; private set; }
    public int Id { get { return checked((int)ProcessId); } }
    public bool HasExited {
        get {
            EnsureUsable();
            uint primary = WaitForExactHandle(ProcessHandle, 0, "primary process handle");
            uint duplicate =
                WaitForExactHandle(ObservationHandle, 0, "duplicated process handle");
            if (primary != duplicate) {
                throw new InvalidOperationException(
                    "exact native process handles disagree on signaled state " +
                    "(pid=" + ProcessId + "; primary_wait=" + primary +
                    "; duplicate_wait=" + duplicate + ")");
            }
            return primary == WAIT_OBJECT_0;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DuplicateHandle(
        IntPtr sourceProcess,
        SafeProcessHandle sourceHandle,
        IntPtr targetProcess,
        out SafeProcessHandle targetHandle,
        uint desiredAccess,
        bool inheritHandle,
        uint options);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    public AstroFsvCreatedProcess BindAndResume() {
        EnsureUsable();
        if (threadHandle == IntPtr.Zero)
            throw new InvalidOperationException("native child primary thread handle is unavailable");

        if (HasExited)
            throw new InvalidOperationException(
                "created-suspended native child exited before exact process resume (pid=" +
                ProcessId + ")");

        uint previousSuspendCount = ResumeThread(threadHandle);
        if (previousSuspendCount == UInt32.MaxValue) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "ResumeThread failed for created-suspended native child " +
                "(native_error=" + error + "; pid=" + ProcessId + ")");
        }
        ClosePrimaryThreadHandle();
        if (previousSuspendCount != 1) {
            throw new InvalidOperationException(
                "created-suspended native child had an unexpected primary-thread suspend count " +
                "(pid=" + ProcessId + "; previous_suspend_count=" +
                previousSuspendCount + "; expected=1)");
        }
        return this;
    }

    public void WaitForExit() {
        EnsureUsable();
        WaitForExactHandle(ProcessHandle, INFINITE, "primary process handle");
        uint duplicate =
            WaitForExactHandle(ObservationHandle, 0, "duplicated process handle");
        if (duplicate != WAIT_OBJECT_0) {
            throw new InvalidOperationException(
                "duplicated exact process handle was not signaled after the primary exact " +
                "process handle completed (pid=" + ProcessId +
                "; duplicate_wait=" + duplicate + ")");
        }
    }

    public void Refresh() {
        EnsureUsable();
    }

    public void TerminateAndWait(uint exitCode, uint timeoutMilliseconds) {
        EnsureUsable();

        if (!TerminateProcess(ProcessHandle, exitCode)) {
            int terminateError = Marshal.GetLastWin32Error();
            uint observedCode;
            if (!GetExitCodeProcess(ProcessHandle, out observedCode)) {
                int observeError = Marshal.GetLastWin32Error();
                throw new Win32Exception(observeError,
                    "TerminateProcess and follow-up GetExitCodeProcess both failed for created native child " +
                    "(pid=" + ProcessId + "; terminate_native_error=" + terminateError +
                    "; observe_native_error=" + observeError + ")");
            }
            if (observedCode == STILL_ACTIVE) {
                throw new Win32Exception(terminateError,
                    "TerminateProcess failed and the exact created native child remains live " +
                    "(native_error=" + terminateError + "; pid=" + ProcessId + ")");
            }
        }

        uint primaryWait = WaitForExactHandle(
            ProcessHandle,
            timeoutMilliseconds,
            "primary process handle during termination");
        if (primaryWait == WAIT_TIMEOUT) {
            throw new TimeoutException(
                "timed out waiting for exact created native child termination " +
                "(pid=" + ProcessId + "; timeout_ms=" + timeoutMilliseconds + ")");
        }
        uint duplicateWait = WaitForExactHandle(
            ObservationHandle,
            0,
            "duplicated process handle after termination");
        if (duplicateWait != WAIT_OBJECT_0) {
            throw new InvalidOperationException(
                "duplicated exact process handle was not signaled after forced termination " +
                "(pid=" + ProcessId + "; duplicate_wait=" + duplicateWait + ")");
        }

        uint finalCode;
        if (!GetExitCodeProcess(ProcessHandle, out finalCode)) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "GetExitCodeProcess failed after exact created native child termination " +
                "(native_error=" + error + "; pid=" + ProcessId + ")");
        }
        if (finalCode == STILL_ACTIVE)
            throw new InvalidOperationException(
                "exact created native child still reports STILL_ACTIVE after termination wait " +
                "(pid=" + ProcessId + ")");
        uint duplicateCode;
        if (!GetExitCodeProcess(ObservationHandle, out duplicateCode)) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "GetExitCodeProcess failed for duplicated exact native child handle after " +
                "termination (native_error=" + error + "; pid=" + ProcessId + ")");
        }
        if (duplicateCode != finalCode) {
            throw new InvalidOperationException(
                "exact native process handles disagree on the forced termination code " +
                "(pid=" + ProcessId + "; primary_exit=" + finalCode +
                "; duplicate_exit=" + duplicateCode + ")");
        }
        ClosePrimaryThreadHandle();
    }

    static uint WaitForExactHandle(
        SafeProcessHandle handle,
        uint timeoutMilliseconds,
        string description) {
        if (handle == null || handle.IsInvalid || handle.IsClosed)
            throw new InvalidOperationException(
                description + " is invalid or closed");
        uint waitResult = WaitForSingleObject(handle, timeoutMilliseconds);
        if (waitResult == WAIT_TIMEOUT)
            return WAIT_TIMEOUT;
        if (waitResult == WAIT_FAILED) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "WaitForSingleObject failed for " + description +
                " (native_error=" + error + ")");
        }
        if (waitResult != WAIT_OBJECT_0) {
            throw new InvalidOperationException(
                "WaitForSingleObject returned an unexpected result for " +
                description + " (wait_result=" + waitResult + ")");
        }
        return waitResult;
    }

    void EnsureUsable() {
        if (disposed)
            throw new ObjectDisposedException("AstroFsvCreatedProcess");
        if (ProcessHandle == null || ProcessHandle.IsInvalid || ProcessHandle.IsClosed)
            throw new InvalidOperationException(
                "primary exact native process handle is invalid or closed " +
                "(pid=" + ProcessId + ")");
        if (ObservationHandle == null ||
            ObservationHandle.IsInvalid ||
            ObservationHandle.IsClosed)
            throw new InvalidOperationException(
                "duplicated exact native process handle is invalid or closed " +
                "(pid=" + ProcessId + ")");
    }

    void ClosePrimaryThreadHandle() {
        if (threadHandle == IntPtr.Zero)
            return;
        IntPtr owned = threadHandle;
        threadHandle = IntPtr.Zero;
        if (!CloseHandle(owned)) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "CloseHandle failed for created native child primary thread " +
                "(native_error=" + error + "; pid=" + ProcessId + ")");
        }
    }

    public void Dispose() {
        if (disposed)
            return;
        disposed = true;
        if (threadHandle != IntPtr.Zero) {
            CloseHandle(threadHandle);
            threadHandle = IntPtr.Zero;
        }
        if (ObservationHandle != null)
            ObservationHandle.Dispose();
        if (ProcessHandle != null)
            ProcessHandle.Dispose();
    }
}

public static class AstroFsvNativeProcess {
    const uint GENERIC_READ = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint CREATE_NEW = 1;
    const uint OPEN_EXISTING = 3;
    const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    const uint STARTF_USESTDHANDLES = 0x00000100;
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const uint PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;
    const int ERROR_INSUFFICIENT_BUFFER = 122;

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFOEX {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        ref SECURITY_ATTRIBUTES security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool DeleteFileW(string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(
        IntPtr attributeList, int attributeCount, int flags, ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(
        IntPtr attributeList, uint flags, IntPtr attribute, IntPtr value,
        IntPtr size, IntPtr previousValue, IntPtr returnSize);

    [DllImport("kernel32.dll")]
    static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFOEX startupInfo,
        out PROCESS_INFORMATION processInformation);

    static string Extended(string path) {
        string full = System.IO.Path.GetFullPath(path);
        if (full.StartsWith(@"\\?\", StringComparison.Ordinal))
            return full;
        if (full.StartsWith(@"\\", StringComparison.Ordinal))
            return @"\\?\UNC\" + full.Substring(2);
        return @"\\?\" + full;
    }

    static SafeFileHandle OpenInherited(
        string path, uint access, uint creation, string operation) {
        SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES();
        security.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        security.lpSecurityDescriptor = IntPtr.Zero;
        security.bInheritHandle = 1;
        SafeFileHandle handle = CreateFileW(path, access, FILE_SHARE_READ,
            ref security, creation, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (handle.IsInvalid) {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error,
                operation + " failed (native_error=" + error + "; path=" + path + ")");
        }
        return handle;
    }

    static string RemoveCreatedOutput(string path) {
        if (String.IsNullOrEmpty(path))
            return null;
        if (DeleteFileW(Extended(path)))
            return null;
        int error = Marshal.GetLastWin32Error();
        return "DeleteFileW pre-launch cleanup failed (native_error=" + error +
            "; path=" + path + ")";
    }

    public static AstroFsvCreatedProcess CreateSuspended(
        string applicationPath,
        string commandLine,
        string standardOutputPath,
        string standardErrorPath) {
        if (String.IsNullOrWhiteSpace(applicationPath))
            throw new ArgumentException("applicationPath is empty", "applicationPath");
        if (String.IsNullOrWhiteSpace(commandLine))
            throw new ArgumentException("commandLine is empty", "commandLine");
        if (commandLine.Length > 32766)
            throw new ArgumentOutOfRangeException("commandLine",
                "CreateProcessW command line exceeds 32,766 UTF-16 characters " +
                "(actual=" + commandLine.Length + ")");

        SafeFileHandle standardInput = null;
        SafeFileHandle standardOutput = null;
        SafeFileHandle standardError = null;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr handleList = IntPtr.Zero;
        bool outputCreated = false;
        bool errorCreated = false;
        bool processCreated = false;
        Exception failure = null;
        try {
            standardInput = OpenInherited("NUL", GENERIC_READ, OPEN_EXISTING,
                "CreateFileW inherited stdin=NUL");
            standardOutput = OpenInherited(Extended(standardOutputPath), GENERIC_WRITE,
                CREATE_NEW, "CreateFileW no-clobber inherited stdout");
            outputCreated = true;
            standardError = OpenInherited(Extended(standardErrorPath), GENERIC_WRITE,
                CREATE_NEW, "CreateFileW no-clobber inherited stderr");
            errorCreated = true;

            IntPtr attributeBytes = IntPtr.Zero;
            bool sizingResult = InitializeProcThreadAttributeList(
                IntPtr.Zero, 1, 0, ref attributeBytes);
            int sizingError = Marshal.GetLastWin32Error();
            if (sizingResult || sizingError != ERROR_INSUFFICIENT_BUFFER ||
                attributeBytes == IntPtr.Zero) {
                throw new Win32Exception(sizingError,
                    "InitializeProcThreadAttributeList sizing failed " +
                    "(native_error=" + sizingError + "; requested_attributes=1)");
            }
            attributeList = Marshal.AllocHGlobal(attributeBytes);
            if (!InitializeProcThreadAttributeList(
                attributeList, 1, 0, ref attributeBytes)) {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error,
                    "InitializeProcThreadAttributeList allocation failed " +
                    "(native_error=" + error + "; requested_attributes=1)");
            }

            handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handleList, 0, standardInput.DangerousGetHandle());
            Marshal.WriteIntPtr(handleList, IntPtr.Size,
                standardOutput.DangerousGetHandle());
            Marshal.WriteIntPtr(handleList, IntPtr.Size * 2,
                standardError.DangerousGetHandle());
            if (!UpdateProcThreadAttribute(
                attributeList, 0,
                new IntPtr(PROC_THREAD_ATTRIBUTE_HANDLE_LIST),
                handleList, new IntPtr(IntPtr.Size * 3),
                IntPtr.Zero, IntPtr.Zero)) {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error,
                    "UpdateProcThreadAttribute restricted handle list failed " +
                    "(native_error=" + error + "; inherited_handle_count=3)");
            }

            STARTUPINFOEX startup = new STARTUPINFOEX();
            startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            startup.StartupInfo.dwFlags = unchecked((int)STARTF_USESTDHANDLES);
            startup.StartupInfo.hStdInput = standardInput.DangerousGetHandle();
            startup.StartupInfo.hStdOutput = standardOutput.DangerousGetHandle();
            startup.StartupInfo.hStdError = standardError.DangerousGetHandle();
            startup.lpAttributeList = attributeList;

            StringBuilder mutableCommandLine =
                new StringBuilder(commandLine, commandLine.Length + 1);
            PROCESS_INFORMATION processInformation;
            uint creationFlags =
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
            if (!CreateProcessW(
                Extended(applicationPath),
                mutableCommandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                creationFlags,
                IntPtr.Zero,
                null,
                ref startup,
                out processInformation)) {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error,
                    "CreateProcessW exact extended application launch failed " +
                    "(native_error=" + error +
                    "; application=" + applicationPath +
                    "; application_extended=" + Extended(applicationPath) +
                    "; command_line_utf16_characters=" + commandLine.Length +
                    "; stdout=" + standardOutputPath +
                    "; stderr=" + standardErrorPath +
                    "; creation_flags=" + creationFlags + ")");
            }

            AstroFsvCreatedProcess created = new AstroFsvCreatedProcess(
                processInformation.hProcess,
                processInformation.hThread,
                processInformation.dwProcessId);
            processCreated = true;
            return created;
        }
        catch (Exception ex) {
            failure = ex;
            throw;
        }
        finally {
            if (attributeList != IntPtr.Zero) {
                DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }
            if (handleList != IntPtr.Zero)
                Marshal.FreeHGlobal(handleList);
            if (standardError != null)
                standardError.Dispose();
            if (standardOutput != null)
                standardOutput.Dispose();
            if (standardInput != null)
                standardInput.Dispose();

            if (!processCreated) {
                string errorCleanup = errorCreated
                    ? RemoveCreatedOutput(standardErrorPath)
                    : null;
                string outputCleanup = outputCreated
                    ? RemoveCreatedOutput(standardOutputPath)
                    : null;
                if (failure != null &&
                    (!String.IsNullOrEmpty(errorCleanup) ||
                     !String.IsNullOrEmpty(outputCleanup))) {
                    throw new InvalidOperationException(
                        failure.Message + "; pre-launch cleanup: " +
                        (errorCleanup ?? "stderr=absent") + "; " +
                        (outputCleanup ?? "stdout=absent"), failure);
                }
            }
        }
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
$launcherLockSnapshotBefore = $null
$launcherJobName = $null
$launcherJobProbeBefore = $null
$directoryHandle = $null
$artifactCleanupLease = $null
$artifactCleanupReadiness = $null
$fsvLockOwned = $false
$child = $null
$childStartedAtUtc = $null
$childExitedAtUtc = $null
$childExitCode = $null
$childExitObservation = $null
$childExitObservationError = $null
$childProcessHandle = $null
$childObservationHandle = $null
$createdChild = $null
$childTerminationUncertain = $false
$artifact = $null
$artifactHashBefore = $null
$receiptFull = $null
$runRecordWritten = $false
$runRecordAuthorized = $false
$arguments = [string[]]::new(0)
$argumentCount = 0

try {
    if ($Issue -le 0) { Fail-Astro 'ASTRO_FSV_ISSUE_INVALID' 'Issue must be positive' 'pass the driving GitHub issue number' }
    if (-not (Test-AstroPathLongPath -LiteralPath $gitExe -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_GIT_MISSING' "required native Git executable is absent: $gitExe" 'restore the canonical Git for Windows installation'
    }
    $receiptFull = Assert-PathWithin $ReceiptPath $evidenceRoot 'ASTRO_FSV_RECEIPT_ESCAPE' 'receipt path'
    if (-not (Test-AstroPathLongPath -LiteralPath $receiptFull -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_MISSING' "receipt does not exist: $receiptFull" 'stage the native artifact first'
    }
    try { $receipt = Read-AstroUtf8FileLongPath $receiptFull | ConvertFrom-Json }
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
    if (-not (Test-AstroPathLongPath -LiteralPath $artifact -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_ARTIFACT_MISSING' "staged artifact is absent: $artifact" 'stage a fresh native artifact'
    }
    Assert-NotReparseEntry $artifact 'staged native artifact'
    foreach ($pair in @(
        @($StandardOutputPath, 'stdout'), @($StandardErrorPath, 'stderr'),
        @($RunRecordPath, 'run record'), @($LiveStatePath, 'live state')
    )) {
        $resolved = Assert-PathWithin ([string]$pair[0]) $sessionDirectory 'ASTRO_FSV_OUTPUT_ESCAPE' ([string]$pair[1])
        if (Test-AstroPathLongPath -LiteralPath $resolved) {
            Fail-Astro 'ASTRO_FSV_OUTPUT_REUSE_REFUSED' "$($pair[1]) already exists: $resolved" 'use fresh output paths; FSV state is append-only and never overwritten'
        }
    }
    $StandardOutputPath = [IO.Path]::GetFullPath($StandardOutputPath)
    $StandardErrorPath = [IO.Path]::GetFullPath($StandardErrorPath)
    $RunRecordPath = [IO.Path]::GetFullPath($RunRecordPath)
    $LiveStatePath = [IO.Path]::GetFullPath($LiveStatePath)
    $runRecordAuthorized = $true

    $launcherOwner = Read-AstroLauncherLock -LockPath $launcherLockPath
    $launcherPid = if ($null -ne $launcherOwner.OwnerPid) {
        [int]$launcherOwner.OwnerPid
    } else {
        0
    }
    if ($launcherOwner.State -ne 'held' -or
        $launcherOwner.Issue -ne $Issue) {
        Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_INVALID' "launcher protocol does not name the exact live owner process identity for issue #$Issue (state=$($launcherOwner.State), pid=$launcherPid, process_start_utc_ticks=$($launcherOwner.OwnerProcessStartUtcTicks), read_error=$($launcherOwner.ReadError), validation_error=$($launcherOwner.ValidationError))" 'start the FSV through the native launcher with the same driving issue'
    }
    if (-not (Test-DescendantOf $PID $launcherPid)) {
        Fail-Astro 'ASTRO_FSV_RUNNER_NOT_OWNED' "runner PID $PID is not a descendant of launcher PID $launcherPid" 'invoke this runner synchronously from the launcher-owned child process'
    }
    try {
        $launcherRootIdentity =
            [AstroLauncherLockNative]::GetDirectoryIdentity($workspace)
        $launcherJobName = Get-AstroLauncherTreeJobObjectName `
            -RootIdentity $launcherRootIdentity `
            -LauncherPid $launcherPid `
            -LauncherProcessStartUtcTicks ([long]$launcherOwner.OwnerProcessStartUtcTicks) `
            -LauncherLeaseStartUtcTicks ([long]$launcherOwner.LeaseStartUtcTicks) `
            -LauncherLockSha256 ([string]$launcherOwner.Sha256)
        $launcherJobProbeBefore =
            Get-AstroLauncherJobObjectProbe -Name $launcherJobName
    }
    catch {
        Fail-Astro 'ASTRO_FSV_LAUNCHER_JOB_UNEVALUABLE' "could not derive and query the exact launcher Job Object: $($_.Exception.Message)" 'preserve the staged session and repair exact launcher Job attribution before running an artifact'
    }
    $launcherJobMembersBefore =
        [int[]]@($launcherJobProbeBefore.ProcessIds | Sort-Object -Unique)
    if ($launcherJobProbeBefore.State -cne 'observed' -or
        $launcherJobMembersBefore -notcontains $launcherPid -or
        $launcherJobMembersBefore -notcontains $PID) {
        Fail-Astro 'ASTRO_FSV_LAUNCHER_JOB_MISMATCH' "exact launcher Job does not contain both launcher PID $launcherPid and runner PID $PID (name=$launcherJobName, state=$($launcherJobProbeBefore.State), members=$($launcherJobMembersBefore -join ','), error=$($launcherJobProbeBefore.Error))" 'invoke the runner only as a non-breakaway descendant of the exact live launcher owner'
    }

    $beforeRepo = Get-RepoState $gitExe $workspace
    if ($beforeRepo.head_sha -cne ([string]$receipt.tree_sha).ToLowerInvariant()) {
        Fail-Astro 'ASTRO_FSV_TREE_MISMATCH' "current HEAD $($beforeRepo.head_sha) differs from staged tree $($receipt.tree_sha)" 'discard the session and rebuild from the current frozen tree'
    }
    if ($null -eq $receipt.repository -or
        [string]$receipt.repository.status_sha256 -cne [string]$beforeRepo.status_sha256 -or
        [string]$receipt.repository.diff_sha256 -cne [string]$beforeRepo.diff_sha256 -or
        [string]$launcherOwner.HeadSha -cne [string]$beforeRepo.head_sha -or
        [string]$launcherOwner.StatusSha256 -cne [string]$beforeRepo.status_sha256 -or
        [string]$launcherOwner.DiffSha256 -cne [string]$beforeRepo.diff_sha256) {
        Fail-Astro 'ASTRO_FSV_REPOSITORY_IDENTITY_MISMATCH' 'receipt, live launcher lock, and current repository fingerprints do not identify the same frozen state' 'discard the artifact and rebuild under a fresh immutable launcher lease'
    }
    $artifactHashBefore = File-Sha256 $artifact
    $receiptHashBefore = File-Sha256 $receiptFull
    try {
        # The launcher's authoritative handle has GENERIC_READ|GENERIC_WRITE|DELETE
        # access while sharing only reads. This read-only classifier handle must
        # therefore share read/write/delete to admit that already-open authority.
        # The launcher's original FILE_SHARE_READ still denies every new writer,
        # rename, and delete opener for the complete runner lifetime.
        $launcherLockHandle =
            [AstroLauncherLockNative]::OpenExactClassifierReadFile($launcherLockPath)
        $launcherLockSnapshotBefore = Get-AstroExactRetainedFileSnapshot `
            -Handle $launcherLockHandle `
            -ExpectedPath $launcherLockPath
        $launcherLockLinksBefore =
            [AstroLauncherLockNative]::GetNumberOfLinks($launcherLockHandle)
    }
    catch {
        Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_RETAIN_FAILED' "could not retain a read-only exact snapshot of the live launcher lease: $($_.Exception.Message)" 'preserve the staged session and repair the live-lock share/identity contract before running an artifact'
    }
    if ($launcherLockLinksBefore -ne 1 -or
        $launcherLockSnapshotBefore.Sha256 -cne [string]$launcherOwner.Sha256 -or
        $launcherLockSnapshotBefore.Length -ne [uint64]$launcherOwner.Length) {
        Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_MISMATCH' "retained live launcher-lock identity differs from its authoritative classifier snapshot (links=$launcherLockLinksBefore, retained_sha256=$($launcherLockSnapshotBefore.Sha256), classified_sha256=$($launcherOwner.Sha256))" 'preserve all state and investigate launcher-lock replacement, aliasing, or byte drift'
    }
    $launcherLockHashBefore = [string]$launcherLockSnapshotBefore.Sha256
    $artifactItem = Get-AstroFileInfoLongPath $artifact
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
    $artifactHandle = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $artifact),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $receiptHandle = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $receiptFull),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
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
        launcher_job = [ordered]@{
            name = $launcherJobName
            members = @($launcherJobMembersBefore)
        }
        owner_pids = @($launcherPid, $PID)
        child_pid = $null
        phase = 'claimed'
    }
    Write-NewDurableUtf8 $lockStage ($lockManifest | ConvertTo-Json -Depth 10 -Compress)
    try { [AstroFsvAtomicFile]::PublishNoClobber($lockStage, $fsvLockPath) }
    catch {
        if (Test-AstroPathLongPath -LiteralPath $lockStage -PathType Leaf) {
            Remove-AstroFileLongPath $lockStage
        }
        Fail-Astro 'ASTRO_FSV_LOCK_HELD' "FSV lock could not be claimed without clobbering: $fsvLockPath" 'wait for the live owner or post dead-owner evidence before removing a stale lock'
    }
    $fsvLockOwned = $true

    $commandLine = ConvertTo-WindowsCommandLineArgument $artifact
    if ($argumentCount -gt 0) {
        $commandLine += " $argumentLine"
    }
    try {
        $createdChild = [AstroFsvNativeProcess]::CreateSuspended(
            $artifact,
            $commandLine,
            $StandardOutputPath,
            $StandardErrorPath
        )
    }
    catch {
        Fail-Astro 'ASTRO_FSV_CHILD_CREATE_FAILED' "direct native process creation failed before a child identity was returned: $($_.Exception.Message)" 'preserve the staged session, inspect the native operation/error/path diagnostics, and repair the exact process-creation boundary before rerunning'
    }
    $childProcessHandle = $createdChild.ProcessHandle
    $childObservationHandle = $createdChild.ObservationHandle
    $child = $createdChild
    try {
        [void]$createdChild.BindAndResume()
    }
    catch {
        $bindFailure = $_.Exception.Message
        try {
            $createdChild.TerminateAndWait([uint32]0xA57F0001, [uint32]30000)
        }
        catch {
            $childTerminationUncertain = $true
            Fail-Astro 'ASTRO_FSV_CHILD_BIND_CLEANUP_FAILED' "exact child PID $($createdChild.ProcessId) could not be bound/resumed and exact termination could not be proved (bind_failure=$bindFailure; termination_failure=$($_.Exception.Message))" 'preserve the launcher/FSV state and use exact process/Job attribution before any cleanup'
        }
        try {
            foreach ($createdOutput in @($StandardOutputPath, $StandardErrorPath)) {
                if (Test-AstroPathLongPath -LiteralPath $createdOutput -PathType Leaf) {
                    Remove-AstroFileLongPath $createdOutput
                }
            }
        }
        catch {
            Fail-Astro 'ASTRO_FSV_CHILD_BIND_OUTPUT_CLEANUP_FAILED' "exact child PID $($createdChild.ProcessId) was terminated after process binding failed, but an output created by that never-executed child could not be removed (bind_failure=$bindFailure; output_cleanup_failure=$($_.Exception.Message))" 'preserve the staged session and inspect the exact output path/handle state before lifecycle recovery'
        }
        Fail-Astro 'ASTRO_FSV_CHILD_BIND_FAILED' "exact child PID $($createdChild.ProcessId) was created suspended but binding/resume failed; exact termination completed (failure=$bindFailure)" 'preserve the durable failed-run record and repair native process binding before rerunning'
    }
    if ($null -eq $childProcessHandle -or $childProcessHandle.IsInvalid -or $childProcessHandle.IsClosed) {
        Fail-Astro 'ASTRO_FSV_CHILD_HANDLE_UNAVAILABLE' "native child PID $($child.Id) did not retain its exact CreateProcessW process handle" 'preserve the session and repair native process launch before rerunning'
    }
    if ($null -eq $childObservationHandle -or
        $childObservationHandle.IsInvalid -or
        $childObservationHandle.IsClosed) {
        Fail-Astro 'ASTRO_FSV_CHILD_HANDLE_UNAVAILABLE' "native child PID $($child.Id) did not retain a duplicated handle to its exact CreateProcessW process object" 'preserve the session and repair exact process-handle duplication before rerunning'
    }
    $childStartedAtUtc = [DateTime]::UtcNow.ToString('o')
    $ownedLock = Read-AstroUtf8FileLongPath $fsvLockPath | ConvertFrom-Json
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
        if (Test-AstroPathLongPath -LiteralPath $lockUpdateStage -PathType Leaf) {
            Remove-AstroFileLongPath $lockUpdateStage
        }
        Fail-Astro 'ASTRO_FSV_LOCK_UPDATE_FAILED' "publishing child PID $($child.Id) into the FSV lock failed: $($_.Exception.Message)" 'preserve state and investigate the lock writer'
    }
    $publishedLock =
        Read-AstroUtf8FileLongPath $fsvLockPath | ConvertFrom-Json
    if ([int]$publishedLock.child_pid -ne $child.Id -or [string]$publishedLock.phase -cne 'running') {
        Fail-Astro 'ASTRO_FSV_LOCK_UPDATE_FAILED' 'FSV lock child-PID readback does not match the real process' 'preserve state and investigate the durable lock write'
    }
    $liveState = [ordered]@{
        schema = 'astrolabe.native-fsv-live.v1'
        runner_pid = $PID
        launcher_pid = $launcherPid
        launcher_job = [ordered]@{
            name = $launcherJobName
            members_before = @($launcherJobMembersBefore)
        }
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
    $childExitedAtUtc = [DateTime]::UtcNow.ToString('o')
    $childExitObservation = Observe-ExitedProcessCode $child
    $childExitCode = [uint32]$childExitObservation.exit_code

    $artifactHashAfter = File-Sha256 $artifact
    $receiptHashAfter = File-Sha256 $receiptFull
    $launcherLockSnapshotAfter = Get-AstroExactRetainedFileSnapshot `
        -Handle $launcherLockHandle `
        -ExpectedPath $launcherLockPath
    $launcherLockLinksAfter =
        [AstroLauncherLockNative]::GetNumberOfLinks($launcherLockHandle)
    $launcherLockHashAfter = [string]$launcherLockSnapshotAfter.Sha256
    $launcherOwnerAfter = Read-AstroLauncherLock -LockPath $launcherLockPath
    $launcherJobProbeAfter =
        Get-AstroLauncherJobObjectProbe -Name $launcherJobName
    $launcherJobMembersAfter =
        [int[]]@($launcherJobProbeAfter.ProcessIds | Sort-Object -Unique)
    $afterRepo = Get-RepoState $gitExe $workspace
    $stdoutHash = File-Sha256 $StandardOutputPath
    $stderrHash = File-Sha256 $StandardErrorPath
    $treeStable = $beforeRepo.head_sha -ceq $afterRepo.head_sha -and
        $beforeRepo.status_sha256 -ceq $afterRepo.status_sha256 -and
        $beforeRepo.diff_sha256 -ceq $afterRepo.diff_sha256
    $artifactStable = $artifactHashBefore -ceq $artifactHashAfter -and
        (Get-AstroFileLengthLongPath $artifact) -eq
            [uint64]$receipt.artifact.bytes
    $receiptStable = $receiptHashBefore -ceq $receiptHashAfter
    $launcherJobStable = $launcherJobProbeAfter.State -ceq 'observed' -and
        $launcherJobMembersAfter -contains $launcherPid -and
        $launcherJobMembersAfter -contains $PID
    $launcherLeaseStable =
        $launcherLockLinksAfter -eq 1 -and
        $launcherLockSnapshotBefore.FileId -ceq $launcherLockSnapshotAfter.FileId -and
        $launcherLockSnapshotBefore.Length -eq $launcherLockSnapshotAfter.Length -and
        $launcherLockHashBefore -ceq $launcherLockHashAfter -and
        [Convert]::ToBase64String($launcherLockSnapshotBefore.Bytes) -ceq
            [Convert]::ToBase64String($launcherLockSnapshotAfter.Bytes) -and
        $launcherOwnerAfter.State -ceq 'held' -and
        $launcherOwnerAfter.Issue -eq $Issue -and
        $launcherOwnerAfter.OwnerPid -eq $launcherPid -and
        $launcherOwnerAfter.OwnerProcessStartUtcTicks -eq
            $launcherOwner.OwnerProcessStartUtcTicks -and
        $launcherOwnerAfter.Sha256 -ceq $launcherLockHashBefore -and
        $launcherJobStable

    # #708: a completed native child and a stable run record are not sufficient
    # cleanup evidence. Prove the *same* access/share request used by exact cleanup
    # can be acquired before returning to the caller. The execution lease must be
    # closed first because it deliberately denies DELETE for the whole child run.
    #
    # Read-only is reversibly cleared because OpenExactRenameSource requests
    # GENERIC_WRITE and Windows returns ERROR_ACCESS_DENIED for that exact open on
    # a read-only file. Once the cleanup lease is retained, restore read-only and
    # independently re-read final path, identity, link count, length, and bytes.
    # The retained lease shares reads only, so it protects the artifact against
    # write/delete drift until this runner exits.
    if ($null -ne $artifactHandle) {
        $artifactHandle.Dispose()
        $artifactHandle = $null
    }
    try {
        Set-AstroFileReadOnlyLongPath -LiteralPath $artifact -ReadOnly $false
        $artifactCleanupLease =
            [AstroLauncherLockNative]::OpenExactRenameSource($artifact)
        Set-AstroFileReadOnlyLongPath -LiteralPath $artifact -ReadOnly $true

        $cleanupFinalPath = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($artifactCleanupLease)
        )
        if (-not [string]::Equals(
                $cleanupFinalPath,
                $artifact,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "cleanup-readiness lease resolved to '$cleanupFinalPath', expected '$artifact'"
        }
        $cleanupFileId =
            [AstroLauncherLockNative]::GetFileIdentity($artifactCleanupLease)
        $cleanupLinks =
            [AstroLauncherLockNative]::GetNumberOfLinks($artifactCleanupLease)
        $cleanupLength = Get-AstroFileLengthLongPath $artifact
        $cleanupHash = File-Sha256UnderCleanupLease $artifact
        $cleanupAttributes = [IO.File]::GetAttributes(
            (ConvertTo-AstroExtendedLengthPath $artifact)
        )
        $cleanupReadOnly =
            ($cleanupAttributes -band [IO.FileAttributes]::ReadOnly) -ne 0
        if ($cleanupLinks -ne 1 -or
            $cleanupLength -ne [uint64]$receipt.artifact.bytes -or
            $cleanupHash -cne $artifactHashAfter -or
            -not $cleanupReadOnly) {
            throw "cleanup-readiness readback drifted (links=$cleanupLinks, bytes=$cleanupLength, sha256=$cleanupHash, read_only=$cleanupReadOnly)"
        }
        $artifactCleanupReadiness = [ordered]@{
            established = $true
            operation =
                'CreateFileW(GENERIC_READ|GENERIC_WRITE|DELETE,FILE_SHARE_READ)'
            final_path = $cleanupFinalPath
            file_id = $cleanupFileId
            links = [uint32]$cleanupLinks
            bytes = [uint64]$cleanupLength
            sha256 = $cleanupHash
            read_only_restored = $cleanupReadOnly
            retained_until_runner_exit = $true
        }
        $artifactStable = $artifactStable -and
            $cleanupHash -ceq $artifactHashAfter
    }
    catch {
        $readinessFailure = $_
        if ($null -ne $artifactCleanupLease) {
            $artifactCleanupLease.Dispose()
            $artifactCleanupLease = $null
        }
        try {
            if (Test-AstroPathLongPath -LiteralPath $artifact -PathType Leaf) {
                Set-AstroFileReadOnlyLongPath `
                    -LiteralPath $artifact -ReadOnly $true
            }
        }
        catch {
            Fail-Astro 'ASTRO_FSV_ARTIFACT_CLEANUP_READINESS_RESTORE_FAILED' `
                "exact cleanup readiness failed and the staged artifact read-only attribute could not be restored (readiness_failure=$($readinessFailure.Exception.Message); restore_failure=$($_.Exception.Message))" `
                'preserve the session and inspect the exact native error/handle owner before any lifecycle cleanup'
        }
        Fail-Astro 'ASTRO_FSV_ARTIFACT_CLEANUP_NOT_READY' `
            "the staged artifact is not exactly ready for cleanup after native child termination: $($readinessFailure.Exception.Message)" `
            'preserve the session; inspect the native error and exact live handle owner, then repair handle lifetime before retrying'
    }

    $verdict = if ($childExitCode -eq 0 -and [bool]$childExitObservation.sources_agree -and
        $treeStable -and $artifactStable -and $receiptStable -and
        $launcherLeaseStable -and
        [bool]$artifactCleanupReadiness.established) {
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
            launch_boundary = 'kernel32!CreateProcessW(non-null extended application; STARTUPINFOEX restricted handle list)'
            standard_input = 'NUL'
            exit_code = $childExitCode
            exit_code_observation = $childExitObservation
            started_at = $childStartedAtUtc
            exited_at = $childExitedAtUtc
            timestamp_basis = 'runner-observed-utc'
        }
        artifact = [ordered]@{ path = $artifact; bytes = Get-AstroFileLengthLongPath $artifact; sha256 = $artifactHashAfter; stable = $artifactStable; delete_share_denied_for_run = $true }
        cleanup_readiness = $artifactCleanupReadiness
        receipt = [ordered]@{ path = $receiptFull; sha256_before = $receiptHashBefore; sha256_after = $receiptHashAfter; stable = $receiptStable }
        launcher_lease = [ordered]@{
            path = $launcherLockPath
            file_id_before = $launcherLockSnapshotBefore.FileId
            file_id_after = $launcherLockSnapshotAfter.FileId
            sha256_before = $launcherLockHashBefore
            sha256_after = $launcherLockHashAfter
            links_before = $launcherLockLinksBefore
            links_after = $launcherLockLinksAfter
            owner_pid = $launcherPid
            owner_process_start_utc_ticks = $launcherOwner.OwnerProcessStartUtcTicks
            lease_start_utc_ticks = $launcherOwner.LeaseStartUtcTicks
            job = [ordered]@{
                name = $launcherJobName
                state_before = $launcherJobProbeBefore.State
                members_before = @($launcherJobMembersBefore)
                state_after = $launcherJobProbeAfter.State
                members_after = @($launcherJobMembersAfter)
                stable = $launcherJobStable
            }
            stable = $launcherLeaseStable
        }
        argument_count = $argumentCount
        arguments = @($arguments)
        stdout = [ordered]@{ path = $StandardOutputPath; bytes = Get-AstroFileLengthLongPath $StandardOutputPath; sha256 = $stdoutHash }
        stderr = [ordered]@{ path = $StandardErrorPath; bytes = Get-AstroFileLengthLongPath $StandardErrorPath; sha256 = $stderrHash }
        repository = [ordered]@{ before = $beforeRepo; after = $afterRepo; stable = $treeStable }
    }
    Write-NewDurableUtf8 $RunRecordPath ($record | ConvertTo-Json -Depth 15)
    $runRecordWritten = $true
    $persistedRecord =
        Read-AstroUtf8FileLongPath $RunRecordPath | ConvertFrom-Json
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
        Fail-Astro 'ASTRO_FSV_CHILD_EXIT_OBSERVATION_MISMATCH' "the original and duplicated exact process handles disagree on native child PID $($child.Id) exit code (primary=$childExitCode; duplicate=$($childExitObservation.exact_duplicate_exit_code))" 'preserve the run record and repair exact process-handle observation; never infer success from disagreeing sources'
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
            }
            if ($child.HasExited) {
                if ($null -eq $childExitedAtUtc) {
                    $childExitedAtUtc = [DateTime]::UtcNow.ToString('o')
                }
                if ($null -eq $childExitCode) {
                    try {
                        $childExitObservation = Observe-ExitedProcessCode $child
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
        -not (Test-AstroPathLongPath -LiteralPath $RunRecordPath)) {
        try {
            $failureArtifactHash = if (
                Test-AstroPathLongPath -LiteralPath $artifact -PathType Leaf
            ) {
                if ($null -ne $artifactCleanupLease) {
                    File-Sha256UnderCleanupLease $artifact
                }
                else {
                    File-Sha256 $artifact
                }
            }
            else { $null }
            $failureRecord = [ordered]@{
                schema = 'astrolabe.native-fsv-run.v1'
                verdict = 'failed'
                issue = $Issue
                receipt_path = $receiptFull
                process = [ordered]@{
                    pid = $child.Id
                    launch_boundary = 'kernel32!CreateProcessW(non-null extended application; STARTUPINFOEX restricted handle list)'
                    standard_input = 'NUL'
                    exit_code = $childExitCode
                    exit_code_observation = $childExitObservation
                    exit_code_observation_error = Failure-Text $childExitObservationError
                    started_at = $childStartedAtUtc
                    exited_at = $childExitedAtUtc
                    timestamp_basis = 'runner-observed-utc'
                }
                artifact = [ordered]@{
                    path = $artifact
                    bytes = if (Test-AstroPathLongPath -LiteralPath $artifact -PathType Leaf) { Get-AstroFileLengthLongPath $artifact } else { 0 }
                    sha256 = $failureArtifactHash
                    stable = $false
                }
                argument_count = $argumentCount
                arguments = @($arguments)
                stdout = [ordered]@{
                    path = $StandardOutputPath
                    bytes = if (Test-AstroPathLongPath -LiteralPath $StandardOutputPath -PathType Leaf) { Get-AstroFileLengthLongPath $StandardOutputPath } else { 0 }
                    sha256 = if (Test-AstroPathLongPath -LiteralPath $StandardOutputPath -PathType Leaf) { File-Sha256 $StandardOutputPath } else { $null }
                }
                stderr = [ordered]@{
                    path = $StandardErrorPath
                    bytes = if (Test-AstroPathLongPath -LiteralPath $StandardErrorPath -PathType Leaf) { Get-AstroFileLengthLongPath $StandardErrorPath } else { 0 }
                    sha256 = if (Test-AstroPathLongPath -LiteralPath $StandardErrorPath -PathType Leaf) { File-Sha256 $StandardErrorPath } else { $null }
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
    $childStillLive = $childTerminationUncertain
    if ($null -ne $child) {
        try { $childStillLive = -not $child.HasExited }
        catch { $childStillLive = $true }
    }
    if ($fsvLockOwned -and -not $childStillLive -and
        (Test-AstroPathLongPath -LiteralPath $fsvLockPath)) {
        $owned = $false
        try {
            $lock = Read-AstroUtf8FileLongPath $fsvLockPath | ConvertFrom-Json
            $owned = [int]$lock.pid -eq $PID -and [string]$lock.artifact_sha256 -ceq $artifactHashBefore
        }
        catch { $owned = $false }
        if ($owned) { Remove-AstroFileLongPath $fsvLockPath }
        else { [Console]::Error.WriteLine('NATIVE_FSV[ASTRO_FSV_LOCK_IDENTITY_CHANGED]: refusing to remove FSV lock whose identity changed while the runner was live') }
    }
    elseif ($fsvLockOwned -and $childStillLive) {
        [Console]::Error.WriteLine('NATIVE_FSV[ASTRO_FSV_LOCK_PRESERVED_LIVE_CHILD]: preserving the FSV lock because the recorded real child is still live')
    }
    if ($null -ne $createdChild) { $createdChild.Dispose() }
    if ($null -ne $child) { $child.Dispose() }
    if ($null -ne $artifactCleanupLease) {
        $artifactCleanupLease.Dispose()
    }
}
