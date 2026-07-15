<#
.SYNOPSIS
    Console-immune detached child-process spawner (#396).

.DESCRIPTION
    The #391 Task Scheduler trampoline breaks the JOB-OBJECT / process-TREE link so a
    detached run survives `taskkill /T` of the launching shell. It does NOT break the
    CONSOLE link: a process that shares/owns a console still receives console-control
    events (CTRL_C, CTRL_BREAK, CTRL_CLOSE, CTRL_LOGOFF, CTRL_SHUTDOWN). Wave-15's P3
    batch was killed twice with exit code 0xC000013A (STATUS_CONTROL_C_EXIT) — a
    console-control event reaching the tree through that surviving link (#396).

    Root-cause cure (documented, not a workaround): create the child with
    DETACHED_PROCESS so it has NO console at all — a process with no console CANNOT be
    delivered any console-control event — plus CREATE_NEW_PROCESS_GROUP (an implicit
    SetConsoleCtrlHandler(NULL,TRUE) that disables CTRL+C for the whole group even if a
    console were present later). Child stdout+stderr are redirected to an inheritable
    file handle because a console-less child has no default std handles.

    This is intentionally NOT combined with CREATE_BREAKAWAY_FROM_JOB: job/tree
    detachment is already provided by the schtasks trampoline, and BREAKAWAY fails unless
    the enclosing job explicitly permits it — adding it would introduce a conditional
    failure/fallback we don't need. The two mechanisms are orthogonal and layered.

    Start-FullyDetachedProcess launches the child and returns its PID. Completion is
    observed via the child's own sentinel/death-marker (the caller's contract), matching
    the fire-and-forget model of the surrounding harness.

.NOTES
    Refs #396, #391. No elevation required.
#>

Set-StrictMode -Version Latest

if (-not ([System.Management.Automation.PSTypeName]'AstroDetach').Type) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class AstroDetach {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX; public int dwY; public int dwXSize; public int dwYSize;
        public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow; public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess; public IntPtr hThread;
        public int dwProcessId; public int dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(
        string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    const uint INFINITE = 0xFFFFFFFF;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    const uint GENERIC_READ   = 0x80000000;
    const uint FILE_SHARE_RW  = 0x00000003;
    const uint OPEN_EXISTING  = 3;
    static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

    const uint CREATE_NO_WINDOW            = 0x08000000;
    const uint CREATE_NEW_PROCESS_GROUP    = 0x00000200;
    const uint CREATE_UNICODE_ENVIRONMENT  = 0x00000400;
    const int  STARTF_USESTDHANDLES        = 0x00000100;
    const uint HANDLE_FLAG_INHERIT         = 0x00000001;

    // Launch commandLine as a fully console-detached process, redirecting its stdout and
    // stderr to logHandle and its stdin to inHandle (a read handle on the NUL device).
    // Both handles must be inheritable; we set the inherit flag here. A console-less child
    // with STARTF_USESTDHANDLES requires ALL THREE std handles to be valid — a NULL stdin
    // makes powershell.exe fail at startup, so a real NUL handle is mandatory, not optional.
    // Returns the child PID. Throws Win32Exception with the concrete GetLastError on failure.
    // Shared CreateProcess with console-immune flags and std-handle redirection. Returns the
    // PROCESS_INFORMATION (caller owns hProcess/hThread and must close them).
    static PROCESS_INFORMATION Create(string commandLine, string workingDir, SafeFileHandle logHandle) {
        IntPtr h = logHandle.DangerousGetHandle();
        if (!SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "SetHandleInformation(stdout inherit) failed");

        // A console-less child with STARTF_USESTDHANDLES needs a valid stdin, or powershell.exe
        // fails at startup. Open the NUL device via CreateFileW (.NET refuses reserved device
        // paths) as an inheritable empty-input handle.
        IntPtr hin = CreateFileW("NUL", GENERIC_READ, FILE_SHARE_RW, IntPtr.Zero,
                                 OPEN_EXISTING, 0, IntPtr.Zero);
        if (hin == INVALID_HANDLE)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW(NUL) for stdin failed");
        if (!SetHandleInformation(hin, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
            int e = Marshal.GetLastWin32Error(); CloseHandle(hin);
            throw new Win32Exception(e, "SetHandleInformation(stdin inherit) failed");
        }

        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = hin;
        si.hStdOutput = h;
        si.hStdError = h;

        // CREATE_NO_WINDOW (not DETACHED_PROCESS): the child gets its OWN windowless console,
        // which powershell.exe's console host requires to initialize. That console is separate
        // from the launcher's, so a CTRL_CLOSE/CTRL_C event on the launcher's console cannot
        // reach the child (the wave-15 0xC000013A vector). CREATE_NEW_PROCESS_GROUP additionally
        // disables CTRL+C for the child's own group. DETACHED_PROCESS was proven to kill
        // powershell.exe at startup (FSV 2026-07-14), so it is deliberately not used here.
        uint flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT;

        PROCESS_INFORMATION pi;
        bool ok = CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero,
                                 true, flags, IntPtr.Zero, workingDir, ref si, out pi);
        int lastErr = Marshal.GetLastWin32Error();
        CloseHandle(hin); // the child has inherited its own copy
        if (!ok)
            throw new Win32Exception(lastErr, "CreateProcessW(CREATE_NO_WINDOW) failed for: " + commandLine);
        return pi;
    }

    // Fire-and-forget: launch and return the child PID. Completion is observed via the child's
    // own sentinel by the caller.
    public static int Spawn(string commandLine, string workingDir, SafeFileHandle logHandle) {
        PROCESS_INFORMATION pi = Create(commandLine, workingDir, logHandle);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return pi.dwProcessId;
    }

    // Launch, record the child PID to pidFile immediately (for liveness probes), then WAIT on the
    // real Win32 process handle and return its true exit code via GetExitCodeProcess. Foreign
    // .NET Process.ExitCode is unreliable for a CreateProcess'd child; this reads the OS directly.
    public static int SpawnAndWait(string commandLine, string workingDir, SafeFileHandle logHandle, string pidFile) {
        PROCESS_INFORMATION pi = Create(commandLine, workingDir, logHandle);
        CloseHandle(pi.hThread);
        try {
            if (!string.IsNullOrEmpty(pidFile))
                System.IO.File.WriteAllText(pidFile, pi.dwProcessId.ToString());
            WaitForSingleObject(pi.hProcess, INFINITE);
            uint code;
            if (!GetExitCodeProcess(pi.hProcess, out code))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess failed");
            return unchecked((int)code);
        }
        finally {
            CloseHandle(pi.hProcess);
        }
    }
}
'@
}

function Start-FullyDetachedProcess {
    <#
      Launches $FilePath $ArgumentList as a console-immune detached process whose combined
      stdout+stderr append to $LogFile. Returns the child PID. Fail-closed: any Win32 error
      surfaces as a terminating exception with the concrete GetLastError code.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [Parameter(Mandatory)][string]$LogFile,
        [string]$WorkingDirectory = (Get-Location).Path
    )

    $parent = Split-Path -Parent $LogFile
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    # Build a properly quoted command line (CreateProcess takes one string). Quote any token
    # containing whitespace or quotes; escape embedded quotes per the CRT/CommandLineToArgvW rules.
    $tokens = @($FilePath) + $ArgumentList
    $quoted = foreach ($t in $tokens) {
        if ($t -match '[\s"]') { '"' + ($t -replace '(\\*)"', '$1$1\"') + '"' } else { $t }
    }
    $commandLine = ($quoted -join ' ')

    # FileShare.ReadWrite so a concurrent reader (monitor tailing the log) never blocks the child.
    $fs = [System.IO.File]::Open($LogFile, [System.IO.FileMode]::Append,
                                 [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    try {
        $pidValue = [AstroDetach]::Spawn($commandLine, $WorkingDirectory, $fs.SafeFileHandle)
    }
    finally {
        $fs.Close()
    }
    return $pidValue
}

function Invoke-FullyDetachedProcessAndWait {
    <#
      Like Start-FullyDetachedProcess, but writes the child PID to $PidFile immediately and BLOCKS
      until the child exits, returning its true OS exit code (read from the Win32 handle, not the
      unreliable .NET Process.ExitCode of a foreign process). Used by the detach-run.ps1 runner so
      DoneFile carries a real exit code. If the runner is hard-killed mid-wait, the console-immune
      child keeps running and writes its own sentinel.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [Parameter(Mandatory)][string]$LogFile,
        [Parameter(Mandatory)][string]$PidFile,
        [string]$WorkingDirectory = (Get-Location).Path
    )
    $parent = Split-Path -Parent $LogFile
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $tokens = @($FilePath) + $ArgumentList
    $quoted = foreach ($t in $tokens) {
        if ($t -match '[\s"]') { '"' + ($t -replace '(\\*)"', '$1$1\"') + '"' } else { $t }
    }
    $commandLine = ($quoted -join ' ')
    $fs = [System.IO.File]::Open($LogFile, [System.IO.FileMode]::Append,
                                 [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    try {
        $code = [AstroDetach]::SpawnAndWait($commandLine, $WorkingDirectory, $fs.SafeFileHandle, $PidFile)
    }
    finally {
        $fs.Close()
    }
    return $code
}
