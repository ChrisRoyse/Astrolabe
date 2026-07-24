<#
.SYNOPSIS
    Retained-handle, console-isolated native Windows process creation.

.DESCRIPTION
    Creates one exact child image with CreateProcessW, an explicit application path,
    byte-preserving Windows argv quoting, and a restricted inherited-handle list.  The
    returned lease retains the real process handle, publishes the process creation time
    and session ID obtained from that handle, and validates both the wait result and
    terminal exit code.

    The lease is authority to wait for this exact child generation.  A numeric PID is
    diagnostic data only.

.NOTES
    Refs #396, #616.
#>

Set-StrictMode -Version Latest

if (-not ([System.Management.Automation.PSTypeName]'AstroDetachV2').Type) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public sealed class AstroDetachedProcessLease : IDisposable {
    private SafeWaitHandle processHandle;
    private bool waited;
    private int exitCode;

    internal AstroDetachedProcessLease(
        IntPtr rawProcessHandle,
        int processId,
        long processStartUtcTicks,
        int sessionId,
        string applicationPath,
        string commandLine
    ) {
        processHandle = new SafeWaitHandle(rawProcessHandle, true);
        ProcessId = processId;
        ProcessStartUtcTicks = processStartUtcTicks;
        ProcessStartedUtc = new DateTime(processStartUtcTicks, DateTimeKind.Utc).ToString("o");
        SessionId = sessionId;
        ApplicationPath = applicationPath;
        CommandLine = commandLine;
    }

    public int ProcessId { get; private set; }
    public long ProcessStartUtcTicks { get; private set; }
    public string ProcessStartedUtc { get; private set; }
    public int SessionId { get; private set; }
    public string ApplicationPath { get; private set; }
    public string CommandLine { get; private set; }
    public bool HasExited { get { return waited; } }
    public int ExitCode {
        get {
            if (!waited) throw new InvalidOperationException("The exact child has not been waited to termination.");
            return exitCode;
        }
    }

    public int Wait() {
        if (waited) return exitCode;
        if (processHandle == null || processHandle.IsClosed || processHandle.IsInvalid)
            throw new ObjectDisposedException("AstroDetachedProcessLease");

        uint waitResult = AstroDetachV2.WaitExact(processHandle.DangerousGetHandle());
        if (waitResult != AstroDetachV2.WAIT_OBJECT_0) {
            if (waitResult == AstroDetachV2.WAIT_FAILED)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject failed for exact detached child");
            throw new InvalidOperationException(
                "WaitForSingleObject returned unexpected value 0x" + waitResult.ToString("x8"));
        }

        uint rawExitCode = AstroDetachV2.ReadExitCode(processHandle.DangerousGetHandle());
        if (rawExitCode == AstroDetachV2.STILL_ACTIVE)
            throw new InvalidOperationException("A signaled exact child reported STILL_ACTIVE.");
        exitCode = unchecked((int)rawExitCode);
        waited = true;
        processHandle.Dispose();
        return exitCode;
    }

    public void Dispose() {
        if (processHandle != null) {
            processHandle.Dispose();
            processHandle = null;
        }
        GC.SuppressFinalize(this);
    }
}

public static class AstroDetachV2 {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOEX {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(
        string lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList,
        int dwAttributeCount,
        int dwFlags,
        ref IntPtr lpSize
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList,
        uint dwFlags,
        IntPtr attribute,
        IntPtr lpValue,
        IntPtr cbSize,
        IntPtr lpPreviousValue,
        IntPtr lpReturnSize
    );

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        ref SECURITY_ATTRIBUTES lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(
        IntPtr hSourceProcessHandle,
        IntPtr hSourceHandle,
        IntPtr hTargetProcessHandle,
        out IntPtr lpTargetHandle,
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwOptions
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(
        IntPtr hProcess,
        out FILETIME lpCreationTime,
        out FILETIME lpExitTime,
        out FILETIME lpKernelTime,
        out FILETIME lpUserTime
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ_WRITE = 0x00000003;
    private const uint OPEN_EXISTING = 3;
    private const uint DUPLICATE_SAME_ACCESS = 0x00000002;
    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST =
        new IntPtr(0x00020002);
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    private const long FILETIME_TO_DOTNET_TICKS = 504911232000000000L;
    private const uint INFINITE = 0xffffffff;
    public const uint WAIT_OBJECT_0 = 0x00000000;
    public const uint WAIT_FAILED = 0xffffffff;
    public const uint STILL_ACTIVE = 259;

    public static string QuoteArgument(string value) {
        if (value == null) throw new ArgumentNullException("value");
        StringBuilder quoted = new StringBuilder();
        quoted.Append('"');
        int backslashes = 0;
        foreach (char current in value) {
            if (current == '\\') {
                backslashes++;
                continue;
            }
            if (current == '"') {
                quoted.Append('\\', checked(backslashes * 2 + 1));
                quoted.Append('"');
                backslashes = 0;
                continue;
            }
            if (backslashes > 0) {
                quoted.Append('\\', backslashes);
                backslashes = 0;
            }
            quoted.Append(current);
        }
        if (backslashes > 0) quoted.Append('\\', checked(backslashes * 2));
        quoted.Append('"');
        return quoted.ToString();
    }

    public static string BuildCommandLine(string applicationPath, string[] arguments) {
        if (String.IsNullOrWhiteSpace(applicationPath))
            throw new ArgumentException("applicationPath must be nonblank", "applicationPath");
        StringBuilder commandLine = new StringBuilder(QuoteArgument(applicationPath));
        if (arguments != null) {
            foreach (string argument in arguments) {
                if (argument == null)
                    throw new ArgumentException("arguments cannot contain null", "arguments");
                commandLine.Append(' ');
                commandLine.Append(QuoteArgument(argument));
            }
        }
        if (commandLine.Length >= 32767)
            throw new ArgumentException(
                "CreateProcessW command line must be shorter than 32767 UTF-16 code units.",
                "arguments");
        return commandLine.ToString();
    }

    public static AstroDetachedProcessLease Spawn(
        string applicationPath,
        string[] arguments,
        string workingDirectory,
        SafeFileHandle logHandle
    ) {
        if (logHandle == null || logHandle.IsInvalid || logHandle.IsClosed)
            throw new ArgumentException("logHandle must be live", "logHandle");
        string commandLineText = BuildCommandLine(applicationPath, arguments);
        StringBuilder commandLine = new StringBuilder(commandLineText);

        IntPtr sourceLog = logHandle.DangerousGetHandle();
        IntPtr inheritedLog = IntPtr.Zero;
        IntPtr input = IntPtr.Zero;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr handleList = IntPtr.Zero;
        PROCESS_INFORMATION process = new PROCESS_INFORMATION();
        try {
            IntPtr currentProcess = GetCurrentProcess();
            if (!DuplicateHandle(
                    currentProcess,
                    sourceLog,
                    currentProcess,
                    out inheritedLog,
                    0,
                    true,
                    DUPLICATE_SAME_ACCESS))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "DuplicateHandle(inheritable log) failed");

            SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES();
            security.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            security.bInheritHandle = true;
            input = CreateFileW(
                "NUL",
                GENERIC_READ,
                FILE_SHARE_READ_WRITE,
                ref security,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);
            if (input == INVALID_HANDLE_VALUE)
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "CreateFileW(NUL) for detached stdin failed");

            IntPtr attributeBytes = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeBytes);
            int sizingError = Marshal.GetLastWin32Error();
            if (attributeBytes == IntPtr.Zero)
                throw new Win32Exception(
                    sizingError,
                    "InitializeProcThreadAttributeList sizing failed");
            attributeList = Marshal.AllocHGlobal(attributeBytes);
            if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeBytes))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "InitializeProcThreadAttributeList failed");

            handleList = Marshal.AllocHGlobal(IntPtr.Size * 2);
            Marshal.WriteIntPtr(handleList, 0, input);
            Marshal.WriteIntPtr(handleList, IntPtr.Size, inheritedLog);
            if (!UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    handleList,
                    new IntPtr(IntPtr.Size * 2),
                    IntPtr.Zero,
                    IntPtr.Zero))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "UpdateProcThreadAttribute(handle list) failed");

            STARTUPINFOEX startup = new STARTUPINFOEX();
            startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = input;
            startup.StartupInfo.hStdOutput = inheritedLog;
            startup.StartupInfo.hStdError = inheritedLog;
            startup.lpAttributeList = attributeList;

            uint creationFlags =
                CREATE_NO_WINDOW |
                CREATE_NEW_PROCESS_GROUP |
                CREATE_UNICODE_ENVIRONMENT |
                EXTENDED_STARTUPINFO_PRESENT;
            if (!CreateProcessW(
                    applicationPath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    creationFlags,
                    IntPtr.Zero,
                    workingDirectory,
                    ref startup,
                    out process))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "CreateProcessW failed for exact application '" + applicationPath + "'");

            CloseCreatedHandleChecked(
                ref process.hThread,
                "CloseHandle(child thread) failed after exact process creation");
            CloseCreatedHandleChecked(
                ref inheritedLog,
                "CloseHandle(parent inheritable log duplicate) failed after exact process creation");
            CloseCreatedHandleChecked(
                ref input,
                "CloseHandle(parent NUL input) failed after exact process creation");

            FILETIME creation;
            FILETIME exit;
            FILETIME kernel;
            FILETIME user;
            if (!GetProcessTimes(process.hProcess, out creation, out exit, out kernel, out user))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetProcessTimes failed for retained detached child");
            ulong fileTime = ((ulong)creation.dwHighDateTime << 32) | creation.dwLowDateTime;
            long startTicks = checked((long)fileTime + FILETIME_TO_DOTNET_TICKS);

            uint session;
            if (!ProcessIdToSessionId((uint)process.dwProcessId, out session))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "ProcessIdToSessionId failed for retained detached child");

            AstroDetachedProcessLease lease = new AstroDetachedProcessLease(
                process.hProcess,
                process.dwProcessId,
                startTicks,
                checked((int)session),
                applicationPath,
                commandLineText);
            process.hProcess = IntPtr.Zero;
            return lease;
        }
        catch (Exception error) {
            if (process.hProcess != IntPtr.Zero)
                throw ContainCreatedProcessAfterSpawnFault(ref process, error);
            throw;
        }
        finally {
            if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
            if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
            if (attributeList != IntPtr.Zero) {
                DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }
            if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
            if (input != IntPtr.Zero && input != INVALID_HANDLE_VALUE) CloseHandle(input);
            if (inheritedLog != IntPtr.Zero) CloseHandle(inheritedLog);
        }
    }

    private static void CloseCreatedHandleChecked(
        ref IntPtr handle,
        string message
    ) {
        if (handle == IntPtr.Zero || handle == INVALID_HANDLE_VALUE) {
            handle = IntPtr.Zero;
            return;
        }
        if (!CloseHandle(handle))
            throw new Win32Exception(Marshal.GetLastWin32Error(), message);
        handle = IntPtr.Zero;
    }

    private static Exception ContainCreatedProcessAfterSpawnFault(
        ref PROCESS_INFORMATION process,
        Exception original
    ) {
        string containment;
        uint waitResult = WaitForSingleObject(process.hProcess, INFINITE);
        if (waitResult == WAIT_OBJECT_0) {
            uint childExitCode;
            if (GetExitCodeProcess(process.hProcess, out childExitCode))
                containment =
                    "exact child waited naturally to exit code " +
                    unchecked((int)childExitCode);
            else
                containment =
                    "exact child waited naturally; GetExitCodeProcess then failed with Win32 error " +
                    Marshal.GetLastWin32Error();
        }
        else if (waitResult == WAIT_FAILED) {
            containment =
                "exact-child containment wait failed with Win32 error " +
                Marshal.GetLastWin32Error();
        }
        else {
            containment =
                "exact-child containment wait returned unexpected value 0x" +
                waitResult.ToString("x8");
        }

        if (process.hThread != IntPtr.Zero) {
            CloseHandle(process.hThread);
            process.hThread = IntPtr.Zero;
        }
        if (process.hProcess != IntPtr.Zero) {
            CloseHandle(process.hProcess);
            process.hProcess = IntPtr.Zero;
        }
        return new InvalidOperationException(
            "post-CreateProcessW detached spawn fault; " + containment,
            original);
    }

    internal static uint WaitExact(IntPtr processHandle) {
        return WaitForSingleObject(processHandle, INFINITE);
    }

    internal static uint ReadExitCode(IntPtr processHandle) {
        uint code;
        if (!GetExitCodeProcess(processHandle, out code))
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "GetExitCodeProcess failed for exact detached child");
        return code;
    }
}
'@
}

function Start-AstroDetachedProcessRetained {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [Parameter(Mandatory)][string]$LogFile,
        [Parameter(Mandatory)][string]$WorkingDirectory
    )

    $application = [IO.Path]::GetFullPath($FilePath)
    if (-not [IO.Path]::IsPathRooted($FilePath) -or
        -not [IO.File]::Exists($application)) {
        throw "DETACH_SPAWN[ASTRO_DETACH_APPLICATION_INVALID]: {code=ASTRO_DETACH_APPLICATION_INVALID; message=`"exact absolute application does not exist: $FilePath`"; remediation=`"pass one existing absolute executable path`"}"
    }
    $working = [IO.Path]::GetFullPath($WorkingDirectory)
    if (-not [IO.Directory]::Exists($working)) {
        throw "DETACH_SPAWN[ASTRO_DETACH_WORKING_DIRECTORY_INVALID]: {code=ASTRO_DETACH_WORKING_DIRECTORY_INVALID; message=`"working directory does not exist: $working`"; remediation=`"create and validate the ordinary working directory before spawn`"}"
    }
    $workingInfo = [IO.DirectoryInfo]::new($working)
    if (($workingInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "DETACH_SPAWN[ASTRO_DETACH_WORKING_DIRECTORY_REPARSE]: {code=ASTRO_DETACH_WORKING_DIRECTORY_REPARSE; message=`"working directory is a reparse point: $working`"; remediation=`"use the canonical ordinary workspace root`"}"
    }
    $log = [IO.Path]::GetFullPath($LogFile)
    $logParent = [IO.Path]::GetDirectoryName($log)
    if (-not [IO.Directory]::Exists($logParent)) {
        throw "DETACH_SPAWN[ASTRO_DETACH_LOG_PARENT_MISSING]: {code=ASTRO_DETACH_LOG_PARENT_MISSING; message=`"log parent does not exist: $logParent`"; remediation=`"create and bind the run directory before spawn`"}"
    }

    $stream = [IO.File]::Open(
        $log,
        [IO.FileMode]::Append,
        [IO.FileAccess]::Write,
        [IO.FileShare]::ReadWrite
    )
    try {
        return [AstroDetachV2]::Spawn(
            $application,
            [string[]]$ArgumentList,
            $working,
            $stream.SafeFileHandle
        )
    }
    finally {
        $stream.Dispose()
    }
}
