// One windowless Task Scheduler boundary for scripts/detach-run.ps1 (#1065).
// Compiled once per detached run as an x64 Windows GUI program. The task never
// launches a console-subsystem image directly into the interactive desktop.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AstroDetachBootstrap
{
    internal sealed class BoundFile : IDisposable
    {
        internal readonly string Path;
        internal readonly string Sha256;
        internal readonly long Length;
        private FileStream stream;

        internal BoundFile(string path, string expectedSha256, string description)
        {
            Path = System.IO.Path.GetFullPath(path);
            if (!System.IO.Path.IsPathRooted(path) || !File.Exists(Path))
                throw new InvalidOperationException(
                    description + " is not one existing absolute file: " + path);
            FileAttributes attributes = File.GetAttributes(Path);
            if ((attributes & FileAttributes.Directory) != 0 ||
                (attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException(
                    description + " must be an ordinary non-reparse file: " + Path);

            stream = new FileStream(
                Path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                1024 * 1024,
                FileOptions.SequentialScan);
            Length = stream.Length;
            using (SHA256 hasher = SHA256.Create())
                Sha256 = Hex(hasher.ComputeHash(stream));
            stream.Position = 0;
            if (!String.Equals(Sha256, expectedSha256, StringComparison.Ordinal))
                throw new InvalidOperationException(
                    description + " SHA-256 differs: expected=" + expectedSha256 +
                    " observed=" + Sha256 + " path=" + Path);
        }

        public void Dispose()
        {
            if (stream != null)
            {
                stream.Dispose();
                stream = null;
            }
            GC.SuppressFinalize(this);
        }

        internal static string Hex(byte[] bytes)
        {
            StringBuilder text = new StringBuilder(checked(bytes.Length * 2));
            foreach (byte value in bytes)
                text.Append(value.ToString("x2", CultureInfo.InvariantCulture));
            return text.ToString();
        }
    }

    internal sealed class Options
    {
        internal string RunDirectory;
        internal string RunId;
        internal string PowerShellPath;
        internal string PowerShellSha256;
        internal string RunnerPath;
        internal string RunnerSha256;
        internal string BootstrapPath;
        internal string BootstrapSha256;
        internal string WorkingDirectory;
    }

    internal sealed class ChildResult
    {
        internal int ProcessId;
        internal long ProcessStartUtcTicks;
        internal int SessionId;
        internal int ExitCode;
        internal uint WaitResult;
        internal string CommandLine;
    }

    internal static class Program
    {
#pragma warning disable 0649 // Native output fields are populated by Win32.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
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
        private struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }
#pragma warning restore 0649

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
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

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
            IntPtr hTemplateFile);

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
            uint dwOptions);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(
            IntPtr hProcess,
            out FILETIME lpCreationTime,
            out FILETIME lpExitTime,
            out FILETIME lpKernelTime,
            out FILETIME lpUserTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ProcessIdToSessionId(
            uint dwProcessId,
            out uint pSessionId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(
            IntPtr hProcess,
            out uint lpExitCode);

        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ_WRITE = 0x00000003;
        private const uint OPEN_EXISTING = 3;
        private const uint DUPLICATE_SAME_ACCESS = 0x00000002;
        private const int STARTF_USESHOWWINDOW = 0x00000001;
        private const int STARTF_USESTDHANDLES = 0x00000100;
        private const short SW_HIDE = 0;
        private const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint CREATION_FLAGS =
            CREATE_NO_WINDOW |
            CREATE_NEW_PROCESS_GROUP |
            CREATE_UNICODE_ENVIRONMENT |
            EXTENDED_STARTUPINFO_PRESENT;
        private static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST =
            new IntPtr(0x00020002);
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        private const long FILETIME_TO_DOTNET_TICKS = 504911232000000000L;
        private const uint INFINITE = 0xffffffff;
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_FAILED = 0xffffffff;
        private const uint STILL_ACTIVE = 259;
        private const int BOOTSTRAP_FAILURE_EXIT = 70;
        private const int BOOTSTRAP_FAULT_PUBLICATION_FAILURE_EXIT = 71;
        private static readonly Encoding Utf8 = new UTF8Encoding(false, true);

        [STAThread]
        private static int Main(string[] args)
        {
            Options options = null;
            string stage = "argument-parse";
            bool bootstrapLogOwned = false;
            try
            {
                options = ParseOptions(args);
                stage = "path-validation";
                ValidateOptions(options);
                string executingPath = Path.GetFullPath(
                    Assembly.GetExecutingAssembly().Location);
                if (!PathEquals(executingPath, options.BootstrapPath))
                    throw new InvalidOperationException(
                        "executing bootstrap path differs from the bound path: expected=" +
                        options.BootstrapPath + " observed=" + executingPath);

                string startPath = Path.Combine(
                    options.RunDirectory,
                    "bootstrap-start.json");
                string faultPath = Path.Combine(
                    options.RunDirectory,
                    "bootstrap-fault.json");
                string completionPath = Path.Combine(
                    options.RunDirectory,
                    "bootstrap-completion.json");
                string bootstrapLog = Path.Combine(
                    options.RunDirectory,
                    "bootstrap.log");
                string runnerLog = Path.Combine(
                    options.RunDirectory,
                    "bootstrap-runner.log");
                foreach (string output in new[] {
                    startPath, faultPath, completionPath, bootstrapLog, runnerLog })
                {
                    if (File.Exists(output) || Directory.Exists(output))
                        throw new InvalidOperationException(
                            "bootstrap output path is not absent: " + output);
                }

                Process current = Process.GetCurrentProcess();
                int bootstrapPid = current.Id;
                long bootstrapTicks = current.StartTime.ToUniversalTime().Ticks;
                int bootstrapSession = current.SessionId;

                stage = "hash-binding";
                using (BoundFile bootstrap = new BoundFile(
                    options.BootstrapPath,
                    options.BootstrapSha256,
                    "bootstrap"))
                using (BoundFile powershell = new BoundFile(
                    options.PowerShellPath,
                    options.PowerShellSha256,
                    "Windows PowerShell"))
                using (BoundFile runner = new BoundFile(
                    options.RunnerPath,
                    options.RunnerSha256,
                    "detached runner"))
                {
                    stage = "start-record";
                    WriteCreateNew(
                        startPath,
                        Object(
                            StringField("schema", "astrolabe.detached.bootstrap-start.v1"),
                            StringField("run_id", options.RunId),
                            IntegerField("written_utc_ticks", DateTime.UtcNow.Ticks),
                            IntegerField("bootstrap_pid", bootstrapPid),
                            IntegerField("bootstrap_start_utc_ticks", bootstrapTicks),
                            IntegerField("bootstrap_session_id", bootstrapSession),
                            StringField("bootstrap_path", bootstrap.Path),
                            StringField("bootstrap_sha256", bootstrap.Sha256),
                            IntegerField("bootstrap_bytes", bootstrap.Length),
                            StringField("powershell_path", powershell.Path),
                            StringField("powershell_sha256", powershell.Sha256),
                            IntegerField("powershell_bytes", powershell.Length),
                            StringField("runner_path", runner.Path),
                            StringField("runner_sha256", runner.Sha256),
                            IntegerField("runner_bytes", runner.Length),
                            StringField("working_directory", options.WorkingDirectory),
                            IntegerField("creation_flags", CREATION_FLAGS),
                            IntegerField("startup_show_window", SW_HIDE),
                            StringField("runner_log_path", runnerLog)));
                    AppendEvent(
                        bootstrapLog,
                        options.RunId,
                        "bootstrap-bound",
                        "exact bootstrap, PowerShell, and runner byte leases retained");
                    bootstrapLogOwned = true;

                    stage = "runner-spawn-and-wait";
                    ChildResult child = SpawnAndWait(
                        powershell.Path,
                        new[] {
                            "-NoProfile",
                            "-NonInteractive",
                            "-ExecutionPolicy",
                            "Bypass",
                            "-File",
                            runner.Path,
                            "-RunDirectory",
                            options.RunDirectory
                        },
                        options.WorkingDirectory,
                        runnerLog);

                    stage = "completion-record";
                    FileInfo runnerLogInfo = new FileInfo(runnerLog);
                    string runnerLogSha256 = FileSha256(runnerLog);
                    WriteCreateNew(
                        completionPath,
                        Object(
                            StringField("schema", "astrolabe.detached.bootstrap-completion.v1"),
                            StringField("run_id", options.RunId),
                            IntegerField("written_utc_ticks", DateTime.UtcNow.Ticks),
                            IntegerField("bootstrap_pid", bootstrapPid),
                            IntegerField("bootstrap_start_utc_ticks", bootstrapTicks),
                            IntegerField("bootstrap_session_id", bootstrapSession),
                            IntegerField("runner_pid", child.ProcessId),
                            IntegerField("runner_start_utc_ticks", child.ProcessStartUtcTicks),
                            IntegerField("runner_session_id", child.SessionId),
                            IntegerField("runner_exit_code", child.ExitCode),
                            StringField(
                                "runner_exit_code_hex",
                                "0x" + unchecked((uint)child.ExitCode).ToString(
                                    "x8",
                                    CultureInfo.InvariantCulture)),
                            IntegerField("wait_result", child.WaitResult),
                            IntegerField("creation_flags", CREATION_FLAGS),
                            StringField("command_line", child.CommandLine),
                            StringField("runner_log_path", runnerLog),
                            IntegerField("runner_log_bytes", runnerLogInfo.Length),
                            StringField("runner_log_sha256", runnerLogSha256)));
                    AppendEvent(
                        bootstrapLog,
                        options.RunId,
                        "runner-terminal",
                        "exact runner exit=" + child.ExitCode.ToString(
                            CultureInfo.InvariantCulture));
                    return child.ExitCode;
                }
            }
            catch (Exception error)
            {
                return TryWriteFault(options, stage, error, bootstrapLogOwned)
                    ? BOOTSTRAP_FAILURE_EXIT
                    : BOOTSTRAP_FAULT_PUBLICATION_FAILURE_EXIT;
            }
        }

        private static Options ParseOptions(string[] args)
        {
            if (args == null || args.Length % 2 != 0)
                throw new ArgumentException(
                    "bootstrap arguments must be exact name/value pairs");
            Dictionary<string, string> values =
                new Dictionary<string, string>(StringComparer.Ordinal);
            for (int index = 0; index < args.Length; index += 2)
            {
                string name = args[index];
                string value = args[index + 1];
                if (!values.ContainsKey(name))
                    values.Add(name, value);
                else
                    throw new ArgumentException("duplicate bootstrap option: " + name);
            }
            string[] expected = {
                "--run-directory",
                "--run-id",
                "--powershell-path",
                "--powershell-sha256",
                "--runner-path",
                "--runner-sha256",
                "--bootstrap-path",
                "--bootstrap-sha256",
                "--working-directory"
            };
            if (values.Count != expected.Length)
                throw new ArgumentException(
                    "bootstrap option count differs: expected=" + expected.Length +
                    " observed=" + values.Count);
            foreach (string name in expected)
                if (!values.ContainsKey(name))
                    throw new ArgumentException("missing bootstrap option: " + name);

            return new Options {
                RunDirectory = values["--run-directory"],
                RunId = values["--run-id"],
                PowerShellPath = values["--powershell-path"],
                PowerShellSha256 = values["--powershell-sha256"],
                RunnerPath = values["--runner-path"],
                RunnerSha256 = values["--runner-sha256"],
                BootstrapPath = values["--bootstrap-path"],
                BootstrapSha256 = values["--bootstrap-sha256"],
                WorkingDirectory = values["--working-directory"]
            };
        }

        private static void ValidateOptions(Options options)
        {
            if (!IsLowerHex(options.RunId, 32))
                throw new ArgumentException(
                    "run id must be 32 lowercase hexadecimal characters");
            options.RunDirectory = Path.GetFullPath(options.RunDirectory).TrimEnd('\\');
            options.PowerShellPath = Path.GetFullPath(options.PowerShellPath);
            options.RunnerPath = Path.GetFullPath(options.RunnerPath);
            options.BootstrapPath = Path.GetFullPath(options.BootstrapPath);
            options.WorkingDirectory = Path.GetFullPath(
                options.WorkingDirectory).TrimEnd('\\');
            if (!Directory.Exists(options.RunDirectory))
                throw new DirectoryNotFoundException(
                    "run directory is missing: " + options.RunDirectory);
            if (!String.Equals(
                    Path.GetFileName(options.RunDirectory),
                    options.RunId,
                    StringComparison.Ordinal))
                throw new InvalidOperationException(
                    "run directory leaf differs from run id");
            if (!Directory.Exists(options.WorkingDirectory))
                throw new DirectoryNotFoundException(
                    "working directory is missing: " + options.WorkingDirectory);
            if (!IsLowerHex(options.PowerShellSha256, 64) ||
                !IsLowerHex(options.RunnerSha256, 64) ||
                !IsLowerHex(options.BootstrapSha256, 64))
                throw new ArgumentException(
                    "all expected SHA-256 values must be lowercase hexadecimal");
        }

        private static ChildResult SpawnAndWait(
            string applicationPath,
            string[] arguments,
            string workingDirectory,
            string logPath)
        {
            string commandLineText = BuildCommandLine(applicationPath, arguments);
            StringBuilder commandLine = new StringBuilder(commandLineText);
            IntPtr inheritedLog = IntPtr.Zero;
            IntPtr input = IntPtr.Zero;
            IntPtr attributeList = IntPtr.Zero;
            IntPtr handleList = IntPtr.Zero;
            PROCESS_INFORMATION process = new PROCESS_INFORMATION();
            FileStream log = null;
            try
            {
                log = new FileStream(
                    logPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.ReadWrite,
                    4096,
                    FileOptions.WriteThrough);
                IntPtr currentProcess = GetCurrentProcess();
                if (!DuplicateHandle(
                        currentProcess,
                        log.SafeFileHandle.DangerousGetHandle(),
                        currentProcess,
                        out inheritedLog,
                        0,
                        true,
                        DUPLICATE_SAME_ACCESS))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "DuplicateHandle(inheritable runner log) failed");

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
                        "CreateFileW(NUL) for runner stdin failed");

                IntPtr attributeBytes = IntPtr.Zero;
                InitializeProcThreadAttributeList(
                    IntPtr.Zero,
                    1,
                    0,
                    ref attributeBytes);
                int sizingError = Marshal.GetLastWin32Error();
                if (attributeBytes == IntPtr.Zero)
                    throw new Win32Exception(
                        sizingError,
                        "InitializeProcThreadAttributeList sizing failed");
                attributeList = Marshal.AllocHGlobal(attributeBytes);
                if (!InitializeProcThreadAttributeList(
                        attributeList,
                        1,
                        0,
                        ref attributeBytes))
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
                startup.StartupInfo.dwFlags =
                    STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
                startup.StartupInfo.wShowWindow = SW_HIDE;
                startup.StartupInfo.hStdInput = input;
                startup.StartupInfo.hStdOutput = inheritedLog;
                startup.StartupInfo.hStdError = inheritedLog;
                startup.lpAttributeList = attributeList;
                if (!CreateProcessW(
                        applicationPath,
                        commandLine,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        true,
                        CREATION_FLAGS,
                        IntPtr.Zero,
                        workingDirectory,
                        ref startup,
                        out process))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "CreateProcessW failed for exact runner application '" +
                        applicationPath + "'");

                CloseChecked(ref process.hThread, "child thread");
                CloseChecked(ref inheritedLog, "inheritable runner log duplicate");
                CloseChecked(ref input, "runner NUL input");
                log.Flush(true);
                log.Dispose();
                log = null;

                FILETIME creation;
                FILETIME exit;
                FILETIME kernel;
                FILETIME user;
                if (!GetProcessTimes(
                        process.hProcess,
                        out creation,
                        out exit,
                        out kernel,
                        out user))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "GetProcessTimes failed for retained runner");
                ulong fileTime =
                    ((ulong)creation.dwHighDateTime << 32) | creation.dwLowDateTime;
                long startTicks = checked(
                    (long)fileTime + FILETIME_TO_DOTNET_TICKS);
                uint session;
                if (!ProcessIdToSessionId((uint)process.dwProcessId, out session))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "ProcessIdToSessionId failed for retained runner");

                uint wait = WaitForSingleObject(process.hProcess, INFINITE);
                if (wait == WAIT_FAILED)
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "WaitForSingleObject failed for retained runner");
                if (wait != WAIT_OBJECT_0)
                    throw new InvalidOperationException(
                        "retained runner wait returned unexpected value 0x" +
                        wait.ToString("x8", CultureInfo.InvariantCulture));
                uint exitCode;
                if (!GetExitCodeProcess(process.hProcess, out exitCode))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "GetExitCodeProcess failed for retained runner");
                if (exitCode == STILL_ACTIVE)
                    throw new InvalidOperationException(
                        "retained runner reported STILL_ACTIVE after terminal wait");
                return new ChildResult {
                    ProcessId = process.dwProcessId,
                    ProcessStartUtcTicks = startTicks,
                    SessionId = checked((int)session),
                    ExitCode = unchecked((int)exitCode),
                    WaitResult = wait,
                    CommandLine = commandLineText
                };
            }
            catch (Exception original)
            {
                if (process.hProcess != IntPtr.Zero)
                {
                    uint wait = WaitForSingleObject(process.hProcess, INFINITE);
                    string containment;
                    if (wait == WAIT_OBJECT_0)
                    {
                        uint exitCode;
                        containment = GetExitCodeProcess(
                            process.hProcess,
                            out exitCode)
                            ? "exact runner waited naturally to exit code " +
                              unchecked((int)exitCode).ToString(CultureInfo.InvariantCulture)
                            : "exact runner waited naturally; exit read failed with Win32 " +
                              Marshal.GetLastWin32Error().ToString(
                                  CultureInfo.InvariantCulture);
                    }
                    else
                    {
                        containment = "exact runner containment wait returned 0x" +
                            wait.ToString("x8", CultureInfo.InvariantCulture);
                    }
                    throw new InvalidOperationException(
                        "post-CreateProcessW bootstrap fault; " + containment,
                        original);
                }
                throw;
            }
            finally
            {
                if (log != null)
                    log.Dispose();
                if (process.hThread != IntPtr.Zero)
                    CloseHandle(process.hThread);
                if (process.hProcess != IntPtr.Zero)
                    CloseHandle(process.hProcess);
                if (attributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(attributeList);
                    Marshal.FreeHGlobal(attributeList);
                }
                if (handleList != IntPtr.Zero)
                    Marshal.FreeHGlobal(handleList);
                if (input != IntPtr.Zero && input != INVALID_HANDLE_VALUE)
                    CloseHandle(input);
                if (inheritedLog != IntPtr.Zero)
                    CloseHandle(inheritedLog);
            }
        }

        private static void CloseChecked(ref IntPtr handle, string description)
        {
            if (handle == IntPtr.Zero || handle == INVALID_HANDLE_VALUE)
            {
                handle = IntPtr.Zero;
                return;
            }
            if (!CloseHandle(handle))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "CloseHandle(" + description + ") failed");
            handle = IntPtr.Zero;
        }

        private static string BuildCommandLine(
            string applicationPath,
            string[] arguments)
        {
            StringBuilder command = new StringBuilder(QuoteArgument(applicationPath));
            foreach (string argument in arguments)
            {
                command.Append(' ');
                command.Append(QuoteArgument(argument));
            }
            if (command.Length >= 32767)
                throw new ArgumentException(
                    "runner command line must be shorter than 32767 UTF-16 code units");
            return command.ToString();
        }

        private static string QuoteArgument(string value)
        {
            if (value == null)
                throw new ArgumentNullException("value");
            StringBuilder quoted = new StringBuilder();
            quoted.Append('"');
            int backslashes = 0;
            foreach (char current in value)
            {
                if (current == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (current == '"')
                {
                    quoted.Append('\\', checked(backslashes * 2 + 1));
                    quoted.Append('"');
                    backslashes = 0;
                    continue;
                }
                if (backslashes > 0)
                {
                    quoted.Append('\\', backslashes);
                    backslashes = 0;
                }
                quoted.Append(current);
            }
            if (backslashes > 0)
                quoted.Append('\\', checked(backslashes * 2));
            quoted.Append('"');
            return quoted.ToString();
        }

        private static bool TryWriteFault(
            Options options,
            string stage,
            Exception error,
            bool bootstrapLogOwned)
        {
            if (options == null || String.IsNullOrWhiteSpace(options.RunDirectory))
                return false;
            try
            {
                string run = Path.GetFullPath(options.RunDirectory).TrimEnd('\\');
                if (!Directory.Exists(run))
                    return false;
                Process current = Process.GetCurrentProcess();
                int nativeError = error is Win32Exception
                    ? ((Win32Exception)error).NativeErrorCode
                    : 0;
                WriteCreateNew(
                    Path.Combine(run, "bootstrap-fault.json"),
                    Object(
                        StringField("schema", "astrolabe.detached.bootstrap-fault.v1"),
                        StringField("run_id", options.RunId ?? ""),
                        IntegerField("written_utc_ticks", DateTime.UtcNow.Ticks),
                        IntegerField("bootstrap_pid", current.Id),
                        IntegerField(
                            "bootstrap_start_utc_ticks",
                            current.StartTime.ToUniversalTime().Ticks),
                        IntegerField("bootstrap_session_id", current.SessionId),
                        StringField("stage", stage ?? "unknown"),
                        StringField("code", "ASTRO_DETACH_BOOTSTRAP_FAILED"),
                        StringField("message", error.ToString()),
                        StringField(
                            "remediation",
                            "preserve the run/task bytes and inspect this exact stage, Win32 code, and bootstrap log; do not retry or fall back"),
                        IntegerField("native_error", nativeError),
                        StringField(
                            "bootstrap_path",
                            options.BootstrapPath ?? "")));
                if (bootstrapLogOwned)
                    AppendEvent(
                        Path.Combine(run, "bootstrap.log"),
                        options.RunId ?? "",
                        "bootstrap-fault",
                        stage + ": " + error.Message);
                return true;
            }
            catch
            {
                // Exit 71 is the Task Scheduler-visible durable publication failure.
                // Any pre-existing/malformed output remains untouched for inspection.
                return false;
            }
        }

        private static void WriteCreateNew(string path, string json)
        {
            byte[] bytes = Utf8.GetBytes(json + "\n");
            using (FileStream stream = new FileStream(
                path,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.Read,
                4096,
                FileOptions.WriteThrough))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }
            byte[] readback = File.ReadAllBytes(path);
            if (!ByteArraysEqual(bytes, readback))
                throw new IOException(
                    "durable create-new readback differs: " + path);
        }

        private static void AppendEvent(
            string path,
            string runId,
            string eventName,
            string detail)
        {
            byte[] bytes = Utf8.GetBytes(
                Object(
                    StringField("schema", "astrolabe.detached.bootstrap-event.v1"),
                    StringField("run_id", runId),
                    IntegerField("written_utc_ticks", DateTime.UtcNow.Ticks),
                    StringField("event", eventName),
                    StringField("detail", detail)) + "\n");
            using (FileStream stream = new FileStream(
                path,
                FileMode.Append,
                FileAccess.Write,
                FileShare.Read,
                4096,
                FileOptions.WriteThrough))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }
        }

        private static string FileSha256(string path)
        {
            using (FileStream stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite,
                1024 * 1024,
                FileOptions.SequentialScan))
            using (SHA256 hasher = SHA256.Create())
                return BoundFile.Hex(hasher.ComputeHash(stream));
        }

        private static bool ByteArraysEqual(byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
                return false;
            int difference = 0;
            for (int index = 0; index < left.Length; index++)
                difference |= left[index] ^ right[index];
            return difference == 0;
        }

        private static string Object(params string[] fields)
        {
            return "{" + String.Join(",", fields) + "}";
        }

        private static string StringField(string name, string value)
        {
            return JsonString(name) + ":" + JsonString(value ?? "");
        }

        private static string IntegerField(string name, long value)
        {
            return JsonString(name) + ":" +
                value.ToString(CultureInfo.InvariantCulture);
        }

        private static string IntegerField(string name, uint value)
        {
            return JsonString(name) + ":" +
                value.ToString(CultureInfo.InvariantCulture);
        }

        private static string JsonString(string value)
        {
            StringBuilder text = new StringBuilder();
            text.Append('"');
            foreach (char current in value)
            {
                switch (current)
                {
                    case '"': text.Append("\\\""); break;
                    case '\\': text.Append("\\\\"); break;
                    case '\b': text.Append("\\b"); break;
                    case '\f': text.Append("\\f"); break;
                    case '\n': text.Append("\\n"); break;
                    case '\r': text.Append("\\r"); break;
                    case '\t': text.Append("\\t"); break;
                    default:
                        if (current < 0x20)
                        {
                            text.Append("\\u");
                            text.Append(((int)current).ToString(
                                "x4",
                                CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            text.Append(current);
                        }
                        break;
                }
            }
            text.Append('"');
            return text.ToString();
        }

        private static bool IsLowerHex(string value, int length)
        {
            if (value == null || value.Length != length)
                return false;
            foreach (char current in value)
                if (!((current >= '0' && current <= '9') ||
                      (current >= 'a' && current <= 'f')))
                    return false;
            return true;
        }

        private static bool PathEquals(string left, string right)
        {
            return String.Equals(
                Path.GetFullPath(left).TrimEnd('\\'),
                Path.GetFullPath(right).TrimEnd('\\'),
                StringComparison.OrdinalIgnoreCase);
        }
    }
}
