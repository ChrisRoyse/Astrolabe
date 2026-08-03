<#
.SYNOPSIS
    Authoritative Astrolabe launcher-lock protocol (#197, #611, #613).

.DESCRIPTION
    This helper is the only supported launcher-lock parser and claim/reclaim synchronizer.
    It never stops a process and never automatically removes stale state.

    A schema-v3 lease binds one canonical protocol authority plus the exact
    Windows process identity (pid, owner_process_start_utc_ticks). Claim,
    cleanup, and explicit reclaim serialize on one Global Windows mutex whose
    name is derived from the opened workspace directory's filesystem identity,
    not a lexical path. Live leases retain one READ|WRITE|DELETE SafeFileHandle
    with FILE_SHARE_READ, so the exact claimed file remains readable for
    observation but cannot be replaced, renamed, or deleted through a
    competing handle.

    Interrupted claim/cleanup/reclaim names are durable protocol state. They are discovered and
    refused rather than ignored. Only the explicit tracker-evidenced reclaim/quarantine
    command may archive them.
#>

if (-not ('AstroLauncherLockNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class AstroLauncherLockNative
{
    private const uint JOB_OBJECT_QUERY = 0x0004;
    private const uint FILE_READ_ATTRIBUTES = 0x0080;
    private const uint FILE_TRAVERSE = 0x0020;
    private const uint DELETE_ACCESS = 0x00010000;
    private const uint READ_CONTROL = 0x00020000;
    private const uint ACCESS_SYSTEM_SECURITY = 0x01000000;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
    private const uint FILE_TYPE_DISK = 0x0001;
    private const uint FILE_BEGIN = 0;
    private const int FILE_ID_INFO_CLASS = 18;
    private const int FILE_RENAME_INFO_CLASS = 3;
    private const int FILE_DISPOSITION_INFO_CLASS = 4;
    private const int FILE_DISPOSITION_INFO_EX_CLASS = 21;
    private const uint FILE_DISPOSITION_DELETE = 0x00000001;
    private const uint FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE = 0x00000010;
    private const int JOB_OBJECT_BASIC_PROCESS_ID_LIST_CLASS = 3;
    private const int ERROR_FILE_NOT_FOUND = 2;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int ERROR_MORE_DATA = 234;
    private const int ERROR_NOT_ALL_ASSIGNED = 1300;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    private const uint OWNER_SECURITY_INFORMATION = 0x00000001;
    private const uint GROUP_SECURITY_INFORMATION = 0x00000002;
    private const uint DACL_SECURITY_INFORMATION = 0x00000004;
    private const uint SACL_SECURITY_INFORMATION = 0x00000008;
    private const uint LABEL_SECURITY_INFORMATION = 0x00000010;
    private const int SE_FILE_OBJECT = 6;
    private const uint SDDL_REVISION_1 = 1;
    private const int MAX_JOB_PROCESS_IDS = 1048576;

    public sealed class JobObjectProcessIdProbe
    {
        public string Name { get; set; }
        public string State { get; set; }
        public int[] ProcessIds { get; set; }
        public int NativeErrorCode { get; set; }
        public string Error { get; set; }
        public uint NumberOfAssignedProcesses { get; set; }
        public uint NumberOfProcessIdsInList { get; set; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out BY_HANDLE_FILE_INFORMATION information
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out IntPtr tokenHandle
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValueW(
        string systemName,
        string name,
        out LUID luid
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
        ref TOKEN_PRIVILEGES newState,
        uint bufferLength,
        IntPtr previousState,
        IntPtr returnLength
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(
        IntPtr handle,
        int objectType,
        uint securityInfo,
        out IntPtr owner,
        out IntPtr group,
        out IntPtr dacl,
        out IntPtr sacl,
        out IntPtr securityDescriptor
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
        IntPtr securityDescriptor,
        uint revision,
        uint securityInfo,
        out IntPtr stringSecurityDescriptor,
        out uint stringSecurityDescriptorLength
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file,
        StringBuilder path,
        uint pathLength,
        uint flags
    );

    private const uint MOVEFILE_WRITE_THROUGH = 0x00000008;

    [DllImport(
        "kernel32.dll",
        EntryPoint = "MoveFileExW",
        CharSet = CharSet.Unicode,
        ExactSpelling = true,
        SetLastError = true
    )]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileExWNative(
        string existingFileName,
        string newFileName,
        uint flags
    );

    [DllImport(
        "kernel32.dll",
        EntryPoint = "ReplaceFileW",
        CharSet = CharSet.Unicode,
        ExactSpelling = true,
        SetLastError = true
    )]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReplaceFileWNative(
        string replacedFileName,
        string replacementFileName,
        string backupFileName,
        uint replaceFlags,
        IntPtr exclude,
        IntPtr reserved
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(
        string pathName,
        IntPtr securityAttributes
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        int informationClass,
        IntPtr information,
        uint size
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileSizeEx(SafeFileHandle file, out long size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFilePointerEx(
        SafeFileHandle file,
        long distance,
        out long newPointer,
        uint moveMethod
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadFile(
        SafeFileHandle file,
        IntPtr buffer,
        uint bytesToRead,
        out uint bytesRead,
        IntPtr overlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(SafeFileHandle file);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(SafeFileHandle file);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        int informationClass,
        IntPtr information,
        uint size
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeWaitHandle OpenJobObjectW(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        string name
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(
        SafeWaitHandle job,
        int informationClass,
        IntPtr information,
        uint informationLength,
        out uint returnLength
    );

    private static SafeFileHandle OpenDirectory(string path)
    {
        SafeFileHandle handle = CreateFileW(
            GetExtendedLengthPath(path),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            IntPtr.Zero
        );
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "could not open directory identity: " + path);
        }
        return handle;
    }

    private static string GetExtendedLengthPath(string path)
    {
        string full = System.IO.Path.GetFullPath(path);
        if (full.StartsWith("\\\\?\\", StringComparison.Ordinal))
        {
            return full;
        }
        if (full.StartsWith("\\\\", StringComparison.Ordinal))
        {
            return "\\\\?\\UNC\\" + full.Substring(2);
        }
        return "\\\\?\\" + full;
    }

    public static void MoveFileWriteThroughNoReplace(
        string existingFileName,
        string newFileName
    )
    {
        string source = GetExtendedLengthPath(existingFileName);
        string destination = GetExtendedLengthPath(newFileName);
        if (MoveFileExWNative(source, destination, MOVEFILE_WRITE_THROUGH))
        {
            return;
        }

        int nativeError = Marshal.GetLastWin32Error();
        string nativeMessage = new Win32Exception(nativeError).Message;
        throw new Win32Exception(
            nativeError,
            string.Format(
                CultureInfo.InvariantCulture,
                "MoveFileExW failed (native_error={0}, native_message='{1}', " +
                    "flags=0x{2:x8}, source='{3}', destination='{4}')",
                nativeError,
                nativeMessage,
                MOVEFILE_WRITE_THROUGH,
                existingFileName,
                newFileName
            )
        );
    }

    public static void ReplaceFilePreserveMetadata(
        string replacedFileName,
        string replacementFileName,
        string backupFileName
    )
    {
        string replaced = GetExtendedLengthPath(replacedFileName);
        string replacement = GetExtendedLengthPath(replacementFileName);
        string backup = GetExtendedLengthPath(backupFileName);
        const uint flags = 0;
        if (ReplaceFileWNative(
                replaced,
                replacement,
                backup,
                flags,
                IntPtr.Zero,
                IntPtr.Zero
            ))
        {
            return;
        }

        int nativeError = Marshal.GetLastWin32Error();
        string nativeMessage = new Win32Exception(nativeError).Message;
        throw new Win32Exception(
            nativeError,
            string.Format(
                CultureInfo.InvariantCulture,
                "ReplaceFileW failed (native_error={0}, native_message='{1}', " +
                    "flags=0x{2:x8}, replaced='{3}', replacement='{4}', backup='{5}')",
                nativeError,
                nativeMessage,
                flags,
                replacedFileName,
                replacementFileName,
                backupFileName
            )
        );
    }

    public static void CreateDirectoryNoReplace(string path)
    {
        string full = System.IO.Path.GetFullPath(path);
        if (!CreateDirectoryW(GetExtendedLengthPath(full), IntPtr.Zero))
        {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(
                error,
                "CreateDirectoryW no-clobber failed (native_error=" + error + "): " +
                full
            );
        }
    }

    public static string GetDirectoryIdentity(string path)
    {
        using (SafeFileHandle handle = OpenDirectory(path))
        {
            return GetDirectoryLockIdentity(handle);
        }
    }

    public static string GetDirectoryLockIdentity(SafeFileHandle handle)
    {
        BY_HANDLE_FILE_INFORMATION information =
            ReadBasicInformation(handle, "retained launcher root");
        if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            throw new InvalidOperationException(
                "retained launcher root must be an ordinary non-reparse directory"
            );
        }
        // FILE_ID_INFO carries the 128-bit identifier required for ReFS as well as
        // NTFS.  BY_HANDLE_FILE_INFORMATION's 64-bit file index is not guaranteed
        // unique on ReFS and therefore cannot key a machine-wide ownership mutex.
        return GetFileIdentity(handle);
    }

    public static string GetDirectoryFinalPath(string path)
    {
        using (SafeFileHandle handle = OpenDirectory(path))
        {
            StringBuilder buffer = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "could not read final directory path: " + path
                );
            }
            return buffer.ToString();
        }
    }

    private static BY_HANDLE_FILE_INFORMATION ReadBasicInformation(
        SafeFileHandle handle,
        string description
    )
    {
        BY_HANDLE_FILE_INFORMATION information;
        if (!GetFileInformationByHandle(handle, out information))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "could not read " + description + " file information"
            );
        }
        return information;
    }

    private static void RequireDiskHandle(SafeFileHandle handle, string description)
    {
        uint type = GetFileType(handle);
        if (type != FILE_TYPE_DISK)
        {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(
                error,
                description + " is not a local disk filesystem handle (type=" + type + ")"
            );
        }
    }

    public static SafeFileHandle OpenExactRenameSource(string path)
    {
        SafeFileHandle handle = CreateFileW(
            GetExtendedLengthPath(path),
            GENERIC_READ | GENERIC_WRITE | DELETE_ACCESS,
            FILE_SHARE_READ,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            IntPtr.Zero
        );
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(
                error,
                "could not open exact write-denying rename source " +
                "(native_error=" + error + "; path=" + path + ")"
            );
        }
        try
        {
            RequireDiskHandle(handle, "exact rename source");
            BY_HANDLE_FILE_INFORMATION information =
                ReadBasicInformation(handle, "exact rename source");
            if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
                (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                throw new InvalidOperationException(
                    "exact rename source must be an ordinary non-reparse file: " + path
                );
            }
            if (information.NumberOfLinks != 1)
            {
                throw new InvalidOperationException(
                    "exact rename source must have one filesystem link; observed " +
                    information.NumberOfLinks + ": " + path
                );
            }
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static SafeFileHandle OpenExactDispositionFile(string path)
    {
        SafeFileHandle handle = CreateFileW(
            GetExtendedLengthPath(path),
            GENERIC_READ | DELETE_ACCESS,
            FILE_SHARE_READ,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            IntPtr.Zero
        );
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(
                error,
                "could not open exact read-only-aware disposition source " +
                "(native_error=" + error + "; path=" + path + ")"
            );
        }
        try
        {
            RequireDiskHandle(handle, "exact disposition source");
            RequireExactOrdinarySingleLinkFile(
                handle,
                "exact disposition source"
            );
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static SafeFileHandle OpenExactOrdinaryRead(
        string path,
        uint shareMode,
        string description,
        bool requireSingleLink
    )
    {
        SafeFileHandle handle = CreateFileW(
            GetExtendedLengthPath(path),
            GENERIC_READ,
            shareMode,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            IntPtr.Zero
        );
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "could not open " + description + ": " + path);
        }
        try
        {
            RequireDiskHandle(handle, description);
            BY_HANDLE_FILE_INFORMATION information =
                ReadBasicInformation(handle, description);
            if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
                (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                throw new InvalidOperationException(
                    description + " must be an ordinary non-reparse file: " + path
                );
            }
            if (requireSingleLink && information.NumberOfLinks != 1)
            {
                throw new InvalidOperationException(
                    description + " must have one filesystem link; observed " +
                    information.NumberOfLinks + ": " + path
                );
            }
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static SafeFileHandle OpenExactProtectedReadFile(string path)
    {
        return OpenExactOrdinaryRead(
            path,
            FILE_SHARE_READ,
            "protected evidence file",
            true
        );
    }

    public static SafeFileHandle OpenProtectedOrdinaryReadFile(string path)
    {
        return OpenExactOrdinaryRead(
            path,
            FILE_SHARE_READ,
            "protected ordinary source file",
            false
        );
    }

    public static SafeFileHandle OpenExactSharedDeleteReadFile(string path)
    {
        return OpenExactOrdinaryRead(
            path,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            "shared-delete evidence file",
            true
        );
    }

    public static SafeFileHandle OpenExactClassifierReadFile(string path)
    {
        SafeFileHandle handle = CreateFileW(
            GetExtendedLengthPath(path),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            IntPtr.Zero
        );
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(
                error,
                "could not open launcher-lock classifier source: " + path
            );
        }
        try
        {
            RequireDiskHandle(handle, "launcher-lock classifier source");
            BY_HANDLE_FILE_INFORMATION information =
                ReadBasicInformation(handle, "launcher-lock classifier source");
            if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
                (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                throw new InvalidOperationException(
                    "launcher-lock classifier source must be an ordinary non-reparse file: " +
                    path
                );
            }
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static uint GetNumberOfLinks(SafeFileHandle handle)
    {
        return ReadBasicInformation(handle, "retained exact file").NumberOfLinks;
    }

    public static SafeFileHandle OpenExactRenameDirectory(string path)
    {
        SafeFileHandle handle = CreateFileW(
            GetExtendedLengthPath(path),
            FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero
        );
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(
                error,
                "could not open exact pinned rename directory: " + path
            );
        }
        try
        {
            RequireDiskHandle(handle, "exact rename directory");
            BY_HANDLE_FILE_INFORMATION information =
                ReadBasicInformation(handle, "exact rename directory");
            if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                throw new InvalidOperationException(
                    "exact rename destination parent must be an ordinary non-reparse directory: " +
                    path
                );
            }
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static SafeFileHandle OpenExactDeleteDirectory(string path)
    {
        SafeFileHandle handle = CreateFileW(
            GetExtendedLengthPath(path),
            FILE_READ_ATTRIBUTES | FILE_TRAVERSE | DELETE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero
        );
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(
                error,
                "CreateFileW exact delete-directory lease failed (native_error=" +
                error.ToString(CultureInfo.InvariantCulture) + "; path=" + path + ")"
            );
        }
        try
        {
            RequireDiskHandle(handle, "exact delete directory");
            BY_HANDLE_FILE_INFORMATION information =
                ReadBasicInformation(handle, "exact delete directory");
            if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                throw new InvalidOperationException(
                    "exact delete source must be an ordinary non-reparse directory: " +
                    path
                );
            }
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static void EnableCurrentTokenSecurityPrivilege()
    {
        IntPtr token = IntPtr.Zero;
        if (!OpenProcessToken(
                System.Diagnostics.Process.GetCurrentProcess().Handle,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                out token
            ))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "OpenProcessToken failed while enabling SeSecurityPrivilege"
            );
        }
        try
        {
            LUID luid;
            if (!LookupPrivilegeValueW(null, "SeSecurityPrivilege", out luid))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "LookupPrivilegeValueW failed for SeSecurityPrivilege"
                );
            }
            TOKEN_PRIVILEGES privileges = new TOKEN_PRIVILEGES();
            privileges.PrivilegeCount = 1;
            privileges.Privileges = new LUID_AND_ATTRIBUTES();
            privileges.Privileges.Luid = luid;
            privileges.Privileges.Attributes = SE_PRIVILEGE_ENABLED;
            if (!AdjustTokenPrivileges(
                    token,
                    false,
                    ref privileges,
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero
                ))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "AdjustTokenPrivileges failed for SeSecurityPrivilege"
                );
            }
            int error = Marshal.GetLastWin32Error();
            if (error == ERROR_NOT_ALL_ASSIGNED)
            {
                throw new Win32Exception(
                    error,
                    "the current token does not hold SeSecurityPrivilege"
                );
            }
        }
        finally
        {
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }

    public static SafeFileHandle OpenExactRecoveryDirectory(string path)
    {
        EnableCurrentTokenSecurityPrivilege();
        SafeFileHandle handle = CreateFileW(
            GetExtendedLengthPath(path),
            FILE_READ_ATTRIBUTES | FILE_TRAVERSE | DELETE_ACCESS |
                READ_CONTROL | ACCESS_SYSTEM_SECURITY,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero
        );
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(
                error,
                "could not open exact security/recovery directory: " + path
            );
        }
        try
        {
            RequireDiskHandle(handle, "exact security/recovery directory");
            BY_HANDLE_FILE_INFORMATION information =
                ReadBasicInformation(handle, "exact security/recovery directory");
            if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                throw new InvalidOperationException(
                    "recovery source must be one ordinary non-reparse directory: " + path
                );
            }
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static string GetExactSecurityDescriptorSddl(SafeFileHandle handle)
    {
        EnableCurrentTokenSecurityPrivilege();
        IntPtr owner;
        IntPtr group;
        IntPtr dacl;
        IntPtr sacl;
        IntPtr descriptor;
        uint information = OWNER_SECURITY_INFORMATION |
            GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION |
            SACL_SECURITY_INFORMATION |
            LABEL_SECURITY_INFORMATION;
        uint result = GetSecurityInfo(
            handle.DangerousGetHandle(),
            SE_FILE_OBJECT,
            information,
            out owner,
            out group,
            out dacl,
            out sacl,
            out descriptor
        );
        if (result != 0)
        {
            throw new Win32Exception(
                unchecked((int)result),
                "GetSecurityInfo failed for exact recovery directory"
            );
        }
        try
        {
            IntPtr text;
            uint textLength;
            if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor,
                    SDDL_REVISION_1,
                    information,
                    out text,
                    out textLength
                ))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "could not convert exact recovery security descriptor to SDDL"
                );
            }
            try
            {
                return Marshal.PtrToStringUni(text);
            }
            finally
            {
                LocalFree(text);
            }
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    public static string GetFileIdentity(SafeFileHandle handle)
    {
        IntPtr buffer = Marshal.AllocHGlobal(24);
        try
        {
            for (int index = 0; index < 24; index++)
            {
                Marshal.WriteByte(buffer, index, 0);
            }
            if (!GetFileInformationByHandleEx(
                    handle,
                    FILE_ID_INFO_CLASS,
                    buffer,
                    24
                ))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "could not read FILE_ID_INFO from retained handle"
                );
            }
            ulong volume = unchecked((ulong)Marshal.ReadInt64(buffer, 0));
            byte[] fileId = new byte[16];
            Marshal.Copy(IntPtr.Add(buffer, 8), fileId, 0, fileId.Length);
            bool allZero = true;
            bool allOnes = true;
            for (int index = 0; index < fileId.Length; index++)
            {
                allZero &= fileId[index] == 0;
                allOnes &= fileId[index] == 0xff;
            }
            if (allZero || allOnes)
            {
                throw new InvalidOperationException(
                    "FILE_ID_INFO returned a reserved all-zero/all-ones file identifier"
                );
            }
            StringBuilder id = new StringBuilder(16 + 1 + 32);
            id.Append(volume.ToString("x16"));
            id.Append(':');
            for (int index = 0; index < fileId.Length; index++)
            {
                id.Append(fileId[index].ToString("x2"));
            }
            return id.ToString();
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static ulong GetFileVolumeSerial(SafeFileHandle handle)
    {
        string identity = GetFileIdentity(handle);
        return UInt64.Parse(
            identity.Substring(0, 16),
            System.Globalization.NumberStyles.AllowHexSpecifier,
            System.Globalization.CultureInfo.InvariantCulture
        );
    }

    public static string GetFileFinalPath(SafeFileHandle handle)
    {
        StringBuilder buffer = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandleW(
            handle,
            buffer,
            (uint)buffer.Capacity,
            0
        );
        if (length == 0 || length >= buffer.Capacity)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "could not read final path from retained file handle"
            );
        }
        return buffer.ToString();
    }

    public static byte[] ReadAllBytes(SafeFileHandle handle, int maximumBytes)
    {
        long size;
        if (!GetFileSizeEx(handle, out size))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "could not read retained file size"
            );
        }
        if (size < 0 || size > maximumBytes || size > Int32.MaxValue)
        {
            throw new InvalidOperationException(
                "retained file size " + size + " exceeds the " + maximumBytes +
                "-byte protocol bound"
            );
        }
        long ignored;
        if (!SetFilePointerEx(handle, 0, out ignored, FILE_BEGIN))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "could not rewind retained file handle"
            );
        }
        byte[] result = new byte[(int)size];
        IntPtr buffer = size == 0 ? IntPtr.Zero : Marshal.AllocHGlobal((int)size);
        try
        {
            int offset = 0;
            while (offset < result.Length)
            {
                uint read;
                uint requested = (uint)(result.Length - offset);
                if (!ReadFile(
                        handle,
                        IntPtr.Add(buffer, offset),
                        requested,
                        out read,
                        IntPtr.Zero
                    ))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "could not read retained exact file bytes"
                    );
                }
                if (read == 0)
                {
                    throw new InvalidOperationException(
                        "retained exact file read ended at byte " + offset +
                        " of " + result.Length
                    );
                }
                offset += (int)read;
            }
            if (result.Length > 0)
            {
                Marshal.Copy(buffer, result, 0, result.Length);
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        long sizeAfter;
        if (!GetFileSizeEx(handle, out sizeAfter) || sizeAfter != size)
        {
            throw new InvalidOperationException(
                "retained exact file size changed during read"
            );
        }
        return result;
    }

    private static string ComputeRetainedFileSha256(
        SafeFileHandle handle,
        bool requireSingleLink
    )
    {
        string description = requireSingleLink
            ? "exact retained digest source"
            : "retained ordinary digest source";
        if (requireSingleLink)
        {
            RequireExactOrdinarySingleLinkFile(handle, description);
        }
        else
        {
            RequireOrdinaryFile(handle, description);
        }
        long sizeBefore;
        if (!GetFileSizeEx(handle, out sizeBefore))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "could not read exact retained digest-source size"
            );
        }
        if (sizeBefore < 0)
        {
            throw new InvalidOperationException(
                "exact retained digest-source size was negative"
            );
        }
        long ignored;
        if (!SetFilePointerEx(handle, 0, out ignored, FILE_BEGIN))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "could not rewind exact retained digest source"
            );
        }

        const int BufferSize = 1048576;
        IntPtr nativeBuffer = Marshal.AllocHGlobal(BufferSize);
        byte[] managedBuffer = new byte[BufferSize];
        long total = 0;
        byte[] hash;
        try
        {
            using (SHA256 digest = SHA256.Create())
            {
                while (total < sizeBefore)
                {
                    uint requested = (uint)Math.Min(
                        (long)BufferSize,
                        sizeBefore - total
                    );
                    uint read;
                    if (!ReadFile(
                            handle,
                            nativeBuffer,
                            requested,
                            out read,
                            IntPtr.Zero
                        ))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "could not read exact retained digest-source bytes"
                        );
                    }
                    if (read == 0)
                    {
                        throw new InvalidOperationException(
                            "exact retained digest-source read ended at byte " +
                            total.ToString(CultureInfo.InvariantCulture) +
                            " of " +
                            sizeBefore.ToString(CultureInfo.InvariantCulture)
                        );
                    }
                    Marshal.Copy(
                        nativeBuffer,
                        managedBuffer,
                        0,
                        checked((int)read)
                    );
                    int transformed = digest.TransformBlock(
                        managedBuffer,
                        0,
                        checked((int)read),
                        managedBuffer,
                        0
                    );
                    if (transformed != checked((int)read))
                    {
                        throw new InvalidOperationException(
                            "exact retained digest source transformed " +
                            transformed.ToString(CultureInfo.InvariantCulture) +
                            " bytes after reading " +
                            read.ToString(CultureInfo.InvariantCulture)
                        );
                    }
                    total += read;
                }
                digest.TransformFinalBlock(new byte[0], 0, 0);
                hash = digest.Hash;
                if (hash == null || hash.Length != 32)
                {
                    throw new InvalidOperationException(
                        "exact retained digest source produced an invalid SHA-256 digest"
                    );
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(nativeBuffer);
        }

        long sizeAfter;
        if (!GetFileSizeEx(handle, out sizeAfter) ||
            sizeAfter != sizeBefore ||
            total != sizeBefore)
        {
            throw new InvalidOperationException(
                "exact retained digest-source size changed during hashing"
            );
        }
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    public static string ComputeExactFileSha256(SafeFileHandle handle)
    {
        return ComputeRetainedFileSha256(handle, true);
    }

    public static string ComputeOrdinaryFileSha256(SafeFileHandle handle)
    {
        return ComputeRetainedFileSha256(handle, false);
    }

    public static void FlushExactFile(SafeFileHandle handle)
    {
        if (!FlushFileBuffers(handle))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "could not durably flush exact retained file handle"
            );
        }
    }

    private static void RequireExactOrdinarySingleLinkFile(
        SafeFileHandle handle,
        string description
    )
    {
        RequireOrdinaryFile(handle, description);
        BY_HANDLE_FILE_INFORMATION information =
            ReadBasicInformation(handle, description);
        if (information.NumberOfLinks != 1)
        {
            throw new InvalidOperationException(
                description + " must retain exactly one filesystem link; observed " +
                information.NumberOfLinks
            );
        }
    }

    private static void RequireOrdinaryFile(
        SafeFileHandle handle,
        string description
    )
    {
        if (handle == null || handle.IsInvalid || handle.IsClosed)
        {
            throw new ObjectDisposedException(description + " retained handle");
        }
        RequireDiskHandle(handle, description);
        BY_HANDLE_FILE_INFORMATION information =
            ReadBasicInformation(handle, description);
        if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
            (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            throw new InvalidOperationException(
                description + " must remain an ordinary non-reparse file"
            );
        }
    }

    private static void RequireExactOrdinaryDirectory(
        SafeFileHandle handle,
        string description
    )
    {
        if (handle == null || handle.IsInvalid || handle.IsClosed)
        {
            throw new ObjectDisposedException(description + " retained handle");
        }
        RequireDiskHandle(handle, description);
        BY_HANDLE_FILE_INFORMATION information =
            ReadBasicInformation(handle, description);
        if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            throw new InvalidOperationException(
                description + " must remain an ordinary non-reparse directory"
            );
        }
    }

    public static void RenameFileHandleNoReplace(
        SafeFileHandle source,
        SafeFileHandle destinationDirectory,
        string destinationLeaf
    )
    {
        RequireExactOrdinarySingleLinkFile(source, "exact rename source");
        RequireExactOrdinaryDirectory(
            destinationDirectory,
            "exact pinned rename destination parent"
        );
        if (String.IsNullOrEmpty(destinationLeaf) ||
            destinationLeaf.IndexOf('\0') >= 0 ||
            destinationLeaf.IndexOf('\\') >= 0 ||
            destinationLeaf.IndexOf('/') >= 0 ||
            destinationLeaf.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) >= 0 ||
            destinationLeaf.EndsWith(" ", StringComparison.Ordinal) ||
            destinationLeaf.EndsWith(".", StringComparison.Ordinal) ||
            destinationLeaf == "." ||
            destinationLeaf == "..")
        {
            throw new ArgumentException(
                "exact rename destination must be one simple nonempty filename",
                "destinationLeaf"
            );
        }
        if (GetFileVolumeSerial(source) !=
            GetFileVolumeSerial(destinationDirectory))
        {
            throw new InvalidOperationException(
                "exact rename source and destination directory are on different volumes"
            );
        }
        // Win32's public FILE_RENAME_INFO contract requires RootDirectory to be
        // NULL.  Keep the destination directory handle pinned and validated for
        // identity, but derive one absolute destination from that retained handle
        // instead of relying on the kernel-only relative-handle form.
        string destinationDirectoryPath = GetFileFinalPath(destinationDirectory);
        string destinationPath = destinationDirectoryPath.EndsWith("\\", StringComparison.Ordinal)
            ? destinationDirectoryPath + destinationLeaf
            : destinationDirectoryPath + "\\" + destinationLeaf;
        string extendedDestinationPath = destinationPath.StartsWith(
            "\\\\?\\",
            StringComparison.Ordinal
        ) ? destinationPath : (
            destinationPath.StartsWith("\\\\", StringComparison.Ordinal)
                ? "\\\\?\\UNC\\" + destinationPath.Substring(2)
                : "\\\\?\\" + destinationPath
        );
        byte[] nameBytes = Encoding.Unicode.GetBytes(extendedDestinationPath);
        int rootOffset = IntPtr.Size == 8 ? 8 : 4;
        int lengthOffset = rootOffset + IntPtr.Size;
        int nameOffset = lengthOffset + 4;
        int rawSize = checked(nameOffset + nameBytes.Length + 2);
        int alignedSize = checked(
            ((rawSize + IntPtr.Size - 1) / IntPtr.Size) * IntPtr.Size
        );
        IntPtr information = Marshal.AllocHGlobal(alignedSize);
        try
        {
            for (int index = 0; index < alignedSize; index++)
            {
                Marshal.WriteByte(information, index, 0);
            }
            Marshal.WriteInt32(information, 0, 0);
            Marshal.WriteIntPtr(information, rootOffset, IntPtr.Zero);
            Marshal.WriteInt32(information, lengthOffset, nameBytes.Length);
            Marshal.Copy(nameBytes, 0, IntPtr.Add(information, nameOffset), nameBytes.Length);
            if (!SetFileInformationByHandle(
                    source,
                    FILE_RENAME_INFO_CLASS,
                    information,
                    (uint)alignedSize
                ))
            {
                int nativeError = Marshal.GetLastWin32Error();
                throw new Win32Exception(
                    nativeError,
                    "exact handle-bound no-replace rename failed; native_error=" +
                    nativeError.ToString(CultureInfo.InvariantCulture)
                );
            }
        }
        finally
        {
            Marshal.FreeHGlobal(information);
        }
    }

    public static void RenameDirectoryHandleNoReplace(
        SafeFileHandle source,
        SafeFileHandle destinationDirectory,
        string destinationLeaf
    )
    {
        RequireExactOrdinaryDirectory(source, "exact directory rename source");
        RequireExactOrdinaryDirectory(
            destinationDirectory,
            "exact pinned directory rename destination parent"
        );
        if (String.IsNullOrEmpty(destinationLeaf) ||
            destinationLeaf.IndexOf('\0') >= 0 ||
            destinationLeaf.IndexOf('\\') >= 0 ||
            destinationLeaf.IndexOf('/') >= 0 ||
            destinationLeaf.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) >= 0 ||
            destinationLeaf.EndsWith(" ", StringComparison.Ordinal) ||
            destinationLeaf.EndsWith(".", StringComparison.Ordinal) ||
            destinationLeaf == "." ||
            destinationLeaf == "..")
        {
            throw new ArgumentException(
                "exact directory rename destination must be one simple nonempty filename",
                "destinationLeaf"
            );
        }
        if (GetFileVolumeSerial(source) !=
            GetFileVolumeSerial(destinationDirectory))
        {
            throw new InvalidOperationException(
                "exact directory rename source and destination are on different volumes"
            );
        }
        string destinationDirectoryPath = GetFileFinalPath(destinationDirectory);
        string destinationPath = destinationDirectoryPath.EndsWith("\\", StringComparison.Ordinal)
            ? destinationDirectoryPath + destinationLeaf
            : destinationDirectoryPath + "\\" + destinationLeaf;
        string extendedDestinationPath = destinationPath.StartsWith(
            "\\\\?\\",
            StringComparison.Ordinal
        ) ? destinationPath : (
            destinationPath.StartsWith("\\\\", StringComparison.Ordinal)
                ? "\\\\?\\UNC\\" + destinationPath.Substring(2)
                : "\\\\?\\" + destinationPath
        );
        byte[] nameBytes = Encoding.Unicode.GetBytes(extendedDestinationPath);
        int rootOffset = IntPtr.Size == 8 ? 8 : 4;
        int lengthOffset = rootOffset + IntPtr.Size;
        int nameOffset = lengthOffset + 4;
        int rawSize = checked(nameOffset + nameBytes.Length + 2);
        int alignedSize = checked(
            ((rawSize + IntPtr.Size - 1) / IntPtr.Size) * IntPtr.Size
        );
        IntPtr information = Marshal.AllocHGlobal(alignedSize);
        try
        {
            for (int index = 0; index < alignedSize; index++)
            {
                Marshal.WriteByte(information, index, 0);
            }
            Marshal.WriteInt32(information, 0, 0);
            Marshal.WriteIntPtr(information, rootOffset, IntPtr.Zero);
            Marshal.WriteInt32(information, lengthOffset, nameBytes.Length);
            Marshal.Copy(nameBytes, 0, IntPtr.Add(information, nameOffset), nameBytes.Length);
            if (!SetFileInformationByHandle(
                    source,
                    FILE_RENAME_INFO_CLASS,
                    information,
                    (uint)alignedSize
                ))
            {
                int nativeError = Marshal.GetLastWin32Error();
                throw new Win32Exception(
                    nativeError,
                    "exact directory handle-bound no-replace rename failed; native_error=" +
                    nativeError.ToString(CultureInfo.InvariantCulture)
                );
            }
        }
        finally
        {
            Marshal.FreeHGlobal(information);
        }
    }

    public static void DeleteExactFileHandle(SafeFileHandle file)
    {
        RequireExactOrdinarySingleLinkFile(file, "exact disposition-delete source");
        IntPtr information = Marshal.AllocHGlobal(1);
        try
        {
            // FILE_DISPOSITION_INFO.DeleteFile is the one-byte Win32 BOOLEAN TRUE.
            Marshal.WriteByte(information, 0, 1);
            if (!SetFileInformationByHandle(
                    file,
                    FILE_DISPOSITION_INFO_CLASS,
                    information,
                    1
                ))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "exact retained-handle FILE_DISPOSITION_INFO delete failed"
                );
            }
        }
        finally
        {
            Marshal.FreeHGlobal(information);
        }
    }

    public static void DeleteExactFileHandleIgnoringReadOnly(
        SafeFileHandle file
    )
    {
        RequireExactOrdinarySingleLinkFile(
            file,
            "exact read-only-aware disposition-delete source"
        );
        IntPtr information = Marshal.AllocHGlobal(4);
        try
        {
            uint flags =
                FILE_DISPOSITION_DELETE |
                FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE;
            Marshal.WriteInt32(information, unchecked((int)flags));
            if (!SetFileInformationByHandle(
                    file,
                    FILE_DISPOSITION_INFO_EX_CLASS,
                    information,
                    4
                ))
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(
                    error,
                    "exact retained-handle FILE_DISPOSITION_INFO_EX delete " +
                    "failed; native_error=" +
                    error.ToString(CultureInfo.InvariantCulture)
                );
            }
        }
        finally
        {
            Marshal.FreeHGlobal(information);
        }
    }

    public static void DeleteExactDirectoryHandle(SafeFileHandle directory)
    {
        BY_HANDLE_FILE_INFORMATION information =
            ReadBasicInformation(directory, "exact disposition-delete directory");
        if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            throw new InvalidOperationException(
                "exact disposition-delete source must remain an ordinary directory"
            );
        }
        IntPtr disposition = Marshal.AllocHGlobal(1);
        try
        {
            Marshal.WriteByte(disposition, 0, 1);
            if (!SetFileInformationByHandle(
                    directory,
                    FILE_DISPOSITION_INFO_CLASS,
                    disposition,
                    1
                ))
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(
                    error,
                    "exact directory FILE_DISPOSITION_INFO delete failed; native_error=" +
                    error.ToString(CultureInfo.InvariantCulture)
                );
            }
        }
        finally
        {
            Marshal.FreeHGlobal(disposition);
        }
    }

    private static JobObjectProcessIdProbe NewJobProbe(
        string name,
        string state,
        int[] processIds,
        int nativeErrorCode,
        string error,
        uint assigned,
        uint listed
    )
    {
        return new JobObjectProcessIdProbe
        {
            Name = name,
            State = state,
            ProcessIds = processIds ?? new int[0],
            NativeErrorCode = nativeErrorCode,
            Error = error,
            NumberOfAssignedProcesses = assigned,
            NumberOfProcessIdsInList = listed
        };
    }

    private static JobObjectProcessIdProbe NewUnevaluableJobProbe(
        string name,
        int nativeErrorCode,
        string error
    )
    {
        return NewJobProbe(
            name,
            "unevaluable",
            new int[0],
            nativeErrorCode,
            error,
            0,
            0
        );
    }

    public static JobObjectProcessIdProbe QueryNamedJobObjectProcessIds(string name)
    {
        if (String.IsNullOrWhiteSpace(name))
        {
            return NewUnevaluableJobProbe(
                name,
                0,
                "named Job Object query requires a nonblank exact name"
            );
        }

        SafeWaitHandle job = OpenJobObjectW(JOB_OBJECT_QUERY, false, name);
        if (job == null || job.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            if (job != null)
            {
                job.Dispose();
            }
            if (error == ERROR_FILE_NOT_FOUND)
            {
                return NewJobProbe(
                    name,
                    "absent",
                    new int[0],
                    error,
                    null,
                    0,
                    0
                );
            }
            return NewUnevaluableJobProbe(
                name,
                error,
                "could not open named Job Object for query: " +
                new Win32Exception(error).Message
            );
        }

        using (job)
        {
            int capacity = 64;
            for (int attempt = 0; attempt < 24; attempt++)
            {
                int size;
                try
                {
                    size = checked(8 + checked(capacity * IntPtr.Size));
                }
                catch (OverflowException exception)
                {
                    return NewUnevaluableJobProbe(name, 0, exception.Message);
                }
                IntPtr information = Marshal.AllocHGlobal(size);
                try
                {
                    for (int index = 0; index < size; index++)
                    {
                        Marshal.WriteByte(information, index, 0);
                    }
                    uint returnLength;
                    if (!QueryInformationJobObject(
                            job,
                            JOB_OBJECT_BASIC_PROCESS_ID_LIST_CLASS,
                            information,
                            (uint)size,
                            out returnLength
                        ))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == ERROR_INSUFFICIENT_BUFFER || error == ERROR_MORE_DATA)
                        {
                            long returnedCapacity = returnLength <= 8
                                ? 0
                                : ((long)returnLength - 8 + IntPtr.Size - 1) / IntPtr.Size;
                            long nextCapacity = Math.Max((long)capacity * 2, returnedCapacity);
                            if (nextCapacity <= capacity)
                            {
                                nextCapacity = (long)capacity + 1;
                            }
                            if (nextCapacity > MAX_JOB_PROCESS_IDS)
                            {
                                return NewUnevaluableJobProbe(
                                    name,
                                    error,
                                    "named Job Object process list exceeds the protocol bound"
                                );
                            }
                            capacity = (int)nextCapacity;
                            continue;
                        }
                        return NewUnevaluableJobProbe(
                            name,
                            error,
                            "could not query JobObjectBasicProcessIdList: " +
                            new Win32Exception(error).Message
                        );
                    }

                    uint assigned = unchecked((uint)Marshal.ReadInt32(information, 0));
                    uint listed = unchecked((uint)Marshal.ReadInt32(information, 4));
                    if (listed > assigned || listed > (uint)capacity)
                    {
                        return NewUnevaluableJobProbe(
                            name,
                            0,
                            "JobObjectBasicProcessIdList returned inconsistent process counts"
                        );
                    }
                    if (listed != assigned)
                    {
                        if (assigned > MAX_JOB_PROCESS_IDS)
                        {
                            return NewUnevaluableJobProbe(
                                name,
                                0,
                                "named Job Object process list exceeds the protocol bound"
                            );
                        }
                        capacity = Math.Max(capacity + 1, (int)assigned);
                        continue;
                    }

                    int[] processIds = new int[listed];
                    for (uint index = 0; index < listed; index++)
                    {
                        IntPtr raw = Marshal.ReadIntPtr(
                            information,
                            checked(8 + checked((int)index * IntPtr.Size))
                        );
                        long value = IntPtr.Size == 8
                            ? raw.ToInt64()
                            : unchecked((uint)raw.ToInt32());
                        if (value <= 0 || value > Int32.MaxValue)
                        {
                            return NewUnevaluableJobProbe(
                                name,
                                0,
                                "JobObjectBasicProcessIdList returned a process identifier outside the positive Int32 range"
                            );
                        }
                        processIds[index] = (int)value;
                    }
                    Array.Sort(processIds);
                    for (int index = 1; index < processIds.Length; index++)
                    {
                        if (processIds[index - 1] == processIds[index])
                        {
                            return NewUnevaluableJobProbe(
                                name,
                                0,
                                "JobObjectBasicProcessIdList returned a duplicate process identifier"
                            );
                        }
                    }
                    return NewJobProbe(
                        name,
                        "observed",
                        processIds,
                        0,
                        null,
                        assigned,
                        listed
                    );
                }
                finally
                {
                    Marshal.FreeHGlobal(information);
                }
            }
        }

        return NewUnevaluableJobProbe(
            name,
            0,
            "JobObjectBasicProcessIdList did not converge to one complete active process list"
        );
    }
}
'@
}

function ConvertTo-AstroExtendedLengthPath {
    <#
    Canonical display paths are the protocol/source-of-truth representation. The
    extended-length prefix is added only at the .NET/Win32 I/O boundary because it
    disables normal `.`/`..` parsing. This keeps containment comparisons readable
    and makes every file operation independent of machine LongPathsEnabled state.
    #>
    param([Parameter(Mandatory)][string]$LiteralPath)

    $displayPath = $LiteralPath
    if ($displayPath.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        $displayPath = '\\' + $displayPath.Substring(8)
    }
    elseif ($displayPath.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {
        $displayPath = $displayPath.Substring(4)
    }
    $full = [IO.Path]::GetFullPath($displayPath)
    if ($full.StartsWith('\\', [StringComparison]::Ordinal)) {
        return '\\?\UNC\' + $full.Substring(2)
    }
    return '\\?\' + $full
}

function ConvertFrom-AstroExtendedLengthPath {
    param([Parameter(Mandatory)][string]$LiteralPath)

    if ($LiteralPath.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        return [IO.Path]::GetFullPath(('\\' + $LiteralPath.Substring(8)))
    }
    if ($LiteralPath.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {
        return [IO.Path]::GetFullPath($LiteralPath.Substring(4))
    }
    return [IO.Path]::GetFullPath($LiteralPath)
}

function New-AstroDirectoryLongPath {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $full = [IO.Path]::GetFullPath($LiteralPath)
    [IO.Directory]::CreateDirectory((ConvertTo-AstroExtendedLengthPath $full)) |
        Out-Null
    return $full
}

function New-AstroDirectoryNoClobberLongPath {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $full = [IO.Path]::GetFullPath($LiteralPath)
    [AstroLauncherLockNative]::CreateDirectoryNoReplace($full)
    return $full
}

function Read-AstroUtf8FileLongPath {
    param([Parameter(Mandatory)][string]$LiteralPath)

    return [IO.File]::ReadAllText(
        (ConvertTo-AstroExtendedLengthPath $LiteralPath),
        [Text.UTF8Encoding]::new($false, $true)
    )
}

function Get-AstroFileLengthLongPath {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $LiteralPath),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    )
    try { return [uint64]$stream.Length }
    finally { $stream.Dispose() }
}

function Test-AstroPathLongPath {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [ValidateSet('Any', 'Leaf', 'Container')]
        [string]$PathType = 'Any'
    )

    $state = Get-AstroPathEntryState $LiteralPath
    if ($state.State -ceq 'absent') { return $false }
    if ($state.State -cne 'present') {
        throw "path presence is unevaluable (error=$($state.Error)): $([IO.Path]::GetFullPath($LiteralPath))"
    }
    $isDirectory =
        ($state.Attributes -band [IO.FileAttributes]::Directory) -ne 0
    switch ($PathType) {
        'Leaf' { return -not $isDirectory }
        'Container' { return $isDirectory }
        default { return $true }
    }
}

function Get-AstroFileInfoLongPath {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $full = [IO.Path]::GetFullPath($LiteralPath)
    $attributes = [IO.File]::GetAttributes(
        (ConvertTo-AstroExtendedLengthPath $full)
    )
    if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
        throw "expected an ordinary file but observed a directory: $full"
    }
    return [pscustomobject]@{
        FullName = $full
        Name = [IO.Path]::GetFileName($full)
        Attributes = $attributes
        Length = Get-AstroFileLengthLongPath $full
        IsReadOnly =
            ($attributes -band [IO.FileAttributes]::ReadOnly) -ne 0
    }
}

function Set-AstroFileReadOnlyLongPath {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][bool]$ReadOnly
    )

    $native = ConvertTo-AstroExtendedLengthPath $LiteralPath
    $attributes = [IO.File]::GetAttributes($native)
    $updated = if ($ReadOnly) {
        $attributes -bor [IO.FileAttributes]::ReadOnly
    }
    else {
        $attributes -band (-bnot [IO.FileAttributes]::ReadOnly)
    }
    [IO.File]::SetAttributes($native, $updated)
}

function Get-AstroDirectoryEntriesLongPath {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $directory = [IO.Path]::GetFullPath($LiteralPath)
    [string[]]$nativeEntries = [IO.Directory]::GetFileSystemEntries(
        (ConvertTo-AstroExtendedLengthPath $directory)
    )
    $entries = [Collections.Generic.List[object]]::new()
    foreach ($nativeEntry in $nativeEntries) {
        $full = ConvertFrom-AstroExtendedLengthPath $nativeEntry
        $attributes = [IO.File]::GetAttributes(
            (ConvertTo-AstroExtendedLengthPath $full)
        )
        $isDirectory =
            ($attributes -band [IO.FileAttributes]::Directory) -ne 0
        $length = if ($isDirectory) {
            $null
        }
        else {
            Get-AstroFileLengthLongPath $full
        }
        $entries.Add([pscustomobject]@{
            Name = [IO.Path]::GetFileName($full)
            FullName = $full
            Attributes = $attributes
            PSIsContainer = $isDirectory
            Length = $length
            IsReadOnly =
                ($attributes -band [IO.FileAttributes]::ReadOnly) -ne 0
        })
    }
    return @($entries | Sort-Object Name)
}

function Remove-AstroFileLongPath {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [switch]$ClearReadOnly
    )

    $native = ConvertTo-AstroExtendedLengthPath $LiteralPath
    if ($ClearReadOnly) {
        $attributes = [IO.File]::GetAttributes($native)
        if (($attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) {
            [IO.File]::SetAttributes(
                $native,
                $attributes -band (-bnot [IO.FileAttributes]::ReadOnly)
            )
        }
    }
    $full = [IO.Path]::GetFullPath($LiteralPath)
    $handle = [AstroLauncherLockNative]::OpenExactRenameSource($full)
    try {
        $final = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($handle)
        )
        if (-not [string]::Equals(
                $final,
                $full,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "exact file-delete lease resolved to '$final', expected '$full'"
        }
        [AstroLauncherLockNative]::DeleteExactFileHandle($handle)
    }
    finally {
        $handle.Dispose()
    }
    $terminal = Get-AstroPathEntryState $full
    if ($terminal.State -cne 'absent') {
        throw "exact file delete did not reach absence (state=$($terminal.State), error=$($terminal.Error)): $full"
    }
}

function Remove-AstroEmptyDirectoryLongPath {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $full = [IO.Path]::GetFullPath($LiteralPath)
    $handle = [AstroLauncherLockNative]::OpenExactDeleteDirectory($full)
    try {
        $final = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($handle)
        )
        if (-not [string]::Equals(
                $final.TrimEnd('\', '/'),
                $full.TrimEnd('\', '/'),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "exact empty-directory delete lease resolved to '$final', expected '$full'"
        }
        if (@(Get-AstroDirectoryEntriesLongPath $full).Count -ne 0) {
            throw "exact empty-directory delete source is not empty: $full"
        }
        [AstroLauncherLockNative]::DeleteExactDirectoryHandle($handle)
    }
    finally {
        $handle.Dispose()
    }
    $terminal = Get-AstroPathEntryState $full
    if ($terminal.State -cne 'absent') {
        throw "exact empty-directory delete did not reach absence (state=$($terminal.State), error=$($terminal.Error)): $full"
    }
}

function Remove-AstroOrdinaryFlatDirectoryLongPath {
    <#
    Native-FSV session directories are intentionally flat. Refuse nested or
    redirected state instead of following it, clear only ReadOnly on ordinary
    files, then remove the now-empty directory. Lifecycle callers remain
    responsible for proving the session may be mutated.
    #>
    param([Parameter(Mandatory)][string]$LiteralPath)

    $full = [IO.Path]::GetFullPath($LiteralPath)
    $rootState = Get-AstroPathEntryState $full
    if ($rootState.State -ceq 'absent') { return }
    if ($rootState.State -cne 'present' -or
        ($rootState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
        ($rootState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "long-path flat-directory removal requires one ordinary directory (state=$($rootState.State), attributes=$($rootState.Attributes), error=$($rootState.Error)): $full"
    }
    $handle = [AstroLauncherLockNative]::OpenExactDeleteDirectory($full)
    try {
        $final = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($handle)
        )
        if (-not [string]::Equals(
                $final.TrimEnd('\', '/'),
                $full.TrimEnd('\', '/'),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "exact flat-directory delete lease resolved to '$final', expected '$full'"
        }
        $entries = @(Get-AstroDirectoryEntriesLongPath $full)
        foreach ($entry in $entries) {
            if ($entry.PSIsContainer -or
                ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "long-path flat-directory removal refuses nested/reparse entry: $($entry.FullName)"
            }
        }
        foreach ($entry in $entries) {
            Remove-AstroFileLongPath -LiteralPath $entry.FullName -ClearReadOnly
        }
        if (@(Get-AstroDirectoryEntriesLongPath $full).Count -ne 0) {
            throw "exact flat-directory delete source changed or remained nonempty: $full"
        }
        [AstroLauncherLockNative]::DeleteExactDirectoryHandle($handle)
    }
    finally {
        $handle.Dispose()
    }
    $terminal = Get-AstroPathEntryState $full
    if ($terminal.State -cne 'absent') {
        throw "exact flat-directory delete did not reach absence (state=$($terminal.State), error=$($terminal.Error)): $full"
    }
}

function Throw-AstroOrdinaryTreeInventoryFailure {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Remediation
    )

    $exception = [InvalidOperationException]::new(
        "$Code`: $Message`nRemediation: $Remediation"
    )
    $exception.Data['AstroCode'] = $Code
    $exception.Data['AstroRemediation'] = $Remediation
    throw $exception
}

function Assert-AstroOrdinaryTreeInventoryContract {
    param(
        [Parameter(Mandatory)][string]$Schema,
        [Parameter(Mandatory)][string]$Encoding
    )

    $requiredSchema =
        'astrolabe.ordinary-directory-tree-inventory.v1'
    $requiredEncoding =
        'astrolabe.ordinary-directory-tree-inventory.binary.v1'
    if ($Schema -cne $requiredSchema) {
        Throw-AstroOrdinaryTreeInventoryFailure `
            -Code 'ASTRO_ORDINARY_TREE_INVENTORY_SCHEMA_UNSUPPORTED' `
            -Message (
                "ordinary-tree inventory schema '$Schema' is not the " +
                "required '$requiredSchema'"
            ) `
            -Remediation (
                're-read the physical tree with the current authoritative ' +
                'launcher-lock helper; legacy or unknown inventory schemas ' +
                'never authorize deletion'
            )
    }
    if ($Encoding -cne $requiredEncoding) {
        Throw-AstroOrdinaryTreeInventoryFailure `
            -Code 'ASTRO_ORDINARY_TREE_INVENTORY_ENCODING_UNSUPPORTED' `
            -Message (
                "ordinary-tree inventory encoding '$Encoding' is not the " +
                "required '$requiredEncoding'"
            ) `
            -Remediation (
                're-read the physical tree with the current authoritative ' +
                'binary encoder; never reinterpret an ambient JSON digest'
            )
    }
}

function Write-AstroCanonicalInventoryUInt32 {
    param(
        [Parameter(Mandatory)][IO.Stream]$Stream,
        [Parameter(Mandatory)][uint32]$Value
    )

    [byte[]]$bytes = [BitConverter]::GetBytes($Value)
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    $Stream.Write($bytes, 0, $bytes.Length)
}

function Write-AstroCanonicalInventoryUInt64 {
    param(
        [Parameter(Mandatory)][IO.Stream]$Stream,
        [Parameter(Mandatory)][uint64]$Value
    )

    [byte[]]$bytes = [BitConverter]::GetBytes($Value)
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    $Stream.Write($bytes, 0, $bytes.Length)
}

function Write-AstroCanonicalInventoryString {
    param(
        [Parameter(Mandatory)][IO.Stream]$Stream,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][string]$Description
    )

    try {
        [byte[]]$bytes =
            [Text.UTF8Encoding]::new($false, $true).GetBytes($Value)
    }
    catch {
        Throw-AstroOrdinaryTreeInventoryFailure `
            -Code 'ASTRO_ORDINARY_TREE_INVENTORY_UTF8_INVALID' `
            -Message "$Description is not strict Unicode: $($_.Exception.Message)" `
            -Remediation (
                'preserve the physical tree and investigate the exact Windows ' +
                'namespace spelling; malformed UTF-16 is never hashable authority'
            )
    }
    Write-AstroCanonicalInventoryUInt64 `
        -Stream $Stream -Value ([uint64]$bytes.Length)
    if ($bytes.Length -ne 0) {
        $Stream.Write($bytes, 0, $bytes.Length)
    }
}

function ConvertTo-AstroCanonicalInventorySha256Bytes {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Description
    )

    if ($Value -cnotmatch '^[0-9a-f]{64}$') {
        Throw-AstroOrdinaryTreeInventoryFailure `
            -Code 'ASTRO_ORDINARY_TREE_INVENTORY_RECORD_MALFORMED' `
            -Message "$Description is not one exact lowercase SHA-256 value" `
            -Remediation (
                'preserve the physical tree and regenerate the record from a ' +
                'retained ordinary-file handle'
            )
    }
    [byte[]]$bytes = [byte[]]::new(32)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte(
            $Value.Substring($index * 2, 2),
            16
        )
    }
    return ,$bytes
}

function Get-AstroOrdinaryTreeInventoryRecordFields {
    param([Parameter(Mandatory)]$Record)

    if ($Record -is [Collections.IDictionary]) {
        return [string[]]@($Record.Keys | ForEach-Object { [string]$_ })
    }
    return [string[]]@(
        $Record.PSObject.Properties | ForEach-Object { [string]$_.Name }
    )
}

function Get-AstroOrdinaryTreeInventoryRecordValue {
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][string]$Field
    )

    if ($Record -is [Collections.IDictionary]) {
        return $Record[$Field]
    }
    return $Record.PSObject.Properties[$Field].Value
}

function Get-AstroOrdinaryTreeInventoryOrderedRecords {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Records
    )

    $expectedFields = [string[]]@(
        'relative_path',
        'kind',
        'file_id',
        'attributes',
        'bytes',
        'sha256'
    )
    for ($recordIndex = 0;
        $recordIndex -lt $Records.Count;
        $recordIndex++) {
        $record = $Records[$recordIndex]
        if ($null -eq $record) {
            Throw-AstroOrdinaryTreeInventoryFailure `
                -Code 'ASTRO_ORDINARY_TREE_INVENTORY_RECORD_MALFORMED' `
                -Message "record $recordIndex is null" `
                -Remediation (
                    'preserve the physical tree and regenerate every record from ' +
                    'the authoritative retained-handle inventory reader'
                )
        }
        [string[]]$actualFields = @(
            Get-AstroOrdinaryTreeInventoryRecordFields -Record $record
        )
        if ($actualFields.Count -ne $expectedFields.Count -or
            @(
                $expectedFields |
                    Where-Object { $actualFields -cnotcontains $_ }
            ).Count -ne 0) {
            Throw-AstroOrdinaryTreeInventoryFailure `
                -Code 'ASTRO_ORDINARY_TREE_INVENTORY_RECORD_MALFORMED' `
                -Message (
                    "record $recordIndex fields differ from the exact " +
                    "contract (expected=$($expectedFields -join ','), " +
                    "actual=$($actualFields -join ','))"
                ) `
                -Remediation (
                    'preserve the physical tree and regenerate every record from ' +
                    'the authoritative retained-handle inventory reader'
                )
        }
        $relativePath = Get-AstroOrdinaryTreeInventoryRecordValue `
            -Record $record -Field 'relative_path'
        if ($relativePath -isnot [string]) {
            Throw-AstroOrdinaryTreeInventoryFailure `
                -Code 'ASTRO_ORDINARY_TREE_INVENTORY_RECORD_MALFORMED' `
                -Message "record $recordIndex relative_path is not a string" `
                -Remediation (
                    'preserve the physical tree and regenerate the record without ' +
                    'a serializer round-trip that erases field types'
                )
        }
    }

    [object[]]$orderedRecords = @($Records)
    $comparison = [Comparison[object]]{
        param($left, $right)

        $leftPath = [string](
            Get-AstroOrdinaryTreeInventoryRecordValue `
                -Record $left -Field 'relative_path'
        )
        $rightPath = [string](
            Get-AstroOrdinaryTreeInventoryRecordValue `
                -Record $right -Field 'relative_path'
        )
        if ($leftPath -ceq '.' -and $rightPath -cne '.') { return -1 }
        if ($rightPath -ceq '.' -and $leftPath -cne '.') { return 1 }
        return [StringComparer]::Ordinal.Compare($leftPath, $rightPath)
    }
    [Array]::Sort($orderedRecords, $comparison)
    return $orderedRecords
}

function ConvertTo-AstroOrdinaryTreeInventoryCanonicalBytes {
    <#
    The hash domain is deliberately narrower than JSON. It is one versioned,
    fixed-width binary record stream: domain/schema/encoding strings, count,
    then root-first + ordinal-path records with explicit enum/null markers.
    Strings are strict BOM-free UTF-8 with big-endian UInt64 byte lengths;
    integers are fixed-width big-endian; SHA-256 values are raw 32-byte fields.
    #>
    param(
        [Parameter(Mandatory)][string]$Schema,
        [Parameter(Mandatory)][string]$Encoding,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records
    )

    Assert-AstroOrdinaryTreeInventoryContract `
        -Schema $Schema -Encoding $Encoding
    [object[]]$orderedRecords = @(
        Get-AstroOrdinaryTreeInventoryOrderedRecords -Records $Records
    )

    $paths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $rootCount = 0
    $stream = [IO.MemoryStream]::new()
    try {
        Write-AstroCanonicalInventoryString `
            -Stream $stream `
            -Value 'astrolabe.ordinary-directory-tree-inventory' `
            -Description 'ordinary-tree inventory domain'
        Write-AstroCanonicalInventoryString `
            -Stream $stream -Value $Schema -Description 'inventory schema'
        Write-AstroCanonicalInventoryString `
            -Stream $stream -Value $Encoding -Description 'inventory encoding'
        Write-AstroCanonicalInventoryUInt64 `
            -Stream $stream -Value ([uint64]$orderedRecords.Count)

        for ($recordIndex = 0;
            $recordIndex -lt $orderedRecords.Count;
            $recordIndex++) {
            $record = $orderedRecords[$recordIndex]
            $relativePath = Get-AstroOrdinaryTreeInventoryRecordValue `
                -Record $record -Field 'relative_path'
            $kind = Get-AstroOrdinaryTreeInventoryRecordValue `
                -Record $record -Field 'kind'
            $fileId = Get-AstroOrdinaryTreeInventoryRecordValue `
                -Record $record -Field 'file_id'
            $attributes = Get-AstroOrdinaryTreeInventoryRecordValue `
                -Record $record -Field 'attributes'
            $byteLength = Get-AstroOrdinaryTreeInventoryRecordValue `
                -Record $record -Field 'bytes'
            $sha256 = Get-AstroOrdinaryTreeInventoryRecordValue `
                -Record $record -Field 'sha256'

            if ($relativePath -isnot [string] -or
                [string]::IsNullOrEmpty([string]$relativePath) -or
                [IO.Path]::IsPathRooted([string]$relativePath) -or
                ([string]$relativePath).Contains('/') -or
                ([string]$relativePath).StartsWith(
                    '\', [StringComparison]::Ordinal
                ) -or
                ([string]$relativePath).EndsWith(
                    '\', [StringComparison]::Ordinal
                ) -or
                @(
                    ([string]$relativePath).ToCharArray() |
                        Where-Object { [char]::IsControl($_) }
                ).Count -ne 0) {
                Throw-AstroOrdinaryTreeInventoryFailure `
                    -Code 'ASTRO_ORDINARY_TREE_INVENTORY_PATH_INVALID' `
                    -Message "record $recordIndex has a noncanonical relative path" `
                    -Remediation (
                        'preserve the physical tree; use only the exact relative ' +
                        'path returned by the retained ordinary-tree walk'
                    )
            }
            if ([string]$relativePath -ceq '.') {
                $rootCount++
            }
            else {
                [string[]]$segments =
                    ([string]$relativePath).Split([char]92)
                if (@(
                        $segments |
                            Where-Object {
                                [string]::IsNullOrEmpty($_) -or
                                $_ -ceq '.' -or $_ -ceq '..'
                            }
                    ).Count -ne 0) {
                    Throw-AstroOrdinaryTreeInventoryFailure `
                        -Code 'ASTRO_ORDINARY_TREE_INVENTORY_PATH_INVALID' `
                        -Message (
                            "record $recordIndex path contains an empty or dot " +
                            'segment'
                        ) `
                        -Remediation (
                            'preserve the tree and investigate namespace drift; ' +
                            'canonical inventory paths never contain dot segments'
                        )
                }
            }
            if (-not $paths.Add([string]$relativePath)) {
                Throw-AstroOrdinaryTreeInventoryFailure `
                    -Code 'ASTRO_ORDINARY_TREE_INVENTORY_PATH_DUPLICATE' `
                    -Message (
                        "record $recordIndex duplicates ordinal path " +
                        "'$relativePath'"
                    ) `
                    -Remediation (
                        'preserve the tree and repeat the retained-handle walk; ' +
                        'duplicate authority is never canonicalized away'
                    )
            }
            if ($kind -isnot [string] -or
                [string]$kind -cnotin @('directory', 'file')) {
                Throw-AstroOrdinaryTreeInventoryFailure `
                    -Code 'ASTRO_ORDINARY_TREE_INVENTORY_RECORD_MALFORMED' `
                    -Message "record $recordIndex has invalid kind '$kind'" `
                    -Remediation (
                        'regenerate the record; the only canonical kinds are ' +
                        'directory and file'
                    )
            }
            if ($fileId -isnot [string] -or
                [string]$fileId -cnotmatch
                    '^[0-9a-f]{16}:[0-9a-f]{32}$') {
                Throw-AstroOrdinaryTreeInventoryFailure `
                    -Code 'ASTRO_ORDINARY_TREE_INVENTORY_RECORD_MALFORMED' `
                    -Message "record $recordIndex has invalid FILE_ID '$fileId'" `
                    -Remediation (
                        'regenerate the record from its retained Windows file ' +
                        'handle; never infer or normalize a FILE_ID'
                    )
            }
            if ($attributes -isnot [uint32]) {
                $attributeType = if ($null -eq $attributes) {
                    '<null>'
                }
                else {
                    $attributes.GetType().FullName
                }
                Throw-AstroOrdinaryTreeInventoryFailure `
                    -Code 'ASTRO_ORDINARY_TREE_INVENTORY_RECORD_MALFORMED' `
                    -Message (
                        "record $recordIndex attributes type is " +
                        "'$attributeType', expected UInt32"
                    ) `
                    -Remediation (
                        'regenerate the record without a JSON or textual ' +
                        'round-trip that erases numeric width'
                    )
            }
            $isDirectoryAttribute =
                ([uint32]$attributes -band
                    [uint32][IO.FileAttributes]::Directory) -ne 0
            $isReparseAttribute =
                ([uint32]$attributes -band
                    [uint32][IO.FileAttributes]::ReparsePoint) -ne 0
            if ($isReparseAttribute -or
                ([string]$kind -ceq 'directory') -ne
                    $isDirectoryAttribute) {
                Throw-AstroOrdinaryTreeInventoryFailure `
                    -Code 'ASTRO_ORDINARY_TREE_INVENTORY_RECORD_MALFORMED' `
                    -Message (
                        "record $recordIndex kind/attributes are inconsistent " +
                        "or reparse-bearing (kind=$kind, attributes=$attributes)"
                    ) `
                    -Remediation (
                        'preserve the tree; ordinary inventories never traverse ' +
                        'or encode reparse entries'
                    )
            }
            if ([string]$kind -ceq 'directory') {
                if ($null -ne $byteLength -or $null -ne $sha256) {
                    Throw-AstroOrdinaryTreeInventoryFailure `
                        -Code 'ASTRO_ORDINARY_TREE_INVENTORY_RECORD_MALFORMED' `
                        -Message (
                            "directory record $recordIndex must contain exact " +
                            'null byte/hash fields'
                        ) `
                        -Remediation (
                            'regenerate the record from its retained directory ' +
                            'handle without synthesizing file metadata'
                        )
                }
            }
            else {
                if ($byteLength -isnot [uint64] -or
                    $sha256 -isnot [string]) {
                    Throw-AstroOrdinaryTreeInventoryFailure `
                        -Code 'ASTRO_ORDINARY_TREE_INVENTORY_RECORD_MALFORMED' `
                        -Message (
                            "file record $recordIndex requires UInt64 bytes and " +
                            'one lowercase SHA-256 string'
                        ) `
                        -Remediation (
                            'regenerate the record from its retained ordinary-file ' +
                            'handle without a lossy serializer round-trip'
                        )
                }
            }

            Write-AstroCanonicalInventoryString `
                -Stream $stream -Value ([string]$relativePath) `
                -Description "record $recordIndex relative path"
            $stream.WriteByte(
                $(if ([string]$kind -ceq 'directory') { 1 } else { 2 })
            )
            Write-AstroCanonicalInventoryString `
                -Stream $stream -Value ([string]$fileId) `
                -Description "record $recordIndex FILE_ID"
            Write-AstroCanonicalInventoryUInt32 `
                -Stream $stream -Value ([uint32]$attributes)
            if ([string]$kind -ceq 'directory') {
                $stream.WriteByte(0)
                $stream.WriteByte(0)
            }
            else {
                $stream.WriteByte(1)
                Write-AstroCanonicalInventoryUInt64 `
                    -Stream $stream -Value ([uint64]$byteLength)
                $stream.WriteByte(1)
                [byte[]]$hashBytes =
                    ConvertTo-AstroCanonicalInventorySha256Bytes `
                        -Value ([string]$sha256) `
                        -Description "record $recordIndex SHA-256"
                $stream.Write($hashBytes, 0, $hashBytes.Length)
            }
        }
        if ($rootCount -ne 1 -or $orderedRecords.Count -eq 0 -or
            [string](
                Get-AstroOrdinaryTreeInventoryRecordValue `
                    -Record $orderedRecords[0] -Field 'relative_path'
            ) -cne '.' -or
            [string](
                Get-AstroOrdinaryTreeInventoryRecordValue `
                    -Record $orderedRecords[0] -Field 'kind'
            ) -cne 'directory') {
            Throw-AstroOrdinaryTreeInventoryFailure `
                -Code 'ASTRO_ORDINARY_TREE_INVENTORY_ROOT_INVALID' `
                -Message (
                    'inventory must contain one root directory record and encode ' +
                    'it before every ordinal descendant'
                ) `
                -Remediation (
                    'preserve the physical tree and repeat the authoritative ' +
                    'retained-handle walk from its exact root'
                )
        }
        return ,([byte[]]$stream.ToArray())
    }
    finally {
        $stream.Dispose()
    }
}

function Get-AstroOrdinaryDirectoryTreeInventoryLongPath {
    <#
    Produces a content- and identity-bound inventory of one ordinary directory
    tree without traversing reparses. Exact read/delete-denying handles remain
    live for the complete observation so every recorded file and directory is
    the same filesystem object whose bytes and metadata were read.
    #>
    param([Parameter(Mandatory)][string]$LiteralPath)

    $root = [IO.Path]::GetFullPath($LiteralPath)
    $rootPrefix = $root.TrimEnd('\', '/') +
        [IO.Path]::DirectorySeparatorChar
    $records = [Collections.Generic.List[object]]::new()
    $handles = [Collections.Generic.List[object]]::new()
    $visit = $null
    try {
        $visit = {
            param(
                [Parameter(Mandatory)][string]$Directory,
                [Parameter(Mandatory)][string]$RelativePath
            )

            $directoryState = Get-AstroPathEntryState $Directory
            if ($directoryState.State -ceq 'present' -and
                ($directoryState.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Throw-AstroOrdinaryTreeInventoryFailure `
                    -Code 'ASTRO_ORDINARY_TREE_INVENTORY_REPARSE_REFUSED' `
                    -Message (
                        "ordinary-tree inventory refuses reparse directory " +
                        "'$Directory' (attributes=$($directoryState.Attributes))"
                    ) `
                    -Remediation (
                        'preserve the namespace object and inventory only a real ' +
                        'ordinary directory tree; never traverse the reparse target'
                    )
            }
            if ($directoryState.State -cne 'present' -or
                ($directoryState.Attributes -band
                    [IO.FileAttributes]::Directory) -eq 0) {
                Throw-AstroOrdinaryTreeInventoryFailure `
                    -Code 'ASTRO_ORDINARY_TREE_INVENTORY_ROOT_INVALID' `
                    -Message (
                    'ordinary tree inventory requires an ordinary directory ' +
                    "(state=$($directoryState.State), " +
                    "attributes=$($directoryState.Attributes), " +
                    "error=$($directoryState.Error)): $Directory"
                    ) `
                    -Remediation (
                        'preserve the path and inspect its exact filesystem state; ' +
                        'only one present ordinary directory is valid authority'
                    )
            }
            $directoryHandle =
                [AstroLauncherLockNative]::OpenExactDeleteDirectory(
                    $Directory
                )
            $handles.Add($directoryHandle)
            $directoryFinal = ConvertFrom-AstroNativeFinalPath (
                [AstroLauncherLockNative]::GetFileFinalPath(
                    $directoryHandle
                )
            )
            if (-not [string]::Equals(
                    $directoryFinal.TrimEnd('\', '/'),
                    $Directory.TrimEnd('\', '/'),
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw (
                    "ordinary tree directory handle resolved to " +
                    "'$directoryFinal', expected '$Directory'"
                )
            }
            $records.Add([ordered]@{
                relative_path = $RelativePath
                kind = 'directory'
                file_id =
                    [AstroLauncherLockNative]::GetFileIdentity(
                        $directoryHandle
                    )
                attributes = [uint32]$directoryState.Attributes
                bytes = $null
                sha256 = $null
            })

            foreach ($entry in @(
                    Get-AstroDirectoryEntriesLongPath $Directory
                )) {
                $entryFull = [IO.Path]::GetFullPath($entry.FullName)
                if (-not $entryFull.StartsWith(
                        $rootPrefix,
                        [StringComparison]::OrdinalIgnoreCase
                    )) {
                    Throw-AstroOrdinaryTreeInventoryFailure `
                        -Code 'ASTRO_ORDINARY_TREE_INVENTORY_PATH_ESCAPE' `
                        -Message (
                            "ordinary-tree entry escapes root '$root': " +
                            $entryFull
                        ) `
                        -Remediation (
                            'preserve the tree and investigate namespace drift; ' +
                            'never hash or delete an entry outside the retained root'
                        )
                }
                if (($entry.Attributes -band
                        [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    Throw-AstroOrdinaryTreeInventoryFailure `
                        -Code 'ASTRO_ORDINARY_TREE_INVENTORY_REPARSE_REFUSED' `
                        -Message (
                            'ordinary-tree inventory refuses reparse entry: ' +
                            $entryFull
                        ) `
                        -Remediation (
                            'preserve the namespace object and inventory only an ' +
                            'ordinary tree; never traverse or hash its target'
                        )
                }
                $entryRelative = $entryFull.Substring(
                    $rootPrefix.Length
                )
                if ($entry.PSIsContainer) {
                    & $visit $entryFull $entryRelative
                    continue
                }

                $fileHandle =
                    [AstroLauncherLockNative]::OpenExactProtectedReadFile(
                        $entryFull
                    )
                $handles.Add($fileHandle)
                $fileFinal = ConvertFrom-AstroNativeFinalPath (
                    [AstroLauncherLockNative]::GetFileFinalPath(
                        $fileHandle
                    )
                )
                if (-not [string]::Equals(
                        $fileFinal,
                        $entryFull,
                        [StringComparison]::OrdinalIgnoreCase
                    )) {
                    throw (
                        "ordinary tree file handle resolved to '$fileFinal', " +
                        "expected '$entryFull'"
                    )
                }
                $fileHash =
                    [AstroLauncherLockNative]::ComputeExactFileSha256(
                        $fileHandle
                    )
                $records.Add([ordered]@{
                    relative_path = $entryRelative
                    kind = 'file'
                    file_id =
                        [AstroLauncherLockNative]::GetFileIdentity(
                            $fileHandle
                        )
                    attributes = [uint32]$entry.Attributes
                    bytes = [uint64]$entry.Length
                    sha256 = $fileHash
                })
            }
        }

        & $visit $root '.'
        [byte[]]$canonicalBytes =
            ConvertTo-AstroOrdinaryTreeInventoryCanonicalBytes `
                -Schema `
                    'astrolabe.ordinary-directory-tree-inventory.v1' `
                -Encoding `
                    'astrolabe.ordinary-directory-tree-inventory.binary.v1' `
                -Records ([object[]]$records.ToArray())
        [object[]]$orderedRecords = @(
            Get-AstroOrdinaryTreeInventoryOrderedRecords `
                -Records ([object[]]$records.ToArray())
        )
        $inventoryHash = Get-AstroByteSha256 $canonicalBytes
        return [pscustomobject]@{
            schema = 'astrolabe.ordinary-directory-tree-inventory.v1'
            encoding =
                'astrolabe.ordinary-directory-tree-inventory.binary.v1'
            root = $root
            entry_count = $orderedRecords.Count
            entries = [object[]]$orderedRecords
            canonical_bytes = $canonicalBytes
            canonical_bytes_length = [uint64]$canonicalBytes.Length
            sha256 = $inventoryHash
        }
    }
    finally {
        foreach ($handle in $handles) {
            $handle.Dispose()
        }
    }
}

function Remove-AstroOrdinaryDirectoryTreeLongPath {
    <#
    Removes only the exact ordinary files and directories bound by a caller's
    inventory hash. Every descendant gets a retained identity-checked handle;
    reparses and namespace drift refuse before deletion. ReadOnly files are
    deleted through FILE_DISPOSITION_INFO_EX on that exact handle, so no
    preflight attribute mutation is needed.
    #>
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$ExpectedInventorySchema,
        [Parameter(Mandatory)][string]$ExpectedInventoryEncoding,
        [Parameter(Mandatory)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedInventorySha256
    )

    Assert-AstroOrdinaryTreeInventoryContract `
        -Schema $ExpectedInventorySchema `
        -Encoding $ExpectedInventoryEncoding
    $inventory =
        Get-AstroOrdinaryDirectoryTreeInventoryLongPath $LiteralPath
    if ([string]$inventory.schema -cne $ExpectedInventorySchema -or
        [string]$inventory.encoding -cne $ExpectedInventoryEncoding -or
        [string]$inventory.sha256 -cne $ExpectedInventorySha256) {
        Throw-AstroOrdinaryTreeInventoryFailure `
            -Code 'ASTRO_ORDINARY_TREE_INVENTORY_DRIFT' `
            -Message (
                'ordinary-tree canonical inventory drifted before deletion ' +
                "(schema=$($inventory.schema), " +
                "encoding=$($inventory.encoding), " +
                "expected=$ExpectedInventorySha256, " +
                "observed=$($inventory.sha256), " +
                "entries=$($inventory.entry_count)): $($inventory.root)"
            ) `
            -Remediation (
                'preserve every tree byte; stop the writer and acquire a fresh ' +
                'canonical inventory before any deletion is authorized'
            )
    }

    $root = [string]$inventory.root
    $rootPrefix = $root.TrimEnd('\', '/') +
        [IO.Path]::DirectorySeparatorChar
    $leases = [Collections.Generic.List[object]]::new()
    $expected = @{}
    foreach ($record in @($inventory.entries)) {
        $path = if ([string]$record.relative_path -ceq '.') {
            $root
        }
        else {
            [IO.Path]::GetFullPath(
                (Join-Path $root ([string]$record.relative_path))
            )
        }
        if (-not [string]::Equals(
                $path,
                $root,
                [StringComparison]::OrdinalIgnoreCase
            ) -and
            -not $path.StartsWith(
                $rootPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "ordinary tree inventory path escapes root '$root': $path"
        }
        if ($expected.ContainsKey($path)) {
            throw "ordinary tree inventory contains duplicate path: $path"
        }
        $expected[$path] = $record
    }

    try {
        foreach ($path in @(
                $expected.Keys |
                    Where-Object {
                        [string]$expected[$_].kind -ceq 'directory'
                    } |
                    Sort-Object { $_.Length }
            )) {
            $handle =
                [AstroLauncherLockNative]::OpenExactDeleteDirectory($path)
            $final = ConvertFrom-AstroNativeFinalPath (
                [AstroLauncherLockNative]::GetFileFinalPath($handle)
            )
            $fileId =
                [AstroLauncherLockNative]::GetFileIdentity($handle)
            if (-not [string]::Equals(
                    $final.TrimEnd('\', '/'),
                    $path.TrimEnd('\', '/'),
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                [string]$fileId -cne
                    [string]$expected[$path].file_id) {
                $handle.Dispose()
                throw (
                    "ordinary tree directory identity drifted before " +
                    "deletion: $path"
                )
            }
            $leases.Add([pscustomobject]@{
                path = $path
                kind = 'directory'
                handle = $handle
            })
        }
        foreach ($path in @(
                $expected.Keys |
                    Where-Object {
                        [string]$expected[$_].kind -ceq 'file'
                    } |
                    Sort-Object
            )) {
            $handle =
                [AstroLauncherLockNative]::OpenExactDispositionFile($path)
            $final = ConvertFrom-AstroNativeFinalPath (
                [AstroLauncherLockNative]::GetFileFinalPath($handle)
            )
            $fileId =
                [AstroLauncherLockNative]::GetFileIdentity($handle)
            $sha256 =
                [AstroLauncherLockNative]::ComputeExactFileSha256($handle)
            if (-not [string]::Equals(
                    $final,
                    $path,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                [string]$fileId -cne
                    [string]$expected[$path].file_id -or
                [string]$sha256 -cne
                    [string]$expected[$path].sha256) {
                $handle.Dispose()
                throw (
                    "ordinary tree file identity/bytes drifted before deletion: " +
                    $path
                )
            }
            $leases.Add([pscustomobject]@{
                path = $path
                kind = 'file'
                handle = $handle
            })
        }

        $namespace = [Collections.Generic.List[object]]::new()
        $scan = $null
        $scan = {
            param(
                [Parameter(Mandatory)][string]$Directory,
                [Parameter(Mandatory)][string]$RelativePath
            )
            $state = Get-AstroPathEntryState $Directory
            if ($state.State -cne 'present' -or
                ($state.Attributes -band
                    [IO.FileAttributes]::Directory) -eq 0 -or
                ($state.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw (
                    'ordinary tree namespace changed at directory ' +
                    "$Directory (state=$($state.State), " +
                    "attributes=$($state.Attributes), error=$($state.Error))"
                )
            }
            $namespace.Add([ordered]@{
                relative_path = $RelativePath
                kind = 'directory'
                attributes = [uint32]$state.Attributes
                bytes = $null
            })
            foreach ($entry in @(
                    Get-AstroDirectoryEntriesLongPath $Directory
                )) {
                $entryFull = [IO.Path]::GetFullPath($entry.FullName)
                if (-not $entryFull.StartsWith(
                        $rootPrefix,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    ($entry.Attributes -band
                        [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw (
                        'ordinary tree namespace gained escaping/reparse ' +
                        "entry: $entryFull"
                    )
                }
                $entryRelative = $entryFull.Substring(
                    $rootPrefix.Length
                )
                if ($entry.PSIsContainer) {
                    & $scan $entryFull $entryRelative
                }
                else {
                    $namespace.Add([ordered]@{
                        relative_path = $entryRelative
                        kind = 'file'
                        attributes = [uint32]$entry.Attributes
                        bytes = [uint64]$entry.Length
                    })
                }
            }
        }
        & $scan $root '.'
        if ($namespace.Count -ne [int]$inventory.entry_count) {
            throw (
                'ordinary tree namespace entry count drifted under retained ' +
                "handles (expected=$($inventory.entry_count), " +
                "observed=$($namespace.Count)): $root"
            )
        }
        foreach ($observed in $namespace) {
            $path = if ([string]$observed.relative_path -ceq '.') {
                $root
            }
            else {
                [IO.Path]::GetFullPath(
                    (Join-Path $root ([string]$observed.relative_path))
                )
            }
            if (-not $expected.ContainsKey($path)) {
                throw "ordinary tree namespace gained unexpected entry: $path"
            }
            $record = $expected[$path]
            if ([string]$observed.kind -cne [string]$record.kind -or
                [uint32]$observed.attributes -ne
                    [uint32]$record.attributes -or
                ([string]$observed.kind -ceq 'file' -and
                    [uint64]$observed.bytes -ne [uint64]$record.bytes)) {
                throw (
                    'ordinary tree namespace metadata drifted under retained ' +
                    "handles: $path"
                )
            }
        }

        foreach ($lease in @(
                $leases |
                    Where-Object { $_.kind -ceq 'file' } |
                    Sort-Object -Property path -Descending
            )) {
            [AstroLauncherLockNative]::
                DeleteExactFileHandleIgnoringReadOnly($lease.handle)
            $lease.handle.Dispose()
            $lease.handle = $null
            $terminal = Get-AstroPathEntryState $lease.path
            if ($terminal.State -cne 'absent') {
                throw (
                    'exact ordinary-tree file delete did not reach absence ' +
                    "(state=$($terminal.State), error=$($terminal.Error)): " +
                    $lease.path
                )
            }
        }
        foreach ($lease in @(
                $leases |
                    Where-Object { $_.kind -ceq 'directory' } |
                    Sort-Object { $_.path.Length } -Descending
            )) {
            if (@(
                    Get-AstroDirectoryEntriesLongPath $lease.path
                ).Count -ne 0) {
                throw (
                    'ordinary tree directory gained or retained entries ' +
                    "before exact delete: $($lease.path)"
                )
            }
            [AstroLauncherLockNative]::
                DeleteExactDirectoryHandle($lease.handle)
            $lease.handle.Dispose()
            $lease.handle = $null
            $terminal = Get-AstroPathEntryState $lease.path
            if ($terminal.State -cne 'absent') {
                throw (
                    'exact ordinary-tree directory delete did not reach ' +
                    "absence (state=$($terminal.State), " +
                    "error=$($terminal.Error)): $($lease.path)"
                )
            }
        }
    }
    finally {
        foreach ($lease in $leases) {
            if ($null -ne $lease.handle) {
                $lease.handle.Dispose()
            }
        }
    }
    $terminalRoot = Get-AstroPathEntryState $root
    if ($terminalRoot.State -cne 'absent') {
        throw (
            'ordinary tree cleanup did not reach root absence ' +
            "(state=$($terminalRoot.State), " +
            "error=$($terminalRoot.Error)): $root"
        )
    }
}

$script:AstroLauncherLockMaxBytes = 65536
$script:AstroLauncherProtocolSnapshotMaxBytes = 1048576

function Get-AstroByteSha256 {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return (
            [BitConverter]::ToString($hasher.ComputeHash($Bytes)) -replace '-', ''
        ).ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }
}

function Get-AstroJsonNextTokenIndex {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Json,
        [Parameter(Mandatory)][int]$StartIndex
    )

    $index = $StartIndex
    while ($index -lt $Json.Length -and
        ($Json[$index] -eq ' ' -or $Json[$index] -eq "`t" -or
            $Json[$index] -eq "`r" -or $Json[$index] -eq "`n")) {
        $index++
    }
    return $index
}

function Read-AstroJsonStringToken {
    param(
        [Parameter(Mandatory)][string]$Json,
        [Parameter(Mandatory)][int]$StartIndex
    )

    if ($StartIndex -ge $Json.Length -or $Json[$StartIndex] -ne '"') {
        throw "expected a JSON string token at character $StartIndex"
    }
    $builder = [Text.StringBuilder]::new()
    $index = $StartIndex + 1
    while ($index -lt $Json.Length) {
        $character = $Json[$index]
        if ($character -eq '"') {
            return [pscustomobject]@{
                Value = $builder.ToString()
                Raw = $Json.Substring($StartIndex, $index - $StartIndex + 1)
                NextIndex = $index + 1
            }
        }
        if ([int]$character -lt 0x20) {
            throw "unescaped control character in JSON string at character $index"
        }
        if ($character -ne '\') {
            [void]$builder.Append($character)
            $index++
            continue
        }

        $index++
        if ($index -ge $Json.Length) {
            throw 'unterminated JSON escape sequence'
        }
        $escape = $Json[$index]
        switch ($escape) {
            '"' { [void]$builder.Append('"') }
            '\' { [void]$builder.Append('\') }
            '/' { [void]$builder.Append('/') }
            'b' { [void]$builder.Append([char]0x08) }
            'f' { [void]$builder.Append([char]0x0c) }
            'n' { [void]$builder.Append([char]0x0a) }
            'r' { [void]$builder.Append([char]0x0d) }
            't' { [void]$builder.Append([char]0x09) }
            'u' {
                if ($index + 4 -ge $Json.Length) {
                    throw "truncated JSON Unicode escape at character $($index - 1)"
                }
                $hex = $Json.Substring($index + 1, 4)
                if ($hex -cnotmatch '^[0-9a-fA-F]{4}$') {
                    throw "invalid JSON Unicode escape '\u$hex'"
                }
                $codeUnit = [Convert]::ToInt32($hex, 16)
                $index += 4
                if ($codeUnit -ge 0xd800 -and $codeUnit -le 0xdbff) {
                    if ($index + 6 -ge $Json.Length -or
                        $Json[$index + 1] -ne '\' -or
                        $Json[$index + 2] -ne 'u') {
                        throw 'high surrogate JSON escape is not followed by a low surrogate'
                    }
                    $lowHex = $Json.Substring($index + 3, 4)
                    if ($lowHex -cnotmatch '^[0-9a-fA-F]{4}$') {
                        throw "invalid low-surrogate JSON escape '\u$lowHex'"
                    }
                    $lowCodeUnit = [Convert]::ToInt32($lowHex, 16)
                    if ($lowCodeUnit -lt 0xdc00 -or $lowCodeUnit -gt 0xdfff) {
                        throw 'high surrogate JSON escape is not followed by a low surrogate'
                    }
                    [void]$builder.Append([char]$codeUnit)
                    [void]$builder.Append([char]$lowCodeUnit)
                    $index += 6
                }
                elseif ($codeUnit -ge 0xdc00 -and $codeUnit -le 0xdfff) {
                    throw 'unpaired low-surrogate JSON escape'
                }
                else {
                    [void]$builder.Append([char]$codeUnit)
                }
            }
            default { throw "invalid JSON escape sequence '\$escape'" }
        }
        $index++
    }
    throw "unterminated JSON string token at character $StartIndex"
}

function ConvertFrom-AstroStrictFlatJsonObject {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json)

    $properties = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    $names = [Collections.Generic.List[string]]::new()
    $index = Get-AstroJsonNextTokenIndex $Json 0
    if ($index -ge $Json.Length -or $Json[$index] -ne '{') {
        throw 'JSON root must be one object'
    }
    $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
    if ($index -lt $Json.Length -and $Json[$index] -eq '}') {
        $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
        if ($index -ne $Json.Length) {
            throw "unexpected data after JSON object at character $index"
        }
        return [pscustomobject]@{ Properties = $properties; Names = @(); Raw = $Json }
    }

    while ($true) {
        $nameToken = Read-AstroJsonStringToken $Json $index
        $name = [string]$nameToken.Value
        if ($properties.ContainsKey($name)) {
            throw "duplicate decoded JSON property '$name'"
        }
        $index = Get-AstroJsonNextTokenIndex $Json $nameToken.NextIndex
        if ($index -ge $Json.Length -or $Json[$index] -ne ':') {
            throw "expected ':' after JSON property '$name'"
        }
        $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
        if ($index -ge $Json.Length) {
            throw "missing value for JSON property '$name'"
        }

        $entry = $null
        if ($Json[$index] -eq '"') {
            $valueToken = Read-AstroJsonStringToken $Json $index
            $entry = [pscustomobject]@{
                Kind = 'string'
                Value = [string]$valueToken.Value
                Raw = [string]$valueToken.Raw
            }
            $index = $valueToken.NextIndex
        }
        elseif ($Json[$index] -eq '-' -or
            ($Json[$index] -ge '0' -and $Json[$index] -le '9')) {
            $numberMatch = [Regex]::Match(
                $Json.Substring($index),
                '^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?',
                [Text.RegularExpressions.RegexOptions]::CultureInvariant
            )
            if (-not $numberMatch.Success) {
                throw "invalid JSON number for property '$name'"
            }
            $rawNumber = $numberMatch.Value
            $entry = [pscustomobject]@{
                Kind = if ($rawNumber -cmatch '^-?(?:0|[1-9][0-9]*)$') {
                    'integer'
                } else {
                    'number'
                }
                Value = $rawNumber
                Raw = $rawNumber
            }
            $index += $rawNumber.Length
        }
        elseif ($Json.Substring($index).StartsWith('true', [StringComparison]::Ordinal)) {
            $entry = [pscustomobject]@{ Kind = 'boolean'; Value = $true; Raw = 'true' }
            $index += 4
        }
        elseif ($Json.Substring($index).StartsWith('false', [StringComparison]::Ordinal)) {
            $entry = [pscustomobject]@{ Kind = 'boolean'; Value = $false; Raw = 'false' }
            $index += 5
        }
        elseif ($Json.Substring($index).StartsWith('null', [StringComparison]::Ordinal)) {
            $entry = [pscustomobject]@{ Kind = 'null'; Value = $null; Raw = 'null' }
            $index += 4
        }
        else {
            throw "JSON property '$name' must have a scalar string/number/boolean/null value"
        }

        $properties.Add($name, $entry)
        $names.Add($name)
        $index = Get-AstroJsonNextTokenIndex $Json $index
        if ($index -ge $Json.Length) {
            throw 'unterminated JSON object'
        }
        if ($Json[$index] -eq '}') {
            $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
            if ($index -ne $Json.Length) {
                throw "unexpected data after JSON object at character $index"
            }
            break
        }
        if ($Json[$index] -ne ',') {
            throw "expected ',' or '}' at character $index"
        }
        $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
    }

    return [pscustomobject]@{
        Properties = $properties
        Names = @($names)
        Raw = $Json
    }
}

function ConvertTo-AstroLauncherTransitionState {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $full = [IO.Path]::GetFullPath($LiteralPath)
    $leaf = [IO.Path]::GetFileName($full)
    $candidatePhase = $null
    foreach ($phaseName in @('claim', 'cleanup', 'reclaim')) {
        $reserved = "astrolabe-launcher.lock.$phaseName"
        if ([string]::Equals(
                $leaf,
                $reserved,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            $leaf.StartsWith(
                "$reserved.",
                [StringComparison]::OrdinalIgnoreCase
            )) {
            $candidatePhase = $phaseName
            break
        }
    }
    if ($null -eq $candidatePhase) {
        return [pscustomobject]@{
            Path = $full
            Candidate = $false
            Valid = $false
            Format = 'none'
            LegacyMarker = $false
            Phase = $null
            Pid = $null
            Issue = $null
            OwnerProcessStartUtcTicks = $null
            Sha256 = $null
            Nonce = $null
            ValidationError = $null
        }
    }

    $strict = [Regex]::Match(
        $leaf,
        '^astrolabe-launcher\.lock\.(?<phase>claim|cleanup|reclaim)\.v2\.' +
            'pid-(?<pid>[1-9][0-9]*)\.issue-(?<issue>[1-9][0-9]*)\.' +
            'ticks-(?<ticks>[1-9][0-9]*)\.sha256-(?<sha>[0-9a-f]{64})\.' +
            '(?<nonce>[0-9a-f]{32})\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $strict.Success) {
        $legacyMarker = [Regex]::Match(
            $leaf,
            '^astrolabe-launcher\.lock\.reclaim\.legacy\.' +
                'pid-(?<pid>[1-9][0-9]*)\.issue-(?<issue>[1-9][0-9]*)\.' +
                'sha256-(?<sha>[0-9a-f]{64})\.(?<nonce>[0-9a-f]{32})\z',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        if ($legacyMarker.Success) {
            $legacyPid = 0
            $legacyIssue = 0
            if ([int]::TryParse(
                    $legacyMarker.Groups['pid'].Value,
                    [Globalization.NumberStyles]::None,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [ref]$legacyPid
                ) -and $legacyPid -gt 0 -and
                [int]::TryParse(
                    $legacyMarker.Groups['issue'].Value,
                    [Globalization.NumberStyles]::None,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [ref]$legacyIssue
                ) -and $legacyIssue -gt 0) {
                return [pscustomobject]@{
                    Path = $full
                    Candidate = $true
                    Valid = $false
                    Format = 'legacy-reclaim-marker'
                    LegacyMarker = $true
                    Phase = 'reclaim'
                    Pid = $legacyPid
                    Issue = $legacyIssue
                    OwnerProcessStartUtcTicks = $null
                    Sha256 = $legacyMarker.Groups['sha'].Value
                    Nonce = $legacyMarker.Groups['nonce'].Value
                    ValidationError = 'recognized legacy reclaim marker requires explicit unreadable quarantine'
                }
            }
        }
        return [pscustomobject]@{
            Path = $full
            Candidate = $true
            Valid = $false
            Format = 'unreadable'
            LegacyMarker = $false
            Phase = $candidatePhase
            Pid = $null
            Issue = $null
            OwnerProcessStartUtcTicks = $null
            Sha256 = $null
            Nonce = $null
            ValidationError = 'transition name does not match the exact lowercase schema-v2 grammar'
        }
    }

    $pidValue = 0
    $issueValue = 0
    $ticksValue = 0L
    if (-not [int]::TryParse(
            $strict.Groups['pid'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$pidValue
        ) -or $pidValue -le 0 -or
        -not [int]::TryParse(
            $strict.Groups['issue'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$issueValue
        ) -or $issueValue -le 0 -or
        -not [long]::TryParse(
            $strict.Groups['ticks'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$ticksValue
        ) -or $ticksValue -le 0 -or $ticksValue -gt [DateTime]::MaxValue.Ticks) {
        return [pscustomobject]@{
            Path = $full
            Candidate = $true
            Valid = $false
            Format = 'v2-invalid'
            LegacyMarker = $false
            Phase = $strict.Groups['phase'].Value
            Pid = $null
            Issue = $null
            OwnerProcessStartUtcTicks = $null
            Sha256 = $strict.Groups['sha'].Value
            Nonce = $strict.Groups['nonce'].Value
            ValidationError = 'transition owner fields are outside their positive integer ranges'
        }
    }
    return [pscustomobject]@{
        Path = $full
        Candidate = $true
        Valid = $true
        Format = 'v2'
        LegacyMarker = $false
        Phase = $strict.Groups['phase'].Value
        Pid = $pidValue
        Issue = $issueValue
        OwnerProcessStartUtcTicks = $ticksValue
        Sha256 = $strict.Groups['sha'].Value
        Nonce = $strict.Groups['nonce'].Value
        ValidationError = $null
    }
}

function Get-AstroLauncherRootFromLockPath {
    param([Parameter(Mandatory)][string]$LockPath)

    $lockFull = [IO.Path]::GetFullPath($LockPath)
    if ([IO.Path]::GetFileName($lockFull) -cne 'astrolabe-launcher.lock') {
        throw "launcher-lock path must end with exact leaf 'astrolabe-launcher.lock': $lockFull"
    }
    $temporaryDirectory = [IO.Path]::GetDirectoryName($lockFull)
    if ([IO.Path]::GetFileName($temporaryDirectory) -cne '.tmp') {
        throw "launcher-lock path must be directly below an exact '.tmp' directory: $lockFull"
    }
    return [IO.Path]::GetDirectoryName($temporaryDirectory)
}

function ConvertFrom-AstroNativeFinalPath {
    param([Parameter(Mandatory)][string]$Path)

    if ($Path.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        return '\\' + $Path.Substring(8)
    }
    if ($Path.StartsWith('\\?\', [StringComparison]::Ordinal)) {
        return $Path.Substring(4)
    }
    return $Path
}

function Get-AstroLauncherLockMutexNameFromIdentity {
    param([Parameter(Mandatory)][string]$Identity)

    if ($Identity -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$') {
        throw "launcher-lock mutex filesystem identity is not canonical FILE_ID_INFO: $Identity"
    }
    $identityBytes = [Text.Encoding]::UTF8.GetBytes(
        "astrolabe.launcher-lock.v2|$Identity"
    )
    $digest = Get-AstroByteSha256 $identityBytes
    return "Global\Astrolabe.LauncherLock.$digest"
}

function Get-AstroLauncherTreeJobObjectName {
    param(
        [Parameter(Mandatory)][string]$RootIdentity,
        [Parameter(Mandatory)]
        [Alias('OwnerPid')]
        [int]$LauncherPid,
        [Parameter(Mandatory)]
        [Alias('OwnerProcessStartUtcTicks')]
        [long]$LauncherProcessStartUtcTicks,
        [Parameter(Mandatory)]
        [Alias('LeaseStartUtcTicks')]
        [long]$LauncherLeaseStartUtcTicks,
        [Parameter(Mandatory)]
        [Alias('LockSha256')]
        [string]$LauncherLockSha256
    )

    if ($RootIdentity -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$') {
        throw "launcher-tree Job Object root identity is not canonical: $RootIdentity"
    }
    if ($LauncherPid -le 0) {
        throw "launcher-tree Job Object PID must be positive: $LauncherPid"
    }
    if ($LauncherProcessStartUtcTicks -le 0 -or
        $LauncherProcessStartUtcTicks -gt [DateTime]::MaxValue.Ticks) {
        throw "launcher-tree Job Object process-start ticks are outside the DateTime range: $LauncherProcessStartUtcTicks"
    }
    if ($LauncherLeaseStartUtcTicks -lt $LauncherProcessStartUtcTicks -or
        $LauncherLeaseStartUtcTicks -gt [DateTime]::MaxValue.Ticks) {
        throw "launcher-tree Job Object lease-start ticks must be within the DateTime range and cannot precede process creation: $LauncherLeaseStartUtcTicks"
    }
    if ($LauncherLockSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "launcher-tree Job Object lock SHA-256 is not canonical lowercase hex: $LauncherLockSha256"
    }

    $identityMaterial = @(
        'astrolabe.launcher-tree-job.v1',
        "root_identity=$RootIdentity",
        "launcher_pid=$LauncherPid",
        "launcher_process_start_utc_ticks=$LauncherProcessStartUtcTicks",
        "launcher_lease_start_utc_ticks=$LauncherLeaseStartUtcTicks",
        "launcher_lock_sha256=$LauncherLockSha256"
    ) -join "`n"
    $digest = Get-AstroByteSha256 (
        [Text.UTF8Encoding]::new($false, $true).GetBytes($identityMaterial)
    )
    return "Global\Astrolabe.LauncherTree.$digest"
}

function Get-AstroLauncherJobObjectProbe {
    param([Parameter(Mandatory)][string]$Name)

    if ($Name -cnotmatch '^Global\\Astrolabe\.LauncherTree\.[0-9a-f]{64}$') {
        return [pscustomobject]@{
            Name = $Name
            State = 'unevaluable'
            ProcessIds = [int[]]@()
            NativeErrorCode = 0
            NumberOfAssignedProcesses = $null
            NumberOfProcessIdsInList = $null
            Error = 'launcher-tree Job Object name is not an exact canonical Global protocol name'
        }
    }

    try {
        $native = [AstroLauncherLockNative]::QueryNamedJobObjectProcessIds($Name)
    }
    catch {
        return [pscustomobject]@{
            Name = $Name
            State = 'unevaluable'
            ProcessIds = [int[]]@()
            NativeErrorCode = 0
            NumberOfAssignedProcesses = $null
            NumberOfProcessIdsInList = $null
            Error = "$($_.FullyQualifiedErrorId): $($_.Exception.Message)"
        }
    }

    $state = [string]$native.State
    if ($state -cnotin @('observed', 'absent', 'unevaluable')) {
        return [pscustomobject]@{
            Name = $Name
            State = 'unevaluable'
            ProcessIds = [int[]]@()
            NativeErrorCode = 0
            NumberOfAssignedProcesses = $null
            NumberOfProcessIdsInList = $null
            Error = "native Job Object query returned unknown state '$state'"
        }
    }
    [int[]]$processIds = @($native.ProcessIds)
    return [pscustomobject]@{
        Name = $Name
        State = $state
        ProcessIds = $processIds
        NativeErrorCode = [int]$native.NativeErrorCode
        NumberOfAssignedProcesses = [uint32]$native.NumberOfAssignedProcesses
        NumberOfProcessIdsInList = [uint32]$native.NumberOfProcessIdsInList
        Error = if ([string]::IsNullOrEmpty([string]$native.Error)) {
            $null
        } else {
            [string]$native.Error
        }
    }
}

function Get-AstroLauncherLockMutexName {
    param([Parameter(Mandatory)][string]$LockPath)

    $root = Get-AstroLauncherRootFromLockPath $LockPath
    $rootHandle = [AstroLauncherLockNative]::OpenExactRenameDirectory($root)
    try {
        $identity = [AstroLauncherLockNative]::GetDirectoryLockIdentity(
            $rootHandle
        )
        return Get-AstroLauncherLockMutexNameFromIdentity $identity
    }
    finally {
        $rootHandle.Dispose()
    }
}

function Assert-AstroLauncherRootCanonical {
    param([Parameter(Mandatory)][string]$Root)

    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $finalPath = [AstroLauncherLockNative]::GetDirectoryFinalPath($rootFull)
    if ($finalPath.StartsWith('\\?\', [StringComparison]::Ordinal)) {
        $finalPath = $finalPath.Substring(4)
    }
    $finalPath = $finalPath.TrimEnd('\', '/')
    if (-not [string]::Equals(
            $rootFull,
            $finalPath,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "launcher root lexical path '$rootFull' resolves to different final path '$finalPath'; reparse/alias roots are unsupported"
    }
    $cursor = $rootFull
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $state = Get-AstroPathEntryState $cursor
        if ($state.State -ne 'present') {
            throw "launcher root ancestor is not exactly evaluable: $cursor ($($state.Error))"
        }
        if (($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "launcher root traverses reparse point '$cursor'; use the canonical non-reparse path"
        }
        $parent = [IO.Path]::GetDirectoryName($cursor.TrimEnd('\', '/'))
        if ([string]::IsNullOrWhiteSpace($parent) -or
            [string]::Equals(
                $parent.TrimEnd('\', '/'),
                $cursor.TrimEnd('\', '/'),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            break
        }
        $cursor = $parent
    }
}

function New-AstroLauncherLockMutexSecurity {
    $security = [Security.AccessControl.MutexSecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $full = [Security.AccessControl.MutexRights]::FullControl
    $coordinate = [Security.AccessControl.MutexRights]::Synchronize -bor
        [Security.AccessControl.MutexRights]::Modify

    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $authenticatedUsersSid =
        [Security.Principal.SecurityIdentifier]::new('S-1-5-11')
    foreach ($entry in @(
            @($currentSid, $full),
            @($systemSid, $full),
            @($authenticatedUsersSid, $coordinate)
        )) {
        $rule = [Security.AccessControl.MutexAccessRule]::new(
            [Security.Principal.IdentityReference]$entry[0],
            [Security.AccessControl.MutexRights]$entry[1],
            $allow
        )
        [void]$security.AddAccessRule($rule)
    }
    return $security
}

function Enter-AstroLauncherLockMutex {
    param([Parameter(Mandatory)][string]$LockPath)

    $root = Get-AstroLauncherRootFromLockPath $LockPath
    $rootHandle = $null
    try {
        $rootHandle = [AstroLauncherLockNative]::OpenExactRenameDirectory($root)
        $rootIdentity = [AstroLauncherLockNative]::GetDirectoryLockIdentity(
            $rootHandle
        )
        $rootFinalPath = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($rootHandle)
        )
        $rootFinalPath = [IO.Path]::GetFullPath($rootFinalPath).TrimEnd('\', '/')
        $rootFull = [IO.Path]::GetFullPath($root).TrimEnd('\', '/')
        if (-not [string]::Equals(
                $rootFull,
                $rootFinalPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "launcher root lexical path '$rootFull' resolves to retained-handle path '$rootFinalPath'"
        }
        $name = Get-AstroLauncherLockMutexNameFromIdentity $rootIdentity
    }
    catch {
        if ($null -ne $rootHandle) {
            $rootHandle.Dispose()
        }
        throw "could not retain exact launcher root while deriving its machine-wide mutex: $($_.Exception.Message)"
    }
    try {
        $security = New-AstroLauncherLockMutexSecurity
    }
    catch {
        $rootHandle.Dispose()
        throw "could not construct launcher-lock mutex security while the exact root was retained: $($_.Exception.Message)"
    }
    $createdNew = $false
    try {
        if ('System.Threading.MutexAcl' -as [type]) {
            $mutex = [System.Threading.MutexAcl]::Create(
                $false,
                $name,
                [ref]$createdNew,
                $security
            )
        }
        else {
            $mutex = [Threading.Mutex]::new(
                $false,
                $name,
                [ref]$createdNew,
                $security
            )
        }
    }
    catch {
        $rootHandle.Dispose()
        throw "could not create/open machine-wide launcher-lock mutex '$name': $($_.Exception.Message)"
    }

    $acquired = $false
    $abandoned = $false
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [Threading.AbandonedMutexException] {
            $acquired = $true
            $abandoned = $true
        }
        return [pscustomobject]@{
            Name = $name
            Mutex = $mutex
            Acquired = $acquired
            WasAbandoned = $abandoned
            CreatedNew = $createdNew
            Root = $rootFull
            RootFinalPath = $rootFinalPath
            RootIdentity = $rootIdentity
            RootHandle = $rootHandle
        }
    }
    catch {
        if ($acquired) {
            try {
                $mutex.ReleaseMutex()
            }
            catch {
                # Preserve the original construction fault; disposal still releases the
                # kernel handle if thread ownership could not be unwound normally.
            }
        }
        $mutex.Dispose()
        $rootHandle.Dispose()
        throw
    }
}

function Exit-AstroLauncherLockMutex {
    param([Parameter(Mandatory)]$Lease)

    try {
        if ($Lease.Acquired) {
            $Lease.Mutex.ReleaseMutex()
        }
    }
    finally {
        try {
            $Lease.Mutex.Dispose()
        }
        finally {
            if ($Lease.PSObject.Properties['RootHandle'] -and
                $null -ne $Lease.RootHandle) {
                $Lease.RootHandle.Dispose()
            }
        }
    }
}

function Get-AstroFsvLifecycleMutexNameFromIdentity {
    param([Parameter(Mandatory)][string]$WorkspaceRootIdentity)

    if ($WorkspaceRootIdentity -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$') {
        throw "native-FSV lifecycle mutex filesystem identity is not canonical FILE_ID_INFO: $WorkspaceRootIdentity"
    }
    $identityBytes = [Text.Encoding]::UTF8.GetBytes(
        "astrolabe.native-fsv-lifecycle.v1|$WorkspaceRootIdentity"
    )
    $digest = Get-AstroByteSha256 $identityBytes
    return "Global\Astrolabe.NativeFsvLifecycle.$digest"
}

function Enter-AstroFsvLifecycleMutex {
    param([Parameter(Mandatory)][string]$WorkspaceRoot)

    $root = [IO.Path]::GetFullPath($WorkspaceRoot).TrimEnd('\', '/')
    $rootHandle = $null
    try {
        $rootHandle = [AstroLauncherLockNative]::OpenExactRenameDirectory($root)
        $rootIdentity = [AstroLauncherLockNative]::GetDirectoryLockIdentity(
            $rootHandle
        )
        $rootFinalPath = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($rootHandle)
        )
        $rootFinalPath = [IO.Path]::GetFullPath(
            $rootFinalPath
        ).TrimEnd('\', '/')
        if (-not [string]::Equals(
                $root,
                $rootFinalPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "native-FSV workspace lexical path '$root' resolves to retained-handle path '$rootFinalPath'"
        }
        $name = Get-AstroFsvLifecycleMutexNameFromIdentity $rootIdentity
        $security = New-AstroLauncherLockMutexSecurity
    }
    catch {
        if ($null -ne $rootHandle) {
            $rootHandle.Dispose()
        }
        throw "could not retain the native-FSV workspace while deriving its shared lifecycle mutex: $($_.Exception.Message)"
    }

    $createdNew = $false
    try {
        if ('System.Threading.MutexAcl' -as [type]) {
            $mutex = [System.Threading.MutexAcl]::Create(
                $false,
                $name,
                [ref]$createdNew,
                $security
            )
        }
        else {
            $mutex = [Threading.Mutex]::new(
                $false,
                $name,
                [ref]$createdNew,
                $security
            )
        }
    }
    catch {
        $rootHandle.Dispose()
        throw "could not create/open shared native-FSV lifecycle mutex '$name': $($_.Exception.Message)"
    }

    $acquired = $false
    $abandoned = $false
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [Threading.AbandonedMutexException] {
            $acquired = $true
            $abandoned = $true
        }
        return [pscustomobject]@{
            Name = $name
            Mutex = $mutex
            Acquired = $acquired
            WasAbandoned = $abandoned
            CreatedNew = $createdNew
            Root = $root
            RootFinalPath = $rootFinalPath
            RootIdentity = $rootIdentity
            RootHandle = $rootHandle
        }
    }
    catch {
        if ($acquired) {
            try { $mutex.ReleaseMutex() } catch {}
        }
        $mutex.Dispose()
        $rootHandle.Dispose()
        throw
    }
}

function Exit-AstroFsvLifecycleMutex {
    param([Parameter(Mandatory)]$Lease)

    Exit-AstroLauncherLockMutex $Lease
}

function Get-AstroFsvLifecycleInterruptionState {
    param([Parameter(Mandatory)][string]$WorkspaceRoot)

    $root = [IO.Path]::GetFullPath($WorkspaceRoot).TrimEnd('\', '/')
    $tmpRoot = Join-Path $root '.tmp'
    $transition = Join-Path $tmpRoot 'astrolabe-fsv-lifecycle.transition.v1.json'
    $transitionState = Get-AstroPathEntryState $transition
    if ($transitionState.State -cne 'absent') {
        return [pscustomobject]@{
            State = if ($transitionState.State -ceq 'present') {
                'interrupted'
            } else { 'unevaluable' }
            Paths = [string[]]@($transition)
            Error = $transitionState.Error
        }
    }
    $recoveryRoot = Join-Path $tmpRoot 'native-fsv-recovery-records'
    $recoveryState = Get-AstroPathEntryState $recoveryRoot
    if ($recoveryState.State -ceq 'absent') {
        return [pscustomobject]@{
            State = 'absent'; Paths = [string[]]@(); Error = $null
        }
    }
    if ($recoveryState.State -cne 'present' -or
        ($recoveryState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
        ($recoveryState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        return [pscustomobject]@{
            State = 'unevaluable'
            Paths = [string[]]@($recoveryRoot)
            Error = if ($recoveryState.State -cne 'present') {
                $recoveryState.Error
            } else { 'native-FSV recovery root is not one ordinary directory' }
        }
    }
    try {
        $inventory = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $recoveryRoot
    }
    catch {
        return [pscustomobject]@{
            State = 'unevaluable'
            Paths = [string[]]@($recoveryRoot)
            Error = "$($_.Exception.GetType().FullName): $($_.Exception.Message)"
        }
    }
    $stages = [Collections.Generic.List[string]]::new()
    foreach ($entry in @($inventory.entries | Where-Object {
                [string]$_.kind -ceq 'file' -and
                ([string]$_.relative_path -cmatch
                    '(^|\\)\.[^\\]+\.publishing\.v1\.json\z' -or
                 [string]$_.relative_path -cmatch
                    '(^|\\)\.[^\\]+\.publishing-[0-9]+-[0-9a-f]{32}\z')
            })) {
        $stages.Add([IO.Path]::GetFullPath(
                (Join-Path $recoveryRoot ([string]$entry.relative_path))
            ))
    }
    if ($stages.Count -gt 0) {
        return [pscustomobject]@{
            State = 'interrupted'
            Paths = [string[]]$stages.ToArray()
            Error = 'one or more durable native-FSV publication stages remain'
        }
    }
    return [pscustomobject]@{
        State = 'absent'; Paths = [string[]]@(); Error = $null
    }
}

function Throw-AstroFileMoveFailure {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Remediation,
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestinationPath,
        [Nullable[int]]$NativeErrorCode
    )

    $exception = [InvalidOperationException]::new(
        "$Code`: $Message`nRemediation: $Remediation"
    )
    $exception.Data['AstroCode'] = $Code
    $exception.Data['AstroRemediation'] = $Remediation
    $exception.Data['SourcePath'] = $SourcePath
    $exception.Data['DestinationPath'] = $DestinationPath
    $exception.Data['MoveFlags'] = '0x00000008'
    if ($null -ne $NativeErrorCode) {
        $exception.Data['NativeErrorCode'] = [int]$NativeErrorCode
    }
    throw $exception
}

function Move-AstroFileWriteThroughNoReplace {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )

    try {
        $sourceFull = [IO.Path]::GetFullPath($Source)
        $destinationFull = [IO.Path]::GetFullPath($Destination)
    }
    catch {
        Throw-AstroFileMoveFailure `
            -Code 'ASTRO_FILE_MOVE_PATH_INVALID' `
            -Message "source or destination path is invalid: $($_.Exception.Message)" `
            -Remediation (
                'supply two canonical Windows file paths; do not normalize, ' +
                'truncate, or redirect an invalid path'
            ) `
            -SourcePath $Source `
            -DestinationPath $Destination
    }

    $destinationState = Get-AstroPathEntryState $destinationFull
    if ($destinationState.State -cne 'absent' -and
        $destinationState.State -cne 'present') {
        Throw-AstroFileMoveFailure `
            -Code 'ASTRO_FILE_MOVE_DESTINATION_UNEVALUABLE' `
            -Message (
                'destination presence is unevaluable ' +
                "(state=$($destinationState.State), " +
                "error=$($destinationState.Error)): $destinationFull"
            ) `
            -Remediation (
                'preserve both namespaces, repair the destination probe failure, ' +
                'and retry only after its exact presence is evaluable'
            ) `
            -SourcePath $sourceFull `
            -DestinationPath $destinationFull
    }

    # The native operation is the atomic no-replace authority. A destination that
    # was present during the probe still reaches Win32 so its exact error survives.
    try {
        [AstroLauncherLockNative]::MoveFileWriteThroughNoReplace(
            $sourceFull,
            $destinationFull
        )
    }
    catch {
        $failure = $_.Exception
        $cursor = $failure
        $nativeFailure = $null
        $typeChain = [Collections.Generic.List[string]]::new()
        while ($null -ne $cursor) {
            $typeChain.Add($cursor.GetType().FullName)
            if ($cursor -is [ComponentModel.Win32Exception]) {
                $nativeFailure = $cursor
                break
            }
            $cursor = $cursor.InnerException
        }

        if ($null -ne $nativeFailure) {
            $nativeError = [int]$nativeFailure.NativeErrorCode
            $remediation = switch ($nativeError) {
                { $_ -eq 2 -or $_ -eq 3 } {
                    'preserve the destination, restore or correct the exact source ' +
                    'namespace, then retry only the same no-replace move'
                    break
                }
                { $_ -eq 80 -or $_ -eq 183 } {
                    'preserve both objects and choose a verified absent destination ' +
                    'or reconcile the existing object; never delete or replace it'
                    break
                }
                17 {
                    'choose a destination on the source volume; cross-volume ' +
                    'copy/delete fallback is intentionally forbidden'
                    break
                }
                5 {
                    'inspect access control and open-handle sharing on both exact ' +
                    'paths, repair authorization, and retry without bypassing it'
                    break
                }
                default {
                    'inspect the exact Win32 error, namespaces, volume, access ' +
                    'control, and sharing state; repair the cause and retry only ' +
                    'this no-replace write-through operation'
                }
            }
            Throw-AstroFileMoveFailure `
                -Code 'ASTRO_FILE_MOVE_NATIVE_FAILED' `
                -Message $nativeFailure.Message `
                -Remediation $remediation `
                -SourcePath $sourceFull `
                -DestinationPath $destinationFull `
                -NativeErrorCode $nativeError
        }

        Throw-AstroFileMoveFailure `
            -Code 'ASTRO_FILE_MOVE_INTEROP_FAILED' `
            -Message (
                "managed/native invocation failed (types=$($typeChain -join ' -> '), " +
                "message=$($failure.Message))"
            ) `
            -Remediation (
                'verify the pinned Windows runtime and the exact MoveFileExW ' +
                'binding, repair the interop defect, and retry without fallback'
            ) `
            -SourcePath $sourceFull `
            -DestinationPath $destinationFull
    }
}

function ConvertTo-AstroProcessStartUtcIso {
    param([Parameter(Mandatory)][long]$UtcTicks)

    if ($UtcTicks -le 0 -or $UtcTicks -gt [DateTime]::MaxValue.Ticks) {
        throw "process-start UTC ticks are outside the DateTime range: $UtcTicks"
    }
    return [DateTime]::new($UtcTicks, [DateTimeKind]::Utc).ToString('o')
}

function Get-AstroProcessIdentityProbe {
    param([Parameter(Mandatory)][int]$OwnerPid)

    try {
        $process = Get-Process -Id $OwnerPid -ErrorAction Stop
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoProcessFoundForGivenId,*') {
            return [pscustomobject]@{
                State = 'absent'
                Pid = $OwnerPid
                ProcessStartUtcTicks = $null
                ProcessStartedUtc = $null
                Error = $null
            }
        }
        return [pscustomobject]@{
            State = 'unevaluable'
            Pid = $OwnerPid
            ProcessStartUtcTicks = $null
            ProcessStartedUtc = $null
            Error = "$($_.FullyQualifiedErrorId): $($_.Exception.Message)"
        }
    }
    try {
        $ticks = [long]$process.StartTime.ToUniversalTime().Ticks
    }
    catch {
        return [pscustomobject]@{
            State = 'unevaluable'
            Pid = $OwnerPid
            ProcessStartUtcTicks = $null
            ProcessStartedUtc = $null
            Error = "$($_.FullyQualifiedErrorId): $($_.Exception.Message)"
        }
    }
    return [pscustomobject]@{
        State = 'observed'
        Pid = $OwnerPid
        ProcessStartUtcTicks = $ticks
        ProcessStartedUtc = ConvertTo-AstroProcessStartUtcIso $ticks
        Error = $null
    }
}

function New-AstroProcessIdentityRecord {
    param(
        [Parameter(Mandatory)]
        [Alias('Pid')]
        [int]$ProcessId,
        [Parameter(Mandatory)][long]$ProcessStartUtcTicks
    )

    if ($ProcessId -le 0 -or
        $ProcessStartUtcTicks -le 0 -or
        $ProcessStartUtcTicks -gt [DateTime]::MaxValue.Ticks) {
        throw "process identity must contain a positive PID and valid UTC ticks: pid=$ProcessId, process_start_utc_ticks=$ProcessStartUtcTicks"
    }
    return [ordered]@{
        pid = $ProcessId
        process_start_utc_ticks = $ProcessStartUtcTicks
        process_started_utc =
            ConvertTo-AstroProcessStartUtcIso $ProcessStartUtcTicks
    }
}

function Get-AstroExactProcessIdentityProbe {
    param(
        [Parameter(Mandatory)]
        [Alias('Pid')]
        [int]$ProcessId,
        [Parameter(Mandatory)][long]$ProcessStartUtcTicks
    )

    if ($ProcessId -le 0 -or
        $ProcessStartUtcTicks -le 0 -or
        $ProcessStartUtcTicks -gt [DateTime]::MaxValue.Ticks) {
        throw "exact process identity must contain a positive PID and valid UTC ticks: pid=$ProcessId, process_start_utc_ticks=$ProcessStartUtcTicks"
    }
    $expectedStartedUtc =
        ConvertTo-AstroProcessStartUtcIso $ProcessStartUtcTicks
    $native = Get-AstroProcessIdentityProbe -OwnerPid $ProcessId
    $state = if ($native.State -ceq 'absent') {
        'absent'
    }
    elseif ($native.State -ceq 'unevaluable') {
        'unevaluable'
    }
    elseif ([long]$native.ProcessStartUtcTicks -eq $ProcessStartUtcTicks) {
        'exact-live'
    }
    else {
        'pid-reused'
    }
    return [pscustomobject]@{
        State = $state
        Pid = $ProcessId
        ExpectedProcessStartUtcTicks = $ProcessStartUtcTicks
        ExpectedProcessStartedUtc = $expectedStartedUtc
        ObservedProcessStartUtcTicks = if ($native.State -ceq 'observed') {
            [long]$native.ProcessStartUtcTicks
        }
        else {
            $null
        }
        ObservedProcessStartedUtc = $native.ProcessStartedUtc
        NumericPidLive = $native.State -ceq 'observed'
        ExactOwnerLive = $state -ceq 'exact-live'
        PidReused = $state -ceq 'pid-reused'
        Error = $native.Error
        ObservedAtUtc = [DateTime]::UtcNow.ToString('o')
    }
}

function Get-AstroPathEntryState {
    param([Parameter(Mandatory)][string]$LiteralPath)

    try {
        $attributes = [IO.File]::GetAttributes(
            (ConvertTo-AstroExtendedLengthPath $LiteralPath)
        )
        return [pscustomobject]@{
            State = 'present'
            Attributes = $attributes
            Error = $null
        }
    }
    catch [IO.FileNotFoundException] {
        return [pscustomobject]@{ State = 'absent'; Attributes = $null; Error = $null }
    }
    catch [IO.DirectoryNotFoundException] {
        return [pscustomobject]@{ State = 'absent'; Attributes = $null; Error = $null }
    }
    catch {
        return [pscustomobject]@{
            State = 'unevaluable'
            Attributes = $null
            Error = "$($_.Exception.GetType().FullName): $($_.Exception.Message)"
        }
    }
}

function Get-AstroFileSnapshot {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [IO.FileShare]$Share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete,
        [int]$MaximumBytes = $script:AstroLauncherProtocolSnapshotMaxBytes
    )

    if ($MaximumBytes -le 0) {
        throw "exact file snapshot maximum must be positive: $MaximumBytes"
    }

    $full = [IO.Path]::GetFullPath($LiteralPath)
    try {
        $stream = [IO.File]::Open(
            (ConvertTo-AstroExtendedLengthPath $full),
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            $Share
        )
    }
    catch {
        throw "could not open '$full' for an exact read snapshot: $($_.Exception.Message)"
    }
    try {
        if ($stream.Length -gt $MaximumBytes) {
            throw "exact file snapshot exceeds the $MaximumBytes-byte caller contract: $full ($($stream.Length) bytes)"
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw "snapshot ended at byte $offset of $($bytes.Length): $full"
            }
            $offset += $read
        }
        return [pscustomobject]@{
            Path = $full
            Bytes = $bytes
            Length = [uint64]$bytes.Length
            Sha256 = Get-AstroByteSha256 $bytes
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Convert-AstroLauncherLockBytesToState {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$LockPath
    )

    if ($Bytes.Length -gt $script:AstroLauncherLockMaxBytes) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = "launcher-lock manifest exceeds the $script:AstroLauncherLockMaxBytes-byte schema limit"
            RawJson = $null
        }
    }
    $raw = $null
    try {
        $raw = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        if ($raw.Length -gt 0 -and $raw[0] -eq [char]0xfeff) {
            throw 'UTF-8 BOM is not permitted'
        }
    }
    catch {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = "invalid UTF-8 launcher lock: $($_.Exception.Message)"
            RawJson = $null
        }
    }

    try {
        $document = ConvertFrom-AstroStrictFlatJsonObject $raw
    }
    catch {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = "invalid structurally strict launcher-lock JSON: $($_.Exception.Message)"
            RawJson = $raw
        }
    }

    $properties = $document.Properties
    $schemaValue = if (
        $properties.ContainsKey('schema') -and
        $properties['schema'].Kind -ceq 'string'
    ) {
        [string]$properties['schema'].Value
    }
    else {
        $null
    }
    $isV2 = $schemaValue -ceq 'astrolabe.launcher-lock.v2'
    $isV3 = $schemaValue -ceq 'astrolabe.launcher-lock.v3'
    if (-not ($isV2 -or $isV3)) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError =
                'schema must be the JSON string astrolabe.launcher-lock.v2 or astrolabe.launcher-lock.v3'
            RawJson = $raw
        }
    }
    $commonRequiredNames = @(
        'schema',
        'pid',
        'issue',
        'started',
        'lease_start_utc_ticks',
        'owner_process_start_utc_ticks',
        'owner_process_started_utc',
        'command',
        'head_sha',
        'status_sha256',
        'diff_sha256'
    )
    $authorityRequiredNames = @(
        'protocol_authority_version',
        'protocol_authority_root',
        'protocol_entrypoint_path',
        'protocol_entrypoint_sha256',
        'protocol_authority_path',
        'protocol_authority_sha256',
        'protocol_lock_helper_path',
        'protocol_lock_helper_sha256',
        'workspace_root',
        'workspace_entrypoint_path',
        'workspace_entrypoint_sha256'
    )
    $requiredNames = if ($isV3) {
        @($commonRequiredNames + $authorityRequiredNames)
    }
    else {
        @($commonRequiredNames)
    }
    $actualNames = @($document.Names)
    $nameValid = $actualNames.Count -eq $requiredNames.Count
    foreach ($name in $requiredNames) {
        if (-not ($actualNames -ccontains $name)) {
            $nameValid = $false
        }
    }
    foreach ($name in $actualNames) {
        if (-not ($requiredNames -ccontains $name)) {
            $nameValid = $false
        }
    }
    if (-not $nameValid) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = "launcher-lock JSON must contain exactly the $(if ($isV3) { 'v3' } else { 'v2' }) property set, once each"
            RawJson = $raw
        }
    }

    $authorityVersion = if ($isV3) { 0L } else { 2L }
    $workspaceRoot = $null
    if ($isV3) {
    if ($properties['protocol_authority_version'].Kind -cne 'integer' -or
        -not [long]::TryParse(
            [string]$properties['protocol_authority_version'].Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$authorityVersion
        ) -or $authorityVersion -ne 3) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'protocol_authority_version must be the integral JSON number 3'
            RawJson = $raw
        }
    }
    $canonicalRoot = 'C:\code\Astrolabe'
    $canonicalEntrypoint = Join-Path `
        (Join-Path $canonicalRoot 'scripts') `
        'windows-gnu-toolchain.ps1'
    $canonicalAuthority = Join-Path `
        (Join-Path $canonicalRoot 'scripts') `
        'windows-gnu-toolchain-authority.ps1'
    $canonicalLockHelper = Join-Path `
        (Join-Path $canonicalRoot 'scripts') `
        'launcher-lock.ps1'
    foreach ($field in @(
            'protocol_authority_root',
            'protocol_entrypoint_path',
            'protocol_entrypoint_sha256',
            'protocol_authority_path',
            'protocol_authority_sha256',
            'protocol_lock_helper_path',
            'protocol_lock_helper_sha256',
            'workspace_root',
            'workspace_entrypoint_path',
            'workspace_entrypoint_sha256'
        )) {
        if ($properties[$field].Kind -cne 'string' -or
            [string]::IsNullOrWhiteSpace(
                [string]$properties[$field].Value
            )) {
            return [pscustomobject]@{
                State = 'unreadable'
                ValidationError = "$field must be a nonblank JSON string"
                RawJson = $raw
            }
        }
    }
    if ([string]$properties['protocol_authority_root'].Value -cne
            $canonicalRoot -or
        [string]$properties['protocol_entrypoint_path'].Value -cne
            $canonicalEntrypoint -or
        [string]$properties['protocol_authority_path'].Value -cne
            $canonicalAuthority -or
        [string]$properties['protocol_lock_helper_path'].Value -cne
            $canonicalLockHelper) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'protocol authority root/paths do not name the exact canonical authority'
            RawJson = $raw
        }
    }
    foreach ($field in @(
            'protocol_entrypoint_sha256',
            'protocol_authority_sha256',
            'protocol_lock_helper_sha256',
            'workspace_entrypoint_sha256'
        )) {
        if ([string]$properties[$field].Value -cnotmatch
            '^[0-9a-f]{64}$') {
            return [pscustomobject]@{
                State = 'unreadable'
                ValidationError = "$field must be exactly 64 lowercase hexadecimal characters"
                RawJson = $raw
            }
        }
    }
    if ([string]$properties['workspace_entrypoint_sha256'].Value -cne
        [string]$properties['protocol_entrypoint_sha256'].Value) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'workspace and canonical trampoline SHA-256 values must match exactly'
            RawJson = $raw
        }
    }
    $workspaceRoot = [string]$properties['workspace_root'].Value
    $worktreeParent = Join-Path `
        (Join-Path $canonicalRoot '.claude') `
        'worktrees'
    $workspaceRootSupported = $workspaceRoot -ceq $canonicalRoot -or
        (
            $workspaceRoot.StartsWith(
                $worktreeParent +
                    [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase
            ) -and
            [IO.Path]::GetDirectoryName($workspaceRoot) -ieq
                $worktreeParent
        )
    $expectedWorkspaceEntrypoint = Join-Path `
        (Join-Path $workspaceRoot 'scripts') `
        'windows-gnu-toolchain.ps1'
    if (-not $workspaceRootSupported -or
        [string]$properties['workspace_entrypoint_path'].Value -cne
            $expectedWorkspaceEntrypoint) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'workspace authority binding must name the canonical root or one direct supported registered-worktree root and its exact trampoline path'
            RawJson = $raw
        }
    }
    }
    $pidValue = 0L
    if ($properties['pid'].Kind -cne 'integer' -or
        -not [long]::TryParse(
            [string]$properties['pid'].Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$pidValue
        ) -or $pidValue -le 0 -or $pidValue -gt [int]::MaxValue) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'pid must be a positive integral JSON number in the Int32 range'
            RawJson = $raw
        }
    }
    $issueValue = 0L
    if ($properties['issue'].Kind -cne 'integer' -or
        -not [long]::TryParse(
            [string]$properties['issue'].Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$issueValue
        ) -or $issueValue -le 0 -or $issueValue -gt [int]::MaxValue) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'issue must be a positive integral JSON number in the Int32 range'
            RawJson = $raw
        }
    }
    $leaseTicks = 0L
    $ownerTicks = 0L
    if ($properties['lease_start_utc_ticks'].Kind -cne 'integer' -or
        $properties['owner_process_start_utc_ticks'].Kind -cne 'integer' -or
        -not [long]::TryParse(
            [string]$properties['lease_start_utc_ticks'].Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$leaseTicks
        ) -or
        -not [long]::TryParse(
            [string]$properties['owner_process_start_utc_ticks'].Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$ownerTicks
        )) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'lease/process UTC ticks must be integral JSON numbers'
            RawJson = $raw
        }
    }

    if ($leaseTicks -le 0 -or $leaseTicks -gt [DateTime]::MaxValue.Ticks -or
        $ownerTicks -le 0 -or $ownerTicks -gt [DateTime]::MaxValue.Ticks) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'lease/process UTC ticks are outside the DateTime range'
            RawJson = $raw
        }
    }
    if ($leaseTicks -lt $ownerTicks) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'lease UTC ticks cannot precede the owner process creation ticks'
            RawJson = $raw
        }
    }
    $leaseIso = ConvertTo-AstroProcessStartUtcIso $leaseTicks
    $ownerIso = ConvertTo-AstroProcessStartUtcIso $ownerTicks
    if ($properties['started'].Kind -cne 'string' -or
        [string]$properties['started'].Value -cne $leaseIso -or
        $properties['owner_process_started_utc'].Kind -cne 'string' -or
        [string]$properties['owner_process_started_utc'].Value -cne $ownerIso) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'root ISO diagnostics must be exact JSON strings derived from their UTC ticks'
            RawJson = $raw
        }
    }
    if ($properties['command'].Kind -cne 'string' -or
        [string]::IsNullOrWhiteSpace([string]$properties['command'].Value)) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'command must be a nonblank JSON string'
            RawJson = $raw
        }
    }
    foreach ($field in @('head_sha', 'status_sha256', 'diff_sha256')) {
        if ($properties[$field].Kind -cne 'string') {
            return [pscustomobject]@{
                State = 'unreadable'
                ValidationError = "$field must be a JSON string"
                RawJson = $raw
            }
        }
    }
    if ([string]$properties['head_sha'].Value -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$properties['status_sha256'].Value -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$properties['diff_sha256'].Value -cnotmatch '^[0-9a-f]{64}$') {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'evidence fingerprint hashes are incomplete or malformed'
            RawJson = $raw
        }
    }

    $ownerPid = [int]$pidValue
    $probe = Get-AstroProcessIdentityProbe $ownerPid
    $state = if ($isV2) {
        'version-mismatch'
    }
    elseif ($probe.State -eq 'absent') {
        'stale'
    }
    elseif ($probe.State -eq 'unevaluable') {
        'unevaluable'
    }
    elseif ([long]$probe.ProcessStartUtcTicks -eq $ownerTicks) {
        'held'
    }
    else {
        'stale'
    }
    return [pscustomobject]@{
        State = $state
        Schema = [string]$properties['schema'].Value
        ProtocolAuthorityVersion = [int]$authorityVersion
        ProtocolAuthorityRoot = if ($isV3) {
            [string]$properties['protocol_authority_root'].Value
        } else { $null }
        ProtocolEntrypointPath = if ($isV3) {
            [string]$properties['protocol_entrypoint_path'].Value
        } else { $null }
        ProtocolEntrypointSha256 = if ($isV3) {
            [string]$properties['protocol_entrypoint_sha256'].Value
        } else { $null }
        ProtocolAuthorityPath = if ($isV3) {
            [string]$properties['protocol_authority_path'].Value
        } else { $null }
        ProtocolAuthoritySha256 = if ($isV3) {
            [string]$properties['protocol_authority_sha256'].Value
        } else { $null }
        ProtocolLockHelperPath = if ($isV3) {
            [string]$properties['protocol_lock_helper_path'].Value
        } else { $null }
        ProtocolLockHelperSha256 = if ($isV3) {
            [string]$properties['protocol_lock_helper_sha256'].Value
        } else { $null }
        WorkspaceRoot = $workspaceRoot
        WorkspaceEntrypointPath = if ($isV3) {
            [string]$properties['workspace_entrypoint_path'].Value
        } else { $null }
        WorkspaceEntrypointSha256 = if ($isV3) {
            [string]$properties['workspace_entrypoint_sha256'].Value
        } else { $null }
        OwnerPid = $ownerPid
        Issue = [int]$issueValue
        LeaseStartUtcTicks = $leaseTicks
        OwnerProcessStartUtcTicks = $ownerTicks
        ObservedProcessStartUtcTicks = if ($probe.State -eq 'observed') {
            [long]$probe.ProcessStartUtcTicks
        } else {
            $null
        }
        OwnerProcessStarted = $ownerIso
        ObservedProcessStarted = $probe.ProcessStartedUtc
        PidReused = $probe.State -eq 'observed' -and
            [long]$probe.ProcessStartUtcTicks -ne $ownerTicks
        Command = [string]$properties['command'].Value
        Started = $leaseIso
        HeadSha = [string]$properties['head_sha'].Value
        StatusSha256 = [string]$properties['status_sha256'].Value
        DiffSha256 = [string]$properties['diff_sha256'].Value
        ProbeError = $probe.Error
        ValidationError = $null
        RawJson = $raw
    }
}

function New-AstroLauncherLockState {
    param(
        [Parameter(Mandatory)][string]$State,
        [string]$ReadError = $null,
        [string]$ValidationError = $null,
        [string[]]$TransitionPaths = @()
    )

    return [pscustomobject]@{
        State = $State
        Schema = $null
        ProtocolAuthorityVersion = $null
        ProtocolAuthorityRoot = $null
        ProtocolEntrypointPath = $null
        ProtocolEntrypointSha256 = $null
        ProtocolAuthorityPath = $null
        ProtocolAuthoritySha256 = $null
        ProtocolLockHelperPath = $null
        ProtocolLockHelperSha256 = $null
        WorkspaceRoot = $null
        WorkspaceEntrypointPath = $null
        WorkspaceEntrypointSha256 = $null
        OwnerPid = $null
        Issue = $null
        LeaseStartUtcTicks = $null
        OwnerProcessStartUtcTicks = $null
        ObservedProcessStartUtcTicks = $null
        OwnerProcessStarted = $null
        ObservedProcessStarted = $null
        PidReused = $false
        Command = $null
        Started = $null
        HeadSha = $null
        StatusSha256 = $null
        DiffSha256 = $null
        ProbeError = $null
        ReadError = $ReadError
        ValidationError = $ValidationError
        Length = $null
        Sha256 = $null
        TransitionPaths = @($TransitionPaths)
    }
}

function Get-AstroLauncherLockTransitions {
    param([Parameter(Mandatory)][string]$LockPath)

    $lockFull = [IO.Path]::GetFullPath($LockPath)
    $directory = [IO.Path]::GetDirectoryName($lockFull)
    $root = [IO.Path]::GetDirectoryName($directory.TrimEnd('\', '/'))
    try {
        $temporaryDirectoryAliases = @(
            [IO.Directory]::EnumerateFileSystemEntries(
                (ConvertTo-AstroExtendedLengthPath $root),
                '*',
                [IO.SearchOption]::TopDirectoryOnly
            ) | Where-Object {
                [string]::Equals(
                    [IO.Path]::GetFileName($_),
                    '.tmp',
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
        )
    }
    catch {
        return [pscustomobject]@{
            State = 'unevaluable'
            Paths = @()
            Items = @()
            ActivePaths = @()
            Error = "could not enumerate launcher root protocol namespace '$root': $($_.Exception.Message)"
        }
    }
    if ($temporaryDirectoryAliases.Count -gt 1 -or
        ($temporaryDirectoryAliases.Count -eq 1 -and
            [IO.Path]::GetFileName($temporaryDirectoryAliases[0]) -cne '.tmp')) {
        return [pscustomobject]@{
            State = 'invalid'
            Paths = @()
            Items = @()
            ActivePaths = @()
            Error = "launcher root contains noncanonical or colliding case-insensitive '.tmp' protocol entries: $($temporaryDirectoryAliases -join '; ')"
        }
    }
    $directoryState = Get-AstroPathEntryState $directory
    if ($directoryState.State -eq 'absent') {
        if ($temporaryDirectoryAliases.Count -ne 0) {
            return [pscustomobject]@{
                State = 'unevaluable'
                Paths = @()
                Items = @()
                ActivePaths = @()
                Error = "canonical '.tmp' entry was enumerated but its exact path is absent: $directory"
            }
        }
        return [pscustomobject]@{
            State = 'clear'
            Paths = @()
            Items = @()
            ActivePaths = @()
            Error = $null
        }
    }
    if ($directoryState.State -ne 'present') {
        return [pscustomobject]@{
            State = 'unevaluable'
            Paths = @()
            Items = @()
            ActivePaths = @()
            Error = "could not query launcher protocol directory '$directory': $($directoryState.Error)"
        }
    }
    if (($directoryState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
        ($directoryState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        return [pscustomobject]@{
            State = 'unevaluable'
            Paths = @()
            Items = @()
            ActivePaths = @()
            Error = "launcher protocol parent is not an ordinary directory: $directory"
        }
    }
    try {
        $prefix = [IO.Path]::GetFileName($lockFull)
        $items = [Collections.Generic.List[object]]::new()
        $activePaths = [Collections.Generic.List[string]]::new()
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries(
                (ConvertTo-AstroExtendedLengthPath $directory),
                '*',
                [IO.SearchOption]::TopDirectoryOnly
            )) {
            $entryFull = ConvertFrom-AstroExtendedLengthPath $entry
            $leaf = [IO.Path]::GetFileName($entryFull)
            if ([string]::Equals(
                    $leaf,
                    $prefix,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                $activePaths.Add($entryFull)
                continue
            }
            $parsed = ConvertTo-AstroLauncherTransitionState $entryFull
            if ($parsed.Candidate) {
                $items.Add($parsed)
            }
        }
        $orderedItems = @($items | Sort-Object Path)
        $paths = @($orderedItems | ForEach-Object { $_.Path })
    }
    catch {
        return [pscustomobject]@{
            State = 'unevaluable'
            Paths = @()
            Items = @()
            ActivePaths = @()
            Error = "could not enumerate launcher protocol transitions in '$directory': $($_.Exception.Message)"
        }
    }
    $orderedActivePaths = @($activePaths | Sort-Object)
    if ($orderedActivePaths.Count -gt 1 -or
        ($orderedActivePaths.Count -eq 1 -and
            [IO.Path]::GetFileName($orderedActivePaths[0]) -cne $prefix)) {
        return [pscustomobject]@{
            State = 'invalid'
            Paths = $paths
            Items = $orderedItems
            ActivePaths = $orderedActivePaths
            Error = "launcher protocol contains noncanonical or colliding case-insensitive active-lock entries: $($orderedActivePaths -join '; ')"
        }
    }
    return [pscustomobject]@{
        State = if ($paths.Count -gt 0) { 'present' } else { 'clear' }
        Paths = $paths
        Items = $orderedItems
        ActivePaths = $orderedActivePaths
        Error = $null
    }
}

function Read-AstroLauncherLockFile {
    param([Parameter(Mandatory)][string]$LockPath)

    $full = [IO.Path]::GetFullPath($LockPath)
    $presence = Get-AstroPathEntryState $full
    if ($presence.State -eq 'absent') {
        return New-AstroLauncherLockState -State 'absent'
    }
    if ($presence.State -ne 'present') {
        return New-AstroLauncherLockState `
            -State 'unevaluable' `
            -ReadError "could not query launcher lock '$full': $($presence.Error)"
    }
    if (($presence.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or
        ($presence.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        return New-AstroLauncherLockState `
            -State 'unreadable' `
            -ValidationError "launcher lock must be an ordinary file, not attributes '$($presence.Attributes)': $full"
    }

    $handle = $null
    try {
        $handle = [AstroLauncherLockNative]::OpenExactClassifierReadFile($full)
    }
    catch {
        return New-AstroLauncherLockState `
            -State 'unevaluable' `
            -ReadError "could not retain launcher-lock classifier source '$full': $($_.Exception.Message)"
    }
    try {
        try {
            $snapshot = Get-AstroExactRetainedFileSnapshot `
                -Handle $handle `
                -ExpectedPath $full `
                -MaximumBytes $script:AstroLauncherLockMaxBytes
            $linkCount = [AstroLauncherLockNative]::GetNumberOfLinks($handle)
        }
        catch {
            return New-AstroLauncherLockState `
                -State 'unevaluable' `
                -ReadError "could not read one retained launcher-lock snapshot '$full': $($_.Exception.Message)"
        }

        $actualLeaf = [IO.Path]::GetFileName($snapshot.FinalPath)
        $actualParent = [IO.Path]::GetDirectoryName($snapshot.FinalPath)
        $actualParentLeaf = [IO.Path]::GetFileName(
            $actualParent.TrimEnd('\', '/')
        )
        $shapeError = if ($actualLeaf -cne 'astrolabe-launcher.lock') {
            "retained launcher-lock leaf has noncanonical casing/name '$actualLeaf'"
        }
        elseif ($actualParentLeaf -cne '.tmp') {
            "retained launcher-lock parent leaf has noncanonical casing/name '$actualParentLeaf'"
        }
        elseif ($linkCount -ne 1) {
            "retained launcher lock must have exactly one filesystem link; observed $linkCount"
        }
        else {
            $null
        }

        if ($null -ne $shapeError) {
            $result = New-AstroLauncherLockState `
                -State 'unreadable' `
                -ValidationError $shapeError
        }
        else {
            $parsed = Convert-AstroLauncherLockBytesToState $snapshot.Bytes $full
            if ($parsed.State -eq 'unreadable') {
                $result = New-AstroLauncherLockState `
                    -State 'unreadable' `
                    -ValidationError $parsed.ValidationError
            }
            else {
                $result = $parsed
                $result | Add-Member -NotePropertyName ReadError -NotePropertyValue $null
                $result | Add-Member -NotePropertyName TransitionPaths -NotePropertyValue @()
            }
        }
        $result | Add-Member -NotePropertyName Length -NotePropertyValue $snapshot.Length -Force
        $result | Add-Member -NotePropertyName Sha256 -NotePropertyValue $snapshot.Sha256 -Force
        return $result
    }
    finally {
        $handle.Dispose()
    }
}

function Read-AstroLauncherLock {
    param([Parameter(Mandatory)][string]$LockPath)

    $transitions = Get-AstroLauncherLockTransitions $LockPath
    if ($transitions.State -eq 'unevaluable') {
        return New-AstroLauncherLockState `
            -State 'unevaluable' `
            -ReadError $transitions.Error
    }
    if ($transitions.State -eq 'invalid') {
        return New-AstroLauncherLockState `
            -State 'unreadable' `
            -ValidationError $transitions.Error `
            -TransitionPaths $transitions.Paths
    }
    if ($transitions.State -eq 'present') {
        return New-AstroLauncherLockState `
            -State 'transition' `
            -ValidationError 'interrupted launcher-lock claim/cleanup/reclaim state requires explicit tracker-evidenced recovery' `
            -TransitionPaths $transitions.Paths
    }
    return Read-AstroLauncherLockFile $LockPath
}

function Get-AstroExactRetainedFileSnapshot {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle,
        [Parameter(Mandatory)][string]$ExpectedPath,
        [int]$MaximumBytes = $script:AstroLauncherProtocolSnapshotMaxBytes
    )

    if ($null -eq $Handle -or $Handle.IsInvalid -or $Handle.IsClosed) {
        throw 'exact retained file snapshot requires one live SafeFileHandle'
    }
    if ($MaximumBytes -le 0) {
        throw "exact retained file snapshot maximum must be positive: $MaximumBytes"
    }

    $expectedFull = [IO.Path]::GetFullPath($ExpectedPath)
    $fileIdBefore = [AstroLauncherLockNative]::GetFileIdentity($Handle)
    $finalPathBefore = ConvertFrom-AstroNativeFinalPath (
        [AstroLauncherLockNative]::GetFileFinalPath($Handle)
    )
    $finalPathBefore = [IO.Path]::GetFullPath($finalPathBefore)
    if (-not [string]::Equals(
            $expectedFull,
            $finalPathBefore,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "retained file path '$finalPathBefore' differs from expected exact path '$expectedFull'"
    }

    $bytes = [AstroLauncherLockNative]::ReadAllBytes($Handle, $MaximumBytes)
    $fileIdAfter = [AstroLauncherLockNative]::GetFileIdentity($Handle)
    $finalPathAfter = ConvertFrom-AstroNativeFinalPath (
        [AstroLauncherLockNative]::GetFileFinalPath($Handle)
    )
    $finalPathAfter = [IO.Path]::GetFullPath($finalPathAfter)
    if ($fileIdAfter -cne $fileIdBefore -or
        -not [string]::Equals(
            $finalPathAfter,
            $finalPathBefore,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'retained file identity/path changed during its exact byte snapshot'
    }

    return [pscustomobject]@{
        Path = $expectedFull
        FinalPath = $finalPathAfter
        FileId = $fileIdAfter
        Length = [uint64]$bytes.LongLength
        Sha256 = Get-AstroByteSha256 $bytes
        Bytes = $bytes
    }
}

function Assert-AstroLauncherLockLeaseCurrent {
    param([Parameter(Mandatory)]$Lease)

    if ($null -eq $Lease -or
        -not $Lease.PSObject.Properties['SafeFileHandle'] -or
        $null -eq $Lease.SafeFileHandle -or
        $Lease.SafeFileHandle.IsInvalid -or
        $Lease.SafeFileHandle.IsClosed) {
        throw 'launcher-lock mutation lease does not retain one live SafeFileHandle'
    }
    if (-not $Lease.PSObject.Properties['CurrentSnapshot'] -or
        $null -eq $Lease.CurrentSnapshot) {
        throw 'launcher-lock mutation lease is missing its current exact snapshot'
    }

    $current = Get-AstroExactRetainedFileSnapshot `
        -Handle $Lease.SafeFileHandle `
        -ExpectedPath $Lease.Path `
        -MaximumBytes $script:AstroLauncherLockMaxBytes
    $expected = $Lease.CurrentSnapshot
    if ($current.FileId -cne $expected.FileId -or
        $current.Length -ne $expected.Length -or
        $current.Sha256 -cne $expected.Sha256 -or
        [Convert]::ToBase64String($current.Bytes) -cne
            [Convert]::ToBase64String($expected.Bytes)) {
        throw "launcher-lock retained handle no longer matches its exact snapshot: $($Lease.Path)"
    }
    return $current
}

function Open-AstroLauncherPinnedDirectoryLease {
    param([Parameter(Mandatory)][string]$DirectoryPath)

    $full = [IO.Path]::GetFullPath($DirectoryPath).TrimEnd('\', '/')
    $handle = $null
    try {
        $handle = [AstroLauncherLockNative]::OpenExactRenameDirectory($full)
        $fileId = [AstroLauncherLockNative]::GetFileIdentity($handle)
        $finalPath = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($handle)
        )
        $finalPath = [IO.Path]::GetFullPath($finalPath).TrimEnd('\', '/')
        if (-not [string]::Equals(
                $full,
                $finalPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "pinned rename directory resolves to a different final path ('$full' -> '$finalPath')"
        }
        $fileIdAfter = [AstroLauncherLockNative]::GetFileIdentity($handle)
        if ($fileIdAfter -cne $fileId) {
            throw 'pinned rename directory FILE_ID changed during acquisition'
        }
        return [pscustomobject]@{
            Path = $full
            FinalPath = $finalPath
            FileId = $fileId
            SafeFileHandle = $handle
            Handle = $handle
            Stream = $handle
        }
    }
    catch {
        if ($null -ne $handle) {
            $handle.Dispose()
        }
        throw "could not retain exact pinned rename directory '$full': $($_.Exception.Message)"
    }
}

function Assert-AstroLauncherPinnedDirectoryLease {
    param([Parameter(Mandatory)]$Lease)

    if ($null -eq $Lease -or
        -not $Lease.PSObject.Properties['SafeFileHandle'] -or
        $null -eq $Lease.SafeFileHandle -or
        $Lease.SafeFileHandle.IsInvalid -or
        $Lease.SafeFileHandle.IsClosed) {
        throw 'pinned rename directory lease does not retain one live SafeFileHandle'
    }
    $fileId = [AstroLauncherLockNative]::GetFileIdentity($Lease.SafeFileHandle)
    $finalPath = ConvertFrom-AstroNativeFinalPath (
        [AstroLauncherLockNative]::GetFileFinalPath($Lease.SafeFileHandle)
    )
    $finalPath = [IO.Path]::GetFullPath($finalPath).TrimEnd('\', '/')
    if ($fileId -cne [string]$Lease.FileId -or
        -not [string]::Equals(
            $finalPath,
            [string]$Lease.FinalPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            $finalPath,
            [string]$Lease.Path,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "pinned rename destination parent changed identity/path: $($Lease.Path)"
    }
    return [pscustomobject]@{
        Path = [string]$Lease.Path
        FinalPath = $finalPath
        FileId = $fileId
    }
}

function Invoke-AstroExactLeaseDurabilityFlush {
    param(
        [Parameter(Mandatory)]$Lease,
        [Parameter(Mandatory)][string]$Operation
    )

    # FlushFileBuffers requires GENERIC_WRITE on the handle.  A lease that
    # declares WriteAccess=$false is an immutable published object (#619): it
    # deliberately holds no write access so that its share mask can deny peer
    # writes through every link of the file for the whole lease lifetime, which
    # is exactly what removes the writable publication window.  Its bytes were
    # durably flushed by the pre-publication scratch write and can never change
    # again, so no data durability is lost here.  Only the namespace metadata of
    # $Operation is left to NTFS logging, and a transition interrupted before
    # that metadata lands is classified as an interrupted transition and fails
    # closed.  This skip is declared on every occurrence, never silent.
    if ($Lease.PSObject.Properties['WriteAccess'] -and
        $Lease.WriteAccess -eq $false) {
        # The mutating launcher runs in a redirected native PowerShell host.
        # Windows PowerShell duplicates Write-Information as formatted stdout
        # plus a CLIXML InformationRecord on stderr even with -OutputFormat
        # Text.  Write the declaration directly to the native stdout boundary:
        # unlike Write-Output this cannot contaminate a caller's function
        # return value, and unlike Write-Information it remains one text line.
        [Console]::Out.WriteLine((
            'LAUNCHER_LOCK[ASTRO_LAUNCHER_IMMUTABLE_LEASE_FLUSH_DECLARED]: ' +
            "operation=$Operation; path=$($Lease.Path); " +
            'reason=immutable published lease holds no write access by design (#619); ' +
            'data_durability_owner=pre-publication scratch FlushFileBuffers'
        ))
        return
    }
    [AstroLauncherLockNative]::FlushExactFile($Lease.SafeFileHandle)
}

function Rename-AstroExactFileHandleNoReplace {
    param(
        [Parameter(Mandatory)]$Lease,
        [Parameter(Mandatory)]$DestinationDirectoryLease,
        [Parameter(Mandatory)][string]$DestinationLeaf
    )

    $before = Assert-AstroLauncherLockLeaseCurrent $Lease
    $directory = Assert-AstroLauncherPinnedDirectoryLease (
        $DestinationDirectoryLease
    )
    $sourceParent = [IO.Path]::GetDirectoryName($before.Path).TrimEnd('\', '/')
    if (-not [string]::Equals(
            $sourceParent,
            $directory.Path,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "launcher protocol rename source is not inside the retained destination parent ('$sourceParent' != '$($directory.Path)')"
    }
    if ([string]::IsNullOrEmpty($DestinationLeaf) -or
        [IO.Path]::GetFileName($DestinationLeaf) -cne $DestinationLeaf) {
        throw 'exact rename destination must be one simple nonempty filename'
    }
    $destination = [IO.Path]::GetFullPath(
        [IO.Path]::Combine($directory.Path, $DestinationLeaf)
    )
    if ([string]::Equals(
            $destination,
            $before.Path,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'exact no-replace rename destination equals its source path'
    }
    $destinationState = Get-AstroPathEntryState $destination
    if ($destinationState.State -eq 'present') {
        throw "exact no-replace rename destination already exists: $destination"
    }
    if ($destinationState.State -ne 'absent') {
        throw "exact no-replace rename destination is unevaluable: $destination ($($destinationState.Error))"
    }

    # Re-read the retained directory handle immediately before the native operation.
    # The native helper derives the documented absolute FILE_RENAME_INFO name from
    # this still-pinned handle and leaves RootDirectory NULL.
    $directory = Assert-AstroLauncherPinnedDirectoryLease (
        $DestinationDirectoryLease
    )
    [AstroLauncherLockNative]::RenameFileHandleNoReplace(
        $Lease.SafeFileHandle,
        $DestinationDirectoryLease.SafeFileHandle,
        $DestinationLeaf
    )
    Invoke-AstroExactLeaseDurabilityFlush -Lease $Lease -Operation 'no-replace rename'

    $after = Get-AstroExactRetainedFileSnapshot `
        -Handle $Lease.SafeFileHandle `
        -ExpectedPath $destination `
        -MaximumBytes $script:AstroLauncherLockMaxBytes
    if ($after.FileId -cne $before.FileId -or
        $after.Length -ne $before.Length -or
        $after.Sha256 -cne $before.Sha256 -or
        [Convert]::ToBase64String($after.Bytes) -cne
            [Convert]::ToBase64String($before.Bytes)) {
        throw 'exact handle-bound rename changed source identity or bytes'
    }
    $sourceState = Get-AstroPathEntryState $before.Path
    if ($sourceState.State -ne 'absent') {
        throw "exact handle-bound rename did not make its original path absent (state=$($sourceState.State), error=$($sourceState.Error)): $($before.Path)"
    }
    $Lease.Path = $destination
    $Lease.CurrentSnapshot = $after
    return [pscustomobject]@{
        State = 'renamed'
        SourcePath = $before.Path
        DestinationPath = $destination
        DestinationParentPath = $directory.Path
        DestinationParentFileId = $directory.FileId
        FileId = $after.FileId
        Length = $after.Length
        Sha256 = $after.Sha256
        SourcePathState = $sourceState.State
    }
}

function Invoke-AstroExactFileDispositionDelete {
    param([Parameter(Mandatory)]$Lease)

    # FILE_DISPOSITION_INFORMATION permits no operation on this handle after
    # DeleteFile=TRUE except CloseHandle.  Complete the final authorized readback
    # first, then arm deletion and immediately close before observing the pathname.
    $before = Assert-AstroLauncherLockLeaseCurrent $Lease
    Invoke-AstroExactLeaseDurabilityFlush -Lease $Lease -Operation 'disposition delete'
    [AstroLauncherLockNative]::DeleteExactFileHandle($Lease.SafeFileHandle)
    try {
        $Lease.SafeFileHandle.Dispose()
    }
    finally {
        $Lease.Disposed = $true
    }

    $terminalPathState = Get-AstroPathEntryState $before.Path
    $terminalState = if ($terminalPathState.State -eq 'absent') {
        'absent'
    } elseif ($terminalPathState.State -eq 'present') {
        'observed'
    } else {
        'unevaluable'
    }
    $terminalError = if ($terminalState -eq 'observed') {
        'exact FILE_DISPOSITION_INFO operation completed but the path remains present after closing the retained handle'
    } elseif ($terminalState -eq 'unevaluable') {
        "could not independently query path after closing the delete-pending handle: $($terminalPathState.Error)"
    } else {
        $null
    }
    return [pscustomobject]@{
        Path = $before.Path
        State = $terminalState
        Error = $terminalError
        DispositionSet = $true
        RetainedHandleClosed = $true
        FileId = $before.FileId
        Length = $before.Length
        Sha256 = $before.Sha256
        FinalAuthorizedFileId = $before.FileId
        FinalAuthorizedLength = $before.Length
        FinalAuthorizedSha256 = $before.Sha256
        TerminalPathState = $terminalPathState.State
    }
}

function Open-AstroLauncherLockLease {
    param([Parameter(Mandatory)][string]$LockPath)

    $full = [IO.Path]::GetFullPath($LockPath)
    $handle = $null
    try {
        # This exact handle is the sole mutation authority for claim->active and
        # active->cleanup. FileShare.Read preserves authoritative read access while
        # physically denying every competing writer, rename, and delete opener.
        $handle = [AstroLauncherLockNative]::OpenExactRenameSource($full)
    }
    catch {
        throw "could not open exact mutable launcher-lock lease handle '$full': $($_.Exception.Message)"
    }
    try {
        $snapshot = Get-AstroExactRetainedFileSnapshot `
            -Handle $handle `
            -ExpectedPath $full `
            -MaximumBytes $script:AstroLauncherLockMaxBytes
        $state = Convert-AstroLauncherLockBytesToState $snapshot.Bytes $full
        if ($state.State -eq 'unreadable') {
            throw "published launcher lock failed strict readback: $($state.ValidationError)"
        }
        return [pscustomobject]@{
            Path = $full
            # Stream remains a compatibility disposal alias for existing consumers.
            # It is deliberately the SafeFileHandle itself, not a path-reopening stream.
            Stream = $handle
            SafeFileHandle = $handle
            Handle = $handle
            State = $state
            InitialSnapshot = $snapshot
            CurrentSnapshot = $snapshot
            Length = $snapshot.Length
            Sha256 = $snapshot.Sha256
            Bytes = $snapshot.Bytes
            Disposed = $false
        }
    }
    catch {
        $handle.Dispose()
        throw
    }
}

function Assert-AstroLauncherLockClaimable {
    param([Parameter(Mandatory)][string]$LockPath)

    $lock = Read-AstroLauncherLock -LockPath $LockPath
    switch ($lock.State) {
        'absent' { return }
        'transition' {
            $paths = @($lock.TransitionPaths) -join '; '
            throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_TRANSITION_RECOVERY_REQUIRED]: interrupted claim/cleanup/reclaim state exists and was not changed ($paths); post exact path/hash/process evidence to the owning issue, then archive it with scripts\reclaim-launcher-lock.ps1"
        }
        'unreadable' {
            throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_UNREADABLE]: launcher lock is present but invalid ($($lock.ValidationError)); preserve its exact bytes and use scripts\reclaim-launcher-lock.ps1 -QuarantineUnreadable only after tracker-posted hash and exact dead-owner evidence: $LockPath"
        }
        'version-mismatch' {
            throw (
                'LAUNCHER_AUTHORITY[ASTRO_LAUNCHER_PROTOCOL_VERSION_MISMATCH]: ' +
                "{code=ASTRO_LAUNCHER_PROTOCOL_VERSION_MISMATCH; " +
                "message=`"launcher protocol state uses retired schema " +
                "'$($lock.Schema)' for exact owner pid=$($lock.OwnerPid), " +
                "process_start_utc_ticks=$($lock.OwnerProcessStartUtcTicks), " +
                "issue=#$($lock.Issue), probe_state=$(if ($lock.ProbeError) { 'unevaluable' } elseif ($lock.PidReused) { 'pid-reused' } elseif ($null -eq $lock.ObservedProcessStartUtcTicks) { 'absent' } else { 'exact-live' }); " +
                "it was preserved unchanged at '$LockPath'`"; " +
                "remediation=`"re-read the owning issue, record the exact " +
                "state hash '$($lock.Sha256)', and use the tracker-evidenced " +
                "reclaim path from canonical authority " +
                "'C:\code\Astrolabe\scripts\windows-gnu-toolchain-authority.ps1'; " +
                "never execute a historical worktree launcher`"}"
            )
        }
        'held' {
            throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_HELD]: another launcher session owns this workspace (pid=$($lock.OwnerPid), owner_process_start_utc_ticks=$($lock.OwnerProcessStartUtcTicks), issue=#$($lock.Issue), lease_started=$($lock.Started), command=$($lock.Command)); never stop or clean it: $LockPath"
        }
        'stale' {
            $reuse = if ($lock.PidReused) {
                "; numeric PID is reused by start_utc_ticks=$($lock.ObservedProcessStartUtcTicks)"
            } else {
                ''
            }
            throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_STALE_RECLAIM_REQUIRED]: launcher lock belongs to dead exact process pid=$($lock.OwnerPid), owner_process_start_utc_ticks=$($lock.OwnerProcessStartUtcTicks), issue=#$($lock.Issue)$reuse; bytes sha256=$($lock.Sha256) were preserved; post the exact probe/hash to issue #$($lock.Issue), then run scripts\reclaim-launcher-lock.ps1: $LockPath"
        }
        'unevaluable' {
            $detail = if ($lock.ReadError) { $lock.ReadError } else { $lock.ProbeError }
            throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_OWNER_UNEVALUABLE]: launcher-lock presence/read/process identity could not be evaluated ($detail); refusing without changing state: $LockPath"
        }
        default {
            throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_UNREADABLE]: unexpected launcher-lock state '$($lock.State)': $LockPath"
        }
    }
}

function Get-AstroCuda13RetirementTransitionPath {
    param([Parameter(Mandatory)][string]$CanonicalWorkspaceRoot)

    $root = [IO.Path]::GetFullPath($CanonicalWorkspaceRoot).TrimEnd('\', '/')
    return [IO.Path]::Combine(
        $root,
        '.tmp',
        'astrolabe-cuda13-retirement.transition.v1.json'
    )
}

function Get-AstroCuda13RetirementMutexNameFromIdentity {
    param([Parameter(Mandatory)][string]$CanonicalRootIdentity)

    if ($CanonicalRootIdentity -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$') {
        throw "CUDA retirement mutex filesystem identity is not canonical FILE_ID_INFO: $CanonicalRootIdentity"
    }
    $identityBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        "astrolabe.cuda13-retirement.v1|$CanonicalRootIdentity"
    )
    $digest = Get-AstroByteSha256 $identityBytes
    return "Global\Astrolabe.Cuda13Retirement.$digest"
}

function Enter-AstroCuda13RetirementMutex {
    param([Parameter(Mandatory)][string]$CanonicalWorkspaceRoot)

    $root = [IO.Path]::GetFullPath($CanonicalWorkspaceRoot).TrimEnd('\', '/')
    $rootHandle = $null
    try {
        $rootHandle = [AstroLauncherLockNative]::OpenExactRenameDirectory($root)
        $rootIdentity = [AstroLauncherLockNative]::GetDirectoryLockIdentity(
            $rootHandle
        )
        $rootFinalPath = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($rootHandle)
        )
        $rootFinalPath = [IO.Path]::GetFullPath(
            $rootFinalPath
        ).TrimEnd('\', '/')
        if (-not [string]::Equals(
                $root,
                $rootFinalPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "canonical workspace lexical path '$root' resolves to retained-handle path '$rootFinalPath'"
        }
        $name = Get-AstroCuda13RetirementMutexNameFromIdentity $rootIdentity
        $security = New-AstroLauncherLockMutexSecurity
    }
    catch {
        if ($null -ne $rootHandle) {
            $rootHandle.Dispose()
        }
        throw "could not retain the canonical workspace while deriving its shared CUDA retirement mutex: $($_.Exception.Message)"
    }

    $createdNew = $false
    try {
        if ('System.Threading.MutexAcl' -as [type]) {
            $mutex = [System.Threading.MutexAcl]::Create(
                $false,
                $name,
                [ref]$createdNew,
                $security
            )
        }
        else {
            $mutex = [Threading.Mutex]::new(
                $false,
                $name,
                [ref]$createdNew,
                $security
            )
        }
    }
    catch {
        $rootHandle.Dispose()
        throw "could not create/open shared CUDA retirement mutex '$name': $($_.Exception.Message)"
    }

    $acquired = $false
    $abandoned = $false
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [Threading.AbandonedMutexException] {
            $acquired = $true
            $abandoned = $true
        }
        return [pscustomobject]@{
            Name = $name
            Mutex = $mutex
            Acquired = $acquired
            WasAbandoned = $abandoned
            CreatedNew = $createdNew
            Root = $root
            RootFinalPath = $rootFinalPath
            RootIdentity = $rootIdentity
            RootHandle = $rootHandle
        }
    }
    catch {
        if ($acquired) {
            try { $mutex.ReleaseMutex() } catch {}
        }
        $mutex.Dispose()
        $rootHandle.Dispose()
        throw
    }
}

function Exit-AstroCuda13RetirementMutex {
    param([Parameter(Mandatory)]$Lease)

    Exit-AstroLauncherLockMutex $Lease
}

function Read-AstroCuda13RetirementTransition {
    param([Parameter(Mandatory)][string]$CanonicalWorkspaceRoot)

    $root = [IO.Path]::GetFullPath($CanonicalWorkspaceRoot).TrimEnd('\', '/')
    $path = Get-AstroCuda13RetirementTransitionPath $root
    $presence = Get-AstroPathEntryState $path
    if ($presence.State -eq 'absent') {
        return [pscustomobject]@{
            State = 'absent'
            Path = $path
            OwnerPid = $null
            OwnerProcessStartUtcTicks = $null
            Issue = $null
            TransactionId = $null
            Sha256 = $null
            FileId = $null
            Probe = $null
            ValidationError = $null
            ReadError = $null
        }
    }
    if ($presence.State -ne 'present') {
        return [pscustomobject]@{
            State = 'unevaluable'
            Path = $path
            OwnerPid = $null
            OwnerProcessStartUtcTicks = $null
            Issue = $null
            TransactionId = $null
            Sha256 = $null
            FileId = $null
            Probe = $null
            ValidationError = $null
            ReadError = $presence.Error
        }
    }
    if (($presence.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or
        ($presence.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        return [pscustomobject]@{
            State = 'unreadable'
            Path = $path
            OwnerPid = $null
            OwnerProcessStartUtcTicks = $null
            Issue = $null
            TransactionId = $null
            Sha256 = $null
            FileId = $null
            Probe = $null
            ValidationError = 'transition path is not one ordinary non-reparse file'
            ReadError = $null
        }
    }

    $handle = $null
    try {
        $handle = [AstroLauncherLockNative]::OpenExactClassifierReadFile($path)
        $snapshot = Get-AstroExactRetainedFileSnapshot `
            -Handle $handle `
            -ExpectedPath $path `
            -MaximumBytes $script:AstroLauncherLockMaxBytes
    }
    catch {
        if ($null -ne $handle) { $handle.Dispose() }
        return [pscustomobject]@{
            State = 'unevaluable'
            Path = $path
            OwnerPid = $null
            OwnerProcessStartUtcTicks = $null
            Issue = $null
            TransactionId = $null
            Sha256 = $null
            FileId = $null
            Probe = $null
            ValidationError = $null
            ReadError = $_.Exception.Message
        }
    }
    finally {
        if ($null -ne $handle -and -not $handle.IsClosed) {
            $handle.Dispose()
        }
    }

    $parsed = $null
    $validationError = $null
    try {
        $text = [Text.UTF8Encoding]::new(
            $false,
            $true
        ).GetString($snapshot.Bytes)
        $parsed = ConvertFrom-Json -InputObject $text -ErrorAction Stop
        $required = @(
            'schema',
            'canonical_workspace_root',
            'canonical_workspace_file_id',
            'pid',
            'owner_process_start_utc_ticks',
            'issue',
            'transaction_id',
            'started_utc'
        )
        $observed = @($parsed.PSObject.Properties.Name)
        foreach ($name in $required) {
            if ($name -cnotin $observed) {
                throw "required property '$name' is absent"
            }
        }
        foreach ($name in $observed) {
            if ($name -cnotin $required) {
                throw "unexpected property '$name' is present"
            }
        }
        $pidValue = [long]$parsed.pid
        $ticksValue = [long]$parsed.owner_process_start_utc_ticks
        $issueValue = [long]$parsed.issue
        if ([string]$parsed.schema -cne
            'astrolabe.cuda13-retirement-transition.v1') {
            throw "schema is not astrolabe.cuda13-retirement-transition.v1"
        }
        if ($pidValue -le 0 -or $pidValue -gt [int]::MaxValue -or
            $ticksValue -le 0 -or
            $ticksValue -gt [DateTime]::MaxValue.Ticks -or
            $issueValue -le 0 -or $issueValue -gt [int]::MaxValue) {
            throw 'owner PID, process-start ticks, or issue is outside its positive range'
        }
        if ([string]$parsed.transaction_id -cnotmatch '^[0-9a-f]{32}$') {
            throw 'transaction_id is not 32 lowercase hexadecimal characters'
        }
        if ([string]$parsed.canonical_workspace_file_id -cnotmatch
            '^[0-9a-f]{16}:[0-9a-f]{32}$') {
            throw 'canonical_workspace_file_id is not canonical FILE_ID_INFO'
        }
        $rootHandle = [AstroLauncherLockNative]::OpenExactRenameDirectory($root)
        try {
            $rootIdentity = [AstroLauncherLockNative]::GetDirectoryLockIdentity(
                $rootHandle
            )
            $rootFinal = ConvertFrom-AstroNativeFinalPath (
                [AstroLauncherLockNative]::GetFileFinalPath($rootHandle)
            )
            $rootFinal = [IO.Path]::GetFullPath($rootFinal).TrimEnd('\', '/')
        }
        finally {
            $rootHandle.Dispose()
        }
        if (-not [string]::Equals(
                [string]$parsed.canonical_workspace_root,
                $root,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [string]::Equals(
                $rootFinal,
                $root,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            [string]$parsed.canonical_workspace_file_id -cne $rootIdentity) {
            throw 'transition canonical workspace path/FILE_ID does not match the retained root'
        }
        # Windows PowerShell 5.1 eagerly materializes ISO-8601 JSON strings as
        # DateTime, while PowerShell 7 preserves this property as a string. Validate
        # both host representations without culture-stringifying a DateTime first.
        if ($parsed.started_utc -is [DateTime]) {
            $startedUtc = [DateTime]$parsed.started_utc
            if ($startedUtc.Ticks -le 0) {
                throw 'started_utc materialized as an invalid DateTime'
            }
        }
        else {
            [void][DateTime]::ParseExact(
                [string]$parsed.started_utc,
                'o',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            )
        }
    }
    catch {
        $validationError = $_.Exception.Message
    }
    if ($null -ne $validationError) {
        return [pscustomobject]@{
            State = 'unreadable'
            Path = $path
            OwnerPid = $null
            OwnerProcessStartUtcTicks = $null
            Issue = $null
            TransactionId = $null
            Sha256 = $snapshot.Sha256
            FileId = $snapshot.FileId
            Probe = $null
            ValidationError = $validationError
            ReadError = $null
        }
    }

    $probe = Get-AstroExactProcessIdentityProbe `
        -ProcessId ([int]$parsed.pid) `
        -ProcessStartUtcTicks ([long]$parsed.owner_process_start_utc_ticks)
    $state = if ($probe.State -ceq 'exact-live') {
        'held'
    }
    elseif ($probe.State -ceq 'unevaluable') {
        'unevaluable'
    }
    else {
        'stale'
    }
    return [pscustomobject]@{
        State = $state
        Path = $path
        OwnerPid = [int]$parsed.pid
        OwnerProcessStartUtcTicks =
            [long]$parsed.owner_process_start_utc_ticks
        Issue = [int]$parsed.issue
        TransactionId = [string]$parsed.transaction_id
        Sha256 = $snapshot.Sha256
        FileId = $snapshot.FileId
        Probe = $probe
        ValidationError = $null
        ReadError = $probe.Error
    }
}

function Assert-AstroCuda13RetirementAdmissionOpen {
    param([Parameter(Mandatory)][string]$CanonicalWorkspaceRoot)

    $transition = Read-AstroCuda13RetirementTransition `
        -CanonicalWorkspaceRoot $CanonicalWorkspaceRoot
    if ($transition.State -eq 'absent') {
        return
    }
    $detail = if ($transition.ValidationError) {
        $transition.ValidationError
    }
    elseif ($transition.ReadError) {
        $transition.ReadError
    }
    else {
        "owner_pid=$($transition.OwnerPid), owner_process_start_utc_ticks=$($transition.OwnerProcessStartUtcTicks), issue=#$($transition.Issue), transaction=$($transition.TransactionId), sha256=$($transition.Sha256)"
    }
    throw "LAUNCHER_BOUNDARY[ASTRO_CUDA13_RETIREMENT_TRANSITION_BLOCKED]: {code=ASTRO_CUDA13_RETIREMENT_TRANSITION_BLOCKED; message=`"shared CUDA retirement transition state '$($transition.State)' blocks launcher admission without change: $($transition.Path); $detail`"; remediation=`"if the exact owner is live, wait; otherwise preserve the bytes and post their path/hash plus exact owner probe to issue #$($transition.Issue) before recovery`"}"
}
