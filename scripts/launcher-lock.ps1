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
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class AstroLauncherLockNative
{
    private const uint JOB_OBJECT_QUERY = 0x0004;
    private const uint FILE_READ_ATTRIBUTES = 0x0080;
    private const uint FILE_TRAVERSE = 0x0020;
    private const uint DELETE_ACCESS = 0x00010000;
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
    private const int JOB_OBJECT_BASIC_PROCESS_ID_LIST_CLASS = 3;
    private const int ERROR_FILE_NOT_FOUND = 2;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int ERROR_MORE_DATA = 234;
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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file,
        StringBuilder path,
        uint pathLength,
        uint flags
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileExWNative(
        string existingFileName,
        string newFileName,
        uint flags
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

    public static bool MoveFileExW(
        string existingFileName,
        string newFileName,
        uint flags
    )
    {
        return MoveFileExWNative(
            GetExtendedLengthPath(existingFileName),
            GetExtendedLengthPath(newFileName),
            flags
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

    private static SafeFileHandle OpenExactOrdinaryRead(
        string path,
        uint shareMode,
        string description
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
            if (information.NumberOfLinks != 1)
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
        return OpenExactOrdinaryRead(path, FILE_SHARE_READ, "protected evidence file");
    }

    public static SafeFileHandle OpenExactSharedDeleteReadFile(string path)
    {
        return OpenExactOrdinaryRead(
            path,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            "shared-delete evidence file"
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
        if (information.NumberOfLinks != 1)
        {
            throw new InvalidOperationException(
                description + " must retain exactly one filesystem link; observed " +
                information.NumberOfLinks
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

function Move-AstroFileWriteThroughNoReplace {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )

    $sourceFull = [IO.Path]::GetFullPath($Source)
    $destinationFull = [IO.Path]::GetFullPath($Destination)
    $destinationState = Get-AstroPathEntryState $destinationFull
    if ($destinationState.State -eq 'present') {
        throw "destination already exists; refusing no-replace move: $destinationFull"
    }
    if ($destinationState.State -ne 'absent') {
        throw "destination presence is unevaluable; refusing no-replace move: $destinationFull ($($destinationState.Error))"
    }
    # MOVEFILE_WRITE_THROUGH = 0x8. REPLACE_EXISTING and COPY_ALLOWED are omitted.
    if (-not [AstroLauncherLockNative]::MoveFileExW(
            $sourceFull,
            $destinationFull,
            [uint32]0x8
        )) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw [ComponentModel.Win32Exception]::new(
            $errorCode,
            "write-through no-replace move failed '$sourceFull' -> '$destinationFull'"
        )
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
        [IO.FileShare]$Share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    )

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
        if ($stream.Length -gt $script:AstroLauncherProtocolSnapshotMaxBytes) {
            throw "launcher protocol file exceeds the $script:AstroLauncherProtocolSnapshotMaxBytes-byte safety limit: $full ($($stream.Length) bytes)"
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
    [AstroLauncherLockNative]::FlushExactFile($Lease.SafeFileHandle)

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
    [AstroLauncherLockNative]::FlushExactFile($Lease.SafeFileHandle)
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
