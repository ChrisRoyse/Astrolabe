<#
.SYNOPSIS
    Exact-generation launcher TEMP/attribution pair lifecycle (#617).

.DESCRIPTION
    This module recognizes only the v2 generation/hash-bound TEMP and cleanup
    tombstone grammars. Sweep authority is an exact absent-or-PID-reused owner
    generation AND an exactly absent deterministic Job Object. Observed (even
    empty), malformed, legacy, missing, mismatched, changing, and unevaluable
    state is preserving.

    Pair cleanup is one recoverable transaction. It retains the exact evidence
    file and TEMP directory handles, renames TEMP first, then renames the same
    evidence handle, validates the captured tree while deleting only captured
    identities, and uses FILE_DISPOSITION_INFO for both final objects. Every
    crash boundary leaves a reserved state that the next pass can classify.
#>

if (-not (Get-Command Get-AstroAttributionInventory -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'attribution-manifest.ps1')
}
if (-not (Get-Command Open-AstroDeadAttributionEvidenceMutationLease -ErrorAction SilentlyContinue) -or
    -not (Get-Command Move-AstroAttributionEvidenceLeaseToCleanupTombstone -ErrorAction SilentlyContinue) -or
    -not (Get-Command Complete-AstroDeadAttributionEvidenceDeletion -ErrorAction SilentlyContinue)) {
    throw 'launcher TEMP lifecycle requires the strict attribution-manifest v2 mutation helpers'
}

$script:AstroLauncherTempReservedPrefix = 'windows-gnu-toolchain-'
$script:AstroLauncherTempCleanupReservedPrefix = '.astro-launcher-temp-cleanup.'
$script:AstroLauncherTempPidRegex = $script:AstroLauncherTempV2Regex
$script:AstroLauncherTempCleanupV2Regex =
    '^\.astro-launcher-temp-cleanup\.v2\.pid-(?<pid>[1-9][0-9]*)\.ticks-(?<ticks>[1-9][0-9]*)\.lock-sha256-(?<sha>[0-9a-f]{64})\.nonce-(?<nonce>[0-9a-f]{32})\.dir\z'

if (-not ('AstroLauncherTempNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class AstroLauncherTempNative
{
    private const uint FILE_LIST_DIRECTORY = 0x0001;
    private const uint FILE_READ_ATTRIBUTES = 0x0080;
    private const uint FILE_WRITE_ATTRIBUTES = 0x0100;
    private const uint FILE_TRAVERSE = 0x0020;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint READ_CONTROL = 0x00020000;
    private const uint DELETE_ACCESS = 0x00010000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint CREATE_NEW = 1;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_FLAG_DELETE_ON_CLOSE = 0x04000000;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
    private const uint FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200;
    private const uint FILE_ATTRIBUTE_COMPRESSED = 0x00000800;
    private const uint FILE_ATTRIBUTE_ENCRYPTED = 0x00004000;
    private const uint INVALID_FILE_ATTRIBUTES = 0xffffffff;
    private const uint FILE_TYPE_DISK = 0x0001;
    private const int FILE_ID_INFO_CLASS = 18;
    private const int FILE_BASIC_INFO_CLASS = 0;
    private const int FILE_ID_BOTH_DIRECTORY_INFO_CLASS = 10;
    private const int FILE_RENAME_INFO_CLASS = 3;
    private const int FILE_DISPOSITION_INFO_CLASS = 4;
    private const int ERROR_FILE_NOT_FOUND = 2;
    private const int ERROR_PATH_NOT_FOUND = 3;
    private const int ERROR_NO_MORE_FILES = 18;
    private const int MAX_TREE_DEPTH = 1024;
    private const uint BACKUP_DATA = 0x00000001;
    private const uint BACKUP_EA_DATA = 0x00000002;
    private const uint BACKUP_SECURITY_DATA = 0x00000003;
    private const uint BACKUP_ALTERNATE_DATA = 0x00000004;
    private const uint BACKUP_LINK = 0x00000005;
    private const uint BACKUP_PROPERTY_DATA = 0x00000006;
    private const uint BACKUP_OBJECT_ID = 0x00000007;
    private const uint BACKUP_REPARSE_DATA = 0x00000008;
    private const uint BACKUP_SPARSE_BLOCK = 0x00000009;
    private const uint BACKUP_TXFS_DATA = 0x0000000a;
    private const int WIN32_STREAM_ID_HEADER_BYTES = 20;
    private const uint MAX_BACKUP_STREAM_NAME_BYTES = 65536;
    private const int FILE_ID_BOTH_DIRECTORY_NAME_OFFSET = 104;
    private const int DIRECTORY_ENUMERATION_BUFFER_BYTES = 65536;

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
    private struct FILE_BASIC_INFO
    {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public uint FileAttributes;
    }

    private sealed class ExactBackupState
    {
        public string Canonical;
        public string BackupSha256;
        public string SecuritySha256;
        public string StreamInventory;
        public string BasicInfo;
    }

    private sealed class ExpectedEntry
    {
        public bool IsDirectory;
        public string RelativePath;
        public string FileId;
        public string ExactBackupState;
        public string ShortNameToken;
        public string ExactRecord;
        public int Depth;
    }

    private sealed class ExactDirectoryEntry
    {
        public string Path;
        public string ShortNameToken;
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
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        int informationClass,
        IntPtr information,
        uint size
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file,
        StringBuilder path,
        uint pathLength,
        uint flags
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(SafeFileHandle file);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        int informationClass,
        IntPtr information,
        uint size
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFileAttributesW(string path);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(
        string newFileName,
        string existingFileName,
        IntPtr securityAttributes
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BackupRead(
        SafeFileHandle file,
        byte[] buffer,
        uint bytesToRead,
        out uint bytesRead,
        [MarshalAs(UnmanagedType.Bool)] bool abort,
        [MarshalAs(UnmanagedType.Bool)] bool processSecurity,
        ref IntPtr context
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileTime(
        SafeFileHandle file,
        IntPtr creationTime,
        IntPtr lastAccessTime,
        IntPtr lastWriteTime
    );

    private static void RequireDisk(SafeFileHandle handle, string description)
    {
        if (handle == null || handle.IsInvalid || handle.IsClosed)
        {
            throw new ObjectDisposedException(description + " handle");
        }
        uint type = GetFileType(handle);
        if (type != FILE_TYPE_DISK)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                description + " is not a local disk filesystem handle (type=" + type + ")"
            );
        }
    }

    private static BY_HANDLE_FILE_INFORMATION ReadInformation(
        SafeFileHandle handle,
        string description
    )
    {
        RequireDisk(handle, description);
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

    private static void RequireOrdinaryDirectory(
        SafeFileHandle handle,
        string description
    )
    {
        BY_HANDLE_FILE_INFORMATION information = ReadInformation(handle, description);
        if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            throw new InvalidOperationException(
                description + " must remain an ordinary non-reparse directory"
            );
        }
    }

    private static BY_HANDLE_FILE_INFORMATION RequireOrdinarySingleLinkFile(
        SafeFileHandle handle,
        string description
    )
    {
        BY_HANDLE_FILE_INFORMATION information = ReadInformation(handle, description);
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
                description + " must have exactly one filesystem link; observed " +
                information.NumberOfLinks
            );
        }
        return information;
    }

    private static string GetIdentity(SafeFileHandle handle)
    {
        IntPtr buffer = Marshal.AllocHGlobal(24);
        try
        {
            for (int index = 0; index < 24; index++)
            {
                Marshal.WriteByte(buffer, index, 0);
            }
            if (!GetFileInformationByHandleEx(handle, FILE_ID_INFO_CLASS, buffer, 24))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "could not read FILE_ID_INFO from exact TEMP handle"
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
            StringBuilder result = new StringBuilder(49);
            result.Append(volume.ToString("x16", CultureInfo.InvariantCulture));
            result.Append(':');
            for (int index = 0; index < fileId.Length; index++)
            {
                result.Append(fileId[index].ToString("x2", CultureInfo.InvariantCulture));
            }
            return result.ToString();
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static ulong GetVolume(SafeFileHandle handle)
    {
        string identity = GetIdentity(handle);
        return UInt64.Parse(
            identity.Substring(0, 16),
            NumberStyles.AllowHexSpecifier,
            CultureInfo.InvariantCulture
        );
    }

    private static string NormalizeFinalPath(string path)
    {
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            path = @"\\" + path.Substring(8);
        }
        else if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        {
            path = path.Substring(4);
        }
        return Path.GetFullPath(path).TrimEnd('\\', '/');
    }

    private static string GetFinalPath(SafeFileHandle handle)
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
                "could not read final path from exact TEMP handle"
            );
        }
        return NormalizeFinalPath(buffer.ToString());
    }

    private static SafeFileHandle OpenEntry(
        string path,
        uint desiredAccess,
        uint shareMode,
        string description
    )
    {
        SafeFileHandle handle = CreateFileW(
            path,
            desiredAccess,
            shareMode,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
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
            RequireDisk(handle, description);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static SafeFileHandle OpenExactDirectoryMutation(string path)
    {
        SafeFileHandle handle = OpenEntry(
            Path.GetFullPath(path),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE |
                FILE_WRITE_ATTRIBUTES | GENERIC_READ | READ_CONTROL |
                DELETE_ACCESS,
            FILE_SHARE_READ,
            "exact TEMP mutation directory"
        );
        try
        {
            RequireOrdinaryDirectory(handle, "exact TEMP mutation directory");
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    // The producer retains this handle from immediately after CreateDirectory
    // until terminal cleanup. READ|WRITE sharing permits ordinary work below the
    // directory, while deliberately omitting SHARE_DELETE prevents any other
    // handle from renaming or deleting the retained root. DELETE access is
    // retained now so cleanup never reacquires authority by pathname later.
    public static SafeFileHandle OpenExactLiveDirectoryLease(string path)
    {
        SafeFileHandle handle = OpenEntry(
            Path.GetFullPath(path),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | DELETE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            "exact live TEMP directory lease"
        );
        try
        {
            RequireOrdinaryDirectory(handle, "exact live TEMP directory lease");
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    // Classification never needs DELETE access. Sharing DELETE here is
    // essential: it permits a read-only identity probe while the producer's
    // live root lease is intentionally denying everyone else DELETE sharing.
    public static SafeFileHandle OpenExactDirectoryIdentity(string path)
    {
        SafeFileHandle handle = OpenEntry(
            Path.GetFullPath(path),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            "exact TEMP identity directory"
        );
        try
        {
            RequireOrdinaryDirectory(handle, "exact TEMP identity directory");
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    // Used only as an identity/backup-state bridge while the continuously live
    // producer root lease still requests DELETE.  Sharing all access keeps the
    // observer compatible with that lease.  The cleanup path later transfers
    // to OpenExactDirectoryMutation before any disposition, which denies both
    // WRITE and DELETE sharing and revalidates this exact FILE_ID/state.
    public static SafeFileHandle OpenExactDirectoryBackupObserver(string path)
    {
        SafeFileHandle handle = OpenEntry(
            Path.GetFullPath(path),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE |
                FILE_WRITE_ATTRIBUTES | GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            "exact TEMP root backup-state observer"
        );
        try
        {
            RequireOrdinaryDirectory(handle, "exact TEMP root backup-state observer");
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static SafeFileHandle CreateDeleteOnCloseScratch(string path)
    {
        string full = Path.GetFullPath(path);
        SafeFileHandle handle = CreateFileW(
            full,
            GENERIC_READ | DELETE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE |
                FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero
        );
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(
                error,
                "could not create exact delete-on-close launcher scratch: " + full
            );
        }
        try
        {
            RequireOrdinarySingleLinkFile(
                handle,
                "delete-on-close launcher scratch"
            );
            if (!String.Equals(GetFinalPath(handle), full, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "delete-on-close launcher scratch resolved to a different final path"
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

    public static SafeFileHandle OpenExactScratchPublisher(string path)
    {
        SafeFileHandle handle = OpenEntry(
            Path.GetFullPath(path),
            GENERIC_READ | GENERIC_WRITE | DELETE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            "exact write-denying launcher scratch publisher"
        );
        try
        {
            RequireOrdinarySingleLinkFile(
                handle,
                "exact write-denying launcher scratch publisher"
            );
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    // This observer is opened through the published hard-link name while both
    // scratch handles are still live.  It must share READ, WRITE, and DELETE so
    // it is compatible with both retained scratch handles, but it requests
    // READ only and therefore cannot mutate the publication object.  Keeping
    // it live bridges identity across closing every handle opened through the
    // delete-on-close scratch name.
    public static SafeFileHandle OpenExactSharedPublicationObserver(string path)
    {
        SafeFileHandle handle = OpenEntry(
            Path.GetFullPath(path),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            "exact shared publication observer"
        );
        try
        {
            BY_HANDLE_FILE_INFORMATION information = ReadInformation(
                handle,
                "exact shared publication observer"
            );
            if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
                (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                information.NumberOfLinks == 0)
            {
                throw new InvalidOperationException(
                    "shared publication observer must bind an ordinary linked file"
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

    public static void WriteExactScratchAndFlush(
        SafeFileHandle handle,
        byte[] bytes
    )
    {
        if (bytes == null)
        {
            throw new ArgumentNullException("bytes");
        }
        RequireOrdinarySingleLinkFile(handle, "delete-on-close launcher scratch");
        bool addedReference = false;
        handle.DangerousAddRef(ref addedReference);
        try
        {
            using (SafeFileHandle borrowed = new SafeFileHandle(
                handle.DangerousGetHandle(),
                false
            ))
            using (FileStream stream = new FileStream(
                borrowed,
                FileAccess.ReadWrite,
                4096,
                false
            ))
            {
                stream.Position = 0;
                stream.SetLength(0);
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }
        }
        finally
        {
            if (addedReference)
            {
                handle.DangerousRelease();
            }
        }
        RequireOrdinarySingleLinkFile(handle, "durable delete-on-close launcher scratch");
    }

    public static void CreateExactHardLinkNoReplace(
        SafeFileHandle source,
        string expectedSourcePath,
        string destinationPath
    )
    {
        RequireOrdinarySingleLinkFile(source, "delete-on-close launcher scratch");
        string sourcePath = Path.GetFullPath(expectedSourcePath);
        string sourceFinal = GetFinalPath(source);
        if (!String.Equals(sourcePath, sourceFinal, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "delete-on-close launcher scratch changed path before publication"
            );
        }
        string destination = Path.GetFullPath(destinationPath);
        uint attributes = GetFileAttributesW(destination);
        if (attributes != INVALID_FILE_ATTRIBUTES)
        {
            throw new IOException(
                "no-replace launcher claim destination already exists: " + destination
            );
        }
        int absenceError = Marshal.GetLastWin32Error();
        if (absenceError != ERROR_FILE_NOT_FOUND && absenceError != ERROR_PATH_NOT_FOUND)
        {
            throw new Win32Exception(
                absenceError,
                "launcher claim destination absence is unevaluable: " + destination
            );
        }
        // CreateHardLinkW is atomic and has no replace-existing mode. Return
        // immediately after the kernel reports success; the caller records the
        // typed transition before performing any fallible readback.
        if (!CreateHardLinkW(destination, sourceFinal, IntPtr.Zero))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "atomic no-replace launcher claim hard-link publication failed"
            );
        }
    }

    public static uint GetExactFileLinkCount(SafeFileHandle handle)
    {
        BY_HANDLE_FILE_INFORMATION information = ReadInformation(
            handle,
            "exact launcher scratch"
        );
        if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
            (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            throw new InvalidOperationException(
                "exact launcher scratch became a directory or reparse entry"
            );
        }
        return information.NumberOfLinks;
    }

    public static string GetExactSingleLinkFileIdentity(SafeFileHandle handle)
    {
        RequireOrdinarySingleLinkFile(handle, "exact launcher scratch");
        return GetIdentity(handle);
    }

    public static string GetExactDirectoryIdentity(SafeFileHandle handle)
    {
        RequireOrdinaryDirectory(handle, "exact TEMP mutation directory");
        return GetIdentity(handle);
    }

    public static string GetExactDirectoryFinalPath(SafeFileHandle handle)
    {
        RequireOrdinaryDirectory(handle, "exact TEMP mutation directory");
        return GetFinalPath(handle);
    }

    private static long FileTimeValue(
        System.Runtime.InteropServices.ComTypes.FILETIME value
    )
    {
        return ((long)(uint)value.dwHighDateTime << 32) | (uint)value.dwLowDateTime;
    }

    private static string EncodeRelativePath(string relativePath)
    {
        UTF8Encoding utf8 = new UTF8Encoding(false, true);
        return Convert.ToBase64String(utf8.GetBytes(relativePath));
    }

    private static string DecodeRelativePath(string encoded)
    {
        UTF8Encoding utf8 = new UTF8Encoding(false, true);
        byte[] bytes = Convert.FromBase64String(encoded);
        string value = utf8.GetString(bytes);
        if (Convert.ToBase64String(utf8.GetBytes(value)) != encoded)
        {
            throw new InvalidOperationException("TEMP tree relative-path token is not canonical base64 UTF-8");
        }
        return value;
    }

    private static string HexDigest(HashAlgorithm algorithm)
    {
        algorithm.TransformFinalBlock(new byte[0], 0, 0);
        StringBuilder result = new StringBuilder(64);
        foreach (byte value in algorithm.Hash)
        {
            result.Append(value.ToString("x2", CultureInfo.InvariantCulture));
        }
        return result.ToString();
    }

    private static void HashBlock(HashAlgorithm algorithm, byte[] buffer, int count)
    {
        if (count > 0)
        {
            algorithm.TransformBlock(buffer, 0, count, buffer, 0);
        }
    }

    private static byte[] ReadBackupExact(
        SafeFileHandle handle,
        int count,
        bool allowCleanEnd,
        ref IntPtr context,
        string description
    )
    {
        byte[] result = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            byte[] part = new byte[count - offset];
            uint read;
            if (!BackupRead(
                handle,
                part,
                (uint)part.Length,
                out read,
                false,
                true,
                ref context
            ))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "TEMP_BACKUP_STATE_READ_FAILED: " + description
                );
            }
            if (read == 0)
            {
                if (allowCleanEnd && offset == 0)
                {
                    return null;
                }
                throw new EndOfStreamException(
                    "TEMP_BACKUP_STATE_TRUNCATED: " + description +
                    " ended at " + offset + " of " + count + " bytes"
                );
            }
            if (read > part.Length)
            {
                throw new InvalidDataException(
                    "TEMP_BACKUP_STATE_INVALID_COUNT: BackupRead returned too many bytes"
                );
            }
            Buffer.BlockCopy(part, 0, result, offset, (int)read);
            offset += (int)read;
        }
        return result;
    }

    private static FILE_BASIC_INFO ReadBasicInfo(
        SafeFileHandle handle,
        string description
    )
    {
        int size = Marshal.SizeOf(typeof(FILE_BASIC_INFO));
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!GetFileInformationByHandleEx(
                handle,
                FILE_BASIC_INFO_CLASS,
                buffer,
                (uint)size
            ))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "TEMP_BASIC_INFO_READ_FAILED: " + description
                );
            }
            return (FILE_BASIC_INFO)Marshal.PtrToStructure(
                buffer,
                typeof(FILE_BASIC_INFO)
            );
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string CanonicalBasicInfo(FILE_BASIC_INFO information)
    {
        return information.CreationTime.ToString(CultureInfo.InvariantCulture) + "," +
            information.LastAccessTime.ToString(CultureInfo.InvariantCulture) + "," +
            information.LastWriteTime.ToString(CultureInfo.InvariantCulture) + "," +
            information.ChangeTime.ToString(CultureInfo.InvariantCulture) + "," +
            information.FileAttributes.ToString(CultureInfo.InvariantCulture);
    }

    private static void RequireSupportedAttributes(
        uint attributes,
        string description
    )
    {
        uint unsupported = attributes & (
            FILE_ATTRIBUTE_REPARSE_POINT |
            FILE_ATTRIBUTE_SPARSE_FILE |
            FILE_ATTRIBUTE_COMPRESSED |
            FILE_ATTRIBUTE_ENCRYPTED
        );
        if (unsupported != 0)
        {
            throw new InvalidOperationException(
                "TEMP_BACKUP_STATE_UNSUPPORTED_ATTRIBUTES: " + description +
                " has unsupported attributes 0x" + unsupported.ToString("x8")
            );
        }
    }

    private static void SuppressAccessTimeUpdate(
        SafeFileHandle handle,
        string description
    )
    {
        // Documented SetFileTime sentinel: a last-access FILETIME with both
        // DWORDs set to 0xffffffff prevents this handle's subsequent reads
        // from changing LastAccessTime; it does not assign that sentinel as
        // the persisted timestamp.  This is required before BackupRead so the
        // act of full-state observation does not invalidate the state itself.
        IntPtr sentinel = Marshal.AllocHGlobal(8);
        try
        {
            Marshal.WriteInt32(sentinel, 0, -1);
            Marshal.WriteInt32(sentinel, 4, -1);
            if (!SetFileTime(
                handle,
                IntPtr.Zero,
                sentinel,
                IntPtr.Zero
            ))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "TEMP_ACCESS_TIME_SUPPRESSION_FAILED: " + description
                );
            }
        }
        finally
        {
            Marshal.FreeHGlobal(sentinel);
        }
    }

    private static ExactBackupState CaptureBackupStateOnce(
        SafeFileHandle handle,
        bool isDirectory,
        string description
    )
    {
        RequireDisk(handle, description);
        SuppressAccessTimeUpdate(handle, description);
        BY_HANDLE_FILE_INFORMATION before = ReadInformation(handle, description);
        bool observedDirectory =
            (before.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (observedDirectory != isDirectory)
        {
            throw new InvalidOperationException(
                "TEMP_BACKUP_STATE_TYPE_CHANGED: " + description
            );
        }
        if (!isDirectory && before.NumberOfLinks != 1)
        {
            throw new InvalidOperationException(
                "TEMP_BACKUP_STATE_LINK_COUNT: " + description +
                " must have exactly one link; observed " + before.NumberOfLinks
            );
        }
        RequireSupportedAttributes(before.FileAttributes, description);
        FILE_BASIC_INFO basicBefore = ReadBasicInfo(handle, description);
        RequireSupportedAttributes(basicBefore.FileAttributes, description);

        IntPtr context = IntPtr.Zero;
        SHA256 fullHasher = SHA256.Create();
        SHA256 securityHasher = SHA256.Create();
        List<string> inventory = new List<string>();
        int dataStreams = 0;
        int securityStreams = 0;
        int eaStreams = 0;
        int objectIdStreams = 0;
        long dataStreamSize = -1;
        long securityStreamSize = -1;
        try
        {
            while (true)
            {
                byte[] header = ReadBackupExact(
                    handle,
                    WIN32_STREAM_ID_HEADER_BYTES,
                    true,
                    ref context,
                    description + " stream header"
                );
                if (header == null)
                {
                    break;
                }
                HashBlock(fullHasher, header, header.Length);
                uint streamId = BitConverter.ToUInt32(header, 0);
                uint streamAttributes = BitConverter.ToUInt32(header, 4);
                long streamSize = BitConverter.ToInt64(header, 8);
                uint nameBytes = BitConverter.ToUInt32(header, 16);
                if (streamSize < 0 || nameBytes > MAX_BACKUP_STREAM_NAME_BYTES ||
                    (nameBytes & 1) != 0)
                {
                    throw new InvalidDataException(
                        "TEMP_BACKUP_STATE_INVALID_HEADER: " + description +
                        " id=" + streamId + " size=" + streamSize +
                        " name_bytes=" + nameBytes
                    );
                }
                if ((streamAttributes & ~0x00000007U) != 0)
                {
                    throw new InvalidOperationException(
                        "TEMP_BACKUP_STATE_UNSUPPORTED_STREAM_ATTRIBUTES: " +
                        description + " id=" + streamId + " attributes=0x" +
                        streamAttributes.ToString("x8")
                    );
                }
                switch (streamId)
                {
                    case BACKUP_DATA:
                        dataStreams++;
                        dataStreamSize = streamSize;
                        if (nameBytes != 0)
                        {
                            throw new InvalidDataException(
                                "TEMP_BACKUP_STATE_DEFAULT_DATA_NAME: " + description
                            );
                        }
                        break;
                    case BACKUP_EA_DATA:
                        eaStreams++;
                        if (nameBytes != 0)
                        {
                            throw new InvalidDataException(
                                "TEMP_BACKUP_STATE_EA_NAME: " + description
                            );
                        }
                        break;
                    case BACKUP_OBJECT_ID:
                        objectIdStreams++;
                        if (nameBytes != 0)
                        {
                            throw new InvalidDataException(
                                "TEMP_BACKUP_STATE_OBJECT_ID_NAME: " + description
                            );
                        }
                        break;
                    case BACKUP_SECURITY_DATA:
                        securityStreams++;
                        securityStreamSize = streamSize;
                        if (nameBytes != 0)
                        {
                            throw new InvalidDataException(
                                "TEMP_BACKUP_STATE_SECURITY_NAME: " + description
                            );
                        }
                        break;
                    case BACKUP_ALTERNATE_DATA:
                        throw new InvalidOperationException(
                            "TEMP_BACKUP_STATE_ALTERNATE_DATA_STREAM: " + description
                        );
                    case BACKUP_LINK:
                        throw new InvalidOperationException(
                            "TEMP_BACKUP_STATE_UNSUPPORTED_LINK: " + description
                        );
                    case BACKUP_PROPERTY_DATA:
                        throw new InvalidOperationException(
                            "TEMP_BACKUP_STATE_UNSUPPORTED_PROPERTY: " + description
                        );
                    case BACKUP_REPARSE_DATA:
                        throw new InvalidOperationException(
                            "TEMP_BACKUP_STATE_UNSUPPORTED_REPARSE: " + description
                        );
                    case BACKUP_SPARSE_BLOCK:
                        throw new InvalidOperationException(
                            "TEMP_BACKUP_STATE_UNSUPPORTED_SPARSE: " + description
                        );
                    case BACKUP_TXFS_DATA:
                        throw new InvalidOperationException(
                            "TEMP_BACKUP_STATE_UNSUPPORTED_TXFS: " + description
                        );
                    default:
                        throw new InvalidOperationException(
                            "TEMP_BACKUP_STATE_UNKNOWN_STREAM_ID: " + description +
                            " id=" + streamId
                        );
                }

                byte[] name = nameBytes == 0
                    ? new byte[0]
                    : ReadBackupExact(
                        handle,
                        checked((int)nameBytes),
                        false,
                        ref context,
                        description + " stream name"
                    );
                HashBlock(fullHasher, name, name.Length);
                string nameToken = Convert.ToBase64String(name);
                inventory.Add(
                    streamId.ToString(CultureInfo.InvariantCulture) + ":" +
                    streamAttributes.ToString(CultureInfo.InvariantCulture) + ":" +
                    streamSize.ToString(CultureInfo.InvariantCulture) + ":" +
                    nameToken
                );

                long remaining = streamSize;
                byte[] payload = new byte[65536];
                while (remaining > 0)
                {
                    int requested = (int)Math.Min((long)payload.Length, remaining);
                    byte[] part = ReadBackupExact(
                        handle,
                        requested,
                        false,
                        ref context,
                        description + " stream payload"
                    );
                    HashBlock(fullHasher, part, part.Length);
                    if (streamId == BACKUP_SECURITY_DATA)
                    {
                        HashBlock(securityHasher, part, part.Length);
                    }
                    remaining -= part.Length;
                }
            }
        }
        finally
        {
            uint ignored;
            bool aborted = BackupRead(
                handle,
                null,
                0,
                out ignored,
                true,
                true,
                ref context
            );
            if (!aborted)
            {
                fullHasher.Dispose();
                securityHasher.Dispose();
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "TEMP_BACKUP_STATE_ABORT_FAILED: " + description
                );
            }
        }

        try
        {
            int expectedDataStreams = isDirectory ? 0 : 1;
            if (dataStreams != expectedDataStreams)
            {
                throw new InvalidDataException(
                    "TEMP_BACKUP_STATE_DEFAULT_DATA_COUNT: " + description +
                    " observed " + dataStreams + ", expected " +
                    expectedDataStreams
                );
            }
            if (securityStreams != 1)
            {
                throw new InvalidDataException(
                    "TEMP_BACKUP_STATE_SECURITY_COUNT: " + description +
                    " observed " + securityStreams +
                    "; security metadata is unevaluable"
                );
            }
            if (securityStreamSize <= 0)
            {
                throw new InvalidDataException(
                    "TEMP_BACKUP_STATE_SECURITY_EMPTY: " + description
                );
            }
            if (eaStreams > 1 || objectIdStreams > 1)
            {
                throw new InvalidDataException(
                    "TEMP_BACKUP_STATE_DUPLICATE_METADATA_STREAM: " + description +
                    " ea=" + eaStreams + " object_id=" + objectIdStreams
                );
            }
            BY_HANDLE_FILE_INFORMATION after = ReadInformation(handle, description);
            ulong fileSize = ((ulong)before.FileSizeHigh << 32) |
                (ulong)before.FileSizeLow;
            if (!isDirectory &&
                (dataStreamSize < 0 || (ulong)dataStreamSize != fileSize))
            {
                throw new InvalidDataException(
                    "TEMP_BACKUP_STATE_DEFAULT_DATA_SIZE: " + description +
                    " backup_size=" + dataStreamSize + " file_size=" + fileSize
                );
            }
            FILE_BASIC_INFO basicAfter = ReadBasicInfo(handle, description);
            string basicAfterCanonical = CanonicalBasicInfo(basicAfter);
            if (!String.Equals(
                    GetIdentityFromInformation(after),
                    GetIdentityFromInformation(before),
                    StringComparison.Ordinal
                ) ||
                after.NumberOfLinks != before.NumberOfLinks ||
                after.FileAttributes != before.FileAttributes ||
                after.FileSizeHigh != before.FileSizeHigh ||
                after.FileSizeLow != before.FileSizeLow)
            {
                throw new InvalidOperationException(
                    "TEMP_BACKUP_STATE_CHANGED_DURING_READ: " + description
                );
            }
            string backupSha256 = HexDigest(fullHasher);
            string securitySha256 = HexDigest(securityHasher);
            string streamInventory = String.Join(";", inventory.ToArray());
            string canonical = basicAfterCanonical + "," + backupSha256 + "," +
                securitySha256 + "," + streamInventory;
            return new ExactBackupState
            {
                Canonical = canonical,
                BackupSha256 = backupSha256,
                SecuritySha256 = securitySha256,
                StreamInventory = streamInventory,
                BasicInfo = basicAfterCanonical
            };
        }
        finally
        {
            fullHasher.Dispose();
            securityHasher.Dispose();
        }
    }

    private static ExactBackupState CaptureBackupState(
        SafeFileHandle handle,
        bool isDirectory,
        string description
    )
    {
        // Reading backup data can itself advance or defer LastAccessTime.  The
        // retained handle denies WRITE and DELETE sharing, so obtain two
        // consecutive identical post-observation states rather than comparing
        // the pre-read atime with the side effects of that same read.  Every
        // ordinary data/security byte is still streamed and hashed each pass.
        ExactBackupState previous = null;
        const int MAX_CONVERGENCE_PASSES = 8;
        for (int pass = 1; pass <= MAX_CONVERGENCE_PASSES; pass++)
        {
            ExactBackupState current = CaptureBackupStateOnce(
                handle,
                isDirectory,
                description + " convergence_pass=" + pass
            );
            if (previous != null && String.Equals(
                previous.Canonical,
                current.Canonical,
                StringComparison.Ordinal
            ))
            {
                return current;
            }
            previous = current;
        }
        throw new InvalidOperationException(
            "TEMP_BACKUP_STATE_NONCONVERGENT: " + description +
            " did not yield two consecutive identical exact states in " +
            MAX_CONVERGENCE_PASSES + " passes"
        );
    }

    private static string GetIdentityFromInformation(
        BY_HANDLE_FILE_INFORMATION information
    )
    {
        // Used only as a stable before/after comparison on the same retained
        // handle.  Public protocol identity remains FILE_ID_INFO based.
        return information.VolumeSerialNumber.ToString("x8") + ":" +
            information.FileIndexHigh.ToString("x8") + ":" +
            information.FileIndexLow.ToString("x8");
    }

    private static string BuildRecord(
        string rootPath,
        string entryPath,
        SafeFileHandle handle,
        BY_HANDLE_FILE_INFORMATION information,
        string exactBackupState,
        string shortNameToken
    )
    {
        string finalPath = GetFinalPath(handle);
        string expectedPath = Path.GetFullPath(entryPath).TrimEnd('\\', '/');
        if (!String.Equals(finalPath, expectedPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "TEMP entry path changed before retained-handle classification ('" +
                expectedPath + "' -> '" + finalPath + "')"
            );
        }
        string prefix = rootPath + Path.DirectorySeparatorChar;
        if (!finalPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "TEMP entry escaped its exact retained root: " + finalPath
            );
        }
        string relative = finalPath.Substring(prefix.Length);
        if (String.IsNullOrEmpty(relative) || Path.IsPathRooted(relative) ||
            relative.IndexOf('\0') >= 0)
        {
            throw new InvalidOperationException("TEMP entry has an invalid relative path");
        }
        bool isDirectory =
            (information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if ((information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            throw new InvalidOperationException(
                "TEMP tree contains a reparse entry and is not recursively deletable: " +
                finalPath
            );
        }
        if (!isDirectory && information.NumberOfLinks != 1)
        {
            throw new InvalidOperationException(
                "TEMP file must have exactly one filesystem link; observed " +
                information.NumberOfLinks + ": " + finalPath
            );
        }
        ulong size = ((ulong)information.FileSizeHigh << 32) |
            (ulong)information.FileSizeLow;
        if (String.IsNullOrEmpty(exactBackupState))
        {
            throw new InvalidOperationException(
                "TEMP snapshot requires one exact backup/basic/security state digest"
            );
        }
        if (String.IsNullOrEmpty(shortNameToken))
        {
            throw new InvalidOperationException(
                "TEMP snapshot requires one exact short-name namespace token"
            );
        }
        return (isDirectory ? "D" : "F") + "|" +
            EncodeRelativePath(relative) + "|" +
            GetIdentity(handle) + "|" +
            Convert.ToBase64String(
                new UTF8Encoding(false, true).GetBytes(exactBackupState)
            ) + "|" + shortNameToken;
    }

    private static ExactDirectoryEntry[] EnumerateExactDirectoryEntries(
        SafeFileHandle directory,
        string description
    )
    {
        RequireOrdinaryDirectory(directory, description);
        SuppressAccessTimeUpdate(directory, description);
        string directoryPath = GetFinalPath(directory);
        List<ExactDirectoryEntry> entries = new List<ExactDirectoryEntry>();
        IntPtr buffer = Marshal.AllocHGlobal(DIRECTORY_ENUMERATION_BUFFER_BYTES);
        try
        {
            while (true)
            {
                for (int index = 0; index < DIRECTORY_ENUMERATION_BUFFER_BYTES; index++)
                {
                    Marshal.WriteByte(buffer, index, 0);
                }
                if (!GetFileInformationByHandleEx(
                    directory,
                    FILE_ID_BOTH_DIRECTORY_INFO_CLASS,
                    buffer,
                    DIRECTORY_ENUMERATION_BUFFER_BYTES
                ))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == ERROR_NO_MORE_FILES)
                    {
                        break;
                    }
                    throw new Win32Exception(
                        error,
                        "TEMP_DIRECTORY_ENUMERATION_FAILED: " + description
                    );
                }

                int offset = 0;
                while (true)
                {
                    if (offset < 0 ||
                        offset > DIRECTORY_ENUMERATION_BUFFER_BYTES -
                            FILE_ID_BOTH_DIRECTORY_NAME_OFFSET)
                    {
                        throw new InvalidDataException(
                            "TEMP_DIRECTORY_ENUMERATION_OFFSET_INVALID: " + description
                        );
                    }
                    int nextOffset = Marshal.ReadInt32(buffer, offset);
                    int nameBytes = Marshal.ReadInt32(buffer, offset + 60);
                    byte shortNameBytes = Marshal.ReadByte(buffer, offset + 68);
                    if (nameBytes < 0 || (nameBytes & 1) != 0 ||
                        nameBytes > DIRECTORY_ENUMERATION_BUFFER_BYTES - offset -
                            FILE_ID_BOTH_DIRECTORY_NAME_OFFSET)
                    {
                        throw new InvalidDataException(
                            "TEMP_DIRECTORY_ENUMERATION_NAME_INVALID: " + description
                        );
                    }
                    if (shortNameBytes > 24 || (shortNameBytes & 1) != 0)
                    {
                        throw new InvalidDataException(
                            "TEMP_DIRECTORY_ENUMERATION_SHORT_NAME_INVALID: " +
                            description + " short_name_bytes=" + shortNameBytes
                        );
                    }
                    byte[] shortName = new byte[shortNameBytes];
                    if (shortNameBytes > 0)
                    {
                        Marshal.Copy(
                            IntPtr.Add(buffer, offset + 70),
                            shortName,
                            0,
                            shortNameBytes
                        );
                    }
                    string shortNameToken = shortNameBytes == 0
                        ? "-"
                        : Convert.ToBase64String(shortName);
                    string name = Marshal.PtrToStringUni(
                        IntPtr.Add(
                            buffer,
                            offset + FILE_ID_BOTH_DIRECTORY_NAME_OFFSET
                        ),
                        nameBytes / 2
                    );
                    if (name != "." && name != "..")
                    {
                        if (String.IsNullOrEmpty(name) || name.IndexOf('\0') >= 0 ||
                            name.IndexOf('\\') >= 0 || name.IndexOf('/') >= 0 ||
                            name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                        {
                            throw new InvalidDataException(
                                "TEMP_DIRECTORY_ENUMERATION_LEAF_INVALID: " + description
                            );
                        }
                        entries.Add(new ExactDirectoryEntry
                        {
                            Path = Path.Combine(directoryPath, name),
                            ShortNameToken = shortNameToken
                        });
                    }
                    if (nextOffset == 0)
                    {
                        break;
                    }
                    if (nextOffset < FILE_ID_BOTH_DIRECTORY_NAME_OFFSET ||
                        nextOffset > DIRECTORY_ENUMERATION_BUFFER_BYTES - offset)
                    {
                        throw new InvalidDataException(
                            "TEMP_DIRECTORY_ENUMERATION_NEXT_OFFSET_INVALID: " +
                            description
                        );
                    }
                    offset = checked(offset + nextOffset);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        ExactDirectoryEntry[] result = entries.ToArray();
        Array.Sort(result, delegate(
            ExactDirectoryEntry left,
            ExactDirectoryEntry right
        ) {
            return StringComparer.Ordinal.Compare(left.Path, right.Path);
        });
        return result;
    }

    private static string GetExactShortNameToken(string path)
    {
        string full = Path.GetFullPath(path);
        string parent = Path.GetDirectoryName(full);
        using (SafeFileHandle directory = OpenExactDirectoryBackupObserver(parent))
        {
            ExactDirectoryEntry[] entries = EnumerateExactDirectoryEntries(
                directory,
                "exact TEMP parent short-name inventory " + parent
            );
            string token = null;
            foreach (ExactDirectoryEntry entry in entries)
            {
                if (String.Equals(entry.Path, full, StringComparison.OrdinalIgnoreCase))
                {
                    if (token != null)
                    {
                        throw new InvalidDataException(
                            "TEMP_DIRECTORY_ENUMERATION_DUPLICATE_PATH: " + full
                        );
                    }
                    if (!String.Equals(entry.Path, full, StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException(
                            "TEMP_DIRECTORY_ENUMERATION_CASE_DRIFT: expected exact long path '" +
                            full + "' but parent enumerated '" + entry.Path + "'"
                        );
                    }
                    token = entry.ShortNameToken;
                }
            }
            if (token == null)
            {
                throw new FileNotFoundException(
                    "TEMP_DIRECTORY_ENUMERATION_ENTRY_MISSING: " + full,
                    full
                );
            }
            return token;
        }
    }

    private static void CaptureDirectory(
        string rootPath,
        SafeFileHandle directory,
        List<string> records,
        int depth
    )
    {
        if (depth > MAX_TREE_DEPTH)
        {
            throw new InvalidOperationException(
                "TEMP tree exceeds the supported depth of " + MAX_TREE_DEPTH
            );
        }
        ExactDirectoryEntry[] entries = EnumerateExactDirectoryEntries(
            directory,
            "exact TEMP directory at depth " + depth
        );
        foreach (ExactDirectoryEntry directoryEntry in entries)
        {
            string entry = directoryEntry.Path;
            using (SafeFileHandle handle = OpenEntry(
                entry,
                GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES |
                    FILE_WRITE_ATTRIBUTES,
                FILE_SHARE_READ,
                "exact TEMP mutation-denying snapshot entry"
            ))
            {
                BY_HANDLE_FILE_INFORMATION information =
                    ReadInformation(handle, "exact TEMP snapshot entry");
                bool isDirectory =
                    (information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                if (isDirectory)
                {
                    CaptureDirectory(rootPath, handle, records, depth + 1);
                }
                ExactBackupState backupState = CaptureBackupState(
                    handle,
                    isDirectory,
                    "exact TEMP snapshot entry " + entry
                );
                information = ReadInformation(
                    handle,
                    "exact TEMP snapshot entry after backup-state digest"
                );
                string record = BuildRecord(
                    rootPath,
                    entry,
                    handle,
                    information,
                    backupState.Canonical,
                    directoryEntry.ShortNameToken
                );
                records.Add(record);
            }
        }
    }

    public static string[] CaptureExactTreeEntries(SafeFileHandle root)
    {
        RequireOrdinaryDirectory(root, "exact TEMP mutation directory");
        string rootPath = GetFinalPath(root);
        List<string> records = new List<string>();
        string rootId = GetIdentity(root);
        using (SafeFileHandle observer = OpenExactDirectoryBackupObserver(rootPath))
        {
            if (!String.Equals(GetIdentity(observer), rootId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "TEMP tree observer bound a different retained root FILE_ID"
                );
            }
            CaptureDirectory(rootPath, observer, records, 0);
            if (!String.Equals(GetIdentity(observer), rootId, StringComparison.Ordinal) ||
                !String.Equals(GetIdentity(root), rootId, StringComparison.Ordinal) ||
                !String.Equals(GetFinalPath(observer), rootPath, StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(GetFinalPath(root), rootPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "TEMP tree root identity/path changed during exact enumeration"
                );
            }
        }
        string[] result = records.ToArray();
        Array.Sort(result, StringComparer.Ordinal);
        return result;
    }

    public static string CaptureExactRootState(SafeFileHandle root)
    {
        RequireOrdinaryDirectory(root, "exact TEMP retained root");
        string rootPath = GetFinalPath(root);
        string rootId = GetIdentity(root);
        using (SafeFileHandle observer = OpenExactDirectoryBackupObserver(rootPath))
        {
            if (!String.Equals(GetIdentity(observer), rootId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "TEMP root backup-state observer bound a different FILE_ID"
                );
            }
            ExactBackupState state = CaptureBackupState(
                observer,
                true,
                "exact TEMP retained root " + rootPath
            );
            if (!String.Equals(GetIdentity(root), rootId, StringComparison.Ordinal) ||
                !String.Equals(GetIdentity(observer), rootId, StringComparison.Ordinal) ||
                !String.Equals(GetFinalPath(root), rootPath, StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(GetFinalPath(observer), rootPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "TEMP root identity/path changed during backup-state digest"
                );
            }
            return Convert.ToBase64String(
                new UTF8Encoding(false, true).GetBytes(state.Canonical)
            );
        }
    }

    public static SafeFileHandle ProtectExactLiveDirectoryForCleanup(
        SafeFileHandle liveRoot,
        string expectedPath,
        string expectedFileId,
        string expectedRootState
    )
    {
        RequireOrdinaryDirectory(liveRoot, "continuously retained live TEMP root");
        string path = Path.GetFullPath(expectedPath).TrimEnd('\\', '/');
        if (!String.Equals(GetFinalPath(liveRoot), path, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(GetIdentity(liveRoot), expectedFileId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "live TEMP root changed before cleanup-protection transfer"
            );
        }
        SafeFileHandle observer = null;
        SafeFileHandle protectedRoot = null;
        try
        {
            observer = OpenExactDirectoryBackupObserver(path);
            ExactBackupState observerState = CaptureBackupState(
                observer,
                true,
                "live TEMP cleanup-transfer observer"
            );
            string observerToken = Convert.ToBase64String(
                new UTF8Encoding(false, true).GetBytes(observerState.Canonical)
            );
            if (!String.Equals(GetIdentity(observer), expectedFileId, StringComparison.Ordinal) ||
                !String.Equals(observerToken, expectedRootState, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "live TEMP cleanup-transfer observer differs from captured root state"
                );
            }

            // The shared observer pins the exact FILE_ID while the original
            // long-lived DELETE-denying lease is released.  The new handle is
            // opened only by the cleanup-tombstone name and denies both WRITE
            // and DELETE sharing.  A concurrent rename/replacement can only
            // make this open or the exact identity comparison fail; it never
            // authorizes mutation of the replacement.
            liveRoot.Dispose();
            protectedRoot = OpenExactDirectoryMutation(path);
            ExactBackupState protectedState = CaptureBackupState(
                protectedRoot,
                true,
                "cleanup-protected exact TEMP root"
            );
            string protectedToken = Convert.ToBase64String(
                new UTF8Encoding(false, true).GetBytes(protectedState.Canonical)
            );
            if (!String.Equals(GetIdentity(protectedRoot), expectedFileId, StringComparison.Ordinal) ||
                !String.Equals(GetIdentity(observer), expectedFileId, StringComparison.Ordinal) ||
                !String.Equals(protectedToken, expectedRootState, StringComparison.Ordinal) ||
                !String.Equals(GetFinalPath(protectedRoot), path, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "cleanup-protected TEMP root differs from the retained transfer observer"
                );
            }
            SafeFileHandle result = protectedRoot;
            protectedRoot = null;
            return result;
        }
        finally
        {
            if (protectedRoot != null)
            {
                protectedRoot.Dispose();
            }
            if (observer != null)
            {
                observer.Dispose();
            }
        }
    }

    private static bool EqualExact(string[] left, string[] right)
    {
        if (left == null || right == null || left.Length != right.Length)
        {
            return false;
        }
        for (int index = 0; index < left.Length; index++)
        {
            if (!String.Equals(left[index], right[index], StringComparison.Ordinal))
            {
                return false;
            }
        }
        return true;
    }

    private static ExpectedEntry ParseExpectedEntry(string record)
    {
        string[] parts = record.Split(new char[] { '|' });
        if (parts.Length != 5 || (parts[0] != "D" && parts[0] != "F"))
        {
            throw new InvalidOperationException("TEMP tree snapshot record is malformed");
        }
        string relative = DecodeRelativePath(parts[1]);
        if (String.IsNullOrEmpty(relative) || Path.IsPathRooted(relative) ||
            relative == "." || relative == ".." || relative.IndexOf('\0') >= 0)
        {
            throw new InvalidOperationException("TEMP tree snapshot relative path is invalid");
        }
        string[] components = relative.Split(
            new char[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
            StringSplitOptions.RemoveEmptyEntries
        );
        if (components.Length == 0)
        {
            throw new InvalidOperationException("TEMP tree snapshot relative path is empty");
        }
        foreach (string component in components)
        {
            if (component == "." || component == "..")
            {
                throw new InvalidOperationException("TEMP tree snapshot relative path traverses its root");
            }
        }
        string exactBackupState;
        try
        {
            UTF8Encoding utf8 = new UTF8Encoding(false, true);
            byte[] stateBytes = Convert.FromBase64String(parts[3]);
            exactBackupState = utf8.GetString(stateBytes);
            if (Convert.ToBase64String(utf8.GetBytes(exactBackupState)) != parts[3] ||
                String.IsNullOrEmpty(exactBackupState))
            {
                throw new InvalidDataException("non-canonical backup-state token");
            }
        }
        catch (Exception fault)
        {
            throw new InvalidOperationException(
                "TEMP tree snapshot backup-state token is invalid",
                fault
            );
        }
        string shortNameToken = parts[4];
        if (shortNameToken != "-")
        {
            try
            {
                byte[] shortNameBytes = Convert.FromBase64String(shortNameToken);
                if (shortNameBytes.Length == 0 || shortNameBytes.Length > 24 ||
                    (shortNameBytes.Length & 1) != 0 ||
                    Convert.ToBase64String(shortNameBytes) != shortNameToken)
                {
                    throw new InvalidDataException("non-canonical short-name token");
                }
            }
            catch (Exception fault)
            {
                throw new InvalidOperationException(
                    "TEMP tree snapshot short-name token is invalid",
                    fault
                );
            }
        }
        return new ExpectedEntry
        {
            IsDirectory = parts[0] == "D",
            RelativePath = relative,
            FileId = parts[2],
            ExactBackupState = exactBackupState,
            ShortNameToken = shortNameToken,
            ExactRecord = record,
            Depth = components.Length
        };
    }

    private static void SetDisposition(
        SafeFileHandle handle,
        string description
    )
    {
        IntPtr information = Marshal.AllocHGlobal(1);
        try
        {
            Marshal.WriteByte(information, 0, 1);
            if (!SetFileInformationByHandle(
                handle,
                FILE_DISPOSITION_INFO_CLASS,
                information,
                1
            ))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "exact retained-handle disposition failed for " + description
                );
            }
        }
        finally
        {
            Marshal.FreeHGlobal(information);
        }
    }

    private static void RequirePathAbsent(string path)
    {
        uint attributes = GetFileAttributesW(path);
        if (attributes != INVALID_FILE_ATTRIBUTES)
        {
            throw new IOException("path remained present after exact disposition: " + path);
        }
        int error = Marshal.GetLastWin32Error();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
        {
            throw new Win32Exception(
                error,
                "path absence is unevaluable after exact disposition: " + path
            );
        }
    }

    public static void DeleteExactTreeContents(
        SafeFileHandle root,
        string[] expectedEntries
    )
    {
        RequireOrdinaryDirectory(root, "exact TEMP mutation directory");
        string rootPath = GetFinalPath(root);
        string[] current = CaptureExactTreeEntries(root);
        if (!EqualExact(current, expectedEntries))
        {
            throw new InvalidOperationException(
                "TEMP tree changed between retained snapshots and exact deletion"
            );
        }

        List<ExpectedEntry> parsed = new List<ExpectedEntry>();
        HashSet<string> paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string record in expectedEntries)
        {
            ExpectedEntry entry = ParseExpectedEntry(record);
            if (!paths.Add(entry.RelativePath))
            {
                throw new InvalidOperationException(
                    "TEMP tree snapshot contains a duplicate Windows path identity: " +
                    entry.RelativePath
                );
            }
            parsed.Add(entry);
        }
        parsed.Sort(delegate(ExpectedEntry left, ExpectedEntry right)
        {
            int depth = right.Depth.CompareTo(left.Depth);
            if (depth != 0)
            {
                return depth;
            }
            return StringComparer.Ordinal.Compare(right.RelativePath, left.RelativePath);
        });

        foreach (ExpectedEntry expected in parsed)
        {
            string path = Path.GetFullPath(Path.Combine(rootPath, expected.RelativePath));
            string prefix = rootPath + Path.DirectorySeparatorChar;
            if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "TEMP deletion candidate escaped its exact root: " + path
                );
            }
            uint desiredAccess = DELETE_ACCESS | FILE_READ_ATTRIBUTES;
            desiredAccess |= GENERIC_READ | READ_CONTROL | FILE_WRITE_ATTRIBUTES;
            using (SafeFileHandle handle = OpenEntry(
                path,
                desiredAccess,
                FILE_SHARE_READ,
                "exact TEMP deletion entry"
            ))
            {
                BY_HANDLE_FILE_INFORMATION information =
                    ReadInformation(handle, "exact TEMP deletion entry");
                bool isDirectory =
                    (information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                if ((information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                    isDirectory != expected.IsDirectory)
                {
                    throw new InvalidOperationException(
                        "TEMP deletion candidate changed type or became a reparse entry: " + path
                    );
                }
                ExactBackupState backupBefore = CaptureBackupState(
                    handle,
                    expected.IsDirectory,
                    "exact TEMP deletion entry " + path
                );
                information = ReadInformation(
                    handle,
                    "exact TEMP deletion entry after backup-state digest"
                );
                string currentRecord = BuildRecord(
                    rootPath,
                    path,
                    handle,
                    information,
                    backupBefore.Canonical,
                    GetExactShortNameToken(path)
                );
                string currentId = currentRecord.Split(new char[] { '|' })[2];
                if (!String.Equals(currentId, expected.FileId, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "TEMP deletion candidate FILE_ID differs from its retained snapshot: " +
                        path
                    );
                }
                if (!String.Equals(
                    currentRecord,
                    expected.ExactRecord,
                    StringComparison.Ordinal
                ))
                {
                    throw new InvalidOperationException(
                        "TEMP entry backup/basic/security state changed before exact deletion: " +
                        path
                    );
                }
                // FileDispositionInfo=TRUE is the final handle operation.  The
                // using scope closes this same retained handle immediately;
                // Windows permits no metadata/read query after disposition.
                // The unavoidable final metadata race is tracked by #620.
                SetDisposition(handle, path);
            }
            RequirePathAbsent(path);
        }

        string[] remaining = CaptureExactTreeEntries(root);
        if (remaining.Length != 0)
        {
            throw new InvalidOperationException(
                "TEMP tree received an unclassified concurrent addition during deletion: " +
                String.Join(",", remaining)
            );
        }
    }

    public static void RenameExactDirectoryNoReplace(
        SafeFileHandle source,
        SafeFileHandle destinationDirectory,
        string destinationLeaf
    )
    {
        RequireOrdinaryDirectory(source, "exact TEMP rename source");
        RequireOrdinaryDirectory(
            destinationDirectory,
            "exact pinned TEMP rename destination parent"
        );
        if (String.IsNullOrEmpty(destinationLeaf) ||
            destinationLeaf.IndexOf('\0') >= 0 ||
            destinationLeaf.IndexOf('\\') >= 0 ||
            destinationLeaf.IndexOf('/') >= 0 ||
            destinationLeaf.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            destinationLeaf.EndsWith(" ", StringComparison.Ordinal) ||
            destinationLeaf.EndsWith(".", StringComparison.Ordinal) ||
            destinationLeaf == "." || destinationLeaf == "..")
        {
            throw new ArgumentException(
                "exact TEMP rename destination must be one simple filename",
                "destinationLeaf"
            );
        }
        if (GetVolume(source) != GetVolume(destinationDirectory))
        {
            throw new InvalidOperationException(
                "exact TEMP source and destination directory are on different volumes"
            );
        }
        string parent = GetFinalPath(destinationDirectory);
        string destination = Path.Combine(parent, destinationLeaf);
        byte[] nameBytes = Encoding.Unicode.GetBytes(destination);
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
            // The public Win32 FILE_RENAME_INFO contract requires RootDirectory NULL.
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
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "exact handle-bound TEMP no-replace rename failed"
                );
            }
        }
        finally
        {
            Marshal.FreeHGlobal(information);
        }
    }

    public static void MarkExactDirectoryDeletePending(
        SafeFileHandle root,
        string expectedRootState
    )
    {
        RequireOrdinaryDirectory(root, "exact TEMP mutation directory");
        string[] remaining = CaptureExactTreeEntries(root);
        if (remaining.Length != 0)
        {
            throw new InvalidOperationException(
                "exact TEMP root cannot enter delete-pending while nonempty"
            );
        }
        ExactBackupState before = CaptureBackupState(
            root,
            true,
            "exact TEMP root before disposition"
        );
        string beforeToken = Convert.ToBase64String(
            new UTF8Encoding(false, true).GetBytes(before.Canonical)
        );
        if (!String.Equals(beforeToken, expectedRootState, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "TEMP root backup/basic/security state changed before exact disposition"
            );
        }
        // SetDisposition is the final filesystem call on this handle.  Dispose
        // immediately in the same native frame; callers perform namespace
        // absence readback only after this exact handle is closed.
        string rootPath = GetFinalPath(root);
        SetDisposition(root, rootPath);
        root.Dispose();
    }
}
'@
}

function New-AstroLauncherPreclaimScratchLease {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)]$DirectoryLease
    )

    $full = [IO.Path]::GetFullPath($Path)
    $leaf = [IO.Path]::GetFileName($full)
    if ($leaf -cnotmatch '^\.astro-preclaim-scratch\.[0-9a-f]{32}\.tmp\z') {
        throw 'preclaim scratch path must use the exact unreserved random grammar'
    }
    $parent = Assert-AstroLauncherPinnedDirectoryLease $DirectoryLease
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($full).TrimEnd('\', '/'),
            $parent.Path,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'preclaim scratch is not inside the retained protocol directory'
    }
    if ((Get-AstroPathEntryState $full).State -ne 'absent') {
        throw "preclaim scratch destination is not exactly absent: $full"
    }

    $deleteOnCloseHandle = $null
    $publisherHandle = $null
    try {
        $deleteOnCloseHandle =
            [AstroLauncherTempNative]::CreateDeleteOnCloseScratch($full)
        $deleteOnCloseFileId =
            [AstroLauncherTempNative]::GetExactSingleLinkFileIdentity(
                $deleteOnCloseHandle
            )
        $publisherHandle =
            [AstroLauncherTempNative]::OpenExactScratchPublisher($full)
        $publisherFileId =
            [AstroLauncherTempNative]::GetExactSingleLinkFileIdentity(
                $publisherHandle
            )
        if ($publisherFileId -cne $deleteOnCloseFileId) {
            throw 'scratch publisher and delete-on-close primary bind different FILE_IDs'
        }
        [AstroLauncherTempNative]::WriteExactScratchAndFlush(
            $publisherHandle,
            $Bytes
        )
        $snapshot = Get-AstroExactRetainedFileSnapshot `
            -Handle $publisherHandle `
            -ExpectedPath $full `
            -MaximumBytes $script:AstroLauncherLockMaxBytes
        if ($snapshot.Length -ne [uint64]$Bytes.LongLength -or
            [Convert]::ToBase64String($snapshot.Bytes) -cne
                [Convert]::ToBase64String($Bytes) -or
            [AstroLauncherTempNative]::GetExactFileLinkCount(
                $publisherHandle
            ) -ne 1) {
            throw 'durable delete-on-close scratch differs from its intended exact bytes or link count'
        }
        return [pscustomobject]@{
            Path = $full
            SafeFileHandle = $publisherHandle
            Handle = $publisherHandle
            Stream = $publisherHandle
            DeleteOnCloseHandle = $deleteOnCloseHandle
            DeleteOnCloseFileId = $deleteOnCloseFileId
            InitialSnapshot = $snapshot
            CurrentSnapshot = $snapshot
            Length = $snapshot.Length
            Sha256 = $snapshot.Sha256
            Bytes = $snapshot.Bytes
            DeleteOnClose = $true
            ScratchLinkClosed = $false
            Disposed = $false
        }
    }
    catch {
        $message = $_.Exception.Message
        if ($null -ne $deleteOnCloseHandle -and
            -not $deleteOnCloseHandle.IsClosed) {
            $deleteOnCloseHandle.Dispose()
        }
        if ($null -ne $publisherHandle -and
            -not $publisherHandle.IsClosed) {
            $publisherHandle.Dispose()
        }
        $terminal = Get-AstroPathEntryState $full
        throw "delete-on-close preclaim scratch construction failed (terminal_state=$($terminal.State), terminal_error=$($terminal.Error)): $message"
    }
}

function Close-AstroLauncherPreclaimScratchLease {
    param([Parameter(Mandatory)]$Lease)

    if ($null -ne $Lease -and
        $Lease.PSObject.Properties['DeleteOnCloseHandle'] -and
        $null -ne $Lease.DeleteOnCloseHandle -and
        -not $Lease.DeleteOnCloseHandle.IsClosed) {
        $Lease.DeleteOnCloseHandle.Dispose()
        $Lease.ScratchLinkClosed = $true
    }
    if ($null -ne $Lease -and $null -ne $Lease.SafeFileHandle -and
        -not $Lease.SafeFileHandle.IsClosed) {
        $Lease.SafeFileHandle.Dispose()
        $Lease.Disposed = $true
    }
}

function Complete-AstroLauncherPreclaimScratchPublication {
    param(
        [Parameter(Mandatory)]$ScratchLease,
        [Parameter(Mandatory)][string]$ClaimPath,
        [Parameter(Mandatory)][byte[]]$ExpectedBytes
    )

    $scratchPath = [IO.Path]::GetFullPath($ScratchLease.Path)
    $claimFull = [IO.Path]::GetFullPath($ClaimPath)
    if ($ScratchLease.SafeFileHandle.IsClosed -or
        $ScratchLease.DeleteOnCloseHandle.IsClosed) {
        throw 'preclaim publication requires both retained scratch handles'
    }
    if ([AstroLauncherTempNative]::GetExactFileLinkCount(
            $ScratchLease.SafeFileHandle
        ) -ne 2) {
        throw 'published preclaim object must have exactly scratch+claim links before scratch close'
    }

    $observer = $null
    $claimHandle = $null
    try {
        # A Windows delete-on-close name is not removed until every handle that
        # was opened through that name is closed.  First retain a read-only
        # observer opened through the published claim name; it shares the
        # publisher's WRITE/DELETE access and bridges the exact FILE_ID while
        # both scratch-path handles are released.
        $observer =
            [AstroLauncherTempNative]::OpenExactSharedPublicationObserver(
                $claimFull
            )
        $observerBefore = Get-AstroExactRetainedFileSnapshot `
            -Handle $observer `
            -ExpectedPath $claimFull `
            -MaximumBytes $script:AstroLauncherLockMaxBytes
        if ($observerBefore.FileId -cne
                $ScratchLease.CurrentSnapshot.FileId -or
            $observerBefore.Length -ne [uint64]$ExpectedBytes.LongLength -or
            $observerBefore.Sha256 -cne $ScratchLease.CurrentSnapshot.Sha256 -or
            [Convert]::ToBase64String($observerBefore.Bytes) -cne
                [Convert]::ToBase64String($ExpectedBytes) -or
            [AstroLauncherTempNative]::GetExactFileLinkCount($observer) -ne 2) {
            throw 'published claim observer differs from the exact two-link durable scratch object'
        }

        $ScratchLease.DeleteOnCloseHandle.Dispose()
        $ScratchLease.ScratchLinkClosed = $true
        # The publisher continues denying WRITE while the primary's
        # delete-on-close is armed.  Closing the publisher last retires the
        # scratch link atomically; the final-name observer then bridges the
        # immutable claim identity without exposing a writeable interval.
        $ScratchLease.SafeFileHandle.Dispose()
        $ScratchLease.Disposed = $true
        $scratchTerminal = Get-AstroPathEntryState $scratchPath
        if ($scratchTerminal.State -ne 'absent') {
            throw "delete-on-close scratch link is not absent after closing every scratch-path handle (state=$($scratchTerminal.State), error=$($scratchTerminal.Error)): $scratchPath"
        }
        if ([AstroLauncherTempNative]::GetExactFileLinkCount($observer) -ne 1) {
            throw 'published claim did not become the sole link after every scratch-path handle closed'
        }
        $observerAfter = Get-AstroExactRetainedFileSnapshot `
            -Handle $observer `
            -ExpectedPath $claimFull `
            -MaximumBytes $script:AstroLauncherLockMaxBytes
        if ($observerAfter.FileId -cne $observerBefore.FileId -or
            $observerAfter.Length -ne $observerBefore.Length -or
            $observerAfter.Sha256 -cne $observerBefore.Sha256 -or
            [Convert]::ToBase64String($observerAfter.Bytes) -cne
                [Convert]::ToBase64String($observerBefore.Bytes)) {
            throw 'published claim changed while the scratch name was retired'
        }

        # Establish the normal write/delete-denying claim lease only by the
        # final name, while the shared observer still pins the proven object.
        $claimHandle = [AstroLauncherLockNative]::OpenExactRenameSource($claimFull)
        $snapshot = Get-AstroExactRetainedFileSnapshot `
            -Handle $claimHandle `
            -ExpectedPath $claimFull `
            -MaximumBytes $script:AstroLauncherLockMaxBytes
        if ($snapshot.FileId -cne $observerAfter.FileId -or
            $snapshot.Length -ne $observerAfter.Length -or
            $snapshot.Sha256 -cne $observerAfter.Sha256 -or
            [Convert]::ToBase64String($snapshot.Bytes) -cne
                [Convert]::ToBase64String($ExpectedBytes) -or
            [AstroLauncherTempNative]::GetExactFileLinkCount(
                $claimHandle
            ) -ne 1) {
            throw 'final restrictive claim lease differs from its retained publication observer'
        }
        $observer.Dispose()
        $observer = $null
        if ([AstroLauncherTempNative]::GetExactFileLinkCount(
                $claimHandle
            ) -ne 1) {
            throw 'published claim gained another filesystem link before restrictive-lease handoff'
        }

        $state = Convert-AstroLauncherLockBytesToState $snapshot.Bytes $claimFull
        if ($state.State -eq 'unreadable') {
            throw "published launcher claim failed strict byte parsing: $($state.ValidationError)"
        }
        $result = [pscustomobject]@{
            Path = $claimFull
            Stream = $claimHandle
            SafeFileHandle = $claimHandle
            Handle = $claimHandle
            State = $state
            InitialSnapshot = $snapshot
            CurrentSnapshot = $snapshot
            Length = $snapshot.Length
            Sha256 = $snapshot.Sha256
            Bytes = $snapshot.Bytes
            Disposed = $false
            ScratchPath = $scratchPath
            ScratchTerminalState = $scratchTerminal.State
        }
        $claimHandle = $null
        return $result
    }
    catch {
        if ($null -ne $claimHandle -and -not $claimHandle.IsClosed) {
            $claimHandle.Dispose()
        }
        if ($null -ne $observer -and -not $observer.IsClosed) {
            $observer.Dispose()
        }
        throw
    }
}

function ConvertFrom-AstroLauncherTempName {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $leaf = [IO.Path]::GetFileName($full)
    $candidate = $leaf.StartsWith(
        $script:AstroLauncherTempReservedPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )
    $match = [Regex]::Match(
        $leaf,
        $script:AstroLauncherTempPidRegex,
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    $pidValue = 0
    $ticksValue = 0L
    if (-not $match.Success -or
        -not [int]::TryParse(
            $match.Groups['pid'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$pidValue
        ) -or $pidValue -le 0 -or
        -not [long]::TryParse(
            $match.Groups['ticks'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$ticksValue
        ) -or $ticksValue -le 0 -or
        $ticksValue -gt [DateTime]::MaxValue.Ticks) {
        return [pscustomobject]@{
            Kind = 'temp'
            Path = $full
            Leaf = $leaf
            Candidate = $candidate
            Valid = $false
            LauncherPid = $null
            LauncherProcessStartUtcTicks = $null
            LauncherLockSha256 = $null
            Nonce = $null
            Error = 'reserved launcher TEMP basename is not the exact canonical v2 grammar'
        }
    }
    return [pscustomobject]@{
        Kind = 'temp'
        Path = $full
        Leaf = $leaf
        Candidate = $true
        Valid = $true
        LauncherPid = $pidValue
        LauncherProcessStartUtcTicks = $ticksValue
        LauncherLockSha256 = $match.Groups['sha'].Value
        Nonce = $null
        Error = $null
    }
}

function ConvertFrom-AstroLauncherTempCleanupName {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $leaf = [IO.Path]::GetFileName($full)
    $candidate = $leaf.StartsWith(
        $script:AstroLauncherTempCleanupReservedPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )
    $match = [Regex]::Match(
        $leaf,
        $script:AstroLauncherTempCleanupV2Regex,
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    $pidValue = 0
    $ticksValue = 0L
    if (-not $match.Success -or
        -not [int]::TryParse(
            $match.Groups['pid'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$pidValue
        ) -or $pidValue -le 0 -or
        -not [long]::TryParse(
            $match.Groups['ticks'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$ticksValue
        ) -or $ticksValue -le 0 -or
        $ticksValue -gt [DateTime]::MaxValue.Ticks) {
        return [pscustomobject]@{
            Kind = 'temp-cleanup-tombstone'
            Path = $full
            Leaf = $leaf
            Candidate = $candidate
            Valid = $false
            LauncherPid = $null
            LauncherProcessStartUtcTicks = $null
            LauncherLockSha256 = $null
            Nonce = $null
            Error = 'reserved launcher TEMP cleanup basename is not the exact canonical v2 grammar'
        }
    }
    return [pscustomobject]@{
        Kind = 'temp-cleanup-tombstone'
        Path = $full
        Leaf = $leaf
        Candidate = $true
        Valid = $true
        LauncherPid = $pidValue
        LauncherProcessStartUtcTicks = $ticksValue
        LauncherLockSha256 = $match.Groups['sha'].Value
        Nonce = $match.Groups['nonce'].Value
        Error = $null
    }
}

function Get-AstroReservedLauncherTempPaths {
    param([Parameter(Mandatory)][string]$Directory)

    $context = Get-AstroAttributionProtocolContext $Directory
    $paths = [Collections.Generic.List[string]]::new()
    try {
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries(
                $context.Directory,
                '*',
                [IO.SearchOption]::TopDirectoryOnly
            )) {
            $leaf = [IO.Path]::GetFileName($entry)
            if ($leaf.StartsWith(
                    $script:AstroLauncherTempReservedPrefix,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                $leaf.StartsWith(
                    $script:AstroLauncherTempCleanupReservedPrefix,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                $paths.Add([IO.Path]::GetFullPath($entry))
            }
        }
    }
    catch {
        throw "could not enumerate every reserved launcher TEMP entry below '$($context.Directory)': $($_.Exception.Message)"
    }
    [string[]]$ordered = @($paths)
    [Array]::Sort($ordered, [StringComparer]::OrdinalIgnoreCase)
    return [pscustomobject]@{
        Context = $context
        Paths = $ordered
    }
}

function Get-AstroReservedLauncherTempEntries {
    param([Parameter(Mandatory)][string]$Directory)

    $inventory = Get-AstroReservedLauncherTempPaths $Directory
    $records = [Collections.Generic.List[object]]::new()
    foreach ($path in $inventory.Paths) {
        $leaf = [IO.Path]::GetFileName($path)
        $name = if ($leaf.StartsWith(
                $script:AstroLauncherTempCleanupReservedPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            ConvertFrom-AstroLauncherTempCleanupName $path
        } else {
            ConvertFrom-AstroLauncherTempName $path
        }
        $state = Get-AstroPathEntryState $path
        $validEntry = $name.Valid -and
            $state.State -eq 'present' -and
            ($state.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -and
            ($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0
        $fileId = $null
        $finalPath = $null
        $identityError = $null
        $identityHandle = $null
        if ($validEntry) {
            try {
                $identityHandle = [AstroLauncherTempNative]::OpenExactDirectoryIdentity(
                    $path
                )
                $fileId = [AstroLauncherTempNative]::GetExactDirectoryIdentity(
                    $identityHandle
                )
                $finalPath = [IO.Path]::GetFullPath(
                    [AstroLauncherTempNative]::GetExactDirectoryFinalPath(
                        $identityHandle
                    )
                ).TrimEnd('\', '/')
                if (-not [string]::Equals(
                        $path.TrimEnd('\', '/'),
                        $finalPath,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    [AstroLauncherTempNative]::GetExactDirectoryIdentity(
                        $identityHandle
                    ) -cne $fileId) {
                    throw 'reserved launcher TEMP path/FILE_ID changed during retained classification'
                }
            }
            catch {
                $validEntry = $false
                $identityError = $_.Exception.Message
            }
            finally {
                if ($null -ne $identityHandle) {
                    $identityHandle.Dispose()
                }
            }
        }
        $expectedTempPath = if ($name.Valid) {
            Join-Path $inventory.Context.Directory (
                Get-AstroLauncherTempLeaf `
                    $name.LauncherPid `
                    $name.LauncherProcessStartUtcTicks `
                    $name.LauncherLockSha256
            )
        } else {
            $null
        }
        $records.Add([pscustomobject]@{
            Kind = $name.Kind
            Path = $path
            ExpectedTempPath = $expectedTempPath
            Name = $name
            Valid = $validEntry
            State = $state
            FileId = $fileId
            FinalPath = $finalPath
            Error = if (-not $name.Valid) {
                $name.Error
            } elseif ($null -ne $identityError) {
                "reserved launcher TEMP identity is unevaluable: $identityError"
            } elseif (-not $validEntry) {
                "reserved launcher TEMP entry is not an evaluable ordinary directory (state=$($state.State), attributes=$($state.Attributes), error=$($state.Error))"
            } else {
                $null
            }
        })
    }
    return [pscustomobject]@{
        Context = $inventory.Context
        Records = @($records)
        Paths = [string[]]@($inventory.Paths)
    }
}

function Assert-AstroLauncherTempEntryInventoriesEqual {
    param(
        [Parameter(Mandatory)]$Before,
        [Parameter(Mandatory)]$After,
        [Parameter(Mandatory)][string]$Description
    )

    Assert-AstroExactProtocolPathInventory `
        -Expected $Before.Paths `
        -Actual $After.Paths `
        -Description $Description
    if ($Before.Records.Count -ne $After.Records.Count) {
        throw "$Description record count changed"
    }
    for ($index = 0; $index -lt $Before.Records.Count; $index++) {
        $left = $Before.Records[$index]
        $right = $After.Records[$index]
        if ($left.Path -cne $right.Path -or
            $left.Kind -cne $right.Kind -or
            $left.Valid -ne $right.Valid -or
            $left.FileId -cne $right.FileId -or
            $left.FinalPath -cne $right.FinalPath -or
            $left.Name.LauncherPid -ne $right.Name.LauncherPid -or
            $left.Name.LauncherProcessStartUtcTicks -ne
                $right.Name.LauncherProcessStartUtcTicks -or
            $left.Name.LauncherLockSha256 -cne
                $right.Name.LauncherLockSha256) {
            throw "$Description entry changed identity or classification at index ${index}: $($left.Path)"
        }
    }
}

function Assert-AstroExactProtocolPathInventory {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Expected,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Actual,
        [Parameter(Mandatory)][string]$Description
    )

    [string[]]$expectedOrdered = @($Expected)
    [string[]]$actualOrdered = @($Actual)
    [Array]::Sort($expectedOrdered, [StringComparer]::OrdinalIgnoreCase)
    [Array]::Sort($actualOrdered, [StringComparer]::OrdinalIgnoreCase)
    if ($expectedOrdered.Count -ne $actualOrdered.Count) {
        throw "$Description inventory count changed (expected=$($expectedOrdered.Count), actual=$($actualOrdered.Count))"
    }
    for ($index = 0; $index -lt $expectedOrdered.Count; $index++) {
        if ($expectedOrdered[$index] -cne $actualOrdered[$index]) {
            throw "$Description inventory changed at index $index ('$($expectedOrdered[$index])' != '$($actualOrdered[$index])')"
        }
    }
}

function Test-AstroExactProtocolPathInventory {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Expected,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Actual
    )
    try {
        Assert-AstroExactProtocolPathInventory `
            -Expected $Expected `
            -Actual $Actual `
            -Description 'candidate'
        return $true
    }
    catch {
        return $false
    }
}

function Get-AstroLauncherTempTreeSnapshot {
    param([Parameter(Mandatory)]$Lease)

    if ($null -eq $Lease -or $null -eq $Lease.Handle -or
        $Lease.Handle.IsInvalid -or $Lease.Handle.IsClosed) {
        throw 'TEMP tree snapshot requires one live exact directory mutation lease'
    }
    $fileId = [AstroLauncherTempNative]::GetExactDirectoryIdentity($Lease.Handle)
    $finalPath = [IO.Path]::GetFullPath(
        [AstroLauncherTempNative]::GetExactDirectoryFinalPath($Lease.Handle)
    ).TrimEnd('\', '/')
    [string[]]$entries = @(
        [AstroLauncherTempNative]::CaptureExactTreeEntries($Lease.Handle)
    )
    $rootState = [AstroLauncherTempNative]::CaptureExactRootState(
        $Lease.Handle
    )
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        $rootState + "`n" + ($entries -join "`n")
    )
    return [pscustomobject]@{
        Path = $Lease.Path
        RootFileId = $fileId
        RootFinalPath = $finalPath
        RootState = $rootState
        EntryCount = $entries.Count
        InventorySha256 = Get-AstroByteSha256 $bytes
        Entries = $entries
        BackupStateScope =
            'BackupRead default-data/EA/owner-group-DACL-security/object-id + FILE_BASIC_INFO + per-entry NTFS short-name bytes; ADS/link/property/reparse/sparse/TXFS rejected'
        SecurityDescriptorScope =
            'READ_CONTROL backup security stream; SACL not proven (coverage #620)'
        MetadataDispositionAtomicity =
            'final exact retained-handle precheck, then FileDispositionInfo TRUE + immediate close with no post-disposition query; final FILE_BASIC_INFO/EA/SET_SECURITY window not atomically excludable in user mode (coverage #620)'
        CoverageGapIssue = 620
    }
}

function Assert-AstroLauncherTempSnapshotsEqual {
    param(
        [Parameter(Mandatory)]$Before,
        [Parameter(Mandatory)]$After
    )

    if ($Before.RootFileId -cne $After.RootFileId -or
        -not [string]::Equals(
            $Before.RootFinalPath,
            $After.RootFinalPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $Before.RootState -cne $After.RootState -or
        $Before.EntryCount -ne $After.EntryCount -or
        $Before.InventorySha256 -cne $After.InventorySha256 -or
        [string]::Join("`n", [string[]]$Before.Entries) -cne
            [string]::Join("`n", [string[]]$After.Entries)) {
        throw "launcher TEMP tree changed across deletion-authority probes: $($Before.Path)"
    }
}

function Open-AstroLiveLauncherTempLease {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$LauncherPid,
        [Parameter(Mandatory)][long]$LauncherProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$LauncherLockSha256,
        [Parameter(Mandatory)]$DirectoryLease
    )

    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $name = ConvertFrom-AstroLauncherTempName $full
    if (-not $name.Valid -or
        $name.LauncherPid -ne $LauncherPid -or
        $name.LauncherProcessStartUtcTicks -ne
            $LauncherProcessStartUtcTicks -or
        $name.LauncherLockSha256 -cne
            $LauncherLockSha256.ToLowerInvariant()) {
        throw 'live TEMP lease path does not bind the expected exact launcher generation/hash'
    }
    $parent = Assert-AstroLauncherPinnedDirectoryLease $DirectoryLease
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($full).TrimEnd('\', '/'),
            $parent.Path,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "live TEMP path is not inside the exact pinned protocol directory ('$full' vs '$($parent.Path)')"
    }

    $handle = $null
    try {
        $handle = [AstroLauncherTempNative]::OpenExactLiveDirectoryLease($full)
        $rootFileId = [AstroLauncherTempNative]::GetExactDirectoryIdentity($handle)
        $record = [pscustomobject]@{
            Kind = 'temp'
            Path = $full
            ExpectedTempPath = $full
            Valid = $true
            FileId = $rootFileId
            Name = $name
        }
        $lease = [pscustomobject]@{
            Authority = 'live-owner-retained-v1'
            OriginalPath = $full
            Path = $full
            Kind = 'temp'
            Record = $record
            Evidence = $null
            Handle = $handle
            SafeFileHandle = $handle
            RootFileId = $rootFileId
            InitialFinalPath = $null
            CreationSnapshot = $null
            Snapshot = $null
            CleanupProtected = $false
            DispositionSet = $false
            Disposed = $false
        }
        $creation = Get-AstroLauncherTempTreeSnapshot $lease
        if ($creation.RootFileId -cne $rootFileId -or
            -not [string]::Equals(
                $creation.RootFinalPath,
                $full,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            $creation.EntryCount -ne 0) {
            throw "new live TEMP root failed initial exact FILE_ID/path/empty-tree proof (file_id=$($creation.RootFileId), final_path=$($creation.RootFinalPath), entries=$($creation.EntryCount)): $full"
        }
        $lease.InitialFinalPath = $creation.RootFinalPath
        $lease.CreationSnapshot = $creation
        return $lease
    }
    catch {
        $message = $_.Exception.Message
        if ($null -ne $handle) {
            $handle.Dispose()
        }
        throw "exact live TEMP lease acquisition failed (path=$full): $message"
    }
}

function Assert-AstroLiveLauncherTempCleanupAuthority {
    param(
        [Parameter(Mandatory)]$Lease,
        [Parameter(Mandatory)]$CleanupTransaction,
        [Parameter(Mandatory)][int]$ExpectedPid,
        [Parameter(Mandatory)][long]$ExpectedOwnerProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$JobObjectName
    )

    if ($null -eq $Lease -or
        -not $Lease.PSObject.Properties['Authority'] -or
        $Lease.Authority -cne 'live-owner-retained-v1' -or
        $null -eq $Lease.Handle -or $Lease.Handle.IsInvalid -or
        $Lease.Handle.IsClosed -or $Lease.Disposed) {
        throw 'live TEMP cleanup requires the continuously retained producer root handle'
    }
    if ($Lease.Record.Name.LauncherPid -ne $ExpectedPid -or
        $Lease.Record.Name.LauncherProcessStartUtcTicks -ne
            $ExpectedOwnerProcessStartUtcTicks) {
        throw 'live TEMP lease binds a different launcher generation'
    }
    if ($null -eq $CleanupTransaction -or
        -not $CleanupTransaction.PSObject.Properties['MutexLease'] -or
        -not $CleanupTransaction.PSObject.Properties['Released'] -or
        $CleanupTransaction.Released -or
        -not $CleanupTransaction.TransitionPublished -or
        -not $CleanupTransaction.MutexLease.Acquired) {
        throw 'live TEMP cleanup requires the retained active-to-cleanup transition and its acquired Global mutex'
    }
    $lockSnapshot = Assert-AstroLauncherLockLeaseCurrent (
        $CleanupTransaction.LeaseHandle
    )
    $transitions = Get-AstroLauncherLockTransitions (
        $CleanupTransaction.LockPath
    )
    if ($lockSnapshot.FileId -cne $CleanupTransaction.FileId -or
        $lockSnapshot.Length -ne $CleanupTransaction.Length -or
        $lockSnapshot.Sha256 -cne $CleanupTransaction.Sha256 -or
        -not [string]::Equals(
            $lockSnapshot.Path,
            $CleanupTransaction.CleanupPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $transitions.State -ne 'present' -or
        @($transitions.Paths).Count -ne 1 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath(@($transitions.Paths)[0]),
            $CleanupTransaction.CleanupPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        (Get-AstroPathEntryState $CleanupTransaction.LockPath).State -ne
            'absent') {
        throw 'launcher cleanup transition/mutex authority changed before exact live TEMP mutation'
    }
    $owner = Get-AstroAttributionOwnerGenerationProbe `
        $ExpectedPid `
        $ExpectedOwnerProcessStartUtcTicks
    $job = Get-AstroLauncherJobObjectProbe $JobObjectName
    [int[]]$jobPids = @($job.ProcessIds | Sort-Object -Unique)
    if ($owner.State -cne 'exact-live' -or
        $job.State -cne 'observed' -or
        $jobPids.Count -ne 1 -or $jobPids[0] -ne $ExpectedPid) {
        throw "live TEMP cleanup authority is not exact owner + Job {PID} (owner=$($owner.State), job=$($job.State), pids=$($jobPids -join ','), owner_error=$($owner.Error), job_error=$($job.Error))"
    }
    $temp = Get-AstroLauncherTempTreeSnapshot $Lease
    if ($temp.RootFileId -cne $Lease.RootFileId -or
        -not [string]::Equals(
            $temp.RootFinalPath,
            [IO.Path]::GetFullPath($Lease.Path).TrimEnd('\', '/'),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'continuously retained live TEMP root changed FILE_ID or final path'
    }
    return [pscustomobject]@{
        LockSnapshot = $lockSnapshot
        Transitions = $transitions
        OwnerProbe = $owner
        JobObjectProbe = $job
        TempSnapshot = $temp
    }
}

function Initialize-AstroLiveLauncherTempCleanupSnapshot {
    param(
        [Parameter(Mandatory)]$Lease,
        [Parameter(Mandatory)]$CleanupTransaction,
        [Parameter(Mandatory)][int]$ExpectedPid,
        [Parameter(Mandatory)][long]$ExpectedOwnerProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$JobObjectName
    )

    if ($Lease.Kind -cne 'temp' -or
        -not [string]::Equals(
            $Lease.Path,
            $Lease.OriginalPath,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'live TEMP cleanup snapshot must begin at the retained original basename'
    }
    $firstAuthority = Assert-AstroLiveLauncherTempCleanupAuthority `
        -Lease $Lease `
        -CleanupTransaction $CleanupTransaction `
        -ExpectedPid $ExpectedPid `
        -ExpectedOwnerProcessStartUtcTicks $ExpectedOwnerProcessStartUtcTicks `
        -JobObjectName $JobObjectName
    $secondAuthority = Assert-AstroLiveLauncherTempCleanupAuthority `
        -Lease $Lease `
        -CleanupTransaction $CleanupTransaction `
        -ExpectedPid $ExpectedPid `
        -ExpectedOwnerProcessStartUtcTicks $ExpectedOwnerProcessStartUtcTicks `
        -JobObjectName $JobObjectName
    Assert-AstroLauncherTempSnapshotsEqual `
        $firstAuthority.TempSnapshot `
        $secondAuthority.TempSnapshot
    $Lease.Snapshot = $secondAuthority.TempSnapshot
    return [pscustomobject]@{
        State = 'captured'
        Path = $Lease.Path
        RootFileId = $Lease.RootFileId
        EntryCount = $Lease.Snapshot.EntryCount
        InventorySha256 = $Lease.Snapshot.InventorySha256
        OwnerProbe = $secondAuthority.OwnerProbe
        JobObjectProbe = $secondAuthority.JobObjectProbe
        CleanupTransitionPath = $CleanupTransaction.CleanupPath
        CleanupTransitionFileId = $CleanupTransaction.FileId
        CleanupTransitionSha256 = $CleanupTransaction.Sha256
        BackupStateScope = $Lease.Snapshot.BackupStateScope
        SecurityDescriptorScope = $Lease.Snapshot.SecurityDescriptorScope
        MetadataDispositionAtomicity =
            $Lease.Snapshot.MetadataDispositionAtomicity
        CoverageGapIssue = $Lease.Snapshot.CoverageGapIssue
    }
}

function Start-AstroLiveLauncherTempExactDisposition {
    param(
        [Parameter(Mandatory)]$Lease,
        [Parameter(Mandatory)]$CleanupTransaction,
        [Parameter(Mandatory)][int]$ExpectedPid,
        [Parameter(Mandatory)][long]$ExpectedOwnerProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$JobObjectName
    )

    if ($Lease.Kind -cne 'temp-cleanup-tombstone' -or
        $null -eq $Lease.Snapshot) {
        throw 'live TEMP exact disposition requires a captured cleanup-tombstone lease'
    }
    $authority = Assert-AstroLiveLauncherTempCleanupAuthority `
        -Lease $Lease `
        -CleanupTransaction $CleanupTransaction `
        -ExpectedPid $ExpectedPid `
        -ExpectedOwnerProcessStartUtcTicks $ExpectedOwnerProcessStartUtcTicks `
        -JobObjectName $JobObjectName
    Assert-AstroLauncherTempSnapshotsEqual `
        $Lease.Snapshot `
        $authority.TempSnapshot
    $originalBefore = Get-AstroPathEntryState $Lease.OriginalPath
    if ($originalBefore.State -ne 'absent') {
        throw "original TEMP basename was recreated before exact live child disposition (state=$($originalBefore.State), error=$($originalBefore.Error)): $($Lease.OriginalPath)"
    }

    $protectedHandle =
        [AstroLauncherTempNative]::ProtectExactLiveDirectoryForCleanup(
            $Lease.Handle,
            $Lease.Path,
            $Lease.RootFileId,
            $authority.TempSnapshot.RootState
        )
    $Lease.Handle = $protectedHandle
    $Lease.SafeFileHandle = $protectedHandle
    $Lease.CleanupProtected = $true
    $protectedAuthority = Assert-AstroLiveLauncherTempCleanupAuthority `
        -Lease $Lease `
        -CleanupTransaction $CleanupTransaction `
        -ExpectedPid $ExpectedPid `
        -ExpectedOwnerProcessStartUtcTicks $ExpectedOwnerProcessStartUtcTicks `
        -JobObjectName $JobObjectName
    Assert-AstroLauncherTempSnapshotsEqual `
        $Lease.Snapshot `
        $protectedAuthority.TempSnapshot

    [AstroLauncherTempNative]::DeleteExactTreeContents(
        $Lease.Handle,
        [string[]]$Lease.Snapshot.Entries
    )
    $afterChildren = Assert-AstroLiveLauncherTempCleanupAuthority `
        -Lease $Lease `
        -CleanupTransaction $CleanupTransaction `
        -ExpectedPid $ExpectedPid `
        -ExpectedOwnerProcessStartUtcTicks $ExpectedOwnerProcessStartUtcTicks `
        -JobObjectName $JobObjectName
    if ($afterChildren.TempSnapshot.RootFileId -cne $Lease.RootFileId -or
        $afterChildren.TempSnapshot.EntryCount -ne 0) {
        throw 'live TEMP retained root changed identity or remained nonempty after captured-child disposition'
    }
    $originalAfter = Get-AstroPathEntryState $Lease.OriginalPath
    if ($originalAfter.State -ne 'absent') {
        throw "original TEMP basename was recreated during exact live child disposition (state=$($originalAfter.State), error=$($originalAfter.Error)): $($Lease.OriginalPath)"
    }
    [AstroLauncherTempNative]::MarkExactDirectoryDeletePending(
        $Lease.Handle,
        $afterChildren.TempSnapshot.RootState
    )
    $Lease.DispositionSet = $true
    $Lease.Disposed = $true
    return [pscustomobject]@{
        State = 'delete-pending'
        Path = $Lease.Path
        OriginalPath = $Lease.OriginalPath
        RootFileId = $Lease.RootFileId
        InitialEntryCount = $Lease.Snapshot.EntryCount
        InitialInventorySha256 = $Lease.Snapshot.InventorySha256
        EmptyInventorySha256 = $afterChildren.TempSnapshot.InventorySha256
        OwnerProbe = $afterChildren.OwnerProbe
        JobObjectProbe = $afterChildren.JobObjectProbe
        DispositionSet = $true
        OriginalPathState = $originalAfter.State
        CleanupTransitionPath = $CleanupTransaction.CleanupPath
        BackupStateScope = $Lease.Snapshot.BackupStateScope
        SecurityDescriptorScope = $Lease.Snapshot.SecurityDescriptorScope
        MetadataDispositionAtomicity =
            $Lease.Snapshot.MetadataDispositionAtomicity
        CoverageGapIssue = $Lease.Snapshot.CoverageGapIssue
    }
}

function Open-AstroLauncherTempMutationLease {
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)]$Evidence,
        [Parameter(Mandatory)]$DirectoryLease
    )

    if ($null -eq $Record -or -not $Record.Valid -or
        $Record.Kind -cnotin @('temp', 'temp-cleanup-tombstone')) {
        throw 'TEMP cleanup requires one exact valid TEMP or TEMP-cleanup record'
    }
    if ($null -eq $Evidence -or -not $Evidence.Valid -or
        $Evidence.OwnerProbe.State -notin @('absent', 'pid-reused') -or
        $Evidence.JobObjectProbe.State -cne 'absent') {
        throw 'TEMP cleanup requires deletion-authorizing exact evidence'
    }
    if ($Record.Name.LauncherPid -ne $Evidence.Parsed.LauncherPid -or
        $Record.Name.LauncherProcessStartUtcTicks -ne
            $Evidence.Parsed.LauncherProcessStartUtcTicks -or
        $Record.Name.LauncherLockSha256 -cne
            $Evidence.Parsed.LauncherLockSha256 -or
        $Record.ExpectedTempPath -cne $Evidence.ExpectedTempPath) {
        throw 'TEMP record and retained attribution evidence bind different generations'
    }
    $parent = Assert-AstroLauncherPinnedDirectoryLease $DirectoryLease
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($Record.Path).TrimEnd('\', '/'),
            $parent.Path,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "TEMP record is not inside the exact pinned protocol directory ('$($Record.Path)' vs '$($parent.Path)')"
    }

    $handle = $null
    try {
        $handle = [AstroLauncherTempNative]::OpenExactDirectoryMutation($Record.Path)
        $lease = [pscustomobject]@{
            OriginalPath = $Record.ExpectedTempPath
            Path = $Record.Path
            Kind = $Record.Kind
            Record = $Record
            Evidence = $Evidence
            Handle = $handle
            SafeFileHandle = $handle
            RootFileId = [AstroLauncherTempNative]::GetExactDirectoryIdentity($handle)
            Snapshot = $null
            DispositionSet = $false
            Disposed = $false
        }
        if ($lease.RootFileId -cne $Record.FileId) {
            throw "TEMP directory FILE_ID changed between classification and exact mutation lease (expected=$($Record.FileId), observed=$($lease.RootFileId))"
        }
        $first = Get-AstroLauncherTempTreeSnapshot $lease
        if (-not [string]::Equals(
                $first.RootFinalPath,
                [IO.Path]::GetFullPath($Record.Path).TrimEnd('\', '/'),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "retained TEMP handle resolves to a different path ('$($Record.Path)' -> '$($first.RootFinalPath)')"
        }
        $ownerFinal = Get-AstroAttributionOwnerGenerationProbe `
            $Evidence.Parsed.LauncherPid `
            $Evidence.Parsed.LauncherProcessStartUtcTicks
        $jobFinal = Get-AstroLauncherJobObjectProbe $Evidence.Parsed.JobObjectName
        if ($ownerFinal.State -notin @('absent', 'pid-reused') -or
            $jobFinal.State -cne 'absent') {
            throw "owner/Job Object state changed while retaining TEMP (owner=$($ownerFinal.State), job=$($jobFinal.State), pids=$(@($jobFinal.ProcessIds) -join ','), error=$($jobFinal.Error))"
        }
        $second = Get-AstroLauncherTempTreeSnapshot $lease
        Assert-AstroLauncherTempSnapshotsEqual $first $second
        $lease.Snapshot = $second
        return $lease
    }
    catch {
        $message = $_.Exception.Message
        if ($null -ne $handle) {
            $handle.Dispose()
        }
        throw "exact TEMP mutation lease acquisition failed (path=$($Record.Path)): $message"
    }
}

function Close-AstroLauncherTempMutationLease {
    param([Parameter(Mandatory)]$Lease)

    if ($null -ne $Lease -and $null -ne $Lease.Handle -and
        -not $Lease.Handle.IsClosed) {
        $Lease.Handle.Dispose()
        $Lease.Disposed = $true
    }
}

function New-AstroLauncherTempCleanupNonce {
    $bytes = New-Object byte[] 16
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

function Move-AstroLauncherTempLeaseToCleanupTombstone {
    param(
        [Parameter(Mandatory)]$Lease,
        [Parameter(Mandatory)]$DestinationDirectoryLease
    )

    if ($Lease.Kind -ceq 'temp-cleanup-tombstone') {
        return [pscustomobject]@{
            State = 'already-cleanup-tombstone'
            SourcePath = $Lease.Path
            DestinationPath = $Lease.Path
            RootFileId = $Lease.RootFileId
            InventorySha256 = $Lease.Snapshot.InventorySha256
            EntryCount = $Lease.Snapshot.EntryCount
            SourcePathState = 'same-path'
        }
    }
    if ($Lease.Kind -cne 'temp') {
        throw "unsupported TEMP mutation-lease kind '$($Lease.Kind)'"
    }
    $parent = Assert-AstroLauncherPinnedDirectoryLease (
        $DestinationDirectoryLease
    )
    $directory = $parent.Path
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($Lease.Path).TrimEnd('\', '/'),
            $directory,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "retained TEMP is not inside the exact pinned cleanup parent ('$($Lease.Path)' vs '$directory')"
    }
    $nonce = New-AstroLauncherTempCleanupNonce
    $leaf = '.astro-launcher-temp-cleanup.v2.pid-{0}.ticks-{1}.lock-sha256-{2}.nonce-{3}.dir' -f
        $Lease.Record.Name.LauncherPid,
        $Lease.Record.Name.LauncherProcessStartUtcTicks,
        $Lease.Record.Name.LauncherLockSha256,
        $nonce
    $destination = [IO.Path]::GetFullPath((Join-Path $Directory $leaf))
    $parsedName = ConvertFrom-AstroLauncherTempCleanupName $destination
    if (-not $parsedName.Valid) {
        throw "generated TEMP cleanup tombstone is not canonical: $($parsedName.Error)"
    }
    $destinationState = Get-AstroPathEntryState $destination
    if ($destinationState.State -ne 'absent') {
        throw "TEMP cleanup tombstone destination is not exactly absent (state=$($destinationState.State), error=$($destinationState.Error)): $destination"
    }

    try {
        [void](Assert-AstroLauncherPinnedDirectoryLease (
            $DestinationDirectoryLease
        ))
        $before = Get-AstroLauncherTempTreeSnapshot $Lease
        Assert-AstroLauncherTempSnapshotsEqual $Lease.Snapshot $before
        [AstroLauncherTempNative]::RenameExactDirectoryNoReplace(
            $Lease.Handle,
            $DestinationDirectoryLease.SafeFileHandle,
            $leaf
        )
        $source = $Lease.Path
        # Preserve crash recoverability even if a subsequent readback fails.
        $Lease.Path = $destination
        $Lease.Kind = 'temp-cleanup-tombstone'
        $after = Get-AstroLauncherTempTreeSnapshot $Lease
        if (-not [string]::Equals(
                $after.RootFinalPath,
                $destination,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "retained TEMP rename resolved to an unexpected destination ('$destination' -> '$($after.RootFinalPath)')"
        }
        Assert-AstroLauncherTempSnapshotsEqual $before $after
        $sourceState = Get-AstroPathEntryState $source
        if ($sourceState.State -ne 'absent') {
            throw "TEMP cleanup rename did not make the original path absent (state=$($sourceState.State), error=$($sourceState.Error)): $source"
        }
        $Lease.Snapshot = $after
        return [pscustomobject]@{
            State = 'renamed'
            SourcePath = $source
            DestinationPath = $destination
            RootFileId = $after.RootFileId
            InventorySha256 = $after.InventorySha256
            EntryCount = $after.EntryCount
            SourcePathState = $sourceState.State
        }
    }
    finally {
        # The caller owns and continuously retains the pinned protocol directory.
        [void](Assert-AstroLauncherPinnedDirectoryLease (
            $DestinationDirectoryLease
        ))
    }
}

function Start-AstroLauncherTempExactDisposition {
    param(
        [Parameter(Mandatory)]$Lease,
        [Parameter(Mandatory)]$EvidenceLease
    )

    if ($Lease.Kind -cne 'temp-cleanup-tombstone') {
        throw 'TEMP recursive cleanup requires the exact directory to be in cleanup-tombstone state'
    }
    if ($null -eq $EvidenceLease -or $EvidenceLease.Handle.IsClosed) {
        throw 'TEMP recursive cleanup requires the exact evidence mutation lease to remain retained'
    }
    $current = Get-AstroLauncherTempTreeSnapshot $Lease
    Assert-AstroLauncherTempSnapshotsEqual $Lease.Snapshot $current
    $ownerFinal = Get-AstroAttributionOwnerGenerationProbe `
        $EvidenceLease.Parsed.LauncherPid `
        $EvidenceLease.Parsed.LauncherProcessStartUtcTicks
    $jobFinal = Get-AstroLauncherJobObjectProbe `
        $EvidenceLease.Parsed.JobObjectName
    if ($ownerFinal.State -notin @('absent', 'pid-reused') -or
        $jobFinal.State -cne 'absent') {
        throw "owner/Job Object state changed before TEMP content disposition (owner=$($ownerFinal.State), job=$($jobFinal.State), pids=$(@($jobFinal.ProcessIds) -join ','), error=$($jobFinal.Error))"
    }
    [AstroLauncherTempNative]::DeleteExactTreeContents(
        $Lease.Handle,
        [string[]]$Lease.Snapshot.Entries
    )
    $empty = Get-AstroLauncherTempTreeSnapshot $Lease
    if ($empty.RootFileId -cne $Lease.RootFileId -or
        $empty.EntryCount -ne 0) {
        throw 'TEMP retained root changed identity or remained nonempty after exact child disposition'
    }
    [AstroLauncherTempNative]::MarkExactDirectoryDeletePending(
        $Lease.Handle,
        $empty.RootState
    )
    $Lease.DispositionSet = $true
    $Lease.Disposed = $true
    return [pscustomobject]@{
        State = 'delete-pending'
        Path = $Lease.Path
        RootFileId = $Lease.RootFileId
        InitialEntryCount = $Lease.Snapshot.EntryCount
        InitialInventorySha256 = $Lease.Snapshot.InventorySha256
        EmptyInventorySha256 = $empty.InventorySha256
        OwnerProbe = $ownerFinal
        JobObjectProbe = $jobFinal
        DispositionSet = $true
        BackupStateScope = $Lease.Snapshot.BackupStateScope
        SecurityDescriptorScope = $Lease.Snapshot.SecurityDescriptorScope
        MetadataDispositionAtomicity =
            $Lease.Snapshot.MetadataDispositionAtomicity
        CoverageGapIssue = $Lease.Snapshot.CoverageGapIssue
    }
}

function ConvertTo-AstroPathArray {
    param([Parameter(Mandatory)]$Set)
    [string[]]$result = @($Set | Sort-Object)
    Write-Output -NoEnumerate $result
}

function Assert-AstroPendingTempProtocolInventory {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)]$ExpectedSet,
        [Parameter(Mandatory)][string]$PendingPath,
        [Parameter(Mandatory)][string]$OriginalPath
    )

    $raw = Get-AstroReservedLauncherTempPaths $Directory
    [string[]]$withPending = ConvertTo-AstroPathArray $ExpectedSet
    $without = [Collections.Generic.HashSet[string]]::new(
        $ExpectedSet,
        [StringComparer]::OrdinalIgnoreCase
    )
    [void]$without.Remove($PendingPath)
    [string[]]$withoutPending = ConvertTo-AstroPathArray $without
    if (-not (Test-AstroExactProtocolPathInventory $withPending $raw.Paths) -and
        -not (Test-AstroExactProtocolPathInventory $withoutPending $raw.Paths)) {
        throw 'reserved TEMP inventory drifted while exact TEMP root was delete-pending'
    }
    if ($raw.Paths -contains $OriginalPath) {
        throw "original TEMP basename was recreated during cleanup and is preserving: $OriginalPath"
    }
    return $raw
}

function Clear-DeadLauncherTempDirs {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [int]$SelfPid = $PID
    )

    $full = [IO.Path]::GetFullPath($Directory)
    $directoryState = Get-AstroPathEntryState $full
    if ($directoryState.State -eq 'absent') {
        return [pscustomobject]@{
            Removed = @()
            Kept = @()
            Skipped = @()
            RemovedManifests = @()
            RemovedStages = @()
            RemovedTombstones = @()
            Decisions = @()
            StageDecisions = @()
            Transactions = @()
            Errors = @()
            State = 'absent'
        }
    }

    $errors = [Collections.Generic.List[string]]::new()
    $removed = [Collections.Generic.List[string]]::new()
    $kept = [Collections.Generic.List[string]]::new()
    $skipped = [Collections.Generic.List[string]]::new()
    $removedManifests = [Collections.Generic.List[string]]::new()
    $removedStages = [Collections.Generic.List[string]]::new()
    $removedTombstones = [Collections.Generic.List[string]]::new()
    $decisions = [Collections.Generic.List[object]]::new()
    $stageDecisions = [Collections.Generic.List[object]]::new()
    $transactions = [Collections.Generic.List[object]]::new()

    try {
        $tempsBefore = Get-AstroReservedLauncherTempEntries $full
        $tempsConfirmation = Get-AstroReservedLauncherTempEntries $full
        Assert-AstroLauncherTempEntryInventoriesEqual `
            -Before $tempsBefore `
            -After $tempsConfirmation `
            -Description 'initial launcher TEMP'
    }
    catch {
        return [pscustomobject]@{
            Removed = @()
            Kept = @()
            Skipped = @()
            RemovedManifests = @()
            RemovedStages = @()
            RemovedTombstones = @()
            Decisions = @()
            StageDecisions = @()
            Transactions = @()
            Errors = @($_.Exception.Message)
            State = 'unevaluable'
        }
    }
    $attribution = Get-AstroAttributionInventory $full
    $refreshTransactionCount = 0
    foreach ($errorText in [string[]]@($attribution.Errors)) {
        $errors.Add($errorText)
    }
    if (-not $attribution.PSObject.Properties['RefreshTransactions']) {
        $errors.Add(
            'strict attribution inventory does not expose RefreshTransactions; ordinary TEMP pairing is preserving'
        )
    }
    else {
        $refreshTransactionCount = @($attribution.RefreshTransactions).Count
        foreach ($refreshTransaction in @($attribution.RefreshTransactions)) {
            $errors.Add(
                "attribution refresh transaction requires tracker-bound explicit reclaim before ordinary TEMP pairing (key=$($refreshTransaction.Key), state=$($refreshTransaction.State), phase=$($refreshTransaction.Phase), envelope=$($refreshTransaction.EnvelopePath), old=$($refreshTransaction.OldTombstonePath), final=$($refreshTransaction.FinalPath))"
            )
        }
    }
    foreach ($temp in $tempsBefore.Records) {
        if (-not $temp.Valid) {
            $errors.Add("launcher TEMP '$($temp.Path)': $($temp.Error)")
        }
    }
    if ($refreshTransactionCount -gt 0) {
        foreach ($temp in $tempsBefore.Records) {
            $kept.Add($temp.Path)
        }
        return [pscustomobject]@{
            Removed = @()
            Kept = [string[]]@($kept)
            Skipped = @()
            RemovedManifests = @()
            RemovedStages = @()
            RemovedTombstones = @()
            Decisions = @()
            StageDecisions = @()
            Transactions = @()
            Errors = [string[]]@($errors)
            State = 'unevaluable'
            InitialTempInventory = $tempsBefore
            InitialAttributionInventory = $attribution
            RefreshTransactionCount = $refreshTransactionCount
            RefreshResolutionAuthority =
                'tracker-bound explicit reclaim only'
        }
    }

    $originalTempByKey = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $cleanupTempByKey = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($temp in $tempsBefore.Records) {
        if (-not $temp.Valid) {
            continue
        }
        $map = if ($temp.Kind -ceq 'temp') {
            $originalTempByKey
        } else {
            $cleanupTempByKey
        }
        if ($map.ContainsKey($temp.ExpectedTempPath)) {
            $errors.Add(
                "more than one '$($temp.Kind)' directory binds generation '$($temp.ExpectedTempPath)'"
            )
        }
        else {
            $map.Add($temp.ExpectedTempPath, $temp)
        }
    }

    $manifestByKey = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $cleanupEvidenceByKey = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $stages = [Collections.Generic.List[object]]::new()
    foreach ($record in $attribution.Records) {
        if (-not $record.Valid) {
            continue
        }
        if ($record.Kind -ceq 'stage') {
            $stages.Add($record)
            continue
        }
        $map = if ($record.Kind -ceq 'manifest') {
            $manifestByKey
        } elseif ($record.Kind -ceq 'cleanup-tombstone') {
            $cleanupEvidenceByKey
        } else {
            # Typed refresh/recovery records must be resolved by their own
            # generation-bound recovery state machine before TEMP pairing.
            # Never reinterpret an unknown future kind as cleanup authority.
            $errors.Add(
                "unsupported attribution transaction kind '$($record.Kind)' remains before launcher TEMP pairing: $($record.Path)"
            )
            continue
        }
        if ($map.ContainsKey($record.ExpectedTempPath)) {
            $errors.Add(
                "more than one '$($record.Kind)' file binds generation '$($record.ExpectedTempPath)'"
            )
        }
        else {
            $map.Add($record.ExpectedTempPath, $record)
        }
    }

    $allKeys = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($map in @(
            $originalTempByKey,
            $cleanupTempByKey,
            $manifestByKey,
            $cleanupEvidenceByKey
        )) {
        foreach ($key in $map.Keys) {
            [void]$allKeys.Add($key)
        }
    }
    $pairs = [Collections.Generic.List[object]]::new()
    $standaloneCleanup = [Collections.Generic.List[object]]::new()
    foreach ($key in [string[]]@($allKeys | Sort-Object)) {
        $hasOriginalTemp = $originalTempByKey.ContainsKey($key)
        $hasCleanupTemp = $cleanupTempByKey.ContainsKey($key)
        $hasManifest = $manifestByKey.ContainsKey($key)
        $hasCleanupEvidence = $cleanupEvidenceByKey.ContainsKey($key)
        if ($hasOriginalTemp -and $hasCleanupTemp) {
            $errors.Add(
                "original TEMP '$key' coexists with its cleanup tombstone; same-name recreation/ambiguous phase is preserving"
            )
            continue
        }
        if ($hasManifest -and $hasCleanupEvidence) {
            $errors.Add(
                "final manifest and attribution cleanup tombstone coexist for generation '$key'"
            )
            continue
        }
        if (-not $hasManifest -and -not $hasCleanupEvidence) {
            if ($hasOriginalTemp -or $hasCleanupTemp) {
                $tempPath = if ($hasOriginalTemp) {
                    $originalTempByKey[$key].Path
                } else {
                    $cleanupTempByKey[$key].Path
                }
                $errors.Add("launcher TEMP '$tempPath' has no exact generation-bound evidence")
            }
            continue
        }
        $evidence = if ($hasManifest) {
            $manifestByKey[$key]
        } else {
            $cleanupEvidenceByKey[$key]
        }
        if (-not $hasOriginalTemp -and -not $hasCleanupTemp) {
            if ($hasCleanupEvidence) {
                # This phase proves TEMP disposition had begun. It is independently
                # recoverable after a crash between TEMP and evidence disposition.
                $standaloneCleanup.Add($evidence)
            }
            else {
                $errors.Add(
                    "standalone final manifest '$($evidence.Path)' is ambiguous and cannot authorize cleanup without its exact TEMP or retained reclaim authority"
                )
            }
            continue
        }
        if ($hasCleanupEvidence -and $hasOriginalTemp) {
            $errors.Add(
                "original TEMP '$key' exists after attribution entered cleanup phase; recreation is preserving"
            )
            continue
        }
        $temp = if ($hasOriginalTemp) {
            $originalTempByKey[$key]
        } else {
            $cleanupTempByKey[$key]
        }
        $pairs.Add([pscustomobject]@{
            Key = $key
            Temp = $temp
            Evidence = $evidence
        })
    }

    if (-not $attribution.Stable -or $errors.Count -gt 0) {
        foreach ($temp in $tempsBefore.Records) {
            $kept.Add($temp.Path)
        }
        return [pscustomobject]@{
            Removed = @()
            Kept = [string[]]@($kept)
            Skipped = @()
            RemovedManifests = @()
            RemovedStages = @()
            RemovedTombstones = @()
            Decisions = @()
            StageDecisions = @()
            Transactions = @()
            Errors = [string[]]@($errors)
            State = 'unevaluable'
            InitialTempInventory = $tempsBefore
            InitialAttributionInventory = $attribution
        }
    }

    $expectedTemps = [Collections.Generic.HashSet[string]]::new(
        [string[]]$tempsBefore.Paths,
        [StringComparer]::OrdinalIgnoreCase
    )
    $expectedAttribution = [Collections.Generic.HashSet[string]]::new(
        [string[]]$attribution.Paths,
        [StringComparer]::OrdinalIgnoreCase
    )
    $mutationBlocked = $false

    foreach ($stage in @($stages | Sort-Object -Property Path)) {
        $ownerState = $stage.OwnerProbe.State
        $jobState = $stage.JobObjectProbe.State
        $result = $null
        $stageErrorPhase = $null
        $stageError = $null
        if ($mutationBlocked) {
            $action = 'kept'
            $reason = 'prior-protocol-mutation-failed'
            $stageErrorPhase = 'prior-mutation'
            $stageError = 'an earlier exact protocol mutation failed'
        }
        elseif ($ownerState -eq 'exact-live') {
            $action = if ($stage.Parsed.LauncherPid -eq $SelfPid) {
                'skipped'
            } else {
                'kept'
            }
            $reason = if ($action -eq 'skipped') {
                'exact-current-owner'
            } else {
                'exact-live-owner'
            }
        }
        elseif ($ownerState -notin @('absent', 'pid-reused')) {
            $action = 'kept'
            $reason = 'owner-unevaluable'
            $stageErrorPhase = 'owner-probe'
            $stageError = $stage.OwnerProbe.Error
        }
        elseif ($jobState -cne 'absent') {
            $action = 'kept'
            $reason = "job-$jobState"
            if ($jobState -ceq 'unevaluable') {
                $stageErrorPhase = 'job-probe'
                $stageError = $stage.JobObjectProbe.Error
            }
        }
        elseif ($ownerState -in @('absent', 'pid-reused') -and
            $jobState -ceq 'absent') {
            # A dead reserved producer stage is durable crash evidence.  The
            # ordinary launcher startup path has no tracker-bound reclaim
            # authority and therefore may classify/report it but never erase
            # it.  Modern producers use unreserved delete-on-close scratch, so
            # this path is recovery evidence rather than routine litter.
            $action = 'kept'
            $reason = 'tracker-authorized-reclaim-required'
            $stageErrorPhase = 'reclaim-authority'
            $stageError = 'dead reserved attribution stage requires tracker-bound explicit reclaim'
        }
        else {
            $action = 'kept'
            $reason = 'unsupported-owner-job-state'
            $stageErrorPhase = 'authority-classification'
            $stageError = "unrecognized owner/job tuple: owner=$ownerState, job=$jobState"
        }
        $stageDecisions.Add([pscustomobject]@{
            Kind = 'stage'
            Path = $stage.Path
            Action = $action
            Reason = $reason
            OwnerState = $ownerState
            JobState = $jobState
            JobProcessIds = [int[]]@($stage.JobObjectProbe.ProcessIds)
            InitialAttributionCount = $attribution.Records.Count
            FileId = if ($null -ne $result) {
                $result.FileId
            } else { $stage.Snapshot.FileId }
            ByteCount = if ($null -ne $result) {
                $result.Length
            } else { $stage.Snapshot.Length }
            Sha256 = if ($null -ne $result) {
                $result.Sha256
            } else { $stage.Snapshot.Sha256 }
            DispositionSet = if ($null -ne $result) {
                [bool]$result.DispositionSet
            } else { $false }
            TerminalPathState = if ($null -ne $result) {
                $result.TerminalPathState
            } else { (Get-AstroPathEntryState $stage.Path).State }
            ErrorPhase = $stageErrorPhase
            Error = $stageError
        })
    }

    foreach ($cleanup in @($standaloneCleanup | Sort-Object -Property Path)) {
        $ownerState = $cleanup.OwnerProbe.State
        $jobState = $cleanup.JobObjectProbe.State
        $isCurrent = $ownerState -ceq 'exact-live' -and
            $cleanup.Parsed.LauncherPid -eq $SelfPid
        $stageDecisions.Add([pscustomobject]@{
            Kind = 'cleanup-tombstone'
            Path = $cleanup.Path
            Action = if ($isCurrent) { 'skipped' } else { 'kept' }
            Reason = if ($isCurrent) {
                'exact-current-owner'
            } elseif ($ownerState -ceq 'exact-live') {
                'exact-live-owner'
            } elseif ($ownerState -notin @('absent', 'pid-reused')) {
                'owner-unevaluable'
            } elseif ($jobState -cne 'absent') {
                "job-$jobState"
            } else {
                'tracker-authorized-reclaim-required'
            }
            OwnerState = $ownerState
            JobState = $jobState
            JobProcessIds = [int[]]@($cleanup.JobObjectProbe.ProcessIds)
            InitialAttributionCount = $attribution.Records.Count
            FileId = $cleanup.Snapshot.FileId
            ByteCount = $cleanup.Snapshot.Length
            Sha256 = $cleanup.Snapshot.Sha256
            DispositionSet = $false
            TerminalPathState = (Get-AstroPathEntryState $cleanup.Path).State
            ErrorPhase = if ($ownerState -ceq 'unevaluable') {
                'owner-probe'
            } elseif ($jobState -ceq 'unevaluable') {
                'job-probe'
            } elseif (-not $isCurrent -and
                $ownerState -in @('absent', 'pid-reused') -and
                $jobState -ceq 'absent') {
                'reclaim-authority'
            } else { $null }
            Error = if ($ownerState -ceq 'unevaluable') {
                $cleanup.OwnerProbe.Error
            } elseif ($jobState -ceq 'unevaluable') {
                $cleanup.JobObjectProbe.Error
            } elseif (-not $isCurrent -and
                $ownerState -in @('absent', 'pid-reused') -and
                $jobState -ceq 'absent') {
                'stale attribution cleanup tombstone requires tracker-bound explicit reclaim'
            } else { $null }
        })
    }
    foreach ($pair in @($pairs | Sort-Object -Property Key)) {
        $temp = $pair.Temp
        $evidence = $pair.Evidence
        $ownerState = $evidence.OwnerProbe.State
        $jobState = $evidence.JobObjectProbe.State
        [int[]]$jobPids = @($evidence.JobObjectProbe.ProcessIds)
        if ($mutationBlocked) {
            $kept.Add($temp.Path)
            $action = 'kept'
            $reason = 'prior-protocol-mutation-failed'
        }
        elseif ($ownerState -eq 'exact-live') {
            if ($evidence.Parsed.LauncherPid -eq $SelfPid) {
                $skipped.Add($temp.Path)
                $action = 'skipped'
                $reason = 'exact-current-owner'
            }
            else {
                $kept.Add($temp.Path)
                $action = 'kept'
                $reason = 'exact-live-owner'
            }
        }
        elseif ($ownerState -notin @('absent', 'pid-reused')) {
            $kept.Add($temp.Path)
            $action = 'kept'
            $reason = 'owner-unevaluable'
        }
        elseif ($jobState -cne 'absent') {
            $kept.Add($temp.Path)
            $action = 'kept'
            $reason = "job-$jobState"
        }
        elseif ($ownerState -in @('absent', 'pid-reused') -and
            $jobState -ceq 'absent') {
            # Complete or partially transitioned TEMP/evidence pairs belong to
            # the launcher generation's stale-v2 recovery transaction.  Owner
            # death and Job absence prove liveness only; they do not grant the
            # ordinary startup sweep the tracker-comment/archive authority
            # required by #611/#617.
            $kept.Add($temp.Path)
            $action = 'kept'
            $reason = 'tracker-authorized-reclaim-required'
        }
        else {
            $kept.Add($temp.Path)
            $action = 'kept'
            $reason = 'unsupported-owner-job-state'
        }
        $decisions.Add([pscustomobject]@{
            TempPath = $temp.Path
            LogicalTempPath = $pair.Key
            ManifestPath = $evidence.Path
            Action = $action
            Reason = $reason
            OwnerState = $ownerState
            JobState = $jobState
            JobProcessIds = $jobPids
        })
    }

    try {
        $tempsAfter = Get-AstroReservedLauncherTempEntries $full
        $attributionAfter = Get-AstroAttributionInventory $full
        Assert-AstroExactProtocolPathInventory `
            -Expected (ConvertTo-AstroPathArray $expectedTemps) `
            -Actual $tempsAfter.Paths `
            -Description 'terminal launcher TEMP'
        Assert-AstroExactProtocolPathInventory `
            -Expected (ConvertTo-AstroPathArray $expectedAttribution) `
            -Actual $attributionAfter.Paths `
            -Description 'terminal attribution evidence'
        foreach ($terminalError in [string[]]@($attributionAfter.Errors)) {
            $errors.Add("terminal attribution inventory: $terminalError")
        }
        foreach ($path in [string[]]@(
                @($removed) +
                @($removedManifests) +
                @($removedStages) +
                @($removedTombstones)
            )) {
            $state = Get-AstroPathEntryState $path
            if ($state.State -ne 'absent') {
                $errors.Add(
                    "removed protocol path readback is not absent (state=$($state.State), error=$($state.Error)): $path"
                )
            }
        }
    }
    catch {
        $tempsAfter = $null
        $attributionAfter = $null
        $errors.Add("terminal pair inventory failed: $($_.Exception.Message)")
    }
    return [pscustomobject]@{
        Removed = [string[]]@($removed)
        Kept = [string[]]@($kept)
        Skipped = [string[]]@($skipped)
        RemovedManifests = [string[]]@($removedManifests)
        RemovedStages = [string[]]@($removedStages)
        RemovedTombstones = [string[]]@($removedTombstones)
        Decisions = @($decisions)
        StageDecisions = @($stageDecisions)
        Transactions = @($transactions)
        Errors = [string[]]@($errors)
        State = if ($errors.Count -gt 0) {
            'unevaluable'
        } elseif ($removed.Count -gt 0 -or
            $removedStages.Count -gt 0 -or
            $removedTombstones.Count -gt 0) {
            'removed'
        } elseif ($tempsBefore.Records.Count -eq 0 -and
            $attribution.Records.Count -eq 0) {
            'absent'
        } else {
            'observed'
        }
        InitialTempInventory = $tempsBefore
        TerminalTempInventory = $tempsAfter
        InitialAttributionInventory = $attribution
        TerminalAttributionInventory = $attributionAfter
    }
}
