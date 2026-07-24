<#
.SYNOPSIS
    Explicit tracker-evidenced archive of dead-owner launcher protocol state.

.DESCRIPTION
    Normal acquisition never removes stale, malformed, or interrupted launcher-lock state.
    This command is the only supported recovery path. It verifies the referenced GitHub
    comment through `gh`, requires that comment to contain an exact machine-readable evidence
    object, probes the exact process identity twice, writes and byte-for-byte reads back an
    append-only authorization record, then atomically archives only the exact unchanged bytes.

    -LegacyPidOnly is resume-only for an already-published, strictly linked legacy reclaim
    marker and still requires complete numeric-PID absence. Fresh pre-v2 state is permanently
    preserving: it cannot derive the generation-bound Job Object needed to prove descendants
    absent. Fresh malformed owner state that lacks exact lease ticks is preserving for the
    same reason. -QuarantineUnreadable may archive only an exact malformed attribution stage
    after a modern deterministic Job proof; it never upgrades ambiguous owner state.

.NOTES
    Refs #611, #519, #197. Manual recovery tooling; this is not a test or gate.
#>
[CmdletBinding()]
param(
    [string]$Root = '',
    [string]$LockPath = '',
    [string]$ExpectedPid = '',
    [string]$ExpectedIssue = '',
    [string]$ExpectedOwnerProcessStartUtcTicks = '',
    [string]$ExpectedLockSha256 = '',
    [string]$RecoveryRecordPath = '',
    [string]$TrackerCommentUrl = '',
    [switch]$LegacyPidOnly,
    [switch]$QuarantineUnreadable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:AstroLauncherGhReadTimeoutMilliseconds = 30000

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

function Add-AstroReclaimSemanticMismatch {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[string]]$Mismatches,
        [Parameter(Mandatory)][string]$Field,
        [AllowNull()]$Actual,
        [AllowNull()]$Expected,
        [ValidateSet('value', 'ordinal', 'ordinal-ignore-case')]
        [string]$Comparison = 'value'
    )

    $valuesMatch = switch ($Comparison) {
        'ordinal' {
            [string]::Equals(
                [string]$Actual,
                [string]$Expected,
                [StringComparison]::Ordinal
            )
            break
        }
        'ordinal-ignore-case' {
            [string]::Equals(
                [string]$Actual,
                [string]$Expected,
                [StringComparison]::OrdinalIgnoreCase
            )
            break
        }
        default {
            if ($null -eq $Actual -or $null -eq $Expected) {
                $null -eq $Actual -and $null -eq $Expected
            }
            else {
                $Actual -eq $Expected
            }
        }
    }
    if ($valuesMatch) {
        return
    }
    $actualText = if ($null -eq $Actual) { '<null>' } else { [string]$Actual }
    $expectedText = if ($null -eq $Expected) { '<null>' } else { [string]$Expected }
    $Mismatches.Add(
        "$Field(actual='$actualText', expected='$expectedText')"
    )
}

function Parse-PositiveIntArgument {
    param(
        [AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][string]$Name
    )

    $parsed = 0
    if (-not [int]::TryParse(
            $Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsed
        ) -or $parsed -le 0) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_EXPECTATION_INVALID' `
            "$Name must be a positive invariant integer; received '$Value'" `
            'pass the exact independently read owner value'
    }
    return $parsed
}

function Parse-PositiveTicksArgument {
    param(
        [AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][string]$Name
    )

    $parsed = 0L
    if (-not [long]::TryParse(
            $Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsed
        ) -or $parsed -le 0 -or $parsed -gt [DateTime]::MaxValue.Ticks) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_EXPECTATION_INVALID' `
            "$Name must be positive UTC ticks in the DateTime range; received '$Value'" `
            'pass the exact independently read process-start tick value'
    }
    return $parsed
}

function Test-ByteArraysEqual {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Left,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) {
            return $false
        }
    }
    return $true
}

function ConvertTo-AstroComparableFinalPath {
    param([Parameter(Mandatory)][string]$Path)

    $value = $Path
    if ($value.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        $value = '\\' + $value.Substring(8)
    }
    elseif ($value.StartsWith('\\?\', [StringComparison]::Ordinal)) {
        $value = $value.Substring(4)
    }
    return [IO.Path]::GetFullPath($value)
}

function Get-AstroExactRenameLeaseSnapshot {
    param(
        [Parameter(Mandatory)]$Lease,
        [Parameter(Mandatory)][string]$Description
    )

    try {
        $bytes = [AstroLauncherLockNative]::ReadAllBytes(
            $Lease.Handle,
            $script:AstroLauncherProtocolSnapshotMaxBytes
        )
        $identity = [AstroLauncherLockNative]::GetFileIdentity($Lease.Handle)
        $finalPath = ConvertTo-AstroComparableFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($Lease.Handle)
        )
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SOURCE_LEASE_UNEVALUABLE' `
            "$description retained-handle read failed: $($_.Exception.Message)" `
            'preserve every protocol/recovery entry and repair exact file-handle access'
    }
    return [pscustomobject]@{
        Path = $finalPath
        Bytes = $bytes
        Length = [uint64]$bytes.Length
        Sha256 = Get-AstroByteSha256 $bytes
        FileIdentity = $identity
    }
}

function Open-AstroExactRenameLease {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    $full = [IO.Path]::GetFullPath($Path)
    try {
        $handle = [AstroLauncherLockNative]::OpenExactRenameSource($full)
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SOURCE_LEASE_FAILED' `
            "could not open write-denying exact $description lease '$full': $($_.Exception.Message)" `
            'preserve the source and resolve every live writer/delete handle before retrying'
    }
    $lease = [pscustomobject]@{
        Handle = $handle
        OriginalPath = $full
        Description = $Description
    }
    try {
        $snapshot = Get-AstroExactRenameLeaseSnapshot $lease $Description
        if (-not [string]::Equals(
                $snapshot.Path,
                $full,
                [StringComparison]::Ordinal
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SOURCE_ALIAS_REFUSED' `
                "$description lexical path '$full' resolves to retained-handle path '$($snapshot.Path)'" `
                'use the exact canonical non-alias protocol path'
        }
        $lease | Add-Member -NotePropertyName InitialSnapshot `
            -NotePropertyValue $snapshot
        return $lease
    }
    catch {
        $handle.Dispose()
        throw
    }
}

function Open-AstroExactEvidenceLease {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description,
        [switch]$SharedDelete
    )

    $full = [IO.Path]::GetFullPath($Path)
    try {
        $handle = if ($SharedDelete) {
            [AstroLauncherLockNative]::OpenExactSharedDeleteReadFile($full)
        }
        else {
            [AstroLauncherLockNative]::OpenExactProtectedReadFile($full)
        }
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_EVIDENCE_LEASE_FAILED' `
            "could not open exact protected $Description lease '$full': $($_.Exception.Message)" `
            'preserve every recovery entry and resolve the exact file-handle conflict before retrying'
    }
    $lease = [pscustomobject]@{
        Handle = $handle
        OriginalPath = $full
        Description = $Description
    }
    try {
        $snapshot = Get-AstroExactRenameLeaseSnapshot $lease $Description
        if (-not [string]::Equals(
                $snapshot.Path,
                $full,
                [StringComparison]::Ordinal
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_EVIDENCE_ALIAS_REFUSED' `
                "$Description lexical path '$full' resolves to retained-handle path '$($snapshot.Path)'" `
                'use exact canonical non-alias recovery paths'
        }
        $lease | Add-Member -NotePropertyName InitialSnapshot `
            -NotePropertyValue $snapshot
        return $lease
    }
    catch {
        $handle.Dispose()
        throw
    }
}

function Move-AstroRetainedLeaseNoReplace {
    param(
        [Parameter(Mandatory)]$Lease,
        [Parameter(Mandatory)]$DestinationDirectoryHandle,
        [Parameter(Mandatory)][string]$DestinationPath,
        [Parameter(Mandatory)]$ExpectedSnapshot,
        [Parameter(Mandatory)][string]$Description
    )

    $destinationFull = [IO.Path]::GetFullPath($DestinationPath)
    $destinationLeaf = [IO.Path]::GetFileName($destinationFull)
    if ([string]::IsNullOrWhiteSpace($destinationLeaf) -or
        $destinationLeaf.IndexOf([char]'\') -ge 0 -or
        $destinationLeaf.IndexOf([char]'/') -ge 0 -or
        $destinationLeaf.IndexOf([char]':') -ge 0 -or
        $destinationLeaf.EndsWith('.', [StringComparison]::Ordinal) -or
        $destinationLeaf.EndsWith(' ', [StringComparison]::Ordinal)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ARCHIVE_DESTINATION_REFUSED' `
            "$Description destination leaf is not one exact non-ADS filename: '$destinationLeaf'" `
            'preserve every entry and use a canonical ordinary-file destination leaf'
    }
    try {
        $destinationDirectoryIdentityBefore =
            [AstroLauncherLockNative]::GetFileIdentity(
                $DestinationDirectoryHandle
            )
        $destinationDirectoryPathBefore = ConvertTo-AstroComparableFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath(
                $DestinationDirectoryHandle
            )
        )
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ARCHIVE_PARENT_UNEVALUABLE' `
            "$Description retained destination-directory identity/path is unevaluable: $($_.Exception.Message)" `
            'preserve every entry and repair exact retained directory-handle access'
    }
    if (-not [string]::Equals(
            $destinationDirectoryPathBefore,
            [IO.Path]::GetDirectoryName($destinationFull),
            [StringComparison]::Ordinal
        )) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ARCHIVE_PARENT_MISMATCH' `
            "$Description destination parent '$([IO.Path]::GetDirectoryName($destinationFull))' differs from retained directory '$destinationDirectoryPathBefore'" `
            'preserve every entry; rename only through the exact parent handle bound to the destination path'
    }
    $destinationState = Get-AstroPathEntryState $destinationFull
    if ($destinationState.State -ne 'absent') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ARCHIVE_DESTINATION_REFUSED' `
            "$Description destination is not exactly absent (state=$($destinationState.State), error=$($destinationState.Error)): $destinationFull" `
            'preserve every entry and use a fresh append-only recovery basename'
    }
    $before = Get-AstroExactRenameLeaseSnapshot $Lease "$Description before rename"
    if ($before.FileIdentity -cne $ExpectedSnapshot.FileIdentity -or
        $before.Length -ne $ExpectedSnapshot.Length -or
        $before.Sha256 -cne $ExpectedSnapshot.Sha256 -or
        -not (Test-ByteArraysEqual $before.Bytes $ExpectedSnapshot.Bytes) -or
        -not [string]::Equals(
            $before.Path,
            $Lease.OriginalPath,
            [StringComparison]::Ordinal
        )) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_LOCK_CHANGED' `
            "$Description retained source changed before its exact archive rename" `
            'preserve every entry and post new evidence for the current exact path/identity/bytes'
    }
    try {
        [AstroLauncherLockNative]::RenameFileHandleNoReplace(
            $Lease.Handle,
            $DestinationDirectoryHandle,
            $destinationLeaf
        )
    }
    catch {
        $renameFaultMessage = $_.Exception.Message
        $postRenameDescription = try {
            $ambiguous = Get-AstroExactRenameLeaseSnapshot `
                $Lease `
                "$Description after failed rename call"
            "retained_path=$($ambiguous.Path), file_identity=$($ambiguous.FileIdentity), bytes=$($ambiguous.Length), sha256=$($ambiguous.Sha256)"
        }
        catch {
            "retained_poststate_unevaluable=$($_.Exception.Message)"
        }
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ARCHIVE_MOVE_FAILED' `
            "$Description exact retained-handle archive rename failed: $renameFaultMessage; $postRenameDescription" `
            'preserve every protocol and recovery entry; inspect the retained source/destination poststate before retrying'
    }
    try {
        [AstroLauncherLockNative]::FlushExactFile($Lease.Handle)
    }
    catch {
        $flushFaultMessage = $_.Exception.Message
        $renamedButUnflushed = try {
            $flushSnapshot = Get-AstroExactRenameLeaseSnapshot `
                $Lease `
                "$Description after flush failure"
            "retained_path=$($flushSnapshot.Path), file_identity=$($flushSnapshot.FileIdentity), bytes=$($flushSnapshot.Length), sha256=$($flushSnapshot.Sha256)"
        }
        catch {
            "retained_poststate_unevaluable=$($_.Exception.Message)"
        }
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ARCHIVE_FLUSH_FAILED' `
            "$Description rename succeeded but exact file flush failed: $flushFaultMessage; $renamedButUnflushed" `
            'preserve the renamed file and every recovery entry; inspect storage durability before any retry'
    }
    $after = Get-AstroExactRenameLeaseSnapshot $Lease "$Description after rename"
    if ($after.FileIdentity -cne $ExpectedSnapshot.FileIdentity -or
        $after.Length -ne $ExpectedSnapshot.Length -or
        $after.Sha256 -cne $ExpectedSnapshot.Sha256 -or
        -not (Test-ByteArraysEqual $after.Bytes $ExpectedSnapshot.Bytes) -or
        -not [string]::Equals(
            $after.Path,
            $destinationFull,
            [StringComparison]::Ordinal
        ) -or
        (Get-AstroPathEntryState $Lease.OriginalPath).State -ne 'absent') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ARCHIVE_MISMATCH' `
            "$Description retained-handle post-rename identity/path/bytes or original-path absence differs from the authorized transition" `
            'preserve all state and investigate filesystem semantics before any new claim'
    }
    try {
        $destinationDirectoryIdentityAfter =
            [AstroLauncherLockNative]::GetFileIdentity(
                $DestinationDirectoryHandle
            )
        $destinationDirectoryPathAfter = ConvertTo-AstroComparableFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath(
                $DestinationDirectoryHandle
            )
        )
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ARCHIVE_PARENT_UNEVALUABLE' `
            "$Description retained destination-directory terminal identity/path is unevaluable: $($_.Exception.Message)" `
            'preserve every entry and investigate the exact directory-handle boundary'
    }
    if ($destinationDirectoryIdentityAfter -cne
            $destinationDirectoryIdentityBefore -or
        -not [string]::Equals(
            $destinationDirectoryPathAfter,
            $destinationDirectoryPathBefore,
            [StringComparison]::Ordinal
        )) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ARCHIVE_PARENT_MISMATCH' `
            "$Description retained destination directory identity/path changed across the rename" `
            'preserve every entry and investigate directory replacement or alias drift'
    }
    $observer = Open-AstroExactEvidenceLease `
        $destinationFull `
        "$Description independent archive readback" `
        -SharedDelete
    $observed = $observer.InitialSnapshot
    if ($observed.FileIdentity -cne $after.FileIdentity -or
        $observed.Length -ne $after.Length -or
        $observed.Sha256 -cne $after.Sha256 -or
        -not (Test-ByteArraysEqual $observed.Bytes $after.Bytes)) {
        $observer.Handle.Dispose()
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ARCHIVE_MISMATCH' `
            "$Description independently opened archive differs from the retained renamed file" `
            'preserve all state and investigate path/FILE_ID ambiguity before any new claim'
    }
    return [pscustomobject]@{
        RetainedSnapshot = $after
        ObserverLease = $observer
        ObserverSnapshot = $observed
    }
}

function Initialize-AstroReclaimPublicationNative {
    if ('AstroReclaimPublicationNative' -as [type]) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class AstroReclaimPublicationNative
{
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint DELETE_ACCESS = 0x00010000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint CREATE_NEW = 1;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
    private const uint FILE_FLAG_DELETE_ON_CLOSE = 0x04000000;
    private const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_TYPE_DISK = 0x0001;

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
    private static extern bool WriteFile(
        SafeFileHandle file,
        byte[] buffer,
        uint bytesToWrite,
        out uint bytesWritten,
        IntPtr overlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(SafeFileHandle file);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(SafeFileHandle file);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(
        string newFileName,
        string existingFileName,
        IntPtr securityAttributes
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out BY_HANDLE_FILE_INFORMATION information
    );

    private static void RequireHandle(SafeFileHandle handle, string description)
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
                description + " is not a local disk file handle (type=" + type + ")"
            );
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
                "could not inspect " + description
            );
        }
        return information;
    }

    private static void RequireOrdinaryLinks(
        SafeFileHandle handle,
        uint expectedLinks,
        string description,
        string path
    )
    {
        BY_HANDLE_FILE_INFORMATION information =
            ReadBasicInformation(handle, description);
        if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
            (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            information.NumberOfLinks != expectedLinks)
        {
            throw new InvalidOperationException(
                description + " must be an ordinary non-reparse file with exactly " +
                expectedLinks + " links; observed links=" +
                information.NumberOfLinks + ": " + path
            );
        }
    }

    public static SafeFileHandle CreateDeleteOnCloseReadLease(string path)
    {
        SafeFileHandle handle = CreateFileW(
            path,
            GENERIC_READ | DELETE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE |
                FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero
        );
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(
                error,
                "could not create exact delete-on-close publication stage: " + path
            );
        }
        try
        {
            RequireHandle(handle, "delete-on-close publication stage");
            RequireOrdinaryLinks(
                handle,
                1,
                "delete-on-close publication stage",
                path
            );
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static SafeFileHandle OpenPublicationWriter(string path)
    {
        SafeFileHandle handle = CreateFileW(
            path,
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero
        );
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(
                error,
                "could not open exact transient publication writer: " + path
            );
        }
        try
        {
            RequireHandle(handle, "transient publication writer");
            RequireOrdinaryLinks(
                handle,
                1,
                "transient publication writer",
                path
            );
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static void WriteAndFlush(SafeFileHandle handle, byte[] bytes)
    {
        RequireHandle(handle, "delete-on-close publication stage");
        if (bytes == null || bytes.Length == 0)
        {
            throw new ArgumentException("publication bytes must be nonempty", "bytes");
        }
        int offset = 0;
        while (offset < bytes.Length)
        {
            int remaining = bytes.Length - offset;
            byte[] chunk = new byte[remaining];
            Buffer.BlockCopy(bytes, offset, chunk, 0, remaining);
            uint written;
            if (!WriteFile(handle, chunk, (uint)chunk.Length, out written, IntPtr.Zero))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "could not write exact delete-on-close publication stage"
                );
            }
            if (written == 0 || written > (uint)remaining)
            {
                throw new IOException(
                    "delete-on-close publication stage write made invalid progress"
                );
            }
            offset += (int)written;
        }
        if (!FlushFileBuffers(handle))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "could not durably flush delete-on-close publication stage"
            );
        }
    }

    public static void CreateHardLinkNoReplace(
        string destinationPath,
        string stagePath
    )
    {
        if (!CreateHardLinkW(destinationPath, stagePath, IntPtr.Zero))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "could not create no-replace immutable publication hard link from " +
                    stagePath + " to " + destinationPath
            );
        }
    }

    private static SafeFileHandle OpenLinkedPublicationFile(
        string path,
        bool retainRenameAuthority
    )
    {
        SafeFileHandle handle = CreateFileW(
            path,
            retainRenameAuthority
                ? GENERIC_READ | GENERIC_WRITE | DELETE_ACCESS
                : GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero
        );
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(
                error,
                "could not open linked immutable publication final: " + path
            );
        }
        try
        {
            RequireHandle(handle, "linked immutable publication final");
            RequireOrdinaryLinks(
                handle,
                2,
                "linked immutable publication final",
                path
            );
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static SafeFileHandle OpenLinkedPublicationReadFile(string path)
    {
        return OpenLinkedPublicationFile(path, false);
    }

    public static SafeFileHandle OpenLinkedPublicationRenameFile(string path)
    {
        return OpenLinkedPublicationFile(path, true);
    }

}
'@
}

function Publish-AstroImmutableBytesNoReplace {
    param(
        [Parameter(Mandatory)][string]$DestinationPath,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$StageDirectoryPath,
        [Parameter(Mandatory)]$StageDirectoryHandle,
        [Parameter(Mandatory)]$DestinationDirectoryHandle,
        [switch]$RetainRenameAuthority
    )

    $destinationFull = [IO.Path]::GetFullPath($DestinationPath)
    $stageDirectoryFull = [IO.Path]::GetFullPath(
        $StageDirectoryPath
    ).TrimEnd('\', '/')
    if ($Bytes.Length -eq 0 -or
        $Bytes.Length -gt $script:AstroLauncherProtocolSnapshotMaxBytes) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_BYTES_INVALID' `
            "$Description must contain 1-$script:AstroLauncherProtocolSnapshotMaxBytes bytes before publication" `
            'preserve source/evidence and investigate the bounded record serialization'
    }
    $destinationLeaf = [IO.Path]::GetFileName($destinationFull)
    if ([string]::IsNullOrWhiteSpace($destinationLeaf) -or
        $destinationLeaf.IndexOf([char]'\') -ge 0 -or
        $destinationLeaf.IndexOf([char]'/') -ge 0 -or
        $destinationLeaf.IndexOf([char]':') -ge 0 -or
        $destinationLeaf.EndsWith('.', [StringComparison]::Ordinal) -or
        $destinationLeaf.EndsWith(' ', [StringComparison]::Ordinal)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_DESTINATION_REFUSED' `
            "$Description destination leaf is not one exact non-ADS filename: '$destinationLeaf'" `
            'preserve all state and use one canonical ordinary-file destination name'
    }
    try {
        $stageDirectoryIdentity = [AstroLauncherLockNative]::GetFileIdentity(
            $StageDirectoryHandle
        )
        $stageDirectoryRetainedPath = ConvertTo-AstroComparableFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath(
                $StageDirectoryHandle
            )
        )
        $destinationDirectoryIdentity =
            [AstroLauncherLockNative]::GetFileIdentity(
                $DestinationDirectoryHandle
            )
        $destinationDirectoryRetainedPath =
            ConvertTo-AstroComparableFinalPath (
                [AstroLauncherLockNative]::GetFileFinalPath(
                    $DestinationDirectoryHandle
                )
            )
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_PARENT_UNEVALUABLE' `
            "$Description retained publication directory is unevaluable: $($_.Exception.Message)" `
            'preserve all state and repair exact retained directory-handle access'
    }
    if (-not [string]::Equals(
            $stageDirectoryRetainedPath,
            $stageDirectoryFull,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            $destinationDirectoryRetainedPath,
            [IO.Path]::GetDirectoryName($destinationFull),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_PARENT_MISMATCH' `
            "$Description lexical stage/destination parent differs from its retained directory handle" `
            'preserve all state and publish only through exact canonical retained directories'
    }
    if (-not [string]::Equals(
            [IO.Path]::GetPathRoot($stageDirectoryFull),
            [IO.Path]::GetPathRoot($destinationFull),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_VOLUME_MISMATCH' `
            "$Description stage and final path are on different volumes" `
            'keep recovery and protocol publication names on one native Windows volume'
    }
    $destinationInitial = Get-AstroPathEntryState $destinationFull
    if ($destinationInitial.State -ne 'absent') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_DESTINATION_REFUSED' `
            "$Description destination is not exactly absent (state=$($destinationInitial.State), error=$($destinationInitial.Error)): $destinationFull" `
            'preserve all state; use a fresh append-only basename or resume only the exact existing marker transaction'
    }

    $stageLeaf = "reclaim-publish-$([Guid]::NewGuid().ToString('N')).tmp"
    $stageFull = [IO.Path]::GetFullPath((Join-Path `
        $stageDirectoryFull `
        $stageLeaf
    ))
    Assert-AstroRecoveryArtifactLeaf $stageFull
    if ((Get-AstroPathEntryState $stageFull).State -ne 'absent') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_STAGE_CONFLICT' `
            "$Description fresh delete-on-close publication stage is not absent: $stageFull" `
            'preserve the conflicting entry and retry with a fresh recovery transaction'
    }

    $stageHandle = $null
    $writerHandle = $null
    $linkedFinalHandle = $null
    $publicationFault = $null
    $stageSnapshot = $null
    $linkedSnapshot = $null
    $linkedLease = $null
    try {
        $stageHandle =
            [AstroReclaimPublicationNative]::CreateDeleteOnCloseReadLease(
                $stageFull
            )
        $writerHandle =
            [AstroReclaimPublicationNative]::OpenPublicationWriter($stageFull)
        [AstroReclaimPublicationNative]::WriteAndFlush(
            $writerHandle,
            $Bytes
        )
        $writerHandle.Dispose()
        $writerHandle = $null

        $stageLease = [pscustomobject]@{
            Handle = $stageHandle
            OriginalPath = $stageFull
            Description = "$Description delete-on-close publication stage"
        }
        $stageSnapshot = Get-AstroExactRenameLeaseSnapshot `
            $stageLease `
            "$Description delete-on-close publication stage"
        if ($stageSnapshot.Length -ne $Bytes.Length -or
            $stageSnapshot.Sha256 -cne (Get-AstroByteSha256 $Bytes) -or
            -not (Test-ByteArraysEqual $stageSnapshot.Bytes $Bytes) -or
            -not [string]::Equals(
                $stageSnapshot.Path,
                $stageFull,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_STAGE_MISMATCH' `
                "$Description delete-on-close stage retained readback/path differs before hard-link publication" `
                'preserve source/evidence; the uncommitted stage disappears with its exact owner handle'
        }
        if ((Get-AstroPathEntryState $destinationFull).State -ne 'absent') {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_DESTINATION_REFUSED' `
                "$Description destination appeared before the no-replace hard-link commit: $destinationFull" `
                'preserve every entry and use a fresh append-only recovery transaction'
        }
        if ([AstroLauncherLockNative]::GetFileIdentity(
                $StageDirectoryHandle
            ) -cne $stageDirectoryIdentity -or
            [AstroLauncherLockNative]::GetFileIdentity(
                $DestinationDirectoryHandle
            ) -cne $destinationDirectoryIdentity) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_PARENT_MISMATCH' `
                "$Description retained stage/destination directory identity changed before publication" `
                'preserve every entry and investigate exact directory replacement or alias drift'
        }

        [AstroReclaimPublicationNative]::CreateHardLinkNoReplace(
            $destinationFull,
            $stageFull
        )
        $linkedFinalHandle = if ($RetainRenameAuthority) {
            [AstroReclaimPublicationNative]::OpenLinkedPublicationRenameFile(
                $destinationFull
            )
        }
        else {
            [AstroReclaimPublicationNative]::OpenLinkedPublicationReadFile(
                $destinationFull
            )
        }
        $linkedLease = [pscustomobject]@{
            Handle = $linkedFinalHandle
            OriginalPath = $destinationFull
            Description = "$Description retained linked final"
        }
        $linkedSnapshot = Get-AstroExactRenameLeaseSnapshot `
            $linkedLease `
            "$Description linked final before stage retirement"
        if ($linkedSnapshot.FileIdentity -cne $stageSnapshot.FileIdentity -or
            $linkedSnapshot.Length -ne $stageSnapshot.Length -or
            $linkedSnapshot.Sha256 -cne $stageSnapshot.Sha256 -or
            -not (Test-ByteArraysEqual `
                $linkedSnapshot.Bytes `
                $stageSnapshot.Bytes) -or
            -not [string]::Equals(
                $linkedSnapshot.Path,
                $destinationFull,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_LINK_MISMATCH' `
                "$Description two-link final differs from the retained flushed stage FILE_ID/hash/bytes" `
                'preserve the complete final link and investigate exact hard-link filesystem semantics'
        }
        if ([AstroLauncherLockNative]::GetFileIdentity(
                $StageDirectoryHandle
            ) -cne $stageDirectoryIdentity -or
            [AstroLauncherLockNative]::GetFileIdentity(
                $DestinationDirectoryHandle
            ) -cne $destinationDirectoryIdentity -or
            -not [string]::Equals(
                (ConvertTo-AstroComparableFinalPath (
                    [AstroLauncherLockNative]::GetFileFinalPath(
                        $StageDirectoryHandle
                    )
                )),
                $stageDirectoryRetainedPath,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [string]::Equals(
                (ConvertTo-AstroComparableFinalPath (
                    [AstroLauncherLockNative]::GetFileFinalPath(
                        $DestinationDirectoryHandle
                    )
                )),
                $destinationDirectoryRetainedPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_PARENT_MISMATCH' `
                "$Description retained stage/destination directory identity or final path changed across publication" `
                'preserve the complete final link and investigate exact directory replacement or alias drift'
        }
    }
    catch {
        $publicationFault = $_
    }
    finally {
        if ($null -ne $writerHandle) {
            try { $writerHandle.Dispose() } catch {
                if ($null -eq $publicationFault) { $publicationFault = $_ }
            }
            $writerHandle = $null
        }
        if ($null -ne $stageHandle) {
            try { $stageHandle.Dispose() } catch {
                if ($null -eq $publicationFault) { $publicationFault = $_ }
            }
            $stageHandle = $null
        }
    }
    $stageTerminal = Get-AstroPathEntryState $stageFull
    if ($stageTerminal.State -ne 'absent') {
        $linkedDisposalFault = $null
        if ($null -ne $linkedFinalHandle) {
            try { $linkedFinalHandle.Dispose() } catch {
                $linkedDisposalFault = $_.Exception.Message
            }
            $linkedFinalHandle = $null
        }
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_STAGE_REMAINS' `
            "$Description delete-on-close stage did not become absent (state=$($stageTerminal.State), error=$($stageTerminal.Error), linked_disposal_fault=$linkedDisposalFault): $stageFull" `
            'preserve every entry and inspect exact kernel delete-on-close semantics; never path-delete a publication stage'
    }
    if ($null -ne $publicationFault) {
        if ($null -ne $linkedFinalHandle) {
            try { $linkedFinalHandle.Dispose() } catch {
                $publicationFault.Exception.Data['AstroLinkedLeaseDisposalFault'] =
                    $_.Exception.Message
            }
            $linkedFinalHandle = $null
        }
        throw $publicationFault
    }

    $observer = $null
    try {
        $linkedTerminal = Get-AstroExactRenameLeaseSnapshot `
            $linkedLease `
            "$Description retained final after stage retirement"
        if ($linkedTerminal.FileIdentity -cne $linkedSnapshot.FileIdentity -or
            $linkedTerminal.Length -ne $linkedSnapshot.Length -or
            $linkedTerminal.Sha256 -cne $linkedSnapshot.Sha256 -or
            -not (Test-ByteArraysEqual `
                $linkedTerminal.Bytes `
                $linkedSnapshot.Bytes) -or
            -not [string]::Equals(
                $linkedTerminal.Path,
                $destinationFull,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_FINAL_MISMATCH' `
                "$Description retained one-link final differs after delete-on-close stage retirement" `
                'preserve every entry and investigate exact hard-link retirement/FILE_ID/byte drift'
        }
        $linkedLease | Add-Member -NotePropertyName InitialSnapshot `
            -NotePropertyValue $linkedTerminal
        $observer = Open-AstroExactEvidenceLease `
            $destinationFull `
            "$Description independent one-link final readback" `
            -SharedDelete:$RetainRenameAuthority
        $terminalSnapshot = $observer.InitialSnapshot
        if ($terminalSnapshot.FileIdentity -cne $linkedTerminal.FileIdentity -or
            $terminalSnapshot.Length -ne $linkedTerminal.Length -or
            $terminalSnapshot.Sha256 -cne $linkedTerminal.Sha256 -or
            -not (Test-ByteArraysEqual `
                $terminalSnapshot.Bytes `
                $linkedTerminal.Bytes)) {
            $observer.Handle.Dispose()
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PUBLICATION_FINAL_MISMATCH' `
                "$Description independent one-link readback differs from retained publication authority" `
                'preserve every entry and investigate exact FILE_ID/hash/byte drift'
        }
        if (-not $RetainRenameAuthority) {
            $linkedFinalHandle.Dispose()
            $linkedFinalHandle = $null
            $linkedLease = $null
        }
        return [pscustomobject]@{
            RetainedLease = $linkedLease
            ObserverLease = $observer
            Snapshot = $terminalSnapshot
            StagePath = $stageFull
            PublicationPrimitive =
                'delete-on-close-stage-hard-link-no-replace-v1'
        }
    }
    catch {
        $terminalFault = $_
        if ($null -ne $observer -and $null -ne $observer.Handle) {
            try { $observer.Handle.Dispose() } catch {
                $terminalFault.Exception.Data[
                    'AstroPublicationObserverDisposalFault'
                ] = $_.Exception.Message
            }
        }
        if ($null -ne $linkedFinalHandle) {
            try { $linkedFinalHandle.Dispose() } catch {
                $terminalFault.Exception.Data[
                    'AstroLinkedLeaseDisposalFault'
                ] = $_.Exception.Message
            }
        }
        throw $terminalFault
    }
}

function Write-NewDurableBytes {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$StageDirectoryPath,
        [Parameter(Mandatory)]$StageDirectoryHandle,
        [Parameter(Mandatory)]$DestinationDirectoryHandle,
        [switch]$RetainRenameAuthority
    )

    return Publish-AstroImmutableBytesNoReplace `
        -DestinationPath $LiteralPath `
        -Bytes $Bytes `
        -Description $Description `
        -StageDirectoryPath $StageDirectoryPath `
        -StageDirectoryHandle $StageDirectoryHandle `
        -DestinationDirectoryHandle $DestinationDirectoryHandle `
        -RetainRenameAuthority:$RetainRenameAuthority
}

function Write-NewDurableJsonAndReadBack {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$StageDirectoryPath,
        [Parameter(Mandatory)]$StageDirectoryHandle,
        [Parameter(Mandatory)]$DestinationDirectoryHandle
    )

    $text = $Value | ConvertTo-Json -Depth 24 -Compress
    $expectedBytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
    if ($expectedBytes.Length -eq 0 -or
        $expectedBytes.Length -gt
            $script:AstroLauncherProtocolSnapshotMaxBytes) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_SIZE_REFUSED' `
            "$Description serialized size $($expectedBytes.Length) is outside the 1-$script:AstroLauncherProtocolSnapshotMaxBytes byte protocol bound" `
            'preserve source/evidence and investigate or reduce the authorization record before publishing any final name'
    }
    $publication = Write-NewDurableBytes `
        -LiteralPath $LiteralPath `
        -Bytes $expectedBytes `
        -Description $Description `
        -StageDirectoryPath $StageDirectoryPath `
        -StageDirectoryHandle $StageDirectoryHandle `
        -DestinationDirectoryHandle $DestinationDirectoryHandle
    try {
        $snapshot = $publication.Snapshot
        if (-not (Test-ByteArraysEqual $expectedBytes $snapshot.Bytes)) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_READBACK_MISMATCH' `
                "$description byte readback differs from the exact serialized bytes: $LiteralPath" `
                'preserve the record and lock; investigate storage corruption'
        }
        try {
            $persisted = [Text.UTF8Encoding]::new($false, $true).GetString(
                $snapshot.Bytes
            ) | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_READBACK_INVALID' `
                "$description exact bytes are not readable JSON: $($_.Exception.Message)" `
                'preserve the record and lock; investigate serialization/storage'
        }
        return [pscustomobject]@{
            Snapshot = $snapshot
            Persisted = $persisted
            ExpectedBytes = $expectedBytes
            PublicationLease = $publication.ObserverLease
            PublicationPrimitive = $publication.PublicationPrimitive
            PublicationStagePath = $publication.StagePath
        }
    }
    catch {
        $readbackFault = $_
        try { $publication.ObserverLease.Handle.Dispose() } catch {
            $readbackFault.Exception.Data[
                'AstroPublicationLeaseDisposalFault'
            ] = $_.Exception.Message
        }
        throw $readbackFault
    }
}

function Assert-NoReparseAncestors {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Boundary,
        [Parameter(Mandatory)][string]$Description
    )

    $boundaryFull = [IO.Path]::GetFullPath($Boundary).TrimEnd('\', '/')
    $cursor = [IO.Path]::GetFullPath($Path)
    $presence = Get-AstroPathEntryState $cursor
    if ($presence.State -eq 'absent') {
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    elseif ($presence.State -eq 'unevaluable') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PATH_UNEVALUABLE' `
            "$description presence is unevaluable at '$cursor': $($presence.Error)" `
            'preserve all state and retry only when every path component is readable'
    }
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $state = Get-AstroPathEntryState $cursor
        if ($state.State -eq 'unevaluable') {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PATH_UNEVALUABLE' `
                "$description ancestor is unevaluable at '$cursor': $($state.Error)" `
                'preserve all state and repair path access before retrying'
        }
        if ($state.State -eq 'present' -and
            ($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_REPARSE_REFUSED' `
                "$description traverses reparse point '$cursor'" `
                'use the canonical non-reparse workspace path; recovery never follows redirects'
        }
        if ([string]::Equals(
                $cursor.TrimEnd('\', '/'),
                $boundaryFull,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            return
        }
        $parent = [IO.Path]::GetDirectoryName($cursor.TrimEnd('\', '/'))
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) {
            break
        }
        $cursor = $parent
    }
    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ROOT_ESCAPE' `
        "$description '$Path' does not stay below boundary '$boundaryFull'" `
        'use the canonical checkout, a registered worktree, or an isolated fixture below it'
}

function Assert-AstroRecoveryRecordLeaf {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(6, 128)][int]$MaxLength = 96
    )

    $leaf = [IO.Path]::GetFileName($Path)
    $reservedDevice =
        '^(?i:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])(?:\.|\z)'
    if ($leaf.Length -lt 6 -or $leaf.Length -gt $MaxLength -or
        $leaf -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*\.json\z' -or
        $leaf -match $reservedDevice -or
        $leaf.EndsWith('.', [StringComparison]::Ordinal) -or
        $leaf.EndsWith(' ', [StringComparison]::Ordinal) -or
        $leaf.IndexOf(':') -ge 0) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_LEAF_INVALID' `
            "recovery JSON leaf must be a 6-$MaxLength character ordinary filename with no ADS, device alias, separator, trailing dot, or trailing space: '$leaf'" `
            'use a fresh ASCII alphanumeric/dot/dash/underscore .json basename directly below lock-recovery'
    }
}

function Assert-AstroRecoveryArtifactLeaf {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 160)][int]$MaxLength = 128
    )

    $leaf = [IO.Path]::GetFileName($Path)
    $reservedDevice =
        '^(?i:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])(?:\.|\z)'
    if ($leaf.Length -eq 0 -or $leaf.Length -gt $MaxLength -or
        $leaf -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*\z' -or
        $leaf -match $reservedDevice -or
        $leaf.EndsWith('.', [StringComparison]::Ordinal) -or
        $leaf.EndsWith(' ', [StringComparison]::Ordinal) -or
        $leaf.IndexOf(':') -ge 0) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_LEAF_INVALID' `
            "recovery artifact leaf is not one 1-$MaxLength character ordinary non-ADS/non-device filename: '$leaf'" `
            'use a fresh ASCII alphanumeric/dot/dash/underscore basename directly below lock-recovery'
    }
}

function Convert-AstroLegacyOwnerBytesToState {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Bytes.Length -gt $script:AstroLauncherLockMaxBytes) {
        throw "legacy launcher lock exceeds the $script:AstroLauncherLockMaxBytes-byte schema limit"
    }
    $document = Read-AstroStrictJsonDocumentObject `
        $Bytes `
        "legacy launcher lock '$Path'"
    $required = @('pid', 'issue', 'started', 'command')
    $allowed = @(
        'pid',
        'issue',
        'started',
        'command',
        'schema',
        'head_sha',
        'status_sha256',
        'diff_sha256'
    )
    foreach ($name in $required) {
        if (-not $document.Properties.ContainsKey($name)) {
            throw "legacy launcher lock is missing '$name'"
        }
    }
    foreach ($name in @($document.Names)) {
        if (-not ($allowed -ccontains $name)) {
            throw "legacy launcher lock contains unsupported property '$name'"
        }
    }
    $properties = $document.Properties
    $pidValue = 0L
    $issueValue = 0L
    if ($properties['pid'].Kind -cne 'integer' -or
        -not [long]::TryParse(
            [string]$properties['pid'].Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$pidValue
        ) -or $pidValue -le 0 -or $pidValue -gt [int]::MaxValue -or
        $properties['issue'].Kind -cne 'integer' -or
        -not [long]::TryParse(
            [string]$properties['issue'].Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$issueValue
        ) -or $issueValue -le 0 -or $issueValue -gt [int]::MaxValue) {
        throw 'legacy pid/issue must be positive integral JSON numbers'
    }
    if ($properties['command'].Kind -cne 'string' -or
        [string]::IsNullOrWhiteSpace([string]$properties['command'].Value)) {
        throw 'legacy command must be a nonblank JSON string'
    }
    if ($properties['started'].Kind -cne 'string') {
        throw 'legacy started must be an exact round-trip ISO JSON string'
    }
    $schema = if ($properties.ContainsKey('schema')) {
        if ($properties['schema'].Kind -cne 'string') {
            throw 'legacy schema, when present, must be a JSON string'
        }
        [string]$properties['schema'].Value
    }
    else {
        'legacy-unversioned'
    }
    if ($schema -cne 'legacy-unversioned' -and
        $schema -cne 'astrolabe.launcher-lock.v1') {
        throw "LegacyPidOnly refuses schema '$schema'"
    }
    $parsedStarted = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            [string]$properties['started'].Value,
            'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsedStarted
        )) {
        throw 'legacy started ISO diagnostic is invalid'
    }
    foreach ($field in @('head_sha', 'status_sha256', 'diff_sha256')) {
        if ($properties.ContainsKey($field) -and
            $properties[$field].Kind -cne 'string') {
            throw "legacy $field must be a JSON string when present"
        }
    }
    $fingerprintCount = @(
        'head_sha',
        'status_sha256',
        'diff_sha256'
    ).Where({ $properties.ContainsKey($_) }).Count
    if ($fingerprintCount -ne 0 -and $fingerprintCount -ne 3) {
        throw 'legacy repository fingerprints must be either entirely absent or contain head_sha/status_sha256/diff_sha256 together'
    }
    if ($properties.ContainsKey('head_sha') -and
        [string]$properties['head_sha'].Value -cnotmatch '^[0-9a-f]{40}$') {
        throw 'legacy head_sha, when present, must be exactly 40 lowercase hexadecimal characters'
    }
    foreach ($field in @('status_sha256', 'diff_sha256')) {
        if ($properties.ContainsKey($field) -and
            [string]$properties[$field].Value -cnotmatch '^[0-9a-f]{64}$') {
            throw "legacy $field, when present, must be exactly 64 lowercase hexadecimal characters"
        }
    }
    return [pscustomobject]@{
        Schema = $schema
        Legacy = $true
        Pid = [int]$pidValue
        Issue = [int]$issueValue
        LeaseStartUtcTicks = [long]$parsedStarted.UtcTicks
        StartedUtc = $parsedStarted.UtcDateTime.ToString('o')
        OwnerProcessStartUtcTicks = $null
        OwnerProcessStartedUtc = $null
        Command = [string]$properties['command'].Value
        HeadSha = if ($properties.ContainsKey('head_sha')) {
            [string]$properties['head_sha'].Value
        } else { $null }
        StatusSha256 = if ($properties.ContainsKey('status_sha256')) {
            [string]$properties['status_sha256'].Value
        } else { $null }
        DiffSha256 = if ($properties.ContainsKey('diff_sha256')) {
            [string]$properties['diff_sha256'].Value
        } else { $null }
    }
}

function Get-AstroEmbeddedOwnerIdentity {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Path
    )

    $raw = $null
    try {
        $raw = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        $document = Read-AstroStrictJsonDocumentObject `
            $Bytes `
            "embedded launcher owner '$Path'"
    }
    catch {
        $ownerIndicator = $false
        $lossyAscii = [Text.Encoding]::ASCII.GetString($Bytes)
        foreach ($literal in @(
                '"pid"',
                '"issue"',
                '"owner_process_start_utc_ticks"',
                '"owner_process_started_utc"',
                'astrolabe.launcher-lock.v2',
                'astrolabe.launcher-lock.v3'
            )) {
            if ($lossyAscii.IndexOf($literal, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $ownerIndicator = $true
            }
        }
        if ($null -ne $raw) {
            $cursor = 0
            while ($cursor -lt $raw.Length) {
                $quote = $raw.IndexOf('"', $cursor)
                if ($quote -lt 0) {
                    break
                }
                try {
                    $token = Read-AstroJsonStringToken $raw $quote
                    $next = Get-AstroJsonNextTokenIndex $raw $token.NextIndex
                    if (([string]$token.Value -iin @(
                                'pid',
                                'issue',
                                'owner_process_start_utc_ticks',
                                'owner_process_started_utc',
                                'schema'
                            ) -and
                            $next -lt $raw.Length -and $raw[$next] -eq ':') -or
                        [string]$token.Value -cin @(
                            'astrolabe.launcher-lock.v2',
                            'astrolabe.launcher-lock.v3'
                        )) {
                        $ownerIndicator = $true
                    }
                    $cursor = $token.NextIndex
                }
                catch {
                    $cursor = $quote + 1
                }
            }
        }
        return [pscustomobject]@{
            State = if ($ownerIndicator) { 'ambiguous' } else { 'unparseable' }
            Path = $Path
            Pid = $null
            Issue = $null
            OwnerProcessStartUtcTicks = $null
            Error = if ($ownerIndicator) {
                "malformed bytes contain one or more decoded/ASCII launcher-owner indicators: $($_.Exception.Message)"
            } else { $_.Exception.Message }
        }
    }

    $properties = $document.Properties
    $schemaIsModern = $properties.ContainsKey('schema') -and
        $properties['schema'].Kind -ceq 'string' -and
        [string]$properties['schema'].Value -cin @(
            'astrolabe.launcher-lock.v2',
            'astrolabe.launcher-lock.v3'
        )
    $hasPid = $properties.ContainsKey('pid')
    $hasIssue = $properties.ContainsKey('issue')
    $hasTicks = $properties.ContainsKey('owner_process_start_utc_ticks')
    $hasModernDiagnostic = $properties.ContainsKey('owner_process_started_utc')
    if (-not ($schemaIsModern -or $hasPid -or $hasIssue -or $hasTicks -or
            $hasModernDiagnostic)) {
        return [pscustomobject]@{
            State = 'none'
            Path = $Path
            Pid = $null
            Issue = $null
            OwnerProcessStartUtcTicks = $null
            Error = $null
        }
    }

    $pidValue = 0L
    $issueValue = 0L
    $pidValid = $hasPid -and $properties['pid'].Kind -ceq 'integer' -and
        [long]::TryParse(
            [string]$properties['pid'].Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$pidValue
        ) -and $pidValue -gt 0 -and $pidValue -le [int]::MaxValue
    $issueValid = $hasIssue -and $properties['issue'].Kind -ceq 'integer' -and
        [long]::TryParse(
            [string]$properties['issue'].Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$issueValue
        ) -and $issueValue -gt 0 -and $issueValue -le [int]::MaxValue

    if ($schemaIsModern -or $hasTicks -or $hasModernDiagnostic) {
        $ticksValue = 0L
        $ticksValid = $hasTicks -and
            $properties['owner_process_start_utc_ticks'].Kind -ceq 'integer' -and
            [long]::TryParse(
                [string]$properties['owner_process_start_utc_ticks'].Raw,
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$ticksValue
            ) -and $ticksValue -gt 0 -and
            $ticksValue -le [DateTime]::MaxValue.Ticks
        if (-not ($pidValid -and $issueValid -and $ticksValid)) {
            return [pscustomobject]@{
                State = 'ambiguous'
                Path = $Path
                Pid = if ($pidValid) { [int]$pidValue } else { $null }
                Issue = if ($issueValid) { [int]$issueValue } else { $null }
                OwnerProcessStartUtcTicks = if ($ticksValid) {
                    [long]$ticksValue
                } else { $null }
                Error = 'modern launcher-owner indicators are present but the complete exact PID/issue/process-start identity is not valid'
            }
        }
        return [pscustomobject]@{
            State = 'exact'
            Path = $Path
            Pid = [int]$pidValue
            Issue = [int]$issueValue
            OwnerProcessStartUtcTicks = [long]$ticksValue
            Error = $null
        }
    }

    if (-not ($pidValid -and $issueValid)) {
        return [pscustomobject]@{
            State = 'ambiguous'
            Path = $Path
            Pid = if ($pidValid) { [int]$pidValue } else { $null }
            Issue = if ($issueValid) { [int]$issueValue } else { $null }
            OwnerProcessStartUtcTicks = $null
            Error = 'legacy launcher-owner indicators are present but the complete PID/issue identity is not valid'
        }
    }
    return [pscustomobject]@{
        State = 'legacy'
        Path = $Path
        Pid = [int]$pidValue
        Issue = [int]$issueValue
        OwnerProcessStartUtcTicks = $null
        Error = $null
    }
}

function ConvertFrom-AstroMarkerUnsignedInteger {
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)][string]$Name,
        [switch]$Positive
    )

    $value = [uint64]0
    if ($Entry.Kind -cne 'integer' -or
        -not [uint64]::TryParse(
            [string]$Entry.Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$value
        ) -or ($Positive -and $value -eq 0)) {
        throw "reclaim marker $Name must be a$(if ($Positive) { ' positive' } else { ' nonnegative' }) invariant integer"
    }
    return $value
}

function Convert-AstroReclaimMarkerBytesToState {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Path
    )

    try {
        $document = Read-AstroStrictJsonDocumentObject `
            $Bytes "reclaim marker '$Path'"
        $required = @(
            'schema',
            'phase',
            'transaction_id',
            'legacy_pid_only',
            'owner_pid',
            'owner_issue',
            'owner_process_start_utc_ticks',
            'authorization_path',
            'authorization_bytes',
            'authorization_sha256',
            'authorization_file_identity',
            'finalization_path',
            'finalization_bytes',
            'finalization_sha256',
            'finalization_file_identity',
            'source_path',
            'source_bytes',
            'source_sha256',
            'source_file_identity',
            'source_archive_path',
            'recovery_directory_path',
            'recovery_directory_file_identity',
            'recovery_directory_final_path',
            'preserved_protocol_kind',
            'preserved_protocol_path',
            'preserved_protocol_bytes',
            'preserved_protocol_sha256'
        )
        if (@($document.Names).Count -ne $required.Count) {
            throw 'reclaim marker must contain exactly the required property set'
        }
        for ($index = 0; $index -lt $required.Count; $index++) {
            $name = $required[$index]
            if (-not $document.Properties.ContainsKey($name)) {
                throw "reclaim marker is missing '$name'"
            }
            if ([string]$document.Names[$index] -cne $name -or
                [string]$document.RawNames[$index] -cne ('"' + $name + '"')) {
                throw "reclaim marker field $index must be the exact canonical '$name' property"
            }
        }
        $properties = $document.Properties
        if ($properties['schema'].Kind -cne 'string' -or
            [string]$properties['schema'].Value -cne
                'astrolabe.launcher-lock-reclaim-marker.v3' -or
            $properties['phase'].Kind -cne 'string' -or
            [string]$properties['phase'].Value -cne 'archive-pending') {
            throw 'reclaim marker schema/phase is invalid'
        }
        if ($properties['transaction_id'].Kind -cne 'string' -or
            [string]$properties['transaction_id'].Value -cnotmatch
                '^[0-9a-f]{32}$') {
            throw 'reclaim marker transaction_id must be a lowercase 32-hex GUID token'
        }
        if ($properties['legacy_pid_only'].Kind -cne 'boolean') {
            throw 'reclaim marker legacy_pid_only must be a JSON boolean'
        }
        $legacy = [bool]$properties['legacy_pid_only'].Value
        $ownerPid = ConvertFrom-AstroMarkerUnsignedInteger `
            $properties['owner_pid'] `
            'owner_pid' `
            -Positive
        $ownerIssue = ConvertFrom-AstroMarkerUnsignedInteger `
            $properties['owner_issue'] `
            'owner_issue' `
            -Positive
        if ($ownerPid -gt [int]::MaxValue -or $ownerIssue -gt [int]::MaxValue) {
            throw 'reclaim marker owner PID/issue exceeds the Int32 range'
        }
        $ownerTicks = $null
        if ($legacy) {
            if ($properties['owner_process_start_utc_ticks'].Kind -cne 'null') {
                throw 'legacy reclaim marker owner ticks must be JSON null'
            }
        }
        else {
            $ownerTicksValue = ConvertFrom-AstroMarkerUnsignedInteger `
                $properties['owner_process_start_utc_ticks'] `
                'owner_process_start_utc_ticks' `
                -Positive
            if ($ownerTicksValue -gt [uint64][DateTime]::MaxValue.Ticks) {
                throw 'reclaim marker owner ticks exceed the DateTime range'
            }
            $ownerTicks = [long]$ownerTicksValue
        }

        foreach ($name in @(
                'authorization_path',
                'finalization_path',
                'source_path',
                'source_archive_path',
                'recovery_directory_path',
                'recovery_directory_final_path'
            )) {
            if ($properties[$name].Kind -cne 'string' -or
                [string]::IsNullOrWhiteSpace([string]$properties[$name].Value)) {
                throw "reclaim marker $name must be a nonblank JSON string"
            }
        }
        foreach ($name in @(
                'authorization_sha256',
                'finalization_sha256',
                'source_sha256'
            )) {
            if ($properties[$name].Kind -cne 'string' -or
                [string]$properties[$name].Value -cnotmatch '^[0-9a-f]{64}$') {
                throw "reclaim marker $name must be a lowercase SHA-256 string"
            }
        }
        foreach ($name in @(
                'authorization_file_identity',
                'finalization_file_identity',
                'source_file_identity',
                'recovery_directory_file_identity'
            )) {
            if ($properties[$name].Kind -cne 'string' -or
                [string]$properties[$name].Value -cnotmatch
                    '^[0-9a-f]{16}:[0-9a-f]{32}$') {
                throw "reclaim marker $name must be an exact lowercase FILE_ID_INFO identity"
            }
        }
        $authorizationBytes = ConvertFrom-AstroMarkerUnsignedInteger `
            $properties['authorization_bytes'] `
            'authorization_bytes' `
            -Positive
        $finalizationBytes = ConvertFrom-AstroMarkerUnsignedInteger `
            $properties['finalization_bytes'] `
            'finalization_bytes' `
            -Positive
        $sourceBytes = ConvertFrom-AstroMarkerUnsignedInteger `
            $properties['source_bytes'] `
            'source_bytes'

        if ($properties['preserved_protocol_kind'].Kind -cne 'string') {
            throw 'reclaim marker preserved_protocol_kind must be a JSON string'
        }
        $preservedKind = [string]$properties['preserved_protocol_kind'].Value
        if ($preservedKind -cnotin @('none', 'active', 'transition')) {
            throw "unsupported reclaim marker preserved_protocol_kind '$preservedKind'"
        }
        $preservedPath = $null
        $preservedBytes = $null
        $preservedSha = $null
        if ($preservedKind -ceq 'none') {
            foreach ($name in @(
                    'preserved_protocol_path',
                    'preserved_protocol_bytes',
                    'preserved_protocol_sha256'
                )) {
                if ($properties[$name].Kind -cne 'null') {
                    throw "reclaim marker $name must be JSON null when no protocol entry is preserved"
                }
            }
        }
        else {
            if ($properties['preserved_protocol_path'].Kind -cne 'string' -or
                [string]::IsNullOrWhiteSpace(
                    [string]$properties['preserved_protocol_path'].Value
                )) {
                throw 'reclaim marker preserved_protocol_path must be a nonblank JSON string'
            }
            if ($properties['preserved_protocol_sha256'].Kind -cne 'string' -or
                [string]$properties['preserved_protocol_sha256'].Value -cnotmatch
                    '^[0-9a-f]{64}$') {
                throw 'reclaim marker preserved_protocol_sha256 must be a lowercase SHA-256 string'
            }
            $preservedPath = [IO.Path]::GetFullPath(
                [string]$properties['preserved_protocol_path'].Value
            )
            $preservedBytes = ConvertFrom-AstroMarkerUnsignedInteger `
                $properties['preserved_protocol_bytes'] `
                'preserved_protocol_bytes'
            $preservedSha = [string]$properties['preserved_protocol_sha256'].Value
        }

        return [pscustomobject]@{
            Valid = $true
            Error = $null
            Path = [IO.Path]::GetFullPath($Path)
            TransactionId = [string]$properties['transaction_id'].Value
            LegacyPidOnly = $legacy
            OwnerPid = [int]$ownerPid
            OwnerIssue = [int]$ownerIssue
            OwnerProcessStartUtcTicks = $ownerTicks
            AuthorizationPath = [IO.Path]::GetFullPath(
                [string]$properties['authorization_path'].Value
            )
            AuthorizationBytes = [uint64]$authorizationBytes
            AuthorizationSha256 = [string]$properties['authorization_sha256'].Value
            AuthorizationFileIdentity =
                [string]$properties['authorization_file_identity'].Value
            FinalizationPath = [IO.Path]::GetFullPath(
                [string]$properties['finalization_path'].Value
            )
            FinalizationBytes = [uint64]$finalizationBytes
            FinalizationSha256 = [string]$properties['finalization_sha256'].Value
            FinalizationFileIdentity =
                [string]$properties['finalization_file_identity'].Value
            SourcePath = [IO.Path]::GetFullPath(
                [string]$properties['source_path'].Value
            )
            SourceBytes = [uint64]$sourceBytes
            SourceSha256 = [string]$properties['source_sha256'].Value
            SourceFileIdentity = [string]$properties['source_file_identity'].Value
            SourceArchivePath = [IO.Path]::GetFullPath(
                [string]$properties['source_archive_path'].Value
            )
            RecoveryDirectoryPath = [IO.Path]::GetFullPath(
                [string]$properties['recovery_directory_path'].Value
            )
            RecoveryDirectoryFileIdentity =
                [string]$properties['recovery_directory_file_identity'].Value
            RecoveryDirectoryFinalPath = [IO.Path]::GetFullPath(
                [string]$properties['recovery_directory_final_path'].Value
            )
            PreservedProtocolKind = $preservedKind
            PreservedProtocolPath = $preservedPath
            PreservedProtocolBytes = $preservedBytes
            PreservedProtocolSha256 = $preservedSha
        }
    }
    catch {
        return [pscustomobject]@{
            Valid = $false
            Error = $_.Exception.Message
            Path = [IO.Path]::GetFullPath($Path)
        }
    }
}

function Read-LegacyOwner {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Path
    )

    try {
        return Convert-AstroLegacyOwnerBytesToState $Bytes $Path
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_UNREADABLE' `
            "legacy launcher lock is not a supported strict flat manifest at '$Path': $($_.Exception.Message)" `
            'preserve it or use the separate -QuarantineUnreadable mode with exact tracker evidence'
    }
}

function Read-ExactOwner {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Path
    )

    $state = Convert-AstroLauncherLockBytesToState $Bytes $Path
    if ($state.State -eq 'unreadable') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_UNREADABLE' `
            "exact-owner launcher lock is invalid: $($state.ValidationError)" `
            'preserve it or use the separate -QuarantineUnreadable mode with exact tracker evidence'
    }
    return [pscustomobject]@{
        Schema = $state.Schema
        Legacy = $false
        Pid = $state.OwnerPid
        Issue = $state.Issue
        LeaseStartUtcTicks = $state.LeaseStartUtcTicks
        StartedUtc = $state.Started
        OwnerProcessStartUtcTicks = $state.OwnerProcessStartUtcTicks
        OwnerProcessStartedUtc = $state.OwnerProcessStarted
        Command = $state.Command
        HeadSha = $state.HeadSha
        StatusSha256 = $state.StatusSha256
        DiffSha256 = $state.DiffSha256
    }
}

function Assert-OwnerDead {
    param(
        [Parameter(Mandatory)][int]$OwnerPid,
        [AllowNull()][Nullable[long]]$OwnerProcessStartUtcTicks,
        [Parameter(Mandatory)][bool]$Legacy,
        [Parameter(Mandatory)][string]$ProbeName
    )

    $probe = Get-AstroProcessIdentityProbe $OwnerPid
    if ($probe.State -eq 'unevaluable') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_UNEVALUABLE' `
            "$ProbeName could not evaluate PID ${OwnerPid}: $($probe.Error)" `
            'preserve the lock and retry only when exact process identity is readable'
    }
    if ($Legacy -and $probe.State -ne 'absent') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_LEGACY_PID_OCCUPIED' `
            "$ProbeName found legacy numeric PID $OwnerPid occupied" `
            'wait for that numeric PID to become completely absent; legacy state cannot distinguish reuse'
    }
    if (-not $Legacy -and $probe.State -eq 'observed' -and
        [long]$probe.ProcessStartUtcTicks -eq [long]$OwnerProcessStartUtcTicks) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_LIVE' `
            "$ProbeName found exact owner pid=$OwnerPid start_utc_ticks=$OwnerProcessStartUtcTicks live" `
            'never reclaim a live owner; wait for that exact process to exit naturally'
    }
    $probeState = if ($probe.State -eq 'absent') { 'absent' } else { 'pid-reused' }
    return [ordered]@{
        probe = $ProbeName
        pid = $OwnerPid
        legacy_pid_only = $Legacy
        owner_process_start_utc_ticks = if ($Legacy) {
            $null
        } else {
            [long]$OwnerProcessStartUtcTicks
        }
        owner_process_started_utc = if ($Legacy) {
            $null
        } else {
            ConvertTo-AstroProcessStartUtcIso ([long]$OwnerProcessStartUtcTicks)
        }
        state = $probeState
        numeric_pid_live = $probe.State -eq 'observed'
        owner_live = $false
        pid_reused = $probe.State -eq 'observed'
        observed_process_start_utc_ticks = if ($probe.State -eq 'observed') {
            [long]$probe.ProcessStartUtcTicks
        } else {
            $null
        }
        observed_process_started_utc = $probe.ProcessStartedUtc
        observed_at_utc = [DateTime]::UtcNow.ToString('o')
    }
}

function Assert-AstroJsonUnicodeScalarString {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$JsonPath
    )

    for ($index = 0; $index -lt $Value.Length; $index++) {
        $code = [int]$Value[$index]
        if ($code -ge 0xd800 -and $code -le 0xdbff) {
            if ($index + 1 -ge $Value.Length) {
                throw "$JsonPath contains an unpaired high surrogate"
            }
            $low = [int]$Value[$index + 1]
            if ($low -lt 0xdc00 -or $low -gt 0xdfff) {
                throw "$JsonPath contains an unpaired high surrogate"
            }
            $index++
        }
        elseif ($code -ge 0xdc00 -and $code -le 0xdfff) {
            throw "$JsonPath contains an unpaired low surrogate"
        }
    }
}

function Read-AstroStrictJsonValueNode {
    param(
        [Parameter(Mandatory)][string]$Json,
        [Parameter(Mandatory)][int]$StartIndex,
        [Parameter(Mandatory)][int]$Depth,
        [Parameter(Mandatory)][string]$JsonPath
    )

    if ($Depth -gt 32) {
        throw "$JsonPath exceeds the maximum JSON nesting depth"
    }
    $index = Get-AstroJsonNextTokenIndex $Json $StartIndex
    if ($index -ge $Json.Length) {
        throw "$JsonPath is missing a JSON value"
    }
    $character = $Json[$index]
    if ($character -eq '"') {
        $token = Read-AstroJsonStringToken $Json $index
        Assert-AstroJsonUnicodeScalarString ([string]$token.Value) $JsonPath
        return [pscustomobject]@{
            Kind = 'string'
            Value = [string]$token.Value
            Raw = [string]$token.Raw
            NextIndex = [int]$token.NextIndex
        }
    }
    if ($character -eq '{') {
        $properties = [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::Ordinal
        )
        $names = [Collections.Generic.List[string]]::new()
        $rawNames = [Collections.Generic.List[string]]::new()
        $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
        if ($index -lt $Json.Length -and $Json[$index] -eq '}') {
            return [pscustomobject]@{
                Kind = 'object'
                Properties = $properties
                Names = @()
                RawNames = @()
                NextIndex = $index + 1
            }
        }
        while ($true) {
            $nameToken = Read-AstroJsonStringToken $Json $index
            $name = [string]$nameToken.Value
            Assert-AstroJsonUnicodeScalarString $name "$JsonPath property name"
            if ($properties.ContainsKey($name)) {
                throw "$JsonPath contains duplicate decoded property '$name'"
            }
            $index = Get-AstroJsonNextTokenIndex $Json $nameToken.NextIndex
            if ($index -ge $Json.Length -or $Json[$index] -ne ':') {
                throw "$JsonPath.$name is missing ':'"
            }
            $valueNode = Read-AstroStrictJsonValueNode `
                $Json `
                ($index + 1) `
                ($Depth + 1) `
                "$JsonPath.$name"
            $properties.Add($name, $valueNode)
            $names.Add($name)
            $rawNames.Add([string]$nameToken.Raw)
            $index = Get-AstroJsonNextTokenIndex $Json $valueNode.NextIndex
            if ($index -ge $Json.Length) {
                throw "$JsonPath is an unterminated JSON object"
            }
            if ($Json[$index] -eq '}') {
                return [pscustomobject]@{
                    Kind = 'object'
                    Properties = $properties
                    Names = @($names)
                    RawNames = @($rawNames)
                    NextIndex = $index + 1
                }
            }
            if ($Json[$index] -ne ',') {
                throw "$JsonPath expected ',' or '}' at character $index"
            }
            $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
        }
    }
    if ($character -eq '[') {
        $items = [Collections.Generic.List[object]]::new()
        $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
        if ($index -lt $Json.Length -and $Json[$index] -eq ']') {
            return [pscustomobject]@{
                Kind = 'array'
                Items = @()
                NextIndex = $index + 1
            }
        }
        while ($true) {
            $itemNode = Read-AstroStrictJsonValueNode `
                $Json `
                $index `
                ($Depth + 1) `
                "$JsonPath[$($items.Count)]"
            $items.Add($itemNode)
            $index = Get-AstroJsonNextTokenIndex $Json $itemNode.NextIndex
            if ($index -ge $Json.Length) {
                throw "$JsonPath is an unterminated JSON array"
            }
            if ($Json[$index] -eq ']') {
                return [pscustomobject]@{
                    Kind = 'array'
                    Items = @($items)
                    NextIndex = $index + 1
                }
            }
            if ($Json[$index] -ne ',') {
                throw "$JsonPath expected ',' or ']' at character $index"
            }
            $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
        }
    }
    if ($character -eq '-' -or
        ($character -ge '0' -and $character -le '9')) {
        $numberRegex = [Regex]::new(
            '\G-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        $match = $numberRegex.Match($Json, $index)
        if (-not $match.Success) {
            throw "$JsonPath contains an invalid JSON number"
        }
        $raw = $match.Value
        return [pscustomobject]@{
            Kind = if ($raw -cmatch '^-?(?:0|[1-9][0-9]*)\z') {
                'integer'
            } else { 'number' }
            Value = $raw
            Raw = $raw
            NextIndex = $index + $raw.Length
        }
    }
    foreach ($literal in @(
            @('true', 'boolean', $true),
            @('false', 'boolean', $false),
            @('null', 'null', $null)
        )) {
        $literalText = [string]$literal[0]
        if ($index + $literalText.Length -le $Json.Length -and
            [string]::CompareOrdinal(
                $Json,
                $index,
                $literalText,
                0,
                $literalText.Length
            ) -eq 0) {
            return [pscustomobject]@{
                Kind = [string]$literal[1]
                Value = $literal[2]
                Raw = [string]$literal[0]
                NextIndex = $index + ([string]$literal[0]).Length
            }
        }
    }
    throw "$JsonPath begins with an unsupported JSON token at character $index"
}

function ConvertFrom-AstroJsonUnsignedNode {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string]$JsonPath,
        [Parameter(Mandatory)][uint64]$Maximum,
        [switch]$Positive
    )

    $value = [uint64]0
    if ($Node.Kind -cne 'integer' -or
        [string]$Node.Raw -cnotmatch '^(?:0|[1-9][0-9]*)\z' -or
        -not [uint64]::TryParse(
            [string]$Node.Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$value
        ) -or $value -gt $Maximum -or ($Positive -and $value -eq 0)) {
        throw "$JsonPath must be a canonical$(if ($Positive) { ' positive' } else { '' }) invariant integer no greater than $Maximum"
    }
    return $value
}

function Get-AstroReservedAttributionPaths {
    param(
        [Parameter(Mandatory)][string]$Temporary,
        [Parameter(Mandatory)][string]$ProbeName
    )

    try {
        $paths = [Collections.Generic.List[string]]::new()
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries(
                $Temporary,
                '*',
                [IO.SearchOption]::TopDirectoryOnly
            )) {
            $leaf = [IO.Path]::GetFileName($entry)
            if ($leaf.StartsWith(
                    'no-escape-attribution',
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                $leaf.StartsWith(
                    '.astro-attribution-stage',
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                $leaf.StartsWith(
                    '.astro-attribution-cleanup',
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                $leaf.StartsWith(
                    '.astro-attribution-refresh.',
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                $leaf.StartsWith(
                    '.astro-attribution-refresh-old.',
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                $paths.Add([IO.Path]::GetFullPath($entry))
            }
        }
        [string[]]$ordered = @($paths)
        [Array]::Sort($ordered, [StringComparer]::OrdinalIgnoreCase)
        return $ordered
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_UNEVALUABLE' `
            "$ProbeName could not enumerate every reserved attribution entry below '$Temporary': $($_.Exception.Message)" `
            'preserve the launcher lock; recovery requires a stable complete process-tree source of truth'
    }
}

function Get-AstroReclaimAttributionProbe {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$ProbeName,
        [Parameter(Mandatory)][int]$ExpectedOwnerPid,
        [AllowNull()][Nullable[long]]$ExpectedOwnerProcessStartUtcTicks,
        [AllowNull()][Nullable[long]]$ExpectedLauncherLeaseStartUtcTicks,
        [Parameter(Mandatory)][string]$ExpectedLauncherLockSha256,
        [Parameter(Mandatory)][string]$RootIdentity,
        [Parameter(Mandatory)][string]$RecoveryRoot,
        [Parameter(Mandatory)][string]$RecoveryTransactionId,
        [Parameter(Mandatory)][bool]$AllowMalformedExactStageQuarantine,
        [Parameter(Mandatory)]
        [ValidateSet('transition-bound-v2', 'transition-bound-v3', 'prior-marker-record', 'post-cleanup')]
        [string]$Policy
    )

    $temporary = [IO.Path]::GetFullPath((Join-Path $Root '.tmp'))
    [string[]]$entries = @(Get-AstroReservedAttributionPaths `
        $temporary `
        $ProbeName)
    $sharedInventory = Get-AstroAttributionInventory `
        $temporary `
        -AllowMalformedRenameSuffixQuarantine:$AllowMalformedExactStageQuarantine
    if (-not $sharedInventory.Stable -or @($sharedInventory.Errors).Count -gt 0) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_UNEVALUABLE' `
            "$ProbeName strict typed attribution inventory is invalid: $(@($sharedInventory.Errors) -join '; ')" `
            'preserve every reserved path; malformed/case-drifted/reparse/unknown refresh combinations are never inferred'
    }
    if (@($sharedInventory.Paths).Count -ne $entries.Count) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_CHANGED' `
            "$ProbeName shared typed attribution inventory cardinality differs from the retained reclaim inventory" `
            'preserve every path and retry only against one exact stable inventory'
    }
    for ($sharedIndex = 0; $sharedIndex -lt $entries.Count; $sharedIndex++) {
        if ($entries[$sharedIndex] -cne $sharedInventory.Paths[$sharedIndex]) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_CHANGED' `
                "$ProbeName shared typed attribution inventory path spelling/order differs from the retained reclaim inventory" `
                'preserve every path; case drift and concurrent namespace changes are non-authorizing'
        }
    }
    $leases = [Collections.Generic.List[object]]::new()
    $rawAttributionRecords = [Collections.Generic.List[object]]::new()
    $refreshTransactionRecords = [Collections.Generic.List[object]]::new()
    $refreshArtifactByPath = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $exactManifestObserved = $false
    $exactManifestLeaseStartUtcTicks = $null
    $exactLeaseCandidates = [Collections.Generic.HashSet[long]]::new()
    $unrelatedManifestByKey =
        [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::Ordinal
        )
    $unrelatedTempByKey =
        [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::Ordinal
        )
    foreach ($transaction in @($sharedInventory.RefreshTransactions)) {
        if (-not $transaction.Valid) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_REFRESH_INVALID' `
                "$ProbeName rejected typed refresh transaction '$($transaction.Key)': $($transaction.Error)" `
                'preserve every transaction artifact; no malformed refresh state authorizes recovery'
        }
        if ($null -eq $ExpectedOwnerProcessStartUtcTicks -or
            $transaction.Parsed.LauncherPid -ne $ExpectedOwnerPid -or
            $transaction.Parsed.LauncherProcessStartUtcTicks -ne
                [long]$ExpectedOwnerProcessStartUtcTicks -or
            $transaction.Parsed.LauncherLockSha256 -cne
                $ExpectedLauncherLockSha256) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_ATTRIBUTION_AMBIGUOUS' `
                "$ProbeName found a typed refresh transaction for a non-exact launcher generation: $($transaction.Key)" `
                'preserve every entry; one reclaim never mutates or ignores unrelated refresh state'
        }
        if ($transaction.OwnerProbe.State -notin @('absent', 'pid-reused') -or
            $transaction.JobObjectProbe.State -cne 'absent') {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_OWNER_NOT_DEAD' `
                "$ProbeName typed refresh transaction is not exact dead-or-reused/Job-absent (owner=$($transaction.OwnerProbe.State), job=$($transaction.JobObjectProbe.State), pids=$(@($transaction.JobObjectProbe.ProcessIds) -join ','), error=$($transaction.JobObjectProbe.Error)): $($transaction.Key)" `
                'preserve every artifact; exact-live, observed Job, and unevaluable state are inviolable'
        }
        if ($transaction.Parsed.ManifestSchemaVersion -ne 3 -and
            $Policy -cne 'prior-marker-record') {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_JOB_CONTRACT_UNTRUSTWORTHY' `
                "$ProbeName refresh transaction uses diagnostic-only attribution v$($transaction.Parsed.ManifestSchemaVersion): $($transaction.Key)" `
                'preserve all v2 state; only a strictly linked authorization published before this contract advance may resume, while every fresh recovery requires v3 KILL_ON_JOB_CLOSE'
        }
        if ($null -ne $ExpectedLauncherLeaseStartUtcTicks -and
            $transaction.Parsed.LauncherLeaseStartUtcTicks -ne
                [long]$ExpectedLauncherLeaseStartUtcTicks) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_ATTRIBUTION_AMBIGUOUS' `
                "$ProbeName refresh lease ticks differ from the exact launcher source: $($transaction.Key)" `
                'preserve every artifact; one launcher generation has one exact lease identity'
        }
        [void]$exactLeaseCandidates.Add(
            [long]$transaction.Parsed.LauncherLeaseStartUtcTicks
        )
        foreach ($artifact in @(
                [pscustomobject]@{
                    Kind = 'refresh-envelope'
                    Path = $transaction.EnvelopePath
                    Snapshot = $transaction.EnvelopeSnapshot
                    Transaction = $transaction
                },
                $(if ($null -ne $transaction.OldSnapshot) {
                    [pscustomobject]@{
                        Kind = 'refresh-old-tombstone'
                        Path = $transaction.OldTombstonePath
                        Snapshot = $transaction.OldSnapshot
                        Transaction = $transaction
                    }
                })
            )) {
            if ($null -eq $artifact) { continue }
            if ($refreshArtifactByPath.ContainsKey($artifact.Path)) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_REFRESH_INVALID' `
                    "$ProbeName refresh artifact is claimed by more than one transaction: $($artifact.Path)" `
                    'preserve every artifact and investigate transaction-key collision'
            }
            $refreshArtifactByPath.Add($artifact.Path, $artifact)
        }
        $ownerProbe = $transaction.OwnerProbe
        $jobProbe = $transaction.JobObjectProbe
        $refreshTransactionRecords.Add([ordered]@{
            key = $transaction.Key
            state = $transaction.State
            phase = $transaction.Phase
            rename_suffix_quarantine =
                [bool]$transaction.RecoverableRenameSuffix
            nonce = $transaction.Parsed.Nonce
            envelope_path = $transaction.EnvelopePath
            envelope_file_identity = $transaction.EnvelopeSnapshot.FileId
            envelope_bytes = $transaction.EnvelopeSnapshot.Length
            envelope_sha256 = $transaction.EnvelopeSnapshot.Sha256
            old_tombstone_path = $transaction.OldTombstonePath
            old_tombstone_present = $null -ne $transaction.OldSnapshot
            old_file_identity = if ($null -ne $transaction.OldSnapshot) {
                $transaction.OldSnapshot.FileId
            } else { $null }
            old_bytes = if ($null -ne $transaction.OldSnapshot) {
                $transaction.OldSnapshot.Length
            } else { $null }
            old_sha256 = if ($null -ne $transaction.OldSnapshot) {
                $transaction.OldSnapshot.Sha256
            } else { $null }
            final_path = $transaction.FinalPath
            final_present = $null -ne $transaction.FinalSnapshot
            final_binding = $transaction.FinalBinding
            final_file_identity = if ($null -ne $transaction.FinalSnapshot) {
                $transaction.FinalSnapshot.FileId
            } else { $null }
            final_bytes = if ($null -ne $transaction.FinalSnapshot) {
                $transaction.FinalSnapshot.Length
            } else { $null }
            final_sha256 = if ($null -ne $transaction.FinalSnapshot) {
                $transaction.FinalSnapshot.Sha256
            } else { $null }
            logical_final_file_identity =
                $transaction.LogicalFinalSnapshot.FileId
            logical_final_bytes = $transaction.LogicalFinalSnapshot.Length
            logical_final_sha256 = $transaction.LogicalFinalSnapshot.Sha256
            launcher_pid = $transaction.Parsed.LauncherPid
            launcher_process_start_utc_ticks =
                $transaction.Parsed.LauncherProcessStartUtcTicks
            launcher_lock_sha256 = $transaction.Parsed.LauncherLockSha256
            launcher_lease_start_utc_ticks =
                $transaction.Parsed.LauncherLeaseStartUtcTicks
            schema_version = $transaction.Parsed.ManifestSchemaVersion
            job_limit_flags = if ($null -ne $transaction.LogicalFinalParsed) {
                $transaction.LogicalFinalParsed.JobLimitFlags
            } else { 0 }
            job_object_name = $transaction.Parsed.JobObjectName
            owner_generation_probe = [ordered]@{
                state = $ownerProbe.State
                launcher_pid = $ownerProbe.LauncherPid
                expected_process_start_utc_ticks =
                    $ownerProbe.ExpectedProcessStartUtcTicks
                observed_process_start_utc_ticks =
                    $ownerProbe.ObservedProcessStartUtcTicks
                error = $ownerProbe.Error
            }
            job_object_probe = [ordered]@{
                name = $jobProbe.Name
                state = $jobProbe.State
                process_ids = [int[]]@($jobProbe.ProcessIds)
                native_error_code = $jobProbe.NativeErrorCode
                number_of_assigned_processes =
                    $jobProbe.NumberOfAssignedProcesses
                number_of_process_ids_in_list =
                    $jobProbe.NumberOfProcessIdsInList
                error = $jobProbe.Error
            }
        })
    }
    try {
        foreach ($path in $entries) {
            $leaf = [IO.Path]::GetFileName($path)
            $isRefreshArtifact = $leaf.StartsWith(
                    '.astro-attribution-refresh.',
                    [StringComparison]::OrdinalIgnoreCase
                ) -or $leaf.StartsWith(
                    '.astro-attribution-refresh-old.',
                    [StringComparison]::OrdinalIgnoreCase
                )
            if ($isRefreshArtifact) {
                if (-not $refreshArtifactByPath.ContainsKey($path)) {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_REFRESH_INVALID' `
                        "$ProbeName reserved refresh artifact has no unique strict transaction binding: $path" `
                        'preserve every artifact; orphan, malformed, case-drifted, and unknown combinations are non-authorizing'
                }
                $artifact = $refreshArtifactByPath[$path]
                $lease = Open-AstroExactEvidenceLease `
                    $path `
                    "typed attribution $($artifact.Kind) $leaf"
                $leases.Add($lease)
                $before = $lease.InitialSnapshot
                if ($before.FileIdentity -cne $artifact.Snapshot.FileId -or
                    $before.Length -ne $artifact.Snapshot.Length -or
                    $before.Sha256 -cne $artifact.Snapshot.Sha256 -or
                    -not (Test-ByteArraysEqual `
                        $before.Bytes $artifact.Snapshot.Bytes)) {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_CHANGED' `
                        "$ProbeName typed refresh artifact changed after strict transaction classification: $path" `
                        'preserve every artifact; recovery binds exact FILE_ID/length/hash/bytes'
                }
                continue
            }
            $entryKind = if ($leaf.StartsWith(
                    '.astro-attribution-stage',
                    [StringComparison]::OrdinalIgnoreCase
                )) { 'stage' } elseif ($leaf.StartsWith(
                    '.astro-attribution-cleanup',
                    [StringComparison]::OrdinalIgnoreCase
                )) { 'cleanup-tombstone' } else { 'manifest' }
            $manifestName = switch ($entryKind) {
                'stage' { ConvertFrom-AstroAttributionStageName $path; break }
                'cleanup-tombstone' {
                    ConvertFrom-AstroAttributionCleanupName $path
                    break
                }
                default { ConvertFrom-AstroAttributionManifestName $path }
            }
            if (-not $manifestName.Candidate -or -not $manifestName.Valid) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_NAME_INVALID' `
                    "$ProbeName found malformed or case-drifted reserved attribution $entryKind entry '$path': $($manifestName.Error)" `
                    'preserve the launcher lock and repair/quarantine the exact reserved entry; never silently filter it'
            }
            $lease = Open-AstroExactEvidenceLease `
                $path `
                "attribution $entryKind $leaf"
            $leases.Add($lease)
            $before = $lease.InitialSnapshot
            $parsed = Convert-AstroAttributionBytesToState `
                -Bytes $before.Bytes `
                -ExpectedLauncherPid $manifestName.LauncherPid `
                -ExpectedLauncherProcessStartUtcTicks `
                    $manifestName.LauncherProcessStartUtcTicks `
                -ExpectedLauncherLockSha256 `
                    $manifestName.LauncherLockSha256 `
                -Path $path
            $isNameExact = $null -ne $ExpectedOwnerProcessStartUtcTicks -and
                $manifestName.LauncherPid -eq $ExpectedOwnerPid -and
                $manifestName.LauncherProcessStartUtcTicks -eq
                    [long]$ExpectedOwnerProcessStartUtcTicks -and
                $manifestName.LauncherLockSha256 -ceq
                    $ExpectedLauncherLockSha256
            $ownerProbe = Get-AstroAttributionOwnerGenerationProbe `
                -LauncherPid $manifestName.LauncherPid `
                -LauncherProcessStartUtcTicks `
                    $manifestName.LauncherProcessStartUtcTicks
            if ($ownerProbe.State -cnotin @('absent', 'pid-reused')) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_OWNER_NOT_DEAD' `
                    "$ProbeName attribution owner generation is not conclusively dead/reused (kind=$entryKind, state=$($ownerProbe.State), error=$($ownerProbe.Error)): $path" `
                    'preserve every protocol entry; exact-live and unevaluable attribution owners are never reclaimable'
            }
            if (-not $isNameExact) {
                if ($entryKind -cne 'manifest' -or -not $parsed.Valid -or
                    $parsed.SchemaVersion -ne 3) {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_ATTRIBUTION_AMBIGUOUS' `
                        "$ProbeName found non-exact attribution state that is not one strict final v3 manifest: $path" `
                        'preserve every entry; only independently complete dead-owner pairs may coexist with an exact reclaim'
                }
                $unrelatedExpectedJob = Get-AstroLauncherTreeJobObjectName `
                    -RootIdentity $RootIdentity `
                    -LauncherPid $parsed.LauncherPid `
                    -LauncherProcessStartUtcTicks `
                        $parsed.LauncherProcessStartUtcTicks `
                    -LauncherLeaseStartUtcTicks `
                        $parsed.LauncherLeaseStartUtcTicks `
                    -LauncherLockSha256 $parsed.LauncherLockSha256
                if ([string]$parsed.JobObjectName -cne
                    [string]$unrelatedExpectedJob) {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_JOB_BINDING_INVALID' `
                        "$ProbeName unrelated final manifest has an invalid deterministic Job binding: $path" `
                        'preserve every entry; unrelated state is ignored only after full strict identity validation'
                }
                $unrelatedJobProbe = Get-AstroLauncherJobObjectProbe `
                    -Name $parsed.JobObjectName
                if ($unrelatedJobProbe.State -cne 'absent') {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTED_CHILD_LIVE' `
                        "$ProbeName unrelated final manifest Job is not absent (state=$($unrelatedJobProbe.State), pids=$(@($unrelatedJobProbe.ProcessIds) -join ','), error=$($unrelatedJobProbe.Error)): $path" `
                        'preserve every entry; unrelated live or unevaluable generations are inviolable'
                }
                $unrelatedKey = '{0}|{1}|{2}' -f
                    $parsed.LauncherPid,
                    $parsed.LauncherProcessStartUtcTicks,
                    $parsed.LauncherLockSha256
                if ($unrelatedManifestByKey.ContainsKey($unrelatedKey)) {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_ATTRIBUTION_AMBIGUOUS' `
                        "$ProbeName found duplicate unrelated final manifests for $unrelatedKey" `
                        'preserve every entry; each unrelated generation must be one complete pair'
                }
                $unrelatedManifestByKey.Add($unrelatedKey, [ordered]@{
                    path = $path
                    file_identity = $before.FileIdentity
                    bytes = $before.Length
                    sha256 = $before.Sha256
                    owner_state = $ownerProbe.State
                    job_state = $unrelatedJobProbe.State
                })
                continue
            }
            $malformedStage = -not $parsed.Valid -and $entryKind -ceq 'stage'
            if (-not $parsed.Valid -and
                (-not $malformedStage -or
                    -not $AllowMalformedExactStageQuarantine)) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_SCHEMA_INVALID' `
                    "$ProbeName rejected exact attribution bytes '$path': $($parsed.Error)" `
                    'preserve the launcher lock and exact attribution entry; malformed stages require explicit QuarantineUnreadable and all other malformed evidence is non-recoverable'
            }
            $jobProbe = $null
            if ($parsed.Valid) {
                if ($parsed.SchemaVersion -ne 3 -and
                    $Policy -cne 'prior-marker-record') {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_JOB_CONTRACT_UNTRUSTWORTHY' `
                        "$ProbeName attribution '$path' uses diagnostic-only schema v$($parsed.SchemaVersion) with flags=$($parsed.JobLimitFlags)" `
                        'preserve all v2 state; named Job absence after owner death is not descendant-absence proof without v3 KILL_ON_JOB_CLOSE'
                }
                [void]$exactLeaseCandidates.Add(
                    [long]$parsed.LauncherLeaseStartUtcTicks
                )
                if ($null -ne $ExpectedLauncherLeaseStartUtcTicks -and
                    $parsed.LauncherLeaseStartUtcTicks -ne
                        [long]$ExpectedLauncherLeaseStartUtcTicks) {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_ATTRIBUTION_AMBIGUOUS' `
                        "$ProbeName attribution lease ticks do not match the exact launcher source: $path" `
                        'preserve every entry; recovery requires one exact PID/process/lease/hash generation'
                }
                $expectedJobObjectName = Get-AstroLauncherTreeJobObjectName `
                    -RootIdentity $RootIdentity `
                    -LauncherPid $parsed.LauncherPid `
                    -LauncherProcessStartUtcTicks `
                        $parsed.LauncherProcessStartUtcTicks `
                    -LauncherLeaseStartUtcTicks `
                        $parsed.LauncherLeaseStartUtcTicks `
                    -LauncherLockSha256 $parsed.LauncherLockSha256
                if ([string]$parsed.JobObjectName -cne
                    [string]$expectedJobObjectName) {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_JOB_BINDING_INVALID' `
                        "$ProbeName $entryKind job-object name does not match the exact root/PID/ticks/lease/hash derivation: $path" `
                        'preserve the launcher lock and exact attribution entry; repair the producer binding before recovery'
                }
                $jobProbe = Get-AstroLauncherJobObjectProbe `
                    -Name $parsed.JobObjectName
                if ($jobProbe.State -cne 'absent') {
                    $code = if ($jobProbe.State -ceq 'observed') {
                        'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTED_CHILD_LIVE'
                    } else {
                        'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_JOB_UNEVALUABLE'
                    }
                    Fail-Astro $code `
                        "$ProbeName exact named Job Object is not absent (name=$($parsed.JobObjectName), state=$($jobProbe.State), members=$(@($jobProbe.ProcessIds) -join ','), error=$($jobProbe.Error))" `
                        'preserve every entry; even an observed empty Job Object can accept future assignments'
                }
                if ($entryKind -cin @('manifest', 'cleanup-tombstone')) {
                    if ($exactManifestObserved) {
                        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_ATTRIBUTION_AMBIGUOUS' `
                            "$ProbeName found more than one exact final-manifest identity" `
                            'preserve the launcher lock and every manifest/tombstone; the exact final identity must be unique'
                    }
                    $exactManifestObserved = $true
                    $exactManifestLeaseStartUtcTicks =
                        [long]$parsed.LauncherLeaseStartUtcTicks
                }
            }
            $rawAttributionRecords.Add([pscustomobject]@{
                Kind = $entryKind
                Path = $path
                Snapshot = $before
                Parsed = if ($parsed.Valid) { $parsed } else { $null }
                ParseError = if ($parsed.Valid) { $null } else { $parsed.Error }
                OwnerProbe = $ownerProbe
                JobObjectProbe = $jobProbe
                MalformedExactStage = [bool]$malformedStage
            })
        }
        foreach ($transaction in @($sharedInventory.RefreshTransactions)) {
            if ($null -ne $transaction.FinalSnapshot) { continue }
            if ($transaction.State -cne
                'prepared-envelope-old-tombstone-no-final' -or
                $null -eq $transaction.LogicalFinalSnapshot -or
                $null -eq $transaction.LogicalFinalParsed) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_REFRESH_INVALID' `
                    "$ProbeName refresh transaction without a final has no exact rollback source: $($transaction.Key)" `
                    'preserve every artifact; missing scratch is never interpreted as intended new bytes'
            }
            if ($exactManifestObserved) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_ATTRIBUTION_AMBIGUOUS' `
                    "$ProbeName refresh rollback source coexists with another logical final identity" `
                    'preserve every artifact; one exact launcher generation must normalize to one final'
            }
            $logical = $transaction.LogicalFinalSnapshot
            $syntheticSnapshot = [pscustomobject]@{
                Path = $transaction.FinalPath
                FileIdentity = $logical.FileId
                FileId = $logical.FileId
                Length = $logical.Length
                Sha256 = $logical.Sha256
                Bytes = $logical.Bytes
            }
            $rawAttributionRecords.Add([pscustomobject]@{
                Kind = 'manifest'
                Path = $transaction.FinalPath
                Snapshot = $syntheticSnapshot
                Parsed = $transaction.LogicalFinalParsed
                ParseError = $null
                OwnerProbe = $transaction.OwnerProbe
                JobObjectProbe = $transaction.JobObjectProbe
                MalformedExactStage = $false
                SyntheticRefreshRollback = $true
            })
            $exactManifestObserved = $true
            $exactManifestLeaseStartUtcTicks =
                [long]$transaction.Parsed.LauncherLeaseStartUtcTicks
        }
        if ($exactLeaseCandidates.Count -gt 1) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_ATTRIBUTION_AMBIGUOUS' `
                "$ProbeName exact attribution records disagree on launcher lease ticks" `
                'preserve every entry; one exact launcher generation must have one lease identity'
        }

        [string[]]$entriesAfter = @(Get-AstroReservedAttributionPaths `
            $temporary `
            $ProbeName)
        if ($entriesAfter.Count -ne $entries.Count) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_CHANGED' `
                "$ProbeName attribution inventory count changed while retained leases were open" `
                'preserve the launcher lock and retry only against a stable complete inventory'
        }
        for ($index = 0; $index -lt $entries.Count; $index++) {
            if (-not [string]::Equals(
                    $entries[$index],
                    $entriesAfter[$index],
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_CHANGED' `
                    "$ProbeName attribution path inventory changed while retained leases were open" `
                    'preserve the launcher lock and retry only against a stable complete inventory'
            }
            $after = Get-AstroExactRenameLeaseSnapshot `
                $leases[$index] `
                "attribution manifest terminal read $($entries[$index])"
            $before = $leases[$index].InitialSnapshot
            if ($after.FileIdentity -cne $before.FileIdentity -or
                $after.Length -ne $before.Length -or
                $after.Sha256 -cne $before.Sha256 -or
                -not (Test-ByteArraysEqual $after.Bytes $before.Bytes) -or
                -not [string]::Equals(
                    $after.Path,
                    $before.Path,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_CHANGED' `
                    "$ProbeName attribution bytes/identity/path changed during the exact probe: $($entries[$index])" `
                    'preserve the launcher lock; recovery requires one immutable process-tree source of truth'
            }
        }
    }
    finally {
        foreach ($lease in @($leases)) {
            if ($null -ne $lease -and $null -ne $lease.Handle) {
                $lease.Handle.Dispose()
            }
        }
    }

    $effectiveLeaseTicks = if ($null -ne $ExpectedLauncherLeaseStartUtcTicks) {
        [long]$ExpectedLauncherLeaseStartUtcTicks
    } elseif ($exactLeaseCandidates.Count -eq 1) {
        [long]@($exactLeaseCandidates)[0]
    } else { $null }
    if ($null -eq $effectiveLeaseTicks) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_JOB_BINDING_MISSING' `
            "$ProbeName cannot derive the exact launcher Job Object because lease ticks are unavailable" `
            'preserve every entry permanently unless this is a strictly linked published marker resume; fresh malformed/pre-v2 state without lease ticks cannot prove deterministic Job absence'
    }
    $exactJobObjectName = Get-AstroLauncherTreeJobObjectName `
        -RootIdentity $RootIdentity `
        -LauncherPid $ExpectedOwnerPid `
        -LauncherProcessStartUtcTicks `
            ([long]$ExpectedOwnerProcessStartUtcTicks) `
        -LauncherLeaseStartUtcTicks $effectiveLeaseTicks `
        -LauncherLockSha256 $ExpectedLauncherLockSha256
    $exactJobProbe = Get-AstroLauncherJobObjectProbe -Name $exactJobObjectName
    if ($exactJobProbe.State -cne 'absent') {
        $code = if ($exactJobProbe.State -ceq 'observed') {
            'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTED_CHILD_LIVE'
        } else {
            'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_JOB_UNEVALUABLE'
        }
        Fail-Astro $code `
            "$ProbeName independently derived Job Object is not absent (name=$exactJobObjectName, state=$($exactJobProbe.State), members=$(@($exactJobProbe.ProcessIds) -join ','), error=$($exactJobProbe.Error))" `
            'preserve every entry; missing attribution is never evidence of Job Object absence'
    }

    try {
        $tempInventory = Get-AstroReservedLauncherTempEntries $temporary
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TEMP_UNEVALUABLE' `
            "$ProbeName could not inventory exact reserved launcher TEMP entries: $($_.Exception.Message)" `
            'preserve every entry and repair protocol-directory access'
    }
    $tempRecords = [Collections.Generic.List[object]]::new()
    foreach ($temp in @($tempInventory.Records)) {
        if (-not $temp.Valid) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TEMP_INVALID' `
                "$ProbeName found malformed/case-drifted/reparse reserved launcher TEMP '$($temp.Path)': $($temp.Error)" `
                'preserve every entry; recovery never ignores an ambiguous reserved TEMP path'
        }
        $isExactTemp = $temp.Name.LauncherPid -eq $ExpectedOwnerPid -and
            $temp.Name.LauncherProcessStartUtcTicks -eq
                [long]$ExpectedOwnerProcessStartUtcTicks -and
            $temp.Name.LauncherLockSha256 -ceq $ExpectedLauncherLockSha256
        if (-not $isExactTemp) {
            $unrelatedKey = '{0}|{1}|{2}' -f
                $temp.Name.LauncherPid,
                $temp.Name.LauncherProcessStartUtcTicks,
                $temp.Name.LauncherLockSha256
            if ($unrelatedTempByKey.ContainsKey($unrelatedKey)) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TEMP_AMBIGUOUS' `
                    "$ProbeName found duplicate unrelated TEMP roots for $unrelatedKey" `
                    'preserve every entry; each unrelated generation must be one complete pair'
            }
            $unrelatedTempByKey.Add($unrelatedKey, [ordered]@{
                path = $temp.Path
                file_identity = $temp.FileId
            })
            continue
        }
        $tempRecords.Add([ordered]@{
            kind = $temp.Kind
            path = $temp.Path
            expected_temp_path = $temp.ExpectedTempPath
            file_identity = $temp.FileId
            nonce = $temp.Name.Nonce
            launcher_pid = $temp.Name.LauncherPid
            launcher_process_start_utc_ticks =
                $temp.Name.LauncherProcessStartUtcTicks
            launcher_lock_sha256 = $temp.Name.LauncherLockSha256
            exact_claim_identity = $true
            state = $temp.State.State
            attributes = [int]$temp.State.Attributes
            error = $temp.Error
        })
    }
    if ($tempRecords.Count -gt 1) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TEMP_AMBIGUOUS' `
            "$ProbeName found more than one exact launcher TEMP" `
            'preserve every entry; the exact v2 TEMP identity must be unique'
    }
    if ($unrelatedManifestByKey.Count -ne $unrelatedTempByKey.Count) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_ATTRIBUTION_AMBIGUOUS' `
            "$ProbeName unrelated complete-pair cardinality differs (manifests=$($unrelatedManifestByKey.Count), temps=$($unrelatedTempByKey.Count))" `
            'preserve every entry; an unrelated generation may coexist only as one strict final manifest plus one exact TEMP root'
    }
    foreach ($unrelatedKey in $unrelatedManifestByKey.Keys) {
        if (-not $unrelatedTempByKey.ContainsKey($unrelatedKey)) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_ATTRIBUTION_AMBIGUOUS' `
                "$ProbeName unrelated final manifest lacks its exact TEMP root: $unrelatedKey" `
                'preserve every entry; partial unrelated generations require their own explicit recovery'
        }
    }

    $finalLikeCount = @($rawAttributionRecords | Where-Object {
            $_.Kind -cin @('manifest', 'cleanup-tombstone')
        }).Count
    if ($tempRecords.Count -eq 1 -and $finalLikeCount -ne 1) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TEMP_WITHOUT_MANIFEST' `
            "$ProbeName exact TEMP exists without exactly one valid final manifest/tombstone (count=$finalLikeCount)" `
            'preserve TEMP and every attribution entry; TEMP without its exact final evidence is ambiguous'
    }
    if ($tempRecords.Count -eq 1 -and $finalLikeCount -eq 1) {
        $expectedTempPath = [IO.Path]::GetFullPath((Join-Path `
            $temporary `
            (Get-AstroLauncherTempLeaf `
                $ExpectedOwnerPid `
                ([long]$ExpectedOwnerProcessStartUtcTicks) `
                $ExpectedLauncherLockSha256)
        ))
        if (-not [string]::Equals(
                $tempRecords[0].expected_temp_path,
                $expectedTempPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TEMP_AMBIGUOUS' `
                "$ProbeName TEMP/tombstone does not map to the exact final manifest identity" `
                'preserve the complete pair; recovery requires one canonical generation mapping'
        }
    }
    $subordinateState = if ($tempRecords.Count -eq 1) {
        'complete-pair'
    } elseif ($rawAttributionRecords.Count -gt 0) {
        'partial-evidence'
    } else {
        'none'
    }
    $manifestRecords = [Collections.Generic.List[object]]::new()
    $quarantineIndex = 0
    foreach ($record in @($rawAttributionRecords)) {
        $parsed = $record.Parsed
        $action = if ($record.MalformedExactStage) {
            'archive-quarantine'
        } elseif ($subordinateState -ceq 'partial-evidence') {
            'delete'
        } else {
            'preserve-complete-pair'
        }
        $quarantineArchivePath = $null
        if ($action -ceq 'archive-quarantine') {
            $quarantineArchivePath = [IO.Path]::GetFullPath((Join-Path `
                $RecoveryRoot `
                ("claim-stage.$RecoveryTransactionId.$quarantineIndex.$($record.Snapshot.Sha256).bin")
            ))
            $quarantineIndex++
        }
        $ownerProbe = $record.OwnerProbe
        $jobProbe = $record.JobObjectProbe
        [int[]]$treePids = @()
        [int[]]$openPids = @()
        [string[]]$ownedPaths = @()
        if ($null -ne $parsed) {
            $treePids = [int[]]@($parsed.TreePids)
            $openPids = [int[]]@($parsed.OpenPids)
            $ownedPaths = [string[]]@($parsed.OwnedPaths)
        }
        $manifestRecords.Add([ordered]@{
            kind = $record.Kind
            path = $record.Path
            file_identity = $record.Snapshot.FileIdentity
            bytes = $record.Snapshot.Length
            sha256 = $record.Snapshot.Sha256
            valid = $null -ne $parsed
            schema_error = $record.ParseError
            launcher_pid = if ($null -ne $parsed) {
                $parsed.LauncherPid
            } else { $ExpectedOwnerPid }
            launcher_process_start_utc_ticks = if ($null -ne $parsed) {
                $parsed.LauncherProcessStartUtcTicks
            } else { [long]$ExpectedOwnerProcessStartUtcTicks }
            launcher_lock_sha256 = if ($null -ne $parsed) {
                $parsed.LauncherLockSha256
            } else { $ExpectedLauncherLockSha256 }
            launcher_lease_start_utc_ticks = if ($null -ne $parsed) {
                $parsed.LauncherLeaseStartUtcTicks
            } else { $effectiveLeaseTicks }
            schema_version = if ($null -ne $parsed) {
                $parsed.SchemaVersion
            } else { $null }
            job_limit_flags = if ($null -ne $parsed) {
                $parsed.JobLimitFlags
            } else { $null }
            job_object_name = if ($null -ne $parsed) {
                $parsed.JobObjectName
            } else { $exactJobObjectName }
            expected_temp_path = [IO.Path]::GetFullPath((Join-Path `
                $temporary `
                (Get-AstroLauncherTempLeaf `
                    $ExpectedOwnerPid `
                    ([long]$ExpectedOwnerProcessStartUtcTicks) `
                    $ExpectedLauncherLockSha256)
            ))
            exact_expected_launcher = [bool](
                $record.Kind -cin @('manifest', 'cleanup-tombstone')
            )
            exact_claim_identity = $true
            cleanup_action = $action
            quarantine_archive_path = $quarantineArchivePath
            run_started_unix_ns = if ($null -ne $parsed) {
                $parsed.RunStartedUnixNs
            } else { $null }
            written_at = if ($null -ne $parsed) { $parsed.WrittenAt } else { $null }
            tree_pids = $treePids
            open_pids = $openPids
            owned_paths_unevaluable = if ($null -ne $parsed) {
                $parsed.OwnedPathsUnevaluable
            } else { $true }
            owned_paths = $ownedPaths
            owner_generation_probe = [ordered]@{
                state = $ownerProbe.State
                launcher_pid = $ownerProbe.LauncherPid
                expected_process_start_utc_ticks =
                    $ownerProbe.ExpectedProcessStartUtcTicks
                observed_process_start_utc_ticks =
                    $ownerProbe.ObservedProcessStartUtcTicks
                error = $ownerProbe.Error
            }
            job_object_probe = [ordered]@{
                name = if ($null -ne $jobProbe) {
                    $jobProbe.Name
                } else { $exactJobObjectName }
                state = if ($null -ne $jobProbe) {
                    $jobProbe.State
                } else { $exactJobProbe.State }
                process_ids = [int[]]@(
                    $(if ($null -ne $jobProbe) { $jobProbe.ProcessIds } else {
                        $exactJobProbe.ProcessIds
                    })
                )
                native_error_code = if ($null -ne $jobProbe) {
                    $jobProbe.NativeErrorCode
                } else { $exactJobProbe.NativeErrorCode }
                number_of_assigned_processes = if ($null -ne $jobProbe) {
                    $jobProbe.NumberOfAssignedProcesses
                } else { $exactJobProbe.NumberOfAssignedProcesses }
                number_of_process_ids_in_list = if ($null -ne $jobProbe) {
                    $jobProbe.NumberOfProcessIdsInList
                } else { $exactJobProbe.NumberOfProcessIdsInList }
                error = if ($null -ne $jobProbe) {
                    $jobProbe.Error
                } else { $exactJobProbe.Error }
            }
        })
    }
    $stable = [ordered]@{
        state = if ($manifestRecords.Count -eq 0 -and $tempRecords.Count -eq 0) { 'absent' } else {
            'observed'
        }
        policy = $Policy
        subordinate_state = $subordinateState
        exact_manifest_observed = $exactManifestObserved
        exact_manifest_lease_start_utc_ticks =
            $exactManifestLeaseStartUtcTicks
        exact_launcher_lease_start_utc_ticks = $effectiveLeaseTicks
        exact_job_object_name = $exactJobObjectName
        exact_job_object_probe = [ordered]@{
            name = $exactJobProbe.Name
            state = $exactJobProbe.State
            process_ids = [int[]]@($exactJobProbe.ProcessIds)
            native_error_code = $exactJobProbe.NativeErrorCode
            number_of_assigned_processes =
                $exactJobProbe.NumberOfAssignedProcesses
            number_of_process_ids_in_list =
                $exactJobProbe.NumberOfProcessIdsInList
            error = $exactJobProbe.Error
        }
        manifests = [object[]]@($manifestRecords)
        refresh_transactions = [object[]]@($refreshTransactionRecords)
        temps = [object[]]@($tempRecords)
        unrelated_complete_pairs = [object[]]@(
            $unrelatedManifestByKey.Keys | Sort-Object | ForEach-Object {
                [ordered]@{
                    identity = $_
                    manifest = $unrelatedManifestByKey[$_]
                    temp = $unrelatedTempByKey[$_]
                    action = 'preserved'
                }
            }
        )
    }
    $stableBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($stable | ConvertTo-Json -Depth 16 -Compress)
    )
    return [ordered]@{
        probe = $ProbeName
        state = $stable.state
        policy = $Policy
        subordinate_state = $subordinateState
        exact_manifest_observed = $exactManifestObserved
        exact_manifest_lease_start_utc_ticks =
            $exactManifestLeaseStartUtcTicks
        exact_launcher_lease_start_utc_ticks = $effectiveLeaseTicks
        exact_job_object_name = $exactJobObjectName
        exact_job_object_probe = $stable.exact_job_object_probe
        manifests = [object[]]@($manifestRecords)
        refresh_transactions = [object[]]@($refreshTransactionRecords)
        temps = [object[]]@($tempRecords)
        unrelated_complete_pairs = $stable.unrelated_complete_pairs
        stable_fingerprint_sha256 = Get-AstroByteSha256 $stableBytes
        observed_at_utc = [DateTime]::UtcNow.ToString('o')
    }
}

function Get-AstroSubordinateShapeKind {
    param(
        [Parameter(Mandatory)][AllowNull()]$Value,
        [Parameter(Mandatory)][string[]]$RuntimeDictionaryMembers,
        [Parameter(Mandatory)][string[]]$LinkedObjectMembers,
        [Parameter(Mandatory)][string]$Description
    )

    if ($null -eq $Value) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_SHAPE_INVALID' `
            "$Description is null" `
            'preserve all state; subordinate cleanup requires one complete typed runtime probe or strictly parsed linked probe'
    }
    if ($Value -is [Collections.IDictionary]) {
        [string[]]$keys = @($Value.Keys | ForEach-Object {
                if ($_ -isnot [string]) {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_SHAPE_INVALID' `
                        "$Description has a non-string runtime dictionary key" `
                        'preserve all state; runtime subordinate probe keys must be exact strings'
                }
                [string]$_
            })
        [string[]]$missing = @($RuntimeDictionaryMembers | Where-Object {
                $keys -cnotcontains $_
            })
        if ($missing.Count -ne 0) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_SHAPE_INVALID' `
                "$Description runtime dictionary is missing exact member(s): $($missing -join ',')" `
                'preserve all state; do not infer cleanup authority from a partial runtime subordinate probe'
        }
        [string[]]$aliases = @($LinkedObjectMembers | Where-Object {
                $keys -ccontains $_
            })
        if ($aliases.Count -ne 0) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_SHAPE_INVALID' `
                "$Description runtime dictionary also contains linked-object alias member(s): $($aliases -join ',')" `
                'preserve all state; one subordinate value must use exactly one unambiguous object shape'
        }
        return 'runtime-dictionary'
    }

    if ($Value -isnot [pscustomobject]) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_SHAPE_INVALID' `
            "$Description is neither a runtime dictionary nor a strictly linked PSCustomObject (type=$($Value.GetType().FullName))" `
            'preserve all state; subordinate cleanup accepts only the two explicitly validated protocol shapes'
    }
    [string[]]$properties = @($Value.PSObject.Properties.Name)
    [string[]]$missing = @($LinkedObjectMembers | Where-Object {
            $properties -cnotcontains $_
        })
    if ($missing.Count -ne 0) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_SHAPE_INVALID' `
            "$Description linked object is missing exact member(s): $($missing -join ',')" `
            'preserve all state; linked subordinate cleanup authority must come from the complete strict parser result'
    }
    [string[]]$aliases = @($RuntimeDictionaryMembers | Where-Object {
            $properties -ccontains $_
        })
    if ($aliases.Count -ne 0) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_SHAPE_INVALID' `
            "$Description linked object also contains runtime-dictionary alias member(s): $($aliases -join ',')" `
            'preserve all state; one subordinate value must use exactly one unambiguous object shape'
    }
    return 'linked-object'
}

function ConvertTo-AstroSubordinateCleanupPlan {
    param(
        [Parameter(Mandatory)]$Probe,
        [Parameter(Mandatory)][string]$RecoveryRoot,
        [Parameter(Mandatory)][string]$TransactionId
    )

    $probeShape = Get-AstroSubordinateShapeKind `
        -Value $Probe `
        -RuntimeDictionaryMembers @(
            'subordinate_state',
            'exact_launcher_lease_start_utc_ticks',
            'exact_job_object_name',
            'manifests',
            'temps'
        ) `
        -LinkedObjectMembers @(
            'SubordinateState',
            'ExactLauncherLeaseStartUtcTicks',
            'ExactJobObjectName',
            'Manifests',
            'Temps'
        ) `
        -Description 'subordinate cleanup probe'
    $runtimeProbe = $probeShape -ceq 'runtime-dictionary'
    $subordinateState = if ($runtimeProbe) {
        [string]$Probe['subordinate_state']
    } else { [string]$Probe.SubordinateState }
    $jobName = if ($runtimeProbe) {
        [string]$Probe['exact_job_object_name']
    } else { [string]$Probe.ExactJobObjectName }
    $leaseTicks = if ($runtimeProbe) {
        [long]$Probe['exact_launcher_lease_start_utc_ticks']
    } else { [long]$Probe.ExactLauncherLeaseStartUtcTicks }
    $probeManifests = $null
    $probeTemps = $null
    if ($runtimeProbe) {
        $probeManifests = $Probe['manifests']
        $probeTemps = $Probe['temps']
    }
    else {
        $probeManifests = $Probe.Manifests
        $probeTemps = $Probe.Temps
    }
    if ($subordinateState -cnotin @(
            'none',
            'partial-evidence',
            'complete-pair'
        ) -or
        $leaseTicks -le 0 -or
        $leaseTicks -gt [DateTime]::MaxValue.Ticks -or
        $jobName -cnotmatch
            '^Global\\Astrolabe\.LauncherTree\.[0-9a-f]{64}$' -or
        $probeManifests -isnot [array] -or
        $probeTemps -isnot [array]) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_SHAPE_INVALID' `
            'subordinate cleanup probe has invalid state, lease, Job, or collection types' `
            'preserve all state; cleanup authority requires one canonical exact-generation subordinate probe'
    }
    $manifestCount = @($probeManifests).Count
    $tempCount = @($probeTemps).Count
    if (($subordinateState -ceq 'none' -and
            ($manifestCount -ne 0 -or $tempCount -ne 0)) -or
        ($subordinateState -ceq 'partial-evidence' -and
            ($manifestCount -eq 0 -or $tempCount -ne 0)) -or
        ($subordinateState -ceq 'complete-pair' -and
            ($manifestCount -eq 0 -or $tempCount -ne 1))) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_SHAPE_INVALID' `
            "subordinate cleanup state/cardinality disagree (state=$subordinateState, manifests=$manifestCount, temps=$tempCount)" `
            'preserve all state; never normalize a partial or contradictory subordinate inventory'
    }
    $records = [Collections.Generic.List[object]]::new()
    foreach ($entry in @($probeManifests)) {
        $entryShape = Get-AstroSubordinateShapeKind `
            -Value $entry `
            -RuntimeDictionaryMembers @(
                'kind',
                'path',
                'file_identity',
                'bytes',
                'sha256',
                'schema_version',
                'job_limit_flags',
                'expected_temp_path',
                'valid',
                'cleanup_action',
                'quarantine_archive_path'
            ) `
            -LinkedObjectMembers @(
                'Kind',
                'Path',
                'FileIdentity',
                'Bytes',
                'Sha256',
                'ExpectedTempPath',
                'Valid',
                'CleanupAction',
                'QuarantineArchivePath'
            ) `
            -Description 'subordinate cleanup manifest entry'
        $linkedShape = $entryShape -ceq 'linked-object'
        $normalized = [ordered]@{
            kind = if ($linkedShape) { [string]$entry.Kind } else {
                [string]$entry['kind']
            }
            path = [IO.Path]::GetFullPath($(if ($linkedShape) {
                    [string]$entry.Path
                } else { [string]$entry['path'] }))
            file_identity = if ($linkedShape) {
                [string]$entry.FileIdentity
            } else { [string]$entry['file_identity'] }
            bytes = [uint64]$(if ($linkedShape) {
                    $entry.Bytes
                } else { $entry['bytes'] })
            sha256 = if ($linkedShape) {
                [string]$entry.Sha256
            } else { [string]$entry['sha256'] }
            schema_version = if ($linkedShape) {
                $entry.SchemaVersion
            } else { $entry['schema_version'] }
            job_limit_flags = if ($linkedShape) {
                $entry.JobLimitFlags
            } else { $entry['job_limit_flags'] }
            expected_temp_path = if ($linkedShape) {
                [string]$entry.ExpectedTempPath
            } else { [string]$entry['expected_temp_path'] }
            valid = [bool]$(if ($linkedShape) {
                    $entry.Valid
                } else { $entry['valid'] })
            cleanup_action = if ($linkedShape) {
                [string]$entry.CleanupAction
            } else { [string]$entry['cleanup_action'] }
            quarantine_archive_path = if ($linkedShape) {
                $entry.QuarantineArchivePath
            } else { $entry['quarantine_archive_path'] }
        }
        if ($null -ne $normalized.quarantine_archive_path) {
            $normalized.quarantine_archive_path = [IO.Path]::GetFullPath(
                [string]$normalized.quarantine_archive_path
            )
            if (-not [string]::Equals(
                    [IO.Path]::GetDirectoryName(
                        $normalized.quarantine_archive_path
                    ),
                    $RecoveryRoot,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_ARCHIVE_ESCAPE' `
                    "subordinate quarantine archive escapes recovery root: $($normalized.quarantine_archive_path)" `
                    'preserve all state; malformed stage archives must be direct transaction-bound recovery children'
            }
            Assert-AstroRecoveryArtifactLeaf `
                $normalized.quarantine_archive_path `
                -MaxLength 160
        }
        if ([bool]$normalized.valid -and
            $null -ne $normalized.schema_version -and
            ([int]$normalized.schema_version -ne 3 -or
                [uint32]$normalized.job_limit_flags -ne 8192)) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_JOB_CONTRACT_UNTRUSTWORTHY' `
                "subordinate cleanup manifest is not v3 KILL_ON_JOB_CLOSE: $($normalized.path)" `
                'preserve the transaction; current recovery authority must bind schema_version=3 and job_limit_flags=8192'
        }
        $records.Add($normalized)
    }
    $temps = [Collections.Generic.List[object]]::new()
    foreach ($entry in @($probeTemps)) {
        $entryShape = Get-AstroSubordinateShapeKind `
            -Value $entry `
            -RuntimeDictionaryMembers @(
                'kind',
                'path',
                'expected_temp_path',
                'file_identity',
                'nonce',
                'launcher_pid',
                'launcher_process_start_utc_ticks',
                'launcher_lock_sha256'
            ) `
            -LinkedObjectMembers @(
                'Kind',
                'Path',
                'ExpectedTempPath',
                'FileIdentity',
                'Nonce',
                'LauncherPid',
                'LauncherProcessStartUtcTicks',
                'LauncherLockSha256'
            ) `
            -Description 'subordinate cleanup TEMP entry'
        $linkedShape = $entryShape -ceq 'linked-object'
        $temps.Add([ordered]@{
            kind = if ($linkedShape) { [string]$entry.Kind } else {
                [string]$entry['kind']
            }
            path = [IO.Path]::GetFullPath($(if ($linkedShape) {
                    [string]$entry.Path
                } else { [string]$entry['path'] }))
            expected_temp_path = [IO.Path]::GetFullPath($(if ($linkedShape) {
                    [string]$entry.ExpectedTempPath
                } else { [string]$entry['expected_temp_path'] }))
            file_identity = if ($linkedShape) {
                [string]$entry.FileIdentity
            } else { [string]$entry['file_identity'] }
            nonce = if ($linkedShape) { $entry.Nonce } else {
                $entry['nonce']
            }
            launcher_pid = [int]$(if ($linkedShape) {
                    $entry.LauncherPid
                } else { $entry['launcher_pid'] })
            launcher_process_start_utc_ticks = [long]$(if ($linkedShape) {
                    $entry.LauncherProcessStartUtcTicks
                } else { $entry['launcher_process_start_utc_ticks'] })
            launcher_lock_sha256 = if ($linkedShape) {
                [string]$entry.LauncherLockSha256
            } else { [string]$entry['launcher_lock_sha256'] }
        })
    }
    $canonical = [ordered]@{
        schema = 'astrolabe.launcher-lock-subordinate-cleanup-plan.v1'
        transaction_id = $TransactionId
        subordinate_state = $subordinateState
        exact_launcher_lease_start_utc_ticks = $leaseTicks
        exact_job_object_name = $jobName
        records = [object[]]@($records)
        temps = [object[]]@($temps)
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($canonical | ConvertTo-Json -Depth 8 -Compress)
    )
    return [pscustomobject]@{
        Schema = $canonical.schema
        TransactionId = $TransactionId
        SubordinateState = $subordinateState
        ExactLauncherLeaseStartUtcTicks = $leaseTicks
        ExactJobObjectName = $jobName
        Records = [object[]]@($records)
        Temps = [object[]]@($temps)
        Sha256 = Get-AstroByteSha256 $bytes
    }
}

function Assert-AstroSubordinateProbeMatchesPlan {
    param(
        [Parameter(Mandatory)]$Probe,
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)][string]$RecoveryRoot,
        [Parameter(Mandatory)][string]$Description
    )

    $current = ConvertTo-AstroSubordinateCleanupPlan `
        -Probe $Probe `
        -RecoveryRoot $RecoveryRoot `
        -TransactionId $Plan.TransactionId
    if ($current.ExactJobObjectName -cne $Plan.ExactJobObjectName -or
        $current.ExactLauncherLeaseStartUtcTicks -ne
            $Plan.ExactLauncherLeaseStartUtcTicks) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_JOB_CHANGED' `
            "$Description exact Job/lease derivation differs from the durable cleanup plan" `
            'preserve all state; subordinate recovery may only continue for the original exact launcher generation'
    }
    $planned = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($record in @($Plan.Records)) {
        if ($planned.ContainsKey($record.path)) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_PLAN_INVALID' `
                "$Description durable cleanup plan repeats path '$($record.path)'" `
                'preserve all state and investigate corrupt linked recovery evidence'
        }
        $planned.Add($record.path, $record)
    }
    $currentPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($record in @($current.Records)) {
        if (-not $currentPaths.Add($record.path) -or
            -not $planned.ContainsKey($record.path)) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_CONFLICT' `
                "$Description found an unplanned/duplicate attribution path '$($record.path)'" `
                'preserve every entry; never extend a durable cleanup transaction to new evidence'
        }
        $expected = $planned[$record.path]
        if ($record.kind -cne $expected.kind -or
            $record.file_identity -cne $expected.file_identity -or
            $record.bytes -ne $expected.bytes -or
            $record.sha256 -cne $expected.sha256 -or
            $record.valid -ne $expected.valid -or
            $record.schema_version -ne $expected.schema_version -or
            $record.job_limit_flags -ne $expected.job_limit_flags -or
            $record.cleanup_action -cne $expected.cleanup_action -or
            -not [string]::Equals(
                $record.expected_temp_path,
                $expected.expected_temp_path,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_CHANGED' `
                "$Description attribution bytes/FILE_ID/kind changed: $($record.path)" `
                'preserve every entry; the durable transaction authorizes only the exact original evidence'
        }
    }
    foreach ($record in @($Plan.Records)) {
        if ($record.cleanup_action -ceq 'preserve-complete-pair' -and
            -not $currentPaths.Contains($record.path)) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_CHANGED' `
                "$Description complete-pair evidence disappeared: $($record.path)" `
                'preserve all state; pair evidence is immutable while its transition recovery is pending'
        }
    }
    [string[]]$expectedTempPaths = @($Plan.Temps | ForEach-Object path)
    [string[]]$currentTempPaths = @($current.Temps | ForEach-Object path)
    [Array]::Sort($expectedTempPaths, [StringComparer]::OrdinalIgnoreCase)
    [Array]::Sort($currentTempPaths, [StringComparer]::OrdinalIgnoreCase)
    if ($expectedTempPaths.Count -ne $currentTempPaths.Count) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_TEMP_CHANGED' `
            "$Description exact TEMP cardinality differs from the durable plan" `
            'preserve every entry; TEMP creation/removal is never inferred during reclaim recovery'
    }
    for ($index = 0; $index -lt $expectedTempPaths.Count; $index++) {
        if (-not [string]::Equals(
                $expectedTempPaths[$index],
                $currentTempPaths[$index],
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_TEMP_CHANGED' `
                "$Description exact TEMP inventory differs from the durable plan" `
                'preserve every entry; TEMP without its exact durable final evidence remains ambiguous'
        }
        $expectedTemp = @($Plan.Temps | Where-Object {
                [string]::Equals(
                    $_.path,
                    $expectedTempPaths[$index],
                    [StringComparison]::OrdinalIgnoreCase
                )
            })[0]
        $currentTemp = @($current.Temps | Where-Object {
                [string]::Equals(
                    $_.path,
                    $currentTempPaths[$index],
                    [StringComparison]::OrdinalIgnoreCase
                )
            })[0]
        if ($currentTemp.kind -cne $expectedTemp.kind -or
            $currentTemp.file_identity -cne $expectedTemp.file_identity -or
            $currentTemp.nonce -cne $expectedTemp.nonce -or
            -not [string]::Equals(
                $currentTemp.expected_temp_path,
                $expectedTemp.expected_temp_path,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            $currentTemp.launcher_pid -ne $expectedTemp.launcher_pid -or
            $currentTemp.launcher_process_start_utc_ticks -ne
                $expectedTemp.launcher_process_start_utc_ticks -or
            $currentTemp.launcher_lock_sha256 -cne
                $expectedTemp.launcher_lock_sha256) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_TEMP_CHANGED' `
                "$Description exact TEMP kind/FILE_ID/generation mapping changed: $($currentTemp.path)" `
                'preserve every entry; the durable transaction binds the exact TEMP directory identity'
        }
    }
    return $current
}

function Invoke-AstroSubordinateCleanupPlan {
    param(
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)]$CurrentProbe,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$RootIdentity,
        [Parameter(Mandatory)][string]$RecoveryRoot,
        [Parameter(Mandatory)]$RecoveryDirectoryHandle,
        [Parameter(Mandatory)][int]$ExpectedOwnerPid,
        [Parameter(Mandatory)][long]$ExpectedOwnerProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$ExpectedLauncherLockSha256,
        [Parameter(Mandatory)][bool]$AllowMalformedExactStageQuarantine
    )

    $null = Assert-AstroSubordinateProbeMatchesPlan `
        -Probe $CurrentProbe `
        -Plan $Plan `
        -RecoveryRoot $RecoveryRoot `
        -Description 'pre-mutation subordinate inventory'
    $actions = [Collections.Generic.List[object]]::new()
    $orderedRecords = @($Plan.Records | Sort-Object -Property @(
            @{ Expression = {
                    if ($_.cleanup_action -ceq 'archive-quarantine') { 0 }
                    elseif ($_.kind -ceq 'stage') { 1 }
                    else { 2 }
                } },
            @{ Expression = { $_.path } }
        ))
    foreach ($record in $orderedRecords) {
        if ($record.cleanup_action -ceq 'preserve-complete-pair') {
            $actions.Add([ordered]@{
                kind = $record.kind
                path = $record.path
                action = 'preserved-complete-pair'
                terminal_state = 'present'
                archive_path = $null
            })
            continue
        }
        $sourceState = Get-AstroPathEntryState $record.path
        if ($record.cleanup_action -ceq 'archive-quarantine') {
            if (-not $AllowMalformedExactStageQuarantine) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_QUARANTINE_REQUIRED' `
                    "durable plan requires malformed-stage quarantine: $($record.path)" `
                    'retry only with explicit QuarantineUnreadable matching the tracker authorization'
            }
            $archiveState = Get-AstroPathEntryState `
                $record.quarantine_archive_path
            if ($sourceState.State -eq 'present' -and
                $archiveState.State -eq 'absent') {
                $lease = Open-AstroExactRenameLease `
                    $record.path `
                    'malformed claim-bound attribution stage'
                try {
                    $snapshot = $lease.InitialSnapshot
                    if ($snapshot.FileIdentity -cne $record.file_identity -or
                        $snapshot.Length -ne $record.bytes -or
                        $snapshot.Sha256 -cne $record.sha256) {
                        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_CHANGED' `
                            "malformed stage differs from durable plan: $($record.path)" `
                            'preserve source/archive/marker and investigate FILE_ID or byte drift'
                    }
                    $moved = Move-AstroRetainedLeaseNoReplace `
                        $lease `
                        $RecoveryDirectoryHandle `
                        $record.quarantine_archive_path `
                        $snapshot `
                        'transaction-bound malformed attribution stage'
                    $moved.ObserverLease.Handle.Dispose()
                }
                finally {
                    $lease.Handle.Dispose()
                }
            }
            elseif ($sourceState.State -eq 'absent' -and
                $archiveState.State -eq 'present') {
                $archiveLease = Open-AstroExactEvidenceLease `
                    $record.quarantine_archive_path `
                    'previously archived malformed attribution stage'
                try {
                    $snapshot = $archiveLease.InitialSnapshot
                    if ($snapshot.FileIdentity -cne $record.file_identity -or
                        $snapshot.Length -ne $record.bytes -or
                        $snapshot.Sha256 -cne $record.sha256) {
                        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_CHANGED' `
                            "malformed-stage archive differs from durable plan: $($record.quarantine_archive_path)" `
                            'preserve every entry and investigate interrupted transaction drift'
                    }
                }
                finally {
                    $archiveLease.Handle.Dispose()
                }
            }
            else {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_ARCHIVE_AMBIGUOUS' `
                    "malformed stage must exist at exactly one source/archive location (source=$($sourceState.State), archive=$($archiveState.State)): $($record.path)" `
                    'preserve all state; never path-delete an unreadable partial stage'
            }
            $actions.Add([ordered]@{
                kind = $record.kind
                path = $record.path
                action = 'archived-quarantine'
                terminal_state = 'absent'
                archive_path = $record.quarantine_archive_path
            })
            continue
        }
        if ($sourceState.State -eq 'absent') {
            $actions.Add([ordered]@{
                kind = $record.kind
                path = $record.path
                action = 'already-absent-from-prior-attempt'
                terminal_state = 'absent'
                archive_path = $null
            })
            continue
        }
        if ($sourceState.State -ne 'present') {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_UNEVALUABLE' `
                "claim-bound attribution source is not evaluable (state=$($sourceState.State), error=$($sourceState.Error)): $($record.path)" `
                'preserve every entry and repair exact path access'
        }
        $probe = if ($record.kind -ceq 'manifest') {
            Get-AstroAttributionManifestProbe `
                -ManifestPath $record.path `
                -RootIdentity $RootIdentity
        } else {
            Get-AstroAttributionStageProbe `
                -StagePath $record.path `
                -RootIdentity $RootIdentity
        }
        if (-not $probe.Valid -or
            $probe.Snapshot.FileId -cne $record.file_identity -or
            $probe.Snapshot.Length -ne $record.bytes -or
            $probe.Snapshot.Sha256 -cne $record.sha256 -or
            $probe.OwnerProbe.State -cnotin @('absent', 'pid-reused') -or
            $probe.JobObjectProbe.State -cne 'absent') {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_CHANGED' `
                "claim-bound attribution evidence no longer matches its dead-owner/absent-Job durable plan: $($record.path)" `
                'preserve every entry and re-establish exact current state'
        }
        $removed = Remove-AstroDeadAttributionEvidenceFile $probe
        if ((Get-AstroPathEntryState $record.path).State -ne 'absent') {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_DELETE_FAILED' `
                "shared exact mutation API did not leave attribution path absent: $($record.path)" `
                'preserve the marker and all remaining state; inspect the retained mutation result'
        }
        $actions.Add([ordered]@{
            kind = $record.kind
            path = $record.path
            action = 'deleted-through-shared-retained-api'
            terminal_state = 'absent'
            archive_path = $null
            shared_result = $removed
        })
    }

    $terminalProbe = Get-AstroReclaimAttributionProbe `
        -Root $Root `
        -ProbeName 'after-transaction-bound-subordinate-cleanup' `
        -ExpectedOwnerPid $ExpectedOwnerPid `
        -ExpectedOwnerProcessStartUtcTicks `
            $ExpectedOwnerProcessStartUtcTicks `
        -ExpectedLauncherLeaseStartUtcTicks `
            $Plan.ExactLauncherLeaseStartUtcTicks `
        -ExpectedLauncherLockSha256 $ExpectedLauncherLockSha256 `
        -RootIdentity $RootIdentity `
        -RecoveryRoot $RecoveryRoot `
        -RecoveryTransactionId $Plan.TransactionId `
        -AllowMalformedExactStageQuarantine `
            $AllowMalformedExactStageQuarantine `
        -Policy 'post-cleanup'
    $expectedTerminalState = if ($Plan.SubordinateState -ceq 'complete-pair') {
        'complete-pair'
    } else { 'none' }
    if ($terminalProbe.subordinate_state -cne $expectedTerminalState) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_POSTSTATE_INVALID' `
            "terminal subordinate state '$($terminalProbe.subordinate_state)' differs from durable expected '$expectedTerminalState'" `
            'preserve marker/source/recovery evidence and inspect the exact terminal inventory'
    }
    $quarantineArchives = [Collections.Generic.List[object]]::new()
    foreach ($record in @($Plan.Records | Where-Object {
                $_.cleanup_action -ceq 'archive-quarantine'
            })) {
        $lease = Open-AstroExactEvidenceLease `
            $record.quarantine_archive_path `
            'terminal malformed-stage quarantine archive'
        try {
            $snapshot = $lease.InitialSnapshot
            if ($snapshot.FileIdentity -cne $record.file_identity -or
                $snapshot.Length -ne $record.bytes -or
                $snapshot.Sha256 -cne $record.sha256) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_CHANGED' `
                    "terminal malformed-stage archive differs from durable plan: $($record.quarantine_archive_path)" `
                    'preserve marker/source/recovery evidence and investigate archive drift'
            }
            $quarantineArchives.Add([ordered]@{
                path = $record.quarantine_archive_path
                file_identity = $snapshot.FileIdentity
                bytes = $snapshot.Length
                sha256 = $snapshot.Sha256
            })
        }
        finally {
            $lease.Handle.Dispose()
        }
    }
    return [pscustomobject]@{
        PlanSha256 = $Plan.Sha256
        InitialState = $Plan.SubordinateState
        TerminalState = $terminalProbe.subordinate_state
        Actions = [object[]]@($actions)
        QuarantineArchives = [object[]]@($quarantineArchives)
        TerminalProbe = $terminalProbe
    }
}

function Assert-AstroStrictObjectShape {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string[]]$Names,
        [Parameter(Mandatory)][string]$JsonPath
    )

    if ($Node.Kind -cne 'object' -or
        @($Node.Names).Count -ne $Names.Count) {
        throw "$JsonPath must contain exactly $($Names.Count) ordered fields"
    }
    for ($index = 0; $index -lt $Names.Count; $index++) {
        $name = $Names[$index]
        if (-not $Node.Properties.ContainsKey($name) -or
            [string]$Node.Names[$index] -cne $name -or
            [string]$Node.RawNames[$index] -cne ('"' + $name + '"')) {
            throw "$JsonPath field $index must be the exact canonical '$name' property"
        }
    }
}

function Read-AstroStrictJsonDocumentObject {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Description
    )

    if ($Bytes.Length -eq 0 -or
        $Bytes.Length -gt $script:AstroLauncherProtocolSnapshotMaxBytes) {
        throw "$Description must contain 1-$script:AstroLauncherProtocolSnapshotMaxBytes bytes"
    }
    $json = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
    if ($json.Length -gt 0 -and $json[0] -eq [char]0xfeff) {
        throw "$Description must not contain a UTF-8 BOM"
    }
    $root = Read-AstroStrictJsonValueNode $json 0 0 '$'
    $end = Get-AstroJsonNextTokenIndex $json $root.NextIndex
    if ($end -ne $json.Length -or $root.Kind -cne 'object') {
        throw "$Description must be exactly one JSON object with no trailing data"
    }
    return $root
}

function Get-AstroStrictStringValue {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string]$JsonPath,
        [switch]$Nonblank
    )

    if ($Node.Kind -cne 'string' -or
        ($Nonblank -and
            [string]::IsNullOrWhiteSpace([string]$Node.Value))) {
        throw "$JsonPath must be a$(if ($Nonblank) { ' nonblank' }) JSON string"
    }
    return [string]$Node.Value
}

function Get-AstroStrictBooleanValue {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string]$JsonPath
    )
    if ($Node.Kind -cne 'boolean') {
        throw "$JsonPath must be a JSON boolean"
    }
    return [bool]$Node.Value
}

function Convert-AstroLinkedAbsentJobProbeNode {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string]$JsonPath,
        [Parameter(Mandatory)][string]$ExpectedName
    )

    Assert-AstroStrictObjectShape $Node @(
        'name',
        'state',
        'process_ids',
        'native_error_code',
        'number_of_assigned_processes',
        'number_of_process_ids_in_list',
        'error'
    ) $JsonPath
    $name = Get-AstroStrictStringValue `
        $Node.Properties['name'] "$JsonPath.name" -Nonblank
    $state = Get-AstroStrictStringValue `
        $Node.Properties['state'] "$JsonPath.state" -Nonblank
    if ($name -cne $ExpectedName -or $state -cne 'absent') {
        throw "$JsonPath does not prove absence of exact Job Object '$ExpectedName'"
    }
    if ($Node.Properties['process_ids'].Kind -cne 'array' -or
        @($Node.Properties['process_ids'].Items).Count -ne 0) {
        throw "$JsonPath absent Job Object probe must have an empty process_ids array"
    }
    $nativeErrorCode = ConvertFrom-AstroJsonUnsignedNode `
        $Node.Properties['native_error_code'] `
        "$JsonPath.native_error_code" `
        ([uint64][uint32]::MaxValue)
    # OpenJobObjectW reports ERROR_FILE_NOT_FOUND (2) for the only state that
    # the native classifier maps to `absent`. Zero would describe success and
    # contradict the persisted producer contract.
    if ($nativeErrorCode -ne 2) {
        throw "$JsonPath absent Job Object probe must bind native ERROR_FILE_NOT_FOUND (2)"
    }
    foreach ($countName in @(
            'number_of_assigned_processes',
            'number_of_process_ids_in_list'
        )) {
        $count = ConvertFrom-AstroJsonUnsignedNode `
            $Node.Properties[$countName] `
            "$JsonPath.$countName" `
            ([uint64][uint32]::MaxValue)
        if ($count -ne 0) {
            throw "$JsonPath absent Job Object probe has nonzero $countName"
        }
    }
    if ($Node.Properties['error'].Kind -cne 'null') {
        throw "$JsonPath successful absent Job Object probe must have null error"
    }
    return [pscustomobject]@{
        Name = $name
        State = $state
        NativeErrorCode = [int]$nativeErrorCode
    }
}

function Convert-AstroLinkedAttributionOwnerProbeNode {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string]$JsonPath,
        [Parameter(Mandatory)][int]$ExpectedPid,
        [Parameter(Mandatory)][long]$ExpectedTicks
    )

    Assert-AstroStrictObjectShape $Node @(
        'state',
        'launcher_pid',
        'expected_process_start_utc_ticks',
        'observed_process_start_utc_ticks',
        'error'
    ) $JsonPath
    $state = Get-AstroStrictStringValue `
        $Node.Properties['state'] "$JsonPath.state" -Nonblank
    $parsedLauncherPid = [int](ConvertFrom-AstroJsonUnsignedNode `
        $Node.Properties['launcher_pid'] "$JsonPath.launcher_pid" `
        ([uint64][int]::MaxValue) -Positive)
    $ticks = [long](ConvertFrom-AstroJsonUnsignedNode `
        $Node.Properties['expected_process_start_utc_ticks'] `
        "$JsonPath.expected_process_start_utc_ticks" `
        ([uint64][DateTime]::MaxValue.Ticks) -Positive)
    $observedTicks = if (
        $Node.Properties['observed_process_start_utc_ticks'].Kind -ceq 'null'
    ) { $null } else {
        [long](ConvertFrom-AstroJsonUnsignedNode `
            $Node.Properties['observed_process_start_utc_ticks'] `
            "$JsonPath.observed_process_start_utc_ticks" `
            ([uint64][DateTime]::MaxValue.Ticks) -Positive)
    }
    if ($parsedLauncherPid -ne $ExpectedPid -or
        $ticks -ne $ExpectedTicks -or
        $state -cnotin @('absent', 'pid-reused') -or
        ($state -ceq 'absent' -and $null -ne $observedTicks) -or
        ($state -ceq 'pid-reused' -and
            ($null -eq $observedTicks -or $observedTicks -eq $ExpectedTicks))) {
        throw "$JsonPath does not prove the exact attribution owner generation absent/reused"
    }
    if ($state -ceq 'absent' -and
        $Node.Properties['error'].Kind -cne 'null') {
        throw "$JsonPath absent owner probe must have null error"
    }
    return [pscustomobject]@{
        State = $state
        LauncherPid = $parsedLauncherPid
        ExpectedProcessStartUtcTicks = $ticks
        ObservedProcessStartUtcTicks = $observedTicks
    }
}

function Convert-AstroStrictJsonNodeToCanonicalValue {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string]$JsonPath
    )

    switch ([string]$Node.Kind) {
        'null' { return $null }
        'boolean' { return [bool]$Node.Value }
        'string' { return [string]$Node.Value }
        'integer' {
            $signed = 0L
            if ([long]::TryParse(
                    [string]$Node.Raw,
                    [Globalization.NumberStyles]::AllowLeadingSign,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [ref]$signed
                )) {
                return $signed
            }
            $unsigned = [uint64]0
            if ([uint64]::TryParse(
                    [string]$Node.Raw,
                    [Globalization.NumberStyles]::None,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [ref]$unsigned
                )) {
                return $unsigned
            }
            throw "$JsonPath integer is outside the canonical 64-bit range"
        }
        'array' {
            $values = [Collections.Generic.List[object]]::new()
            for ($index = 0; $index -lt @($Node.Items).Count; $index++) {
                $values.Add((Convert-AstroStrictJsonNodeToCanonicalValue `
                    $Node.Items[$index] "$JsonPath[$index]"))
            }
            Write-Output -NoEnumerate ([object[]]@($values))
            return
        }
        'object' {
            $value = [ordered]@{}
            foreach ($name in [string[]]@($Node.Names)) {
                $value[$name] = Convert-AstroStrictJsonNodeToCanonicalValue `
                    $Node.Properties[$name] "$JsonPath.$name"
            }
            return $value
        }
        default {
            throw "$JsonPath contains unsupported canonical JSON kind '$($Node.Kind)'"
        }
    }
}

function Convert-AstroLinkedAttributionProbeNode {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string]$JsonPath
    )

    Assert-AstroStrictObjectShape $Node @(
        'probe',
        'state',
        'policy',
        'subordinate_state',
        'exact_manifest_observed',
        'exact_manifest_lease_start_utc_ticks',
        'exact_launcher_lease_start_utc_ticks',
        'exact_job_object_name',
        'exact_job_object_probe',
        'manifests',
        'refresh_transactions',
        'temps',
        'unrelated_complete_pairs',
        'stable_fingerprint_sha256',
        'observed_at_utc'
    ) $JsonPath
    $state = Get-AstroStrictStringValue `
        $Node.Properties['state'] "$JsonPath.state" -Nonblank
    if ($state -cnotin @('absent', 'observed')) {
        throw "$JsonPath.state is unsupported: '$state'"
    }
    $policy = Get-AstroStrictStringValue `
        $Node.Properties['policy'] "$JsonPath.policy" -Nonblank
    if ($policy -cnotin @(
            'transition-bound-v2',
            'transition-bound-v3',
            'prior-marker-record',
            'post-cleanup'
        )) {
        throw "$JsonPath.policy is unsupported: '$policy'"
    }
    $subordinateState = Get-AstroStrictStringValue `
        $Node.Properties['subordinate_state'] `
        "$JsonPath.subordinate_state" -Nonblank
    if ($subordinateState -cnotin @(
            'none',
            'partial-evidence',
            'complete-pair'
        )) {
        throw "$JsonPath.subordinate_state is unsupported: '$subordinateState'"
    }
    $exact = Get-AstroStrictBooleanValue `
        $Node.Properties['exact_manifest_observed'] `
        "$JsonPath.exact_manifest_observed"
    $exactLeaseTicks = if (
        $Node.Properties['exact_manifest_lease_start_utc_ticks'].Kind -ceq
            'null'
    ) { $null } else {
        [long](ConvertFrom-AstroJsonUnsignedNode `
            $Node.Properties['exact_manifest_lease_start_utc_ticks'] `
            "$JsonPath.exact_manifest_lease_start_utc_ticks" `
            ([uint64][DateTime]::MaxValue.Ticks) `
            -Positive)
    }
    $fingerprint = Get-AstroStrictStringValue `
        $Node.Properties['stable_fingerprint_sha256'] `
        "$JsonPath.stable_fingerprint_sha256" `
        -Nonblank
    if ($fingerprint -cnotmatch '^[0-9a-f]{64}$') {
        throw "$JsonPath.stable_fingerprint_sha256 is not lowercase SHA-256"
    }
    $exactLauncherLeaseTicks = [long](ConvertFrom-AstroJsonUnsignedNode `
        $Node.Properties['exact_launcher_lease_start_utc_ticks'] `
        "$JsonPath.exact_launcher_lease_start_utc_ticks" `
        ([uint64][DateTime]::MaxValue.Ticks) `
        -Positive)
    $exactJobObjectName = Get-AstroStrictStringValue `
        $Node.Properties['exact_job_object_name'] `
        "$JsonPath.exact_job_object_name" `
        -Nonblank
    $exactJobProbe = Convert-AstroLinkedAbsentJobProbeNode `
        $Node.Properties['exact_job_object_probe'] `
        "$JsonPath.exact_job_object_probe" `
        $exactJobObjectName
    $manifestsNode = $Node.Properties['manifests']
    if ($manifestsNode.Kind -cne 'array') {
        throw "$JsonPath.manifests must be an array, including for zero/one entries"
    }
    $manifestBindings = [Collections.Generic.List[object]]::new()
    foreach ($manifest in [object[]]@($manifestsNode.Items)) {
        $hasSchemaVersion = $manifest.Properties.ContainsKey('schema_version')
        $hasJobLimitFlags = $manifest.Properties.ContainsKey('job_limit_flags')
        if ($hasSchemaVersion -ne $hasJobLimitFlags) {
            throw "$JsonPath manifest job-contract fields must be both present or both absent"
        }
        $manifestFields = [Collections.Generic.List[string]]::new()
        foreach ($field in @(
            'kind',
            'path',
            'file_identity',
            'bytes',
            'sha256',
            'valid',
            'schema_error',
            'launcher_pid',
            'launcher_process_start_utc_ticks',
            'launcher_lock_sha256',
            'launcher_lease_start_utc_ticks'
        )) { $manifestFields.Add($field) }
        if ($hasSchemaVersion) {
            $manifestFields.Add('schema_version')
            $manifestFields.Add('job_limit_flags')
        }
        foreach ($field in @(
            'job_object_name',
            'expected_temp_path',
            'exact_expected_launcher',
            'exact_claim_identity',
            'cleanup_action',
            'quarantine_archive_path',
            'run_started_unix_ns',
            'written_at',
            'tree_pids',
            'open_pids',
            'owned_paths_unevaluable',
            'owned_paths',
            'owner_generation_probe',
            'job_object_probe'
        )) { $manifestFields.Add($field) }
        Assert-AstroStrictObjectShape `
            $manifest `
            ([string[]]@($manifestFields)) `
            "$JsonPath.manifests[]"
        $entryKind = Get-AstroStrictStringValue `
            $manifest.Properties['kind'] `
            "$JsonPath.manifests[].kind" `
            -Nonblank
        if ($entryKind -cnotin @(
                'manifest',
                'stage',
                'cleanup-tombstone'
            )) {
            throw "$JsonPath contains an unsupported attribution entry kind '$entryKind'"
        }
        $entryPath = [IO.Path]::GetFullPath((Get-AstroStrictStringValue `
            $manifest.Properties['path'] `
            "$JsonPath.manifests[].path" `
            -Nonblank))
        $entryFileIdentity = Get-AstroStrictStringValue `
            $manifest.Properties['file_identity'] `
            "$JsonPath.manifests[].file_identity" -Nonblank
        if ($entryFileIdentity -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$') {
            throw "$JsonPath attribution FILE_ID_INFO identity is invalid"
        }
        $entryBytes = [uint64](ConvertFrom-AstroJsonUnsignedNode `
            $manifest.Properties['bytes'] "$JsonPath.manifests[].bytes" `
            ([uint64]::MaxValue) -Positive)
        $entrySha = Get-AstroStrictStringValue `
            $manifest.Properties['sha256'] `
            "$JsonPath.manifests[].sha256" -Nonblank
        if ($entrySha -cnotmatch '^[0-9a-f]{64}$') {
            throw "$JsonPath attribution sha256 is invalid"
        }
        $entryValid = Get-AstroStrictBooleanValue `
            $manifest.Properties['valid'] "$JsonPath.manifests[].valid"
        $jobObjectName = Get-AstroStrictStringValue `
            $manifest.Properties['job_object_name'] `
            "$JsonPath.manifests[].job_object_name" `
            -Nonblank
        $expectedTempPath = [IO.Path]::GetFullPath((Get-AstroStrictStringValue `
            $manifest.Properties['expected_temp_path'] `
            "$JsonPath.manifests[].expected_temp_path" `
            -Nonblank))
        $launcherPid = [int](ConvertFrom-AstroJsonUnsignedNode `
            $manifest.Properties['launcher_pid'] `
            "$JsonPath.manifests[].launcher_pid" `
            ([uint64][int]::MaxValue) `
            -Positive)
        $launcherTicks = [long](ConvertFrom-AstroJsonUnsignedNode `
            $manifest.Properties['launcher_process_start_utc_ticks'] `
            "$JsonPath.manifests[].launcher_process_start_utc_ticks" `
            ([uint64][DateTime]::MaxValue.Ticks) `
            -Positive)
        $launcherLockSha = Get-AstroStrictStringValue `
            $manifest.Properties['launcher_lock_sha256'] `
            "$JsonPath.manifests[].launcher_lock_sha256" `
            -Nonblank
        if ($launcherLockSha -cnotmatch '^[0-9a-f]{64}$') {
            throw "$JsonPath manifest launcher_lock_sha256 is invalid"
        }
        $launcherLeaseTicks = [long](ConvertFrom-AstroJsonUnsignedNode `
            $manifest.Properties['launcher_lease_start_utc_ticks'] `
            "$JsonPath.manifests[].launcher_lease_start_utc_ticks" `
            ([uint64][DateTime]::MaxValue.Ticks) `
            -Positive)
        if ($launcherLeaseTicks -lt $launcherTicks) {
            throw "$JsonPath manifest lease ticks precede launcher process ticks"
        }
        $schemaVersion = if ($hasSchemaVersion -and
            $manifest.Properties['schema_version'].Kind -cne 'null') {
            [int](ConvertFrom-AstroJsonUnsignedNode `
                $manifest.Properties['schema_version'] `
                "$JsonPath.manifests[].schema_version" 3 -Positive)
        } else { $null }
        $jobLimitFlags = if ($hasJobLimitFlags -and
            $manifest.Properties['job_limit_flags'].Kind -cne 'null') {
            [uint32](ConvertFrom-AstroJsonUnsignedNode `
                $manifest.Properties['job_limit_flags'] `
                "$JsonPath.manifests[].job_limit_flags" `
                ([uint64][uint32]::MaxValue) -Positive)
        } else { $null }
        if ($entryValid -and $hasSchemaVersion -and
            ($schemaVersion -ne 3 -or $jobLimitFlags -ne 8192)) {
            throw "$JsonPath valid current attribution record must bind schema_version=3 and job_limit_flags=8192"
        }
        if (-not $entryValid -and $hasSchemaVersion -and
            ($null -ne $schemaVersion -or $null -ne $jobLimitFlags)) {
            throw "$JsonPath malformed attribution stage must carry null job-contract fields"
        }
        $manifestExact = Get-AstroStrictBooleanValue `
            $manifest.Properties['exact_expected_launcher'] `
            "$JsonPath.manifests[].exact_expected_launcher"
        $claimExact = Get-AstroStrictBooleanValue `
            $manifest.Properties['exact_claim_identity'] `
            "$JsonPath.manifests[].exact_claim_identity"
        if (-not $claimExact -or
            $manifestExact -ne
                ($entryKind -cin @('manifest', 'cleanup-tombstone'))) {
            throw "$JsonPath attribution exact identity/final flags are inconsistent"
        }
        $action = Get-AstroStrictStringValue `
            $manifest.Properties['cleanup_action'] `
            "$JsonPath.manifests[].cleanup_action" -Nonblank
        if ($action -cnotin @(
                'delete',
                'archive-quarantine',
                'preserve-complete-pair'
            )) {
            throw "$JsonPath attribution cleanup action is unsupported: '$action'"
        }
        $quarantineArchivePath = if (
            $manifest.Properties['quarantine_archive_path'].Kind -ceq 'null'
        ) { $null } else {
            [IO.Path]::GetFullPath((Get-AstroStrictStringValue `
                $manifest.Properties['quarantine_archive_path'] `
                "$JsonPath.manifests[].quarantine_archive_path" `
                -Nonblank))
        }
        if ($entryValid) {
            if ($manifest.Properties['schema_error'].Kind -cne 'null' -or
                $action -ceq 'archive-quarantine' -or
                $null -ne $quarantineArchivePath) {
                throw "$JsonPath valid attribution record has malformed-stage quarantine fields"
            }
        }
        elseif ($entryKind -cne 'stage' -or
            $manifest.Properties['schema_error'].Kind -cne 'string' -or
            [string]::IsNullOrWhiteSpace(
                [string]$manifest.Properties['schema_error'].Value
            ) -or $action -cne 'archive-quarantine' -or
            $null -eq $quarantineArchivePath) {
            throw "$JsonPath only an exact malformed stage may carry archive-quarantine"
        }
        if (($subordinateState -ceq 'partial-evidence' -and
                $entryValid -and $action -cne 'delete') -or
            ($subordinateState -ceq 'complete-pair' -and
                $entryValid -and $action -cne 'preserve-complete-pair')) {
            throw "$JsonPath cleanup action disagrees with subordinate_state"
        }
        $ownerGenerationProbe = Convert-AstroLinkedAttributionOwnerProbeNode `
            $manifest.Properties['owner_generation_probe'] `
            "$JsonPath.manifests[].owner_generation_probe" `
            $launcherPid `
            $launcherTicks
        $job = $manifest.Properties['job_object_probe']
        $jobBinding = Convert-AstroLinkedAbsentJobProbeNode `
            $job `
            "$JsonPath.manifests[].job_object_probe" `
            $jobObjectName
        $manifestBindings.Add([pscustomobject]@{
            Path = $entryPath
            FileIdentity = $entryFileIdentity
            Bytes = $entryBytes
            Sha256 = $entrySha
            Valid = $entryValid
            LauncherPid = $launcherPid
            LauncherProcessStartUtcTicks = $launcherTicks
            LauncherLockSha256 = $launcherLockSha
            LauncherLeaseStartUtcTicks = $launcherLeaseTicks
            SchemaVersion = $schemaVersion
            JobLimitFlags = $jobLimitFlags
            JobObjectName = $jobObjectName
            ExpectedTempPath = $expectedTempPath
            ExactExpectedLauncher = $manifestExact
            ExactClaimIdentity = $claimExact
            Kind = $entryKind
            CleanupAction = $action
            QuarantineArchivePath = $quarantineArchivePath
            OwnerProbe = $ownerGenerationProbe
            JobObjectProbe = $jobBinding
        })
    }
    $refreshNode = $Node.Properties['refresh_transactions']
    if ($refreshNode.Kind -cne 'array') {
        throw "$JsonPath.refresh_transactions must be an array"
    }
    $refreshBindings = [Collections.Generic.List[object]]::new()
    $refreshKeys = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($refresh in [object[]]@($refreshNode.Items)) {
        $hasRefreshSchemaVersion =
            $refresh.Properties.ContainsKey('schema_version')
        $hasRefreshJobLimitFlags =
            $refresh.Properties.ContainsKey('job_limit_flags')
        if ($hasRefreshSchemaVersion -ne $hasRefreshJobLimitFlags) {
            throw "$JsonPath refresh job-contract fields must be both present or both absent"
        }
        $refreshFields = [Collections.Generic.List[string]]::new()
        foreach ($field in @(
            'key',
            'state',
            'phase',
            'rename_suffix_quarantine',
            'nonce',
            'envelope_path',
            'envelope_file_identity',
            'envelope_bytes',
            'envelope_sha256',
            'old_tombstone_path',
            'old_tombstone_present',
            'old_file_identity',
            'old_bytes',
            'old_sha256',
            'final_path',
            'final_present',
            'final_binding',
            'final_file_identity',
            'final_bytes',
            'final_sha256',
            'logical_final_file_identity',
            'logical_final_bytes',
            'logical_final_sha256',
            'launcher_pid',
            'launcher_process_start_utc_ticks',
            'launcher_lock_sha256',
            'launcher_lease_start_utc_ticks'
        )) { $refreshFields.Add($field) }
        if ($hasRefreshSchemaVersion) {
            $refreshFields.Add('schema_version')
            $refreshFields.Add('job_limit_flags')
        }
        foreach ($field in @(
            'job_object_name',
            'owner_generation_probe',
            'job_object_probe'
        )) { $refreshFields.Add($field) }
        Assert-AstroStrictObjectShape `
            $refresh `
            ([string[]]@($refreshFields)) `
            "$JsonPath.refresh_transactions[]"
        $refreshPath = "$JsonPath.refresh_transactions[]"
        $key = Get-AstroStrictStringValue `
            $refresh.Properties['key'] "$refreshPath.key" -Nonblank
        if (-not $refreshKeys.Add($key)) {
            throw "$JsonPath repeats refresh transaction key '$key'"
        }
        $state = Get-AstroStrictStringValue `
            $refresh.Properties['state'] "$refreshPath.state" -Nonblank
        $phase = Get-AstroStrictStringValue `
            $refresh.Properties['phase'] "$refreshPath.phase" -Nonblank
        $renameSuffixQuarantine = Get-AstroStrictBooleanValue `
            $refresh.Properties['rename_suffix_quarantine'] `
            "$refreshPath.rename_suffix_quarantine"
        $nonce = Get-AstroStrictStringValue `
            $refresh.Properties['nonce'] "$refreshPath.nonce" -Nonblank
        $refreshLauncherPid = [int](ConvertFrom-AstroJsonUnsignedNode `
            $refresh.Properties['launcher_pid'] "$refreshPath.launcher_pid" `
            ([uint64][int]::MaxValue) -Positive)
        $ticks = [long](ConvertFrom-AstroJsonUnsignedNode `
            $refresh.Properties['launcher_process_start_utc_ticks'] `
            "$refreshPath.launcher_process_start_utc_ticks" `
            ([uint64][DateTime]::MaxValue.Ticks) -Positive)
        $lockSha = Get-AstroStrictStringValue `
            $refresh.Properties['launcher_lock_sha256'] `
            "$refreshPath.launcher_lock_sha256" -Nonblank
        $leaseTicks = [long](ConvertFrom-AstroJsonUnsignedNode `
            $refresh.Properties['launcher_lease_start_utc_ticks'] `
            "$refreshPath.launcher_lease_start_utc_ticks" `
            ([uint64][DateTime]::MaxValue.Ticks) -Positive)
        $refreshSchemaVersion = if ($hasRefreshSchemaVersion) {
            [int](ConvertFrom-AstroJsonUnsignedNode `
                $refresh.Properties['schema_version'] `
                "$refreshPath.schema_version" 3 -Positive)
        } else { 2 }
        $refreshJobLimitFlags = if ($hasRefreshJobLimitFlags) {
            [uint32](ConvertFrom-AstroJsonUnsignedNode `
                $refresh.Properties['job_limit_flags'] `
                "$refreshPath.job_limit_flags" `
                ([uint64][uint32]::MaxValue) -Positive)
        } else { [uint32]0 }
        if ($hasRefreshSchemaVersion -and
            ($refreshSchemaVersion -ne 3 -or
                $refreshJobLimitFlags -ne 8192)) {
            throw "$refreshPath current job contract must be schema_version=3 and job_limit_flags=8192"
        }
        $jobName = Get-AstroStrictStringValue `
            $refresh.Properties['job_object_name'] `
            "$refreshPath.job_object_name" -Nonblank
        if ($nonce -cnotmatch '^[0-9a-f]{32}$' -or
            $lockSha -cnotmatch '^[0-9a-f]{64}$' -or
            $leaseTicks -lt $ticks -or
            $leaseTicks -ne $exactLauncherLeaseTicks -or
            $jobName -cne $exactJobObjectName -or
            $key -cne ("$refreshLauncherPid|$ticks|$lockSha|$nonce")) {
            throw "$refreshPath generation/nonce/lease/Job fields are not exact"
        }
        $envelopePathText = Get-AstroStrictStringValue `
            $refresh.Properties['envelope_path'] `
            "$refreshPath.envelope_path" -Nonblank
        $envelopePath = [IO.Path]::GetFullPath($envelopePathText)
        $envelopeName = ConvertFrom-AstroAttributionRefreshName $envelopePath
        if (-not $envelopeName.Valid -and $renameSuffixQuarantine) {
            $actualLeaf = [IO.Path]::GetFileName($envelopePath)
            $candidateLeaf = if ($actualLeaf.Length -gt 1) {
                $actualLeaf.Substring(0, $actualLeaf.Length - 1)
            } else { '' }
            $candidatePath = if ([string]::IsNullOrEmpty($candidateLeaf)) {
                ''
            } else {
                Join-Path ([IO.Path]::GetDirectoryName($envelopePath)) `
                    $candidateLeaf
            }
            $candidateName = if ([string]::IsNullOrEmpty($candidatePath)) {
                $null
            } else {
                ConvertFrom-AstroAttributionRefreshName $candidatePath
            }
            if ($null -ne $candidateName -and $candidateName.Valid -and
                $candidateName.Phase -ceq 'old-disposition-set' -and
                $actualLeaf -ceq ($candidateName.Leaf +
                    $actualLeaf[$actualLeaf.Length - 1])) {
                $envelopeName = $candidateName
            }
        }
        if ($envelopePathText -cne $envelopePath -or
            -not $envelopeName.Valid -or
            ($renameSuffixQuarantine -and
                $envelopeName.Phase -cne 'old-disposition-set') -or
            $envelopeName.Phase -cne $phase -or
            $envelopeName.LauncherPid -ne $refreshLauncherPid -or
            $envelopeName.LauncherProcessStartUtcTicks -ne $ticks -or
            $envelopeName.LauncherLockSha256 -cne $lockSha -or
            $envelopeName.Nonce -cne $nonce) {
            throw "$refreshPath envelope path/name does not bind its exact phase/generation/nonce"
        }
        $envelopeId = Get-AstroStrictStringValue `
            $refresh.Properties['envelope_file_identity'] `
            "$refreshPath.envelope_file_identity" -Nonblank
        $envelopeBytes = [uint64](ConvertFrom-AstroJsonUnsignedNode `
            $refresh.Properties['envelope_bytes'] `
            "$refreshPath.envelope_bytes" `
            ([uint64]$script:AstroLauncherProtocolSnapshotMaxBytes) -Positive)
        $envelopeSha = Get-AstroStrictStringValue `
            $refresh.Properties['envelope_sha256'] `
            "$refreshPath.envelope_sha256" -Nonblank
        if ($envelopeId -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$' -or
            $envelopeSha -cnotmatch '^[0-9a-f]{64}$') {
            throw "$refreshPath envelope FILE_ID/hash is invalid"
        }
        $oldPathText = Get-AstroStrictStringValue `
            $refresh.Properties['old_tombstone_path'] `
            "$refreshPath.old_tombstone_path" -Nonblank
        $oldPath = [IO.Path]::GetFullPath($oldPathText)
        $oldName = ConvertFrom-AstroAttributionRefreshOldName $oldPath
        if ($oldPathText -cne $oldPath -or -not $oldName.Valid -or
            $oldName.LauncherPid -ne $refreshLauncherPid -or
            $oldName.LauncherProcessStartUtcTicks -ne $ticks -or
            $oldName.LauncherLockSha256 -cne $lockSha -or
            $oldName.Nonce -cne $nonce) {
            throw "$refreshPath old tombstone path/name does not bind its generation/nonce"
        }
        $finalPathText = Get-AstroStrictStringValue `
            $refresh.Properties['final_path'] `
            "$refreshPath.final_path" -Nonblank
        $finalPath = [IO.Path]::GetFullPath($finalPathText)
        $finalManifestName = ConvertFrom-AstroAttributionManifestName $finalPath
        $expectedFinalLeaf = Get-AstroAttributionManifestLeaf `
            $refreshLauncherPid $ticks $lockSha `
            -SchemaVersion $refreshSchemaVersion
        if ($finalPathText -cne $finalPath -or
            -not $finalManifestName.Valid -or
            $finalManifestName.SchemaVersion -ne $refreshSchemaVersion -or
            [IO.Path]::GetFileName($finalPath) -cne $expectedFinalLeaf -or
            -not [string]::Equals(
                [IO.Path]::GetDirectoryName($finalPath),
                [IO.Path]::GetDirectoryName($envelopePath),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "$refreshPath final path is not the exact same-directory generation manifest"
        }
        $oldPresent = Get-AstroStrictBooleanValue `
            $refresh.Properties['old_tombstone_present'] `
            "$refreshPath.old_tombstone_present"
        $finalPresent = Get-AstroStrictBooleanValue `
            $refresh.Properties['final_present'] `
            "$refreshPath.final_present"
        $finalBinding = Get-AstroStrictStringValue `
            $refresh.Properties['final_binding'] `
            "$refreshPath.final_binding" -Nonblank
        $nullableIdentity = {
            param($ValueNode, [string]$FieldPath)
            if ($ValueNode.Kind -ceq 'null') { return $null }
            $value = Get-AstroStrictStringValue $ValueNode $FieldPath -Nonblank
            if ($value -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$') {
                throw "$FieldPath is not an exact FILE_ID_INFO identity"
            }
            return $value
        }
        $nullableSha = {
            param($ValueNode, [string]$FieldPath)
            if ($ValueNode.Kind -ceq 'null') { return $null }
            $value = Get-AstroStrictStringValue $ValueNode $FieldPath -Nonblank
            if ($value -cnotmatch '^[0-9a-f]{64}$') {
                throw "$FieldPath is not lowercase SHA-256"
            }
            return $value
        }
        $nullableLength = {
            param($ValueNode, [string]$FieldPath)
            if ($ValueNode.Kind -ceq 'null') { return $null }
            return [uint64](ConvertFrom-AstroJsonUnsignedNode `
                $ValueNode $FieldPath `
                ([uint64]$script:AstroLauncherProtocolSnapshotMaxBytes) `
                -Positive)
        }
        $oldId = & $nullableIdentity `
            $refresh.Properties['old_file_identity'] `
            "$refreshPath.old_file_identity"
        $oldBytes = & $nullableLength `
            $refresh.Properties['old_bytes'] "$refreshPath.old_bytes"
        $oldSha = & $nullableSha `
            $refresh.Properties['old_sha256'] "$refreshPath.old_sha256"
        $finalId = & $nullableIdentity `
            $refresh.Properties['final_file_identity'] `
            "$refreshPath.final_file_identity"
        $finalBytes = & $nullableLength `
            $refresh.Properties['final_bytes'] "$refreshPath.final_bytes"
        $finalSha = & $nullableSha `
            $refresh.Properties['final_sha256'] "$refreshPath.final_sha256"
        $logicalId = & $nullableIdentity `
            $refresh.Properties['logical_final_file_identity'] `
            "$refreshPath.logical_final_file_identity"
        $logicalBytes = & $nullableLength `
            $refresh.Properties['logical_final_bytes'] `
            "$refreshPath.logical_final_bytes"
        $logicalSha = & $nullableSha `
            $refresh.Properties['logical_final_sha256'] `
            "$refreshPath.logical_final_sha256"
        if (($oldPresent -and
                ($null -eq $oldId -or $null -eq $oldBytes -or
                 $null -eq $oldSha)) -or
            (-not $oldPresent -and
                ($null -ne $oldId -or $null -ne $oldBytes -or
                 $null -ne $oldSha)) -or
            ($finalPresent -and
                ($null -eq $finalId -or $null -eq $finalBytes -or
                 $null -eq $finalSha -or $finalBinding -cnotin @('old', 'new'))) -or
            (-not $finalPresent -and
                ($null -ne $finalId -or $null -ne $finalBytes -or
                 $null -ne $finalSha -or $finalBinding -cne 'absent')) -or
            $null -eq $logicalId -or $null -eq $logicalBytes -or
            $null -eq $logicalSha) {
            throw "$refreshPath presence/binding/nullability fields are inconsistent"
        }
        $expectedShape = switch ($state) {
            'prepared-envelope-old-final' {
                $phase -ceq 'prepared' -and -not $oldPresent -and
                $finalPresent -and $finalBinding -ceq 'old'
                break
            }
            'prepared-envelope-old-tombstone-no-final' {
                $phase -ceq 'prepared' -and $oldPresent -and
                -not $finalPresent -and $finalBinding -ceq 'absent'
                break
            }
            'prepared-envelope-old-tombstone-new-final' {
                $phase -ceq 'prepared' -and $oldPresent -and
                $finalPresent -and $finalBinding -ceq 'new'
                break
            }
            'proof-envelope-old-tombstone-new-final' {
                $phase -ceq 'old-disposition-set' -and $oldPresent -and
                $finalPresent -and $finalBinding -ceq 'new'
                break
            }
            'proof-envelope-new-final' {
                $phase -ceq 'old-disposition-set' -and -not $oldPresent -and
                $finalPresent -and $finalBinding -ceq 'new'
                break
            }
            default { $false }
        }
        if (-not $expectedShape) {
            throw "$refreshPath state/phase/artifact combination is unsupported"
        }
        $expectedLogicalId = if ($state -ceq
            'prepared-envelope-old-tombstone-no-final') { $oldId } else {
            $finalId
        }
        $expectedLogicalBytes = if ($state -ceq
            'prepared-envelope-old-tombstone-no-final') { $oldBytes } else {
            $finalBytes
        }
        $expectedLogicalSha = if ($state -ceq
            'prepared-envelope-old-tombstone-no-final') { $oldSha } else {
            $finalSha
        }
        if ($logicalId -cne $expectedLogicalId -or
            $logicalBytes -ne $expectedLogicalBytes -or
            $logicalSha -cne $expectedLogicalSha) {
            throw "$refreshPath logical final does not match the exact rollback/commit source"
        }
        $ownerBinding = Convert-AstroLinkedAttributionOwnerProbeNode `
            $refresh.Properties['owner_generation_probe'] `
            "$refreshPath.owner_generation_probe" `
            $refreshLauncherPid `
            $ticks
        $jobBinding = Convert-AstroLinkedAbsentJobProbeNode `
            $refresh.Properties['job_object_probe'] `
            "$refreshPath.job_object_probe" $jobName
        $refreshBindings.Add([pscustomobject]@{
            Key = $key
            State = $state
            Phase = $phase
            RenameSuffixQuarantine = $renameSuffixQuarantine
            Nonce = $nonce
            EnvelopePath = $envelopePath
            EnvelopeFileIdentity = $envelopeId
            EnvelopeBytes = $envelopeBytes
            EnvelopeSha256 = $envelopeSha
            OldTombstonePath = $oldPath
            OldTombstonePresent = $oldPresent
            OldFileIdentity = $oldId
            OldBytes = $oldBytes
            OldSha256 = $oldSha
            FinalPath = $finalPath
            FinalPresent = $finalPresent
            FinalBinding = $finalBinding
            FinalFileIdentity = $finalId
            FinalBytes = $finalBytes
            FinalSha256 = $finalSha
            LogicalFinalFileIdentity = $logicalId
            LogicalFinalBytes = $logicalBytes
            LogicalFinalSha256 = $logicalSha
            LauncherPid = $refreshLauncherPid
            LauncherProcessStartUtcTicks = $ticks
            LauncherLockSha256 = $lockSha
            LauncherLeaseStartUtcTicks = $leaseTicks
            SchemaVersion = $refreshSchemaVersion
            JobLimitFlags = $refreshJobLimitFlags
            JobObjectName = $jobName
            OwnerProbe = $ownerBinding
            JobObjectProbe = $jobBinding
        })
    }
    if ($refreshBindings.Count -gt 1) {
        throw "$JsonPath contains more than one refresh transaction for one exact launcher generation"
    }
    $tempsNode = $Node.Properties['temps']
    if ($tempsNode.Kind -cne 'array') {
        throw "$JsonPath.temps must be an array"
    }
    $tempBindings = [Collections.Generic.List[object]]::new()
    foreach ($temp in @($tempsNode.Items)) {
        Assert-AstroStrictObjectShape $temp @(
            'kind',
            'path',
            'expected_temp_path',
            'file_identity',
            'nonce',
            'launcher_pid',
            'launcher_process_start_utc_ticks',
            'launcher_lock_sha256',
            'exact_claim_identity',
            'state',
            'attributes',
            'error'
        ) "$JsonPath.temps[]"
        $tempKind = Get-AstroStrictStringValue `
            $temp.Properties['kind'] "$JsonPath.temps[].kind" -Nonblank
        if ($tempKind -cnotin @('temp', 'temp-cleanup-tombstone')) {
            throw "$JsonPath contains an unsupported TEMP record kind '$tempKind'"
        }
        $tempFileIdentity = Get-AstroStrictStringValue `
            $temp.Properties['file_identity'] `
            "$JsonPath.temps[].file_identity" -Nonblank
        if ($tempFileIdentity -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$') {
            throw "$JsonPath TEMP FILE_ID_INFO identity is invalid"
        }
        $tempNonce = if ($temp.Properties['nonce'].Kind -ceq 'null') {
            $null
        } else {
            Get-AstroStrictStringValue `
                $temp.Properties['nonce'] "$JsonPath.temps[].nonce" -Nonblank
        }
        if (($tempKind -ceq 'temp' -and $null -ne $tempNonce) -or
            ($tempKind -ceq 'temp-cleanup-tombstone' -and
                ($null -eq $tempNonce -or
                    $tempNonce -cnotmatch '^[0-9a-f]{32}$'))) {
            throw "$JsonPath TEMP kind/nonce fields are inconsistent"
        }
        $tempExact = Get-AstroStrictBooleanValue `
            $temp.Properties['exact_claim_identity'] `
            "$JsonPath.temps[].exact_claim_identity"
        $tempState = Get-AstroStrictStringValue `
            $temp.Properties['state'] "$JsonPath.temps[].state" -Nonblank
        if (-not $tempExact -or $tempState -cne 'present' -or
            $temp.Properties['error'].Kind -cne 'null') {
            throw "$JsonPath contains a non-exact or unevaluable TEMP record"
        }
        $tempBindings.Add([pscustomobject]@{
            Kind = $tempKind
            Path = [IO.Path]::GetFullPath((Get-AstroStrictStringValue `
                $temp.Properties['path'] "$JsonPath.temps[].path" -Nonblank))
            ExpectedTempPath = [IO.Path]::GetFullPath((Get-AstroStrictStringValue `
                $temp.Properties['expected_temp_path'] `
                "$JsonPath.temps[].expected_temp_path" -Nonblank))
            FileIdentity = $tempFileIdentity
            Nonce = $tempNonce
            LauncherPid = [int](ConvertFrom-AstroJsonUnsignedNode `
                $temp.Properties['launcher_pid'] "$JsonPath.temps[].launcher_pid" `
                ([uint64][int]::MaxValue) -Positive)
            LauncherProcessStartUtcTicks = [long](ConvertFrom-AstroJsonUnsignedNode `
                $temp.Properties['launcher_process_start_utc_ticks'] `
                "$JsonPath.temps[].launcher_process_start_utc_ticks" `
                ([uint64][DateTime]::MaxValue.Ticks) -Positive)
            LauncherLockSha256 = Get-AstroStrictStringValue `
                $temp.Properties['launcher_lock_sha256'] `
                "$JsonPath.temps[].launcher_lock_sha256" -Nonblank
        })
    }
    $unrelatedNode = $Node.Properties['unrelated_complete_pairs']
    if ($unrelatedNode.Kind -cne 'array') {
        throw "$JsonPath.unrelated_complete_pairs must be an array"
    }
    $unrelatedBindings = [Collections.Generic.List[object]]::new()
    $unrelatedKeys = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $previousUnrelatedKey = $null
    foreach ($pair in @($unrelatedNode.Items)) {
        $pairPath = "$JsonPath.unrelated_complete_pairs[]"
        Assert-AstroStrictObjectShape $pair @(
            'identity', 'manifest', 'temp', 'action'
        ) $pairPath
        $identity = Get-AstroStrictStringValue `
            $pair.Properties['identity'] "$pairPath.identity" -Nonblank
        $identityMatch = [Regex]::Match(
            $identity,
            '^(?<pid>[1-9][0-9]*)\|(?<ticks>[1-9][0-9]*)\|(?<sha>[0-9a-f]{64})$',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        $unrelatedPid = 0
        $unrelatedTicks = 0L
        if (-not $identityMatch.Success -or
            -not [int]::TryParse(
                $identityMatch.Groups['pid'].Value,
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$unrelatedPid
            ) -or $unrelatedPid -le 0 -or
            -not [long]::TryParse(
                $identityMatch.Groups['ticks'].Value,
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$unrelatedTicks
            ) -or $unrelatedTicks -le 0 -or
            $unrelatedTicks -gt [DateTime]::MaxValue.Ticks) {
            throw "$pairPath.identity is not a canonical launcher generation identity"
        }
        if (-not $unrelatedKeys.Add($identity)) {
            throw "$JsonPath repeats unrelated complete-pair identity '$identity'"
        }
        if ($null -ne $previousUnrelatedKey -and
            [string]::CompareOrdinal($previousUnrelatedKey, $identity) -ge 0) {
            throw "$JsonPath.unrelated_complete_pairs is not in canonical identity order"
        }
        $previousUnrelatedKey = $identity
        $unrelatedSha = $identityMatch.Groups['sha'].Value

        $manifest = $pair.Properties['manifest']
        Assert-AstroStrictObjectShape $manifest @(
            'path',
            'file_identity',
            'bytes',
            'sha256',
            'owner_state',
            'job_state'
        ) "$pairPath.manifest"
        $manifestPathText = Get-AstroStrictStringValue `
            $manifest.Properties['path'] "$pairPath.manifest.path" -Nonblank
        $manifestPath = [IO.Path]::GetFullPath($manifestPathText)
        $manifestName = ConvertFrom-AstroAttributionManifestName $manifestPath
        if ($manifestPathText -cne $manifestPath -or
            -not $manifestName.Valid -or
            $manifestName.SchemaVersion -ne 3 -or
            $manifestName.LauncherPid -ne $unrelatedPid -or
            $manifestName.LauncherProcessStartUtcTicks -ne $unrelatedTicks -or
            $manifestName.LauncherLockSha256 -cne $unrelatedSha) {
            throw "$pairPath.manifest.path does not bind the exact v3 generation identity"
        }
        $manifestFileIdentity = Get-AstroStrictStringValue `
            $manifest.Properties['file_identity'] `
            "$pairPath.manifest.file_identity" -Nonblank
        $manifestBytes = [uint64](ConvertFrom-AstroJsonUnsignedNode `
            $manifest.Properties['bytes'] "$pairPath.manifest.bytes" `
            ([uint64]$script:AstroLauncherProtocolSnapshotMaxBytes) -Positive)
        $manifestSha = Get-AstroStrictStringValue `
            $manifest.Properties['sha256'] "$pairPath.manifest.sha256" -Nonblank
        $ownerState = Get-AstroStrictStringValue `
            $manifest.Properties['owner_state'] `
            "$pairPath.manifest.owner_state" -Nonblank
        $jobState = Get-AstroStrictStringValue `
            $manifest.Properties['job_state'] `
            "$pairPath.manifest.job_state" -Nonblank
        if ($manifestFileIdentity -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$' -or
            $manifestSha -cnotmatch '^[0-9a-f]{64}$' -or
            $ownerState -cnotin @('absent', 'pid-reused') -or
            $jobState -cne 'absent') {
            throw "$pairPath.manifest does not prove an exact dead-owner/Job-absent file binding"
        }

        $temp = $pair.Properties['temp']
        Assert-AstroStrictObjectShape $temp @(
            'path', 'file_identity'
        ) "$pairPath.temp"
        $tempPathText = Get-AstroStrictStringValue `
            $temp.Properties['path'] "$pairPath.temp.path" -Nonblank
        $tempPath = [IO.Path]::GetFullPath($tempPathText)
        $tempName = ConvertFrom-AstroLauncherTempName $tempPath
        $tempFileIdentity = Get-AstroStrictStringValue `
            $temp.Properties['file_identity'] `
            "$pairPath.temp.file_identity" -Nonblank
        if ($tempPathText -cne $tempPath -or -not $tempName.Valid -or
            $tempName.LauncherPid -ne $unrelatedPid -or
            $tempName.LauncherProcessStartUtcTicks -ne $unrelatedTicks -or
            $tempName.LauncherLockSha256 -cne $unrelatedSha -or
            $tempFileIdentity -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$') {
            throw "$pairPath.temp does not bind the exact generation TEMP identity"
        }
        $action = Get-AstroStrictStringValue `
            $pair.Properties['action'] "$pairPath.action" -Nonblank
        if ($action -cne 'preserved') {
            throw "$pairPath.action must be exactly 'preserved'"
        }
        $unrelatedBindings.Add([pscustomobject]@{
            Identity = $identity
            LauncherPid = $unrelatedPid
            LauncherProcessStartUtcTicks = $unrelatedTicks
            LauncherLockSha256 = $unrelatedSha
            ManifestPath = $manifestPath
            ManifestFileIdentity = $manifestFileIdentity
            ManifestBytes = $manifestBytes
            ManifestSha256 = $manifestSha
            OwnerState = $ownerState
            JobState = $jobState
            TempPath = $tempPath
            TempFileIdentity = $tempFileIdentity
            Action = $action
        })
    }
    $finalCount = @($manifestBindings | Where-Object ExactExpectedLauncher).Count
    foreach ($refreshBinding in @($refreshBindings)) {
        $logicalMatches = @($manifestBindings | Where-Object {
                [string]::Equals(
                    $_.Path,
                    $refreshBinding.FinalPath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -and
                $_.FileIdentity -ceq
                    $refreshBinding.LogicalFinalFileIdentity -and
                $_.Bytes -eq $refreshBinding.LogicalFinalBytes -and
                $_.Sha256 -ceq $refreshBinding.LogicalFinalSha256 -and
                $_.ExactExpectedLauncher
            })
        if ($logicalMatches.Count -ne 1) {
            throw "$JsonPath refresh transaction does not normalize to exactly one bound logical final manifest"
        }
    }
    if (($subordinateState -ceq 'none' -and
            ($manifestBindings.Count -ne 0 -or $tempBindings.Count -ne 0 -or
             $refreshBindings.Count -ne 0)) -or
        ($subordinateState -ceq 'partial-evidence' -and
            ($manifestBindings.Count -eq 0 -or $tempBindings.Count -ne 0)) -or
        ($subordinateState -ceq 'complete-pair' -and
            ($tempBindings.Count -ne 1 -or $finalCount -ne 1)) -or
        $tempBindings.Count -gt 1 -or $finalCount -gt 1 -or
        $exact -ne ($finalCount -eq 1)) {
        throw "$JsonPath subordinate state/cardinality/final-manifest flags are inconsistent"
    }
    if ($subordinateState -ceq 'complete-pair') {
        $finalManifest = @(
            $manifestBindings | Where-Object ExactExpectedLauncher
        )[0]
        if (-not [string]::Equals(
                $finalManifest.ExpectedTempPath,
                $tempBindings[0].ExpectedTempPath,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            ($tempBindings[0].Kind -ceq 'temp' -and
                -not [string]::Equals(
                    $tempBindings[0].Path,
                    $tempBindings[0].ExpectedTempPath,
                    [StringComparison]::OrdinalIgnoreCase
                ))) {
            throw "$JsonPath complete pair does not bind one exact canonical TEMP identity"
        }
    }
    $stable = [ordered]@{}
    foreach ($field in @(
            'state',
            'policy',
            'subordinate_state',
            'exact_manifest_observed',
            'exact_manifest_lease_start_utc_ticks',
            'exact_launcher_lease_start_utc_ticks',
            'exact_job_object_name',
            'exact_job_object_probe',
            'manifests',
            'refresh_transactions',
            'temps',
            'unrelated_complete_pairs'
        )) {
        $stable[$field] = Convert-AstroStrictJsonNodeToCanonicalValue `
            $Node.Properties[$field] "$JsonPath.$field"
    }
    $computedFingerprint = Get-AstroByteSha256(
        [Text.UTF8Encoding]::new($false).GetBytes(
            ($stable | ConvertTo-Json -Depth 16 -Compress)
        )
    )
    if ($computedFingerprint -cne $fingerprint) {
        throw "$JsonPath.stable_fingerprint_sha256 does not bind the canonical durable attribution state"
    }
    return [pscustomobject]@{
        Policy = $policy
        SubordinateState = $subordinateState
        ExactManifestObserved = $exact
        ExactManifestLeaseStartUtcTicks = $exactLeaseTicks
        ExactLauncherLeaseStartUtcTicks = $exactLauncherLeaseTicks
        ExactJobObjectName = $exactJobObjectName
        ExactJobObjectProbe = $exactJobProbe
        FingerprintSha256 = $fingerprint
        ManifestCount = @($manifestsNode.Items).Count
        Manifests = [object[]]@($manifestBindings)
        RefreshTransactionCount = @($refreshNode.Items).Count
        RefreshTransactions = [object[]]@($refreshBindings)
        TempCount = @($tempsNode.Items).Count
        Temps = [object[]]@($tempBindings)
        UnrelatedCompletePairCount = @($unrelatedNode.Items).Count
        UnrelatedCompletePairs = [object[]]@($unrelatedBindings)
    }
}

function Convert-AstroLinkedOwnerProbeNode {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string]$JsonPath
    )

    Assert-AstroStrictObjectShape $Node @(
        'probe',
        'pid',
        'legacy_pid_only',
        'owner_process_start_utc_ticks',
        'owner_process_started_utc',
        'state',
        'numeric_pid_live',
        'owner_live',
        'pid_reused',
        'observed_process_start_utc_ticks',
        'observed_process_started_utc',
        'observed_at_utc'
    ) $JsonPath
    $parsedOwnerPid = ConvertFrom-AstroJsonUnsignedNode `
        $Node.Properties['pid'] "$JsonPath.pid" ([uint64][int]::MaxValue) -Positive
    $legacy = Get-AstroStrictBooleanValue `
        $Node.Properties['legacy_pid_only'] "$JsonPath.legacy_pid_only"
    $state = Get-AstroStrictStringValue `
        $Node.Properties['state'] "$JsonPath.state" -Nonblank
    $ownerLive = Get-AstroStrictBooleanValue `
        $Node.Properties['owner_live'] "$JsonPath.owner_live"
    $numericPidLive = Get-AstroStrictBooleanValue `
        $Node.Properties['numeric_pid_live'] "$JsonPath.numeric_pid_live"
    $pidReused = Get-AstroStrictBooleanValue `
        $Node.Properties['pid_reused'] "$JsonPath.pid_reused"
    if ($state -cnotin @('absent', 'pid-reused') -or $ownerLive) {
        throw "$JsonPath does not prove an absent exact owner"
    }
    $ticks = $null
    if ($legacy) {
        if ($Node.Properties['owner_process_start_utc_ticks'].Kind -cne 'null') {
            throw "$JsonPath legacy probe must have null owner ticks"
        }
    }
    else {
        $ticks = [long](ConvertFrom-AstroJsonUnsignedNode `
            $Node.Properties['owner_process_start_utc_ticks'] `
            "$JsonPath.owner_process_start_utc_ticks" `
            ([uint64][DateTime]::MaxValue.Ticks) `
            -Positive)
    }
    $observedTicks = $null
    if ($Node.Properties['observed_process_start_utc_ticks'].Kind -cne 'null') {
        $observedTicks = [long](ConvertFrom-AstroJsonUnsignedNode `
            $Node.Properties['observed_process_start_utc_ticks'] `
            "$JsonPath.observed_process_start_utc_ticks" `
            ([uint64][DateTime]::MaxValue.Ticks) `
            -Positive)
    }
    if (($state -ceq 'absent' -and
            ($numericPidLive -or $pidReused -or $null -ne $observedTicks)) -or
        ($state -ceq 'pid-reused' -and
            (-not $numericPidLive -or -not $pidReused -or
                $null -eq $observedTicks -or
                (-not $legacy -and $observedTicks -eq $ticks)))) {
        throw "$JsonPath PID occupancy/reuse/ticks fields are internally inconsistent"
    }
    if ($legacy -and $state -cne 'absent') {
        throw "$JsonPath legacy proof requires complete numeric PID absence"
    }
    return [pscustomobject]@{
        Pid = [int]$parsedOwnerPid
        LegacyPidOnly = $legacy
        OwnerProcessStartUtcTicks = $ticks
        State = $state
    }
}

function Convert-AstroLinkedAuthorizationBytesToBinding {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Path
    )

    $root = Read-AstroStrictJsonDocumentObject `
        $Bytes "linked authorization '$Path'"
    Assert-AstroStrictObjectShape $root @(
        'schema',
        'phase',
        'transaction_id',
        'recorded_at_utc',
        'mode',
        'tracker',
        'mutex',
        'reclaim_process',
        'root',
        'recovery_paths',
        'protocol_directory',
        'recovery_directory',
        'target',
        'pre_publication_pid_probe',
        'pre_publication_attribution_probe',
        'subordinate_cleanup_plan'
    ) '$'
    $schema = Get-AstroStrictStringValue $root.Properties['schema'] '$.schema'
    $phase = Get-AstroStrictStringValue $root.Properties['phase'] '$.phase'
    if ($schema -cne 'astrolabe.launcher-lock-recovery.authorization.v7' -or
        $phase -cne 'authorized-before-archive') {
        throw 'linked authorization schema/phase is unsupported'
    }
    $transactionId = Get-AstroStrictStringValue `
        $root.Properties['transaction_id'] '$.transaction_id'
    if ($transactionId -cnotmatch '^[0-9a-f]{32}$') {
        throw 'linked authorization transaction_id is invalid'
    }
    $mode = $root.Properties['mode']
    Assert-AstroStrictObjectShape $mode @(
        'recovery_branch',
        'legacy_pid_only',
        'quarantine_unreadable',
        'protocol_state',
        'transition_name_valid'
    ) '$.mode'
    $tracker = $root.Properties['tracker']
    Assert-AstroStrictObjectShape $tracker @(
        'url',
        'comment_id',
        'api_url',
        'created_at',
        'updated_at',
        'body_bytes',
        'body_sha256',
        'evidence'
    ) '$.tracker'
    $mutex = $root.Properties['mutex']
    Assert-AstroStrictObjectShape $mutex @(
        'name',
        'root_identity',
        'root_final_path',
        'recovered_abandoned_owner'
    ) '$.mutex'
    $target = $root.Properties['target']
    Assert-AstroStrictObjectShape $target @(
        'path',
        'bytes',
        'sha256',
        'retained_file_identity',
        'retained_final_path',
        'archive_path',
        'transition_name_intended_sha256',
        'recognized_marker',
        'owner'
    ) '$.target'
    $owner = $target.Properties['owner']
    Assert-AstroStrictObjectShape $owner @(
        'schema',
        'legacy_pid_only',
        'pid',
        'issue',
        'lease_start_utc_ticks',
        'started_utc',
        'owner_process_start_utc_ticks',
        'owner_process_started_utc',
        'command',
        'head_sha',
        'status_sha256',
        'diff_sha256'
    ) '$.target.owner'
    if ($target.Properties['recognized_marker'].Kind -cne 'null') {
        throw 'linked ordinary-source authorization must not itself recover a nested marker'
    }
    $targetPathValue = [IO.Path]::GetFullPath(
        (Get-AstroStrictStringValue `
            $target.Properties['path'] `
            '$.target.path' `
            -Nonblank)
    )
    $targetFinalPathValue = [IO.Path]::GetFullPath(
        (Get-AstroStrictStringValue `
            $target.Properties['retained_final_path'] `
            '$.target.retained_final_path' `
            -Nonblank)
    )
    if (-not [string]::Equals(
            $targetPathValue,
            $targetFinalPathValue,
            [StringComparison]::Ordinal
        )) {
        throw 'linked authorization target path and retained final path differ'
    }
    $recoveryDirectory = $root.Properties['recovery_directory']
    Assert-AstroStrictObjectShape $recoveryDirectory @(
        'path',
        'retained_final_path',
        'retained_file_identity'
    ) '$.recovery_directory'
    $protocolDirectory = $root.Properties['protocol_directory']
    Assert-AstroStrictObjectShape $protocolDirectory @(
        'path',
        'retained_final_path',
        'retained_file_identity'
    ) '$.protocol_directory'
    $ownerProbe = Convert-AstroLinkedOwnerProbeNode `
        $root.Properties['pre_publication_pid_probe'] `
        '$.pre_publication_pid_probe'
    $attributionProbe = Convert-AstroLinkedAttributionProbeNode `
        $root.Properties['pre_publication_attribution_probe'] `
        '$.pre_publication_attribution_probe'
    $cleanupPlanNode = $root.Properties['subordinate_cleanup_plan']
    Assert-AstroStrictObjectShape $cleanupPlanNode @(
        'schema', 'transaction_id', 'initial_state', 'sha256'
    ) '$.subordinate_cleanup_plan'
    $cleanupPlanSchema = Get-AstroStrictStringValue `
        $cleanupPlanNode.Properties['schema'] `
        '$.subordinate_cleanup_plan.schema'
    $cleanupPlanTransactionId = Get-AstroStrictStringValue `
        $cleanupPlanNode.Properties['transaction_id'] `
        '$.subordinate_cleanup_plan.transaction_id'
    $cleanupPlanInitialState = Get-AstroStrictStringValue `
        $cleanupPlanNode.Properties['initial_state'] `
        '$.subordinate_cleanup_plan.initial_state'
    $cleanupPlanSha = Get-AstroStrictStringValue `
        $cleanupPlanNode.Properties['sha256'] `
        '$.subordinate_cleanup_plan.sha256'
    $recoveryDirectoryPath = [IO.Path]::GetFullPath(
        (Get-AstroStrictStringValue `
            $recoveryDirectory.Properties['path'] `
            '$.recovery_directory.path' -Nonblank)
    )
    $computedCleanupPlan = ConvertTo-AstroSubordinateCleanupPlan `
        -Probe $attributionProbe `
        -RecoveryRoot $recoveryDirectoryPath `
        -TransactionId $transactionId
    if ($cleanupPlanSchema -cne
            'astrolabe.launcher-lock-subordinate-cleanup-plan.v1' -or
        $cleanupPlanTransactionId -cne $transactionId -or
        $cleanupPlanInitialState -cne $computedCleanupPlan.SubordinateState -or
        $cleanupPlanSha -cne $computedCleanupPlan.Sha256) {
        throw 'linked authorization subordinate cleanup plan does not match its exact attribution probe/transaction'
    }
    $trackerBodySha = Get-AstroStrictStringValue `
        $tracker.Properties['body_sha256'] '$.tracker.body_sha256' -Nonblank
    if ($trackerBodySha -cnotmatch '^[0-9a-f]{64}$') {
        throw 'linked authorization tracker body_sha256 is invalid'
    }
    return [pscustomobject]@{
        TransactionId = $transactionId
        Root = [IO.Path]::GetFullPath(
            (Get-AstroStrictStringValue $root.Properties['root'] '$.root' -Nonblank)
        )
        RootIdentity = Get-AstroStrictStringValue `
            $mutex.Properties['root_identity'] '$.mutex.root_identity' -Nonblank
        RecoveryBranch = Get-AstroStrictStringValue `
            $mode.Properties['recovery_branch'] '$.mode.recovery_branch'
        ProtocolState = Get-AstroStrictStringValue `
            $mode.Properties['protocol_state'] '$.mode.protocol_state'
        LegacyPidOnly = Get-AstroStrictBooleanValue `
            $mode.Properties['legacy_pid_only'] '$.mode.legacy_pid_only'
        QuarantineUnreadable = Get-AstroStrictBooleanValue `
            $mode.Properties['quarantine_unreadable'] `
            '$.mode.quarantine_unreadable'
        TrackerUrl = Get-AstroStrictStringValue `
            $tracker.Properties['url'] '$.tracker.url' -Nonblank
        TrackerCommentId = [long](ConvertFrom-AstroJsonUnsignedNode `
            $tracker.Properties['comment_id'] '$.tracker.comment_id' `
            ([uint64][long]::MaxValue) -Positive)
        TrackerUpdatedAt = Get-AstroStrictStringValue `
            $tracker.Properties['updated_at'] '$.tracker.updated_at' -Nonblank
        TrackerBodySha256 = $trackerBodySha
        TargetPath = $targetPathValue
        TargetBytes = [uint64](ConvertFrom-AstroJsonUnsignedNode `
            $target.Properties['bytes'] '$.target.bytes' ([uint64]::MaxValue))
        TargetSha256 = Get-AstroStrictStringValue `
            $target.Properties['sha256'] '$.target.sha256' -Nonblank
        TargetFileIdentity = Get-AstroStrictStringValue `
            $target.Properties['retained_file_identity'] `
            '$.target.retained_file_identity' -Nonblank
        ArchivePath = [IO.Path]::GetFullPath(
            (Get-AstroStrictStringValue `
                $target.Properties['archive_path'] '$.target.archive_path' -Nonblank)
        )
        OwnerPid = [int](ConvertFrom-AstroJsonUnsignedNode `
            $owner.Properties['pid'] '$.target.owner.pid' `
            ([uint64][int]::MaxValue) -Positive)
        OwnerIssue = [int](ConvertFrom-AstroJsonUnsignedNode `
            $owner.Properties['issue'] '$.target.owner.issue' `
            ([uint64][int]::MaxValue) -Positive)
        OwnerProcessStartUtcTicks = if (
            $owner.Properties['owner_process_start_utc_ticks'].Kind -ceq 'null'
        ) { $null } else {
            [long](ConvertFrom-AstroJsonUnsignedNode `
                $owner.Properties['owner_process_start_utc_ticks'] `
                '$.target.owner.owner_process_start_utc_ticks' `
                ([uint64][DateTime]::MaxValue.Ticks) -Positive)
        }
        OwnerLeaseStartUtcTicks = if (
            $owner.Properties['lease_start_utc_ticks'].Kind -ceq 'null'
        ) { $null } else {
            [long](ConvertFrom-AstroJsonUnsignedNode `
                $owner.Properties['lease_start_utc_ticks'] `
                '$.target.owner.lease_start_utc_ticks' `
                ([uint64][DateTime]::MaxValue.Ticks) -Positive)
        }
        RecoveryDirectoryPath = $recoveryDirectoryPath
        RecoveryDirectoryFinalPath = [IO.Path]::GetFullPath(
            (Get-AstroStrictStringValue `
                $recoveryDirectory.Properties['retained_final_path'] `
                '$.recovery_directory.retained_final_path' -Nonblank)
        )
        RecoveryDirectoryFileIdentity = Get-AstroStrictStringValue `
            $recoveryDirectory.Properties['retained_file_identity'] `
            '$.recovery_directory.retained_file_identity' -Nonblank
        ProtocolDirectoryPath = [IO.Path]::GetFullPath(
            (Get-AstroStrictStringValue `
                $protocolDirectory.Properties['path'] `
                '$.protocol_directory.path' -Nonblank)
        )
        ProtocolDirectoryFinalPath = [IO.Path]::GetFullPath(
            (Get-AstroStrictStringValue `
                $protocolDirectory.Properties['retained_final_path'] `
                '$.protocol_directory.retained_final_path' -Nonblank)
        )
        ProtocolDirectoryFileIdentity = Get-AstroStrictStringValue `
            $protocolDirectory.Properties['retained_file_identity'] `
            '$.protocol_directory.retained_file_identity' -Nonblank
        OwnerProbe = $ownerProbe
        AttributionProbe = $attributionProbe
        SubordinateCleanupPlan = $computedCleanupPlan
    }
}

function Convert-AstroLinkedFinalizationBytesToBinding {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Path
    )

    $root = Read-AstroStrictJsonDocumentObject `
        $Bytes "linked finalization '$Path'"
    Assert-AstroStrictObjectShape $root @(
        'schema',
        'phase',
        'transaction_id',
        'recovery_branch',
        'recorded_at_utc',
        'authorization',
        'tracker',
        'second_owner_probe',
        'second_attribution_probe',
        'subordinate_cleanup_plan',
        'source',
        'archive_path',
        'recovery_directory',
        'protected_interrupted_transaction',
        'preserved_other_transition_paths'
    ) '$'
    if ((Get-AstroStrictStringValue $root.Properties['schema'] '$.schema') -cne
            'astrolabe.launcher-lock-recovery.finalization.v3' -or
        (Get-AstroStrictStringValue $root.Properties['phase'] '$.phase') -cne
            'verified-ready-to-archive') {
        throw 'linked finalization schema/phase is unsupported'
    }
    $authorization = $root.Properties['authorization']
    Assert-AstroStrictObjectShape $authorization @(
        'path', 'bytes', 'sha256'
    ) '$.authorization'
    $tracker = $root.Properties['tracker']
    Assert-AstroStrictObjectShape $tracker @(
        'url', 'comment_id', 'updated_at', 'body_sha256'
    ) '$.tracker'
    $source = $root.Properties['source']
    Assert-AstroStrictObjectShape $source @(
        'path',
        'bytes',
        'sha256',
        'retained_file_identity',
        'retained_final_path'
    ) '$.source'
    $sourcePathValue = [IO.Path]::GetFullPath(
        (Get-AstroStrictStringValue `
            $source.Properties['path'] `
            '$.source.path' `
            -Nonblank)
    )
    $sourceFinalPathValue = [IO.Path]::GetFullPath(
        (Get-AstroStrictStringValue `
            $source.Properties['retained_final_path'] `
            '$.source.retained_final_path' `
            -Nonblank)
    )
    if (-not [string]::Equals(
            $sourcePathValue,
            $sourceFinalPathValue,
            [StringComparison]::Ordinal
        )) {
        throw 'linked finalization source path and retained final path differ'
    }
    $recoveryDirectory = $root.Properties['recovery_directory']
    Assert-AstroStrictObjectShape $recoveryDirectory @(
        'path',
        'retained_final_path',
        'retained_file_identity'
    ) '$.recovery_directory'
    if ($root.Properties['protected_interrupted_transaction'].Kind -cne 'null') {
        throw 'linked ordinary-source finalization must not contain nested interrupted state'
    }
    if ($root.Properties['preserved_other_transition_paths'].Kind -cne 'array' -or
        @($root.Properties['preserved_other_transition_paths'].Items).Count -ne 0) {
        throw 'linked ordinary-source finalization must preserve no other transitions'
    }
    $trackerBodySha = Get-AstroStrictStringValue `
        $tracker.Properties['body_sha256'] '$.tracker.body_sha256' -Nonblank
    if ($trackerBodySha -cnotmatch '^[0-9a-f]{64}$') {
        throw 'linked finalization tracker body_sha256 is invalid'
    }
    $transactionId = Get-AstroStrictStringValue `
        $root.Properties['transaction_id'] '$.transaction_id'
    $attributionProbe = Convert-AstroLinkedAttributionProbeNode `
        $root.Properties['second_attribution_probe'] `
        '$.second_attribution_probe'
    $cleanupPlanNode = $root.Properties['subordinate_cleanup_plan']
    Assert-AstroStrictObjectShape $cleanupPlanNode @(
        'schema', 'transaction_id', 'initial_state', 'sha256'
    ) '$.subordinate_cleanup_plan'
    $recoveryDirectoryPath = [IO.Path]::GetFullPath(
        (Get-AstroStrictStringValue `
            $recoveryDirectory.Properties['path'] `
            '$.recovery_directory.path' -Nonblank)
    )
    $computedCleanupPlan = ConvertTo-AstroSubordinateCleanupPlan `
        -Probe $attributionProbe `
        -RecoveryRoot $recoveryDirectoryPath `
        -TransactionId $transactionId
    $cleanupPlanSha = Get-AstroStrictStringValue `
        $cleanupPlanNode.Properties['sha256'] `
        '$.subordinate_cleanup_plan.sha256'
    if ((Get-AstroStrictStringValue `
            $cleanupPlanNode.Properties['schema'] `
            '$.subordinate_cleanup_plan.schema') -cne
            'astrolabe.launcher-lock-subordinate-cleanup-plan.v1' -or
        (Get-AstroStrictStringValue `
            $cleanupPlanNode.Properties['transaction_id'] `
            '$.subordinate_cleanup_plan.transaction_id') -cne $transactionId -or
        (Get-AstroStrictStringValue `
            $cleanupPlanNode.Properties['initial_state'] `
            '$.subordinate_cleanup_plan.initial_state') -cne
            $computedCleanupPlan.SubordinateState -or
        $cleanupPlanSha -cne $computedCleanupPlan.Sha256) {
        throw 'linked finalization subordinate cleanup plan does not match its exact attribution probe/transaction'
    }
    return [pscustomobject]@{
        TransactionId = $transactionId
        RecoveryBranch = Get-AstroStrictStringValue `
            $root.Properties['recovery_branch'] '$.recovery_branch'
        AuthorizationPath = [IO.Path]::GetFullPath(
            (Get-AstroStrictStringValue `
                $authorization.Properties['path'] '$.authorization.path' -Nonblank)
        )
        AuthorizationBytes = [uint64](ConvertFrom-AstroJsonUnsignedNode `
            $authorization.Properties['bytes'] '$.authorization.bytes' `
            ([uint64]::MaxValue) -Positive)
        AuthorizationSha256 = Get-AstroStrictStringValue `
            $authorization.Properties['sha256'] '$.authorization.sha256' -Nonblank
        TrackerUrl = Get-AstroStrictStringValue `
            $tracker.Properties['url'] '$.tracker.url' -Nonblank
        TrackerCommentId = [long](ConvertFrom-AstroJsonUnsignedNode `
            $tracker.Properties['comment_id'] '$.tracker.comment_id' `
            ([uint64][long]::MaxValue) -Positive)
        TrackerUpdatedAt = Get-AstroStrictStringValue `
            $tracker.Properties['updated_at'] '$.tracker.updated_at' -Nonblank
        TrackerBodySha256 = $trackerBodySha
        OwnerProbe = Convert-AstroLinkedOwnerProbeNode `
            $root.Properties['second_owner_probe'] '$.second_owner_probe'
        AttributionProbe = $attributionProbe
        SubordinateCleanupPlan = $computedCleanupPlan
        SourcePath = $sourcePathValue
        SourceBytes = [uint64](ConvertFrom-AstroJsonUnsignedNode `
            $source.Properties['bytes'] '$.source.bytes' ([uint64]::MaxValue))
        SourceSha256 = Get-AstroStrictStringValue `
            $source.Properties['sha256'] '$.source.sha256' -Nonblank
        SourceFileIdentity = Get-AstroStrictStringValue `
            $source.Properties['retained_file_identity'] `
            '$.source.retained_file_identity' -Nonblank
        ArchivePath = [IO.Path]::GetFullPath(
            (Get-AstroStrictStringValue `
                $root.Properties['archive_path'] '$.archive_path' -Nonblank)
        )
        RecoveryDirectoryPath = $recoveryDirectoryPath
        RecoveryDirectoryFinalPath = [IO.Path]::GetFullPath(
            (Get-AstroStrictStringValue `
                $recoveryDirectory.Properties['retained_final_path'] `
                '$.recovery_directory.retained_final_path' -Nonblank)
        )
        RecoveryDirectoryFileIdentity = Get-AstroStrictStringValue `
            $recoveryDirectory.Properties['retained_file_identity'] `
            '$.recovery_directory.retained_file_identity' -Nonblank
    }
}

function Assert-AstroLinkedAttributionOwnerBinding {
    param(
        [Parameter(Mandatory)]$Probe,
        [Parameter(Mandatory)][string]$RootIdentity,
        [Parameter(Mandatory)][int]$OwnerPid,
        [AllowNull()][Nullable[long]]$OwnerProcessStartUtcTicks,
        [AllowNull()][Nullable[long]]$LauncherLeaseStartUtcTicks,
        [Parameter(Mandatory)][string]$LauncherLockSha256,
        [Parameter(Mandatory)][string]$JsonPath
    )

    if ($null -eq $OwnerProcessStartUtcTicks -or
        $null -eq $LauncherLeaseStartUtcTicks) {
        throw "$JsonPath cannot bind v2 subordinate state without exact process and lease ticks"
    }
    $derivedExactJobName = Get-AstroLauncherTreeJobObjectName `
        -RootIdentity $RootIdentity `
        -LauncherPid $OwnerPid `
        -LauncherProcessStartUtcTicks ([long]$OwnerProcessStartUtcTicks) `
        -LauncherLeaseStartUtcTicks ([long]$LauncherLeaseStartUtcTicks) `
        -LauncherLockSha256 $LauncherLockSha256
    if ($Probe.ExactLauncherLeaseStartUtcTicks -ne
            [long]$LauncherLeaseStartUtcTicks -or
        $Probe.ExactJobObjectName -cne $derivedExactJobName -or
        $Probe.ExactJobObjectProbe.State -cne 'absent') {
        throw "$JsonPath does not bind the independently derived exact absent Job Object"
    }
    $exactCount = 0
    foreach ($manifest in [object[]]@($Probe.Manifests)) {
        $derivedJobName = Get-AstroLauncherTreeJobObjectName `
            -RootIdentity $RootIdentity `
            -LauncherPid $manifest.LauncherPid `
            -LauncherProcessStartUtcTicks `
                $manifest.LauncherProcessStartUtcTicks `
            -LauncherLeaseStartUtcTicks `
                $manifest.LauncherLeaseStartUtcTicks `
            -LauncherLockSha256 $manifest.LauncherLockSha256
        if ([string]$manifest.JobObjectName -cne
            [string]$derivedJobName) {
            throw "$JsonPath contains a Job Object name not derived from its exact root/PID/ticks/lease/hash"
        }
        if (-not $manifest.ExactClaimIdentity -or
            $manifest.LauncherPid -ne $OwnerPid -or
            $manifest.LauncherProcessStartUtcTicks -ne
                [long]$OwnerProcessStartUtcTicks -or
            $manifest.LauncherLeaseStartUtcTicks -ne
                [long]$LauncherLeaseStartUtcTicks -or
            $manifest.LauncherLockSha256 -cne $LauncherLockSha256 -or
            $manifest.JobObjectName -cne $derivedExactJobName -or
            $manifest.OwnerProbe.State -cnotin @('absent', 'pid-reused') -or
            $manifest.JobObjectProbe.State -cne 'absent') {
            throw "$JsonPath contains attribution evidence outside the exact dead owner/absent Job generation"
        }
        if ($manifest.ExactExpectedLauncher) {
            $exactCount++
        }
    }
    foreach ($temp in [object[]]@($Probe.Temps)) {
        if ($temp.LauncherPid -ne $OwnerPid -or
            $temp.LauncherProcessStartUtcTicks -ne
                [long]$OwnerProcessStartUtcTicks -or
            $temp.LauncherLockSha256 -cne $LauncherLockSha256) {
            throw "$JsonPath contains a TEMP outside the exact source generation"
        }
    }
    if ($exactCount -gt 1 -or
        [bool]$Probe.ExactManifestObserved -ne ($exactCount -eq 1) -or
        (($exactCount -eq 0) -and
            $null -ne $Probe.ExactManifestLeaseStartUtcTicks)) {
        throw "$JsonPath exact manifest cardinality/flag/policy is inconsistent"
    }
    if ($exactCount -eq 1) {
        $exactManifest = @(
            $Probe.Manifests | Where-Object ExactExpectedLauncher
        )[0]
        if ($null -eq $Probe.ExactManifestLeaseStartUtcTicks -or
            $Probe.ExactManifestLeaseStartUtcTicks -ne
                $exactManifest.LauncherLeaseStartUtcTicks) {
            throw "$JsonPath exact manifest lease binding is inconsistent"
        }
    }
}

function Invoke-GhCommentRead {
    param(
        [Parameter(Mandatory)][long]$CommentId,
        [Parameter(Mandatory)][int]$ExpectedIssue
    )

    $gh = Get-Command gh -CommandType Application -ErrorAction Stop
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = [Diagnostics.ProcessStartInfo]::new()
    $process.StartInfo.FileName = $gh.Source
    $process.StartInfo.Arguments =
        "api --hostname github.com repos/ChrisRoyse/Astrolabe/issues/comments/$CommentId"
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $stdoutTask = $null
    $stderrTask = $null
    $stdout = ''
    $stderr = ''
    $exitCode = $null
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(
                $script:AstroLauncherGhReadTimeoutMilliseconds
            )) {
            $identity = Get-AstroProcessIdentityProbe $process.Id
            try {
                $process.Kill()
                $process.WaitForExit()
            }
            catch {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_READ_TIMEOUT_KILL_FAILED' `
                    "gh tracker read exceeded $script:AstroLauncherGhReadTimeoutMilliseconds ms and its retained process could not be terminated (pid=$($process.Id), start_utc_ticks=$($identity.ProcessStartUtcTicks)): $($_.Exception.Message)" `
                    'preserve all state; inspect the exact retained gh process and authenticated network path before retrying'
            }
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_READ_TIMEOUT' `
                "gh tracker read exceeded the $script:AstroLauncherGhReadTimeoutMilliseconds-ms protocol bound (pid=$($process.Id), start_utc_ticks=$($identity.ProcessStartUtcTicks))" `
                'preserve all state; repair authenticated github.com access before retrying with a fresh recovery basename'
        }
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
    }
    catch {
        if ($_.Exception.Data.Contains('AstroCode')) {
            throw
        }
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_READ_FAILED' `
            "gh could not read tracker comment $CommentId`: $($_.Exception.Message)" `
            'repair authenticated gh access; recovery never trusts an unverified URL'
    }
    finally {
        $process.Dispose()
    }
    if ($exitCode -ne 0) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_READ_FAILED' `
            "gh api failed for tracker comment $CommentId (exit=$exitCode): $($stderr.Trim())" `
            'repair authenticated gh access and verify that the exact comment still exists'
    }
    try {
        $comment = ConvertFrom-Json -InputObject $stdout -ErrorAction Stop
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_READ_INVALID' `
            "gh returned invalid comment JSON: $($_.Exception.Message)" `
            'preserve the lock and inspect authenticated gh output'
    }
    $expectedIssueApi =
        "https://api.github.com/repos/ChrisRoyse/Astrolabe/issues/$ExpectedIssue"
    if ($comment.id -isnot [long] -and $comment.id -isnot [int]) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_READ_INVALID' `
            'tracker comment id is not an integral JSON number' `
            'preserve the lock and inspect the GitHub API response'
    }
    if ([long]$comment.id -ne $CommentId -or
        $comment.issue_url -isnot [string] -or
        [string]$comment.issue_url -cne $expectedIssueApi -or
        $comment.user.login -isnot [string] -or
        [string]$comment.user.login -cne 'ChrisRoyse' -or
        $comment.author_association -isnot [string] -or
        [string]$comment.author_association -cne 'OWNER' -or
        $comment.body -isnot [string]) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_READ_INVALID' `
            'tracker comment response does not bind the exact issue and repository owner' `
            'post the recovery evidence from the repository owner account and pass its exact URL'
    }
    $bodyBytes = [Text.UTF8Encoding]::new($false).GetBytes([string]$comment.body)
    return [pscustomobject]@{
        Comment = $comment
        BodySha256 = Get-AstroByteSha256 $bodyBytes
        BodyBytes = $bodyBytes
    }
}

function Read-TrackerEvidence {
    param(
        [Parameter(Mandatory)][string]$CommentUrl,
        [Parameter(Mandatory)][int]$Issue,
        [Parameter(Mandatory)][string]$Lock,
        [Parameter(Mandatory)][string]$LockSha256,
        [Parameter(Mandatory)][int]$OwnerPid,
        [AllowNull()][Nullable[long]]$OwnerTicks,
        [Parameter(Mandatory)][bool]$Legacy,
        [Parameter(Mandatory)][bool]$Unreadable,
        [Parameter(Mandatory)]$OwnerProbe
    )

    $urlPattern = '^https://github\.com/ChrisRoyse/Astrolabe/issues/' +
        [Regex]::Escape([string]$Issue) +
        '#issuecomment-(?<id>[0-9]+)$'
    $urlMatch = [Regex]::Match($CommentUrl, $urlPattern)
    if (-not $urlMatch.Success) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_EVIDENCE_INVALID' `
            "tracker URL is not an exact comment on owning issue #$Issue`: $CommentUrl" `
            'post the exact machine-readable evidence with gh and pass its returned comment URL'
    }
    $commentId = [long]::Parse(
        $urlMatch.Groups['id'].Value,
        [Globalization.CultureInfo]::InvariantCulture
    )
    $read = Invoke-GhCommentRead $commentId $Issue
    if ([string]$read.Comment.html_url -cne $CommentUrl) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_EVIDENCE_INVALID' `
            "GitHub comment canonical URL differs from supplied URL: $($read.Comment.html_url)" `
            'pass the exact html_url returned by gh api'
    }
    $prefix = 'ASTRO_LAUNCHER_LOCK_RECLAIM_EVIDENCE '
    $candidates = @(
        ([string]$read.Comment.body -split "\r?\n") |
            Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) }
    )
    if ($candidates.Count -ne 1) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_EVIDENCE_INVALID' `
            "tracker comment contains $($candidates.Count) evidence-prefixed lines; required exactly one" `
            "post exactly one line beginning '$prefix' with the exact path/hash/owner/probe values"
    }
    try {
        $trackerEvidenceBytes = [Text.UTF8Encoding]::new(
            $false,
            $true
        ).GetBytes($candidates[0].Substring($prefix.Length))
        $document = Read-AstroStrictJsonDocumentObject `
            $trackerEvidenceBytes `
            'tracker reclaim evidence'
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_EVIDENCE_INVALID' `
            "tracker evidence is not one structurally strict flat JSON object: $($_.Exception.Message)" `
            'post a fresh exact evidence line with no duplicate, nested, or extra properties'
    }
    $required = @(
        'schema',
        'issue',
        'lock_path',
        'lock_sha256',
        'expected_pid',
        'expected_owner_process_start_utc_ticks',
        'legacy_pid_only',
        'quarantine_unreadable',
        'owner_probe_state',
        'observed_process_start_utc_ticks'
    )
    if (@($document.Names).Count -ne $required.Count) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_EVIDENCE_INVALID' `
            'tracker evidence must contain exactly the required property set' `
            'remove extra fields and include every documented evidence field exactly once'
    }
    foreach ($name in $required) {
        if (-not $document.Properties.ContainsKey($name)) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_EVIDENCE_INVALID' `
                "tracker evidence is missing exact property '$name'" `
                'post a fresh complete evidence object'
        }
    }
    $properties = $document.Properties
    $issueValue = 0L
    $pidValue = 0L
    $ownerTicksValue = 0L
    $observedTicksValue = 0L
    $ownerTicksValid = $properties['expected_owner_process_start_utc_ticks'].Kind -eq
        'integer' -and [long]::TryParse(
            [string]$properties['expected_owner_process_start_utc_ticks'].Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$ownerTicksValue
        )
    $observedTicksValid = $properties['observed_process_start_utc_ticks'].Kind -eq
        'integer' -and [long]::TryParse(
            [string]$properties['observed_process_start_utc_ticks'].Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$observedTicksValue
        )
    try {
        $evidencePath = if ($properties['lock_path'].Kind -eq 'string') {
            [IO.Path]::GetFullPath([string]$properties['lock_path'].Value)
        } else {
            ''
        }
    }
    catch {
        $evidencePath = ''
    }
    $baseValid =
        $properties['schema'].Kind -eq 'string' -and
        [string]$properties['schema'].Value -ceq
            'astrolabe.launcher-lock-reclaim-evidence.v1' -and
        $properties['issue'].Kind -eq 'integer' -and
        [long]::TryParse(
            [string]$properties['issue'].Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$issueValue
        ) -and $issueValue -eq $Issue -and
        [string]::Equals($evidencePath, $Lock, [StringComparison]::Ordinal) -and
        $properties['lock_sha256'].Kind -eq 'string' -and
        [string]$properties['lock_sha256'].Value -ceq $LockSha256 -and
        $properties['expected_pid'].Kind -eq 'integer' -and
        [long]::TryParse(
            [string]$properties['expected_pid'].Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$pidValue
        ) -and $pidValue -eq $OwnerPid -and
        $properties['legacy_pid_only'].Kind -eq 'boolean' -and
        [bool]$properties['legacy_pid_only'].Value -eq $Legacy -and
        $properties['quarantine_unreadable'].Kind -eq 'boolean' -and
        [bool]$properties['quarantine_unreadable'].Value -eq $Unreadable -and
        $properties['owner_probe_state'].Kind -eq 'string' -and
        [string]$properties['owner_probe_state'].Value -ceq
            [string]$OwnerProbe.state
    $ownerTicksMatch = if ($Legacy) {
        $properties['expected_owner_process_start_utc_ticks'].Kind -eq 'null'
    } else {
        $ownerTicksValid -and $ownerTicksValue -eq [long]$OwnerTicks
    }
    $observedTicksMatch = if (
        $null -eq $OwnerProbe.observed_process_start_utc_ticks
    ) {
        $properties['observed_process_start_utc_ticks'].Kind -eq 'null'
    } else {
        $observedTicksValid -and $observedTicksValue -eq
            [long]$OwnerProbe.observed_process_start_utc_ticks
    }
    if (-not $baseValid -or -not $ownerTicksMatch -or
        -not $observedTicksMatch) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_EVIDENCE_INVALID' `
            'tracker evidence does not exactly match the current path/hash/owner/mode/probe state' `
            'post a fresh evidence line from an independent read of the unchanged target and process identity'
    }
    $evidence = [ordered]@{
        schema = [string]$properties['schema'].Value
        issue = [int]$issueValue
        lock_path = $evidencePath
        lock_sha256 = [string]$properties['lock_sha256'].Value
        expected_pid = [int]$pidValue
        expected_owner_process_start_utc_ticks = if ($Legacy) {
            $null
        } else { [long]$ownerTicksValue }
        legacy_pid_only = [bool]$properties['legacy_pid_only'].Value
        quarantine_unreadable = [bool]$properties['quarantine_unreadable'].Value
        owner_probe_state = [string]$properties['owner_probe_state'].Value
        observed_process_start_utc_ticks = if (
            $properties['observed_process_start_utc_ticks'].Kind -eq 'null'
        ) { $null } else { [long]$observedTicksValue }
    }
    return [pscustomobject]@{
        Url = $CommentUrl
        Id = $commentId
        ApiUrl = [string]$read.Comment.url
        CreatedAt = [string]$read.Comment.created_at
        UpdatedAt = [string]$read.Comment.updated_at
        BodyBytes = [uint64]$read.BodyBytes.Length
        BodySha256 = $read.BodySha256
        Evidence = $evidence
    }
}

$failure = $null
$result = $null
$mutexLease = $null
$sourceRenameLease = $null
$archiveDirectoryHandle = $null
$protocolDirectoryHandle = $null
$markerRenameLease = $null
$markerPublicationResult = $null
$terminalFileHandles = @()
$linkedMarkerLeases = @()
$markerProtectedLease = $null
$subordinateCleanupPlan = $null
$subordinateCleanupResult = $null
$subordinateArchiveLeases = @()
$recoveryDirectoryIdentity = $null
$recoveryDirectoryFinalPath = $null
$reclaimPhase = 'argument-validation'
try {
    . (Join-Path $PSScriptRoot 'launcher-lock.ps1')
    . (Join-Path $PSScriptRoot 'attribution-manifest.ps1')
    . (Join-Path $PSScriptRoot 'launcher-temp-guard.ps1')
    $null = Initialize-AstroReclaimPublicationNative

    foreach ($requiredValue in @(
            @('Root', $Root),
            @('LockPath', $LockPath),
            @('RecoveryRecordPath', $RecoveryRecordPath),
            @('TrackerCommentUrl', $TrackerCommentUrl)
        )) {
        if ([string]::IsNullOrWhiteSpace([string]$requiredValue[1])) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_EXPECTATION_INVALID' `
                "$($requiredValue[0]) is required and nonblank" `
                'pass every exact path/value after posting tracker evidence'
        }
    }
    $expectedPidValue = Parse-PositiveIntArgument $ExpectedPid 'ExpectedPid'
    $expectedIssueValue = Parse-PositiveIntArgument $ExpectedIssue 'ExpectedIssue'
    $expectedTicksValue = if ($LegacyPidOnly) {
        if (-not [string]::IsNullOrWhiteSpace($ExpectedOwnerProcessStartUtcTicks)) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_EXPECTATION_INVALID' `
                'LegacyPidOnly requires ExpectedOwnerProcessStartUtcTicks omitted' `
                'never infer process creation identity for a pre-v2 lock'
        }
        $null
    }
    else {
        Parse-PositiveTicksArgument `
            $ExpectedOwnerProcessStartUtcTicks `
            'ExpectedOwnerProcessStartUtcTicks'
    }
    if ($ExpectedLockSha256 -cnotmatch '^[0-9a-fA-F]{64}$') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_EXPECTATION_INVALID' `
            'ExpectedLockSha256 must be exactly 64 hexadecimal characters' `
            'pass the independently read SHA-256 of the unchanged target bytes'
    }
    $expectedHash = $ExpectedLockSha256.ToLowerInvariant()

    $workspace = [IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..')
    ).TrimEnd('\', '/')
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $workspacePrefix = $workspace + [IO.Path]::DirectorySeparatorChar
    if (-not [string]::Equals(
            $rootFull,
            $workspace,
            [StringComparison]::OrdinalIgnoreCase
        ) -and
        -not $rootFull.StartsWith(
            $workspacePrefix,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ROOT_ESCAPE' `
            "root '$rootFull' is outside canonical workspace '$workspace'" `
            'use the canonical checkout, registered worktree, or isolated fixture below it'
    }
    $rootState = Get-AstroPathEntryState $rootFull
    if ($rootState.State -ne 'present' -or
        ($rootState.Attributes -band [IO.FileAttributes]::Directory) -eq 0) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ROOT_MISSING' `
            "root is not an evaluable directory: $rootFull ($($rootState.Error))" `
            'pass the exact existing non-reparse root'
    }
    Assert-NoReparseAncestors $rootFull $workspace 'reclaim root'

    $tmpRoot = [IO.Path]::GetFullPath((Join-Path $rootFull '.tmp'))
    $activeLock = [IO.Path]::GetFullPath(
        (Join-Path $tmpRoot 'astrolabe-launcher.lock')
    )
    $lockFull = [IO.Path]::GetFullPath($LockPath)
    $transitionState = ConvertTo-AstroLauncherTransitionState $lockFull
    # Protocol leaf spelling is authority, not a cosmetic Windows-path detail.
    # A caller-supplied lowercase alias must never make a case-drifted on-disk
    # active/transition entry mutation-authorizing.
    $isActive = [string]::Equals(
        $lockFull,
        $activeLock,
        [StringComparison]::Ordinal
    )
    $isTransition = $transitionState.Candidate -and
        [string]::Equals(
            [IO.Path]::GetDirectoryName($lockFull),
            $tmpRoot,
            [StringComparison]::Ordinal
        )
    if (-not ($isActive -or $isTransition)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PATH_MISMATCH' `
            "path is neither the exact active lock nor a recognized transition for root '$rootFull': $lockFull" `
            'pass the exact .tmp launcher-lock active/claim/cleanup path'
    }
    if ($isTransition -and -not $transitionState.Valid -and
        -not $QuarantineUnreadable) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRANSITION_SCHEMA_UNREADABLE' `
            "legacy/unknown transition name requires -QuarantineUnreadable: $lockFull ($($transitionState.ValidationError))" `
            'bind its exact raw bytes and externally known owner in tracker evidence; never infer fields from an unknown name'
    }
    if ($isTransition -and $transitionState.LegacyMarker) {
        if (-not $QuarantineUnreadable -or -not $LegacyPidOnly) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_LEGACY_MARKER_MODE_REQUIRED' `
                'a recognized legacy reclaim marker requires both -QuarantineUnreadable and -LegacyPidOnly' `
                'use the marker filename PID/issue and exact current byte hash; legacy markers never infer process-start ticks'
        }
        if ($transitionState.Pid -ne $expectedPidValue -or
            $transitionState.Issue -ne $expectedIssueValue) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_MISMATCH' `
                'legacy reclaim-marker filename owner differs from independently expected PID/issue' `
                'bind quarantine to the exact PID/issue encoded in the unchanged marker name'
        }
    }
    elseif ($isTransition -and $transitionState.Valid) {
        if ($transitionState.Pid -ne $expectedPidValue -or
            $transitionState.Issue -ne $expectedIssueValue -or
            $transitionState.OwnerProcessStartUtcTicks -ne
                [long]$expectedTicksValue) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_MISMATCH' `
                'transition filename owner identity differs from independently expected values' `
                'use the exact PID/issue/ticks encoded in the unchanged transition name'
        }
        if ($LegacyPidOnly) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_LEGACY_SCHEMA_REFUSED' `
                'modern v2 transition names cannot be reclaimed with LegacyPidOnly' `
            'use exact v2 process-start ticks from the transition filename'
        }
    }
    Assert-NoReparseAncestors $lockFull $workspace 'launcher protocol state'

    $recoveryRoot = [IO.Path]::GetFullPath(
        (Join-Path $tmpRoot 'lock-recovery')
    )
    $recordFull = [IO.Path]::GetFullPath($RecoveryRecordPath)
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($recordFull),
            $recoveryRoot,
            [StringComparison]::Ordinal
        )) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_ESCAPE' `
            "recovery record must live directly below '$recoveryRoot': $recordFull" `
            'use one fresh .tmp\lock-recovery\<unique>.json basename'
    }
    Assert-AstroRecoveryRecordLeaf $recordFull
    $completionFull = "$recordFull.completed.json"
    $finalizationFull = "$recordFull.finalizing.json"
    $archiveFull = "$recordFull.lock.bin"
    $markerArchiveFull = "$recordFull.marker.bin"
    foreach ($candidate in @(
            $recordFull,
            $finalizationFull,
            $completionFull,
            $archiveFull,
            $markerArchiveFull
        )) {
        Assert-AstroRecoveryArtifactLeaf $candidate
        $state = Get-AstroPathEntryState $candidate
        if ($state.State -eq 'present') {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_REUSE_REFUSED' `
                "append-only recovery path exists: $candidate" `
                'use a fresh recovery basename'
        }
        if ($state.State -eq 'unevaluable') {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_PATH_UNEVALUABLE' `
                "recovery path is unevaluable: $candidate ($($state.Error))" `
                'preserve all state and repair path access'
        }
    }
    Assert-NoReparseAncestors $recordFull $workspace 'recovery record'

    $reclaimPhase = 'mutex-acquisition'
    try {
        $mutexLease = Enter-AstroLauncherLockMutex $activeLock
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MUTEX_FAILED' `
            "could not enter machine-wide launcher-lock mutex: $($_.Exception.Message)" `
            'preserve all state and repair cross-session synchronization'
    }
    if (-not $mutexLease.Acquired) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_BUSY' `
            "another process owns machine-wide launcher-lock mutex '$($mutexLease.Name)'" `
            'wait for the bounded claim/cleanup/reclaim transition; never race it'
    }
    try {
        $protocolDirectoryHandle =
            [AstroLauncherLockNative]::OpenExactRenameDirectory($tmpRoot)
        $protocolDirectoryFinalPath = ConvertTo-AstroComparableFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath(
                $protocolDirectoryHandle
            )
        )
        $protocolDirectoryIdentity =
            [AstroLauncherLockNative]::GetFileIdentity(
                $protocolDirectoryHandle
            )
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_ROOT_INVALID' `
            "could not retain exact launcher protocol directory '$tmpRoot': $($_.Exception.Message)" `
            'preserve all protocol state and repair the exact non-reparse .tmp directory'
    }
    if (-not [string]::Equals(
            $protocolDirectoryFinalPath,
            $tmpRoot,
            [StringComparison]::Ordinal
        )) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_ROOT_ALIAS' `
            "protocol directory '$tmpRoot' resolves to retained-handle path '$protocolDirectoryFinalPath'" `
            'preserve all state and use the exact canonical non-alias protocol directory'
    }
    $protocolDirectoryLeaf = [IO.Path]::GetFileName(
        $protocolDirectoryFinalPath.TrimEnd('\', '/')
    )
    if ($protocolDirectoryLeaf -cne '.tmp') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_ROOT_NONCANONICAL' `
            "retained launcher protocol directory has noncanonical leaf '$protocolDirectoryLeaf': $protocolDirectoryFinalPath" `
            "preserve all protocol state; the retained directory leaf must be exact lowercase '.tmp'"
    }

    $reclaimPhase = 'protocol-inventory'
    $transitions = Get-AstroLauncherLockTransitions $activeLock
    if ($transitions.State -eq 'unevaluable') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_UNEVALUABLE' `
            $transitions.Error `
            'preserve all protocol state and repair directory access'
    }
    if ($transitions.State -cnotin @('clear', 'present')) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_NONCANONICAL' `
            "launcher protocol inventory is not one canonical clear/present state (state=$($transitions.State), active_paths=$(@($transitions.ActivePaths) -join '; '), transition_paths=$(@($transitions.Paths) -join '; '), error=$($transitions.Error))" `
            'preserve every entry; case-drifted, colliding, or otherwise invalid protocol names never authorize recovery'
    }
    [string[]]$inventoriedActivePaths = @($transitions.ActivePaths)
    foreach ($inventoriedActivePath in $inventoriedActivePaths) {
        if ([IO.Path]::GetFileName($inventoriedActivePath) -cne
                'astrolabe-launcher.lock' -or
            -not [string]::Equals(
                [IO.Path]::GetFullPath($inventoriedActivePath),
                $activeLock,
                [StringComparison]::Ordinal
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_NONCANONICAL' `
                "launcher protocol inventory contains a noncanonical active-lock spelling: $inventoriedActivePath" `
                "preserve every entry; the sole active basename must be exact lowercase 'astrolabe-launcher.lock' below exact '.tmp'"
        }
    }
    foreach ($inventoriedTransition in @($transitions.Items)) {
        $allowedLegacyTarget = $isTransition -and
            [string]::Equals(
                [IO.Path]::GetFullPath($inventoriedTransition.Path),
                $lockFull,
                [StringComparison]::Ordinal
            ) -and
            [bool]$inventoriedTransition.LegacyMarker -and
            [bool]$LegacyPidOnly -and
            [bool]$QuarantineUnreadable
        if (-not $inventoriedTransition.Valid -and -not $allowedLegacyTarget) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_NONCANONICAL' `
                "launcher protocol inventory contains a malformed or case-drifted transition: $($inventoriedTransition.Path) ($($inventoriedTransition.ValidationError))" `
                'preserve every entry; only the exact explicitly selected legacy reclaim marker may use legacy resume authority'
        }
    }
    $activeInventoryState = Get-AstroPathEntryState $activeLock
    if ($activeInventoryState.State -eq 'unevaluable' -or
        ($activeInventoryState.State -eq 'present' -and
            (($activeInventoryState.Attributes -band
                    [IO.FileAttributes]::Directory) -ne 0 -or
                ($activeInventoryState.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0))) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_UNEVALUABLE' `
            "active launcher path is not an evaluable ordinary-file/absence state (state=$($activeInventoryState.State), attributes=$($activeInventoryState.Attributes), error=$($activeInventoryState.Error)): $activeLock" `
            'preserve all protocol state and repair the active path before recovery'
    }
    $inventoriedSourcePath = $null
    $otherTransitions = @()
    if ($isActive) {
        if ($transitions.State -cne 'clear' -or
            @($transitions.Paths).Count -ne 0 -or
            $inventoriedActivePaths.Count -ne 1 -or
            -not [string]::Equals(
                [IO.Path]::GetFullPath($inventoriedActivePaths[0]),
                $lockFull,
                [StringComparison]::Ordinal
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_CONFLICT' `
                "active recovery requires the exact canonical active path as the sole protocol entry (state=$($transitions.State), active_paths=$($inventoriedActivePaths -join '; '), transitions=$(@($transitions.Paths) -join '; '))" `
                'recover the sole exact transition first or preserve noncanonical/colliding state for investigation'
        }
        $inventoriedSourcePath = [IO.Path]::GetFullPath(
            $inventoriedActivePaths[0]
        )
    }
    elseif ($isTransition) {
        if ($transitions.State -cne 'present') {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_CONFLICT' `
                "transition recovery requires an exact present transition inventory; observed '$($transitions.State)'" `
                'preserve every entry and re-read the complete protocol directory'
        }
        $otherTransitions = @(
            $transitions.Paths |
                Where-Object {
                    -not [string]::Equals(
                        $_,
                        $lockFull,
                        [StringComparison]::Ordinal
                    )
                }
        )
        $targetInventoryItems = @(
            $transitions.Items | Where-Object {
                [string]::Equals(
                    [IO.Path]::GetFullPath($_.Path),
                    $lockFull,
                    [StringComparison]::Ordinal
                )
            }
        )
        if ($targetInventoryItems.Count -ne 1) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_CONFLICT' `
                "transition inventory does not contain the exact ordinal target exactly once: $(@($transitions.Paths) -join '; ')" `
                'preserve all state and re-read the complete active/transition inventory'
        }
        $inventoriedTarget = $targetInventoryItems[0]
        $targetShapeMatches =
            [bool]$inventoriedTarget.Valid -eq [bool]$transitionState.Valid -and
            [bool]$inventoriedTarget.LegacyMarker -eq
                [bool]$transitionState.LegacyMarker -and
            [string]$inventoriedTarget.Format -ceq
                [string]$transitionState.Format -and
            [string]$inventoriedTarget.Phase -ceq
                [string]$transitionState.Phase -and
            $inventoriedTarget.Pid -eq $transitionState.Pid -and
            $inventoriedTarget.Issue -eq $transitionState.Issue -and
            $inventoriedTarget.OwnerProcessStartUtcTicks -eq
                $transitionState.OwnerProcessStartUtcTicks -and
            [string]$inventoriedTarget.Sha256 -ceq
                [string]$transitionState.Sha256 -and
            [string]$inventoriedTarget.Nonce -ceq
                [string]$transitionState.Nonce
        if (-not $targetShapeMatches -or
            (-not $inventoriedTarget.Valid -and
                -not ($inventoriedTarget.LegacyMarker -and
                    $LegacyPidOnly -and $QuarantineUnreadable))) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_NONCANONICAL' `
                "enumerated transition target does not exactly match the caller-bound canonical/legacy identity: $($inventoriedTarget.Path)" `
                'preserve the transition; recovery authority must bind the exact enumerated basename and parsed fields'
        }
        $inventoriedSourcePath = [IO.Path]::GetFullPath(
            $inventoriedTarget.Path
        )
    }

    $presence = Get-AstroPathEntryState $lockFull
    if ($presence.State -ne 'present' -or
        ($presence.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or
        ($presence.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_LOCK_MISSING' `
            "target is not an evaluable ordinary file: $lockFull ($($presence.Error))" `
            're-read protocol state; never manufacture missing ownership evidence'
    }
    $reclaimPhase = 'exact-source-lease'
    $sourceRenameLease = Open-AstroExactRenameLease `
        $lockFull `
        'launcher protocol source'
    $initial = $sourceRenameLease.InitialSnapshot
    $retainedSourceLeaf = [IO.Path]::GetFileName($initial.Path)
    $retainedSourceParent = [IO.Path]::GetDirectoryName($initial.Path)
    $retainedSourceParentLeaf = [IO.Path]::GetFileName(
        $retainedSourceParent.TrimEnd('\', '/')
    )
    $expectedSourceLeaf = [IO.Path]::GetFileName($inventoriedSourcePath)
    if ($retainedSourceLeaf -cne $expectedSourceLeaf -or
        $retainedSourceParentLeaf -cne '.tmp' -or
        -not [string]::Equals(
            $retainedSourceParent,
            $protocolDirectoryFinalPath,
            [StringComparison]::Ordinal
        )) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SOURCE_ALIAS_REFUSED' `
            "retained source spelling/parent is noncanonical (expected_leaf=$expectedSourceLeaf, retained_leaf=$retainedSourceLeaf, retained_parent_leaf=$retainedSourceParentLeaf, retained_parent=$retainedSourceParent, protocol_parent=$protocolDirectoryFinalPath)" `
            "preserve the source; recovery requires the exact enumerated basename below retained lowercase '.tmp'"
    }
    if ($initial.Sha256 -cne $expectedHash) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_HASH_MISMATCH' `
            "target SHA-256 '$($initial.Sha256)' differs from expected '$expectedHash'" `
            'post and pass the current exact bytes; never recover changed state'
    }
    $recognizedReclaimMarker = $false
    $reclaimMarkerEnvelope = $null
    $markerProtectedSourceSnapshot = $null
    $markerProtectedArchiveSnapshot = $null
    if ($isTransition -and $transitionState.Phase -ceq 'reclaim' -and
        $QuarantineUnreadable -and
        $transitionState.Sha256 -ceq $initial.Sha256) {
        $candidateEnvelope = Convert-AstroReclaimMarkerBytesToState `
            $initial.Bytes `
            $lockFull
        if ($candidateEnvelope.Valid) {
            $modeMatches =
                [bool]$candidateEnvelope.LegacyPidOnly -eq
                    [bool]$LegacyPidOnly -and
                $candidateEnvelope.OwnerPid -eq $expectedPidValue -and
                $candidateEnvelope.OwnerIssue -eq $expectedIssueValue -and
                (($LegacyPidOnly -and
                        $null -eq
                            $candidateEnvelope.OwnerProcessStartUtcTicks) -or
                    (-not $LegacyPidOnly -and
                        $candidateEnvelope.OwnerProcessStartUtcTicks -eq
                            $expectedTicksValue))
            $filenameMatches = if ($transitionState.LegacyMarker) {
                $LegacyPidOnly -and
                    $transitionState.Pid -eq $candidateEnvelope.OwnerPid -and
                    $transitionState.Issue -eq $candidateEnvelope.OwnerIssue -and
                    $transitionState.Nonce -ceq $candidateEnvelope.TransactionId
            }
            else {
                $transitionState.Valid -and -not $LegacyPidOnly -and
                    $transitionState.Pid -eq $candidateEnvelope.OwnerPid -and
                    $transitionState.Issue -eq $candidateEnvelope.OwnerIssue -and
                    $transitionState.OwnerProcessStartUtcTicks -eq
                        $candidateEnvelope.OwnerProcessStartUtcTicks -and
                    $transitionState.Nonce -ceq $candidateEnvelope.TransactionId
            }
            if (-not $modeMatches -or -not $filenameMatches) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_MISMATCH' `
                    'reclaim-marker envelope, filename, and requested owner/mode do not bind the same identity' `
                    'preserve the marker and use its exact filename/envelope PID, issue, and process-start mode'
            }
            if ($candidateEnvelope.PreservedProtocolKind -cne 'none') {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_SCHEMA_INVALID' `
                    'reclaim-marker v2 unexpectedly names a preserved nested protocol entry' `
                    'preserve the marker; v2 marker recovery never creates nested markers'
            }
            $linkedMarkerRecords = @(
                [pscustomobject]@{
                    Path = $candidateEnvelope.AuthorizationPath
                    Bytes = $candidateEnvelope.AuthorizationBytes
                    Sha256 = $candidateEnvelope.AuthorizationSha256
                    FileIdentity = $candidateEnvelope.AuthorizationFileIdentity
                    Description = 'authorization'
                },
                [pscustomobject]@{
                    Path = $candidateEnvelope.FinalizationPath
                    Bytes = $candidateEnvelope.FinalizationBytes
                    Sha256 = $candidateEnvelope.FinalizationSha256
                    FileIdentity = $candidateEnvelope.FinalizationFileIdentity
                    Description = 'finalization'
                }
            )
            foreach ($linked in $linkedMarkerRecords) {
                if (-not [string]::Equals(
                        [IO.Path]::GetDirectoryName([string]$linked.Path),
                        $recoveryRoot,
                        [StringComparison]::Ordinal
                    )) {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_RECORD_ESCAPE' `
                        "reclaim marker $($linked.Description) path escapes '$recoveryRoot': $($linked.Path)" `
                        'preserve the marker; linked recovery records must stay directly below its root recovery directory'
                }
                Assert-AstroRecoveryRecordLeaf `
                    ([string]$linked.Path) `
                    -MaxLength 128
                Assert-AstroRecoveryArtifactLeaf `
                    ([string]$linked.Path) `
                    -MaxLength 128
                Assert-NoReparseAncestors `
                    ([string]$linked.Path) `
                    $workspace `
                    "reclaim marker $($linked.Description) record"
                $linkedLease = Open-AstroExactEvidenceLease `
                    ([string]$linked.Path) `
                    "linked reclaim-marker $($linked.Description)"
                $linkedMarkerLeases += $linkedLease
                $terminalFileHandles += $linkedLease.Handle
                $linkedSnapshot = $linkedLease.InitialSnapshot
                if ($linkedSnapshot.Length -ne [uint64]$linked.Bytes -or
                    $linkedSnapshot.Sha256 -cne [string]$linked.Sha256 -or
                    $linkedSnapshot.FileIdentity -cne
                        [string]$linked.FileIdentity) {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_RECORD_MISMATCH' `
                        "reclaim marker $($linked.Description) record no longer matches its length/hash/FILE_ID binding: $($linked.Path)" `
                        'preserve all state and investigate recovery-record drift'
                }
            }
            try {
                $linkedAuthorizationBinding =
                    Convert-AstroLinkedAuthorizationBytesToBinding `
                        $linkedMarkerLeases[0].InitialSnapshot.Bytes `
                        $candidateEnvelope.AuthorizationPath
                $linkedFinalizationBinding =
                    Convert-AstroLinkedFinalizationBytesToBinding `
                        $linkedMarkerLeases[1].InitialSnapshot.Bytes `
                        $candidateEnvelope.FinalizationPath
            }
            catch {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_RECORD_SCHEMA_INVALID' `
                    "reclaim marker linked authorization/finalization bytes are not strict recovery records: $($_.Exception.Message)" `
                    'preserve every entry; interrupted recovery requires semantically bound strict records, not hashes alone'
            }
            $expectedPriorAttributionPolicy = switch (
                $linkedAuthorizationBinding.ProtocolState
            ) {
                'active' {
                    $linkedAuthorizationBinding.AttributionProbe.Policy
                    break
                }
                'cleanup' {
                    $linkedAuthorizationBinding.AttributionProbe.Policy
                    break
                }
                'claim' {
                    $linkedAuthorizationBinding.AttributionProbe.Policy
                    break
                }
                default {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_RECORD_MISMATCH' `
                        "linked authorization has unsupported protocol state '$($linkedAuthorizationBinding.ProtocolState)'" `
                        'preserve the marker; interrupted recovery must originate from active, valid cleanup, or valid claim state'
                }
            }
            $ownerTicksMatch = if ($candidateEnvelope.LegacyPidOnly) {
                $null -eq $linkedAuthorizationBinding.OwnerProcessStartUtcTicks -and
                    $null -eq $linkedFinalizationBinding.OwnerProbe.OwnerProcessStartUtcTicks
            }
            else {
                $linkedAuthorizationBinding.OwnerProcessStartUtcTicks -eq
                    $candidateEnvelope.OwnerProcessStartUtcTicks -and
                $linkedFinalizationBinding.OwnerProbe.OwnerProcessStartUtcTicks -eq
                    $candidateEnvelope.OwnerProcessStartUtcTicks
            }
            try {
                Assert-AstroLinkedAttributionOwnerBinding `
                    -Probe $linkedAuthorizationBinding.AttributionProbe `
                    -RootIdentity $linkedAuthorizationBinding.RootIdentity `
                    -OwnerPid $linkedAuthorizationBinding.OwnerPid `
                    -OwnerProcessStartUtcTicks `
                        $linkedAuthorizationBinding.OwnerProcessStartUtcTicks `
                    -LauncherLeaseStartUtcTicks `
                        $linkedAuthorizationBinding.OwnerLeaseStartUtcTicks `
                    -LauncherLockSha256 `
                        $linkedAuthorizationBinding.TargetSha256 `
                    -JsonPath '$.pre_publication_attribution_probe'
                Assert-AstroLinkedAttributionOwnerBinding `
                    -Probe $linkedFinalizationBinding.AttributionProbe `
                    -RootIdentity $linkedAuthorizationBinding.RootIdentity `
                    -OwnerPid $linkedAuthorizationBinding.OwnerPid `
                    -OwnerProcessStartUtcTicks `
                        $linkedAuthorizationBinding.OwnerProcessStartUtcTicks `
                    -LauncherLeaseStartUtcTicks `
                        $linkedAuthorizationBinding.OwnerLeaseStartUtcTicks `
                    -LauncherLockSha256 `
                        $linkedAuthorizationBinding.TargetSha256 `
                    -JsonPath '$.second_attribution_probe'
            }
            catch {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_RECORD_MISMATCH' `
                    "linked attribution/Job Object proof does not bind its exact authorization: $($_.Exception.Message)" `
                    'preserve every entry and repair the prior exact attribution evidence before interrupted recovery'
            }
            $markerSemanticMismatches =
                [Collections.Generic.List[string]]::new()
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.transaction_id' `
                $linkedAuthorizationBinding.TransactionId `
                $candidateEnvelope.TransactionId ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.transaction_id' `
                $linkedFinalizationBinding.TransactionId `
                $candidateEnvelope.TransactionId ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.recovery_branch' `
                $linkedAuthorizationBinding.RecoveryBranch `
                'ordinary-source' ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.recovery_branch' `
                $linkedFinalizationBinding.RecoveryBranch `
                'ordinary-source' ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.root' $linkedAuthorizationBinding.Root `
                $rootFull ordinal-ignore-case
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.root_identity' `
                $linkedAuthorizationBinding.RootIdentity `
                $mutexLease.RootIdentity ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.protocol_directory.path' `
                $linkedAuthorizationBinding.ProtocolDirectoryPath `
                $tmpRoot ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.protocol_directory.final_path' `
                $linkedAuthorizationBinding.ProtocolDirectoryFinalPath `
                $protocolDirectoryFinalPath ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.protocol_directory.file_identity' `
                $linkedAuthorizationBinding.ProtocolDirectoryFileIdentity `
                $protocolDirectoryIdentity ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.target.path' `
                $linkedAuthorizationBinding.TargetPath `
                $candidateEnvelope.SourcePath ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.target.bytes' `
                $linkedAuthorizationBinding.TargetBytes `
                $candidateEnvelope.SourceBytes
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.target.sha256' `
                $linkedAuthorizationBinding.TargetSha256 `
                $candidateEnvelope.SourceSha256 ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.target.file_identity' `
                $linkedAuthorizationBinding.TargetFileIdentity `
                $candidateEnvelope.SourceFileIdentity ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.target.archive_path' `
                $linkedAuthorizationBinding.ArchivePath `
                $candidateEnvelope.SourceArchivePath ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.owner.pid' `
                $linkedAuthorizationBinding.OwnerPid `
                $candidateEnvelope.OwnerPid
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.owner.issue' `
                $linkedAuthorizationBinding.OwnerIssue `
                $candidateEnvelope.OwnerIssue
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.mode.legacy_pid_only' `
                $linkedAuthorizationBinding.LegacyPidOnly `
                $candidateEnvelope.LegacyPidOnly
            # The prior authorization's quarantine flag describes how the
            # original source was classified. The current switch authorizes
            # mutation of this already-published marker. They are distinct
            # phases and deliberately need not have the same value.
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.owner.lease_present' `
                ($candidateEnvelope.LegacyPidOnly -or
                    $null -ne $linkedAuthorizationBinding.OwnerLeaseStartUtcTicks) `
                $true
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.owner.generation_ticks' $ownerTicksMatch $true
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.owner_probe.pid' `
                $linkedAuthorizationBinding.OwnerProbe.Pid `
                $candidateEnvelope.OwnerPid
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.owner_probe.pid' `
                $linkedFinalizationBinding.OwnerProbe.Pid `
                $candidateEnvelope.OwnerPid
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.owner_probe.legacy_pid_only' `
                $linkedAuthorizationBinding.OwnerProbe.LegacyPidOnly `
                $candidateEnvelope.LegacyPidOnly
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.owner_probe.legacy_pid_only' `
                $linkedFinalizationBinding.OwnerProbe.LegacyPidOnly `
                $candidateEnvelope.LegacyPidOnly
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.owner_probe.generation_ticks' `
                ($candidateEnvelope.LegacyPidOnly -or
                    $linkedAuthorizationBinding.OwnerProbe.OwnerProcessStartUtcTicks -eq
                        $candidateEnvelope.OwnerProcessStartUtcTicks) $true
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.recovery_directory.path' `
                $linkedAuthorizationBinding.RecoveryDirectoryPath `
                $candidateEnvelope.RecoveryDirectoryPath ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.recovery_directory.final_path' `
                $linkedAuthorizationBinding.RecoveryDirectoryFinalPath `
                $candidateEnvelope.RecoveryDirectoryFinalPath ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.recovery_directory.file_identity' `
                $linkedAuthorizationBinding.RecoveryDirectoryFileIdentity `
                $candidateEnvelope.RecoveryDirectoryFileIdentity ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.authorization.path' `
                $linkedFinalizationBinding.AuthorizationPath `
                $candidateEnvelope.AuthorizationPath ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.authorization.bytes' `
                $linkedFinalizationBinding.AuthorizationBytes `
                $candidateEnvelope.AuthorizationBytes
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.authorization.sha256' `
                $linkedFinalizationBinding.AuthorizationSha256 `
                $candidateEnvelope.AuthorizationSha256 ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.source.path' `
                $linkedFinalizationBinding.SourcePath `
                $candidateEnvelope.SourcePath ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.source.bytes' `
                $linkedFinalizationBinding.SourceBytes `
                $candidateEnvelope.SourceBytes
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.source.sha256' `
                $linkedFinalizationBinding.SourceSha256 `
                $candidateEnvelope.SourceSha256 ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.source.file_identity' `
                $linkedFinalizationBinding.SourceFileIdentity `
                $candidateEnvelope.SourceFileIdentity ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.source.archive_path' `
                $linkedFinalizationBinding.ArchivePath `
                $candidateEnvelope.SourceArchivePath ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.recovery_directory.path' `
                $linkedFinalizationBinding.RecoveryDirectoryPath `
                $candidateEnvelope.RecoveryDirectoryPath ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.recovery_directory.final_path' `
                $linkedFinalizationBinding.RecoveryDirectoryFinalPath `
                $candidateEnvelope.RecoveryDirectoryFinalPath ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.recovery_directory.file_identity' `
                $linkedFinalizationBinding.RecoveryDirectoryFileIdentity `
                $candidateEnvelope.RecoveryDirectoryFileIdentity ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'tracker.url' $linkedAuthorizationBinding.TrackerUrl `
                $linkedFinalizationBinding.TrackerUrl ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'tracker.comment_id' `
                $linkedAuthorizationBinding.TrackerCommentId `
                $linkedFinalizationBinding.TrackerCommentId
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'tracker.updated_at' `
                $linkedAuthorizationBinding.TrackerUpdatedAt `
                $linkedFinalizationBinding.TrackerUpdatedAt ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'tracker.body_sha256' `
                $linkedAuthorizationBinding.TrackerBodySha256 `
                $linkedFinalizationBinding.TrackerBodySha256 ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'authorization.attribution.policy' `
                $linkedAuthorizationBinding.AttributionProbe.Policy `
                $expectedPriorAttributionPolicy ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'finalization.attribution.policy' `
                $linkedFinalizationBinding.AttributionProbe.Policy `
                $expectedPriorAttributionPolicy ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'attribution.fingerprint_sha256' `
                $linkedAuthorizationBinding.AttributionProbe.FingerprintSha256 `
                $linkedFinalizationBinding.AttributionProbe.FingerprintSha256 `
                ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'subordinate_cleanup_plan.sha256' `
                $linkedAuthorizationBinding.SubordinateCleanupPlan.Sha256 `
                $linkedFinalizationBinding.SubordinateCleanupPlan.Sha256 ordinal
            Add-AstroReclaimSemanticMismatch $markerSemanticMismatches `
                'owner_probe.state' $linkedAuthorizationBinding.OwnerProbe.State `
                $linkedFinalizationBinding.OwnerProbe.State ordinal
            if ($markerSemanticMismatches.Count -ne 0) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_RECORD_MISMATCH' `
                    "linked authorization/finalization semantics do not cross-bind the marker transaction, owner, root, source, archive, tracker, and two attribution/Job Object probes: $($markerSemanticMismatches -join '; ')" `
                    'preserve every entry and investigate the exact semantic drift; hash-linked but unrelated records never authorize recovery'
            }
            if (-not [string]::Equals(
                    $candidateEnvelope.RecoveryDirectoryPath,
                    $recoveryRoot,
                    [StringComparison]::Ordinal
                )) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_RECORD_ESCAPE' `
                    "reclaim marker recovery directory differs from '$recoveryRoot': $($candidateEnvelope.RecoveryDirectoryPath)" `
                    'preserve the marker; it must bind the exact workspace-local recovery directory'
            }
            try {
                $archiveDirectoryHandle =
                    [AstroLauncherLockNative]::OpenExactRenameDirectory(
                        $recoveryRoot
                    )
                $recoveryDirectoryIdentity =
                    [AstroLauncherLockNative]::GetFileIdentity(
                        $archiveDirectoryHandle
                    )
                $recoveryDirectoryFinalPath = ConvertTo-AstroComparableFinalPath (
                    [AstroLauncherLockNative]::GetFileFinalPath(
                        $archiveDirectoryHandle
                    )
                )
            }
            catch {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_ROOT_INVALID' `
                    "could not retain the marker-bound recovery directory '$recoveryRoot': $($_.Exception.Message)" `
                    'preserve all state and repair the exact non-reparse recovery directory'
            }
            if ($recoveryDirectoryIdentity -cne
                    $candidateEnvelope.RecoveryDirectoryFileIdentity -or
                -not [string]::Equals(
                    $recoveryDirectoryFinalPath,
                    $candidateEnvelope.RecoveryDirectoryFinalPath,
                    [StringComparison]::Ordinal
                )) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_DIRECTORY_MISMATCH' `
                    'reclaim marker recovery-directory FILE_ID/final-path binding no longer matches reality' `
                    'preserve every entry; never recover through a replaced or aliased directory'
            }
            if (-not [string]::Equals(
                    [IO.Path]::GetDirectoryName(
                        $candidateEnvelope.SourceArchivePath
                    ),
                    $recoveryRoot,
                    [StringComparison]::Ordinal
                )) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_RECORD_ESCAPE' `
                    "reclaim marker source archive escapes '$recoveryRoot': $($candidateEnvelope.SourceArchivePath)" `
                    'preserve the marker; its source archive must stay directly below the same recovery directory'
            }
            Assert-NoReparseAncestors `
                $candidateEnvelope.SourceArchivePath `
                $workspace `
                'reclaim marker source archive'
            Assert-AstroRecoveryArtifactLeaf `
                $candidateEnvelope.SourceArchivePath `
                -MaxLength 128
            $sourceIsActive = [string]::Equals(
                $candidateEnvelope.SourcePath,
                $activeLock,
                [StringComparison]::Ordinal
            )
            $sourceTransition = ConvertTo-AstroLauncherTransitionState `
                $candidateEnvelope.SourcePath
            $sourceIsTransition = $sourceTransition.Candidate -and
                [string]::Equals(
                    [IO.Path]::GetDirectoryName(
                        $candidateEnvelope.SourcePath
                    ),
                    $tmpRoot,
                    [StringComparison]::Ordinal
                )
            $sourceTransitionBindingMatches = if ($sourceIsActive) {
                $linkedAuthorizationBinding.ProtocolState -ceq 'active'
            }
            else {
                $sourceTransition.Valid -and
                    $sourceTransition.Phase -ceq
                        $linkedAuthorizationBinding.ProtocolState -and
                    $sourceTransition.Pid -eq $candidateEnvelope.OwnerPid -and
                    $sourceTransition.Issue -eq $candidateEnvelope.OwnerIssue -and
                    $sourceTransition.OwnerProcessStartUtcTicks -eq
                        $candidateEnvelope.OwnerProcessStartUtcTicks -and
                    $sourceTransition.Sha256 -ceq
                        $candidateEnvelope.SourceSha256
            }
            if (-not ($sourceIsActive -or $sourceIsTransition) -or
                [string]::Equals(
                    $candidateEnvelope.SourcePath,
                    $lockFull,
                    [StringComparison]::Ordinal
                ) -or -not $sourceTransitionBindingMatches) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_SOURCE_INVALID' `
                    "reclaim marker source is not a distinct exactly bound active/valid-transition protocol path: $($candidateEnvelope.SourcePath)" `
                    'preserve the marker and investigate the source path/phase/PID/issue/ticks/hash binding'
            }
            $sourceState = Get-AstroPathEntryState `
                $candidateEnvelope.SourcePath
            $sourceArchiveState = Get-AstroPathEntryState `
                $candidateEnvelope.SourceArchivePath
            if ($sourceState.State -eq 'present' -and
                $sourceArchiveState.State -eq 'absent') {
                if (($sourceState.Attributes -band
                        [IO.FileAttributes]::Directory) -ne 0 -or
                    ($sourceState.Attributes -band
                        [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_SOURCE_UNEVALUABLE' `
                        "reclaim marker source is not an ordinary file: $($candidateEnvelope.SourcePath) ($($sourceState.Attributes))" `
                        'preserve every protocol entry and repair the exact source path'
                }
                Assert-NoReparseAncestors `
                    $candidateEnvelope.SourcePath `
                    $workspace `
                    'reclaim marker source'
                $markerProtectedLease = Open-AstroExactEvidenceLease `
                    $candidateEnvelope.SourcePath `
                    'reclaim-marker protected original source'
                $terminalFileHandles += $markerProtectedLease.Handle
                $markerProtectedSourceSnapshot =
                    $markerProtectedLease.InitialSnapshot
                $protectedSourceLeaf = [IO.Path]::GetFileName(
                    $markerProtectedSourceSnapshot.Path
                )
                $protectedSourceParent = [IO.Path]::GetDirectoryName(
                    $markerProtectedSourceSnapshot.Path
                )
                $protectedSourceParentLeaf = [IO.Path]::GetFileName(
                    $protectedSourceParent.TrimEnd('\', '/')
                )
                if ($protectedSourceLeaf -cne
                        [IO.Path]::GetFileName(
                            $candidateEnvelope.SourcePath
                        ) -or
                    $protectedSourceParentLeaf -cne '.tmp' -or
                    -not [string]::Equals(
                        $protectedSourceParent,
                        $protocolDirectoryFinalPath,
                        [StringComparison]::Ordinal
                    ) -or
                    $markerProtectedSourceSnapshot.Length -ne
                        $candidateEnvelope.SourceBytes -or
                    $markerProtectedSourceSnapshot.Sha256 -cne
                        $candidateEnvelope.SourceSha256 -or
                    $markerProtectedSourceSnapshot.FileIdentity -cne
                        $candidateEnvelope.SourceFileIdentity) {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_SOURCE_MISMATCH' `
                        'reclaim marker source path bytes/FILE_ID differ from the envelope binding' `
                        'preserve every protocol entry and investigate source drift'
                }
            }
            elseif ($sourceState.State -eq 'absent' -and
                $sourceArchiveState.State -eq 'present') {
                if (($sourceArchiveState.Attributes -band
                        [IO.FileAttributes]::Directory) -ne 0 -or
                    ($sourceArchiveState.Attributes -band
                        [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_SOURCE_UNEVALUABLE' `
                        "reclaim marker source archive is not an ordinary file: $($candidateEnvelope.SourceArchivePath) ($($sourceArchiveState.Attributes))" `
                        'preserve every protocol entry and repair the exact archive path'
                }
                $markerProtectedLease = Open-AstroExactEvidenceLease `
                    $candidateEnvelope.SourceArchivePath `
                    'reclaim-marker protected original archive'
                $terminalFileHandles += $markerProtectedLease.Handle
                $markerProtectedArchiveSnapshot =
                    $markerProtectedLease.InitialSnapshot
                if ($markerProtectedArchiveSnapshot.Length -ne
                        $candidateEnvelope.SourceBytes -or
                    $markerProtectedArchiveSnapshot.Sha256 -cne
                        $candidateEnvelope.SourceSha256 -or
                    $markerProtectedArchiveSnapshot.FileIdentity -cne
                        $candidateEnvelope.SourceFileIdentity) {
                    Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_SOURCE_MISMATCH' `
                        'reclaim marker source archive bytes/FILE_ID differ from the envelope binding' `
                        'preserve every protocol entry and investigate archive drift'
                }
            }
            else {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_SOURCE_AMBIGUOUS' `
                    "reclaim marker requires exactly one bound source location (source_state=$($sourceState.State), archive_state=$($sourceArchiveState.State))" `
                    'preserve every entry; the source must be either still present or exactly archived, never both/neither/unevaluable'
            }

            [string[]]$expectedOtherTransitions = @()
            if ($null -ne $markerProtectedSourceSnapshot -and
                $sourceIsTransition) {
                $expectedOtherTransitions = [string[]]@(
                    $candidateEnvelope.SourcePath
                )
            }
            $activeExpected = $null -ne $markerProtectedSourceSnapshot -and
                $sourceIsActive
            $otherSetMatches = $otherTransitions.Count -eq
                $expectedOtherTransitions.Count
            foreach ($expectedTransition in $expectedOtherTransitions) {
                if (-not ($otherTransitions -ccontains $expectedTransition)) {
                    $otherSetMatches = $false
                }
            }
            $activeMatches = ($activeExpected -and
                    $activeInventoryState.State -eq 'present') -or
                (-not $activeExpected -and
                    $activeInventoryState.State -eq 'absent')
            if (-not $otherSetMatches -or -not $activeMatches) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_CONFLICT' `
                    'active/transition inventory contains entries not exactly named and hash-bound by the reclaim marker' `
                    'preserve the whole protocol directory and investigate the conflicting writer'
            }
            $recognizedReclaimMarker = $true
            $reclaimMarkerEnvelope = $candidateEnvelope
        }
    }
    if ($isTransition -and -not $recognizedReclaimMarker -and
        ($otherTransitions.Count -ne 0 -or
            $activeInventoryState.State -ne 'absent')) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_CONFLICT' `
            "ordinary transition recovery requires active absence and the exact target as the sole transition (active=$($activeInventoryState.State), transitions=$(@($transitions.Paths) -join '; '))" `
            'preserve the complete protocol state; only a strict hash-bound reclaim marker may coexist with its exact named source'
    }
    if ($isTransition -and $transitionState.Valid -and
        -not $QuarantineUnreadable -and
        $transitionState.Sha256 -cne $initial.Sha256) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRANSITION_HASH_MISMATCH' `
            "transition filename SHA-256 '$($transitionState.Sha256)' differs from its exact bytes '$($initial.Sha256)'" `
            'preserve the transition; use explicit unreadable quarantine only after posting the filename/byte mismatch'
    }

    $owner = $null
    $quarantineRequiresMalformedExactStage = $false
    if ($recognizedReclaimMarker) {
        $owner = [pscustomobject]@{
            Schema = 'astrolabe.launcher-lock-reclaim-marker.v3'
            Legacy = [bool]$reclaimMarkerEnvelope.LegacyPidOnly
            Pid = $reclaimMarkerEnvelope.OwnerPid
            Issue = $reclaimMarkerEnvelope.OwnerIssue
            LeaseStartUtcTicks =
                $linkedAuthorizationBinding.OwnerLeaseStartUtcTicks
            StartedUtc = $null
            OwnerProcessStartUtcTicks =
                $reclaimMarkerEnvelope.OwnerProcessStartUtcTicks
            OwnerProcessStartedUtc = if ($LegacyPidOnly) { $null } else {
                ConvertTo-AstroProcessStartUtcIso `
                    $reclaimMarkerEnvelope.OwnerProcessStartUtcTicks
            }
            Command = $null
            HeadSha = $null
            StatusSha256 = $null
            DiffSha256 = $null
        }
    }
    elseif (-not $QuarantineUnreadable) {
        $owner = if ($LegacyPidOnly) {
            Read-LegacyOwner $initial.Bytes $lockFull
        } else {
            Read-ExactOwner $initial.Bytes $lockFull
        }
        if ($owner.Pid -ne $expectedPidValue -or
            $owner.Issue -ne $expectedIssueValue -or
            (-not $LegacyPidOnly -and
                $owner.OwnerProcessStartUtcTicks -ne $expectedTicksValue)) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_MISMATCH' `
                "manifest owner differs from expected pid=$expectedPidValue issue=#$expectedIssueValue ticks=$expectedTicksValue" `
                'use the exact owner identity from the unchanged manifest'
        }
    }
    else {
        $v2Candidate = Convert-AstroLauncherLockBytesToState `
            $initial.Bytes `
            $lockFull
        $legacyCandidate = $null
        try {
            $legacyCandidate = Convert-AstroLegacyOwnerBytesToState `
                $initial.Bytes `
                $lockFull
        }
        catch {
            $legacyCandidate = $null
        }
        $embeddedOwner = Get-AstroEmbeddedOwnerIdentity `
            $initial.Bytes `
            $lockFull
        $transitionEnvelopeUnreadable = $isTransition -and
            (-not $transitionState.Valid -or
                $transitionState.Sha256 -cne $initial.Sha256)
        if ($v2Candidate.State -ne 'unreadable') {
            if (-not $transitionEnvelopeUnreadable) {
                # A valid exact-owner source can still own one malformed exact attribution
                # stage. Defer the necessity decision until the retained, exact
                # attribution inventory proves that this is the sole unreadable
                # subordinate state. No mutation occurs before that proof.
                $quarantineRequiresMalformedExactStage = $true
            }
            if ($LegacyPidOnly -or
                $v2Candidate.OwnerPid -ne $expectedPidValue -or
                $v2Candidate.Issue -ne $expectedIssueValue -or
                $v2Candidate.OwnerProcessStartUtcTicks -ne $expectedTicksValue) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_MISMATCH' `
                    'valid exact-owner bytes inside an unreadable transition envelope differ from the expected exact owner' `
                    'bind quarantine to the embedded PID/issue/process-start ticks; never downgrade them'
            }
            $owner = [pscustomobject]@{
                Schema = $v2Candidate.Schema
                Legacy = $false
                Pid = $v2Candidate.OwnerPid
                Issue = $v2Candidate.Issue
                LeaseStartUtcTicks = $v2Candidate.LeaseStartUtcTicks
                StartedUtc = $v2Candidate.Started
                OwnerProcessStartUtcTicks = $v2Candidate.OwnerProcessStartUtcTicks
                OwnerProcessStartedUtc = $v2Candidate.OwnerProcessStarted
                Command = $v2Candidate.Command
                HeadSha = $v2Candidate.HeadSha
                StatusSha256 = $v2Candidate.StatusSha256
                DiffSha256 = $v2Candidate.DiffSha256
            }
        }
        elseif ($null -ne $legacyCandidate) {
            if (-not $transitionEnvelopeUnreadable) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_QUARANTINE_NOT_REQUIRED' `
                    'QuarantineUnreadable refuses structurally valid fresh legacy state, which has no deterministic Job binding' `
                    'preserve fresh pre-v2 state permanently; LegacyPidOnly is resume-only for an already-published strictly linked legacy reclaim marker'
            }
            if (-not $LegacyPidOnly -or
                $legacyCandidate.Pid -ne $expectedPidValue -or
                $legacyCandidate.Issue -ne $expectedIssueValue) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_MISMATCH' `
                    'valid legacy bytes inside an unreadable transition envelope differ from the expected PID/issue mode' `
                    'use -LegacyPidOnly and bind quarantine to the embedded legacy PID/issue'
            }
            $owner = $legacyCandidate
        }
        elseif ($embeddedOwner.State -eq 'exact') {
            if ($LegacyPidOnly -or
                $embeddedOwner.Pid -ne $expectedPidValue -or
                $embeddedOwner.Issue -ne $expectedIssueValue -or
                $embeddedOwner.OwnerProcessStartUtcTicks -ne
                    $expectedTicksValue) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_MISMATCH' `
                    'malformed manifest still contains an unambiguous modern owner that differs from the requested quarantine identity' `
                    'bind quarantine to the embedded PID/issue/process-start ticks; invalid non-owner fields never authorize an ownership downgrade'
            }
            $owner = [pscustomobject]@{
                Schema = 'embedded-exact-quarantine'
                Legacy = $false
                Pid = $embeddedOwner.Pid
                Issue = $embeddedOwner.Issue
                LeaseStartUtcTicks = $null
                StartedUtc = $null
                OwnerProcessStartUtcTicks =
                    $embeddedOwner.OwnerProcessStartUtcTicks
                OwnerProcessStartedUtc = ConvertTo-AstroProcessStartUtcIso `
                    $embeddedOwner.OwnerProcessStartUtcTicks
                Command = $null
                HeadSha = $null
                StatusSha256 = $null
                DiffSha256 = $null
            }
        }
        elseif ($embeddedOwner.State -eq 'legacy') {
            if (-not $LegacyPidOnly -or
                $embeddedOwner.Pid -ne $expectedPidValue -or
                $embeddedOwner.Issue -ne $expectedIssueValue) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_MISMATCH' `
                    'malformed manifest still contains an unambiguous legacy owner that differs from the requested quarantine identity/mode' `
                    'use -LegacyPidOnly and bind quarantine to the embedded legacy PID/issue'
            }
            $owner = [pscustomobject]@{
                Schema = 'embedded-legacy-quarantine'
                Legacy = $true
                Pid = $embeddedOwner.Pid
                Issue = $embeddedOwner.Issue
                LeaseStartUtcTicks = $null
                StartedUtc = $null
                OwnerProcessStartUtcTicks = $null
                OwnerProcessStartedUtc = $null
                Command = $null
                HeadSha = $null
                StatusSha256 = $null
                DiffSha256 = $null
            }
        }
        elseif ($embeddedOwner.State -eq 'ambiguous') {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_IDENTITY_AMBIGUOUS' `
                "malformed manifest contains incomplete/invalid owner indicators: $($embeddedOwner.Error)" `
                'preserve the bytes; automated quarantine never replaces ambiguous embedded ownership with external values'
        }
        else {
            $owner = [pscustomobject]@{
                Schema = 'unreadable-quarantine'
                Legacy = [bool]$LegacyPidOnly
                Pid = $expectedPidValue
                Issue = $expectedIssueValue
                LeaseStartUtcTicks = $null
                StartedUtc = $null
                OwnerProcessStartUtcTicks = $expectedTicksValue
                OwnerProcessStartedUtc = if ($LegacyPidOnly) {
                    $null
                } else {
                    ConvertTo-AstroProcessStartUtcIso $expectedTicksValue
                }
                Command = $null
                HeadSha = $null
                StatusSha256 = $null
                DiffSha256 = $null
            }
        }
    }

    if (-not $recognizedReclaimMarker -and
        $null -eq $owner.LeaseStartUtcTicks) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_POLICY_UNTRUSTWORTHY' `
            'fresh malformed/pre-v2 owner state has no exact launcher lease-start ticks from which to derive its generation-bound Job Object' `
            'preserve the state permanently; only a strictly linked already-published marker may resume prior authority, and subordinate evidence never supplies missing source authority'
    }
    $launcherGenerationLockSha256 = if ($recognizedReclaimMarker) {
        [string]$reclaimMarkerEnvelope.SourceSha256
    } else { $expectedHash }
    $attributionPolicy = if ($recognizedReclaimMarker) {
        'prior-marker-record'
    }
    elseif (-not $LegacyPidOnly -and $isActive) {
        'transition-bound-v3'
    }
    elseif (-not $LegacyPidOnly -and $isTransition -and
        $transitionState.Valid -and
        $transitionState.Phase -ceq 'cleanup') {
        'transition-bound-v3'
    }
    elseif (-not $LegacyPidOnly -and $isTransition -and
        $transitionState.Valid -and
        $transitionState.Phase -ceq 'claim') {
        'transition-bound-v3'
    }
    else {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_POLICY_UNTRUSTWORTHY' `
            "protocol state has no trustworthy exact attribution policy (active=$isActive, transition_phase=$($transitionState.Phase), transition_valid=$($transitionState.Valid), legacy=$LegacyPidOnly, recognized_marker=$recognizedReclaimMarker)" `
            'preserve the complete protocol state; fresh legacy/malformed owner state without deterministic Job derivation is permanently preserving, and LegacyPidOnly is resume-only for a strictly linked published marker'
    }
    $recoveryTransactionId = [Guid]::NewGuid().ToString('N')
    $reclaimPhase = 'first-local-probes'
    $firstProbe = Assert-OwnerDead `
        $expectedPidValue `
        $expectedTicksValue `
        ([bool]$LegacyPidOnly) `
        'before-tracker-authorization-read'
    $firstAttributionProbe = Get-AstroReclaimAttributionProbe `
        -Root $rootFull `
        -ProbeName 'before-tracker-authorization-read' `
        -ExpectedOwnerPid $expectedPidValue `
        -ExpectedOwnerProcessStartUtcTicks $expectedTicksValue `
        -ExpectedLauncherLeaseStartUtcTicks $owner.LeaseStartUtcTicks `
        -ExpectedLauncherLockSha256 $launcherGenerationLockSha256 `
        -RootIdentity $mutexLease.RootIdentity `
        -RecoveryRoot $recoveryRoot `
        -RecoveryTransactionId $recoveryTransactionId `
        -AllowMalformedExactStageQuarantine ([bool]$QuarantineUnreadable) `
        -Policy $attributionPolicy
    if ($quarantineRequiresMalformedExactStage) {
        $malformedExactStages = @($firstAttributionProbe.manifests | Where-Object {
                -not [bool]$_.valid -and $_.kind -ceq 'stage'
            })
        $malformedRenameTransactions = @(
            $firstAttributionProbe.refresh_transactions |
                Where-Object { [bool]$_.rename_suffix_quarantine }
        )
        if (($malformedExactStages.Count +
                $malformedRenameTransactions.Count) -ne 1) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_QUARANTINE_NOT_REQUIRED' `
                "QuarantineUnreadable on a valid exact-owner source requires exactly one malformed exact attribution stage or one strictly cross-bound one-code-unit refresh rename; observed stages=$($malformedExactStages.Count), refresh_renames=$($malformedRenameTransactions.Count)" `
                'use normal exact-owner reclaim when no malformed subordinate exists; preserve multiple or otherwise ambiguous malformed states for investigation'
        }
    }
    $subordinateCleanupPlan = if ($recognizedReclaimMarker) {
        ConvertTo-AstroSubordinateCleanupPlan `
            -Probe $linkedFinalizationBinding.AttributionProbe `
            -RecoveryRoot $recoveryRoot `
            -TransactionId $reclaimMarkerEnvelope.TransactionId
    } else {
        ConvertTo-AstroSubordinateCleanupPlan `
            -Probe $firstAttributionProbe `
            -RecoveryRoot $recoveryRoot `
            -TransactionId $recoveryTransactionId
    }
    $null = Assert-AstroSubordinateProbeMatchesPlan `
        -Probe $firstAttributionProbe `
        -Plan $subordinateCleanupPlan `
        -RecoveryRoot $recoveryRoot `
        -Description 'first subordinate inventory'
    $reclaimPhase = 'first-tracker-read'
    $trackerFirst = Read-TrackerEvidence `
        $TrackerCommentUrl `
        $expectedIssueValue `
        $lockFull `
        $expectedHash `
        $expectedPidValue `
        $expectedTicksValue `
        ([bool]$LegacyPidOnly) `
        ([bool]$QuarantineUnreadable) `
        $firstProbe

    $recoveryState = Get-AstroPathEntryState $recoveryRoot
    if ($recoveryState.State -eq 'absent') {
        [IO.Directory]::CreateDirectory($recoveryRoot) | Out-Null
    }
    elseif ($recoveryState.State -ne 'present' -or
        ($recoveryState.Attributes -band [IO.FileAttributes]::Directory) -eq 0) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_ROOT_INVALID' `
            "recovery root is not an evaluable directory: $recoveryRoot" `
            'preserve all state and repair the workspace-local recovery directory'
    }
    Assert-NoReparseAncestors $recoveryRoot $workspace 'recovery directory'
    if ($null -eq $archiveDirectoryHandle) {
        try {
            $archiveDirectoryHandle =
                [AstroLauncherLockNative]::OpenExactRenameDirectory(
                    $recoveryRoot
                )
            $recoveryDirectoryIdentity =
                [AstroLauncherLockNative]::GetFileIdentity(
                    $archiveDirectoryHandle
                )
            $recoveryDirectoryFinalPath = ConvertTo-AstroComparableFinalPath (
                [AstroLauncherLockNative]::GetFileFinalPath(
                    $archiveDirectoryHandle
                )
            )
        }
        catch {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_ROOT_INVALID' `
                "could not retain exact recovery directory '$recoveryRoot': $($_.Exception.Message)" `
                'preserve all state and repair the workspace-local non-reparse recovery directory'
        }
    }
    if (-not [string]::Equals(
            $recoveryDirectoryFinalPath,
            $recoveryRoot,
            [StringComparison]::Ordinal
        )) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_ROOT_ALIAS' `
            "recovery directory '$recoveryRoot' resolves to retained-handle path '$recoveryDirectoryFinalPath'" `
            'use the exact canonical non-alias recovery directory'
    }
    foreach ($candidate in @(
            $recordFull,
            $finalizationFull,
            $completionFull,
            $archiveFull,
            $markerArchiveFull
        )) {
        Assert-AstroRecoveryArtifactLeaf $candidate
        if ((Get-AstroPathEntryState $candidate).State -ne 'absent') {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_REUSE_REFUSED' `
                "recovery path appeared during validation: $candidate" `
                'preserve all state and use a fresh basename'
        }
    }
    if (-not $recognizedReclaimMarker) {
        foreach ($record in @($subordinateCleanupPlan.Records)) {
            if ($record.cleanup_action -ceq 'archive-quarantine' -and
                (Get-AstroPathEntryState `
                    $record.quarantine_archive_path).State -ne 'absent') {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_REUSE_REFUSED' `
                    "subordinate quarantine archive path is not fresh: $($record.quarantine_archive_path)" `
                    'preserve every entry and retry with a fresh recovery transaction'
            }
        }
    }

    $selfProbe = Get-AstroProcessIdentityProbe $PID
    if ($selfProbe.State -ne 'observed') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SELF_IDENTITY_UNEVALUABLE' `
            "reclaim process PID $PID identity is unevaluable: $($selfProbe.Error)" `
            'run recovery only when its own native process identity is readable'
    }
    $reclaimPhase = 'authorization-publication'
    $authorization = [ordered]@{
        schema = 'astrolabe.launcher-lock-recovery.authorization.v7'
        phase = 'authorized-before-archive'
        transaction_id = $recoveryTransactionId
        recorded_at_utc = [DateTime]::UtcNow.ToString('o')
        mode = [ordered]@{
            recovery_branch = if ($recognizedReclaimMarker) {
                'recognized-marker'
            } else { 'ordinary-source' }
            legacy_pid_only = [bool]$LegacyPidOnly
            quarantine_unreadable = [bool]$QuarantineUnreadable
            protocol_state = if ($isActive) { 'active' } else {
                $transitionState.Phase
            }
            transition_name_valid = if ($isTransition) {
                [bool]$transitionState.Valid
            } else { $null }
        }
        tracker = [ordered]@{
            url = $trackerFirst.Url
            comment_id = $trackerFirst.Id
            api_url = $trackerFirst.ApiUrl
            created_at = $trackerFirst.CreatedAt
            updated_at = $trackerFirst.UpdatedAt
            body_bytes = $trackerFirst.BodyBytes
            body_sha256 = $trackerFirst.BodySha256
            evidence = $trackerFirst.Evidence
        }
        mutex = [ordered]@{
            name = $mutexLease.Name
            root_identity = $mutexLease.RootIdentity
            root_final_path = $mutexLease.RootFinalPath
            recovered_abandoned_owner = [bool]$mutexLease.WasAbandoned
        }
        reclaim_process = [ordered]@{
            pid = $PID
            process_start_utc_ticks = [long]$selfProbe.ProcessStartUtcTicks
            process_started_utc = $selfProbe.ProcessStartedUtc
        }
        root = $rootFull
        recovery_paths = [ordered]@{
            authorization = $recordFull
            finalization = $finalizationFull
            completion = $completionFull
            archive = $archiveFull
            marker_archive = $markerArchiveFull
            immutable_publication =
                'delete-on-close-stage-hard-link-no-replace-v1'
        }
        protocol_directory = [ordered]@{
            path = $tmpRoot
            retained_final_path = $protocolDirectoryFinalPath
            retained_file_identity = $protocolDirectoryIdentity
        }
        recovery_directory = [ordered]@{
            path = $recoveryRoot
            retained_final_path = $recoveryDirectoryFinalPath
            retained_file_identity = $recoveryDirectoryIdentity
        }
        target = [ordered]@{
            path = $lockFull
            bytes = $initial.Length
            sha256 = $initial.Sha256
            retained_file_identity = $initial.FileIdentity
            retained_final_path = $initial.Path
            archive_path = if ($recognizedReclaimMarker) {
                $markerArchiveFull
            } else { $archiveFull }
            transition_name_intended_sha256 = if ($isTransition) {
                $transitionState.Sha256
            } else { $null }
            recognized_marker = if ($recognizedReclaimMarker) {
                [ordered]@{
                    transaction_id = $reclaimMarkerEnvelope.TransactionId
                    linked_authorization_path =
                        $reclaimMarkerEnvelope.AuthorizationPath
                    linked_finalization_path =
                        $reclaimMarkerEnvelope.FinalizationPath
                    protected_source_path = if (
                        $null -ne $markerProtectedSourceSnapshot
                    ) { $reclaimMarkerEnvelope.SourcePath } else {
                        $reclaimMarkerEnvelope.SourceArchivePath
                    }
                    protected_source_file_identity =
                        $reclaimMarkerEnvelope.SourceFileIdentity
                    protected_source_disposition = if (
                        $null -ne $markerProtectedSourceSnapshot
                    ) { 'source-present' } else { 'source-archived' }
                }
            } else { $null }
            owner = [ordered]@{
                schema = $owner.Schema
                legacy_pid_only = [bool]$owner.Legacy
                pid = $owner.Pid
                issue = $owner.Issue
                lease_start_utc_ticks = $owner.LeaseStartUtcTicks
                started_utc = $owner.StartedUtc
                owner_process_start_utc_ticks =
                    $owner.OwnerProcessStartUtcTicks
                owner_process_started_utc = $owner.OwnerProcessStartedUtc
                command = $owner.Command
                head_sha = $owner.HeadSha
                status_sha256 = $owner.StatusSha256
                diff_sha256 = $owner.DiffSha256
            }
        }
        pre_publication_pid_probe = $firstProbe
        pre_publication_attribution_probe = $firstAttributionProbe
        subordinate_cleanup_plan = [ordered]@{
            schema = $subordinateCleanupPlan.Schema
            transaction_id = $subordinateCleanupPlan.TransactionId
            initial_state = $subordinateCleanupPlan.SubordinateState
            sha256 = $subordinateCleanupPlan.Sha256
        }
    }
    $authorizationReadback = Write-NewDurableJsonAndReadBack `
        -LiteralPath $recordFull `
        -Value $authorization `
        -Description 'reclaim authorization record' `
        -StageDirectoryPath $recoveryRoot `
        -StageDirectoryHandle $archiveDirectoryHandle `
        -DestinationDirectoryHandle $archiveDirectoryHandle
    $terminalFileHandles += $authorizationReadback.PublicationLease.Handle
    if ([string]$authorizationReadback.Persisted.transaction_id -cne
        $recoveryTransactionId) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRANSACTION_MISMATCH' `
            'authorization durable JSON readback lost its exact transaction_id binding' `
            'preserve the authorization and source; investigate serialization/storage before retrying'
    }
    $authorizationLease = Open-AstroExactEvidenceLease `
        $recordFull `
        'reclaim authorization record'
    $terminalFileHandles += $authorizationLease.Handle
    if ($authorizationLease.InitialSnapshot.Sha256 -cne
            $authorizationReadback.Snapshot.Sha256 -or
        -not (Test-ByteArraysEqual `
            $authorizationLease.InitialSnapshot.Bytes `
            $authorizationReadback.Snapshot.Bytes)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_AUTHORIZATION_CHANGED' `
            'authorization bytes changed while establishing the immutable evidence lease' `
            'preserve all recovery state and investigate concurrent modification'
    }

    $beforeArchive = Get-AstroExactRenameLeaseSnapshot `
        $sourceRenameLease `
        'launcher protocol source after authorization'
    if ($beforeArchive.Length -ne $initial.Length -or
        $beforeArchive.Sha256 -cne $initial.Sha256 -or
        $beforeArchive.FileIdentity -cne $initial.FileIdentity -or
        -not [string]::Equals(
            $beforeArchive.Path,
            $lockFull,
            [StringComparison]::Ordinal
        ) -or
        -not (Test-ByteArraysEqual $beforeArchive.Bytes $initial.Bytes)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_LOCK_CHANGED' `
            'target bytes changed after authorization publication' `
            'preserve target and authorization; re-establish current ownership'
    }
    $reclaimPhase = 'second-tracker-read'
    $trackerSecond = Read-TrackerEvidence `
        $TrackerCommentUrl `
        $expectedIssueValue `
        $lockFull `
        $expectedHash `
        $expectedPidValue `
        $expectedTicksValue `
        ([bool]$LegacyPidOnly) `
        ([bool]$QuarantineUnreadable) `
        $firstProbe
    if ($trackerSecond.BodySha256 -cne $trackerFirst.BodySha256 -or
        $trackerSecond.UpdatedAt -cne $trackerFirst.UpdatedAt) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_CHANGED' `
            'tracker comment changed between authorization and archive' `
            'preserve target/authorization and post a fresh immutable evidence comment'
    }

    $refreshRecordsBefore = @($firstAttributionProbe.refresh_transactions)
    $refreshRecovery = $null
    if ($refreshRecordsBefore.Count -gt 0) {
        $reclaimPhase = 'authorized-attribution-refresh-recovery'
        $refreshRecovery = Resolve-AstroDeadAttributionRefreshTransactions `
            -Directory $tmpRoot `
            -ExpectedLauncherPid $expectedPidValue `
            -ExpectedLauncherProcessStartUtcTicks $expectedTicksValue `
            -ExpectedLauncherLockSha256 $launcherGenerationLockSha256 `
            -ExpectedTransactions $refreshRecordsBefore `
            -AllowMalformedRenameSuffixQuarantine:([bool]$QuarantineUnreadable)
        [string[]]$expectedRefreshKeys = @(
            $refreshRecordsBefore | ForEach-Object { [string]$_.key }
        )
        [string[]]$resolvedRefreshKeys = @($refreshRecovery.ResolvedKeys)
        [Array]::Sort($expectedRefreshKeys, [StringComparer]::Ordinal)
        [Array]::Sort($resolvedRefreshKeys, [StringComparer]::Ordinal)
        if ($expectedRefreshKeys.Count -ne $resolvedRefreshKeys.Count) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_REFRESH_CHANGED' `
                'authorized refresh recovery did not consume exactly the transaction set bound in the durable authorization' `
                'preserve authorization/source and every remaining refresh artifact; never expand or infer the authorized set'
        }
        for ($refreshIndex = 0;
            $refreshIndex -lt $expectedRefreshKeys.Count;
            $refreshIndex++) {
            if ($expectedRefreshKeys[$refreshIndex] -cne
                $resolvedRefreshKeys[$refreshIndex]) {
                Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_REFRESH_CHANGED' `
                    'authorized refresh recovery transaction keys differ from durable authorization' `
                    'preserve authorization/source and re-establish exact transaction identity'
            }
        }
        if (@($refreshRecovery.TerminalInventory.RefreshTransactions).Count -ne 0) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_REFRESH_CHANGED' `
                'authorized refresh recovery did not reach final-only terminal state' `
                'preserve authorization/source and inspect typed envelope/tombstone terminal state'
        }
    }

    $reclaimPhase = 'final-local-probes'
    $secondProbe = Assert-OwnerDead `
        $expectedPidValue `
        $expectedTicksValue `
        ([bool]$LegacyPidOnly) `
        'after-tracker-before-finalization'
    if ([string]$secondProbe.state -cne [string]$firstProbe.state -or
        $secondProbe.observed_process_start_utc_ticks -ne
            $firstProbe.observed_process_start_utc_ticks) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_OWNER_CHANGED' `
            'owner PID occupancy/process-start observation changed across the tracker/authorization boundary' `
            'preserve target/authorization and post fresh evidence for the current exact process state'
    }
    $secondAttributionProbe = Get-AstroReclaimAttributionProbe `
        -Root $rootFull `
        -ProbeName 'after-tracker-before-finalization' `
        -ExpectedOwnerPid $expectedPidValue `
        -ExpectedOwnerProcessStartUtcTicks $expectedTicksValue `
        -ExpectedLauncherLeaseStartUtcTicks $owner.LeaseStartUtcTicks `
        -ExpectedLauncherLockSha256 $launcherGenerationLockSha256 `
        -RootIdentity $mutexLease.RootIdentity `
        -RecoveryRoot $recoveryRoot `
        -RecoveryTransactionId $recoveryTransactionId `
        -AllowMalformedExactStageQuarantine ([bool]$QuarantineUnreadable) `
        -Policy $attributionPolicy
    if ($refreshRecordsBefore.Count -eq 0 -and
        $secondAttributionProbe.stable_fingerprint_sha256 -cne
            $firstAttributionProbe.stable_fingerprint_sha256) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_CHANGED' `
            'attribution manifest/Job Object state changed across the tracker/authorization boundary' `
            'preserve target/authorization and re-establish current descendant state before retrying'
    }
    if ($refreshRecordsBefore.Count -gt 0 -and
        @($secondAttributionProbe.refresh_transactions).Count -ne 0) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ATTRIBUTION_REFRESH_CHANGED' `
            'typed refresh artifacts remain after authorized exact recovery' `
            'preserve target/authorization and inspect the residual transaction before retrying'
    }
    $null = Assert-AstroSubordinateProbeMatchesPlan `
        -Probe $secondAttributionProbe `
        -Plan $subordinateCleanupPlan `
        -RecoveryRoot $recoveryRoot `
        -Description 'second subordinate inventory'
    if (-not $recognizedReclaimMarker) {
        $secondPlan = ConvertTo-AstroSubordinateCleanupPlan `
            -Probe $secondAttributionProbe `
            -RecoveryRoot $recoveryRoot `
            -TransactionId $recoveryTransactionId
        if ($secondPlan.Sha256 -cne $subordinateCleanupPlan.Sha256) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_CHANGED' `
                'subordinate cleanup plan changed across tracker authorization/finalization' `
                'preserve target/authorization and restart from an exact stable inventory'
        }
    }

    $finalSource = Get-AstroExactRenameLeaseSnapshot `
        $sourceRenameLease `
        'launcher protocol source after final local probes'
    if ($finalSource.Length -ne $initial.Length -or
        $finalSource.Sha256 -cne $initial.Sha256 -or
        $finalSource.FileIdentity -cne $initial.FileIdentity -or
        -not [string]::Equals(
            $finalSource.Path,
            $lockFull,
            [StringComparison]::Ordinal
        ) -or
        -not (Test-ByteArraysEqual $finalSource.Bytes $initial.Bytes)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_LOCK_CHANGED' `
            'target bytes changed during the tracker/second-owner verification window' `
            'preserve target and authorization; post fresh evidence for the current exact bytes'
    }
    $authorizationFinal = Get-AstroFileSnapshot $recordFull ([IO.FileShare]::Read)
    if ($authorizationFinal.Sha256 -cne
            $authorizationReadback.Snapshot.Sha256 -or
        -not (Test-ByteArraysEqual `
                $authorizationFinal.Bytes `
                $authorizationReadback.Snapshot.Bytes)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_AUTHORIZATION_CHANGED' `
            'authorization record changed before finalization publication' `
            'preserve all recovery state and investigate concurrent modification'
    }

    $finalization = [ordered]@{
        schema = 'astrolabe.launcher-lock-recovery.finalization.v3'
        phase = 'verified-ready-to-archive'
        transaction_id = $recoveryTransactionId
        recovery_branch = if ($recognizedReclaimMarker) {
            'recognized-marker'
        } else { 'ordinary-source' }
        recorded_at_utc = [DateTime]::UtcNow.ToString('o')
        authorization = [ordered]@{
            path = $recordFull
            bytes = $authorizationFinal.Length
            sha256 = $authorizationFinal.Sha256
        }
        tracker = [ordered]@{
            url = $trackerSecond.Url
            comment_id = $trackerSecond.Id
            updated_at = $trackerSecond.UpdatedAt
            body_sha256 = $trackerSecond.BodySha256
        }
        second_owner_probe = $secondProbe
        second_attribution_probe = $secondAttributionProbe
        subordinate_cleanup_plan = [ordered]@{
            schema = $subordinateCleanupPlan.Schema
            transaction_id = $subordinateCleanupPlan.TransactionId
            initial_state = $subordinateCleanupPlan.SubordinateState
            sha256 = $subordinateCleanupPlan.Sha256
        }
        source = [ordered]@{
            path = $lockFull
            bytes = $finalSource.Length
            sha256 = $finalSource.Sha256
            retained_file_identity = $finalSource.FileIdentity
            retained_final_path = $finalSource.Path
        }
        archive_path = if ($recognizedReclaimMarker) {
            $markerArchiveFull
        } else { $archiveFull }
        recovery_directory = [ordered]@{
            path = $recoveryRoot
            retained_final_path = $recoveryDirectoryFinalPath
            retained_file_identity = $recoveryDirectoryIdentity
        }
        protected_interrupted_transaction = if ($recognizedReclaimMarker) {
            [ordered]@{
                transaction_id = $reclaimMarkerEnvelope.TransactionId
                source_path = $reclaimMarkerEnvelope.SourcePath
                source_archive_path =
                    $reclaimMarkerEnvelope.SourceArchivePath
                source_file_identity =
                    $reclaimMarkerEnvelope.SourceFileIdentity
                disposition = if ($null -ne $markerProtectedSourceSnapshot) {
                    'source-present'
                } else { 'source-archived' }
            }
        } else { $null }
        preserved_other_transition_paths = @($otherTransitions)
    }
    $finalizationReadback = Write-NewDurableJsonAndReadBack `
        -LiteralPath $finalizationFull `
        -Value $finalization `
        -Description 'reclaim finalization record' `
        -StageDirectoryPath $recoveryRoot `
        -StageDirectoryHandle $archiveDirectoryHandle `
        -DestinationDirectoryHandle $archiveDirectoryHandle
    $terminalFileHandles += $finalizationReadback.PublicationLease.Handle
    if ([string]$finalizationReadback.Persisted.transaction_id -cne
        $recoveryTransactionId) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRANSACTION_MISMATCH' `
            'finalization durable JSON readback lost its exact transaction_id binding' `
            'preserve every recovery entry and source; investigate serialization/storage'
    }
    $finalizationLease = Open-AstroExactEvidenceLease `
        $finalizationFull `
        'reclaim finalization record'
    $terminalFileHandles += $finalizationLease.Handle
    if ($finalizationLease.InitialSnapshot.Sha256 -cne
            $finalizationReadback.Snapshot.Sha256 -or
        -not (Test-ByteArraysEqual `
            $finalizationLease.InitialSnapshot.Bytes `
            $finalizationReadback.Snapshot.Bytes)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_FINALIZATION_CHANGED' `
            'finalization bytes changed while establishing the immutable evidence lease' `
            'preserve every recovery entry and investigate concurrent modification'
    }

    $markerEnvelopeState = $null
    if (-not $recognizedReclaimMarker) {
        $markerTransactionId = $recoveryTransactionId
        $markerEnvelope = [ordered]@{
            schema = 'astrolabe.launcher-lock-reclaim-marker.v3'
            phase = 'archive-pending'
            transaction_id = $markerTransactionId
            legacy_pid_only = [bool]$LegacyPidOnly
            owner_pid = $expectedPidValue
            owner_issue = $expectedIssueValue
            owner_process_start_utc_ticks = if ($LegacyPidOnly) {
                $null
            } else { [long]$expectedTicksValue }
            authorization_path = $recordFull
            authorization_bytes =
                $authorizationLease.InitialSnapshot.Length
            authorization_sha256 =
                $authorizationLease.InitialSnapshot.Sha256
            authorization_file_identity =
                $authorizationLease.InitialSnapshot.FileIdentity
            finalization_path = $finalizationFull
            finalization_bytes =
                $finalizationLease.InitialSnapshot.Length
            finalization_sha256 =
                $finalizationLease.InitialSnapshot.Sha256
            finalization_file_identity =
                $finalizationLease.InitialSnapshot.FileIdentity
            source_path = $lockFull
            source_bytes = $initial.Length
            source_sha256 = $initial.Sha256
            source_file_identity = $initial.FileIdentity
            source_archive_path = $archiveFull
            recovery_directory_path = $recoveryRoot
            recovery_directory_file_identity = $recoveryDirectoryIdentity
            recovery_directory_final_path = $recoveryDirectoryFinalPath
            preserved_protocol_kind = 'none'
            preserved_protocol_path = $null
            preserved_protocol_bytes = $null
            preserved_protocol_sha256 = $null
        }
        $markerBytes = [Text.UTF8Encoding]::new($false).GetBytes(
            ($markerEnvelope | ConvertTo-Json -Depth 4 -Compress)
        )
        $markerHash = Get-AstroByteSha256 $markerBytes
        $markerLeaf = if ($LegacyPidOnly) {
            "astrolabe-launcher.lock.reclaim.legacy.pid-$expectedPidValue.issue-$expectedIssueValue.sha256-$markerHash.$markerTransactionId"
        }
        else {
            "astrolabe-launcher.lock.reclaim.v2.pid-$expectedPidValue.issue-$expectedIssueValue.ticks-$expectedTicksValue.sha256-$markerHash.$markerTransactionId"
        }
        $reclaimMarker = [IO.Path]::GetFullPath(
            (Join-Path $tmpRoot $markerLeaf)
        )
        $markerPublicationResult = Write-NewDurableBytes `
            -LiteralPath $reclaimMarker `
            -Bytes $markerBytes `
            -Description 'classifier-visible reclaim marker envelope' `
            -StageDirectoryPath $recoveryRoot `
            -StageDirectoryHandle $archiveDirectoryHandle `
            -DestinationDirectoryHandle $protocolDirectoryHandle `
            -RetainRenameAuthority
        $terminalFileHandles +=
            $markerPublicationResult.ObserverLease.Handle
        $markerRenameLease = $markerPublicationResult.RetainedLease
        $markerSnapshot = $markerRenameLease.InitialSnapshot
        if ($markerSnapshot.FileIdentity -cne
                $markerPublicationResult.Snapshot.FileIdentity -or
            $markerSnapshot.Sha256 -cne
                $markerPublicationResult.Snapshot.Sha256 -or
            -not (Test-ByteArraysEqual `
                $markerSnapshot.Bytes `
                $markerPublicationResult.Snapshot.Bytes)) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_MISMATCH' `
                'write-denying marker lease differs from the exact one-link hard-link publication readback' `
                'preserve marker/source/evidence and investigate exact FILE_ID/byte drift'
        }
        $markerEnvelopeState = Convert-AstroReclaimMarkerBytesToState `
            $markerSnapshot.Bytes `
            $reclaimMarker
        $publishedTransition = ConvertTo-AstroLauncherTransitionState `
            $reclaimMarker
        if (-not $markerEnvelopeState.Valid -or
            $markerSnapshot.Sha256 -cne $markerHash -or
            -not (Test-ByteArraysEqual $markerSnapshot.Bytes $markerBytes) -or
            $markerEnvelopeState.TransactionId -cne $markerTransactionId -or
            $markerEnvelopeState.SourceFileIdentity -cne $initial.FileIdentity -or
            -not $publishedTransition.Candidate -or
            $publishedTransition.Phase -cne 'reclaim' -or
            $publishedTransition.Pid -ne $expectedPidValue -or
            $publishedTransition.Issue -ne $expectedIssueValue -or
            $publishedTransition.Sha256 -cne $markerHash -or
            $publishedTransition.Nonce -cne $markerTransactionId -or
            ((-not $LegacyPidOnly) -and -not $publishedTransition.Valid) -or
            ((-not $LegacyPidOnly) -and
                $publishedTransition.OwnerProcessStartUtcTicks -ne
                    $expectedTicksValue) -or
            ($LegacyPidOnly -and -not $publishedTransition.LegacyMarker)) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_MISMATCH' `
                'classifier-visible marker filename/envelope/FILE_ID bindings differ from the exact durable transaction' `
                'preserve source/finalization/marker and recover only the exact interrupted marker through tracker evidence'
        }
        $markerArchiveDestination = $markerArchiveFull
    }
    else {
        $markerTransactionId = $reclaimMarkerEnvelope.TransactionId
        $reclaimMarker = $lockFull
        $markerSnapshot = $initial
        $markerEnvelopeState = $reclaimMarkerEnvelope
        $markerArchiveDestination = $markerArchiveFull
    }

    $reclaimPhase = 'transaction-bound-subordinate-cleanup'
    $subordinateCleanupResult = Invoke-AstroSubordinateCleanupPlan `
        -Plan $subordinateCleanupPlan `
        -CurrentProbe $secondAttributionProbe `
        -Root $rootFull `
        -RootIdentity $mutexLease.RootIdentity `
        -RecoveryRoot $recoveryRoot `
        -RecoveryDirectoryHandle $archiveDirectoryHandle `
        -ExpectedOwnerPid $expectedPidValue `
        -ExpectedOwnerProcessStartUtcTicks $expectedTicksValue `
        -ExpectedLauncherLockSha256 $launcherGenerationLockSha256 `
        -AllowMalformedExactStageQuarantine ([bool]$QuarantineUnreadable)
    foreach ($archiveRecord in @(
            $subordinateCleanupResult.QuarantineArchives
        )) {
        $lease = Open-AstroExactEvidenceLease `
            $archiveRecord.path `
            'durable transaction malformed-stage archive'
        if ($lease.InitialSnapshot.FileIdentity -cne
                $archiveRecord.file_identity -or
            $lease.InitialSnapshot.Length -ne $archiveRecord.bytes -or
            $lease.InitialSnapshot.Sha256 -cne $archiveRecord.sha256) {
            $lease.Handle.Dispose()
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_CHANGED' `
                "quarantine archive changed while establishing terminal evidence lease: $($archiveRecord.path)" `
                'preserve marker/source/recovery evidence and investigate exact archive drift'
        }
        $subordinateArchiveLeases += $lease
        $terminalFileHandles += $lease.Handle
    }

    $targetArchiveResult = $null
    if (-not $recognizedReclaimMarker) {
        $reclaimPhase = 'ordinary-source-exact-archive'
        $targetArchiveResult = Move-AstroRetainedLeaseNoReplace `
            $sourceRenameLease `
            $archiveDirectoryHandle `
            $archiveFull `
            $initial `
            'authorized launcher protocol source'
        $terminalFileHandles +=
            $targetArchiveResult.ObserverLease.Handle
        $archive = $targetArchiveResult.ObserverSnapshot
    }
    else {
        # A recognized interrupted marker is itself the sole target authorized by
        # this invocation. Its bound original source/archive remains immutable and
        # is never silently completed under evidence that names only the marker.
        $archive = $null
    }

    $activePost = Get-AstroPathEntryState $activeLock
    $transitionPost = Get-AstroLauncherLockTransitions $activeLock
    if ($transitionPost.State -eq 'unevaluable') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_POSTSTATE_UNEVALUABLE' `
            $transitionPost.Error `
            'preserve recovery state and repair protocol-directory access'
    }
    if ($transitionPost.State -cne 'present') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_CONFLICT' `
            "pre-commit transition inventory is not exact present state (state=$($transitionPost.State), error=$($transitionPost.Error))" `
            'preserve all state; the retained reclaim marker must remain classifier-visible and canonical until commit'
    }
    $expectedActivePost = if ($recognizedReclaimMarker -and
        $null -ne $markerProtectedSourceSnapshot -and $sourceIsActive) {
        'present'
    } else { 'absent' }
    if ($activePost.State -ne $expectedActivePost) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_CONFLICT' `
            "pre-commit active state '$($activePost.State)' differs from expected '$expectedActivePost'" `
            'preserve all state and investigate the unexpected protocol writer'
    }
    [string[]]$expectedActivePostPaths = @()
    if ($expectedActivePost -ceq 'present') {
        $expectedActivePostPaths = [string[]]@($activeLock)
    }
    [string[]]$actualActivePostPaths = @($transitionPost.ActivePaths)
    $activePostSetMatches = $actualActivePostPaths.Count -eq
        $expectedActivePostPaths.Count
    foreach ($path in $expectedActivePostPaths) {
        if (-not ($actualActivePostPaths -ccontains $path)) {
            $activePostSetMatches = $false
        }
    }
    if (-not $activePostSetMatches) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_NONCANONICAL' `
            "pre-commit active inventory spelling differs from the exact expected set: $($actualActivePostPaths -join '; ')" `
            'preserve all state; case drift or active-path aliases never authorize marker commit'
    }
    $expectedPostTransitions = @($otherTransitions) + @($reclaimMarker)
    $actualPostTransitions = @($transitionPost.Paths)
    $transitionSetMatches = $actualPostTransitions.Count -eq
        $expectedPostTransitions.Count
    foreach ($path in $expectedPostTransitions) {
        if (-not ($actualPostTransitions -ccontains $path)) {
            $transitionSetMatches = $false
        }
    }
    if (-not $transitionSetMatches) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_CONFLICT' `
            "pre-commit transition inventory differs from the exact protected set plus the target marker: $($actualPostTransitions -join '; ')" `
            'preserve all state and investigate the unexpected protocol writer'
    }
    $completion = [ordered]@{
        schema = 'astrolabe.launcher-lock-recovery.completion.v6'
        phase = if ($recognizedReclaimMarker) {
            'recognized-marker-archive-authorized'
        } else {
            'source-archive-committed-marker-archive-authorized'
        }
        authorized_at_utc = [DateTime]::UtcNow.ToString('o')
        transaction_id = $recoveryTransactionId
        recovery_branch = if ($recognizedReclaimMarker) {
            'recognized-marker'
        } else { 'ordinary-source' }
        tracker = [ordered]@{
            url = $trackerSecond.Url
            comment_id = $trackerSecond.Id
            updated_at = $trackerSecond.UpdatedAt
            body_sha256 = $trackerSecond.BodySha256
        }
        authorization = [ordered]@{
            path = $recordFull
            bytes = $authorizationLease.InitialSnapshot.Length
            sha256 = $authorizationLease.InitialSnapshot.Sha256
            file_identity =
                $authorizationLease.InitialSnapshot.FileIdentity
        }
        finalization = [ordered]@{
            path = $finalizationFull
            bytes = $finalizationReadback.Snapshot.Length
            sha256 = $finalizationReadback.Snapshot.Sha256
            file_identity =
                $finalizationLease.InitialSnapshot.FileIdentity
        }
        target_marker = [ordered]@{
            path = $reclaimMarker
            bytes = $markerSnapshot.Length
            sha256 = $markerSnapshot.Sha256
            file_identity = $markerSnapshot.FileIdentity
            transaction_id = $markerTransactionId
            archive_path = $markerArchiveDestination
            archive_authorized = $true
        }
        post_publication_pid_probe = $secondProbe
        post_publication_attribution_probe = $secondAttributionProbe
        subordinate_cleanup = [ordered]@{
            plan_sha256 = $subordinateCleanupResult.PlanSha256
            initial_state = $subordinateCleanupResult.InitialState
            terminal_state = $subordinateCleanupResult.TerminalState
            actions = $subordinateCleanupResult.Actions
            quarantine_archives =
                $subordinateCleanupResult.QuarantineArchives
            terminal_probe = $subordinateCleanupResult.TerminalProbe
        }
        recovered_target = [ordered]@{
            path = $lockFull
            source_archive_committed = -not $recognizedReclaimMarker
        }
        source_archive = if (-not $recognizedReclaimMarker) {
            [ordered]@{
                path = $archiveFull
                bytes = $archive.Length
                sha256 = $archive.Sha256
                file_identity = $archive.FileIdentity
            }
        } else { $null }
        protected_interrupted_transaction = if ($recognizedReclaimMarker) {
            [ordered]@{
                transaction_id = $reclaimMarkerEnvelope.TransactionId
                disposition = if ($null -ne $markerProtectedSourceSnapshot) {
                    'source-present'
                } else { 'source-archived' }
                path = $markerProtectedLease.OriginalPath
                bytes = $markerProtectedLease.InitialSnapshot.Length
                sha256 = $markerProtectedLease.InitialSnapshot.Sha256
                file_identity =
                    $markerProtectedLease.InitialSnapshot.FileIdentity
            }
        } else { $null }
        expected_final_protocol = [ordered]@{
            active_state = $expectedActivePost
            transition_paths = @($otherTransitions)
        }
        protocol_before_marker_commit = [ordered]@{
            active_path = $activeLock
            active_state = $activePost.State
            transition_state = $transitionPost.State
            transition_paths = @($transitionPost.Paths)
        }
    }
    $completionReadback = Write-NewDurableJsonAndReadBack `
        -LiteralPath $completionFull `
        -Value $completion `
        -Description 'reclaim completion commit record' `
        -StageDirectoryPath $recoveryRoot `
        -StageDirectoryHandle $archiveDirectoryHandle `
        -DestinationDirectoryHandle $archiveDirectoryHandle
    $terminalFileHandles += $completionReadback.PublicationLease.Handle
    if ([string]$completionReadback.Persisted.transaction_id -cne
        $recoveryTransactionId) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRANSACTION_MISMATCH' `
            'completion durable JSON readback lost its exact transaction_id binding' `
            'preserve every recovery/protocol entry and investigate serialization/storage'
    }
    $completionLease = Open-AstroExactEvidenceLease `
        $completionFull `
        'reclaim completion authorization record'
    $terminalFileHandles += $completionLease.Handle
    if ($completionLease.InitialSnapshot.Sha256 -cne
            $completionReadback.Snapshot.Sha256 -or
        -not (Test-ByteArraysEqual `
            $completionLease.InitialSnapshot.Bytes `
            $completionReadback.Snapshot.Bytes)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_COMPLETION_CHANGED' `
            'completion authorization bytes changed while establishing the immutable evidence lease' `
            'preserve every recovery/protocol entry and investigate concurrent modification'
    }

    $authorizationTerminal = Get-AstroExactRenameLeaseSnapshot `
        $authorizationLease `
        'authorization before marker archive'
    $finalizationTerminal = Get-AstroExactRenameLeaseSnapshot `
        $finalizationLease `
        'finalization before marker archive'
    $completionTerminal = Get-AstroExactRenameLeaseSnapshot `
        $completionLease `
        'completion before marker archive'
    if ($authorizationTerminal.FileIdentity -cne
            $authorizationLease.InitialSnapshot.FileIdentity -or
        $authorizationTerminal.Sha256 -cne
            $authorizationLease.InitialSnapshot.Sha256 -or
        -not (Test-ByteArraysEqual `
            $authorizationTerminal.Bytes `
            $authorizationLease.InitialSnapshot.Bytes) -or
        $finalizationTerminal.FileIdentity -cne
            $finalizationLease.InitialSnapshot.FileIdentity -or
        $finalizationTerminal.Sha256 -cne
            $finalizationLease.InitialSnapshot.Sha256 -or
        -not (Test-ByteArraysEqual `
            $finalizationTerminal.Bytes `
            $finalizationLease.InitialSnapshot.Bytes) -or
        $completionTerminal.FileIdentity -cne
            $completionLease.InitialSnapshot.FileIdentity -or
        $completionTerminal.Sha256 -cne
            $completionLease.InitialSnapshot.Sha256 -or
        -not (Test-ByteArraysEqual `
            $completionTerminal.Bytes `
            $completionLease.InitialSnapshot.Bytes)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TERMINAL_READBACK_FAILED' `
            'immutable authorization/finalization/completion evidence changed before the authorized marker archive' `
            'preserve every recovery and protocol entry; investigate the exact FILE_ID/byte drift'
    }

    foreach ($linkedLease in @($linkedMarkerLeases)) {
        $linkedTerminal = Get-AstroExactRenameLeaseSnapshot `
            $linkedLease `
            'linked interrupted-transaction evidence before marker archive'
        if ($linkedTerminal.FileIdentity -cne
                $linkedLease.InitialSnapshot.FileIdentity -or
            $linkedTerminal.Sha256 -cne
                $linkedLease.InitialSnapshot.Sha256 -or
            -not [string]::Equals(
                $linkedTerminal.Path,
                $linkedLease.InitialSnapshot.Path,
                [StringComparison]::Ordinal
            ) -or
            -not (Test-ByteArraysEqual `
                $linkedTerminal.Bytes `
                $linkedLease.InitialSnapshot.Bytes)) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_RECORD_MISMATCH' `
                'linked interrupted-transaction evidence changed before marker archive' `
                'preserve every entry and investigate the exact linked FILE_ID/byte drift'
        }
    }
    for ($index = 0; $index -lt $subordinateArchiveLeases.Count; $index++) {
        $lease = $subordinateArchiveLeases[$index]
        $expectedArchive = $subordinateCleanupResult.QuarantineArchives[$index]
        $snapshot = Get-AstroExactRenameLeaseSnapshot `
            $lease `
            'malformed-stage archive before marker disposition'
        if ($snapshot.FileIdentity -cne $expectedArchive.file_identity -or
            $snapshot.Length -ne $expectedArchive.bytes -or
            $snapshot.Sha256 -cne $expectedArchive.sha256 -or
            -not [string]::Equals(
                $snapshot.Path,
                $expectedArchive.path,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_CHANGED' `
                'retained malformed-stage archive changed before marker disposition' `
                'preserve all state and investigate exact archive FILE_ID/path/byte drift'
        }
    }
    if ($recognizedReclaimMarker) {
        $protectedBeforeMove = Get-AstroExactRenameLeaseSnapshot `
            $markerProtectedLease `
            'protected interrupted-transaction source before marker archive'
        if ($protectedBeforeMove.FileIdentity -cne
                $markerProtectedLease.InitialSnapshot.FileIdentity -or
            $protectedBeforeMove.Sha256 -cne
                $markerProtectedLease.InitialSnapshot.Sha256 -or
            -not (Test-ByteArraysEqual `
                $protectedBeforeMove.Bytes `
                $markerProtectedLease.InitialSnapshot.Bytes)) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_SOURCE_MISMATCH' `
                'protected interrupted-transaction source/archive changed before marker archive' `
                'preserve every entry and investigate the exact protected FILE_ID/byte drift'
        }
    }

    $markerMoveLease = if ($recognizedReclaimMarker) {
        $sourceRenameLease
    } else { $markerRenameLease }
    $markerMoveExpected = if ($recognizedReclaimMarker) {
        $initial
    } else { $markerSnapshot }
    $reclaimPhase = 'authorized-marker-exact-archive'
    $markerArchiveResult = Move-AstroRetainedLeaseNoReplace `
        $markerMoveLease `
        $archiveDirectoryHandle `
        $markerArchiveDestination `
        $markerMoveExpected `
        'authorized classifier-visible reclaim marker'
    $terminalFileHandles += $markerArchiveResult.ObserverLease.Handle
    $markerArchiveTerminal = $markerArchiveResult.ObserverSnapshot
    if ($recognizedReclaimMarker) {
        $archive = $markerArchiveTerminal
    }

    $transitionFinal = Get-AstroLauncherLockTransitions $activeLock
    if ($transitionFinal.State -eq 'unevaluable') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_POSTSTATE_UNEVALUABLE' `
            $transitionFinal.Error `
            'preserve committed recovery state and repair protocol-directory access'
    }
    $expectedTransitionFinalState = if (@($otherTransitions).Count -eq 0) {
        'clear'
    } else { 'present' }
    if ($transitionFinal.State -cne $expectedTransitionFinalState) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_CONFLICT' `
            "final transition classifier state '$($transitionFinal.State)' differs from expected '$expectedTransitionFinalState' (error=$($transitionFinal.Error))" `
            'preserve committed recovery state and investigate noncanonical or colliding protocol entries'
    }
    $activeFinal = Get-AstroPathEntryState $activeLock
    if ($activeFinal.State -ne $expectedActivePost) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_CONFLICT' `
            "final active state '$($activeFinal.State)' differs from durable expected state '$expectedActivePost'" `
            'preserve committed recovery state and investigate the unexpected protocol writer'
    }
    [string[]]$actualActiveFinalPaths = @($transitionFinal.ActivePaths)
    $activeFinalSetMatches = $actualActiveFinalPaths.Count -eq
        $expectedActivePostPaths.Count
    foreach ($path in $expectedActivePostPaths) {
        if (-not ($actualActiveFinalPaths -ccontains $path)) {
            $activeFinalSetMatches = $false
        }
    }
    if (-not $activeFinalSetMatches) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_NONCANONICAL' `
            "final active inventory spelling differs from the exact durable set: $($actualActiveFinalPaths -join '; ')" `
            'preserve committed recovery state and investigate case drift or active-path aliases'
    }
    foreach ($finalTransitionItem in @($transitionFinal.Items)) {
        if (-not $finalTransitionItem.Valid) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_NONCANONICAL' `
                "final preserved transition is malformed or case-drifted: $($finalTransitionItem.Path) ($($finalTransitionItem.ValidationError))" `
                'preserve committed recovery state; terminal protocol entries must retain exact canonical spelling and schema'
        }
    }
    $finalSetMatches = @($transitionFinal.Paths).Count -eq
        @($otherTransitions).Count
    foreach ($path in $otherTransitions) {
        if (-not (@($transitionFinal.Paths) -ccontains $path)) {
            $finalSetMatches = $false
        }
    }
    if (-not $finalSetMatches) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_CONFLICT' `
            "final transition inventory differs from the pre-existing preserved set: $(@($transitionFinal.Paths) -join '; ')" `
            'preserve committed recovery state and investigate the unexpected protocol writer'
    }

    if ($recognizedReclaimMarker) {
        $protectedTerminal = Get-AstroExactRenameLeaseSnapshot `
            $markerProtectedLease `
            'protected interrupted-transaction source after marker archive'
        if ($protectedTerminal.FileIdentity -cne
                $markerProtectedLease.InitialSnapshot.FileIdentity -or
            $protectedTerminal.Sha256 -cne
                $markerProtectedLease.InitialSnapshot.Sha256 -or
            -not (Test-ByteArraysEqual `
                $protectedTerminal.Bytes `
                $markerProtectedLease.InitialSnapshot.Bytes) -or
            -not [string]::Equals(
                $protectedTerminal.Path,
                $markerProtectedLease.InitialSnapshot.Path,
                [StringComparison]::Ordinal
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_SOURCE_MISMATCH' `
                'protected original source/archive changed while archiving its interrupted marker' `
                'preserve all evidence and investigate the exact protected FILE_ID/path/byte drift'
        }
    }

    $authorizationTerminal = Get-AstroExactRenameLeaseSnapshot `
        $authorizationLease `
        'authorization terminal readback'
    $finalizationTerminal = Get-AstroExactRenameLeaseSnapshot `
        $finalizationLease `
        'finalization terminal readback'
    $completionTerminal = Get-AstroExactRenameLeaseSnapshot `
        $completionLease `
        'completion terminal readback'
    if ($authorizationTerminal.FileIdentity -cne
            $authorizationLease.InitialSnapshot.FileIdentity -or
        $authorizationTerminal.Sha256 -cne
            $authorizationLease.InitialSnapshot.Sha256 -or
        -not (Test-ByteArraysEqual `
            $authorizationTerminal.Bytes `
            $authorizationLease.InitialSnapshot.Bytes) -or
        $finalizationTerminal.FileIdentity -cne
            $finalizationLease.InitialSnapshot.FileIdentity -or
        $finalizationTerminal.Sha256 -cne
            $finalizationLease.InitialSnapshot.Sha256 -or
        -not (Test-ByteArraysEqual `
            $finalizationTerminal.Bytes `
            $finalizationLease.InitialSnapshot.Bytes) -or
        $completionTerminal.FileIdentity -cne
            $completionLease.InitialSnapshot.FileIdentity -or
        $completionTerminal.Sha256 -cne
            $completionLease.InitialSnapshot.Sha256 -or
        -not (Test-ByteArraysEqual `
            $completionTerminal.Bytes `
            $completionLease.InitialSnapshot.Bytes)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TERMINAL_READBACK_FAILED' `
            'terminal retained-handle evidence differs from the immutable authorization/finalization/completion commits' `
            'preserve all state and investigate exact FILE_ID/path/byte drift'
    }
    foreach ($linkedLease in @($linkedMarkerLeases)) {
        $linkedTerminal = Get-AstroExactRenameLeaseSnapshot `
            $linkedLease `
            'linked interrupted-transaction terminal readback'
        if ($linkedTerminal.FileIdentity -cne
                $linkedLease.InitialSnapshot.FileIdentity -or
            $linkedTerminal.Sha256 -cne
                $linkedLease.InitialSnapshot.Sha256 -or
            -not [string]::Equals(
                $linkedTerminal.Path,
                $linkedLease.InitialSnapshot.Path,
                [StringComparison]::Ordinal
            ) -or
            -not (Test-ByteArraysEqual `
                $linkedTerminal.Bytes `
                $linkedLease.InitialSnapshot.Bytes)) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TERMINAL_READBACK_FAILED' `
                'linked interrupted-transaction terminal evidence changed' `
                'preserve all state and investigate exact linked FILE_ID/path/byte drift'
        }
    }
    $recoveryDirectoryTerminalIdentity =
        [AstroLauncherLockNative]::GetFileIdentity($archiveDirectoryHandle)
    $recoveryDirectoryTerminalPath = ConvertTo-AstroComparableFinalPath (
        [AstroLauncherLockNative]::GetFileFinalPath(
            $archiveDirectoryHandle
        )
    )
    if ($recoveryDirectoryTerminalIdentity -cne
            $recoveryDirectoryIdentity -or
        -not [string]::Equals(
            $recoveryDirectoryTerminalPath,
            $recoveryDirectoryFinalPath,
            [StringComparison]::Ordinal
        )) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TERMINAL_READBACK_FAILED' `
            'retained recovery-directory FILE_ID/final path changed across the transaction' `
            'preserve all state and investigate the exact directory identity boundary'
    }
    try {
        $protocolDirectoryTerminalIdentity =
            [AstroLauncherLockNative]::GetFileIdentity(
                $protocolDirectoryHandle
            )
        $protocolDirectoryTerminalPath = ConvertTo-AstroComparableFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath(
                $protocolDirectoryHandle
            )
        )
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TERMINAL_READBACK_FAILED' `
            "retained protocol-directory terminal read failed: $($_.Exception.Message)" `
            'preserve all state and investigate exact .tmp directory-handle access'
    }
    if ($protocolDirectoryTerminalIdentity -cne
            $protocolDirectoryIdentity -or
        -not [string]::Equals(
            $protocolDirectoryTerminalPath,
            $protocolDirectoryFinalPath,
            [StringComparison]::Ordinal
        )) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TERMINAL_READBACK_FAILED' `
            'retained protocol-directory FILE_ID/final path changed across the transaction' `
            'preserve all state and investigate exact .tmp directory replacement or alias drift'
    }
    if (-not $recognizedReclaimMarker) {
        $archiveTerminal = Get-AstroExactRenameLeaseSnapshot `
            $sourceRenameLease `
            'source archive terminal readback'
        if ($archiveTerminal.FileIdentity -cne $initial.FileIdentity -or
            $archiveTerminal.Sha256 -cne $initial.Sha256 -or
            -not (Test-ByteArraysEqual $archiveTerminal.Bytes $initial.Bytes) -or
            -not [string]::Equals(
                $archiveTerminal.Path,
                $archiveFull,
                [StringComparison]::Ordinal
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TERMINAL_READBACK_FAILED' `
                'ordinary source archive differs from the exact authorized source at terminal readback' `
                'preserve every recovery archive and investigate FILE_ID/path/byte drift'
        }
    }
    else {
        $archiveTerminal = $markerArchiveResult.RetainedSnapshot
    }
    $markerRetainedTerminal = Get-AstroExactRenameLeaseSnapshot `
        $markerMoveLease `
        'authorized reclaim marker retained terminal readback'
    $markerObserverTerminal = Get-AstroExactRenameLeaseSnapshot `
        $markerArchiveResult.ObserverLease `
        'authorized reclaim marker observer terminal readback'
    $terminalMarkerSnapshots = @(
        $markerRetainedTerminal,
        $markerObserverTerminal
    )
    if (-not $recognizedReclaimMarker) {
        $markerPublicationObserverTerminal =
            Get-AstroExactRenameLeaseSnapshot `
                $markerPublicationResult.ObserverLease `
                'published reclaim marker original observer terminal readback'
        $terminalMarkerSnapshots += $markerPublicationObserverTerminal
    }
    foreach ($terminalMarkerSnapshot in @($terminalMarkerSnapshots)) {
        if ($terminalMarkerSnapshot.FileIdentity -cne
                $markerSnapshot.FileIdentity -or
            $terminalMarkerSnapshot.Length -ne $markerSnapshot.Length -or
            $terminalMarkerSnapshot.Sha256 -cne $markerSnapshot.Sha256 -or
            -not (Test-ByteArraysEqual `
                $terminalMarkerSnapshot.Bytes `
                $markerSnapshot.Bytes) -or
            -not [string]::Equals(
                $terminalMarkerSnapshot.Path,
                $markerArchiveDestination,
                [StringComparison]::Ordinal
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_MARKER_TERMINAL_MISMATCH' `
                'retained or independently opened marker archive differs from the exact authorized marker bytes/FILE_ID/path' `
                'preserve every recovery entry and investigate marker archive drift before any new claim'
        }
    }
    for ($index = 0; $index -lt $subordinateArchiveLeases.Count; $index++) {
        $snapshot = Get-AstroExactRenameLeaseSnapshot `
            $subordinateArchiveLeases[$index] `
            'malformed-stage archive terminal readback'
        $expectedArchive = $subordinateCleanupResult.QuarantineArchives[$index]
        if ($snapshot.FileIdentity -cne $expectedArchive.file_identity -or
            $snapshot.Length -ne $expectedArchive.bytes -or
            $snapshot.Sha256 -cne $expectedArchive.sha256 -or
            -not [string]::Equals(
                $snapshot.Path,
                $expectedArchive.path,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SUBORDINATE_CHANGED' `
                'malformed-stage archive changed across terminal marker disposition' `
                'preserve every recovery entry and investigate exact archive drift'
        }
    }
    $markerArchiveTerminal = $markerObserverTerminal

    $result = [ordered]@{
        operation = 'reclaim-launcher-lock'
        verdict = 'archived'
        transaction_id = $recoveryTransactionId
        recovery_branch = if ($recognizedReclaimMarker) {
            'recognized-marker'
        } else { 'ordinary-source' }
        tracker_comment_url = $TrackerCommentUrl
        subordinate_cleanup = [ordered]@{
            plan_sha256 = $subordinateCleanupResult.PlanSha256
            initial_state = $subordinateCleanupResult.InitialState
            terminal_state = $subordinateCleanupResult.TerminalState
            actions = $subordinateCleanupResult.Actions
            quarantine_archives =
                $subordinateCleanupResult.QuarantineArchives
            terminal_probe = $subordinateCleanupResult.TerminalProbe
        }
        mutex = [ordered]@{
            name = $mutexLease.Name
            root_identity = $mutexLease.RootIdentity
            root_final_path = $mutexLease.RootFinalPath
            recovered_abandoned_owner = [bool]$mutexLease.WasAbandoned
        }
        authorization = [ordered]@{
            path = $recordFull
            bytes = $authorizationTerminal.Length
            sha256 = $authorizationTerminal.Sha256
            file_identity = $authorizationTerminal.FileIdentity
        }
        finalization = [ordered]@{
            path = $finalizationFull
            bytes = $finalizationTerminal.Length
            sha256 = $finalizationTerminal.Sha256
            file_identity = $finalizationTerminal.FileIdentity
        }
        completion = [ordered]@{
            path = $completionFull
            bytes = $completionTerminal.Length
            sha256 = $completionTerminal.Sha256
            file_identity = $completionTerminal.FileIdentity
        }
        archive = [ordered]@{
            path = if ($recognizedReclaimMarker) {
                $markerArchiveFull
            } else { $archiveFull }
            bytes = $archiveTerminal.Length
            sha256 = $archiveTerminal.Sha256
            file_identity = $archiveTerminal.FileIdentity
        }
        marker_archive = [ordered]@{
            path = $markerArchiveDestination
            bytes = $markerArchiveTerminal.Length
            sha256 = $markerArchiveTerminal.Sha256
            file_identity = $markerArchiveTerminal.FileIdentity
        }
        reclaim_marker = [ordered]@{
            path = $reclaimMarker
            exists = $false
        }
        recovered_target = [ordered]@{
            path = $lockFull
            exists = $false
        }
        protected_interrupted_transaction = if ($recognizedReclaimMarker) {
            [ordered]@{
                transaction_id = $reclaimMarkerEnvelope.TransactionId
                path = $markerProtectedLease.InitialSnapshot.Path
                file_identity =
                    $markerProtectedLease.InitialSnapshot.FileIdentity
                bytes = $markerProtectedLease.InitialSnapshot.Length
                sha256 = $markerProtectedLease.InitialSnapshot.Sha256
                unchanged = $true
            }
        } else { $null }
        protocol_final = [ordered]@{
            active_state = $activeFinal.State
            transition_state = $transitionFinal.State
            transition_paths = @($transitionFinal.Paths)
        }
    }
}
catch {
    $failure = $_
}
finally {
    $disposalFaults = [Collections.Generic.List[string]]::new()
    foreach ($handle in @($terminalFileHandles)) {
        if ($null -ne $handle) {
            try { $handle.Dispose() } catch {
                $disposalFaults.Add("terminal evidence handle: $($_.Exception.Message)")
            }
        }
    }
    if ($null -ne $markerRenameLease -and
        $null -ne $markerRenameLease.Handle) {
        try { $markerRenameLease.Handle.Dispose() } catch {
            $disposalFaults.Add("marker rename lease: $($_.Exception.Message)")
        }
    }
    if ($null -ne $sourceRenameLease -and
        $null -ne $sourceRenameLease.Handle) {
        try { $sourceRenameLease.Handle.Dispose() } catch {
            $disposalFaults.Add("source rename lease: $($_.Exception.Message)")
        }
    }
    if ($null -ne $archiveDirectoryHandle) {
        try { $archiveDirectoryHandle.Dispose() } catch {
            $disposalFaults.Add("recovery directory handle: $($_.Exception.Message)")
        }
    }
    if ($null -ne $protocolDirectoryHandle) {
        try { $protocolDirectoryHandle.Dispose() } catch {
            $disposalFaults.Add("protocol directory handle: $($_.Exception.Message)")
        }
    }
    if ($null -ne $mutexLease) {
        try {
            Exit-AstroLauncherLockMutex $mutexLease
        }
        catch {
            if ($null -eq $failure) {
                $failure = $_
                $failure.Exception.Data['AstroCode'] =
                    'ASTRO_LAUNCHER_LOCK_RECLAIM_MUTEX_RELEASE_FAILED'
                $failure.Exception.Data['AstroRemediation'] =
                    'preserve all state and inspect the exact machine-wide mutex release failure'
            }
        }
    }
    if ($disposalFaults.Count -gt 0) {
        if ($null -eq $failure) {
            $disposeException = [InvalidOperationException]::new(
                'one or more retained-handle disposals failed: ' +
                    ($disposalFaults -join '; ')
            )
            $disposeException.Data['AstroCode'] =
                'ASTRO_LAUNCHER_LOCK_RECLAIM_DISPOSAL_FAILED'
            $disposeException.Data['AstroRemediation'] =
                'preserve all state and inspect exact retained-handle release failures before retrying'
            $failure = [Management.Automation.ErrorRecord]::new(
                $disposeException,
                'AstroLauncherLockReclaimDisposalFailed',
                [Management.Automation.ErrorCategory]::CloseError,
                $null
            )
        }
        else {
            $failure.Exception.Data['AstroDisposalFaults'] =
                [string]($disposalFaults -join '; ')
        }
    }
}

if ($null -ne $failure) {
    $code = if ($failure.Exception.Data.Contains('AstroCode')) {
        [string]$failure.Exception.Data['AstroCode']
    } else {
        'ASTRO_LAUNCHER_LOCK_RECLAIM_FAULT'
    }
    $remediation = if ($failure.Exception.Data.Contains('AstroRemediation')) {
        [string]$failure.Exception.Data['AstroRemediation']
    } else {
        'preserve the lock and recovery state; inspect the exact fault before retrying'
    }
    $payload = [ordered]@{
        code = $code
        message = $failure.Exception.Message
        remediation = $remediation
        phase = $reclaimPhase
        exception_type = $failure.Exception.GetType().FullName
        fully_qualified_error_id = $failure.FullyQualifiedErrorId
        script_stack_trace = $failure.ScriptStackTrace
        disposal_faults = if (
            $failure.Exception.Data.Contains('AstroDisposalFaults')
        ) {
            [string]$failure.Exception.Data['AstroDisposalFaults']
        } else { $null }
    } | ConvertTo-Json -Compress
    [Console]::Error.WriteLine("LAUNCHER_LOCK_RECLAIM[$code]: $payload")
    exit 70
}

$result | ConvertTo-Json -Depth 16 -Compress | Write-Output
