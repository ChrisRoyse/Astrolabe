<#
.SYNOPSIS
    Authoritative Astrolabe launcher-lock protocol (#197, #611).

.DESCRIPTION
    This helper is the only supported launcher-lock parser and claim/reclaim synchronizer.
    It never stops a process and never automatically removes stale state.

    A schema-v2 owner is the exact Windows process identity
    (pid, owner_process_start_utc_ticks). Claim, cleanup, and explicit reclaim serialize on
    one Global Windows mutex whose name is derived from the opened workspace directory's
    filesystem identity, not a lexical path. Live leases retain a read-only, no-write,
    no-delete-share handle to the published manifest.

    Interrupted claim/cleanup names are durable protocol state. They are discovered and
    refused rather than ignored. Only the explicit tracker-evidenced reclaim/quarantine
    command may archive them.
#>

if (-not ('AstroLauncherLockNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class AstroLauncherLockNative
{
    private const uint FILE_READ_ATTRIBUTES = 0x0080;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

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
    public static extern bool MoveFileExW(
        string existingFileName,
        string newFileName,
        uint flags
    );

    private static SafeFileHandle OpenDirectory(string path)
    {
        SafeFileHandle handle = CreateFileW(
            path,
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

    public static string GetDirectoryIdentity(string path)
    {
        using (SafeFileHandle handle = OpenDirectory(path))
        {
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(handle, out information))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "could not read directory file identity: " + path
                );
            }
            return String.Format(
                System.Globalization.CultureInfo.InvariantCulture,
                "{0:x8}:{1:x8}:{2:x8}",
                information.VolumeSerialNumber,
                information.FileIndexHigh,
                information.FileIndexLow
            );
        }
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
}
'@
}

function Get-AstroByteSha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)

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

function Get-AstroLauncherLockMutexName {
    param([Parameter(Mandatory)][string]$LockPath)

    $root = Get-AstroLauncherRootFromLockPath $LockPath
    $identity = [AstroLauncherLockNative]::GetDirectoryIdentity($root)
    $identityBytes = [Text.Encoding]::UTF8.GetBytes(
        "astrolabe.launcher-lock.v2|$identity"
    )
    $digest = Get-AstroByteSha256 $identityBytes
    return "Global\Astrolabe.LauncherLock.$digest"
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

    $name = Get-AstroLauncherLockMutexName $LockPath
    $security = New-AstroLauncherLockMutexSecurity
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
            Root = Get-AstroLauncherRootFromLockPath $LockPath
            RootFinalPath = [AstroLauncherLockNative]::GetDirectoryFinalPath(
                (Get-AstroLauncherRootFromLockPath $LockPath)
            )
        }
    }
    catch {
        $mutex.Dispose()
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
        $Lease.Mutex.Dispose()
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

function Get-AstroPathEntryState {
    param([Parameter(Mandatory)][string]$LiteralPath)

    try {
        $attributes = [IO.File]::GetAttributes([IO.Path]::GetFullPath($LiteralPath))
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
            $full,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            $Share
        )
    }
    catch {
        throw "could not open '$full' for an exact read snapshot: $($_.Exception.Message)"
    }
    try {
        if ($stream.Length -gt 1048576) {
            throw "launcher protocol file exceeds 1 MiB safety limit: $full ($($stream.Length) bytes)"
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

function Test-AstroJsonIntegerType {
    param($Value)

    if ($null -eq $Value) {
        return $false
    }
    $type = $Value.GetType()
    return $type -eq [int] -or $type -eq [long]
}

function Test-AstroExactJsonStringToken {
    param(
        [Parameter(Mandatory)][string]$RawJson,
        [Parameter(Mandatory)][string]$Property,
        [Parameter(Mandatory)][string]$ExpectedValue
    )

    $pattern = '(?<!\\)"' + [Regex]::Escape($Property) +
        '"\s*:\s*"' + [Regex]::Escape($ExpectedValue) + '"'
    return [Regex]::Matches($RawJson, $pattern).Count -eq 1
}

function Convert-AstroLauncherLockBytesToState {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$LockPath
    )

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
        $manifest = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = "invalid launcher-lock JSON: $($_.Exception.Message)"
            RawJson = $raw
        }
    }
    if ($null -eq $manifest -or
        $manifest -is [Array] -or
        $manifest -isnot [Management.Automation.PSCustomObject]) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'launcher-lock JSON root must be one object'
            RawJson = $raw
        }
    }

    $requiredNames = @(
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
    $actualNames = @($manifest.PSObject.Properties | ForEach-Object { $_.Name })
    $nameValid = $actualNames.Count -eq $requiredNames.Count
    foreach ($name in $requiredNames) {
        if (-not ($actualNames -ccontains $name)) {
            $nameValid = $false
        }
        $propertyPattern = '(?<!\\)"' + [Regex]::Escape($name) + '"\s*:'
        if ([Regex]::Matches($raw, $propertyPattern).Count -ne 1) {
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
            ValidationError = 'launcher-lock JSON must contain exactly the v2 property set, once each'
            RawJson = $raw
        }
    }

    if ($manifest.schema -isnot [string] -or
        [string]$manifest.schema -cne 'astrolabe.launcher-lock.v2') {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'schema must be the JSON string astrolabe.launcher-lock.v2'
            RawJson = $raw
        }
    }
    if (-not (Test-AstroJsonIntegerType $manifest.pid) -or
        [long]$manifest.pid -le 0 -or [long]$manifest.pid -gt [int]::MaxValue) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'pid must be a positive integral JSON number in the Int32 range'
            RawJson = $raw
        }
    }
    if (-not (Test-AstroJsonIntegerType $manifest.issue) -or
        [long]$manifest.issue -le 0 -or [long]$manifest.issue -gt [int]::MaxValue) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'issue must be a positive integral JSON number in the Int32 range'
            RawJson = $raw
        }
    }
    if (-not (Test-AstroJsonIntegerType $manifest.lease_start_utc_ticks) -or
        -not (Test-AstroJsonIntegerType $manifest.owner_process_start_utc_ticks)) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'lease/process UTC ticks must be integral JSON numbers'
            RawJson = $raw
        }
    }

    $leaseTicks = [long]$manifest.lease_start_utc_ticks
    $ownerTicks = [long]$manifest.owner_process_start_utc_ticks
    if ($leaseTicks -le 0 -or $leaseTicks -gt [DateTime]::MaxValue.Ticks -or
        $ownerTicks -le 0 -or $ownerTicks -gt [DateTime]::MaxValue.Ticks) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'lease/process UTC ticks are outside the DateTime range'
            RawJson = $raw
        }
    }
    $leaseIso = ConvertTo-AstroProcessStartUtcIso $leaseTicks
    $ownerIso = ConvertTo-AstroProcessStartUtcIso $ownerTicks
    if (-not (Test-AstroExactJsonStringToken $raw 'started' $leaseIso) -or
        -not (Test-AstroExactJsonStringToken $raw 'owner_process_started_utc' $ownerIso)) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'ISO diagnostics must be exact JSON strings derived from their UTC ticks'
            RawJson = $raw
        }
    }
    if ($manifest.command -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$manifest.command)) {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'command must be a nonblank JSON string'
            RawJson = $raw
        }
    }
    foreach ($field in @('head_sha', 'status_sha256', 'diff_sha256')) {
        if ($manifest.$field -isnot [string]) {
            return [pscustomobject]@{
                State = 'unreadable'
                ValidationError = "$field must be a JSON string"
                RawJson = $raw
            }
        }
    }
    if ([string]$manifest.head_sha -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$manifest.status_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$manifest.diff_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        return [pscustomobject]@{
            State = 'unreadable'
            ValidationError = 'evidence fingerprint hashes are incomplete or malformed'
            RawJson = $raw
        }
    }

    $ownerPid = [int][long]$manifest.pid
    $probe = Get-AstroProcessIdentityProbe $ownerPid
    $state = if ($probe.State -eq 'absent') {
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
        Schema = [string]$manifest.schema
        OwnerPid = $ownerPid
        Issue = [int][long]$manifest.issue
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
        Command = [string]$manifest.command
        Started = $leaseIso
        HeadSha = [string]$manifest.head_sha
        StatusSha256 = [string]$manifest.status_sha256
        DiffSha256 = [string]$manifest.diff_sha256
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
    $directoryState = Get-AstroPathEntryState $directory
    if ($directoryState.State -eq 'absent') {
        return [pscustomobject]@{ State = 'clear'; Paths = @(); Error = $null }
    }
    if ($directoryState.State -ne 'present') {
        return [pscustomobject]@{
            State = 'unevaluable'
            Paths = @()
            Error = "could not query launcher protocol directory '$directory': $($directoryState.Error)"
        }
    }
    if (($directoryState.Attributes -band [IO.FileAttributes]::Directory) -eq 0) {
        return [pscustomobject]@{
            State = 'unevaluable'
            Paths = @()
            Error = "launcher protocol parent is not a directory: $directory"
        }
    }
    try {
        $prefix = [IO.Path]::GetFileName($lockFull)
        $paths = @(
            [IO.Directory]::EnumerateFileSystemEntries(
                $directory,
                "$prefix.*",
                [IO.SearchOption]::TopDirectoryOnly
            ) |
                Where-Object {
                    [IO.Path]::GetFileName($_) -match
                        '^astrolabe-launcher\.lock\.(claim|cleanup)\.'
                } |
                ForEach-Object { [IO.Path]::GetFullPath($_) } |
                Sort-Object
        )
    }
    catch {
        return [pscustomobject]@{
            State = 'unevaluable'
            Paths = @()
            Error = "could not enumerate launcher protocol transitions in '$directory': $($_.Exception.Message)"
        }
    }
    return [pscustomobject]@{
        State = if ($paths.Count -gt 0) { 'present' } else { 'clear' }
        Paths = $paths
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

    try {
        $snapshot = Get-AstroFileSnapshot $full
    }
    catch {
        return New-AstroLauncherLockState `
            -State 'unevaluable' `
            -ReadError $_.Exception.Message
    }
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
    $result | Add-Member -NotePropertyName Length -NotePropertyValue $snapshot.Length -Force
    $result | Add-Member -NotePropertyName Sha256 -NotePropertyValue $snapshot.Sha256 -Force
    return $result
}

function Read-AstroLauncherLock {
    param([Parameter(Mandatory)][string]$LockPath)

    $transitions = Get-AstroLauncherLockTransitions $LockPath
    if ($transitions.State -eq 'unevaluable') {
        return New-AstroLauncherLockState `
            -State 'unevaluable' `
            -ReadError $transitions.Error
    }
    if ($transitions.State -eq 'present') {
        return New-AstroLauncherLockState `
            -State 'transition' `
            -ValidationError 'interrupted launcher-lock claim/cleanup state requires explicit tracker-evidenced recovery' `
            -TransitionPaths $transitions.Paths
    }
    return Read-AstroLauncherLockFile $LockPath
}

function Open-AstroLauncherLockLease {
    param([Parameter(Mandatory)][string]$LockPath)

    $full = [IO.Path]::GetFullPath($LockPath)
    try {
        # FileShare.Read permits authoritative readers and physically denies write/delete/
        # rename for the full lease lifetime.
        $stream = [IO.File]::Open(
            $full,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
    }
    catch {
        throw "could not open immutable launcher-lock lease handle '$full': $($_.Exception.Message)"
    }
    try {
        if ($stream.Length -gt 1048576) {
            throw "launcher lock exceeds 1 MiB safety limit: $full"
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw "immutable launcher-lock read ended at byte $offset of $($bytes.Length)"
            }
            $offset += $read
        }
        $state = Convert-AstroLauncherLockBytesToState $bytes $full
        if ($state.State -eq 'unreadable') {
            throw "published launcher lock failed strict readback: $($state.ValidationError)"
        }
        return [pscustomobject]@{
            Path = $full
            Stream = $stream
            State = $state
            Length = [uint64]$bytes.Length
            Sha256 = Get-AstroByteSha256 $bytes
            Bytes = $bytes
        }
    }
    catch {
        $stream.Dispose()
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
            throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_TRANSITION_RECOVERY_REQUIRED]: interrupted claim/cleanup state exists and was not changed ($paths); post exact path/hash/process evidence to the owning issue, then archive it with scripts\reclaim-launcher-lock.ps1"
        }
        'unreadable' {
            throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_UNREADABLE]: launcher lock is present but invalid ($($lock.ValidationError)); preserve its exact bytes and use scripts\reclaim-launcher-lock.ps1 -QuarantineUnreadable only after tracker-posted hash and exact dead-owner evidence: $LockPath"
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
