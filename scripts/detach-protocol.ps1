<#
.SYNOPSIS
    Shared exact-state protocol for the Astrolabe detached launcher boundary.

.DESCRIPTION
    Provides create-new durable records, strict scalar-envelope parsing, exact process
    probes, and create-only Task Scheduler registration/readback.  All lifecycle records
    are immutable files below one fresh run directory and form a SHA-256 predecessor chain.

.NOTES
    Refs #616, #1065.
#>

Set-StrictMode -Version Latest

$script:AstroDetachedCanonicalRoot = 'C:\code\Astrolabe'
$script:AstroDetachedStateRoot = Join-Path `
    (Join-Path $script:AstroDetachedCanonicalRoot '.tmp') `
    'detached-runs'
$script:AstroDetachedRecordMaximumBytes = 8MB

$strictJsonHelper = Join-Path $PSScriptRoot 'detach-strict-json.ps1'
if (-not (Test-Path Function:\ConvertFrom-AstroStrictFlatJsonObject)) {
    . $strictJsonHelper
}

function Get-AstroDetachedSha256Bytes {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '').
            ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-AstroDetachedUtf8Bytes {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    return [Text.UTF8Encoding]::new($false, $true).GetBytes($Text)
}

function Get-AstroDetachedCanonicalWindowsPowerShellModulePath {
    $entries = [Collections.Generic.List[string]]::new()
    $documents = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::MyDocuments
    )
    if (-not [string]::IsNullOrWhiteSpace($documents)) {
        $entries.Add((Join-Path $documents 'WindowsPowerShell\Modules'))
    }
    $programFiles = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFiles
    )
    if (-not [string]::IsNullOrWhiteSpace($programFiles)) {
        $entries.Add((Join-Path $programFiles 'WindowsPowerShell\Modules'))
    }
    $entries.Add((Join-Path $env:WINDIR 'system32\WindowsPowerShell\v1.0\Modules'))

    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    return @(
        $entries |
            ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\', '/') } |
            Where-Object { $seen.Add($_) }
    )
}

function Test-AstroDetachedPathListEquivalent {
    param(
        [Parameter(Mandatory)][string[]]$Actual,
        [Parameter(Mandatory)][string[]]$Expected
    )

    if ($Actual.Count -ne $Expected.Count) {
        return $false
    }

    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
                $Actual[$index],
                $Expected[$index]
            )) {
            return $false
        }
    }

    return $true
}

function Initialize-AstroDetachedPowerShellModulePath {
    param([Parameter(Mandatory)][string]$Role)

    $before = [string]$env:PSModulePath
    $beforeEntries = @(
        $before -split ';' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ }
    )
    $requiredModules = @(
        'Microsoft.PowerShell.Security',
        'Microsoft.PowerShell.Utility'
    )
    $edition = [string]$PSVersionTable.PSEdition
    $version = [string]$PSVersionTable.PSVersion
    $policy = [ordered]@{
        schema = 'astrolabe.detached.psmodulepath-policy.v1'
        role = $Role
        powershell_edition = $edition
        powershell_version = $version
        before = $before
        before_entries = [string[]]$beforeEntries
        action = 'preserved'
        canonical_entries = @()
        after = $before
        offending_entries = @()
        imported_modules = @()
        import_error = $null
    }

    if ($edition -ceq 'Desktop') {
        $canonicalEntries = Get-AstroDetachedCanonicalWindowsPowerShellModulePath
        $canonical = $canonicalEntries -join ';'
        $canonicalSet = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        foreach ($entry in $canonicalEntries) {
            [void]$canonicalSet.Add($entry.TrimEnd('\', '/'))
        }
        $normalizedBefore = @(
            $beforeEntries |
                ForEach-Object {
                    try { [IO.Path]::GetFullPath($_).TrimEnd('\', '/') }
                    catch { $_.TrimEnd('\', '/') }
                }
        )
        $policy.canonical_entries = [string[]]$canonicalEntries
        $policy.offending_entries = [string[]]@(
            $normalizedBefore |
                Where-Object { -not $canonicalSet.Contains($_) }
        )
        $isCanonicalEquivalent = Test-AstroDetachedPathListEquivalent `
            -Actual ([string[]]$normalizedBefore) `
            -Expected ([string[]]$canonicalEntries)
        if (-not $isCanonicalEquivalent) {
            $env:PSModulePath = $canonical
            $policy.action = 'normalized-windows-powershell-5.1'
        }
        else {
            $policy.action = 'already-canonical-windows-powershell-5.1'
        }
        $policy.after = [string]$env:PSModulePath
    }
    else {
        $policy.action = 'preserved-non-desktop-powershell'
    }

    try {
        foreach ($moduleName in $requiredModules) {
            Import-Module $moduleName -ErrorAction Stop
            $module = Get-Module -Name $moduleName -ErrorAction Stop |
                Select-Object -First 1
            $policy.imported_modules += [ordered]@{
                name = $moduleName
                path = [string]$module.Path
                version = [string]$module.Version
            }
        }
    }
    catch {
        $policy.import_error = "$($_.FullyQualifiedErrorId): $($_.Exception.Message)"
        throw "DETACH_PROTOCOL[ASTRO_DETACH_PSMODULEPATH_INVALID]: {code=ASTRO_DETACH_PSMODULEPATH_INVALID; message=`"PowerShell module path cannot load required module for $Role after policy $($policy.action): $($policy.import_error)`"; remediation=`"preserve the process state, inspect the recorded PSModulePath, and restore the canonical Windows PowerShell 5.1 module roots`"}"
    }

    # This is protocol state, not operator-facing UI. Both callers persist the
    # returned object in their append-only intent/runner record. Writing the
    # successful measurement to the host leaks internal JSON into any console
    # attached by a legacy or invalid runner boundary before that boundary can
    # be rejected. Import failures above remain cause-specific hard errors.
    return $policy
}

function ConvertTo-AstroDetachedUtcIso {
    param([Parameter(Mandatory)][long]$UtcTicks)

    if ($UtcTicks -le 0 -or $UtcTicks -gt [DateTime]::MaxValue.Ticks) {
        throw "detached protocol UTC ticks are outside the DateTime range: $UtcTicks"
    }
    return [DateTime]::new($UtcTicks, [DateTimeKind]::Utc).ToString('o')
}

function Get-AstroDetachedCurrentIdentity {
    $process = Get-Process -Id $PID -ErrorAction Stop
    $ticks = [long]$process.StartTime.ToUniversalTime().Ticks
    return [ordered]@{
        pid = [int]$PID
        process_start_utc_ticks = $ticks
        process_started_utc = ConvertTo-AstroDetachedUtcIso $ticks
        session_id = [int]$process.SessionId
        user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
}

function Get-AstroDetachedProcessProbe {
    param(
        [Parameter(Mandatory)][int]$ProcessId,
        [Parameter(Mandatory)][long]$ProcessStartUtcTicks,
        [Parameter(Mandatory)][int]$SessionId
    )

    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoProcessFoundForGivenId,*') {
            return [ordered]@{
                state = 'absent'
                pid = $ProcessId
                expected_process_start_utc_ticks = $ProcessStartUtcTicks
                expected_session_id = $SessionId
                observed_process_start_utc_ticks = $null
                observed_session_id = $null
                error = $null
            }
        }
        return [ordered]@{
            state = 'unevaluable'
            pid = $ProcessId
            expected_process_start_utc_ticks = $ProcessStartUtcTicks
            expected_session_id = $SessionId
            observed_process_start_utc_ticks = $null
            observed_session_id = $null
            error = "$($_.FullyQualifiedErrorId): $($_.Exception.Message)"
        }
    }

    try {
        $observedTicks = [long]$process.StartTime.ToUniversalTime().Ticks
        $observedSession = [int]$process.SessionId
        $hasExited = [bool]$process.HasExited
    }
    catch {
        return [ordered]@{
            state = 'unevaluable'
            pid = $ProcessId
            expected_process_start_utc_ticks = $ProcessStartUtcTicks
            expected_session_id = $SessionId
            observed_process_start_utc_ticks = $null
            observed_session_id = $null
            error = "$($_.FullyQualifiedErrorId): $($_.Exception.Message)"
        }
    }
    $exact = $observedTicks -eq $ProcessStartUtcTicks -and
        $observedSession -eq $SessionId
    return [ordered]@{
        state = if (-not $exact) {
            'reused'
        }
        elseif ($hasExited) {
            'exact-exited'
        }
        else {
            'exact-live'
        }
        pid = $ProcessId
        expected_process_start_utc_ticks = $ProcessStartUtcTicks
        expected_session_id = $SessionId
        observed_process_start_utc_ticks = $observedTicks
        observed_session_id = $observedSession
        error = $null
    }
}

function Get-AstroDetachedParentIdentity {
    param(
        [Parameter(Mandatory)][int]$ChildProcessId,
        [Parameter(Mandatory)][long]$ChildProcessStartUtcTicks,
        [Parameter(Mandatory)][int]$ChildSessionId
    )

    $childProbe = Get-AstroDetachedProcessProbe `
        -ProcessId $ChildProcessId `
        -ProcessStartUtcTicks $ChildProcessStartUtcTicks `
        -SessionId $ChildSessionId
    if ($childProbe.state -cne 'exact-live') {
        throw "DETACH_PROTOCOL[ASTRO_DETACH_CHILD_NOT_EXACT_LIVE]: {code=ASTRO_DETACH_CHILD_NOT_EXACT_LIVE; message=`"cannot attribute parent because child probe is '$($childProbe.state)' for pid=$ChildProcessId`"; remediation=`"preserve the run directory and inspect the exact process probes`"}"
    }
    $row = Get-CimInstance `
        -ClassName Win32_Process `
        -Filter "ProcessId = $ChildProcessId" `
        -ErrorAction Stop
    if ($null -eq $row -or [int]$row.ProcessId -ne $ChildProcessId) {
        throw "DETACH_PROTOCOL[ASTRO_DETACH_PARENT_QUERY_EMPTY]: {code=ASTRO_DETACH_PARENT_QUERY_EMPTY; message=`"Win32_Process did not return the exact child pid=$ChildProcessId`"; remediation=`"preserve the run and inspect CIM/WMI health`"}"
    }
    $childReadback = Get-AstroDetachedProcessProbe `
        -ProcessId $ChildProcessId `
        -ProcessStartUtcTicks $ChildProcessStartUtcTicks `
        -SessionId $ChildSessionId
    if ($childReadback.state -cne 'exact-live') {
        throw "DETACH_PROTOCOL[ASTRO_DETACH_CHILD_CHANGED_DURING_PARENT_QUERY]: {code=ASTRO_DETACH_CHILD_CHANGED_DURING_PARENT_QUERY; message=`"child generation changed during parent attribution: pid=$ChildProcessId state=$($childReadback.state)`"; remediation=`"preserve the run directory and do not attribute the returned parent row`"}"
    }
    $parentPid = [int]$row.ParentProcessId
    if ($parentPid -le 0) {
        throw "DETACH_PROTOCOL[ASTRO_DETACH_PARENT_INVALID]: {code=ASTRO_DETACH_PARENT_INVALID; message=`"exact child has invalid parent PID $parentPid`"; remediation=`"preserve the run and inspect the process tree`"}"
    }
    $parent = Get-Process -Id $parentPid -ErrorAction Stop
    $ticks = [long]$parent.StartTime.ToUniversalTime().Ticks
    return [ordered]@{
        pid = $parentPid
        process_start_utc_ticks = $ticks
        process_started_utc = ConvertTo-AstroDetachedUtcIso $ticks
        session_id = [int]$parent.SessionId
    }
}

function Assert-AstroDetachedOrdinaryDirectory {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not [IO.Directory]::Exists($full)) {
        throw "detached protocol directory does not exist: $full"
    }
    $info = [IO.DirectoryInfo]::new($full)
    if (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "detached protocol directory must be ordinary, not a reparse point: $full"
    }
    return $full
}

function New-AstroDetachedDirectoryNoReplace {
    <#
    Scripting.FileSystemObject.CreateFolder is an in-process Windows create-new
    directory operation.  Unlike Directory.CreateDirectory, it reports an
    existing destination as an error.  The detached bootstrap uses it before any
    CodeDOM compiler can run, then independently validates the resulting object.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $parent = [IO.Path]::GetDirectoryName($full).TrimEnd('\', '/')
    $leaf = [IO.Path]::GetFileName($full)
    if ([string]::IsNullOrEmpty($leaf) -or
        [IO.Path]::Combine($parent, $leaf) -cne $full) {
        throw "DETACH_PROTOCOL[ASTRO_DETACH_CREATE_PATH_INVALID]: {code=ASTRO_DETACH_CREATE_PATH_INVALID; message=`"create-new directory path is not one canonical direct child: $full`"; remediation=`"pass one absolute child path beneath an already validated ordinary parent`"}"
    }
    [void](Assert-AstroDetachedOrdinaryDirectory $parent)
    if ([IO.File]::Exists($full) -or [IO.Directory]::Exists($full)) {
        throw "DETACH_PROTOCOL[ASTRO_DETACH_CREATE_COLLISION]: {code=ASTRO_DETACH_CREATE_COLLISION; message=`"create-new directory destination already exists: $full`"; remediation=`"preserve the existing object and choose a fresh generation name`"}"
    }

    $fileSystemObject = $null
    $createdFolder = $null
    try {
        $fileSystemObject = New-Object -ComObject Scripting.FileSystemObject
        $createdFolder = $fileSystemObject.CreateFolder($full)
        $reported = [IO.Path]::GetFullPath(
            [string]$createdFolder.Path
        ).TrimEnd('\', '/')
        if (-not [string]::Equals(
                $reported,
                $full,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "CreateFolder returned '$reported', expected '$full'"
        }
    }
    catch {
        throw "DETACH_PROTOCOL[ASTRO_DETACH_CREATE_NEW_FAILED]: {code=ASTRO_DETACH_CREATE_NEW_FAILED; message=`"Windows create-new directory failed for '$full': $($_.Exception.Message)`"; remediation=`"preserve any observed path, inspect the exact collision/security state, and retry only with a fresh generation`"}"
    }
    finally {
        if ($null -ne $createdFolder -and
            [Runtime.InteropServices.Marshal]::IsComObject($createdFolder)) {
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject(
                $createdFolder
            )
        }
        if ($null -ne $fileSystemObject -and
            [Runtime.InteropServices.Marshal]::IsComObject($fileSystemObject)) {
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject(
                $fileSystemObject
            )
        }
    }

    $readback = Assert-AstroDetachedOrdinaryDirectory $full
    if ([IO.Path]::GetDirectoryName($readback).TrimEnd('\', '/') -cne $parent -or
        [IO.Path]::GetFileName($readback) -cne $leaf) {
        throw "DETACH_PROTOCOL[ASTRO_DETACH_CREATE_READBACK_DRIFT]: {code=ASTRO_DETACH_CREATE_READBACK_DRIFT; message=`"created directory escaped its exact parent/leaf binding: $readback`"; remediation=`"preserve the namespace object and inspect its final path before any use`"}"
    }
    return $readback
}

function Initialize-AstroDetachedStateRoot {
    $tmp = Assert-AstroDetachedOrdinaryDirectory (
        Join-Path $script:AstroDetachedCanonicalRoot '.tmp'
    )
    $root = $script:AstroDetachedStateRoot
    if (-not [IO.Directory]::Exists($root)) {
        try {
            [void](New-AstroDetachedDirectoryNoReplace $root)
        }
        catch {
            if (-not [IO.Directory]::Exists($root)) {
                throw
            }
        }
    }
    $root = Assert-AstroDetachedOrdinaryDirectory $root
    if ([IO.Path]::GetDirectoryName($root) -cne $tmp) {
        throw "detached state root escaped canonical .tmp: $root"
    }
    return $root
}

function New-AstroDetachedRunDirectory {
    param([Parameter(Mandatory)][string]$RunId)

    if ($RunId -cnotmatch '^[0-9a-f]{32}$') {
        throw "DETACH_PROTOCOL[ASTRO_DETACH_RUN_ID_INVALID]: {code=ASTRO_DETACH_RUN_ID_INVALID; message=`"run ID must be 32 lowercase hexadecimal characters: '$RunId'`"; remediation=`"omit RunId for a fresh GUID or pass one canonical GUID N value`"}"
    }
    $root = Initialize-AstroDetachedStateRoot
    $runDirectory = Join-Path $root $RunId
    try {
        [void](New-AstroDetachedDirectoryNoReplace $runDirectory)
    }
    catch {
        throw "DETACH_PROTOCOL[ASTRO_DETACH_STATE_COLLISION]: {code=ASTRO_DETACH_STATE_COLLISION; message=`"create-new run directory refused existing or uncreatable path '$runDirectory': $($_.Exception.Message)`"; remediation=`"never overwrite or delete it; choose a fresh run ID and inspect the existing state independently`"}"
    }
    $runDirectory = Assert-AstroDetachedOrdinaryDirectory $runDirectory
    if ([IO.Path]::GetDirectoryName($runDirectory) -cne $root -or
        [IO.Path]::GetFileName($runDirectory) -cne $RunId) {
        throw "detached run directory identity escaped the fixed state root: $runDirectory"
    }
    return $runDirectory
}

function Assert-AstroDetachedRunDirectory {
    param([Parameter(Mandatory)][string]$RunDirectory)

    $full = Assert-AstroDetachedOrdinaryDirectory $RunDirectory
    $root = Assert-AstroDetachedOrdinaryDirectory $script:AstroDetachedStateRoot
    if ([IO.Path]::GetDirectoryName($full) -cne $root -or
        [IO.Path]::GetFileName($full) -cnotmatch '^[0-9a-f]{32}$') {
        throw "detached run directory is not one direct canonical run-ID child: $full"
    }
    return $full
}

function Read-AstroDetachedOrdinaryFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaximumBytes = $script:AstroDetachedRecordMaximumBytes
    )

    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.File]::Exists($full)) {
        throw "detached protocol file does not exist: $full"
    }
    $info = [IO.FileInfo]::new($full)
    if (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "detached protocol file must be ordinary, not a reparse point: $full"
    }
    $stream = [IO.File]::Open(
        $full,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        if ($stream.Length -gt $MaximumBytes) {
            throw "detached protocol file exceeds $MaximumBytes bytes: $full"
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw "unexpected EOF reading detached protocol file: $full"
            }
            $offset += $read
        }
        return [pscustomobject]@{
            Path = $full
            Bytes = $bytes
            Length = [long]$bytes.Length
            Sha256 = Get-AstroDetachedSha256Bytes $bytes
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Write-AstroDetachedRecord {
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Schema,
        [Parameter(Mandatory)][int]$Sequence,
        [AllowEmptyString()][string]$PreviousName = '',
        [AllowEmptyString()][string]$PreviousSha256 = '',
        [Parameter(Mandatory)]$Payload
    )

    $run = Assert-AstroDetachedRunDirectory $RunDirectory
    if ($Name -cnotmatch '^[0-9]{3}-[a-z0-9-]+\.json$') {
        throw "detached record name is noncanonical: $Name"
    }
    if ($Schema -cnotmatch '^astrolabe\.detached\.[a-z0-9-]+\.v1$') {
        throw "detached record schema is noncanonical: $Schema"
    }
    if ($Sequence -lt 0 -or
        ($Sequence -eq 0 -and
            (-not [string]::IsNullOrEmpty($PreviousName) -or
             -not [string]::IsNullOrEmpty($PreviousSha256))) -or
        ($Sequence -gt 0 -and
            ($PreviousName -cnotmatch '^[0-9]{3}-[a-z0-9-]+\.json$' -or
             $PreviousSha256 -cnotmatch '^[0-9a-f]{64}$'))) {
        throw "detached record predecessor/sequence contract is invalid for $Name"
    }

    $payloadJson = $Payload | ConvertTo-Json -Depth 32 -Compress
    $payloadBytes = Get-AstroDetachedUtf8Bytes $payloadJson
    $identity = Get-AstroDetachedCurrentIdentity
    $writtenTicks = [DateTime]::UtcNow.Ticks
    $document = [ordered]@{
        schema = $Schema
        run_id = [IO.Path]::GetFileName($run)
        sequence = $Sequence
        written_utc_ticks = $writtenTicks
        written_utc = ConvertTo-AstroDetachedUtcIso $writtenTicks
        writer_pid = $identity.pid
        writer_process_start_utc_ticks = $identity.process_start_utc_ticks
        writer_process_started_utc = $identity.process_started_utc
        writer_session_id = $identity.session_id
        previous_name = $PreviousName
        previous_sha256 = $PreviousSha256
        payload_sha256 = Get-AstroDetachedSha256Bytes $payloadBytes
        payload_bytes = [long]$payloadBytes.Length
        payload_json_base64 = [Convert]::ToBase64String($payloadBytes)
    }
    $json = $document | ConvertTo-Json -Compress
    $bytes = Get-AstroDetachedUtf8Bytes $json
    if ($bytes.Length -gt $script:AstroDetachedRecordMaximumBytes) {
        throw "detached record exceeds the maximum durable size before create-new write: name=$Name bytes=$($bytes.Length) maximum=$script:AstroDetachedRecordMaximumBytes"
    }
    $path = Join-Path $run $Name
    $stream = [IO.File]::Open(
        $path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    $readback = Read-AstroDetachedOrdinaryFile $path
    $writtenHash = Get-AstroDetachedSha256Bytes $bytes
    if ($readback.Length -ne $bytes.Length -or
        $readback.Sha256 -cne $writtenHash) {
        throw "durable detached record readback differs immediately after create-new write: $path"
    }
    return [pscustomobject]@{
        Name = $Name
        Path = $path
        Sequence = $Sequence
        Sha256 = $readback.Sha256
        Length = $readback.Length
        Document = [pscustomobject]$document
        Payload = $Payload
    }
}

function Read-AstroDetachedRecord {
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)][string]$Name,
        [string]$ExpectedSchema = '',
        [int]$ExpectedSequence = -1
    )

    $run = Assert-AstroDetachedRunDirectory $RunDirectory
    if ($Name -cnotmatch '^[0-9]{3}-[a-z0-9-]+\.json$') {
        throw "detached record name is noncanonical: $Name"
    }
    $snapshot = Read-AstroDetachedOrdinaryFile (Join-Path $run $Name)
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($snapshot.Bytes)
        $strict = ConvertFrom-AstroStrictFlatJsonObject -Json $text
    }
    catch {
        throw "detached record strict JSON decode failed for $Name`: $($_.Exception.Message)"
    }
    $required = @(
        'schema',
        'run_id',
        'sequence',
        'written_utc_ticks',
        'written_utc',
        'writer_pid',
        'writer_process_start_utc_ticks',
        'writer_process_started_utc',
        'writer_session_id',
        'previous_name',
        'previous_sha256',
        'payload_sha256',
        'payload_bytes',
        'payload_json_base64'
    )
    $names = @($strict.Names)
    if ($names.Count -ne $required.Count) {
        throw "detached record must contain exactly the v1 property set: $Name"
    }
    foreach ($requiredName in $required) {
        if (-not ($names -ccontains $requiredName)) {
            throw "detached record misses required property '$requiredName': $Name"
        }
    }
    $properties = $strict.Properties
    foreach ($stringName in @(
            'schema',
            'run_id',
            'written_utc',
            'writer_process_started_utc',
            'previous_name',
            'previous_sha256',
            'payload_sha256',
            'payload_json_base64'
        )) {
        if ($properties[$stringName].Kind -cne 'string') {
            throw "detached record property '$stringName' must be a JSON string: $Name"
        }
    }
    foreach ($integerName in @(
            'sequence',
            'written_utc_ticks',
            'writer_pid',
            'writer_process_start_utc_ticks',
            'writer_session_id',
            'payload_bytes'
        )) {
        if ($properties[$integerName].Kind -cne 'integer') {
            throw "detached record property '$integerName' must be an integral JSON number: $Name"
        }
    }
    $sequence = [int64]::Parse(
        [string]$properties['sequence'].Raw,
        [Globalization.CultureInfo]::InvariantCulture
    )
    $writtenTicks = [int64]::Parse(
        [string]$properties['written_utc_ticks'].Raw,
        [Globalization.CultureInfo]::InvariantCulture
    )
    $writerPid = [int64]::Parse(
        [string]$properties['writer_pid'].Raw,
        [Globalization.CultureInfo]::InvariantCulture
    )
    $writerTicks = [int64]::Parse(
        [string]$properties['writer_process_start_utc_ticks'].Raw,
        [Globalization.CultureInfo]::InvariantCulture
    )
    $writerSession = [int64]::Parse(
        [string]$properties['writer_session_id'].Raw,
        [Globalization.CultureInfo]::InvariantCulture
    )
    $payloadLength = [int64]::Parse(
        [string]$properties['payload_bytes'].Raw,
        [Globalization.CultureInfo]::InvariantCulture
    )
    $schema = [string]$properties['schema'].Value
    if ($schema -cnotmatch '^astrolabe\.detached\.[a-z0-9-]+\.v1$' -or
        (-not [string]::IsNullOrEmpty($ExpectedSchema) -and
            $schema -cne $ExpectedSchema) -or
        [string]$properties['run_id'].Value -cne [IO.Path]::GetFileName($run) -or
        ($ExpectedSequence -ge 0 -and
            $sequence -ne $ExpectedSequence) -or
        $sequence -lt 0 -or
        $writerPid -le 0 -or
        $writerPid -gt [int]::MaxValue -or
        $writerSession -lt 0 -or
        $writerSession -gt [int]::MaxValue -or
        $payloadLength -lt 0 -or
        [string]$properties['written_utc'].Value -cne
            (ConvertTo-AstroDetachedUtcIso $writtenTicks) -or
        [string]$properties['writer_process_started_utc'].Value -cne
            (ConvertTo-AstroDetachedUtcIso $writerTicks)) {
        throw "detached record root identity/schema/range validation failed: $Name"
    }
    try {
        $payloadBytes = [Convert]::FromBase64String(
            [string]$properties['payload_json_base64'].Value
        )
        $payloadJson = [Text.UTF8Encoding]::new($false, $true).GetString($payloadBytes)
        $payload = ConvertFrom-Json -InputObject $payloadJson
    }
    catch {
        throw "detached record payload decode failed for $Name`: $($_.Exception.Message)"
    }
    if ($payloadBytes.Length -ne $payloadLength -or
        (Get-AstroDetachedSha256Bytes $payloadBytes) -cne
            [string]$properties['payload_sha256'].Value) {
        throw "detached record payload length/hash readback mismatch: $Name"
    }
    return [pscustomobject]@{
        Name = $Name
        Path = $snapshot.Path
        Sequence = [int]$sequence
        Sha256 = $snapshot.Sha256
        Length = $snapshot.Length
        Schema = $schema
        PreviousName = [string]$properties['previous_name'].Value
        PreviousSha256 = [string]$properties['previous_sha256'].Value
        WriterPid = [int]$writerPid
        WriterProcessStartUtcTicks = $writerTicks
        WriterSessionId = [int]$writerSession
        PayloadJson = $payloadJson
        Payload = $payload
    }
}

function Read-AstroDetachedBootstrapRecord {
    <#
    The GUI bootstrap cannot import PowerShell protocol code before it creates the
    runner, so its three records are deliberately flat JSON. Parse them with the
    same duplicate-key/type-preserving reader as the main record chain and accept
    only the exact schema-specific property set.
    #>
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)]
        [ValidateSet(
            'bootstrap-start.json',
            'bootstrap-completion.json',
            'bootstrap-fault.json'
        )]
        [string]$Name
    )

    $run = Assert-AstroDetachedRunDirectory $RunDirectory
    $snapshot = Read-AstroDetachedOrdinaryFile (Join-Path $run $Name)
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($snapshot.Bytes)
        $strict = ConvertFrom-AstroStrictFlatJsonObject -Json $text
    }
    catch {
        throw "detached bootstrap record strict JSON decode failed for $Name`: $($_.Exception.Message)"
    }

    $definitions = @{
        'bootstrap-start.json' = [ordered]@{
            schema = 'astrolabe.detached.bootstrap-start.v1'
            strings = @(
                'schema', 'run_id', 'bootstrap_path', 'bootstrap_sha256',
                'powershell_path', 'powershell_sha256', 'runner_path',
                'runner_sha256', 'working_directory', 'runner_log_path'
            )
            integers = @(
                'written_utc_ticks', 'bootstrap_pid',
                'bootstrap_start_utc_ticks', 'bootstrap_session_id',
                'bootstrap_bytes', 'powershell_bytes', 'runner_bytes',
                'creation_flags', 'startup_show_window'
            )
        }
        'bootstrap-completion.json' = [ordered]@{
            schema = 'astrolabe.detached.bootstrap-completion.v1'
            strings = @(
                'schema', 'run_id', 'runner_exit_code_hex', 'command_line',
                'runner_log_path', 'runner_log_sha256'
            )
            integers = @(
                'written_utc_ticks', 'bootstrap_pid',
                'bootstrap_start_utc_ticks', 'bootstrap_session_id',
                'runner_pid', 'runner_start_utc_ticks', 'runner_session_id',
                'runner_exit_code', 'wait_result', 'creation_flags',
                'runner_log_bytes'
            )
        }
        'bootstrap-fault.json' = [ordered]@{
            schema = 'astrolabe.detached.bootstrap-fault.v1'
            strings = @(
                'schema', 'run_id', 'stage', 'code', 'message',
                'remediation', 'bootstrap_path'
            )
            integers = @(
                'written_utc_ticks', 'bootstrap_pid',
                'bootstrap_start_utc_ticks', 'bootstrap_session_id',
                'native_error'
            )
        }
    }
    $definition = $definitions[$Name]
    $expectedNames = @($definition.strings) + @($definition.integers)
    $observedNames = @($strict.Names)
    if ($observedNames.Count -ne $expectedNames.Count) {
        throw "detached bootstrap record has the wrong property count: $Name"
    }
    foreach ($propertyName in $expectedNames) {
        if (-not ($observedNames -ccontains $propertyName)) {
            throw "detached bootstrap record misses '$propertyName': $Name"
        }
    }
    foreach ($propertyName in $definition.strings) {
        if ($strict.Properties[$propertyName].Kind -cne 'string') {
            throw "detached bootstrap property '$propertyName' must be a JSON string: $Name"
        }
    }
    foreach ($propertyName in $definition.integers) {
        if ($strict.Properties[$propertyName].Kind -cne 'integer') {
            throw "detached bootstrap property '$propertyName' must be an integral JSON number: $Name"
        }
    }

    $values = [ordered]@{}
    foreach ($propertyName in $definition.strings) {
        $values[$propertyName] = [string]$strict.Properties[$propertyName].Value
    }
    foreach ($propertyName in $definition.integers) {
        $values[$propertyName] = [int64]::Parse(
            [string]$strict.Properties[$propertyName].Raw,
            [Globalization.CultureInfo]::InvariantCulture
        )
    }
    if ($values.schema -cne [string]$definition.schema -or
        $values.run_id -cne [IO.Path]::GetFileName($run) -or
        $values.written_utc_ticks -le 0 -or
        $values.bootstrap_pid -le 0 -or
        $values.bootstrap_pid -gt [int]::MaxValue -or
        $values.bootstrap_start_utc_ticks -le 0 -or
        $values.bootstrap_session_id -lt 0 -or
        $values.bootstrap_session_id -gt [int]::MaxValue) {
        throw "detached bootstrap record identity/schema/range validation failed: $Name"
    }
    return [pscustomobject]@{
        Name = $Name
        Path = $snapshot.Path
        Sha256 = $snapshot.Sha256
        Length = $snapshot.Length
        Values = [pscustomobject]$values
    }
}

function Assert-AstroDetachedRecordLink {
    param(
        [Parameter(Mandatory)]$Previous,
        [Parameter(Mandatory)]$Current
    )

    if ($Current.Sequence -ne ($Previous.Sequence + 1) -or
        $Current.PreviousName -cne $Previous.Name -or
        $Current.PreviousSha256 -cne $Previous.Sha256) {
        throw "detached record chain link is invalid: $($Previous.Name) -> $($Current.Name)"
    }
}

function Get-AstroDetachedTaskService {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    return $service
}

function Get-AstroDetachedRegisteredTask {
    param(
        [Parameter(Mandatory)]$TaskService,
        [Parameter(Mandatory)][string]$TaskName,
        [switch]$AllowAbsent
    )

    try {
        return $TaskService.GetFolder('\').GetTask("\$TaskName")
    }
    catch {
        if ($AllowAbsent -and $_.Exception.HResult -eq -2147024894) {
            return $null
        }
        throw
    }
}

function Get-AstroDetachedTaskSnapshot {
    param([Parameter(Mandatory)]$RegisteredTask)

    $definition = $RegisteredTask.Definition
    if ([int]$definition.Actions.Count -ne 1) {
        throw "detached scheduled task must have exactly one action"
    }
    $action = $definition.Actions.Item(1)
    $lastTaskResult = [int]$RegisteredTask.LastTaskResult
    $taskHasNotRun = $lastTaskResult -eq 267011
    $lastRunTime = [DateTime]$RegisteredTask.LastRunTime
    $hasLastRunTime = -not $taskHasNotRun -and $lastRunTime.Year -ge 1900
    $xml = [string]$RegisteredTask.Xml
    $xmlBytes = Get-AstroDetachedUtf8Bytes $xml
    $xmlDocument = [xml]$xml
    $namespace = [Xml.XmlNamespaceManager]::new($xmlDocument.NameTable)
    $namespace.AddNamespace(
        'task',
        'http://schemas.microsoft.com/windows/2004/02/mit/task'
    )
    $principalSidNode = $xmlDocument.SelectSingleNode(
        '/task:Task/task:Principals/task:Principal/task:UserId',
        $namespace
    )
    if ($null -eq $principalSidNode -or
        [string]::IsNullOrWhiteSpace([string]$principalSidNode.InnerText)) {
        throw 'detached task XML does not contain one principal UserId'
    }
    return [ordered]@{
        path = [string]$RegisteredTask.Path
        name = [string]$RegisteredTask.Name
        enabled = [bool]$RegisteredTask.Enabled
        scheduler_state = [int]$RegisteredTask.State
        last_task_result = $lastTaskResult
        last_task_result_hex = '0x{0:x8}' -f (
            [int64]$lastTaskResult -band 0xffffffffL
        )
        task_has_not_run = $taskHasNotRun
        last_run_time_utc_ticks = if ($hasLastRunTime) {
            [long]$lastRunTime.ToUniversalTime().Ticks
        }
        else {
            $null
        }
        last_run_time_utc = if ($hasLastRunTime) {
            $lastRunTime.ToUniversalTime().ToString('o')
        }
        else {
            $null
        }
        principal_user_id = [string]$definition.Principal.UserId
        principal_sid = [string]$principalSidNode.InnerText
        principal_logon_type = [int]$definition.Principal.LogonType
        principal_run_level = [int]$definition.Principal.RunLevel
        action_count = [int]$definition.Actions.Count
        action_path = [string]$action.Path
        action_arguments = [string]$action.Arguments
        action_working_directory = [string]$action.WorkingDirectory
        hidden = [bool]$definition.Settings.Hidden
        allow_demand_start = [bool]$definition.Settings.AllowDemandStart
        disallow_start_on_batteries =
            [bool]$definition.Settings.DisallowStartIfOnBatteries
        stop_if_going_on_batteries =
            [bool]$definition.Settings.StopIfGoingOnBatteries
        execution_time_limit = [string]$definition.Settings.ExecutionTimeLimit
        multiple_instances = [int]$definition.Settings.MultipleInstances
        start_when_available = [bool]$definition.Settings.StartWhenAvailable
        wake_to_run = [bool]$definition.Settings.WakeToRun
        xml_sha256 = Get-AstroDetachedSha256Bytes $xmlBytes
        xml_bytes = [long]$xmlBytes.Length
        xml_base64 = [Convert]::ToBase64String($xmlBytes)
    }
}

function Register-AstroDetachedTaskCreateOnly {
    param(
        [Parameter(Mandatory)]$TaskService,
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][string]$PrincipalUserId,
        [Parameter(Mandatory)][ValidateSet('InteractiveToken', 'S4U')]
        [string]$LogonType,
        [Parameter(Mandatory)][string]$ActionPath,
        [Parameter(Mandatory)][string]$ActionArguments,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)][string]$Description
    )

    if ($TaskName -cnotmatch '^Astrolabe\.Detached\.[0-9a-f]{32}$') {
        throw "detached task name is noncanonical: $TaskName"
    }
    if ($null -ne (Get-AstroDetachedRegisteredTask `
            -TaskService $TaskService `
            -TaskName $TaskName `
            -AllowAbsent)) {
        throw "DETACH_TASK[ASTRO_DETACH_TASK_COLLISION]: {code=ASTRO_DETACH_TASK_COLLISION; message=`"create-only task already exists: $TaskName`"; remediation=`"preserve and inspect the existing task; choose a fresh run ID`"}"
    }
    $logonValue = if ($LogonType -ceq 'InteractiveToken') { 3 } else { 2 }
    $definition = $TaskService.NewTask(0)
    $definition.RegistrationInfo.Description = $Description
    $definition.RegistrationInfo.Author = $PrincipalUserId
    $definition.Principal.UserId = $PrincipalUserId
    $definition.Principal.LogonType = $logonValue
    $definition.Principal.RunLevel = 0
    $definition.Settings.Enabled = $true
    $definition.Settings.Hidden = $false
    $definition.Settings.AllowDemandStart = $true
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $definition.Settings.ExecutionTimeLimit = 'PT0S'
    $definition.Settings.MultipleInstances = 2
    $definition.Settings.StartWhenAvailable = $false
    $definition.Settings.WakeToRun = $false
    $action = $definition.Actions.Create(0)
    $action.Path = $ActionPath
    $action.Arguments = $ActionArguments
    $action.WorkingDirectory = $WorkingDirectory

    $root = $TaskService.GetFolder('\')
    $registered = $root.RegisterTaskDefinition(
        $TaskName,
        $definition,
        2,
        $null,
        $null,
        $logonValue,
        $null
    )
    return $registered
}

function Remove-AstroDetachedTaskExact {
    param(
        [Parameter(Mandatory)]$TaskService,
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][string]$ExpectedXmlSha256
    )

    $registered = Get-AstroDetachedRegisteredTask `
        -TaskService $TaskService `
        -TaskName $TaskName
    $before = Get-AstroDetachedTaskSnapshot $registered
    if ($before.xml_sha256 -cne $ExpectedXmlSha256) {
        throw "DETACH_TASK[ASTRO_DETACH_TASK_IDENTITY_CHANGED]: {code=ASTRO_DETACH_TASK_IDENTITY_CHANGED; message=`"registered task XML changed before exact cleanup: expected=$ExpectedXmlSha256 observed=$($before.xml_sha256)`"; remediation=`"preserve the task and run directory; do not delete changed state`"}"
    }
    $TaskService.GetFolder('\').DeleteTask($TaskName, 0)
    if ($null -ne (Get-AstroDetachedRegisteredTask `
            -TaskService $TaskService `
            -TaskName $TaskName `
            -AllowAbsent)) {
        throw "DETACH_TASK[ASTRO_DETACH_TASK_CLEANUP_READBACK_FAILED]: {code=ASTRO_DETACH_TASK_CLEANUP_READBACK_FAILED; message=`"task still exists after exact DeleteTask: $TaskName`"; remediation=`"preserve the run directory and inspect Task Scheduler state`"}"
    }
    return $before
}
