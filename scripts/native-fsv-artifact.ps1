<#
.SYNOPSIS
    Content-addressed promotion and lifecycle management for native FSV artifacts (#596).

.DESCRIPTION
    Cargo's target directory is disposable launcher-owned build state. A native artifact that
    will be exercised after it is built must therefore be promoted, byte-for-byte, into a fresh
    workspace-local evidence directory before target cleanup. Promotion is fail-closed:

      * the source must live below an owned Cargo target root;
      * the source bytes are hashed before and after copying;
      * the staged bytes are flushed to disk and independently re-hashed;
      * a provenance receipt binds issue, tree SHA, source, staged path, length, and SHA-256;
      * the complete staging directory is published with one same-volume, write-through,
        no-clobber rename;
      * reuse, drift, path escape, and partial publication are structured failures.

    The companion native-fsv-run.ps1 holds a Windows handle that denies delete/rename while
    the artifact is executing. Every owner is a strict PID/process-start identity. Lifecycle
    removal refuses exact-live and unevaluable generations, records PID reuse without treating
    it as ownership, and accepts legacy PID-only state only through a tracker-bound migration.

.NOTES
    Refs #612, #596, #424, #197. Manual FSV tooling; this is not a test or a gate.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Stage', 'Inspect', 'Cleanup', 'Abandon', 'Quarantine', 'MigrateLegacy', 'RetireLock')]
    [string]$Operation,

    [string]$SourcePath = '',
    [string]$ReceiptPath = '',
    [string]$RunRecordPath = '',
    [int]$Issue = 0,
    [string]$TreeSha = '',
    [string]$SessionId = '',
    [string]$AbandonRecordPath = '',
    [string]$RecoveryRecordPath = '',
    [string]$MigrationRecordPath = '',
    [string]$LiveStatePath = '',
    [string]$TrackerCommentUrl = '',
    [string]$ReasonCode = '',
    [string]$ReasonMessage = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

. (Join-Path $PSScriptRoot 'launcher-lock.ps1')

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

function Path-WithTrailingSeparator {
    param([Parameter(Mandatory)][string]$Path)
    return ([IO.Path]::GetFullPath($Path).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar)
}

function Assert-PathWithin {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )
    $full = [IO.Path]::GetFullPath($Path)
    $rootPrefix = Path-WithTrailingSeparator $Root
    if (-not $full.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Fail-Astro $Code "$Description '$full' escapes required root '$($rootPrefix.TrimEnd('\'))'" `
            "use a fresh path below the required workspace-local root"
    }
    return $full
}

function Assert-NotReparseEntry {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )
    $state = Get-AstroPathEntryState $Path
    if ($state.State -ceq 'absent') { return }
    if ($state.State -cne 'present') {
        Fail-Astro 'ASTRO_FSV_PATH_UNEVALUABLE' `
            "$Description presence/attributes are unevaluable: $Path ($($state.Error))" `
            'repair filesystem access before mutating evidence state'
    }
    if (($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Astro 'ASTRO_FSV_REPARSE_ENTRY_REFUSED' "$Description is a reparse point: $Path" `
            'use ordinary workspace-local files and directories; evidence paths may not redirect elsewhere'
    }
}

function File-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($stream)) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

function String-Sha256 {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))) -replace '-', '').ToLowerInvariant()
    }
    finally { $hasher.Dispose() }
}

function ByteArray-Sha256 {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Value)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($Value)) -replace '-', '').ToLowerInvariant()
    }
    finally { $hasher.Dispose() }
}

function Invoke-GitRawCapture {
    param(
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)][string]$Workspace,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Description
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $GitExe
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    [void]$start.ArgumentList.Add('-C')
    [void]$start.ArgumentList.Add([IO.Path]::GetFullPath($Workspace).TrimEnd('\', '/'))
    foreach ($argument in $Arguments) {
        [void]$start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $stdout = [IO.MemoryStream]::new()
    try {
        if (-not $process.Start()) {
            Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' "$Description did not start during artifact promotion" `
                'repair native Git before staging evidence'
        }
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            try { $process.Kill() } catch {}
            Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' "$Description exceeded the 30000 ms bounded timeout during artifact promotion" `
                'repair native Git or repository state before staging evidence'
        }
        [void]$stdoutTask.GetAwaiter().GetResult()
        return [pscustomobject]@{
            ExitCode = [int]$process.ExitCode
            Bytes = [byte[]]$stdout.ToArray()
            Stderr = $stderrTask.GetAwaiter().GetResult()
        }
    }
    finally {
        $stdout.Dispose()
        $process.Dispose()
    }
}

function Read-GitStatusFingerprint {
    param(
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)][string]$Workspace
    )
    $status = Invoke-GitRawCapture `
        -GitExe $GitExe `
        -Workspace $Workspace `
        -Arguments @(
            '-c',
            'core.quotepath=false',
            'status',
            '--porcelain=v1',
            '-z',
            '--untracked-files=normal'
        ) `
        -Description 'git status --porcelain=v1 -z --untracked-files=normal'
    if ($status.ExitCode -ne 0) {
        Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' "git status --porcelain=v1 -z failed during artifact promotion (exit=$($status.ExitCode), stderr=$($status.Stderr))" `
            'repair repository state before staging evidence'
    }
    try {
        $statusText = [Text.UTF8Encoding]::new($false, $true).GetString($status.Bytes)
    }
    catch {
        Fail-Astro 'ASTRO_FSV_GIT_STATUS_UTF8_INVALID' "Git status emitted bytes that are not strict UTF-8 during artifact promotion: $($_.Exception.Message)" `
            'rename the unsupported Windows worktree path before staging evidence'
    }
    if ($status.Bytes.Length -gt 0 -and
        $status.Bytes[$status.Bytes.Length - 1] -ne 0) {
        Fail-Astro 'ASTRO_FSV_GIT_STATUS_TERMINAL_NUL_MISSING' `
            'nonempty Git porcelain-v1 -z output lacks its terminal NUL during artifact promotion' `
            'repair or replace the native Git executable before staging evidence'
    }
    $parts = @($statusText.Split([char]0))
    $records = if ($statusText.Length -eq 0) {
        @()
    }
    else {
        @($parts[0..($parts.Count - 2)])
    }
    return [ordered]@{
        sha256 = ByteArray-Sha256 $status.Bytes
        records = [string[]]$records
    }
}

function Test-DescendantOf {
    param(
        [Parameter(Mandatory)][int]$CandidatePid,
        [Parameter(Mandatory)][int]$AncestorPid
    )
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

function Get-RepoState {
    param(
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)][string]$Workspace
    )
    $head = (& $GitExe -C $Workspace rev-parse HEAD).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
        Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' 'git rev-parse HEAD failed during artifact promotion' `
            'repair repository state before staging evidence'
    }
    $status = Read-GitStatusFingerprint -GitExe $GitExe -Workspace $Workspace
    $diff = Invoke-GitRawCapture `
        -GitExe $GitExe `
        -Workspace $Workspace `
        -Arguments @('diff', '--binary', 'HEAD') `
        -Description 'git diff --binary HEAD'
    if ($diff.ExitCode -ne 0) {
        Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' "git diff --binary HEAD failed during artifact promotion (exit=$($diff.ExitCode), stderr=$($diff.Stderr))" `
            'repair repository state before staging evidence'
    }
    return [ordered]@{
        head_sha = $head
        status_sha256 = [string]$status.sha256
        status_records = [string[]]$status.records
        diff_sha256 = ByteArray-Sha256 $diff.Bytes
    }
}

function Write-NewDurableUtf8 {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )
    $encoding = [Text.UTF8Encoding]::new($false)
    $bytes = $encoding.GetBytes($Content)
    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
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
}

function Copy-FileDurable {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )
    $input = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Source),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $output = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Destination),
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $input.CopyTo($output)
        $output.Flush($true)
    }
    finally {
        $output.Dispose()
        $input.Dispose()
    }
}

if (-not ([Management.Automation.PSTypeName]'AstroFsvPublish').Type) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class AstroFsvPublish {
    const uint MOVEFILE_WRITE_THROUGH = 0x00000008;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool MoveFileExW(string existingName, string newName, uint flags);

    static string Extended(string path) {
        string full = System.IO.Path.GetFullPath(path);
        if (full.StartsWith(@"\\?\", StringComparison.Ordinal))
            return full;
        if (full.StartsWith(@"\\", StringComparison.Ordinal))
            return @"\\?\UNC\" + full.Substring(2);
        return @"\\?\" + full;
    }

    public static void PublishDirectory(string source, string destination) {
        if (!MoveFileExW(Extended(source), Extended(destination),
                MOVEFILE_WRITE_THROUGH)) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "MoveFileExW write-through no-clobber evidence-directory publication failed " +
                "(native_error=" + error + "; source=" + source +
                "; destination=" + destination + ")");
        }
    }
}
'@
}

function Read-AstroFsvProcessIdentity {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    if ($null -eq $Object) {
        Fail-Astro $Code "$Description is absent" `
            'preserve the session and investigate its incomplete process provenance'
    }
    $properties = @($Object.PSObject.Properties | ForEach-Object Name)
    $required = @('pid', 'process_start_utc_ticks', 'process_started_utc')
    if ($properties.Count -ne $required.Count -or
        @($required | Where-Object { $properties -notcontains $_ }).Count -ne 0) {
        Fail-Astro $Code `
            "$Description must contain exactly pid, process_start_utc_ticks, process_started_utc" `
            'preserve the session; legacy, partial, and extended authority records require explicit schema handling'
    }
    $parsedPid = 0
    $parsedTicks = 0L
    if (-not [int]::TryParse(
            [string]$Object.pid,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsedPid
        ) -or $parsedPid -le 0 -or
        -not [long]::TryParse(
            [string]$Object.process_start_utc_ticks,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsedTicks
        ) -or $parsedTicks -le 0 -or
        $parsedTicks -gt [DateTime]::MaxValue.Ticks) {
        Fail-Astro $Code "$Description has an invalid PID or process-start UTC ticks" `
            'preserve the session and investigate its incomplete process provenance'
    }
    $expectedIso = ConvertTo-AstroProcessStartUtcIso $parsedTicks
    $startedValue = $Object.process_started_utc
    $startedMatches = if ($startedValue -is [DateTime]) {
        $startedValue.ToUniversalTime().Ticks -eq $parsedTicks
    }
    elseif ($startedValue -is [DateTimeOffset]) {
        $startedValue.UtcDateTime.Ticks -eq $parsedTicks
    }
    else {
        [string]::Equals(
            [string]$startedValue,
            $expectedIso,
            [StringComparison]::Ordinal
        )
    }
    if (-not $startedMatches) {
        Fail-Astro $Code `
            "$Description process_started_utc does not resolve to its exact UTC ticks" `
            'preserve the session and investigate identity byte drift'
    }
    return New-AstroProcessIdentityRecord $parsedPid $parsedTicks
}

function New-AstroFsvOwnerBinding {
    param(
        [Parameter(Mandatory)][string]$Role,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)]$Identity
    )

    return [pscustomobject]@{
        Role = $Role
        Source = $Source
        Identity = $Identity
    }
}

function Test-AstroFsvIdentityEqual {
    param(
        [Parameter(Mandatory)]$Left,
        [Parameter(Mandatory)]$Right
    )

    return [int]$Left.pid -eq [int]$Right.pid -and
        [long]$Left.process_start_utc_ticks -eq
            [long]$Right.process_start_utc_ticks
}

function Get-AstroFsvOwnerProbes {
    param([Parameter(Mandatory)][object[]]$Bindings)

    $probes = foreach ($binding in $Bindings) {
        $identity = $binding.Identity
        $probe = Get-AstroExactProcessIdentityProbe `
            -Pid ([int]$identity.pid) `
            -ProcessStartUtcTicks ([long]$identity.process_start_utc_ticks)
        [ordered]@{
            role = [string]$binding.Role
            source = [string]$binding.Source
            identity = $identity
            state = $probe.State
            numeric_pid_live = $probe.NumericPidLive
            exact_owner_live = $probe.ExactOwnerLive
            pid_reused = $probe.PidReused
            observed_process_start_utc_ticks =
                $probe.ObservedProcessStartUtcTicks
            observed_process_started_utc =
                $probe.ObservedProcessStartedUtc
            observed_at_utc = $probe.ObservedAtUtc
            error = $probe.Error
        }
    }
    return @($probes)
}

function Assert-AstroFsvOwnersInactive {
    param(
        [Parameter(Mandatory)][object[]]$Bindings,
        [Parameter(Mandatory)][string]$CodePrefix,
        [Parameter(Mandatory)][string]$Description
    )

    $probes = @(Get-AstroFsvOwnerProbes $Bindings)
    $live = @($probes | Where-Object { $_.state -ceq 'exact-live' })
    if ($live.Count -gt 0) {
        Fail-Astro "${CodePrefix}_LIVE_OWNER" `
            "$Description retains exact-live owner(s): $($live | ConvertTo-Json -Depth 8 -Compress)" `
            'wait for every exact recorded process generation to exit naturally'
    }
    $unevaluable = @($probes | Where-Object { $_.state -ceq 'unevaluable' })
    if ($unevaluable.Count -gt 0) {
        Fail-Astro "${CodePrefix}_OWNER_UNEVALUABLE" `
            "$Description has unevaluable owner state: $($unevaluable | ConvertTo-Json -Depth 8 -Compress)" `
            'preserve every byte and retry only when exact process identity is readable'
    }
    return $probes
}

function Assert-AstroFsvPersistedOwnerEnvelope {
    param(
        [Parameter(Mandatory)]$Owners,
        [Parameter(Mandatory)][object[]]$ExpectedBindings,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    if ($null -eq $Owners -or
        -not $Owners.PSObject.Properties['identities'] -or
        -not $Owners.PSObject.Properties['initial_probes'] -or
        -not $Owners.PSObject.Properties['final_probes']) {
        Fail-Astro $Code `
            "$Description omits its identities or authorization probes" `
            'preserve both session and external record and investigate the durable-write mismatch'
    }
    $persistedIdentities = @($Owners.identities)
    $initialProbes = @($Owners.initial_probes)
    $finalProbes = @($Owners.final_probes)
    if ($persistedIdentities.Count -ne $ExpectedBindings.Count -or
        $initialProbes.Count -ne $ExpectedBindings.Count -or
        $finalProbes.Count -ne $ExpectedBindings.Count) {
        Fail-Astro $Code `
            "$Description owner/probe cardinality differs from the authorization set" `
            'preserve both session and external record and investigate the durable-write mismatch'
    }
    for ($index = 0; $index -lt $ExpectedBindings.Count; $index++) {
        $expected = $ExpectedBindings[$index]
        $persisted = $persistedIdentities[$index]
        $persistedIdentity = Read-AstroFsvProcessIdentity `
            $persisted.identity $Code `
            "$Description persisted owner identity $index"
        if ([string]$persisted.role -cne [string]$expected.Role -or
            [string]$persisted.source -cne [string]$expected.Source -or
            -not (Test-AstroFsvIdentityEqual `
                $persistedIdentity $expected.Identity)) {
            Fail-Astro $Code `
                "$Description persisted owner identity $index differs from the authorization set" `
                'preserve both session and external record and investigate the durable-write mismatch'
        }
        foreach ($probeSet in @($initialProbes, $finalProbes)) {
            $persistedProbe = $probeSet[$index]
            $probeIdentity = Read-AstroFsvProcessIdentity `
                $persistedProbe.identity $Code `
                "$Description persisted owner probe identity $index"
            if ([string]$persistedProbe.role -cne
                    [string]$expected.Role -or
                [string]$persistedProbe.source -cne
                    [string]$expected.Source -or
                -not (Test-AstroFsvIdentityEqual `
                    $probeIdentity $expected.Identity) -or
                [string]$persistedProbe.state -notin
                    @('absent', 'pid-reused')) {
                Fail-Astro $Code `
                    "$Description persisted owner probe $index differs from its inactive authorization" `
                    'preserve both session and external record and investigate the durable-write mismatch'
            }
        }
    }
}

function Get-AstroCurrentProcessIdentity {
    param(
        [Parameter(Mandatory)]
        [Alias('Pid')]
        [int]$ProcessId,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    $probe = Get-AstroProcessIdentityProbe -OwnerPid $ProcessId
    if ($probe.State -cne 'observed') {
        Fail-Astro $Code `
            "$Description process identity is '$($probe.State)': $($probe.Error)" `
            'preserve state and retry only when the live process creation time is readable'
    }
    return New-AstroProcessIdentityRecord `
        $ProcessId ([long]$probe.ProcessStartUtcTicks)
}

function Invoke-AstroFsvGhJson {
    param([Parameter(Mandatory)][string]$ApiPath)

    $gh = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $gh) {
        Fail-Astro 'ASTRO_FSV_MIGRATION_GH_MISSING' `
            'authenticated GitHub CLI is unavailable' `
            'restore authenticated gh access; no legacy session bytes were authorized for removal'
    }
    $process = $null
    try {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $gh.Source
        $start.Arguments = 'api ' + $ApiPath
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.EnvironmentVariables['NO_COLOR'] = '1'
        $start.EnvironmentVariables['GH_FORCE_TTY'] = '0'
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        if (-not $process.Start()) {
            throw 'Process.Start returned false'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            try { $process.Kill() } catch {}
            throw 'gh read exceeded the 30000 ms bounded timeout'
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "gh exited $($process.ExitCode): $stderr"
        }
        return $stdout | ConvertFrom-Json
    }
    catch {
        Fail-Astro 'ASTRO_FSV_MIGRATION_GH_READ_FAILED' `
            $_.Exception.Message `
            'repair authenticated GitHub access; no legacy session bytes were authorized for removal'
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Read-AstroFsvLegacyTrackerEvidence {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][string]$ExpectedReceiptPath,
        [Parameter(Mandatory)][string]$ExpectedReceiptSha256,
        [Parameter(Mandatory)][string]$ExpectedSessionDirectory,
        [Parameter(Mandatory)][string]$ExpectedInventorySchema,
        [Parameter(Mandatory)][string]$ExpectedInventoryEncoding,
        [Parameter(Mandatory)][int]$ExpectedInventoryEntryCount,
        [Parameter(Mandatory)][uint64]$ExpectedInventoryCanonicalByteCount,
        [Parameter(Mandatory)][string]$ExpectedInventorySha256,
        [Parameter(Mandatory)][int[]]$ExpectedNumericOwnerPids,
        [Parameter(Mandatory)][string]$ExpectedMigrationRecordPath
    )

    $match = [Regex]::Match(
        $Url,
        '^https://github\.com/(?<owner>[^/]+)/(?<repo>[^/]+)/issues/(?<issue>[1-9][0-9]*)#issuecomment-(?<comment>[1-9][0-9]*)\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success -or
        [int]$match.Groups['issue'].Value -ne $ExpectedIssue) {
        Fail-Astro 'ASTRO_FSV_MIGRATION_TRACKER_URL_INVALID' `
            "tracker URL is not an exact issue-comment URL for #${ExpectedIssue}: $Url" `
            'post one fresh owner-authored evidence comment on the exact driving issue'
    }
    $api = 'repos/{0}/{1}/issues/comments/{2}' -f
        $match.Groups['owner'].Value,
        $match.Groups['repo'].Value,
        $match.Groups['comment'].Value
    $comment = Invoke-AstroFsvGhJson $api
    if ([string]$comment.html_url -cne $Url -or
        [string]$comment.author_association -cne 'OWNER') {
        Fail-Astro 'ASTRO_FSV_MIGRATION_TRACKER_IDENTITY_INVALID' `
            'GitHub readback does not bind the exact owner-authored comment URL' `
            'use the canonical html_url of a repository-owner evidence comment'
    }
    $prefix = 'ASTRO_FSV_LEGACY_MIGRATION_EVIDENCE '
    [string[]]$markers = @(
        [string]$comment.body -split "`r?`n" |
            Where-Object {
                $_.StartsWith($prefix, [StringComparison]::Ordinal)
            }
    )
    if ($markers.Count -ne 1) {
        Fail-Astro 'ASTRO_FSV_MIGRATION_TRACKER_EVIDENCE_INVALID' `
            "tracker comment must contain exactly one '$prefix' line" `
            'post one fresh machine-readable legacy migration evidence object'
    }
    try {
        $evidence = $markers[0].Substring($prefix.Length) | ConvertFrom-Json
    }
    catch {
        Fail-Astro 'ASTRO_FSV_MIGRATION_TRACKER_EVIDENCE_INVALID' `
            "tracker evidence JSON is invalid: $($_.Exception.Message)" `
            'post one fresh exact JSON evidence object'
    }
    $expectedFields = @(
        'schema',
        'issue',
        'receipt_path',
        'receipt_sha256',
        'session_directory',
        'inventory_schema',
        'inventory_encoding',
        'inventory_entry_count',
        'inventory_canonical_byte_count',
        'inventory_sha256',
        'legacy_numeric_owner_pids',
        'numeric_owner_probe_state',
        'migration_record_path',
        'authorized_action'
    )
    $actualFields = @($evidence.PSObject.Properties | ForEach-Object Name)
    if ($actualFields.Count -ne $expectedFields.Count -or
        @($expectedFields | Where-Object { $actualFields -notcontains $_ }).Count -ne 0) {
        Fail-Astro 'ASTRO_FSV_MIGRATION_TRACKER_EVIDENCE_INVALID' `
            'tracker evidence fields differ from the exact legacy migration contract' `
            'post a fresh object containing exactly the documented fields'
    }
    $actualPids = [int[]]@(
        @($evidence.legacy_numeric_owner_pids) |
            ForEach-Object { [int]$_ } |
            Sort-Object -Unique
    )
    $expectedPids = [int[]]@($ExpectedNumericOwnerPids | Sort-Object -Unique)
    if ($evidence.schema -cne
            'astrolabe.native-fsv-legacy-migration-evidence.v2' -or
        [int]$evidence.issue -ne $ExpectedIssue -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$evidence.receipt_path),
            [IO.Path]::GetFullPath($ExpectedReceiptPath),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$evidence.receipt_sha256 -cne $ExpectedReceiptSha256 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$evidence.session_directory),
            [IO.Path]::GetFullPath($ExpectedSessionDirectory),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$evidence.inventory_schema -cne
            $ExpectedInventorySchema -or
        [string]$evidence.inventory_encoding -cne
            $ExpectedInventoryEncoding -or
        [int]$evidence.inventory_entry_count -ne
            $ExpectedInventoryEntryCount -or
        [uint64]$evidence.inventory_canonical_byte_count -ne
            $ExpectedInventoryCanonicalByteCount -or
        [string]$evidence.inventory_sha256 -cne $ExpectedInventorySha256 -or
        ($actualPids -join ',') -cne ($expectedPids -join ',') -or
        [string]$evidence.numeric_owner_probe_state -cne 'all-absent' -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$evidence.migration_record_path),
            [IO.Path]::GetFullPath($ExpectedMigrationRecordPath),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$evidence.authorized_action -cne
            'remove-legacy-session-without-inventing-process-start-ticks') {
        Fail-Astro 'ASTRO_FSV_MIGRATION_TRACKER_EVIDENCE_MISMATCH' `
            'tracker evidence differs from the exact local legacy session binding' `
            're-read physical state and post a fresh exact evidence object'
    }
    return [ordered]@{
        url = $Url
        comment_id = [long]$match.Groups['comment'].Value
        author = [string]$comment.user.login
        evidence = $evidence
    }
}

function Read-Receipt {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$EvidenceRoot
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_REQUIRED' 'ReceiptPath is required for this operation' `
            'pass the receipt.json path emitted by the Stage operation'
    }
    $full = Assert-PathWithin $Path $EvidenceRoot 'ASTRO_FSV_RECEIPT_ESCAPE' 'receipt path'
    if (-not (Test-AstroPathLongPath -LiteralPath $full -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_MISSING' "evidence receipt does not exist: $full" `
            'stage the native artifact first and pass its exact persisted receipt path'
    }
    try { $receipt = Read-AstroUtf8FileLongPath $full | ConvertFrom-Json }
    catch {
        Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' "parse evidence receipt '$full' failed: $($_.Exception.Message)" `
            'discard the incomplete evidence session and stage the artifact again'
    }
    if ($receipt.schema -eq 'astrolabe.native-fsv-artifact.v1') {
        Fail-Astro 'ASTRO_FSV_RECEIPT_LEGACY_MIGRATION_REQUIRED' `
            "evidence receipt '$full' uses legacy PID-only schema v1" `
            'preserve the session and use MigrateLegacy with a fresh owner-authored tracker evidence comment; never infer missing process generations'
    }
    if ($receipt.schema -ne 'astrolabe.native-fsv-artifact.v2' -or
        -not $receipt.PSObject.Properties['owners'] -or
        -not $receipt.owners.PSObject.Properties['launcher'] -or
        -not $receipt.owners.PSObject.Properties['promoter'] -or
        -not $receipt.artifact -or -not $receipt.artifact.path -or
        [string]::IsNullOrWhiteSpace([string]$receipt.artifact.sha256)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' "evidence receipt '$full' violates the required schema" `
            'discard the invalid session and stage the artifact again'
    }
    return [pscustomobject]@{ Path = $full; Receipt = $receipt }
}

function Inspect-ReceiptArtifact {
    param(
        [Parameter(Mandatory)]$ReceiptState,
        [Parameter(Mandatory)][string]$EvidenceRoot
    )
    $receipt = $ReceiptState.Receipt
    $sessionDirectory = [IO.Path]::GetFullPath((Split-Path -Parent $ReceiptState.Path))
    Assert-NotReparseEntry $ReceiptState.Path 'evidence receipt'
    Assert-NotReparseEntry $sessionDirectory 'evidence session directory'
    if ([string]$receipt.tree_sha -notmatch '^[0-9a-f]{40}$' -or
        [string]$receipt.artifact.sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$receipt.session_id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$' -or
        [int]$receipt.issue -le 0) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' "evidence receipt '$($ReceiptState.Path)' contains invalid identity fields" `
            'discard the invalid session and stage the artifact again'
    }
    $launcherIdentity = Read-AstroFsvProcessIdentity `
        -Object $receipt.owners.launcher `
        -Code 'ASTRO_FSV_RECEIPT_INVALID' `
        -Description 'artifact receipt launcher identity'
    $promoterIdentity = Read-AstroFsvProcessIdentity `
        -Object $receipt.owners.promoter `
        -Code 'ASTRO_FSV_RECEIPT_INVALID' `
        -Description 'artifact receipt promoter identity'
    $expectedSession = Join-Path (Join-Path (Join-Path $EvidenceRoot ([string]$receipt.tree_sha)) `
        ([string]$receipt.artifact.sha256)) ([string]$receipt.session_id)
    if (-not [string]::Equals($sessionDirectory, [IO.Path]::GetFullPath($expectedSession), [StringComparison]::OrdinalIgnoreCase)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_PATH_MISMATCH' `
            "receipt path '$sessionDirectory' does not match its tree/hash/session identity '$expectedSession'" `
            'discard the cross-session or relocated receipt and stage a fresh artifact'
    }
    $artifact = Assert-PathWithin ([string]$receipt.artifact.path) $sessionDirectory `
        'ASTRO_FSV_ARTIFACT_ESCAPE' 'staged artifact path'
    if (-not (Test-AstroPathLongPath -LiteralPath $artifact -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_ARTIFACT_MISSING' "staged native artifact is absent: $artifact" `
            'treat this evidence session as invalid and stage a fresh artifact'
    }
    Assert-NotReparseEntry $artifact 'staged native artifact'
    $item = Get-AstroFileInfoLongPath $artifact
    $hash = File-Sha256 $artifact
    if ([uint64]$item.Length -ne [uint64]$receipt.artifact.bytes -or
        $hash -cne ([string]$receipt.artifact.sha256).ToLowerInvariant()) {
        Fail-Astro 'ASTRO_FSV_ARTIFACT_DRIFT' `
            "staged artifact bytes drifted: expected bytes=$($receipt.artifact.bytes) sha256=$($receipt.artifact.sha256), observed bytes=$($item.Length) sha256=$hash" `
            'discard the evidence session, identify the writer, and rebuild from a frozen tree'
    }
    return [ordered]@{
        receipt_path = $ReceiptState.Path
        session_directory = $sessionDirectory
        artifact_path = $artifact
        bytes = [uint64]$item.Length
        sha256 = $hash
        read_only = [bool]($item.Attributes -band [IO.FileAttributes]::ReadOnly)
        tree_sha = [string]$receipt.tree_sha
        issue = [int]$receipt.issue
        session_id = [string]$receipt.session_id
        owners = [ordered]@{
            launcher = $launcherIdentity
            promoter = $promoterIdentity
        }
        owner_probes = @(
            Get-AstroFsvOwnerProbes @(
                New-AstroFsvOwnerBinding `
                    'launcher' 'artifact receipt' $launcherIdentity
                New-AstroFsvOwnerBinding `
                    'promoter' 'artifact receipt' $promoterIdentity
            )
        )
    }
}

function Assert-FsvLockAbsent {
    param([Parameter(Mandatory)][string]$LockPath)
    if (-not (Test-AstroPathLongPath -LiteralPath $LockPath)) { return }
    try {
        $lockState = Read-AstroUtf8FileLongPath $LockPath | ConvertFrom-Json
    }
    catch {
        Fail-Astro 'ASTRO_FSV_LOCK_INVALID' `
            "FSV lock exists but is unreadable at ${LockPath}: $($_.Exception.Message)" `
            'preserve the lock and session; repair or tracker-migrate the exact legacy state without inferring ownership'
    }
    if ($lockState.schema -ne 'astrolabe.native-fsv-lock.v2') {
        Fail-Astro 'ASTRO_FSV_LOCK_LEGACY_OR_UNKNOWN' `
            "FSV lock exists with unsupported schema '$($lockState.schema)' at $LockPath" `
            'preserve the lock and session; PID-only state has no destructive authority'
    }
    if (-not $lockState.PSObject.Properties['owners'] -or
        -not $lockState.owners.PSObject.Properties['launcher'] -or
        -not $lockState.owners.PSObject.Properties['runner'] -or
        -not $lockState.owners.PSObject.Properties['child']) {
        Fail-Astro 'ASTRO_FSV_LOCK_INVALID' `
            "FSV lock omits the required launcher, runner, or child identity field at $LockPath" `
            'preserve the lock and session; incomplete exact ownership has no destructive authority'
    }
    $bindings = New-Object System.Collections.Generic.List[object]
    foreach ($role in @('launcher', 'runner')) {
        $identity = Read-AstroFsvProcessIdentity $lockState.owners.$role `
            'ASTRO_FSV_LOCK_INVALID' "FSV lock $role identity"
        $bindings.Add((New-AstroFsvOwnerBinding $role 'FSV lock' $identity))
    }
    if ($null -ne $lockState.owners.child) {
        $identity = Read-AstroFsvProcessIdentity $lockState.owners.child `
            'ASTRO_FSV_LOCK_INVALID' 'FSV lock child identity'
        $bindings.Add((New-AstroFsvOwnerBinding 'child' 'FSV lock' $identity))
    }
    $probes = @(
        Get-AstroFsvOwnerProbes ([object[]]$bindings.ToArray())
    )
    $states = @($probes | ForEach-Object { $_.state })
    $code = if ($states -contains 'exact-live') {
        'ASTRO_FSV_CLEANUP_LIVE_LOCK'
    }
    elseif ($states -contains 'unevaluable') {
        'ASTRO_FSV_CLEANUP_UNEVALUABLE_LOCK'
    }
    else {
        'ASTRO_FSV_CLEANUP_STALE_LOCK'
    }
    Fail-Astro $code `
        "FSV lock exists at $LockPath; lifecycle mutation refused; exact_probes=$($probes | ConvertTo-Json -Depth 8 -Compress)" `
        'never remove or bypass an FSV lock; resolve it through its exact tracker-bound lifecycle'
}

function Get-SessionFileInventory {
    param([Parameter(Mandatory)][string]$Session)
    $inventory = @()
    foreach ($entry in @(Get-AstroDirectoryEntriesLongPath $Session)) {
        Assert-NotReparseEntry $entry.FullName "evidence session entry '$($entry.Name)'"
        if (-not $entry.PSIsContainer -and
            -not (Test-AstroPathLongPath -LiteralPath $entry.FullName -PathType Leaf)) {
            Fail-Astro 'ASTRO_FSV_QUARANTINE_ENTRY_INVALID' "evidence session entry is not an ordinary file: $($entry.FullName)" 'preserve the session and investigate its filesystem identity'
        }
        if ($entry.PSIsContainer) {
            Fail-Astro 'ASTRO_FSV_QUARANTINE_DIRECTORY_REFUSED' "evidence session contains a nested directory: $($entry.FullName)" 'preserve the session; recovery inventory accepts only ordinary files in the exact session root'
        }
        $inventory += [ordered]@{
            name = $entry.Name
            path = [IO.Path]::GetFullPath($entry.FullName)
            bytes = [uint64]$entry.Length
            sha256 = File-Sha256 $entry.FullName
            attributes = $entry.Attributes.ToString()
            read_only = [bool]($entry.Attributes -band [IO.FileAttributes]::ReadOnly)
        }
    }
    return $inventory
}

function Get-AstroFsvSessionOwnerBindings {
    param(
        [Parameter(Mandatory)]$ReceiptState,
        [Parameter(Mandatory)]$Inspection,
        [Parameter(Mandatory)][string]$RunRecordPath,
        [Parameter(Mandatory)]$RunRecord
    )

    $bindings = New-Object System.Collections.Generic.List[object]
    $bindings.Add((New-AstroFsvOwnerBinding `
                'launcher' 'artifact receipt' $Inspection.owners.launcher))
    $bindings.Add((New-AstroFsvOwnerBinding `
                'promoter' 'artifact receipt' $Inspection.owners.promoter))
    $runLauncher = Read-AstroFsvProcessIdentity $RunRecord.launcher `
        'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
        'run-record launcher identity'
    $runRunner = Read-AstroFsvProcessIdentity $RunRecord.runner `
        'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
        'run-record runner identity'
    $runChild = Read-AstroFsvProcessIdentity $RunRecord.process.identity `
        'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
        'run-record child identity'
    if (-not (Test-AstroFsvIdentityEqual `
            $Inspection.owners.launcher $runLauncher)) {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "run-record launcher generation differs from its receipt: $RunRecordPath" `
            'preserve the complete session and investigate cross-lease provenance'
    }
    $bindings.Add((New-AstroFsvOwnerBinding `
                'launcher' $RunRecordPath $runLauncher))
    $bindings.Add((New-AstroFsvOwnerBinding `
                'runner' $RunRecordPath $runRunner))
    $bindings.Add((New-AstroFsvOwnerBinding `
                'child' $RunRecordPath $runChild))

    if (-not $RunRecord.PSObject.Properties['live_state'] -or
        -not $RunRecord.live_state.PSObject.Properties['path'] -or
        -not $RunRecord.live_state.PSObject.Properties['published'] -or
        -not $RunRecord.live_state.PSObject.Properties['bytes'] -or
        -not $RunRecord.live_state.PSObject.Properties['sha256']) {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "run record omits its exact live-state publication binding: $RunRecordPath" `
            'preserve the complete session and investigate its partial durable state'
    }
    $liveStatePath = Assert-PathWithin `
        ([string]$RunRecord.live_state.path) `
        $Inspection.session_directory `
        'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
        'run-record live-state path'
    if (-not [bool]$RunRecord.live_state.published) {
        if (Test-AstroPathLongPath -LiteralPath $liveStatePath) {
            Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
                "run record says its live state was not published, but the path exists: $liveStatePath" `
                'preserve the complete session and investigate the contradictory durable state'
        }
        if ([uint64]$RunRecord.live_state.bytes -ne 0 -or
            $null -ne $RunRecord.live_state.sha256) {
            Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
                "unpublished live-state binding carries bytes or a hash: $RunRecordPath" `
                'preserve the complete session and investigate the contradictory durable state'
        }
        return [object[]]$bindings.ToArray()
    }
    if (-not (Test-AstroPathLongPath `
            -LiteralPath $liveStatePath -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "run record binds a published live state that is absent: $liveStatePath" `
            'preserve the complete session and investigate its missing durable state'
    }
    $liveStateItem = Get-AstroFileInfoLongPath $liveStatePath
    $liveStateHash = File-Sha256 $liveStatePath
    if ([uint64]$RunRecord.live_state.bytes -ne
            [uint64]$liveStateItem.Length -or
        [string]$RunRecord.live_state.sha256 -cne $liveStateHash) {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "run-record live-state bytes drifted: $liveStatePath" `
            'preserve the complete session and investigate the durable-state writer'
    }
    Assert-NotReparseEntry $liveStatePath 'native FSV live-state record'
    try {
        $liveRecord = Read-AstroUtf8FileLongPath $liveStatePath |
            ConvertFrom-Json
    }
    catch {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "live-state record is unreadable: ${liveStatePath}: $($_.Exception.Message)" `
            'preserve the complete session and investigate its partial durable state'
    }
    if ($liveRecord.schema -ne 'astrolabe.native-fsv-live.v2' -or
        -not $liveRecord.PSObject.Properties['owners'] -or
        -not $liveRecord.owners.PSObject.Properties['launcher'] -or
        -not $liveRecord.owners.PSObject.Properties['runner'] -or
        -not $liveRecord.owners.PSObject.Properties['child'] -or
        -not $liveRecord.PSObject.Properties['artifact'] -or
        -not $liveRecord.artifact.PSObject.Properties['path'] -or
        -not $liveRecord.artifact.PSObject.Properties['sha256']) {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "live-state record omits required exact ownership or artifact binding: $liveStatePath" `
            'preserve the complete session and investigate its partial durable state'
    }
    if ([int]$liveRecord.issue -ne [int]$Inspection.issue -or
        [string]$liveRecord.tree_sha -cne [string]$Inspection.tree_sha -or
        [string]$liveRecord.artifact.sha256 -cne [string]$Inspection.sha256 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$liveRecord.artifact.path),
            [IO.Path]::GetFullPath($Inspection.artifact_path),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "live-state record is not bound to this session: $liveStatePath" `
            'preserve the complete session and investigate cross-session provenance'
    }
    $liveLauncher = Read-AstroFsvProcessIdentity `
        $liveRecord.owners.launcher `
        'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
        'live-state launcher identity'
    $liveRunner = Read-AstroFsvProcessIdentity `
        $liveRecord.owners.runner `
        'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
        'live-state runner identity'
    $liveChild = Read-AstroFsvProcessIdentity `
        $liveRecord.owners.child `
        'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
        'live-state child identity'
    if (-not (Test-AstroFsvIdentityEqual $runLauncher $liveLauncher) -or
        -not (Test-AstroFsvIdentityEqual $runRunner $liveRunner) -or
        -not (Test-AstroFsvIdentityEqual $runChild $liveChild)) {
        Fail-Astro 'ASTRO_FSV_SESSION_OWNER_RECORD_INVALID' `
            "live-state owner generations differ from the exact run record: $liveStatePath" `
            'preserve the complete session and investigate cross-run provenance'
    }
    foreach ($binding in @(
            (New-AstroFsvOwnerBinding `
                'launcher' $liveStatePath $liveLauncher),
            (New-AstroFsvOwnerBinding `
                'runner' $liveStatePath $liveRunner),
            (New-AstroFsvOwnerBinding `
                'child' $liveStatePath $liveChild)
        )) {
        $bindings.Add($binding)
    }
    return [object[]]$bindings.ToArray()
}

function Remove-EmptyEvidenceParents {
    param([Parameter(Mandatory)][string]$Session)

    foreach ($parent in @(
            (Split-Path -Parent $Session),
            (Split-Path -Parent (Split-Path -Parent $Session))
        )) {
        if ((Test-AstroPathLongPath -LiteralPath $parent -PathType Container) -and
            @(Get-AstroDirectoryEntriesLongPath $parent).Count -eq 0) {
            Remove-AstroEmptyDirectoryLongPath $parent
        }
    }
}

$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$evidenceRoot = Join-Path $workspace '.tmp\native-fsv-artifacts'
$abandonRoot = Join-Path $workspace '.tmp\native-fsv-abandon-records'
$recoveryRoot = Join-Path $workspace '.tmp\native-fsv-recovery-records'
$migrationRoot = Join-Path $workspace '.tmp\native-fsv-legacy-migration-records'
$fsvLock = Join-Path (Join-Path $workspace '.tmp') 'astrolabe-fsv.lock'
$launcherLockPath = Join-Path (Join-Path $workspace '.tmp') 'astrolabe-launcher.lock'
$gitExe = 'C:\Program Files\Git\bin\git.exe'

try {
    switch ($Operation) {
        'Stage' {
            if ($Issue -le 0) {
                Fail-Astro 'ASTRO_FSV_ISSUE_INVALID' "Issue must be a positive integer; received $Issue" `
                    'pass the driving GitHub issue number'
            }
            if ($TreeSha -notmatch '^[0-9a-fA-F]{40}$') {
                Fail-Astro 'ASTRO_FSV_TREE_SHA_INVALID' "TreeSha is not a full Git object id: '$TreeSha'" `
                    'pass the exact full commit SHA reported by git rev-parse HEAD'
            }
            $TreeSha = $TreeSha.ToLowerInvariant()
            if ($SessionId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') {
                Fail-Astro 'ASTRO_FSV_SESSION_ID_INVALID' "SessionId contains unsupported characters or length: '$SessionId'" `
                    'use 1-96 ASCII letters, digits, dot, underscore, or hyphen, beginning with a letter or digit'
            }
            if ([string]::IsNullOrWhiteSpace($SourcePath)) {
                Fail-Astro 'ASTRO_FSV_SOURCE_REQUIRED' 'SourcePath is required for Stage' `
                    'pass the exact native artifact emitted below the launcher-owned target root'
            }
            $source = [IO.Path]::GetFullPath($SourcePath)
            if (-not (Test-AstroPathLongPath -LiteralPath $source -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_SOURCE_MISSING' "native build artifact does not exist: $source" `
                    'build the real native artifact successfully before staging it'
            }
            Assert-NotReparseEntry $source 'native build artifact'
            $ownedTargets = @(
                (Join-Path $workspace 'target'),
                (Join-Path $workspace 'calyx\target')
            )
            $sourceOwned = $false
            foreach ($owned in $ownedTargets) {
                $prefix = Path-WithTrailingSeparator $owned
                if ($source.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                    $sourceOwned = $true
                    break
                }
            }
            if (-not $sourceOwned) {
                Fail-Astro 'ASTRO_FSV_SOURCE_OUTSIDE_TARGET' `
                    "native artifact '$source' is outside the launcher-owned Cargo target roots" `
                    'stage only a real artifact emitted under workspace target/ by the native launcher'
            }
            if (-not (Test-AstroPathLongPath -LiteralPath $gitExe -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_GIT_MISSING' "required native Git executable is absent: $gitExe" `
                    'restore the canonical Git for Windows installation before staging evidence'
            }
            $launcherOwner = Read-AstroLauncherLock -LockPath $launcherLockPath
            $launcherPid = if ($null -ne $launcherOwner.OwnerPid) {
                [int]$launcherOwner.OwnerPid
            } else {
                0
            }
            if ($launcherOwner.State -ne 'held' -or
                $launcherOwner.Issue -ne $Issue -or
                [string]$launcherOwner.HeadSha -cne $TreeSha) {
                Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_INVALID' `
                    "launcher protocol does not name the exact live issue #$Issue process identity for tree $TreeSha (state=$($launcherOwner.State), pid=$launcherPid, process_start_utc_ticks=$($launcherOwner.OwnerProcessStartUtcTicks), read_error=$($launcherOwner.ReadError), validation_error=$($launcherOwner.ValidationError))" `
                    'start artifact promotion through the native launcher with the same issue and tree'
            }
            $launcherIdentity = New-AstroProcessIdentityRecord `
                $launcherPid ([long]$launcherOwner.OwnerProcessStartUtcTicks)
            $launcherIdentityProbe = Get-AstroExactProcessIdentityProbe `
                -Pid $launcherPid `
                -ProcessStartUtcTicks (
                    [long]$launcherOwner.OwnerProcessStartUtcTicks
                )
            if ($launcherIdentityProbe.State -cne 'exact-live') {
                Fail-Astro 'ASTRO_FSV_LAUNCHER_IDENTITY_DRIFT' `
                    "launcher identity changed before Stage owner capture: $($launcherIdentityProbe | ConvertTo-Json -Depth 6 -Compress)" `
                    'preserve target and protocol state; only the exact live launcher may stage an artifact'
            }
            if (-not (Test-DescendantOf -CandidatePid $PID -AncestorPid $launcherPid)) {
                Fail-Astro 'ASTRO_FSV_PROMOTER_NOT_OWNED' "promoter PID $PID is not a descendant of launcher PID $launcherPid" `
                    'invoke Stage synchronously from the launcher-owned child process'
            }
            $promoterIdentity = Get-AstroCurrentProcessIdentity `
                -Pid $PID `
                -Code 'ASTRO_FSV_PROMOTER_IDENTITY_UNEVALUABLE' `
                -Description 'artifact promoter'
            $repoState = Get-RepoState -GitExe $gitExe -Workspace $workspace
            if ($repoState.head_sha -cne $TreeSha) {
                Fail-Astro 'ASTRO_FSV_TREE_MISMATCH' "current HEAD '$($repoState.head_sha)' does not match requested evidence tree '$TreeSha'" `
                    'freeze the checkout, rebuild, and stage with the exact current full commit SHA'
            }
            $tracked = (& $gitExe -C $workspace status --porcelain --untracked-files=no) -join "`n"
            if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace($tracked)) {
                Fail-Astro 'ASTRO_FSV_TREE_DIRTY' "tracked checkout is not clean at artifact promotion: $tracked" `
                    'commit the implementation and rebuild from a clean frozen tree'
            }
            if ([string]$launcherOwner.StatusSha256 -cne [string]$repoState.status_sha256 -or
                [string]$launcherOwner.DiffSha256 -cne [string]$repoState.diff_sha256) {
                Fail-Astro 'ASTRO_FSV_LAUNCHER_TREE_DRIFT' `
                    "repository status/diff fingerprints differ from the launcher acquisition state (expected_status_sha256=$($launcherOwner.StatusSha256), actual_status_sha256=$($repoState.status_sha256), expected_diff_sha256=$($launcherOwner.DiffSha256), actual_diff_sha256=$($repoState.diff_sha256))" `
                    'discard this build, restore the frozen checkout, and rebuild from a fresh launcher lease'
            }

            $sourceHashBefore = File-Sha256 $source
            $sourceItem = Get-AstroFileInfoLongPath $source
            $hashParent = Join-Path (Join-Path $evidenceRoot $TreeSha) $sourceHashBefore
            $finalDirectory = Join-Path $hashParent $SessionId
            if (Test-AstroPathLongPath -LiteralPath $finalDirectory) {
                Fail-Astro 'ASTRO_FSV_STAGE_REUSE_REFUSED' "evidence session already exists: $finalDirectory" `
                    'use a fresh SessionId; evidence sessions are immutable and never overwritten'
            }
            Assert-NotReparseEntry (Join-Path $workspace '.tmp') 'workspace temporary directory'
            Assert-NotReparseEntry $evidenceRoot 'evidence root'
            Assert-NotReparseEntry (Join-Path $evidenceRoot $TreeSha) 'evidence tree directory'
            Assert-NotReparseEntry $hashParent 'evidence hash directory'
            New-AstroDirectoryLongPath $hashParent | Out-Null
            Assert-NotReparseEntry $hashParent 'evidence hash directory'
            $publishingDirectory = Join-Path $hashParent (".$SessionId.publishing-$PID-" + [guid]::NewGuid().ToString('N'))
            New-AstroDirectoryNoClobberLongPath $publishingDirectory | Out-Null
            $published = $false
            try {
                $artifactName = [IO.Path]::GetFileName($source)
                $staged = Join-Path $publishingDirectory $artifactName
                Copy-FileDurable $source $staged
                $sourceHashAfter = File-Sha256 $source
                $stagedHash = File-Sha256 $staged
                $stagedItem = Get-AstroFileInfoLongPath $staged
                if ($sourceHashBefore -cne $sourceHashAfter -or $sourceHashBefore -cne $stagedHash -or
                    [uint64]$sourceItem.Length -ne [uint64]$stagedItem.Length) {
                    Fail-Astro 'ASTRO_FSV_STAGE_COPY_MISMATCH' `
                        "source/staged bytes changed during promotion: source_before=$sourceHashBefore source_after=$sourceHashAfter staged=$stagedHash" `
                        'discard the partial publication, stop the writer, and rebuild from a frozen tree'
                }
                Set-AstroFileReadOnlyLongPath -LiteralPath $staged -ReadOnly $true
                $finalArtifact = Join-Path $finalDirectory $artifactName
                $receipt = [ordered]@{
                    schema = 'astrolabe.native-fsv-artifact.v2'
                    issue = $Issue
                    session_id = $SessionId
                    tree_sha = $TreeSha
                    promoted_at_utc = [DateTime]::UtcNow.ToString('o')
                    owners = [ordered]@{
                        launcher = $launcherIdentity
                        promoter = $promoterIdentity
                    }
                    repository = $repoState
                    source = [ordered]@{ path = $source; bytes = [uint64]$sourceItem.Length; sha256 = $sourceHashBefore }
                    artifact = [ordered]@{ path = $finalArtifact; bytes = [uint64]$stagedItem.Length; sha256 = $stagedHash; read_only = $true }
                    publication = [ordered]@{ method = 'MoveFileExW(MOVEFILE_WRITE_THROUGH,no-replace)'; same_volume = $true }
                }
                $receiptJson = $receipt | ConvertTo-Json -Depth 12
                Write-NewDurableUtf8 (Join-Path $publishingDirectory 'receipt.json') $receiptJson
                [AstroFsvPublish]::PublishDirectory($publishingDirectory, $finalDirectory)
                $published = $true
                Assert-NotReparseEntry $finalDirectory 'published evidence session directory'
            }
            finally {
                if (-not $published -and
                    (Test-AstroPathLongPath -LiteralPath $publishingDirectory)) {
                    Remove-AstroOrdinaryFlatDirectoryLongPath $publishingDirectory
                }
            }
            $receiptState = Read-Receipt (Join-Path $finalDirectory 'receipt.json') $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            [ordered]@{ operation = 'stage'; receipt = $receiptState.Receipt; readback = $inspection } |
                ConvertTo-Json -Depth 15 -Compress | Write-Output
        }
        'Inspect' {
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            [ordered]@{ operation = 'inspect'; readback = $inspection } |
                ConvertTo-Json -Depth 12 -Compress | Write-Output
        }
        'RetireLock' {
            if ($Issue -le 0) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_ISSUE_INVALID' `
                    'Issue must be positive for stale FSV lock retirement' `
                    'pass the driving GitHub issue number'
            }
            if ([string]::IsNullOrWhiteSpace($TrackerCommentUrl)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_TRACKER_REQUIRED' `
                    'TrackerCommentUrl is required for stale FSV lock retirement' `
                    'post a GitHub issue comment binding the exact lock/run/session state before mutation'
            }
            if ($ReasonCode -notmatch '^[A-Z][A-Z0-9_]{2,95}$') {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_REASON_INVALID' `
                    "ReasonCode is not a structured upper-case code: '$ReasonCode'" `
                    'pass the exact stable failure code that left the stale FSV lock'
            }
            if ([string]::IsNullOrWhiteSpace($ReasonMessage)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_REASON_INVALID' `
                    'ReasonMessage is required and may not be blank' `
                    'describe the exact stale-lock condition being retired'
            }
            if ([string]::IsNullOrWhiteSpace($RecoveryRecordPath)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_RECORD_REQUIRED' `
                    'RecoveryRecordPath is required for RetireLock' `
                    "use a fresh JSON path below $recoveryRoot; the record persists after exact lock removal"
            }
            if ([string]::IsNullOrWhiteSpace($RunRecordPath)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_REQUIRED' `
                    'RunRecordPath is required for RetireLock' `
                    'pass the exact run record written by native-fsv-run.ps1'
            }
            if ([string]::IsNullOrWhiteSpace($LiveStatePath)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_LIVE_STATE_REQUIRED' `
                    'LiveStatePath is required for RetireLock' `
                    'pass the exact live-state record written by native-fsv-run.ps1'
            }
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            $launcherProtocolState =
                Read-AstroLauncherLock -LockPath $launcherLockPath
            if ($launcherProtocolState.State -ne 'absent') {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_LAUNCHER_LOCK' `
                    "launcher protocol is '$($launcherProtocolState.State)'; stale-lock retirement requires authoritative absence (transitions=$(@($launcherProtocolState.TransitionPaths) -join '; '), read_error=$($launcherProtocolState.ReadError), validation_error=$($launcherProtocolState.ValidationError))" `
                    'wait for the exact launcher generation to finish or recover it through the launcher protocol before retiring the FSV lock'
            }
            if (-not (Test-AstroPathLongPath -LiteralPath $fsvLock -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_ABSENT' `
                    "FSV lock is already absent: $fsvLock" `
                    'do not manufacture retirement evidence for an absent lock'
            }
            Assert-NotReparseEntry $fsvLock 'native FSV lock'
            $lockShaBefore = File-Sha256 $fsvLock
            try {
                $lockState = Read-AstroUtf8FileLongPath $fsvLock | ConvertFrom-Json
            }
            catch {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_INVALID_LOCK' `
                    "FSV lock is unreadable: ${fsvLock}: $($_.Exception.Message)" `
                    'preserve the lock and investigate its exact bytes'
            }
            if ($lockState.schema -ne 'astrolabe.native-fsv-lock.v2' -or
                [int]$lockState.issue -ne [int]$inspection.issue -or
                [string]$lockState.tree_sha -cne [string]$inspection.tree_sha -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$lockState.artifact_path), $inspection.artifact_path, [StringComparison]::OrdinalIgnoreCase) -or
                [string]$lockState.artifact_sha256 -cne [string]$inspection.sha256 -or
                -not $lockState.PSObject.Properties['owners'] -or
                -not $lockState.owners.PSObject.Properties['launcher'] -or
                -not $lockState.owners.PSObject.Properties['runner'] -or
                -not $lockState.owners.PSObject.Properties['child']) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_INVALID_LOCK' `
                    "FSV lock is not bound to the selected issue/tree/artifact: $fsvLock" `
                    'preserve the lock and session; retry with the exact receipt/run/live-state binding'
            }
            $lockLauncher = Read-AstroFsvProcessIdentity $lockState.owners.launcher `
                'ASTRO_FSV_LOCK_RETIRE_INVALID_LOCK' 'FSV lock launcher identity'
            $lockRunner = Read-AstroFsvProcessIdentity $lockState.owners.runner `
                'ASTRO_FSV_LOCK_RETIRE_INVALID_LOCK' 'FSV lock runner identity'
            $lockChild = Read-AstroFsvProcessIdentity $lockState.owners.child `
                'ASTRO_FSV_LOCK_RETIRE_INVALID_LOCK' 'FSV lock child identity'
            $runRecord = Assert-PathWithin $RunRecordPath $inspection.session_directory `
                'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_ESCAPE' 'run record path'
            if (-not (Test-AstroPathLongPath -LiteralPath $runRecord -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_MISSING' `
                    "run record does not exist: $runRecord" `
                    'preserve the lock and session; retry only with a completed run record'
            }
            try {
                $record = Read-AstroUtf8FileLongPath $runRecord | ConvertFrom-Json
            }
            catch {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_INVALID' `
                    "parse run record '$runRecord' failed: $($_.Exception.Message)" `
                    'preserve the lock and session; investigate the incomplete run'
            }
            if ($record.schema -ne 'astrolabe.native-fsv-run.v2' -or
                [int]$record.issue -ne [int]$inspection.issue -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$record.receipt_path), $receiptState.Path, [StringComparison]::OrdinalIgnoreCase) -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$record.artifact.path), $inspection.artifact_path, [StringComparison]::OrdinalIgnoreCase) -or
                [string]$record.artifact.sha256 -cne [string]$inspection.sha256) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_INVALID' `
                    "run record '$runRecord' is not bound to the selected receipt/artifact" `
                    'preserve the lock and session; retry with the exact completed run record'
            }
            $explicitLiveState = Assert-PathWithin $LiveStatePath $inspection.session_directory `
                'ASTRO_FSV_LOCK_RETIRE_LIVE_STATE_ESCAPE' 'live-state path'
            if (-not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$record.live_state.path),
                    $explicitLiveState,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_LIVE_STATE_MISMATCH' `
                    "explicit live-state path does not match run-record binding: $explicitLiveState" `
                    'preserve the lock and session; pass the exact live-state path named by the run record'
            }
            $sessionBindings = @(
                Get-AstroFsvSessionOwnerBindings `
                    -ReceiptState $receiptState `
                    -Inspection $inspection `
                    -RunRecordPath $runRecord `
                    -RunRecord $record
            )
            $runRunner = Read-AstroFsvProcessIdentity $record.runner `
                'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_INVALID' 'run-record runner identity'
            $runChild = Read-AstroFsvProcessIdentity $record.process.identity `
                'ASTRO_FSV_LOCK_RETIRE_RUN_RECORD_INVALID' 'run-record child identity'
            if (-not (Test-AstroFsvIdentityEqual $lockLauncher $inspection.owners.launcher) -or
                -not (Test-AstroFsvIdentityEqual $lockRunner $runRunner) -or
                -not (Test-AstroFsvIdentityEqual $lockChild $runChild)) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_OWNER_MISMATCH' `
                    'FSV lock owner generations differ from the selected receipt/run/live-state records' `
                    'preserve the lock and session; retry with the exact bound artifacts'
            }
            $ownerBindings = New-Object System.Collections.Generic.List[object]
            foreach ($binding in $sessionBindings) { $ownerBindings.Add($binding) }
            $ownerBindings.Add((New-AstroFsvOwnerBinding 'launcher' $fsvLock $lockLauncher))
            $ownerBindings.Add((New-AstroFsvOwnerBinding 'runner' $fsvLock $lockRunner))
            $ownerBindings.Add((New-AstroFsvOwnerBinding 'child' $fsvLock $lockChild))
            $initialOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings ([object[]]$ownerBindings.ToArray()) `
                    -CodePrefix 'ASTRO_FSV_LOCK_RETIRE' `
                    -Description 'stale FSV lock retirement'
            )
            $recoveryRecord = Assert-PathWithin $RecoveryRecordPath $recoveryRoot `
                'ASTRO_FSV_LOCK_RETIRE_RECORD_ESCAPE' 'retirement record path'
            if (Test-AstroPathLongPath -LiteralPath $recoveryRecord) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_RECORD_REUSE_REFUSED' `
                    "retirement record already exists: $recoveryRecord" `
                    'use one fresh append-only recovery record path for each stale lock retirement'
            }
            Assert-NotReparseEntry $recoveryRoot 'recovery record root'
            $recordParent = Split-Path -Parent $recoveryRecord
            New-AstroDirectoryLongPath $recordParent | Out-Null
            Assert-NotReparseEntry $recordParent 'retirement record parent'
            $currentRepository = Get-RepoState -GitExe $gitExe -Workspace $workspace
            $finalOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings ([object[]]$ownerBindings.ToArray()) `
                    -CodePrefix 'ASTRO_FSV_LOCK_RETIRE' `
                    -Description 'stale FSV lock retirement final authorization'
            )
            $retirement = [ordered]@{
                schema = 'astrolabe.native-fsv-lock-retirement.v1'
                verdict = 'retired-stale-lock'
                issue = [int]$inspection.issue
                recorded_at_utc = [DateTime]::UtcNow.ToString('o')
                tracker_comment_url = $TrackerCommentUrl
                fsv_lock = [ordered]@{
                    path = $fsvLock
                    sha256 = $lockShaBefore
                    state = $lockState
                }
                receipt_path = $receiptState.Path
                session_directory = $inspection.session_directory
                run_record_path = $runRecord
                run_record_sha256 = File-Sha256 $runRecord
                live_state_path = $explicitLiveState
                live_state_sha256 = File-Sha256 $explicitLiveState
                artifact = [ordered]@{
                    path = $inspection.artifact_path
                    bytes = [uint64]$inspection.bytes
                    sha256 = $inspection.sha256
                }
                launcher_protocol_state = $launcherProtocolState.State
                staged_repository = $receiptState.Receipt.repository
                current_repository = $currentRepository
                owners = [ordered]@{
                    identities = @($ownerBindings.ToArray() | ForEach-Object {
                            [ordered]@{
                                role = $_.Role
                                source = $_.Source
                                identity = $_.Identity
                            }
                        })
                    initial_probes = $initialOwnerProbes
                    final_probes = $finalOwnerProbes
                }
                failure = [ordered]@{
                    code = $ReasonCode
                    message = $ReasonMessage
                }
            }
            Write-NewDurableUtf8 $recoveryRecord ($retirement | ConvertTo-Json -Depth 24)
            $persistedRetirement =
                Read-AstroUtf8FileLongPath $recoveryRecord | ConvertFrom-Json
            if ($persistedRetirement.schema -ne 'astrolabe.native-fsv-lock-retirement.v1' -or
                [string]$persistedRetirement.fsv_lock.sha256 -cne $lockShaBefore -or
                [string]$persistedRetirement.artifact.sha256 -cne [string]$inspection.sha256 -or
                [string]$persistedRetirement.failure.code -cne $ReasonCode) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_RECORD_INVALID' `
                    "persisted retirement record readback does not bind the stale lock: $recoveryRecord" `
                    'preserve both lock and record and investigate the durable-write mismatch'
            }
            Assert-AstroFsvPersistedOwnerEnvelope `
                -Owners $persistedRetirement.owners `
                -ExpectedBindings ([object[]]$ownerBindings.ToArray()) `
                -Code 'ASTRO_FSV_LOCK_RETIRE_RECORD_INVALID' `
                -Description 'persisted stale-lock retirement record'
            Remove-AstroFileLongPath $fsvLock
            if (Test-AstroPathLongPath -LiteralPath $fsvLock) {
                Fail-Astro 'ASTRO_FSV_LOCK_RETIRE_DELETE_FAILED' `
                    "FSV lock remains after exact retirement delete: $fsvLock" `
                    'preserve the recovery record and inspect open handles before retrying'
            }
            [ordered]@{
                operation = 'retire-lock'
                record_path = $recoveryRecord
                record_sha256 = File-Sha256 $recoveryRecord
                record = $persistedRetirement
                before = [ordered]@{
                    fsv_lock = $fsvLock
                    exists = $true
                    sha256 = $lockShaBefore
                    owners = $retirement.owners
                }
                after = [ordered]@{ fsv_lock = $fsvLock; exists = $false }
            } | ConvertTo-Json -Depth 26 -Compress | Write-Output
        }
        'Abandon' {
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            Assert-FsvLockAbsent $fsvLock
            $launcherProtocolState = Read-AstroLauncherLock -LockPath $launcherLockPath
            if ($launcherProtocolState.State -ne 'absent') {
                Fail-Astro 'ASTRO_FSV_ABANDON_LAUNCHER_LOCK' `
                    "launcher protocol state is '$($launcherProtocolState.State)' at $launcherLockPath; never-run session abandonment requires authoritative absence (transitions=$(@($launcherProtocolState.TransitionPaths) -join '; '), read_error=$($launcherProtocolState.ReadError), validation_error=$($launcherProtocolState.ValidationError))" `
                    'wait for a live owner to finish, or use the tracker-bound explicit reclaim command for stale/unreadable/transition state; then independently prove every receipt owner dead'
            }
            if ($ReasonCode -notmatch '^[A-Z][A-Z0-9_]{2,95}$') {
                Fail-Astro 'ASTRO_FSV_ABANDON_REASON_INVALID' "ReasonCode is not a structured upper-case code: '$ReasonCode'" `
                    'pass a stable code such as ASTRO_FSV_ORCHESTRATION_FAILED'
            }
            if ([string]::IsNullOrWhiteSpace($ReasonMessage)) {
                Fail-Astro 'ASTRO_FSV_ABANDON_REASON_INVALID' 'ReasonMessage is required and may not be blank' `
                    'describe the exact pre-run failure whose persisted evidence authorizes abandonment'
            }
            if ([string]::IsNullOrWhiteSpace($AbandonRecordPath)) {
                Fail-Astro 'ASTRO_FSV_ABANDON_RECORD_REQUIRED' 'AbandonRecordPath is required for Abandon' `
                    "use a fresh JSON path below $abandonRoot; the record persists after session removal"
            }
            $abandonRecord = Assert-PathWithin $AbandonRecordPath $abandonRoot `
                'ASTRO_FSV_ABANDON_RECORD_ESCAPE' 'abandonment record path'
            if (Test-AstroPathLongPath -LiteralPath $abandonRecord) {
                Fail-Astro 'ASTRO_FSV_ABANDON_RECORD_REUSE_REFUSED' "abandonment record already exists: $abandonRecord" `
                    'use one fresh append-only record path for each never-run evidence session'
            }
            $receipt = $receiptState.Receipt
            $ownerBindings = @(
                New-AstroFsvOwnerBinding `
                    'launcher' 'artifact receipt' $inspection.owners.launcher
                New-AstroFsvOwnerBinding `
                    'promoter' 'artifact receipt' $inspection.owners.promoter
            )
            $initialOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_ABANDON' `
                    -Description 'never-run evidence session'
            )
            $session = [IO.Path]::GetFullPath($inspection.session_directory)
            $allowedEntries = @(
                [IO.Path]::GetFullPath($receiptState.Path),
                [IO.Path]::GetFullPath($inspection.artifact_path)
            )
            $sessionEntries = @(Get-AstroDirectoryEntriesLongPath $session)
            $unexpectedEntries = @($sessionEntries | Where-Object {
                $full = [IO.Path]::GetFullPath($_.FullName)
                -not ($allowedEntries -contains $full)
            } | ForEach-Object { $_.FullName })
            if ($unexpectedEntries.Count -gt 0 -or $sessionEntries.Count -ne 2) {
                Fail-Astro 'ASTRO_FSV_ABANDON_NONPRISTINE' `
                    "session contains state beyond its never-run artifact and receipt: $($unexpectedEntries -join ', ')" `
                    'preserve the session; inspect the partial/live run state and use Cleanup only with a valid bound run record'
            }
            Assert-NotReparseEntry $abandonRoot 'abandonment record root'
            $recordParent = Split-Path -Parent $abandonRecord
            Assert-NotReparseEntry $recordParent 'abandonment record parent'
            New-AstroDirectoryLongPath $recordParent | Out-Null
            Assert-NotReparseEntry $recordParent 'abandonment record parent'
            $currentRepository = Get-RepoState -GitExe $gitExe -Workspace $workspace
            $finalOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_ABANDON' `
                    -Description 'never-run evidence session final authorization'
            )
            $record = [ordered]@{
                schema = 'astrolabe.native-fsv-abandon.v2'
                verdict = 'abandoned-before-run'
                issue = [int]$inspection.issue
                recorded_at_utc = [DateTime]::UtcNow.ToString('o')
                receipt_path = $receiptState.Path
                session_directory = $session
                artifact = [ordered]@{
                    path = $inspection.artifact_path
                    bytes = [uint64]$inspection.bytes
                    sha256 = $inspection.sha256
                }
                staged_repository = $receipt.repository
                current_repository = $currentRepository
                owners = [ordered]@{
                    identities = @($ownerBindings | ForEach-Object {
                            [ordered]@{
                                role = $_.Role
                                source = $_.Source
                                identity = $_.Identity
                            }
                        })
                    initial_probes = $initialOwnerProbes
                    final_probes = $finalOwnerProbes
                }
                failure = [ordered]@{
                    code = $ReasonCode
                    message = $ReasonMessage
                }
            }
            Write-NewDurableUtf8 $abandonRecord ($record | ConvertTo-Json -Depth 15)
            $persistedRecord =
                Read-AstroUtf8FileLongPath $abandonRecord | ConvertFrom-Json
            if ($persistedRecord.schema -ne 'astrolabe.native-fsv-abandon.v2' -or
                [string]$persistedRecord.artifact.sha256 -cne [string]$inspection.sha256 -or
                [string]$persistedRecord.failure.code -cne $ReasonCode) {
                Fail-Astro 'ASTRO_FSV_ABANDON_RECORD_INVALID' `
                    "persisted abandonment record readback does not bind the session: $abandonRecord" `
                    'preserve both session and record and investigate the durable-write mismatch'
            }
            Assert-AstroFsvPersistedOwnerEnvelope `
                -Owners $persistedRecord.owners `
                -ExpectedBindings $ownerBindings `
                -Code 'ASTRO_FSV_ABANDON_RECORD_INVALID' `
                -Description 'persisted abandonment record'
            $recordHash = File-Sha256 $abandonRecord
            $before = [ordered]@{
                session = $session
                exists = $true
                artifact_sha256 = $inspection.sha256
                owners = $record.owners
            }
            Set-AstroFileReadOnlyLongPath `
                -LiteralPath $inspection.artifact_path -ReadOnly $false
            Remove-AstroOrdinaryFlatDirectoryLongPath $session
            if (Test-AstroPathLongPath -LiteralPath $session) {
                Fail-Astro 'ASTRO_FSV_ABANDON_FAILED' "evidence session remains after abandonment: $session" `
                    'preserve the external abandonment record and inspect open handles before retrying exact cleanup'
            }
            Remove-EmptyEvidenceParents $session
            [ordered]@{
                operation = 'abandon'
                record_path = $abandonRecord
                record_sha256 = $recordHash
                record = $persistedRecord
                before = $before
                after = [ordered]@{ session = $session; exists = $false }
            } | ConvertTo-Json -Depth 18 -Compress | Write-Output
        }
        'Quarantine' {
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            Assert-FsvLockAbsent $fsvLock
            $launcherProtocolState = Read-AstroLauncherLock -LockPath $launcherLockPath
            if ($launcherProtocolState.State -ne 'absent') {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_LAUNCHER_LOCK' `
                    "launcher protocol state is '$($launcherProtocolState.State)' at $launcherLockPath; terminal-session quarantine requires authoritative absence (transitions=$(@($launcherProtocolState.TransitionPaths) -join '; '), read_error=$($launcherProtocolState.ReadError), validation_error=$($launcherProtocolState.ValidationError))" `
                    'wait for a live owner to finish, or archive stale/unreadable/transition state through scripts\reclaim-launcher-lock.ps1 with exact tracker evidence before quarantine'
            }
            if ($ReasonCode -notmatch '^[A-Z][A-Z0-9_]{2,95}$') {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_REASON_INVALID' "ReasonCode is not a structured upper-case code: '$ReasonCode'" `
                    'pass the exact stable failure code that left the terminal partial session'
            }
            if ([string]::IsNullOrWhiteSpace($ReasonMessage)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_REASON_INVALID' 'ReasonMessage is required and may not be blank' `
                    'describe the exact terminal runner failure that prevented a valid run record'
            }
            if ([string]::IsNullOrWhiteSpace($RecoveryRecordPath)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_RECORD_REQUIRED' 'RecoveryRecordPath is required for Quarantine' `
                    "use a fresh JSON path below $recoveryRoot; the record persists after exact session removal"
            }
            $recoveryRecord = Assert-PathWithin $RecoveryRecordPath $recoveryRoot `
                'ASTRO_FSV_QUARANTINE_RECORD_ESCAPE' 'recovery record path'
            if (Test-AstroPathLongPath -LiteralPath $recoveryRecord) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_RECORD_REUSE_REFUSED' "recovery record already exists: $recoveryRecord" `
                    'use one fresh append-only recovery record path for each terminal partial session'
            }
            if ([string]::IsNullOrWhiteSpace($LiveStatePath)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_LIVE_STATE_REQUIRED' 'LiveStatePath is required for Quarantine' `
                    'pass the exact live-state JSON published by native-fsv-run.ps1 for this session'
            }
            $liveStateFile = Assert-PathWithin $LiveStatePath $inspection.session_directory `
                'ASTRO_FSV_QUARANTINE_LIVE_STATE_ESCAPE' 'live-state path'
            if (-not (Test-AstroPathLongPath -LiteralPath $liveStateFile -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_LIVE_STATE_MISSING' "live-state file does not exist: $liveStateFile" `
                    'pristine never-run sessions use Abandon; preserve any unexplained nonpristine session'
            }
            Assert-NotReparseEntry $liveStateFile 'native FSV live-state file'
            try {
                $liveState =
                    Read-AstroUtf8FileLongPath $liveStateFile | ConvertFrom-Json
            }
            catch {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_LIVE_STATE_INVALID' "parse live-state '$liveStateFile' failed: $($_.Exception.Message)" `
                    'preserve the session and investigate its incomplete process provenance'
            }
            if ($liveState.schema -ne 'astrolabe.native-fsv-live.v2' -or
                -not $liveState.PSObject.Properties['owners'] -or
                -not $liveState.owners.PSObject.Properties['launcher'] -or
                -not $liveState.owners.PSObject.Properties['runner'] -or
                -not $liveState.owners.PSObject.Properties['child'] -or
                [int]$liveState.issue -ne [int]$inspection.issue -or
                [string]$liveState.tree_sha -cne [string]$inspection.tree_sha -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$liveState.artifact.path), $inspection.artifact_path, [StringComparison]::OrdinalIgnoreCase) -or
                [uint64]$liveState.artifact.bytes -ne [uint64]$inspection.bytes -or
                [string]$liveState.artifact.sha256 -cne [string]$inspection.sha256) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_LIVE_STATE_INVALID' `
                    "live-state '$liveStateFile' is not bound to the staged issue/tree/artifact" `
                    'preserve the session and investigate the cross-session or incomplete provenance'
            }
            $receipt = $receiptState.Receipt
            $liveLauncherIdentity = Read-AstroFsvProcessIdentity `
                $liveState.owners.launcher `
                'ASTRO_FSV_QUARANTINE_OWNER_INVALID' `
                'runner live-state launcher identity'
            $liveRunnerIdentity = Read-AstroFsvProcessIdentity `
                $liveState.owners.runner `
                'ASTRO_FSV_QUARANTINE_OWNER_INVALID' `
                'runner live-state runner identity'
            $liveChildIdentity = Read-AstroFsvProcessIdentity `
                $liveState.owners.child `
                'ASTRO_FSV_QUARANTINE_OWNER_INVALID' `
                'runner live-state child identity'
            if (-not (Test-AstroFsvIdentityEqual `
                    $inspection.owners.launcher $liveLauncherIdentity)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_OWNER_MISMATCH' `
                    'receipt and runner live-state launcher generations differ' `
                    'preserve the session and investigate the cross-lease provenance'
            }
            $ownerBindings = @(
                New-AstroFsvOwnerBinding `
                    'launcher' 'artifact receipt' $inspection.owners.launcher
                New-AstroFsvOwnerBinding `
                    'promoter' 'artifact receipt' $inspection.owners.promoter
                New-AstroFsvOwnerBinding `
                    'launcher' 'runner live state' $liveLauncherIdentity
                New-AstroFsvOwnerBinding `
                    'runner' 'runner live state' $liveRunnerIdentity
                New-AstroFsvOwnerBinding `
                    'child' 'runner live state' $liveChildIdentity
            )
            $initialOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_QUARANTINE' `
                    -Description 'terminal partial evidence session'
            )
            if ([string]::IsNullOrWhiteSpace($RunRecordPath)) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_RUN_RECORD_PATH_REQUIRED' 'RunRecordPath is required for Quarantine' `
                    'pass the exact run-record path that the failed runner was required to publish'
            }
            $expectedRunRecord = Assert-PathWithin $RunRecordPath $inspection.session_directory `
                'ASTRO_FSV_QUARANTINE_RUN_RECORD_ESCAPE' 'expected run-record path'
            $runRecordState = 'missing'
            if (Test-AstroPathLongPath -LiteralPath $expectedRunRecord -PathType Leaf) {
                Assert-NotReparseEntry $expectedRunRecord 'native FSV run record'
                $runRecordState = 'invalid'
                try {
                    $candidateRecord =
                        Read-AstroUtf8FileLongPath $expectedRunRecord |
                            ConvertFrom-Json
                    if ($candidateRecord.schema -eq 'astrolabe.native-fsv-run.v2' -and
                        [int]$candidateRecord.issue -eq [int]$inspection.issue -and
                        [string]::Equals([IO.Path]::GetFullPath([string]$candidateRecord.receipt_path), $receiptState.Path, [StringComparison]::OrdinalIgnoreCase) -and
                        [string]::Equals([IO.Path]::GetFullPath([string]$candidateRecord.artifact.path), $inspection.artifact_path, [StringComparison]::OrdinalIgnoreCase) -and
                        [string]$candidateRecord.artifact.sha256 -ceq [string]$inspection.sha256) {
                        Fail-Astro 'ASTRO_FSV_QUARANTINE_VALID_RUN_RECORD' `
                            "session has a valid bound run record at $expectedRunRecord" `
                            'use Cleanup for a completed real run; Quarantine is only for terminal partial state'
                    }
                }
                catch {
                    if ($_.Exception.Data.Contains('AstroCode')) { throw }
                }
            }
            $session = [IO.Path]::GetFullPath($inspection.session_directory)
            $inventory = @(Get-SessionFileInventory $session)
            if ($inventory.Count -lt 4) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_NONPARTIAL' `
                    "session inventory has only $($inventory.Count) files; no terminal partial-run state is proven" `
                    'use Abandon only for a pristine two-file never-run session; otherwise preserve and investigate the incomplete state'
            }
            $inventoryPaths = @($inventory | ForEach-Object { [string]$_.path })
            foreach ($requiredPath in @($receiptState.Path, $inspection.artifact_path, $liveStateFile)) {
                if (-not ($inventoryPaths -contains [IO.Path]::GetFullPath($requiredPath))) {
                    Fail-Astro 'ASTRO_FSV_QUARANTINE_INVENTORY_INVALID' `
                        "session inventory omitted required path $requiredPath" `
                        'preserve the session and investigate its filesystem identity'
                }
            }
            $outputInventory = @($inventory | Where-Object {
                [string]$_.path -cne [string]$receiptState.Path -and
                [string]$_.path -cne [string]$inspection.artifact_path -and
                [string]$_.path -cne [string]$liveStateFile -and
                [string]$_.path -cne [string]$expectedRunRecord
            })
            if ($outputInventory.Count -eq 0) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_OUTPUT_EVIDENCE_MISSING' `
                    'terminal partial session contains no child output file beyond receipt/artifact/live state' `
                    'preserve the session; no real child-output state exists to distinguish it from incomplete staging'
            }
            Assert-NotReparseEntry $recoveryRoot 'recovery record root'
            $recordParent = Split-Path -Parent $recoveryRecord
            New-AstroDirectoryLongPath $recordParent | Out-Null
            Assert-NotReparseEntry $recordParent 'recovery record parent'
            $currentRepository = Get-RepoState -GitExe $gitExe -Workspace $workspace
            $finalOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_QUARANTINE' `
                    -Description 'terminal partial evidence session final authorization'
            )
            $record = [ordered]@{
                schema = 'astrolabe.native-fsv-recovery.v2'
                verdict = 'quarantined-unverified-run'
                issue = [int]$inspection.issue
                recorded_at_utc = [DateTime]::UtcNow.ToString('o')
                receipt_path = $receiptState.Path
                session_directory = $session
                expected_run_record_path = $expectedRunRecord
                expected_run_record_state = $runRecordState
                live_state_path = $liveStateFile
                artifact = [ordered]@{
                    path = $inspection.artifact_path
                    bytes = [uint64]$inspection.bytes
                    sha256 = $inspection.sha256
                }
                staged_repository = $receipt.repository
                current_repository = $currentRepository
                source_of_truth = [ordered]@{
                    fsv_lock = $fsvLock
                    fsv_lock_exists = $false
                    launcher_lock = $launcherLockPath
                    launcher_lock_exists = $false
                    launcher_protocol_state = $launcherProtocolState.State
                    session_files = $inventory
                }
                owners = [ordered]@{
                    identities = @($ownerBindings | ForEach-Object {
                            [ordered]@{
                                role = $_.Role
                                source = $_.Source
                                identity = $_.Identity
                            }
                        })
                    initial_probes = $initialOwnerProbes
                    final_probes = $finalOwnerProbes
                }
                failure = [ordered]@{
                    code = $ReasonCode
                    message = $ReasonMessage
                }
            }
            Write-NewDurableUtf8 $recoveryRecord ($record | ConvertTo-Json -Depth 20)
            $persistedRecord =
                Read-AstroUtf8FileLongPath $recoveryRecord | ConvertFrom-Json
            if ($persistedRecord.schema -ne 'astrolabe.native-fsv-recovery.v2' -or
                $persistedRecord.verdict -ne 'quarantined-unverified-run' -or
                [string]$persistedRecord.artifact.sha256 -cne [string]$inspection.sha256 -or
                [string]$persistedRecord.failure.code -cne $ReasonCode -or
                @($persistedRecord.source_of_truth.session_files).Count -ne $inventory.Count) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_RECORD_INVALID' `
                    "persisted recovery record readback does not bind the terminal session: $recoveryRecord" `
                    'preserve both session and record and investigate the durable-write mismatch'
            }
            Assert-AstroFsvPersistedOwnerEnvelope `
                -Owners $persistedRecord.owners `
                -ExpectedBindings $ownerBindings `
                -Code 'ASTRO_FSV_QUARANTINE_RECORD_INVALID' `
                -Description 'persisted recovery record'
            $recordHash = File-Sha256 $recoveryRecord
            $before = [ordered]@{
                session = $session
                exists = $true
                artifact_sha256 = $inspection.sha256
                file_count = $inventory.Count
                owners = $record.owners
            }
            Remove-AstroOrdinaryFlatDirectoryLongPath $session
            if (Test-AstroPathLongPath -LiteralPath $session) {
                Fail-Astro 'ASTRO_FSV_QUARANTINE_FAILED' "evidence session remains after quarantine: $session" `
                    'preserve the external recovery record and inspect open handles before retrying exact cleanup'
            }
            Remove-EmptyEvidenceParents $session
            [ordered]@{
                operation = 'quarantine'
                record_path = $recoveryRecord
                record_sha256 = $recordHash
                record = $persistedRecord
                before = $before
                after = [ordered]@{ session = $session; exists = $false }
            } | ConvertTo-Json -Depth 22 -Compress | Write-Output
        }
        'MigrateLegacy' {
            if ($Issue -le 0) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_ISSUE_INVALID' `
                    'Issue must be positive for legacy migration' `
                    'pass the exact driving GitHub issue number'
            }
            Assert-FsvLockAbsent $fsvLock
            $launcherProtocolState =
                Read-AstroLauncherLock -LockPath $launcherLockPath
            if ($launcherProtocolState.State -ne 'absent') {
                Fail-Astro 'ASTRO_FSV_MIGRATION_LAUNCHER_LOCK' `
                    "launcher protocol is '$($launcherProtocolState.State)'; legacy migration requires authoritative absence" `
                    'wait for or tracker-reclaim the exact launcher state before migration'
            }
            if ([string]::IsNullOrWhiteSpace($ReceiptPath)) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECEIPT_REQUIRED' `
                    'ReceiptPath is required for MigrateLegacy' `
                    'pass the exact legacy v1 receipt inside the staged session'
            }
            $legacyReceiptPath = Assert-PathWithin `
                $ReceiptPath $evidenceRoot `
                'ASTRO_FSV_MIGRATION_RECEIPT_ESCAPE' `
                'legacy receipt path'
            if (-not (Test-AstroPathLongPath `
                    -LiteralPath $legacyReceiptPath -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECEIPT_MISSING' `
                    "legacy receipt is absent: $legacyReceiptPath" `
                    'preserve surrounding state and pass the exact persisted receipt'
            }
            try {
                $legacyReceipt =
                    Read-AstroUtf8FileLongPath $legacyReceiptPath |
                        ConvertFrom-Json
            }
            catch {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECEIPT_INVALID' `
                    "legacy receipt parse failed: $($_.Exception.Message)" `
                    'preserve the session; malformed state is not migration-authorizing'
            }
            if ($legacyReceipt.schema -ne
                    'astrolabe.native-fsv-artifact.v1' -or
                [int]$legacyReceipt.issue -ne $Issue -or
                [string]$legacyReceipt.tree_sha -cnotmatch '^[0-9a-f]{40}$' -or
                [string]$legacyReceipt.artifact.sha256 -cnotmatch
                    '^[0-9a-f]{64}$' -or
                [string]$legacyReceipt.session_id -cnotmatch
                    '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECEIPT_INVALID' `
                    'receipt is not the exact supported legacy v1 shape/issue' `
                    'preserve the session; only valid v1 state has this explicit migration path'
            }
            $legacySession =
                [IO.Path]::GetFullPath((Split-Path -Parent $legacyReceiptPath))
            $expectedLegacySession = Join-Path (
                Join-Path (
                    Join-Path $evidenceRoot ([string]$legacyReceipt.tree_sha)
                ) ([string]$legacyReceipt.artifact.sha256)
            ) ([string]$legacyReceipt.session_id)
            if (-not [string]::Equals(
                    $legacySession,
                    [IO.Path]::GetFullPath($expectedLegacySession),
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECEIPT_INVALID' `
                    'legacy receipt path differs from its tree/hash/session identity' `
                    'preserve relocated or cross-session state for investigation'
            }
            Assert-NotReparseEntry $legacySession 'legacy evidence session'
            $legacyArtifact = Assert-PathWithin `
                ([string]$legacyReceipt.artifact.path) `
                $legacySession `
                'ASTRO_FSV_MIGRATION_ARTIFACT_ESCAPE' `
                'legacy artifact path'
            if (-not (Test-AstroPathLongPath `
                    -LiteralPath $legacyArtifact -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_ARTIFACT_MISSING' `
                    "legacy artifact is absent: $legacyArtifact" `
                    'preserve the session; incomplete legacy state is not migration-authorizing'
            }
            $legacyArtifactItem = Get-AstroFileInfoLongPath $legacyArtifact
            $legacyArtifactHash = File-Sha256 $legacyArtifact
            if ([uint64]$legacyArtifactItem.Length -ne
                    [uint64]$legacyReceipt.artifact.bytes -or
                $legacyArtifactHash -cne
                    [string]$legacyReceipt.artifact.sha256) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_ARTIFACT_DRIFT' `
                    'legacy artifact bytes differ from the receipt' `
                    'preserve the drifted session and investigate its writer'
            }
            $legacyPids =
                New-Object System.Collections.Generic.List[int]
            foreach ($field in @('launcher_pid', 'promoter_pid')) {
                $parsedPid = 0
                if (-not $legacyReceipt.PSObject.Properties[$field] -or
                    -not [int]::TryParse(
                        [string]$legacyReceipt.$field,
                        [Globalization.NumberStyles]::None,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [ref]$parsedPid
                    ) -or $parsedPid -le 0) {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_RECEIPT_INVALID' `
                        "legacy receipt $field is absent or invalid" `
                        'preserve the session; missing legacy numeric ownership cannot be inferred'
                }
                if (-not $legacyPids.Contains($parsedPid)) {
                    $legacyPids.Add($parsedPid)
                }
            }
            $legacySessionEntries =
                @(Get-AstroDirectoryEntriesLongPath $legacySession)
            $legacyControlPaths = @(
                $legacyReceiptPath,
                $legacyArtifact
            )
            $legacyAdditionalEntries = @(
                $legacySessionEntries |
                    Where-Object {
                        [IO.Path]::GetFullPath($_.FullName) -notin
                            $legacyControlPaths
                    }
            )
            if ($legacyAdditionalEntries.Count -gt 0) {
                if ([string]::IsNullOrWhiteSpace($RunRecordPath) -or
                    [string]::IsNullOrWhiteSpace($LiveStatePath)) {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_CONTROL_PATH_REQUIRED' `
                        'nonpristine legacy sessions require explicit RunRecordPath and LiveStatePath bindings' `
                        'pass the exact two v1 control records; ordinary JSON output is never inferred to be authority'
                }
                $legacyRunPath = Assert-PathWithin `
                    $RunRecordPath $legacySession `
                    'ASTRO_FSV_MIGRATION_CONTROL_PATH_ESCAPE' `
                    'legacy run-record path'
                $legacyLivePath = Assert-PathWithin `
                    $LiveStatePath $legacySession `
                    'ASTRO_FSV_MIGRATION_CONTROL_PATH_ESCAPE' `
                    'legacy live-state path'
                if (-not (Test-AstroPathLongPath `
                        -LiteralPath $legacyRunPath -PathType Leaf) -or
                    -not (Test-AstroPathLongPath `
                        -LiteralPath $legacyLivePath -PathType Leaf) -or
                    [string]::Equals(
                        $legacyRunPath,
                        $legacyLivePath,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    $legacyControlPaths -contains $legacyRunPath -or
                    $legacyControlPaths -contains $legacyLivePath) {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_CONTROL_PATH_INVALID' `
                        'legacy run/live control paths are absent, duplicate, or overlap receipt/artifact state' `
                        'preserve the session and pass two exact distinct persisted v1 control files'
                }
                try {
                    $legacyRun =
                        Read-AstroUtf8FileLongPath $legacyRunPath |
                        ConvertFrom-Json
                    $legacyLive =
                        Read-AstroUtf8FileLongPath $legacyLivePath |
                        ConvertFrom-Json
                }
                catch {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_SESSION_INVALID' `
                        "explicit legacy run/live control state is unreadable: $($_.Exception.Message)" `
                        'preserve malformed legacy state; migration requires a complete inventory'
                }
                if ($legacyRun.schema -ne 'astrolabe.native-fsv-run.v1' -or
                    $legacyLive.schema -ne
                        'astrolabe.native-fsv-live.v1' -or
                    -not $legacyRun.PSObject.Properties['runner'] -or
                    -not $legacyRun.PSObject.Properties['process'] -or
                    -not $legacyRun.PSObject.Properties['receipt_path'] -or
                    -not $legacyRun.PSObject.Properties['artifact'] -or
                    -not $legacyRun.artifact.PSObject.Properties['path'] -or
                    -not $legacyRun.artifact.PSObject.Properties['sha256'] -or
                    -not $legacyLive.PSObject.Properties['artifact'] -or
                    -not $legacyLive.artifact.PSObject.Properties['path'] -or
                    -not $legacyLive.artifact.PSObject.Properties['sha256'] -or
                    [int]$legacyRun.issue -ne $Issue -or
                    [int]$legacyLive.issue -ne $Issue -or
                    [string]$legacyRun.artifact.sha256 -cne
                        [string]$legacyReceipt.artifact.sha256 -or
                    [string]$legacyLive.artifact.sha256 -cne
                        [string]$legacyReceipt.artifact.sha256 -or
                    -not [string]::Equals(
                        [IO.Path]::GetFullPath(
                            [string]$legacyRun.receipt_path
                        ),
                        $legacyReceiptPath,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    -not [string]::Equals(
                        [IO.Path]::GetFullPath(
                            [string]$legacyRun.artifact.path
                        ),
                        $legacyArtifact,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    -not [string]::Equals(
                        [IO.Path]::GetFullPath(
                            [string]$legacyLive.artifact.path
                        ),
                        $legacyArtifact,
                        [StringComparison]::OrdinalIgnoreCase
                    )) {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_SESSION_INVALID' `
                        'explicit legacy run/live records are incomplete or not bound to the receipt/artifact' `
                        'preserve unknown, partial, or mixed-session state for investigation'
                }
                $pidValues = @(
                    $legacyLive.launcher_pid,
                    $legacyLive.runner_pid,
                    $legacyLive.child_pid,
                    $legacyRun.runner.pid,
                    $legacyRun.runner.launcher_pid,
                    $legacyRun.process.pid
                )
                if ($legacyRun.PSObject.Properties['launcher_lease']) {
                    $pidValues += @(
                        $legacyRun.launcher_lease.owner_pid
                    )
                }
                foreach ($value in @($pidValues)) {
                    $parsedPid = 0
                    if (-not [int]::TryParse(
                            [string]$value,
                            [Globalization.NumberStyles]::None,
                            [Globalization.CultureInfo]::InvariantCulture,
                            [ref]$parsedPid
                        ) -or $parsedPid -le 0) {
                        Fail-Astro 'ASTRO_FSV_MIGRATION_SESSION_INVALID' `
                            'legacy run/live owner PID is absent or invalid' `
                            'preserve incomplete legacy ownership state'
                    }
                    if (-not $legacyPids.Contains($parsedPid)) {
                        $legacyPids.Add($parsedPid)
                    }
                }
                if ([int]$legacyLive.launcher_pid -ne
                        [int]$legacyReceipt.launcher_pid -or
                    [int]$legacyRun.runner.launcher_pid -ne
                        [int]$legacyLive.launcher_pid -or
                    [int]$legacyRun.runner.pid -ne
                        [int]$legacyLive.runner_pid -or
                    [int]$legacyRun.process.pid -ne
                        [int]$legacyLive.child_pid -or
                    ($legacyRun.PSObject.Properties['launcher_lease'] -and
                        [int]$legacyRun.launcher_lease.owner_pid -ne
                            [int]$legacyLive.launcher_pid)) {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_SESSION_INVALID' `
                        'legacy receipt, live state, and run record disagree on numeric ownership' `
                        'preserve cross-generation or contradictory legacy state for investigation'
                }
            }
            $legacyInventory = @(Get-SessionFileInventory $legacySession)
            try {
                $legacyTree =
                    Get-AstroOrdinaryDirectoryTreeInventoryLongPath `
                        $legacySession
            }
            catch {
                Fail-Astro 'ASTRO_FSV_MIGRATION_INVENTORY_INVALID' `
                    "legacy session canonical inventory failed without mutation: $($_.Exception.Message)" `
                    'preserve every session byte and investigate the exact ordinary-tree state'
            }
            $legacyInventorySchema = [string]$legacyTree.schema
            $legacyInventoryEncoding = [string]$legacyTree.encoding
            $legacyInventorySha256 = [string]$legacyTree.sha256
            $legacyReceiptSha256 = File-Sha256 $legacyReceiptPath
            $initialLegacyProbes = foreach ($legacyPid in $legacyPids) {
                $probe =
                    Get-AstroProcessIdentityProbe -OwnerPid $legacyPid
                if ($probe.State -ceq 'unevaluable') {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_OWNER_UNEVALUABLE' `
                        "legacy numeric PID $legacyPid is unevaluable: $($probe.Error)" `
                        'preserve every session byte and retry only when PID state is readable'
                }
                if ($probe.State -cne 'absent') {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_PID_OCCUPIED' `
                        "legacy numeric PID $legacyPid is occupied; v1 cannot distinguish the original owner from reuse" `
                        'wait until every legacy numeric PID is completely absent'
                }
                [ordered]@{
                    pid = $legacyPid
                    state = 'absent'
                    observed_at_utc = [DateTime]::UtcNow.ToString('o')
                }
            }
            if ([string]::IsNullOrWhiteSpace($MigrationRecordPath)) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECORD_REQUIRED' `
                    'MigrationRecordPath is required for MigrateLegacy' `
                    "use a fresh JSON path below $migrationRoot"
            }
            $migrationRecord = Assert-PathWithin `
                $MigrationRecordPath $migrationRoot `
                'ASTRO_FSV_MIGRATION_RECORD_ESCAPE' `
                'legacy migration record path'
            if (Test-AstroPathLongPath -LiteralPath $migrationRecord) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECORD_REUSE_REFUSED' `
                    "migration record already exists: $migrationRecord" `
                    'use one fresh append-only record path per legacy session'
            }
            if ($ReasonCode -notmatch '^[A-Z][A-Z0-9_]{2,95}$' -or
                [string]::IsNullOrWhiteSpace($ReasonMessage)) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_REASON_INVALID' `
                    'MigrateLegacy requires a structured ReasonCode and nonblank ReasonMessage' `
                    'describe why this exact legacy session must be retired'
            }
            $tracker = Read-AstroFsvLegacyTrackerEvidence `
                -Url $TrackerCommentUrl `
                -ExpectedIssue $Issue `
                -ExpectedReceiptPath $legacyReceiptPath `
                -ExpectedReceiptSha256 $legacyReceiptSha256 `
                -ExpectedSessionDirectory $legacySession `
                -ExpectedInventorySchema $legacyInventorySchema `
                -ExpectedInventoryEncoding $legacyInventoryEncoding `
                -ExpectedInventoryEntryCount `
                    ([int]$legacyTree.entry_count) `
                -ExpectedInventoryCanonicalByteCount `
                    ([uint64]$legacyTree.canonical_bytes_length) `
                -ExpectedInventorySha256 $legacyInventorySha256 `
                -ExpectedNumericOwnerPids ([int[]]$legacyPids.ToArray()) `
                -ExpectedMigrationRecordPath $migrationRecord
            try {
                $finalLegacyTree =
                    Get-AstroOrdinaryDirectoryTreeInventoryLongPath `
                        $legacySession
            }
            catch {
                Fail-Astro 'ASTRO_FSV_MIGRATION_SESSION_DRIFT' `
                    "legacy session final canonical inventory failed without mutation: $($_.Exception.Message)" `
                    'preserve the session and post fresh evidence for its current exact tree'
            }
            if ([string]$finalLegacyTree.schema -cne
                    $legacyInventorySchema -or
                [string]$finalLegacyTree.encoding -cne
                    $legacyInventoryEncoding -or
                [string]$finalLegacyTree.sha256 -cne
                    $legacyInventorySha256 -or
                [uint64]$finalLegacyTree.canonical_bytes_length -ne
                    [uint64]$legacyTree.canonical_bytes_length -or
                [int]$finalLegacyTree.entry_count -ne
                    [int]$legacyTree.entry_count -or
                (File-Sha256 $legacyReceiptPath) -cne
                    $legacyReceiptSha256) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_SESSION_DRIFT' `
                    'legacy session inventory changed after tracker authorization' `
                    'preserve the session and post fresh evidence for its current bytes'
            }
            $finalLegacyProbes = foreach ($legacyPid in $legacyPids) {
                $probe =
                    Get-AstroProcessIdentityProbe -OwnerPid $legacyPid
                if ($probe.State -cne 'absent') {
                    Fail-Astro 'ASTRO_FSV_MIGRATION_OWNER_CHANGED' `
                        "legacy numeric PID $legacyPid changed to '$($probe.State)' before removal" `
                        'preserve the session and repeat tracker authorization only after every numeric PID is absent'
                }
                [ordered]@{
                    pid = $legacyPid
                    state = 'absent'
                    observed_at_utc = [DateTime]::UtcNow.ToString('o')
                }
            }
            $recordParent = Split-Path -Parent $migrationRecord
            New-AstroDirectoryLongPath $recordParent | Out-Null
            Assert-NotReparseEntry $recordParent `
                'legacy migration record parent'
            $migration = [ordered]@{
                schema = 'astrolabe.native-fsv-legacy-migration.v2'
                verdict = 'legacy-session-removed-without-identity-inference'
                issue = $Issue
                recorded_at_utc = [DateTime]::UtcNow.ToString('o')
                receipt_path = $legacyReceiptPath
                receipt_sha256 = $legacyReceiptSha256
                session_directory = $legacySession
                inventory = $legacyInventory
                inventory_schema = $legacyInventorySchema
                inventory_encoding = $legacyInventoryEncoding
                inventory_entry_count = [int]$legacyTree.entry_count
                inventory_canonical_byte_count =
                    [uint64]$legacyTree.canonical_bytes_length
                inventory_sha256 = $legacyInventorySha256
                legacy_numeric_owner_pids =
                    [int[]]@($legacyPids | Sort-Object -Unique)
                initial_numeric_owner_probes = @($initialLegacyProbes)
                final_numeric_owner_probes = @($finalLegacyProbes)
                tracker = $tracker
                failure = [ordered]@{
                    code = $ReasonCode
                    message = $ReasonMessage
                }
            }
            Write-NewDurableUtf8 `
                $migrationRecord ($migration | ConvertTo-Json -Depth 22)
            $persistedMigration =
                Read-AstroUtf8FileLongPath $migrationRecord |
                    ConvertFrom-Json
            if ($persistedMigration.schema -ne
                    'astrolabe.native-fsv-legacy-migration.v2' -or
                [string]$persistedMigration.receipt_sha256 -cne
                    $legacyReceiptSha256 -or
                [string]$persistedMigration.inventory_schema -cne
                    $legacyInventorySchema -or
                [string]$persistedMigration.inventory_encoding -cne
                    $legacyInventoryEncoding -or
                [int]$persistedMigration.inventory_entry_count -ne
                    [int]$legacyTree.entry_count -or
                [uint64]$persistedMigration.inventory_canonical_byte_count -ne
                    [uint64]$legacyTree.canonical_bytes_length -or
                [string]$persistedMigration.inventory_sha256 -cne
                    $legacyInventorySha256 -or
                [string]$persistedMigration.tracker.url -cne
                    $TrackerCommentUrl) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_RECORD_INVALID' `
                    'persisted migration record does not bind the authorized legacy session' `
                    'preserve both session and external record for investigation'
            }
            $migrationRecordSha256 = File-Sha256 $migrationRecord
            Set-AstroFileReadOnlyLongPath `
                -LiteralPath $legacyArtifact -ReadOnly $false
            Remove-AstroOrdinaryFlatDirectoryLongPath $legacySession
            if (Test-AstroPathLongPath -LiteralPath $legacySession) {
                Fail-Astro 'ASTRO_FSV_MIGRATION_REMOVE_FAILED' `
                    "legacy session remains after migration: $legacySession" `
                    'preserve the external record and inspect exact filesystem handles'
            }
            Remove-EmptyEvidenceParents $legacySession
            [ordered]@{
                operation = 'migrate-legacy'
                record_path = $migrationRecord
                record_sha256 = $migrationRecordSha256
                record = $persistedMigration
                before = [ordered]@{
                    session = $legacySession
                    exists = $true
                    receipt_sha256 = $legacyReceiptSha256
                    inventory_schema = $legacyInventorySchema
                    inventory_encoding = $legacyInventoryEncoding
                    inventory_entry_count = [int]$legacyTree.entry_count
                    inventory_canonical_byte_count =
                        [uint64]$legacyTree.canonical_bytes_length
                    inventory_sha256 = $legacyInventorySha256
                }
                after = [ordered]@{
                    session = $legacySession
                    exists = $false
                }
            } | ConvertTo-Json -Depth 24 -Compress | Write-Output
        }
        'Cleanup' {
            $receiptState = Read-Receipt $ReceiptPath $evidenceRoot
            $inspection = Inspect-ReceiptArtifact $receiptState $evidenceRoot
            Assert-FsvLockAbsent $fsvLock
            $launcherProtocolState =
                Read-AstroLauncherLock -LockPath $launcherLockPath
            if ($launcherProtocolState.State -ne 'absent') {
                Fail-Astro 'ASTRO_FSV_CLEANUP_LAUNCHER_LOCK' `
                    "launcher protocol is '$($launcherProtocolState.State)'; completed-session cleanup requires authoritative absence (transitions=$(@($launcherProtocolState.TransitionPaths) -join '; '), read_error=$($launcherProtocolState.ReadError), validation_error=$($launcherProtocolState.ValidationError))" `
                    'wait for the exact launcher generation to exit and finish its protocol cleanup'
            }
            if ([string]::IsNullOrWhiteSpace($RunRecordPath)) {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_REQUIRED' 'RunRecordPath is required for Cleanup' `
                    'pass the persisted run record written by native-fsv-run.ps1 after the real process exited'
            }
            $runRecord = Assert-PathWithin $RunRecordPath $inspection.session_directory `
                'ASTRO_FSV_RUN_RECORD_ESCAPE' 'run record path'
            if (-not (Test-AstroPathLongPath -LiteralPath $runRecord -PathType Leaf)) {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_MISSING' "run record does not exist: $runRecord" `
                    'complete the real staged-artifact run and persist its readback before cleanup'
            }
            try {
                $record = Read-AstroUtf8FileLongPath $runRecord | ConvertFrom-Json
            }
            catch {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_INVALID' "parse run record '$runRecord' failed: $($_.Exception.Message)" `
                    'preserve the evidence directory and investigate the incomplete run'
            }
            if (-not $record.PSObject.Properties['launcher'] -or
                -not $record.PSObject.Properties['runner'] -or
                -not $record.PSObject.Properties['process'] -or
                -not $record.process.PSObject.Properties['identity'] -or
                -not $record.PSObject.Properties['artifact'] -or
                -not $record.artifact.PSObject.Properties['path'] -or
                -not $record.artifact.PSObject.Properties['sha256'] -or
                -not $record.PSObject.Properties['receipt_path']) {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_INVALID' `
                    "run record '$runRecord' omits required exact ownership or artifact binding" `
                    'preserve the evidence directory and investigate the incomplete run'
            }
            if ($record.schema -ne 'astrolabe.native-fsv-run.v2' -or
                [int]$record.issue -ne [int]$inspection.issue -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$record.receipt_path), $receiptState.Path, [StringComparison]::OrdinalIgnoreCase) -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$record.artifact.path), $inspection.artifact_path, [StringComparison]::OrdinalIgnoreCase) -or
                [string]$record.artifact.sha256 -cne [string]$inspection.sha256) {
                Fail-Astro 'ASTRO_FSV_RUN_RECORD_INVALID' "run record '$runRecord' is not bound to the staged artifact" `
                    'preserve the evidence directory and investigate the provenance mismatch'
            }
            $ownerBindings = @(
                Get-AstroFsvSessionOwnerBindings `
                    -ReceiptState $receiptState `
                    -Inspection $inspection `
                    -RunRecordPath $runRecord `
                    -RunRecord $record
            )
            $initialOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_CLEANUP' `
                    -Description 'completed evidence session'
            )
            $session = [IO.Path]::GetFullPath($inspection.session_directory)
            try {
                $initialTree =
                    Get-AstroOrdinaryDirectoryTreeInventoryLongPath $session
            }
            catch {
                Fail-Astro 'ASTRO_FSV_CLEANUP_TREE_INVALID' `
                    "completed evidence tree preflight failed without mutation: $($_.Exception.Message)" `
                    'preserve every session byte; remove reparses/foreign writers only through an explicitly authorized recovery lifecycle'
            }
            $finalOwnerProbes = @(
                Assert-AstroFsvOwnersInactive `
                    -Bindings $ownerBindings `
                    -CodePrefix 'ASTRO_FSV_CLEANUP' `
                    -Description 'completed evidence session final authorization'
            )
            try {
                $finalTree =
                    Get-AstroOrdinaryDirectoryTreeInventoryLongPath $session
            }
            catch {
                Fail-Astro 'ASTRO_FSV_CLEANUP_TREE_INVALID' `
                    "completed evidence tree final preflight failed without mutation: $($_.Exception.Message)" `
                    'preserve every session byte and investigate the exact filesystem state before retrying'
            }
            if ([string]$initialTree.schema -cne
                    [string]$finalTree.schema -or
                [string]$initialTree.encoding -cne
                    [string]$finalTree.encoding -or
                [string]$initialTree.sha256 -cne
                    [string]$finalTree.sha256 -or
                [uint64]$initialTree.canonical_bytes_length -ne
                    [uint64]$finalTree.canonical_bytes_length -or
                [int]$initialTree.entry_count -ne
                    [int]$finalTree.entry_count) {
                Fail-Astro 'ASTRO_FSV_CLEANUP_TREE_DRIFT' `
                    "completed evidence tree changed between authorization reads (initial_schema=$($initialTree.schema), final_schema=$($finalTree.schema), initial_encoding=$($initialTree.encoding), final_encoding=$($finalTree.encoding), initial_canonical_bytes=$($initialTree.canonical_bytes_length), final_canonical_bytes=$($finalTree.canonical_bytes_length), initial_sha256=$($initialTree.sha256), final_sha256=$($finalTree.sha256), initial_entries=$($initialTree.entry_count), final_entries=$($finalTree.entry_count))" `
                    'preserve every session byte; stop the writer and retry only after the exact tree is stable'
            }
            $before = [ordered]@{
                session = $session
                exists = Test-AstroPathLongPath -LiteralPath $session
                artifact_sha256 = $inspection.sha256
                tree = [ordered]@{
                    schema = [string]$finalTree.schema
                    encoding = [string]$finalTree.encoding
                    entry_count = [int]$finalTree.entry_count
                    canonical_byte_count =
                        [uint64]$finalTree.canonical_bytes_length
                    inventory_sha256 = [string]$finalTree.sha256
                }
                owners = [ordered]@{
                    identities = @($ownerBindings | ForEach-Object {
                            [ordered]@{
                                role = $_.Role
                                source = $_.Source
                                identity = $_.Identity
                            }
                        })
                    initial_probes = $initialOwnerProbes
                    final_probes = $finalOwnerProbes
                }
            }
            try {
                Remove-AstroOrdinaryDirectoryTreeLongPath `
                    -LiteralPath $session `
                    -ExpectedInventorySchema ([string]$finalTree.schema) `
                    -ExpectedInventoryEncoding ([string]$finalTree.encoding) `
                    -ExpectedInventorySha256 ([string]$finalTree.sha256)
            }
            catch {
                Fail-Astro 'ASTRO_FSV_CLEANUP_TREE_DELETE_FAILED' `
                    "exact completed evidence-tree deletion failed: $($_.Exception.Message)" `
                    'preserve all remaining state; inspect the exact error and retry Cleanup only after any foreign handle or namespace drift is resolved'
            }
            if (Test-AstroPathLongPath -LiteralPath $session) {
                Fail-Astro 'ASTRO_FSV_CLEANUP_FAILED' "evidence session remains after cleanup: $session" `
                    'inspect open handles and retry only after every exact owner generation is dead'
            }
            Remove-EmptyEvidenceParents $session
            [ordered]@{ operation = 'cleanup'; before = $before; after = [ordered]@{ session = $session; exists = $false } } |
                ConvertTo-Json -Depth 10 -Compress | Write-Output
        }
    }
}
catch {
    $failure = $_
    $code = if ($failure.Exception.Data.Contains('AstroCode')) { [string]$failure.Exception.Data['AstroCode'] } else { 'ASTRO_FSV_ARTIFACT_INTERNAL' }
    $remediation = if ($failure.Exception.Data.Contains('AstroRemediation')) { [string]$failure.Exception.Data['AstroRemediation'] } else { 'preserve the evidence state, inspect the full error, repair the root cause, and retry from a fresh session' }
    [Console]::Error.WriteLine(([ordered]@{
        code = $code
        message = $failure.Exception.Message
        remediation = $remediation
        exception_type = $failure.Exception.GetType().FullName
        script_stack_trace = $failure.ScriptStackTrace
        invocation = $failure.InvocationInfo.PositionMessage
    } | ConvertTo-Json -Compress))
    exit 1
}
