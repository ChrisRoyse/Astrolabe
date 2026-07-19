<#
.SYNOPSIS
    Explicit tracker-evidenced archive of dead-owner launcher protocol state.

.DESCRIPTION
    Normal acquisition never removes stale, malformed, or interrupted launcher-lock state.
    This command is the only supported recovery path. It verifies the referenced GitHub
    comment through `gh`, requires that comment to contain an exact machine-readable evidence
    object, probes the exact process identity twice, writes and byte-for-byte reads back an
    append-only authorization record, then atomically archives only the exact unchanged bytes.

    -LegacyPidOnly is restricted to pre-v2 manifests and requires the numeric PID completely
    absent. -QuarantineUnreadable is a separate explicit mode for truncated/malformed active
    or transition files; it still requires an externally known dead owner identity, exact
    bytes/hash, tracker evidence, and the physical no-delete-share boundary used by modern
    live leases.

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
        [Parameter(Mandatory)][byte[]]$Left,
        [Parameter(Mandatory)][byte[]]$Right
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

function Write-NewDurableBytes {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Description
    )

    try {
        $stream = [IO.File]::Open(
            $LiteralPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
    }
    catch {
        $presence = Get-AstroPathEntryState $LiteralPath
        $code = if ($presence.State -eq 'present') {
            'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_REUSE_REFUSED'
        } else {
            'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_CREATE_FAILED'
        }
        Fail-Astro $code `
            "could not create fresh $description '$LiteralPath': $($_.Exception.Message)" `
            'preserve all state and use a fresh workspace-local recovery basename'
    }
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_FLUSH_FAILED' `
            "durable write failed for $description '$LiteralPath': $($_.Exception.Message)" `
            'preserve the partial append-only record and lock; investigate storage before retrying'
    }
    finally {
        $stream.Dispose()
    }
}

function Write-NewDurableJsonAndReadBack {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Description
    )

    $text = $Value | ConvertTo-Json -Depth 24 -Compress
    $expectedBytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
    Write-NewDurableBytes $LiteralPath $expectedBytes $Description
    $snapshot = Get-AstroFileSnapshot $LiteralPath ([IO.FileShare]::Read)
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

function Read-LegacyOwner {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Path
    )

    try {
        $raw = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        if ($raw.Length -gt 0 -and $raw[0] -eq [char]0xfeff) {
            throw 'UTF-8 BOM is not permitted'
        }
        $manifest = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_UNREADABLE' `
            "legacy launcher lock is not strict UTF-8 JSON at '$Path': $($_.Exception.Message)" `
            'preserve it or use the separate -QuarantineUnreadable mode with tracker evidence'
    }
    if ($manifest -isnot [Management.Automation.PSCustomObject] -or
        $manifest -is [Array]) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_UNREADABLE' `
            'legacy launcher-lock JSON root must be one object' `
            'preserve it or use the separate unreadable quarantine protocol'
    }
    foreach ($name in @('pid', 'issue', 'started', 'command')) {
        if ($null -eq $manifest.PSObject.Properties[$name]) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_UNREADABLE' `
                "legacy launcher lock is missing '$name'" `
                'preserve the malformed lock and identify its producer'
        }
    }
    if (-not (Test-AstroJsonIntegerType $manifest.pid) -or
        [long]$manifest.pid -le 0 -or [long]$manifest.pid -gt [int]::MaxValue -or
        -not (Test-AstroJsonIntegerType $manifest.issue) -or
        [long]$manifest.issue -le 0 -or [long]$manifest.issue -gt [int]::MaxValue) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_UNREADABLE' `
            'legacy pid/issue must be positive integral JSON numbers' `
            'never coerce strings, booleans, exponents, or floating-point owner IDs'
    }
    if ($manifest.command -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$manifest.command)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_UNREADABLE' `
            'legacy command must be a nonblank JSON string' `
            'preserve the malformed lock and identify its producer'
    }
    if ($null -ne $manifest.PSObject.Properties['owner_process_start_utc_ticks']) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_LEGACY_SCHEMA_REFUSED' `
            'LegacyPidOnly refuses a lock carrying a modern process-start identity' `
            'use normal v2 reclaim with the exact owner process-start ticks'
    }
    $schema = if ($null -ne $manifest.PSObject.Properties['schema']) {
        if ($manifest.schema -isnot [string]) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_LEGACY_SCHEMA_REFUSED' `
                'legacy schema, when present, must be a JSON string' `
                'preserve the malformed lock and identify its producer'
        }
        [string]$manifest.schema
    }
    else {
        'legacy-unversioned'
    }
    if ($schema -cne 'legacy-unversioned' -and
        $schema -cne 'astrolabe.launcher-lock.v1') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_LEGACY_SCHEMA_REFUSED' `
            "LegacyPidOnly refuses schema '$schema'" `
            'use normal v2 reclaim for v2; never downgrade a modern identity'
    }
    $timestampPattern =
        '(?<!\\)"started"\s*:\s*"(?<value>[0-9]{4}-[0-9]{2}-[0-9]{2}T' +
        '[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}(?:Z|[+-][0-9]{2}:[0-9]{2}))"'
    $matches = [Regex]::Matches($raw, $timestampPattern)
    if ($matches.Count -ne 1) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_UNREADABLE' `
            'legacy started must be one exact round-trip ISO JSON string' `
            'preserve the malformed lock and identify its producer'
    }
    $parsedStarted = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            $matches[0].Groups['value'].Value,
            'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsedStarted
        )) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_UNREADABLE' `
            'legacy started ISO diagnostic is invalid' `
            'preserve the malformed lock and identify its producer'
    }
    return [pscustomobject]@{
        Schema = $schema
        Legacy = $true
        Pid = [int][long]$manifest.pid
        Issue = [int][long]$manifest.issue
        LeaseStartUtcTicks = [long]$parsedStarted.UtcTicks
        StartedUtc = $parsedStarted.UtcDateTime.ToString('o')
        OwnerProcessStartUtcTicks = $null
        OwnerProcessStartedUtc = $null
        Command = [string]$manifest.command
        HeadSha = if ($manifest.PSObject.Properties['head_sha']) {
            [string]$manifest.head_sha
        } else { $null }
        StatusSha256 = if ($manifest.PSObject.Properties['status_sha256']) {
            [string]$manifest.status_sha256
        } else { $null }
        DiffSha256 = if ($manifest.PSObject.Properties['diff_sha256']) {
            [string]$manifest.diff_sha256
        } else { $null }
    }
}

function Read-V2Owner {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Path
    )

    $state = Convert-AstroLauncherLockBytesToState $Bytes $Path
    if ($state.State -eq 'unreadable') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_UNREADABLE' `
            "schema-v2 lock is invalid: $($state.ValidationError)" `
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
        "api repos/ChrisRoyse/Astrolabe/issues/comments/$CommentId"
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        $exitCode = $process.ExitCode
    }
    catch {
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
    $matched = @()
    foreach ($line in $candidates) {
        try {
            $evidence = ConvertFrom-Json -InputObject (
                $line.Substring($prefix.Length)
            ) -ErrorAction Stop
        }
        catch {
            continue
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
        $complete = $true
        foreach ($name in $required) {
            if ($null -eq $evidence.PSObject.Properties[$name]) {
                $complete = $false
            }
        }
        if (-not $complete -or
            $evidence.schema -isnot [string] -or
            [string]$evidence.schema -cne
                'astrolabe.launcher-lock-reclaim-evidence.v1' -or
            -not (Test-AstroJsonIntegerType $evidence.issue) -or
            [long]$evidence.issue -ne $Issue -or
            $evidence.lock_path -isnot [string] -or
            -not [string]::Equals(
                [IO.Path]::GetFullPath([string]$evidence.lock_path),
                $Lock,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            $evidence.lock_sha256 -isnot [string] -or
            [string]$evidence.lock_sha256 -cne $LockSha256 -or
            -not (Test-AstroJsonIntegerType $evidence.expected_pid) -or
            [long]$evidence.expected_pid -ne $OwnerPid -or
            $evidence.legacy_pid_only -isnot [bool] -or
            [bool]$evidence.legacy_pid_only -ne $Legacy -or
            $evidence.quarantine_unreadable -isnot [bool] -or
            [bool]$evidence.quarantine_unreadable -ne $Unreadable -or
            $evidence.owner_probe_state -isnot [string] -or
            [string]$evidence.owner_probe_state -cne
                [string]$OwnerProbe.state) {
            continue
        }
        $evidenceOwnerTicksIntegral = Test-AstroJsonIntegerType `
            $evidence.expected_owner_process_start_utc_ticks
        if ($Legacy) {
            if ($null -ne $evidence.expected_owner_process_start_utc_ticks) {
                continue
            }
        }
        elseif (-not $evidenceOwnerTicksIntegral -or
            [long]$evidence.expected_owner_process_start_utc_ticks -ne
                [long]$OwnerTicks) {
            continue
        }
        $evidenceObservedTicksIntegral = Test-AstroJsonIntegerType `
            $evidence.observed_process_start_utc_ticks
        if ($null -eq $OwnerProbe.observed_process_start_utc_ticks) {
            if ($null -ne $evidence.observed_process_start_utc_ticks) {
                continue
            }
        }
        elseif (-not $evidenceObservedTicksIntegral -or
            [long]$evidence.observed_process_start_utc_ticks -ne
                [long]$OwnerProbe.observed_process_start_utc_ticks) {
            continue
        }
        $matched += $evidence
    }
    if ($matched.Count -ne 1) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_EVIDENCE_INVALID' `
            "tracker comment contains $($matched.Count) exact matching evidence objects; required exactly one" `
            "post one line beginning '$prefix' with the exact path/hash/owner/probe values"
    }
    return [pscustomobject]@{
        Url = $CommentUrl
        Id = $commentId
        ApiUrl = [string]$read.Comment.url
        CreatedAt = [string]$read.Comment.created_at
        UpdatedAt = [string]$read.Comment.updated_at
        BodyBytes = [uint64]$read.BodyBytes.Length
        BodySha256 = $read.BodySha256
        Evidence = $matched[0]
    }
}

$failure = $null
$result = $null
$mutexLease = $null
try {
    . (Join-Path $PSScriptRoot 'launcher-lock.ps1')

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
    $lockLeaf = [IO.Path]::GetFileName($lockFull)
    $transitionPattern =
        '^astrolabe-launcher\.lock\.(?<phase>claim|cleanup)\.v2\.' +
        'pid-(?<pid>[0-9]+)\.issue-(?<issue>[0-9]+)\.' +
        'ticks-(?<ticks>[0-9]+)\.sha256-(?<sha>[0-9a-f]{64})\.' +
        '(?<nonce>[0-9a-f]{32})$'
    $transitionMatch = [Regex]::Match($lockLeaf, $transitionPattern)
    $transitionCandidateMatch = [Regex]::Match(
        $lockLeaf,
        '^astrolabe-launcher\.lock\.(?<phase>claim|cleanup)\..+$'
    )
    $isActive = [string]::Equals(
        $lockFull,
        $activeLock,
        [StringComparison]::OrdinalIgnoreCase
    )
    $isTransition = $transitionCandidateMatch.Success -and
        [string]::Equals(
            [IO.Path]::GetDirectoryName($lockFull),
            $tmpRoot,
            [StringComparison]::OrdinalIgnoreCase
        )
    if (-not ($isActive -or $isTransition)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PATH_MISMATCH' `
            "path is neither the exact active lock nor a recognized transition for root '$rootFull': $lockFull" `
            'pass the exact .tmp launcher-lock active/claim/cleanup path'
    }
    if ($isTransition -and -not $transitionMatch.Success -and
        -not $QuarantineUnreadable) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRANSITION_SCHEMA_UNREADABLE' `
            "legacy/unknown transition name requires -QuarantineUnreadable: $lockLeaf" `
            'bind its exact raw bytes and externally known owner in tracker evidence; never infer fields from an unknown name'
    }
    if ($isTransition -and $transitionMatch.Success) {
        if ([int]::Parse($transitionMatch.Groups['pid'].Value) -ne
                $expectedPidValue -or
            [int]::Parse($transitionMatch.Groups['issue'].Value) -ne
                $expectedIssueValue -or
            [long]::Parse($transitionMatch.Groups['ticks'].Value) -ne
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
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_ESCAPE' `
            "recovery record must live directly below '$recoveryRoot': $recordFull" `
            'use one fresh .tmp\lock-recovery\<unique>.json basename'
    }
    $completionFull = "$recordFull.completed.json"
    $archiveFull = "$recordFull.lock.bin"
    foreach ($candidate in @($recordFull, $completionFull, $archiveFull)) {
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

    $transitions = Get-AstroLauncherLockTransitions $activeLock
    if ($transitions.State -eq 'unevaluable') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_UNEVALUABLE' `
            $transitions.Error `
            'preserve all protocol state and repair directory access'
    }
    if ($isActive -and $transitions.Paths.Count -gt 0) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_CONFLICT' `
            "recover transition state before the active lock: $(@($transitions.Paths) -join '; ')" `
            'archive the sole exact transition first, then re-read active state'
    }
    if ($isTransition) {
        $otherTransitions = @(
            $transitions.Paths |
                Where-Object {
                    -not [string]::Equals(
                        $_,
                        $lockFull,
                        [StringComparison]::OrdinalIgnoreCase
                    )
                }
        )
        if (-not ($transitions.Paths | Where-Object {
                    [string]::Equals(
                        $_,
                        $lockFull,
                        [StringComparison]::OrdinalIgnoreCase
                    )
                }) -or $otherTransitions.Count -gt 0) {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_PROTOCOL_CONFLICT' `
                "transition inventory does not contain only the exact target: $(@($transitions.Paths) -join '; ')" `
                'preserve all state and recover one unambiguous transition at a time'
        }
    }

    $presence = Get-AstroPathEntryState $lockFull
    if ($presence.State -ne 'present' -or
        ($presence.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or
        ($presence.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_LOCK_MISSING' `
            "target is not an evaluable ordinary file: $lockFull ($($presence.Error))" `
            're-read protocol state; never manufacture missing ownership evidence'
    }
    $initial = Get-AstroFileSnapshot $lockFull ([IO.FileShare]::Read)
    if ($initial.Sha256 -cne $expectedHash) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_HASH_MISMATCH' `
            "target SHA-256 '$($initial.Sha256)' differs from expected '$expectedHash'" `
            'post and pass the current exact bytes; never recover changed state'
    }

    $owner = $null
    if (-not $QuarantineUnreadable) {
        $owner = if ($LegacyPidOnly) {
            Read-LegacyOwner $initial.Bytes $lockFull
        } else {
            Read-V2Owner $initial.Bytes $lockFull
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

    $firstProbe = Assert-OwnerDead `
        $expectedPidValue `
        $expectedTicksValue `
        ([bool]$LegacyPidOnly) `
        'before-tracker-authorization-read'
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
    foreach ($candidate in @($recordFull, $completionFull, $archiveFull)) {
        if ((Get-AstroPathEntryState $candidate).State -ne 'absent') {
            Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_RECORD_REUSE_REFUSED' `
                "recovery path appeared during validation: $candidate" `
                'preserve all state and use a fresh basename'
        }
    }

    $selfProbe = Get-AstroProcessIdentityProbe $PID
    if ($selfProbe.State -ne 'observed') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_SELF_IDENTITY_UNEVALUABLE' `
            "reclaim process PID $PID identity is unevaluable: $($selfProbe.Error)" `
            'run recovery only when its own native process identity is readable'
    }
    $authorization = [ordered]@{
        schema = 'astrolabe.launcher-lock-recovery.authorization.v4'
        phase = 'authorized-before-archive'
        recorded_at_utc = [DateTime]::UtcNow.ToString('o')
        mode = [ordered]@{
            legacy_pid_only = [bool]$LegacyPidOnly
            quarantine_unreadable = [bool]$QuarantineUnreadable
            protocol_state = if ($isActive) { 'active' } else {
                $transitionCandidateMatch.Groups['phase'].Value
            }
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
            root_final_path = $mutexLease.RootFinalPath
            recovered_abandoned_owner = [bool]$mutexLease.WasAbandoned
        }
        reclaim_process = [ordered]@{
            pid = $PID
            process_start_utc_ticks = [long]$selfProbe.ProcessStartUtcTicks
            process_started_utc = $selfProbe.ProcessStartedUtc
        }
        root = $rootFull
        target = [ordered]@{
            path = $lockFull
            bytes = $initial.Length
            sha256 = $initial.Sha256
            raw_bytes_base64 = [Convert]::ToBase64String($initial.Bytes)
            archive_path = $archiveFull
            transition_name_intended_sha256 = if ($isTransition) {
                if ($transitionMatch.Success) {
                    $transitionMatch.Groups['sha'].Value
                } else {
                    $null
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
    }
    $authorizationReadback = Write-NewDurableJsonAndReadBack `
        $recordFull `
        $authorization `
        'reclaim authorization record'

    $beforeArchive = Get-AstroFileSnapshot $lockFull ([IO.FileShare]::Read)
    if ($beforeArchive.Length -ne $initial.Length -or
        $beforeArchive.Sha256 -cne $initial.Sha256 -or
        -not (Test-ByteArraysEqual $beforeArchive.Bytes $initial.Bytes)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_LOCK_CHANGED' `
            'target bytes changed after authorization publication' `
            'preserve target and authorization; re-establish current ownership'
    }
    $secondProbe = Assert-OwnerDead `
        $expectedPidValue `
        $expectedTicksValue `
        ([bool]$LegacyPidOnly) `
        'after-authorization-before-archive'
    $trackerSecond = Read-TrackerEvidence `
        $TrackerCommentUrl `
        $expectedIssueValue `
        $lockFull `
        $expectedHash `
        $expectedPidValue `
        $expectedTicksValue `
        ([bool]$LegacyPidOnly) `
        ([bool]$QuarantineUnreadable) `
        $secondProbe
    if ($trackerSecond.BodySha256 -cne $trackerFirst.BodySha256 -or
        $trackerSecond.UpdatedAt -cne $trackerFirst.UpdatedAt) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TRACKER_CHANGED' `
            'tracker comment changed between authorization and archive' `
            'preserve target/authorization and post a fresh immutable evidence comment'
    }

    try {
        Move-AstroFileWriteThroughNoReplace $lockFull $archiveFull
    }
    catch {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ARCHIVE_MOVE_FAILED' `
            "exact write-through archive failed: $($_.Exception.Message)" `
            'preserve target and authorization; a live immutable lease or filesystem fault must be resolved'
    }
    if ((Get-AstroPathEntryState $lockFull).State -ne 'absent') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TARGET_REMAINS' `
            "target remains after archive move: $lockFull" `
            'preserve all state and investigate filesystem semantics'
    }
    $archive = Get-AstroFileSnapshot $archiveFull ([IO.FileShare]::Read)
    if ($archive.Length -ne $initial.Length -or
        $archive.Sha256 -cne $initial.Sha256 -or
        -not (Test-ByteArraysEqual $archive.Bytes $initial.Bytes)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_ARCHIVE_MISMATCH' `
            'archived bytes differ from the exact authorization source' `
            'preserve authorization/archive and investigate storage corruption'
    }
    $authorizationFinal = Get-AstroFileSnapshot $recordFull ([IO.FileShare]::Read)
    if ($authorizationFinal.Sha256 -cne
            $authorizationReadback.Snapshot.Sha256 -or
        -not (Test-ByteArraysEqual `
                $authorizationFinal.Bytes `
                $authorizationReadback.Snapshot.Bytes)) {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_AUTHORIZATION_CHANGED' `
            'authorization record changed before completion publication' `
            'preserve all recovery state and investigate concurrent modification'
    }

    $activePost = Read-AstroLauncherLockFile $activeLock
    $transitionPost = Get-AstroLauncherLockTransitions $activeLock
    if ($transitionPost.State -eq 'unevaluable') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_POSTSTATE_UNEVALUABLE' `
            $transitionPost.Error `
            'preserve recovery state and repair protocol-directory access'
    }
    $completion = [ordered]@{
        schema = 'astrolabe.launcher-lock-recovery.completion.v2'
        phase = 'archived-complete'
        completed_at_utc = [DateTime]::UtcNow.ToString('o')
        tracker = [ordered]@{
            url = $trackerSecond.Url
            comment_id = $trackerSecond.Id
            updated_at = $trackerSecond.UpdatedAt
            body_sha256 = $trackerSecond.BodySha256
        }
        authorization = [ordered]@{
            path = $recordFull
            bytes = $authorizationFinal.Length
            sha256 = $authorizationFinal.Sha256
        }
        post_publication_pid_probe = $secondProbe
        recovered_target = [ordered]@{
            path = $lockFull
            exists = $false
        }
        archive = [ordered]@{
            path = $archiveFull
            bytes = $archive.Length
            sha256 = $archive.Sha256
        }
        protocol_post_state = [ordered]@{
            active_path = $activeLock
            active_state = $activePost.State
            transition_state = $transitionPost.State
            transition_paths = @($transitionPost.Paths)
        }
    }
    $completionReadback = Write-NewDurableJsonAndReadBack `
        $completionFull `
        $completion `
        'reclaim completion record'

    $authorizationTerminal = Get-AstroFileSnapshot $recordFull ([IO.FileShare]::Read)
    $archiveTerminal = Get-AstroFileSnapshot $archiveFull ([IO.FileShare]::Read)
    $targetTerminal = Get-AstroPathEntryState $lockFull
    if ($authorizationTerminal.Sha256 -cne
            $authorizationReadback.Snapshot.Sha256 -or
        -not (Test-ByteArraysEqual `
                $authorizationTerminal.Bytes `
                $authorizationReadback.Snapshot.Bytes) -or
        $archiveTerminal.Sha256 -cne $initial.Sha256 -or
        -not (Test-ByteArraysEqual $archiveTerminal.Bytes $initial.Bytes) -or
        $targetTerminal.State -ne 'absent') {
        Fail-Astro 'ASTRO_LAUNCHER_LOCK_RECLAIM_TERMINAL_READBACK_FAILED' `
            'terminal authorization/archive/target state differs from the completion claim' `
            'preserve every recovery file and investigate before any new claim'
    }

    $result = [ordered]@{
        operation = 'reclaim-launcher-lock'
        verdict = 'archived'
        tracker_comment_url = $TrackerCommentUrl
        mutex = [ordered]@{
            name = $mutexLease.Name
            root_final_path = $mutexLease.RootFinalPath
            recovered_abandoned_owner = [bool]$mutexLease.WasAbandoned
        }
        authorization = [ordered]@{
            path = $recordFull
            bytes = $authorizationTerminal.Length
            sha256 = $authorizationTerminal.Sha256
        }
        completion = [ordered]@{
            path = $completionFull
            bytes = $completionReadback.Snapshot.Length
            sha256 = $completionReadback.Snapshot.Sha256
        }
        archive = [ordered]@{
            path = $archiveFull
            bytes = $archiveTerminal.Length
            sha256 = $archiveTerminal.Sha256
        }
        recovered_target = [ordered]@{
            path = $lockFull
            exists = $false
        }
    }
}
catch {
    $failure = $_
}
finally {
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
    } | ConvertTo-Json -Compress
    [Console]::Error.WriteLine("LAUNCHER_LOCK_RECLAIM[$code]: $payload")
    exit 70
}

$result | ConvertTo-Json -Depth 16 -Compress | Write-Output
