<#
.SYNOPSIS
    Tracker-authorized archive of one dead complete launcher TEMP/manifest pair.

.DESCRIPTION
    Ordinary launcher startup never mutates a dead pair.  This command verifies
    an exact machine-readable GitHub issue comment, acquires the workspace Global
    launcher mutex, probes owner and Job absence twice, retains both source FILE_IDs,
    and invokes the shared append-only archive transaction.  It never deletes TEMP,
    manifest, target, lock, transition, or archive bytes.

.NOTES
    Refs #620, #617, #611. Manual recovery tooling; this is not a test or gate.
#>
[CmdletBinding()]
param(
    [string]$Root = '',
    [Parameter(Mandatory)][string]$ExpectedIssue,
    [Parameter(Mandatory)][string]$ExpectedPid,
    [Parameter(Mandatory)][string]$ExpectedOwnerProcessStartUtcTicks,
    [Parameter(Mandatory)][string]$ExpectedLauncherLockSha256,
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][string]$ExpectedManifestSha256,
    [Parameter(Mandatory)][string]$TempPath,
    [Parameter(Mandatory)][string]$ExpectedTempFileId,
    [Parameter(Mandatory)][string]$TrackerCommentUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

. (Join-Path $PSScriptRoot 'launcher-lock.ps1')
. (Join-Path $PSScriptRoot 'attribution-manifest.ps1')
. (Join-Path $PSScriptRoot 'launcher-temp-guard.ps1')
. (Join-Path $PSScriptRoot 'launcher-state-archive.ps1')

function Fail-AstroArchive {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Remediation
    )
    $exception = [InvalidOperationException]::new($Message)
    $exception.Data['AstroCode'] = $Code
    $exception.Data['AstroRemediation'] = $Remediation
    [Console]::Error.WriteLine((
        [ordered]@{
            schema = 'astrolabe.launcher-pair-archive-error.v1'
            code = $Code
            message = $Message
            remediation = $Remediation
        } | ConvertTo-Json -Compress
    ))
    throw $exception
}

function Parse-PositiveInt {
    param([string]$Value, [string]$Name)
    $parsed = 0
    if (-not [int]::TryParse(
            $Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsed
        ) -or $parsed -le 0) {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_ARGUMENT_INVALID' `
            "$Name must be a positive invariant integer; received '$Value'" `
            'pass the exact independently observed value'
    }
    return $parsed
}

function Parse-PositiveTicks {
    param([string]$Value, [string]$Name)
    $parsed = 0L
    if (-not [long]::TryParse(
            $Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsed
        ) -or $parsed -le 0 -or $parsed -gt [DateTime]::MaxValue.Ticks) {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_ARGUMENT_INVALID' `
            "$Name must be positive UTC ticks in the DateTime range; received '$Value'" `
            'pass the exact independently observed process creation ticks'
    }
    return $parsed
}

function Invoke-AstroGhJson {
    param([Parameter(Mandatory)][string]$ApiPath)

    $gh = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $gh) {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_GH_MISSING' `
            'authenticated GitHub CLI is not available' `
            'install/authenticate gh and retry without changing protocol state'
    }
    $stdoutPath = Join-Path ([IO.Path]::GetTempPath()) (
        'astro-archive-gh-' + [Guid]::NewGuid().ToString('N') + '.out'
    )
    $stderrPath = Join-Path ([IO.Path]::GetTempPath()) (
        'astro-archive-gh-' + [Guid]::NewGuid().ToString('N') + '.err'
    )
    $process = $null
    try {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $gh.Source
        $start.Arguments = 'api ' + $ApiPath
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $false
        $start.RedirectStandardError = $false
        $start.EnvironmentVariables['NO_COLOR'] = '1'
        $start.EnvironmentVariables['GH_FORCE_TTY'] = '0'
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
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
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_GH_READ_FAILED' `
            $_.Exception.Message `
            'repair authenticated github.com access; no local state was authorized by this failed read'
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Read-AstroTrackerEvidence {
    param(
        [string]$Url,
        [int]$Issue,
        [string]$ExpectedRoot,
        [string]$ExpectedManifest,
        [string]$ManifestSha256,
        [string]$ExpectedTemp,
        [string]$TempFileId,
        [int]$PidValue,
        [long]$TicksValue,
        [string]$LockSha256
    )

    $match = [Regex]::Match(
        $Url,
        '^https://github\.com/(?<owner>[^/]+)/(?<repo>[^/]+)/issues/(?<issue>[1-9][0-9]*)#issuecomment-(?<comment>[1-9][0-9]*)\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success -or [int]$match.Groups['issue'].Value -ne $Issue) {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_TRACKER_URL_INVALID' `
            "tracker URL is not an exact issue-comment URL for #${Issue}: $Url" `
            'pass the fresh evidence comment URL from the driving issue'
    }
    $api = 'repos/{0}/{1}/issues/comments/{2}' -f
        $match.Groups['owner'].Value,
        $match.Groups['repo'].Value,
        $match.Groups['comment'].Value
    $comment = Invoke-AstroGhJson $api
    if ([string]$comment.html_url -cne $Url -or
        [string]$comment.author_association -cne 'OWNER') {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_TRACKER_IDENTITY_INVALID' `
            "GitHub readback does not bind the exact owner-authored URL (url='$($comment.html_url)', association='$($comment.author_association)')" `
            'use a repository-owner evidence comment and its exact canonical URL'
    }
    $prefix = 'ASTRO_LAUNCHER_PAIR_ARCHIVE_EVIDENCE '
    [string[]]$lines = @([string]$comment.body -split "`r?`n")
    [string[]]$markers = @($lines | Where-Object {
            $_.StartsWith($prefix, [StringComparison]::Ordinal)
        })
    if ($markers.Count -ne 1) {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_TRACKER_EVIDENCE_INVALID' `
            "tracker comment must contain exactly one '$prefix' line; observed $($markers.Count)" `
            'post one fresh canonical machine-readable evidence object'
    }
    $json = $markers[0].Substring($prefix.Length)
    try {
        $node = Read-AstroAttributionJsonValueNode $json 0 0 '$'
        $end = Get-AstroJsonNextTokenIndex $json $node.NextIndex
        if ($end -ne $json.Length -or
            (ConvertTo-AstroAttributionCanonicalJsonNode $node) -cne $json) {
            throw 'evidence JSON must be one exact canonical minified object'
        }
        $fields = @(
            'schema',
            'issue',
            'root',
            'manifest_path',
            'manifest_sha256',
            'temp_path',
            'temp_file_id',
            'expected_pid',
            'expected_owner_process_start_utc_ticks',
            'launcher_lock_sha256',
            'owner_probe_state',
            'job_probe_state'
        )
        Assert-AstroAttributionExactObjectFields $node $fields '$'
        $p = $node.Properties
        $actual = [ordered]@{
            schema = ConvertFrom-AstroAttributionStringNode $p['schema'] '$.schema' -Nonblank
            issue = [int](ConvertFrom-AstroAttributionUnsignedNode $p['issue'] '$.issue' ([uint64][int]::MaxValue) -Positive)
            root = ConvertFrom-AstroAttributionAbsolutePathNode $p['root'] '$.root'
            manifest_path = ConvertFrom-AstroAttributionAbsolutePathNode $p['manifest_path'] '$.manifest_path'
            manifest_sha256 = ConvertFrom-AstroAttributionStringNode $p['manifest_sha256'] '$.manifest_sha256' -Nonblank
            temp_path = ConvertFrom-AstroAttributionAbsolutePathNode $p['temp_path'] '$.temp_path'
            temp_file_id = ConvertFrom-AstroAttributionStringNode $p['temp_file_id'] '$.temp_file_id' -Nonblank
            expected_pid = [int](ConvertFrom-AstroAttributionUnsignedNode $p['expected_pid'] '$.expected_pid' ([uint64][int]::MaxValue) -Positive)
            expected_owner_process_start_utc_ticks = [long](ConvertFrom-AstroAttributionUnsignedNode $p['expected_owner_process_start_utc_ticks'] '$.expected_owner_process_start_utc_ticks' ([uint64][DateTime]::MaxValue.Ticks) -Positive)
            launcher_lock_sha256 = ConvertFrom-AstroAttributionStringNode $p['launcher_lock_sha256'] '$.launcher_lock_sha256' -Nonblank
            owner_probe_state = ConvertFrom-AstroAttributionStringNode $p['owner_probe_state'] '$.owner_probe_state' -Nonblank
            job_probe_state = ConvertFrom-AstroAttributionStringNode $p['job_probe_state'] '$.job_probe_state' -Nonblank
        }
    }
    catch {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_TRACKER_EVIDENCE_INVALID' `
            $_.Exception.Message `
            'post one fresh exact ordered canonical evidence object'
    }
    if ($actual.schema -cne 'astrolabe.launcher-pair-archive-evidence.v1' -or
        $actual.issue -ne $Issue -or
        -not [string]::Equals($actual.root, $ExpectedRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($actual.manifest_path, $ExpectedManifest, [StringComparison]::OrdinalIgnoreCase) -or
        $actual.manifest_sha256 -cne $ManifestSha256 -or
        -not [string]::Equals($actual.temp_path, $ExpectedTemp, [StringComparison]::OrdinalIgnoreCase) -or
        $actual.temp_file_id -cne $TempFileId -or
        $actual.expected_pid -ne $PidValue -or
        $actual.expected_owner_process_start_utc_ticks -ne $TicksValue -or
        $actual.launcher_lock_sha256 -cne $LockSha256 -or
        $actual.owner_probe_state -cne 'absent' -or
        $actual.job_probe_state -cne 'absent') {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_TRACKER_EVIDENCE_MISMATCH' `
            'tracker evidence differs from the exact command/local state binding' `
            're-read physical state and post a fresh evidence object with every exact field'
    }
    return [pscustomobject]@{
        Url = $Url
        CommentId = [long]$match.Groups['comment'].Value
        Author = [string]$comment.user.login
        Evidence = $actual
    }
}

$expectedIssueValue = Parse-PositiveInt $ExpectedIssue 'ExpectedIssue'
$expectedPidValue = Parse-PositiveInt $ExpectedPid 'ExpectedPid'
$expectedTicksValue = Parse-PositiveTicks `
    $ExpectedOwnerProcessStartUtcTicks `
    'ExpectedOwnerProcessStartUtcTicks'
if ($ExpectedLauncherLockSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $ExpectedManifestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $ExpectedTempFileId -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$') {
    Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_ARGUMENT_INVALID' `
        'hash/FILE_ID expectations are not canonical lowercase protocol values' `
        'pass exact lowercase readback values'
}

$rootFull = if ([string]::IsNullOrWhiteSpace($Root)) {
    [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
} else {
    [IO.Path]::GetFullPath($Root)
}
$protocol = [IO.Path]::GetFullPath((Join-Path $rootFull '.tmp'))
$manifestFull = [IO.Path]::GetFullPath($ManifestPath)
$tempFull = [IO.Path]::GetFullPath($TempPath).TrimEnd('\', '/')
Assert-AstroLauncherRootCanonical $rootFull
if (-not [string]::Equals(
        [IO.Path]::GetDirectoryName($manifestFull),
        $protocol,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    -not [string]::Equals(
        [IO.Path]::GetDirectoryName($tempFull),
        $protocol,
        [StringComparison]::OrdinalIgnoreCase
    )) {
    Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_PATH_ESCAPE' `
        'manifest and TEMP must be direct children of the exact root .tmp directory' `
        'pass only the exact independently inventoried complete pair'
}

$lockPath = Join-Path $protocol 'astrolabe-launcher.lock'
$mutex = $null
$protocolLease = $null
$tempLease = $null
$manifestLease = $null
$transaction = $null
try {
    $mutex = Enter-AstroLauncherLockMutex $lockPath
    if (-not $mutex.Acquired) {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_MUTEX_HELD' `
            "launcher protocol mutex is owned by another process: $($mutex.Name)" `
            'preserve the pair and retry only after the exact live owner exits'
    }
    $active = Get-AstroPathEntryState $lockPath
    $transitions = Get-AstroLauncherLockTransitions $lockPath
    if ($active.State -ne 'absent' -or $transitions.State -ne 'clear') {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_PROTOCOL_BUSY' `
            "active=$($active.State); transitions=$($transitions.State); paths=$(@($transitions.Paths) -join '; ')" `
            'archive a complete pair only when active/transition protocol state is absent'
    }
    $targetState = Get-AstroPathEntryState (Join-Path $rootFull 'target')
    if ($targetState.State -ne 'absent') {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_TARGET_NOT_ABSENT' `
            "target state is '$($targetState.State)' ($($targetState.Error))" `
            'preserve the pair and complete the target ownership procedure first'
    }

    $manifestProbe = Get-AstroAttributionManifestProbe $manifestFull
    $tempInventory = Get-AstroReservedLauncherTempEntries $protocol
    $manifestProbeSha256 = if ($null -ne $manifestProbe.Snapshot) {
        [string]$manifestProbe.Snapshot.Sha256
    } else { '<unavailable>' }
    $manifestOwnerState = if ($null -ne $manifestProbe.OwnerProbe) {
        [string]$manifestProbe.OwnerProbe.State
    } else { '<unavailable>' }
    $manifestJobState = if ($null -ne $manifestProbe.JobObjectProbe) {
        [string]$manifestProbe.JobObjectProbe.State
    } else { '<unavailable>' }
    if (-not $manifestProbe.Valid -or
        $manifestProbe.Snapshot.Sha256 -cne $ExpectedManifestSha256 -or
        $manifestProbe.Parsed.LauncherPid -ne $expectedPidValue -or
        $manifestProbe.Parsed.LauncherProcessStartUtcTicks -ne $expectedTicksValue -or
        $manifestProbe.Parsed.LauncherLockSha256 -cne $ExpectedLauncherLockSha256 -or
        $manifestProbe.OwnerProbe.State -cne 'absent' -or
        $manifestProbe.JobObjectProbe.State -cne 'absent') {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_MANIFEST_STATE_MISMATCH' `
            "state=$($manifestProbe.State); valid=$($manifestProbe.Valid); error=$($manifestProbe.Error); sha=$manifestProbeSha256; owner=$manifestOwnerState; job=$manifestJobState" `
            'preserve all state and post evidence only for the current strict physical pair'
    }
    $matchingTemps = @($tempInventory.Records | Where-Object {
            [string]::Equals(
                $_.Path,
                $tempFull,
                [StringComparison]::OrdinalIgnoreCase
            )
        })
    if (@($tempInventory.Records | Where-Object { -not $_.Valid }).Count -ne 0 -or
        $matchingTemps.Count -ne 1 -or
        -not $matchingTemps[0].Valid -or
        -not [string]::Equals(
            $matchingTemps[0].Path,
            $tempFull,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $matchingTemps[0].FileId -cne $ExpectedTempFileId) {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_TEMP_STATE_MISMATCH' `
            "records=$($tempInventory.Records.Count); paths=$(@($tempInventory.Paths) -join '; ')" `
            'preserve every TEMP entry; the selected pair must have one exact valid TEMP even when other complete pairs are queued'
    }

    $trackerFirst = Read-AstroTrackerEvidence `
        $TrackerCommentUrl $expectedIssueValue $rootFull $manifestFull `
        $ExpectedManifestSha256 $tempFull $ExpectedTempFileId `
        $expectedPidValue $expectedTicksValue $ExpectedLauncherLockSha256
    $ownerFirst = Get-AstroAttributionOwnerGenerationProbe `
        $expectedPidValue $expectedTicksValue
    $jobFirst = Get-AstroLauncherJobObjectProbe `
        $manifestProbe.Parsed.JobObjectName
    Start-Sleep -Milliseconds 1000
    $ownerSecond = Get-AstroAttributionOwnerGenerationProbe `
        $expectedPidValue $expectedTicksValue
    $jobSecond = Get-AstroLauncherJobObjectProbe `
        $manifestProbe.Parsed.JobObjectName
    if ($ownerFirst.State -cne 'absent' -or
        $ownerSecond.State -cne 'absent' -or
        $jobFirst.State -cne 'absent' -or
        $jobSecond.State -cne 'absent') {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_LIVENESS_CHANGED' `
            "owner_first=$($ownerFirst.State); owner_second=$($ownerSecond.State); job_first=$($jobFirst.State); job_second=$($jobSecond.State)" `
            'preserve every byte; recovery requires stable exact owner and Job absence'
    }

    $protocolLease = Open-AstroLauncherPinnedDirectoryLease $protocol
    $tempLease = Open-AstroLauncherTempArchiveLease `
        -Record $matchingTemps[0] `
        -Evidence $manifestProbe `
        -DirectoryLease $protocolLease
    $manifestLease = Open-AstroAttributionArchiveLease `
        -ManifestProbe $manifestProbe `
        -AuthorityMode tracker-reclaim `
        -TrackerEvidenceVerified
    $transaction = Start-AstroLauncherStateArchiveTransaction `
        -ProtocolDirectory $protocol `
        -ProtocolDirectoryLease $protocolLease `
        -TempLease $tempLease `
        -ManifestLease $manifestLease `
        -AuthorityMode tracker-reclaim `
        -DrivingIssue $expectedIssueValue `
        -TrackerCommentUrl $TrackerCommentUrl

    $trackerFinal = Read-AstroTrackerEvidence `
        $TrackerCommentUrl $expectedIssueValue $rootFull $manifestFull `
        $ExpectedManifestSha256 $tempFull $ExpectedTempFileId `
        $expectedPidValue $expectedTicksValue $ExpectedLauncherLockSha256
    $ownerFinal = Get-AstroAttributionOwnerGenerationProbe `
        $expectedPidValue $expectedTicksValue
    $jobFinal = Get-AstroLauncherJobObjectProbe `
        $manifestProbe.Parsed.JobObjectName
    if ($ownerFinal.State -cne 'absent' -or $jobFinal.State -cne 'absent' -or
        $trackerFinal.CommentId -ne $trackerFirst.CommentId) {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_FINAL_AUTHORITY_CHANGED' `
            "owner=$($ownerFinal.State); job=$($jobFinal.State); tracker=$($trackerFinal.CommentId)" `
            'preserve the published authorization transaction and inspect exact state'
    }

    $tempMove = Move-AstroLauncherStateArchiveTemp $transaction
    $manifestMove = Move-AstroLauncherStateArchiveManifest $transaction
    $completion = Complete-AstroLauncherStateArchiveTransaction $transaction

    $directManifest = Get-AstroPathEntryState $manifestFull
    $directTemp = Get-AstroPathEntryState $tempFull
    $terminalAttribution = Get-AstroAttributionInventory $protocol
    $terminalTemps = Get-AstroReservedLauncherTempEntries $protocol
    $remainingPairsValid = $terminalAttribution.Stable -and
        @($terminalAttribution.Errors).Count -eq 0 -and
        @($terminalAttribution.RefreshTransactions).Count -eq 0 -and
        @($terminalAttribution.Records).Count -eq
            @($terminalTemps.Records).Count -and
        @($terminalAttribution.Records | Where-Object {
                -not $_.Valid -or $_.Kind -cne 'manifest' -or
                $_.Parsed.SchemaVersion -ne 3 -or
                $_.OwnerProbe.State -cnotin @('absent', 'pid-reused') -or
                $_.JobObjectProbe.State -cne 'absent'
            }).Count -eq 0 -and
        @($terminalTemps.Records | Where-Object { -not $_.Valid }).Count -eq 0
    if ($remainingPairsValid) {
        foreach ($remainingManifest in @($terminalAttribution.Records)) {
            if (@($terminalTemps.Records | Where-Object {
                        [string]::Equals(
                            $_.Path,
                            $remainingManifest.ExpectedTempPath,
                            [StringComparison]::OrdinalIgnoreCase
                        )
                    }).Count -ne 1) {
                $remainingPairsValid = $false
                break
            }
        }
    }
    if ($directManifest.State -ne 'absent' -or
        $directTemp.State -ne 'absent' -or
        -not $remainingPairsValid) {
        Fail-AstroArchive 'ASTRO_LAUNCHER_ARCHIVE_TERMINAL_PROTOCOL_INVALID' `
            "manifest=$($directManifest.State); temp=$($directTemp.State); attribution_paths=$(@($terminalAttribution.Paths) -join '; '); attribution_errors=$(@($terminalAttribution.Errors) -join '; '); temp_paths=$(@($terminalTemps.Paths) -join '; ')" `
            'preserve the complete archive; the selected pair must be absent and every queued remainder must still be one strict dead-owner/Job-absent complete pair'
    }
    [pscustomobject]@{
        schema = 'astrolabe.launcher-pair-archive-result.v1'
        issue = $expectedIssueValue
        tracker_comment_url = $TrackerCommentUrl
        transaction_id = $completion.TransactionId
        transaction_path = $completion.TransactionPath
        authorization_path = $completion.AuthorizationPath
        authorization_sha256 = $completion.AuthorizationSha256
        completion_path = $completion.CompletionPath
        completion_sha256 = $completion.CompletionSha256
        temp_source_state = $directTemp.State
        temp_archive_path = $completion.TempArchivePath
        temp_file_id = $completion.TempRootFileId
        temp_inventory_state = $completion.TempInventoryState
        temp_inventory_error = $completion.TempInventoryError
        temp_entries = $completion.TempEntryCount
        temp_inventory_sha256 = $completion.TempInventorySha256
        temp_integrity_state = $completion.TempIntegrityState
        temp_authorization_to_rename_state =
            $completion.TempAuthorizationToRenameState
        temp_rename_operation_state = $completion.TempRenameOperationState
        temp_rename_to_completion_state =
            $completion.TempRenameToCompletionState
        temp_authorization_to_completion_state =
            $completion.TempAuthorizationToCompletionState
        manifest_source_state = $directManifest.State
        manifest_archive_path = $completion.ManifestArchivePath
        manifest_file_id = $completion.ManifestFileId
        manifest_bytes = $completion.ManifestLength
        manifest_sha256 = $completion.ManifestSha256
        owner_probes = @($ownerFirst.State, $ownerSecond.State, $ownerFinal.State)
        job_probes = @($jobFirst.State, $jobSecond.State, $jobFinal.State)
        target_state = $targetState.State
        active_lock_state = $active.State
        transition_state = $transitions.State
        remaining_complete_pairs = @($terminalAttribution.Records).Count
    } | ConvertTo-Json -Depth 8 -Compress
}
finally {
    if ($null -ne $transaction) {
        try { Close-AstroLauncherStateArchiveTransaction $transaction }
        catch { [Console]::Error.WriteLine($_.Exception.Message) }
    }
    else {
        if ($null -ne $tempLease -and $null -ne $tempLease.Handle -and
            -not $tempLease.Handle.IsClosed) {
            Close-AstroLauncherTempMutationLease $tempLease
        }
        if ($null -ne $manifestLease -and
            -not $manifestLease.Handle.IsClosed) {
            $manifestLease.Handle.Dispose()
        }
    }
    if ($null -ne $protocolLease -and
        -not $protocolLease.SafeFileHandle.IsClosed) {
        $protocolLease.SafeFileHandle.Dispose()
    }
    if ($null -ne $mutex) {
        Exit-AstroLauncherLockMutex $mutex
    }
}
