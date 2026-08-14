<#
.SYNOPSIS
    Execute a promoted native FSV artifact under a live launcher lease (#596).

.DESCRIPTION
    Verifies the content-addressed receipt, requires this runner to be a descendant of the
    live launcher-lock owner, acquires a dedicated JSON FSV lock, and opens the artifact with
    FileShare.Read (intentionally omitting FILE_SHARE_WRITE and FILE_SHARE_DELETE). The handle
    remains open for the complete child lifetime, so Windows refuses artifact mutation,
    rename, and directory cleanup while the real process is running.

    Before returning, it independently reads back the artifact hash, output hashes, and the
    kernel exit code through both the original PROCESS_INFORMATION process handle and a
    separately duplicated handle to that exact kernel object. Every launcher, runner, and child
    owner is persisted with process-start UTC ticks; the child ticks come from GetProcessTimes
    on the retained CreateProcess handle. It also records Git tree state into a durable run
    record. No PID-reopened process authority, CPU fallback, output substitution, retry, or mock
    behavior exists here.

    StandardOutputPath, StandardErrorPath, RunRecordPath, and LiveStatePath must each be a
    distinct absent file directly below the staged session root. The runner owns those four
    paths; callers must not pre-create an evidence/output directory in the session.

.NOTES
    Refs #612, #600, #596, #424, #197. Manual FSV tooling; this is not a test or a gate.
#>
[CmdletBinding(DefaultParameterSetName = 'SingleInline')]
param(
    [Parameter(Mandatory)][string]$ReceiptPath,
    [Parameter(Mandatory, ParameterSetName = 'SingleInline')][string]$ArgumentsJson,
    [Parameter(Mandatory, ParameterSetName = 'SingleFile')][string]$ArgumentsJsonPath,
    [Parameter(Mandatory, ParameterSetName = 'ResidentCohort')][switch]$ResidentCohort,
    [Parameter(Mandatory, ParameterSetName = 'ResidentCohort')][string]$CohortPlanPath,
    [Parameter(Mandatory)][string]$StandardOutputPath,
    [Parameter(Mandatory)][string]$StandardErrorPath,
    [Parameter(Mandatory)][string]$RunRecordPath,
    [Parameter(Mandatory)][string]$LiveStatePath,
    [Parameter(Mandatory)][int]$Issue
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

. (Join-Path $PSScriptRoot 'launcher-lock.ps1')

function Fail-Astro {
    param([string]$Code, [string]$Message, [string]$Remediation)
    $exception = [InvalidOperationException]::new($Message)
    $exception.Data['AstroCode'] = $Code
    $exception.Data['AstroRemediation'] = $Remediation
    throw $exception
}

# #1059: classify how a child process terminated.
#
# The g26 evidence leg was destroyed by a concurrent session's `Stop-Process
# -Force`; the run record recorded `exit_code = -1` and reported a generic child
# failure, so the incident took a multi-hour forensic session to attribute.
# `Process.Kill()`/`Stop-Process -Force` are literally `TerminateProcess(handle,
# -1)`, which is why 0xFFFFFFFF is the external-termination signature. Astrolabe
# no longer produces that code itself (launcher relay kills use 0xA57F0004; the
# Rust entrypoints remap a computed -1 to 0xA57F0006), so 0xFFFFFFFF in a run
# record is provably foreign and points straight at the kill-attribution log.
#
# This is additive metadata only: the verdict is computed exactly as before and
# an unrecognised code is reported as 'unclassified' rather than guessed at.
$script:AstroKillAttributionLog =
    'C:\ProgramData\astrolabe-kill-attribution\kills.log'

function Get-AstroTerminationClassification {
    param([AllowNull()]$ExitCode)

    if ($null -eq $ExitCode) {
        return [ordered]@{
            exit_code = $null
            exit_code_hex = $null
            classification = 'unobserved'
            detail = 'no exit code was observed for this process'
            remediation = 'inspect the run record process identity and observation error before drawing any conclusion'
        }
    }

    # Callers pass exit codes in both native shapes: signed Int32 (-1 from
    # Process.ExitCode) and unsigned UInt32 (4294967295 from the exact
    # GetExitCodeProcess observation). [int] on the latter overflows - the run
    # record writer must never be unable to persist exactly the code the g26
    # incident produced. Normalize through Int64 and keep the low 32 bits.
    $unsigned = [uint32]([int64]$ExitCode -band 0xFFFFFFFFL)
    $signed = [BitConverter]::ToInt32([BitConverter]::GetBytes($unsigned), 0)
    $hex = '0x' + $unsigned.ToString('X8', [Globalization.CultureInfo]::InvariantCulture)

    $classification = 'unclassified'
    $detail = 'exit code is not a known Astrolabe, Windows-status, or external-termination signature'
    $remediation = 'read the run stdout/stderr for this process and classify the code manually before reusing this evidence'

    # The `L` suffixes are load-bearing: PowerShell parses a bare 0xA57F0004 as a
    # two's-complement Int32, which never compares equal to the [uint32] subject.
    switch ($unsigned) {
        0x00000000L {
            $classification = 'clean_exit'
            $detail = 'the process exited 0 under its own control'
            $remediation = '<none>'
        }
        0x00000001L {
            $classification = 'structured_failure'
            $detail = 'the process exited 1, its ordinary structured-failure code'
            $remediation = 'read the structured {code,message,remediation} line on this process stderr'
        }
        0x00000003L {
            $classification = 'abort'
            $detail = 'exit 3 is the C runtime abort() code (assertion/panic=abort path)'
            $remediation = 'read the process stderr for the abort reason and check for a Windows Error Reporting record'
        }
        0xA57F0001L {
            $classification = 'runner_sentinel_bind_failure'
            $detail = 'native-fsv-run terminated the created-suspended child because exact handle binding failed'
            $remediation = 'inspect the runner failure record; this termination is ours, not external'
        }
        0xA57F0002L {
            $classification = 'runner_sentinel_duplicate_failure'
            $detail = 'native-fsv-run terminated the child because exact handle duplication/redirection failed'
            $remediation = 'inspect the runner failure record; this termination is ours, not external'
        }
        0xA57F0003L {
            $classification = 'runner_sentinel_cohort_failure'
            $detail = 'native-fsv-run terminated a resident-cohort member after a cohort fault'
            $remediation = 'inspect the cohort failure record; this termination is ours, not external'
        }
        0xA57F0004L {
            $classification = 'launcher_relay_sentinel'
            $detail = 'the launcher wrapper terminated its exact dedicated owner after a relay/drain fault'
            $remediation = 'read the ASTRO_LAUNCHER_DEDICATED_RELAY_FAILED boundary error; this termination is ours, not external'
        }
        0xA57F0006L {
            $classification = 'self_exit_sentinel_collision_remap'
            $detail = 'the process computed exit code -1 itself and remapped it so 0xFFFFFFFF stays provably foreign'
            $remediation = 'read the ASTRO_EXIT_CODE_SENTINEL_COLLISION stderr line and treat this as the original in-process failure'
        }
        0xC0000005L {
            $classification = 'native_crash_expect_wer'
            $detail = 'STATUS_ACCESS_VIOLATION'
            $remediation = 'read the Windows Error Reporting record for this pid and the process stderr'
        }
        0xC0000409L {
            $classification = 'native_crash_expect_wer'
            $detail = 'STATUS_STACK_BUFFER_OVERRUN (also the Rust/__fastfail abort path)'
            $remediation = 'read the Windows Error Reporting record for this pid and the process stderr'
        }
        0xC00000FDL {
            $classification = 'native_crash_expect_wer'
            $detail = 'STATUS_STACK_OVERFLOW; the sized host-thread contract exists for exactly this'
            $remediation = 'read the Windows Error Reporting record for this pid and confirm the entrypoint used the sized host thread'
        }
        0xC000013AL {
            $classification = 'console_interrupt'
            $detail = 'STATUS_CONTROL_C_EXIT; the process was killed by a console CTRL event (window close, Ctrl+C, console detach)'
            $remediation = 'rerun the leg detached from an interactive console (scripts\detach-run.ps1) so console lifetime cannot end it'
        }
        0xFFFFFFFFL {
            $classification = 'external_terminate_minus_one'
            $detail = 'TerminateProcess(handle, -1): the Process.Kill()/Stop-Process -Force signature. No Astrolabe path produces this code, so the process was terminated by another process'
            $remediation = "read $script:AstroKillAttributionLog for the JSON line whose exiting_pid matches this process (its initiating_pid names the killer), then the Application-log ProcessExitMonitor record - provider 'Microsoft-Windows-ProcessExitMonitor', event id 3001 on Windows 11 26100 (3000 on older pairings); if the log is absent, kill attribution was not armed - arm it with scripts\kill-attribution.ps1 -Operation Enable before the next long run"
        }
    }

    return [ordered]@{
        exit_code = $signed
        exit_code_hex = $hex
        classification = $classification
        detail = $detail
        remediation = $remediation
    }
}

function Path-WithTrailingSeparator([string]$Path) {
    return ([IO.Path]::GetFullPath($Path).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar)
}

function Assert-PathWithin([string]$Path, [string]$Root, [string]$Code, [string]$Description) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith((Path-WithTrailingSeparator $Root), [StringComparison]::OrdinalIgnoreCase)) {
        Fail-Astro $Code "$Description '$full' escapes required root '$Root'" 'use a fresh path inside the staged evidence session'
    }
    return $full
}

function Assert-DirectSessionRootOutputPath([string]$Path, [string]$SessionDirectory, [string]$Description) {
    $full = Assert-PathWithin $Path $SessionDirectory 'ASTRO_FSV_OUTPUT_ESCAPE' $Description
    if (-not [string]::Equals(
            [IO.Path]::GetFullPath((Split-Path -Parent $full)),
            [IO.Path]::GetFullPath($SessionDirectory),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Fail-Astro 'ASTRO_FSV_OUTPUT_NOT_SESSION_ROOT' `
            "$Description must be a direct file child of staged session '$SessionDirectory': $full" `
            'use one fresh direct session-root output file; the runner owns its four output files and no output directories may be pre-created'
    }
    return $full
}

function Assert-NotReparseEntry([string]$Path, [string]$Description) {
    $state = Get-AstroPathEntryState $Path
    if ($state.State -ceq 'absent') { return }
    if ($state.State -cne 'present') {
        Fail-Astro 'ASTRO_FSV_PATH_UNEVALUABLE' `
            "$Description presence/attributes are unevaluable: $Path ($($state.Error))" `
            'repair filesystem access before executing evidence state'
    }
    if (($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Astro 'ASTRO_FSV_REPARSE_ENTRY_REFUSED' "$Description is a reparse point: $Path" 'use ordinary workspace-local evidence paths that cannot redirect elsewhere'
    }
}

function File-Sha256([string]$Path) {
    $handle = [AstroLauncherLockNative]::OpenExactProtectedReadFile(
        [IO.Path]::GetFullPath($Path)
    )
    try {
        return [AstroLauncherLockNative]::ComputeExactFileSha256($handle)
    }
    finally { $handle.Dispose() }
}

function Assert-AstroFsvLifecycleAdmissionClear([string]$Workspace) {
    $state = Get-AstroFsvLifecycleInterruptionState -WorkspaceRoot $Workspace
    if ($state.State -cne 'absent') {
        Fail-Astro 'ASTRO_FSV_LIFECYCLE_TRANSITION_PRESENT' `
            "native-FSV lifecycle state is '$($state.State)' (paths=$(@($state.Paths) -join ';'); error=$($state.Error))" `
            'resume the exact durable lifecycle transaction before admitting another FSV generation'
    }
}

function Enter-AstroFsvAdmissionLease([string]$Workspace) {
    $lease = Enter-AstroFsvLifecycleMutex -WorkspaceRoot $Workspace
    if (-not $lease.Acquired) {
        $name = [string]$lease.Name
        Exit-AstroFsvLifecycleMutex $lease
        Fail-Astro 'ASTRO_FSV_LIFECYCLE_MUTEX_HELD' `
            "native-FSV lifecycle mutex is held: $name" `
            'wait for the exact active claim/recovery transaction to publish durable state'
    }
    return $lease
}

function String-Sha256([AllowEmptyString()][string]$Value) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))) -replace '-', '').ToLowerInvariant()
    }
    finally { $hasher.Dispose() }
}

function ByteArray-Sha256([AllowEmptyCollection()][byte[]]$Value) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($Value)) -replace '-', '').ToLowerInvariant()
    }
    finally { $hasher.Dispose() }
}

function ConvertTo-AstroNativeCommandLineArgument {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    # Windows PowerShell 5.1 lacks ProcessStartInfo.ArgumentList. Encode each
    # native argument with CommandLineToArgvW's inverse rules so Git sees the
    # exact values without shell tokenization or lossy fallback behavior.
    if ($Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }

    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append('\', ($slashes * 2) + 1)
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) {
            [void]$builder.Append('\', $slashes)
            $slashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($slashes -gt 0) { [void]$builder.Append('\', $slashes * 2) }
    [void]$builder.Append('"')
    return $builder.ToString()
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
    $nativeArguments = @('-C', [IO.Path]::GetFullPath($Workspace).TrimEnd('\', '/')) + @($Arguments)
    $start.Arguments = [string]::Join(
        ' ',
        @($nativeArguments | ForEach-Object {
            ConvertTo-AstroNativeCommandLineArgument -Value ([string]$_)
        })
    )
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $stdout = [IO.MemoryStream]::new()
    try {
        if (-not $process.Start()) {
            Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' "$Description did not start during evidence execution" `
                'repair native Git before executing evidence'
        }
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            try { $process.Kill() } catch {}
            Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' "$Description exceeded the 30000 ms bounded timeout during evidence execution" `
                'repair native Git or repository state before executing evidence'
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
        Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' "git status --porcelain=v1 -z failed during evidence execution (exit=$($status.ExitCode), stderr=$($status.Stderr))" `
            'repair repository state before evidence execution'
    }
    try {
        $statusText = [Text.UTF8Encoding]::new($false, $true).GetString($status.Bytes)
    }
    catch {
        Fail-Astro 'ASTRO_FSV_GIT_STATUS_UTF8_INVALID' "Git status emitted bytes that are not strict UTF-8 during evidence execution: $($_.Exception.Message)" `
            'rename the unsupported Windows worktree path before executing evidence'
    }
    if ($status.Bytes.Length -gt 0 -and
        $status.Bytes[$status.Bytes.Length - 1] -ne 0) {
        Fail-Astro 'ASTRO_FSV_GIT_STATUS_TERMINAL_NUL_MISSING' `
            'nonempty Git porcelain-v1 -z output lacks its terminal NUL during evidence execution' `
            'repair or replace the native Git executable before executing evidence'
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

function Observe-ExitedProcessCode(
    [AstroFsvCreatedProcess]$Process
) {
    if (-not $Process.HasExited) {
        Fail-Astro 'ASTRO_FSV_CHILD_STILL_LIVE' "native child PID $($Process.Id) is still live after the runner wait completed" 'preserve the FSV lock and wait for the exact recorded child to exit naturally'
    }
    try {
        [uint32]$kernelCode =
            [AstroFsvAtomicFile]::ReadTerminatedProcessExitCode($Process.ProcessHandle)
        [uint32]$duplicateCode =
            [AstroFsvAtomicFile]::ReadTerminatedProcessExitCode($Process.ObservationHandle)
    }
    catch {
        Fail-Astro 'ASTRO_FSV_CHILD_EXIT_UNREADABLE' "kernel32!GetExitCodeProcess failed for an exact retained handle to native child PID $($Process.Id): $($_.Exception.Message)" 'preserve the session and both exact process-handle observations; repair process-exit observation before rerunning'
    }
    return [ordered]@{
        exit_code = $kernelCode
        exit_code_hex = ('0x{0:X8}' -f [uint64]$kernelCode)
        primary_source = 'kernel32!GetExitCodeProcess(PROCESS_INFORMATION.hProcess)'
        exact_duplicate_source = 'kernel32!GetExitCodeProcess(DuplicateHandle(PROCESS_INFORMATION.hProcess))'
        exact_duplicate_exit_code = $duplicateCode
        exact_duplicate_exit_code_hex = ('0x{0:X8}' -f [uint64]$duplicateCode)
        sources_agree = $duplicateCode -eq $kernelCode
    }
}

function Get-AstroStructuredObjectFieldNames {
    param(
        [Parameter(Mandatory)][AllowNull()]$Object
    )

    if ($null -eq $Object) { return [string[]]::new(0) }
    if ($Object -is [Collections.IDictionary]) {
        return [string[]]@($Object.Keys | ForEach-Object { [string]$_ })
    }
    return [string[]]@($Object.PSObject.Properties | ForEach-Object Name)
}

function Get-AstroStructuredObjectFieldValue {
    param(
        [Parameter(Mandatory)][AllowNull()]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) { return $Object[$Name] }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Read-AstroFsvExitCodeObservation {
    param(
        [Parameter(Mandatory)][AllowNull()]$Observation,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    $requiredFields = @(
        'exit_code', 'exit_code_hex', 'primary_source',
        'exact_duplicate_source', 'exact_duplicate_exit_code',
        'exact_duplicate_exit_code_hex', 'sources_agree'
    )
    if ($null -eq $Observation) {
        Fail-Astro $Code `
            "$Description is absent" `
            'preserve the session and inspect the durable process observation'
    }
    $actualFields = @(Get-AstroStructuredObjectFieldNames $Observation)
    if (
        $actualFields.Count -ne $requiredFields.Count -or
        @($requiredFields | Where-Object {
                $actualFields -cnotcontains $_
            }).Count -ne 0) {
        Fail-Astro $Code `
            "$Description does not contain the exact exit-observation field set" `
            'preserve the session and inspect the durable process observation'
    }

    $codes = [Collections.Generic.List[uint64]]::new()
    foreach ($field in @('exit_code', 'exact_duplicate_exit_code')) {
        $raw = Get-AstroStructuredObjectFieldValue $Observation $field
        $text = if ($null -eq $raw) {
            ''
        }
        else {
            [Convert]::ToString(
                $raw,
                [Globalization.CultureInfo]::InvariantCulture
            )
        }
        [uint64]$parsed = 0
        if ($text -cnotmatch '^(0|[1-9][0-9]{0,9})$' -or
            -not [uint64]::TryParse(
                $text,
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$parsed
            ) -or
            $parsed -gt [uint32]::MaxValue) {
            Fail-Astro $Code `
                "$Description $field is not one canonical unsigned 32-bit decimal value" `
                'preserve the session and inspect the durable process observation'
        }
        $codes.Add($parsed)
    }

    $primaryHex = '0x{0:X8}' -f $codes[0]
    $duplicateHex = '0x{0:X8}' -f $codes[1]
    $primarySource =
        'kernel32!GetExitCodeProcess(PROCESS_INFORMATION.hProcess)'
    $duplicateSource =
        'kernel32!GetExitCodeProcess(DuplicateHandle(PROCESS_INFORMATION.hProcess))'
    $observedPrimaryHex = [string](Get-AstroStructuredObjectFieldValue `
            $Observation 'exit_code_hex')
    $observedDuplicateHex = [string](Get-AstroStructuredObjectFieldValue `
            $Observation 'exact_duplicate_exit_code_hex')
    $observedPrimarySource = [string](Get-AstroStructuredObjectFieldValue `
            $Observation 'primary_source')
    $observedDuplicateSource = [string](Get-AstroStructuredObjectFieldValue `
            $Observation 'exact_duplicate_source')
    $observedAgreement = Get-AstroStructuredObjectFieldValue `
        $Observation 'sources_agree'
    if ($observedPrimaryHex -cne $primaryHex -or
        $observedDuplicateHex -cne
            $duplicateHex -or
        $observedPrimarySource -cne $primarySource -or
        $observedDuplicateSource -cne $duplicateSource -or
        $observedAgreement -isnot [bool] -or
        [bool]$observedAgreement -ne ($codes[0] -eq $codes[1])) {
        Fail-Astro $Code `
            "$Description decimal/hex/source/agreement fields are internally inconsistent" `
            'preserve the session and inspect the durable process observation'
    }

    return [ordered]@{
        exit_code = [uint64]$codes[0]
        exit_code_hex = $primaryHex
        primary_source = $primarySource
        exact_duplicate_source = $duplicateSource
        exact_duplicate_exit_code = [uint64]$codes[1]
        exact_duplicate_exit_code_hex = $duplicateHex
        sources_agree = [bool]$observedAgreement
    }
}

function Assert-AstroFsvExitCodeObservationReadback {
    param(
        [Parameter(Mandatory)]$Persisted,
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    $persistedObservation = Read-AstroFsvExitCodeObservation `
        $Persisted $Code "$Description persisted observation"
    $expectedObservation = Read-AstroFsvExitCodeObservation `
        $Expected $Code "$Description in-memory observation"
    foreach ($field in @(
        'exit_code', 'exit_code_hex', 'primary_source',
        'exact_duplicate_source', 'exact_duplicate_exit_code',
        'exact_duplicate_exit_code_hex', 'sources_agree'
    )) {
        if ([string]$persistedObservation.$field -cne
            [string]$expectedObservation.$field) {
            Fail-Astro $Code `
                "$Description persisted $field differs from the exact observed value" `
                'preserve the session and investigate the failed durable write'
        }
    }
    return $persistedObservation
}

function Assert-AstroFsvCohortProcessExitReadback {
    param(
        [Parameter(Mandatory)][object[]]$PersistedProcesses,
        [Parameter(Mandatory)][object[]]$ExpectedStates,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    if ($PersistedProcesses.Count -ne $ExpectedStates.Count) {
        Fail-Astro $Code `
            "$Description process cardinality differs from the in-memory cohort" `
            'preserve the session and investigate the failed durable write'
    }
    foreach ($expected in $ExpectedStates) {
        $matches = @($PersistedProcesses | Where-Object {
            [string]$_.role -ceq [string]$expected.role -and
            [int]$_.ordinal -eq [int]$expected.ordinal
        })
        if ($matches.Count -ne 1) {
            Fail-Astro $Code `
                "$Description has no unique $($expected.role)/$($expected.ordinal) process record" `
                'preserve the session and investigate the failed durable write'
        }
        $persisted = $matches[0]
        if (-not $persisted.PSObject.Properties['exit_code'] -or
            -not $persisted.PSObject.Properties['exit_code_observation'] -or
            $null -eq $persisted.exit_code_observation -or
            -not $persisted.PSObject.Properties['termination_proved'] -or
            $persisted.termination_proved -isnot [bool] -or
            -not $persisted.PSObject.Properties['exact_process_handles_closed'] -or
            $persisted.exact_process_handles_closed -isnot [bool]) {
            Fail-Astro $Code `
                "$Description $($expected.role)/$($expected.ordinal) omits its exact exit/termination envelope" `
                'preserve the session and investigate the failed durable write'
        }
        $normalized = Assert-AstroFsvExitCodeObservationReadback `
            $persisted.exit_code_observation `
            $expected.exit_code_observation `
            $Code `
            "$Description $($expected.role)/$($expected.ordinal) exit observation"
        if ([uint64]$persisted.exit_code -ne
                [uint64]$normalized.exit_code -or
            [uint64]$persisted.exit_code -ne [uint64]$expected.exit_code -or
            [bool]$persisted.termination_proved -ne
                [bool]$expected.termination_proved -or
            [bool]$persisted.exact_process_handles_closed -ne
                [bool]$expected.handles_closed) {
            Fail-Astro $Code `
                "$Description $($expected.role)/$($expected.ordinal) exit/termination fields differ from the exact observed state" `
                'preserve the session and investigate the failed durable write'
        }
    }
}

function Failure-Text($Value) {
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text
}

function Write-NewDurableUtf8([string]$Path, [string]$Content) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Content)
    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Publish-NewFile([string]$Path, [string]$Content) {
    $parent = Split-Path -Parent $Path
    if (-not (Test-AstroPathLongPath -LiteralPath $parent -PathType Container)) {
        New-AstroDirectoryLongPath $parent | Out-Null
    }
    $stage = Join-Path $parent ('.' + [IO.Path]::GetFileName($Path) + ".publishing-$PID-" + [guid]::NewGuid().ToString('N'))
    try {
        Write-NewDurableUtf8 $stage $Content
        [AstroFsvAtomicFile]::PublishNoClobber($stage, $Path)
    }
    catch {
        if (Test-AstroPathLongPath -LiteralPath $stage -PathType Leaf) {
            Remove-AstroFileLongPath $stage
        }
        throw
    }
}

function Remove-TerminalFsvLock {
    param(
        [Parameter(Mandatory)][string]$LockPath,
        [Parameter(Mandatory)][AllowNull()]$RunnerIdentity,
        [Parameter(Mandatory)][AllowNull()]$ChildIdentity,
        [Parameter(Mandatory)][string]$ArtifactSha256
    )

    if (-not (Test-AstroPathLongPath -LiteralPath $LockPath)) {
        return [ordered]@{
            path = $LockPath
            before_exists = $false
            removed = $false
            after_exists = $false
            sha256_before = $null
        }
    }
    $lockSha = File-Sha256 $LockPath
    try {
        $lock = Read-AstroUtf8FileLongPath $LockPath | ConvertFrom-Json
        $lockRunnerIdentity = Read-AstroFsvProcessIdentity `
            $lock.owners.runner `
            'ASTRO_FSV_LOCK_IDENTITY_CHANGED' `
            'terminal FSV lock runner identity'
        $lockChildIdentity = Read-AstroFsvProcessIdentity `
            $lock.owners.child `
            'ASTRO_FSV_LOCK_IDENTITY_CHANGED' `
            'terminal FSV lock child identity'
    }
    catch {
        Fail-Astro `
            'ASTRO_FSV_LOCK_IDENTITY_CHANGED' `
            "terminal FSV lock is unreadable or malformed: $($_.Exception.Message)" `
            'preserve the lock and session; retire only through the tracker-bound stale-lock lifecycle after exact identity readback'
    }
    if ($lock.schema -cne 'astrolabe.native-fsv-lock.v2' -or
        -not (Test-AstroFsvIdentityEqual $lockRunnerIdentity $RunnerIdentity) -or
        -not (Test-AstroFsvIdentityEqual $lockChildIdentity $ChildIdentity) -or
        [string]$lock.artifact_sha256 -cne $ArtifactSha256) {
        Fail-Astro `
            'ASTRO_FSV_LOCK_IDENTITY_CHANGED' `
            'terminal FSV lock no longer matches this exact runner/child/artifact generation' `
            'preserve the lock and session; retire only through the tracker-bound stale-lock lifecycle after exact identity readback'
    }
    Remove-AstroFileLongPath $LockPath
    if (Test-AstroPathLongPath -LiteralPath $LockPath) {
        Fail-Astro `
            'ASTRO_FSV_LOCK_CLEANUP_READBACK_FAILED' `
            "owned FSV lock remained after terminal cleanup: $LockPath" `
            'preserve the lock and session; retire only through the tracker-bound stale-lock lifecycle after exact owner absence'
    }
    return [ordered]@{
        path = $LockPath
        before_exists = $true
        removed = $true
        after_exists = $false
        sha256_before = $lockSha
    }
}

function Get-RepoState([string]$GitExe, [string]$Workspace) {
    $head = (& $GitExe -C $Workspace rev-parse HEAD).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0) { Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' 'git rev-parse HEAD failed' 'repair repository state before evidence execution' }
    $status = Read-GitStatusFingerprint -GitExe $GitExe -Workspace $Workspace
    $diff = Invoke-GitRawCapture `
        -GitExe $GitExe `
        -Workspace $Workspace `
        -Arguments @('diff', '--binary', 'HEAD') `
        -Description 'git diff --binary HEAD'
    if ($diff.ExitCode -ne 0) {
        Fail-Astro 'ASTRO_FSV_GIT_UNREADABLE' "git diff --binary HEAD failed during evidence execution (exit=$($diff.ExitCode), stderr=$($diff.Stderr))" `
            'repair repository state before evidence execution'
    }
    return [ordered]@{
        head_sha = $head
        status_sha256 = [string]$status.sha256
        status_records = [string[]]$status.records
        diff_sha256 = ByteArray-Sha256 $diff.Bytes
    }
}

function Read-AstroFsvProcessIdentity(
    $Object,
    [string]$Code,
    [string]$Description
) {
    if ($null -eq $Object) {
        Fail-Astro $Code "$Description is absent" `
            'preserve the session and investigate incomplete process provenance'
    }
    $properties = @(Get-AstroStructuredObjectFieldNames $Object)
    $required = @('pid', 'process_start_utc_ticks', 'process_started_utc')
    if ($properties.Count -ne $required.Count -or
        @($required | Where-Object { $properties -notcontains $_ }).Count -ne 0) {
        Fail-Astro $Code `
            "$Description must contain exactly pid, process_start_utc_ticks, process_started_utc" `
            'preserve the session; legacy and partial authority records fail closed'
    }
    $parsedPid = 0
    $parsedTicks = 0L
    if (-not [int]::TryParse(
            [string](Get-AstroStructuredObjectFieldValue $Object 'pid'),
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsedPid
        ) -or $parsedPid -le 0 -or
        -not [long]::TryParse(
            [string](Get-AstroStructuredObjectFieldValue `
                $Object 'process_start_utc_ticks'),
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsedTicks
        ) -or $parsedTicks -le 0 -or
        $parsedTicks -gt [DateTime]::MaxValue.Ticks) {
        Fail-Astro $Code "$Description has an invalid PID or process-start UTC ticks" `
            'preserve the session and investigate incomplete process provenance'
    }
    $expectedIso = ConvertTo-AstroProcessStartUtcIso $parsedTicks
    $startedValue = Get-AstroStructuredObjectFieldValue `
        $Object 'process_started_utc'
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
            "$Description UTC diagnostic differs from its exact UTC ticks" `
            'preserve the session and investigate durable identity drift'
    }
    return New-AstroProcessIdentityRecord $parsedPid $parsedTicks
}

function Test-AstroFsvIdentityEqual($Left, $Right) {
    return [int]$Left.pid -eq [int]$Right.pid -and
        [long]$Left.process_start_utc_ticks -eq
            [long]$Right.process_start_utc_ticks
}

function Get-AstroCurrentProcessIdentity(
    [Alias('Pid')][int]$ProcessId,
    [string]$Code,
    [string]$Description
) {
    $probe = Get-AstroProcessIdentityProbe -OwnerPid $ProcessId
    if ($probe.State -cne 'observed') {
        Fail-Astro $Code `
            "$Description process identity is '$($probe.State)': $($probe.Error)" `
            'preserve state and retry only when the live process creation time is readable'
    }
    return New-AstroProcessIdentityRecord `
        $ProcessId ([long]$probe.ProcessStartUtcTicks)
}

if (-not ([Management.Automation.PSTypeName]'AstroFsvAtomicFile').Type) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

public static class AstroFsvAtomicFile {
    const uint MOVEFILE_REPLACE_EXISTING = 0x00000001;
    const uint MOVEFILE_WRITE_THROUGH = 0x00000008;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint OPEN_EXISTING = 3;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const uint STILL_ACTIVE = 259;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool MoveFileExW(string existingName, string newName, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    static string Extended(string path) {
        string full = System.IO.Path.GetFullPath(path);
        if (full.StartsWith(@"\\?\", StringComparison.Ordinal))
            return full;
        if (full.StartsWith(@"\\", StringComparison.Ordinal))
            return @"\\?\UNC\" + full.Substring(2);
        return @"\\?\" + full;
    }

    public static void PublishNoClobber(string source, string destination) {
        Move(source, destination, MOVEFILE_WRITE_THROUGH);
    }

    public static void ReplaceOwned(string source, string destination) {
        Move(source, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }

    static void Move(string source, string destination, uint flags) {
        if (!MoveFileExW(Extended(source), Extended(destination), flags)) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "MoveFileExW atomic write-through publication failed " +
                "(native_error=" + error + "; flags=" + flags +
                "; source=" + source + "; destination=" + destination + ")");
        }
    }

    public static SafeFileHandle OpenDirectoryWithoutDeleteShare(string path) {
        SafeFileHandle handle = CreateFileW(Extended(path), 0, FILE_SHARE_READ,
            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (handle.IsInvalid) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "CreateFileW evidence-directory lease failed (native_error=" +
                error + "; path=" + path + ")");
        }
        return handle;
    }

    public static uint ReadTerminatedProcessExitCode(SafeProcessHandle process) {
        if (process == null || process.IsInvalid || process.IsClosed)
            throw new InvalidOperationException("retained native process handle is invalid or closed");
        uint exitCode;
        if (!GetExitCodeProcess(process, out exitCode))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess failed");
        if (exitCode == STILL_ACTIVE)
            throw new InvalidOperationException("retained native process handle still reports STILL_ACTIVE");
        return exitCode;
    }
}

public sealed class AstroFsvCreatedProcess : IDisposable {
    const uint STILL_ACTIVE = 259;
    const uint WAIT_OBJECT_0 = 0;
    const uint WAIT_TIMEOUT = 258;
    const uint WAIT_FAILED = 0xFFFFFFFF;
    const uint INFINITE = 0xFFFFFFFF;
    const uint DUPLICATE_SAME_ACCESS = 0x00000002;
    const uint BIND_FAILURE_EXIT_CODE = 0xA57F0001U;
    const uint DUPLICATE_FAILURE_EXIT_CODE = 0xA57F0002U;
    const uint COHORT_FAILURE_EXIT_CODE = 0xA57F0003U;
    const uint DUPLICATE_FAILURE_WAIT_MS = 30000;

    public static uint BindFailureExitCode {
        get { return BIND_FAILURE_EXIT_CODE; }
    }

    public static uint DuplicateFailureExitCode {
        get { return DUPLICATE_FAILURE_EXIT_CODE; }
    }

    public static uint CohortFailureExitCode {
        get { return COHORT_FAILURE_EXIT_CODE; }
    }

    IntPtr threadHandle;
    bool disposed;
    StreamWriter inputWriter;
    StreamReader outputReader;
    StreamReader errorReader;
    Task<string> outputDrain;
    Task<string> errorDrain;

    [StructLayout(LayoutKind.Sequential)]
    struct FILETIME {
        public uint Low;
        public uint High;
    }

    internal AstroFsvCreatedProcess(IntPtr processHandle, IntPtr primaryThreadHandle, uint processId) {
        ProcessHandle = new SafeProcessHandle(processHandle, true);
        threadHandle = primaryThreadHandle;
        ProcessId = processId;
        try {
            FILETIME creation;
            FILETIME exit;
            FILETIME kernel;
            FILETIME user;
            if (!GetProcessTimes(
                ProcessHandle,
                out creation,
                out exit,
                out kernel,
                out user)) {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error,
                    "GetProcessTimes failed for exact created native child " +
                    "(native_error=" + error + "; pid=" + ProcessId + ")");
            }
            ulong fileTime =
                ((ulong)creation.High << 32) | (ulong)creation.Low;
            ProcessStartFileTime = checked((long)fileTime);
            ProcessStartUtcTicks =
                DateTime.FromFileTimeUtc(ProcessStartFileTime).Ticks;
            SafeProcessHandle duplicate;
            IntPtr current = GetCurrentProcess();
            if (!DuplicateHandle(
                current,
                ProcessHandle,
                current,
                out duplicate,
                0,
                false,
                DUPLICATE_SAME_ACCESS)) {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error,
                    "DuplicateHandle failed for exact created native child process " +
                    "(native_error=" + error + "; pid=" + ProcessId + ")");
            }
            ObservationHandle = duplicate;
        }
        catch (Exception identityFailure) {
            Exception cleanupFailure = null;
            try {
                if (!TerminateProcess(ProcessHandle, DUPLICATE_FAILURE_EXIT_CODE)) {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error,
                        "TerminateProcess failed after exact process-identity capture failure " +
                        "(native_error=" + error + "; pid=" + ProcessId + ")");
                }
                uint cleanupWait = WaitForExactHandle(
                    ProcessHandle,
                    DUPLICATE_FAILURE_WAIT_MS,
                        "primary process handle after identity capture failure");
                if (cleanupWait == WAIT_TIMEOUT) {
                    throw new TimeoutException(
                        "timed out waiting for exact suspended child cleanup after " +
                        "process-identity capture failure (pid=" + ProcessId +
                        "; timeout_ms=" + DUPLICATE_FAILURE_WAIT_MS + ")");
                }
            }
            catch (Exception cleanup) {
                cleanupFailure = cleanup;
            }
            if (threadHandle != IntPtr.Zero) {
                if (!CloseHandle(threadHandle) && cleanupFailure == null) {
                    int error = Marshal.GetLastWin32Error();
                    cleanupFailure = new Win32Exception(error,
                        "CloseHandle failed for primary thread after process-identity capture failure " +
                        "(native_error=" + error + "; pid=" + ProcessId + ")");
                }
                threadHandle = IntPtr.Zero;
            }
            ProcessHandle.Dispose();
            if (cleanupFailure != null) {
                throw new InvalidOperationException(
                    identityFailure.Message +
                    "; exact suspended-child cleanup also failed: " +
                    cleanupFailure.Message,
                    identityFailure);
            }
            throw;
        }
    }

    internal AstroFsvCreatedProcess(
        IntPtr processHandle,
        IntPtr primaryThreadHandle,
        uint processId,
        SafeFileHandle parentInputWrite,
        SafeFileHandle parentOutputRead,
        SafeFileHandle parentErrorRead) : this(processHandle, primaryThreadHandle, processId) {
        try {
            UTF8Encoding strictUtf8 = new UTF8Encoding(false, true);
            inputWriter = new StreamWriter(
                new FileStream(parentInputWrite, FileAccess.Write, 4096, false),
                strictUtf8, 4096);
            inputWriter.AutoFlush = true;
            outputReader = new StreamReader(
                new FileStream(parentOutputRead, FileAccess.Read, 4096, false),
                strictUtf8, true, 4096, false);
            errorReader = new StreamReader(
                new FileStream(parentErrorRead, FileAccess.Read, 4096, false),
                strictUtf8, true, 4096, false);
        }
        catch {
            try { TerminateAndWait(DUPLICATE_FAILURE_EXIT_CODE, DUPLICATE_FAILURE_WAIT_MS); }
            finally {
                Dispose();
            }
            throw;
        }
    }

    public SafeProcessHandle ProcessHandle { get; private set; }
    public SafeProcessHandle ObservationHandle { get; private set; }
    public uint ProcessId { get; private set; }
    public long ProcessStartFileTime { get; private set; }
    public long ProcessStartUtcTicks { get; private set; }
    public int Id { get { return checked((int)ProcessId); } }
    public bool HasExited {
        get {
            EnsureUsable();
            uint primary = WaitForExactHandle(ProcessHandle, 0, "primary process handle");
            uint duplicate =
                WaitForExactHandle(ObservationHandle, 0, "duplicated process handle");
            if (primary != duplicate) {
                throw new InvalidOperationException(
                    "exact native process handles disagree on signaled state " +
                    "(pid=" + ProcessId + "; primary_wait=" + primary +
                    "; duplicate_wait=" + duplicate + ")");
            }
            return primary == WAIT_OBJECT_0;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetProcessTimes(
        SafeProcessHandle process,
        out FILETIME creationTime,
        out FILETIME exitTime,
        out FILETIME kernelTime,
        out FILETIME userTime);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DuplicateHandle(
        IntPtr sourceProcess,
        SafeProcessHandle sourceHandle,
        IntPtr targetProcess,
        out SafeProcessHandle targetHandle,
        uint desiredAccess,
        bool inheritHandle,
        uint options);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    public AstroFsvCreatedProcess BindAndResume() {
        EnsureUsable();
        if (threadHandle == IntPtr.Zero)
            throw new InvalidOperationException("native child primary thread handle is unavailable");

        if (HasExited)
            throw new InvalidOperationException(
                "created-suspended native child exited before exact process resume (pid=" +
                ProcessId + ")");

        uint previousSuspendCount = ResumeThread(threadHandle);
        if (previousSuspendCount == UInt32.MaxValue) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "ResumeThread failed for created-suspended native child " +
                "(native_error=" + error + "; pid=" + ProcessId + ")");
        }
        ClosePrimaryThreadHandle();
        if (previousSuspendCount != 1) {
            throw new InvalidOperationException(
                "created-suspended native child had an unexpected primary-thread suspend count " +
                "(pid=" + ProcessId + "; previous_suspend_count=" +
                previousSuspendCount + "; expected=1)");
        }
        return this;
    }

    public void WaitForExit() {
        EnsureUsable();
        WaitForExactHandle(ProcessHandle, INFINITE, "primary process handle");
        uint duplicate =
            WaitForExactHandle(ObservationHandle, 0, "duplicated process handle");
        if (duplicate != WAIT_OBJECT_0) {
            throw new InvalidOperationException(
                "duplicated exact process handle was not signaled after the primary exact " +
                "process handle completed (pid=" + ProcessId +
                "; duplicate_wait=" + duplicate + ")");
        }
    }

    public bool WaitForExit(uint timeoutMilliseconds) {
        EnsureUsable();
        uint primary = WaitForExactHandle(
            ProcessHandle, timeoutMilliseconds, "primary process handle");
        if (primary == WAIT_TIMEOUT)
            return false;
        uint duplicate =
            WaitForExactHandle(ObservationHandle, 0, "duplicated process handle");
        if (duplicate != WAIT_OBJECT_0) {
            throw new InvalidOperationException(
                "duplicated exact process handle was not signaled after the primary exact " +
                "process handle completed (pid=" + ProcessId +
                "; duplicate_wait=" + duplicate + ")");
        }
        return true;
    }

    public void WriteInputLine(string line) {
        EnsureUsable();
        if (inputWriter == null)
            throw new InvalidOperationException("native child has no parent-owned stdin pipe");
        if (line == null || line.IndexOfAny(new char[] { '\r', '\n' }) >= 0)
            throw new ArgumentException("stdin protocol message must be one non-null line", "line");
        inputWriter.WriteLine(line);
        inputWriter.Flush();
    }

    public string ReadOutputLine(uint timeoutMilliseconds) {
        EnsureUsable();
        if (outputReader == null)
            throw new InvalidOperationException("native child has no parent-owned stdout pipe");
        Task<string> read = outputReader.ReadLineAsync();
        if (!read.Wait(checked((int)timeoutMilliseconds)))
            throw new TimeoutException(
                "timed out reading one native child stdout protocol line " +
                "(pid=" + ProcessId + "; timeout_ms=" + timeoutMilliseconds + ")");
        string line = read.Result;
        if (line == null)
            throw new EndOfStreamException(
                "native child stdout closed before a protocol line was read " +
                "(pid=" + ProcessId + ")");
        return line;
    }

    public void CloseInput() {
        if (inputWriter == null)
            return;
        inputWriter.Dispose();
        inputWriter = null;
    }

    public void BeginOutputDrain() {
        EnsureUsable();
        if (outputReader == null || errorReader == null)
            throw new InvalidOperationException("native child has no parent-owned output pipes");
        if (outputDrain != null)
            throw new InvalidOperationException("native child stdout drain is already active");
        outputDrain = outputReader.ReadToEndAsync();
        if (errorDrain == null)
            errorDrain = errorReader.ReadToEndAsync();
    }

    public void BeginErrorDrain() {
        EnsureUsable();
        if (errorReader == null)
            throw new InvalidOperationException("native child has no parent-owned stderr pipe");
        if (errorDrain != null)
            throw new InvalidOperationException("native child stderr drain is already active");
        errorDrain = errorReader.ReadToEndAsync();
    }

    public string GetOutputText(uint timeoutMilliseconds) {
        return GetDrainText(outputDrain, timeoutMilliseconds, "stdout");
    }

    public string GetErrorText(uint timeoutMilliseconds) {
        return GetDrainText(errorDrain, timeoutMilliseconds, "stderr");
    }

    string GetDrainText(Task<string> drain, uint timeoutMilliseconds, string streamName) {
        if (drain == null)
            throw new InvalidOperationException(
                "native child " + streamName + " drain was not started");
        if (!drain.Wait(checked((int)timeoutMilliseconds)))
            throw new TimeoutException(
                "timed out draining native child " + streamName +
                " (pid=" + ProcessId + "; timeout_ms=" + timeoutMilliseconds + ")");
        return drain.Result;
    }

    public void Refresh() {
        EnsureUsable();
    }

    public void TerminateAfterBindFailureAndWait(uint timeoutMilliseconds) {
        TerminateAndWait(BIND_FAILURE_EXIT_CODE, timeoutMilliseconds);
    }

    public void TerminateAfterCohortFailureAndWait(uint timeoutMilliseconds) {
        TerminateAndWait(COHORT_FAILURE_EXIT_CODE, timeoutMilliseconds);
    }

    void TerminateAndWait(uint exitCode, uint timeoutMilliseconds) {
        EnsureUsable();

        if (!TerminateProcess(ProcessHandle, exitCode)) {
            int terminateError = Marshal.GetLastWin32Error();
            uint observedCode;
            if (!GetExitCodeProcess(ProcessHandle, out observedCode)) {
                int observeError = Marshal.GetLastWin32Error();
                throw new Win32Exception(observeError,
                    "TerminateProcess and follow-up GetExitCodeProcess both failed for created native child " +
                    "(pid=" + ProcessId + "; terminate_native_error=" + terminateError +
                    "; observe_native_error=" + observeError + ")");
            }
            if (observedCode == STILL_ACTIVE) {
                throw new Win32Exception(terminateError,
                    "TerminateProcess failed and the exact created native child remains live " +
                    "(native_error=" + terminateError + "; pid=" + ProcessId + ")");
            }
        }

        uint primaryWait = WaitForExactHandle(
            ProcessHandle,
            timeoutMilliseconds,
            "primary process handle during termination");
        if (primaryWait == WAIT_TIMEOUT) {
            throw new TimeoutException(
                "timed out waiting for exact created native child termination " +
                "(pid=" + ProcessId + "; timeout_ms=" + timeoutMilliseconds + ")");
        }
        uint duplicateWait = WaitForExactHandle(
            ObservationHandle,
            0,
            "duplicated process handle after termination");
        if (duplicateWait != WAIT_OBJECT_0) {
            throw new InvalidOperationException(
                "duplicated exact process handle was not signaled after forced termination " +
                "(pid=" + ProcessId + "; duplicate_wait=" + duplicateWait + ")");
        }

        uint finalCode;
        if (!GetExitCodeProcess(ProcessHandle, out finalCode)) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "GetExitCodeProcess failed after exact created native child termination " +
                "(native_error=" + error + "; pid=" + ProcessId + ")");
        }
        if (finalCode == STILL_ACTIVE)
            throw new InvalidOperationException(
                "exact created native child still reports STILL_ACTIVE after termination wait " +
                "(pid=" + ProcessId + ")");
        uint duplicateCode;
        if (!GetExitCodeProcess(ObservationHandle, out duplicateCode)) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "GetExitCodeProcess failed for duplicated exact native child handle after " +
                "termination (native_error=" + error + "; pid=" + ProcessId + ")");
        }
        if (duplicateCode != finalCode) {
            throw new InvalidOperationException(
                "exact native process handles disagree on the forced termination code " +
                "(pid=" + ProcessId + "; primary_exit=" + finalCode +
                "; duplicate_exit=" + duplicateCode + ")");
        }
        ClosePrimaryThreadHandle();
    }

    static uint WaitForExactHandle(
        SafeProcessHandle handle,
        uint timeoutMilliseconds,
        string description) {
        if (handle == null || handle.IsInvalid || handle.IsClosed)
            throw new InvalidOperationException(
                description + " is invalid or closed");
        uint waitResult = WaitForSingleObject(handle, timeoutMilliseconds);
        if (waitResult == WAIT_TIMEOUT)
            return WAIT_TIMEOUT;
        if (waitResult == WAIT_FAILED) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "WaitForSingleObject failed for " + description +
                " (native_error=" + error + ")");
        }
        if (waitResult != WAIT_OBJECT_0) {
            throw new InvalidOperationException(
                "WaitForSingleObject returned an unexpected result for " +
                description + " (wait_result=" + waitResult + ")");
        }
        return waitResult;
    }

    void EnsureUsable() {
        if (disposed)
            throw new ObjectDisposedException("AstroFsvCreatedProcess");
        if (ProcessHandle == null || ProcessHandle.IsInvalid || ProcessHandle.IsClosed)
            throw new InvalidOperationException(
                "primary exact native process handle is invalid or closed " +
                "(pid=" + ProcessId + ")");
        if (ObservationHandle == null ||
            ObservationHandle.IsInvalid ||
            ObservationHandle.IsClosed)
            throw new InvalidOperationException(
                "duplicated exact native process handle is invalid or closed " +
                "(pid=" + ProcessId + ")");
    }

    void ClosePrimaryThreadHandle() {
        if (threadHandle == IntPtr.Zero)
            return;
        IntPtr owned = threadHandle;
        threadHandle = IntPtr.Zero;
        if (!CloseHandle(owned)) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "CloseHandle failed for created native child primary thread " +
                "(native_error=" + error + "; pid=" + ProcessId + ")");
        }
    }

    public void Dispose() {
        if (disposed)
            return;
        disposed = true;
        if (inputWriter != null) {
            inputWriter.Dispose();
            inputWriter = null;
        }
        if (outputReader != null) {
            outputReader.Dispose();
            outputReader = null;
        }
        if (errorReader != null) {
            errorReader.Dispose();
            errorReader = null;
        }
        if (threadHandle != IntPtr.Zero) {
            CloseHandle(threadHandle);
            threadHandle = IntPtr.Zero;
        }
        if (ObservationHandle != null)
            ObservationHandle.Dispose();
        if (ProcessHandle != null)
            ProcessHandle.Dispose();
    }
}

public static class AstroFsvNativeProcess {
    const uint GENERIC_READ = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint CREATE_NEW = 1;
    const uint OPEN_EXISTING = 3;
    const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    const uint STARTF_USESTDHANDLES = 0x00000100;
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const uint PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;
    const uint HANDLE_FLAG_INHERIT = 0x00000001;
    const int ERROR_INSUFFICIENT_BUFFER = 122;

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
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

    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFOEX {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        ref SECURITY_ATTRIBUTES security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool DeleteFileW(string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreatePipe(
        out SafeFileHandle readPipe,
        out SafeFileHandle writePipe,
        ref SECURITY_ATTRIBUTES pipeAttributes,
        uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetHandleInformation(
        SafeFileHandle handle, uint mask, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(
        IntPtr attributeList, int attributeCount, int flags, ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(
        IntPtr attributeList, uint flags, IntPtr attribute, IntPtr value,
        IntPtr size, IntPtr previousValue, IntPtr returnSize);

    [DllImport("kernel32.dll")]
    static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFOEX startupInfo,
        out PROCESS_INFORMATION processInformation);

    static string Extended(string path) {
        string full = System.IO.Path.GetFullPath(path);
        if (full.StartsWith(@"\\?\", StringComparison.Ordinal))
            return full;
        if (full.StartsWith(@"\\", StringComparison.Ordinal))
            return @"\\?\UNC\" + full.Substring(2);
        return @"\\?\" + full;
    }

    static SafeFileHandle OpenInherited(
        string path, uint access, uint creation, string operation) {
        SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES();
        security.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        security.lpSecurityDescriptor = IntPtr.Zero;
        security.bInheritHandle = 1;
        SafeFileHandle handle = CreateFileW(path, access, FILE_SHARE_READ,
            ref security, creation, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (handle.IsInvalid) {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error,
                operation + " failed (native_error=" + error + "; path=" + path + ")");
        }
        return handle;
    }

    static void CreateInheritablePipe(
        out SafeFileHandle readPipe,
        out SafeFileHandle writePipe,
        bool parentOwnsRead,
        string description) {
        SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES();
        security.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        security.lpSecurityDescriptor = IntPtr.Zero;
        security.bInheritHandle = 1;
        if (!CreatePipe(out readPipe, out writePipe, ref security, 0)) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error,
                "CreatePipe failed for " + description +
                " (native_error=" + error + ")");
        }
        SafeFileHandle parentEnd = parentOwnsRead ? readPipe : writePipe;
        if (!SetHandleInformation(parentEnd, HANDLE_FLAG_INHERIT, 0)) {
            int error = Marshal.GetLastWin32Error();
            readPipe.Dispose();
            writePipe.Dispose();
            throw new Win32Exception(error,
                "SetHandleInformation(non-inheritable parent pipe end) failed for " +
                description + " (native_error=" + error + ")");
        }
    }

    static string RemoveCreatedOutput(string path) {
        if (String.IsNullOrEmpty(path))
            return null;
        if (DeleteFileW(Extended(path)))
            return null;
        int error = Marshal.GetLastWin32Error();
        return "DeleteFileW pre-launch cleanup failed (native_error=" + error +
            "; path=" + path + ")";
    }

    public static AstroFsvCreatedProcess CreateSuspended(
        string applicationPath,
        string commandLine,
        string standardOutputPath,
        string standardErrorPath) {
        if (String.IsNullOrWhiteSpace(applicationPath))
            throw new ArgumentException("applicationPath is empty", "applicationPath");
        if (String.IsNullOrWhiteSpace(commandLine))
            throw new ArgumentException("commandLine is empty", "commandLine");
        if (commandLine.Length > 32766)
            throw new ArgumentOutOfRangeException("commandLine",
                "CreateProcessW command line exceeds 32,766 UTF-16 characters " +
                "(actual=" + commandLine.Length + ")");

        SafeFileHandle standardInput = null;
        SafeFileHandle standardOutput = null;
        SafeFileHandle standardError = null;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr handleList = IntPtr.Zero;
        bool outputCreated = false;
        bool errorCreated = false;
        bool processCreated = false;
        Exception failure = null;
        try {
            standardInput = OpenInherited("NUL", GENERIC_READ, OPEN_EXISTING,
                "CreateFileW inherited stdin=NUL");
            standardOutput = OpenInherited(Extended(standardOutputPath), GENERIC_WRITE,
                CREATE_NEW, "CreateFileW no-clobber inherited stdout");
            outputCreated = true;
            standardError = OpenInherited(Extended(standardErrorPath), GENERIC_WRITE,
                CREATE_NEW, "CreateFileW no-clobber inherited stderr");
            errorCreated = true;

            IntPtr attributeBytes = IntPtr.Zero;
            bool sizingResult = InitializeProcThreadAttributeList(
                IntPtr.Zero, 1, 0, ref attributeBytes);
            int sizingError = Marshal.GetLastWin32Error();
            if (sizingResult || sizingError != ERROR_INSUFFICIENT_BUFFER ||
                attributeBytes == IntPtr.Zero) {
                throw new Win32Exception(sizingError,
                    "InitializeProcThreadAttributeList sizing failed " +
                    "(native_error=" + sizingError + "; requested_attributes=1)");
            }
            attributeList = Marshal.AllocHGlobal(attributeBytes);
            if (!InitializeProcThreadAttributeList(
                attributeList, 1, 0, ref attributeBytes)) {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error,
                    "InitializeProcThreadAttributeList allocation failed " +
                    "(native_error=" + error + "; requested_attributes=1)");
            }

            handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handleList, 0, standardInput.DangerousGetHandle());
            Marshal.WriteIntPtr(handleList, IntPtr.Size,
                standardOutput.DangerousGetHandle());
            Marshal.WriteIntPtr(handleList, IntPtr.Size * 2,
                standardError.DangerousGetHandle());
            if (!UpdateProcThreadAttribute(
                attributeList, 0,
                new IntPtr(PROC_THREAD_ATTRIBUTE_HANDLE_LIST),
                handleList, new IntPtr(IntPtr.Size * 3),
                IntPtr.Zero, IntPtr.Zero)) {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error,
                    "UpdateProcThreadAttribute restricted handle list failed " +
                    "(native_error=" + error + "; inherited_handle_count=3)");
            }

            STARTUPINFOEX startup = new STARTUPINFOEX();
            startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            startup.StartupInfo.dwFlags = unchecked((int)STARTF_USESTDHANDLES);
            startup.StartupInfo.hStdInput = standardInput.DangerousGetHandle();
            startup.StartupInfo.hStdOutput = standardOutput.DangerousGetHandle();
            startup.StartupInfo.hStdError = standardError.DangerousGetHandle();
            startup.lpAttributeList = attributeList;

            StringBuilder mutableCommandLine =
                new StringBuilder(commandLine, commandLine.Length + 1);
            PROCESS_INFORMATION processInformation;
            uint creationFlags =
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
            if (!CreateProcessW(
                Extended(applicationPath),
                mutableCommandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                creationFlags,
                IntPtr.Zero,
                null,
                ref startup,
                out processInformation)) {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error,
                    "CreateProcessW exact extended application launch failed " +
                    "(native_error=" + error +
                    "; application=" + applicationPath +
                    "; application_extended=" + Extended(applicationPath) +
                    "; command_line_utf16_characters=" + commandLine.Length +
                    "; stdout=" + standardOutputPath +
                    "; stderr=" + standardErrorPath +
                    "; creation_flags=" + creationFlags + ")");
            }

            AstroFsvCreatedProcess created = new AstroFsvCreatedProcess(
                processInformation.hProcess,
                processInformation.hThread,
                processInformation.dwProcessId);
            processCreated = true;
            return created;
        }
        catch (Exception ex) {
            failure = ex;
            throw;
        }
        finally {
            if (attributeList != IntPtr.Zero) {
                DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }
            if (handleList != IntPtr.Zero)
                Marshal.FreeHGlobal(handleList);
            if (standardError != null)
                standardError.Dispose();
            if (standardOutput != null)
                standardOutput.Dispose();
            if (standardInput != null)
                standardInput.Dispose();

            if (!processCreated) {
                string errorCleanup = errorCreated
                    ? RemoveCreatedOutput(standardErrorPath)
                    : null;
                string outputCleanup = outputCreated
                    ? RemoveCreatedOutput(standardOutputPath)
                    : null;
                if (failure != null &&
                    (!String.IsNullOrEmpty(errorCleanup) ||
                     !String.IsNullOrEmpty(outputCleanup))) {
                    throw new InvalidOperationException(
                        failure.Message + "; pre-launch cleanup: " +
                        (errorCleanup ?? "stderr=absent") + "; " +
                        (outputCleanup ?? "stdout=absent"), failure);
                }
            }
        }
    }

    public static AstroFsvCreatedProcess CreateSuspendedPiped(
        string applicationPath,
        string commandLine) {
        if (String.IsNullOrWhiteSpace(applicationPath))
            throw new ArgumentException("applicationPath is empty", "applicationPath");
        if (String.IsNullOrWhiteSpace(commandLine))
            throw new ArgumentException("commandLine is empty", "commandLine");
        if (commandLine.Length > 32766)
            throw new ArgumentOutOfRangeException("commandLine",
                "CreateProcessW command line exceeds 32,766 UTF-16 characters " +
                "(actual=" + commandLine.Length + ")");

        SafeFileHandle childInputRead = null;
        SafeFileHandle parentInputWrite = null;
        SafeFileHandle parentOutputRead = null;
        SafeFileHandle childOutputWrite = null;
        SafeFileHandle parentErrorRead = null;
        SafeFileHandle childErrorWrite = null;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr handleList = IntPtr.Zero;
        try {
            CreateInheritablePipe(
                out childInputRead, out parentInputWrite, false, "child stdin");
            CreateInheritablePipe(
                out parentOutputRead, out childOutputWrite, true, "child stdout");
            CreateInheritablePipe(
                out parentErrorRead, out childErrorWrite, true, "child stderr");

            IntPtr attributeBytes = IntPtr.Zero;
            bool sizingResult = InitializeProcThreadAttributeList(
                IntPtr.Zero, 1, 0, ref attributeBytes);
            int sizingError = Marshal.GetLastWin32Error();
            if (sizingResult || sizingError != ERROR_INSUFFICIENT_BUFFER ||
                attributeBytes == IntPtr.Zero) {
                throw new Win32Exception(sizingError,
                    "InitializeProcThreadAttributeList sizing failed " +
                    "(native_error=" + sizingError + "; requested_attributes=1)");
            }
            attributeList = Marshal.AllocHGlobal(attributeBytes);
            if (!InitializeProcThreadAttributeList(
                attributeList, 1, 0, ref attributeBytes)) {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error,
                    "InitializeProcThreadAttributeList allocation failed " +
                    "(native_error=" + error + "; requested_attributes=1)");
            }

            handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handleList, 0, childInputRead.DangerousGetHandle());
            Marshal.WriteIntPtr(
                handleList, IntPtr.Size, childOutputWrite.DangerousGetHandle());
            Marshal.WriteIntPtr(
                handleList, IntPtr.Size * 2, childErrorWrite.DangerousGetHandle());
            if (!UpdateProcThreadAttribute(
                attributeList, 0,
                new IntPtr(PROC_THREAD_ATTRIBUTE_HANDLE_LIST),
                handleList, new IntPtr(IntPtr.Size * 3),
                IntPtr.Zero, IntPtr.Zero)) {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error,
                    "UpdateProcThreadAttribute restricted pipe handle list failed " +
                    "(native_error=" + error + "; inherited_handle_count=3)");
            }

            STARTUPINFOEX startup = new STARTUPINFOEX();
            startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            startup.StartupInfo.dwFlags = unchecked((int)STARTF_USESTDHANDLES);
            startup.StartupInfo.hStdInput = childInputRead.DangerousGetHandle();
            startup.StartupInfo.hStdOutput = childOutputWrite.DangerousGetHandle();
            startup.StartupInfo.hStdError = childErrorWrite.DangerousGetHandle();
            startup.lpAttributeList = attributeList;

            StringBuilder mutableCommandLine =
                new StringBuilder(commandLine, commandLine.Length + 1);
            PROCESS_INFORMATION processInformation;
            uint creationFlags =
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
            if (!CreateProcessW(
                Extended(applicationPath),
                mutableCommandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                creationFlags,
                IntPtr.Zero,
                null,
                ref startup,
                out processInformation)) {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error,
                    "CreateProcessW exact piped extended application launch failed " +
                    "(native_error=" + error +
                    "; application=" + applicationPath +
                    "; application_extended=" + Extended(applicationPath) +
                    "; command_line_utf16_characters=" + commandLine.Length +
                    "; creation_flags=" + creationFlags + ")");
            }

            childInputRead.Dispose();
            childInputRead = null;
            childOutputWrite.Dispose();
            childOutputWrite = null;
            childErrorWrite.Dispose();
            childErrorWrite = null;

            AstroFsvCreatedProcess created = new AstroFsvCreatedProcess(
                processInformation.hProcess,
                processInformation.hThread,
                processInformation.dwProcessId,
                parentInputWrite,
                parentOutputRead,
                parentErrorRead);
            parentInputWrite = null;
            parentOutputRead = null;
            parentErrorRead = null;
            return created;
        }
        finally {
            if (attributeList != IntPtr.Zero) {
                DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }
            if (handleList != IntPtr.Zero)
                Marshal.FreeHGlobal(handleList);
            if (childInputRead != null) childInputRead.Dispose();
            if (parentInputWrite != null) parentInputWrite.Dispose();
            if (parentOutputRead != null) parentOutputRead.Dispose();
            if (childOutputWrite != null) childOutputWrite.Dispose();
            if (parentErrorRead != null) parentErrorRead.Dispose();
            if (childErrorWrite != null) childErrorWrite.Dispose();
        }
    }
}
'@
}

if (-not ([Management.Automation.PSTypeName]'AstroFsvRestartManager').Type) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

public sealed class AstroFsvRestartManagerOwner {
    public uint ProcessId { get; internal set; }
    public long ProcessStartFileTime { get; internal set; }
    public long ProcessStartUtcTicks { get; internal set; }
    public string ApplicationName { get; internal set; }
    public string ServiceShortName { get; internal set; }
    public int ApplicationType { get; internal set; }
    public uint ApplicationStatus { get; internal set; }
    public uint TerminalSessionId { get; internal set; }
    public bool Restartable { get; internal set; }
}

public sealed class AstroFsvRestartManagerResult {
    public AstroFsvRestartManagerOwner[] Owners { get; internal set; }
    public uint RebootReasons { get; internal set; }
    public int ListQueryAttempts { get; internal set; }
}

public static class AstroFsvRestartManager {
    const int CCH_RM_SESSION_KEY = 32;
    const int CCH_RM_MAX_APP_NAME = 255;
    const int CCH_RM_MAX_SVC_NAME = 63;
    const int ERROR_SUCCESS = 0;
    const int ERROR_MORE_DATA = 234;

    [StructLayout(LayoutKind.Sequential)]
    struct RM_UNIQUE_PROCESS {
        public uint ProcessId;
        public FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct RM_PROCESS_INFO {
        public RM_UNIQUE_PROCESS Process;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
        public string ApplicationName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
        public string ServiceShortName;

        public int ApplicationType;
        public uint ApplicationStatus;
        public uint TerminalSessionId;
        public int Restartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmStartSession(
        out uint sessionHandle,
        int sessionFlags,
        StringBuilder sessionKey);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmRegisterResources(
        uint sessionHandle,
        uint fileCount,
        string[] fileNames,
        uint applicationCount,
        RM_UNIQUE_PROCESS[] applications,
        uint serviceCount,
        string[] serviceNames);

    [DllImport("rstrtmgr.dll")]
    static extern int RmGetList(
        uint sessionHandle,
        out uint processInfoNeeded,
        ref uint processInfoCount,
        [In, Out] RM_PROCESS_INFO[] processInfo,
        ref uint rebootReasons);

    [DllImport("rstrtmgr.dll")]
    static extern int RmEndSession(uint sessionHandle);

    static long ToFileTime(FILETIME value) {
        return ((long)(uint)value.dwHighDateTime << 32) |
            (uint)value.dwLowDateTime;
    }

    static Win32Exception Failure(string operation, int error, string path) {
        return new Win32Exception(
            error,
            operation + " failed while identifying exact artifact users " +
            "(native_error=" + error + "; path=" + path + ")");
    }

    public static AstroFsvRestartManagerResult GetOwners(string path) {
        if (String.IsNullOrWhiteSpace(path))
            throw new ArgumentException("artifact path is empty", "path");

        string fullPath = System.IO.Path.GetFullPath(path);
        StringBuilder sessionKey = new StringBuilder(CCH_RM_SESSION_KEY + 1);
        uint sessionHandle;
        int result = RmStartSession(out sessionHandle, 0, sessionKey);
        if (result != ERROR_SUCCESS)
            throw Failure("RmStartSession", result, fullPath);

        Exception failure = null;
        try {
            result = RmRegisterResources(
                sessionHandle,
                1,
                new string[] { fullPath },
                0,
                null,
                0,
                null);
            if (result != ERROR_SUCCESS)
                throw Failure("RmRegisterResources", result, fullPath);

            RM_PROCESS_INFO[] processInfo = null;
            for (int attempt = 1; attempt <= 5; attempt++) {
                uint needed;
                uint count = processInfo == null
                    ? 0
                    : (uint)processInfo.Length;
                uint rebootReasons = 0;
                result = RmGetList(
                    sessionHandle,
                    out needed,
                    ref count,
                    processInfo,
                    ref rebootReasons);
                if (result == ERROR_SUCCESS) {
                    List<AstroFsvRestartManagerOwner> owners =
                        new List<AstroFsvRestartManagerOwner>();
                    for (int index = 0; index < count; index++) {
                        long fileTime = ToFileTime(
                            processInfo[index].Process.ProcessStartTime);
                        owners.Add(new AstroFsvRestartManagerOwner {
                            ProcessId =
                                processInfo[index].Process.ProcessId,
                            ProcessStartFileTime = fileTime,
                            ProcessStartUtcTicks =
                                DateTime.FromFileTimeUtc(fileTime).Ticks,
                            ApplicationName =
                                processInfo[index].ApplicationName,
                            ServiceShortName =
                                processInfo[index].ServiceShortName,
                            ApplicationType =
                                processInfo[index].ApplicationType,
                            ApplicationStatus =
                                processInfo[index].ApplicationStatus,
                            TerminalSessionId =
                                processInfo[index].TerminalSessionId,
                            Restartable =
                                processInfo[index].Restartable != 0
                        });
                    }
                    return new AstroFsvRestartManagerResult {
                        Owners = owners.ToArray(),
                        RebootReasons = rebootReasons,
                        ListQueryAttempts = attempt
                    };
                }
                if (result != ERROR_MORE_DATA)
                    throw Failure("RmGetList", result, fullPath);
                if (needed == 0)
                    throw new InvalidOperationException(
                        "RmGetList returned ERROR_MORE_DATA with zero required " +
                        "owners (attempt=" + attempt + "; path=" + fullPath + ")");
                processInfo = new RM_PROCESS_INFO[needed];
            }
            throw new InvalidOperationException(
                "RmGetList owner cardinality changed across five bounded " +
                "buffer reads (path=" + fullPath + ")");
        }
        catch (Exception caught) {
            failure = caught;
            throw;
        }
        finally {
            int endResult = RmEndSession(sessionHandle);
            if (endResult != ERROR_SUCCESS && failure == null)
                throw Failure("RmEndSession", endResult, fullPath);
        }
    }
}
'@
}

function Get-AstroNativeErrorCode([Exception]$Exception) {
    $current = $Exception
    $depth = 0
    while ($null -ne $current -and $depth -lt 16) {
        if ($current -is [ComponentModel.Win32Exception]) {
            return [int]$current.NativeErrorCode
        }
        $current = $current.InnerException
        $depth++
    }
    return $null
}

function Get-AstroArtifactOwnerDiagnostic([string]$ArtifactPath) {
    try {
        $restartManager =
            [AstroFsvRestartManager]::GetOwners($ArtifactPath)
        return [ordered]@{
            state = 'observed'
            operation =
                'Restart Manager RmRegisterResources(exact file) + RmGetList'
            list_query_attempts =
                [int]$restartManager.ListQueryAttempts
            owners = @($restartManager.Owners | ForEach-Object {
                [ordered]@{
                    pid = [uint32]$_.ProcessId
                    process_start_filetime =
                        [int64]$_.ProcessStartFileTime
                    process_start_utc_ticks =
                        [int64]$_.ProcessStartUtcTicks
                    application_name = [string]$_.ApplicationName
                    service_short_name = [string]$_.ServiceShortName
                    application_type = [int]$_.ApplicationType
                    application_status =
                        [uint32]$_.ApplicationStatus
                    terminal_session_id =
                        [uint32]$_.TerminalSessionId
                    restartable = [bool]$_.Restartable
                }
            })
            reboot_reasons = [uint32]$restartManager.RebootReasons
        }
    }
    catch {
        return [ordered]@{
            state = 'fault'
            operation =
                'Restart Manager RmRegisterResources(exact file) + RmGetList'
            error = $_.Exception.Message
        }
    }
}

function Test-DescendantOf([int]$CandidatePid, [int]$AncestorPid) {
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

function ConvertTo-WindowsCommandLineArgument([string]$Argument) {
    if ($Argument.Length -gt 0 -and $Argument -notmatch '[\s"]') { return $Argument }
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) { [void]$builder.Append(('\' * ($backslashes * 2))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertFrom-FlatStringArrayJson([string]$Json) {
    if ([string]::IsNullOrWhiteSpace($Json)) {
        Fail-Astro 'ASTRO_FSV_ARGUMENTS_INVALID' 'ArgumentsJson is empty' 'pass a JSON array containing only strings; use [] for zero arguments'
    }

    # ConvertFrom-Json normally enumerates a top-level JSON array, collapsing []
    # to $null and a single item to a scalar. Parse through an object envelope so
    # the array identity and cardinality survive on Windows PowerShell 5.1 and
    # PowerShell 7. Random property names make injected sibling properties
    # observable rather than allowing trailing JSON to escape the array contract.
    $argumentProperty = "arguments_$([Guid]::NewGuid().ToString('N'))"
    $sentinelProperty = "sentinel_$([Guid]::NewGuid().ToString('N'))"
    $envelopeJson = '{"' + $argumentProperty + '":' + $Json + ',"' + $sentinelProperty + '":true}'
    try { $envelope = ConvertFrom-Json -InputObject $envelopeJson }
    catch {
        Fail-Astro 'ASTRO_FSV_ARGUMENTS_INVALID' "ArgumentsJson is invalid: $($_.Exception.Message)" 'pass a flat JSON array containing only strings'
    }

    $properties = @($envelope.PSObject.Properties)
    $argumentEntry = $envelope.PSObject.Properties[$argumentProperty]
    $sentinelEntry = $envelope.PSObject.Properties[$sentinelProperty]
    if ($properties.Count -ne 2 -or $null -eq $argumentEntry -or $null -eq $sentinelEntry -or
        $sentinelEntry.Value -isnot [bool] -or -not [bool]$sentinelEntry.Value) {
        Fail-Astro 'ASTRO_FSV_ARGUMENTS_INVALID' 'ArgumentsJson contains data outside its top-level value' 'pass exactly one flat JSON array containing only strings'
    }

    $rawArguments = $argumentEntry.Value
    if ($rawArguments -isnot [Array]) {
        Fail-Astro 'ASTRO_FSV_ARGUMENTS_INVALID' 'ArgumentsJson top-level value is not an array' 'pass a flat JSON array containing only strings; use [] for zero arguments'
    }
    $values = [string[]]::new($rawArguments.Count)
    for ($index = 0; $index -lt $rawArguments.Count; $index++) {
        if ($rawArguments[$index] -isnot [string]) {
            Fail-Astro 'ASTRO_FSV_ARGUMENTS_INVALID' "ArgumentsJson item $index is not a string" 'pass a flat JSON array containing only strings'
        }
        $values[$index] = [string]$rawArguments[$index]
    }
    return [pscustomobject]@{
        Count = [int]$values.Length
        Values = $values
    }
}

function Open-AstroFsvArgumentJsonFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Workspace
    )

    $full = Assert-PathWithin $Path $Workspace `
        'ASTRO_FSV_ARGUMENTS_FILE_ESCAPE' 'arguments JSON file'
    if (-not (Test-AstroPathLongPath -LiteralPath $full -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_ARGUMENTS_FILE_MISSING' `
            "arguments JSON file does not exist: $full" `
            'write one ordinary strict UTF-8 JSON file inside the canonical workspace'
    }
    $workspaceFull = [IO.Path]::GetFullPath($Workspace).TrimEnd('\', '/')
    $ancestor = Split-Path -Parent $full
    while ($ancestor.Length -ge $workspaceFull.Length) {
        Assert-NotReparseEntry $ancestor 'arguments JSON ancestor'
        if ([string]::Equals(
                [IO.Path]::GetFullPath($ancestor),
                $workspaceFull,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            break
        }
        $parent = Split-Path -Parent $ancestor
        if ([string]::Equals($parent, $ancestor, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-Astro 'ASTRO_FSV_ARGUMENTS_FILE_ESCAPE' `
                "arguments JSON ancestor walk escaped the canonical workspace: $full" `
                'use an ordinary file inside the canonical workspace'
        }
        $ancestor = $parent
    }
    Assert-NotReparseEntry $full 'arguments JSON file'

    try {
        $stream = [AstroLauncherLockNative]::OpenExactProtectedReadFile(
            $full
        )
    }
    catch {
        Fail-Astro 'ASTRO_FSV_ARGUMENTS_FILE_OPEN_FAILED' `
            "arguments JSON file could not be retained without write/delete sharing: $full ($($_.Exception.Message))" `
            'close every writer/deleter and provide one immutable ordinary workspace file'
    }
    try {
        $retainedLength = Get-AstroFileLengthLongPath $full
        if ($retainedLength -le 0 -or $retainedLength -gt 1048576) {
            Fail-Astro 'ASTRO_FSV_ARGUMENTS_FILE_LENGTH_INVALID' `
                "arguments JSON file length is invalid: $retainedLength bytes ($full)" `
                'use one nonempty strict UTF-8 JSON array no larger than 1 MiB'
        }
        try {
            $bytes = [AstroLauncherLockNative]::ReadAllBytes(
                $stream,
                1048576
            )
        }
        catch {
            Fail-Astro 'ASTRO_FSV_ARGUMENTS_FILE_READ_FAILED' `
                "arguments JSON exact retained read failed: $full ($($_.Exception.Message))" `
                'preserve the file and investigate filesystem identity or read instability'
        }
        if ($bytes.Length -ne $retainedLength) {
            Fail-Astro 'ASTRO_FSV_ARGUMENTS_FILE_READ_FAILED' `
                "arguments JSON exact retained read returned $($bytes.Length) bytes after a $retainedLength-byte observation: $full" `
                'preserve the file and investigate filesystem identity or size drift'
        }
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and
            $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            Fail-Astro 'ASTRO_FSV_ARGUMENTS_FILE_BOM_REFUSED' `
                "arguments JSON file has a UTF-8 BOM: $full" `
                'write canonical strict UTF-8 JSON without a BOM'
        }
        try { $json = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) }
        catch {
            Fail-Astro 'ASTRO_FSV_ARGUMENTS_FILE_UTF8_INVALID' `
                "arguments JSON file is not strict UTF-8: $full ($($_.Exception.Message))" `
                'write canonical strict UTF-8 JSON without replacement characters'
        }
        return [pscustomobject]@{
            Handle = $stream
            Path = $full
            Bytes = [uint64]$bytes.Length
            Sha256 = ByteArray-Sha256 $bytes
            Json = $json
        }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Get-AstroRetainedFileSha256 {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle
    )
    return [AstroLauncherLockNative]::ComputeExactFileSha256($Handle)
}

function Assert-AstroExactObjectProperties {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string[]]$Names,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )
    if ($null -eq $Object -or
        ($Object -isnot [Collections.IDictionary] -and
         $Object -isnot [psobject])) {
        Fail-Astro $Code "$Description is absent or is not an object" `
            'preserve the plan/session and correct the exact structured envelope'
    }
    $actual = @(Get-AstroStructuredObjectFieldNames $Object)
    if ($actual.Count -ne $Names.Count -or
        @($Names | Where-Object { $actual -cnotcontains $_ }).Count -ne 0) {
        Fail-Astro $Code `
            "$Description must contain exactly [$($Names -join ', ')]; observed [$($actual -join ', ')]" `
            'preserve the plan/session and correct the exact structured envelope'
    }
}

function ConvertFrom-AstroStrictUtf8File {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )
    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt 1048576) {
            Fail-Astro $Code "$Description length is invalid: $($stream.Length) bytes" `
                'use one nonempty strict UTF-8 JSON plan no larger than 1 MiB'
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                Fail-Astro $Code "$Description ended before its retained length was read" `
                    'preserve the plan and investigate concurrent byte mutation'
            }
            $offset += $read
        }
    }
    finally { $stream.Dispose() }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and
        $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Fail-Astro $Code "$Description has a UTF-8 BOM" `
            'write canonical strict UTF-8 JSON without a BOM'
    }
    try { return [Text.UTF8Encoding]::new($false, $true).GetString($bytes) }
    catch {
        Fail-Astro $Code "$Description is not strict UTF-8: $($_.Exception.Message)" `
            'write canonical strict UTF-8 JSON without replacement characters'
    }
}

function ConvertFrom-AstroCohortStringArray {
    param(
        $Value,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )
    if ($Value -isnot [Array]) {
        Fail-Astro $Code "$Description is not an array" 'use a JSON array containing only strings'
    }
    $result = [string[]]::new($Value.Count)
    for ($index = 0; $index -lt $Value.Count; $index++) {
        if ($Value[$index] -isnot [string]) {
            Fail-Astro $Code "$Description item $index is not a string" `
                'use a JSON array containing only strings'
        }
        $result[$index] = [string]$Value[$index]
    }
    return ,$result
}

function Read-AstroResidentCohortPlan {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Workspace,
        [Parameter(Mandatory)][int]$ExpectedIssue
    )
    $manualRoot = Join-Path $Workspace '.tmp\manual-fsv'
    $full = Assert-PathWithin $Path $manualRoot `
        'ASTRO_FSV_COHORT_PLAN_ESCAPE' 'resident-cohort plan'
    if (-not (Test-AstroPathLongPath -LiteralPath $full -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_COHORT_PLAN_MISSING' `
            "resident-cohort plan is absent: $full" `
            'publish the issue-scoped plan below .tmp\manual-fsv before entering the launcher'
    }
    Assert-NotReparseEntry $full 'resident-cohort plan'
    $shaBefore = File-Sha256 $full
    $json = ConvertFrom-AstroStrictUtf8File $full `
        'ASTRO_FSV_COHORT_PLAN_INVALID' 'resident-cohort plan'
    try { $plan = ConvertFrom-Json -InputObject $json }
    catch {
        Fail-Astro 'ASTRO_FSV_COHORT_PLAN_INVALID' `
            "resident-cohort plan JSON is invalid: $($_.Exception.Message)" `
            'publish one exact issue-scoped cohort plan object'
    }
    $basePlanProperties = @(
        'schema', 'issue', 'resident_count', 'cache_directory', 'store_paths',
        'prime_request', 'prime_expected_substring', 'indexer_arguments',
        'indexer_expected_substring', 'reopen_request',
        'reopen_expected_substring', 'response_timeout_ms', 'holder_timeout_ms',
        'indexer_timeout_ms', 'resident_exit_timeout_ms'
    )
    $schema = [string]$plan.schema
    $planProperties = if ($schema -ceq 'astrolabe.native-fsv-resident-cohort-plan.v1') {
        $basePlanProperties
    }
    elseif ($schema -ceq 'astrolabe.native-fsv-resident-cohort-plan.v2') {
        @($basePlanProperties) + 'phase_store_owner_contract'
    }
    elseif ($schema -ceq 'astrolabe.native-fsv-resident-cohort-plan.v3') {
        @($basePlanProperties) + @(
            'phase_store_owner_contract', 'auxiliary_state_contract'
        )
    }
    else {
        Fail-Astro 'ASTRO_FSV_COHORT_PLAN_INVALID' `
            "resident-cohort plan schema '$schema' is not supported" `
            'publish an exact v1 retained-SQLite, v2 explicit phase-owner, or v3 explicit auxiliary-state plan'
    }
    Assert-AstroExactObjectProperties $plan $planProperties `
        'ASTRO_FSV_COHORT_PLAN_INVALID' 'resident-cohort plan'
    if ([int]$plan.issue -ne $ExpectedIssue) {
        Fail-Astro 'ASTRO_FSV_COHORT_PLAN_INVALID' `
            "resident-cohort plan schema/issue does not match issue #$ExpectedIssue" `
            'publish a fresh plan bound to the driving issue'
    }
    $phaseStoreOwnerContract = if ($schema -ceq 'astrolabe.native-fsv-resident-cohort-plan.v1') {
        [ordered]@{ prime = 'residents'; reopen = 'residents' }
    }
    else {
        Assert-AstroExactObjectProperties $plan.phase_store_owner_contract `
            @('prime', 'reopen') 'ASTRO_FSV_COHORT_PLAN_INVALID' `
            'phase_store_owner_contract'
        $contract = [ordered]@{}
        foreach ($phase in @('prime', 'reopen')) {
            $value = [string]$plan.phase_store_owner_contract.$phase
            if ($value -cne 'residents' -and $value -cne 'absent') {
                Fail-Astro 'ASTRO_FSV_COHORT_PLAN_INVALID' `
                    "phase_store_owner_contract.$phase must be exactly 'residents' or 'absent', observed '$value'" `
                    'declare the exact expected Restart Manager owner set for every resident phase'
            }
            $contract[$phase] = $value
        }
        $contract
    }
    $auxiliaryStateContract = if ($schema -ceq 'astrolabe.native-fsv-resident-cohort-plan.v3') {
        $value = [string]$plan.auxiliary_state_contract
        if ($value -cne 'absent' -and $value -cne 'read_only_tail') {
            Fail-Astro 'ASTRO_FSV_COHORT_PLAN_INVALID' `
                "auxiliary_state_contract must be exactly 'absent' or 'read_only_tail', observed '$value'" `
                'declare whether the SQLite lifecycle requires namespace absence or admits only a zero-owner, empty-WAL read-only tail'
        }
        $value
    }
    else { 'absent' }
    $residentCount = [int]$plan.resident_count
    if ($residentCount -lt 2 -or $residentCount -gt 16 -or
        [string]$residentCount -cne [string]$plan.resident_count) {
        Fail-Astro 'ASTRO_FSV_COHORT_PLAN_INVALID' `
            'resident_count must be an exact integer from 2 through 16' `
            'use the smallest cohort that reproduces the real concurrency boundary'
    }
    $cacheDirectory = Assert-PathWithin ([string]$plan.cache_directory) $manualRoot `
        'ASTRO_FSV_COHORT_CACHE_ESCAPE' 'resident-cohort cache directory'
    if (-not (Test-AstroPathLongPath -LiteralPath $cacheDirectory -PathType Container)) {
        Fail-Astro 'ASTRO_FSV_COHORT_CACHE_MISSING' `
            "resident-cohort cache directory is absent: $cacheDirectory" `
            'seed the real store before starting the cohort'
    }
    Assert-NotReparseEntry $cacheDirectory 'resident-cohort cache directory'
    $ambientCache = [Environment]::GetEnvironmentVariable('CBM_CACHE_DIR', 'Process')
    if ([string]::IsNullOrWhiteSpace($ambientCache) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath($ambientCache), $cacheDirectory,
            [StringComparison]::OrdinalIgnoreCase)) {
        Fail-Astro 'ASTRO_FSV_COHORT_CACHE_ENV_MISMATCH' `
            "process CBM_CACHE_DIR does not exactly name plan cache '$cacheDirectory'" `
            'set CBM_CACHE_DIR for the full launcher batch to the issue-scoped real store root'
    }
    $storePaths = ConvertFrom-AstroCohortStringArray $plan.store_paths `
        'ASTRO_FSV_COHORT_PLAN_INVALID' 'store_paths'
    if ($storePaths.Count -ne 3) {
        Fail-Astro 'ASTRO_FSV_COHORT_PLAN_INVALID' `
            'store_paths must name exactly the SQLite db, db-wal, and db-shm family' `
            'publish the exact three paths derived from the seeded real store'
    }
    for ($index = 0; $index -lt $storePaths.Count; $index++) {
        $storePaths[$index] = Assert-PathWithin $storePaths[$index] $cacheDirectory `
            'ASTRO_FSV_COHORT_STORE_ESCAPE' "store_paths[$index]"
    }
    if (-not $storePaths[0].EndsWith('.db', [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($storePaths[1], $storePaths[0] + '-wal', [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($storePaths[2], $storePaths[0] + '-shm', [StringComparison]::OrdinalIgnoreCase)) {
        Fail-Astro 'ASTRO_FSV_COHORT_PLAN_INVALID' `
            'store_paths is not one exact SQLite db/db-wal/db-shm family' `
            'publish the seeded database path followed by its literal -wal and -shm paths'
    }
    if (-not (Test-AstroPathLongPath -LiteralPath $storePaths[0] -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_COHORT_STORE_MISSING' `
            "seeded SQLite database is absent: $($storePaths[0])" `
            'complete the real seed invocation before starting resident processes'
    }
    foreach ($sidecar in $storePaths[1..2]) {
        if (Test-AstroPathLongPath -LiteralPath $sidecar) {
            Fail-Astro 'ASTRO_FSV_COHORT_INITIAL_SIDECAR_PRESENT' `
                "SQLite sidecar is already present before cohort admission: $sidecar" `
                'close every prior store owner and use a clean seeded store generation'
        }
    }
    foreach ($requestName in @('prime_request', 'reopen_request')) {
        $request = $plan.$requestName
        Assert-AstroExactObjectProperties $request @('jsonrpc', 'id', 'method', 'params') `
            'ASTRO_FSV_COHORT_PLAN_INVALID' $requestName
        if ([string]$request.jsonrpc -cne '2.0' -or
            [string]$request.method -cne 'tools/call' -or $null -eq $request.id) {
            Fail-Astro 'ASTRO_FSV_COHORT_PLAN_INVALID' `
                "$requestName must be one tools/call JSON-RPC 2.0 request with a non-null id" `
                'publish the exact real resident request envelope'
        }
    }
    foreach ($name in @(
        'prime_expected_substring', 'indexer_expected_substring',
        'reopen_expected_substring'
    )) {
        if ($plan.$name -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$plan.$name)) {
            Fail-Astro 'ASTRO_FSV_COHORT_PLAN_INVALID' "$name must be a nonempty string" `
                'bind each phase to a real response marker'
        }
    }
    $indexerArguments = ConvertFrom-AstroCohortStringArray $plan.indexer_arguments `
        'ASTRO_FSV_COHORT_PLAN_INVALID' 'indexer_arguments'
    if ($indexerArguments.Count -lt 5 -or $indexerArguments[0] -cne 'cli' -or
        $indexerArguments -cnotcontains '--json' -or
        $indexerArguments -cnotcontains 'index_repository' -or
        $indexerArguments -cnotcontains '--args-file') {
        Fail-Astro 'ASTRO_FSV_COHORT_PLAN_INVALID' `
            'indexer_arguments must be the real cli --json index_repository --args-file invocation' `
            'bind the cohort writer to an existing issue-scoped real arguments file'
    }
    $timeouts = [ordered]@{}
    foreach ($name in @(
        'response_timeout_ms', 'holder_timeout_ms', 'indexer_timeout_ms',
        'resident_exit_timeout_ms'
    )) {
        $parsed = 0
        if (-not [int]::TryParse(
                [string]$plan.$name,
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$parsed
            ) -or $parsed -lt 1000 -or $parsed -gt 3600000 -or
            [string]$parsed -cne [string]$plan.$name) {
            Fail-Astro 'ASTRO_FSV_COHORT_PLAN_INVALID' `
                "$name must be an exact integer from 1000 through 3600000" `
                'publish bounded positive cohort time budgets in milliseconds'
        }
        $timeouts[$name] = $parsed
    }
    return [ordered]@{
        path = $full
        sha256_before = $shaBefore
        resident_count = $residentCount
        cache_directory = $cacheDirectory
        store_paths = [string[]]$storePaths
        prime_request = $plan.prime_request
        prime_expected_substring = [string]$plan.prime_expected_substring
        reopen_request = $plan.reopen_request
        reopen_expected_substring = [string]$plan.reopen_expected_substring
        indexer_arguments = [string[]]$indexerArguments
        indexer_expected_substring = [string]$plan.indexer_expected_substring
        response_timeout_ms = [int]$timeouts.response_timeout_ms
        holder_timeout_ms = [int]$timeouts.holder_timeout_ms
        indexer_timeout_ms = [int]$timeouts.indexer_timeout_ms
        resident_exit_timeout_ms = [int]$timeouts.resident_exit_timeout_ms
        phase_store_owner_contract = $phaseStoreOwnerContract
        auxiliary_state_contract = $auxiliaryStateContract
    }
}

function Write-AstroFsvEventLine {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Event
    )
    $line = ($Event | ConvertTo-Json -Depth 20 -Compress) + [Environment]::NewLine
    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::Append,
        [IO.FileAccess]::Write,
        [IO.FileShare]::Read
    )
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($line)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
}

function Get-AstroCohortStoreSnapshot {
    param([Parameter(Mandatory)][string[]]$StorePaths)
    $owners = [ordered]@{}
    $files = [Collections.Generic.List[object]]::new()
    foreach ($path in $StorePaths) {
        $state = Get-AstroPathEntryState $path
        if ($state.State -ceq 'absent') {
            $files.Add([ordered]@{ path = $path; state = 'absent'; owners = @() })
            continue
        }
        if ($state.State -cne 'present' -or
            ($state.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or
            ($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-Astro 'ASTRO_FSV_COHORT_STORE_UNEVALUABLE' `
                "store-family path is not an ordinary readable file: $path (state=$($state.State); error=$($state.Error))" `
                'preserve the real store and repair path identity before lifecycle cleanup'
        }
        $diagnostic = Get-AstroArtifactOwnerDiagnostic $path
        if ([string]$diagnostic.state -cne 'observed') {
            Fail-Astro 'ASTRO_FSV_COHORT_OWNER_UNEVALUABLE' `
                "Restart Manager could not classify exact owners of '$path': $($diagnostic.error)" `
                'preserve every process and store byte until exact holder attribution is readable'
        }
        $fileOwners = [Collections.Generic.List[object]]::new()
        foreach ($owner in @($diagnostic.owners)) {
            $identity = New-AstroProcessIdentityRecord `
                ([int]$owner.pid) ([long]$owner.process_start_utc_ticks)
            $key = '{0}:{1}' -f $identity.pid,$identity.process_start_utc_ticks
            if (-not $owners.Contains($key)) {
                $owners[$key] = [ordered]@{
                    identity = $identity
                    paths = [Collections.Generic.List[string]]::new()
                }
            }
            $owners[$key].paths.Add($path)
            $fileOwners.Add($identity)
        }
        $files.Add([ordered]@{
            path = $path
            state = 'present'
            owners = @($fileOwners | Sort-Object `
                @{ Expression = { [int]$_.pid } },
                @{ Expression = { [long]$_.process_start_utc_ticks } })
        })
    }
    $canonicalOwners = @($owners.Values | ForEach-Object {
        [ordered]@{
            identity = $_.identity
            paths = [string[]]@($_.paths | Sort-Object -Unique)
        }
    } | Sort-Object `
        @{ Expression = { [int]$_.identity.pid } },
        @{ Expression = { [long]$_.identity.process_start_utc_ticks } })
    return [ordered]@{
        observed_at_utc = [DateTime]::UtcNow.ToString('o')
        files = @($files)
        owners = @($canonicalOwners)
        owner_signature = (@($canonicalOwners | ForEach-Object {
            '{0}:{1}' -f $_.identity.pid,$_.identity.process_start_utc_ticks
        }) -join ',')
    }
}

function Wait-AstroCohortStoreOwners {
    param(
        [Parameter(Mandatory)][string[]]$StorePaths,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ExpectedIdentities,
        [Parameter(Mandatory)][int]$TimeoutMilliseconds,
        [Parameter(Mandatory)][string]$Phase
    )
    $expectedSignature = @($ExpectedIdentities | Sort-Object `
        @{ Expression = { [int]$_.pid } },
        @{ Expression = { [long]$_.process_start_utc_ticks } } | ForEach-Object {
            '{0}:{1}' -f $_.pid,$_.process_start_utc_ticks
        }) -join ','
    $attempts = [Collections.Generic.List[object]]::new()
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $previousMatchingSignature = $null
    while ($stopwatch.ElapsedMilliseconds -le $TimeoutMilliseconds) {
        $snapshot = Get-AstroCohortStoreSnapshot -StorePaths $StorePaths
        $matches = [string]$snapshot.owner_signature -ceq $expectedSignature
        $attempts.Add([ordered]@{
            attempt = $attempts.Count + 1
            elapsed_ms = [int64]$stopwatch.ElapsedMilliseconds
            expected_signature = $expectedSignature
            observed_signature = [string]$snapshot.owner_signature
            matches = $matches
        })
        if ($matches -and $previousMatchingSignature -ceq $expectedSignature) {
            $stopwatch.Stop()
            return [ordered]@{
                phase = $Phase
                stable = $true
                required_consecutive_matches = 2
                elapsed_ms = [int64]$stopwatch.ElapsedMilliseconds
                attempts = @($attempts)
                snapshot = $snapshot
            }
        }
        $previousMatchingSignature = if ($matches) { $expectedSignature } else { $null }
        [Threading.Thread]::Sleep(100)
    }
    $stopwatch.Stop()
    Fail-Astro 'ASTRO_FSV_COHORT_OWNER_MISMATCH' `
        "store-owner phase '$Phase' did not reach two stable exact snapshots (expected=$expectedSignature; attempts=$($attempts | ConvertTo-Json -Depth 12 -Compress))" `
        'preserve the cohort/store/session and inspect the exact PID/start-ticks holder chronology'
}

function Get-AstroCohortExpectedStoreOwners {
    param(
        [Parameter(Mandatory)][ValidateSet('residents', 'absent')][string]$Contract,
        [Parameter(Mandatory)][object[]]$ResidentIdentities
    )
    if ($Contract -ceq 'residents') {
        return ,@($ResidentIdentities)
    }
    return ,@()
}

function Wait-AstroCohortSidecarsAbsent {
    param(
        [Parameter(Mandatory)][string[]]$SidecarPaths,
        [Parameter(Mandatory)][int]$TimeoutMilliseconds,
        [Parameter(Mandatory)][string]$Phase
    )
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $attempts = [Collections.Generic.List[object]]::new()
    $priorMatch = $false
    while ($stopwatch.ElapsedMilliseconds -le $TimeoutMilliseconds) {
        $states = @($SidecarPaths | ForEach-Object {
            [ordered]@{ path = $_; exists = Test-AstroPathLongPath -LiteralPath $_ }
        })
        $match = @($states | Where-Object exists).Count -eq 0
        $attempts.Add([ordered]@{
            attempt = $attempts.Count + 1
            elapsed_ms = [int64]$stopwatch.ElapsedMilliseconds
            states = $states
            matches = $match
        })
        if ($match -and $priorMatch) {
            $stopwatch.Stop()
            return [ordered]@{
                phase = $Phase; stable = $true; required_consecutive_matches = 2
                elapsed_ms = [int64]$stopwatch.ElapsedMilliseconds
                attempts = @($attempts)
            }
        }
        $priorMatch = $match
        [Threading.Thread]::Sleep(100)
    }
    $stopwatch.Stop()
    Fail-Astro 'ASTRO_FSV_COHORT_SIDECAR_RETAINED' `
        "SQLite sidecars did not become stably absent during '$Phase': $($attempts | ConvertTo-Json -Depth 8 -Compress)" `
        'preserve the store and exact process chronology; inspect the owner that retained the SQLite generation'
}

function Get-AstroCohortStoreInventory {
    param([Parameter(Mandatory)][string[]]$StorePaths)
    $files = @($StorePaths | ForEach-Object {
        $path = $_
        if (-not (Test-AstroPathLongPath -LiteralPath $path)) {
            return [ordered]@{
                path = $path; exists = $false; bytes = 0; sha256 = $null
            }
        }
        if (-not (Test-AstroPathLongPath -LiteralPath $path -PathType Leaf)) {
            Fail-Astro 'ASTRO_FSV_COHORT_STORE_TYPE_INVALID' `
                "SQLite family member is not one ordinary file: $path" `
                'preserve the complete family and replace the non-file entry before retrying'
        }
        Assert-NotReparseEntry $path 'SQLite cohort family member'
        return [ordered]@{
            path = $path
            exists = $true
            bytes = [uint64](Get-AstroFileLengthLongPath $path)
            sha256 = File-Sha256 $path
        }
    })
    return [ordered]@{
        observed_at_utc = [DateTime]::UtcNow.ToString('o')
        files = $files
    }
}

function Read-AstroCohortAuxiliaryState {
    param(
        [Parameter(Mandatory)][string[]]$StorePaths,
        [Parameter(Mandatory)][ValidateSet('absent', 'read_only_tail')][string]$Contract,
        [Parameter(Mandatory)][int]$TimeoutMilliseconds,
        [Parameter(Mandatory)][string]$Phase
    )
    if ($Contract -ceq 'absent') {
        $absence = Wait-AstroCohortSidecarsAbsent $StorePaths[1..2] `
            $TimeoutMilliseconds "$Phase-sidecars-absent"
        return [ordered]@{
            phase = $Phase; contract = $Contract; state = 'absent'
            evidence = $absence
        }
    }

    # #1124 / #1064 PC-03/07/13/35/41: after exact zero-owner proof, read the
    # fixed three-file family twice. No timeout/poll loop depends on project or
    # ledger N. Hashing cost is O(B), where B is the physical config-family byte
    # count named by the plan; paths and read order are invariant.
    $first = Get-AstroCohortStoreInventory -StorePaths $StorePaths
    [Threading.Thread]::Sleep(100)
    $second = Get-AstroCohortStoreInventory -StorePaths $StorePaths
    $firstBytes = $first.files | ConvertTo-Json -Depth 8 -Compress
    $secondBytes = $second.files | ConvertTo-Json -Depth 8 -Compress
    if ($firstBytes -cne $secondBytes) {
        Fail-Astro 'ASTRO_FSV_COHORT_AUXILIARY_STATE_DRIFT' `
            "SQLite family changed between zero-owner stable reads during '$Phase' (before=$firstBytes; after=$secondBytes)" `
            'preserve every family byte and inspect the unrecorded writer or filesystem transition'
    }
    $database = $second.files[0]
    $wal = $second.files[1]
    $shm = $second.files[2]
    if (-not [bool]$database.exists) {
        Fail-Astro 'ASTRO_FSV_COHORT_STORE_MISSING' `
            "SQLite main database disappeared during '$Phase': $($database.path)" `
            'preserve the family and repair the missing source of truth before retrying'
    }
    if ([bool]$wal.exists -and [uint64]$wal.bytes -ne 0) {
        Fail-Astro 'ASTRO_FSV_COHORT_NONEMPTY_WAL_RETAINED' `
            "read_only_tail during '$Phase' retained a nonempty WAL ($($wal.bytes) bytes, sha256=$($wal.sha256))" `
            'preserve the complete SQLite family; committed state may live outside the main DB and cannot be inferred or discarded'
    }
    if ([bool]$wal.exists -ne [bool]$shm.exists) {
        Fail-Astro 'ASTRO_FSV_COHORT_AUXILIARY_FAMILY_PARTIAL' `
            "read_only_tail during '$Phase' observed WAL/SHM presence mismatch (wal=$([bool]$wal.exists), shm=$([bool]$shm.exists))" `
            'preserve the partial family and diagnose its exact SQLite lifecycle before retrying'
    }
    return [ordered]@{
        phase = $Phase
        contract = $Contract
        state = if ([bool]$wal.exists) { 'read_only_tail' } else { 'absent' }
        stable = $true
        required_consecutive_matches = 2
        before = $first
        after = $second
        wal_empty = (-not [bool]$wal.exists) -or [uint64]$wal.bytes -eq 0
        shm_trust = if ([bool]$shm.exists) { 'transient_wal_index' } else { 'absent' }
    }
}

function Invoke-AstroCohortRequest {
    param(
        [Parameter(Mandatory)][AstroFsvCreatedProcess]$Process,
        [Parameter(Mandatory)]$Request,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ExpectedSubstring,
        [Parameter(Mandatory)][int]$TimeoutMilliseconds,
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][int]$Ordinal,
        [Parameter(Mandatory)][string]$EventPath
    )
    $requestLine = $Request | ConvertTo-Json -Depth 30 -Compress
    $Process.WriteInputLine($requestLine)
    Write-AstroFsvEventLine $EventPath ([ordered]@{
        event = 'request_sent'; phase = $Phase; role = 'resident'; ordinal = $Ordinal
        identity = New-AstroProcessIdentityRecord $Process.Id ([long]$Process.ProcessStartUtcTicks)
        at_utc = [DateTime]::UtcNow.ToString('o'); request_sha256 = String-Sha256 $requestLine
        request = $Request
    })
    $responseLine = $Process.ReadOutputLine([uint32]$TimeoutMilliseconds)
    try { $response = ConvertFrom-Json -InputObject $responseLine }
    catch {
        Fail-Astro 'ASTRO_FSV_COHORT_RESPONSE_INVALID' `
            "resident $Ordinal returned invalid JSON during '$Phase': $($_.Exception.Message); line=$responseLine" `
            'preserve the output and repair the real resident protocol response'
    }
    if ($null -eq $response -or [string]$response.jsonrpc -cne '2.0' -or
        $null -eq $response.PSObject.Properties['id'] -or
        (($response.id | ConvertTo-Json -Compress) -cne ($Request.id | ConvertTo-Json -Compress)) -or
        ($response.PSObject.Properties['error'] -and $null -ne $response.error) -or
        -not $response.PSObject.Properties['result'] -or
        ($ExpectedSubstring.Length -gt 0 -and
            $responseLine.IndexOf($ExpectedSubstring, [StringComparison]::Ordinal) -lt 0)) {
        Fail-Astro 'ASTRO_FSV_COHORT_RESPONSE_INVALID' `
            "resident $Ordinal returned an unexpected '$Phase' response: $responseLine" `
            'preserve the exact response and correct the expected real request/result contract'
    }
    $event = [ordered]@{
        event = 'response_received'; phase = $Phase; role = 'resident'; ordinal = $Ordinal
        identity = New-AstroProcessIdentityRecord $Process.Id ([long]$Process.ProcessStartUtcTicks)
        at_utc = [DateTime]::UtcNow.ToString('o'); response_sha256 = String-Sha256 $responseLine
        response = $response
    }
    Write-AstroFsvEventLine $EventPath $event
    return $event
}

function Read-AstroFsvCohortOwnerEntries {
    param(
        $Entries,
        [Parameter(Mandatory)][int]$ResidentCount,
        [int]$ExpectedProcessCount = -1,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )
    if ($Entries -isnot [Array] -or $Entries.Count -gt ($ResidentCount + 1) -or
        ($ExpectedProcessCount -ge 0 -and $Entries.Count -ne $ExpectedProcessCount)) {
        Fail-Astro $Code "$Description has an invalid process count (observed=$($Entries.Count); expected=$ExpectedProcessCount; maximum=$($ResidentCount + 1))" `
            'preserve the lifecycle state and investigate incomplete multi-process provenance'
    }
    $keys = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $result = [Collections.Generic.List[object]]::new()
    foreach ($entry in $Entries) {
        Assert-AstroExactObjectProperties $entry @('role', 'ordinal', 'identity') $Code `
            "$Description process entry"
        $role = [string]$entry.role
        $ordinal = [int]$entry.ordinal
        $valid = ($role -ceq 'indexer' -and $ordinal -eq 0) -or
            ($role -ceq 'resident' -and $ordinal -ge 1 -and $ordinal -le $ResidentCount)
        $identity = Read-AstroFsvProcessIdentity $entry.identity $Code `
            "$Description $role/$ordinal identity"
        $key = "$role/$ordinal/$($identity.pid)/$($identity.process_start_utc_ticks)"
        $roleKey = "$role/$ordinal"
        $identityKey = "$($identity.pid)/$($identity.process_start_utc_ticks)"
        if (-not $valid -or -not $keys.Add($roleKey) -or
            -not $identities.Add($identityKey)) {
            Fail-Astro $Code "$Description has an invalid or duplicate process entry '$key'" `
                'preserve the lifecycle state and investigate incomplete multi-process provenance'
        }
        $result.Add([pscustomobject][ordered]@{
            role = $role
            ordinal = $ordinal
            identity = $identity
        })
    }
    if ($ExpectedProcessCount -eq ($ResidentCount + 1) -and
        (@($result | Where-Object role -ceq 'indexer').Count -ne 1 -or
         @($result | Where-Object role -ceq 'resident').Count -ne $ResidentCount)) {
        Fail-Astro $Code "$Description process roles/cardinality are invalid" `
            'preserve the lifecycle state and investigate incomplete multi-process provenance'
    }
    return ,@($result | Sort-Object role, ordinal)
}

function Test-AstroFsvCohortOwnerEntriesEqual($Left, $Right) {
    if ($Left.Count -ne $Right.Count) { return $false }
    for ($index = 0; $index -lt $Left.Count; $index++) {
        if ([string]$Left[$index].role -cne [string]$Right[$index].role -or
            [int]$Left[$index].ordinal -ne [int]$Right[$index].ordinal -or
            -not (Test-AstroFsvIdentityEqual $Left[$index].identity $Right[$index].identity)) {
            return $false
        }
    }
    return $true
}

function Remove-TerminalFsvCohortLock {
    param(
        [Parameter(Mandatory)][string]$LockPath,
        [Parameter(Mandatory)]$RunnerIdentity,
        [Parameter(Mandatory)][object[]]$Processes,
        [Parameter(Mandatory)][int]$ResidentCount,
        [Parameter(Mandatory)][string]$ArtifactSha256
    )
    if (-not (Test-AstroPathLongPath -LiteralPath $LockPath)) {
        return [ordered]@{ path = $LockPath; before_exists = $false; removed = $false; after_exists = $false; sha256_before = $null }
    }
    $lockSha = File-Sha256 $LockPath
    try {
        $lock = Read-AstroUtf8FileLongPath $LockPath | ConvertFrom-Json
        if ([string]$lock.schema -cne 'astrolabe.native-fsv-lock.v3' -or
            [int]$lock.resident_count -ne $ResidentCount -or
            [string]$lock.artifact_sha256 -cne $ArtifactSha256) { throw 'v3 envelope mismatch' }
        $lockRunner = Read-AstroFsvProcessIdentity $lock.owners.runner `
            'ASTRO_FSV_LOCK_IDENTITY_CHANGED' 'terminal cohort-lock runner identity'
        $lockProcesses = Read-AstroFsvCohortOwnerEntries $lock.owners.processes `
            $ResidentCount $Processes.Count 'ASTRO_FSV_LOCK_IDENTITY_CHANGED' `
            'terminal cohort lock'
    }
    catch {
        Fail-Astro 'ASTRO_FSV_LOCK_IDENTITY_CHANGED' `
            "terminal cohort lock is unreadable, malformed, or mismatched: $($_.Exception.Message)" `
            'preserve the lock/session and retire only after exact multi-process identity readback'
    }
    if (-not (Test-AstroFsvIdentityEqual $lockRunner $RunnerIdentity) -or
        -not (Test-AstroFsvCohortOwnerEntriesEqual $lockProcesses $Processes)) {
        Fail-Astro 'ASTRO_FSV_LOCK_IDENTITY_CHANGED' `
            'terminal cohort lock no longer matches this exact runner/process generation set' `
            'preserve the lock/session and retire only after exact multi-process identity readback'
    }
    Remove-AstroFileLongPath $LockPath
    if (Test-AstroPathLongPath -LiteralPath $LockPath) {
        Fail-Astro 'ASTRO_FSV_LOCK_CLEANUP_READBACK_FAILED' `
            "owned cohort lock remained after terminal cleanup: $LockPath" `
            'preserve the lock/session and retire only after exact multi-process owner absence'
    }
    return [ordered]@{ path = $LockPath; before_exists = $true; removed = $true; after_exists = $false; sha256_before = $lockSha }
}

function Open-AstroCohortCleanupReadiness {
    param(
        [Parameter(Mandatory)][string]$ArtifactPath,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [Parameter(Mandatory)][uint64]$ExpectedBytes,
        [Parameter(Mandatory)][int[]]$OwnedPids,
        [Parameter(Mandatory)][string]$LauncherJobName
    )
    $lease = $null
    $attempts = [Collections.Generic.List[object]]::new()
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $timeoutMs = 15000
    $delayMs = 100
    try {
        while ($null -eq $lease) {
            Set-AstroFileReadOnlyLongPath -LiteralPath $ArtifactPath -ReadOnly $false
            $openFailure = $null
            try {
                $lease = [AstroLauncherLockNative]::OpenExactRenameSource($ArtifactPath)
            }
            catch { $openFailure = $_ }
            if ($null -ne $lease) {
                Set-AstroFileReadOnlyLongPath -LiteralPath $ArtifactPath -ReadOnly $true
                break
            }
            Set-AstroFileReadOnlyLongPath -LiteralPath $ArtifactPath -ReadOnly $true
            $nativeError = Get-AstroNativeErrorCode $openFailure.Exception
            $ownerDiagnostic = Get-AstroArtifactOwnerDiagnostic $ArtifactPath
            $attempts.Add([ordered]@{
                attempt = $attempts.Count + 1
                elapsed_ms = [int64]$stopwatch.ElapsedMilliseconds
                native_error = $nativeError
                message = $openFailure.Exception.Message
                owner_diagnostic = $ownerDiagnostic
                read_only_restored = $true
            })
            if ($nativeError -ne 32 -or [string]$ownerDiagnostic.state -cne 'observed' -or
                @($ownerDiagnostic.owners).Count -eq 0) {
                throw "cleanup-readiness sharing failure is not a completely attributed transient (native_error=$nativeError; owner_diagnostic=$($ownerDiagnostic | ConvertTo-Json -Depth 8 -Compress))"
            }
            $internal = @($ownerDiagnostic.owners | Where-Object {
                [int]$_.pid -in $OwnedPids
            })
            if ($internal.Count -ne 0) {
                throw "cleanup-readiness sharing violation remains inside exact launcher Job '$LauncherJobName' (owners=$($internal | ConvertTo-Json -Depth 8 -Compress))"
            }
            $remaining = $timeoutMs - [int64]$stopwatch.ElapsedMilliseconds
            if ($remaining -le 0) {
                throw "cleanup-readiness sharing violation exceeded $timeoutMs ms"
            }
            [Threading.Thread]::Sleep([int][Math]::Min($delayMs, $remaining))
            $delayMs = [int][Math]::Min($delayMs * 2, 1000)
        }
        $stopwatch.Stop()
        $finalPath = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($lease)
        )
        $fileId = [AstroLauncherLockNative]::GetFileIdentity($lease)
        $links = [AstroLauncherLockNative]::GetNumberOfLinks($lease)
        $length = Get-AstroFileLengthLongPath $ArtifactPath
        $hash =
            [AstroLauncherLockNative]::ComputeExactFileSha256($lease)
        $attributes = [IO.File]::GetAttributes(
            (ConvertTo-AstroExtendedLengthPath $ArtifactPath)
        )
        $readOnly = ($attributes -band [IO.FileAttributes]::ReadOnly) -ne 0
        if (-not [string]::Equals($finalPath, $ArtifactPath, [StringComparison]::OrdinalIgnoreCase) -or
            $links -ne 1 -or $length -ne $ExpectedBytes -or
            $hash -cne $ExpectedSha256 -or -not $readOnly) {
            throw "cleanup-readiness readback drifted (final_path=$finalPath; links=$links; bytes=$length; sha256=$hash; read_only=$readOnly)"
        }
        return [pscustomobject]@{
            Lease = $lease
            Evidence = [ordered]@{
                established = $true
                operation = 'CreateFileW(GENERIC_READ|GENERIC_WRITE|DELETE,FILE_SHARE_READ)'
                final_path = $finalPath
                file_id = $fileId
                links = [uint32]$links
                bytes = [uint64]$length
                sha256 = $hash
                read_only_restored = $readOnly
                process_termination_proved = $true
                process_handles_closed = $true
                retained_until_runner_exit = $true
                transition = [ordered]@{
                    kind = if ($attempts.Count -eq 0) { 'immediate' } else { 'bounded-foreign-owner-sharing-violation' }
                    timeout_ms = $timeoutMs
                    initial_delay_ms = 100
                    maximum_delay_ms = 1000
                    failed_attempts = @($attempts)
                    successful_attempt = $attempts.Count + 1
                    elapsed_ms = [int64]$stopwatch.ElapsedMilliseconds
                }
            }
        }
    }
    catch {
        $stopwatch.Stop()
        $failure = $_
        $leaseDisposeError = $null
        if ($null -ne $lease) {
            try { $lease.Dispose() }
            catch { $leaseDisposeError = $_.Exception.Message }
            $lease = $null
        }
        try {
            if (Test-AstroPathLongPath -LiteralPath $ArtifactPath -PathType Leaf) {
                Set-AstroFileReadOnlyLongPath -LiteralPath $ArtifactPath -ReadOnly $true
            }
        }
        catch {
            Fail-Astro 'ASTRO_FSV_ARTIFACT_CLEANUP_READINESS_RESTORE_FAILED' `
                "cohort cleanup readiness failed and read-only restoration also failed (readiness=$($failure.Exception.Message); lease_dispose=$leaseDisposeError; restore=$($_.Exception.Message))" `
                'preserve the session and exact owner state before lifecycle cleanup'
        }
        Fail-Astro 'ASTRO_FSV_ARTIFACT_CLEANUP_NOT_READY' `
            "staged cohort artifact is not exactly ready for cleanup: $($failure.Exception.Message); lease_dispose_error=$leaseDisposeError; attempts=$($attempts | ConvertTo-Json -Depth 12 -Compress)" `
            'preserve the session and inspect the exact native error/owner transition'
    }
}

function Invoke-AstroResidentCohort {
    param(
        [Parameter(Mandatory)][string]$PlanPath,
        [Parameter(Mandatory)][string]$Workspace,
        [Parameter(Mandatory)][int]$IssueNumber,
        [Parameter(Mandatory)][string]$SessionDirectory,
        [Parameter(Mandatory)][string]$ReceiptFull,
        [Parameter(Mandatory)]$Receipt,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][string]$ArtifactHashBefore,
        [Parameter(Mandatory)][string]$ReceiptHashBefore,
        [Parameter(Mandatory)]$ArtifactItem,
        [Parameter(Mandatory)]$LauncherIdentity,
        [Parameter(Mandatory)]$RunnerIdentity,
        [Parameter(Mandatory)][int]$LauncherPid,
        [Parameter(Mandatory)]$LauncherOwner,
        [Parameter(Mandatory)][string]$LauncherLockPath,
        [Parameter(Mandatory)]$LauncherLockHandle,
        [Parameter(Mandatory)]$LauncherLockSnapshotBefore,
        [Parameter(Mandatory)][uint32]$LauncherLockLinksBefore,
        [Parameter(Mandatory)][string]$LauncherLockHashBefore,
        [Parameter(Mandatory)][string]$LauncherJobName,
        [Parameter(Mandatory)][int[]]$LauncherJobMembersBefore,
        [Parameter(Mandatory)]$BeforeRepo,
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)]$ArtifactExecutionHandle,
        [Parameter(Mandatory)][string]$FsvLockPath,
        [Parameter(Mandatory)][string]$StandardOutputPath,
        [Parameter(Mandatory)][string]$StandardErrorPath,
        [Parameter(Mandatory)][string]$RunRecordPath,
        [Parameter(Mandatory)][string]$LiveStatePath
    )

    $plan = Read-AstroResidentCohortPlan $PlanPath $Workspace $IssueNumber
    $processStates = [Collections.Generic.List[object]]::new()
    $residentResponses = [Collections.Generic.List[object]]::new()
    $storeChronology = [Collections.Generic.List[object]]::new()
    $cleanupLease = $null
    $lockOwned = $false
    $lockCleanup = $null
    $liveStatePublished = $false
    $liveStateBytes = 0L
    $liveStateSha256 = $null
    $runRecordWritten = $false
    $lockManifest = $null
    $cohortJobMembers = [int[]]::new(0)
    $cohortFailureInFlight = $false

    $ownerEntries = {
        return @($processStates | ForEach-Object {
            [pscustomobject][ordered]@{
                role = [string]$_.role
                ordinal = [int]$_.ordinal
                identity = $_.identity
            }
        } | Sort-Object role, ordinal)
    }
    $publishLock = {
        param([string]$Phase)
        $lockManifest.phase = $Phase
        $lockManifest.process_count = $processStates.Count
        $lockManifest.owners.processes = @(& $ownerEntries)
        $stage = "$FsvLockPath.$PID.$Phase.tmp"
        Write-NewDurableUtf8 $stage ($lockManifest | ConvertTo-Json -Depth 15 -Compress)
        try { [AstroFsvAtomicFile]::ReplaceOwned($stage, $FsvLockPath) }
        catch {
            if (Test-AstroPathLongPath -LiteralPath $stage -PathType Leaf) {
                Remove-AstroFileLongPath $stage
            }
            throw
        }
        $readback = Read-AstroUtf8FileLongPath $FsvLockPath | ConvertFrom-Json
        $readbackRunner = Read-AstroFsvProcessIdentity $readback.owners.runner `
            'ASTRO_FSV_LOCK_UPDATE_FAILED' 'cohort-lock runner identity'
        $readbackProcesses = Read-AstroFsvCohortOwnerEntries `
            $readback.owners.processes $plan.resident_count $processStates.Count `
            'ASTRO_FSV_LOCK_UPDATE_FAILED' 'cohort-lock process readback'
        $expectedProcesses = Read-AstroFsvCohortOwnerEntries `
            @(& $ownerEntries) $plan.resident_count $processStates.Count `
            'ASTRO_FSV_LOCK_UPDATE_FAILED' 'local cohort process set'
        if ([string]$readback.schema -cne 'astrolabe.native-fsv-lock.v3' -or
            [int]$readback.issue -ne $IssueNumber -or
            [int]$readback.resident_count -ne $plan.resident_count -or
            [int]$readback.process_count -ne $processStates.Count -or
            [string]$readback.phase -cne $Phase -or
            [string]$readback.artifact_sha256 -cne $ArtifactHashBefore -or
            -not (Test-AstroFsvIdentityEqual $readbackRunner $RunnerIdentity) -or
            -not (Test-AstroFsvCohortOwnerEntriesEqual $readbackProcesses $expectedProcesses)) {
            Fail-Astro 'ASTRO_FSV_LOCK_UPDATE_FAILED' `
                "cohort-lock '$Phase' readback differs from the exact local process set" `
                'preserve the lock/session and inspect the durable multi-process owner envelope'
        }
    }
    $processRecords = {
        return @($processStates | ForEach-Object {
            [pscustomobject][ordered]@{
                role = [string]$_.role
                ordinal = [int]$_.ordinal
                identity = $_.identity
                launch_boundary = 'kernel32!CreateProcessW(non-null extended application; STARTUPINFOEX restricted anonymous-pipe handle list)'
                standard_input = 'runner-owned anonymous pipe'
                standard_output = 'runner-owned anonymous pipe'
                standard_error = 'runner-owned anonymous pipe'
                argument_count = @($_.arguments).Count
                arguments = @($_.arguments)
                created_suspended_at_utc = $_.created_suspended_at_utc
                started_at_utc = $_.started_at_utc
                exited_at_utc = $_.exited_at_utc
                exit_code = $_.exit_code
                exit_code_observation = $_.exit_code_observation
                # #1059: additive classification of how this cohort member ended.
                termination_classification =
                    Get-AstroTerminationClassification $_.exit_code
                termination_proved = [bool]$_.termination_proved
                exact_process_handles_closed = [bool]$_.handles_closed
            }
        } | Sort-Object role, ordinal)
    }

    try {
        $lockManifest = [ordered]@{
            schema = 'astrolabe.native-fsv-lock.v3'
            mode = 'resident-cohort'
            issue = $IssueNumber
            started = [DateTime]::UtcNow.ToString('o')
            resident_count = $plan.resident_count
            process_count = 0
            tree_sha = [string]$Receipt.tree_sha
            artifact_path = $Artifact
            artifact_sha256 = $ArtifactHashBefore
            cohort_plan = [ordered]@{ path = $plan.path; sha256 = $plan.sha256_before }
            owners = [ordered]@{
                launcher = $LauncherIdentity
                runner = $RunnerIdentity
                processes = @()
            }
            launcher_job = [ordered]@{
                name = $LauncherJobName
                members = @($LauncherJobMembersBefore)
            }
            phase = 'claimed'
        }
        $admissionLease = Enter-AstroFsvAdmissionLease $Workspace
        try {
            Assert-AstroFsvLifecycleAdmissionClear $Workspace
            $lockStage = "$FsvLockPath.$PID.tmp"
            Write-NewDurableUtf8 $lockStage ($lockManifest | ConvertTo-Json -Depth 15 -Compress)
            try { [AstroFsvAtomicFile]::PublishNoClobber($lockStage, $FsvLockPath) }
            catch {
                if (Test-AstroPathLongPath -LiteralPath $lockStage -PathType Leaf) {
                    Remove-AstroFileLongPath $lockStage
                }
                Fail-Astro 'ASTRO_FSV_LOCK_HELD' `
                    "FSV lock could not be claimed for resident cohort: $FsvLockPath" `
                    'wait for the live owner or complete the exact tracker-bound stale-lock lifecycle'
            }
            $lockOwned = $true
        }
        finally {
            Exit-AstroFsvLifecycleMutex $admissionLease
        }
        Write-NewDurableUtf8 $StandardOutputPath ''
        Write-NewDurableUtf8 $StandardErrorPath ''
        Write-AstroFsvEventLine $StandardOutputPath ([ordered]@{
            event = 'cohort_admitted'; at_utc = [DateTime]::UtcNow.ToString('o')
            issue = $IssueNumber; resident_count = $plan.resident_count
            plan = [ordered]@{ path = $plan.path; sha256 = $plan.sha256_before }
            store_paths = $plan.store_paths
            phase_store_owner_contract = $plan.phase_store_owner_contract
            auxiliary_state_contract = $plan.auxiliary_state_contract
        })

        for ($ordinal = 1; $ordinal -le $plan.resident_count; $ordinal++) {
            $commandLine = ConvertTo-WindowsCommandLineArgument $Artifact
            try {
                $native = [AstroFsvNativeProcess]::CreateSuspendedPiped(
                    $Artifact, $commandLine
                )
            }
            catch {
                Fail-Astro 'ASTRO_FSV_COHORT_PROCESS_CREATE_FAILED' `
                    "resident $ordinal creation failed before a complete identity was returned: $($_.Exception.Message)" `
                    'preserve every recorded generation and repair the exact native process boundary'
            }
            $state = [ordered]@{
                role = 'resident'; ordinal = $ordinal; native = $native
                identity = New-AstroProcessIdentityRecord $native.Id ([long]$native.ProcessStartUtcTicks)
                arguments = [string[]]::new(0)
                created_suspended_at_utc = [DateTime]::UtcNow.ToString('o')
                started_at_utc = $null; exited_at_utc = $null
                exit_code = $null; exit_code_observation = $null
                termination_proved = $false; stderr_captured = $false; handles_closed = $false
            }
            $processStates.Add($state)
            try { & $publishLock 'creating' }
            catch {
                Fail-Astro 'ASTRO_FSV_LOCK_UPDATE_FAILED' `
                    "resident $ordinal exact identity could not be published: $($_.Exception.Message)" `
                    'preserve the lock/session and the failure record containing every locally retained exact handle'
            }
        }

        $indexerArgumentLine = @($plan.indexer_arguments | ForEach-Object {
            ConvertTo-WindowsCommandLineArgument ([string]$_)
        }) -join ' '
        $indexerCommandLine = (ConvertTo-WindowsCommandLineArgument $Artifact) +
            ' ' + $indexerArgumentLine
        try {
            $indexerNative = [AstroFsvNativeProcess]::CreateSuspendedPiped(
                $Artifact, $indexerCommandLine
            )
        }
        catch {
            Fail-Astro 'ASTRO_FSV_COHORT_PROCESS_CREATE_FAILED' `
                "indexer creation failed before a complete identity was returned: $($_.Exception.Message)" `
                'preserve every recorded generation and repair the exact native process boundary'
        }
        $processStates.Add([ordered]@{
            role = 'indexer'; ordinal = 0; native = $indexerNative
            identity = New-AstroProcessIdentityRecord $indexerNative.Id ([long]$indexerNative.ProcessStartUtcTicks)
            arguments = [string[]]$plan.indexer_arguments
            created_suspended_at_utc = [DateTime]::UtcNow.ToString('o')
            started_at_utc = $null; exited_at_utc = $null
            exit_code = $null; exit_code_observation = $null
            termination_proved = $false; stderr_captured = $false; handles_closed = $false
        })
        & $publishLock 'suspended'

        $jobProbe = Get-AstroLauncherJobObjectProbe -Name $LauncherJobName
        $cohortJobMembers = [int[]]@($jobProbe.ProcessIds | Sort-Object -Unique)
        $missingJobPids = @($processStates | Where-Object {
            $cohortJobMembers -notcontains [int]$_.identity.pid
        })
        if ($jobProbe.State -cne 'observed' -or $missingJobPids.Count -ne 0) {
            Fail-Astro 'ASTRO_FSV_COHORT_JOB_MISMATCH' `
                "launcher Job does not contain every created cohort generation (state=$($jobProbe.State); members=$($cohortJobMembers -join ','); missing=$(@($missingJobPids | ForEach-Object { $_.identity.pid }) -join ','))" `
                'preserve every process/session byte and repair non-breakaway launcher attribution'
        }

        $liveState = [ordered]@{
            schema = 'astrolabe.native-fsv-live.v3'
            mode = 'resident-cohort'
            owners = [ordered]@{
                launcher = $LauncherIdentity
                runner = $RunnerIdentity
                processes = @(& $ownerEntries)
            }
            resident_count = $plan.resident_count
            process_count = $processStates.Count
            launcher_job = [ordered]@{
                name = $LauncherJobName
                members_before = @($LauncherJobMembersBefore)
                members_with_suspended_cohort = @($cohortJobMembers)
            }
            issue = $IssueNumber
            tree_sha = [string]$Receipt.tree_sha
            artifact = [ordered]@{
                path = $Artifact; bytes = [uint64]$ArtifactItem.Length
                sha256 = $ArtifactHashBefore
            }
            cohort_plan = [ordered]@{ path = $plan.path; sha256 = $plan.sha256_before }
            created_at_utc = [DateTime]::UtcNow.ToString('o')
        }
        Publish-NewFile $LiveStatePath ($liveState | ConvertTo-Json -Depth 15)
        $liveStatePublished = $true
        $persistedLive = Read-AstroUtf8FileLongPath $LiveStatePath | ConvertFrom-Json
        $persistedLiveRunner = Read-AstroFsvProcessIdentity $persistedLive.owners.runner `
            'ASTRO_FSV_LIVE_STATE_READBACK_FAILED' 'cohort live-state runner identity'
        $persistedLiveProcesses = Read-AstroFsvCohortOwnerEntries `
            $persistedLive.owners.processes $plan.resident_count $processStates.Count `
            'ASTRO_FSV_LIVE_STATE_READBACK_FAILED' 'cohort live-state process set'
        $expectedLiveProcesses = Read-AstroFsvCohortOwnerEntries `
            @(& $ownerEntries) $plan.resident_count $processStates.Count `
            'ASTRO_FSV_LIVE_STATE_READBACK_FAILED' 'local cohort process set'
        if ([string]$persistedLive.schema -cne 'astrolabe.native-fsv-live.v3' -or
            [int]$persistedLive.issue -ne $IssueNumber -or
            [string]$persistedLive.artifact.sha256 -cne $ArtifactHashBefore -or
            -not (Test-AstroFsvIdentityEqual $persistedLiveRunner $RunnerIdentity) -or
            -not (Test-AstroFsvCohortOwnerEntriesEqual $persistedLiveProcesses $expectedLiveProcesses)) {
            Fail-Astro 'ASTRO_FSV_LIVE_STATE_READBACK_FAILED' `
                'persisted cohort live state differs from the exact six-process generation set' `
                'preserve the session and investigate the failed durable write'
        }
        $liveStateBytes = Get-AstroFileLengthLongPath $LiveStatePath
        $liveStateSha256 = File-Sha256 $LiveStatePath

        foreach ($state in @($processStates | Where-Object role -ceq 'resident' | Sort-Object ordinal)) {
            try {
                [void]$state.native.BindAndResume()
                $state.started_at_utc = [DateTime]::UtcNow.ToString('o')
                $state.native.BeginErrorDrain()
            }
            catch {
                Fail-Astro 'ASTRO_FSV_COHORT_RESIDENT_START_FAILED' `
                    "resident $($state.ordinal) could not be resumed with its pipes: $($_.Exception.Message)" `
                    'preserve the exact process set and inspect the retained CreateProcess handles'
            }
        }
        & $publishLock 'residents-running'

        foreach ($state in @($processStates | Where-Object role -ceq 'resident' | Sort-Object ordinal)) {
            $initialize = [ordered]@{
                jsonrpc = '2.0'
                id = "cohort-$IssueNumber-resident-$($state.ordinal)-initialize"
                method = 'initialize'
                params = [ordered]@{
                    protocolVersion = '2024-11-05'
                    capabilities = [ordered]@{}
                    clientInfo = [ordered]@{
                        name = 'astrolabe-native-fsv'; version = '1'
                    }
                }
            }
            $residentResponses.Add((Invoke-AstroCohortRequest `
                $state.native $initialize '' $plan.response_timeout_ms `
                'initialize' $state.ordinal $StandardOutputPath))
            $notification = [ordered]@{
                jsonrpc = '2.0'; method = 'notifications/initialized'
                params = [ordered]@{}
            }
            $notificationLine = $notification | ConvertTo-Json -Depth 10 -Compress
            $state.native.WriteInputLine($notificationLine)
            Write-AstroFsvEventLine $StandardOutputPath ([ordered]@{
                event = 'notification_sent'; phase = 'initialized'
                role = 'resident'; ordinal = $state.ordinal; identity = $state.identity
                at_utc = [DateTime]::UtcNow.ToString('o')
                request_sha256 = String-Sha256 $notificationLine
            })
            $residentResponses.Add((Invoke-AstroCohortRequest `
                $state.native $plan.prime_request $plan.prime_expected_substring `
                $plan.response_timeout_ms 'prime' $state.ordinal $StandardOutputPath))
        }
        $residentIdentities = @($processStates | Where-Object role -ceq 'resident' |
            Sort-Object ordinal | ForEach-Object { $_.identity })
        $primeExpectedOwners = Get-AstroCohortExpectedStoreOwners `
            $plan.phase_store_owner_contract.prime $residentIdentities
        $primeOwners = Wait-AstroCohortStoreOwners $plan.store_paths `
            $primeExpectedOwners $plan.holder_timeout_ms `
            "prime-$($plan.phase_store_owner_contract.prime)"
        $storeChronology.Add($primeOwners)
        Write-AstroFsvEventLine $StandardOutputPath ([ordered]@{
            event = 'store_owner_snapshot'; phase = 'prime'
            contract = $plan.phase_store_owner_contract.prime
            evidence = $primeOwners
        })

        $indexer = @($processStates | Where-Object role -ceq 'indexer')[0]
        $indexer.native.BeginOutputDrain()
        $indexer.native.CloseInput()
        [void]$indexer.native.BindAndResume()
        $indexer.started_at_utc = [DateTime]::UtcNow.ToString('o')
        & $publishLock 'indexer-running'
        if (-not $indexer.native.WaitForExit([uint32]$plan.indexer_timeout_ms)) {
            Fail-Astro 'ASTRO_FSV_COHORT_INDEXER_TIMEOUT' `
                "indexer exceeded its bounded $($plan.indexer_timeout_ms) ms execution budget" `
                'preserve the process/store chronology; reduce the fixture or explicitly raise the issue-scoped bound'
        }
        $indexer.exited_at_utc = [DateTime]::UtcNow.ToString('o')
        $indexer.exit_code_observation = Observe-ExitedProcessCode $indexer.native
        $indexer.exit_code = [uint32]$indexer.exit_code_observation.exit_code
        $indexer.termination_proved = $true
        $indexerStdout = $indexer.native.GetOutputText([uint32]$plan.response_timeout_ms)
        $indexerStderr = $indexer.native.GetErrorText([uint32]$plan.response_timeout_ms)
        Write-AstroFsvEventLine $StandardOutputPath ([ordered]@{
            event = 'indexer_completed'; at_utc = $indexer.exited_at_utc
            identity = $indexer.identity; exit_code = $indexer.exit_code
            exit_code_observation = $indexer.exit_code_observation
            stdout_sha256 = String-Sha256 $indexerStdout; stdout = $indexerStdout
        })
        Write-AstroFsvEventLine $StandardErrorPath ([ordered]@{
            event = 'process_stderr'; role = 'indexer'; ordinal = 0
            identity = $indexer.identity; at_utc = [DateTime]::UtcNow.ToString('o')
            stderr_sha256 = String-Sha256 $indexerStderr; stderr = $indexerStderr
        })
        $indexer.stderr_captured = $true
        if (-not [bool]$indexer.exit_code_observation.sources_agree -or
            $indexer.exit_code -ne 0 -or
            $indexerStdout.IndexOf($plan.indexer_expected_substring, [StringComparison]::Ordinal) -lt 0) {
            Fail-Astro 'ASTRO_FSV_COHORT_INDEXER_FAILED' `
                "real indexer did not meet its bound result (exit=$($indexer.exit_code); expected_substring=$($plan.indexer_expected_substring))" `
                'preserve the exact output/store generation and repair the real index mutation'
        }

        $zeroAfterIndexer = Wait-AstroCohortStoreOwners $plan.store_paths @() `
            $plan.holder_timeout_ms 'after-indexer-zero-holders'
        $sidecarsAfterIndexer = Read-AstroCohortAuxiliaryState $plan.store_paths `
            $plan.auxiliary_state_contract $plan.holder_timeout_ms 'after-indexer'
        $storeChronology.Add($zeroAfterIndexer)
        $storeChronology.Add($sidecarsAfterIndexer)
        Write-AstroFsvEventLine $StandardOutputPath ([ordered]@{
            event = 'store_zero_holder_transition'; owner_evidence = $zeroAfterIndexer
            sidecar_evidence = $sidecarsAfterIndexer
        })

        foreach ($state in @($processStates | Where-Object role -ceq 'resident' | Sort-Object ordinal)) {
            $residentResponses.Add((Invoke-AstroCohortRequest `
                $state.native $plan.reopen_request $plan.reopen_expected_substring `
                $plan.response_timeout_ms 'reopen' $state.ordinal $StandardOutputPath))
        }
        $reopenExpectedOwners = Get-AstroCohortExpectedStoreOwners `
            $plan.phase_store_owner_contract.reopen $residentIdentities
        $reopenedOwners = Wait-AstroCohortStoreOwners $plan.store_paths `
            $reopenExpectedOwners $plan.holder_timeout_ms `
            "reopen-$($plan.phase_store_owner_contract.reopen)"
        $storeChronology.Add($reopenedOwners)
        Write-AstroFsvEventLine $StandardOutputPath ([ordered]@{
            event = 'store_owner_snapshot'; phase = 'reopen'
            contract = $plan.phase_store_owner_contract.reopen
            evidence = $reopenedOwners
        })

        foreach ($state in @($processStates | Where-Object role -ceq 'resident' | Sort-Object ordinal)) {
            $state.native.CloseInput()
        }
        foreach ($state in @($processStates | Where-Object role -ceq 'resident' | Sort-Object ordinal)) {
            if (-not $state.native.WaitForExit([uint32]$plan.resident_exit_timeout_ms)) {
                Fail-Astro 'ASTRO_FSV_COHORT_RESIDENT_EXIT_TIMEOUT' `
                    "resident $($state.ordinal) did not exit after stdin EOF within $($plan.resident_exit_timeout_ms) ms" `
                    'preserve the cohort/store chronology and inspect the real resident shutdown path'
            }
            $state.exited_at_utc = [DateTime]::UtcNow.ToString('o')
            $state.exit_code_observation = Observe-ExitedProcessCode $state.native
            $state.exit_code = [uint32]$state.exit_code_observation.exit_code
            $state.termination_proved = $true
            $stderrText = $state.native.GetErrorText([uint32]$plan.response_timeout_ms)
            Write-AstroFsvEventLine $StandardErrorPath ([ordered]@{
                event = 'process_stderr'; role = 'resident'; ordinal = $state.ordinal
                identity = $state.identity; at_utc = $state.exited_at_utc
                exit_code = $state.exit_code
                exit_code_observation = $state.exit_code_observation
                stderr_sha256 = String-Sha256 $stderrText; stderr = $stderrText
            })
            $state.stderr_captured = $true
            if (-not [bool]$state.exit_code_observation.sources_agree -or
                $state.exit_code -ne 0) {
                Fail-Astro 'ASTRO_FSV_COHORT_RESIDENT_EXIT_FAILED' `
                    "resident $($state.ordinal) exited inconsistently or nonzero (exit=$($state.exit_code))" `
                    'preserve the exact output and process observations'
            }
        }
        $finalOwners = Wait-AstroCohortStoreOwners $plan.store_paths @() `
            $plan.holder_timeout_ms 'final-zero-holders'
        $finalSidecars = Read-AstroCohortAuxiliaryState $plan.store_paths `
            $plan.auxiliary_state_contract $plan.holder_timeout_ms 'final'
        $storeChronology.Add($finalOwners)
        $storeChronology.Add($finalSidecars)
        Write-AstroFsvEventLine $StandardOutputPath ([ordered]@{
            event = 'cohort_terminal_store_state'; owner_evidence = $finalOwners
            sidecar_evidence = $finalSidecars
        })

        $artifactHashAfter = File-Sha256 $Artifact
        $receiptHashAfter = File-Sha256 $ReceiptFull
        $planHashAfter = File-Sha256 $plan.path
        $launcherLockSnapshotAfter = Get-AstroExactRetainedFileSnapshot `
            -Handle $LauncherLockHandle -ExpectedPath $LauncherLockPath
        $launcherLockLinksAfter =
            [AstroLauncherLockNative]::GetNumberOfLinks($LauncherLockHandle)
        $launcherOwnerAfter = Read-AstroLauncherLock -LockPath $LauncherLockPath
        $launcherJobProbeAfter = Get-AstroLauncherJobObjectProbe -Name $LauncherJobName
        $launcherJobMembersAfter = [int[]]@($launcherJobProbeAfter.ProcessIds | Sort-Object -Unique)
        $afterRepo = Get-RepoState $GitExe $Workspace
        $treeStable = $BeforeRepo.head_sha -ceq $afterRepo.head_sha -and
            $BeforeRepo.status_sha256 -ceq $afterRepo.status_sha256 -and
            $BeforeRepo.diff_sha256 -ceq $afterRepo.diff_sha256
        $artifactStable = $ArtifactHashBefore -ceq $artifactHashAfter -and
            (Get-AstroFileLengthLongPath $Artifact) -eq [uint64]$Receipt.artifact.bytes
        $receiptStable = $ReceiptHashBefore -ceq $receiptHashAfter
        $planStable = $plan.sha256_before -ceq $planHashAfter
        $launcherLeaseStable = $launcherLockLinksAfter -eq 1 -and
            $LauncherLockSnapshotBefore.FileId -ceq $launcherLockSnapshotAfter.FileId -and
            $LauncherLockSnapshotBefore.Length -eq $launcherLockSnapshotAfter.Length -and
            $LauncherLockHashBefore -ceq [string]$launcherLockSnapshotAfter.Sha256 -and
            [Convert]::ToBase64String($LauncherLockSnapshotBefore.Bytes) -ceq
                [Convert]::ToBase64String($launcherLockSnapshotAfter.Bytes) -and
            $launcherOwnerAfter.State -ceq 'held' -and
            $launcherOwnerAfter.Issue -eq $IssueNumber -and
            $launcherOwnerAfter.OwnerPid -eq $LauncherPid -and
            $launcherOwnerAfter.OwnerProcessStartUtcTicks -eq
                $LauncherOwner.OwnerProcessStartUtcTicks -and
            $launcherJobProbeAfter.State -ceq 'observed' -and
            $launcherJobMembersAfter -contains $LauncherPid -and
            $launcherJobMembersAfter -contains $PID
        if (-not $treeStable -or -not $artifactStable -or -not $receiptStable -or
            -not $planStable -or -not $launcherLeaseStable) {
            Fail-Astro 'ASTRO_FSV_COHORT_STABILITY_FAILED' `
                "cohort immutable-state readback failed (tree=$treeStable; artifact=$artifactStable; receipt=$receiptStable; plan=$planStable; launcher=$launcherLeaseStable)" `
                'preserve the session/store evidence and investigate the exact drifting authority'
        }

        $ArtifactExecutionHandle.Dispose()
        foreach ($state in $processStates) {
            $state.native.Dispose()
            $state.handles_closed = $true
        }
        $ownedPids = [int[]]@(
            @($launcherJobMembersAfter) + @($LauncherPid, $PID) +
            @($processStates | ForEach-Object { [int]$_.identity.pid }) |
                Sort-Object -Unique
        )
        $cleanup = Open-AstroCohortCleanupReadiness $Artifact $artifactHashAfter `
            ([uint64]$Receipt.artifact.bytes) $ownedPids $LauncherJobName
        $cleanupLease = $cleanup.Lease
        $cleanupReadiness = $cleanup.Evidence

        $expectedOwnerEntries = Read-AstroFsvCohortOwnerEntries `
            @(& $ownerEntries) $plan.resident_count $processStates.Count `
            'ASTRO_FSV_LOCK_IDENTITY_CHANGED' 'terminal local cohort process set'
        $lockCleanup = Remove-TerminalFsvCohortLock $FsvLockPath $RunnerIdentity `
            $expectedOwnerEntries $plan.resident_count $ArtifactHashBefore
        $lockOwned = $false
        $stdoutHash = File-Sha256 $StandardOutputPath
        $stderrHash = File-Sha256 $StandardErrorPath
        $record = [ordered]@{
            schema = 'astrolabe.native-fsv-run.v3'
            verdict = 'verified'
            mode = 'resident-cohort'
            issue = $IssueNumber
            receipt_path = $ReceiptFull
            launcher = $LauncherIdentity
            runner = $RunnerIdentity
            resident_count = $plan.resident_count
            process_count = $processStates.Count
            processes = @(& $processRecords)
            artifact = [ordered]@{
                path = $Artifact; bytes = Get-AstroFileLengthLongPath $Artifact
                sha256 = $artifactHashAfter; stable = $artifactStable
                delete_share_denied_for_run = $true
            }
            cleanup_readiness = $cleanupReadiness
            receipt = [ordered]@{
                path = $ReceiptFull; sha256_before = $ReceiptHashBefore
                sha256_after = $receiptHashAfter; stable = $receiptStable
            }
            cohort_plan = [ordered]@{
                path = $plan.path; sha256_before = $plan.sha256_before
                sha256_after = $planHashAfter; stable = $planStable
                phase_store_owner_contract = $plan.phase_store_owner_contract
                auxiliary_state_contract = $plan.auxiliary_state_contract
            }
            live_state = [ordered]@{
                path = $LiveStatePath; published = $true
                bytes = $liveStateBytes; sha256 = $liveStateSha256
            }
            launcher_lease = [ordered]@{
                path = $LauncherLockPath
                file_id_before = $LauncherLockSnapshotBefore.FileId
                file_id_after = $launcherLockSnapshotAfter.FileId
                sha256_before = $LauncherLockHashBefore
                sha256_after = [string]$launcherLockSnapshotAfter.Sha256
                links_before = $LauncherLockLinksBefore
                links_after = $launcherLockLinksAfter
                owner = $LauncherIdentity
                lease_start_utc_ticks = $LauncherOwner.LeaseStartUtcTicks
                job = [ordered]@{
                    name = $LauncherJobName
                    members_before = @($LauncherJobMembersBefore)
                    members_with_suspended_cohort = @($cohortJobMembers)
                    members_after = @($launcherJobMembersAfter)
                    stable = $true
                }
                stable = $launcherLeaseStable
            }
            protocol_evidence = [ordered]@{
                responses = @($residentResponses)
                store_chronology = @($storeChronology)
            }
            stdout = [ordered]@{
                path = $StandardOutputPath
                bytes = Get-AstroFileLengthLongPath $StandardOutputPath
                sha256 = $stdoutHash
            }
            stderr = [ordered]@{
                path = $StandardErrorPath
                bytes = Get-AstroFileLengthLongPath $StandardErrorPath
                sha256 = $stderrHash
            }
            repository = [ordered]@{
                before = $BeforeRepo; after = $afterRepo; stable = $treeStable
            }
            fsv_lock_cleanup = $lockCleanup
        }
        Write-NewDurableUtf8 $RunRecordPath ($record | ConvertTo-Json -Depth 30)
        $persistedRun = Read-AstroUtf8FileLongPath $RunRecordPath | ConvertFrom-Json
        $persistedRunOwners = @($persistedRun.processes | ForEach-Object {
            [ordered]@{ role = $_.role; ordinal = $_.ordinal; identity = $_.identity }
        })
        $persistedRunProcesses = Read-AstroFsvCohortOwnerEntries `
            $persistedRunOwners $plan.resident_count $processStates.Count `
            'ASTRO_FSV_RUN_READBACK_FAILED' 'cohort run-record process set'
        $persistedRunRunner = Read-AstroFsvProcessIdentity $persistedRun.runner `
            'ASTRO_FSV_RUN_READBACK_FAILED' 'cohort run-record runner identity'
        Assert-AstroFsvCohortProcessExitReadback `
            ([object[]]@($persistedRun.processes)) `
            ([object[]]$processStates.ToArray()) `
            'ASTRO_FSV_RUN_READBACK_FAILED' `
            'cohort run-record process set'
        if ([string]$persistedRun.schema -cne 'astrolabe.native-fsv-run.v3' -or
            [string]$persistedRun.verdict -cne 'verified' -or
            [int]$persistedRun.resident_count -ne $plan.resident_count -or
            [int]$persistedRun.process_count -ne $processStates.Count -or
            -not (Test-AstroFsvIdentityEqual $persistedRunRunner $RunnerIdentity) -or
            -not (Test-AstroFsvCohortOwnerEntriesEqual $persistedRunProcesses $expectedOwnerEntries) -or
            [string]$persistedRun.live_state.sha256 -cne $liveStateSha256 -or
            [bool]$persistedRun.fsv_lock_cleanup.after_exists -ne $false) {
            Fail-Astro 'ASTRO_FSV_RUN_READBACK_FAILED' `
                'persisted v3 cohort run record differs from exact observed lifecycle state' `
                'preserve the session and investigate the failed durable write'
        }
        $runRecordWritten = $true
        $record | ConvertTo-Json -Depth 30 -Compress | Write-Output
        return
    }
    catch {
        $cohortFailureInFlight = $true
        $failure = $_
        $allTerminationProved = $true
        foreach ($state in $processStates) {
            if (-not [bool]$state.handles_closed) {
                try { $state.native.CloseInput() } catch {}
                try {
                    if (-not [bool]$state.termination_proved) {
                        if (-not $state.native.HasExited) {
                            $state.native.TerminateAfterCohortFailureAndWait([uint32]30000)
                        }
                        elseif (-not $state.native.WaitForExit([uint32]0)) {
                            throw 'exact process handle was unexpectedly unsignaled'
                        }
                        $state.exited_at_utc = [DateTime]::UtcNow.ToString('o')
                        $state.exit_code_observation = Observe-ExitedProcessCode $state.native
                        $state.exit_code = [uint32]$state.exit_code_observation.exit_code
                        $state.termination_proved = $true
                    }
                }
                catch {
                    $allTerminationProved = $false
                    [Console]::Error.WriteLine("NATIVE_FSV[ASTRO_FSV_COHORT_TERMINATION_UNEVALUABLE]: role=$($state.role); ordinal=$($state.ordinal); identity=$($state.identity | ConvertTo-Json -Compress); error=$($_.Exception.Message)")
                }
            }
            if (-not [bool]$state.termination_proved) { $allTerminationProved = $false }
        }
        if ($allTerminationProved) {
            foreach ($state in $processStates) {
                if ([bool]$state.stderr_captured) { continue }
                try {
                    $stderrText = $state.native.GetErrorText([uint32]$plan.response_timeout_ms)
                    Write-AstroFsvEventLine $StandardErrorPath ([ordered]@{
                        event = 'process_stderr'; role = [string]$state.role
                        ordinal = [int]$state.ordinal; identity = $state.identity
                        at_utc = [DateTime]::UtcNow.ToString('o')
                        exit_code = $state.exit_code
                        exit_code_observation = $state.exit_code_observation
                        stderr_sha256 = String-Sha256 $stderrText; stderr = $stderrText
                        captured_during_failure_recovery = $true
                    })
                    $state.stderr_captured = $true
                }
                catch {
                    [Console]::Error.WriteLine(
                        "NATIVE_FSV[ASTRO_FSV_COHORT_STDERR_CAPTURE_FAILED]: role=$($state.role); ordinal=$($state.ordinal); identity=$($state.identity | ConvertTo-Json -Compress); error=$($_.Exception.Message)"
                    )
                }
            }
        }
        $code = if ($failure.Exception.Data.Contains('AstroCode')) {
            [string]$failure.Exception.Data['AstroCode']
        } else { 'ASTRO_FSV_COHORT_INTERNAL' }
        $remediation = if ($failure.Exception.Data.Contains('AstroRemediation')) {
            [string]$failure.Exception.Data['AstroRemediation']
        } else {
            'preserve the cohort/session/store state and inspect the exact structured failure'
        }
        if ($allTerminationProved -and -not $runRecordWritten -and
            -not (Test-AstroPathLongPath -LiteralPath $RunRecordPath)) {
            try {
                $failureOwnerEntries = Read-AstroFsvCohortOwnerEntries `
                    @(& $ownerEntries) $plan.resident_count $processStates.Count `
                    'ASTRO_FSV_LOCK_IDENTITY_CHANGED' 'failed local cohort process set'
                if ($lockOwned) {
                    try {
                        $lockCleanup = Remove-TerminalFsvCohortLock `
                            $FsvLockPath $RunnerIdentity $failureOwnerEntries `
                            $plan.resident_count $ArtifactHashBefore
                        $lockOwned = $false
                    }
                    catch {
                        $lockCleanup = [ordered]@{
                            path = $FsvLockPath
                            before_exists = Test-AstroPathLongPath -LiteralPath $FsvLockPath
                            removed = $false
                            after_exists = Test-AstroPathLongPath -LiteralPath $FsvLockPath
                            error = $_.Exception.Message
                        }
                    }
                }
                $failureArtifactHash = if (Test-AstroPathLongPath -LiteralPath $Artifact -PathType Leaf) {
                    File-Sha256 $Artifact
                } else { $null }
                $failureRecord = [ordered]@{
                    schema = 'astrolabe.native-fsv-run.v3'
                    verdict = 'failed'
                    mode = 'resident-cohort'
                    issue = $IssueNumber
                    receipt_path = $ReceiptFull
                    launcher = $LauncherIdentity
                    runner = $RunnerIdentity
                    resident_count = $plan.resident_count
                    process_count = $processStates.Count
                    processes = @(& $processRecords)
                    artifact = [ordered]@{
                        path = $Artifact
                        bytes = if (Test-AstroPathLongPath -LiteralPath $Artifact -PathType Leaf) {
                            Get-AstroFileLengthLongPath $Artifact
                        } else { 0 }
                        sha256 = $failureArtifactHash
                        stable = $failureArtifactHash -ceq $ArtifactHashBefore
                    }
                    cohort_plan = [ordered]@{
                        path = $plan.path; sha256_before = $plan.sha256_before
                        sha256_after = if (Test-AstroPathLongPath -LiteralPath $plan.path -PathType Leaf) {
                            File-Sha256 $plan.path
                        } else { $null }
                        phase_store_owner_contract = $plan.phase_store_owner_contract
                        auxiliary_state_contract = $plan.auxiliary_state_contract
                    }
                    live_state = [ordered]@{
                        path = $LiveStatePath; published = $liveStatePublished
                        bytes = if ($liveStatePublished) {
                            Get-AstroFileLengthLongPath $LiveStatePath
                        } else { 0 }
                        sha256 = if ($liveStatePublished) { File-Sha256 $LiveStatePath } else { $null }
                    }
                    stdout = [ordered]@{
                        path = $StandardOutputPath
                        bytes = if (Test-AstroPathLongPath -LiteralPath $StandardOutputPath -PathType Leaf) {
                            Get-AstroFileLengthLongPath $StandardOutputPath
                        } else { 0 }
                        sha256 = if (Test-AstroPathLongPath -LiteralPath $StandardOutputPath -PathType Leaf) {
                            File-Sha256 $StandardOutputPath
                        } else { $null }
                    }
                    stderr = [ordered]@{
                        path = $StandardErrorPath
                        bytes = if (Test-AstroPathLongPath -LiteralPath $StandardErrorPath -PathType Leaf) {
                            Get-AstroFileLengthLongPath $StandardErrorPath
                        } else { 0 }
                        sha256 = if (Test-AstroPathLongPath -LiteralPath $StandardErrorPath -PathType Leaf) {
                            File-Sha256 $StandardErrorPath
                        } else { $null }
                    }
                    protocol_evidence = [ordered]@{
                        responses = @($residentResponses)
                        store_chronology = @($storeChronology)
                    }
                    fsv_lock_cleanup = $lockCleanup
                    failure = [ordered]@{
                        code = $code; message = $failure.Exception.Message
                        remediation = $remediation
                        exception_type = $failure.Exception.GetType().FullName
                        script_stack_trace = Failure-Text $failure.ScriptStackTrace
                        invocation = Failure-Text $failure.InvocationInfo.PositionMessage
                    }
                }
                Write-NewDurableUtf8 $RunRecordPath ($failureRecord | ConvertTo-Json -Depth 30)
                $persistedFailure = Read-AstroUtf8FileLongPath $RunRecordPath | ConvertFrom-Json
                if ([string]$persistedFailure.schema -cne 'astrolabe.native-fsv-run.v3' -or
                    [string]$persistedFailure.failure.code -cne $code -or
                    [int]$persistedFailure.process_count -ne $processStates.Count) {
                    throw 'persisted v3 cohort failure record differs from exact observed state'
                }
                Assert-AstroFsvCohortProcessExitReadback `
                    ([object[]]@($persistedFailure.processes)) `
                    ([object[]]$processStates.ToArray()) `
                    'ASTRO_FSV_COHORT_FAILURE_RECORD_READBACK_FAILED' `
                    'cohort failure-record process set'
                $runRecordWritten = $true
            }
            catch {
                [Console]::Error.WriteLine("NATIVE_FSV[ASTRO_FSV_COHORT_FAILURE_RECORD_WRITE_FAILED]: $($_.Exception.Message)")
            }
        }
        [Console]::Error.WriteLine(([ordered]@{
            code = $code; message = $failure.Exception.Message
            remediation = $remediation; process_count = $processStates.Count
            all_termination_proved = $allTerminationProved
            lock_preserved = Test-AstroPathLongPath -LiteralPath $FsvLockPath
            run_record_written = $runRecordWritten
        } | ConvertTo-Json -Compress))
        throw $failure.Exception
    }
    finally {
        $disposeFailures = [Collections.Generic.List[object]]::new()
        foreach ($state in $processStates) {
            if (-not [bool]$state.handles_closed) {
                try {
                    $state.native.Dispose()
                    $state.handles_closed = $true
                }
                catch {
                    $disposeFailures.Add([ordered]@{
                        kind = 'cohort-process-handle'
                        role = [string]$state.role
                        ordinal = [int]$state.ordinal
                        identity = $state.identity
                        error = $_.Exception.Message
                    })
                }
            }
        }
        if ($null -ne $cleanupLease) {
            try { $cleanupLease.Dispose() }
            catch {
                $disposeFailures.Add([ordered]@{
                    kind = 'artifact-cleanup-readiness-lease'
                    path = $Artifact
                    error = $_.Exception.Message
                })
            }
        }
        if ($disposeFailures.Count -ne 0) {
            $diagnostic = $disposeFailures | ConvertTo-Json -Depth 10 -Compress
            if ($cohortFailureInFlight) {
                [Console]::Error.WriteLine(
                    "NATIVE_FSV[ASTRO_FSV_COHORT_SECONDARY_DISPOSE_FAILED]: $diagnostic"
                )
            }
            else {
                Fail-Astro 'ASTRO_FSV_COHORT_DISPOSE_FAILED' `
                    "cohort completed but exact retained-handle disposal failed: $diagnostic" `
                    'preserve the session and inspect the exact retained owner/handle state'
            }
        }
    }
}

$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$evidenceRoot = Join-Path $workspace '.tmp\native-fsv-artifacts'
$launcherLockPath = Join-Path (Join-Path $workspace '.tmp') 'astrolabe-launcher.lock'
$fsvLockPath = Join-Path (Join-Path $workspace '.tmp') 'astrolabe-fsv.lock'
$gitExe = 'C:\Program Files\Git\bin\git.exe'
$artifactHandle = $null
$receiptHandle = $null
$launcherLockHandle = $null
$launcherLockSnapshotBefore = $null
$launcherJobName = $null
$launcherJobProbeBefore = $null
$directoryHandle = $null
$artifactCleanupLease = $null
$artifactCleanupReadiness = $null
$fsvLockOwned = $false
$child = $null
$childStartedAtUtc = $null
$childExitedAtUtc = $null
$childExitCode = $null
$childExitObservation = $null
$childExitObservationError = $null
$childProcessHandle = $null
$childObservationHandle = $null
$createdChild = $null
$childTerminationUncertain = $false
$childTerminationProved = $false
$childProcessHandlesClosed = $false
$artifact = $null
$artifactHashBefore = $null
$receiptFull = $null
$launcherIdentity = $null
$runnerIdentity = $null
$childIdentity = $null
$runRecordWritten = $false
$runRecordAuthorized = $false
$fsvLockCleanup = $null
$arguments = [string[]]::new(0)
$argumentCount = 0
$argumentSource = $null
$argumentsFileHandle = $null
$bindCleanupDiagnostic = $null

try {
    if ($Issue -le 0) { Fail-Astro 'ASTRO_FSV_ISSUE_INVALID' 'Issue must be positive' 'pass the driving GitHub issue number' }
    if (-not (Test-AstroPathLongPath -LiteralPath $gitExe -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_GIT_MISSING' "required native Git executable is absent: $gitExe" 'restore the canonical Git for Windows installation'
    }
    $receiptFull = Assert-PathWithin $ReceiptPath $evidenceRoot 'ASTRO_FSV_RECEIPT_ESCAPE' 'receipt path'
    if (-not (Test-AstroPathLongPath -LiteralPath $receiptFull -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_MISSING' "receipt does not exist: $receiptFull" 'stage the native artifact first'
    }
    try { $receipt = Read-AstroUtf8FileLongPath $receiptFull | ConvertFrom-Json }
    catch { Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' "parse receipt failed: $($_.Exception.Message)" 'stage a fresh native artifact' }
    if ($receipt.schema -eq 'astrolabe.native-fsv-artifact.v1') {
        Fail-Astro 'ASTRO_FSV_RECEIPT_LEGACY_MIGRATION_REQUIRED' `
            'receipt uses legacy PID-only schema v1' `
            'preserve the session and use the tracker-bound MigrateLegacy lifecycle; never infer process generations'
    }
    if ($receipt.schema -ne 'astrolabe.native-fsv-artifact.v2' -or
        [int]$receipt.issue -ne $Issue -or
        -not $receipt.PSObject.Properties['owners'] -or
        -not $receipt.owners.PSObject.Properties['launcher'] -or
        -not $receipt.owners.PSObject.Properties['promoter']) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' "receipt schema/issue does not match issue #$Issue" 'pass the exact receipt emitted for this driving issue'
    }
    $receiptLauncherIdentity = Read-AstroFsvProcessIdentity `
        $receipt.owners.launcher `
        'ASTRO_FSV_RECEIPT_INVALID' `
        'artifact receipt launcher identity'
    $receiptPromoterIdentity = Read-AstroFsvProcessIdentity `
        $receipt.owners.promoter `
        'ASTRO_FSV_RECEIPT_INVALID' `
        'artifact receipt promoter identity'
    if ([string]$receipt.tree_sha -notmatch '^[0-9a-f]{40}$' -or
        [string]$receipt.artifact.sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$receipt.session_id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') {
        Fail-Astro 'ASTRO_FSV_RECEIPT_INVALID' 'receipt contains invalid tree/hash/session identity fields' 'discard the invalid session and stage a fresh artifact'
    }
    $sessionDirectory = Split-Path -Parent $receiptFull
    $expectedSessionDirectory = Join-Path (Join-Path (Join-Path $evidenceRoot ([string]$receipt.tree_sha)) `
        ([string]$receipt.artifact.sha256)) ([string]$receipt.session_id)
    if (-not [string]::Equals([IO.Path]::GetFullPath($sessionDirectory), [IO.Path]::GetFullPath($expectedSessionDirectory), [StringComparison]::OrdinalIgnoreCase)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_PATH_MISMATCH' 'receipt path does not match its tree/hash/session identity' 'discard the relocated receipt and stage a fresh artifact'
    }
    Assert-NotReparseEntry $receiptFull 'evidence receipt'
    Assert-NotReparseEntry $sessionDirectory 'evidence session directory'
    $artifact = Assert-PathWithin ([string]$receipt.artifact.path) $sessionDirectory 'ASTRO_FSV_ARTIFACT_ESCAPE' 'artifact path'
    if (-not (Test-AstroPathLongPath -LiteralPath $artifact -PathType Leaf)) {
        Fail-Astro 'ASTRO_FSV_ARTIFACT_MISSING' "staged artifact is absent: $artifact" 'stage a fresh native artifact'
    }
    Assert-NotReparseEntry $artifact 'staged native artifact'
    $pristineEntries = @(
        Get-AstroDirectoryEntriesLongPath $sessionDirectory
    )
    $expectedPristinePaths = @(
        [IO.Path]::GetFullPath($receiptFull),
        [IO.Path]::GetFullPath($artifact)
    )
    $pristinePaths = @(
        $pristineEntries | ForEach-Object {
            if ($_.PSIsContainer -or
                ($_.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail-Astro 'ASTRO_FSV_SESSION_NONPRISTINE' `
                    "staged session contains a directory or reparse entry before its one allowed run: $($_.FullName)" `
                    'preserve the session and use its exact completed, abandoned, or quarantine lifecycle'
            }
            [IO.Path]::GetFullPath($_.FullName)
        }
    )
    if ($pristinePaths.Count -ne $expectedPristinePaths.Count -or
        @($expectedPristinePaths | Where-Object {
                $expected = $_
                -not @($pristinePaths | Where-Object {
                        [string]::Equals(
                            $_,
                            $expected,
                            [StringComparison]::OrdinalIgnoreCase
                        )
                    }).Count
            }).Count -ne 0) {
        Fail-Astro 'ASTRO_FSV_SESSION_NONPRISTINE' `
            "staged session is not the exact two-file pre-run state (entries=$($pristinePaths -join '; '))" `
            'each staged session permits exactly one run; stage a fresh session for another invocation'
    }
    $claimedPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    [void]$claimedPaths.Add([IO.Path]::GetFullPath($receiptFull))
    [void]$claimedPaths.Add([IO.Path]::GetFullPath($artifact))
    foreach ($pair in @(
        @($StandardOutputPath, 'stdout'), @($StandardErrorPath, 'stderr'),
        @($RunRecordPath, 'run record'), @($LiveStatePath, 'live state')
    )) {
        $resolved = Assert-DirectSessionRootOutputPath ([string]$pair[0]) $sessionDirectory ([string]$pair[1])
        if (-not $claimedPaths.Add($resolved)) {
            Fail-Astro 'ASTRO_FSV_OUTPUT_COLLISION' `
                "$($pair[1]) path collides with another immutable session path: $resolved" `
                'use four distinct fresh direct session-root output file paths'
        }
        if (Test-AstroPathLongPath -LiteralPath $resolved) {
            Fail-Astro 'ASTRO_FSV_OUTPUT_REUSE_REFUSED' "$($pair[1]) already exists: $resolved" 'use fresh direct session-root output paths; FSV state is append-only and never overwritten'
        }
        switch ([string]$pair[1]) {
            'stdout' { $StandardOutputPath = $resolved }
            'stderr' { $StandardErrorPath = $resolved }
            'run record' { $RunRecordPath = $resolved }
            'live state' { $LiveStatePath = $resolved }
        }
    }
    $runRecordAuthorized = $true

    $launcherOwner = Read-AstroLauncherLock -LockPath $launcherLockPath
    $launcherPid = if ($null -ne $launcherOwner.OwnerPid) {
        [int]$launcherOwner.OwnerPid
    } else {
        0
    }
    if ($launcherOwner.State -ne 'held' -or
        $launcherOwner.Issue -ne $Issue) {
        Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_INVALID' "launcher protocol does not name the exact live owner process identity for issue #$Issue (state=$($launcherOwner.State), pid=$launcherPid, process_start_utc_ticks=$($launcherOwner.OwnerProcessStartUtcTicks), read_error=$($launcherOwner.ReadError), validation_error=$($launcherOwner.ValidationError))" 'start the FSV through the native launcher with the same driving issue'
    }
    $launcherIdentity = New-AstroProcessIdentityRecord `
        $launcherPid ([long]$launcherOwner.OwnerProcessStartUtcTicks)
    if (-not (Test-AstroFsvIdentityEqual `
            $launcherIdentity $receiptLauncherIdentity)) {
        Fail-Astro 'ASTRO_FSV_RECEIPT_LAUNCHER_MISMATCH' `
            'receipt launcher generation differs from the exact live launcher lease' `
            'discard the cross-lease session and stage under the current exact launcher'
    }
    if (-not (Test-DescendantOf $PID $launcherPid)) {
        Fail-Astro 'ASTRO_FSV_RUNNER_NOT_OWNED' "runner PID $PID is not a descendant of launcher PID $launcherPid" 'invoke this runner synchronously from the launcher-owned child process'
    }
    $runnerIdentity = Get-AstroCurrentProcessIdentity `
        $PID `
        'ASTRO_FSV_RUNNER_IDENTITY_UNEVALUABLE' `
        'native FSV runner'
    try {
        $launcherRootIdentity =
            [AstroLauncherLockNative]::GetDirectoryIdentity($workspace)
        $launcherJobName = Get-AstroLauncherTreeJobObjectName `
            -RootIdentity $launcherRootIdentity `
            -LauncherPid $launcherPid `
            -LauncherProcessStartUtcTicks ([long]$launcherOwner.OwnerProcessStartUtcTicks) `
            -LauncherLeaseStartUtcTicks ([long]$launcherOwner.LeaseStartUtcTicks) `
            -LauncherLockSha256 ([string]$launcherOwner.Sha256)
        $launcherJobProbeBefore =
            Get-AstroLauncherJobObjectProbe -Name $launcherJobName
    }
    catch {
        Fail-Astro 'ASTRO_FSV_LAUNCHER_JOB_UNEVALUABLE' "could not derive and query the exact launcher Job Object: $($_.Exception.Message)" 'preserve the staged session and repair exact launcher Job attribution before running an artifact'
    }
    $launcherJobMembersBefore =
        [int[]]@($launcherJobProbeBefore.ProcessIds | Sort-Object -Unique)
    if ($launcherJobProbeBefore.State -cne 'observed' -or
        $launcherJobMembersBefore -notcontains $launcherPid -or
        $launcherJobMembersBefore -notcontains $PID) {
        Fail-Astro 'ASTRO_FSV_LAUNCHER_JOB_MISMATCH' "exact launcher Job does not contain both launcher PID $launcherPid and runner PID $PID (name=$launcherJobName, state=$($launcherJobProbeBefore.State), members=$($launcherJobMembersBefore -join ','), error=$($launcherJobProbeBefore.Error))" 'invoke the runner only as a non-breakaway descendant of the exact live launcher owner'
    }

    $beforeRepo = Get-RepoState $gitExe $workspace
    if ($beforeRepo.head_sha -cne ([string]$receipt.tree_sha).ToLowerInvariant()) {
        Fail-Astro 'ASTRO_FSV_TREE_MISMATCH' "current HEAD $($beforeRepo.head_sha) differs from staged tree $($receipt.tree_sha)" 'discard the session and rebuild from the current frozen tree'
    }
    if ($null -eq $receipt.repository -or
        [string]$receipt.repository.status_sha256 -cne [string]$beforeRepo.status_sha256 -or
        [string]$receipt.repository.diff_sha256 -cne [string]$beforeRepo.diff_sha256 -or
        [string]$launcherOwner.HeadSha -cne [string]$beforeRepo.head_sha -or
        [string]$launcherOwner.StatusSha256 -cne [string]$beforeRepo.status_sha256 -or
        [string]$launcherOwner.DiffSha256 -cne [string]$beforeRepo.diff_sha256) {
        Fail-Astro 'ASTRO_FSV_REPOSITORY_IDENTITY_MISMATCH' "receipt, live launcher lock, and current repository fingerprints do not identify the same frozen state (receipt_status_sha256=$($receipt.repository.status_sha256), launcher_status_sha256=$($launcherOwner.StatusSha256), current_status_sha256=$($beforeRepo.status_sha256), receipt_diff_sha256=$($receipt.repository.diff_sha256), launcher_diff_sha256=$($launcherOwner.DiffSha256), current_diff_sha256=$($beforeRepo.diff_sha256))" 'discard the artifact and rebuild under a fresh immutable launcher lease'
    }
    $artifactHashBefore = File-Sha256 $artifact
    $receiptHashBefore = File-Sha256 $receiptFull
    try {
        # The launcher's authoritative handle has GENERIC_READ|GENERIC_WRITE|DELETE
        # access while sharing only reads. This read-only classifier handle must
        # therefore share read/write/delete to admit that already-open authority.
        # The launcher's original FILE_SHARE_READ still denies every new writer,
        # rename, and delete opener for the complete runner lifetime.
        $launcherLockHandle =
            [AstroLauncherLockNative]::OpenExactClassifierReadFile($launcherLockPath)
        $launcherLockSnapshotBefore = Get-AstroExactRetainedFileSnapshot `
            -Handle $launcherLockHandle `
            -ExpectedPath $launcherLockPath
        $launcherLockLinksBefore =
            [AstroLauncherLockNative]::GetNumberOfLinks($launcherLockHandle)
    }
    catch {
        Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_RETAIN_FAILED' "could not retain a read-only exact snapshot of the live launcher lease: $($_.Exception.Message)" 'preserve the staged session and repair the live-lock share/identity contract before running an artifact'
    }
    if ($launcherLockLinksBefore -ne 1 -or
        $launcherLockSnapshotBefore.Sha256 -cne [string]$launcherOwner.Sha256 -or
        $launcherLockSnapshotBefore.Length -ne [uint64]$launcherOwner.Length) {
        Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_MISMATCH' "retained live launcher-lock identity differs from its authoritative classifier snapshot (links=$launcherLockLinksBefore, retained_sha256=$($launcherLockSnapshotBefore.Sha256), classified_sha256=$($launcherOwner.Sha256))" 'preserve all state and investigate launcher-lock replacement, aliasing, or byte drift'
    }
    $launcherLockHashBefore = [string]$launcherLockSnapshotBefore.Sha256
    $artifactItem = Get-AstroFileInfoLongPath $artifact
    if ($artifactHashBefore -cne ([string]$receipt.artifact.sha256).ToLowerInvariant() -or
        [uint64]$artifactItem.Length -ne [uint64]$receipt.artifact.bytes) {
        Fail-Astro 'ASTRO_FSV_ARTIFACT_DRIFT' 'staged artifact hash/length differs from its receipt before launch' 'discard the session, identify the writer, and rebuild'
    }

    if ($PSCmdlet.ParameterSetName -ceq 'SingleInline' -or
        $PSCmdlet.ParameterSetName -ceq 'SingleFile') {
        if ($PSCmdlet.ParameterSetName -ceq 'SingleFile') {
            $argumentFile = Open-AstroFsvArgumentJsonFile `
                -Path $ArgumentsJsonPath -Workspace $workspace
            $argumentsFileHandle = $argumentFile.Handle
            $argumentJsonValue = [string]$argumentFile.Json
            $argumentSource = [ordered]@{
                kind = 'strict-utf8-json-file'
                path = [string]$argumentFile.Path
                bytes = [uint64]$argumentFile.Bytes
                sha256_before = [string]$argumentFile.Sha256
                sha256_after = $null
                stable = $false
            }
        }
        else {
            $argumentJsonValue = $ArgumentsJson
            $argumentJsonBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($ArgumentsJson)
            $argumentJsonHash = ByteArray-Sha256 $argumentJsonBytes
            $argumentSource = [ordered]@{
                kind = 'inline-json'
                path = $null
                bytes = [uint64]$argumentJsonBytes.Length
                sha256_before = $argumentJsonHash
                sha256_after = $argumentJsonHash
                stable = $true
            }
        }
        $argumentVector = ConvertFrom-FlatStringArrayJson $argumentJsonValue
        $argumentCount = [int]$argumentVector.Count
        $arguments = [string[]]@($argumentVector.Values)
        if ($arguments.Length -ne $argumentCount) {
            Fail-Astro 'ASTRO_FSV_ARGUMENTS_INVALID' 'ArgumentsJson cardinality changed during parsing' 'preserve the invocation and investigate the PowerShell JSON runtime'
        }
        $argumentLine = if ($argumentCount -gt 0) {
            (@($arguments | ForEach-Object { ConvertTo-WindowsCommandLineArgument ([string]$_) }) -join ' ')
        } else {
            $null
        }
    }

    # FileShare.Read intentionally omits write/delete sharing. Microsoft documents that a
    # subsequent delete/rename open then fails until this handle is closed.
    $directoryHandle = [AstroFsvAtomicFile]::OpenDirectoryWithoutDeleteShare($sessionDirectory)
    $artifactHandle = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $artifact),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $receiptHandle = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $receiptFull),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    if ($PSCmdlet.ParameterSetName -ceq 'ResidentCohort') {
        Invoke-AstroResidentCohort `
            -PlanPath $CohortPlanPath `
            -Workspace $workspace `
            -IssueNumber $Issue `
            -SessionDirectory $sessionDirectory `
            -ReceiptFull $receiptFull `
            -Receipt $receipt `
            -Artifact $artifact `
            -ArtifactHashBefore $artifactHashBefore `
            -ReceiptHashBefore $receiptHashBefore `
            -ArtifactItem $artifactItem `
            -LauncherIdentity $launcherIdentity `
            -RunnerIdentity $runnerIdentity `
            -LauncherPid $launcherPid `
            -LauncherOwner $launcherOwner `
            -LauncherLockPath $launcherLockPath `
            -LauncherLockHandle $launcherLockHandle `
            -LauncherLockSnapshotBefore $launcherLockSnapshotBefore `
            -LauncherLockLinksBefore $launcherLockLinksBefore `
            -LauncherLockHashBefore $launcherLockHashBefore `
            -LauncherJobName $launcherJobName `
            -LauncherJobMembersBefore $launcherJobMembersBefore `
            -BeforeRepo $beforeRepo `
            -GitExe $gitExe `
            -ArtifactExecutionHandle $artifactHandle `
            -FsvLockPath $fsvLockPath `
            -StandardOutputPath $StandardOutputPath `
            -StandardErrorPath $StandardErrorPath `
            -RunRecordPath $RunRecordPath `
            -LiveStatePath $LiveStatePath
        return
    }
    $lockManifest = [ordered]@{
        schema = 'astrolabe.native-fsv-lock.v2'
        issue = $Issue
        started = [DateTime]::UtcNow.ToString('o')
        command = if ($argumentCount -gt 0) { "$artifact $argumentLine" } else { $artifact }
        argument_count = $argumentCount
        arguments = @($arguments)
        argument_source = $argumentSource
        tree_sha = [string]$receipt.tree_sha
        artifact_path = $artifact
        artifact_sha256 = $artifactHashBefore
        owners = [ordered]@{
            launcher = $launcherIdentity
            runner = $runnerIdentity
            child = $null
        }
        launcher_job = [ordered]@{
            name = $launcherJobName
            members = @($launcherJobMembersBefore)
        }
        phase = 'claimed'
    }
    $admissionLease = Enter-AstroFsvAdmissionLease $workspace
    try {
        Assert-AstroFsvLifecycleAdmissionClear $workspace
        $lockStage = "$fsvLockPath.$PID.tmp"
        Write-NewDurableUtf8 $lockStage ($lockManifest | ConvertTo-Json -Depth 10 -Compress)
        try { [AstroFsvAtomicFile]::PublishNoClobber($lockStage, $fsvLockPath) }
        catch {
            if (Test-AstroPathLongPath -LiteralPath $lockStage -PathType Leaf) {
                Remove-AstroFileLongPath $lockStage
            }
            Fail-Astro 'ASTRO_FSV_LOCK_HELD' "FSV lock could not be claimed without clobbering: $fsvLockPath" 'wait for the live owner or post dead-owner evidence before removing a stale lock'
        }
        $fsvLockOwned = $true
    }
    finally {
        Exit-AstroFsvLifecycleMutex $admissionLease
    }

    $commandLine = ConvertTo-WindowsCommandLineArgument $artifact
    if ($argumentCount -gt 0) {
        $commandLine += " $argumentLine"
    }
    try {
        $createdChild = [AstroFsvNativeProcess]::CreateSuspended(
            $artifact,
            $commandLine,
            $StandardOutputPath,
            $StandardErrorPath
        )
    }
    catch {
        Fail-Astro 'ASTRO_FSV_CHILD_CREATE_FAILED' "direct native process creation failed before a child identity was returned: $($_.Exception.Message)" 'preserve the staged session, inspect the native operation/error/path diagnostics, and repair the exact process-creation boundary before rerunning'
    }
    $childProcessHandle = $createdChild.ProcessHandle
    $childObservationHandle = $createdChild.ObservationHandle
    $child = $createdChild
    try {
        [void]$createdChild.BindAndResume()
    }
    catch {
        $bindFailure = $_
        $bindFailureDiagnostic = [ordered]@{
            message = $bindFailure.Exception.Message
            exception_type = $bindFailure.Exception.GetType().FullName
            native_error = Get-AstroNativeErrorCode $bindFailure.Exception
            script_stack_trace = Failure-Text $bindFailure.ScriptStackTrace
            invocation = Failure-Text $bindFailure.InvocationInfo.PositionMessage
        }
        [uint64]$expectedBindExitCode =
            [AstroFsvCreatedProcess]::BindFailureExitCode
        $expectedBindExitCodeHex = '0x{0:X8}' -f $expectedBindExitCode
        try {
            $createdChild.TerminateAfterBindFailureAndWait([uint32]30000)
        }
        catch {
            $childTerminationUncertain = $true
            $bindCleanupDiagnostic = [ordered]@{
                bind_failure = $bindFailureDiagnostic
                termination = [ordered]@{
                    operation = 'TerminateAfterBindFailureAndWait'
                    expected_exit_code = $expectedBindExitCode
                    expected_exit_code_hex = $expectedBindExitCodeHex
                    proved = $false
                    failure = [ordered]@{
                        message = $_.Exception.Message
                        exception_type = $_.Exception.GetType().FullName
                        native_error = Get-AstroNativeErrorCode $_.Exception
                    }
                }
                outputs_preserved = $true
            }
            Fail-Astro 'ASTRO_FSV_CHILD_BIND_CLEANUP_FAILED' `
                "exact child PID $($createdChild.ProcessId) could not be bound/resumed and exact termination could not be proved (diagnostic=$($bindCleanupDiagnostic | ConvertTo-Json -Depth 10 -Compress))" `
                'preserve the launcher/FSV state and use exact process/Job attribution before any cleanup'
        }

        $childTerminationProved = $true
        $childExitedAtUtc = [DateTime]::UtcNow.ToString('o')
        try {
            $childExitObservation = Observe-ExitedProcessCode $createdChild
            $childExitCode = [uint32]$childExitObservation.exit_code
        }
        catch {
            $childExitObservationError = $_.Exception.Message
            $bindCleanupDiagnostic = [ordered]@{
                bind_failure = $bindFailureDiagnostic
                termination = [ordered]@{
                    operation = 'TerminateAfterBindFailureAndWait'
                    expected_exit_code = $expectedBindExitCode
                    expected_exit_code_hex = $expectedBindExitCodeHex
                    proved = $true
                    observation_error = $childExitObservationError
                }
                outputs_preserved = $true
            }
            Fail-Astro 'ASTRO_FSV_CHILD_BIND_EXIT_OBSERVATION_FAILED' `
                "exact child PID $($createdChild.ProcessId) termination completed after bind/resume failure, but durable exit observation failed (diagnostic=$($bindCleanupDiagnostic | ConvertTo-Json -Depth 10 -Compress))" `
                'preserve the FSV lock/session and repair exact retained-handle exit observation'
        }
        $normalizedBindObservation = Read-AstroFsvExitCodeObservation `
            $childExitObservation `
            'ASTRO_FSV_CHILD_BIND_EXIT_OBSERVATION_INVALID' `
            'bind-failure cleanup exit observation'
        $bindCleanupDiagnostic = [ordered]@{
            bind_failure = $bindFailureDiagnostic
            termination = [ordered]@{
                operation = 'TerminateAfterBindFailureAndWait'
                expected_exit_code = $expectedBindExitCode
                expected_exit_code_hex = $expectedBindExitCodeHex
                proved = $true
                observation = $normalizedBindObservation
            }
            outputs_preserved = $true
        }
        if (-not [bool]$normalizedBindObservation.sources_agree -or
            [uint64]$normalizedBindObservation.exit_code -ne
                $expectedBindExitCode) {
            Fail-Astro 'ASTRO_FSV_CHILD_BIND_CLEANUP_STATUS_MISMATCH' `
                "exact child PID $($createdChild.ProcessId) terminated after bind/resume failure with a different retained-handle status (diagnostic=$($bindCleanupDiagnostic | ConvertTo-Json -Depth 10 -Compress))" `
                'preserve the FSV lock/session and investigate the exact child lifecycle transition'
        }
        Fail-Astro 'ASTRO_FSV_CHILD_BIND_FAILED' `
            "exact child PID $($createdChild.ProcessId) was created suspended but binding/resume failed; exact termination and dual-handle status readback completed (diagnostic=$($bindCleanupDiagnostic | ConvertTo-Json -Depth 10 -Compress))" `
            'preserve the durable failed-run record and repair native process binding before rerunning'
    }
    if ($null -eq $childProcessHandle -or $childProcessHandle.IsInvalid -or $childProcessHandle.IsClosed) {
        Fail-Astro 'ASTRO_FSV_CHILD_HANDLE_UNAVAILABLE' "native child PID $($child.Id) did not retain its exact CreateProcessW process handle" 'preserve the session and repair native process launch before rerunning'
    }
    if ($null -eq $childObservationHandle -or
        $childObservationHandle.IsInvalid -or
        $childObservationHandle.IsClosed) {
        Fail-Astro 'ASTRO_FSV_CHILD_HANDLE_UNAVAILABLE' "native child PID $($child.Id) did not retain a duplicated handle to its exact CreateProcessW process object" 'preserve the session and repair exact process-handle duplication before rerunning'
    }
    $childStartedAtUtc = [DateTime]::UtcNow.ToString('o')
    $ownedLock = Read-AstroUtf8FileLongPath $fsvLockPath | ConvertFrom-Json
    if ($ownedLock.schema -cne 'astrolabe.native-fsv-lock.v2' -or
        -not $ownedLock.PSObject.Properties['owners'] -or
        -not $ownedLock.owners.PSObject.Properties['launcher'] -or
        -not $ownedLock.owners.PSObject.Properties['runner'] -or
        -not $ownedLock.owners.PSObject.Properties['child']) {
        Fail-Astro 'ASTRO_FSV_LOCK_IDENTITY_CHANGED' `
            'claimed FSV lock omits its exact owner envelope' `
            'preserve state and investigate the competing or incomplete writer'
    }
    $ownedLockLauncherIdentity = Read-AstroFsvProcessIdentity `
        $ownedLock.owners.launcher `
        'ASTRO_FSV_LOCK_IDENTITY_CHANGED' `
        'claimed FSV lock launcher identity'
    $ownedLockRunnerIdentity = Read-AstroFsvProcessIdentity `
        $ownedLock.owners.runner `
        'ASTRO_FSV_LOCK_IDENTITY_CHANGED' `
        'claimed FSV lock runner identity'
    if ($null -ne $ownedLock.owners.child -or
        -not (Test-AstroFsvIdentityEqual `
            $ownedLockLauncherIdentity $launcherIdentity) -or
        -not (Test-AstroFsvIdentityEqual `
            $ownedLockRunnerIdentity $runnerIdentity) -or
        [string]$ownedLock.artifact_sha256 -cne $artifactHashBefore) {
        Fail-Astro 'ASTRO_FSV_LOCK_IDENTITY_CHANGED' 'FSV lock identity changed before child PID publication' 'preserve state and investigate the competing writer'
    }
    $childIdentity = New-AstroProcessIdentityRecord `
        $child.Id ([long]$child.ProcessStartUtcTicks)
    $lockManifest.owners.child = $childIdentity
    $lockManifest.phase = 'running'
    $lockUpdateStage = "$fsvLockPath.$PID.running.tmp"
    Write-NewDurableUtf8 $lockUpdateStage ($lockManifest | ConvertTo-Json -Depth 10 -Compress)
    try { [AstroFsvAtomicFile]::ReplaceOwned($lockUpdateStage, $fsvLockPath) }
    catch {
        if (Test-AstroPathLongPath -LiteralPath $lockUpdateStage -PathType Leaf) {
            Remove-AstroFileLongPath $lockUpdateStage
        }
        Fail-Astro 'ASTRO_FSV_LOCK_UPDATE_FAILED' "publishing child PID $($child.Id) into the FSV lock failed: $($_.Exception.Message)" 'preserve state and investigate the lock writer'
    }
    $publishedLock =
        Read-AstroUtf8FileLongPath $fsvLockPath | ConvertFrom-Json
    if ($null -eq $publishedLock -or
        -not $publishedLock.PSObject.Properties['schema'] -or
        [string]$publishedLock.schema -cne
            'astrolabe.native-fsv-lock.v2' -or
        -not $publishedLock.PSObject.Properties['owners'] -or
        $null -eq $publishedLock.owners -or
        -not $publishedLock.owners.PSObject.Properties['launcher'] -or
        -not $publishedLock.owners.PSObject.Properties['runner'] -or
        -not $publishedLock.owners.PSObject.Properties['child']) {
        Fail-Astro 'ASTRO_FSV_LOCK_UPDATE_FAILED' `
            'published FSV lock omits its v2 exact owner envelope' `
            'preserve state and investigate the failed durable lock update'
    }
    $publishedLauncherIdentity = Read-AstroFsvProcessIdentity `
        $publishedLock.owners.launcher `
        'ASTRO_FSV_LOCK_UPDATE_FAILED' `
        'published FSV lock launcher identity'
    $publishedRunnerIdentity = Read-AstroFsvProcessIdentity `
        $publishedLock.owners.runner `
        'ASTRO_FSV_LOCK_UPDATE_FAILED' `
        'published FSV lock runner identity'
    $publishedChildIdentity = Read-AstroFsvProcessIdentity `
        $publishedLock.owners.child `
        'ASTRO_FSV_LOCK_UPDATE_FAILED' `
        'published FSV lock child identity'
    if (-not (Test-AstroFsvIdentityEqual `
            $publishedLauncherIdentity $launcherIdentity) -or
        -not (Test-AstroFsvIdentityEqual `
            $publishedRunnerIdentity $runnerIdentity) -or
        -not (Test-AstroFsvIdentityEqual `
            $publishedChildIdentity $childIdentity) -or
        [string]$publishedLock.phase -cne 'running') {
        Fail-Astro 'ASTRO_FSV_LOCK_UPDATE_FAILED' 'FSV lock child-PID readback does not match the real process' 'preserve state and investigate the durable lock write'
    }
    $liveState = [ordered]@{
        schema = 'astrolabe.native-fsv-live.v2'
        owners = [ordered]@{
            launcher = $launcherIdentity
            runner = $runnerIdentity
            child = $childIdentity
        }
        launcher_job = [ordered]@{
            name = $launcherJobName
            members_before = @($launcherJobMembersBefore)
        }
        issue = $Issue
        tree_sha = [string]$receipt.tree_sha
        artifact = [ordered]@{ path = $artifact; bytes = [uint64]$artifactItem.Length; sha256 = $artifactHashBefore }
        started_at_utc = $childStartedAtUtc
        argument_count = $argumentCount
        arguments = @($arguments)
        argument_source = $argumentSource
    }
    Publish-NewFile $LiveStatePath ($liveState | ConvertTo-Json -Depth 10)
    $persistedLiveState =
        Read-AstroUtf8FileLongPath $LiveStatePath | ConvertFrom-Json
    if ($null -eq $persistedLiveState -or
        -not $persistedLiveState.PSObject.Properties['schema'] -or
        [string]$persistedLiveState.schema -cne
            'astrolabe.native-fsv-live.v2' -or
        -not $persistedLiveState.PSObject.Properties['owners'] -or
        $null -eq $persistedLiveState.owners -or
        -not $persistedLiveState.owners.PSObject.Properties['launcher'] -or
        -not $persistedLiveState.owners.PSObject.Properties['runner'] -or
        -not $persistedLiveState.owners.PSObject.Properties['child'] -or
        -not $persistedLiveState.PSObject.Properties['artifact'] -or
        $null -eq $persistedLiveState.artifact -or
        -not $persistedLiveState.artifact.PSObject.Properties['sha256']) {
        Fail-Astro 'ASTRO_FSV_LIVE_STATE_READBACK_FAILED' `
            'persisted live state omits its v2 exact owner/artifact envelope' `
            'preserve the session and investigate the failed durable write'
    }
    $persistedLiveLauncherIdentity = Read-AstroFsvProcessIdentity `
        $persistedLiveState.owners.launcher `
        'ASTRO_FSV_LIVE_STATE_READBACK_FAILED' `
        'persisted live-state launcher identity'
    $persistedLiveRunnerIdentity = Read-AstroFsvProcessIdentity `
        $persistedLiveState.owners.runner `
        'ASTRO_FSV_LIVE_STATE_READBACK_FAILED' `
        'persisted live-state runner identity'
    $persistedLiveChildIdentity = Read-AstroFsvProcessIdentity `
        $persistedLiveState.owners.child `
        'ASTRO_FSV_LIVE_STATE_READBACK_FAILED' `
        'persisted live-state child identity'
    if ($persistedLiveState.schema -cne
            'astrolabe.native-fsv-live.v2' -or
        [int]$persistedLiveState.issue -ne $Issue -or
        [string]$persistedLiveState.artifact.sha256 -cne
            $artifactHashBefore -or
        -not (Test-AstroFsvIdentityEqual `
            $persistedLiveLauncherIdentity $launcherIdentity) -or
        -not (Test-AstroFsvIdentityEqual `
            $persistedLiveRunnerIdentity $runnerIdentity) -or
        -not (Test-AstroFsvIdentityEqual `
            $persistedLiveChildIdentity $childIdentity)) {
        Fail-Astro 'ASTRO_FSV_LIVE_STATE_READBACK_FAILED' `
            'persisted live state does not match the exact owner/artifact state' `
            'preserve the session and investigate the failed durable write'
    }
    $liveStateBytes = Get-AstroFileLengthLongPath $LiveStatePath
    $liveStateSha256 = File-Sha256 $LiveStatePath
    $child.WaitForExit()
    $childExitedAtUtc = [DateTime]::UtcNow.ToString('o')
    $childExitObservation = Observe-ExitedProcessCode $child
    $childExitCode = [uint32]$childExitObservation.exit_code
    $childTerminationProved = $true

    $artifactHashAfter = File-Sha256 $artifact
    $receiptHashAfter = File-Sha256 $receiptFull
    if ($null -ne $argumentsFileHandle) {
        $argumentFileHashAfter =
            Get-AstroRetainedFileSha256 $argumentsFileHandle
        $argumentSource.sha256_after = $argumentFileHashAfter
        $argumentSource.stable =
            $argumentFileHashAfter -ceq [string]$argumentSource.sha256_before
        if (-not [bool]$argumentSource.stable) {
            Fail-Astro 'ASTRO_FSV_ARGUMENTS_FILE_DRIFT' `
                "retained arguments JSON bytes changed during the real artifact run: $($argumentSource.path)" `
                'preserve the session and investigate filesystem identity or byte drift'
        }
    }
    $launcherLockSnapshotAfter = Get-AstroExactRetainedFileSnapshot `
        -Handle $launcherLockHandle `
        -ExpectedPath $launcherLockPath
    $launcherLockLinksAfter =
        [AstroLauncherLockNative]::GetNumberOfLinks($launcherLockHandle)
    $launcherLockHashAfter = [string]$launcherLockSnapshotAfter.Sha256
    $launcherOwnerAfter = Read-AstroLauncherLock -LockPath $launcherLockPath
    $launcherJobProbeAfter =
        Get-AstroLauncherJobObjectProbe -Name $launcherJobName
    $launcherJobMembersAfter =
        [int[]]@($launcherJobProbeAfter.ProcessIds | Sort-Object -Unique)
    $afterRepo = Get-RepoState $gitExe $workspace
    $stdoutHash = File-Sha256 $StandardOutputPath
    $stderrHash = File-Sha256 $StandardErrorPath
    $treeStable = $beforeRepo.head_sha -ceq $afterRepo.head_sha -and
        $beforeRepo.status_sha256 -ceq $afterRepo.status_sha256 -and
        $beforeRepo.diff_sha256 -ceq $afterRepo.diff_sha256
    $artifactStable = $artifactHashBefore -ceq $artifactHashAfter -and
        (Get-AstroFileLengthLongPath $artifact) -eq
            [uint64]$receipt.artifact.bytes
    $receiptStable = $receiptHashBefore -ceq $receiptHashAfter
    $launcherJobStable = $launcherJobProbeAfter.State -ceq 'observed' -and
        $launcherJobMembersAfter -contains $launcherPid -and
        $launcherJobMembersAfter -contains $PID
    $launcherLeaseStable =
        $launcherLockLinksAfter -eq 1 -and
        $launcherLockSnapshotBefore.FileId -ceq $launcherLockSnapshotAfter.FileId -and
        $launcherLockSnapshotBefore.Length -eq $launcherLockSnapshotAfter.Length -and
        $launcherLockHashBefore -ceq $launcherLockHashAfter -and
        [Convert]::ToBase64String($launcherLockSnapshotBefore.Bytes) -ceq
            [Convert]::ToBase64String($launcherLockSnapshotAfter.Bytes) -and
        $launcherOwnerAfter.State -ceq 'held' -and
        $launcherOwnerAfter.Issue -eq $Issue -and
        $launcherOwnerAfter.OwnerPid -eq $launcherPid -and
        $launcherOwnerAfter.OwnerProcessStartUtcTicks -eq
            $launcherOwner.OwnerProcessStartUtcTicks -and
        $launcherOwnerAfter.Sha256 -ceq $launcherLockHashBefore -and
        $launcherJobStable

    # #708: a completed native child and a stable run record are not sufficient
    # cleanup evidence. Prove the *same* access/share request used by exact cleanup
    # can be acquired before returning to the caller. The execution lease must be
    # closed first because it deliberately denies DELETE for the whole child run.
    #
    # Read-only is reversibly cleared because OpenExactRenameSource requests
    # GENERIC_WRITE and Windows returns ERROR_ACCESS_DENIED for that exact open on
    # a read-only file. Once the cleanup lease is retained, restore read-only and
    # independently re-read final path, identity, link count, length, and bytes.
    # The retained lease shares reads only, so it protects the artifact against
    # write/delete drift until this runner exits.
    if ($null -ne $artifactHandle) {
        $artifactHandle.Dispose()
        $artifactHandle = $null
    }
    if ($null -ne $createdChild) {
        # The two retained exact handles already agreed on signal state and exit
        # code. Close them before readiness so any remaining owner is foreign to
        # the runner's explicit process-observation state.
        $createdChild.Dispose()
        $childProcessHandlesClosed = $true
    }
    $cleanupReadinessTimeoutMs = 15000
    $cleanupReadinessInitialDelayMs = 100
    $cleanupReadinessMaximumDelayMs = 1000
    $cleanupReadinessDelayMs = $cleanupReadinessInitialDelayMs
    $cleanupReadinessAttempts = [Collections.Generic.List[object]]::new()
    $cleanupReadinessStopwatch = [Diagnostics.Stopwatch]::StartNew()
    try {
        while ($null -eq $artifactCleanupLease) {
            Set-AstroFileReadOnlyLongPath `
                -LiteralPath $artifact -ReadOnly $false
            $openFailure = $null
            try {
                $artifactCleanupLease =
                    [AstroLauncherLockNative]::OpenExactRenameSource(
                        $artifact
                    )
            }
            catch {
                $openFailure = $_
            }

            if ($null -ne $artifactCleanupLease) {
                Set-AstroFileReadOnlyLongPath `
                    -LiteralPath $artifact -ReadOnly $true
                break
            }

            # Never leave the immutable receipt artifact writable while waiting
            # for a foreign Windows reader to release its exact file handle.
            Set-AstroFileReadOnlyLongPath `
                -LiteralPath $artifact -ReadOnly $true
            $nativeError =
                Get-AstroNativeErrorCode $openFailure.Exception
            $ownerDiagnostic =
                Get-AstroArtifactOwnerDiagnostic $artifact
            $cleanupReadinessAttempts.Add([ordered]@{
                attempt = $cleanupReadinessAttempts.Count + 1
                elapsed_ms =
                    [int64]$cleanupReadinessStopwatch.ElapsedMilliseconds
                native_error = $nativeError
                message = $openFailure.Exception.Message
                owner_diagnostic = $ownerDiagnostic
                read_only_restored = $true
            })

            if ($nativeError -ne 32) {
                throw "cleanup-readiness open failed with non-transient native error (native_error=$nativeError; failure=$($openFailure.Exception.Message))"
            }
            if ([string]$ownerDiagnostic.state -cne 'observed' -or
                @($ownerDiagnostic.owners).Count -eq 0) {
                throw "cleanup-readiness sharing violation has no complete nonempty owner attribution (owner_diagnostic=$($ownerDiagnostic | ConvertTo-Json -Depth 8 -Compress))"
            }
            $ownedTreePids = @(
                @($launcherJobMembersAfter) +
                @($launcherPid, $PID, $child.Id) |
                    Sort-Object -Unique
            )
            $internalOwners = @($ownerDiagnostic.owners | Where-Object {
                [uint32]$_.pid -in $ownedTreePids
            })
            if ($internalOwners.Count -ne 0) {
                throw "cleanup-readiness sharing violation is owned by an exact member of the launcher Job (owners=$($internalOwners | ConvertTo-Json -Depth 8 -Compress); job=$launcherJobName)"
            }

            $remainingMs = $cleanupReadinessTimeoutMs -
                [int64]$cleanupReadinessStopwatch.ElapsedMilliseconds
            if ($remainingMs -le 0) {
                throw "cleanup-readiness sharing violation exceeded its bounded foreign-owner transition (timeout_ms=$cleanupReadinessTimeoutMs)"
            }
            $waitMs = [int][Math]::Min(
                [int64]$cleanupReadinessDelayMs,
                $remainingMs
            )
            [Threading.Thread]::Sleep($waitMs)
            $cleanupReadinessDelayMs = [int][Math]::Min(
                [int64]$cleanupReadinessDelayMs * 2,
                [int64]$cleanupReadinessMaximumDelayMs
            )
        }
        $cleanupReadinessStopwatch.Stop()

        $cleanupFinalPath = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($artifactCleanupLease)
        )
        if (-not [string]::Equals(
                $cleanupFinalPath,
                $artifact,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "cleanup-readiness lease resolved to '$cleanupFinalPath', expected '$artifact'"
        }
        $cleanupFileId =
            [AstroLauncherLockNative]::GetFileIdentity($artifactCleanupLease)
        $cleanupLinks =
            [AstroLauncherLockNative]::GetNumberOfLinks($artifactCleanupLease)
        $cleanupLength = Get-AstroFileLengthLongPath $artifact
        $cleanupHash =
            [AstroLauncherLockNative]::ComputeExactFileSha256(
                $artifactCleanupLease
            )
        $cleanupAttributes = [IO.File]::GetAttributes(
            (ConvertTo-AstroExtendedLengthPath $artifact)
        )
        $cleanupReadOnly =
            ($cleanupAttributes -band [IO.FileAttributes]::ReadOnly) -ne 0
        if ($cleanupLinks -ne 1 -or
            $cleanupLength -ne [uint64]$receipt.artifact.bytes -or
            $cleanupHash -cne $artifactHashAfter -or
            -not $cleanupReadOnly) {
            throw "cleanup-readiness readback drifted (links=$cleanupLinks, bytes=$cleanupLength, sha256=$cleanupHash, read_only=$cleanupReadOnly)"
        }
        $artifactCleanupReadiness = [ordered]@{
            established = $true
            operation =
                'CreateFileW(GENERIC_READ|GENERIC_WRITE|DELETE,FILE_SHARE_READ)'
            final_path = $cleanupFinalPath
            file_id = $cleanupFileId
            links = [uint32]$cleanupLinks
            bytes = [uint64]$cleanupLength
            sha256 = $cleanupHash
            read_only_restored = $cleanupReadOnly
            child_termination_proved = $childTerminationProved
            child_process_handles_closed = $childProcessHandlesClosed
            retained_until_runner_exit = $true
            transition = [ordered]@{
                kind = if ($cleanupReadinessAttempts.Count -eq 0) {
                    'immediate'
                } else {
                    'bounded-foreign-owner-sharing-violation'
                }
                timeout_ms = $cleanupReadinessTimeoutMs
                initial_delay_ms = $cleanupReadinessInitialDelayMs
                maximum_delay_ms = $cleanupReadinessMaximumDelayMs
                failed_attempts = @($cleanupReadinessAttempts)
                successful_attempt =
                    $cleanupReadinessAttempts.Count + 1
                elapsed_ms =
                    [int64]$cleanupReadinessStopwatch.ElapsedMilliseconds
            }
        }
        $artifactStable = $artifactStable -and
            $cleanupHash -ceq $artifactHashAfter
    }
    catch {
        $cleanupReadinessStopwatch.Stop()
        $readinessFailure = $_
        if ($null -ne $artifactCleanupLease) {
            $artifactCleanupLease.Dispose()
            $artifactCleanupLease = $null
        }
        $ownerDiagnostic =
            Get-AstroArtifactOwnerDiagnostic $artifact
        $transitionFailure = [ordered]@{
            timeout_ms = $cleanupReadinessTimeoutMs
            initial_delay_ms = $cleanupReadinessInitialDelayMs
            maximum_delay_ms = $cleanupReadinessMaximumDelayMs
            elapsed_ms =
                [int64]$cleanupReadinessStopwatch.ElapsedMilliseconds
            failed_attempts = @($cleanupReadinessAttempts)
            final_owner_diagnostic = $ownerDiagnostic
        }
        try {
            if (Test-AstroPathLongPath -LiteralPath $artifact -PathType Leaf) {
                Set-AstroFileReadOnlyLongPath `
                    -LiteralPath $artifact -ReadOnly $true
            }
        }
        catch {
            Fail-Astro 'ASTRO_FSV_ARTIFACT_CLEANUP_READINESS_RESTORE_FAILED' `
                "exact cleanup readiness failed and the staged artifact read-only attribute could not be restored (readiness_failure=$($readinessFailure.Exception.Message); restore_failure=$($_.Exception.Message))" `
                'preserve the session and inspect the exact native error/handle owner before any lifecycle cleanup'
        }
        Fail-Astro 'ASTRO_FSV_ARTIFACT_CLEANUP_NOT_READY' `
            "the staged artifact is not exactly ready for cleanup after native child termination: $($readinessFailure.Exception.Message); transition=$($transitionFailure | ConvertTo-Json -Depth 12 -Compress)" `
            'preserve the session; inspect the exact native error and PID/creation-time owner transition, then repair or release that owner before rerunning'
    }

    $verdict = if ($childExitCode -eq 0 -and [bool]$childExitObservation.sources_agree -and
        $treeStable -and $artifactStable -and $receiptStable -and
        $launcherLeaseStable -and
        [bool]$artifactCleanupReadiness.established) {
        'verified'
    } else {
        'failed'
    }
    $fsvLockCleanup = Remove-TerminalFsvLock `
        -LockPath $fsvLockPath `
        -RunnerIdentity $runnerIdentity `
        -ChildIdentity $childIdentity `
        -ArtifactSha256 $artifactHashBefore
    $record = [ordered]@{
        schema = 'astrolabe.native-fsv-run.v2'
        verdict = $verdict
        issue = $Issue
        receipt_path = $receiptFull
        launcher = $launcherIdentity
        runner = $runnerIdentity
        process = [ordered]@{
            identity = $childIdentity
            launch_boundary = 'kernel32!CreateProcessW(non-null extended application; STARTUPINFOEX restricted handle list)'
            standard_input = 'NUL'
            exit_code = $childExitCode
            exit_code_observation = $childExitObservation
            # #1059: additive classification of how the child ended. The verdict
            # above is unchanged; this only names the termination signature.
            termination_classification =
                Get-AstroTerminationClassification $childExitCode
            started_at = $childStartedAtUtc
            exited_at = $childExitedAtUtc
            timestamp_basis = 'runner-observed-utc'
        }
        artifact = [ordered]@{ path = $artifact; bytes = Get-AstroFileLengthLongPath $artifact; sha256 = $artifactHashAfter; stable = $artifactStable; delete_share_denied_for_run = $true }
        cleanup_readiness = $artifactCleanupReadiness
        receipt = [ordered]@{ path = $receiptFull; sha256_before = $receiptHashBefore; sha256_after = $receiptHashAfter; stable = $receiptStable }
        launcher_lease = [ordered]@{
            path = $launcherLockPath
            file_id_before = $launcherLockSnapshotBefore.FileId
            file_id_after = $launcherLockSnapshotAfter.FileId
            sha256_before = $launcherLockHashBefore
            sha256_after = $launcherLockHashAfter
            links_before = $launcherLockLinksBefore
            links_after = $launcherLockLinksAfter
            owner = $launcherIdentity
            lease_start_utc_ticks = $launcherOwner.LeaseStartUtcTicks
            job = [ordered]@{
                name = $launcherJobName
                state_before = $launcherJobProbeBefore.State
                members_before = @($launcherJobMembersBefore)
                state_after = $launcherJobProbeAfter.State
                members_after = @($launcherJobMembersAfter)
                stable = $launcherJobStable
            }
            stable = $launcherLeaseStable
        }
        argument_count = $argumentCount
        arguments = @($arguments)
        argument_source = $argumentSource
        live_state = [ordered]@{
            path = $LiveStatePath
            published = $true
            bytes = $liveStateBytes
            sha256 = $liveStateSha256
        }
        stdout = [ordered]@{ path = $StandardOutputPath; bytes = Get-AstroFileLengthLongPath $StandardOutputPath; sha256 = $stdoutHash }
        stderr = [ordered]@{ path = $StandardErrorPath; bytes = Get-AstroFileLengthLongPath $StandardErrorPath; sha256 = $stderrHash }
        repository = [ordered]@{ before = $beforeRepo; after = $afterRepo; stable = $treeStable }
        fsv_lock_cleanup = $fsvLockCleanup
    }
    Write-NewDurableUtf8 $RunRecordPath ($record | ConvertTo-Json -Depth 15)
    $runRecordWritten = $true
    $persistedRecord =
        Read-AstroUtf8FileLongPath $RunRecordPath | ConvertFrom-Json
    if ($null -eq $persistedRecord -or
        -not $persistedRecord.PSObject.Properties['schema'] -or
        [string]$persistedRecord.schema -cne
            'astrolabe.native-fsv-run.v2' -or
        -not $persistedRecord.PSObject.Properties['launcher'] -or
        -not $persistedRecord.PSObject.Properties['runner'] -or
        -not $persistedRecord.PSObject.Properties['process'] -or
        $null -eq $persistedRecord.process -or
        -not $persistedRecord.process.PSObject.Properties['identity'] -or
        -not $persistedRecord.process.PSObject.Properties['exit_code'] -or
        -not $persistedRecord.process.PSObject.Properties[
            'exit_code_observation'
        ] -or
        $null -eq $persistedRecord.process.exit_code_observation -or
        -not $persistedRecord.PSObject.Properties['artifact'] -or
        $null -eq $persistedRecord.artifact -or
        -not $persistedRecord.artifact.PSObject.Properties['sha256'] -or
        -not $persistedRecord.PSObject.Properties['argument_count'] -or
        -not $persistedRecord.PSObject.Properties['arguments'] -or
        -not $persistedRecord.PSObject.Properties['argument_source'] -or
        $null -eq $persistedRecord.argument_source -or
        -not $persistedRecord.PSObject.Properties['live_state'] -or
        $null -eq $persistedRecord.live_state -or
        -not $persistedRecord.live_state.PSObject.Properties['path'] -or
        -not $persistedRecord.live_state.PSObject.Properties['published'] -or
        -not $persistedRecord.live_state.PSObject.Properties['bytes'] -or
        -not $persistedRecord.live_state.PSObject.Properties['sha256'] -or
        -not $persistedRecord.PSObject.Properties['fsv_lock_cleanup'] -or
        -not $persistedRecord.fsv_lock_cleanup.PSObject.Properties['after_exists']) {
        Fail-Astro 'ASTRO_FSV_RUN_READBACK_FAILED' `
            'persisted run record omits its v2 exact process/artifact/live-state envelope' `
            'preserve the session and investigate the failed durable write'
    }
    $persistedArguments = @($persistedRecord.arguments)
    $argumentsMatch = [int]$persistedRecord.argument_count -eq $argumentCount -and
        $persistedArguments.Count -eq $argumentCount
    if ($argumentsMatch) {
        for ($index = 0; $index -lt $argumentCount; $index++) {
            if ($persistedArguments[$index] -isnot [string] -or
                -not [string]::Equals([string]$persistedArguments[$index], $arguments[$index], [StringComparison]::Ordinal)) {
                $argumentsMatch = $false
                break
            }
        }
    }
    $argumentSourceMatch =
        [string]$persistedRecord.argument_source.kind -ceq [string]$argumentSource.kind -and
        [string]$persistedRecord.argument_source.path -ceq [string]$argumentSource.path -and
        [uint64]$persistedRecord.argument_source.bytes -eq [uint64]$argumentSource.bytes -and
        [string]$persistedRecord.argument_source.sha256_before -ceq [string]$argumentSource.sha256_before -and
        [string]$persistedRecord.argument_source.sha256_after -ceq [string]$argumentSource.sha256_after -and
        [bool]$persistedRecord.argument_source.stable -eq [bool]$argumentSource.stable
    $persistedLauncherIdentity = Read-AstroFsvProcessIdentity `
        $persistedRecord.launcher `
        'ASTRO_FSV_RUN_READBACK_FAILED' `
        'persisted run-record launcher identity'
    $persistedRunnerIdentity = Read-AstroFsvProcessIdentity `
        $persistedRecord.runner `
        'ASTRO_FSV_RUN_READBACK_FAILED' `
        'persisted run-record runner identity'
    $persistedChildIdentity = Read-AstroFsvProcessIdentity `
        $persistedRecord.process.identity `
        'ASTRO_FSV_RUN_READBACK_FAILED' `
        'persisted run-record child identity'
    $persistedChildExitObservation =
        Assert-AstroFsvExitCodeObservationReadback `
            $persistedRecord.process.exit_code_observation `
            $childExitObservation `
            'ASTRO_FSV_RUN_READBACK_FAILED' `
            'run-record child exit observation'
    if ([string]$persistedRecord.live_state.path -cne
            $LiveStatePath -or
        -not [bool]$persistedRecord.live_state.published -or
        [uint64]$persistedRecord.live_state.bytes -ne
            [uint64]$liveStateBytes -or
        [string]$persistedRecord.live_state.sha256 -cne
            $liveStateSha256 -or
        [uint64]$persistedRecord.process.exit_code -ne [uint64]$childExitCode -or
        [uint64]$persistedRecord.process.exit_code -ne
            [uint64]$persistedChildExitObservation.exit_code -or
        [string]$persistedRecord.artifact.sha256 -cne $artifactHashAfter -or
        [bool]$persistedRecord.fsv_lock_cleanup.after_exists -ne $false -or
        -not (Test-AstroFsvIdentityEqual `
            $persistedLauncherIdentity $launcherIdentity) -or
        -not (Test-AstroFsvIdentityEqual `
            $persistedRunnerIdentity $runnerIdentity) -or
        -not (Test-AstroFsvIdentityEqual `
            $persistedChildIdentity $childIdentity) -or
        -not $argumentsMatch -or -not $argumentSourceMatch) {
        Fail-Astro 'ASTRO_FSV_RUN_READBACK_FAILED' 'persisted run record does not match the observed process/artifact state' 'preserve the session and investigate the failed durable write'
    }
    $record | ConvertTo-Json -Depth 15 -Compress | Write-Output
    if (-not $treeStable) { Fail-Astro 'ASTRO_FSV_TREE_MUTATED' 'repository state changed during the native FSV run' 'discard the evidence, freeze the checkout, rebuild, and rerun' }
    if (-not $artifactStable) { Fail-Astro 'ASTRO_FSV_ARTIFACT_DRIFT' 'staged artifact changed during the native FSV run' 'preserve state, identify the writer, rebuild, and rerun' }
    if (-not $receiptStable) { Fail-Astro 'ASTRO_FSV_RECEIPT_DRIFT' 'artifact receipt changed during the native FSV run' 'preserve state, identify the writer, rebuild, and rerun' }
    if (-not $launcherLeaseStable) { Fail-Astro 'ASTRO_FSV_LAUNCHER_LEASE_DRIFT' 'launcher lock changed during the native FSV run' 'discard the evidence and investigate the lease writer' }
    if (-not [bool]$childExitObservation.sources_agree) {
        Fail-Astro 'ASTRO_FSV_CHILD_EXIT_OBSERVATION_MISMATCH' "the original and duplicated exact process handles disagree on native child PID $($child.Id) exit code (primary=$childExitCode; duplicate=$($childExitObservation.exact_duplicate_exit_code))" 'preserve the run record and repair exact process-handle observation; never infer success from disagreeing sources'
    }
    if ($childExitCode -ne 0) { exit 1 }
    exit 0
}
catch {
    $failure = $_
    if ($null -ne $child -and -not $childTerminationProved) {
        try {
            if (-not $child.HasExited) {
                [Console]::Error.WriteLine("NATIVE_FSV[ASTRO_FSV_FAILURE_WAITING_FOR_CHILD]: runner failed after real child PID $($child.Id) started; waiting for that exact process to exit naturally before releasing its immutable artifact lease")
                $child.WaitForExit()
            }
            if ($child.HasExited) {
                $childTerminationProved = $true
                if ($null -eq $childExitedAtUtc) {
                    $childExitedAtUtc = [DateTime]::UtcNow.ToString('o')
                }
                if ($null -eq $childExitCode) {
                    try {
                        $childExitObservation = Observe-ExitedProcessCode $child
                        $childExitCode = [uint32]$childExitObservation.exit_code
                    }
                    catch { $childExitObservationError = $_.Exception.Message }
                }
            }
        }
        catch {
            [Console]::Error.WriteLine("NATIVE_FSV[ASTRO_FSV_CHILD_LIVENESS_UNEVALUABLE]: could not prove real child termination: $($_.Exception.Message); preserving the FSV lock fail-closed")
        }
    }
    $code = if ($failure.Exception.Data.Contains('AstroCode')) { [string]$failure.Exception.Data['AstroCode'] } else { 'ASTRO_FSV_RUN_INTERNAL' }
    $remediation = if ($failure.Exception.Data.Contains('AstroRemediation')) { [string]$failure.Exception.Data['AstroRemediation'] } else { 'preserve the evidence state, inspect the full error, repair the root cause, and retry from a fresh session' }
    if ($runRecordAuthorized -and -not $runRecordWritten -and
        $null -ne $child -and $childTerminationProved -and
        -not (Test-AstroPathLongPath -LiteralPath $RunRecordPath)) {
        try {
            if ($null -eq $childIdentity) {
                $childIdentity = New-AstroProcessIdentityRecord `
                    $child.Id ([long]$child.ProcessStartUtcTicks)
            }
            if ($null -eq $fsvLockCleanup) {
                try {
                    $fsvLockCleanup = Remove-TerminalFsvLock `
                        -LockPath $fsvLockPath `
                        -RunnerIdentity $runnerIdentity `
                        -ChildIdentity $childIdentity `
                        -ArtifactSha256 $artifactHashBefore
                }
                catch {
                    $fsvLockCleanup = [ordered]@{
                        path = $fsvLockPath
                        before_exists = Test-AstroPathLongPath -LiteralPath $fsvLockPath
                        removed = $false
                        after_exists = Test-AstroPathLongPath -LiteralPath $fsvLockPath
                        error = $_.Exception.Message
                    }
                }
            }
            $failureArtifactHash = if (
                Test-AstroPathLongPath -LiteralPath $artifact -PathType Leaf
            ) {
                if ($null -ne $artifactCleanupLease) {
                    [AstroLauncherLockNative]::ComputeExactFileSha256(
                        $artifactCleanupLease
                    )
                }
                else {
                    File-Sha256 $artifact
                }
            }
            else { $null }
            $failureLiveStatePublished =
                Test-AstroPathLongPath -LiteralPath $LiveStatePath -PathType Leaf
            $failureRecord = [ordered]@{
                schema = 'astrolabe.native-fsv-run.v2'
                verdict = 'failed'
                issue = $Issue
                receipt_path = $receiptFull
                launcher = $launcherIdentity
                runner = $runnerIdentity
                process = [ordered]@{
                    identity = $childIdentity
                    launch_boundary = 'kernel32!CreateProcessW(non-null extended application; STARTUPINFOEX restricted handle list)'
                    standard_input = 'NUL'
                    exit_code = $childExitCode
                    exit_code_observation = $childExitObservation
                    exit_code_observation_error = Failure-Text $childExitObservationError
                    # #1059: additive classification of how the child ended.
                    termination_classification =
                        Get-AstroTerminationClassification $childExitCode
                    started_at = $childStartedAtUtc
                    exited_at = $childExitedAtUtc
                    timestamp_basis = 'runner-observed-utc'
                }
                artifact = [ordered]@{
                    path = $artifact
                    bytes = if (Test-AstroPathLongPath -LiteralPath $artifact -PathType Leaf) { Get-AstroFileLengthLongPath $artifact } else { 0 }
                    sha256 = $failureArtifactHash
                    stable = $false
                }
                argument_count = $argumentCount
                arguments = @($arguments)
                argument_source = $argumentSource
                live_state = [ordered]@{
                    path = $LiveStatePath
                    published = $failureLiveStatePublished
                    bytes = if ($failureLiveStatePublished) {
                        Get-AstroFileLengthLongPath $LiveStatePath
                    }
                    else { 0 }
                    sha256 = if ($failureLiveStatePublished) {
                        File-Sha256 $LiveStatePath
                    }
                    else { $null }
                }
                stdout = [ordered]@{
                    path = $StandardOutputPath
                    bytes = if (Test-AstroPathLongPath -LiteralPath $StandardOutputPath -PathType Leaf) { Get-AstroFileLengthLongPath $StandardOutputPath } else { 0 }
                    sha256 = if (Test-AstroPathLongPath -LiteralPath $StandardOutputPath -PathType Leaf) { File-Sha256 $StandardOutputPath } else { $null }
                }
                stderr = [ordered]@{
                    path = $StandardErrorPath
                    bytes = if (Test-AstroPathLongPath -LiteralPath $StandardErrorPath -PathType Leaf) { Get-AstroFileLengthLongPath $StandardErrorPath } else { 0 }
                    sha256 = if (Test-AstroPathLongPath -LiteralPath $StandardErrorPath -PathType Leaf) { File-Sha256 $StandardErrorPath } else { $null }
                }
                fsv_lock_cleanup = $fsvLockCleanup
                bind_cleanup = $bindCleanupDiagnostic
                failure = [ordered]@{
                    code = $code
                    message = $failure.Exception.Message
                    remediation = $remediation
                    exception_type = $failure.Exception.GetType().FullName
                    script_stack_trace = Failure-Text $failure.ScriptStackTrace
                    invocation = Failure-Text $failure.InvocationInfo.PositionMessage
                }
            }
            Write-NewDurableUtf8 $RunRecordPath ($failureRecord | ConvertTo-Json -Depth 15)
            $persistedFailure =
                Read-AstroUtf8FileLongPath $RunRecordPath |
                    ConvertFrom-Json
            if ($null -eq $persistedFailure -or
                -not $persistedFailure.PSObject.Properties['schema'] -or
                [string]$persistedFailure.schema -cne
                    'astrolabe.native-fsv-run.v2' -or
                -not $persistedFailure.PSObject.Properties['launcher'] -or
                -not $persistedFailure.PSObject.Properties['runner'] -or
                -not $persistedFailure.PSObject.Properties['process'] -or
                $null -eq $persistedFailure.process -or
                -not $persistedFailure.process.PSObject.Properties[
                    'identity'
                ] -or
                -not $persistedFailure.process.PSObject.Properties[
                    'exit_code'
                ] -or
                -not $persistedFailure.process.PSObject.Properties[
                    'exit_code_observation'
                ] -or
                -not $persistedFailure.process.PSObject.Properties[
                    'exit_code_observation_error'
                ] -or
                -not $persistedFailure.PSObject.Properties['failure'] -or
                $null -eq $persistedFailure.failure -or
                -not $persistedFailure.failure.PSObject.Properties['code'] -or
                -not $persistedFailure.PSObject.Properties['bind_cleanup'] -or
                -not $persistedFailure.PSObject.Properties['argument_source'] -or
                $null -eq $persistedFailure.argument_source -or
                -not $persistedFailure.PSObject.Properties['live_state'] -or
                $null -eq $persistedFailure.live_state -or
                -not $persistedFailure.live_state.PSObject.Properties[
                    'published'
                ]) {
                Fail-Astro 'ASTRO_FSV_FAILURE_RECORD_READBACK_FAILED' `
                    'persisted failure record omits its v2 exact process/failure/live-state envelope' `
                    'preserve the session and investigate the failed durable write'
            }
            $persistedFailureLauncher = Read-AstroFsvProcessIdentity `
                $persistedFailure.launcher `
                'ASTRO_FSV_FAILURE_RECORD_READBACK_FAILED' `
                'persisted failure-record launcher identity'
            $persistedFailureRunner = Read-AstroFsvProcessIdentity `
                $persistedFailure.runner `
                'ASTRO_FSV_FAILURE_RECORD_READBACK_FAILED' `
                'persisted failure-record runner identity'
            $persistedFailureChild = Read-AstroFsvProcessIdentity `
                $persistedFailure.process.identity `
                'ASTRO_FSV_FAILURE_RECORD_READBACK_FAILED' `
                'persisted failure-record child identity'
            if ($null -ne $childExitObservation) {
                [void](Assert-AstroFsvExitCodeObservationReadback `
                    $persistedFailure.process.exit_code_observation `
                    $childExitObservation `
                    'ASTRO_FSV_FAILURE_RECORD_READBACK_FAILED' `
                    'failure-record child exit observation')
            }
            elseif ($null -ne
                $persistedFailure.process.exit_code_observation) {
                Fail-Astro 'ASTRO_FSV_FAILURE_RECORD_READBACK_FAILED' `
                    'persisted failure record invented a child exit observation' `
                    'preserve the session and investigate the failed durable write'
            }
            $persistedBindCleanup = if ($null -eq
                $persistedFailure.bind_cleanup) {
                $null
            }
            else {
                $persistedFailure.bind_cleanup | ConvertTo-Json -Depth 15 -Compress
            }
            $expectedBindCleanup = if ($null -eq $bindCleanupDiagnostic) {
                $null
            }
            else {
                $bindCleanupDiagnostic | ConvertTo-Json -Depth 15 -Compress
            }
            if ($persistedFailure.schema -cne
                    'astrolabe.native-fsv-run.v2' -or
                [string]$persistedFailure.failure.code -cne $code -or
                [string]$persistedBindCleanup -cne
                    [string]$expectedBindCleanup -or
                [string]$persistedFailure.process.exit_code_observation_error -cne
                    [string](Failure-Text $childExitObservationError) -or
                ($null -ne $childExitObservation -and
                    [uint64]$persistedFailure.process.exit_code -ne
                        [uint64]$childExitObservation.exit_code) -or
                ($null -eq $childExitObservation -and
                    $null -ne $persistedFailure.process.exit_code) -or
                -not (Test-AstroFsvIdentityEqual `
                    $persistedFailureLauncher $launcherIdentity) -or
                -not (Test-AstroFsvIdentityEqual `
                    $persistedFailureRunner $runnerIdentity) -or
                -not (Test-AstroFsvIdentityEqual `
                    $persistedFailureChild $childIdentity) -or
                [bool]$persistedFailure.live_state.published -ne
                    $failureLiveStatePublished) {
                Fail-Astro 'ASTRO_FSV_FAILURE_RECORD_READBACK_FAILED' `
                    'persisted failure record differs from exact observed failure state' `
                    'preserve the session and investigate the failed durable write'
            }
            $runRecordWritten = $true
        }
        catch {
            [Console]::Error.WriteLine("NATIVE_FSV[ASTRO_FSV_FAILURE_RECORD_WRITE_FAILED]: could not persist the failure record: $($_.Exception.Message)")
        }
    }
    [Console]::Error.WriteLine(([ordered]@{ code = $code; message = $failure.Exception.Message; remediation = $remediation; run_record_written = $runRecordWritten } | ConvertTo-Json -Compress))
    exit 1
}
finally {
    if ($null -ne $argumentsFileHandle) { $argumentsFileHandle.Dispose() }
    if ($null -ne $launcherLockHandle) { $launcherLockHandle.Dispose() }
    if ($null -ne $receiptHandle) { $receiptHandle.Dispose() }
    if ($null -ne $artifactHandle) { $artifactHandle.Dispose() }
    if ($null -ne $directoryHandle) { $directoryHandle.Dispose() }
    $childStillLive = if ($childTerminationProved) {
        $false
    }
    else {
        $childTerminationUncertain
    }
    if ($null -ne $child -and -not $childTerminationProved) {
        try { $childStillLive = -not $child.HasExited }
        catch { $childStillLive = $true }
    }
    if ($fsvLockOwned) {
        if ($childStillLive) {
            Fail-Astro `
                'ASTRO_FSV_LOCK_PRESERVED_LIVE_CHILD' `
                'preserving the FSV lock because the recorded real child is still live' `
                'wait for the exact child generation to terminate, then retire the lock through the tracker-bound lifecycle'
        }
        if (Test-AstroPathLongPath -LiteralPath $fsvLockPath) {
            $owned = $false
            try {
                $lock = Read-AstroUtf8FileLongPath $fsvLockPath | ConvertFrom-Json
                $lockRunnerIdentity = Read-AstroFsvProcessIdentity `
                    $lock.owners.runner `
                    'ASTRO_FSV_LOCK_IDENTITY_CHANGED' `
                    'terminal FSV lock runner identity'
                $owned = $lock.schema -ceq 'astrolabe.native-fsv-lock.v2' -and
                    (Test-AstroFsvIdentityEqual `
                        $lockRunnerIdentity $runnerIdentity) -and
                    [string]$lock.artifact_sha256 -ceq $artifactHashBefore
            }
            catch { $owned = $false }
            if (-not $owned) {
                Fail-Astro `
                    'ASTRO_FSV_LOCK_IDENTITY_CHANGED' `
                    'terminal FSV lock no longer matches this exact runner/artifact generation' `
                    'preserve the lock and session; retire only through the tracker-bound stale-lock lifecycle after exact identity readback'
            }
            Remove-AstroFileLongPath $fsvLockPath
        }
        if (Test-AstroPathLongPath -LiteralPath $fsvLockPath) {
            Fail-Astro `
                'ASTRO_FSV_LOCK_CLEANUP_READBACK_FAILED' `
                "owned FSV lock remained after terminal cleanup: $fsvLockPath" `
                'preserve the lock and session; retire only through the tracker-bound stale-lock lifecycle after exact owner absence'
        }
    }
    if ($null -ne $createdChild) { $createdChild.Dispose() }
    if ($null -ne $child) { $child.Dispose() }
    if ($null -ne $artifactCleanupLease) {
        $artifactCleanupLease.Dispose()
    }
}
