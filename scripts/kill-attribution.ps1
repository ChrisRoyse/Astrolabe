<#
.SYNOPSIS
    Arm, inspect, prove, and disarm Windows Silent Process Exit monitoring so a
    cross-process kill of an Astrolabe evidence run names its killer (#1059).

.DESCRIPTION
    A concurrent session's `Stop-Process -Id <pid> -Force` destroyed the g26
    canonical FSV leg. `Process.Kill()`/`Stop-Process -Force` are literally
    `TerminateProcess(handle, -1)`, so the victim exited 0xFFFFFFFF and Windows
    recorded nothing about who did it: no WER report, no event-log entry, no
    attribution anywhere. Identifying the killer took a multi-hour forensic
    session.

    Silent Process Exit monitoring is the only Windows mechanism that names a
    terminating process which already holds a handle (Sysmon Event 10 fires on
    OpenProcess, so a parent-held handle never trips it; Security 4689 records
    only the dying process). WerSvc consults the registry AT KILL TIME, so:
    nothing needs a reboot, no monitored process restarts, no runtime cost is
    added, and nothing blocks or delays the exit.

    Two registry keys per image:
      IFEO\<image>              GlobalFlag       += 0x200 (FLG_MONITOR_SILENT_PROCESS_EXIT)
      SilentProcessExit\<image> ReportingMode     = 1 (LAUNCH_MONITORPROCESS only)
                                IgnoreSelfExits   = 1 (fire ONLY on cross-process kills)
                                MonitorProcess    = <monitor command with %e %i %t %c>

    ReportingMode is 1 and never 2: LOCAL_DUMP of a process whose working set is
    tens of gigabytes would be catastrophic on this machine. IgnoreSelfExits=1
    means an ordinary exit — including every short-lived MCP/CLI invocation of
    the same image — writes nothing, so the log stays near-empty until a real
    external kill happens.

    Only the 0x200 bit of GlobalFlag is ever set. Page-heap and loader-snap bits
    change runtime behavior and are never touched; any pre-existing GlobalFlag
    is captured to ifeo-before.json and restored byte-for-byte by -Operation
    Disable.

    Disclosed blind spots (not fixed here, by design): a direct
    NtTerminateProcess syscall that bypasses the documented path, and kernel or
    Job-object terminations, are not reported by this mechanism.

    This is operator/agent-invoked diagnostic instrumentation. The launcher, the
    build path, and every product code path MUST NOT call it. It performs no
    operating-system servicing: it writes two registry keys and one ProgramData
    directory, and removes exactly what it wrote.

.NOTES
    Refs #1059. Manual FSV tooling; this is not a test or a gate.
    Windows-only (owner directive). No CI.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Enable', 'Disable', 'Status', 'Test')]
    [string]$Operation,

    # Image names to manage. Defaults to the canonical evidence binary only; the
    # shim and any other entrypoint must be named explicitly.
    [string[]]$Image = @('astrolabe.exe'),

    # GlobalFlag encoding. REG_SZ '512' is the documented form; DWORD 512 is the
    # empirical fallback. -Operation Test settles which one this host honours.
    [ValidateSet('String', 'DWord')]
    [string]$GlobalFlagKind = 'String',

    # Seconds to wait for the monitor process to publish its kills.log line.
    [ValidateRange(5, 600)]
    [int]$TestTimeoutSeconds = 60,

    # Scratch image used by -Operation Test. The default is a scratch-named copy
    # of cmd.exe; pass a System32 image name (e.g. notepad.exe) to exercise a
    # shipped binary instead.
    [string]$TestImage = 'astrolabe-kill-victim.exe',

    # Internal re-entry used by the elevated child. Never pass these by hand.
    [ValidateSet('ApplyRegistration', 'RemoveRegistration')]
    [string]$InternalElevatedOperation,
    [string]$InternalResultPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

$script:StateRoot = 'C:\ProgramData\astrolabe-kill-attribution'
$script:MonitorScriptPath = Join-Path $script:StateRoot 'monitor.ps1'
$script:KillsLogPath = Join-Path $script:StateRoot 'kills.log'
$script:BaselinePath = Join-Path $script:StateRoot 'ifeo-before.json'
$script:IfeoRoot =
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$script:SilentProcessExitRoot =
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
# FLG_MONITOR_SILENT_PROCESS_EXIT. This is the ONLY GlobalFlag bit this script
# ever sets; every other bit changes loader/heap runtime behavior.
$script:MonitorSilentProcessExitFlag = 0x200
# LAUNCH_MONITORPROCESS. 2 (LOCAL_DUMP) is deliberately unreachable here.
$script:ReportingModeLaunchMonitorProcess = 1
$script:WindowsPowerShell =
    Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:DefaultTestImage = 'astrolabe-kill-victim.exe'

function Fail-Astro {
    param([string]$Code, [string]$Message, [string]$Remediation)
    $exception = [InvalidOperationException]::new($Message)
    $exception.Data['AstroCode'] = $Code
    $exception.Data['AstroRemediation'] = $Remediation
    throw $exception
}

function Write-AstroStructuredFailure {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    $code = 'ASTRO_KILL_ATTRIBUTION_FAILED'
    $remediation = 'inspect the message, repair the named state, and rerun the same operation'
    if ($null -ne $ErrorRecord.Exception.Data -and
        $ErrorRecord.Exception.Data.Contains('AstroCode')) {
        $code = [string]$ErrorRecord.Exception.Data['AstroCode']
        $remediation = [string]$ErrorRecord.Exception.Data['AstroRemediation']
    }
    $payload = [ordered]@{
        code = $code
        message = $ErrorRecord.Exception.Message
        remediation = $remediation
    }
    [Console]::Error.WriteLine(($payload | ConvertTo-Json -Depth 6 -Compress))
}

function Test-AstroElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-AstroImageName {
    param([string]$Name)
    # IFEO/SilentProcessExit keys are keyed by bare image name. A path separator
    # or wildcard here would silently register nothing, or the wrong thing.
    if ([string]::IsNullOrWhiteSpace($Name) -or
        $Name -match '[\\/:*?"<>|]' -or
        $Name -notmatch '^[A-Za-z0-9._+-]+\.exe$') {
        Fail-Astro 'ASTRO_KILL_ATTRIBUTION_IMAGE_INVALID' `
            "image '$Name' is not a bare executable image name" `
            'pass the bare image file name only, for example: -Image astrolabe.exe'
    }
    return $Name
}

# ---------------------------------------------------------------------------
# Monitor script (written to ProgramData; launched by WerSvc at kill time)
# ---------------------------------------------------------------------------

$script:MonitorScriptSource = @'
# Astrolabe kill-attribution monitor (#1059).
#
# Launched by WerSvc (Silent Process Exit / LAUNCH_MONITORPROCESS) at the moment
# a monitored image is terminated by ANOTHER process. IgnoreSelfExits=1, so an
# ordinary self-exit never reaches this script. WerSvc substitutes:
#   %e exiting process id   %i initiating process id
#   %t initiating thread id %c exit status
#
# WerSvc launches it as the OWNER OF THE DYING PROCESS (proven by readback:
# monitor_identity was the interactive user, not SYSTEM), detached from any
# console, which is why the state root is ACL'd for BUILTIN\Users. It must never throw
# out: an unhandled fault here would lose the only record of the kill, so every
# fault is written into the same log line instead.
param(
    [string]$ExitingPid = '<absent>',
    [string]$InitiatingPid = '<absent>',
    [string]$InitiatingTid = '<absent>',
    [string]$StatusCode = '<absent>'
)

$ErrorActionPreference = 'Stop'
$logPath = Join-Path $PSScriptRoot 'kills.log'

function ConvertTo-LongOrNull([string]$Value) {
    $parsed = 0L
    if ([long]::TryParse($Value, [ref]$parsed)) { return $parsed }
    return $null
}

function Resolve-Initiator([string]$RawPid) {
    $numeric = ConvertTo-LongOrNull $RawPid
    if ($null -eq $numeric) {
        return [ordered]@{
            state = 'unevaluable'
            reason = "initiating pid '$RawPid' is not numeric (WerSvc substitution may have failed)"
        }
    }
    if ($numeric -le 0) {
        return [ordered]@{
            state = 'unevaluable'
            reason = "initiating pid $numeric is not a real process id"
        }
    }
    try {
        $process = Get-CimInstance -ClassName Win32_Process `
            -Filter "ProcessId = $numeric" -ErrorAction Stop
    }
    catch {
        return [ordered]@{
            state = 'unevaluable'
            pid = $numeric
            reason = "Win32_Process query failed: $($_.Exception.Message)"
        }
    }
    if ($null -eq $process) {
        # Expected whenever the killer exits immediately after the kill (a
        # one-shot `powershell -Command Stop-Process ...`). The pid is still the
        # attribution; only its live details are gone.
        return [ordered]@{
            state = 'gone'
            pid = $numeric
            name = '<gone>'
            path = '<gone>'
            command_line = '<gone>'
            parent_pid = $null
            parent_name = '<gone>'
            create_date = $null
            reason = 'the initiating process had already exited when the monitor queried it'
        }
    }
    $parentName = '<unresolved>'
    $parentPid = $null
    try {
        $parentPid = [long]$process.ParentProcessId
        if ($parentPid -gt 0) {
            $parent = Get-CimInstance -ClassName Win32_Process `
                -Filter "ProcessId = $parentPid" -ErrorAction Stop
            $parentName = if ($null -eq $parent) { '<gone>' } else { [string]$parent.Name }
        }
    }
    catch { $parentName = "<unevaluable: $($_.Exception.Message)>" }
    $createDate = $null
    try {
        if ($null -ne $process.CreationDate) {
            $createDate = ([datetime]$process.CreationDate).ToUniversalTime().ToString('o')
        }
    }
    catch { $createDate = '<unevaluable>' }
    return [ordered]@{
        state = 'resolved'
        pid = $numeric
        name = [string]$process.Name
        path = [string]$process.ExecutablePath
        command_line = [string]$process.CommandLine
        parent_pid = $parentPid
        parent_name = $parentName
        create_date = $createDate
    }
}

function Write-LogLine([string]$Line) {
    # WerSvc can launch several monitors at once. Retry the exclusive append
    # rather than dropping a kill record.
    $bytes = [Text.Encoding]::UTF8.GetBytes($Line + "`r`n")
    for ($attempt = 1; $attempt -le 40; $attempt++) {
        try {
            $stream = [IO.FileStream]::new(
                $logPath, [IO.FileMode]::Append, [IO.FileAccess]::Write,
                [IO.FileShare]::Read)
            try {
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Flush($true)
            }
            finally { $stream.Dispose() }
            return $true
        }
        catch {
            Start-Sleep -Milliseconds 50
        }
    }
    return $false
}

$record = [ordered]@{
    schema = 'astrolabe.kill-attribution.v1'
    utc = [DateTime]::UtcNow.ToString('o')
    monitor_pid = $PID
    monitor_identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    exiting_pid_raw = $ExitingPid
    exiting_pid = ConvertTo-LongOrNull $ExitingPid
    initiating_pid_raw = $InitiatingPid
    initiating_pid = ConvertTo-LongOrNull $InitiatingPid
    initiating_tid_raw = $InitiatingTid
    initiating_tid = ConvertTo-LongOrNull $InitiatingTid
    status_code_raw = $StatusCode
    status_code_hex = $null
    initiator = $null
    monitor_error = $null
}
try {
    $status = ConvertTo-LongOrNull $StatusCode
    if ($null -ne $status) {
        $record.status_code_hex = '0x' + ([uint32]($status -band 0xFFFFFFFFL)).ToString('X8')
    }
    $record.initiator = Resolve-Initiator $InitiatingPid
}
catch {
    $record.monitor_error = $_.Exception.Message
}
$line = $record | ConvertTo-Json -Depth 8 -Compress
if (-not (Write-LogLine $line)) {
    # Last resort so a lost record is still discoverable. It must NOT borrow
    # another component's event source: writing under 'Application Error' would
    # forge a crash record for a process that never crashed.
    try {
        $fallback = Join-Path ([IO.Path]::GetTempPath()) 'astrolabe-kill-attribution-fallback.log'
        [IO.File]::AppendAllText($fallback,
            "could not append to $logPath : $line`r`n", [Text.Encoding]::UTF8)
    }
    catch { }
    exit 1
}
exit 0
'@

function Get-AstroMonitorCommand {
    # WerSvc substitutes %e/%i/%t/%c inside this command line at kill time.
    return ('"{0}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{1}" ' +
        '-ExitingPid %e -InitiatingPid %i -InitiatingTid %t -StatusCode %c') -f
        $script:WindowsPowerShell, $script:MonitorScriptPath
}

# ---------------------------------------------------------------------------
# Registry read (works unelevated; HKLM read is not privileged)
# ---------------------------------------------------------------------------

function Get-AstroRegistryValueState {
    param([string]$KeyPath, [string]$ValueName)
    $native = $KeyPath -replace '^HKLM:\\', ''
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($native, $false)
    if ($null -eq $key) {
        return [ordered]@{ key_exists = $false; present = $false; value = $null; kind = $null }
    }
    try {
        $names = @($key.GetValueNames())
        if ($names -notcontains $ValueName) {
            return [ordered]@{ key_exists = $true; present = $false; value = $null; kind = $null }
        }
        return [ordered]@{
            key_exists = $true
            present = $true
            value = $key.GetValue($ValueName)
            kind = [string]$key.GetValueKind($ValueName)
        }
    }
    finally { $key.Dispose() }
}

function Get-AstroImageRegistrationState {
    param([string]$ImageName)
    $ifeoKey = Join-Path $script:IfeoRoot $ImageName
    $speKey = Join-Path $script:SilentProcessExitRoot $ImageName
    $globalFlag = Get-AstroRegistryValueState $ifeoKey 'GlobalFlag'
    $flagNumeric = $null
    if ($globalFlag.present) {
        $parsed = 0L
        if ([long]::TryParse([string]$globalFlag.value, [ref]$parsed)) { $flagNumeric = $parsed }
        elseif ($globalFlag.value -is [int]) { $flagNumeric = [long]$globalFlag.value }
    }
    $reportingMode = Get-AstroRegistryValueState $speKey 'ReportingMode'
    $monitorProcess = Get-AstroRegistryValueState $speKey 'MonitorProcess'
    $ignoreSelfExits = Get-AstroRegistryValueState $speKey 'IgnoreSelfExits'
    $armed = $globalFlag.present -and $null -ne $flagNumeric -and
        (($flagNumeric -band $script:MonitorSilentProcessExitFlag) -eq
            $script:MonitorSilentProcessExitFlag) -and
        $reportingMode.present -and
        ([int]$reportingMode.value -eq $script:ReportingModeLaunchMonitorProcess) -and
        $monitorProcess.present -and
        ([string]$monitorProcess.value).Contains($script:MonitorScriptPath)
    return [ordered]@{
        image = $ImageName
        armed = [bool]$armed
        ifeo_key = $ifeoKey
        global_flag = [ordered]@{
            present = $globalFlag.present
            value = $globalFlag.value
            kind = $globalFlag.kind
            numeric = $flagNumeric
            monitor_bit_set = ($null -ne $flagNumeric -and
                ($flagNumeric -band $script:MonitorSilentProcessExitFlag) -eq
                    $script:MonitorSilentProcessExitFlag)
        }
        silent_process_exit_key = $speKey
        silent_process_exit_key_exists = $reportingMode.key_exists
        reporting_mode = [ordered]@{
            present = $reportingMode.present; value = $reportingMode.value; kind = $reportingMode.kind
        }
        ignore_self_exits = [ordered]@{
            present = $ignoreSelfExits.present; value = $ignoreSelfExits.value; kind = $ignoreSelfExits.kind
        }
        monitor_process = [ordered]@{
            present = $monitorProcess.present; value = $monitorProcess.value; kind = $monitorProcess.kind
        }
    }
}

function Get-AstroStateSummary {
    param([string[]]$Images)
    $monitorPresent = Test-Path -LiteralPath $script:MonitorScriptPath -PathType Leaf
    $logPresent = Test-Path -LiteralPath $script:KillsLogPath -PathType Leaf
    $baselinePresent = Test-Path -LiteralPath $script:BaselinePath -PathType Leaf
    return [ordered]@{
        state_root = $script:StateRoot
        state_root_exists = (Test-Path -LiteralPath $script:StateRoot -PathType Container)
        monitor_script = [ordered]@{
            path = $script:MonitorScriptPath
            present = $monitorPresent
            sha256 = if ($monitorPresent) {
                (Get-FileHash -LiteralPath $script:MonitorScriptPath -Algorithm SHA256).Hash
            } else { $null }
        }
        kills_log = [ordered]@{
            path = $script:KillsLogPath
            present = $logPresent
            bytes = if ($logPresent) { (Get-Item -LiteralPath $script:KillsLogPath).Length } else { 0 }
            lines = if ($logPresent) {
                @(Get-Content -LiteralPath $script:KillsLogPath -ErrorAction SilentlyContinue).Count
            } else { 0 }
        }
        baseline = [ordered]@{
            path = $script:BaselinePath
            present = $baselinePresent
            images = if ($baselinePresent) {
                # Enumerate the property objects, not `.Properties.Name`: an
                # empty baseline ({}) makes the member-access form fault under
                # StrictMode.
                @((Get-Content -Raw -LiteralPath $script:BaselinePath |
                    ConvertFrom-Json).PSObject.Properties | ForEach-Object { $_.Name })
            } else { @() }
        }
        elevated_caller = (Test-AstroElevated)
        images = @($Images | ForEach-Object { Get-AstroImageRegistrationState $_ })
    }
}

# ---------------------------------------------------------------------------
# Elevated half: the only code that writes HKLM or ProgramData
# ---------------------------------------------------------------------------

function Invoke-AstroElevatedApply {
    param([string]$ImageName, [string]$FlagKind)

    if (-not (Test-Path -LiteralPath $script:StateRoot -PathType Container)) {
        [void][IO.Directory]::CreateDirectory($script:StateRoot)
    }
    # WerSvc launches MonitorProcess as the OWNER OF THE DYING PROCESS, not as
    # SYSTEM (proven: monitor_identity=CABDRU\hotra in the #1059 FSV). A
    # directory created by the elevated half is read-only for BUILTIN\Users, so
    # without this grant every monitor run resolves the killer correctly and then
    # fails to append the record — the exact silent-loss failure this tool exists
    # to prevent. Not a security decision (#740): a local diagnostic log the
    # monitored processes must be able to write.
    $acl = Get-Acl -LiteralPath $script:StateRoot
    $usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $usersSid,
        [Security.AccessControl.FileSystemRights]::Modify,
        ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $script:StateRoot -AclObject $acl
    Set-Content -LiteralPath $script:MonitorScriptPath `
        -Value $script:MonitorScriptSource -Encoding UTF8 -NoNewline:$false
    if (-not (Test-Path -LiteralPath $script:KillsLogPath -PathType Leaf)) {
        Set-Content -LiteralPath $script:KillsLogPath -Value '' -NoNewline -Encoding UTF8
    }

    # Baseline capture: record the PRE-EXISTING state once per image and never
    # overwrite it, otherwise Disable would restore state we wrote ourselves.
    $baseline = if (Test-Path -LiteralPath $script:BaselinePath -PathType Leaf) {
        Get-Content -Raw -LiteralPath $script:BaselinePath | ConvertFrom-Json
    } else { [pscustomobject]@{} }
    $baselineCaptured = $false
    if (-not $baseline.PSObject.Properties[$ImageName]) {
        $before = Get-AstroImageRegistrationState $ImageName
        $baseline | Add-Member -NotePropertyName $ImageName -NotePropertyValue ([ordered]@{
            captured_utc = [DateTime]::UtcNow.ToString('o')
            ifeo_key_existed = [bool]$before.global_flag.present -or
                ($null -ne ([Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                    ($before.ifeo_key -replace '^HKLM:\\', ''), $false)))
            global_flag_present = [bool]$before.global_flag.present
            global_flag_value = $before.global_flag.value
            global_flag_kind = $before.global_flag.kind
            silent_process_exit_key_existed = [bool]$before.silent_process_exit_key_exists
        })
        $baseline | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $script:BaselinePath -Encoding UTF8
        $baselineCaptured = $true
    }

    $ifeoNative = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$ImageName"
    $speNative = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$ImageName"

    # GlobalFlag: preserve every pre-existing bit and OR in ONLY 0x200.
    $existing = Get-AstroImageRegistrationState $ImageName
    $existingFlag = if ($null -ne $existing.global_flag.numeric) {
        [long]$existing.global_flag.numeric
    } else { 0L }
    $newFlag = $existingFlag -bor $script:MonitorSilentProcessExitFlag
    $ifeoKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($ifeoNative)
    try {
        if ($FlagKind -ceq 'String') {
            $ifeoKey.SetValue('GlobalFlag',
                $newFlag.ToString([Globalization.CultureInfo]::InvariantCulture),
                [Microsoft.Win32.RegistryValueKind]::String)
        }
        else {
            $ifeoKey.SetValue('GlobalFlag', [int]$newFlag,
                [Microsoft.Win32.RegistryValueKind]::DWord)
        }
    }
    finally { $ifeoKey.Dispose() }

    $speKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($speNative)
    try {
        # ReportingMode 1 = LAUNCH_MONITORPROCESS only. LOCAL_DUMP (2) is never
        # written: dumping a multi-gigabyte working set would be catastrophic.
        $speKey.SetValue('ReportingMode',
            [int]$script:ReportingModeLaunchMonitorProcess,
            [Microsoft.Win32.RegistryValueKind]::DWord)
        # Fire only on cross-process termination, so ordinary MCP/CLI exits of
        # the same image write nothing.
        $speKey.SetValue('IgnoreSelfExits', [int]1,
            [Microsoft.Win32.RegistryValueKind]::DWord)
        $speKey.SetValue('MonitorProcess', (Get-AstroMonitorCommand),
            [Microsoft.Win32.RegistryValueKind]::String)
    }
    finally { $speKey.Dispose() }

    return [ordered]@{
        action = 'ApplyRegistration'
        image = $ImageName
        global_flag_kind = $FlagKind
        global_flag_before = $existingFlag
        global_flag_after = $newFlag
        baseline_captured_now = $baselineCaptured
        readback = Get-AstroImageRegistrationState $ImageName
    }
}

function Invoke-AstroElevatedRemove {
    param([string]$ImageName)

    $before = Get-AstroImageRegistrationState $ImageName
    $baseline = if (Test-Path -LiteralPath $script:BaselinePath -PathType Leaf) {
        Get-Content -Raw -LiteralPath $script:BaselinePath | ConvertFrom-Json
    } else { $null }
    $entry = if ($null -ne $baseline -and $baseline.PSObject.Properties[$ImageName]) {
        $baseline.$ImageName
    } else { $null }
    if ($null -eq $entry) {
        Fail-Astro 'ASTRO_KILL_ATTRIBUTION_BASELINE_MISSING' `
            "no captured pre-existing state for image '$ImageName' in $script:BaselinePath" `
            'refusing to guess the original GlobalFlag; restore the baseline file or remove the values by hand after inspecting them'
    }

    $ifeoNative = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$ImageName"
    $speNative = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$ImageName"

    # SilentProcessExit: remove the whole subkey only if we created it.
    $speRemoved = $false
    if (-not [bool]$entry.silent_process_exit_key_existed) {
        $speParent = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit', $true)
        if ($null -ne $speParent) {
            try {
                if (@($speParent.GetSubKeyNames()) -contains $ImageName) {
                    $speParent.DeleteSubKeyTree($ImageName)
                    $speRemoved = $true
                }
            }
            finally { $speParent.Dispose() }
        }
    }
    else {
        # The key pre-dated us: remove only the three values we wrote.
        $speKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($speNative, $true)
        if ($null -ne $speKey) {
            try {
                foreach ($name in @('ReportingMode', 'IgnoreSelfExits', 'MonitorProcess')) {
                    if (@($speKey.GetValueNames()) -contains $name) {
                        $speKey.DeleteValue($name, $false)
                    }
                }
                $speRemoved = $true
            }
            finally { $speKey.Dispose() }
        }
    }

    # GlobalFlag: restore the captured original exactly, or remove the value we
    # introduced. Never delete an IFEO key that pre-dated this script.
    $globalFlagAction = 'unchanged'
    $ifeoKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($ifeoNative, $true)
    if ($null -ne $ifeoKey) {
        try {
            if ([bool]$entry.global_flag_present) {
                $kind = if ([string]$entry.global_flag_kind -ceq 'DWord') {
                    [Microsoft.Win32.RegistryValueKind]::DWord
                } else { [Microsoft.Win32.RegistryValueKind]::String }
                $value = if ($kind -eq [Microsoft.Win32.RegistryValueKind]::DWord) {
                    [int]$entry.global_flag_value
                } else { [string]$entry.global_flag_value }
                $ifeoKey.SetValue('GlobalFlag', $value, $kind)
                $globalFlagAction = 'restored-preexisting'
            }
            elseif (@($ifeoKey.GetValueNames()) -contains 'GlobalFlag') {
                $ifeoKey.DeleteValue('GlobalFlag', $false)
                $globalFlagAction = 'removed'
            }
        }
        finally { $ifeoKey.Dispose() }
    }

    # Remove an IFEO subkey only when this script created it AND it is now empty.
    $ifeoKeyRemoved = $false
    if (-not [bool]$entry.ifeo_key_existed) {
        $ifeoParent = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', $true)
        if ($null -ne $ifeoParent) {
            try {
                $child = $ifeoParent.OpenSubKey($ImageName, $false)
                if ($null -ne $child) {
                    $empty = (@($child.GetValueNames()).Count -eq 0 -and
                        @($child.GetSubKeyNames()).Count -eq 0)
                    $child.Dispose()
                    if ($empty) {
                        $ifeoParent.DeleteSubKey($ImageName)
                        $ifeoKeyRemoved = $true
                    }
                }
            }
            finally { $ifeoParent.Dispose() }
        }
    }

    # Drop the baseline entry so a later Enable captures a fresh, honest baseline.
    $remaining = [ordered]@{}
    foreach ($property in $baseline.PSObject.Properties) {
        if ($property.Name -cne $ImageName) { $remaining[$property.Name] = $property.Value }
    }
    ($remaining | ConvertTo-Json -Depth 8) |
        Set-Content -LiteralPath $script:BaselinePath -Encoding UTF8

    return [ordered]@{
        action = 'RemoveRegistration'
        image = $ImageName
        before = $before
        silent_process_exit_removed = $speRemoved
        global_flag_action = $globalFlagAction
        ifeo_key_removed = $ifeoKeyRemoved
        readback = Get-AstroImageRegistrationState $ImageName
    }
}

# ---------------------------------------------------------------------------
# Elevation: run the mutating half with a full administrator token
# ---------------------------------------------------------------------------

function Get-AstroElevatedCommandText {
    param([string]$Action, [string]$ImageName, [string]$FlagKind)
    $publicOperation = if ($Action -ceq 'ApplyRegistration') { 'Enable' } else { 'Disable' }
    return ('"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}" -Operation {2} ' +
        '-Image {3} -GlobalFlagKind {4}') -f
        $script:WindowsPowerShell, $PSCommandPath, $publicOperation, $ImageName, $FlagKind
}

function Invoke-AstroElevatedAction {
    param(
        [ValidateSet('ApplyRegistration', 'RemoveRegistration')][string]$Action,
        [string]$ImageName,
        [string]$FlagKind
    )

    if (Test-AstroElevated) {
        Write-Host "ELEVATION[already-elevated]: running $Action for $ImageName in-process"
        return @{
            mechanism = 'already-elevated'
            attempts = @('already-elevated')
            result = if ($Action -ceq 'ApplyRegistration') {
                Invoke-AstroElevatedApply $ImageName $FlagKind
            } else {
                Invoke-AstroElevatedRemove $ImageName
            }
        }
    }

    $resultPath = Join-Path ([IO.Path]::GetTempPath()) (
        'astro-kill-attribution-{0}.json' -f [Guid]::NewGuid().ToString('n'))
    $arguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`"",
        '-Operation', 'Status',
        '-Image', $ImageName,
        '-GlobalFlagKind', $FlagKind,
        '-InternalElevatedOperation', $Action,
        '-InternalResultPath', "`"$resultPath`""
    )
    $attempts = [Collections.Generic.List[string]]::new()

    # Mechanism 1: elevated re-launch of this same script. The child writes its
    # structured result to a file because -Verb RunAs cannot redirect streams.
    $childExit = $null
    try {
        $child = Start-Process -FilePath $script:WindowsPowerShell `
            -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -Wait -PassThru
        $childExit = $child.ExitCode
        $attempts.Add("runas(exit=$childExit)")
    }
    catch {
        $attempts.Add("runas(failed: $($_.Exception.Message))")
    }

    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        # Mechanism 2: one-shot scheduled task with /RL HIGHEST. Windows denies
        # this to a non-elevated caller on a default host, so it is a genuine
        # second chance, never a silent substitute: the failure is reported.
        $taskName = 'AstrolabeKillAttributionOneShot'
        $taskCommand = ('"{0}" {1}' -f $script:WindowsPowerShell, ($arguments -join ' '))
        try {
            $create = & schtasks.exe /create /TN $taskName /TR $taskCommand /SC ONCE `
                /ST 23:59 /RL HIGHEST /F 2>&1
            if ($LASTEXITCODE -ne 0) {
                $attempts.Add("schtasks-create(failed: $($create -join ' '))")
            }
            else {
                $attempts.Add('schtasks-create(ok)')
                $run = & schtasks.exe /run /TN $taskName 2>&1
                $attempts.Add("schtasks-run(rc=$LASTEXITCODE; $($run -join ' '))")
                $deadline = (Get-Date).AddSeconds(60)
                while ((Get-Date) -lt $deadline -and
                    -not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
                    Start-Sleep -Milliseconds 300
                }
                & schtasks.exe /delete /TN $taskName /F *> $null
            }
        }
        catch {
            $attempts.Add("schtasks(failed: $($_.Exception.Message))")
        }
    }

    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        Fail-Astro 'ASTRO_KILL_ATTRIBUTION_ELEVATION_UNAVAILABLE' `
            ("no elevation mechanism produced a result for $Action on '$ImageName' " +
            "(attempts: $($attempts -join '; '); child_exit=$childExit)") `
            ("run this command yourself from an elevated PowerShell, then rerun the " +
            "unelevated Status/Test operation: " + (Get-AstroElevatedCommandText $Action $ImageName $FlagKind))
    }

    $payload = Get-Content -Raw -LiteralPath $resultPath | ConvertFrom-Json
    Remove-Item -LiteralPath $resultPath -Force
    if ([string]$payload.status -cne 'ok') {
        Fail-Astro 'ASTRO_KILL_ATTRIBUTION_ELEVATED_CHILD_FAILED' `
            ("the elevated $Action for '$ImageName' failed: " +
            "$($payload.error.code): $($payload.error.message)") `
            ([string]$payload.error.remediation)
    }
    $mechanism = if ($attempts -join ' ' -match 'schtasks-run') {
        'scheduled-task(/RL HIGHEST)'
    } else { 'runas(Start-Process -Verb RunAs)' }
    Write-Host "ELEVATION[$mechanism]: $Action for $ImageName succeeded (attempts: $($attempts -join '; '))"
    return @{ mechanism = $mechanism; attempts = @($attempts); result = $payload.result }
}

# ---------------------------------------------------------------------------
# Internal elevated child entry
# ---------------------------------------------------------------------------

if (-not [string]::IsNullOrEmpty($InternalElevatedOperation)) {
    if ([string]::IsNullOrWhiteSpace($InternalResultPath)) {
        Write-AstroStructuredFailure (
            [System.Management.Automation.ErrorRecord]::new(
                [InvalidOperationException]::new(
                    '-InternalElevatedOperation requires -InternalResultPath'),
                'ASTRO_KILL_ATTRIBUTION_INTERNAL_INVOCATION_INVALID',
                [System.Management.Automation.ErrorCategory]::InvalidArgument, $null))
        exit 2
    }
    $childImage = @($Image)[0]
    $payload = $null
    try {
        [void](Assert-AstroImageName $childImage)
        if (-not (Test-AstroElevated)) {
            Fail-Astro 'ASTRO_KILL_ATTRIBUTION_ELEVATION_UNAVAILABLE' `
                'the internal elevated child is not running with an administrator token' `
                'invoke the elevated command printed by the parent from an elevated PowerShell'
        }
        $result = if ($InternalElevatedOperation -ceq 'ApplyRegistration') {
            Invoke-AstroElevatedApply $childImage $GlobalFlagKind
        } else {
            Invoke-AstroElevatedRemove $childImage
        }
        $payload = [ordered]@{
            status = 'ok'
            operation = $InternalElevatedOperation
            image = $childImage
            elevated_identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            utc = [DateTime]::UtcNow.ToString('o')
            result = $result
        }
    }
    catch {
        $code = 'ASTRO_KILL_ATTRIBUTION_ELEVATED_CHILD_FAILED'
        $remediation = 'inspect the message and repair the named registry/ProgramData state'
        if ($null -ne $_.Exception.Data -and $_.Exception.Data.Contains('AstroCode')) {
            $code = [string]$_.Exception.Data['AstroCode']
            $remediation = [string]$_.Exception.Data['AstroRemediation']
        }
        $payload = [ordered]@{
            status = 'failed'
            operation = $InternalElevatedOperation
            image = $childImage
            utc = [DateTime]::UtcNow.ToString('o')
            error = [ordered]@{ code = $code; message = $_.Exception.Message; remediation = $remediation }
        }
    }
    ($payload | ConvertTo-Json -Depth 12) |
        Set-Content -LiteralPath $InternalResultPath -Encoding UTF8
    exit $(if ([string]$payload.status -ceq 'ok') { 0 } else { 1 })
}

# ---------------------------------------------------------------------------
# Test operation: prove the mechanism end to end against a scratch image
# ---------------------------------------------------------------------------

function Wait-AstroKillRecord {
    param([long]$ExitingProcessId, [int]$TimeoutSeconds, [long]$SkipLines)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $script:KillsLogPath -PathType Leaf) {
            $lines = @(Get-Content -LiteralPath $script:KillsLogPath -ErrorAction SilentlyContinue)
            for ($index = [int]$SkipLines; $index -lt $lines.Count; $index++) {
                $line = [string]$lines[$index]
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                try { $record = $line | ConvertFrom-Json } catch { continue }
                if ($null -ne $record.exiting_pid -and
                    [long]$record.exiting_pid -eq $ExitingProcessId) {
                    return $record
                }
            }
        }
        Start-Sleep -Milliseconds 400
    }
    return $null
}

function Get-AstroKillsLogLineCount {
    if (-not (Test-Path -LiteralPath $script:KillsLogPath -PathType Leaf)) { return 0 }
    return @(Get-Content -LiteralPath $script:KillsLogPath -ErrorAction SilentlyContinue).Count
}

function Get-AstroExitMonitorEvents {
    param([datetime]$SinceUtc)
    # Event ID: the channel record is written by provider
    # Microsoft-Windows-ProcessExitMonitor as event 3001 on Windows 11 26100
    # (proven by readback in #1059 — the commonly cited "Process Exit Monitor /
    # 3000" is the legacy pairing), so both ids are accepted and the observed
    # provider/id is reported rather than assumed.
    #
    # The leading comma is load-bearing: `return @()` unrolls to $null in
    # PowerShell, and StrictMode then faults on the caller's .Count.
    try {
        return , @(Get-WinEvent -FilterHashtable @{
                LogName = 'Application'; Id = @(3000, 3001); StartTime = $SinceUtc.ToLocalTime()
            } -ErrorAction Stop)
    }
    catch { return , @() }
}

function Resolve-AstroTestVictim {
    param([string]$ImageName)
    # Default victim: a scratch-named copy of cmd.exe. Windows 11 ships
    # IFEO\notepad.exe with UseFilter=1 plus AppExecutionAlias redirect subkeys
    # (0/1/2 -> FilterFullPath), so a top-level GlobalFlag on that image is not
    # the configuration the loader consults and `notepad.exe` never fires. A
    # scratch image name has no shipped IFEO policy, so it exercises exactly the
    # registration astrolabe.exe will get.
    if ($ImageName -ceq $script:DefaultTestImage) {
        $victimRoot = Join-Path ([IO.Path]::GetTempPath()) 'astrolabe-kill-attribution-test'
        [void][IO.Directory]::CreateDirectory($victimRoot)
        $victimPath = Join-Path $victimRoot $ImageName
        Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') `
            -Destination $victimPath -Force
        return [ordered]@{
            path = $victimPath
            arguments = @('/c', 'pause')
            scratch_root = $victimRoot
            source = (Join-Path $env:SystemRoot 'System32\cmd.exe')
        }
    }
    $systemPath = Join-Path $env:SystemRoot "System32\$ImageName"
    if (-not (Test-Path -LiteralPath $systemPath -PathType Leaf)) {
        Fail-Astro 'ASTRO_KILL_ATTRIBUTION_IMAGE_INVALID' `
            "test victim image '$ImageName' was not found at $systemPath" `
            "pass -TestImage $script:DefaultTestImage to use the scratch victim, or name an image present in System32"
    }
    return [ordered]@{
        path = $systemPath; arguments = @(); scratch_root = $null; source = $systemPath
    }
}

function Invoke-AstroKillAttributionTest {
    param([string]$FlagKind, [int]$TimeoutSeconds, [string]$VictimImage)

    $image = Assert-AstroImageName $VictimImage
    $victim = Resolve-AstroTestVictim $image
    Write-Host '=============================================================='
    Write-Host "TEST[before]: state for '$image' (GlobalFlagKind=$FlagKind)"
    Write-Host ("TEST[victim]: image={0}; args={1}" -f $victim.path, ($victim.arguments -join ' '))
    Write-Host '=============================================================='
    (Get-AstroStateSummary @($image)) | ConvertTo-Json -Depth 12 | Write-Host

    $apply = Invoke-AstroElevatedAction 'ApplyRegistration' $image $FlagKind
    Write-Host '--------------------------------------------------------------'
    Write-Host "TEST[registered]: independent unelevated registry readback for '$image'"
    Write-Host '--------------------------------------------------------------'
    $armedState = Get-AstroImageRegistrationState $image
    $armedState | ConvertTo-Json -Depth 12 | Write-Host
    if (-not $armedState.armed) {
        Fail-Astro 'ASTRO_KILL_ATTRIBUTION_REGISTRY_READBACK_FAILED' `
            "independent readback shows '$image' is not armed after the elevated apply" `
            'inspect the printed readback; the elevated child reported success, so the registry changed under us'
    }

    $findings = [ordered]@{
        global_flag_kind = $FlagKind
        elevation_mechanism = $apply.mechanism
        legs = [Collections.Generic.List[object]]::new()
    }

    # Leg 1: the killer stays alive, so initiator details must resolve fully.
    # Leg 2: the killer exits immediately, exercising the '<gone>' path.
    #
    # The registration is removed in the finally below even when a leg fails:
    # leaving a scratch image armed on the host would be a leaked mutation.
    try {
    foreach ($leg in @(
            @{ name = 'killer-alive'; linger = 25 },
            @{ name = 'killer-exits-immediately'; linger = 0 })) {

        $startUtc = [DateTime]::UtcNow.AddSeconds(-2)
        $skip = Get-AstroKillsLogLineCount
        $victimProcess = if (@($victim.arguments).Count -gt 0) {
            Start-Process -FilePath $victim.path -ArgumentList @($victim.arguments) `
                -WindowStyle Hidden -PassThru
        } else {
            Start-Process -FilePath $victim.path -PassThru
        }
        Start-Sleep -Seconds 2
        $killerScript = if ($leg.linger -gt 0) {
            "Stop-Process -Id $($victimProcess.Id) -Force; Start-Sleep -Seconds $($leg.linger)"
        } else {
            "Stop-Process -Id $($victimProcess.Id) -Force"
        }
        $killer = Start-Process -FilePath $script:WindowsPowerShell `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $killerScript) `
            -WindowStyle Hidden -PassThru
        Write-Host ("TEST[$($leg.name)]: victim {0} pid={1}; killer powershell pid={2}" -f
            $image, $victimProcess.Id, $killer.Id)

        $record = Wait-AstroKillRecord -ExitingProcessId $victimProcess.Id `
            -TimeoutSeconds $TimeoutSeconds -SkipLines $skip
        $events = Get-AstroExitMonitorEvents -SinceUtc $startUtc
        $matchedEvent = @($events | Where-Object {
                $_.Message -match "\b$($victimProcess.Id)\b" -or $_.Message -match [regex]::Escape($image)
            })

        if ($null -eq $record) {
            Write-Host "TEST[$($leg.name)]: NO kills.log record within ${TimeoutSeconds}s"
        }
        else {
            Write-Host "TEST[$($leg.name)]: kills.log record:"
            $record | ConvertTo-Json -Depth 10 | Write-Host
        }
        Write-Host ("TEST[$($leg.name)]: Application ProcessExitMonitor event (3000/3001) since {0}: total={1}; matching={2}" -f
            $startUtc.ToString('o'), $events.Count, $matchedEvent.Count)
        foreach ($event in ($matchedEvent | Select-Object -First 2)) {
            Write-Host ("  EVENT id={0} provider='{1}' time={2}" -f
                $event.Id, $event.ProviderName, $event.TimeCreated.ToUniversalTime().ToString('o'))
            Write-Host ("  MESSAGE: {0}" -f ($event.Message -replace '\s+', ' '))
        }

        $initiatorMatches = ($null -ne $record -and $null -ne $record.initiating_pid -and
            [long]$record.initiating_pid -eq [long]$killer.Id)
        $findings.legs.Add([ordered]@{
                leg = $leg.name
                victim_pid = $victimProcess.Id
                killer_pid = $killer.Id
                record_present = ($null -ne $record)
                initiating_pid = if ($null -ne $record) { $record.initiating_pid } else { $null }
                initiating_pid_matches_killer = $initiatorMatches
                initiator_state = if ($null -ne $record -and $null -ne $record.initiator) {
                    [string]$record.initiator.state
                } else { $null }
                status_code_raw = if ($null -ne $record) { [string]$record.status_code_raw } else { $null }
                process_exit_monitor_events_total = $events.Count
                process_exit_monitor_events_matching = $matchedEvent.Count
            })

        if ($leg.linger -gt 0) {
            try { Stop-Process -Id $killer.Id -Force -ErrorAction Stop } catch { }
        }
        Start-Sleep -Seconds 1
    }
    }
    finally {
        Write-Host '--------------------------------------------------------------'
        Write-Host "TEST[cleanup]: removing the '$image' registration"
        Write-Host '--------------------------------------------------------------'
        [void](Invoke-AstroElevatedAction 'RemoveRegistration' $image $FlagKind)
        if ($null -ne $victim.scratch_root -and
            (Test-Path -LiteralPath $victim.scratch_root -PathType Container)) {
            Remove-Item -LiteralPath $victim.scratch_root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host "TEST[after]: independent unelevated registry readback for '$image'"
    $afterState = Get-AstroImageRegistrationState $image
    $afterState | ConvertTo-Json -Depth 12 | Write-Host
    if ($afterState.armed) {
        Fail-Astro 'ASTRO_KILL_ATTRIBUTION_REGISTRY_READBACK_FAILED' `
            "independent readback shows '$image' is still armed after removal" `
            'inspect the printed readback and remove the SilentProcessExit/IFEO values by hand from an elevated shell'
    }

    $findings.removal_verified = (-not $afterState.armed -and
        -not $afterState.silent_process_exit_key_exists)
    Write-Host '=============================================================='
    Write-Host 'TEST[verdict]'
    Write-Host '=============================================================='
    $findings | ConvertTo-Json -Depth 10 | Write-Host

    $proven = @($findings.legs | Where-Object { $_.initiating_pid_matches_killer }).Count
    if ($proven -eq 0) {
        Fail-Astro 'ASTRO_KILL_ATTRIBUTION_TEST_NO_RECORD' `
            ("no test leg produced a kills.log record whose initiating_pid equals the killing " +
            "process id (GlobalFlagKind=$FlagKind)") `
            "rerun with -GlobalFlagKind $(if ($FlagKind -ceq 'String') { 'DWord' } else { 'String' }); if neither encoding fires, WerSvc is not consulting the registration on this host"
    }
    return $findings
}

# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------

try {
    # `powershell -File script.ps1 -Image a.exe,b.exe` delivers ONE string, not an
    # array, so split on commas before validating; the validator still refuses
    # anything that is not a bare image name.
    $images = @($Image |
        ForEach-Object { ([string]$_).Split(',') } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { Assert-AstroImageName $_.Trim() })

    switch ($Operation) {
        'Status' {
            (Get-AstroStateSummary $images) | ConvertTo-Json -Depth 12 | Write-Output
        }
        'Enable' {
            foreach ($name in $images) {
                Write-Host "ENABLE[before]: $name"
                (Get-AstroImageRegistrationState $name) | ConvertTo-Json -Depth 12 | Write-Host
                [void](Invoke-AstroElevatedAction 'ApplyRegistration' $name $GlobalFlagKind)
                Write-Host "ENABLE[after]: independent unelevated readback for $name"
                $after = Get-AstroImageRegistrationState $name
                $after | ConvertTo-Json -Depth 12 | Write-Host
                if (-not $after.armed) {
                    Fail-Astro 'ASTRO_KILL_ATTRIBUTION_REGISTRY_READBACK_FAILED' `
                        "independent readback shows '$name' is not armed after the elevated apply" `
                        'inspect the printed readback and rerun; do not treat this image as monitored'
                }
            }
            Write-Host ("ENABLE[done]: monitored images armed. Kill records append to " +
                "$script:KillsLogPath; the mechanism was proven by -Operation Test.")
        }
        'Disable' {
            foreach ($name in $images) {
                Write-Host "DISABLE[before]: $name"
                (Get-AstroImageRegistrationState $name) | ConvertTo-Json -Depth 12 | Write-Host
                [void](Invoke-AstroElevatedAction 'RemoveRegistration' $name $GlobalFlagKind)
                Write-Host "DISABLE[after]: independent unelevated readback for $name"
                $after = Get-AstroImageRegistrationState $name
                $after | ConvertTo-Json -Depth 12 | Write-Host
                if ($after.armed) {
                    Fail-Astro 'ASTRO_KILL_ATTRIBUTION_REGISTRY_READBACK_FAILED' `
                        "independent readback shows '$name' is still armed after removal" `
                        'inspect the printed readback and remove the values by hand from an elevated shell'
                }
            }
            Write-Host "DISABLE[done]: $script:KillsLogPath is deliberately preserved as evidence."
        }
        'Test' {
            [void](Invoke-AstroKillAttributionTest $GlobalFlagKind $TestTimeoutSeconds $TestImage)
            Write-Host "TEST[done]: the mechanism is proven on this host with -GlobalFlagKind $GlobalFlagKind."
        }
    }
    exit 0
}
catch {
    Write-AstroStructuredFailure $_
    exit 1
}
