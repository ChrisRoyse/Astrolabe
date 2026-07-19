<#
.SYNOPSIS
    Session-independent detached launch for long native measurement runs (#391).

.DESCRIPTION
    Wave-14's #42/#23 M-scale measurement runs were killed TWICE mid-run: a native launcher
    run started from an agent's background wrapper is a DESCENDANT of that wrapper's process
    tree, so when the agent kills the wrapper tree (taskkill /T, or a Job Object with
    KILL_ON_JOB_CLOSE that every child inherits) the launcher — and its multi-minute build /
    measurement — dies with it.

    This trampoline breaks that lifetime link by launching the work through the Windows Task
    Scheduler. A task started with `schtasks /Run` executes under the Task Scheduler service
    (a child of svchost.exe), NOT under the calling shell. It is therefore NOT in the caller's
    process tree and NOT in the caller's Job Object, so neither taskkill /T on the caller nor
    the Job Object closing can reach it. The detached run survives the launching session
    entirely.

    The #197/#611 lock protocol is preserved: this trampoline does not touch launcher state.
    Detached work publishes its strict v2 identity `(pid, owner_process_start_utc_ticks,
    issue)` plus the frozen-tree fingerprint, retains the immutable manifest handle, and
    performs exact-owner cleanup. The printed PID is monitoring data only, never reclaim/stop
    authority without its process-start ticks. This trampoline only changes process ancestry.

    Contract (fire-and-forget):
      * Generates a runner .ps1 and a .cmd trampoline (the task action, so schtasks /TR is a
        single clean quoted path — no embedded-argument quoting hazards).
      * The runner writes its own PID to -RunPidFile at start, runs -WorkScript as a CHILD
        process (so the launcher's `exit` cannot kill the runner before it records the result),
        streams combined stdout+stderr to -LogFile, then writes the child exit code to
        -DoneFile and self-deletes the scheduled task.
      * This script registers + starts the task, polls until -RunPidFile appears, prints one
        structured DETACH_RUN[...] line with the real run PID, and EXITS. The caller (and its
        whole process tree) may then die with no effect on the run.

    FSV of the mechanism itself is performed manually against isolated fixture paths: launch a
    long dummy run, kill the launching shell tree, prove the run completes and the lock lifecycle
    stays correct.

.NOTES
    Refs #391, #197. No elevation required: a one-time task in the current user's \ folder is
    created and run with the interactive user token.
#>
[CmdletBinding()]
param(
    # Absolute path to the .ps1 to run detached. For measurement runs this is a batch
    # orchestrator that invokes scripts/windows-gnu-toolchain.ps1 one or more times.
    [Parameter(Mandatory)][string]$WorkScript,
    # JSON array of string arguments forwarded to -WorkScript (e.g. '["-Issue","391"]').
    [string]$WorkArgsJson = "[]",
    # Combined stdout+stderr of the detached work.
    [Parameter(Mandatory)][string]$LogFile,
    # The runner writes its own PID here at start; this script polls it and reports it.
    [Parameter(Mandatory)][string]$RunPidFile,
    # The runner writes the child exit code here at end (completion sentinel).
    [Parameter(Mandatory)][string]$DoneFile,
    # Optional explicit task name; a per-invocation unique name is derived otherwise.
    [string]$TaskName = "",
    # How long to wait for the detached runner to record its PID before failing closed.
    [int]$PidWaitSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

function Resolve-Absolute {
    param([string]$Path)
    return [IO.Path]::GetFullPath($Path)
}

function Ensure-ParentDir {
    param([string]$Path)
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
}

# --- Resolve + validate inputs -------------------------------------------------------------
$WorkScript = Resolve-Absolute $WorkScript
if (-not (Test-Path -LiteralPath $WorkScript -PathType Leaf)) {
    throw "DETACH_RUN[ASTRO_DETACH_WORKSCRIPT_MISSING]: WorkScript not found: $WorkScript"
}
$LogFile = Resolve-Absolute $LogFile
$RunPidFile = Resolve-Absolute $RunPidFile
$DoneFile = Resolve-Absolute $DoneFile
Ensure-ParentDir $LogFile
Ensure-ParentDir $RunPidFile
Ensure-ParentDir $DoneFile

# Validate the forwarded-args JSON parses to a flat string array (5.1-safe normalization).
$parsedArgs = ConvertFrom-Json -InputObject $WorkArgsJson
$workArgs = @()
if ($null -ne $parsedArgs) {
    if (($parsedArgs -is [System.Collections.IEnumerable]) -and ($parsedArgs -isnot [string])) {
        foreach ($a in $parsedArgs) { $workArgs += $a }
    }
    else { $workArgs += $parsedArgs }
}
foreach ($a in $workArgs) {
    if ($a -isnot [string]) { throw "DETACH_RUN[ASTRO_DETACH_ARGS_INVALID]: WorkArgsJson must contain only strings" }
}

if ([string]::IsNullOrWhiteSpace($TaskName)) {
    $TaskName = "astro-detach-$PID-" + (Get-Date).ToString("yyyyMMddHHmmssfff")
}

# Clear stale sentinels from a prior run of these exact paths so our poll can't read them.
foreach ($stale in @($RunPidFile, $DoneFile)) {
    if (Test-Path -LiteralPath $stale) { Remove-Item -LiteralPath $stale -Force }
}

# --- Generate the runner script (baked-in absolute values, no argument quoting hazards) -----
$runnerPath = "$RunPidFile.runner.ps1"
$cmdPath = "$RunPidFile.trampoline.cmd"

# Re-encode the forwarded args as a compact JSON literal the runner re-parses at execution
# time; this keeps arbitrary argument content (paths, JSON payloads) intact across the file.
$workArgsLiteral = (@($workArgs) | ConvertTo-Json -Compress)
if ([string]::IsNullOrWhiteSpace($workArgsLiteral)) { $workArgsLiteral = "[]" }
# ConvertTo-Json on a single-element array yields a scalar under 5.1; force array shape.
if ($workArgs.Count -le 1) { $workArgsLiteral = "[" + (($workArgs | ForEach-Object { ($_ | ConvertTo-Json) }) -join ",") + "]" }

# Absolute paths baked into the runner: the console-immune spawner (#396) and the repo root
# (the launcher hard-refuses non-canonical roots, so the work must run from there).
$detachSpawnPath = Join-Path $PSScriptRoot 'detach-spawn.ps1'
if (-not (Test-Path -LiteralPath $detachSpawnPath -PathType Leaf)) {
    throw "DETACH_RUN[ASTRO_DETACH_SPAWN_MISSING]: detach-spawn.ps1 not found beside detach-run.ps1: $detachSpawnPath"
}
$repoRoot = Split-Path -Parent $PSScriptRoot
$deathFile = "$DoneFile.death"

$runner = @"
# Auto-generated by scripts/detach-run.ps1 (#391, #396). Runs under the Task Scheduler service,
# detached from any calling shell's process tree / Job Object. The WORK is launched via
# Start-FullyDetachedProcess (CREATE_NO_WINDOW + CREATE_NEW_PROCESS_GROUP), giving it its OWN
# windowless console so a console-control event (CTRL_CLOSE/CTRL_C, the wave-15 0xC000013A
# vector, #396) on any launching shell's console cannot reach it.
`$ErrorActionPreference = 'Continue'
`$PSNativeCommandUseErrorActionPreference = `$false
Set-Content -LiteralPath '$RunPidFile' -Value `$PID -Encoding ASCII
if (Test-Path -LiteralPath '$deathFile') { Remove-Item -LiteralPath '$deathFile' -Force }
`$ec = 0
try {
    . '$detachSpawnPath'
    `$fwd = @()
    `$parsed = ConvertFrom-Json -InputObject '$workArgsLiteral'
    if (`$null -ne `$parsed) {
        if ((`$parsed -is [System.Collections.IEnumerable]) -and (`$parsed -isnot [string])) {
            foreach (`$a in `$parsed) { `$fwd += `$a }
        } else { `$fwd += `$parsed }
    }
    `$wargs = @('-NoProfile','-ExecutionPolicy','Bypass','-File','$WorkScript') + `$fwd
    # Launch console-immune, record the real work PID for liveness probes, and wait on the OS
    # handle for the true exit code (own console; the child outlives this runner if killed).
    `$ec = Invoke-FullyDetachedProcessAndWait -FilePath 'powershell.exe' -ArgumentList `$wargs -LogFile '$LogFile' -PidFile '$RunPidFile.work' -WorkingDirectory '$repoRoot'
}
catch {
    `$ec = 70
    ("DETACH_RUNNER_FAULT: " + `$_.Exception.Message) | Out-File -FilePath '$LogFile' -Append -Encoding utf8
    # Death marker for the catchable-failure path (a hard console kill bypasses this; the
    # caller's PID-gone-without-DoneFile probe covers that case).
    `$wp = if (Test-Path -LiteralPath '$RunPidFile.work') { (Get-Content -LiteralPath '$RunPidFile.work' -Raw).Trim() } else { 'unknown' }
    ("DEATH workPid=" + `$wp + " ec=" + `$ec + " reason=" + `$_.Exception.Message) | Set-Content -LiteralPath '$deathFile' -Encoding ASCII
}
finally {
    Set-Content -LiteralPath '$DoneFile' -Value `$ec -Encoding ASCII
    if (`$ec -ne 0 -and -not (Test-Path -LiteralPath '$deathFile')) {
        `$wp = if (Test-Path -LiteralPath '$RunPidFile.work') { (Get-Content -LiteralPath '$RunPidFile.work' -Raw).Trim() } else { 'unknown' }
        ("DEATH workPid=" + `$wp + " ec=" + `$ec + " reason=nonzero-exit") | Set-Content -LiteralPath '$deathFile' -Encoding ASCII
    }
    # Self-clean: remove the one-time task and the generated trampoline/runner files.
    schtasks.exe /Delete /TN '$TaskName' /F *> `$null
    Remove-Item -LiteralPath '$cmdPath' -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath '$runnerPath' -Force -ErrorAction SilentlyContinue
}
"@
Set-Content -LiteralPath $runnerPath -Value $runner -Encoding UTF8

# The .cmd is the task action, so schtasks /TR is a single clean quoted path.
$cmd = "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$runnerPath`"`r`n"
Set-Content -LiteralPath $cmdPath -Value $cmd -Encoding ASCII

# --- Register + start the one-time task -----------------------------------------------------
# /SC ONCE requires a /ST; the concrete time is irrelevant because we trigger via /Run now.
& schtasks.exe /Create /TN $TaskName /TR "`"$cmdPath`"" /SC ONCE /ST 00:00 /F /RL LIMITED
if ($LASTEXITCODE -ne 0) {
    throw "DETACH_RUN[ASTRO_DETACH_TASK_CREATE_FAILED]: schtasks /Create exit=$LASTEXITCODE (task=$TaskName)"
}

# Harden the task settings (#396): schtasks-created tasks default to StopIfGoingOnBatteries=$true
# and a finite ExecutionTimeLimit (PT72H) — both silently kill multi-hour runs. Disarm them at
# creation via the ScheduledTasks module, and read the settings back to fail closed if the harden
# did not take (never present an un-hardened task as ready).
try {
    $hardened = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
    Set-ScheduledTask -TaskName $TaskName -Settings $hardened | Out-Null
    $rb = (Get-ScheduledTask -TaskName $TaskName).Settings
    if ($rb.StopIfGoingOnBatteries -or $rb.DisallowStartIfOnBatteries) {
        throw "battery-stop still armed after harden (Stop=$($rb.StopIfGoingOnBatteries) DisallowStart=$($rb.DisallowStartIfOnBatteries))"
    }
    Write-Output "DETACH_RUN[ASTRO_DETACH_HARDENED]: battery-stop disarmed, ExecutionTimeLimit=$($rb.ExecutionTimeLimit)"
}
catch {
    & schtasks.exe /Delete /TN $TaskName /F *> $null
    throw "DETACH_RUN[ASTRO_DETACH_HARDEN_FAILED]: could not disarm battery/time-limit killers on task=$TaskName : $($_.Exception.Message)"
}
& schtasks.exe /Run /TN $TaskName
if ($LASTEXITCODE -ne 0) {
    & schtasks.exe /Delete /TN $TaskName /F *> $null
    throw "DETACH_RUN[ASTRO_DETACH_TASK_RUN_FAILED]: schtasks /Run exit=$LASTEXITCODE (task=$TaskName)"
}

# --- Poll for the run PID, then report + exit (fire-and-forget) ------------------------------
$deadline = (Get-Date).AddSeconds($PidWaitSeconds)
$runPid = $null
while ((Get-Date) -lt $deadline) {
    if (Test-Path -LiteralPath $RunPidFile) {
        $raw = (Get-Content -LiteralPath $RunPidFile -Raw -ErrorAction SilentlyContinue)
        $parsedPid = 0
        if (-not [string]::IsNullOrWhiteSpace($raw) -and [int]::TryParse($raw.Trim(), [ref]$parsedPid) -and $parsedPid -gt 0) {
            $runPid = $parsedPid
            break
        }
    }
    Start-Sleep -Milliseconds 250
}
if ($null -eq $runPid) {
    & schtasks.exe /Delete /TN $TaskName /F *> $null
    throw "DETACH_RUN[ASTRO_DETACH_PID_TIMEOUT]: the detached runner did not record its PID at $RunPidFile within ${PidWaitSeconds}s (task=$TaskName)"
}

Write-Output "DETACH_RUN[ASTRO_DETACH_STARTED]: runPid=$runPid task=$TaskName log=$LogFile done=$DoneFile"
Write-Output "DETACH_RUN[ASTRO_DETACH_NOTE]: the run is detached under the Task Scheduler service; killing this shell's process tree cannot reach it."
exit 0
