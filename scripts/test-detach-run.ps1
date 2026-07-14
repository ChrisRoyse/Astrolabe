<#
.SYNOPSIS
    FSV harness for the #391 session-independent detached launch (scripts/detach-run.ps1).

.DESCRIPTION
    Proves the property #391 requires: a run launched through detach-run.ps1 survives the death
    of the launching shell's entire process tree, and the #197 lock lifecycle stays correct
    (lock present + naming the REAL run PID while alive; lock gone after completion; a completion
    output appears). Per #197 rule 5, this exercises an ISOLATED FIXTURE lock in a temp root,
    never the live workspace launcher lock.

    Method:
      1. Generate a dummy long "work" script that emulates the launcher's lock protocol on a
         fixture lock path: write {pid,issue,started,command} JSON naming its own PID, sleep,
         then write an OUTPUT file and delete the lock in its finally.
      2. Start a VICTIM launching shell (a real child powershell tree) that calls detach-run.ps1
         and then stays alive, so there is a genuine process tree to kill.
      3. Wait until the detached run records its PID, capture it, and assert the fixture lock is
         present and names a LIVE pid.
      4. taskkill /T /F the victim launching shell's whole tree (the #391 kill that murdered
         wave-14's runs).
      5. Assert the detached run PID is STILL ALIVE (it is under the Task Scheduler service, not
         the victim tree), then wait for completion and assert: OUTPUT file written, DONE sentinel
         written, fixture lock removed.

    Exit 0 = PASS with a printed evidence block; non-zero + a named boundary = FAIL.

.NOTES
    Refs #391, #197.
#>
[CmdletBinding()]
param(
    [int]$SleepSeconds = 45,
    [string]$Root = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$scriptDir = $PSScriptRoot
$detach = Join-Path $scriptDir "detach-run.ps1"
if (-not (Test-Path -LiteralPath $detach -PathType Leaf)) {
    throw "TEST_DETACH[MISSING_DETACH]: scripts/detach-run.ps1 not found next to this test: $detach"
}

if ([string]::IsNullOrWhiteSpace($Root)) {
    $Root = Join-Path ([IO.Path]::GetTempPath()) ("astro-detach-fsv-" + [Guid]::NewGuid().ToString("N"))
}
New-Item -ItemType Directory -Path $Root -Force | Out-Null

$fixtureLock = Join-Path $Root "fixture-launcher.lock"
$outFile = Join-Path $Root "work-output.txt"
$logFile = Join-Path $Root "run.log"
$runPidFile = Join-Path $Root "run.pid"
$doneFile = Join-Path $Root "run.done"
$workScript = Join-Path $Root "dummy-work.ps1"
$victimLog = Join-Path $Root "victim.log"

# --- Dummy long work: emulate the launcher's #197 lock protocol on the fixture lock ---------
$work = @"
[CmdletBinding()]
param([string]`$LockPath, [string]`$OutFile, [int]`$Seconds)
`$ErrorActionPreference = 'Continue'
try {
    [ordered]@{ pid = `$PID; issue = 391; started = (Get-Date).ToString('o'); command = 'detach-fsv-dummy-sleep' } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath `$LockPath -Encoding UTF8
    Start-Sleep -Seconds `$Seconds
    Set-Content -LiteralPath `$OutFile -Value ("completed pid=" + `$PID + " at " + (Get-Date).ToString('o')) -Encoding UTF8
}
finally {
    if (Test-Path -LiteralPath `$LockPath) { Remove-Item -LiteralPath `$LockPath -Force }
}
"@
Set-Content -LiteralPath $workScript -Value $work -Encoding UTF8

$workArgsJson = (@("-LockPath", $fixtureLock, "-OutFile", $outFile, "-Seconds", "$SleepSeconds") | ConvertTo-Json -Compress)

# --- Victim launching shell: a real child tree that calls detach-run then stays alive --------
$victimScript = Join-Path $Root "victim-shell.ps1"
$victim = @"
& '$detach' -WorkScript '$workScript' -WorkArgsJson '$workArgsJson' -LogFile '$logFile' -RunPidFile '$runPidFile' -DoneFile '$doneFile' -PidWaitSeconds 90
# Stay alive so there is a genuine launching-shell tree for the test to kill.
Start-Sleep -Seconds 600
"@
Set-Content -LiteralPath $victimScript -Value $victim -Encoding UTF8

function Fail { param([string]$Code, [string]$Msg) throw "TEST_DETACH[$Code]: $Msg (fixture root: $Root)" }

Write-Output "TEST_DETACH: fixture root = $Root"
$victimProc = Start-Process -FilePath "powershell.exe" `
    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $victimScript) `
    -PassThru -WindowStyle Hidden -RedirectStandardOutput $victimLog -RedirectStandardError "$victimLog.err"
$victimPid = $victimProc.Id
Write-Output "TEST_DETACH: victim launching-shell pid = $victimPid"

# 1) Wait for the detached run to record its PID.
$deadline = (Get-Date).AddSeconds(90)
$runPid = $null
while ((Get-Date) -lt $deadline) {
    if (Test-Path -LiteralPath $runPidFile) {
        $raw = (Get-Content -LiteralPath $runPidFile -Raw -ErrorAction SilentlyContinue)
        $p = 0
        if (-not [string]::IsNullOrWhiteSpace($raw) -and [int]::TryParse($raw.Trim(), [ref]$p) -and $p -gt 0) { $runPid = $p; break }
    }
    Start-Sleep -Milliseconds 250
}
if ($null -eq $runPid) { Fail "PID_TIMEOUT" "detached run never recorded a PID at $runPidFile" }
Write-Output "TEST_DETACH: detached run pid = $runPid"

# 2) Assert the fixture lock is present and names a live pid WHILE running.
$lockDeadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $lockDeadline -and -not (Test-Path -LiteralPath $fixtureLock)) { Start-Sleep -Milliseconds 200 }
if (-not (Test-Path -LiteralPath $fixtureLock)) { Fail "LOCK_ABSENT_DURING" "fixture lock not present while the run is alive" }
$lockObj = Get-Content -LiteralPath $fixtureLock -Raw | ConvertFrom-Json
$lockPid = [int]$lockObj.pid
if ($null -eq (Get-Process -Id $lockPid -ErrorAction SilentlyContinue)) { Fail "LOCK_PID_DEAD_DURING" "lock names pid $lockPid which is not live" }
Write-Output "TEST_DETACH: lock present during run; lock pid = $lockPid (live), issue = $($lockObj.issue)"

# 3) KILL the victim launching shell's entire process tree (the #391 kill).
Write-Output "TEST_DETACH: killing victim launching-shell tree (pid $victimPid) with taskkill /T /F ..."
& taskkill.exe /PID $victimPid /T /F *> $null
Start-Sleep -Seconds 2
if ($null -ne (Get-Process -Id $victimPid -ErrorAction SilentlyContinue)) { Fail "VICTIM_SURVIVED" "victim launching shell $victimPid was not killed; test invalid" }
Write-Output "TEST_DETACH: victim tree dead."

# 4) Assert the detached run is STILL ALIVE after the launching shell tree died.
if ($null -eq (Get-Process -Id $runPid -ErrorAction SilentlyContinue)) {
    Fail "RUN_DIED_WITH_SHELL" "detached run pid $runPid died when the launching shell tree was killed — #391 NOT fixed"
}
Write-Output "TEST_DETACH: run pid $runPid STILL ALIVE after launching-shell tree kill (survival proven)."

# 5) Wait for completion; assert output written, done sentinel written, lock removed.
$completeDeadline = (Get-Date).AddSeconds($SleepSeconds + 90)
while ((Get-Date) -lt $completeDeadline -and -not (Test-Path -LiteralPath $doneFile)) { Start-Sleep -Milliseconds 500 }
if (-not (Test-Path -LiteralPath $doneFile)) { Fail "NO_COMPLETION" "detached run did not complete (no done sentinel at $doneFile)" }
if (-not (Test-Path -LiteralPath $outFile)) { Fail "NO_OUTPUT" "run completed but produced no output file at $outFile" }
$outContent = (Get-Content -LiteralPath $outFile -Raw).Trim()
$doneContent = (Get-Content -LiteralPath $doneFile -Raw).Trim()
# Give the finally a moment to remove the lock.
$lockGoneDeadline = (Get-Date).AddSeconds(15)
while ((Get-Date) -lt $lockGoneDeadline -and (Test-Path -LiteralPath $fixtureLock)) { Start-Sleep -Milliseconds 200 }
if (Test-Path -LiteralPath $fixtureLock) { Fail "LOCK_LEAKED" "fixture lock still present after completion (lifecycle broken)" }

Write-Output ""
Write-Output "TEST_DETACH[PASS]: session-independent detach verified."
Write-Output "  evidence:"
Write-Output "    run pid                 : $runPid (survived launching-shell tree kill)"
Write-Output "    victim shell pid killed : $victimPid"
Write-Output "    lock during run         : present, pid=$lockPid live, issue=$($lockObj.issue)"
Write-Output "    lock after completion   : absent (released)"
Write-Output "    output file             : $outFile -> `"$outContent`""
Write-Output "    done sentinel           : $doneFile -> exit=$doneContent"
Write-Output "    log                     : $logFile"

# Cleanup fixture root (best effort).
try { Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue } catch {}
exit 0
