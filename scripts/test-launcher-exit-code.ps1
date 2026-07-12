<#
.SYNOPSIS
    Regression test for the launcher's exit-code contract (#239) and for the sccache
    daemon lifecycle that produced the leak and the nested-cargo bind race (#242).

.DESCRIPTION
    Drives the REAL scripts\windows-gnu-toolchain.ps1 -- no mocks, no stubs, no fixture
    launcher -- and asserts, with an independent read-back of the source of truth in each
    case, that:

      1. The launcher's exit code IS the child command's exit code (0, 1, 42).
      2. That holds in BOTH invocation forms:
           a. in-session   `& .\scripts\windows-gnu-toolchain.ps1 ...` then $LASTEXITCODE
              -- the form scripts\invoke-native-aggregate.ps1 uses, and the form that
              leaked, because $LASTEXITCODE is global and a script that falls off its end
              leaves it set by the last native command it ran;
           b. fresh process `powershell.exe -File ...` then the process exit code
              -- read back from a process object, not from a log line.
      3. A REAL `sccache --stop-server` exit-2 in the launcher's finally block -- produced
         by genuinely tearing the daemon down mid-run, exactly as the 600s idle timeout did
         during long C builds -- does NOT change the launcher's exit code, and IS named on
         stdout as SCCACHE[ASTRO_CACHE_SERVER_STOP_NONZERO] rather than silently swallowed.
      4. Determinism: the exit-code cases are replayed N times and every repetition must
         produce the identical exit code (#242 DoD -- same inputs, same result).

    Runs from the canonical workspace or from any registered worktree of it; the launcher
    accepts both roots and each keeps its own session lock, target/, and sccache daemon port.

.PARAMETER Repetitions
    How many times to replay the exit-code matrix. Default 5 (#242 DoD requires N >= 5).
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 50)]
    [int]$Repetitions = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
# The launcher's own contract depends on native exit codes being data rather than
# terminating errors; this harness must observe them the same way.
$PSNativeCommandUseErrorActionPreference = $false

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$launcher = Join-Path $root "scripts\windows-gnu-toolchain.ps1"
$cmdExe = Join-Path $env:SystemRoot "System32\cmd.exe"
$sccacheExe = "C:\code\Astrolabe\.toolchains\sccache-0.16.0-x86_64-pc-windows-msvc\sccache.exe"
foreach ($required in @($launcher, $cmdExe, $sccacheExe)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "TEST_SETUP[ASTRO_MISSING_PREREQUISITE]: $required (bootstrap the pinned toolchain first)"
    }
}

# The launcher derives one sccache daemon port per root; recompute it here INDEPENDENTLY
# so the state read-backs below observe the same port the launcher will bind, without
# trusting anything the launcher prints.
function Get-ExpectedSccachePort {
    param([string]$Root)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Root.ToLowerInvariant())
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha256.ComputeHash($bytes) } finally { $sha256.Dispose() }
    return 20000 + ([BitConverter]::ToUInt16($hash, 0) % 10000)
}
$expectedPort = Get-ExpectedSccachePort -Root $root

$target = Join-Path $root "target"
$workspaceTempParent = Join-Path $root ".tmp"
$launcherLock = Join-Path $workspaceTempParent "astrolabe-launcher.lock"
# Workspace-local outputs only: this harness's transient capture files live under the
# launcher's own .tmp parent, never under %TEMP% or an agent scratchpad. Creating .tmp up
# front also makes the launcher treat it as pre-existing, so it will not try to remove a
# directory this test is still using.
$testTempCreatedParent = -not (Test-Path -LiteralPath $workspaceTempParent)
New-Item -ItemType Directory -Path $workspaceTempParent -Force | Out-Null

function Get-SystemState {
    param([string]$Label)
    $listeners = @(Get-NetTCPConnection -LocalPort $expectedPort -State Listen -ErrorAction SilentlyContinue)
    $sccacheProcs = @(Get-Process -Name sccache -ErrorAction SilentlyContinue)
    $state = [ordered]@{
        label = $Label
        sccache_listeners_on_port = $listeners.Count
        sccache_processes = $sccacheProcs.Count
        target_present = (Test-Path -LiteralPath $target)
        launcher_lock_present = (Test-Path -LiteralPath $launcherLock)
    }
    # Written straight to the console stream: the caller pipes the returned state object to
    # Out-Null, and Write-Output here would be swallowed with it.
    [Console]::Out.WriteLine(("STATE[{0}]: port={1} listeners={2} sccache_procs={3} target_present={4} lock_present={5}" -f `
        $Label, $expectedPort, $state.sccache_listeners_on_port, $state.sccache_processes, `
        $state.target_present, $state.launcher_lock_present))
    return $state
}

$failures = @()
function Assert-Equal {
    param($Expected, $Actual, [string]$What)
    if ($Expected -eq $Actual) {
        Write-Output "  PASS  $What : expected=$Expected actual=$Actual"
    }
    else {
        Write-Output "  FAIL  $What : expected=$Expected actual=$Actual"
        $script:failures += "$What (expected=$Expected actual=$Actual)"
    }
}
function Assert-Contains {
    param([string[]]$Haystack, [string]$Needle, [string]$What)
    # LITERAL substring match. PowerShell's -like treats `[...]` as a character class, so a
    # needle such as `SCCACHE[ASTRO_CACHE_SERVER_STOP_NONZERO]` would both fail to match the
    # real label AND match spuriously against unrelated text like `SCCACHE_CACHE_SIZE` (the
    # `_` is a member of the bracketed set). Every label this harness asserts on is bracketed,
    # so -like is not merely wrong here, it manufactures false PASSes.
    if (($Haystack -join "`n").IndexOf($Needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        Write-Output "  PASS  $What : found '$Needle'"
    }
    else {
        Write-Output "  FAIL  $What : '$Needle' absent from launcher stdout"
        $script:failures += $What
    }
}

# --- Invocation form (a): in-session. This is the form invoke-native-aggregate.ps1 uses,
# and the form the exit-2 leak actually travelled through: the caller's $LASTEXITCODE is
# global, so a launcher that falls off its end leaves it set by the last native command it
# ran (`sccache --stop-server`, exit 2 once the daemon had idle-timed-out).
function Invoke-LauncherInSession {
    param([string]$ChildCommand, [string[]]$ChildArgs)
    $json = ConvertTo-Json -InputObject @($ChildArgs) -Compress
    # Poison $LASTEXITCODE first: a passing result must be produced by the launcher, not
    # inherited from a previously-clean session.
    $global:LASTEXITCODE = 99
    $stdout = & $launcher -Command $ChildCommand -CommandArgsJson $json 2>&1 | ForEach-Object { "$_" }
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Stdout = @($stdout) }
}

# --- Invocation form (b): a fresh process. The exit code is read back from the OS process
# object, so nothing in this session's variable state can flatter the result.
function Invoke-LauncherFreshProcess {
    param([string]$ChildCommand, [string[]]$ChildArgs)
    $json = ConvertTo-Json -InputObject @($ChildArgs) -Compress
    $out = Join-Path $workspaceTempParent "launcher-exit-test-$PID.out"
    # Start-Process does NOT quote the elements of -ArgumentList, and powershell.exe -File
    # treats a bare `["/c","exit","0"]` as PowerShell syntax (the commas build an array),
    # which reaches the launcher as garbage. Hand the child a properly quoted command line:
    # the JSON must arrive as ONE argv element with its inner quotes intact.
    $quotedJson = '"' + $json.Replace('"', '\"') + '"'
    $proc = Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$launcher`"",
                        "-Command", "`"$ChildCommand`"", "-CommandArgsJson", $quotedJson) `
        -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out
    $stdout = @()
    if (Test-Path -LiteralPath $out) {
        $stdout = @(Get-Content -LiteralPath $out)
        Remove-Item -LiteralPath $out -Force
    }
    return [pscustomobject]@{ ExitCode = $proc.ExitCode; Stdout = $stdout }
}

Write-Output "LAUNCHER_EXIT_CODE_TEST: root=$root launcher=$launcher sccache_port=$expectedPort repetitions=$Repetitions"
Write-Output ""
Get-SystemState -Label "BEFORE_SUITE" | Out-Null
Write-Output ""

# ---------------------------------------------------------------------------------------
# Case 1-3 x N: exit-code fidelity, both invocation forms, replayed for determinism (#242).
# ---------------------------------------------------------------------------------------
foreach ($expected in @(0, 1, 42)) {
    for ($i = 1; $i -le $Repetitions; $i++) {
        Write-Output "CASE[exit=$expected] repetition $i/$Repetitions"
        $inSession = Invoke-LauncherInSession -ChildCommand $cmdExe -ChildArgs @("/c", "exit", "$expected")
        Assert-Equal -Expected $expected -Actual $inSession.ExitCode `
            -What "in-session `$LASTEXITCODE after launcher with child exit $expected (rep $i)"
        Assert-Contains -Haystack $inSession.Stdout -Needle "LAUNCHER_EXIT[ASTRO_CHILD_EXIT]: child command exited with $expected" `
            -What "launcher reported the child's exit code on stdout (exit=$expected, rep $i)"
        if ($i -eq 1) {
            $fresh = Invoke-LauncherFreshProcess -ChildCommand $cmdExe -ChildArgs @("/c", "exit", "$expected")
            Assert-Equal -Expected $expected -Actual $fresh.ExitCode `
                -What "fresh-process exit code after launcher with child exit $expected"
        }
    }
}
Write-Output ""

# ---------------------------------------------------------------------------------------
# Case 4: the REAL #239 condition. The child command IS `sccache --stop-server`, so it tears
# down the very daemon the launcher started moments earlier -- reproducing, deterministically
# and without a single mock, the state the 600s idle timeout produced during long C builds.
# The child exits 0. The launcher's finally block then calls `sccache --stop-server` against
# a daemon that is genuinely gone, and sccache genuinely returns 2.
#
# Contract: the launcher must exit 0 (the child's code) and must NAME the degradation.
# ---------------------------------------------------------------------------------------
Write-Output "CASE[sccache stop-server exit 2 during launcher cleanup] -- real condition, no mock"
$before = Get-SystemState -Label "BEFORE_STOP_SERVER_CASE"
$stopCase = Invoke-LauncherInSession -ChildCommand $sccacheExe -ChildArgs @("--stop-server")
$after = Get-SystemState -Label "AFTER_STOP_SERVER_CASE"
Assert-Equal -Expected 0 -Actual $stopCase.ExitCode `
    -What "launcher exit code is the child's 0 despite `sccache --stop-server` exiting 2 in cleanup"
Assert-Contains -Haystack $stopCase.Stdout -Needle "SCCACHE[ASTRO_CACHE_SERVER_STOP_NONZERO]" `
    -What "cleanup-time sccache failure is NAMED, not silently swallowed"
Assert-Contains -Haystack $stopCase.Stdout -Needle "exit=2" `
    -What "the named degradation reports the failing command's actual exit code"
Assert-Equal -Expected $false -Actual $after.launcher_lock_present -What "launcher lock released after run"
Assert-Equal -Expected $false -Actual $after.target_present -What "target/ absent after run"
Write-Output ""

# ---------------------------------------------------------------------------------------
# Case 5: the daemon the child inherits is the one the launcher pre-started on this root's
# port (#242). Read it back from the OS: the child asks sccache for its stats and the port
# it was told to use, and the listener on that port must exist while the child runs.
# ---------------------------------------------------------------------------------------
Write-Output "CASE[nested child inherits the launcher's sccache daemon] (#242)"
$probe = Invoke-LauncherInSession -ChildCommand $cmdExe -ChildArgs @("/c", "echo SCCACHE_SERVER_PORT=%SCCACHE_SERVER_PORT% SCCACHE_IDLE_TIMEOUT=%SCCACHE_IDLE_TIMEOUT% RUSTC_WRAPPER=%RUSTC_WRAPPER%")
Assert-Equal -Expected 0 -Actual $probe.ExitCode -What "env-probe child exit code"
Assert-Contains -Haystack $probe.Stdout -Needle "SCCACHE_SERVER_PORT=$expectedPort" `
    -What "child (and therefore any nested cargo it spawns) inherits this root's sccache port"
Assert-Contains -Haystack $probe.Stdout -Needle "SCCACHE_IDLE_TIMEOUT=0" `
    -What "child inherits SCCACHE_IDLE_TIMEOUT=0 so the daemon cannot idle-exit mid-run"
Assert-Contains -Haystack $probe.Stdout -Needle "RUSTC_WRAPPER=" `
    -What "RUSTC_WRAPPER stays set for nested cargo (server inheritance, not a silent cache drop)"
Write-Output ""

Get-SystemState -Label "AFTER_SUITE" | Out-Null
if ($testTempCreatedParent -and (Test-Path -LiteralPath $workspaceTempParent)) {
    if (@(Get-ChildItem -LiteralPath $workspaceTempParent -Force).Count -eq 0) {
        Remove-Item -LiteralPath $workspaceTempParent -Force
    }
}
Write-Output ""
if ($failures.Count -gt 0) {
    [Console]::Error.WriteLine("LAUNCHER_EXIT_CODE_TEST[FAIL]: $($failures.Count) assertion(s) failed:")
    foreach ($failure in $failures) {
        [Console]::Error.WriteLine("  - $failure")
    }
    exit 1
}
Write-Output "LAUNCHER_EXIT_CODE_TEST[PASS]: every assertion held across $Repetitions repetitions"
exit 0
