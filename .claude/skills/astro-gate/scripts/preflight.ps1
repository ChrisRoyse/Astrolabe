# preflight.ps1 - ASTROLABE toolchain/lock/target preflight.
# Prints ONE minified JSON object to stdout and exits 0; any internal failure
# prints {"error":...} and exits 1 (fail closed - callers must not proceed on error).
# No log files are written: stdout of the invoking process is the evidence stream.
# -Root exists ONLY for isolated fixture-root FSV of lock semantics (#197 rule 5);
# real preflights always use the canonical default.

param([string]$Root = 'C:/code/Astrolabe')

$ErrorActionPreference = 'Stop'
try {
    $root = $Root
    if (-not (Test-Path "$root/CLAUDE.md")) {
        throw "workspace root not found (no CLAUDE.md) at $root"
    }

    # --- Launcher lock ---------------------------------------------------
    $lockPath = Join-Path $root '.tmp/astrolabe-launcher.lock'
    $lock = $null
    $lockLivePids = @()
    $lockDeadPids = @()
    if (Test-Path $lockPath) {
        $raw = Get-Content -Raw $lockPath
        try { $lock = $raw | ConvertFrom-Json } catch { throw "lock file exists but is not valid JSON: $lockPath" }
        # Lock schema: pid (int or array), started, command. Treat any pid field found as authoritative.
        $pids = @()
        if ($null -ne $lock.pid) { $pids = @($lock.pid) }
        if ($null -ne $lock.pids) { $pids += @($lock.pids) }
        foreach ($p in $pids) {
            $alive = $false
            try { $alive = $null -ne (Get-Process -Id ([int]$p) -ErrorAction SilentlyContinue) } catch {}
            if ($alive) { $lockLivePids += [int]$p } else { $lockDeadPids += [int]$p }
        }
    }

    # --- Toolchain processes ----------------------------------------------
    $names = "'cargo.exe','rustc.exe','cc1.exe','cc1plus.exe','gcc.exe','g++.exe','make.exe','mingw32-make.exe','ld.exe','clang.exe','clang++.exe','sccache.exe','cppcheck.exe'"
    $filter = ($names -replace "'", '"' -split ',' | ForEach-Object { "Name=$_" }) -join ' or '
    $procs = @(Get-CimInstance Win32_Process -Filter $filter -ErrorAction Stop)
    $astro = @(); $foreign = @()
    foreach ($p in $procs) {
        $cmd = [string]$p.CommandLine
        $entry = [ordered]@{ pid = $p.ProcessId; name = $p.Name; cmd = if ($cmd.Length -gt 160) { $cmd.Substring(0,160) } else { $cmd } }
        if ($cmd -match '(?i)astrolabe|calyx|cbm[-_]sys|libcbm|codebase-memory-mcp') { $astro += $entry } else { $foreign += $entry }
    }

    # --- target/ ------------------------------------------------------------
    $targetPath = Join-Path $root 'target'
    $targetExists = Test-Path $targetPath
    $targetAgeMin = $null
    if ($targetExists) {
        $newest = Get-ChildItem $targetPath -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        $stamp = if ($newest) { $newest.LastWriteTimeUtc } else { (Get-Item $targetPath).LastWriteTimeUtc }
        $targetAgeMin = [math]::Round(((Get-Date).ToUniversalTime() - $stamp).TotalMinutes, 1)
    }

    # --- Git ------------------------------------------------------------------
    # Supplementary info: a git failure is labeled in the output rather than
    # aborting the preflight, because the lock/toolchain verdict must still be
    # delivered (e.g. fixture roots per #197 rule 5 are not git repositories).
    Push-Location $root
    try {
        $branchRaw = git rev-parse --abbrev-ref HEAD 2>$null
        if ($LASTEXITCODE -eq 0) {
            $gitInfo = [ordered]@{ branch = ([string]$branchRaw).Trim(); dirty_files = @(git status --porcelain).Count }
        } else {
            $gitInfo = [ordered]@{ error = "not a git repository: $root" }
        }
    } finally { Pop-Location }

    # --- Verdict ---------------------------------------------------------------
    $verdict =
        if ($lockLivePids.Count -gt 0) { 'LOCKED_LIVE' }
        elseif ($null -ne $lock)       { 'LOCKED_DEAD' }
        elseif ($astro.Count -gt 0)    { 'OWNED_BUSY' }
        elseif ($foreign.Count -gt 0)  { 'CPU_CONTENDED' }
        else                           { 'FREE' }

    $out = [ordered]@{
        ts            = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        verdict       = $verdict
        lock          = if ($null -ne $lock) { [ordered]@{ path = $lockPath; live_pids = $lockLivePids; dead_pids = $lockDeadPids; command = [string]$lock.command; started = [string]$lock.started } } else { $null }
        astro_procs   = $astro
        foreign_procs = $foreign
        target        = [ordered]@{ exists = $targetExists; newest_write_age_min = $targetAgeMin }
        git           = $gitInfo
    }
    $out | ConvertTo-Json -Depth 6 -Compress
    exit 0
}
catch {
    @{ error = $_.Exception.Message; remediation = 'Fix the reported condition; do not proceed to builds on a failed preflight.' } | ConvertTo-Json -Compress
    exit 1
}
