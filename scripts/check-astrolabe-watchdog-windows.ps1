<#
.SYNOPSIS
    Native-Windows integration test for the #253 parent-death watchdog.

.DESCRIPTION
    Proves that when the process that spawned the astrolabe MCP server dies, the server
    terminates via the WATCHDOG -- not merely via stdin EOF. The isolation is the whole
    point: this grandparent process opens a named pipe and holds it open for astrolabe's
    stdin, so when the parent is killed the server's stdin never reaches EOF; only the
    watchdog (a SYNCHRONIZE handle to the now-dead parent) can end it.

    Layout:  this script (grandparent, holds the stdin pipe)
               -> cmd.exe (parent, killable)
                    -> astrolabe.exe (server; its parent is cmd, its stdin is the pipe)

    No mocks: the real astrolabe binary, a real parent process, a real kill, and the real
    OS process table read back to confirm the server is gone.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Astrolabe
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Astrolabe -PathType Leaf)) {
    Write-Output "ASTRO_WATCHDOG_WIN[FAIL]: astrolabe binary not found: $Astrolabe"
    exit 2
}
$astrolabeFull = (Resolve-Path -LiteralPath $Astrolabe).Path

$pipeName = "astro-watchdog-$PID-$([guid]::NewGuid().ToString('N').Substring(0,8))"
$errFile = Join-Path $env:TEMP "astro-watchdog-$PID.err"
$batFile = Join-Path $env:TEMP "astro-watchdog-$PID.bat"
$serverPid = $null
$parent = $null
$pipe = $null

function Test-Alive([int]$ProcId) {
    $null -ne (Get-Process -Id $ProcId -ErrorAction SilentlyContinue)
}

try {
    # Grandparent owns the stdin pipe; async server end so we can connect + hold it open.
    $pipe = New-Object System.IO.Pipes.NamedPipeServerStream(
        $pipeName, [System.IO.Pipes.PipeDirection]::Out, 1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous)
    $connect = $pipe.WaitForConnectionAsync()

    # Parent = cmd running astrolabe with stdin from the pipe and stderr to a file. A .bat
    # wrapper keeps the redirection quoting robust.
    Set-Content -LiteralPath $batFile -Encoding Ascii -Value @(
        "`"$astrolabeFull`" < \\.\pipe\$pipeName 2> `"$errFile`""
    )
    $parent = Start-Process -FilePath $env:ComSpec -ArgumentList '/c', "`"$batFile`"" `
        -PassThru -WindowStyle Hidden

    # astrolabe must connect (proves its stdin is the pipe we hold).
    if (-not $connect.Wait(15000)) {
        Write-Output "ASTRO_WATCHDOG_WIN[FAIL]: astrolabe never connected to the stdin pipe within 15s"
        exit 3
    }

    # Discover the server PID = the astrolabe child of our cmd parent (read the OS table).
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ([DateTime]::UtcNow -lt $deadline) {
        $child = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($parent.Id)" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'astrolabe*' } | Select-Object -First 1
        if ($child) { $serverPid = [int]$child.ProcessId; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $serverPid) {
        Write-Output "ASTRO_WATCHDOG_WIN[FAIL]: could not find the astrolabe child of parent $($parent.Id)"
        if (Test-Path $errFile) { Write-Output ("stderr: " + (Get-Content $errFile -Raw)) }
        exit 3
    }

    # Wait for the watchdog-ready startup point (server.start on stderr).
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Test-Path $errFile) -and (Select-String -Path $errFile -Pattern 'server\.start' -Quiet)) { break }
        Start-Sleep -Milliseconds 100
    }

    # BEFORE: server alive, stdin pipe held open by us.
    $before = Test-Alive $serverPid
    Write-Output "ASTRO_WATCHDOG_WIN[before]: server pid=$serverPid alive=$before parent=$($parent.Id)"
    if (-not $before) {
        Write-Output "ASTRO_WATCHDOG_WIN[FAIL]: server exited before the parent was killed"
        exit 3
    }

    # Trigger: kill ONLY the parent. astrolabe is orphaned; its stdin pipe stays open (we
    # hold the server end), so nothing but the watchdog can terminate it.
    Stop-Process -Id $parent.Id -Force
    $killedAt = [DateTime]::UtcNow

    # AFTER: assert the server exits within the watchdog window (500ms poll + margin).
    $deadline = $killedAt.AddSeconds(5)
    $gone = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        if (-not (Test-Alive $serverPid)) { $gone = $true; break }
        Start-Sleep -Milliseconds 50
    }
    $elapsedMs = [int]([DateTime]::UtcNow - $killedAt).TotalMilliseconds
    $stillHeld = $pipe.IsConnected
    Write-Output "ASTRO_WATCHDOG_WIN[after]: server pid=$serverPid gone=$gone elapsed_ms=$elapsedMs stdin_pipe_still_connected=$stillHeld"

    if ($gone) {
        Write-Output "ASTRO_WATCHDOG_WIN[PASS]: parent death terminated the server in ${elapsedMs}ms via the watchdog (stdin held open the whole time)"
        exit 0
    }
    Write-Output "ASTRO_WATCHDOG_WIN[FAIL]: server pid=$serverPid survived >5s after parent death (watchdog did not fire)"
    exit 1
}
finally {
    if ($serverPid -and (Test-Alive $serverPid)) { Stop-Process -Id $serverPid -Force -ErrorAction SilentlyContinue }
    if ($parent -and (Test-Alive $parent.Id)) { Stop-Process -Id $parent.Id -Force -ErrorAction SilentlyContinue }
    if ($pipe) { $pipe.Dispose() }
    foreach ($f in @($errFile, $batFile)) { if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue } }
}
