<#
.SYNOPSIS
    Manual full-state verification for #671 transactional layout edges.

.DESCRIPTION
    Stages and runs the real native example through the launcher-bound FSV
    lifecycle, then performs independent read-only SQLite and JSON readback of
    the produced databases. This is manual FSV evidence, not a test or gate.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourcePath,
    [Parameter(Mandatory)][string]$TreeSha,
    [Parameter(Mandatory)][string]$SessionId,
    [int]$Issue = 671
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Fail-Astro([string]$Code, [string]$Message, [string]$Remediation) {
    $exception = [InvalidOperationException]::new($Message)
    $exception.Data['AstroCode'] = $Code
    $exception.Data['AstroRemediation'] = $Remediation
    throw $exception
}

function Assert-Astro([bool]$Condition, [string]$Code, [string]$Message) {
    if (-not $Condition) {
        Fail-Astro $Code $Message 'preserve the staged session and inspect the first mismatched source-of-truth readback'
    }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-SqliteJson([string]$Sqlite, [string]$Database, [string]$Query) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Sqlite
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @('-readonly', '-json', $Database, $Query)) {
        [void]$start.ArgumentList.Add([string]$argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    Assert-Astro $process.Start() 'ISSUE_671_FSV_SQLITE_START_FAILED' "sqlite3 did not start for $Database"
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    Assert-Astro ($process.ExitCode -eq 0) 'ISSUE_671_FSV_SQLITE_FAILED' `
        "sqlite3 exit=$($process.ExitCode) database=$Database stderr=$stderr"
    Assert-Astro ([string]::IsNullOrEmpty($stderr)) 'ISSUE_671_FSV_SQLITE_STDERR' `
        "sqlite3 emitted stderr for $Database`: $stderr"
    return ($stdout | ConvertFrom-Json)
}

Assert-Astro ($Issue -eq 671) 'ISSUE_671_FSV_ISSUE_MISMATCH' "expected issue 671, observed $Issue"
$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$source = [IO.Path]::GetFullPath($SourcePath)
$head = (& 'C:\Program Files\Git\bin\git.exe' -C $workspace rev-parse HEAD).Trim()
Assert-Astro ($LASTEXITCODE -eq 0 -and $head -ceq $TreeSha) 'ISSUE_671_FSV_TREE_MISMATCH' `
    "expected committed tree $TreeSha, observed $head"
Assert-Astro (Test-Path -LiteralPath $source -PathType Leaf) 'ISSUE_671_FSV_ARTIFACT_MISSING' `
    "native artifact is absent: $source"

$sourceHash = Get-Sha256 $source
$session = Join-Path (
    Join-Path (Join-Path (Join-Path $workspace '.tmp\native-fsv-artifacts') $TreeSha) $sourceHash
) $SessionId
$receiptPath = Join-Path $session 'receipt.json'

& powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $PSScriptRoot 'native-fsv-artifact.ps1') `
    -Operation Stage -SourcePath $source -Issue $Issue -TreeSha $TreeSha -SessionId $SessionId
Assert-Astro ($LASTEXITCODE -eq 0) 'ISSUE_671_FSV_STAGE_FAILED' `
    "artifact Stage exited $LASTEXITCODE"

$payload = Join-Path $session 'payload'
$stdoutPath = Join-Path $session 'stdout.txt'
$stderrPath = Join-Path $session 'stderr.txt'
$runRecordPath = Join-Path $session 'run.json'
$liveStatePath = Join-Path $session 'live.json'
$runnerHostStdoutPath = Join-Path $session 'runner-host.stdout.txt'
$runnerHostStderrPath = Join-Path $session 'runner-host.stderr.txt'
$sqliteCommand = Get-Command sqlite3.exe -ErrorAction SilentlyContinue
Assert-Astro ($null -ne $sqliteCommand) 'ISSUE_671_FSV_SQLITE_MISSING' `
    'sqlite3.exe is unavailable for corrupt-schema setup and independent physical database readback'
$sqlite = [string]$sqliteCommand.Source
$argumentsJson = ConvertTo-Json -Compress -InputObject @([string]$payload, $sqlite)

$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$runnerStart = [Diagnostics.ProcessStartInfo]::new()
$runnerStart.FileName = $windowsPowerShell
$runnerStart.UseShellExecute = $false
$runnerStart.CreateNoWindow = $true
$runnerStart.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
$runnerStart.RedirectStandardOutput = $true
$runnerStart.RedirectStandardError = $true
foreach ($argument in @(
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $PSScriptRoot 'native-fsv-run.ps1'),
    '-ReceiptPath', $receiptPath,
    '-ArgumentsJson', $argumentsJson,
    '-StandardOutputPath', $stdoutPath,
    '-StandardErrorPath', $stderrPath,
    '-RunRecordPath', $runRecordPath,
    '-LiveStatePath', $liveStatePath,
    '-Issue', [string]$Issue
)) {
    [void]$runnerStart.ArgumentList.Add([string]$argument)
}
$runner = [Diagnostics.Process]::new()
$runner.StartInfo = $runnerStart
Assert-Astro $runner.Start() 'ISSUE_671_FSV_RUNNER_START_FAILED' 'Windows PowerShell runner did not start'
$runnerStdoutTask = $runner.StandardOutput.ReadToEndAsync()
$runnerStderrTask = $runner.StandardError.ReadToEndAsync()
$runner.WaitForExit()
$runnerStdout = $runnerStdoutTask.GetAwaiter().GetResult()
$runnerStderr = $runnerStderrTask.GetAwaiter().GetResult()
Assert-Astro ($runner.ExitCode -eq 0) 'ISSUE_671_FSV_RUNNER_FAILED' `
    "native-fsv-run exit=$($runner.ExitCode) stdout=$runnerStdout stderr=$runnerStderr"

& powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $PSScriptRoot 'native-fsv-artifact.ps1') `
    -Operation Inspect -ReceiptPath $receiptPath
Assert-Astro ($LASTEXITCODE -eq 0) 'ISSUE_671_FSV_INSPECT_FAILED' `
    "artifact Inspect exited $LASTEXITCODE"

[IO.File]::WriteAllText($runnerHostStdoutPath, $runnerStdout, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($runnerHostStderrPath, $runnerStderr, [Text.UTF8Encoding]::new($false))
$run = Get-Content -LiteralPath $runRecordPath -Raw | ConvertFrom-Json
Assert-Astro (
    @('astrolabe.native-fsv-run.v2', 'astrolabe.native-fsv-run.v3') -ccontains [string]$run.schema -and
    [string]$run.verdict -ceq 'verified' -and [int]$run.process.exit_code -eq 0 -and
    [bool]$run.artifact.stable -and [bool]$run.repository.stable -and
    [bool]$run.launcher_lease.stable
) 'ISSUE_671_FSV_RUN_RECORD_INVALID' 'run record did not prove a stable real artifact and exit 0'

$reportPath = Join-Path $payload 'report.json'
$happyLayoutPath = Join-Path $payload 'happy-layout.json'
$maxLayoutPath = Join-Path $payload 'max-one-layout.json'
$emptyLayoutPath = Join-Path $payload 'empty-layout.json'
$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
$happyLayout = Get-Content -LiteralPath $happyLayoutPath -Raw | ConvertFrom-Json
$maxLayout = Get-Content -LiteralPath $maxLayoutPath -Raw | ConvertFrom-Json
$emptyLayout = Get-Content -LiteralPath $emptyLayoutPath -Raw | ConvertFrom-Json

Assert-Astro ([string]$report.schema -ceq 'astrolabe.issue-671.layout-fsv.v1') `
    'ISSUE_671_FSV_REPORT_INVALID' 'report schema does not identify the issue-671 FSV contract'
Assert-Astro (@($happyLayout.nodes).Count -eq 300 -and @($happyLayout.edges).Count -eq 299 -and `
    [int]$happyLayout.total_nodes -eq 300) 'ISSUE_671_FSV_HAPPY_LAYOUT_INVALID' `
    'happy layout is not exactly 300 nodes / 299 edges / 300 total nodes'
Assert-Astro (@($maxLayout.nodes).Count -eq 1 -and @($maxLayout.edges).Count -eq 0 -and `
    [int]$maxLayout.total_nodes -eq 300) 'ISSUE_671_FSV_MAX_LAYOUT_INVALID' `
    'max-one layout did not retain exactly one of 300 persisted nodes and no visible edge'
Assert-Astro (@($emptyLayout.nodes).Count -eq 0 -and @($emptyLayout.edges).Count -eq 0 -and `
    [int]$emptyLayout.total_nodes -eq 0) 'ISSUE_671_FSV_EMPTY_LAYOUT_INVALID' `
    'empty layout did not serialize exact empty arrays'
Assert-Astro ([string]$report.invalid.code -ceq 'CBM_LAYOUT_INPUT_INVALID') `
    'ISSUE_671_FSV_INVALID_REFUSAL_MISSING' 'invalid project input did not report its exact code'
Assert-Astro ([string]$report.corrupt.code -like 'CBM_LAYOUT_*') `
    'ISSUE_671_FSV_CORRUPT_REFUSAL_MISSING' 'corrupt persisted schema did not report a layout code'

$happyDb = Join-Path $payload 'happy.db'
$emptyDb = Join-Path $payload 'empty.db'
$corruptDb = Join-Path $payload 'corrupt.db'
$happyState = @(Invoke-SqliteJson $sqlite $happyDb `
    "SELECT (SELECT count(*) FROM projects) AS projects,(SELECT count(*) FROM nodes) AS nodes,(SELECT count(DISTINCT atom_id) FROM nodes) AS distinct_atoms,(SELECT count(*) FROM nodes WHERE length(atom_id)=64 AND atom_id NOT GLOB '*[^0-9a-f]*') AS canonical_atoms,(SELECT count(*) FROM edges) AS edges,(SELECT count(*) FROM edges WHERE type='CALLS') AS calls,(SELECT min(id) FROM nodes) AS min_node_id,(SELECT max(id) FROM nodes) AS max_node_id,integrity_check AS integrity FROM pragma_integrity_check;")[0]
$emptyState = @(Invoke-SqliteJson $sqlite $emptyDb `
    "SELECT (SELECT count(*) FROM projects) AS projects,(SELECT count(*) FROM nodes) AS nodes,(SELECT count(*) FROM edges) AS edges,integrity_check AS integrity FROM pragma_integrity_check;")[0]
$corruptState = @(Invoke-SqliteJson $sqlite $corruptDb `
    "SELECT (SELECT count(*) FROM projects) AS projects,(SELECT count(*) FROM nodes) AS nodes,(SELECT count(*) FROM sqlite_master WHERE type='table' AND name='edges') AS edge_table,integrity_check AS integrity FROM pragma_integrity_check;")[0]

Assert-Astro ([int]$happyState.projects -eq 1 -and [int]$happyState.nodes -eq 300 -and `
    [int]$happyState.distinct_atoms -eq 300 -and [int]$happyState.canonical_atoms -eq 300 -and `
    [int]$happyState.edges -eq 299 -and [int]$happyState.calls -eq 299 -and `
    [int]$happyState.min_node_id -eq 1 -and [int]$happyState.max_node_id -eq 300 -and `
    [string]$happyState.integrity -ceq 'ok') 'ISSUE_671_FSV_HAPPY_DB_INVALID' `
    'physical happy.db readback differs from the exact synthetic fixture'
Assert-Astro ([int]$emptyState.projects -eq 1 -and [int]$emptyState.nodes -eq 0 -and `
    [int]$emptyState.edges -eq 0 -and [string]$emptyState.integrity -ceq 'ok') `
    'ISSUE_671_FSV_EMPTY_DB_INVALID' 'physical empty.db readback differs from the empty fixture'
Assert-Astro ([int]$corruptState.projects -eq 1 -and [int]$corruptState.nodes -eq 2 -and `
    [int]$corruptState.edge_table -eq 0 -and [string]$corruptState.integrity -ceq 'ok') `
    'ISSUE_671_FSV_CORRUPT_DB_INVALID' 'physical corrupt.db does not retain the expected missing-edge-table state'

$readback = [ordered]@{
    schema = 'astrolabe.issue-671.layout-fsv-readback.v1'
    artifact_sha256 = $sourceHash
    run_record_sha256 = Get-Sha256 $runRecordPath
    report_sha256 = Get-Sha256 $reportPath
    happy_layout_sha256 = Get-Sha256 $happyLayoutPath
    max_layout_sha256 = Get-Sha256 $maxLayoutPath
    empty_layout_sha256 = Get-Sha256 $emptyLayoutPath
    happy_db_sha256 = Get-Sha256 $happyDb
    empty_db_sha256 = Get-Sha256 $emptyDb
    corrupt_db_sha256 = Get-Sha256 $corruptDb
    happy_state = $happyState
    empty_state = $emptyState
    corrupt_state = $corruptState
    edge_cases = [ordered]@{
        max_one = $report.max_one
        empty = $report.empty
        invalid = $report.invalid
        corrupt = $report.corrupt
    }
}
$readbackPath = Join-Path $payload 'readback.json'
$readbackJson = $readback | ConvertTo-Json -Depth 12 -Compress
[IO.File]::WriteAllText($readbackPath, $readbackJson, [Text.UTF8Encoding]::new($false))
$readbackAgain = Get-Content -LiteralPath $readbackPath -Raw
Assert-Astro ($readbackAgain -ceq $readbackJson) 'ISSUE_671_FSV_READBACK_WRITE_UNSTABLE' `
    'persisted physical readback record differs from the bytes written'

Write-Output "ISSUE_671_FSV_SOURCE_OF_TRUTH $readbackAgain"
Write-Output "ISSUE_671_FSV_RECEIPT $receiptPath"
Write-Output "ISSUE_671_FSV_RUN $runRecordPath"
Write-Output "ISSUE_671_FSV_READBACK $readbackPath sha256=$(Get-Sha256 $readbackPath)"
