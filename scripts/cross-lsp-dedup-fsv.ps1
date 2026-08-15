<#
.SYNOPSIS
    Manual full-state verification for #1099 cross-LSP canonical identity.

.DESCRIPTION
    Stages and runs the real native server example, then independently reads
    both physical SQLite stores and the persisted receipt files. This is a
    manual FSV instrument, not a test or gate.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourcePath,
    [Parameter(Mandatory)][string]$TreeSha,
    [Parameter(Mandatory)][string]$SessionId,
    [int]$Issue = 1099
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
        Fail-Astro $Code $Message 'preserve the staged session and inspect the first mismatched physical readback'
    }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-SqliteRaw([string]$Sqlite, [string]$Database, [string]$Query) {
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
    Assert-Astro $process.Start() 'ISSUE_1099_FSV_SQLITE_START_FAILED' "sqlite3 did not start for $Database"
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    Assert-Astro ($process.ExitCode -eq 0) 'ISSUE_1099_FSV_SQLITE_FAILED' `
        "sqlite3 exit=$($process.ExitCode) database=$Database stderr=$stderr"
    Assert-Astro ([string]::IsNullOrEmpty($stderr)) 'ISSUE_1099_FSV_SQLITE_STDERR' `
        "sqlite3 emitted stderr for $Database`: $stderr"
    return $stdout.Trim()
}

Assert-Astro ($Issue -eq 1099) 'ISSUE_1099_FSV_ISSUE_MISMATCH' "expected issue 1099, observed $Issue"
$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$source = [IO.Path]::GetFullPath($SourcePath)
$head = (& 'C:\Program Files\Git\bin\git.exe' -C $workspace rev-parse HEAD).Trim()
Assert-Astro ($LASTEXITCODE -eq 0 -and $head -ceq $TreeSha) 'ISSUE_1099_FSV_TREE_MISMATCH' `
    "expected committed tree $TreeSha, observed $head"
Assert-Astro (Test-Path -LiteralPath $source -PathType Leaf) 'ISSUE_1099_FSV_ARTIFACT_MISSING' `
    "native artifact is absent: $source"

$sourceHash = Get-Sha256 $source
$session = Join-Path (
    Join-Path (Join-Path (Join-Path $workspace '.tmp\native-fsv-artifacts') $TreeSha) $sourceHash
) $SessionId
$receiptPath = Join-Path $session 'receipt.json'

& powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $PSScriptRoot 'native-fsv-artifact.ps1') `
    -Operation Stage -SourcePath $source -Issue $Issue -TreeSha $TreeSha -SessionId $SessionId
Assert-Astro ($LASTEXITCODE -eq 0) 'ISSUE_1099_FSV_STAGE_FAILED' "artifact Stage exited $LASTEXITCODE"

$payload = Join-Path $session 'payload'
$stdoutPath = Join-Path $session 'stdout.txt'
$stderrPath = Join-Path $session 'stderr.txt'
$runRecordPath = Join-Path $session 'run.json'
$liveStatePath = Join-Path $session 'live.json'
$runnerHostStdoutPath = Join-Path $session 'runner-host.stdout.txt'
$runnerHostStderrPath = Join-Path $session 'runner-host.stderr.txt'
$argumentsJson = ConvertTo-Json -Compress -InputObject @([string]$payload)

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
Assert-Astro $runner.Start() 'ISSUE_1099_FSV_RUNNER_START_FAILED' 'Windows PowerShell runner did not start'
$runnerStdoutTask = $runner.StandardOutput.ReadToEndAsync()
$runnerStderrTask = $runner.StandardError.ReadToEndAsync()
$runner.WaitForExit()
$runnerStdout = $runnerStdoutTask.GetAwaiter().GetResult()
$runnerStderr = $runnerStderrTask.GetAwaiter().GetResult()
Assert-Astro ($runner.ExitCode -eq 0) 'ISSUE_1099_FSV_RUNNER_FAILED' `
    "native-fsv-run exit=$($runner.ExitCode) stdout=$runnerStdout stderr=$runnerStderr"

& powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $PSScriptRoot 'native-fsv-artifact.ps1') `
    -Operation Inspect -ReceiptPath $receiptPath
Assert-Astro ($LASTEXITCODE -eq 0) 'ISSUE_1099_FSV_INSPECT_FAILED' "artifact Inspect exited $LASTEXITCODE"

[IO.File]::WriteAllText($runnerHostStdoutPath, $runnerStdout, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($runnerHostStderrPath, $runnerStderr, [Text.UTF8Encoding]::new($false))
$run = Get-Content -LiteralPath $runRecordPath -Raw | ConvertFrom-Json
Assert-Astro (
    @('astrolabe.native-fsv-run.v2', 'astrolabe.native-fsv-run.v3') -ccontains [string]$run.schema -and
    [string]$run.verdict -ceq 'verified' -and [int]$run.process.exit_code -eq 0 -and
    [bool]$run.artifact.stable -and [bool]$run.repository.stable -and [bool]$run.launcher_lease.stable
) 'ISSUE_1099_FSV_RUN_RECORD_INVALID' 'run record did not prove a stable real artifact and exit 0'

$reportPath = Join-Path $payload 'report.json'
$directPath = Join-Path $payload 'direct.json'
$allocationPath = Join-Path $payload 'allocation.json'
$firstMcpPath = Join-Path $payload 'first.mcp.json'
$secondMcpPath = Join-Path $payload 'second.mcp.json'
$firstIndexPath = Join-Path $payload 'first.index.json'
$secondIndexPath = Join-Path $payload 'second.index.json'
$firstChildPath = Join-Path $payload 'first.child.json'
$secondChildPath = Join-Path $payload 'second.child.json'
$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
$direct = Get-Content -LiteralPath $directPath -Raw | ConvertFrom-Json
$allocation = Get-Content -LiteralPath $allocationPath -Raw | ConvertFrom-Json
$firstMcpRaw = Get-Content -LiteralPath $firstMcpPath -Raw
$secondMcpRaw = Get-Content -LiteralPath $secondMcpPath -Raw
$firstIndexRaw = Get-Content -LiteralPath $firstIndexPath -Raw
$secondIndexRaw = Get-Content -LiteralPath $secondIndexPath -Raw
$firstMcp = $firstMcpRaw | ConvertFrom-Json
$secondMcp = $secondMcpRaw | ConvertFrom-Json
$firstIndex = Get-Content -LiteralPath $firstIndexPath -Raw | ConvertFrom-Json
$secondIndex = Get-Content -LiteralPath $secondIndexPath -Raw | ConvertFrom-Json
$firstChild = Get-Content -LiteralPath $firstChildPath -Raw | ConvertFrom-Json
$secondChild = Get-Content -LiteralPath $secondChildPath -Raw | ConvertFrom-Json

Assert-Astro ([string]$report.schema -ceq 'astrolabe.issue-1099.cross-lsp-fsv.v2') `
    'ISSUE_1099_FSV_REPORT_INVALID' 'report schema does not identify the issue-1099 contract'
Assert-Astro (
    [string]$firstChild.schema -ceq 'astrolabe.issue-1099.index-child.v1' -and
    [string]$secondChild.schema -ceq 'astrolabe.issue-1099.index-child.v1' -and
    [string]$firstChild.cache_requested -ceq [string]$firstChild.cache_readback -and
    [string]$secondChild.cache_requested -ceq [string]$secondChild.cache_readback
) 'ISSUE_1099_FSV_INDEX_CHILD_RECEIPT_INVALID' `
    'an index child did not read back its exact isolated native cache binding'
$firstStore = [IO.Path]::GetFullPath((Join-Path $payload 'first-store'))
$secondStore = [IO.Path]::GetFullPath((Join-Path $payload 'second-store'))
$firstDb = [IO.Path]::GetFullPath([string]$firstChild.database)
$secondDb = [IO.Path]::GetFullPath([string]$secondChild.database)
Assert-Astro (
    [IO.Path]::GetFullPath([string]$firstChild.cache_readback) -ceq $firstStore -and
    [IO.Path]::GetDirectoryName($firstDb) -ceq $firstStore -and
    [IO.Path]::GetFullPath([string]$secondChild.cache_readback) -ceq $secondStore -and
    [IO.Path]::GetDirectoryName($secondDb) -ceq $secondStore -and
    $firstDb -cne $secondDb -and
    (Test-Path -LiteralPath $firstDb -PathType Leaf) -and
    (Test-Path -LiteralPath $secondDb -PathType Leaf)
) 'ISSUE_1099_FSV_DATABASE_AUTHORITY_INVALID' `
    'the worker-reported database source of truth is absent or outside its isolated payload cache'
$mcpPairs = @(
    [pscustomobject]@{ Mcp = $firstMcp; McpRaw = $firstMcpRaw; IndexRaw = $firstIndexRaw; Index = $firstIndex },
    [pscustomobject]@{ Mcp = $secondMcp; McpRaw = $secondMcpRaw; IndexRaw = $secondIndexRaw; Index = $secondIndex }
)
foreach ($pair in $mcpPairs) {
    $mcp = $pair.Mcp
    $mcpRaw = [string]$pair.McpRaw
    $indexRaw = [string]$pair.IndexRaw
    $index = $pair.Index
    Assert-Astro (
        -not [bool]$mcp.isError -and @($mcp.content).Count -eq 1 -and
        [string]$mcp.content[0].type -ceq 'text' -and
        [string]$mcp.content[0].text -ceq $indexRaw -and
        [string]$index.status -ceq 'indexed' -and
        [string]$index.project -ceq [string]$mcp.structuredContent.project -and
        (($mcp.structuredContent | ConvertTo-Json -Depth 100 -Compress) -ceq
            ($index | ConvertTo-Json -Depth 100 -Compress))
    ) 'ISSUE_1099_FSV_MCP_ENVELOPE_INVALID' `
        "outer MCP envelope does not exactly mirror its persisted payload: $mcpRaw"
}
Assert-Astro (
    [int]$direct.happy.after.count -eq 2 -and [int]$direct.happy.after.seeded -eq 1 -and
    [int]$direct.happy.after.source -eq 2 -and [int]$direct.happy.after.duplicate -eq 1 -and
    [int]$direct.happy.after.appended -eq 1 -and
    @($direct.happy.after.contexts).Count -eq 2 -and
    [string]$direct.happy.after.contexts[0] -ceq '' -and
    [string]$direct.happy.after.contexts[1] -ceq 'ctx-B' -and
    [string]$direct.happy.after.rows[0].strategy -ceq 'cross-higher-confidence' -and
    [double]$direct.happy.after.rows[0].confidence -eq 0.95 -and
    [bool]$direct.happy.after.rows[0].context_is_null -and
    [string]$direct.happy.after.rows[1].strategy -ceq 'cross-distinct-context' -and
    -not [bool]$direct.happy.after.rows[1].context_is_null
) 'ISSUE_1099_FSV_HAPPY_RECEIPT_INVALID' `
    'exact duplicate, context canonicalization, confidence update, or distinct-context result is wrong'
Assert-Astro (
    [int]$direct.empty.before.count -eq 0 -and [int]$direct.empty.after.count -eq 0 -and
    [bool]$direct.empty.after.accounting_present
) 'ISSUE_1099_FSV_EMPTY_RECEIPT_INVALID' 'empty canonicalization did not persist its zero receipt'
Assert-Astro (
    [int]$direct.malformed.before.count -eq 2 -and [int]$direct.malformed.after.count -eq 0 -and
    [bool]$direct.malformed.after.has_error -and
    [string]$direct.malformed.after.code -ceq 'CBM_LSP_DEDUP_IDENTITY_INVALID'
) 'ISSUE_1099_FSV_MALFORMED_RECEIPT_INVALID' 'malformed identity did not fail terminally and discard rows'
Assert-Astro (
    [int]$allocation.before.count -eq 100000 -and [int]$allocation.after.count -eq 0 -and
    [bool]$allocation.after.has_error -and
    ([string]$allocation.after.code -like '*ALLOC*' -or [string]$allocation.after.code -like '*CAPACITY*')
) 'ISSUE_1099_FSV_ALLOCATION_RECEIPT_INVALID' 'real OS-limited allocation did not fail terminally'

$sqliteCommand = Get-Command sqlite3.exe -ErrorAction SilentlyContinue
Assert-Astro ($null -ne $sqliteCommand) 'ISSUE_1099_FSV_SQLITE_MISSING' `
    'sqlite3.exe is required for independent physical database readback'
$sqlite = [string]$sqliteCommand.Source
$stateQuery = "SELECT (SELECT count(*) FROM projects) AS projects,(SELECT count(*) FROM nodes) AS nodes,(SELECT count(*) FROM edges) AS edges,(SELECT count(*) FROM edges WHERE type='CALLS') AS calls,(SELECT count(*) FROM node_vectors) AS node_vectors,(SELECT count(*) FROM token_vectors) AS token_vectors,(SELECT count(*) FROM (SELECT source_id,target_id,type,local_name_gen,preprocess_context_id_gen,count(*) AS n FROM edges GROUP BY source_id,target_id,type,local_name_gen,preprocess_context_id_gen HAVING n>1)) AS duplicate_edge_identities,integrity_check AS integrity FROM pragma_integrity_check;"
$callQuery = "SELECT s.qualified_name AS source,t.qualified_name AS target,e.preprocess_context_id_gen AS context,e.properties FROM edges e JOIN nodes s ON s.id=e.source_id JOIN nodes t ON t.id=e.target_id WHERE e.type='CALLS' ORDER BY source,target,context,e.properties;"
$logicalQuery = "SELECT label,name,qualified_name,file_path,start_line,end_line,properties,atom_id FROM nodes ORDER BY label,name,qualified_name,file_path,start_line,end_line,atom_id; SELECT s.qualified_name AS source,t.qualified_name AS target,e.type,e.preprocess_context_id_gen AS context,e.properties FROM edges e JOIN nodes s ON s.id=e.source_id JOIN nodes t ON t.id=e.target_id ORDER BY source,target,e.type,context,e.properties; SELECT token,hex(vector) AS vector,idf FROM token_vectors ORDER BY token; SELECT n.atom_id,hex(v.vector) AS vector FROM node_vectors v JOIN nodes n ON n.id=v.node_id ORDER BY n.atom_id;"
$firstStateRaw = Invoke-SqliteRaw $sqlite $firstDb $stateQuery
$secondStateRaw = Invoke-SqliteRaw $sqlite $secondDb $stateQuery
$firstCallsRaw = Invoke-SqliteRaw $sqlite $firstDb $callQuery
$secondCallsRaw = Invoke-SqliteRaw $sqlite $secondDb $callQuery
$firstLogical = Invoke-SqliteRaw $sqlite $firstDb $logicalQuery
$secondLogical = Invoke-SqliteRaw $sqlite $secondDb $logicalQuery
$firstState = @($firstStateRaw | ConvertFrom-Json)[0]
$secondState = @($secondStateRaw | ConvertFrom-Json)[0]
$firstCalls = @($firstCallsRaw | ConvertFrom-Json)
$secondCalls = @($secondCallsRaw | ConvertFrom-Json)

Assert-Astro (
    [int]$firstState.projects -eq 1 -and [int]$firstState.nodes -gt 0 -and
    [int]$firstState.calls -eq 4 -and [int]$firstState.duplicate_edge_identities -eq 0 -and
    [string]$firstState.integrity -ceq 'ok'
) 'ISSUE_1099_FSV_FIRST_DB_INVALID' `
    'first physical graph does not contain the four known canonical Python/JVM CALLS edges'
Assert-Astro (
    [int]$secondState.projects -eq 1 -and [int]$secondState.nodes -eq [int]$firstState.nodes -and
    [int]$secondState.edges -eq [int]$firstState.edges -and
    [int]$secondState.calls -eq [int]$firstState.calls -and
    [int]$secondState.node_vectors -eq [int]$firstState.node_vectors -and
    [int]$secondState.token_vectors -eq [int]$firstState.token_vectors -and
    [int]$secondState.duplicate_edge_identities -eq 0 -and [string]$secondState.integrity -ceq 'ok'
) 'ISSUE_1099_FSV_SECOND_DB_INVALID' 'second physical graph/vector state differs in cardinality'
Assert-Astro ($firstLogical -ceq $secondLogical) 'ISSUE_1099_FSV_DETERMINISM_MISMATCH' `
    'two fresh unchanged full runs did not produce byte-identical logical graph/vector rows'
Assert-Astro ($firstCallsRaw -ceq $secondCallsRaw -and $firstCalls.Count -eq 4 -and $secondCalls.Count -eq 4) `
    'ISSUE_1099_FSV_CALL_READBACK_MISMATCH' 'CALLS edge rows are not exact and stable across fresh runs'

$firstAccounting = $firstChild.accounting
$secondAccounting = $secondChild.accounting
foreach ($accounting in @($firstAccounting, $secondAccounting)) {
    Assert-Astro (
        [string]$accounting.state -ceq 'measured' -and
        [uint64]$accounting.cross_lsp_units -eq [uint64]$accounting.cross_lsp_accounted_units -and
        [uint64]$accounting.cross_lsp_seen_rows -eq
            ([uint64]$accounting.cross_lsp_seeded_rows + [uint64]$accounting.cross_lsp_source_rows) -and
        [uint64]$accounting.cross_lsp_source_rows -eq
            ([uint64]$accounting.cross_lsp_duplicate_rows + [uint64]$accounting.cross_lsp_appended_rows) -and
        [uint64]$accounting.cross_lsp_duplicate_rows -gt 0 -and
        [uint64]$accounting.cross_lsp_appended_rows -gt 0
    ) 'ISSUE_1099_FSV_MCP_ACCOUNTING_INVALID' 'MCP accounting violates its exact row algebra'
}

$readback = [ordered]@{
    schema = 'astrolabe.issue-1099.cross-lsp-fsv-readback.v1'
    artifact_sha256 = $sourceHash
    run_record_sha256 = Get-Sha256 $runRecordPath
    report_sha256 = Get-Sha256 $reportPath
    direct_sha256 = Get-Sha256 $directPath
    allocation_sha256 = Get-Sha256 $allocationPath
    first_mcp_sha256 = Get-Sha256 $firstMcpPath
    second_mcp_sha256 = Get-Sha256 $secondMcpPath
    first_index_sha256 = Get-Sha256 $firstIndexPath
    second_index_sha256 = Get-Sha256 $secondIndexPath
    first_child_sha256 = Get-Sha256 $firstChildPath
    second_child_sha256 = Get-Sha256 $secondChildPath
    first_db_sha256 = Get-Sha256 $firstDb
    second_db_sha256 = Get-Sha256 $secondDb
    logical_readback_sha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($firstLogical))
    ).ToLowerInvariant()
    direct = $direct
    allocation = $allocation
    first_accounting = $firstAccounting
    second_accounting = $secondAccounting
    first_state = $firstState
    second_state = $secondState
    calls = $firstCalls
}
$readbackPath = Join-Path $payload 'readback.json'
$readbackJson = $readback | ConvertTo-Json -Depth 16 -Compress
[IO.File]::WriteAllText($readbackPath, $readbackJson, [Text.UTF8Encoding]::new($false))
$readbackAgain = Get-Content -LiteralPath $readbackPath -Raw
Assert-Astro ($readbackAgain -ceq $readbackJson) 'ISSUE_1099_FSV_READBACK_WRITE_UNSTABLE' `
    'persisted source-of-truth readback differs from the bytes written'

Write-Output "ISSUE_1099_FSV_SOURCE_OF_TRUTH $readbackAgain"
Write-Output "ISSUE_1099_FSV_RECEIPT $receiptPath"
Write-Output "ISSUE_1099_FSV_RUN $runRecordPath"
Write-Output "ISSUE_1099_FSV_READBACK $readbackPath sha256=$(Get-Sha256 $readbackPath)"
