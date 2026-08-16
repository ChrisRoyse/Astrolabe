<#
.SYNOPSIS
    Manual Full State Verification for #1134 causal numeric correctness.

.DESCRIPTION
    Promotes and runs the real native server example under the live launcher
    lease, then independently reads its persisted report and exact artifact-run
    records. This is a manual reality probe, not a test or gate.
#>
#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourcePath,
    [Parameter(Mandatory)][string]$TreeSha,
    [Parameter(Mandatory)][string]$SessionId,
    [Parameter(Mandatory)][string]$NomicDir,
    [int]$Issue = 1134
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
        Fail-Astro $Code $Message `
            'preserve the staged session and inspect the first mismatched physical readback'
    }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

Assert-Astro ($Issue -eq 1134) 'ISSUE_1134_FSV_ISSUE_MISMATCH' `
    "expected issue 1134, observed $Issue"
$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$source = [IO.Path]::GetFullPath($SourcePath)
$nomicRoot = [IO.Path]::GetFullPath($NomicDir)
$nomicVectors = Join-Path $nomicRoot 'code_vectors.bin'
$nomicTokens = Join-Path $nomicRoot 'code_tokens.txt'
$head = (& 'C:\Program Files\Git\bin\git.exe' -C $workspace rev-parse HEAD).Trim()
Assert-Astro ($LASTEXITCODE -eq 0 -and $head -ceq $TreeSha) `
    'ISSUE_1134_FSV_TREE_MISMATCH' "expected committed tree $TreeSha, observed $head"
Assert-Astro (Test-Path -LiteralPath $source -PathType Leaf) `
    'ISSUE_1134_FSV_ARTIFACT_MISSING' "native artifact is absent: $source"
Assert-Astro (
    (Test-Path -LiteralPath $nomicVectors -PathType Leaf) -and
    (Test-Path -LiteralPath $nomicTokens -PathType Leaf)
) 'ISSUE_1134_FSV_NOMIC_DATA_MISSING' `
    "required Nomic runtime-data pair is absent below $nomicRoot"
$nomicVectorsHash = Get-Sha256 $nomicVectors
$nomicTokensHash = Get-Sha256 $nomicTokens
$env:ASTRO_NOMIC_DIR = $nomicRoot

$sourceHash = Get-Sha256 $source
$session = Join-Path (
    Join-Path (Join-Path (Join-Path $workspace '.tmp\native-fsv-artifacts') $TreeSha) $sourceHash
) $SessionId
$receiptPath = Join-Path $session 'receipt.json'

& powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $PSScriptRoot 'native-fsv-artifact.ps1') `
    -Operation Stage -SourcePath $source -Issue $Issue -TreeSha $TreeSha -SessionId $SessionId
Assert-Astro ($LASTEXITCODE -eq 0) 'ISSUE_1134_FSV_STAGE_FAILED' `
    "artifact Stage exited $LASTEXITCODE"

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
Assert-Astro $runner.Start() 'ISSUE_1134_FSV_RUNNER_START_FAILED' `
    'Windows PowerShell runner did not start'
$runnerStdoutTask = $runner.StandardOutput.ReadToEndAsync()
$runnerStderrTask = $runner.StandardError.ReadToEndAsync()
$runner.WaitForExit()
$runnerStdout = $runnerStdoutTask.GetAwaiter().GetResult()
$runnerStderr = $runnerStderrTask.GetAwaiter().GetResult()
Assert-Astro ($runner.ExitCode -eq 0) 'ISSUE_1134_FSV_RUNNER_FAILED' `
    "native-fsv-run exit=$($runner.ExitCode) stdout=$runnerStdout stderr=$runnerStderr"

& powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $PSScriptRoot 'native-fsv-artifact.ps1') `
    -Operation Inspect -ReceiptPath $receiptPath
Assert-Astro ($LASTEXITCODE -eq 0) 'ISSUE_1134_FSV_INSPECT_FAILED' `
    "artifact Inspect exited $LASTEXITCODE"

[IO.File]::WriteAllText($runnerHostStdoutPath, $runnerStdout, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($runnerHostStderrPath, $runnerStderr, [Text.UTF8Encoding]::new($false))
$run = Get-Content -LiteralPath $runRecordPath -Raw | ConvertFrom-Json
Assert-Astro (
    @('astrolabe.native-fsv-run.v2', 'astrolabe.native-fsv-run.v3') -ccontains [string]$run.schema -and
    [string]$run.verdict -ceq 'verified' -and [int]$run.process.exit_code -eq 0 -and
    [bool]$run.artifact.stable -and [bool]$run.repository.stable -and
    [bool]$run.launcher_lease.stable
) 'ISSUE_1134_FSV_RUN_RECORD_INVALID' `
    'run record did not prove a stable real artifact and exit 0'

$reportPath = Join-Path $payload 'report.json'
$reportRaw = Get-Content -LiteralPath $reportPath -Raw
$report = $reportRaw | ConvertFrom-Json
$reportAgain = Get-Content -LiteralPath $reportPath -Raw
Assert-Astro ($reportRaw -ceq $reportAgain) 'ISSUE_1134_FSV_REPORT_UNSTABLE' `
    'the persisted report changed across two independent reads'
Assert-Astro (
    (Get-Sha256 $nomicVectors) -ceq $nomicVectorsHash -and
    (Get-Sha256 $nomicTokens) -ceq $nomicTokensHash
) 'ISSUE_1134_FSV_NOMIC_DATA_DRIFT' `
    'the exact Nomic runtime-data pair changed across the native artifact run'
Assert-Astro ([string]$report.schema -ceq 'astrolabe.issue-1134.causal-numeric-fsv.v1') `
    'ISSUE_1134_FSV_REPORT_INVALID' 'report schema does not identify the issue-1134 contract'
Assert-Astro (
    [int]$report.tools.count -le 40 -and [int]$report.tools.count -eq [int]$report.tools.unique_count -and
    @($report.tools.names) -ccontains 'causal_analysis' -and
    @($report.tools.names) -ccontains 'expected_gain'
) 'ISSUE_1134_FSV_MCP_ROSTER_INVALID' 'MCP tool exposure is missing, duplicated, or over budget'

$happyBefore = $report.happy.before
$happyAfter = $report.happy.after
Assert-Astro (
    -not [bool]$happyBefore.state.causal.present -and [bool]$happyAfter.state.causal.present -and
    [string]$happyBefore.fingerprint -cne [string]$happyAfter.fingerprint -and
    [string]$happyAfter.state.config_integrity -ceq 'ok' -and
    [bool]$happyAfter.state.causal.current_pointer.present -and
    [bool]$happyAfter.state.causal.assay_artifact.present -and
    [bool]$happyAfter.state.causal.kernel.present -and
    [bool]$happyAfter.state.causal.manifest.present -and
    [bool]$happyAfter.state.causal.ledger.present -and
    [bool]$happyAfter.state.causal.ledger_decoded.verified -and
    [bool]$happyAfter.state.ledger_head_current.exists -and
    [bool]$happyAfter.state.current_manifest_pointer.exists -and
    [bool]$happyAfter.state.pointed_manifest.exists -and
    @($happyAfter.state.vault_tree.files).Count -gt 0
) 'ISSUE_1134_FSV_PHYSICAL_STATE_INVALID' `
    'the expected Assay/Kernel/Ledger/config/manifest/file-tree source of truth is absent'

$latency = @($report.happy.response.artifact.expected_gains | Where-Object outcome -CEQ 'latency')
$throughput = @($report.happy.response.artifact.expected_gains | Where-Object outcome -CEQ 'throughput')
Assert-Astro (
    $latency.Count -eq 1 -and [double]$latency[0].outcome_value -eq -10.0 -and
    [double]$latency[0].expected_net_gain -eq 35.0 -and [int]$latency[0].rank_within_unit -eq 1 -and
    [double]$latency[0].expected_net_gain_lower -le [double]$latency[0].expected_net_gain -and
    [double]$latency[0].expected_net_gain -le [double]$latency[0].expected_net_gain_upper -and
    $throughput.Count -eq 1 -and [double]$throughput[0].expected_net_gain -eq 19.0 -and
    [int]$throughput[0].rank_within_unit -eq 2
) 'ISSUE_1134_FSV_SIGNED_MATH_INVALID' `
    'signed utility, normalized interval, or mixed-sign ranking differs from the manual oracle'

$expectedCodes = @(
    'CALYX_LOOM_EXPECTED_GAIN_NUMERIC_INVALID',
    'ASTRO_ASSAY_CAUSAL_NUMERIC_INVALID',
    'ASTRO_MCP_ARGUMENT_CONST_FORBIDDEN'
)
$edges = @($report.edges)
Assert-Astro ($edges.Count -eq 3) 'ISSUE_1134_FSV_EDGE_COUNT_INVALID' `
    "expected three refusal edges, observed $($edges.Count)"
for ($index = 0; $index -lt $edges.Count; $index++) {
    $edge = $edges[$index]
    Assert-Astro (
        [string]$edge.expected_code -ceq $expectedCodes[$index] -and [bool]$edge.state_unchanged -and
        [string]$edge.before.fingerprint -ceq [string]$edge.after.fingerprint
    ) 'ISSUE_1134_FSV_EDGE_MUTATED_STATE' `
        "edge $index did not refuse with its exact code and byte-stable physical state"
}
Assert-Astro (
    [bool]$report.idempotent.state_unchanged -and
    [string]$report.idempotent.before.fingerprint -ceq [string]$report.idempotent.after.fingerprint -and
    [bool]$report.independent_reads.state_unchanged -and
    [string]$report.independent_reads.before.fingerprint -ceq
        [string]$report.independent_reads.after.fingerprint
) 'ISSUE_1134_FSV_READ_PATH_MUTATED_STATE' `
    'idempotent prepare or either read tool mutated the physical source of truth'

$readback = [ordered]@{
    schema = 'astrolabe.issue-1134.causal-numeric-fsv-readback.v1'
    artifact_sha256 = $sourceHash
    run_record_sha256 = Get-Sha256 $runRecordPath
    report_sha256 = Get-Sha256 $reportPath
    nomic_runtime = [ordered]@{
        directory = $nomicRoot
        code_vectors_sha256 = $nomicVectorsHash
        code_tokens_sha256 = $nomicTokensHash
    }
    project = [string]$report.project
    artifact_generation = [string]$happyAfter.state.causal.artifact_sha256
    snapshot_seq = [uint64]$happyAfter.state.snapshot_seq
    tool_count = [int]$report.tools.count
    signed_latency_net = [double]$latency[0].expected_net_gain
    signed_latency_rank = [int]$latency[0].rank_within_unit
    throughput_net = [double]$throughput[0].expected_net_gain
    throughput_rank = [int]$throughput[0].rank_within_unit
    edge_codes = $expectedCodes
    physical_fingerprint = [string]$happyAfter.fingerprint
    physical_rows = [ordered]@{
        assay_sha256 = [string]$happyAfter.state.causal.assay_artifact.sha256
        kernel_sha256 = [string]$happyAfter.state.causal.kernel.sha256
        manifest_sha256 = [string]$happyAfter.state.causal.manifest.sha256
        ledger_sha256 = [string]$happyAfter.state.causal.ledger.sha256
    }
}
$readbackPath = Join-Path $payload 'readback.json'
$readbackJson = $readback | ConvertTo-Json -Depth 12 -Compress
[IO.File]::WriteAllText($readbackPath, $readbackJson, [Text.UTF8Encoding]::new($false))
$readbackAgain = Get-Content -LiteralPath $readbackPath -Raw
Assert-Astro ($readbackAgain -ceq $readbackJson) 'ISSUE_1134_FSV_READBACK_WRITE_UNSTABLE' `
    'persisted source-of-truth readback differs from the bytes written'

Write-Output "ISSUE_1134_FSV_SOURCE_OF_TRUTH $readbackAgain"
Write-Output "ISSUE_1134_FSV_RECEIPT $receiptPath"
Write-Output "ISSUE_1134_FSV_RUN $runRecordPath"
Write-Output "ISSUE_1134_FSV_REPORT $reportPath sha256=$(Get-Sha256 $reportPath)"
Write-Output "ISSUE_1134_FSV_READBACK $readbackPath sha256=$(Get-Sha256 $readbackPath)"
