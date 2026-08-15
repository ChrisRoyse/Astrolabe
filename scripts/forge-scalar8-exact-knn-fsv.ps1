<#
.SYNOPSIS
    Stages, runs, and independently verifies Forge-backed Weave exact scalar8 kNN.

.DESCRIPTION
    Manual Full State Verification for #1057. Run synchronously beneath the
    exact issue-owned native launcher after Cargo builds the release example.
    The script promotes the committed executable, invokes native-fsv-run.ps1 in
    a distinct Windows PowerShell process with stdout/stderr captured separately,
    and independently reads every durable result and refusal record. This is a
    reality probe, not a test or gate.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$Issue,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$TreeSha,
    [Parameter(Mandatory)][string]$SourcePath,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$')]
    [string]$SessionId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Assert-Astro {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message
    )
    if (-not $Condition) { throw "${Code}: ${Message}" }
}

function Read-Json {
    param([Parameter(Mandatory)][string]$Path)
    Assert-Astro (Test-Path -LiteralPath $Path -PathType Leaf) `
        'CALYX_FORGE_EXACT_KNN_FSV_FILE_MISSING' "persisted file is absent: $Path"
    return ([IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8) | ConvertFrom-Json)
}

function Get-Sha256File {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function ConvertTo-OneArgumentJson {
    param([Parameter(Mandatory)][string]$Value)
    Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
    $serializer = [System.Web.Script.Serialization.JavaScriptSerializer]::new()
    $json = $serializer.Serialize([object[]]@($Value))
    $readback = $serializer.DeserializeObject($json)
    Assert-Astro (
        $readback -is [object[]] -and $readback.Count -eq 1 -and
        [string]$readback[0] -ceq $Value
    ) 'CALYX_FORGE_EXACT_KNN_FSV_ARGUMENT_JSON_INVALID' `
        'runner argument JSON did not round-trip exactly'
    return $json
}

function ConvertTo-StableJson {
    param([Parameter(Mandatory)]$Value)
    return ($Value | ConvertTo-Json -Compress -Depth 50)
}

function Assert-InventoryRefusal {
    param(
        [Parameter(Mandatory)]$Transition,
        [Parameter(Mandatory)][string]$ExpectedCode,
        [Parameter(Mandatory)][string]$Label
    )
    Assert-Astro (
        [string]$Transition.action.code -ceq $ExpectedCode -and
        [bool]$Transition.state_unchanged -and
        (ConvertTo-StableJson $Transition.before) -ceq (ConvertTo-StableJson $Transition.after)
    ) 'CALYX_FORGE_EXACT_KNN_FSV_REFUSAL_MUTATED_STATE' `
        "$Label did not preserve its exact pre-action payload inventory"
}

Assert-Astro ($Issue -eq 1057) 'CALYX_FORGE_EXACT_KNN_FSV_ISSUE_MISMATCH' `
    "this driver is bound to issue 1057, observed $Issue"
$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$source = [IO.Path]::GetFullPath($SourcePath)
$head = (& 'C:\Program Files\Git\bin\git.exe' -C $workspace rev-parse HEAD).Trim()
Assert-Astro ($LASTEXITCODE -eq 0 -and $head -ceq $TreeSha) `
    'CALYX_FORGE_EXACT_KNN_FSV_TREE_MISMATCH' `
    "expected committed tree $TreeSha, observed $head"
Assert-Astro (Test-Path -LiteralPath $source -PathType Leaf) `
    'CALYX_FORGE_EXACT_KNN_FSV_ARTIFACT_MISSING' "release executable is absent: $source"

$sourceHash = Get-Sha256File $source
$session = Join-Path (
    Join-Path (Join-Path (Join-Path $workspace '.tmp\native-fsv-artifacts') $TreeSha) $sourceHash
) $SessionId
$receiptPath = Join-Path $session 'receipt.json'

& powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $PSScriptRoot 'native-fsv-artifact.ps1') `
    -Operation Stage -SourcePath $source -Issue $Issue -TreeSha $TreeSha -SessionId $SessionId
Assert-Astro ($LASTEXITCODE -eq 0) 'CALYX_FORGE_EXACT_KNN_FSV_STAGE_FAILED' `
    "artifact Stage exited $LASTEXITCODE"
Assert-Astro (Test-Path -LiteralPath $receiptPath -PathType Leaf) `
    'CALYX_FORGE_EXACT_KNN_FSV_RECEIPT_MISSING' "receipt is absent: $receiptPath"

$payload = Join-Path $session 'payload'
$stdoutPath = Join-Path $session 'stdout.txt'
$stderrPath = Join-Path $session 'stderr.txt'
$runRecordPath = Join-Path $session 'run.json'
$liveStatePath = Join-Path $session 'live.json'
$runnerHostStdoutPath = Join-Path $session 'runner-host.stdout.txt'
$runnerHostStderrPath = Join-Path $session 'runner-host.stderr.txt'
$argumentsJson = ConvertTo-OneArgumentJson $payload

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
$runnerProcess = [Diagnostics.Process]::new()
$runnerProcess.StartInfo = $runnerStart
Assert-Astro $runnerProcess.Start() 'CALYX_FORGE_EXACT_KNN_FSV_RUNNER_START_FAILED' `
    'Windows PowerShell runner process did not start'
$runnerStdoutTask = $runnerProcess.StandardOutput.ReadToEndAsync()
$runnerStderrTask = $runnerProcess.StandardError.ReadToEndAsync()
$runnerProcess.WaitForExit()
$runnerExit = $runnerProcess.ExitCode
$runnerHostStdout = $runnerStdoutTask.GetAwaiter().GetResult()
$runnerHostStderr = $runnerStderrTask.GetAwaiter().GetResult()
Assert-Astro ($runnerExit -eq 0) 'CALYX_FORGE_EXACT_KNN_FSV_RUNNER_FAILED' `
    "native-fsv-run exited $runnerExit; stdout=$runnerHostStdout stderr=$runnerHostStderr"

& powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $PSScriptRoot 'native-fsv-artifact.ps1') `
    -Operation Inspect -ReceiptPath $receiptPath
Assert-Astro ($LASTEXITCODE -eq 0) 'CALYX_FORGE_EXACT_KNN_FSV_INSPECT_FAILED' `
    "artifact Inspect exited $LASTEXITCODE"
[IO.File]::WriteAllText($runnerHostStdoutPath, $runnerHostStdout, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($runnerHostStderrPath, $runnerHostStderr, [Text.UTF8Encoding]::new($false))
$runnerHostStdoutReadback = [IO.File]::ReadAllText($runnerHostStdoutPath, [Text.Encoding]::UTF8)
$runnerHostStderrReadback = [IO.File]::ReadAllText($runnerHostStderrPath, [Text.Encoding]::UTF8)
Assert-Astro (
    $runnerHostStdoutReadback -ceq $runnerHostStdout -and
    $runnerHostStderrReadback -ceq $runnerHostStderr
) 'CALYX_FORGE_EXACT_KNN_FSV_RUNNER_STREAM_READBACK_INVALID' `
    'separate completed Windows PowerShell runner streams did not read back byte-for-character'

$run = Read-Json $runRecordPath
Assert-Astro (
    @('astrolabe.native-fsv-run.v2', 'astrolabe.native-fsv-run.v3') -ccontains [string]$run.schema -and
    [string]$run.verdict -ceq 'verified' -and [int]$run.process.exit_code -eq 0 -and
    [bool]$run.artifact.stable -and [bool]$run.repository.stable -and
    [bool]$run.launcher_lease.stable
) 'CALYX_FORGE_EXACT_KNN_FSV_RUN_RECORD_INVALID' `
    'run record does not prove stable committed artifact/repository/launcher state and exit 0'

$cpu = Read-Json (Join-Path $payload '10-cpu-oracle.json')
$gpu = Read-Json (Join-Path $payload '20-gpu-first.json')
$concurrent = Read-Json (Join-Path $payload '21-gpu-concurrent.json')
$weave = Read-Json (Join-Path $payload '30-weave-plan.json')
$maxDimension = Read-Json (Join-Path $payload '40-max-dimension.json')
$reportPath = Join-Path $payload 'report.json'
$report = Read-Json $reportPath
$reportHash = Get-Sha256File $reportPath
$hashRecord = [IO.File]::ReadAllText((Join-Path $payload 'report.sha256'), [Text.Encoding]::UTF8).Trim()
Assert-Astro (
    [string]$report.schema -ceq 'astrolabe.issue-1057.forge-exact-knn-fsv.v1' -and
    [int]$report.issue -eq 1057 -and $hashRecord -ceq "$reportHash  report.json"
) 'CALYX_FORGE_EXACT_KNN_FSV_REPORT_INVALID' `
    'persisted report identity or independent SHA-256 readback failed'

$expectedRows = '0,1,2|1,0,2|2,1,0|3,2,4|4,0,1|5,0,1'
foreach ($execution in @($cpu, $gpu, $concurrent.caller_a, $concurrent.caller_b)) {
    $actualRows = @($execution.neighbors | ForEach-Object {
        (@($_ | ForEach-Object { [int]$_.index })) -join ','
    }) -join '|'
    Assert-Astro ($actualRows -ceq $expectedRows) `
        'CALYX_FORGE_EXACT_KNN_FSV_NEIGHBORS_INVALID' `
        "persisted neighbor rows differ from the hand-derived result: $actualRows"
}
Assert-Astro (
    [string]$cpu.receipt.executor -ceq 'cpu' -and [string]$gpu.receipt.executor -ceq 'cuda' -and
    [string]$cpu.receipt.output_sha256 -ceq [string]$gpu.receipt.output_sha256 -and
    [string]$gpu.receipt.output_sha256 -ceq [string]$weave.forge_receipt.output_sha256 -and
    [bool]$concurrent.stable_receipt_equal -and [bool]$concurrent.neighbors_equal_cpu -and
    (ConvertTo-StableJson $concurrent.caller_a.receipt) -ceq
        (ConvertTo-StableJson $concurrent.caller_b.receipt)
) 'CALYX_FORGE_EXACT_KNN_FSV_PARITY_INVALID' `
    'CPU/GPU/Weave output hashes or repeat/concurrent stable receipts differ'

Assert-Astro (
    [uint64]$gpu.receipt.score_evaluations -eq 36 -and
    [uint64]$gpu.receipt.coordinate_products -eq 144 -and
    [uint64]$gpu.receipt.candidate_upload_bytes -eq 96 -and
    [uint64]$gpu.receipt.query_upload_bytes -eq 96 -and
    [uint64]$gpu.receipt.topk_readback_bytes -eq 144 -and
    [uint64]$gpu.receipt.device_workspace_bytes -eq 160 -and
    [uint64]$gpu.observation.reserved_bytes -eq 160 -and
    [uint64]$gpu.observation.forge_allocated_while_reserved_bytes -eq 160 -and
    [uint64]$gpu.observation.forge_allocated_after_release_bytes -eq 0 -and
    [uint64]$gpu.observation.device_free_before_bytes -gt
        [uint64]$gpu.observation.device_free_while_workspace_live_bytes -and
    [uint64]$gpu.observation.device_free_after_release_bytes -gt
        [uint64]$gpu.observation.device_free_while_workspace_live_bytes
) 'CALYX_FORGE_EXACT_KNN_FSV_COST_OR_RELEASE_INVALID' `
    'persisted work/transfer/workspace counts or physical/logical VRAM lifecycle disagree'

$kernels = @($gpu.receipt.kernels)
Assert-Astro (
    [string]$gpu.receipt.submission_contract -ceq 'process_serial_attested_context_default_stream' -and
    [string]$gpu.receipt.device_name -ceq 'NVIDIA GeForce RTX 5090' -and
    [int]$gpu.receipt.compute_capability[0] -eq 12 -and
    [int]$gpu.receipt.compute_capability[1] -eq 0 -and
    $kernels.Count -eq 2 -and (@($kernels.module_name) -join ',') -ceq 'distance,topk' -and
    @($kernels | Where-Object {
        [string]$_.target -cne 'sm_120a' -or [bool]$_.fmad -or
        [string]$_.module_kind -cne 'cubin' -or [string]$_.module_sha256 -notmatch '^[0-9a-f]{64}$'
    }).Count -eq 0
) 'CALYX_FORGE_EXACT_KNN_FSV_ATTESTATION_INVALID' `
    'CUDA physical identity, submission contract, or distance/topk kernel attestations differ'

$edgePath = Join-Path $payload '30-weave-edges.tsv'
$edgeLines = [IO.File]::ReadAllLines($edgePath, [Text.Encoding]::UTF8)
$edgePairs = @($edgeLines | ForEach-Object {
    $columns = $_ -split "`t"
    Assert-Astro ($columns.Count -ge 5) 'CALYX_FORGE_EXACT_KNN_FSV_EDGE_FORMAT_INVALID' `
        "edge row has fewer than five columns: $_"
    "$($columns[3])->$($columns[4])"
})
$expectedPairs = @(
    'fsv::0->fsv::1', 'fsv::0->fsv::2', 'fsv::1->fsv::2',
    'fsv::1->fsv::4', 'fsv::2->fsv::3', 'fsv::3->fsv::4'
)
Assert-Astro (
    ($edgePairs -join '|') -ceq ($expectedPairs -join '|') -and
    [int]$weave.edge_count -eq 6 -and [int]$weave.pair_counts.candidate_pairs -eq 9 -and
    [int]$weave.pair_counts.incompatible_shape_pairs -eq 0 -and
    [int]$weave.pair_counts.below_threshold_pairs -eq 0 -and
    [int]$weave.pair_counts.cap_dropped_pairs -eq 3 -and
    [int]$weave.pair_counts.admitted_pairs -eq 6
) 'CALYX_FORGE_EXACT_KNN_FSV_WEAVE_INVALID' `
    'physical Weave edge rows or the independently expected 9/0/0/3/6 accounting differ'

Assert-Astro (
    [int]$maxDimension.receipt.dim -eq 1040 -and [int]$maxDimension.receipt.rows -eq 2
) 'CALYX_FORGE_EXACT_KNN_FSV_MAX_DIMENSION_INVALID' `
    'the inclusive signed-int8 exactness boundary did not persist as dim 1040'
foreach ($refusal in @(
    @('50-empty', 'CALYX_FORGE_SHAPE_MISMATCH'),
    @('51-malformed-length', 'CALYX_FORGE_SHAPE_MISMATCH'),
    @('52-zero-norm', 'CALYX_FORGE_NUMERICAL_INVARIANT'),
    @('53-over-dimension', 'CALYX_FORGE_SHAPE_MISMATCH')
)) {
    Assert-InventoryRefusal (Read-Json (Join-Path $payload "$($refusal[0]).json")) `
        $refusal[1] $refusal[0]
}
foreach ($childRefusal in @(
    @('54-vram-budget', 'CALYX_FORGE_VRAM_BUDGET'),
    @('55-unavailable-device', 'CALYX_CUDA_DEVICE_SELECTOR_INVALID')
)) {
    $errorPath = Join-Path $payload "$($childRefusal[0]).error.json"
    $resultPath = Join-Path $payload "$($childRefusal[0]).result.json"
    $error = Read-Json $errorPath
    Assert-Astro (
        [string]$error.code -ceq 'CALYX_FORGE_SCALAR8_EXACT_KNN_FAILED' -and
        ([string]$error.detail).Contains($childRefusal[1]) -and
        -not (Test-Path -LiteralPath $resultPath)
    ) 'CALYX_FORGE_EXACT_KNN_FSV_CHILD_REFUSAL_INVALID' `
        "$($childRefusal[0]) did not retain its cause or published a derived result"
}

$nvidiaSmi = Join-Path $env:SystemRoot 'System32\nvidia-smi.exe'
$nvidiaRows = @(& $nvidiaSmi `
    '--query-gpu=uuid,name,memory.total,memory.free,driver_version' `
    '--format=csv,noheader,nounits')
Assert-Astro ($LASTEXITCODE -eq 0 -and $nvidiaRows.Count -gt 0) `
    'CALYX_FORGE_EXACT_KNN_FSV_NVIDIA_SMI_FAILED' "nvidia-smi exited $LASTEXITCODE"
$nvidiaPath = Join-Path $session 'nvidia-smi-after.csv'
[IO.File]::WriteAllLines($nvidiaPath, $nvidiaRows, [Text.UTF8Encoding]::new($false))
$nvidiaReadback = [IO.File]::ReadAllText($nvidiaPath, [Text.Encoding]::UTF8)
Assert-Astro (
    $nvidiaReadback.Contains('NVIDIA GeForce RTX 5090') -and
    ([string]$gpu.receipt.physical_device).IndexOf(
        ($nvidiaRows[0] -split ',')[0].Trim(), [StringComparison]::OrdinalIgnoreCase
    ) -ge 0
) 'CALYX_FORGE_EXACT_KNN_FSV_PHYSICAL_DEVICE_MISMATCH' `
    'post-run nvidia-smi UUID/name disagrees with the persisted Forge receipt'

$childStdout = [IO.File]::ReadAllText($stdoutPath, [Text.Encoding]::UTF8)
$childStderr = [IO.File]::ReadAllText($stderrPath, [Text.Encoding]::UTF8)
Assert-Astro ($childStdout.Contains('ASTRO_ISSUE_1057_FSV_OK')) `
    'CALYX_FORGE_EXACT_KNN_FSV_SUCCESS_MARKER_MISSING' `
    "real artifact stdout lacks its success marker; stderr=$childStderr"

$analysis = [ordered]@{
    schema = 'astrolabe.issue-1057.forge-exact-knn-analysis.v1'
    issue = 1057
    tree_sha = $TreeSha
    artifact_sha256 = $sourceHash
    report_sha256 = $reportHash
    output_sha256 = [string]$gpu.receipt.output_sha256
    input_sha256 = [string]$gpu.receipt.input_sha256
    executor = [string]$gpu.receipt.executor
    physical_device = [string]$gpu.receipt.physical_device
    device_name = [string]$gpu.receipt.device_name
    compute_capability = @($gpu.receipt.compute_capability)
    kernel_modules = @($kernels.module_name)
    score_evaluations = [uint64]$gpu.receipt.score_evaluations
    coordinate_products = [uint64]$gpu.receipt.coordinate_products
    transfer_bytes = [ordered]@{
        candidate_upload = [uint64]$gpu.receipt.candidate_upload_bytes
        query_upload = [uint64]$gpu.receipt.query_upload_bytes
        chunk_topk_readback = [uint64]$gpu.receipt.topk_readback_bytes
    }
    workspace_bytes = [uint64]$gpu.receipt.device_workspace_bytes
    forge_allocated_after_release_bytes = [uint64]$gpu.observation.forge_allocated_after_release_bytes
    known_neighbor_rows = $expectedRows
    weave_edge_pairs = $edgePairs
    weave_pair_counts = $weave.pair_counts
    maximum_dimension = [int]$maxDimension.receipt.dim
    refusal_codes = @(
        'CALYX_FORGE_SHAPE_MISMATCH', 'CALYX_FORGE_NUMERICAL_INVARIANT',
        'CALYX_FORGE_VRAM_BUDGET', 'CALYX_CUDA_DEVICE_SELECTOR_INVALID'
    )
    nvidia_smi_sha256 = Get-Sha256File $nvidiaPath
    runner_schema = [string]$run.schema
    runner_exit_code = [int]$run.process.exit_code
    source_of_truth = $payload
    run_record = $runRecordPath
}
$analysisPath = Join-Path $session 'analysis.json'
Assert-Astro (-not (Test-Path -LiteralPath $analysisPath)) `
    'CALYX_FORGE_EXACT_KNN_FSV_ANALYSIS_REUSE' "analysis already exists: $analysisPath"
$analysisJson = $analysis | ConvertTo-Json -Depth 20
[IO.File]::WriteAllText($analysisPath, $analysisJson + "`r`n", [Text.UTF8Encoding]::new($false))
$analysisReadback = Read-Json $analysisPath
Assert-Astro (
    [string]$analysisReadback.report_sha256 -ceq $reportHash -and
    [string]$analysisReadback.output_sha256 -ceq [string]$gpu.receipt.output_sha256 -and
    [int]$analysisReadback.runner_exit_code -eq 0
) 'CALYX_FORGE_EXACT_KNN_FSV_ANALYSIS_READBACK_INVALID' `
    'analysis did not read back with the verified report/output/run identities'

Write-Output ($analysis | ConvertTo-Json -Compress -Depth 20)
