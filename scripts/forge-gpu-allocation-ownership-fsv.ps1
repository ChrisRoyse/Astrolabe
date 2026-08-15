<#
.SYNOPSIS
    Runs and independently verifies Forge's real CUDA allocation-ownership lifecycle.

.DESCRIPTION
    Manual Full State Verification for #872. Run this script as a synchronous
    descendant of the issue-owned native launcher after Cargo builds
    gpu_allocation_ownership_fsv.exe. It promotes the executable, runs it only
    through native-fsv-run.ps1, then separately reads every persisted state
    transition, recomputes the allocation-journal hash chain, and writes a
    read-back analysis record. No generated state is substituted or inferred.
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

function Get-Sha256File {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-Sha256Text {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Read-Json {
    param([Parameter(Mandatory)][string]$Path)
    Assert-Astro (Test-Path -LiteralPath $Path -PathType Leaf) `
        'CALYX_FORGE_GPU_FSV_FILE_MISSING' "persisted evidence file is absent: $Path"
    return ([IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8) | ConvertFrom-Json)
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
    ) 'CALYX_FORGE_GPU_FSV_ARGUMENT_JSON_INVALID' `
        'runner argument JSON did not round-trip exactly'
    return $json
}

function Get-StateHash {
    param([Parameter(Mandatory)]$State)
    $canonical = [ordered]@{
        device = $State.device
        stats = $State.stats
        allocations = $State.allocations
        physical_allocations = $State.physical_allocations
    } | ConvertTo-Json -Compress -Depth 20
    return Get-Sha256Text $canonical
}

function Assert-RefusalState {
    param(
        [Parameter(Mandatory)]$Transition,
        [Parameter(Mandatory)][string]$ExpectedCode,
        [Parameter(Mandatory)][string]$Label
    )
    Assert-Astro ($Transition.action.code -ceq $ExpectedCode) `
        'CALYX_FORGE_GPU_FSV_EDGE_CODE_MISMATCH' `
        "$Label returned '$($Transition.action.code)', expected '$ExpectedCode'"
    Assert-Astro ((Get-StateHash $Transition.before) -ceq (Get-StateHash $Transition.after)) `
        'CALYX_FORGE_GPU_FSV_EDGE_MUTATED_STATE' `
        "$Label changed physical, registry, journal, or accounting state"
}

Assert-Astro ($Issue -eq 872) 'CALYX_FORGE_GPU_FSV_ISSUE_MISMATCH' `
    "this driver is bound to issue 872, observed $Issue"
$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$source = [IO.Path]::GetFullPath($SourcePath)
$head = (& 'C:\Program Files\Git\bin\git.exe' -C $workspace rev-parse HEAD).Trim()
Assert-Astro ($LASTEXITCODE -eq 0 -and $head -ceq $TreeSha) `
    'CALYX_FORGE_GPU_FSV_TREE_MISMATCH' "expected tree $TreeSha, observed $head"
Assert-Astro (Test-Path -LiteralPath $source -PathType Leaf) `
    'CALYX_FORGE_GPU_FSV_ARTIFACT_MISSING' "built executable is absent: $source"

$sourceHash = Get-Sha256File $source
$session = Join-Path (Join-Path (Join-Path (Join-Path $workspace '.tmp\native-fsv-artifacts') $TreeSha) $sourceHash) $SessionId
$receiptPath = Join-Path $session 'receipt.json'

& powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $PSScriptRoot 'native-fsv-artifact.ps1') `
    -Operation Stage -SourcePath $source -Issue $Issue -TreeSha $TreeSha -SessionId $SessionId
Assert-Astro ($LASTEXITCODE -eq 0) 'CALYX_FORGE_GPU_FSV_STAGE_FAILED' `
    "artifact Stage exited $LASTEXITCODE"
Assert-Astro (Test-Path -LiteralPath $receiptPath -PathType Leaf) `
    'CALYX_FORGE_GPU_FSV_RECEIPT_MISSING' "receipt is absent: $receiptPath"

$payload = Join-Path $session 'payload'
$stdoutPath = Join-Path $session 'stdout.txt'
$stderrPath = Join-Path $session 'stderr.txt'
$runRecordPath = Join-Path $session 'run.json'
$liveStatePath = Join-Path $session 'live.json'
$argumentsJson = ConvertTo-OneArgumentJson $payload

& (Join-Path $PSScriptRoot 'native-fsv-run.ps1') `
    -ReceiptPath $receiptPath -ArgumentsJson $argumentsJson `
    -StandardOutputPath $stdoutPath -StandardErrorPath $stderrPath `
    -RunRecordPath $runRecordPath -LiveStatePath $liveStatePath -Issue $Issue
Assert-Astro $? 'CALYX_FORGE_GPU_FSV_RUNNER_FAILED' `
    'native FSV runner did not complete normally'

& powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $PSScriptRoot 'native-fsv-artifact.ps1') `
    -Operation Inspect -ReceiptPath $receiptPath
Assert-Astro ($LASTEXITCODE -eq 0) 'CALYX_FORGE_GPU_FSV_INSPECT_FAILED' `
    "artifact Inspect exited $LASTEXITCODE"

$run = Read-Json $runRecordPath
Assert-Astro (
    $run.schema -ceq 'astrolabe.native-fsv-run.v2' -and
    $run.verdict -ceq 'verified' -and [int]$run.process.exit_code -eq 0 -and
    [bool]$run.artifact.stable -and [bool]$run.repository.stable -and
    [bool]$run.launcher_lease.stable
) 'CALYX_FORGE_GPU_FSV_RUN_RECORD_INVALID' `
    'run record does not prove a stable artifact, repository, launcher, and exit 0'

$driverDispatch = Read-Json (Join-Path $payload '00-driver-dispatch.json')
$initial = Read-Json (Join-Path $payload '00-initial.json')
$happy = Read-Json (Join-Path $payload '10-happy.json')
$failed = Read-Json (Join-Path $payload '20-induced-free-failure.json')
$admission = Read-Json (Join-Path $payload '30-admission-refusal.json')
$wrongGeneration = Read-Json (Join-Path $payload '40-edge-wrong-generation.json')
$wrongPointer = Read-Json (Join-Path $payload '41-edge-reused-pointer.json')
$wrongDevice = Read-Json (Join-Path $payload '42-edge-wrong-device.json')
$unavailableDevice = Read-Json (Join-Path $payload '43-edge-unavailable-device.json')
$recovery = Read-Json (Join-Path $payload '50-recovery.json')
$reportPath = Join-Path $payload 'report.json'
$report = Read-Json $reportPath
$reportHash = Get-Sha256File $reportPath
$hashRecord = ([IO.File]::ReadAllText((Join-Path $payload 'report.sha256'))).Trim()
Assert-Astro (
    $report.schema -ceq 'calyx.forge.gpu-allocation-ownership-fsv.v1' -and
    [int]$report.issue -eq 872 -and $hashRecord -ceq "$reportHash  report.json"
) 'CALYX_FORGE_GPU_FSV_REPORT_INVALID' 'report identity or SHA-256 readback failed'

$expectedDriverSymbols = @('cuMemGetInfo', 'cuMemAlloc', 'cuMemFree', 'cuMemGetAddressRange')
Assert-Astro (
    $driverDispatch.schema -ceq 'calyx.forge.cuda-driver-memory-api.v1' -and
    [int]$driverDispatch.driver_version -ge 3020 -and
    [int]$driverDispatch.requested_abi_version -eq 3020 -and
    [uint64]$driverDispatch.flags -eq 0 -and
    @($driverDispatch.entries).Count -eq $expectedDriverSymbols.Count -and
    (@($driverDispatch.entries.symbol) -join ',') -ceq ($expectedDriverSymbols -join ',') -and
    @($driverDispatch.entries | Where-Object {
        [int]$_.requested_abi_version -ne 3020 -or
        [uint32]$_.query_status -ne 0 -or
        [uint64]$_.function_address -eq 0
    }).Count -eq 0 -and
    [int]$report.driver_dispatch.driver_version -eq [int]$driverDispatch.driver_version -and
    (@($report.driver_dispatch.entries.symbol) -join ',') -ceq ($expectedDriverSymbols -join ',')
) 'CALYX_FORGE_GPU_FSV_DRIVER_DISPATCH_INVALID' `
    'persisted CUDA driver dispatch did not prove four exact ABI-3020 entries with nonzero addresses'

$allocationBytes = [uint64]$report.allocation_bytes
Assert-Astro (
    [uint64]$initial.stats.reserved_bytes -eq 0 -and
    [uint64]$happy.before.stats.reserved_bytes -eq $allocationBytes -and
    [uint64]$happy.after.stats.reserved_bytes -eq 0 -and
    @($happy.after.allocations).Count -eq 0 -and
    [uint64]$happy.action.pointer -eq [uint64]$happy.before.allocations[0].identity.ptr -and
    [int]$happy.action.physical_absence.Absent.driver_status -eq 500 -and
    $happy.action.physical_absence.Absent.driver_status_name -ceq 'CUDA_ERROR_NOT_FOUND' -and
    $happy.before.physical_allocations[0].state.Present.size_bytes -eq $allocationBytes -and
    $happy.after.device.free_bytes -ge $happy.before.device.free_bytes
) 'CALYX_FORGE_GPU_FSV_HAPPY_PATH_INVALID' `
    'happy allocation/free did not agree across pointer, documented absence status, physical VRAM, registry, and accounting'

$failedPointer = [uint64]$failed.before.allocations[0].identity.ptr
$attemptedPointer = [uint64]($failedPointer + [uint64]1)
$failureDetail = [string]$failed.action.detail
Assert-Astro (
    $failed.action.code -ceq 'CALYX_FORGE_GPU_DEALLOCATION_QUARANTINED' -and
    $failureDetail.Contains("tracked_ptr=$failedPointer attempted_ptr=$attemptedPointer") -and
    $failureDetail.Contains('driver_code=CALYX_FORGE_GPU_DEALLOCATION_FAILED') -and
    $failureDetail.Contains('CUDA_ERROR_INVALID_VALUE') -and
    $failureDetail.Contains('numeric=1') -and
    [uint64]$failed.after.allocations[0].identity.ptr -eq $failedPointer -and
    $failed.after.allocations[0].state -ceq 'quarantined' -and
    $failed.after.allocations[0].failure_code -ceq 'CALYX_FSV_INDUCED_CUDA_FREE_FAILURE' -and
    [uint64]$failed.after.stats.quarantined_bytes -eq $allocationBytes -and
    [uint64]$failed.after.stats.reserved_bytes -eq $allocationBytes -and
    [bool]$failed.after.stats.accounting_equation_valid -and
    [uint64]$failed.after.physical_allocations[0].state.Present.size_bytes -eq $allocationBytes
) 'CALYX_FORGE_GPU_FSV_QUARANTINE_INVALID' `
    'real non-base cuMemFree rejection did not preserve exact attempted/tracked pointers, driver status, bytes, and physical allocation'

Assert-RefusalState $admission 'CALYX_FORGE_GPU_DEALLOCATION_QUARANTINED' 'unsafe admission'
Assert-RefusalState $wrongGeneration 'CALYX_FORGE_GPU_ALLOCATION_IDENTITY_MISMATCH' 'wrong generation'
Assert-RefusalState $wrongPointer 'CALYX_FORGE_GPU_ALLOCATION_IDENTITY_MISMATCH' 'wrong pointer token'
Assert-RefusalState $wrongDevice 'CALYX_FORGE_GPU_ALLOCATION_IDENTITY_MISMATCH' 'wrong device UUID'
Assert-RefusalState $unavailableDevice 'CALYX_FSV_INDUCED_DEVICE_UNAVAILABLE' 'unavailable real device context'

Assert-Astro (
    [uint64]$recovery.before.allocations[0].identity.ptr -eq $failedPointer -and
    @($recovery.after.allocations).Count -eq 0 -and
    [uint64]$recovery.after.stats.reserved_bytes -eq 0 -and
    [uint64]$recovery.after.stats.quarantined_bytes -eq 0 -and
    [bool]$recovery.after.stats.accounting_equation_valid -and
    [uint64]$recovery.action.release_receipt.identity.ptr -eq $failedPointer -and
    [int]$recovery.action.physical_absence.Absent.driver_status -eq 500 -and
    $recovery.action.physical_absence.Absent.driver_status_name -ceq 'CUDA_ERROR_NOT_FOUND' -and
    $recovery.after.device.free_bytes -ge $recovery.before.device.free_bytes
) 'CALYX_FORGE_GPU_FSV_RECOVERY_INVALID' `
    'exact recovery did not prove documented pointer absence and release the retained accounting record'

$journalPath = Join-Path $payload 'allocation-journal.ndjson'
$journalLines = [IO.File]::ReadAllLines($journalPath, [Text.Encoding]::UTF8)
$previous = '0' * 64
$expectedTransitions = @('registered', 'evicted', 'registered', 'quarantined', 'recovered')
$journalEntries = @()
for ($index = 0; $index -lt $journalLines.Count; $index++) {
    Assert-Astro (-not [string]::IsNullOrWhiteSpace($journalLines[$index])) `
        'CALYX_FORGE_GPU_FSV_JOURNAL_EMPTY_ROW' "journal row $index is empty"
    $entry = $journalLines[$index] | ConvertFrom-Json
    Assert-Astro (
        $entry.schema -ceq 'calyx.forge.gpu-allocation-journal.v1' -and
        [uint64]$entry.seq -eq [uint64]$index -and
        $entry.previous_sha256 -ceq $previous -and
        $entry.event.transition -ceq $expectedTransitions[$index]
    ) 'CALYX_FORGE_GPU_FSV_JOURNAL_CHAIN_INVALID' `
        "journal identity/transition mismatch at row $index"
    $canonical = ConvertTo-Json -InputObject @(
        $entry.schema, [uint64]$entry.seq, $entry.previous_sha256, $entry.event
    ) -Compress -Depth 20
    $computed = Get-Sha256Text $canonical
    Assert-Astro ($computed -ceq $entry.entry_sha256) `
        'CALYX_FORGE_GPU_FSV_JOURNAL_DIGEST_INVALID' `
        "journal digest mismatch at row $index expected=$computed observed=$($entry.entry_sha256)"
    $previous = $entry.entry_sha256
    $journalEntries += $entry
}
Assert-Astro (
    $journalLines.Count -eq 5 -and
    $previous -ceq $report.journal_readback.head_sha256 -and
    [uint64]$report.journal_readback.entries -eq 5 -and
    $journalEntries[3].event.failure_code -ceq 'CALYX_FSV_INDUCED_CUDA_FREE_FAILURE' -and
    [uint64]$journalEntries[3].event.device_ptr -eq $failedPointer
) 'CALYX_FORGE_GPU_FSV_JOURNAL_READBACK_INVALID' `
    'journal terminal head, failure identity, or report readback disagrees'

$nvidiaCsvPath = Join-Path $payload 'nvidia-smi-gpu.csv'
$nvidiaCsv = [IO.File]::ReadAllText($nvidiaCsvPath, [Text.Encoding]::UTF8)
$deviceUuid = [string]$journalEntries[2].event.device_uuid
Assert-Astro (
    -not [string]::IsNullOrWhiteSpace($deviceUuid) -and
    $nvidiaCsv.IndexOf($deviceUuid, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
    $report.nvidia_smi.sha256 -ceq (Get-Sha256File $nvidiaCsvPath)
) 'CALYX_FORGE_GPU_FSV_NVML_READBACK_INVALID' `
    'nvidia-smi physical device UUID/hash disagrees with the allocation journal'

$analysis = [ordered]@{
    schema = 'calyx.forge.gpu-allocation-ownership-analysis.v1'
    issue = 872
    tree_sha = $TreeSha
    artifact_sha256 = $sourceHash
    report_sha256 = $reportHash
    device_uuid = $deviceUuid
    allocation_bytes = $allocationBytes
    quarantined_pointer = $failedPointer
    rejected_non_base_pointer = $attemptedPointer
    journal_entries = $journalLines.Count
    journal_head_sha256 = $previous
    happy_path = 'verified'
    failed_free_quarantine = 'verified'
    refusal_edges = @('admission', 'wrong_generation', 'wrong_pointer', 'wrong_device', 'unavailable_device')
    recovery = 'verified'
    cuda_driver_version = [int]$driverDispatch.driver_version
    cuda_memory_abi_version = [int]$driverDispatch.requested_abi_version
    cuda_memory_symbols = $expectedDriverSymbols
    physical_source = 'cuGetProcAddress_v2 exact ABI 3020 dispatch + cuMemGetAddressRange + cuMemGetInfo + nvidia-smi'
    run_record = $runRecordPath
    payload = $payload
}
$analysisPath = Join-Path $session 'analysis.json'
$analysisJson = $analysis | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText($analysisPath, $analysisJson + "`r`n", [Text.UTF8Encoding]::new($false))
$analysisReadback = Read-Json $analysisPath
Assert-Astro (
    $analysisReadback.schema -ceq $analysis.schema -and
    $analysisReadback.report_sha256 -ceq $reportHash -and
    $analysisReadback.journal_head_sha256 -ceq $previous
) 'CALYX_FORGE_GPU_FSV_ANALYSIS_READBACK_INVALID' `
    'analysis file did not read back with the verified identities'

Write-Output ($analysis | ConvertTo-Json -Compress -Depth 10)
