<#
.SYNOPSIS
    Stages, runs, and independently reads back the real Forge CUDA-kernel artifact.

.DESCRIPTION
    This is a manual Full State Verification driver, not a test or gate. It must run as
    one synchronous descendant of the exact live native Windows launcher owner after
    Cargo has built cuda_kernel_policy_fsv.exe. The script promotes that executable
    through native-fsv-artifact.ps1, launches it only through native-fsv-run.ps1, reads
    the persisted artifact/run/report/output state independently, and inspects every
    CUBIN with the pinned CUDA cuobjdump and nvdisasm binaries while the same launcher
    lease remains live.

    A completed session is intentionally retained for the caller to inspect and later
    remove through the Cleanup lifecycle after every recorded owner generation is dead.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Measurement', 'Production')]
    [string]$Mode,

    [Parameter(Mandatory)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$Issue,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$TreeSha,

    [Parameter(Mandatory)]
    [string]$SourcePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$')]
    [string]$SessionId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$ExpectedDeviceName = 'NVIDIA GeForce RTX 5090'
$ExpectedDeviceUuid = 'GPU-de2d5475-3447-83c3-1539-876a7257ae8a'
$ExpectedDevicePciBusId = '00000000:01:00.0'
$ExpectedDriverVersion = '610.47'
$ExpectedDeviceMemoryMib = 32607
$ExpectedComputeCapability = '12.0'
$ExpectedToolkitVersion = '13.3.0'
$ExpectedToolkitManifestSha256 =
    '7a600527fedf8205de85a506d7bcc01c3d85a6a8db45f030523797eeb2a356cb'
$ExpectedCuobjdumpSha256 =
    'b6f56c1eb5edd046949f9c947e730a1bf0ed5beff6fc20f8ccafd8a1f5d2eff1'
$ExpectedNvdisasmSha256 =
    '02a69a49da9803afebebb93e045aa99f8243c7eca54faf2a59959be2d12915b0'

. (Join-Path $PSScriptRoot 'launcher-lock.ps1')

function Assert-Astro {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message
    )
    if (-not $Condition) {
        throw "${Code}: ${Message}"
    }
}

function Get-AstroSha256 {
    param([Parameter(Mandatory)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function ConvertTo-AstroStrictDisplayWindowsFilePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    $containsControl = $false
    foreach ($character in $Path.ToCharArray()) {
        if ([char]::IsControl($character)) {
            $containsControl = $true
            break
        }
    }
    Assert-Astro (
        -not [string]::IsNullOrWhiteSpace($Path) -and
        -not $Path.Contains('/') -and
        -not $containsControl
    ) 'CALYX_FORGE_CUDA_FSV_WINDOWS_PATH_INVALID' `
        "$Description is empty or contains a forbidden separator/control byte: '$Path'"

    if ($Path.StartsWith(
            '\\?\UNC\',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        $display = '\\' + $Path.Substring(8)
    }
    elseif ($Path.StartsWith(
            '\\?\',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        $display = $Path.Substring(4)
    }
    else {
        $display = $Path
    }
    Assert-Astro (
        -not $display.StartsWith(
            '\\.\',
            [StringComparison]::OrdinalIgnoreCase
        ) -and
        -not $display.StartsWith(
            '\\?\',
            [StringComparison]::OrdinalIgnoreCase
        ) -and
        -not $display.EndsWith(
            '\',
            [StringComparison]::Ordinal
        )
    ) 'CALYX_FORGE_CUDA_FSV_WINDOWS_NAMESPACE_INVALID' `
        "$Description uses an unsupported device namespace or trailing separator: '$Path'"

    $driveAbsolute = $display -match '^[A-Za-z]:\\.+$'
    $uncAbsolute = $display -match '^\\\\[^\\]+\\[^\\]+\\.+$'
    Assert-Astro ($driveAbsolute -or $uncAbsolute) `
        'CALYX_FORGE_CUDA_FSV_WINDOWS_PATH_NOT_ABSOLUTE' `
        "$Description is not an absolute DOS-or-UNC file path: '$Path'"
    $tail = if ($driveAbsolute) {
        $display.Substring(3)
    }
    else {
        $display.Substring(2)
    }
    $components = $tail.Split([char]'\')
    Assert-Astro (
        $components.Count -gt 0 -and
        @($components | Where-Object {
                [string]::IsNullOrEmpty($_) -or
                $_ -ceq '.' -or
                $_ -ceq '..'
            }).Count -eq 0
    ) 'CALYX_FORGE_CUDA_FSV_WINDOWS_PATH_COMPONENT_INVALID' `
        "$Description contains an empty/dot path component: '$Path'"
    $full = [IO.Path]::GetFullPath($display)
    Assert-Astro (
        [string]::Equals(
            $full,
            $display,
            [StringComparison]::OrdinalIgnoreCase
        )
    ) 'CALYX_FORGE_CUDA_FSV_WINDOWS_PATH_LEXICAL_DRIFT' `
        "$Description changes under GetFullPath ('$display' -> '$full')"
    return $full
}

function Get-AstroExactWindowsFileBinding {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    $display = ConvertTo-AstroStrictDisplayWindowsFilePath `
        -Path $Path `
        -Description $Description
    $handle = $null
    try {
        $handle =
            [AstroLauncherLockNative]::OpenExactProtectedReadFile($display)
        $finalPath = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($handle)
        )
        $finalPath = [IO.Path]::GetFullPath($finalPath)
        $fileId =
            [AstroLauncherLockNative]::GetFileIdentity($handle)
        $sha256 =
            [AstroLauncherLockNative]::ComputeExactFileSha256($handle)
        Assert-Astro (
            [string]::Equals(
                $display,
                $finalPath,
                [StringComparison]::OrdinalIgnoreCase
            )
        ) 'CALYX_FORGE_CUDA_FSV_WINDOWS_PATH_RESOLUTION_DRIFT' `
            "$Description resolves to '$finalPath', not '$display'"
        $evidence = [pscustomobject][ordered]@{
            raw_path = $Path
            display_path = $display
            final_path = $finalPath
            file_id = $fileId
            sha256 = $sha256
        }
        $retainedHandle = $handle
        $handle = $null
        return [pscustomobject][ordered]@{
            evidence = $evidence
            handle = $retainedHandle
        }
    }
    catch {
        if ($_.Exception.Message.StartsWith(
                'CALYX_FORGE_CUDA_FSV_',
                [StringComparison]::Ordinal
            )) {
            throw
        }
        throw (
            'CALYX_FORGE_CUDA_FSV_WINDOWS_FILE_BINDING_FAILED: ' +
            "$Description '$Path' could not be bound through one retained " +
            "ordinary-file handle ($($_.Exception.GetType().FullName): " +
            "$($_.Exception.Message))"
        )
    }
    finally {
        if ($null -ne $handle) {
            $handle.Dispose()
        }
    }
}

function Read-AstroNvidiaCsv {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Columns
    )

    $full = [IO.Path]::GetFullPath($Path)
    Assert-Astro (Test-Path -LiteralPath $full -PathType Leaf) `
        'CALYX_FORGE_CUDA_FSV_NVIDIA_CSV_MISSING' `
        "NVIDIA CSV source of truth is absent: $full"
    try {
        $encoding = [Text.UTF8Encoding]::new($false, $true)
        $bytes = [IO.File]::ReadAllBytes($full)
        $text = $encoding.GetString($bytes)
        Assert-Astro (-not $text.Contains([char]0)) `
            'CALYX_FORGE_CUDA_FSV_NVIDIA_CSV_INVALID' `
            "NVIDIA CSV contains NUL bytes: $full"
        Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
        $reader = [IO.StringReader]::new($text)
        $parser =
            [Microsoft.VisualBasic.FileIO.TextFieldParser]::new($reader)
        $parser.TextFieldType =
            [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
        $parser.HasFieldsEnclosedInQuotes = $true
        $parser.TrimWhiteSpace = $true
        $parser.SetDelimiters(',')
        $rows = [Collections.Generic.List[object]]::new()
        try {
            while (-not $parser.EndOfData) {
                $lineNumber = [long]$parser.LineNumber
                $fields = $parser.ReadFields()
                Assert-Astro (
                    $null -ne $fields -and
                    $fields.Count -eq $Columns.Count
                ) 'CALYX_FORGE_CUDA_FSV_NVIDIA_CSV_INVALID' `
                    "NVIDIA CSV row $lineNumber has $(@($fields).Count) fields, expected $($Columns.Count): $full"
                $record = [ordered]@{
                    source_line = $lineNumber
                }
                for ($index = 0; $index -lt $Columns.Count; $index++) {
                    $value = [string]$fields[$index]
                    Assert-Astro (
                        -not [string]::IsNullOrWhiteSpace($value) -and
                        $value.IndexOfAny([char[]]@(
                                [char]0, [char]10, [char]13
                            )) -lt 0
                    ) 'CALYX_FORGE_CUDA_FSV_NVIDIA_CSV_INVALID' `
                        "NVIDIA CSV row $lineNumber field '$($Columns[$index])' is empty or contains a forbidden control byte: $full"
                    $record[$Columns[$index]] = $value
                }
                [void]$rows.Add([pscustomobject]$record)
            }
        }
        finally {
            $parser.Dispose()
            $reader.Dispose()
        }
    }
    catch {
        if ($_.Exception.Message.StartsWith(
                'CALYX_FORGE_CUDA_FSV_NVIDIA_',
                [StringComparison]::Ordinal
            )) {
            throw
        }
        throw (
            'CALYX_FORGE_CUDA_FSV_NVIDIA_CSV_INVALID: ' +
            "strict CSV parse failed for '$full' " +
            "($($_.Exception.GetType().FullName): " +
            "$($_.Exception.Message))"
        )
    }
    Assert-Astro ($rows.Count -gt 0) `
        'CALYX_FORGE_CUDA_FSV_NVIDIA_CSV_EMPTY' `
        "NVIDIA CSV contains no physical rows: $full"
    return [pscustomobject]@{
        path = $full
        bytes = [uint64]$bytes.Length
        sha256 = Get-AstroSha256 $full
        rows = [object[]]$rows.ToArray()
    }
}

function Test-AstroCanonicalGpuUuid {
    param([Parameter(Mandatory)][string]$Value)

    return $Value -match (
        '^GPU-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-' +
        '[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
    )
}

function Test-AstroPciBusId {
    param([Parameter(Mandatory)][string]$Value)

    return $Value -match (
        '^(?:[0-9A-Fa-f]{4}|[0-9A-Fa-f]{8}):' +
        '[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7]$'
    )
}

function Write-AstroReadbackText {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Text
    )

    $encoding = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($Path, $Text, $encoding)
    $readback = [IO.File]::ReadAllText($Path, $encoding)
    Assert-Astro ($readback -ceq $Text) `
        'CALYX_FORGE_CUDA_FSV_ANALYSIS_READBACK_MISMATCH' `
        "analysis write/readback mismatch: $Path"
}

function ConvertTo-AstroSingleStringArrayJson {
    param([Parameter(Mandatory)][string]$Value)

    try {
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
        $serializer =
            [System.Web.Script.Serialization.JavaScriptSerializer]::new()
        $json = $serializer.Serialize([object[]]@($Value))
        $readback = $serializer.DeserializeObject($json)
    }
    catch {
        throw (
            'CALYX_FORGE_CUDA_FSV_ARGUMENT_JSON_SERIALIZER_FAILED: ' +
            "the required Windows JSON serializer could not encode and read back " +
            "the runner argument array ($($_.Exception.GetType().FullName): " +
            "$($_.Exception.Message))"
        )
    }
    Assert-Astro (
        $readback -is [object[]] -and
        $readback.Count -eq 1 -and
        $readback[0] -is [string] -and
        [string]$readback[0] -ceq $Value
    ) 'CALYX_FORGE_CUDA_FSV_ARGUMENT_JSON_INVALID' `
        "one-element runner argument JSON did not round-trip: $json"
    return $json
}

$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$source = [IO.Path]::GetFullPath($SourcePath)
$gitExe = 'C:\Program Files\Git\bin\git.exe'
$head = (& $gitExe -C $workspace rev-parse HEAD).Trim()
Assert-Astro ($LASTEXITCODE -eq 0 -and $head -ceq $TreeSha) `
    'CALYX_FORGE_CUDA_FSV_TREE_MISMATCH' `
    "expected frozen tree $TreeSha, observed $head"
Assert-Astro (Test-Path -LiteralPath $source -PathType Leaf) `
    'CALYX_FORGE_CUDA_FSV_ARTIFACT_MISSING' `
    "built FSV executable is absent: $source"

$sourceHash = Get-AstroSha256 $source
$session = Join-Path (
    Join-Path (
        Join-Path (
            Join-Path $workspace '.tmp\native-fsv-artifacts'
        ) $TreeSha
    ) $sourceHash
) $SessionId
$receiptPath = Join-Path $session 'receipt.json'

& powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $PSScriptRoot 'native-fsv-artifact.ps1') `
    -Operation Stage `
    -SourcePath $source `
    -Issue $Issue `
    -TreeSha $TreeSha `
    -SessionId $SessionId
Assert-Astro ($LASTEXITCODE -eq 0) `
    'CALYX_FORGE_CUDA_FSV_STAGE_FAILED' `
    "native artifact Stage exited $LASTEXITCODE"
Assert-Astro (Test-Path -LiteralPath $receiptPath -PathType Leaf) `
    'CALYX_FORGE_CUDA_FSV_RECEIPT_MISSING' `
    "Stage receipt is absent: $receiptPath"

$payload = Join-Path $session 'payload'
$stdoutPath = Join-Path $session 'stdout.txt'
$stderrPath = Join-Path $session 'stderr.txt'
$runRecordPath = Join-Path $session 'run.json'
$liveStatePath = Join-Path $session 'live.json'
$argumentsJson = ConvertTo-AstroSingleStringArrayJson $payload

& (Join-Path $PSScriptRoot 'native-fsv-run.ps1') `
    -ReceiptPath $receiptPath `
    -ArgumentsJson $argumentsJson `
    -StandardOutputPath $stdoutPath `
    -StandardErrorPath $stderrPath `
    -RunRecordPath $runRecordPath `
    -LiveStatePath $liveStatePath `
    -Issue $Issue
$runnerSucceeded = $?
Assert-Astro $runnerSucceeded `
    'CALYX_FORGE_CUDA_FSV_RUNNER_FAILED' `
    'native FSV runner did not complete normally'

& powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $PSScriptRoot 'native-fsv-artifact.ps1') `
    -Operation Inspect `
    -ReceiptPath $receiptPath
Assert-Astro ($LASTEXITCODE -eq 0) `
    'CALYX_FORGE_CUDA_FSV_INSPECT_FAILED' `
    "native artifact Inspect exited $LASTEXITCODE"

$runRecordBytes = [IO.File]::ReadAllBytes($runRecordPath)
$runRecord = [Text.Encoding]::UTF8.GetString($runRecordBytes) | ConvertFrom-Json
Assert-Astro (
    $runRecord.schema -ceq 'astrolabe.native-fsv-run.v2' -and
    $runRecord.verdict -ceq 'verified' -and
    [int]$runRecord.process.exit_code -eq 0 -and
    [bool]$runRecord.artifact.stable -and
    [bool]$runRecord.repository.stable -and
    [bool]$runRecord.launcher_lease.stable
) 'CALYX_FORGE_CUDA_FSV_RUN_RECORD_INVALID' `
    'persisted native FSV run record is not verified and stable'

$reportPath = Join-Path $payload 'report.json'
$reportBytes = [IO.File]::ReadAllBytes($reportPath)
$reportHash = Get-AstroSha256 $reportPath
$report = [Text.Encoding]::UTF8.GetString($reportBytes) | ConvertFrom-Json
$hashRecord = (
    Get-Content -LiteralPath (Join-Path $payload 'report.sha256') -Raw
).Trim()
Assert-Astro (
    $report.schema -ceq 'calyx.forge.cuda-kernel-fsv.v1' -and
    [int]$report.issue -eq $Issue -and
    $hashRecord -ceq "$reportHash  report.json"
) 'CALYX_FORGE_CUDA_FSV_REPORT_INVALID' `
    'persisted report/hash record failed independent readback'
Assert-Astro (
    [int]$report.execution.runtime_ordinal -eq 0 -and
    [int]$report.execution.driver_ordinal -eq 0 -and
    $report.execution.device_name -ceq $ExpectedDeviceName -and
    [int]$report.execution.compute_capability[0] -eq 12 -and
    [int]$report.execution.compute_capability[1] -eq 0 -and
    [bool]$report.execution.post_run_physical_attestation
) 'CALYX_FORGE_CUDA_FSV_DEVICE_INVALID' `
    'persisted execution identity differs from the selected RTX 5090/sm_120 device'
Assert-Astro (
    $report.build.toolkit_version -ceq $ExpectedToolkitVersion -and
    $report.build.toolkit_version_manifest_sha256 -ceq
        $ExpectedToolkitManifestSha256 -and
    $report.build.target -ceq 'sm_120a' -and
    $report.build.module_kind -ceq 'cubin' -and
    @($report.build.toolkit_components).Count -eq 4
) 'CALYX_FORGE_CUDA_FSV_BUILD_ATTESTATION_INVALID' `
    'persisted build attestation differs from the exact CUDA 13.3/sm_120a contract'

$loadedModules = @($report.loaded_modules)
Assert-Astro ($loadedModules.Count -eq 3) `
    'CALYX_FORGE_CUDA_FSV_MODULE_COUNT_INVALID' `
    "expected three physically loaded production modules, observed $($loadedModules.Count)"
foreach ($module in $loadedModules) {
    Assert-Astro (
        $module.module_kind -ceq 'cubin' -and
        $module.target -ceq 'sm_120a' -and
        [int]$module.runtime_ordinal -eq 0 -and
        [int]$module.driver_ordinal -eq 0 -and
        [int]$module.compute_capability[0] -eq 12 -and
        [int]$module.compute_capability[1] -eq 0 -and
        [uint64]$module.module_bytes -gt 0 -and
        [uint64]$module.module_load_elapsed_ns -gt 0
    ) 'CALYX_FORGE_CUDA_FSV_MODULE_RECEIPT_INVALID' `
        "loaded module receipt is incomplete or mismatched: $($module.module_name)"
}

$policy = Get-Content -LiteralPath (
    Join-Path $payload 'cuda-kernel-policy-v1.json'
) -Raw | ConvertFrom-Json
$expectedPolicyStatus = if ($Mode -ceq 'Measurement') {
    'measurement-pending'
} else {
    'measured'
}
Assert-Astro ($policy.status -ceq $expectedPolicyStatus) `
    'CALYX_FORGE_CUDA_FSV_POLICY_STATUS_INVALID' `
    "expected policy status $expectedPolicyStatus, observed $($policy.status)"

if ($Mode -ceq 'Measurement') {
    $measurements = @($report.measurement.artifacts)
    Assert-Astro (
        [bool]$report.measurement.enabled -and
        [int]$report.measurement.rounds -eq 5 -and
        [int]$report.measurement.warm_runs -eq 100 -and
        $report.measurement.ordering -ceq
            'round-robin-rotated-and-reversed-v1' -and
        $measurements.Count -eq 12
    ) 'CALYX_FORGE_CUDA_FSV_MEASUREMENT_MATRIX_INVALID' `
        'persisted measurement matrix does not contain the exact 12 x five-round protocol'
    foreach ($measurement in $measurements) {
        Assert-Astro (
            [bool]$measurement.correctness_verified -and
            [uint64]$measurement.artifact_bytes -gt 0 -and
            [uint64]$measurement.output_bytes -gt 0 -and
            @($measurement.module_load_ns).Count -eq 5 -and
            @($measurement.function_load_ns).Count -eq 5 -and
            @($measurement.first_dispatch_ns).Count -eq 5 -and
            @($measurement.warm_total_ns).Count -eq 5 -and
            @($measurement.sample_order).Count -eq 5
        ) 'CALYX_FORGE_CUDA_FSV_MEASUREMENT_RESULT_INVALID' `
            "invalid physical result for $($measurement.module_name)/$($measurement.module_kind)/$($measurement.fmad)"
    }
} else {
    Assert-Astro (
        -not [bool]$report.measurement.enabled -and
        -not (Test-Path -LiteralPath (Join-Path $payload 'measurement-artifacts'))
    ) 'CALYX_FORGE_CUDA_FSV_UNUSED_ARTIFACT_PRESENT' `
        'production verification emitted measurement/PTX artifacts'
}

foreach ($edgeName in @(
        'empty', 'malformed_shape', 'nonfinite_input', 'invalid_selector'
    )) {
    Assert-Astro ([bool]$report.edges.$edgeName.persisted_state_unchanged) `
        'CALYX_FORGE_CUDA_FSV_EDGE_MUTATED_STATE' `
        "edge $edgeName mutated persisted state"
}

$gpuIdentityPath = Join-Path $payload 'nvidia-smi-gpu.csv'
$gpuProcessesPath = Join-Path $payload 'nvidia-smi-compute-apps.csv'
$gpuIdentity = Read-AstroNvidiaCsv `
    -Path $gpuIdentityPath `
    -Columns @(
        'index',
        'name',
        'uuid',
        'pci_bus_id',
        'driver_version',
        'memory_total_mib',
        'compute_capability'
    )
$gpuIdentityMatches = [Collections.Generic.List[object]]::new()
foreach ($row in @($gpuIdentity.rows)) {
    [uint32]$ordinal = 0
    [uint64]$memoryMib = 0
    Assert-Astro (
        [uint32]::TryParse(
            [string]$row.index,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$ordinal
        ) -and
        (Test-AstroCanonicalGpuUuid ([string]$row.uuid)) -and
        (Test-AstroPciBusId ([string]$row.pci_bus_id)) -and
        [string]$row.driver_version -match
            '^[0-9]+\.[0-9]+(?:\.[0-9]+)?$' -and
        [uint64]::TryParse(
            [string]$row.memory_total_mib,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$memoryMib
        ) -and
        $memoryMib -gt 0 -and
        [string]$row.compute_capability -match '^[0-9]+\.[0-9]+$'
    ) 'CALYX_FORGE_CUDA_FSV_NVIDIA_GPU_ROW_INVALID' `
        "NVIDIA GPU row $($row.source_line) has an invalid physical schema"
    if (
        $ordinal -eq [uint32]$report.execution.driver_ordinal -and
        [string]::Equals(
            [string]$row.name,
            $ExpectedDeviceName,
            [StringComparison]::Ordinal
        ) -and
        [string]::Equals(
            [string]$row.uuid,
            $ExpectedDeviceUuid,
            [StringComparison]::OrdinalIgnoreCase
        ) -and
        [string]::Equals(
            [string]$row.pci_bus_id,
            $ExpectedDevicePciBusId,
            [StringComparison]::OrdinalIgnoreCase
        ) -and
        [string]$row.driver_version -ceq $ExpectedDriverVersion -and
        $memoryMib -eq [uint64]$ExpectedDeviceMemoryMib -and
        [string]$row.compute_capability -ceq
            $ExpectedComputeCapability
    ) {
        [void]$gpuIdentityMatches.Add($row)
    }
}
Assert-Astro ($gpuIdentityMatches.Count -eq 1) `
    'CALYX_FORGE_CUDA_FSV_NVIDIA_GPU_MATCH_INVALID' `
    "expected exactly one selected physical GPU row, observed $($gpuIdentityMatches.Count)"

$gpuProcesses = Read-AstroNvidiaCsv `
    -Path $gpuProcessesPath `
    -Columns @('pid', 'process_name', 'gpu_uuid', 'used_gpu_memory')
$expectedPid = [uint32]$runRecord.process.identity.pid
$expectedArtifactPath =
    [IO.Path]::GetFullPath([string]$runRecord.artifact.path)
$expectedArtifactBinding = Get-AstroExactWindowsFileBinding `
    -Path $expectedArtifactPath `
    -Description 'run-record artifact'
Assert-Astro (
    $expectedArtifactBinding.evidence.sha256 -ceq
        [string]$runRecord.artifact.sha256
) 'CALYX_FORGE_CUDA_FSV_ARTIFACT_BINDING_INVALID' `
    'run-record artifact handle/hash binding differs from the run record'
$gpuProcessMatches = [Collections.Generic.List[object]]::new()
foreach ($row in @($gpuProcesses.rows)) {
    [uint32]$observedPid = 0
    Assert-Astro (
        [uint32]::TryParse(
            [string]$row.pid,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$observedPid
        ) -and
        $observedPid -gt 0 -and
        (Test-AstroCanonicalGpuUuid ([string]$row.gpu_uuid)) -and
        [string]$row.used_gpu_memory -match
            '^(?:\[N/A\]|[0-9]+ MiB)$'
    ) 'CALYX_FORGE_CUDA_FSV_NVIDIA_PROCESS_ROW_INVALID' `
        "NVIDIA process row $($row.source_line) has an invalid physical schema"
    if (
        $observedPid -eq $expectedPid -and
        [string]::Equals(
            [string]$row.gpu_uuid,
            $ExpectedDeviceUuid,
            [StringComparison]::OrdinalIgnoreCase
        )
    ) {
        try {
            $observedArtifactBinding = Get-AstroExactWindowsFileBinding `
                -Path ([string]$row.process_name) `
                -Description (
                    "matching NVIDIA process row $($row.source_line) executable"
                )
        }
        catch {
            throw (
                'CALYX_FORGE_CUDA_FSV_NVIDIA_PROCESS_PATH_INVALID: ' +
                "matching PID/UUID row $($row.source_line) contains an " +
                "invalid executable path '$($row.process_name)': " +
                $_.Exception.Message
            )
        }
        if (
            [string]$observedArtifactBinding.evidence.file_id -ceq
                [string]$expectedArtifactBinding.evidence.file_id -and
            [string]$observedArtifactBinding.evidence.sha256 -ceq
                [string]$expectedArtifactBinding.evidence.sha256 -and
            [string]::Equals(
                [string]$observedArtifactBinding.evidence.final_path,
                [string]$expectedArtifactBinding.evidence.final_path,
                [StringComparison]::OrdinalIgnoreCase
            )
        ) {
            [void]$gpuProcessMatches.Add([pscustomobject][ordered]@{
                    row = $row
                    binding = $observedArtifactBinding.evidence
                    handle = $observedArtifactBinding.handle
                })
        }
        else {
            $observedArtifactBinding.handle.Dispose()
        }
    }
}
Assert-Astro ($gpuProcessMatches.Count -eq 1) `
    'CALYX_FORGE_CUDA_FSV_NVIDIA_PROCESS_MATCH_INVALID' `
    "expected exactly one PID/path/UUID-bound GPU process row, observed $($gpuProcessMatches.Count)"
$selectedProcess = $gpuProcessMatches[0]
$producerBindingPath =
    Join-Path $payload 'nvidia-smi-process-binding.json'
$producerBinding =
    Get-Content -LiteralPath $producerBindingPath -Raw |
        ConvertFrom-Json
$producerExpectedDisplay = ConvertTo-AstroStrictDisplayWindowsFilePath `
    -Path ([string]$producerBinding.expected.canonical_path) `
    -Description 'producer expected canonical executable'
$producerObservedDisplay = ConvertTo-AstroStrictDisplayWindowsFilePath `
    -Path ([string]$producerBinding.observed.canonical_path) `
    -Description 'producer observed canonical executable'
Assert-Astro (
    $producerBinding.schema -ceq
        'calyx.forge.cuda-kernel-process-binding.v1' -and
    [uint32]$producerBinding.pid -eq $expectedPid -and
    [string]$producerBinding.gpu_uuid -ceq $ExpectedDeviceUuid -and
    [uint64]$producerBinding.source_line -eq
        [uint64]$selectedProcess.row.source_line -and
    [string]$producerBinding.observed.raw_path -ceq
        [string]$selectedProcess.row.process_name -and
    [bool]$producerBinding.canonical_paths_equal -and
    [uint64]$producerBinding.artifact.bytes -eq
        [uint64]$runRecord.artifact.bytes -and
    [string]$producerBinding.artifact.sha256 -ceq
        [string]$runRecord.artifact.sha256 -and
    [string]::Equals(
        $producerExpectedDisplay,
        [string]$expectedArtifactBinding.evidence.final_path,
        [StringComparison]::OrdinalIgnoreCase
    ) -and
    [string]::Equals(
        $producerObservedDisplay,
        [string]$selectedProcess.binding.final_path,
        [StringComparison]::OrdinalIgnoreCase
    )
) 'CALYX_FORGE_CUDA_FSV_PRODUCER_PROCESS_BINDING_INVALID' `
    'producer raw/canonical executable binding differs from independent handle/FILE_ID/hash readback'
$gpuReadback = [ordered]@{
    schema = 'calyx.forge.cuda-kernel-nvidia-readback.v2'
    selected_gpu = $gpuIdentityMatches[0]
    selected_process = $selectedProcess.row
    path_binding = [ordered]@{
        expected = $expectedArtifactBinding.evidence
        observed = $selectedProcess.binding
        same_final_path = $true
        same_file_id = $true
        same_sha256 = $true
    }
    producer_binding = $producerBinding
    gpu_source = [ordered]@{
        path = $gpuIdentity.path
        bytes = $gpuIdentity.bytes
        sha256 = $gpuIdentity.sha256
        row_count = @($gpuIdentity.rows).Count
    }
    process_source = [ordered]@{
        path = $gpuProcesses.path
        bytes = $gpuProcesses.bytes
        sha256 = $gpuProcesses.sha256
        row_count = @($gpuProcesses.rows).Count
    }
    expected = [ordered]@{
        pid = $expectedPid
        artifact_path = $expectedArtifactPath
        gpu_uuid = $ExpectedDeviceUuid
    }
}

$inventoryPath = Join-Path $payload 'evidence-inventory.json'
$measurementPath = Join-Path $payload 'measurement.json'
$inventoryHash = Get-AstroSha256 $inventoryPath
$measurementHash = if (Test-Path -LiteralPath $measurementPath -PathType Leaf) {
    Get-AstroSha256 $measurementPath
} else {
    $null
}

$analysisDirectory = Join-Path $payload 'binary-analysis'
[IO.Directory]::CreateDirectory($analysisDirectory) | Out-Null
$gpuReadbackPath = Join-Path $analysisDirectory 'nvidia-readback.json'
$gpuReadbackJson = $gpuReadback | ConvertTo-Json -Depth 8
try {
    Write-AstroReadbackText $gpuReadbackPath $gpuReadbackJson
}
finally {
    $selectedProcess.handle.Dispose()
    $expectedArtifactBinding.handle.Dispose()
}
$cuobjdump = Join-Path $env:CUDA_PATH 'bin\cuobjdump.exe'
$nvdisasm = Join-Path $env:CUDA_PATH 'bin\nvdisasm.exe'
Assert-Astro (
    (Test-Path -LiteralPath $cuobjdump -PathType Leaf) -and
    (Get-AstroSha256 $cuobjdump) -ceq $ExpectedCuobjdumpSha256 -and
    (Test-Path -LiteralPath $nvdisasm -PathType Leaf) -and
    (Get-AstroSha256 $nvdisasm) -ceq $ExpectedNvdisasmSha256
) 'CALYX_FORGE_CUDA_FSV_BINARY_TOOL_INVALID' `
    'CUDA binary-analysis tools are absent or differ from pinned CUDA 13.3 bytes'

$cubins = @(
    Get-ChildItem -LiteralPath (
        Join-Path $payload 'production-modules'
    ) -Filter '*.cubin' -File
)
if ($Mode -ceq 'Measurement') {
    $cubins += @(
        Get-ChildItem -LiteralPath (
            Join-Path $payload 'measurement-artifacts'
        ) -Filter '*.cubin' -File
    )
}
$expectedCubinCount = if ($Mode -ceq 'Measurement') { 9 } else { 3 }
Assert-Astro ($cubins.Count -eq $expectedCubinCount) `
    'CALYX_FORGE_CUDA_FSV_CUBIN_COUNT_INVALID' `
    "expected $expectedCubinCount CUBIN files, observed $($cubins.Count)"

$binaryAnalysis = [Collections.Generic.List[object]]::new()
foreach ($cubin in $cubins) {
    $label = $cubin.Name
    if ($cubin.Directory.Name -ceq 'production-modules') {
        $label = "production.$label"
    }
    $elfLines = @(& $cuobjdump --dump-elf $cubin.FullName 2>&1)
    Assert-Astro ($LASTEXITCODE -eq 0 -and $elfLines.Count -gt 0) `
        'CALYX_FORGE_CUDA_FSV_CUOBJDUMP_ELF_FAILED' `
        "cuobjdump ELF inspection failed for $($cubin.FullName)"
    $sassLines = @(& $cuobjdump --dump-sass $cubin.FullName 2>&1)
    Assert-Astro ($LASTEXITCODE -eq 0 -and $sassLines.Count -gt 0) `
        'CALYX_FORGE_CUDA_FSV_CUOBJDUMP_SASS_FAILED' `
        "cuobjdump SASS inspection failed for $($cubin.FullName)"
    $disassemblyLines = @(& $nvdisasm $cubin.FullName 2>&1)
    Assert-Astro ($LASTEXITCODE -eq 0 -and $disassemblyLines.Count -gt 0) `
        'CALYX_FORGE_CUDA_FSV_NVDISASM_FAILED' `
        "nvdisasm inspection failed for $($cubin.FullName)"

    $elfText = ($elfLines -join "`r`n") + "`r`n"
    $sassText = ($sassLines -join "`r`n") + "`r`n"
    $disassemblyText = ($disassemblyLines -join "`r`n") + "`r`n"
    Assert-Astro (
        $elfText -match '(?i)(sm_120|SM120)' -and
        $disassemblyText -match '(?i)(sm_120|SM120)'
    ) 'CALYX_FORGE_CUDA_FSV_CUBIN_ARCH_INVALID' `
        "binary tools did not report sm_120 for $($cubin.FullName)"

    $elfPath = Join-Path $analysisDirectory "$label.elf.txt"
    $sassPath = Join-Path $analysisDirectory "$label.sass.txt"
    $disassemblyPath = Join-Path $analysisDirectory "$label.nvdisasm.txt"
    Write-AstroReadbackText $elfPath $elfText
    Write-AstroReadbackText $sassPath $sassText
    Write-AstroReadbackText $disassemblyPath $disassemblyText
    [void]$binaryAnalysis.Add([ordered]@{
            file = $cubin.FullName
            bytes = [uint64]$cubin.Length
            sha256 = Get-AstroSha256 $cubin.FullName
            elf_sha256 = Get-AstroSha256 $elfPath
            sass_sha256 = Get-AstroSha256 $sassPath
            nvdisasm_sha256 = Get-AstroSha256 $disassemblyPath
            ffma_instruction_count = [regex]::Matches(
                $sassText, '\bFFMA\b'
            ).Count
        })
}

$binaryAnalysisSummaryPath = Join-Path (
    $analysisDirectory
) 'summary.json'
$binaryAnalysisSummary = [ordered]@{
    schema = 'calyx.forge.cuda-kernel-binary-analysis.v1'
    cuobjdump_sha256 = Get-AstroSha256 $cuobjdump
    nvdisasm_sha256 = Get-AstroSha256 $nvdisasm
    cubins = @($binaryAnalysis.ToArray())
}
$binaryAnalysisJson = $binaryAnalysisSummary |
    ConvertTo-Json -Depth 10
Write-AstroReadbackText $binaryAnalysisSummaryPath $binaryAnalysisJson

[ordered]@{
    event = 'forge_cuda_kernel_fsv_orchestrator_readback'
    mode = $Mode.ToLowerInvariant()
    tree_sha = $TreeSha
    source_sha256 = $sourceHash
    session = $session
    receipt_path = $receiptPath
    receipt_sha256 = Get-AstroSha256 $receiptPath
    run_record_sha256 = Get-AstroSha256 $runRecordPath
    report_sha256 = $reportHash
    report_bytes = [uint64]$reportBytes.Length
    evidence_inventory_sha256 = $inventoryHash
    measurement_json_sha256 = $measurementHash
    measurement_results = if ($Mode -ceq 'Measurement') {
        @($report.measurement.artifacts).Count
    } else {
        0
    }
    measurement_rounds = if ($Mode -ceq 'Measurement') {
        [int]$report.measurement.rounds
    } else {
        0
    }
    disassembled_cubins = $cubins.Count
    binary_analysis_sha256 = Get-AstroSha256 $binaryAnalysisSummaryPath
    nvidia_readback_sha256 = Get-AstroSha256 $gpuReadbackPath
    nvidia_gpu_rows = @($gpuIdentity.rows).Count
    nvidia_process_rows = @($gpuProcesses.rows).Count
    runtime_ordinal = [int]$report.execution.runtime_ordinal
    driver_ordinal = [int]$report.execution.driver_ordinal
    physical_device = [string]$report.execution.physical_device
    gpu_process_pid = [int]$runRecord.process.identity.pid
} | ConvertTo-Json -Depth 8 -Compress | Write-Output
