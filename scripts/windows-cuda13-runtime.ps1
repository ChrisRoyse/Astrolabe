[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$WorkspaceRoot,

    [string]$ToolchainsRoot = "",

    # #613: every launcher call carries the canonical protocol decision.
    # Defaults keep parameter binding non-interactive for a retired caller, then
    # the attestation below emits one structured fail-closed error before any
    # bundle inspection, lock, download, extraction, or shared-state mutation.
    [string]$LauncherProtocolAuthorityVersion = "",
    [string]$LauncherProtocolAuthorityPath = "",
    [string]$LauncherProtocolAuthoritySha256 = "",
    [string]$LauncherProtocolEntrypointSha256 = "",
    [string]$LauncherWorkspaceRoot = "",
    [string]$LauncherWorkspaceEntrypointSha256 = "",
    [int]$LauncherOwnerPid = 0,
    [long]$LauncherOwnerProcessStartUtcTicks = 0,
    [int]$LauncherIssue = 0,
    [string]$LauncherLockPath = "",
    [string]$LauncherLockSha256 = "",
    [string]$LauncherGitExe = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$LockSchema = "astrolabe.windows-ort-cuda-runtime-lock.v3"
$ReceiptSchema = "astrolabe.windows-ort-cuda-runtime-receipt.v2"
$LockFileName = "ort-cuda13.3-windows-x86_64.lock.json"
$CanonicalWorkspace = "C:\code\Astrolabe"
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Fail-Runtime {
    param(
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][string]$Remediation
    )

    throw "CUDA13_RUNTIME[$Code]: {code=$Code; message=`"$Message`"; remediation=`"$Remediation`"}"
}

function Fail-Runtime-Missing-Helper {
    param([Parameter(Mandatory = $true)][string]$HelperPath)
    throw "CUDA13_RUNTIME[ASTRO_CUDA13_RETIRE_HELPER_MISSING]: {code=ASTRO_CUDA13_RETIRE_HELPER_MISSING; message=`"required helper script is missing: $HelperPath`"; remediation=`"restore the checked-in scripts/ helper from the repository`"}"
}

# Fail-closed dot-source of the shared launcher-lock semantics and the obsolete-bundle
# retirer (#559). Both must exist; a missing helper is a named fail-closed boundary, never a
# silent skip -- retirement is part of provisioning's contract now that lock revisions leak
# ~1.8 GB roots per revision into the canonical workspace.
$LauncherLockHelper = Join-Path $PSScriptRoot 'launcher-lock.ps1'
if (-not (Test-Path -LiteralPath $LauncherLockHelper -PathType Leaf)) {
    Fail-Runtime-Missing-Helper $LauncherLockHelper
}
. $LauncherLockHelper
$Cuda13RetireHelper = Join-Path $PSScriptRoot 'cuda13-bundle-retire.ps1'
if (-not (Test-Path -LiteralPath $Cuda13RetireHelper -PathType Leaf)) {
    Fail-Runtime-Missing-Helper $Cuda13RetireHelper
}
. $Cuda13RetireHelper

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    [System.IO.FileStream]$stream = [System.IO.File]::OpenRead($LiteralPath)
    try {
        return [AstroLauncherLockNative]::ComputeExactFileSha256(
            $stream.SafeFileHandle
        )
    }
    finally {
        $stream.Dispose()
    }
}

function Initialize-AstroCuda13BoundedStreamSha256 {
    if ($null -ne ('AstroCuda13BoundedStreamSha256' -as [type])) {
        return
    }

    Add-Type -Language CSharp -ErrorAction Stop -TypeDefinition @'
using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public static class AstroCuda13BoundedStreamSha256
{
    private const int BufferSize = 1024 * 1024;

    public static byte[] Compute(Stream stream)
    {
        if (stream == null) throw new ArgumentNullException("stream");
        if (!stream.CanRead)
            throw new InvalidOperationException("SHA-256 source stream is not readable");

        byte[] buffer = new byte[BufferSize];
        using (SHA256 digest = SHA256.Create())
        {
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                int transformed = digest.TransformBlock(buffer, 0, read, buffer, 0);
                if (transformed != read)
                    throw new InvalidOperationException(
                        "SHA-256 transform consumed " +
                        transformed.ToString(CultureInfo.InvariantCulture) +
                        " of " + read.ToString(CultureInfo.InvariantCulture) +
                        " bytes"
                    );
            }
            digest.TransformFinalBlock(new byte[0], 0, 0);
            byte[] hash = digest.Hash;
            if (hash == null || hash.Length != 32)
                throw new InvalidOperationException("SHA-256 final digest is not exactly 32 bytes");
            return hash;
        }
    }
}
'@
}

# #613: this canonical shared-state boundary is also the hard stop for every
# historical registered launcher currently in the repository. Those launchers
# all call this canonical provisioner before creating their old PID-only lock,
# TEMP, target, or bundle state, but cannot supply this v3 authority binding.
$CanonicalLauncherEntrypoint = Join-Path `
    (Join-Path $CanonicalWorkspace 'scripts') `
    'windows-gnu-toolchain.ps1'
$CanonicalLauncherAuthority = Join-Path `
    (Join-Path $CanonicalWorkspace 'scripts') `
    'windows-gnu-toolchain-authority.ps1'
$expectedCaller = [IO.Path]::GetFullPath($CanonicalLauncherAuthority)
$observedCaller = if ([string]::IsNullOrWhiteSpace($MyInvocation.ScriptName)) {
    ''
}
else {
    [IO.Path]::GetFullPath($MyInvocation.ScriptName)
}
if ($LauncherProtocolAuthorityVersion -cne '3' -or
    -not [string]::Equals(
        $LauncherProtocolAuthorityPath,
        $expectedCaller,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    -not [string]::Equals(
        $observedCaller,
        $expectedCaller,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    $LauncherProtocolAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $LauncherProtocolEntrypointSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $LauncherWorkspaceEntrypointSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [string]::IsNullOrWhiteSpace($LauncherWorkspaceRoot) -or
    $LauncherOwnerPid -le 0 -or
    $LauncherOwnerProcessStartUtcTicks -le 0 -or
    $LauncherIssue -le 0 -or
    [string]::IsNullOrWhiteSpace($LauncherLockPath) -or
    $LauncherLockSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [string]::IsNullOrWhiteSpace($LauncherGitExe)) {
    Fail-Runtime `
        'ASTRO_LAUNCHER_PROTOCOL_VERSION_MISMATCH' `
        "caller '$observedCaller' did not supply the complete launcher protocol authority v3 binding" `
        "invoke '$CanonicalLauncherEntrypoint'; safely update or retire any historical registered-worktree launcher"
}
foreach ($authorityFile in @(
        $CanonicalLauncherEntrypoint,
        $CanonicalLauncherAuthority
    )) {
    if (-not [IO.File]::Exists($authorityFile)) {
        Fail-Runtime `
            'ASTRO_LAUNCHER_AUTHORITY_INCOMPLETE' `
            "canonical authority file is absent: '$authorityFile'" `
            "restore and verify the canonical checkout at '$CanonicalWorkspace'"
    }
    $authorityItem = Get-Item -LiteralPath $authorityFile -Force
    if (($authorityItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($authorityItem.Attributes -band
            [IO.FileAttributes]::Directory) -ne 0) {
        Fail-Runtime `
            'ASTRO_LAUNCHER_AUTHORITY_FILE_INVALID' `
            "canonical authority path is not one ordinary non-reparse file: '$authorityFile'" `
            "restore the exact canonical tracked file before retrying"
    }
}
$observedAuthoritySha256 = Get-Sha256Hex $CanonicalLauncherAuthority
$observedEntrypointSha256 = Get-Sha256Hex $CanonicalLauncherEntrypoint
$launcherWorkspaceFull = try {
    [IO.Path]::GetFullPath($LauncherWorkspaceRoot).TrimEnd('\', '/')
}
catch {
    Fail-Runtime `
        'ASTRO_LAUNCHER_WORKSPACE_INVALID' `
        "launcher workspace root cannot be resolved: '$LauncherWorkspaceRoot'" `
        "invoke only the canonical launcher entrypoint"
}
$launcherWorkspaceEntrypoint = Join-Path `
    (Join-Path $launcherWorkspaceFull 'scripts') `
    'windows-gnu-toolchain.ps1'
if (-not [IO.File]::Exists($launcherWorkspaceEntrypoint)) {
    Fail-Runtime `
        'ASTRO_LAUNCHER_PROTOCOL_VERSION_MISMATCH' `
        "launcher workspace entrypoint is absent: '$launcherWorkspaceEntrypoint'" `
        "update or safely retire the historical registered worktree"
}
$observedWorkspaceEntrypointSha256 =
    Get-Sha256Hex $launcherWorkspaceEntrypoint
if ($observedAuthoritySha256 -cne $LauncherProtocolAuthoritySha256 -or
    $observedEntrypointSha256 -cne $LauncherProtocolEntrypointSha256 -or
    $observedWorkspaceEntrypointSha256 -cne
        $LauncherWorkspaceEntrypointSha256 -or
    $observedWorkspaceEntrypointSha256 -cne
        $observedEntrypointSha256) {
    Fail-Runtime `
        'ASTRO_LAUNCHER_PROTOCOL_VERSION_MISMATCH' `
        "launcher authority changed or the workspace trampoline differs from canonical bytes (authority=$observedAuthoritySha256; canonical_entrypoint=$observedEntrypointSha256; workspace_entrypoint=$observedWorkspaceEntrypointSha256)" `
        "preserve all state; invoke '$CanonicalLauncherEntrypoint' only after restoring one clean canonical authority"
}
$currentProcess = Get-Process -Id $PID -ErrorAction Stop
try {
    $currentProcessStartUtcTicks =
        [long]$currentProcess.StartTime.ToUniversalTime().Ticks
}
finally {
    $currentProcess.Dispose()
}
$launcherLockFull = try {
    [IO.Path]::GetFullPath($LauncherLockPath)
}
catch {
    Fail-Runtime `
        'ASTRO_CUDA13_CALLER_LEASE_INVALID' `
        "launcher lock path is not canonical: '$LauncherLockPath'" `
        "invoke only the canonical launcher while its exact v3 lease is active"
}
$launcherLock = Read-AstroLauncherLock -LockPath $launcherLockFull
if ($LauncherOwnerPid -ne $PID -or
    $LauncherOwnerProcessStartUtcTicks -ne $currentProcessStartUtcTicks -or
    $launcherLock.State -cne 'held' -or
    $launcherLock.OwnerPid -ne $LauncherOwnerPid -or
    $launcherLock.OwnerProcessStartUtcTicks -ne
        $LauncherOwnerProcessStartUtcTicks -or
    $launcherLock.Issue -ne $LauncherIssue -or
    $launcherLock.Sha256 -cne $LauncherLockSha256 -or
    -not [string]::Equals(
        [string]$launcherLock.WorkspaceRoot,
        $launcherWorkspaceFull,
        [StringComparison]::OrdinalIgnoreCase
    )) {
    Fail-Runtime `
        'ASTRO_CUDA13_CALLER_LEASE_INVALID' `
        "the runtime provisioner is not executing as the exact active launcher owner (current_pid=$PID; current_ticks=$currentProcessStartUtcTicks; supplied_pid=$LauncherOwnerPid; supplied_ticks=$LauncherOwnerProcessStartUtcTicks; lock_state=$($launcherLock.State); lock_pid=$($launcherLock.OwnerPid); lock_ticks=$($launcherLock.OwnerProcessStartUtcTicks); lock_issue=$($launcherLock.Issue); lock_sha256=$($launcherLock.Sha256))" `
        "invoke only the canonical launcher while its exact v3 lease is active"
}
$launcherGitFull = try {
    [IO.Path]::GetFullPath($LauncherGitExe)
}
catch {
    Fail-Runtime `
        'ASTRO_CUDA13_GIT_INVALID' `
        "Git executable path is not canonical: '$LauncherGitExe'" `
        "repair the canonical Git for Windows installation and retry"
}
if (-not [IO.File]::Exists($launcherGitFull)) {
    Fail-Runtime `
        'ASTRO_CUDA13_GIT_INVALID' `
        "Git executable is absent: '$launcherGitFull'" `
        "repair the canonical Git for Windows installation and retry"
}
$launcherGitItem = Get-Item -LiteralPath $launcherGitFull -Force
if (($launcherGitItem.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or
    ($launcherGitItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail-Runtime `
        'ASTRO_CUDA13_GIT_INVALID' `
        "Git executable is not one ordinary non-reparse file: '$launcherGitFull'" `
        "repair the canonical Git for Windows installation and retry"
}
$launcherSelf = [pscustomobject]@{
    LockPath = $launcherLockFull
    Pid = $LauncherOwnerPid
    OwnerProcessStartUtcTicks = $LauncherOwnerProcessStartUtcTicks
    Issue = $LauncherIssue
    LockSha256 = $LauncherLockSha256
}

function Assert-ExactFields {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string[]]$Fields,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($null -eq $Object) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "$Context is null" "restore the checked-in CUDA 13 runtime lock"
    }
    $actual = @($Object.PSObject.Properties.Name)
    foreach ($field in $Fields) {
        if ($actual -notcontains $field) {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "$Context is missing required field $field" "restore the checked-in CUDA 13 runtime lock"
        }
    }
    foreach ($field in $actual) {
        if ($Fields -notcontains $field) {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "$Context contains unknown field $field" "update the provisioner and lock schema together"
        }
    }
}

function Assert-NonBlankString {
    param($Value, [string]$Context)

    if (-not ($Value -is [string]) -or [string]::IsNullOrWhiteSpace($Value)) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "$Context must be a non-blank string" "restore the checked-in CUDA 13 runtime lock"
    }
}

function Assert-PositiveInteger {
    param($Value, [string]$Context)

    if (-not ($Value -is [int]) -and -not ($Value -is [long])) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "$Context must be an integer" "restore the checked-in CUDA 13 runtime lock"
    }
    if ([long]$Value -le 0) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "$Context must be a positive integer" "restore the checked-in CUDA 13 runtime lock"
    }
}

function Assert-Sha256 {
    param($Value, [string]$Context)

    if (-not ($Value -is [string]) -or $Value -cnotmatch '^[0-9a-f]{64}$') {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "$Context must be lowercase SHA-256 hex" "restore the checked-in CUDA 13 runtime lock"
    }
}

function Assert-SafeRelativePath {
    param($Value, [string]$Context)

    Assert-NonBlankString $Value $Context
    if ($Value.Contains('\') -or $Value.StartsWith('/') -or $Value.EndsWith('/') -or $Value.Contains(':')) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_PATH" "$Context is not a normalized forward-slash relative path: $Value" "restore the checked-in CUDA 13 runtime lock"
    }
    $segments = $Value.Split('/')
    foreach ($segment in $segments) {
        if ([string]::IsNullOrEmpty($segment) -or $segment -eq '.' -or $segment -eq '..') {
            Fail-Runtime "ASTRO_CUDA13_LOCK_PATH" "$Context contains an unsafe path segment: $Value" "restore the checked-in CUDA 13 runtime lock"
        }
    }
}

function Assert-SafeFileName {
    param($Value, [string]$Context)

    Assert-NonBlankString $Value $Context
    if ([System.IO.Path]::GetFileName($Value) -cne $Value -or $Value.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_PATH" "$Context is not a safe file name: $Value" "restore the checked-in CUDA 13 runtime lock"
    }
}

function Get-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Get-RelativeChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $rootPrefix = (Get-FullPath $Root) + '\'
    $fullPath = Get-FullPath $Path
    if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Fail-Runtime "ASTRO_CUDA13_BUNDLE_ESCAPE" "$fullPath is outside bundle root $Root" "remove the invalid bundle and rerun provisioning"
    }
    return $fullPath.Substring($rootPrefix.Length).Replace('\', '/')
}

function Convert-HexToRecordDigest {
    param([Parameter(Mandatory = $true)][string]$Hex)

    $bytes = New-Object byte[] 32
    for ($index = 0; $index -lt 32; $index++) {
        $bytes[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
    }
    $encoded = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    return "sha256=$encoded"
}

function Read-Lock {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    try {
        $raw = [System.IO.File]::ReadAllText($LiteralPath, [Text.Encoding]::UTF8)
        $lock = ConvertFrom-Json -InputObject $raw
    }
    catch {
        Fail-Runtime "ASTRO_CUDA13_LOCK_JSON" "cannot parse $LiteralPath as JSON: $($_.Exception.Message)" "restore the checked-in CUDA 13 runtime lock"
    }

    Assert-ExactFields $lock @('schema', 'bundle', 'contract', 'artifacts', 'files', 'notices', 'loaded_module_policy') 'lock'
    if ($lock.schema -cne $LockSchema) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "unsupported lock schema $($lock.schema)" "use lock schema $LockSchema"
    }

    Assert-ExactFields $lock.bundle @('id', 'platform', 'layout', 'root_prefix', 'root_from') 'lock.bundle'
    foreach ($field in @('id', 'platform', 'layout', 'root_prefix', 'root_from')) {
        Assert-NonBlankString $lock.bundle.$field "lock.bundle.$field"
    }
    if ($lock.bundle.platform -cne 'windows-x86_64' -or $lock.bundle.layout -cne 'flat-bin-v1' -or $lock.bundle.root_from -cne 'sha256(lock_file_bytes)') {
        Fail-Runtime "ASTRO_CUDA13_LOCK_PLATFORM" "lock bundle platform/layout/root derivation is not the supported Windows CUDA contract" "restore the checked-in lock"
    }
    if ($lock.bundle.root_prefix -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]+$') {
        Fail-Runtime "ASTRO_CUDA13_LOCK_PATH" "invalid bundle root_prefix $($lock.bundle.root_prefix)" "restore the checked-in lock"
    }

    Assert-ExactFields $lock.contract @('ort_version', 'ort_file_version', 'ort_api', 'api_non_null', 'first_api_null', 'provider', 'ort_dll', 'provider_dll', 'direct_non_system_imports') 'lock.contract'
    foreach ($field in @('ort_version', 'ort_file_version', 'provider')) {
        Assert-NonBlankString $lock.contract.$field "lock.contract.$field"
    }
    Assert-PositiveInteger $lock.contract.ort_api 'lock.contract.ort_api'
    Assert-PositiveInteger $lock.contract.first_api_null 'lock.contract.first_api_null'
    foreach ($api in @($lock.contract.api_non_null)) {
        Assert-PositiveInteger $api 'lock.contract.api_non_null[]'
    }
    foreach ($name in @($lock.contract.direct_non_system_imports)) {
        Assert-SafeFileName $name 'lock.contract.direct_non_system_imports[]'
    }
    Assert-SafeRelativePath $lock.contract.ort_dll 'lock.contract.ort_dll'
    Assert-SafeRelativePath $lock.contract.provider_dll 'lock.contract.provider_dll'

    Assert-ExactFields $lock.loaded_module_policy @('boundary_load', 'dependency_preload_order', 'ort_managed_load', 'bundle_module_globs', 'system_modules', 'driver_store_companions', 'system_roots', 'reject_application_dir', 'reject_path_search') 'lock.loaded_module_policy'
    $loadOrderSet = @{}
    foreach ($phase in @('boundary_load', 'dependency_preload_order', 'ort_managed_load')) {
        foreach ($path in @($lock.loaded_module_policy.$phase)) {
            Assert-SafeRelativePath $path "lock.loaded_module_policy.$phase[]"
            if (-not $path.EndsWith('.dll', [StringComparison]::OrdinalIgnoreCase)) {
                Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "$phase entry is not a DLL: $path" "restore the checked-in lock"
            }
            if ($loadOrderSet.ContainsKey($path)) {
                Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "module $path appears in multiple load phases" "restore the checked-in lock"
            }
            $loadOrderSet.Add($path, $phase)
        }
    }
    if (@($lock.loaded_module_policy.boundary_load).Count -ne 1 -or $lock.loaded_module_policy.boundary_load[0] -cne $lock.contract.ort_dll) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "boundary_load must contain only the contracted ORT core" "restore the checked-in lock"
    }
    if (@($lock.loaded_module_policy.ort_managed_load).Count -ne 1 -or $lock.loaded_module_policy.ort_managed_load[0] -cne $lock.contract.provider_dll) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "ort_managed_load must contain only the contracted CUDA provider" "restore the checked-in lock"
    }
    $systemModules = @($lock.loaded_module_policy.system_modules)
    if ($systemModules.Count -ne 2) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "system_modules must contain exactly nvcuda.dll and nvml.dll" "restore the checked-in lock"
    }
    $systemModuleNames = @{}
    foreach ($module in $systemModules) {
        Assert-ExactFields $module @('name', 'required_root', 'signature_kind', 'signer_organization', 'signed_company_name') 'lock.loaded_module_policy.system_modules[]'
        Assert-SafeFileName $module.name 'lock.loaded_module_policy.system_modules[].name'
        foreach ($field in @('required_root', 'signature_kind', 'signer_organization', 'signed_company_name')) {
            Assert-NonBlankString $module.$field "lock.loaded_module_policy.system_modules[].$field"
        }
        if ($module.signature_kind -cne 'catalog') {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "system module $($module.name) must require catalog trust" "restore the checked-in lock"
        }
        if ($module.required_root -cne '%SystemRoot%\System32' -or $module.signer_organization -cne 'Microsoft Corporation' -or $module.signed_company_name -cne 'NVIDIA Corporation') {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "system module $($module.name) trust identity differs from the Windows NVIDIA driver contract" "restore the checked-in lock"
        }
        $key = $module.name.ToLowerInvariant()
        if ($systemModuleNames.ContainsKey($key)) {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "duplicate system module $($module.name)" "restore the checked-in lock"
        }
        $systemModuleNames.Add($key, $true)
    }
    foreach ($required in @('nvcuda.dll', 'nvml.dll')) {
        if (-not $systemModuleNames.ContainsKey($required)) {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "system_modules omits $required" "restore the checked-in lock"
        }
    }
    $driverStoreCompanions = @($lock.loaded_module_policy.driver_store_companions)
    if ($driverStoreCompanions.Count -ne 2) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "driver_store_companions must contain exactly nvcuda64.dll and the NVML DriverStore implementation" "restore the checked-in lock"
    }
    $companionAttestations = @{}
    foreach ($companion in $driverStoreCompanions) {
        Assert-ExactFields $companion @('name', 'attestation_name', 'owner', 'required_root', 'signature_kind', 'signer_organization', 'signed_company_name', 'require_same_catalog', 'require_same_signer_certificate', 'require_same_file_version', 'require_same_product_name') 'lock.loaded_module_policy.driver_store_companions[]'
        Assert-SafeFileName $companion.name 'lock.loaded_module_policy.driver_store_companions[].name'
        Assert-SafeFileName $companion.attestation_name 'lock.loaded_module_policy.driver_store_companions[].attestation_name'
        Assert-SafeFileName $companion.owner 'lock.loaded_module_policy.driver_store_companions[].owner'
        foreach ($field in @('required_root', 'signature_kind', 'signer_organization', 'signed_company_name')) {
            Assert-NonBlankString $companion.$field "lock.loaded_module_policy.driver_store_companions[].$field"
        }
        $attestationKey = $companion.attestation_name.ToLowerInvariant()
        if ($companionAttestations.ContainsKey($attestationKey)) {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "duplicate DriverStore companion attestation_name $($companion.attestation_name)" "restore the checked-in lock"
        }
        $companionAttestations.Add($attestationKey, $companion)
        if ($companion.required_root -cne '%SystemRoot%\System32\DriverStore\FileRepository' -or
            $companion.signature_kind -cne 'catalog' -or
            $companion.signer_organization -cne 'Microsoft Corporation' -or
            $companion.signed_company_name -cne 'NVIDIA Corporation') {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "DriverStore companion trust identity differs from the Windows NVIDIA driver contract" "restore the checked-in lock"
        }
        foreach ($field in @('require_same_catalog', 'require_same_signer_certificate', 'require_same_file_version', 'require_same_product_name')) {
            if (-not ($companion.$field -is [bool]) -or -not $companion.$field) {
                Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "DriverStore companion must set $field=true" "restore the checked-in lock"
            }
        }
    }
    if (-not $companionAttestations.ContainsKey('nvcuda64.dll') -or
        $companionAttestations['nvcuda64.dll'].name -cne 'nvcuda64.dll' -or
        $companionAttestations['nvcuda64.dll'].owner -cne 'nvcuda.dll' -or
        -not $companionAttestations.ContainsKey('nvml.driverstore.dll') -or
        $companionAttestations['nvml.driverstore.dll'].name -cne 'nvml.dll' -or
        $companionAttestations['nvml.driverstore.dll'].owner -cne 'nvml.dll') {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "DriverStore companion owner/attestation mapping differs from the NVIDIA CUDA/NVML loader contract" "restore the checked-in lock"
    }
    foreach ($glob in @($lock.loaded_module_policy.bundle_module_globs)) {
        Assert-NonBlankString $glob 'lock.loaded_module_policy.bundle_module_globs[]'
    }
    foreach ($root in @($lock.loaded_module_policy.system_roots)) {
        Assert-NonBlankString $root 'lock.loaded_module_policy.system_roots[]'
    }
    if (@($lock.loaded_module_policy.system_roots).Count -ne 2 -or
        $lock.loaded_module_policy.system_roots[0] -cne '%SystemRoot%\System32' -or
        $lock.loaded_module_policy.system_roots[1] -cne '%SystemRoot%\System32\DriverStore\FileRepository') {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "system_roots must contain exactly System32 and DriverStore FileRepository" "restore the checked-in lock"
    }
    if (-not ($lock.loaded_module_policy.reject_application_dir -is [bool]) -or -not ($lock.loaded_module_policy.reject_path_search -is [bool]) -or -not $lock.loaded_module_policy.reject_application_dir -or -not $lock.loaded_module_policy.reject_path_search) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "loaded module policy must reject application-directory and PATH search" "restore the checked-in lock"
    }

    $artifacts = @{}
    foreach ($artifact in @($lock.artifacts)) {
        Assert-ExactFields $artifact @('id', 'distribution', 'version', 'filename', 'url', 'bytes', 'sha256', 'archive_verification', 'record', 'metadata', 'license_expression') "artifact"
        foreach ($field in @('id', 'distribution', 'version', 'url', 'archive_verification', 'license_expression')) {
            Assert-NonBlankString $artifact.$field "artifact.$($artifact.id).$field"
        }
        if ($artifact.id -cnotmatch '^[a-z0-9][a-z0-9-]*$') {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "invalid artifact id $($artifact.id)" "restore the checked-in lock"
        }
        if ($artifacts.ContainsKey($artifact.id)) {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "duplicate artifact id $($artifact.id)" "restore the checked-in lock"
        }
        Assert-SafeFileName $artifact.filename "artifact.$($artifact.id).filename"
        Assert-PositiveInteger $artifact.bytes "artifact.$($artifact.id).bytes"
        Assert-Sha256 $artifact.sha256 "artifact.$($artifact.id).sha256"
        if ($artifact.archive_verification -ceq 'wheel-record-sha256') {
            Assert-SafeRelativePath $artifact.record "artifact.$($artifact.id).record"
            Assert-SafeRelativePath $artifact.metadata "artifact.$($artifact.id).metadata"
        }
        elseif ($artifact.archive_verification -ceq 'release-archive-sha256') {
            if ($null -ne $artifact.record -or $null -ne $artifact.metadata) {
                Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "release archive $($artifact.id) must not claim wheel RECORD/METADATA paths" "restore the checked-in lock"
            }
        }
        else {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "artifact $($artifact.id) has unsupported archive verification $($artifact.archive_verification)" "update the provisioner and lock schema together"
        }
        try {
            $uri = [Uri]$artifact.url
        }
        catch {
            Fail-Runtime "ASTRO_CUDA13_LOCK_URL" "invalid artifact URL for $($artifact.id)" "restore the checked-in lock"
        }
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -cne 'https' -or -not [string]::IsNullOrEmpty($uri.Query) -or -not [string]::IsNullOrEmpty($uri.Fragment)) {
            Fail-Runtime "ASTRO_CUDA13_LOCK_URL" "artifact $($artifact.id) URL must be stable HTTPS without query or fragment" "restore the checked-in lock"
        }
        $artifacts.Add($artifact.id, $artifact)
    }
    if ($artifacts.Count -eq 0) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "lock has no artifacts" "restore the checked-in lock"
    }

    $bundlePaths = @{}
    foreach ($file in @($lock.files)) {
        Assert-ExactFields $file @('artifact', 'archive_path', 'bundle_path', 'bytes', 'sha256', 'file_version', 'authenticode', 'role') 'lock.files[]'
        if (-not $artifacts.ContainsKey($file.artifact)) {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "file references unknown artifact $($file.artifact)" "restore the checked-in lock"
        }
        Assert-SafeRelativePath $file.archive_path "file.$($file.bundle_path).archive_path"
        Assert-SafeRelativePath $file.bundle_path "file.$($file.bundle_path).bundle_path"
        if (-not $file.bundle_path.StartsWith('bin/', [StringComparison]::Ordinal) -or -not $file.bundle_path.EndsWith('.dll', [StringComparison]::OrdinalIgnoreCase)) {
            Fail-Runtime "ASTRO_CUDA13_LOCK_PATH" "DLL bundle path must be under bin/: $($file.bundle_path)" "restore the checked-in lock"
        }
        Assert-PositiveInteger $file.bytes "file.$($file.bundle_path).bytes"
        Assert-Sha256 $file.sha256 "file.$($file.bundle_path).sha256"
        Assert-ExactFields $file.authenticode @('status', 'subject', 'thumbprint') "file.$($file.bundle_path).authenticode"
        foreach ($field in @('status', 'subject', 'thumbprint')) {
            Assert-NonBlankString $file.authenticode.$field "file.$($file.bundle_path).authenticode.$field"
        }
        if ($file.authenticode.status -cne 'Valid' -or $file.authenticode.thumbprint -cnotmatch '^[0-9A-F]{40}$') {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SIGNATURE" "invalid signature contract for $($file.bundle_path)" "restore the checked-in lock"
        }
        if ($null -ne $file.file_version) {
            Assert-NonBlankString $file.file_version "file.$($file.bundle_path).file_version"
        }
        Assert-NonBlankString $file.role "file.$($file.bundle_path).role"
        if ($bundlePaths.ContainsKey($file.bundle_path)) {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "duplicate bundle path $($file.bundle_path)" "restore the checked-in lock"
        }
        $bundlePaths.Add($file.bundle_path, $true)
    }

    if ($loadOrderSet.Count -ne @($lock.files).Count) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "the three module load phases must name every locked DLL exactly once" "restore the checked-in lock"
    }
    foreach ($path in $loadOrderSet.Keys) {
        if (-not $bundlePaths.ContainsKey($path)) {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "module load phases name unlocked path $path" "restore the checked-in lock"
        }
    }

    foreach ($notice in @($lock.notices)) {
        Assert-ExactFields $notice @('artifact', 'archive_path', 'bundle_path', 'bytes', 'sha256') 'lock.notices[]'
        if (-not $artifacts.ContainsKey($notice.artifact)) {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "notice references unknown artifact $($notice.artifact)" "restore the checked-in lock"
        }
        Assert-SafeRelativePath $notice.archive_path "notice.$($notice.bundle_path).archive_path"
        Assert-SafeRelativePath $notice.bundle_path "notice.$($notice.bundle_path).bundle_path"
        if (-not $notice.bundle_path.StartsWith('licenses/', [StringComparison]::Ordinal)) {
            Fail-Runtime "ASTRO_CUDA13_LOCK_PATH" "notice bundle path must be under licenses/: $($notice.bundle_path)" "restore the checked-in lock"
        }
        Assert-PositiveInteger $notice.bytes "notice.$($notice.bundle_path).bytes"
        Assert-Sha256 $notice.sha256 "notice.$($notice.bundle_path).sha256"
        if ($bundlePaths.ContainsKey($notice.bundle_path)) {
            Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "duplicate bundle path $($notice.bundle_path)" "restore the checked-in lock"
        }
        $bundlePaths.Add($notice.bundle_path, $true)
    }

    if (-not $bundlePaths.ContainsKey($lock.contract.ort_dll) -or -not $bundlePaths.ContainsKey($lock.contract.provider_dll)) {
        Fail-Runtime "ASTRO_CUDA13_LOCK_SCHEMA" "ORT contract paths are absent from locked files" "restore the checked-in lock"
    }
    return $lock
}

function Assert-FileBytes {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)]$ExpectedBytes,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        Fail-Runtime "ASTRO_CUDA13_FILE_MISSING" "$Context is missing at $LiteralPath" "remove the incomplete bundle and rerun provisioning"
    }
    $item = Get-Item -LiteralPath $LiteralPath -Force
    if ($item.Length -ne [long]$ExpectedBytes) {
        Fail-Runtime "ASTRO_CUDA13_FILE_SIZE" "$Context byte count mismatch at $LiteralPath; expected $ExpectedBytes, got $($item.Length)" "remove the corrupted bundle and rerun provisioning"
    }
    $actualHash = Get-Sha256Hex $LiteralPath
    if ($actualHash -cne $ExpectedSha256) {
        Fail-Runtime "ASTRO_CUDA13_FILE_HASH" "$Context SHA-256 mismatch at $LiteralPath; expected $ExpectedSha256, got $actualHash" "remove the corrupted bundle and rerun provisioning"
    }
}

function Assert-Authenticode {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)]$File
    )

    $ambientModulePath = $env:PSModulePath
    try {
        # Resolve the security cmdlet from this host's own installation. Inheriting a mixed
        # PowerShell 7 / Windows PowerShell 5.1 module path can discover an ABI-incompatible
        # Microsoft.PowerShell.Security module and then fail while loading it.
        $env:PSModulePath = Join-Path $PSHOME "Modules"
        $securityManifest = Join-Path $PSHOME "Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1"
        if (-not (Test-Path -LiteralPath $securityManifest -PathType Leaf)) {
            Fail-Runtime "ASTRO_CUDA13_SECURITY_MODULE_MISSING" "the current PowerShell host is missing its built-in security module at $securityManifest" "repair the current PowerShell installation before provisioning the CUDA runtime"
        }
        Import-Module -Name $securityManifest -ErrorAction Stop
        $signature = Get-AuthenticodeSignature -LiteralPath $LiteralPath
    }
    finally {
        $env:PSModulePath = $ambientModulePath
    }
    $actualStatus = $signature.Status.ToString()
    if ($actualStatus -cne $File.authenticode.status -or $null -eq $signature.SignerCertificate) {
        Fail-Runtime "ASTRO_CUDA13_SIGNATURE" "Authenticode status for $LiteralPath is $actualStatus, expected $($File.authenticode.status)" "restore the pinned official artifact and rerun provisioning"
    }
    if ($signature.SignerCertificate.Subject -cne $File.authenticode.subject -or $signature.SignerCertificate.Thumbprint -cne $File.authenticode.thumbprint) {
        Fail-Runtime "ASTRO_CUDA13_SIGNER" "Authenticode signer mismatch for $LiteralPath" "restore the pinned official artifact and rerun provisioning"
    }
    $actualVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($LiteralPath).FileVersion
    if ($null -eq $File.file_version) {
        if (-not [string]::IsNullOrEmpty($actualVersion)) {
            Fail-Runtime "ASTRO_CUDA13_FILE_VERSION" "$LiteralPath unexpectedly reports file version $actualVersion" "restore the pinned official artifact and rerun provisioning"
        }
    }
    elseif ($actualVersion -cne $File.file_version) {
        Fail-Runtime "ASTRO_CUDA13_FILE_VERSION" "$LiteralPath reports file version $actualVersion, expected $($File.file_version)" "restore the pinned official artifact and rerun provisioning"
    }
}

function Get-ArchiveEntries {
    param([Parameter(Mandatory = $true)]$Archive)

    $entries = @{}
    foreach ($entry in $Archive.Entries) {
        $name = $entry.FullName
        if ($name.EndsWith('/')) {
            $name = $name.TrimEnd('/')
            if ([string]::IsNullOrEmpty($name)) {
                continue
            }
            Assert-SafeRelativePath $name "wheel directory entry"
            continue
        }
        Assert-SafeRelativePath $name "wheel entry"
        if ($entries.ContainsKey($entry.FullName)) {
            Fail-Runtime "ASTRO_CUDA13_WHEEL_DUPLICATE" "wheel contains duplicate or case-colliding entry $($entry.FullName)" "report the changed upstream wheel and update the lock deliberately"
        }
        $entries.Add($entry.FullName, $entry)
    }
    return $entries
}

function Get-ZipEntryRecordDigest {
    param([Parameter(Mandatory = $true)]$Entry)

    Initialize-AstroCuda13BoundedStreamSha256
    [IO.Stream]$stream = $Entry.Open()
    try {
        [byte[]]$bytes = [AstroCuda13BoundedStreamSha256]::Compute(
            [IO.Stream]$stream
        )
    }
    finally {
        $stream.Dispose()
    }
    $encoded = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    return "sha256=$encoded"
}

function Read-ZipEntryText {
    param([Parameter(Mandatory = $true)]$Entry)

    $stream = $Entry.Open()
    try {
        $reader = [System.IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true, 4096, $true)
        try {
            return $reader.ReadToEnd()
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-RecordRows {
    param(
        [Parameter(Mandatory = $true)]$Entries,
        [Parameter(Mandatory = $true)]$Artifact
    )

    if (-not $Entries.ContainsKey($Artifact.record)) {
        Fail-Runtime "ASTRO_CUDA13_WHEEL_RECORD" "artifact $($Artifact.id) is missing $($Artifact.record)" "report the changed upstream wheel and update the lock deliberately"
    }
    $text = Read-ZipEntryText $Entries[$Artifact.record]
    try {
        $parsed = @($text | ConvertFrom-Csv -Header Path, Digest, Size)
    }
    catch {
        Fail-Runtime "ASTRO_CUDA13_WHEEL_RECORD" "cannot parse RECORD for $($Artifact.id): $($_.Exception.Message)" "report the changed upstream wheel and update the lock deliberately"
    }
    $rows = @{}
    foreach ($row in $parsed) {
        Assert-SafeRelativePath $row.Path "RECORD path"
        if ($rows.ContainsKey($row.Path)) {
            Fail-Runtime "ASTRO_CUDA13_WHEEL_RECORD" "artifact $($Artifact.id) RECORD contains duplicate path $($row.Path)" "report the changed upstream wheel and update the lock deliberately"
        }
        $rows.Add($row.Path, $row)
    }
    if ($rows.Count -ne $Entries.Count) {
        Fail-Runtime "ASTRO_CUDA13_WHEEL_RECORD" "artifact $($Artifact.id) RECORD has $($rows.Count) rows for $($Entries.Count) archive files" "report the changed upstream wheel and update the lock deliberately"
    }
    foreach ($entryName in @($Entries.Keys)) {
        if (-not $rows.ContainsKey($entryName)) {
            Fail-Runtime "ASTRO_CUDA13_WHEEL_RECORD" "artifact $($Artifact.id) RECORD is missing archive file $entryName" "report the changed upstream wheel and update the lock deliberately"
        }
        $row = $rows[$entryName]
        if ($entryName -ceq $Artifact.record) {
            if (-not [string]::IsNullOrEmpty($row.Digest) -or -not [string]::IsNullOrEmpty($row.Size)) {
                Fail-Runtime "ASTRO_CUDA13_WHEEL_RECORD" "artifact $($Artifact.id) RECORD must leave only its own digest and size blank" "report the changed upstream wheel and update the lock deliberately"
            }
            continue
        }
        $expectedSize = $Entries[$entryName].Length.ToString([Globalization.CultureInfo]::InvariantCulture)
        if ($row.Digest -cnotmatch '^sha256=[A-Za-z0-9_-]{43}$' -or $row.Size -cne $expectedSize) {
            Fail-Runtime "ASTRO_CUDA13_WHEEL_RECORD" "artifact $($Artifact.id) RECORD metadata is invalid for $entryName" "report the changed upstream wheel and update the lock deliberately"
        }
        $actualDigest = Get-ZipEntryRecordDigest $Entries[$entryName]
        if ($actualDigest -cne $row.Digest) {
            Fail-Runtime "ASTRO_CUDA13_WHEEL_RECORD" "artifact $($Artifact.id) RECORD digest mismatch for $entryName" "report the changed upstream wheel and update the lock deliberately"
        }
    }
    foreach ($recordName in @($rows.Keys)) {
        if (-not $Entries.ContainsKey($recordName)) {
            Fail-Runtime "ASTRO_CUDA13_WHEEL_RECORD" "artifact $($Artifact.id) RECORD names absent archive file $recordName" "report the changed upstream wheel and update the lock deliberately"
        }
    }
    return $rows
}

function Assert-RecordRow {
    param(
        [Parameter(Mandatory = $true)]$Rows,
        [Parameter(Mandatory = $true)]$Payload,
        [Parameter(Mandatory = $true)][string]$ArtifactId
    )

    if (-not $Rows.ContainsKey($Payload.archive_path)) {
        Fail-Runtime "ASTRO_CUDA13_WHEEL_RECORD" "artifact $ArtifactId RECORD is missing $($Payload.archive_path)" "report the changed upstream wheel and update the lock deliberately"
    }
    $row = $Rows[$Payload.archive_path]
    $expectedDigest = Convert-HexToRecordDigest $Payload.sha256
    if ($row.Digest -cne $expectedDigest -or $row.Size -cne ([long]$Payload.bytes).ToString([Globalization.CultureInfo]::InvariantCulture)) {
        Fail-Runtime "ASTRO_CUDA13_WHEEL_RECORD" "artifact $ArtifactId RECORD contract mismatch for $($Payload.archive_path)" "report the changed upstream wheel and update the lock deliberately"
    }
}

function Expand-LockedPayload {
    param(
        [Parameter(Mandatory = $true)]$Entry,
        [Parameter(Mandatory = $true)]$Payload,
        [Parameter(Mandatory = $true)][string]$BundleRoot
    )

    $destination = Join-Path $BundleRoot ($Payload.bundle_path.Replace('/', '\'))
    $parent = Split-Path -Parent $destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $input = $Entry.Open()
    try {
        $output = [System.IO.FileStream]::new($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $input.CopyTo($output)
        }
        finally {
            $output.Dispose()
        }
    }
    finally {
        $input.Dispose()
    }
    Assert-FileBytes $destination $Payload.bytes $Payload.sha256 "locked payload $($Payload.bundle_path)"
}

function Download-Artifact {
    param(
        [Parameter(Mandatory = $true)]$Artifact,
        [Parameter(Mandatory = $true)][string]$DownloadRoot,
        [Parameter(Mandatory = $true)][string]$CurlExe
    )

    $partial = Join-Path $DownloadRoot ($Artifact.filename + '.partial')
    $complete = Join-Path $DownloadRoot $Artifact.filename
    $arguments = @(
        '--fail',
        '--location',
        '--proto', '=https',
        '--proto-redir', '=https',
        '--retry', '3',
        '--silent',
        '--show-error',
        '--output', $partial,
        '--url', $Artifact.url
    )
    & $CurlExe @arguments
    if ($LASTEXITCODE -ne 0) {
        Fail-Runtime "ASTRO_CUDA13_DOWNLOAD" "download failed for $($Artifact.id) with curl exit $LASTEXITCODE" "check HTTPS access to the locked official URL and retry"
    }
    Assert-FileBytes $partial $Artifact.bytes $Artifact.sha256 "artifact $($Artifact.id)"
    Move-Item -LiteralPath $partial -Destination $complete -ErrorAction Stop
    return $complete
}

function Install-Bundle {
    param(
        [Parameter(Mandatory = $true)]$Lock,
        [Parameter(Mandatory = $true)][string]$LockPath,
        [Parameter(Mandatory = $true)][string]$LockSha256,
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [Parameter(Mandatory = $true)][string]$CurlExe
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $downloadRoot = Join-Path $StageRoot 'downloads'
    $bundleRoot = Join-Path $StageRoot 'bundle'
    New-Item -ItemType Directory -Path $downloadRoot, $bundleRoot -ErrorAction Stop | Out-Null
    $artifactReceipt = @()

    foreach ($artifact in @($Lock.artifacts)) {
        Write-Verbose "provisioning locked CUDA artifact $($artifact.id) $($artifact.version)"
        $archivePath = Download-Artifact $artifact $downloadRoot $CurlExe
        $archive = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
        try {
            $entries = Get-ArchiveEntries $archive
            $rows = $null
            $manifestEntries = 0L
            $manifestEntriesVerified = 0L
            if ($artifact.archive_verification -ceq 'wheel-record-sha256') {
                if (-not $entries.ContainsKey($artifact.metadata)) {
                    Fail-Runtime "ASTRO_CUDA13_WHEEL_METADATA" "artifact $($artifact.id) is missing $($artifact.metadata)" "report the changed upstream wheel and update the lock deliberately"
                }
                $metadata = Read-ZipEntryText $entries[$artifact.metadata]
                $escapedDistribution = [Regex]::Escape($artifact.distribution)
                $escapedVersion = [Regex]::Escape($artifact.version)
                if ($metadata -notmatch "(?m)^Name:\s*$escapedDistribution\s*`r?$" -or $metadata -notmatch "(?m)^Version:\s*$escapedVersion\s*`r?$") {
                    Fail-Runtime "ASTRO_CUDA13_WHEEL_METADATA" "artifact $($artifact.id) METADATA identity does not match the lock" "report the changed upstream wheel and update the lock deliberately"
                }
                $rows = Get-RecordRows $entries $artifact
                $manifestEntries = [long]$rows.Count
                $manifestEntriesVerified = [long]$rows.Count
            }
            elseif ($artifact.archive_verification -cne 'release-archive-sha256') {
                Fail-Runtime "ASTRO_CUDA13_ARCHIVE_VERIFICATION" "artifact $($artifact.id) has unsupported verification $($artifact.archive_verification)" "update the provisioner and lock schema together"
            }
            $payloads = @(@($Lock.files) | Where-Object { $_.artifact -ceq $artifact.id }) + @(@($Lock.notices) | Where-Object { $_.artifact -ceq $artifact.id })
            foreach ($payload in $payloads) {
                if (-not $entries.ContainsKey($payload.archive_path)) {
                    Fail-Runtime "ASTRO_CUDA13_ARCHIVE_PAYLOAD" "artifact $($artifact.id) is missing $($payload.archive_path)" "report the changed upstream archive and update the lock deliberately"
                }
                if ($artifact.archive_verification -ceq 'wheel-record-sha256') {
                    Assert-RecordRow $rows $payload $artifact.id
                }
                Expand-LockedPayload $entries[$payload.archive_path] $payload $bundleRoot
                if ($payload.PSObject.Properties.Name -contains 'authenticode') {
                    $destination = Join-Path $bundleRoot ($payload.bundle_path.Replace('/', '\'))
                    Assert-Authenticode $destination $payload
                }
            }
            $artifactReceipt += [ordered]@{
                id = $artifact.id
                filename = $artifact.filename
                bytes = [long]$artifact.bytes
                sha256 = $artifact.sha256
                verification = $artifact.archive_verification
                archive_entries = [long]$entries.Count
                manifest_entries = $manifestEntries
                manifest_entries_verified = $manifestEntriesVerified
                locked_payloads_verified = [long]$payloads.Count
            }
        }
        finally {
            $archive.Dispose()
        }
        Remove-Item -LiteralPath $archivePath -Force
    }

    [System.IO.File]::WriteAllBytes((Join-Path $bundleRoot 'bundle.lock.json'), [System.IO.File]::ReadAllBytes($LockPath))
    [System.IO.File]::WriteAllText((Join-Path $bundleRoot 'bundle.lock.sha256'), "$LockSha256`n", $Utf8NoBom)

    $fileReceipt = @()
    foreach ($file in @($Lock.files) | Sort-Object bundle_path) {
        $fileReceipt += [ordered]@{
            path = $file.bundle_path
            bytes = [long]$file.bytes
            sha256 = $file.sha256
            file_version = $file.file_version
            authenticode = [ordered]@{
                status = $file.authenticode.status
                subject = $file.authenticode.subject
                thumbprint = $file.authenticode.thumbprint
            }
        }
    }
    $noticeReceipt = @()
    foreach ($notice in @($Lock.notices) | Sort-Object bundle_path) {
        $noticeReceipt += [ordered]@{
            path = $notice.bundle_path
            bytes = [long]$notice.bytes
            sha256 = $notice.sha256
        }
    }
    $receipt = [ordered]@{
        schema = $ReceiptSchema
        bundle_id = $Lock.bundle.id
        lock_sha256 = $LockSha256
        provisioned_at_utc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        artifacts = $artifactReceipt
        files = $fileReceipt
        notices = $noticeReceipt
    }
    $receiptPartial = Join-Path $bundleRoot 'bundle.receipt.json.partial'
    $receiptPath = Join-Path $bundleRoot 'bundle.receipt.json'
    [System.IO.File]::WriteAllText($receiptPartial, (($receipt | ConvertTo-Json -Depth 6) + "`n"), $Utf8NoBom)
    Move-Item -LiteralPath $receiptPartial -Destination $receiptPath -ErrorAction Stop
    return $bundleRoot
}

function Verify-Bundle {
    param(
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)]$Lock,
        [Parameter(Mandatory = $true)][string]$LockSha256
    )

    if (-not (Test-Path -LiteralPath $BundleRoot -PathType Container)) {
        Fail-Runtime "ASTRO_CUDA13_BUNDLE_MISSING" "immutable bundle root is missing: $BundleRoot" "rerun provisioning"
    }
    $rootItem = Get-Item -LiteralPath $BundleRoot -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Runtime "ASTRO_CUDA13_BUNDLE_REPARSE" "bundle root is a reparse point: $BundleRoot" "remove the redirected bundle and rerun provisioning"
    }
    foreach ($item in Get-ChildItem -LiteralPath $BundleRoot -Force -Recurse) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-Runtime "ASTRO_CUDA13_BUNDLE_REPARSE" "bundle contains reparse point $($item.FullName)" "remove the redirected bundle and rerun provisioning"
        }
    }

    $installedLock = Join-Path $BundleRoot 'bundle.lock.json'
    if ((Get-Sha256Hex $installedLock) -cne $LockSha256) {
        Fail-Runtime "ASTRO_CUDA13_BUNDLE_LOCK" "installed lock digest does not match $LockSha256" "remove the corrupted bundle and rerun provisioning"
    }
    $digestPath = Join-Path $BundleRoot 'bundle.lock.sha256'
    if (-not (Test-Path -LiteralPath $digestPath -PathType Leaf) -or [System.IO.File]::ReadAllText($digestPath, [Text.Encoding]::UTF8).Trim() -cne $LockSha256) {
        Fail-Runtime "ASTRO_CUDA13_BUNDLE_LOCK" "installed bundle.lock.sha256 is missing or mismatched" "remove the corrupted bundle and rerun provisioning"
    }

    $receiptPath = Join-Path $BundleRoot 'bundle.receipt.json'
    try {
        $receipt = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($receiptPath, [Text.Encoding]::UTF8))
    }
    catch {
        Fail-Runtime "ASTRO_CUDA13_RECEIPT" "cannot read installed receipt: $($_.Exception.Message)" "remove the incomplete bundle and rerun provisioning"
    }
    Assert-ExactFields $receipt @('schema', 'bundle_id', 'lock_sha256', 'provisioned_at_utc', 'artifacts', 'files', 'notices') 'receipt'
    if ($receipt.schema -cne $ReceiptSchema -or $receipt.bundle_id -cne $Lock.bundle.id -or $receipt.lock_sha256 -cne $LockSha256) {
        Fail-Runtime "ASTRO_CUDA13_RECEIPT" "installed receipt identity does not match the lock" "remove the incomplete bundle and rerun provisioning"
    }
    # PowerShell 7's JSON reader materializes ISO-8601 strings as DateTime,
    # while Windows PowerShell 5.1 leaves the same token as String. Normalize
    # both representations before applying the exact round-trip contract.
    if ($receipt.provisioned_at_utc -is [DateTime]) {
        $receiptTimestamp = $receipt.provisioned_at_utc.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
    elseif ($receipt.provisioned_at_utc -is [DateTimeOffset]) {
        $receiptTimestamp = $receipt.provisioned_at_utc.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
    elseif ($receipt.provisioned_at_utc -is [string]) {
        $receiptTimestamp = $receipt.provisioned_at_utc
    }
    else {
        $receiptTimestampType = if ($null -eq $receipt.provisioned_at_utc) { 'null' } else { $receipt.provisioned_at_utc.GetType().FullName }
        Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt provisioned_at_utc has unsupported CLR type $receiptTimestampType" "remove the incomplete bundle and rerun provisioning"
    }
    if ([string]::IsNullOrWhiteSpace($receiptTimestamp)) {
        Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt provisioned_at_utc is blank" "remove the incomplete bundle and rerun provisioning"
    }
    $parsedTimestamp = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact($receiptTimestamp, 'o', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsedTimestamp)) {
        Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt provisioned_at_utc is not a valid round-trip timestamp" "remove the incomplete bundle and rerun provisioning"
    }

    $receiptArtifacts = @{}
    foreach ($artifact in @($receipt.artifacts)) {
        Assert-ExactFields $artifact @('id', 'filename', 'bytes', 'sha256', 'verification', 'archive_entries', 'manifest_entries', 'manifest_entries_verified', 'locked_payloads_verified') 'receipt.artifacts[]'
        if ($receiptArtifacts.ContainsKey($artifact.id)) {
            Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt contains duplicate artifact $($artifact.id)" "remove the incomplete bundle and rerun provisioning"
        }
        $receiptArtifacts.Add($artifact.id, $artifact)
    }
    foreach ($lockedArtifact in @($Lock.artifacts)) {
        if (-not $receiptArtifacts.ContainsKey($lockedArtifact.id)) {
            Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt is missing artifact $($lockedArtifact.id)" "remove the incomplete bundle and rerun provisioning"
        }
        $artifact = $receiptArtifacts[$lockedArtifact.id]
        $lockedCount = (@(@($Lock.files) | Where-Object { $_.artifact -ceq $lockedArtifact.id })).Count + (@(@($Lock.notices) | Where-Object { $_.artifact -ceq $lockedArtifact.id })).Count
        $wheelManifestValid = $artifact.verification -cne 'wheel-record-sha256' -or ([long]$artifact.archive_entries -eq [long]$artifact.manifest_entries -and [long]$artifact.manifest_entries_verified -eq [long]$artifact.manifest_entries -and [long]$artifact.manifest_entries -ge $lockedCount)
        $releaseManifestValid = $artifact.verification -cne 'release-archive-sha256' -or ([long]$artifact.manifest_entries -eq 0 -and [long]$artifact.manifest_entries_verified -eq 0 -and [long]$artifact.archive_entries -ge $lockedCount)
        if ($artifact.filename -cne $lockedArtifact.filename -or [long]$artifact.bytes -ne [long]$lockedArtifact.bytes -or $artifact.sha256 -cne $lockedArtifact.sha256 -or $artifact.verification -cne $lockedArtifact.archive_verification -or [long]$artifact.locked_payloads_verified -ne $lockedCount -or -not $wheelManifestValid -or -not $releaseManifestValid) {
            Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt artifact facts do not match lock for $($lockedArtifact.id)" "remove the incomplete bundle and rerun provisioning"
        }
        $null = $receiptArtifacts.Remove($lockedArtifact.id)
    }
    if ($receiptArtifacts.Count -ne 0) {
        Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt contains artifacts absent from the lock" "remove the contaminated bundle and rerun provisioning"
    }

    $receiptFiles = @{}
    foreach ($file in @($receipt.files)) {
        Assert-ExactFields $file @('path', 'bytes', 'sha256', 'file_version', 'authenticode') 'receipt.files[]'
        Assert-ExactFields $file.authenticode @('status', 'subject', 'thumbprint') "receipt.files.$($file.path).authenticode"
        if ($receiptFiles.ContainsKey($file.path)) {
            Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt contains duplicate file $($file.path)" "remove the incomplete bundle and rerun provisioning"
        }
        $receiptFiles.Add($file.path, $file)
    }
    foreach ($lockedFile in @($Lock.files)) {
        if (-not $receiptFiles.ContainsKey($lockedFile.bundle_path)) {
            Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt is missing file $($lockedFile.bundle_path)" "remove the incomplete bundle and rerun provisioning"
        }
        $file = $receiptFiles[$lockedFile.bundle_path]
        $versionMatches = ($null -eq $file.file_version -and $null -eq $lockedFile.file_version) -or ($null -ne $file.file_version -and $null -ne $lockedFile.file_version -and $file.file_version -ceq $lockedFile.file_version)
        if ([long]$file.bytes -ne [long]$lockedFile.bytes -or $file.sha256 -cne $lockedFile.sha256 -or -not $versionMatches -or $file.authenticode.status -cne $lockedFile.authenticode.status -or $file.authenticode.subject -cne $lockedFile.authenticode.subject -or $file.authenticode.thumbprint -cne $lockedFile.authenticode.thumbprint) {
            Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt file facts do not match lock for $($lockedFile.bundle_path)" "remove the incomplete bundle and rerun provisioning"
        }
        $null = $receiptFiles.Remove($lockedFile.bundle_path)
    }
    if ($receiptFiles.Count -ne 0) {
        Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt contains files absent from the lock" "remove the contaminated bundle and rerun provisioning"
    }

    $receiptNotices = @{}
    foreach ($notice in @($receipt.notices)) {
        Assert-ExactFields $notice @('path', 'bytes', 'sha256') 'receipt.notices[]'
        if ($receiptNotices.ContainsKey($notice.path)) {
            Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt contains duplicate notice $($notice.path)" "remove the incomplete bundle and rerun provisioning"
        }
        $receiptNotices.Add($notice.path, $notice)
    }
    foreach ($lockedNotice in @($Lock.notices)) {
        if (-not $receiptNotices.ContainsKey($lockedNotice.bundle_path)) {
            Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt is missing notice $($lockedNotice.bundle_path)" "remove the incomplete bundle and rerun provisioning"
        }
        $notice = $receiptNotices[$lockedNotice.bundle_path]
        if ([long]$notice.bytes -ne [long]$lockedNotice.bytes -or $notice.sha256 -cne $lockedNotice.sha256) {
            Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt notice facts do not match lock for $($lockedNotice.bundle_path)" "remove the incomplete bundle and rerun provisioning"
        }
        $null = $receiptNotices.Remove($lockedNotice.bundle_path)
    }
    if ($receiptNotices.Count -ne 0) {
        Fail-Runtime "ASTRO_CUDA13_RECEIPT" "receipt contains notices absent from the lock" "remove the contaminated bundle and rerun provisioning"
    }

    $expectedPaths = @{}
    foreach ($file in @($Lock.files)) {
        $path = Join-Path $BundleRoot ($file.bundle_path.Replace('/', '\'))
        Assert-FileBytes $path $file.bytes $file.sha256 "bundle file $($file.bundle_path)"
        Assert-Authenticode $path $file
        $expectedPaths.Add($file.bundle_path, $true)
    }
    foreach ($notice in @($Lock.notices)) {
        $path = Join-Path $BundleRoot ($notice.bundle_path.Replace('/', '\'))
        Assert-FileBytes $path $notice.bytes $notice.sha256 "bundle notice $($notice.bundle_path)"
        $expectedPaths.Add($notice.bundle_path, $true)
    }
    foreach ($name in @('bundle.lock.json', 'bundle.lock.sha256', 'bundle.receipt.json')) {
        $expectedPaths.Add($name, $true)
    }

    $actualFiles = @(Get-ChildItem -LiteralPath $BundleRoot -Force -File -Recurse)
    foreach ($file in $actualFiles) {
        $relative = Get-RelativeChildPath $BundleRoot $file.FullName
        if (-not $expectedPaths.ContainsKey($relative)) {
            Fail-Runtime "ASTRO_CUDA13_BUNDLE_EXTRA" "immutable bundle contains unexpected file $relative" "remove the contaminated bundle and rerun provisioning"
        }
        $null = $expectedPaths.Remove($relative)
    }
    if ($expectedPaths.Count -ne 0) {
        $missing = @($expectedPaths.Keys) | Sort-Object
        Fail-Runtime "ASTRO_CUDA13_BUNDLE_MISSING" "immutable bundle is missing: $($missing -join ', ')" "remove the incomplete bundle and rerun provisioning"
    }
}

function Remove-OwnedStage {
    param(
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [Parameter(Mandatory = $true)][string]$CanonicalToolchainsRoot
    )

    if (-not (Test-Path -LiteralPath $StageRoot)) {
        return
    }
    $stageItem = Get-Item -LiteralPath $StageRoot -Force
    if (-not $stageItem.PSIsContainer -or ($stageItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Runtime "ASTRO_CUDA13_STAGE_OWNERSHIP" "refusing cleanup of non-directory or redirected stage $StageRoot" "inspect and remove only the invalid owned stage manually"
    }
    $resolvedStage = (Resolve-Path -LiteralPath $StageRoot).ProviderPath.TrimEnd('\')
    $stageParent = Split-Path -Parent $resolvedStage
    $stageName = Split-Path -Leaf $resolvedStage
    $expectedPrefix = '.installing-ort-cuda13-' + $PID + '-'
    if (-not [string]::Equals($stageParent, $CanonicalToolchainsRoot, [StringComparison]::OrdinalIgnoreCase) -or -not $stageName.StartsWith($expectedPrefix, [StringComparison]::Ordinal) -or $stageName.Substring($expectedPrefix.Length) -cnotmatch '^[0-9a-f]{32}$') {
        Fail-Runtime "ASTRO_CUDA13_STAGE_OWNERSHIP" "refusing cleanup of stage not owned by PID $PID under canonical .toolchains: $resolvedStage" "inspect the stage ownership before cleanup"
    }
    foreach ($item in Get-ChildItem -LiteralPath $resolvedStage -Force -Recurse) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-Runtime "ASTRO_CUDA13_STAGE_OWNERSHIP" "refusing cleanup because owned stage contains reparse point $($item.FullName)" "inspect and remove only the invalid owned stage manually"
        }
    }
    Remove-Item -LiteralPath $resolvedStage -Recurse -Force
}

function Invoke-ObsoleteBundleRetirement {
    # Retire obsolete sibling bundle roots after active-bundle attestation. Retirement is a
    # provisioning invariant: every foreign/unevaluable consumer, transition fault, inventory
    # change, or evidence-publication failure throws a structured error. Continuing would turn
    # an observable correctness fault back into the permanent silent leak fixed by #614.
    param(
        [Parameter(Mandatory = $true)][string]$Toolchains,
        [Parameter(Mandatory = $true)]$Lock,
        [Parameter(Mandatory = $true)][string]$LockSha256,
        [Parameter(Mandatory = $true)][string]$Workspace
    )

    $retirement = Remove-AstroObsoleteCudaBundleRoots `
        -ToolchainsRoot $Toolchains `
        -RootPrefix $Lock.bundle.root_prefix `
        -ActiveDigest $LockSha256 `
        -WorkspaceRoot $Workspace `
        -GitExe $launcherGitFull `
        -DrivingIssue $LauncherIssue `
        -CallerSelf $launcherSelf
    if ($retirement.State -cne 'completed') {
        Fail-Runtime `
            'ASTRO_CUDA13_RETIRE_RESULT_INVALID' `
            "retirement returned unexpected state '$($retirement.State)'" `
            'preserve all protocol/evidence bytes and repair the retirement helper'
    }
}

$workspace = Get-FullPath $WorkspaceRoot
if (-not [string]::Equals($workspace, $CanonicalWorkspace, [StringComparison]::OrdinalIgnoreCase)) {
    Fail-Runtime "ASTRO_CUDA13_WORKSPACE" "workspace must be the canonical checkout $CanonicalWorkspace, got $workspace" "run from the canonical Astrolabe checkout"
}
if (-not (Test-Path -LiteralPath $workspace -PathType Container)) {
    Fail-Runtime "ASTRO_CUDA13_WORKSPACE" "workspace does not exist: $workspace" "run from the canonical Astrolabe checkout"
}
$workspace = (Resolve-Path -LiteralPath $workspace).ProviderPath.TrimEnd('\')
if (-not [string]::Equals($workspace, $CanonicalWorkspace, [StringComparison]::OrdinalIgnoreCase)) {
    Fail-Runtime "ASTRO_CUDA13_WORKSPACE" "workspace resolves outside canonical checkout: $workspace" "remove the redirected checkout path and retry"
}
$expectedScriptRoot = Get-FullPath (Join-Path $workspace 'scripts')
if (-not [string]::Equals((Get-FullPath $PSScriptRoot), $expectedScriptRoot, [StringComparison]::OrdinalIgnoreCase)) {
    Fail-Runtime "ASTRO_CUDA13_WORKSPACE" "provisioner is not running from $expectedScriptRoot" "run the checked-in provisioner from the canonical Astrolabe checkout"
}

$expectedToolchains = Get-FullPath (Join-Path $workspace '.toolchains')
if ([string]::IsNullOrWhiteSpace($ToolchainsRoot)) {
    $toolchains = $expectedToolchains
}
else {
    $toolchains = Get-FullPath $ToolchainsRoot
}
if (-not [string]::Equals($toolchains, $expectedToolchains, [StringComparison]::OrdinalIgnoreCase)) {
    Fail-Runtime "ASTRO_CUDA13_TOOLCHAINS_ROOT" "ToolchainsRoot must be the canonical workspace .toolchains directory: $expectedToolchains" "pass the canonical .toolchains root"
}
New-Item -ItemType Directory -Path $toolchains -Force | Out-Null
$toolchains = (Resolve-Path -LiteralPath $toolchains).ProviderPath.TrimEnd('\')
if (-not [string]::Equals($toolchains, $expectedToolchains, [StringComparison]::OrdinalIgnoreCase)) {
    Fail-Runtime "ASTRO_CUDA13_TOOLCHAINS_ROOT" "canonical .toolchains resolves to $toolchains instead of $expectedToolchains" "remove the redirected .toolchains path and retry"
}
$toolchainsItem = Get-Item -LiteralPath $toolchains -Force
if (($toolchainsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail-Runtime "ASTRO_CUDA13_TOOLCHAINS_ROOT" "canonical .toolchains is a reparse point" "remove the redirected .toolchains path and retry"
}

$lockPath = Join-Path $expectedScriptRoot (Join-Path 'toolchains' $LockFileName)
if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
    Fail-Runtime "ASTRO_CUDA13_LOCK_MISSING" "checked-in lock is missing: $lockPath" "restore $LockFileName from the repository"
}
$lock = Read-Lock $lockPath
$lockSha256 = Get-Sha256Hex $lockPath
$finalRoot = Join-Path $toolchains ($lock.bundle.root_prefix + '-' + $lockSha256)

if (Test-Path -LiteralPath $finalRoot) {
    Verify-Bundle $finalRoot $lock $lockSha256
    Invoke-ObsoleteBundleRetirement $toolchains $lock $lockSha256 $workspace
    Write-Output (Resolve-Path -LiteralPath $finalRoot).ProviderPath
    return
}

$system32Root = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$curlExe = Join-Path $system32Root 'curl.exe'
if (-not (Test-Path -LiteralPath $curlExe -PathType Leaf)) {
    Fail-Runtime "ASTRO_CUDA13_CURL_MISSING" "pinned Windows curl.exe is missing at $curlExe" "restore the Windows curl component and retry"
}

$stageRoot = Join-Path $toolchains ('.installing-ort-cuda13-' + $PID + '-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $stageRoot -ErrorAction Stop | Out-Null
    $stagedBundle = Install-Bundle $lock $lockPath $lockSha256 $stageRoot $curlExe
    Verify-Bundle $stagedBundle $lock $lockSha256

    if (-not (Test-Path -LiteralPath $finalRoot)) {
        try {
            Move-Item -LiteralPath $stagedBundle -Destination $finalRoot -ErrorAction Stop
        }
        catch {
            if (-not (Test-Path -LiteralPath $finalRoot -PathType Container)) {
                throw
            }
            Write-Verbose "another provisioner installed the same immutable bundle first"
        }
    }
    Verify-Bundle $finalRoot $lock $lockSha256
    Invoke-ObsoleteBundleRetirement $toolchains $lock $lockSha256 $workspace
    Write-Output (Resolve-Path -LiteralPath $finalRoot).ProviderPath
}
finally {
    Remove-OwnedStage $stageRoot $toolchains
}
