[CmdletBinding()]
param(
    [ValidateSet("portable", "full", "release")]
    [string]$Gate = "full",
    [switch]$UnboundedWorkspaceTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ExpectedWorkspace = "C:\code\Astrolabe"
if ($env:OS -ne "Windows_NT") {
    throw "invoke-native-aggregate.ps1 is native Windows only"
}
if ($env:WSL_DISTRO_NAME -or $env:WSL_INTEROP) {
    throw "EXECUTION_BOUNDARY[ASTRO_NATIVE_CONTEXT_REQUIRED]: run from native Windows PowerShell"
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not [string]::Equals($root, $ExpectedWorkspace, [StringComparison]::OrdinalIgnoreCase)) {
    throw "canonical workspace required: $ExpectedWorkspace (found $root)"
}
Set-Location -LiteralPath $root

$launcher = Join-Path $root "scripts\windows-gnu-toolchain.ps1"
$gitBash = "C:\Program Files\Git\bin\bash.exe"
foreach ($path in @($launcher, $gitBash)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "required native aggregate executable is missing: $path"
    }
}

$gateScripts = @{
    portable = "scripts/check.sh"
    full = "scripts/check-full.sh"
    release = "scripts/check-release.sh"
}
if ($UnboundedWorkspaceTests -and $Gate -ne "full") {
    throw "-UnboundedWorkspaceTests is valid only with -Gate full"
}

$previousTimeout = Get-Item -Path "Env:ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS" -ErrorAction SilentlyContinue
$commandExit = 0
try {
    if ($UnboundedWorkspaceTests) {
        $env:ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS = "0"
    }
    Write-Output "NATIVE_AGGREGATE[ASTRO_STDOUT_ONLY]: gate=$Gate; evidence is streamed to the invoking process; no log file is created"
    $commandArgsJson = ConvertTo-Json -InputObject @($gateScripts[$Gate]) -Compress
    & $launcher -Command $gitBash -CommandArgsJson $commandArgsJson
    if ($null -ne $LASTEXITCODE) {
        $commandExit = $LASTEXITCODE
    }
}
finally {
    if ($null -eq $previousTimeout) {
        Remove-Item -Path "Env:ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS" -ErrorAction SilentlyContinue
    }
    else {
        $env:ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS = $previousTimeout.Value
    }
}

if ($commandExit -ne 0) {
    exit $commandExit
}
