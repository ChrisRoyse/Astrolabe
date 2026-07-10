[CmdletBinding()]
param(
    [switch]$Bootstrap,
    [string]$Command,
    [string]$CommandArgsJson = "[]"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ExpectedWorkspace = "C:\code\Astrolabe"
$RustToolchain = "1.95.0-x86_64-pc-windows-gnu"
$ArchiveName = "x86_64-14.1.0-release-posix-seh-msvcrt-rt_v12-rev0.7z"
$ArchiveUrl = "https://ci-mirrors.rust-lang.org/rustc/$ArchiveName"
$ArchiveSha256 = "BC0DE4321141730E83FD2457B1F7639946CC66787BF98BA9B03770D06D414DF1"
$ToolchainDirectoryName = "mingw-14.1.0-posix-seh-msvcrt-rt_v12-rev0"
$ExpectedGccVersion = "14.1.0"
$ExpectedGccTriple = "x86_64-w64-mingw32"
$ExpectedMakeSha256 = "35F7A48546FC3A64B39E3B6AB13CBBCDBF2DAC9C79707714858975E94C7E8A0B"
$RequiredTools = @(
    "gcc.exe",
    "g++.exe",
    "ar.exe",
    "ld.exe",
    "nm.exe",
    "objcopy.exe",
    "mingw32-make.exe",
    "make.exe"
)
$RuntimeDlls = @("libgcc_s_seh-1.dll", "libwinpthread-1.dll")

function Require-Path {
    param([string]$Path, [string]$Message)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "${Message}: $Path"
    }
}

function Require-Success {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

function Get-SevenZip {
    $candidates = @(
        (Join-Path $env:ProgramFiles "7-Zip\7z.exe"),
        "C:\Program Files\7-Zip\7z.exe"
    ) | Select-Object -Unique
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    $command = Get-Command 7z.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }
    throw "7-Zip is required only for -Bootstrap; install a native Windows 7-Zip package and retry"
}

function Install-PinnedToolchain {
    param([string]$ToolsRoot, [string]$MingwRoot)

    if (Test-Path -LiteralPath $MingwRoot) {
        return
    }

    New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null
    $staging = Join-Path $ToolsRoot ".installing-$PID"
    try {
        New-Item -ItemType Directory -Path $staging -ErrorAction Stop | Out-Null
        $archive = Join-Path $staging $ArchiveName
        & curl.exe --fail --location --retry 3 --output $archive $ArchiveUrl
        Require-Success "download of $ArchiveName"

        $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash
        if ($actualHash -ne $ArchiveSha256) {
            throw "pinned MinGW archive hash mismatch: expected $ArchiveSha256, got $actualHash"
        }

        $sevenZip = Get-SevenZip
        & $sevenZip x "-o$staging" $archive | Out-Null
        Require-Success "extraction of $ArchiveName"

        $extractedRoot = Join-Path $staging "mingw64"
        Require-Path (Join-Path $extractedRoot "bin\gcc.exe") "archive did not contain the expected MinGW root"
        if (Test-Path -LiteralPath $MingwRoot) {
            throw "pinned MinGW destination appeared during installation: $MingwRoot"
        }
        Move-Item -LiteralPath $extractedRoot -Destination $MingwRoot
    }
    finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Recurse -Force
        }
    }
}

function Ensure-BundledMakeAlias {
    param([string]$MingwBin)

    $source = Join-Path $MingwBin "mingw32-make.exe"
    $alias = Join-Path $MingwBin "make.exe"
    Require-Path $source "pinned MinGW GNU Make is missing"

    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash
    if ($sourceHash -ne $ExpectedMakeSha256) {
        throw "pinned MinGW GNU Make hash mismatch: expected $ExpectedMakeSha256, got $sourceHash"
    }

    if (Test-Path -LiteralPath $alias) {
        if (-not (Test-Path -LiteralPath $alias -PathType Leaf)) {
            throw "pinned GNU Make alias is not a file: $alias"
        }
        $aliasHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $alias).Hash
        if ($aliasHash -ne $ExpectedMakeSha256) {
            Remove-Item -LiteralPath $alias -Force
        }
    }
    if (-not (Test-Path -LiteralPath $alias -PathType Leaf)) {
        Copy-Item -LiteralPath $source -Destination $alias
    }

    $aliasHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $alias).Hash
    if ($aliasHash -ne $ExpectedMakeSha256) {
        throw "pinned GNU Make alias hash mismatch: expected $ExpectedMakeSha256, got $aliasHash"
    }
}

function Set-ToolchainEnvironment {
    param([string]$MingwBin, [string]$GitBin, [string]$GitUsrBin)

    $env:PATH = "$MingwBin;$GitUsrBin;$GitBin;$env:PATH"
    $env:SHELL = Join-Path $GitUsrBin "sh.exe"
    $env:RUSTUP_TOOLCHAIN = $RustToolchain
    $env:MAKE = Join-Path $MingwBin "make.exe"
    $env:CC = Join-Path $MingwBin "gcc.exe"
    $env:CXX = Join-Path $MingwBin "g++.exe"
    $env:AR = Join-Path $MingwBin "ar.exe"
    $env:LD = Join-Path $MingwBin "ld.exe"
    $env:NM = Join-Path $MingwBin "nm.exe"
    $env:OBJCOPY = Join-Path $MingwBin "objcopy.exe"
}

function Set-WorkspaceTempEnvironment {
    param([string]$WorkspaceTemp)

    $env:TEMP = $WorkspaceTemp
    $env:TMP = $WorkspaceTemp
    $env:TMPDIR = $WorkspaceTemp
}

function Test-PinnedToolchain {
    param([string]$MingwBin)

    foreach ($tool in $RequiredTools) {
        Require-Path (Join-Path $MingwBin $tool) "pinned MinGW tool is missing"
    }
    foreach ($dll in $RuntimeDlls) {
        Require-Path (Join-Path $MingwBin $dll) "pinned MinGW runtime DLL is missing"
    }

    $gccVersion = (& $env:CC --version) -join "`n"
    Require-Success "gcc version check"
    if ($gccVersion -notmatch [regex]::Escape($ExpectedGccVersion)) {
        throw "unexpected GCC version; expected $ExpectedGccVersion, got: $gccVersion"
    }
    $gccTriple = (& $env:CC -dumpmachine).Trim()
    Require-Success "gcc target check"
    if ($gccTriple -ne $ExpectedGccTriple) {
        throw "unexpected GCC target; expected $ExpectedGccTriple, got $gccTriple"
    }

    $rustup = Get-Command rustup.exe -ErrorAction SilentlyContinue
    if ($null -eq $rustup) {
        $rustup = Get-Command rustup -ErrorAction SilentlyContinue
    }
    if ($null -eq $rustup) {
        throw "rustup is required; install the pinned $RustToolchain host before retrying"
    }
    $rustInfo = (& $rustup.Source run $RustToolchain rustc -vV) -join "`n"
    Require-Success "Rust host check"
    if ($rustInfo -notmatch "host: x86_64-pc-windows-gnu") {
        throw "unexpected Rust host; expected x86_64-pc-windows-gnu, got: $rustInfo"
    }
    $rustSysroot = (& $rustup.Source run $RustToolchain rustc --print sysroot).Trim()
    Require-Success "Rust toolchain lookup"
    $rustBin = Join-Path $rustSysroot "bin"
    foreach ($dll in $RuntimeDlls) {
        $mingwHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $MingwBin $dll)).Hash
        $rustHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $rustBin $dll)).Hash
        if ($mingwHash -ne $rustHash) {
            throw "runtime DLL mismatch for $dll; refusing a mixed MinGW runtime"
        }
    }

    & $env:MAKE --version | Out-Null
    Require-Success "GNU Make check"
}

if ($env:OS -ne "Windows_NT") {
    throw "windows-gnu-toolchain.ps1 is native Windows only"
}
if ($env:WSL_DISTRO_NAME) {
    throw "WSL execution is forbidden; run this launcher from native Windows PowerShell"
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not [string]::Equals($root, $ExpectedWorkspace, [StringComparison]::OrdinalIgnoreCase)) {
    throw "canonical workspace required: $ExpectedWorkspace (found $root)"
}
Set-Location -LiteralPath $root
$target = Join-Path $root "target"
$workspaceTemp = Join-Path $target "tmp"
if (Test-Path -LiteralPath $target) {
    throw "target must be absent before toolchain work: $target"
}

$toolsRoot = Join-Path $root ".toolchains"
$mingwRoot = Join-Path $toolsRoot $ToolchainDirectoryName
$mingwBin = Join-Path $mingwRoot "bin"
$gitBin = "C:\Program Files\Git\bin"
$gitUsrBin = "C:\Program Files\Git\usr\bin"
Require-Path (Join-Path $gitBin "bash.exe") "native Git for Windows Bash is required"
Require-Path (Join-Path $gitUsrBin "sh.exe") "native Git for Windows shell is required"

if ($Bootstrap) {
    Install-PinnedToolchain -ToolsRoot $toolsRoot -MingwRoot $mingwRoot
}
Require-Path (Join-Path $mingwBin "gcc.exe") "pinned MinGW toolchain is missing; rerun with -Bootstrap"
Ensure-BundledMakeAlias -MingwBin $mingwBin
Set-ToolchainEnvironment -MingwBin $mingwBin -GitBin $gitBin -GitUsrBin $gitUsrBin
Test-PinnedToolchain -MingwBin $mingwBin
Write-Output "WINDOWS_GNU_TOOLCHAIN: Rust $RustToolchain, GCC $ExpectedGccVersion, runtime $mingwBin"

if ([string]::IsNullOrWhiteSpace($Command)) {
    Write-Output 'Ready. Example: .\scripts\windows-gnu-toolchain.ps1 -Command cargo -CommandArgsJson ''["test","-p","cbm-sys","--lib"]'''
    exit 0
}

$commandArgs = @(ConvertFrom-Json -InputObject $CommandArgsJson)
foreach ($argument in $commandArgs) {
    if ($argument -isnot [string]) {
        throw "CommandArgsJson must contain only strings"
    }
}

$commandExit = 0
$previousTempEnvironment = @{}
foreach ($name in @("TEMP", "TMP", "TMPDIR")) {
    $previousTempEnvironment[$name] = Get-Item -Path "Env:$name" -ErrorAction SilentlyContinue
}
try {
    Set-WorkspaceTempEnvironment -WorkspaceTemp $workspaceTemp
    New-Item -ItemType Directory -Path $workspaceTemp -Force | Out-Null
    & $Command @commandArgs
    if ($null -ne $LASTEXITCODE) {
        $commandExit = $LASTEXITCODE
    }
}
finally {
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
    if (Test-Path -LiteralPath $target) {
        throw "target cleanup failed: $target remains"
    }
    foreach ($name in @("TEMP", "TMP", "TMPDIR")) {
        $previous = $previousTempEnvironment[$name]
        if ($null -eq $previous) {
            Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
        }
        else {
            Set-Item -Path "Env:$name" -Value $previous.Value
        }
    }
    Write-Output "CLEANUP[ASTRO_TARGET]: $target is absent"
}

if ($commandExit -ne 0) {
    exit $commandExit
}
