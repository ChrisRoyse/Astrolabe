[CmdletBinding()]
param(
    [switch]$Bootstrap,
    [string]$Command,
    [string]$CommandArgsJson = "[]"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
# #239: exit-code fidelity depends on native commands reporting through $LASTEXITCODE
# and NOT raising terminating errors. PowerShell 7.3+ exposes
# $PSNativeCommandUseErrorActionPreference; when it is $true, a native command that
# exits non-zero throws under $ErrorActionPreference='Stop'. That would convert the
# child command's real exit code (say 42) into a generic terminating error -> exit 1,
# and it would make every $LASTEXITCODE check in this script (Require-Success and the
# sccache lifecycle below) unreachable. Pin it off so exit codes are data, not errors.
# Windows PowerShell 5.1 ignores the variable; assigning it there is inert.
$PSNativeCommandUseErrorActionPreference = $false

# #239: module-independent SHA-256 so the launcher's toolchain-bundle verification does
# not depend on Get-FileHash autoloading Microsoft.PowerShell.Utility. A fresh child
# PowerShell whose inherited PSModulePath cannot resolve that module raised a raw
# CommandNotFoundException on Get-FileHash -- the launcher then died with a generic exit
# 1 instead of the child's real exit code. This uses the same .NET SHA-256 Get-FileHash
# wraps and returns a .Hash property with byte-identical uppercase hex (verified -ceq),
# so every pinned-hash comparison below is unchanged.
function Get-Sha256Hex {
    param([Parameter(Mandatory)][string]$LiteralPath)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($LiteralPath)
        try {
            $hex = [System.BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', ''
        }
        finally { $stream.Dispose() }
    }
    finally { $sha.Dispose() }
    return [pscustomobject]@{ Hash = $hex }
}

# #239: launcher-owned exit codes. These are protocol codes, not measurements. The
# launcher's exit code is ALWAYS the child command's exit code when the child ran and
# cleanup succeeded; these two codes are reserved for the cases where there is no child
# exit code to report (launcher fault) or where reporting the child's green would hide a
# hygiene violation (cleanup failure after a green child). Both are announced on stderr
# with a named boundary label so they can never be confused with a child's own code.
$LauncherFaultExitCode = 70
$LauncherCleanupFailedExitCode = 71

$ExpectedWorkspace = "C:\code\Astrolabe"
$RustToolchain = "1.95.0-x86_64-pc-windows-gnu"
$ArchiveName = "x86_64-14.1.0-release-posix-seh-msvcrt-rt_v12-rev0.7z"
$ArchiveUrl = "https://ci-mirrors.rust-lang.org/rustc/$ArchiveName"
$ArchiveSha256 = "BC0DE4321141730E83FD2457B1F7639946CC66787BF98BA9B03770D06D414DF1"
$ToolchainDirectoryName = "mingw-14.1.0-posix-seh-msvcrt-rt_v12-rev0"
$ExpectedGccVersion = "14.1.0"
$ExpectedGccTriple = "x86_64-w64-mingw32"
$ExpectedMakeSha256 = "35F7A48546FC3A64B39E3B6AB13CBBCDBF2DAC9C79707714858975E94C7E8A0B"
$LlvmArchiveName = "clang+llvm-20.1.8-x86_64-pc-windows-msvc.tar.xz"
$LlvmArchiveUrl = "https://github.com/llvm/llvm-project/releases/download/llvmorg-20.1.8/clang%2Bllvm-20.1.8-x86_64-pc-windows-msvc.tar.xz"
$LlvmArchiveSha256 = "F229769F11D6A6EDC8ADA599C0CDA964B7DEE6AB1A08C6CF9DD7F513E85B107F"
$LlvmDirectoryName = "llvm-20.1.8-x86_64-pc-windows-msvc"
$LlvmExtractedDirectoryName = "clang+llvm-20.1.8-x86_64-pc-windows-msvc"
$ExpectedClangTidyVersion = "20.1.8"
$CppcheckRepository = "https://github.com/cppcheck-opensource/cppcheck.git"
$CppcheckTag = "2.20.0"
$CppcheckCommit = "502C802A69C78F3D8CFD9973AA2108AE169C73B5"
$CppcheckDirectoryName = "cppcheck-2.20.0-x86_64-w64-mingw32"
$ExpectedCppcheckVersion = "2.20.0"
$RipgrepVersion = "14.1.1"
$RipgrepArchiveName = "ripgrep-14.1.1-x86_64-pc-windows-msvc.zip"
$RipgrepArchiveUrl = "https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-pc-windows-msvc.zip"
$ExpectedRipgrepSha256 = "D0F534024C42AFD6CB4D38907C25CD2B249B79BBE6CC1DBEE8E3E37C2B6E25A1"
$RipgrepDirectoryName = "ripgrep-14.1.1-x86_64-pc-windows-msvc"
$SccacheVersion = "0.16.0"
$SccacheArchiveName = "sccache-v0.16.0-x86_64-pc-windows-msvc.zip"
$SccacheArchiveUrl = "https://github.com/mozilla/sccache/releases/download/v0.16.0/sccache-v0.16.0-x86_64-pc-windows-msvc.zip"
$SccacheArchiveSha256 = "B8514ED7552E148B0A032114F745118DCB801791ADAFAFEAF9935E4BFB0EDF1B"
$SccacheDirectoryName = "sccache-0.16.0-x86_64-pc-windows-msvc"
$SccacheExtractedDirectoryName = "sccache-v0.16.0-x86_64-pc-windows-msvc"
$ExpectedSccacheVersion = "0.16.0"
# #190: content-addressed compiler-cache budget. The cache lives in a launcher-owned
# workspace-local dir that survives the target/ wipe, so this bounds on-disk growth.
$SccacheCacheSize = "20G"
# #242: the sccache local daemon must never idle-exit mid-run. Its default idle timeout
# is 600s; a long libcbm C build leaves rustc idle well past that, the daemon exits, and
# the next Rust phase fires N concurrent sccache clients (cargo's parallel rustc, further
# amplified by trybuild's NESTED cargo) that each auto-start a server on the same fixed
# port -- all but one lose the bind race and die with WSAEADDRINUSE (os error 10048).
# "0" means "run permanently" (mozilla/sccache docs/Configuration.md) and is a mode, not
# a tunable threshold: it removes the race condition rather than widening a window.
$SccacheIdleTimeout = "0"
# #242: stable per-root server port window. Ports must sit OUTSIDE the Windows dynamic
# (ephemeral) range -- `netsh int ipv4 show dynamicport tcp` reports 49152..65535 on this
# host, and `netsh int ipv4 show excludedportrange protocol=tcp` reserves several 100-port
# blocks inside it -- or a fixed listener can collide with an ephemeral/reserved port and
# fail to bind with the very same os error 10048 for reasons unrelated to sccache. The
# #226 derivation (49152 + hash % 16000) landed entirely inside that hazard. 20000..29999
# is in the registered range, below the ephemeral floor.
$SccacheServerPortBase = 20000
$SccacheServerPortSpan = 10000
$GitInstallRoot = "C:\Program Files\Git"
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
$RequiredLlvmTools = @("clang-tidy.exe", "clang-format.exe")

function Require-Path {
    param([string]$Path, [string]$Message)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "${Message}: $Path"
    }
}

function Remove-LauncherLockFile {
    param([string]$LockPath)
    if (Test-Path -LiteralPath $LockPath) {
        Remove-Item -LiteralPath $LockPath -Force
    }
    if (Test-Path -LiteralPath $LockPath) {
        throw "launcher lock cleanup failed: $LockPath remains"
    }
}

function Test-PathUnderRoot {
    param([string]$Path, [string]$Root)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }
    $rootPrefix = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    $fullPath = [IO.Path]::GetFullPath($Path)
    return $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-AllowedBashCommand {
    param([string]$Command, [string]$GitRoot)

    if ([string]::IsNullOrWhiteSpace($Command)) {
        return
    }
    $leaf = [IO.Path]::GetFileName($Command)
    if ($leaf -notin @("bash", "bash.exe")) {
        return
    }
    if ([IO.Path]::IsPathRooted($Command) -or $Command.Contains("\") -or $Command.Contains("/")) {
        $resolved = (Resolve-Path -LiteralPath $Command -ErrorAction Stop).Path
        if (-not (Test-PathUnderRoot -Path $resolved -Root $GitRoot)) {
            throw "EXECUTION_BOUNDARY[ASTRO_BASH_COMMAND_FORBIDDEN]: Bash command must resolve under $GitRoot, found $resolved"
        }
    }
}

function Require-Success {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

function Invoke-NativeCapture {
    <#
      #239: run a native command and return its exit code AS DATA.

      Windows PowerShell 5.1 converts anything a native command writes to stderr into an
      ErrorRecord; under $ErrorActionPreference='Stop' that ErrorRecord is TERMINATING. So
      `& sccache --stop-server` -- which prints "couldn't connect to server" on stderr and
      exits 2 when the daemon has already idle-exited -- does not merely leak an exit code,
      it can abort the launcher outright, even with `*> $null` attached. Neither the exit
      code nor a stderr line from a cleanup step may decide this script's fate.

      Drop to 'Continue' for the duration of the call so stderr is output, not an exception,
      and hand the caller the exit code and the merged output to adjudicate explicitly.
    #>
    param([string]$Exe, [string[]]$Arguments)

    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $Exe @Arguments 2>&1
        $exitCode = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = @($output | ForEach-Object { "$_" })
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

        $actualHash = (Get-Sha256Hex -LiteralPath $archive).Hash
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

function Install-PinnedLlvm {
    param([string]$ToolsRoot, [string]$LlvmRoot)

    if (Test-Path -LiteralPath $LlvmRoot) {
        return
    }

    New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null
    $staging = Join-Path $ToolsRoot ".installing-llvm-$PID"
    try {
        New-Item -ItemType Directory -Path $staging -ErrorAction Stop | Out-Null
        $archive = Join-Path $staging $LlvmArchiveName
        & curl.exe --fail --location --retry 3 --output $archive $LlvmArchiveUrl
        Require-Success "download of $LlvmArchiveName"

        $actualHash = (Get-Sha256Hex -LiteralPath $archive).Hash
        if ($actualHash -ne $LlvmArchiveSha256) {
            throw "pinned LLVM archive hash mismatch: expected $LlvmArchiveSha256, got $actualHash"
        }

        $sevenZip = Get-SevenZip
        & $sevenZip x "-o$staging" $archive | Out-Null
        Require-Success "outer extraction of $LlvmArchiveName"
        $tarArchive = Join-Path $staging ($LlvmArchiveName -replace "\.xz$", "")
        Require-Path $tarArchive "LLVM archive did not contain its tar payload"
        & $sevenZip x "-o$staging" $tarArchive | Out-Null
        Require-Success "inner extraction of $LlvmArchiveName"

        $extractedRoot = Join-Path $staging $LlvmExtractedDirectoryName
        Require-Path (Join-Path $extractedRoot "bin\clang-tidy.exe") "archive did not contain the expected LLVM root"
        if (Test-Path -LiteralPath $LlvmRoot) {
            throw "pinned LLVM destination appeared during installation: $LlvmRoot"
        }
        Move-Item -LiteralPath $extractedRoot -Destination $LlvmRoot
    }
    finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Recurse -Force
        }
    }
}

function Remove-StalePinnedLlvm {
    param([string]$ToolsRoot, [string]$LlvmRoot)

    if (-not (Test-Path -LiteralPath $ToolsRoot -PathType Container)) {
        return
    }

    $currentRoot = (Resolve-Path -LiteralPath $LlvmRoot -ErrorAction Stop).Path
    Get-ChildItem -LiteralPath $ToolsRoot -Directory -Force |
        Where-Object {
            $_.Name -match '^(?:llvm-[0-9]+[.][0-9]+[.][0-9]+-x86_64-pc-windows-msvc)$' -and
            -not [string]::Equals($_.FullName, $currentRoot, [StringComparison]::OrdinalIgnoreCase)
        } |
        ForEach-Object {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force
        }
}

function Install-PinnedCppcheck {
    param(
        [string]$ToolsRoot,
        [string]$CppcheckRoot,
        [string]$MingwBin,
        [string]$GitBin,
        [string]$GitUsrBin
    )

    if (Test-Path -LiteralPath $CppcheckRoot) {
        return
    }

    New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null
    $staging = Join-Path $ToolsRoot ".installing-cppcheck-$PID"
    try {
        $gitExe = Join-Path $GitBin "git.exe"
        $makeExe = Join-Path $MingwBin "make.exe"
        Require-Path $gitExe "native Git executable is required for the pinned cppcheck source build"
        Require-Path $makeExe "pinned GNU Make is required for the pinned cppcheck source build"

        New-Item -ItemType Directory -Path $staging -ErrorAction Stop | Out-Null
        $source = Join-Path $staging "source"
        & $gitExe clone --depth 1 --branch $CppcheckTag $CppcheckRepository $source
        Require-Success "clone of cppcheck $CppcheckTag"

        $actualCommit = (& $gitExe -C $source rev-parse HEAD).Trim().ToUpperInvariant()
        Require-Success "cppcheck commit verification"
        if ($actualCommit -ne $CppcheckCommit) {
            throw "unexpected cppcheck commit; expected $CppcheckCommit, got $actualCommit"
        }

        $env:PATH = "$MingwBin;$GitUsrBin;$GitBin;$env:PATH"
        $env:CXX = Join-Path $MingwBin "g++.exe"
        & $makeExe -C $source --jobs=2 RDYNAMIC= | Out-Null
        Require-Success "native cppcheck source build"

        $sourceBinary = Join-Path $source "cppcheck.exe"
        $sourceCfg = Join-Path $source "cfg"
        Require-Path $sourceBinary "cppcheck source build did not produce cppcheck.exe"
        if (-not (Test-Path -LiteralPath $sourceCfg -PathType Container)) {
            throw "cppcheck source build did not contain cfg data: $sourceCfg"
        }

        $package = Join-Path $staging "package"
        New-Item -ItemType Directory -Path $package -ErrorAction Stop | Out-Null
        Copy-Item -LiteralPath $sourceBinary -Destination (Join-Path $package "cppcheck.exe")
        Copy-Item -LiteralPath $sourceCfg -Destination (Join-Path $package "cfg") -Recurse
        Require-Path (Join-Path $package "cppcheck.exe") "cppcheck package is missing cppcheck.exe"
        Require-Path (Join-Path $package "cfg\std.cfg") "cppcheck package is missing std.cfg"
        if (Test-Path -LiteralPath $CppcheckRoot) {
            throw "pinned cppcheck destination appeared during installation: $CppcheckRoot"
        }
        Move-Item -LiteralPath $package -Destination $CppcheckRoot
    }
    finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Recurse -Force
        }
    }
}

function Remove-StalePinnedCppcheck {
    param([string]$ToolsRoot, [string]$CppcheckRoot)

    if (-not (Test-Path -LiteralPath $ToolsRoot -PathType Container)) {
        return
    }

    $currentRoot = (Resolve-Path -LiteralPath $CppcheckRoot -ErrorAction Stop).Path
    Get-ChildItem -LiteralPath $ToolsRoot -Directory -Force |
        Where-Object {
            $_.Name -match '^(?:cppcheck-[0-9]+[.][0-9]+[.][0-9]+-x86_64-w64-mingw32)$' -and
            -not [string]::Equals($_.FullName, $currentRoot, [StringComparison]::OrdinalIgnoreCase)
        } |
        ForEach-Object {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force
        }
}

function Install-PinnedRipgrep {
    param([string]$ToolsRoot, [string]$RipgrepRoot)

    if (Test-Path -LiteralPath $RipgrepRoot) {
        return
    }

    New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null
    $staging = Join-Path $ToolsRoot ".installing-ripgrep-$PID"
    try {
        New-Item -ItemType Directory -Path $staging -ErrorAction Stop | Out-Null
        $archive = Join-Path $staging $RipgrepArchiveName
        & curl.exe --fail --location --retry 3 --output $archive $RipgrepArchiveUrl
        Require-Success "download of $RipgrepArchiveName"

        $actualHash = (Get-Sha256Hex -LiteralPath $archive).Hash
        if ($actualHash -ne $ExpectedRipgrepSha256) {
            throw "pinned ripgrep archive hash mismatch: expected $ExpectedRipgrepSha256, got $actualHash"
        }

        $sevenZip = Get-SevenZip
        & $sevenZip x "-o$staging" $archive | Out-Null
        Require-Success "extraction of $RipgrepArchiveName"

        $extractedRoot = Join-Path $staging $RipgrepDirectoryName
        Require-Path (Join-Path $extractedRoot "rg.exe") "archive did not contain the expected ripgrep binary"
        if (Test-Path -LiteralPath $RipgrepRoot) {
            throw "pinned ripgrep destination appeared during installation: $RipgrepRoot"
        }
        Move-Item -LiteralPath $extractedRoot -Destination $RipgrepRoot
    }
    finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Recurse -Force
        }
    }
}

function Remove-StalePinnedRipgrep {
    param([string]$ToolsRoot, [string]$RipgrepRoot)

    if (-not (Test-Path -LiteralPath $ToolsRoot -PathType Container)) {
        return
    }

    $currentRoot = (Resolve-Path -LiteralPath $RipgrepRoot -ErrorAction Stop).Path
    Get-ChildItem -LiteralPath $ToolsRoot -Directory -Force |
        Where-Object {
            $_.Name -match '^(?:ripgrep-[0-9]+[.][0-9]+[.][0-9]+-x86_64-pc-windows-msvc)$' -and
            -not [string]::Equals($_.FullName, $currentRoot, [StringComparison]::OrdinalIgnoreCase)
        } |
        ForEach-Object {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force
        }
}

function Install-PinnedSccache {
    param([string]$ToolsRoot, [string]$SccacheRoot)

    if (Test-Path -LiteralPath $SccacheRoot) {
        return
    }

    New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null
    $staging = Join-Path $ToolsRoot ".installing-sccache-$PID"
    try {
        New-Item -ItemType Directory -Path $staging -ErrorAction Stop | Out-Null
        $archive = Join-Path $staging $SccacheArchiveName
        & curl.exe --fail --location --retry 3 --output $archive $SccacheArchiveUrl
        Require-Success "download of $SccacheArchiveName"

        $actualHash = (Get-Sha256Hex -LiteralPath $archive).Hash
        if ($actualHash -ne $SccacheArchiveSha256) {
            throw "pinned sccache archive hash mismatch: expected $SccacheArchiveSha256, got $actualHash"
        }

        $sevenZip = Get-SevenZip
        & $sevenZip x "-o$staging" $archive | Out-Null
        Require-Success "extraction of $SccacheArchiveName"

        $extractedRoot = Join-Path $staging $SccacheExtractedDirectoryName
        Require-Path (Join-Path $extractedRoot "sccache.exe") "archive did not contain the expected sccache binary"
        if (Test-Path -LiteralPath $SccacheRoot) {
            throw "pinned sccache destination appeared during installation: $SccacheRoot"
        }
        Move-Item -LiteralPath $extractedRoot -Destination $SccacheRoot
    }
    finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Recurse -Force
        }
    }
}

function Remove-StalePinnedSccache {
    param([string]$ToolsRoot, [string]$SccacheRoot)

    if (-not (Test-Path -LiteralPath $ToolsRoot -PathType Container)) {
        return
    }

    $currentRoot = (Resolve-Path -LiteralPath $SccacheRoot -ErrorAction Stop).Path
    Get-ChildItem -LiteralPath $ToolsRoot -Directory -Force |
        Where-Object {
            $_.Name -match '^(?:sccache-[0-9]+[.][0-9]+[.][0-9]+-x86_64-pc-windows-msvc)$' -and
            -not [string]::Equals($_.FullName, $currentRoot, [StringComparison]::OrdinalIgnoreCase)
        } |
        ForEach-Object {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force
        }
}

function Ensure-BundledMakeAlias {
    param([string]$MingwBin)

    $source = Join-Path $MingwBin "mingw32-make.exe"
    $alias = Join-Path $MingwBin "make.exe"
    Require-Path $source "pinned MinGW GNU Make is missing"

    $sourceHash = (Get-Sha256Hex -LiteralPath $source).Hash
    if ($sourceHash -ne $ExpectedMakeSha256) {
        throw "pinned MinGW GNU Make hash mismatch: expected $ExpectedMakeSha256, got $sourceHash"
    }

    if (Test-Path -LiteralPath $alias) {
        if (-not (Test-Path -LiteralPath $alias -PathType Leaf)) {
            throw "pinned GNU Make alias is not a file: $alias"
        }
        $aliasHash = (Get-Sha256Hex -LiteralPath $alias).Hash
        if ($aliasHash -ne $ExpectedMakeSha256) {
            Remove-Item -LiteralPath $alias -Force
        }
    }
    if (-not (Test-Path -LiteralPath $alias -PathType Leaf)) {
        Copy-Item -LiteralPath $source -Destination $alias
    }

    $aliasHash = (Get-Sha256Hex -LiteralPath $alias).Hash
    if ($aliasHash -ne $ExpectedMakeSha256) {
        throw "pinned GNU Make alias hash mismatch: expected $ExpectedMakeSha256, got $aliasHash"
    }
}

function Get-SccacheServerPort {
    param([string]$Root)

    # #226/#242: one sccache server per launcher root, on a port that is a deterministic
    # function of that root, so (a) reruns in one root reuse one warm server, (b) sibling
    # worktrees and the canonical workspace never share a daemon, and (c) the launcher's
    # session lock -- which serialises launcher runs within a root -- therefore also makes
    # THIS root's server unambiguously owned by THIS session. Every child, including
    # trybuild's nested cargo, inherits SCCACHE_SERVER_PORT and so talks to the one server
    # the launcher already started instead of racing to create its own.
    #
    # SHA256.Create()/ComputeHash is used rather than the .NET 5+ [SHA256]::HashData static:
    # the launcher is documented as runnable under Windows PowerShell 5.1
    # (`powershell -ExecutionPolicy Bypass -File scripts\windows-gnu-toolchain.ps1`), whose
    # .NET Framework 4.8 surface has no HashData.
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Root.ToLowerInvariant())
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($bytes)
    }
    finally {
        $sha256.Dispose()
    }
    return [string]($SccacheServerPortBase + ([BitConverter]::ToUInt16($hash, 0) % $SccacheServerPortSpan))
}

function Set-ToolchainEnvironment {
    param(
        [string]$MingwBin,
        [string]$LlvmBin,
        [string]$CppcheckRoot,
        [string]$RipgrepRoot,
        [string]$GitBin,
        [string]$GitUsrBin,
        [string]$SccacheExe,
        [string]$SccacheDir,
        [string]$SccacheServerPort
    )

    $env:PATH = "$MingwBin;$LlvmBin;$CppcheckRoot;$RipgrepRoot;$GitUsrBin;$GitBin;$env:PATH"
    $env:SHELL = Join-Path $GitUsrBin "sh.exe"
    $env:BASH = Join-Path $GitBin "bash.exe"
    $env:RUSTUP_TOOLCHAIN = $RustToolchain
    $env:MAKE = Join-Path $MingwBin "make.exe"
    $env:CC = Join-Path $MingwBin "gcc.exe"
    $env:CXX = Join-Path $MingwBin "g++.exe"
    $env:AR = Join-Path $MingwBin "ar.exe"
    $env:LD = Join-Path $MingwBin "ld.exe"
    $env:NM = Join-Path $MingwBin "nm.exe"
    $env:OBJCOPY = Join-Path $MingwBin "objcopy.exe"
    $env:CLANG_TIDY = Join-Path $LlvmBin "clang-tidy.exe"
    $env:CLANG_FORMAT = Join-Path $LlvmBin "clang-format.exe"
    $env:CPPCHECK = Join-Path $CppcheckRoot "cppcheck.exe"
    $env:RIPGREP = Join-Path $RipgrepRoot "rg.exe"
    # #190: route rustc through the content-addressed sccache so compilation reuse
    # survives the mandated target/ wipe. SCCACHE_DIR is a launcher-owned,
    # workspace-local dir (sibling of .toolchains/.tmp, gitignored) that the
    # target/temp cleanup below deliberately does NOT delete. sccache refuses to
    # cache incremental artifacts, so incremental compilation must be disabled.
    $env:RUSTC_WRAPPER = $SccacheExe
    $env:SCCACHE_DIR = $SccacheDir
    $env:SCCACHE_CACHE_SIZE = $SccacheCacheSize
    $env:CARGO_INCREMENTAL = "0"
    # #242: every descendant of the child command -- cargo, its parallel rustc processes,
    # and the NESTED cargo that trybuild spawns -- inherits these two, so they all address
    # the single server this launcher pre-starts on this root's port and none of them ever
    # takes the auto-start path that produced the os error 10048 bind race. RUSTC_WRAPPER
    # is deliberately NOT unset for nested cargo: an unset wrapper would silently drop the
    # trybuild phase out of the cache (an unlabelled degradation), whereas server
    # inheritance keeps one consistent, cached, deterministic compile path.
    $env:SCCACHE_SERVER_PORT = $SccacheServerPort
    $env:SCCACHE_IDLE_TIMEOUT = $SccacheIdleTimeout
}

function Set-WorkspaceTempEnvironment {
    param([string]$WorkspaceTemp)

    $env:TEMP = $WorkspaceTemp
    $env:TMP = $WorkspaceTemp
    $env:TMPDIR = $WorkspaceTemp
    # The launcher relocates TEMP inside the workspace checkout. Stop git
    # repository discovery from ascending out of the temp tree, or every
    # "outside any checkout" temp directory inherits the Astrolabe repo
    # identity — vendored calyx-buildinfo's outside-checkout FSV asserts
    # exactly that property, and fixture repos created inside temp dirs are
    # below the ceiling so their own discovery is unaffected (relates #175).
    $tempCeiling = (Split-Path -Parent $WorkspaceTemp) -replace '\\', '/'
    if ($env:GIT_CEILING_DIRECTORIES) {
        $env:GIT_CEILING_DIRECTORIES = "$tempCeiling;$($env:GIT_CEILING_DIRECTORIES)"
    }
    else {
        $env:GIT_CEILING_DIRECTORIES = $tempCeiling
    }
    # NOTE (#194/#232): a launcher-level CBM_CACHE_DIR redirect was tried here to keep
    # codebase-memory-mcp project registrations out of the operator's global store,
    # but it splits the vendored C tests' write path from their read path — those
    # tests index via cbm_mcp_server_new(NULL) (which honours CBM_CACHE_DIR) yet open
    # the db at a HARDCODED $HOME/.cache/codebase-memory-mcp/<project>.db (e.g.
    # tests/test_edge_types_probe.c:104, test_integration.c), so a redirect empties
    # the store they assert on and regresses ~808 CBM C tests. Do NOT set CBM_CACHE_DIR
    # globally here: it would also reach git, cargo and sccache children that have no
    # business being repointed.
    #
    # The store leak is fixed where the store is decided instead. scripts/ci-cbm-test.sh
    # redirects HOME/USERPROFILE (the one input BOTH halves read: cbm_get_home_dir()
    # in src/foundation/platform.c) to a run-scoped store under target/ for the CBM
    # phase only, so the library and the vendored tests move together; the Rust
    # row-sink test cleans up through a fail-closed Drop guard; and
    # scripts/check-cbm-cache-hermeticity.py re-reads the operator's real store before
    # and after the phase and fails closed on a single added registration.
}

# #278: causal attribution source for the no-escape gate. The gate protects roots
# the operator SHARES with the OS and -- on this machine -- with other Calyx/CBM
# checkouts and concurrent codebase-memory-mcp MCP servers. Classifying a delta as
# "ours" by NAME PATTERN (calyx*, cbm*) false-positives there. Instead the launcher
# records THIS run's process tree so the gate attributes a shared-root delta only to
# a process that was actually part of our run. A Windows Job Object receives a
# JOB_OBJECT_MSG_NEW_PROCESS completion for EVERY descendant at creation time (no
# poll-miss), so short-lived `cargo test` binaries -- whose scratch-dir names embed
# std::process::id() -- are captured. If this recorder cannot start, the gate fails
# CLOSED (ASTRO_NO_ESCAPE_NO_ATTRIBUTION) rather than reverting to name matching.
$AstroTreeRecorderSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public class AstroTreeRecorder {
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateJobObjectW(IntPtr a, string name);
    [DllImport("kernel32", SetLastError = true)]
    static extern IntPtr CreateIoCompletionPort(IntPtr handle, IntPtr existing, UIntPtr key, uint threads);
    [DllImport("kernel32", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr job, int cls, IntPtr info, uint len);
    [DllImport("kernel32", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr proc);
    [DllImport("kernel32")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32", SetLastError = true)]
    static extern bool GetQueuedCompletionStatus(IntPtr port, out uint bytes, out UIntPtr key, out IntPtr overlapped, uint ms);
    [DllImport("kernel32", SetLastError = true)]
    static extern bool PostQueuedCompletionStatus(IntPtr port, uint bytes, UIntPtr key, IntPtr overlapped);
    [DllImport("kernel32")]
    static extern bool CloseHandle(IntPtr h);

    const int JobObjectAssociateCompletionPortInformation = 7;
    const uint JOB_OBJECT_MSG_NEW_PROCESS = 6;
    const uint STOP_SENTINEL = 0xFFFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_ASSOCIATE_COMPLETION_PORT { public IntPtr CompletionKey; public IntPtr CompletionPort; }

    IntPtr job, port;
    Thread thread;
    volatile bool stop;
    // #278 attempt 6: pid alone is ambiguous under PID REUSE (a foreign batch's
    // creator pid recycled by one of our thousands of short-lived children).
    // Stamp each pid's FIRST-SEEN time so the gate only attributes an entry
    // whose timestamp is >= that pid instance's birth in OUR tree.
    readonly Dictionary<int, long> pidFirstSeenNs = new Dictionary<int, long>();
    readonly object gate = new object();
    string manifestPath;
    int launcherPid;
    long runStartedNs;

    static long NowUnixNs() {
        return (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).Ticks * 100L;
    }

    public static AstroTreeRecorder Start(string manifestPath, int launcherPid) {
        AstroTreeRecorder r = new AstroTreeRecorder();
        r.manifestPath = manifestPath;
        r.launcherPid = launcherPid;
        r.runStartedNs = NowUnixNs();
        r.job = CreateJobObjectW(IntPtr.Zero, null);
        if (r.job == IntPtr.Zero) throw new Exception("CreateJobObject failed " + Marshal.GetLastWin32Error());
        r.port = CreateIoCompletionPort(new IntPtr(-1), IntPtr.Zero, UIntPtr.Zero, 1);
        if (r.port == IntPtr.Zero) throw new Exception("CreateIoCompletionPort failed " + Marshal.GetLastWin32Error());
        JOBOBJECT_ASSOCIATE_COMPLETION_PORT assoc = new JOBOBJECT_ASSOCIATE_COMPLETION_PORT();
        assoc.CompletionKey = r.job;
        assoc.CompletionPort = r.port;
        IntPtr buf = Marshal.AllocHGlobal(Marshal.SizeOf(assoc));
        try {
            Marshal.StructureToPtr(assoc, buf, false);
            if (!SetInformationJobObject(r.job, JobObjectAssociateCompletionPortInformation, buf, (uint)Marshal.SizeOf(assoc)))
                throw new Exception("SetInformationJobObject failed " + Marshal.GetLastWin32Error());
        } finally {
            Marshal.FreeHGlobal(buf);
        }
        // Assign the launcher itself: every child (bash -> gates -> cargo -> test
        // binaries) inherits the job, so all descendant PIDs flow to the port.
        if (!AssignProcessToJobObject(r.job, GetCurrentProcess()))
            throw new Exception("AssignProcessToJobObject failed " + Marshal.GetLastWin32Error());
        lock (r.gate) { r.pidFirstSeenNs[launcherPid] = r.runStartedNs; }
        r.Flush();
        r.thread = new Thread(r.Loop);
        r.thread.IsBackground = true;
        r.thread.Start();
        return r;
    }

    void Loop() {
        while (!stop) {
            uint bytes; UIntPtr key; IntPtr ov;
            if (GetQueuedCompletionStatus(port, out bytes, out key, out ov, 500)) {
                if (bytes == JOB_OBJECT_MSG_NEW_PROCESS) {
                    int pid = (int)ov.ToInt64();
                    long now = NowUnixNs();
                    bool added = false;
                    lock (gate) {
                        if (!pidFirstSeenNs.ContainsKey(pid)) { pidFirstSeenNs[pid] = now; added = true; }
                    }
                    if (added) Flush();
                } else if (bytes == STOP_SENTINEL) {
                    break;
                }
            }
        }
    }

    void Flush() {
        List<KeyValuePair<int, long>> snap;
        lock (gate) { snap = new List<KeyValuePair<int, long>>(pidFirstSeenNs); }
        StringBuilder sb = new StringBuilder();
        sb.Append("{\"schema\":\"astrolabe.no_escape_attribution.v1\",\"launcher_pid\":");
        sb.Append(launcherPid);
        sb.Append(",\"run_started_unix_ns\":");
        sb.Append(runStartedNs);
        sb.Append(",\"tree_pids\":[");
        for (int i = 0; i < snap.Count; i++) { if (i > 0) sb.Append(','); sb.Append(snap[i].Key); }
        sb.Append("],\"pid_first_seen\":{");
        for (int i = 0; i < snap.Count; i++) {
            if (i > 0) sb.Append(',');
            sb.Append('"'); sb.Append(snap[i].Key); sb.Append("\":"); sb.Append(snap[i].Value);
        }
        sb.Append("},\"owned_paths\":[]}");
        try {
            string tmp = manifestPath + ".tmp";
            File.WriteAllText(tmp, sb.ToString());
            if (File.Exists(manifestPath)) File.Delete(manifestPath);
            File.Move(tmp, manifestPath);
        } catch { }
    }

    public void Stop() {
        stop = true;
        PostQueuedCompletionStatus(port, STOP_SENTINEL, UIntPtr.Zero, IntPtr.Zero);
        if (thread != null) thread.Join(2000);
        Flush();
        if (port != IntPtr.Zero) CloseHandle(port);
        if (job != IntPtr.Zero) CloseHandle(job);
    }
}
'@

function Start-AstroTreeAttribution {
    param([string]$ManifestPath, [int]$LauncherPid)
    if (-not ([System.Management.Automation.PSTypeName]'AstroTreeRecorder').Type) {
        Add-Type -TypeDefinition $AstroTreeRecorderSource -Language CSharp -ErrorAction Stop
    }
    return [AstroTreeRecorder]::Start($ManifestPath, $LauncherPid)
}

function Test-PinnedToolchain {
    param([string]$MingwBin, [string]$LlvmBin, [string]$CppcheckRoot, [string]$RipgrepRoot, [string]$SccacheExe)

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
        $mingwHash = (Get-Sha256Hex -LiteralPath (Join-Path $MingwBin $dll)).Hash
        $rustHash = (Get-Sha256Hex -LiteralPath (Join-Path $rustBin $dll)).Hash
        if ($mingwHash -ne $rustHash) {
            throw "runtime DLL mismatch for $dll; refusing a mixed MinGW runtime"
        }
    }

    foreach ($tool in $RequiredLlvmTools) {
        Require-Path (Join-Path $LlvmBin $tool) "pinned LLVM analysis tool is missing"
    }
    $clangTidyVersion = (& $env:CLANG_TIDY --version) -join "`n"
    Require-Success "clang-tidy version check"
    if ($clangTidyVersion -notmatch [regex]::Escape($ExpectedClangTidyVersion)) {
        throw "unexpected clang-tidy version; expected $ExpectedClangTidyVersion, got: $clangTidyVersion"
    }
    & $env:CLANG_FORMAT --version | Out-Null
    Require-Success "clang-format version check"

    Require-Path $env:CPPCHECK "pinned cppcheck is missing"
    Require-Path (Join-Path $CppcheckRoot "cfg\std.cfg") "pinned cppcheck data is missing"
    $cppcheckVersion = (& $env:CPPCHECK --version) -join "`n"
    Require-Success "cppcheck version check"
    if ($cppcheckVersion -notmatch [regex]::Escape($ExpectedCppcheckVersion)) {
        throw "unexpected cppcheck version; expected $ExpectedCppcheckVersion, got: $cppcheckVersion"
    }

    $rgExe = Join-Path $RipgrepRoot "rg.exe"
    Require-Path $rgExe "pinned ripgrep is missing"
    $ripgrepVersion = (& $rgExe --version) -join "`n"
    Require-Success "ripgrep version check"
    if ($ripgrepVersion -notmatch [regex]::Escape($RipgrepVersion)) {
        throw "unexpected ripgrep version; expected $RipgrepVersion, got: $ripgrepVersion"
    }

    & $env:MAKE --version | Out-Null
    Require-Success "GNU Make check"

    Require-Path $SccacheExe "pinned sccache is missing"
    $sccacheVersion = (& $SccacheExe --version) -join "`n"
    Require-Success "sccache version check"
    if ($sccacheVersion -notmatch [regex]::Escape($ExpectedSccacheVersion)) {
        throw "unexpected sccache version; expected $ExpectedSccacheVersion, got: $sccacheVersion"
    }
}

if ($env:OS -ne "Windows_NT") {
    throw "windows-gnu-toolchain.ps1 is native Windows only"
}
if ($env:WSL_DISTRO_NAME -or $env:WSL_INTEROP) {
    throw "EXECUTION_BOUNDARY[ASTRO_NATIVE_CONTEXT_REQUIRED]: run this launcher from native Windows PowerShell"
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
# #226: a registered git worktree of the canonical workspace (a `.git` FILE under
# .claude\worktrees\) is a valid launcher root for parallel-session verification.
# It keeps its own target/, .tmp/, and session lock, and shares the canonical
# pinned .toolchains and .sccache. Everything else stays canonical-only.
$worktreeParent = Join-Path (Join-Path $ExpectedWorkspace ".claude") "worktrees"
$isCanonicalRoot = [string]::Equals($root, $ExpectedWorkspace, [StringComparison]::OrdinalIgnoreCase)
$isWorktreeRoot = (-not $isCanonicalRoot) -and
    $root.StartsWith($worktreeParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -and
    (Test-Path -LiteralPath (Join-Path $root ".git") -PathType Leaf)
if (-not ($isCanonicalRoot -or $isWorktreeRoot)) {
    throw "canonical workspace required: $ExpectedWorkspace (found $root)"
}
if ($isWorktreeRoot -and $Bootstrap) {
    throw "LAUNCHER_BOUNDARY[ASTRO_BOOTSTRAP_CANONICAL_ONLY]: -Bootstrap installs pinned tools and must run from $ExpectedWorkspace, not worktree $root"
}
if ($isWorktreeRoot) {
    Write-Output "LAUNCHER_WORKTREE[ASTRO_WORKTREE_ROOT]: root=$root; pinned tools and sccache shared from $ExpectedWorkspace; target/, .tmp/, and session lock stay worktree-local"
}
# #226/#242: every root -- canonical AND worktree -- gets its own sccache server on a
# deterministic, non-ephemeral port. #226 derived a port for worktrees only, which left the
# canonical workspace on sccache's machine-wide default (127.0.0.1:4226): a stray default-port
# server from any other project on this host, or an orphan started under a since-deleted
# per-session temp dir, would then silently serve the canonical gate. Deriving the port here
# for both roots makes server ownership follow the launcher session lock exactly.
$sccacheServerPort = Get-SccacheServerPort -Root $root
Set-Location -LiteralPath $root
$target = Join-Path $root "target"
$workspaceTempParent = Join-Path $root ".tmp"
$workspaceTempParentExisted = Test-Path -LiteralPath $workspaceTempParent
$workspaceTemp = Join-Path $workspaceTempParent "windows-gnu-toolchain-$PID"
$launcherLock = Join-Path $workspaceTempParent "astrolabe-launcher.lock"
# #197/#247: the session-lock semantics live in one audited, dot-sourceable place
# (scripts/launcher-lock.ps1) that has NO capability to stop any process. A live foreign
# holder is refused (ASTRO_LAUNCHER_LOCK_HELD), a malformed lock fails closed
# (ASTRO_LAUNCHER_LOCK_UNREADABLE), and only a dead-pid stale lock is removed -- never a
# by-name process sweep. The helper is tested in isolation by scripts/test-launcher-lock.ps1
# (fixture locks, never the live workspace).
. (Join-Path $PSScriptRoot "launcher-lock.ps1")
Assert-AstroLauncherLockClaimable -LockPath $launcherLock
if (Test-Path -LiteralPath $target) {
    throw "target must be absent before toolchain work: $target"
}
if ((Test-Path -LiteralPath $workspaceTempParent) -and -not (Test-Path -LiteralPath $workspaceTempParent -PathType Container)) {
    throw "workspace temporary parent is not a directory: $workspaceTempParent"
}
New-Item -ItemType Directory -Path $workspaceTempParent -Force | Out-Null
# #197: atomic lock claim — write the full manifest to a PID-named staging
# sibling, then move it onto the lock name WITHOUT clobbering. No reader can
# ever observe a claimed-but-empty or half-written lock (the #186 UNREADABLE
# race), and a concurrent claim between the boundary check above and this move
# surfaces as a named fail-closed refusal instead of overwriting a live lock.
$launcherLockStage = "$launcherLock.$PID.tmp"
[ordered]@{
    pid = $PID
    started = (Get-Date).ToString("o")
    command = ("$Command $CommandArgsJson").Trim()
} | ConvertTo-Json -Compress | Set-Content -LiteralPath $launcherLockStage -Encoding UTF8
try {
    Move-Item -LiteralPath $launcherLockStage -Destination $launcherLock -ErrorAction Stop
}
catch {
    Remove-Item -LiteralPath $launcherLockStage -Force -ErrorAction SilentlyContinue
    throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_RACE]: another launcher session claimed this workspace between the lock check and the atomic claim; never stop or clean a live session's run - wait for the lock to release: $launcherLock"
}

# #226: pinned tools always live in the canonical workspace so worktree sessions
# reuse one bootstrapped bundle instead of re-downloading per worktree.
$toolsRoot = Join-Path $ExpectedWorkspace ".toolchains"
$mingwRoot = Join-Path $toolsRoot $ToolchainDirectoryName
$mingwBin = Join-Path $mingwRoot "bin"
$llvmRoot = Join-Path $toolsRoot $LlvmDirectoryName
$llvmBin = Join-Path $llvmRoot "bin"
$cppcheckRoot = Join-Path $toolsRoot $CppcheckDirectoryName
$ripgrepRoot = Join-Path $toolsRoot $RipgrepDirectoryName
$sccacheRoot = Join-Path $toolsRoot $SccacheDirectoryName
$sccacheExe = Join-Path $sccacheRoot "sccache.exe"
# #190: workspace-local compiler cache, sibling of .toolchains/.tmp. It survives the
# target/ wipe (the finally block deletes target/ and the workspace temp, never this).
# #226: the cache is canonical-workspace-shared so worktree sessions hit the same
# warm content-addressed cache; sccache's disk cache is safe under concurrency.
$sccacheDir = Join-Path $ExpectedWorkspace ".sccache"
$gitRoot = $GitInstallRoot
$gitBin = Join-Path $gitRoot "bin"
$gitUsrBin = Join-Path $gitRoot "usr\bin"
Require-Path (Join-Path $gitBin "bash.exe") "native Git for Windows Bash is required"
Require-Path (Join-Path $gitUsrBin "sh.exe") "native Git for Windows shell is required"
Assert-AllowedBashCommand -Command $Command -GitRoot $gitRoot

if ($Bootstrap) {
    Install-PinnedToolchain -ToolsRoot $toolsRoot -MingwRoot $mingwRoot
}
Require-Path (Join-Path $mingwBin "gcc.exe") "pinned MinGW toolchain is missing; rerun with -Bootstrap"
Ensure-BundledMakeAlias -MingwBin $mingwBin
if ($Bootstrap) {
    Install-PinnedLlvm -ToolsRoot $toolsRoot -LlvmRoot $llvmRoot
    Install-PinnedCppcheck -ToolsRoot $toolsRoot -CppcheckRoot $cppcheckRoot -MingwBin $mingwBin -GitBin $gitBin -GitUsrBin $gitUsrBin
    Install-PinnedRipgrep -ToolsRoot $toolsRoot -RipgrepRoot $ripgrepRoot
    Install-PinnedSccache -ToolsRoot $toolsRoot -SccacheRoot $sccacheRoot
    Remove-StalePinnedLlvm -ToolsRoot $toolsRoot -LlvmRoot $llvmRoot
    Remove-StalePinnedCppcheck -ToolsRoot $toolsRoot -CppcheckRoot $cppcheckRoot
    Remove-StalePinnedRipgrep -ToolsRoot $toolsRoot -RipgrepRoot $ripgrepRoot
    Remove-StalePinnedSccache -ToolsRoot $toolsRoot -SccacheRoot $sccacheRoot
}
Require-Path (Join-Path $llvmBin "clang-tidy.exe") "pinned LLVM analysis toolchain is missing; rerun with -Bootstrap"
Require-Path (Join-Path $cppcheckRoot "cppcheck.exe") "pinned cppcheck is missing; rerun with -Bootstrap"
Require-Path (Join-Path $ripgrepRoot "rg.exe") "pinned ripgrep is missing; rerun with -Bootstrap"
Require-Path $sccacheExe "pinned sccache is missing; rerun with -Bootstrap"
New-Item -ItemType Directory -Path $sccacheDir -Force | Out-Null
Set-ToolchainEnvironment -MingwBin $mingwBin -LlvmBin $llvmBin -CppcheckRoot $cppcheckRoot -RipgrepRoot $ripgrepRoot -GitBin $gitBin -GitUsrBin $gitUsrBin -SccacheExe $sccacheExe -SccacheDir $sccacheDir -SccacheServerPort $sccacheServerPort
# No ambient-PATH bash.exe policing: WSL is a permitted, coexisting part of this
# host (direction reversed 2026-07-11), so a WSL bash.exe on PATH is not a fault
# (and `Get-Command bash.exe` returning multiple sources crashed GetFullPath under
# PS 5.1). The launcher uses Git bash explicitly via $env:BASH/$env:SHELL, and
# Set-ToolchainEnvironment prepends $GitBin to the child PATH; $Command is invoked
# by explicit path. An explicitly-passed bash $Command is still validated by
# Assert-AllowedBashCommand above. See #205.
Test-PinnedToolchain -MingwBin $mingwBin -LlvmBin $llvmBin -CppcheckRoot $cppcheckRoot -RipgrepRoot $ripgrepRoot -SccacheExe $sccacheExe
Write-Output "WINDOWS_GNU_TOOLCHAIN: Rust $RustToolchain, GCC $ExpectedGccVersion, LLVM $ExpectedClangTidyVersion, Cppcheck $ExpectedCppcheckVersion, ripgrep $RipgrepVersion, sccache $ExpectedSccacheVersion, runtime $mingwBin"

if ([string]::IsNullOrWhiteSpace($Command)) {
    Write-Output 'Ready. Example: .\scripts\windows-gnu-toolchain.ps1 -Command cargo -CommandArgsJson ''["test","-p","cbm-sys","--lib"]'''
    Remove-LauncherLockFile -LockPath $launcherLock
    if (-not $workspaceTempParentExisted -and (Test-Path -LiteralPath $workspaceTempParent)) {
        Remove-Item -LiteralPath $workspaceTempParent -Force -ErrorAction SilentlyContinue
    }
    exit 0
}

# Windows PowerShell 5.1's ConvertFrom-Json emits a JSON array as ONE object instead of
# enumerating it, so `@(ConvertFrom-Json '["a","b"]')` yields an array-of-one-array there
# while PowerShell 7 unrolls it into two strings. Under 5.1 -- the host CLAUDE.md documents
# for `powershell -ExecutionPolicy Bypass -File scripts\windows-gnu-toolchain.ps1` -- that
# made every multi-argument invocation (including CLAUDE.md's own
# '["test","-p","cbm-sys","--lib"]' example) fail the string check below. Normalise both
# hosts to a flat argument list before validating.
$parsedCommandArgs = ConvertFrom-Json -InputObject $CommandArgsJson
$commandArgs = @()
if ($null -ne $parsedCommandArgs) {
    if (($parsedCommandArgs -is [System.Collections.IEnumerable]) -and ($parsedCommandArgs -isnot [string])) {
        foreach ($argument in $parsedCommandArgs) {
            $commandArgs += $argument
        }
    }
    else {
        $commandArgs += $parsedCommandArgs
    }
}
foreach ($argument in $commandArgs) {
    if ($argument -isnot [string]) {
        throw "CommandArgsJson must contain only strings"
    }
}

# #239: $commandExit stays $null until the child command actually reports an exit code.
# "the child never ran" and "the child exited 0" are different facts and must not collapse.
$commandExit = $null
$launcherFault = $null
$cleanupErrors = @()
$treeRecorder = $null
$attributionManifest = Join-Path $workspaceTempParent "no-escape-attribution-$PID.json"
$previousTempEnvironment = @{}
foreach ($name in @("TEMP", "TMP", "TMPDIR", "GIT_CEILING_DIRECTORIES", "ASTRO_NO_ESCAPE_ATTRIBUTION")) {
    $previousTempEnvironment[$name] = Get-Item -Path "Env:$name" -ErrorAction SilentlyContinue
}
try {
    Set-WorkspaceTempEnvironment -WorkspaceTemp $workspaceTemp
    New-Item -ItemType Directory -Path $workspaceTemp -Force | Out-Null
    # #190: ensure the sccache server is up and zero its counters so --show-stats in
    # the finally reports THIS run's cold-vs-warm hit rate. The on-disk cache in
    # $sccacheDir persists across runs and the target/ wipe.
    # #226: the server may outlive this session, so it must NOT inherit the per-session
    # workspace temp — a server whose temp dir is deleted at session end fatally poisons
    # every later compile with "Failed to create temp dir". Start it with a stable temp
    # under the shared cache root, then restore the per-session temp for the child command.
    $sccacheServerTemp = Join-Path $sccacheDir "server-tmp"
    New-Item -ItemType Directory -Path $sccacheServerTemp -Force | Out-Null
    Set-WorkspaceTempEnvironment -WorkspaceTemp $sccacheServerTemp
    # #242: replace any leftover daemon on THIS root's port before starting ours. The
    # launcher session lock serialises launcher runs within a root, so a server on this
    # port is either ours-from-a-previous-run or an orphan of a crashed run — in both
    # cases its configuration (idle timeout, temp dir, cache dir) is unknown, and an
    # orphan started under a since-deleted per-session temp poisons every compile. Stop
    # it, then start one daemon whose environment we know exactly. Exit 2 here means
    # "no server was listening", which is the normal, expected case.
    $sccachePreStop = Invoke-NativeCapture -Exe $sccacheExe -Arguments @("--stop-server")
    if ($sccachePreStop.ExitCode -eq 0) {
        Write-Output "SCCACHE[ASTRO_CACHE_SERVER_REPLACED]: stopped a pre-existing sccache daemon on 127.0.0.1:$sccacheServerPort before starting this session's daemon"
    }
    $sccacheStart = Invoke-NativeCapture -Exe $sccacheExe -Arguments @("--start-server")
    Set-WorkspaceTempEnvironment -WorkspaceTemp $workspaceTemp
    # #242: --zero-stats round-trips to the daemon, so its exit code is a direct readback of
    # "a daemon is listening on this port and answering". If it is not, EVERY rustc invocation
    # in the child would fail through the sccache wrapper; fail closed here with a named
    # boundary instead of letting that surface as an unattributable mid-build error.
    $sccacheZero = Invoke-NativeCapture -Exe $sccacheExe -Arguments @("--zero-stats")
    if ($sccacheZero.ExitCode -ne 0) {
        throw "LAUNCHER_BOUNDARY[ASTRO_SCCACHE_SERVER_UNAVAILABLE]: no sccache daemon is answering on 127.0.0.1:$sccacheServerPort ('--start-server' exit=$($sccacheStart.ExitCode), '--zero-stats' exit=$($sccacheZero.ExitCode)). Every rustc invocation would fail through RUSTC_WRAPPER. Remediation: check for a foreign listener on that port (Get-NetTCPConnection -LocalPort $sccacheServerPort) and for stale sccache.exe processes, then retry. Daemon output: $($sccacheStart.Output -join ' | ') $($sccacheZero.Output -join ' | ')"
    }
    Write-Output "SCCACHE[ASTRO_CACHE_ENABLED]: dir=$sccacheDir; size=$SccacheCacheSize; wrapper=$sccacheExe; CARGO_INCREMENTAL=0; SCCACHE_SERVER_PORT=$sccacheServerPort; SCCACHE_IDLE_TIMEOUT=$SccacheIdleTimeout"
    # #278: start recording THIS run's process tree so the no-escape gate attributes
    # shared-root deltas causally (see $AstroTreeRecorderSource). Point the gate at the
    # manifest via the environment the child inherits. If the recorder cannot start, do
    # NOT set the variable: the gate then fails closed (ASTRO_NO_ESCAPE_NO_ATTRIBUTION)
    # instead of silently reverting to the unsound name-pattern classification.
    try {
        $treeRecorder = Start-AstroTreeAttribution -ManifestPath $attributionManifest -LauncherPid $PID
        $env:ASTRO_NO_ESCAPE_ATTRIBUTION = $attributionManifest
        Write-Output "NO_ESCAPE[ASTRO_ATTRIBUTION_RECORDING]: process-tree PIDs -> $attributionManifest"
    }
    catch {
        Write-Output "NO_ESCAPE[ASTRO_ATTRIBUTION_UNAVAILABLE]: could not start the process-tree recorder ($($_.Exception.Message)); the no-escape gate will fail closed rather than fall back to name-pattern attribution"
    }
    # #239: the child's exit code is the ONLY thing that decides this launcher's exit code.
    # $ErrorActionPreference drops to 'Continue' for the call because Windows PowerShell 5.1
    # turns a native command's stderr into a TERMINATING ErrorRecord under 'Stop' — a child
    # that merely writes a warning to stderr would otherwise be reported as a launcher fault
    # instead of by its own exit code.
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $Command @commandArgs
        # Capture immediately, before any cleanup command can overwrite $LASTEXITCODE.
        $commandExit = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    Write-Output "LAUNCHER_EXIT[ASTRO_CHILD_EXIT]: child command exited with $commandExit"
}
catch {
    # #239: a fault in the launcher itself (bad sccache daemon, unlaunchable command, ...)
    # is NOT a child exit code. Record it, let the finally run, and report it below under
    # its own reserved code so it can never be mistaken for the child's result.
    $launcherFault = $_
}
finally {
    # #278: stop the process-tree recorder FIRST (flush the final PID manifest) before any
    # teardown removes .tmp. Stopping never changes the launcher's exit code.
    if ($null -ne $treeRecorder) {
        try { $treeRecorder.Stop() } catch { $cleanupErrors += "tree-attribution recorder stop failed: $($_.Exception.Message)" }
    }
    # #190: surface this run's sccache stats to the evidence stream, then stop the daemon
    # (flushes stats, releases handles) BEFORE the target/temp cleanup below. The on-disk
    # cache in $sccacheDir is intentionally kept.
    # #226/#242: the daemon is bound to THIS root's derived port and the session lock makes
    # this session its only user, so stopping it is correct for worktree roots too — it no
    # longer risks tearing down a live canonical session's daemon, and it leaves no orphan
    # behind for the next session to inherit blindly.
    # #239: NOTHING in this block may change the launcher's exit code. Every native call
    # here has its exit code captured and reported under a named label, never propagated.
    try {
        Write-Output "SCCACHE[ASTRO_CACHE_STATS]:"
        $sccacheStats = Invoke-NativeCapture -Exe $sccacheExe -Arguments @("--show-stats")
        foreach ($line in $sccacheStats.Output) {
            Write-Output $line
        }
        if ($sccacheStats.ExitCode -ne 0) {
            Write-Output "SCCACHE[ASTRO_CACHE_STATS_UNAVAILABLE]: '$sccacheExe --show-stats' exit=$($sccacheStats.ExitCode)"
        }
        $sccacheStop = Invoke-NativeCapture -Exe $sccacheExe -Arguments @("--stop-server")
        if ($sccacheStop.ExitCode -ne 0) {
            # #239: sccache exits 2 from --stop-server when no daemon is listening (it has
            # already idle-exited, or was never started). That is a cleanup-time degradation,
            # named here, and it MUST NOT become this script's exit code — that leak is what
            # made a fully green gate report red.
            Write-Output "SCCACHE[ASTRO_CACHE_SERVER_STOP_NONZERO]: '$sccacheExe --stop-server' (127.0.0.1:$sccacheServerPort) exit=$($sccacheStop.ExitCode); the daemon was already gone. Cleanup-only degradation: the launcher exit code remains the child's. Daemon output: $($sccacheStop.Output -join ' | ')"
        }
    }
    catch {
        Write-Output "SCCACHE[ASTRO_CACHE_STATS_UNAVAILABLE]: $($_.Exception.Message)"
    }
    if (Test-Path -LiteralPath $target) {
        try {
            Remove-Item -LiteralPath $target -Recurse -Force
        }
        catch {
            $cleanupErrors += "target cleanup failed: $($_.Exception.Message)"
        }
    }
    if (Test-Path -LiteralPath $target) {
        $cleanupErrors += "target cleanup failed: $target remains"
    }
    if (Test-Path -LiteralPath $workspaceTemp) {
        try {
            Remove-Item -LiteralPath $workspaceTemp -Recurse -Force
        }
        catch {
            $cleanupErrors += "workspace temporary cleanup failed: $($_.Exception.Message)"
        }
    }
    if (Test-Path -LiteralPath $workspaceTemp) {
        $cleanupErrors += "workspace temporary cleanup failed: $workspaceTemp remains"
    }
    try {
        Remove-LauncherLockFile -LockPath $launcherLock
    }
    catch {
        $cleanupErrors += "launcher lock cleanup failed: $($_.Exception.Message)"
    }
    if (-not $workspaceTempParentExisted -and (Test-Path -LiteralPath $workspaceTempParent)) {
        try {
            Remove-Item -LiteralPath $workspaceTempParent -Force
        }
        catch {
            $cleanupErrors += "workspace temporary parent cleanup failed: $($_.Exception.Message)"
        }
    }
    foreach ($name in @("TEMP", "TMP", "TMPDIR", "GIT_CEILING_DIRECTORIES", "ASTRO_NO_ESCAPE_ATTRIBUTION")) {
        $previous = $previousTempEnvironment[$name]
        if ($null -eq $previous) {
            Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
        }
        else {
            Set-Item -Path "Env:$name" -Value $previous.Value
        }
    }
    # #239: the finally block must NEVER throw. A throw here unwinds past the exit
    # decision below and PowerShell reports a generic terminating error (exit 1),
    # destroying the child's real exit code — a red-for-green AND a green-for-red hazard.
    # Cleanup failures are recorded in $cleanupErrors and adjudicated below, loudly.
    if ($cleanupErrors.Count -eq 0) {
        Write-Output "CLEANUP[ASTRO_TARGET]: $target is absent"
        Write-Output "CLEANUP[ASTRO_WORKSPACE_TEMP]: $workspaceTemp is absent"
    }
}

# #239: THE exit-code contract, in one place.
#
#   1. Launcher fault (the child never produced an exit code)   -> $LauncherFaultExitCode
#   2. Child ran, cleanup failed, child was non-zero            -> the child's exit code
#      (a real hygiene failure is announced, but the child's own red is never overwritten)
#   3. Child ran, cleanup failed, child was zero                -> $LauncherCleanupFailedExitCode
#      (target/ or the workspace temp survived: a hygiene violation must not report green)
#   4. Child ran, cleanup clean                                 -> the child's exit code
#
# In every case the exit is EXPLICIT. The previous code only called `exit` when the child
# was non-zero and otherwise fell off the end of the script, which leaves $LASTEXITCODE as
# whatever the last native command in the finally block set — `sccache --stop-server`,
# exit 2 once the daemon had idle-timed-out. Callers that invoke this launcher in-session
# (`& .\scripts\windows-gnu-toolchain.ps1 ...`, which is exactly what
# scripts/invoke-native-aggregate.ps1 does before reading $LASTEXITCODE) then observed 2
# and reported a fully green gate as red.
if ($null -ne $launcherFault) {
    if ($cleanupErrors.Count -gt 0) {
        [Console]::Error.WriteLine("LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_CLEANUP_FAILED]: " + ($cleanupErrors -join "; "))
    }
    [Console]::Error.WriteLine("LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_FAULT]: " + $launcherFault.Exception.Message)
    [Console]::Error.WriteLine(($launcherFault | Out-String))
    exit $LauncherFaultExitCode
}
if ($cleanupErrors.Count -gt 0) {
    [Console]::Error.WriteLine("LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_CLEANUP_FAILED]: " + ($cleanupErrors -join "; "))
    if ($commandExit -ne 0) {
        [Console]::Error.WriteLine("LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_CLEANUP_FAILED]: reporting the child's exit code $commandExit; the cleanup failure above is additional, not a substitute.")
        exit $commandExit
    }
    exit $LauncherCleanupFailedExitCode
}
exit $commandExit
