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

        $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash
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

        $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash
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

        $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash
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
    param(
        [string]$MingwBin,
        [string]$LlvmBin,
        [string]$CppcheckRoot,
        [string]$RipgrepRoot,
        [string]$GitBin,
        [string]$GitUsrBin,
        [string]$SccacheExe,
        [string]$SccacheDir
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
}

function Set-WorkspaceTempEnvironment {
    param([string]$WorkspaceTemp)

    $env:TEMP = $WorkspaceTemp
    $env:TMP = $WorkspaceTemp
    $env:TMPDIR = $WorkspaceTemp
    # CBM store redirection (#194): codebase-memory-mcp registers a project by
    # writing <cache_dir>/<project>.db, where cache_dir is resolved by
    # cbm_resolve_cache_dir() (vendor/codebase-memory-mcp/src/foundation/platform.c)
    # with priority CBM_CACHE_DIR > $HOME/.cache/codebase-memory-mcp. Astrolabe
    # tests that call cbm_mcp_server_new(NULL) (astrolabe-bridge row-sink tool-runner,
    # vendored C integration tests) would otherwise persist project .db files into the
    # operator's GLOBAL store and never clean them up. Pinning CBM_CACHE_DIR to a
    # launcher-owned child of the workspace temp keeps every registration inside .tmp,
    # so it is deleted together with $workspaceTemp on launcher exit. Single-point,
    # fail-closed root-cause fix covering both the Rust and C test families.
    $cbmCacheDir = Join-Path $WorkspaceTemp "cbm-cache"
    New-Item -ItemType Directory -Path $cbmCacheDir -Force | Out-Null
    $env:CBM_CACHE_DIR = $cbmCacheDir
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
        $mingwHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $MingwBin $dll)).Hash
        $rustHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $rustBin $dll)).Hash
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
if (-not [string]::Equals($root, $ExpectedWorkspace, [StringComparison]::OrdinalIgnoreCase)) {
    throw "canonical workspace required: $ExpectedWorkspace (found $root)"
}
Set-Location -LiteralPath $root
$target = Join-Path $root "target"
$workspaceTempParent = Join-Path $root ".tmp"
$workspaceTempParentExisted = Test-Path -LiteralPath $workspaceTempParent
$workspaceTemp = Join-Path $workspaceTempParent "windows-gnu-toolchain-$PID"
$launcherLock = Join-Path $workspaceTempParent "astrolabe-launcher.lock"
if (Test-Path -LiteralPath $launcherLock) {
    $lockRaw = Get-Content -LiteralPath $launcherLock -Raw -ErrorAction SilentlyContinue
    $lockState = $null
    if (-not [string]::IsNullOrWhiteSpace($lockRaw)) {
        try {
            $lockState = ConvertFrom-Json -InputObject $lockRaw
        }
        catch {
            $lockState = $null
        }
    }
    $lockOwnerPid = $null
    if ($null -ne $lockState -and $lockState.PSObject.Properties['pid']) {
        $lockOwnerPid = [int]$lockState.pid
    }
    if ($null -eq $lockOwnerPid) {
        throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_UNREADABLE]: launcher lock exists but names no readable pid; verify no toolchain session is live, then remove it manually: $launcherLock"
    }
    $lockHolder = Get-Process -Id $lockOwnerPid -ErrorAction SilentlyContinue
    if ($null -ne $lockHolder) {
        $lockCommand = if ($lockState.PSObject.Properties['command']) { $lockState.command } else { "unknown" }
        $lockStarted = if ($lockState.PSObject.Properties['started']) { $lockState.started } else { "unknown" }
        throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_HELD]: another launcher session owns this workspace (pid=$lockOwnerPid, started=$lockStarted, command=$lockCommand); never stop or clean a live session's run - wait for the lock to release: $launcherLock"
    }
    Write-Output "LAUNCHER_LOCK[ASTRO_LAUNCHER_LOCK_STALE]: removing lock left by dead pid $lockOwnerPid"
    Remove-Item -LiteralPath $launcherLock -Force
}
if (Test-Path -LiteralPath $target) {
    throw "target must be absent before toolchain work: $target"
}
if ((Test-Path -LiteralPath $workspaceTempParent) -and -not (Test-Path -LiteralPath $workspaceTempParent -PathType Container)) {
    throw "workspace temporary parent is not a directory: $workspaceTempParent"
}
New-Item -ItemType Directory -Path $workspaceTempParent -Force | Out-Null
New-Item -ItemType File -Path $launcherLock -ErrorAction Stop | Out-Null
[ordered]@{
    pid = $PID
    started = (Get-Date).ToString("o")
    command = ("$Command $CommandArgsJson").Trim()
} | ConvertTo-Json -Compress | Set-Content -LiteralPath $launcherLock -Encoding UTF8

$toolsRoot = Join-Path $root ".toolchains"
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
$sccacheDir = Join-Path $root ".sccache"
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
Set-ToolchainEnvironment -MingwBin $mingwBin -LlvmBin $llvmBin -CppcheckRoot $cppcheckRoot -RipgrepRoot $ripgrepRoot -GitBin $gitBin -GitUsrBin $gitUsrBin -SccacheExe $sccacheExe -SccacheDir $sccacheDir
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

$commandArgs = @(ConvertFrom-Json -InputObject $CommandArgsJson)
foreach ($argument in $commandArgs) {
    if ($argument -isnot [string]) {
        throw "CommandArgsJson must contain only strings"
    }
}

$commandExit = 0
$previousTempEnvironment = @{}
foreach ($name in @("TEMP", "TMP", "TMPDIR", "CBM_CACHE_DIR")) {
    $previousTempEnvironment[$name] = Get-Item -Path "Env:$name" -ErrorAction SilentlyContinue
}
try {
    Set-WorkspaceTempEnvironment -WorkspaceTemp $workspaceTemp
    New-Item -ItemType Directory -Path $workspaceTemp -Force | Out-Null
    # #190: ensure the sccache server is up and zero its counters so --show-stats in
    # the finally reports THIS run's cold-vs-warm hit rate. The on-disk cache in
    # $sccacheDir persists across runs and the target/ wipe.
    & $sccacheExe --start-server *> $null
    & $sccacheExe --zero-stats *> $null
    Write-Output "SCCACHE[ASTRO_CACHE_ENABLED]: dir=$sccacheDir; size=$SccacheCacheSize; wrapper=$sccacheExe; CARGO_INCREMENTAL=0"
    & $Command @commandArgs
    if ($null -ne $LASTEXITCODE) {
        $commandExit = $LASTEXITCODE
    }
}
finally {
    # #190: surface this run's sccache stats to the evidence stream, then stop the
    # server (flushes stats, releases any handles under the workspace temp) BEFORE the
    # target/temp cleanup below. The on-disk cache in $sccacheDir is intentionally kept.
    try {
        Write-Output "SCCACHE[ASTRO_CACHE_STATS]:"
        & $sccacheExe --show-stats
        & $sccacheExe --stop-server *> $null
    }
    catch {
        Write-Output "SCCACHE[ASTRO_CACHE_STATS_UNAVAILABLE]: $($_.Exception.Message)"
    }
    $cleanupErrors = @()
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
    foreach ($name in @("TEMP", "TMP", "TMPDIR", "CBM_CACHE_DIR")) {
        $previous = $previousTempEnvironment[$name]
        if ($null -eq $previous) {
            Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
        }
        else {
            Set-Item -Path "Env:$name" -Value $previous.Value
        }
    }
    if ($cleanupErrors.Count -gt 0) {
        throw ($cleanupErrors -join "; ")
    }
    Write-Output "CLEANUP[ASTRO_TARGET]: $target is absent"
    Write-Output "CLEANUP[ASTRO_WORKSPACE_TEMP]: $workspaceTemp is absent"
}

if ($commandExit -ne 0) {
    exit $commandExit
}
