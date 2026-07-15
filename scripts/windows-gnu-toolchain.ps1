[CmdletBinding()]
param(
    [switch]$Bootstrap,
    [string]$Command,
    [string]$CommandArgsJson = "[]",
    # #317: positive driving GitHub issue recorded in every launcher lock.
    # String input permits a stable fail-closed refusal for malformed values.
    [string]$Issue = "",
    # #303: read-only diagnostic. Resolve the pinned ld.lld and print its path + version,
    # then exit. Runs before the lock/workspace/toolchain-env machinery so it can prove the
    # linker-resolution guard in isolation (FSV) without a full native build. -LlvmBinOverride
    # points the resolver at a sandbox bin (never a real build path) for the missing-binary
    # edge test; empty means the canonical pinned .toolchains bin.
    [switch]$ProbeLld,
    [string]$LlvmBinOverride = ""
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
# #303: the lld linker ships in the same pinned LLVM 20.1.8 bundle as clang-tidy/clang-format.
# Its version string is asserted independently of PATH resolution: gcc/collect2 PATH-searches
# for `ld.lld`, and this host carries an UNPINNED MSVS BuildTools LLD 12.0.0 ahead of the
# pinned bundle, so any lld-enabled build that does not force the pinned bin silently links
# with the stale linker (a "no silent fallback" invariant breach surfaced by #270).
$ExpectedLldVersion = "20.1.8"
$PinnedLldExeName = "ld.lld.exe"

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

function Remove-TreeResilient {
    <#
      #421: depth-independent recursive directory removal that is NOT MAX_PATH-bound.

      The launcher's exit cleanup previously used `Remove-Item -LiteralPath <dir>
      -Recurse -Force`. Under Windows PowerShell 5.1 (the documented host — see the
      Get-SccacheServerPort note — running on .NET Framework 4.8) that provider call
      is MAX_PATH (260-char) bound: a single path deeper than 260 bytes inside
      target/ — exactly what deep-store FSV fixtures create — makes it throw
      PathTooLongException. target/ then survives, the launcher exits
      $LauncherCleanupFailedExitCode (71, ASTRO_LAUNCHER_CLEANUP_FAILED), and the
      NEXT run refuses fail-closed at the "target must be absent" preflight (#421,
      observed live twice in wave-17; recovery needed a manual \\?\ python rmtree).

      robocopy is long-path aware WITHOUT a \\?\ prefix — it calls the *W path APIs
      internally — and mirroring an EMPTY source over the target with /MIR purges
      every descendant regardless of nesting depth, leaving only the now-empty top
      directory (a short path Remove-Item deletes trivially). This is Microsoft's own
      recommended path-too-long deletion technique. The alternatives the #421 recon
      named are both unreliable on this host: `Remove-Item \\?\...` (the WinPS 5.1
      provider mangles the \\?\ prefix) and .NET `[IO.Directory]::Delete(recursive)`
      (its .NET Framework 4.8 recursive enumerator is not dependably long-path-safe
      even under a \\?\ root). robocopy is depth-independent by construction.

      Bounded retries (/R:1 /W:1) so a genuinely LOCKED file cannot hang the launcher.
      This function does NOT decide success: the caller re-tests `Test-Path` after it
      returns and appends to $cleanupErrors (-> fail-closed ASTRO_LAUNCHER_CLEANUP_FAILED)
      if anything survived. The "target must be absent" preflight is untouched — only
      the deleter is made depth-independent, exactly per the #421 scope.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    # Scratch empty dir as a SIBLING of $Path (same volume, never nested inside the
    # tree being purged). It must not live under $env:TEMP: the launcher repoints
    # TEMP into $workspaceTemp, which is itself one of the trees this cleans, so a
    # scratch dir there would be deleted out from under the robocopy source.
    $parent = Split-Path -Parent $Path
    if ([string]::IsNullOrEmpty($parent)) {
        $parent = "."
    }
    $emptyDir = Join-Path $parent (".astro-rmtree-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
    try {
        $robocopy = Join-Path $env:SystemRoot "System32\robocopy.exe"
        if (-not (Test-Path -LiteralPath $robocopy -PathType Leaf)) {
            $robocopy = "robocopy.exe"
        }
        # /MIR mirror empty->target purges all descendants (files AND dirs) at any
        # depth. robocopy exit codes 0-7 are success bit-flags (>=8 = a real failure);
        # either way the caller's Test-Path is the authoritative fail-closed check, so
        # the code is captured as data (never thrown) and not used to decide success.
        $null = Invoke-NativeCapture -Exe $robocopy -Arguments @(
            $emptyDir, $Path, "/MIR", "/R:1", "/W:1",
            "/NFL", "/NDL", "/NJH", "/NJS", "/NP", "/NC", "/NS"
        )
        if (Test-Path -LiteralPath $Path) {
            # Only the now-empty top directory remains — a short path.
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        }
    }
    finally {
        if (Test-Path -LiteralPath $emptyDir) {
            Remove-Item -LiteralPath $emptyDir -Recurse -Force -ErrorAction SilentlyContinue
        }
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
    const uint JOB_OBJECT_MSG_EXIT_PROCESS = 7;
    const uint JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS = 8;
    const uint STOP_SENTINEL = 0xFFFFFFFF;
    const long OPEN = -1L;

    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_ASSOCIATE_COMPLETION_PORT { public IntPtr CompletionKey; public IntPtr CompletionPort; }

    IntPtr job, port;
    Thread thread;
    volatile bool stop;
    // #278 attempts 6+7: pid alone is ambiguous under PID REUSE, and first-seen
    // alone still false-attributes DEAD instances (attempt 7: four foreign-sweep
    // pids collided with startup children of ours first seen at 14:2x and long
    // dead when the foreign dirs appeared at 14:34+). Record each pid's INSTANCE
    // LIFETIME intervals [first_seen, last_seen] -- the port delivers both
    // NEW_PROCESS and (ABNORMAL_)EXIT_PROCESS -- a list per pid, because the OS
    // can recycle a pid WITHIN our own tree. last = OPEN(-1) means the instance
    // had not exited when the manifest was written (serialized as null; the gate
    // treats it as an open window -- never 'assume dead').
    readonly Dictionary<int, List<long[]>> pidIntervals = new Dictionary<int, List<long[]>>();
    readonly object gate = new object();
    string manifestPath;
    int launcherPid;
    long runStartedNs;
    bool dirty;
    long lastFlushNs;
    // #279: CAUSAL OWNED-PATH PROBE for the ATTRIBUTED (CBM store) roots. Store files
    // (_config.db, project DBs) carry no pid in their name, so pid-token attribution
    // cannot see an our-tree store write. The probe enumerates the protected store
    // roots and, via the Restart Manager, asks WHICH process currently holds each
    // file open; a file held by a tree pid is one our run touched -> owned_paths. The
    // gate reddens on an owned_paths store delta (the #246 backstop). COVERAGE WINDOW
    // (disclosed honestly, per #279): this is a periodic open-HANDLE probe, so a store
    // write that opens-and-closes between probe passes is not caught here -- that leak
    // is caught by the per-phase check-cbm-cache-hermeticity.py HOME-redirect bracket,
    // the authoritative #246 guard; this run-wide probe is a defence-in-depth layer
    // under it, catching long-held handles (an MCP server our tree spawned). FAIL
    // CLOSED: if the probe MECHANISM cannot run at all (RM unavailable), owned_paths
    // is serialized as JSON null and the gate treats attributed-root deltas as
    // unevaluable (ASTRO_NO_ESCAPE_OWNED_PATHS_UNEVALUABLE), never a silent empty.
    string[] storeRoots;
    readonly HashSet<string> ownedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    bool ownedProbeFailed;
    long lastProbeNs;

    static long NowUnixNs() {
        return (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).Ticks * 100L;
    }

    public static AstroTreeRecorder Start(string manifestPath, int launcherPid) {
        return Start(manifestPath, launcherPid, null);
    }

    public static AstroTreeRecorder Start(string manifestPath, int launcherPid, string[] storeRoots) {
        AstroTreeRecorder r = new AstroTreeRecorder();
        r.manifestPath = manifestPath;
        r.launcherPid = launcherPid;
        r.storeRoots = storeRoots;
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
        lock (r.gate) {
            List<long[]> spans = new List<long[]>();
            spans.Add(new long[] { r.runStartedNs, OPEN });
            r.pidIntervals[launcherPid] = spans;
        }
        r.Flush();
        r.thread = new Thread(r.Loop);
        r.thread.IsBackground = true;
        r.thread.Start();
        return r;
    }

    void OnNewProcess(int pid, long now) {
        lock (gate) {
            List<long[]> spans;
            if (!pidIntervals.TryGetValue(pid, out spans)) {
                spans = new List<long[]>();
                pidIntervals[pid] = spans;
            }
            // A NEW message for a pid whose last interval is still open is a
            // duplicate; otherwise this is a fresh instance (possibly the OS
            // recycling the pid WITHIN our tree) -> open a new interval.
            if (spans.Count == 0 || spans[spans.Count - 1][1] != OPEN) {
                spans.Add(new long[] { now, OPEN });
                dirty = true;
            }
        }
    }

    void OnExitProcess(int pid, long now) {
        lock (gate) {
            List<long[]> spans;
            if (pidIntervals.TryGetValue(pid, out spans)) {
                if (spans.Count > 0 && spans[spans.Count - 1][1] == OPEN) {
                    spans[spans.Count - 1][1] = now;
                    dirty = true;
                }
            } else {
                // Exit for a pid we never saw born (port-association edge case):
                // fail closed toward attribution -- treat it as alive since run
                // start, dead now.
                spans = new List<long[]>();
                spans.Add(new long[] { runStartedNs, now });
                pidIntervals[pid] = spans;
                dirty = true;
            }
        }
    }

    // ---- #279: Restart Manager owned-store-path probe -----------------------------
    const int CCH_RM_SESSION_KEY = 32;
    const int RM_MAX_APP_NAME = 256;    // CCH_RM_MAX_APP_NAME + 1
    const int RM_MAX_SVC_NAME = 64;     // CCH_RM_MAX_SVC_NAME + 1
    const int ERROR_MORE_DATA = 234;
    const int STORE_FILE_CAP = 4096;

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, StringBuilder strSessionKey);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames,
        uint nApplications, IntPtr rgApplications, uint nServices, string[] rgsServiceNames);
    [DllImport("rstrtmgr.dll")]
    static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo,
        [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);
    [DllImport("rstrtmgr.dll")]
    static extern int RmEndSession(uint pSessionHandle);

    [StructLayout(LayoutKind.Sequential)]
    struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct RM_PROCESS_INFO {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = RM_MAX_APP_NAME)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = RM_MAX_SVC_NAME)] public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }

    // Which protected store files are CURRENTLY held open by a process in `treePids`.
    // Static + explicit args so it is FSV-testable in isolation (scripts/test-attribution-owned-probe.ps1
    // holds a fixture store file open in a known pid and asserts the probe attributes it).
    // Throws only when the RM mechanism itself is unavailable (RmStartSession fails) --
    // that propagates to the caller as the fail-closed 'probe could not run' signal.
    public static List<string> ProbeOwnedStorePaths(int[] treePids, string[] roots) {
        List<string> owned = new List<string>();
        if (roots == null) return owned;
        HashSet<int> pids = new HashSet<int>();
        if (treePids != null) foreach (int p in treePids) pids.Add(p);
        foreach (string root in roots) {
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) continue;
            string[] files;
            try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
            catch { continue; }  // enumeration hiccup for one root: skip it, not a mechanism failure
            int n = Math.Min(files.Length, STORE_FILE_CAP);
            for (int i = 0; i < n; i++) {
                if (FileHeldByTreePid(files[i], pids)) owned.Add(files[i]);
            }
        }
        return owned;
    }

    static bool FileHeldByTreePid(string file, HashSet<int> pids) {
        uint session;
        StringBuilder key = new StringBuilder(CCH_RM_SESSION_KEY + 1);
        int rc = RmStartSession(out session, 0, key);
        if (rc != 0) throw new Exception("RmStartSession failed " + rc);  // RM mechanism unavailable
        try {
            string[] resources = new string[] { file };
            rc = RmRegisterResources(session, 1, resources, 0, IntPtr.Zero, 0, null);
            if (rc != 0) return false;  // per-file registration hiccup: skip this file
            uint needed = 0, count = 0, reason = 0;
            rc = RmGetList(session, out needed, ref count, null, ref reason);
            if (rc == 0 || needed == 0) return false;  // no holders
            if (rc != ERROR_MORE_DATA) return false;
            count = needed;
            RM_PROCESS_INFO[] infos = new RM_PROCESS_INFO[count];
            rc = RmGetList(session, out needed, ref count, infos, ref reason);
            if (rc != 0) return false;
            for (int i = 0; i < count; i++) {
                if (pids.Contains(infos[i].Process.dwProcessId)) return true;
            }
            return false;
        } finally {
            RmEndSession(session);
        }
    }

    // One probe pass over the store roots, unioned into the accumulated owned set.
    // A mechanism failure (RM unavailable) latches ownedProbeFailed -> owned_paths
    // serializes as JSON null -> the gate fails closed on attributed roots.
    void RunOwnedProbe() {
        if (storeRoots == null || storeRoots.Length == 0) return;
        int[] pids;
        lock (gate) {
            pids = new int[pidIntervals.Count];
            pidIntervals.Keys.CopyTo(pids, 0);
        }
        try {
            List<string> found = ProbeOwnedStorePaths(pids, storeRoots);
            lock (gate) {
                foreach (string p in found) { if (ownedPaths.Add(p)) dirty = true; }
            }
        } catch {
            lock (gate) { if (!ownedProbeFailed) { ownedProbeFailed = true; dirty = true; } }
        }
    }

    void Loop() {
        while (!stop) {
            uint bytes; UIntPtr key; IntPtr ov;
            bool got = GetQueuedCompletionStatus(port, out bytes, out key, out ov, 500);
            if (got) {
                long now = NowUnixNs();
                if (bytes == JOB_OBJECT_MSG_NEW_PROCESS) {
                    OnNewProcess((int)ov.ToInt64(), now);
                } else if (bytes == JOB_OBJECT_MSG_EXIT_PROCESS || bytes == JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS) {
                    OnExitProcess((int)ov.ToInt64(), now);
                } else if (bytes == STOP_SENTINEL) {
                    break;
                }
            }
            // #279: throttled owned-path probe (~every 3s), decoupled from the manifest
            // flush cadence -- an RM sweep of the store roots is heavier than a rewrite,
            // and long-held handles do not need sub-second sampling.
            long probeTick = NowUnixNs();
            bool doProbe;
            lock (gate) { doProbe = (probeTick - lastProbeNs > 3000000000L); }
            if (doProbe) { lock (gate) { lastProbeNs = NowUnixNs(); } RunOwnedProbe(); }
            // Throttled persistence: thousands of short-lived children generate
            // ~2 messages each; rewrite the manifest at most once a second and
            // always once more at Stop().
            long tick = NowUnixNs();
            bool doFlush;
            lock (gate) { doFlush = dirty && (tick - lastFlushNs > 1000000000L); }
            if (doFlush) Flush();
        }
    }

    static void AppendJsonString(StringBuilder sb, string value) {
        sb.Append('"');
        foreach (char c in value) {
            if (c == '"' || c == '\\') { sb.Append('\\'); sb.Append(c); }
            else if (c == '\n') sb.Append("\\n");
            else if (c == '\r') sb.Append("\\r");
            else if (c == '\t') sb.Append("\\t");
            else if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
            else sb.Append(c);
        }
        sb.Append('"');
    }

    void Flush() {
        List<KeyValuePair<int, List<long[]>>> snap = new List<KeyValuePair<int, List<long[]>>>();
        long flushNs;
        bool probeFailedSnap;
        List<string> ownedSnap = new List<string>();
        lock (gate) {
            foreach (KeyValuePair<int, List<long[]>> entry in pidIntervals) {
                List<long[]> copy = new List<long[]>();
                foreach (long[] span in entry.Value) copy.Add(new long[] { span[0], span[1] });
                snap.Add(new KeyValuePair<int, List<long[]>>(entry.Key, copy));
            }
            probeFailedSnap = ownedProbeFailed;
            foreach (string p in ownedPaths) ownedSnap.Add(p);
            dirty = false;
            lastFlushNs = NowUnixNs();
            flushNs = lastFlushNs;
        }
        ownedSnap.Sort(StringComparer.OrdinalIgnoreCase);
        StringBuilder sb = new StringBuilder();
        sb.Append("{\"schema\":\"astrolabe.no_escape_attribution.v1\",\"launcher_pid\":");
        sb.Append(launcherPid);
        sb.Append(",\"run_started_unix_ns\":");
        sb.Append(runStartedNs);
        // #278 attempt 8b: THROTTLE-RACE guard. This manifest is rewritten at most
        // once a second while the run is live, and the no-escape gate reads it
        // MID-SESSION (before the final Stop() flush). written_at stamps THIS flush
        // so the gate can tell that a shared-root delta postdates the manifest --
        // meaning the recorder had not yet observed the writing process -- and fail
        // toward RED (ASTRO_NO_ESCAPE_STALE_MANIFEST) instead of silently 'foreign'.
        sb.Append(",\"written_at\":");
        sb.Append(flushNs);
        sb.Append(",\"tree_pids\":[");
        for (int i = 0; i < snap.Count; i++) { if (i > 0) sb.Append(','); sb.Append(snap[i].Key); }
        sb.Append("],\"pid_first_seen\":{");
        for (int i = 0; i < snap.Count; i++) {
            if (i > 0) sb.Append(',');
            sb.Append('"'); sb.Append(snap[i].Key); sb.Append("\":"); sb.Append(snap[i].Value[0][0]);
        }
        sb.Append("},\"pid_intervals\":{");
        for (int i = 0; i < snap.Count; i++) {
            if (i > 0) sb.Append(',');
            sb.Append('"'); sb.Append(snap[i].Key); sb.Append("\":[");
            List<long[]> spans = snap[i].Value;
            for (int j = 0; j < spans.Count; j++) {
                if (j > 0) sb.Append(',');
                sb.Append('['); sb.Append(spans[j][0]); sb.Append(',');
                if (spans[j][1] == OPEN) sb.Append("null"); else sb.Append(spans[j][1]);
                sb.Append(']');
            }
            sb.Append(']');
        }
        // #279: owned_paths is JSON null when the probe MECHANISM could not run (the
        // gate then treats attributed-root deltas as unevaluable, fail-closed), else a
        // list of the store paths a tree process was observed holding open (empty = the
        // probe ran and our tree touched no store file, so foreign store churn stays
        // counted). null vs [] is the load-bearing distinction the gate reads (#279).
        sb.Append("},\"owned_paths\":");
        if (probeFailedSnap) {
            sb.Append("null");
        } else {
            sb.Append('[');
            for (int i = 0; i < ownedSnap.Count; i++) {
                if (i > 0) sb.Append(',');
                AppendJsonString(sb, ownedSnap[i]);
            }
            sb.Append(']');
        }
        sb.Append('}');
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
        // #279: one last owned-path probe before the final flush. Our tree processes
        // are mostly dead by now (RM finds nothing on them), so this teardown pass
        // rarely adds paths -- the accumulation across the throttled in-run passes is
        // what catches live store handles. It also latches ownedProbeFailed if RM only
        // became unavailable late, keeping the final owned_paths honest (null on failure).
        RunOwnedProbe();
        // Final write happens AFTER the tree is done, so nearly every instance
        // carries a real exit stamp; anything still open stays an open window.
        Flush();
        if (port != IntPtr.Zero) CloseHandle(port);
        if (job != IntPtr.Zero) CloseHandle(job);
    }
}
'@

function Start-AstroTreeAttribution {
    param([string]$ManifestPath, [int]$LauncherPid, [string[]]$StoreRoots = @())
    if (-not ([System.Management.Automation.PSTypeName]'AstroTreeRecorder').Type) {
        Add-Type -TypeDefinition $AstroTreeRecorderSource -Language CSharp -ErrorAction Stop
    }
    return [AstroTreeRecorder]::Start($ManifestPath, $LauncherPid, $StoreRoots)
}

# #279: the protected CBM-store roots the owned-path probe scans, read from the SAME
# registry the gate polices (scripts/no-escape-roots.json, mode=attributed) so the two
# never drift. The launcher never redirects its OWN $HOME (only child sandboxes do), so
# ${REAL_HOME}/${REAL_LOCALAPPDATA} resolved here from the launcher's real profile match
# the env-independent roots the gate resolves via SHGetKnownFolderPath. A registry that
# cannot be read yields an empty set (the probe scans nothing, owned_paths=[]); it is not
# a probe MECHANISM failure, so it never forces the fail-closed null.
function Get-AstroAttributedStoreRoots {
    param([string]$RegistryPath)
    $roots = @()
    try {
        if (-not (Test-Path -LiteralPath $RegistryPath)) { return @() }
        $registry = Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json
        $realHome = [Environment]::GetFolderPath('UserProfile')
        $vars = @{
            'REAL_HOME'         = $realHome
            'REAL_LOCALAPPDATA' = (Join-Path $realHome 'AppData\Local')
            'REAL_CACHE'        = (Join-Path $realHome '.cache')
        }
        foreach ($root in $registry.roots) {
            if ($root.mode -ne 'attributed') { continue }
            $expanded = $root.path
            foreach ($name in $vars.Keys) {
                $expanded = $expanded.Replace('${' + $name + '}', $vars[$name])
            }
            if ($expanded -notmatch '\$\{') {
                $roots += ($expanded -replace '/', '\')
            }
        }
    }
    catch {
        return @()
    }
    return $roots
}

function Resolve-PinnedLld {
    <#
      #303: resolve the `ld.lld` used for lld-enabled x86_64-pc-windows-gnu links to the
      pinned LLVM 20.1.8 bundle ONLY. This computes the linker path DIRECTLY from the pinned
      .toolchains bin -- it NEVER consults PATH -- so a decoy `ld.lld` earlier on PATH (this
      host's unpinned MSVS BuildTools LLD 12.0.0) can never be returned. It refuses to hand
      back the path unless `ld.lld --version` reports the pinned $ExpectedLldVersion. Every
      refusal is fail-closed and carries {code, message, remediation}. Returns the resolved
      absolute path on success.
    #>
    param([Parameter(Mandatory)][string]$LlvmBin)

    $pinnedLld = Join-Path $LlvmBin $PinnedLldExeName
    if (-not (Test-Path -LiteralPath $pinnedLld -PathType Leaf)) {
        throw "LAUNCHER_BOUNDARY[ASTRO_PINNED_LLD_MISSING]: {code=ASTRO_PINNED_LLD_MISSING; message=`"pinned ld.lld ($PinnedLldExeName) is absent from the pinned LLVM $ExpectedLldVersion bundle at $pinnedLld`"; remediation=`"rerun 'scripts\windows-gnu-toolchain.ps1 -Issue <driving-issue> -Bootstrap' from $ExpectedWorkspace to (re)install the pinned LLVM $ExpectedLldVersion bundle`"}"
    }
    $probe = Invoke-NativeCapture -Exe $pinnedLld -Arguments @("--version")
    $versionText = ($probe.Output -join "`n").Trim()
    if ($probe.ExitCode -ne 0) {
        throw "LAUNCHER_BOUNDARY[ASTRO_PINNED_LLD_PROBE_FAILED]: {code=ASTRO_PINNED_LLD_PROBE_FAILED; message=`"pinned ld.lld at $pinnedLld failed its '--version' probe (exit $($probe.ExitCode)): $versionText`"; remediation=`"the pinned linker is corrupt or unrunnable; rerun 'scripts\windows-gnu-toolchain.ps1 -Issue <driving-issue> -Bootstrap' from $ExpectedWorkspace to reinstall the pinned LLVM $ExpectedLldVersion bundle`"}"
    }
    if ($versionText -notmatch [regex]::Escape($ExpectedLldVersion)) {
        throw "LAUNCHER_BOUNDARY[ASTRO_PINNED_LLD_VERSION]: {code=ASTRO_PINNED_LLD_VERSION; message=`"pinned ld.lld at $pinnedLld reported an unexpected version; expected LLD $ExpectedLldVersion, got: $versionText`"; remediation=`"remove the mismatched .toolchains LLVM bundle and rerun 'scripts\windows-gnu-toolchain.ps1 -Issue <driving-issue> -Bootstrap' from $ExpectedWorkspace to reinstall the pinned LLVM $ExpectedLldVersion bundle`"}"
    }
    return (Resolve-Path -LiteralPath $pinnedLld).Path
}

function Assert-GccResolvesPinnedLld {
    <#
      #303: end-to-end guard run BEFORE any lld-enabled build. gcc/collect2 must resolve
      `ld.lld` to the pinned LLVM 20.1.8 linker, not the host's unpinned MSVS BuildTools LLD.
      Passing `-B<pinned-bin>\` pins collect2's ld.lld search to the pinned directory ahead of
      PATH; `-Wl,--version` makes the resolved linker print its identity so it can be asserted.
      Fails closed with {code, message, remediation} unless the linker reports LLD
      $ExpectedLldVersion. Returns the pinned ld.lld path on success.
    #>
    param(
        [Parameter(Mandatory)][string]$GccExe,
        [Parameter(Mandatory)][string]$LlvmBin,
        [Parameter(Mandatory)][string]$ScratchDir
    )

    $pinnedLld = Resolve-PinnedLld -LlvmBin $LlvmBin
    # gcc treats -B as a filename PREFIX, so it must end in a directory separator or the
    # concatenation becomes "<bin>ld.lld" instead of "<bin>\ld.lld".
    $lldPrefix = ($LlvmBin.TrimEnd('\', '/')) + '\'
    New-Item -ItemType Directory -Path $ScratchDir -Force | Out-Null
    $trivialC = Join-Path $ScratchDir "astro-lld-probe-$PID.c"
    $trivialExe = Join-Path $ScratchDir "astro-lld-probe-$PID.exe"
    Set-Content -LiteralPath $trivialC -Value "int main(void){return 0;}" -Encoding ASCII
    try {
        $probe = Invoke-NativeCapture -Exe $GccExe -Arguments @("-B$lldPrefix", "-fuse-ld=lld", $trivialC, "-o", $trivialExe, "-Wl,--version")
        $versionText = ($probe.Output -join "`n").Trim()
        if ($versionText -notmatch [regex]::Escape("LLD $ExpectedLldVersion")) {
            throw "LAUNCHER_BOUNDARY[ASTRO_LLD_RESOLUTION_POISONED]: {code=ASTRO_LLD_RESOLUTION_POISONED; message=`"gcc -fuse-ld=lld resolved a linker other than the pinned LLD $ExpectedLldVersion (pinned=$pinnedLld); linker reported: $versionText`"; remediation=`"an unpinned ld.lld (e.g. this host's MSVS BuildTools LLD 12.0.0) is shadowing the pinned bundle; the launcher prepends $LlvmBin to PATH and pins collect2 to it via -B$lldPrefix -- if this still fires the pinned bundle is broken, so rerun 'scripts\windows-gnu-toolchain.ps1 -Issue <driving-issue> -Bootstrap' from $ExpectedWorkspace`"}"
        }
    }
    finally {
        Remove-Item -LiteralPath $trivialC -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $trivialExe -Force -ErrorAction SilentlyContinue
    }
    return $pinnedLld
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

# #303: read-only linker-resolution diagnostic. Proves Resolve-PinnedLld in isolation --
# never PATH-searched, fail-closed on missing/wrong-version -- without touching the session
# lock, target/, or the toolchain environment. Runs before all of that machinery.
if ($ProbeLld) {
    if ([string]::IsNullOrWhiteSpace($LlvmBinOverride)) {
        $probeLlvmBin = Join-Path (Join-Path (Join-Path $ExpectedWorkspace ".toolchains") $LlvmDirectoryName) "bin"
    }
    else {
        $probeLlvmBin = $LlvmBinOverride
    }
    try {
        $resolved = Resolve-PinnedLld -LlvmBin $probeLlvmBin
    }
    catch {
        Write-Output "PROBE_LLD[ASTRO_PINNED_LLD_FAILCLOSED]: $($_.Exception.Message)"
        exit 3
    }
    $probeVersion = (Invoke-NativeCapture -Exe $resolved -Arguments @("--version")).Output -join "`n"
    Write-Output "PROBE_LLD[ASTRO_PINNED_LLD_RESOLVED]: path=$resolved"
    Write-Output "PROBE_LLD[ASTRO_PINNED_LLD_VERSION]: $($probeVersion.Trim())"
    exit 0
}

# #317: tracker ownership is part of the lock schema, not optional metadata.
# Validate before resolving/creating any workspace lock path so a malformed or
# absent issue can never acquire a partially owned session.
$drivingIssue = 0
if (-not [int]::TryParse($Issue, [ref]$drivingIssue) -or $drivingIssue -le 0) {
    throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_ISSUE_INVALID]: {code=ASTRO_LAUNCHER_ISSUE_INVALID; message=`"the native launcher requires a positive driving GitHub issue number; received '$Issue'`"; remediation=`"re-read the driving issue, post the tracker comment required by #197, then rerun with -Issue <positive-issue-number>`"}"
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
    # #436: fail closed with a structured, layout-naming remediation. #226 deliberately
    # scoped valid worktree roots to `.claude\worktrees\` (predictable hygiene surface --
    # worktree-local target/, .tmp/, and session lock -- with shared pinned tools adjacent
    # to the canonical workspace). A registered git worktree (a `.git` FILE) parked anywhere
    # else is still refused, but the operator gets the exact `git worktree move` remediation
    # instead of a bare boundary message. Scope kept (not widened to gitdir-verified roots
    # anywhere): the fixed layout is what makes the shared-tool/port/lock derivation and the
    # cross-session hygiene sweeps predictable, and wave provisioning already parks worktrees
    # under `.claude\worktrees\`.
    $rootIsRegisteredWorktree = Test-Path -LiteralPath (Join-Path $root ".git") -PathType Leaf
    $rootKind = if ($rootIsRegisteredWorktree) { "a registered git worktree outside the supported worktree layout" } else { "neither the canonical workspace nor a registered git worktree of it" }
    throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_ROOT_UNSUPPORTED]: {code=ASTRO_LAUNCHER_ROOT_UNSUPPORTED; message=`"the native launcher runs only from the canonical workspace '$ExpectedWorkspace' or a registered git worktree directly under '$worktreeParent\'; the resolved root '$root' is $rootKind`"; remediation=`"move the worktree under the supported layout with: git -C '$ExpectedWorkspace' worktree move '$root' '$worktreeParent\<name>' -- then rerun the launcher from the new path; or run the launcher from the canonical workspace '$ExpectedWorkspace'`"}"
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
# #301: the no-escape attribution manifest lifecycle (dead-PID startup sweep + own-manifest
# exit removal) lives in one audited, dot-sourceable helper that -- like the lock helper --
# NEVER stops a process and treats a live-PID manifest as inviolable.
. (Join-Path $PSScriptRoot "attribution-manifest.ps1")
# #320: liveness-gated reaper for per-run TEMP child dirs left behind when a run's owner
# pwsh died while a detached child was still executing (that run's finally deferred its own
# cleanup). Like the lock/manifest helpers it NEVER stops a process and reaps a dir only when
# the whole owning process tree is dead.
. (Join-Path $PSScriptRoot "launcher-temp-guard.ps1")
Assert-AstroLauncherLockClaimable -LockPath $launcherLock
# #280: ASTROLABE_CONTIGUOUS_BATCH=1 (the CLAUDE.md contiguous-verification-
# batch carve-out) keeps target/ warm between consecutive runs of one session,
# so a present target/ is the expected state there, not a hygiene fault.
if ((Test-Path -LiteralPath $target) -and ($env:ASTROLABE_CONTIGUOUS_BATCH -ne "1")) {
    throw "target must be absent before toolchain work: $target"
}
if (($env:ASTROLABE_CONTIGUOUS_BATCH -eq "1") -and (Test-Path -LiteralPath $target)) {
    Write-Output "TARGET[ASTRO_BATCH_WARM]: ASTROLABE_CONTIGUOUS_BATCH=1 -> reusing warm target/ from this session's batch"
}
if ((Test-Path -LiteralPath $workspaceTempParent) -and -not (Test-Path -LiteralPath $workspaceTempParent -PathType Container)) {
    throw "workspace temporary parent is not a directory: $workspaceTempParent"
}
New-Item -ItemType Directory -Path $workspaceTempParent -Force | Out-Null
# #301: sweep stale dead-PID attribution manifests left by crashed/killed prior runs
# before starting this run's recorder. Probes each manifest's embedded PID (Get-Process
# -Id) and removes ONLY dead-PID ones; a manifest naming a live concurrent session's PID
# is inviolable (#197), and this run's own (not-yet-written) manifest is skipped.
$attributionSweep = Clear-DeadAttributionManifests -Directory $workspaceTempParent -SelfPid $PID
if ($attributionSweep.Removed.Count -gt 0 -or $attributionSweep.Kept.Count -gt 0) {
    Write-Output "NO_ESCAPE[ASTRO_ATTRIBUTION_SWEEP]: removed $($attributionSweep.Removed.Count) stale dead-PID attribution manifest(s); left $($attributionSweep.Kept.Count) live-PID manifest(s) untouched (#197/#301)"
}
# #320: reap per-run TEMP child dirs (.tmp/windows-gnu-toolchain-<pid>) left by prior runs
# whose owner pwsh died while a detached child kept executing -- those runs' finally blocks
# deliberately DEFERRED their own cleanup so the live child kept its working tree. This is
# where that deferred cleanup is finally collected, but ONLY for dirs whose whole process
# tree is dead: a dir owned by a live concurrent session, or one whose detached child is
# still alive, is left untouched (#197/#320). Runs after the attribution sweep so a dir's
# sibling manifest is still on disk to probe its recorded child pids.
$tempSweep = Clear-DeadLauncherTempDirs -Directory $workspaceTempParent -SelfPid $PID
if ($tempSweep.Removed.Count -gt 0 -or $tempSweep.Kept.Count -gt 0) {
    Write-Output "CLEANUP[ASTRO_LAUNCHER_TEMP_SWEEP]: reaped $($tempSweep.Removed.Count) dead-owner TEMP child dir(s); left $($tempSweep.Kept.Count) still-live-owner dir(s) untouched (#197/#320)"
}
# #197: atomic lock claim — write the full manifest to a PID-named staging
# sibling, then move it onto the lock name WITHOUT clobbering. No reader can
# ever observe a claimed-but-empty or half-written lock (the #186 UNREADABLE
# race), and a concurrent claim between the boundary check above and this move
# surfaces as a named fail-closed refusal instead of overwriting a live lock.
$launcherLockStage = "$launcherLock.$PID.tmp"
$launcherCommand = ("$Command $CommandArgsJson").Trim()
if ([string]::IsNullOrWhiteSpace($launcherCommand)) {
    $launcherCommand = if ($Bootstrap) { "bootstrap" } else { "environment-probe" }
}
[ordered]@{
    pid = $PID
    issue = $drivingIssue
    started = (Get-Date).ToString("o")
    command = $launcherCommand
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

# #303: when the operator opts into the #270 lld linker (RUSTFLAGS carries -fuse-ld=lld),
# guarantee the pinned LLVM 20.1.8 ld.lld -- never the host's unpinned MSVS BuildTools LLD --
# is the one gcc/collect2 uses. Set-ToolchainEnvironment already prepends the pinned LLVM bin
# to PATH; here we (1) end-to-end probe gcc and FAIL CLOSED unless it resolves LLD 20.1.8,
# then (2) pin collect2's ld.lld search to the pinned dir via -B for the actual child build,
# so a poisoned PATH cannot silently downgrade the linker. This only ADDS a pin when lld is
# already requested; the default ld.bfd path is untouched.
if ($env:RUSTFLAGS -and ($env:RUSTFLAGS -match 'fuse-ld=lld')) {
    $pinnedLld = Assert-GccResolvesPinnedLld -GccExe $env:CC -LlvmBin $llvmBin -ScratchDir $workspaceTempParent
    $lldPrefix = ($llvmBin.TrimEnd('\', '/')) + '\'
    $lldPinArg = "-Clink-arg=-B$lldPrefix"
    if ($env:RUSTFLAGS -notmatch [regex]::Escape($lldPinArg)) {
        $env:RUSTFLAGS = "$lldPinArg $($env:RUSTFLAGS)"
    }
    Write-Output "LLD[ASTRO_PINNED_LLD]: lld-enabled build detected in RUSTFLAGS; verified gcc resolves $pinnedLld (LLD $ExpectedLldVersion); pinned collect2 ld.lld search via -B$lldPrefix ahead of PATH"
}

if ([string]::IsNullOrWhiteSpace($Command)) {
    Write-Output 'Ready. Example: .\scripts\windows-gnu-toolchain.ps1 -Issue <driving-issue> -Command cargo -CommandArgsJson ''["test","-p","cbm-sys","--lib"]'''
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
        # #279: resolve the attributed CBM-store roots from the gate's own registry so
        # the recorder's owned-path probe scans exactly the roots the gate polices.
        # #318: PowerShell unwraps function output: zero rows become $null and one row
        # becomes a scalar. Keep the native zero/one/many shapes normalized so strict
        # mode can safely read .Count and the recorder always receives string[].
        [string[]]$attributedStoreRoots = @(Get-AstroAttributedStoreRoots -RegistryPath (Join-Path $PSScriptRoot "no-escape-roots.json"))
        $treeRecorder = Start-AstroTreeAttribution -ManifestPath $attributionManifest -LauncherPid $PID -StoreRoots $attributedStoreRoots
        $env:ASTRO_NO_ESCAPE_ATTRIBUTION = $attributionManifest
        Write-Output "NO_ESCAPE[ASTRO_ATTRIBUTION_RECORDING]: process-tree PIDs -> $attributionManifest"
        Write-Output "NO_ESCAPE[ASTRO_OWNED_PATH_PROBE]: owned-path probe over $($attributedStoreRoots.Count) attributed store root(s): $($attributedStoreRoots -join '; ')"
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
    # #320: LIVENESS GATE. The recorder's final flush (above) leaves any DETACHED child of
    # this run -- a cargo/rustc/test grandchild that outlived the owner pwsh -- as an OPEN
    # interval in $attributionManifest. Probe those recorded pids against the OS; if ANY is
    # still alive, tearing down target/ or the per-run TEMP child ($workspaceTemp) would rip a
    # live process's working tree out from under it (the #23 M-scale hazard: a running test's
    # fixture path resolved into a removed .tmp tree). In that case SKIP ALL cleanup atomically
    # -- attribution manifest, sccache daemon, target/, TEMP child, session lock, and temp
    # parent all stay in place, never a PARTIAL teardown -- and emit one fail-closed boundary
    # line. The next launcher start reaps this run's leftovers (Clear-DeadLauncherTempDirs /
    # Clear-DeadAttributionManifests) once the whole tree is dead. Env restore below still runs
    # (restoring the launcher's own process env is not a hazard to the children).
    $deferCleanupForLiveChildren = $false
    $liveAttributedPids = @()
    try {
        $liveAttributedPids = @((Get-AstroLiveAttributedPids -ManifestPath $attributionManifest -SelfPid $PID).LivePids)
    }
    catch {
        $liveAttributedPids = @()
    }
    if ($liveAttributedPids.Count -gt 0) {
        $deferCleanupForLiveChildren = $true
        [Console]::Error.WriteLine("LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_CLEANUP_DEFERRED_LIVE_CHILD]: {code=ASTRO_LAUNCHER_CLEANUP_DEFERRED_LIVE_CHILD; message=`"$($liveAttributedPids.Count) attributed child process(es) of this run are still alive (pids: $($liveAttributedPids -join ', ')); ALL exit cleanup is skipped so their working tree is not torn out mid-execution -- target/, the TEMP child $workspaceTemp, the session lock, and the attribution manifest are left in place, never partially removed`"; remediation=`"do not remove .tmp or target/ by hand while those PIDs live; the next 'scripts\\windows-gnu-toolchain.ps1' start reaps this run's leftovers automatically once the whole process tree is dead (Clear-DeadLauncherTempDirs / Clear-DeadAttributionManifests)`"}")
        Write-Output "CLEANUP[ASTRO_CLEANUP_DEFERRED]: deferred all exit cleanup; $($liveAttributedPids.Count) attributed child pid(s) still alive: $($liveAttributedPids -join ', ') (#320)"
    }
  if (-not $deferCleanupForLiveChildren) {
    # #301: remove THIS run's attribution manifest (and its atomic-rename sibling) on
    # EVERY exit path -- success, child failure, and launcher fault all reach this finally.
    # The manifest lives in $workspaceTempParent (.tmp), NOT the per-session $workspaceTemp
    # the block below wipes, so without this it accumulated forever (49 stale files, #301).
    # Non-throwing (Remove-AstroAttributionManifest reports via return, never throws) so the
    # #239 finally-must-not-throw contract holds. Runs even if the recorder never started
    # (the manifest may have been flushed once before a fault).
    try {
        $removedManifests = @(Remove-AstroAttributionManifest -Path $attributionManifest)
        if ($removedManifests.Count -gt 0) {
            Write-Output "CLEANUP[ASTRO_ATTRIBUTION_MANIFEST]: removed this run's attribution manifest ($($removedManifests -join ', '))"
        }
    }
    catch {
        $cleanupErrors += "attribution manifest cleanup failed: $($_.Exception.Message)"
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
    # #280: ASTROLABE_CONTIGUOUS_BATCH=1 invokes the CLAUDE.md "contiguous
    # verification batch" carve-out — consecutive gate runs within one session
    # keep target/ warm (the workspace-test phase is ~95% rebuild cost from a
    # cold target/; measured 143s rebuild vs 6.6s of actual test execution).
    # The invoking session REMAINS obligated to wipe target/ at every batch
    # boundary (turn end, pause, issue close, handoff) — this flag never
    # weakens that rule, it only moves the wipe from per-invocation to
    # per-batch, and the default (unset) behavior is unchanged.
    if ($env:ASTROLABE_CONTIGUOUS_BATCH -eq "1") {
        Write-Output "CLEANUP[ASTRO_TARGET_BATCH_DEFERRED]: ASTROLABE_CONTIGUOUS_BATCH=1 -> target/ kept warm; the batch owner wipes it at the batch boundary"
    }
    else {
        if (Test-Path -LiteralPath $target) {
            try {
                # #421: depth-independent, not MAX_PATH-bound (deep-store FSV fixtures).
                Remove-TreeResilient -Path $target
            }
            catch {
                $cleanupErrors += "target cleanup failed: $($_.Exception.Message)"
            }
        }
        if (Test-Path -LiteralPath $target) {
            $cleanupErrors += "target cleanup failed: $target remains"
        }
    }
    if (Test-Path -LiteralPath $workspaceTemp) {
        try {
            # #421: depth-independent, not MAX_PATH-bound (deep FSV temp fixtures).
            Remove-TreeResilient -Path $workspaceTemp
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
  }
  # #320: env restore ALWAYS runs, even when cleanup was deferred for live children --
  # restoring the launcher's own process environment cannot affect the detached children
  # (they already inherited their env at spawn) and leaving TEMP/TMP pointed at a now-kept
  # child dir would poison this pwsh's remaining lifetime.
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
    if (-not $deferCleanupForLiveChildren -and $cleanupErrors.Count -eq 0) {
        if ($env:ASTROLABE_CONTIGUOUS_BATCH -ne "1") {
            Write-Output "CLEANUP[ASTRO_TARGET]: $target is absent"
        }
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
