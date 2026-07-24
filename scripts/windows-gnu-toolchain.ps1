[CmdletBinding()]
param(
    [switch]$Bootstrap,
    [string]$Command,
    [string]$CommandArgsJson = "[]",
    # #317: positive driving GitHub issue recorded in every launcher lock.
    # String input permits a stable fail-closed refusal for malformed values.
    [string]$Issue = "",
    # #651: explicit tracker-bound cleanup handoff for a target tree preserved by
    # a prior dead launcher generation after that generation's lease was archived.
    [switch]$RecoverPreservedTarget,
    [string]$TrackerCommentUrl = "",
    [string]$ExpectedTargetInventorySha256 = "",
    [string]$ExpectedTargetEntryCount = "",
    [string]$PriorRecoveryTransactionId = "",
    # #303: read-only diagnostic. Resolve the pinned ld.lld and print its path + version,
    # then exit. Runs before the lock/workspace/toolchain-env machinery so it can prove the
    # linker-resolution guard in isolation (FSV) without a full native build. -LlvmBinOverride
    # points the resolver at a sandbox bin (never a real build path) for the missing-binary
    # edge test; empty means the canonical pinned .toolchains bin.
    [switch]$ProbeLld,
    [string]$LlvmBinOverride = "",
    # #625: mutating launcher work always runs in a dedicated native PowerShell
    # process. This private handshake prevents direct invocation of the internal
    # process mode; the public invocation creates and waits for that process below.
    [Parameter(DontShow = $true)]
    [string]$InternalDedicatedToken = ""
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

function Get-AstroPreservedTargetInventory {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $root = [IO.Path]::GetFullPath($LiteralPath).TrimEnd('\', '/')
    $rootInfo = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootInfo.PSIsContainer -or
        ($rootInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "preserved target root is not one ordinary non-reparse directory: $root"
    }
    $items = @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop)
    [string[]]$paths = @($items | ForEach-Object { [IO.Path]::GetFullPath($_.FullName) })
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($path in $paths) {
        $prefix = $root + [IO.Path]::DirectorySeparatorChar
        if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "preserved target inventory escaped its exact root: $path"
        }
        $entry = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "preserved target inventory contains an unsupported reparse entry: $path"
        }
        $relative = $path.Substring($prefix.Length).Replace('\', '/')
        $relativeBase64 = [Convert]::ToBase64String(
            [Text.UTF8Encoding]::new($false, $true).GetBytes($relative)
        )
        if ($entry.PSIsContainer) {
            $lines.Add("D`t$relativeBase64")
        }
        elseif (($entry.Attributes -band [IO.FileAttributes]::Directory) -eq 0) {
            $fileHash = (Get-Sha256Hex -LiteralPath $path).Hash.ToLowerInvariant()
            $lines.Add("F`t$relativeBase64`t$($entry.Length)`t$fileHash")
        }
        else {
            throw "preserved target inventory contains an unsupported entry type: $path"
        }
    }
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($lines -join "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $inventoryHash = ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
    return [pscustomobject]@{
        Path = $root
        EntryCount = $lines.Count
        InventorySha256 = $inventoryHash
    }
}

function Write-NewDurableUtf8File {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$Text
    )
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
    $stream = [IO.File]::Open(
        $LiteralPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
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
$NvccCcbinEnv = "NVCC_CCBIN"
$ForgeCudaCcbinEnv = "FORGE_CUDA_CCBIN"
$NvccAppendFlagsEnv = "NVCC_APPEND_FLAGS"
$MsvcRuntimeArchiveName = "msvcrt.lib"
$MsvcRuntimeSupportMembers = @(
    "amdsecgs.obj",
    "gshandler.obj",
    "gshandlereh4.obj",
    "gs_cookie.obj",
    "gs_report.obj",
    "thread_safe_statics.obj"
)
$MsvcRuntimeImportLibNames = @(
    "vcruntime.lib",
    "msvcprt.lib"
)
$MsvcVcStartupArchiveName = "libcmt.lib"
$MsvcVcStartupSupportMembers = @(
    "delete_scalar_size.obj",
    "delete_array_size.obj",
    "std_type_info_static.obj",
    "ehvecdtr.obj",
    "fltused.obj"
)
$WindowsKitUcrtImportLibName = "ucrt.lib"
$CudaImportLibNames = @(
    "cudart.lib",
    "cuda.lib",
    "nvrtc.lib",
    "curand.lib",
    "cublas.lib",
    "cublasLt.lib"
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

function Start-LauncherLockCleanupTransaction {
    param(
        [Parameter(Mandatory)][string]$LockPath,
        [Parameter(Mandatory)][int]$ExpectedPid,
        [Parameter(Mandatory)][int]$ExpectedIssue,
        [Parameter(Mandatory)][long]$ExpectedOwnerProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [Parameter(Mandatory)]$LeaseHandle,
        [Parameter(Mandatory)]$ProtocolDirectoryLease
    )
    $mutexLease = $null
    $transitionPublished = $false
    try {
        $mutexLease = Enter-AstroLauncherLockMutex $LockPath
        if (-not $mutexLease.Acquired) {
            $busyName = $mutexLease.Name
            Exit-AstroLauncherLockMutex $mutexLease
            $mutexLease = $null
            throw "exact launcher-lock claim/reclaim mutex is owned by another process ($busyName)"
        }
        $transitions = Get-AstroLauncherLockTransitions $LockPath
        if ($transitions.State -ne 'clear') {
            throw "launcher protocol transition inventory is '$($transitions.State)' ($(@($transitions.Paths) -join '; '); $($transitions.Error))"
        }
        $retained = Assert-AstroLauncherLockLeaseCurrent $LeaseHandle
        $handleState = $LeaseHandle.State
        if ($handleState.OwnerPid -ne $ExpectedPid -or
            $handleState.Issue -ne $ExpectedIssue -or
            $handleState.OwnerProcessStartUtcTicks -ne
                $ExpectedOwnerProcessStartUtcTicks -or
            $retained.Sha256 -cne $ExpectedSha256.ToLowerInvariant() -or
            -not [string]::Equals(
                $retained.Path,
                [IO.Path]::GetFullPath($LockPath),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "immutable handle does not bind expected pid=$ExpectedPid issue=#$ExpectedIssue ticks=$ExpectedOwnerProcessStartUtcTicks sha256=$($ExpectedSha256.ToLowerInvariant())"
        }
        $selfProbe = Get-AstroProcessIdentityProbe $ExpectedPid
        if ($selfProbe.State -ne 'observed' -or
            [long]$selfProbe.ProcessStartUtcTicks -ne
                $ExpectedOwnerProcessStartUtcTicks) {
            throw "cleanup process identity is not the exact lease owner (probe_state=$($selfProbe.State), observed_ticks=$($selfProbe.ProcessStartUtcTicks), error=$($selfProbe.Error))"
        }

        # The same DELETE-capable FILE_ID retained since claim is the only mutation
        # authority. The typed transition remains visible, and the Global mutex remains
        # held, throughout every subordinate cleanup operation.
        $cleanupLeaf = "astrolabe-launcher.lock.cleanup.v2.pid-$ExpectedPid.issue-$ExpectedIssue.ticks-$ExpectedOwnerProcessStartUtcTicks.sha256-$($ExpectedSha256.ToLowerInvariant()).$([Guid]::NewGuid().ToString('N'))"
        $renamed = Rename-AstroExactFileHandleNoReplace `
            -Lease $LeaseHandle `
            -DestinationDirectoryLease $ProtocolDirectoryLease `
            -DestinationLeaf $cleanupLeaf
        $transitionPublished = $true
        if ((Get-AstroPathEntryState $LockPath).State -ne 'absent') {
            throw "active launcher lock remains after exact handle-bound move: $LockPath"
        }
        if ($renamed.Sha256 -cne $ExpectedSha256.ToLowerInvariant() -or
            $renamed.FileId -cne $retained.FileId -or
            $renamed.Length -ne $retained.Length) {
            throw "cleanup transition does not retain the exact active FILE_ID/hash/length: $($renamed.DestinationPath)"
        }
        $duringTransition = Get-AstroLauncherLockTransitions $LockPath
        if ($duringTransition.State -ne 'present' -or
            @($duringTransition.Paths).Count -ne 1 -or
            -not [string]::Equals(
                [IO.Path]::GetFullPath(@($duringTransition.Paths)[0]),
                [IO.Path]::GetFullPath($renamed.DestinationPath),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "exact cleanup transition is not the sole classifier-visible transition after rename (state=$($duringTransition.State), paths=$(@($duringTransition.Paths) -join '; '), error=$($duringTransition.Error))"
        }
        $cleanupSnapshot = Assert-AstroLauncherLockLeaseCurrent $LeaseHandle
        if ($cleanupSnapshot.FileId -cne $retained.FileId -or
            $cleanupSnapshot.Length -ne $retained.Length -or
            $cleanupSnapshot.Sha256 -cne $retained.Sha256 -or
            [Convert]::ToBase64String($cleanupSnapshot.Bytes) -cne
                [Convert]::ToBase64String($retained.Bytes)) {
            throw 'cleanup transition retained handle changed identity or bytes after publication'
        }
        return [pscustomobject]@{
            LockPath = [IO.Path]::GetFullPath($LockPath)
            CleanupPath = [IO.Path]::GetFullPath($renamed.DestinationPath)
            CleanupLeaf = $cleanupLeaf
            FileId = $retained.FileId
            Length = $retained.Length
            Sha256 = $retained.Sha256
            Bytes = $retained.Bytes
            LeaseHandle = $LeaseHandle
            MutexLease = $mutexLease
            TransitionPublished = $true
            DispositionSet = $false
            Completed = $false
            Released = $false
        }
    }
    catch {
        $beginFault = $_.Exception.Message
        $releaseErrors = @()
        if ($null -ne $LeaseHandle -and
            $null -ne $LeaseHandle.SafeFileHandle -and
            -not $LeaseHandle.SafeFileHandle.IsClosed) {
            try { $LeaseHandle.SafeFileHandle.Dispose() }
            catch {
                $releaseErrors += "retained lock handle release failed: $($_.Exception.Message)"
            }
        }
        if ($null -ne $mutexLease) {
            try { Exit-AstroLauncherLockMutex $mutexLease }
            catch {
                $releaseErrors += "Global cleanup mutex release failed: $($_.Exception.Message)"
            }
        }
        $releaseSuffix = if ($releaseErrors.Count -gt 0) {
            '; release_errors=' + ($releaseErrors -join '; ')
        } else { '' }
        throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_CLEANUP_BEGIN_FAILED]: transition_published=$transitionPublished; active/subordinate state was not deleted; $beginFault$releaseSuffix"
    }
}

function Stop-LauncherLockCleanupTransaction {
    param(
        [Parameter(Mandatory)]$Transaction,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Reason
    )

    $errors = @()
    try {
        if ($Transaction.Released) {
            throw 'cleanup transaction was already released'
        }
        $retained = Assert-AstroLauncherLockLeaseCurrent $Transaction.LeaseHandle
        $transitions = Get-AstroLauncherLockTransitions $Transaction.LockPath
        if ($retained.FileId -cne $Transaction.FileId -or
            $retained.Length -ne $Transaction.Length -or
            $retained.Sha256 -cne $Transaction.Sha256 -or
            [Convert]::ToBase64String($retained.Bytes) -cne
                [Convert]::ToBase64String($Transaction.Bytes) -or
            -not [string]::Equals(
                $retained.Path,
                $Transaction.CleanupPath,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            $transitions.State -ne 'present' -or
            @($transitions.Paths).Count -ne 1 -or
            -not [string]::Equals(
                [IO.Path]::GetFullPath(@($transitions.Paths)[0]),
                $Transaction.CleanupPath,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            (Get-AstroPathEntryState $Transaction.LockPath).State -ne 'absent') {
            throw "cleanup transition could not be proven unchanged while preserving it (transition_state=$($transitions.State), paths=$(@($transitions.Paths) -join '; '))"
        }
    }
    catch {
        $errors += "preservation readback failed: $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $Transaction.LeaseHandle.SafeFileHandle -and
            -not $Transaction.LeaseHandle.SafeFileHandle.IsClosed) {
            try { $Transaction.LeaseHandle.SafeFileHandle.Dispose() }
            catch {
                $errors += "retained cleanup-transition handle release failed: $($_.Exception.Message)"
            }
        }
        if (-not $Transaction.Released) {
            try { Exit-AstroLauncherLockMutex $Transaction.MutexLease }
            catch {
                $errors += "Global cleanup mutex release failed: $($_.Exception.Message)"
            }
            $Transaction.Released = $true
        }
    }
    if ($errors.Count -gt 0) {
        throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_CLEANUP_PRESERVE_FAILED]: reason=$Reason; $($errors -join '; ')"
    }
    return [pscustomobject]@{
        State = 'preserved'
        CleanupPath = $Transaction.CleanupPath
        FileId = $Transaction.FileId
        Sha256 = $Transaction.Sha256
        Reason = $Reason
        MutexReleased = $Transaction.Released
    }
}

function Complete-LauncherLockCleanupTransaction {
    param(
        [Parameter(Mandatory)]$Transaction,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$OwnedTargetRoots,
        [Parameter(Mandatory)][string]$WorkspaceTemp,
        [Parameter(Mandatory)][string]$WorkspaceTempArchivePath,
        [Parameter(Mandatory)][string]$AttributionManifest,
        [Parameter(Mandatory)][string]$AttributionManifestArchivePath,
        [Parameter(Mandatory)][string]$ArchiveCompletionPath,
        [Parameter(Mandatory)][string]$JobObjectName,
        [Parameter(Mandatory)][int]$ExpectedPid
    )

    $completionFault = $null
    $releaseErrors = @()
    $deleted = $null
    try {
        if ($Transaction.Released) {
            throw 'cleanup transaction was already released'
        }
        foreach ($ownedPath in @($OwnedTargetRoots) + @(
                $WorkspaceTemp,
                $AttributionManifest
            )) {
            $state = Get-AstroPathEntryState $ownedPath
            if ($state.State -ne 'absent') {
                throw "owned subordinate is not independently absent (state=$($state.State), error=$($state.Error)): $ownedPath"
            }
        }
        foreach ($archivePath in @(
                $WorkspaceTempArchivePath,
                $AttributionManifestArchivePath,
                $ArchiveCompletionPath
            )) {
            $state = Get-AstroPathEntryState $archivePath
            if ($state.State -ne 'present') {
                throw "append-only archive evidence is not independently present (state=$($state.State), error=$($state.Error)): $archivePath"
            }
        }
        $jobProbe = Get-AstroLauncherJobObjectProbe -Name $JobObjectName
        [int[]]$jobPids = @($jobProbe.ProcessIds | Sort-Object -Unique)
        if ($jobProbe.State -ne 'observed' -or
            $jobPids.Count -ne 1 -or
            $jobPids[0] -ne $ExpectedPid) {
            throw "final named Job Object requery is not exact launcher-only state (state=$($jobProbe.State), pids=$($jobPids -join ','), error=$($jobProbe.Error))"
        }
        $retained = Assert-AstroLauncherLockLeaseCurrent $Transaction.LeaseHandle
        $transitions = Get-AstroLauncherLockTransitions $Transaction.LockPath
        if ($retained.FileId -cne $Transaction.FileId -or
            $retained.Length -ne $Transaction.Length -or
            $retained.Sha256 -cne $Transaction.Sha256 -or
            [Convert]::ToBase64String($retained.Bytes) -cne
                [Convert]::ToBase64String($Transaction.Bytes) -or
            -not [string]::Equals(
                $retained.Path,
                $Transaction.CleanupPath,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            $transitions.State -ne 'present' -or
            @($transitions.Paths).Count -ne 1 -or
            -not [string]::Equals(
                [IO.Path]::GetFullPath(@($transitions.Paths)[0]),
                $Transaction.CleanupPath,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            (Get-AstroPathEntryState $Transaction.LockPath).State -ne 'absent') {
            throw "cleanup transition changed before terminal disposition (transition_state=$($transitions.State), paths=$(@($transitions.Paths) -join '; '))"
        }

        # This is intentionally the final destructive operation in the transaction.
        $deleted = Invoke-AstroExactFileDispositionDelete $Transaction.LeaseHandle
        $Transaction.DispositionSet = $deleted.DispositionSet
        if ($deleted.State -ne 'absent') {
            throw "exact cleanup-transition disposition ended in state '$($deleted.State)' ($($deleted.Error)): $($deleted.Path)"
        }
        $terminalTransitions = Get-AstroLauncherLockTransitions $Transaction.LockPath
        $terminalActive = Get-AstroPathEntryState $Transaction.LockPath
        if ($terminalTransitions.State -ne 'clear' -or
            $terminalActive.State -ne 'absent') {
            throw "launcher protocol is not wholly absent after terminal disposition (active=$($terminalActive.State), transition_state=$($terminalTransitions.State), paths=$(@($terminalTransitions.Paths) -join '; '), error=$($terminalTransitions.Error))"
        }
        $Transaction.Completed = $true
    }
    catch {
        $completionFault = $_.Exception.Message
    }
    finally {
        if ($null -ne $completionFault -and
            -not $Transaction.DispositionSet -and
            $null -ne $Transaction.LeaseHandle.SafeFileHandle -and
            -not $Transaction.LeaseHandle.SafeFileHandle.IsClosed) {
            try {
                $preserved = Assert-AstroLauncherLockLeaseCurrent (
                    $Transaction.LeaseHandle
                )
                $preservedTransitions = Get-AstroLauncherLockTransitions (
                    $Transaction.LockPath
                )
                if ($preserved.FileId -cne $Transaction.FileId -or
                    $preserved.Length -ne $Transaction.Length -or
                    $preserved.Sha256 -cne $Transaction.Sha256 -or
                    [Convert]::ToBase64String($preserved.Bytes) -cne
                        [Convert]::ToBase64String($Transaction.Bytes) -or
                    -not [string]::Equals(
                        $preserved.Path,
                        $Transaction.CleanupPath,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    $preservedTransitions.State -ne 'present' -or
                    @($preservedTransitions.Paths).Count -ne 1 -or
                    -not [string]::Equals(
                        [IO.Path]::GetFullPath(
                            @($preservedTransitions.Paths)[0]
                        ),
                        $Transaction.CleanupPath,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    (Get-AstroPathEntryState $Transaction.LockPath).State -ne
                        'absent') {
                    throw "cleanup transition changed while handling a pre-disposition completion failure (transition_state=$($preservedTransitions.State), paths=$(@($preservedTransitions.Paths) -join '; '))"
                }
            }
            catch {
                $releaseErrors += "pre-disposition transition preservation readback failed: $($_.Exception.Message)"
            }
        }
        if ($null -ne $Transaction.LeaseHandle.SafeFileHandle -and
            -not $Transaction.LeaseHandle.SafeFileHandle.IsClosed) {
            try { $Transaction.LeaseHandle.SafeFileHandle.Dispose() }
            catch {
                $releaseErrors += "retained cleanup-transition handle release failed: $($_.Exception.Message)"
            }
        }
        if (-not $Transaction.Released) {
            try { Exit-AstroLauncherLockMutex $Transaction.MutexLease }
            catch {
                $releaseErrors += "Global cleanup mutex release failed: $($_.Exception.Message)"
            }
            $Transaction.Released = $true
        }
    }
    if ($null -ne $completionFault -or $releaseErrors.Count -gt 0) {
        throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_CLEANUP_COMPLETE_FAILED]: disposition_set=$($Transaction.DispositionSet); completed=$($Transaction.Completed); fault=$completionFault; release_errors=$($releaseErrors -join '; ')"
    }
    return [pscustomobject]@{
        State = 'absent'
        CleanupPath = $Transaction.CleanupPath
        FileId = $Transaction.FileId
        Sha256 = $Transaction.Sha256
        DispositionSet = $Transaction.DispositionSet
        Completed = $Transaction.Completed
        MutexReleased = $Transaction.Released
        TerminalPathState = $deleted.TerminalPathState
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

function Get-AstroOwnedCargoTargetRoots {
    # #534/#566: the complete set of Cargo target directories this launcher owns and must
    # clean under one root. An authoritative CARGO_TARGET_DIR (exported by
    # Set-ToolchainEnvironment) confines every Cargo child -- a nested
    # `--manifest-path calyx/Cargo.toml` invocation included -- to $Root\target, but a target
    # that already exists from a run predating that confinement (or a non-launcher cargo run)
    # must still be swept. The owned surface is the canonical root target plus one
    # `<dir>\target` for every depth-1 directory carrying its own Cargo.toml -- i.e. every
    # workspace a `--manifest-path <dir>/Cargo.toml` child could resolve (calyx/ today; cbm/ is
    # C source and has no Cargo.toml). Returns absolute, de-duplicated target paths, root first.
    param([Parameter(Mandatory)][string]$Root)

    $roots = New-Object System.Collections.Generic.List[string]
    $rootTarget = [IO.Path]::GetFullPath((Join-Path $Root "target"))
    $roots.Add($rootTarget)
    Get-ChildItem -LiteralPath $Root -Directory -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            $manifest = Join-Path $_.FullName "Cargo.toml"
            if (Test-Path -LiteralPath $manifest -PathType Leaf) {
                $nestedTarget = [IO.Path]::GetFullPath((Join-Path $_.FullName "target"))
                if (-not [string]::Equals($nestedTarget, $rootTarget, [StringComparison]::OrdinalIgnoreCase)) {
                    $roots.Add($nestedTarget)
                }
            }
        }
    return @($roots | Select-Object -Unique)
}

function Get-AstroRepoEvidenceState {
    # #424/#519: the frozen-tree evidence fingerprint for a build root, captured read-only.
    #
    #   HeadSha      -- `git rev-parse HEAD` (the commit the built artifact is attributable to)
    #   StatusSha256 -- SHA-256 of `git status --porcelain` (tracked AND untracked path states;
    #                   catches adds/removes/stage changes and new untracked sources)
    #   DiffSha256   -- SHA-256 of `git diff HEAD` (content-level tracked deltas vs HEAD;
    #                   catches byte edits inside already-dirty tracked files)
    #
    # Limitations recorded honestly: a content edit inside an UNTRACKED file whose path set is
    # unchanged is not captured (path-level only for untracked); everything tracked is captured
    # at content level. `git status` may racily refresh the index cache, which is why the
    # fingerprint hashes command OUTPUT, never raw index bytes.
    param(
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)][string]$Root
    )

    $head = Invoke-NativeCapture -Exe $GitExe -Arguments @("-C", $Root, "rev-parse", "HEAD")
    $headSha = (@($head.Output) -join "`n").Trim()
    if ($head.ExitCode -ne 0 -or $headSha -notmatch '^[0-9a-f]{40}$') {
        throw "GIT_FREEZE[ASTRO_GIT_EVIDENCE_STATE_UNREADABLE]: {code=ASTRO_GIT_EVIDENCE_STATE_UNREADABLE; message=`"could not resolve HEAD for evidence-lease recording at $Root (git exit=$($head.ExitCode): $headSha)`"; remediation=`"run the launcher from a healthy git checkout of the workspace; repair the repository state first`"}"
    }
    $status = Invoke-NativeCapture -Exe $GitExe -Arguments @("-C", $Root, "status", "--porcelain")
    if ($status.ExitCode -ne 0) {
        throw "GIT_FREEZE[ASTRO_GIT_EVIDENCE_STATE_UNREADABLE]: {code=ASTRO_GIT_EVIDENCE_STATE_UNREADABLE; message=`"'git status --porcelain' failed for evidence-lease recording at $Root (exit=$($status.ExitCode))`"; remediation=`"run the launcher from a healthy git checkout of the workspace; repair the repository state first`"}"
    }
    $diff = Invoke-NativeCapture -Exe $GitExe -Arguments @("-C", $Root, "diff", "HEAD")
    if ($diff.ExitCode -ne 0) {
        throw "GIT_FREEZE[ASTRO_GIT_EVIDENCE_STATE_UNREADABLE]: {code=ASTRO_GIT_EVIDENCE_STATE_UNREADABLE; message=`"'git diff HEAD' failed for evidence-lease recording at $Root (exit=$($diff.ExitCode))`"; remediation=`"run the launcher from a healthy git checkout of the workspace; repair the repository state first`"}"
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $statusSha = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes((@($status.Output) -join "`n")))) -replace '-', '').ToLowerInvariant()
        $diffSha = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes((@($diff.Output) -join "`n")))) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
    return [pscustomobject]@{ HeadSha = $headSha; StatusSha256 = $statusSha; DiffSha256 = $diffSha }
}

function Get-AstroGitPath {
    param(
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$GitPath
    )

    $capture = Invoke-NativeCapture `
        -Exe $GitExe `
        -Arguments @(
            "-C",
            $Root,
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            $GitPath
        )
    $value = (@($capture.Output) -join "`n").Trim()
    if ($capture.ExitCode -ne 0 -or
        [string]::IsNullOrWhiteSpace($value) -or
        -not [IO.Path]::IsPathRooted($value)) {
        throw "GIT_FREEZE[ASTRO_GIT_PATH_UNREADABLE]: {code=ASTRO_GIT_PATH_UNREADABLE; message=`"git could not resolve absolute path '$GitPath' for evidence root '$Root' (exit=$($capture.ExitCode), output=$value)`"; remediation=`"repair the registered worktree metadata before acquiring a native evidence lease`"}"
    }
    return [IO.Path]::GetFullPath($value)
}

function Get-AstroGitFrozenSourcePaths {
    # Git pathnames are arbitrary byte sequences except NUL and slash. Native PowerShell's
    # line-oriented command adapter cannot represent a newline-bearing pathname without
    # ambiguity, so read the authoritative `-z` stream as bytes and decode strict UTF-8.
    param(
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)][string]$Root
    )

    $rootArgument = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    if ($rootArgument.Contains('"')) {
        throw "GIT_FREEZE[ASTRO_GIT_SOURCE_LIST_UNREADABLE]: {code=ASTRO_GIT_SOURCE_LIST_UNREADABLE; message=`"workspace path contains a quote and cannot be passed to the exact native Git pathname reader: $rootArgument`"; remediation=`"use the canonical checkout or a registered worktree whose absolute path contains no quote`"}"
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $GitExe
    $start.Arguments = "-C `"$rootArgument`" -c core.quotepath=false ls-files -z --cached --others --exclude-standard"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $stdout = [IO.MemoryStream]::new()
    try {
        if (-not $process.Start()) {
            throw 'native Git process did not start'
        }
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.StandardOutput.BaseStream.CopyTo($stdout)
        $process.WaitForExit()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "native Git exited $($process.ExitCode): $stderr"
        }
        $bytes = $stdout.ToArray()
    }
    catch {
        throw "GIT_FREEZE[ASTRO_GIT_SOURCE_LIST_UNREADABLE]: {code=ASTRO_GIT_SOURCE_LIST_UNREADABLE; message=`"could not read the exact NUL-delimited tracked/untracked source set: $($_.Exception.Message)`"; remediation=`"repair Git worktree/index readability before acquiring evidence`"}"
    }
    finally {
        $stdout.Dispose()
        $process.Dispose()
    }

    if ($bytes.Length -eq 0) {
        return @()
    }
    if ($bytes[$bytes.Length - 1] -ne 0) {
        throw "GIT_FREEZE[ASTRO_GIT_SOURCE_LIST_INVALID]: {code=ASTRO_GIT_SOURCE_LIST_INVALID; message=`"git ls-files -z did not terminate its nonempty pathname stream with NUL`"; remediation=`"repair or replace the native Git executable before acquiring evidence`"}"
    }
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    }
    catch {
        throw "GIT_FREEZE[ASTRO_GIT_SOURCE_LIST_INVALID]: {code=ASTRO_GIT_SOURCE_LIST_INVALID; message=`"git emitted a pathname that is not strict UTF-8: $($_.Exception.Message)`"; remediation=`"rename the unsupported path explicitly before acquiring native Windows evidence`"}"
    }
    $parts = @($text.Split([char]0))
    if ($parts.Count -eq 0 -or $parts[$parts.Count - 1] -cne '') {
        throw "GIT_FREEZE[ASTRO_GIT_SOURCE_LIST_INVALID]: {code=ASTRO_GIT_SOURCE_LIST_INVALID; message=`"the exact Git pathname stream has an invalid terminal record`"; remediation=`"repair the repository index before acquiring evidence`"}"
    }
    if ($parts.Count -eq 1) {
        return @()
    }
    return @($parts[0..($parts.Count - 2)])
}

function New-AstroGitMutationFreezeLease {
    # #519: Git's own lockfile protocol creates <gitdir>/index.lock with O_EXCL before
    # index-backed porcelain may update either the index or worktree. Hold that exact name
    # with DELETE_ON_CLOSE for the dedicated launcher's process lifetime. A normal or abrupt
    # owner exit therefore removes it in-kernel; while live, commit/merge/checkout/reset/add/
    # restore fail before their first index/worktree write even when hooks are overridden.
    #
    # Retained FILE_SHARE_READ-only handles over the complete tracked + visible-untracked
    # source set independently deny write/delete/rename of every existing evidence byte.
    # The source set is re-fingerprinted after every handle is acquired, closing the
    # enumeration/open race. The reference-transaction hook remains the ref-only backstop.
    param(
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][int]$Issue,
        [Parameter(Mandatory)][long]$OwnerProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$LauncherLockPath,
        [Parameter(Mandatory)][string]$LauncherLockSha256,
        [Parameter(Mandatory)]$EvidenceBefore
    )

    $handles = [Collections.Generic.List[IO.FileStream]]::new()
    $handleRecords = [Collections.Generic.List[object]]::new()
    $indexInterlock = $null
    $indexInterlockPath = Get-AstroGitPath `
        -GitExe $GitExe `
        -Root $Root `
        -GitPath 'index.lock'
    $indexParent = [IO.Path]::GetDirectoryName($indexInterlockPath)
    $indexParentState = Get-AstroPathEntryState $indexParent
    if ($indexParentState.State -cne 'present' -or
        ($indexParentState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
        ($indexParentState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "GIT_FREEZE[ASTRO_GIT_INDEX_INTERLOCK_PARENT_INVALID]: {code=ASTRO_GIT_INDEX_INTERLOCK_PARENT_INVALID; message=`"Git index-lock parent is not one ordinary directory (state=$($indexParentState.State), attributes=$($indexParentState.Attributes), error=$($indexParentState.Error)): $indexParent`"; remediation=`"repair the registered worktree Git directory before acquiring evidence`"}"
    }

    $interlockJson = [ordered]@{
        schema = 'astrolabe.git-index-interlock.v1'
        pid = $PID
        issue = $Issue
        owner_process_start_utc_ticks = $OwnerProcessStartUtcTicks
        launcher_lock_path = [IO.Path]::GetFullPath($LauncherLockPath)
        launcher_lock_sha256 = $LauncherLockSha256
        head_sha = $EvidenceBefore.HeadSha
        status_sha256 = $EvidenceBefore.StatusSha256
        diff_sha256 = $EvidenceBefore.DiffSha256
        created_utc = [DateTime]::UtcNow.ToString('o')
    } | ConvertTo-Json -Compress
    $interlockBytes = [Text.UTF8Encoding]::new($false).GetBytes($interlockJson)
    $interlockHash = Get-AstroByteSha256 $interlockBytes

    try {
        $options = [IO.FileOptions]::DeleteOnClose -bor
            [IO.FileOptions]::WriteThrough
        try {
            $indexInterlock = [IO.FileStream]::new(
                $indexInterlockPath,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::Read,
                4096,
                $options
            )
        }
        catch {
            $existing = Get-AstroPathEntryState $indexInterlockPath
            throw "GIT_FREEZE[ASTRO_GIT_INDEX_INTERLOCK_HELD]: {code=ASTRO_GIT_INDEX_INTERLOCK_HELD; message=`"could not exclusively create the Git pre-write interlock (state=$($existing.State), attributes=$($existing.Attributes), error=$($existing.Error)): $indexInterlockPath; native=$($_.Exception.Message)`"; remediation=`"wait for the real Git writer to finish, or inspect and recover its index.lock through Git's documented lockfile lifecycle before retrying`"}"
        }
        $indexInterlock.Write(
            $interlockBytes,
            0,
            $interlockBytes.Length
        )
        $indexInterlock.Flush($true)
        $indexInterlock.Position = 0
        $observed = [byte[]]::new($interlockBytes.Length)
        $offset = 0
        while ($offset -lt $observed.Length) {
            $read = $indexInterlock.Read(
                $observed,
                $offset,
                $observed.Length - $offset
            )
            if ($read -le 0) {
                throw "Git index interlock ended after $offset of $($observed.Length) bytes"
            }
            $offset += $read
        }
        if ([Convert]::ToBase64String($observed) -cne
            [Convert]::ToBase64String($interlockBytes)) {
            throw 'Git index interlock bytes differ after durable handle readback'
        }
        $indexFileId = [AstroLauncherLockNative]::GetFileIdentity(
            $indexInterlock.SafeFileHandle
        )

        $relativePaths = @(
            Get-AstroGitFrozenSourcePaths -GitExe $GitExe -Root $Root
        )
        $rootPrefix = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + '\'
        $normalizedRelativePaths = [Collections.Generic.List[string]]::new()
        foreach ($relativePath in $relativePaths) {
            if ([string]::IsNullOrWhiteSpace($relativePath) -or
                [IO.Path]::IsPathRooted($relativePath)) {
                throw "Git emitted an empty/absolute evidence path: '$relativePath'"
            }
            $fullPath = [IO.Path]::GetFullPath(
                (Join-Path $Root $relativePath)
            )
            if (-not $fullPath.StartsWith(
                    $rootPrefix,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw "Git evidence path escapes the operating worktree: $relativePath -> $fullPath"
            }
            $state = Get-AstroPathEntryState $fullPath
            if ($state.State -cne 'present' -or
                ($state.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or
                ($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "evidence source is not one present ordinary non-reparse file (state=$($state.State), attributes=$($state.Attributes), error=$($state.Error)): $fullPath"
            }
            try {
                $handle = [IO.FileStream]::new(
                    $fullPath,
                    [IO.FileMode]::Open,
                    [IO.FileAccess]::Read,
                    [IO.FileShare]::Read,
                    4096,
                    [IO.FileOptions]::SequentialScan
                )
            }
            catch {
                throw "could not retain deny-write/delete evidence handle '$fullPath': $($_.Exception.Message)"
            }
            $handles.Add($handle)
            $handleRecords.Add([pscustomobject]@{
                    Path = $fullPath
                    Handle = $handle
                    FileId = [AstroLauncherLockNative]::GetFileIdentity(
                        $handle.SafeFileHandle
                    )
                    Length = [uint64]$handle.Length
                })
            $normalizedRelativePaths.Add(
                $relativePath.Replace('\', '/')
            )
        }

        $metadataPaths = [Collections.Generic.List[string]]::new()
        foreach ($gitPath in @('index', 'HEAD', 'packed-refs')) {
            $metadataPath = Get-AstroGitPath `
                -GitExe $GitExe `
                -Root $Root `
                -GitPath $gitPath
            $metadataState = Get-AstroPathEntryState $metadataPath
            if ($metadataState.State -ceq 'absent' -and
                $gitPath -ceq 'packed-refs') {
                continue
            }
            if ($metadataState.State -cne 'present' -or
                ($metadataState.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or
                ($metadataState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Git metadata '$gitPath' is not one present ordinary file (state=$($metadataState.State), attributes=$($metadataState.Attributes), error=$($metadataState.Error)): $metadataPath"
            }
            $metadataPaths.Add($metadataPath)
        }
        $symbolic = Invoke-NativeCapture `
            -Exe $GitExe `
            -Arguments @("-C", $Root, "symbolic-ref", "-q", "HEAD")
        if ($symbolic.ExitCode -eq 0) {
            $refName = (@($symbolic.Output) -join "`n").Trim()
            if ($refName -notmatch '^refs/heads/[^\x00-\x1f]+$') {
                throw "symbolic HEAD returned a noncanonical local ref: $refName"
            }
            $refPath = Get-AstroGitPath `
                -GitExe $GitExe `
                -Root $Root `
                -GitPath $refName
            if ((Get-AstroPathEntryState $refPath).State -ceq 'present') {
                $metadataPaths.Add($refPath)
            }
        }
        elseif ($symbolic.ExitCode -ne 1) {
            throw "git symbolic-ref -q HEAD failed unexpectedly (exit=$($symbolic.ExitCode)): $(@($symbolic.Output) -join ' | ')"
        }

        foreach ($metadataPath in @($metadataPaths | Select-Object -Unique)) {
            try {
                $handle = [IO.FileStream]::new(
                    $metadataPath,
                    [IO.FileMode]::Open,
                    [IO.FileAccess]::Read,
                    [IO.FileShare]::Read,
                    4096,
                    [IO.FileOptions]::SequentialScan
                )
            }
            catch {
                throw "could not retain deny-write/delete Git-metadata handle '$metadataPath': $($_.Exception.Message)"
            }
            $handles.Add($handle)
            $handleRecords.Add([pscustomobject]@{
                    Path = $metadataPath
                    Handle = $handle
                    FileId = [AstroLauncherLockNative]::GetFileIdentity(
                        $handle.SafeFileHandle
                    )
                    Length = [uint64]$handle.Length
                })
        }

        $evidenceAfter = Get-AstroRepoEvidenceState `
            -GitExe $GitExe `
            -Root $Root
        if ($evidenceAfter.HeadSha -cne $EvidenceBefore.HeadSha -or
            $evidenceAfter.StatusSha256 -cne $EvidenceBefore.StatusSha256 -or
            $evidenceAfter.DiffSha256 -cne $EvidenceBefore.DiffSha256) {
            throw "repository changed while the index/source freeze was being acquired: head $($EvidenceBefore.HeadSha) -> $($evidenceAfter.HeadSha), status $($EvidenceBefore.StatusSha256) -> $($evidenceAfter.StatusSha256), diff $($EvidenceBefore.DiffSha256) -> $($evidenceAfter.DiffSha256)"
        }
        $pathSetText = (@($normalizedRelativePaths) -join "`0") + "`0"
        $pathSetSha256 = Get-AstroByteSha256 (
            [Text.UTF8Encoding]::new($false).GetBytes($pathSetText)
        )
        return [pscustomobject]@{
            IndexInterlock = $indexInterlock
            IndexInterlockPath = $indexInterlockPath
            IndexInterlockFileId = $indexFileId
            IndexInterlockSha256 = $interlockHash
            IndexInterlockBytes = $interlockBytes
            Handles = $handles
            HandleRecords = $handleRecords
            SourcePathCount = $normalizedRelativePaths.Count
            MetadataPathCount = $metadataPaths.Count
            PathSetSha256 = $pathSetSha256
        }
    }
    catch {
        $failure = $_
        foreach ($handle in $handles) {
            try { $handle.Dispose() } catch {}
        }
        if ($null -ne $indexInterlock) {
            try { $indexInterlock.Dispose() } catch {}
        }
        $terminal = Get-AstroPathEntryState $indexInterlockPath
        $suffix = if ($terminal.State -ceq 'absent') {
            ''
        }
        else {
            "; index_interlock_terminal_state=$($terminal.State); error=$($terminal.Error)"
        }
        throw "GIT_FREEZE[ASTRO_GIT_MUTATION_FREEZE_FAILED]: {code=ASTRO_GIT_MUTATION_FREEZE_FAILED; message=`"could not acquire the complete Git index/source mutation freeze: $($failure.Exception.Message)$suffix`"; remediation=`"preserve any non-absent Git lock, repair the named path/reader conflict, and retry from an unchanged checkout`"}"
    }
}

function Assert-AstroGitMutationFreezeLease {
    param([Parameter(Mandatory)]$Lease)

    if ($null -eq $Lease.IndexInterlock -or
        $Lease.IndexInterlock.SafeFileHandle.IsClosed) {
        throw 'process-lifetime Git index interlock handle is closed'
    }
    $interlockFileId = [AstroLauncherLockNative]::GetFileIdentity(
        $Lease.IndexInterlock.SafeFileHandle
    )
    if ($interlockFileId -cne $Lease.IndexInterlockFileId) {
        throw "Git index interlock FILE_ID changed (expected=$($Lease.IndexInterlockFileId), observed=$interlockFileId)"
    }
    foreach ($record in $Lease.HandleRecords) {
        $handle = $record.Handle
        if ($null -eq $handle -or $handle.SafeFileHandle.IsClosed -or
            -not [string]::Equals(
                $handle.Name,
                $record.Path,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "frozen evidence handle is absent or changed: $($record.Path)"
        }
        $fileId = [AstroLauncherLockNative]::GetFileIdentity(
            $handle.SafeFileHandle
        )
        if ($fileId -cne $record.FileId -or
            [uint64]$handle.Length -ne [uint64]$record.Length) {
            throw "frozen evidence handle identity/length changed: $($record.Path)"
        }
    }
    return [pscustomobject]@{
        IndexInterlockPath = $Lease.IndexInterlockPath
        IndexInterlockFileId = $interlockFileId
        IndexInterlockSha256 = $Lease.IndexInterlockSha256
        SourcePathCount = $Lease.SourcePathCount
        MetadataPathCount = $Lease.MetadataPathCount
        PathSetSha256 = $Lease.PathSetSha256
        HandleCount = $Lease.Handles.Count
    }
}

function Assert-NoAmbientCargoTargetEscape {
    # #534/#566: the launcher exports an authoritative CARGO_TARGET_DIR (= $OwnedTargetRoot) so
    # every Cargo child is confined to the owned, cleaned root. An ambient CARGO_TARGET_DIR or
    # CARGO_BUILD_TARGET_DIR in the launcher's own environment that points ELSEWHERE would be
    # silently overwritten -- masking operator intent, and leaving an unowned artifact tree
    # behind if any child read the ambient value first. Fail closed instead: an ambient value
    # is admitted only when it resolves to the owned root; anything else is refused by name.
    param([Parameter(Mandatory)][string]$OwnedTargetRoot)

    $ownedFull = [IO.Path]::GetFullPath($OwnedTargetRoot).TrimEnd('\', '/')
    foreach ($varName in @("CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR")) {
        $item = Get-Item -Path "Env:$varName" -ErrorAction SilentlyContinue
        if ($null -eq $item -or [string]::IsNullOrWhiteSpace($item.Value)) {
            continue
        }
        $ambientFull = [IO.Path]::GetFullPath($item.Value).TrimEnd('\', '/')
        if (-not [string]::Equals($ambientFull, $ownedFull, [StringComparison]::OrdinalIgnoreCase)) {
            throw "LAUNCHER_BOUNDARY[ASTRO_CARGO_TARGET_ESCAPE]: {code=ASTRO_CARGO_TARGET_ESCAPE; message=`"ambient $varName=$($item.Value) resolves to '$ambientFull', outside the launcher-owned Cargo target root '$ownedFull'; the launcher owns and cleans only that root, so a Cargo child writing there would escape hygiene`"; remediation=`"unset $varName (the launcher exports its own authoritative CARGO_TARGET_DIR) or set it to '$ownedFull', then rerun the launcher`"}"
        }
    }
}

function Assert-NoCargoTargetDirOverride {
    # #534/#566: a child `--target-dir <path>` / `--target-dir=<path>` on the Cargo CLI outranks
    # the launcher's authoritative CARGO_TARGET_DIR (CLI > env), so it cannot be overridden --
    # only refused. Reject it fail-closed so no invocation can steer Cargo output out of the
    # owned, cleaned target root.
    param([string[]]$CommandArgs)

    foreach ($rawArg in $CommandArgs) {
        $arg = [string]$rawArg
        if ($arg -eq "--target-dir" -or $arg -like "--target-dir=*") {
            throw "LAUNCHER_BOUNDARY[ASTRO_CARGO_TARGET_DIR_OVERRIDE]: {code=ASTRO_CARGO_TARGET_DIR_OVERRIDE; message=`"the child command passes '$arg', which overrides the launcher's authoritative CARGO_TARGET_DIR and would write Cargo output outside the owned, cleaned target root`"; remediation=`"remove --target-dir from the command; the launcher confines every Cargo child (nested manifests included) to its owned target root automatically`"}"
        }
    }
}

function Resolve-PinnedCuda13Runtime {
    param(
        [string]$Provisioner,
        [string]$LockManifest,
        [string]$WorkspaceRoot,
        [string]$ToolchainsRoot
    )

    if (-not (Test-Path -LiteralPath $Provisioner -PathType Leaf)) {
        throw "CUDA13_RUNTIME[ASTRO_CUDA13_RUNTIME_PROVISIONER_MISSING]: {code=ASTRO_CUDA13_RUNTIME_PROVISIONER_MISSING; message=`"the checked-in CUDA 13 runtime provisioner is missing: $Provisioner`"; remediation=`"restore scripts\windows-cuda13-runtime.ps1 from the repository before invoking the launcher`"}"
    }
    if (-not (Test-Path -LiteralPath $LockManifest -PathType Leaf)) {
        throw "CUDA13_RUNTIME[ASTRO_CUDA13_RUNTIME_LOCK_MISSING]: {code=ASTRO_CUDA13_RUNTIME_LOCK_MISSING; message=`"the checked-in CUDA 13 runtime lock is missing: $LockManifest`"; remediation=`"restore scripts\toolchains\ort-cuda13.3-windows-x86_64.lock.json from the repository before invoking the launcher`"}"
    }
    try {
        $lockDigest = (Get-Sha256Hex -LiteralPath $LockManifest).Hash.ToLowerInvariant()
    }
    catch {
        throw "CUDA13_RUNTIME[ASTRO_CUDA13_RUNTIME_LOCK_UNREADABLE]: {code=ASTRO_CUDA13_RUNTIME_LOCK_UNREADABLE; message=`"the checked-in CUDA 13 runtime lock could not be hashed: $($_.Exception.Message)`"; remediation=`"restore a readable lock manifest from the repository, then rerun the launcher`"}"
    }
    $expectedRoot = [IO.Path]::GetFullPath((Join-Path $ToolchainsRoot "ort-cuda13.3-windows-x86_64-$lockDigest")).TrimEnd('\', '/')

    $ambientModulePath = $env:PSModulePath
    try {
        # The provisioner owns download, extraction, and full bundle re-attestation. Its
        # stdout contract is deliberately machine-readable: exactly one canonical root.
        # Pin module discovery to the current PowerShell host. A pwsh parent can otherwise
        # inject PowerShell 7 modules into a Windows PowerShell 5.1 launcher (or vice versa),
        # making the security module discoverable but unloadable. Restore the caller's
        # environment immediately after this in-process capability check.
        $env:PSModulePath = Join-Path $PSHOME "Modules"
        $provisionerOutput = @(& $Provisioner -WorkspaceRoot $WorkspaceRoot -ToolchainsRoot $ToolchainsRoot)
    }
    catch {
        throw "CUDA13_RUNTIME[ASTRO_CUDA13_RUNTIME_PROVISION_FAILED]: {code=ASTRO_CUDA13_RUNTIME_PROVISION_FAILED; message=`"the pinned CUDA 13 runtime could not be provisioned or attested: $($_.Exception.Message)`"; remediation=`"repair the reported bundle fault, then rerun scripts\windows-gnu-toolchain.ps1 -Issue <driving-issue> -Bootstrap from $WorkspaceRoot`"}"
    }
    finally {
        $env:PSModulePath = $ambientModulePath
    }

    if ($provisionerOutput.Count -ne 1) {
        throw "CUDA13_RUNTIME[ASTRO_CUDA13_RUNTIME_OUTPUT_INVALID]: {code=ASTRO_CUDA13_RUNTIME_OUTPUT_INVALID; message=`"the pinned CUDA 13 runtime provisioner emitted $($provisionerOutput.Count) stdout records; exactly one canonical bundle root is required`"; remediation=`"inspect $Provisioner and restore its one-path stdout contract; diagnostics belong on stderr or the Verbose stream`"}"
    }

    $reportedRoot = ([string]$provisionerOutput[0]).Trim()
    if ([string]::IsNullOrWhiteSpace($reportedRoot) -or -not [IO.Path]::IsPathRooted($reportedRoot)) {
        throw "CUDA13_RUNTIME[ASTRO_CUDA13_RUNTIME_ROOT_INVALID]: {code=ASTRO_CUDA13_RUNTIME_ROOT_INVALID; message=`"the pinned CUDA 13 runtime provisioner did not emit an absolute bundle root: '$reportedRoot'`"; remediation=`"rerun -Bootstrap; if the error persists, repair the provisioner's canonical-root output contract`"}"
    }
    if (-not (Test-Path -LiteralPath $reportedRoot -PathType Container)) {
        throw "CUDA13_RUNTIME[ASTRO_CUDA13_RUNTIME_ROOT_MISSING]: {code=ASTRO_CUDA13_RUNTIME_ROOT_MISSING; message=`"the attested CUDA 13 runtime root does not exist as a directory: $reportedRoot`"; remediation=`"rerun scripts\windows-gnu-toolchain.ps1 -Issue <driving-issue> -Bootstrap from $WorkspaceRoot`"}"
    }

    $rootItem = Get-Item -LiteralPath $reportedRoot -Force -ErrorAction Stop
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "CUDA13_RUNTIME[ASTRO_CUDA13_RUNTIME_ROOT_REPARSE_POINT]: {code=ASTRO_CUDA13_RUNTIME_ROOT_REPARSE_POINT; message=`"the attested CUDA 13 runtime root is a reparse point and may redirect outside the immutable bundle: $reportedRoot`"; remediation=`"remove the reparse point and rerun the canonical provisioner to materialize the locked bundle`"}"
    }

    $canonicalRoot = (Resolve-Path -LiteralPath $reportedRoot -ErrorAction Stop).Path.TrimEnd('\', '/')
    $emittedRoot = [IO.Path]::GetFullPath($reportedRoot).TrimEnd('\', '/')
    if (-not [string]::Equals($emittedRoot, $canonicalRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "CUDA13_RUNTIME[ASTRO_CUDA13_RUNTIME_ROOT_NOT_CANONICAL]: {code=ASTRO_CUDA13_RUNTIME_ROOT_NOT_CANONICAL; message=`"the provisioner emitted '$reportedRoot', but its canonical path is '$canonicalRoot'`"; remediation=`"repair the provisioner to emit the resolved canonical bundle root`"}"
    }
    if (-not [string]::Equals($canonicalRoot, $expectedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "CUDA13_RUNTIME[ASTRO_CUDA13_RUNTIME_LOCK_ROOT_MISMATCH]: {code=ASTRO_CUDA13_RUNTIME_LOCK_ROOT_MISMATCH; message=`"the provisioner emitted '$canonicalRoot', but raw lock digest $lockDigest requires '$expectedRoot'`"; remediation=`"remove the mismatched bundle and rerun the canonical provisioner; do not override CALYX_CUDA13_RUNTIME_ROOT`"}"
    }
    if (-not (Test-PathUnderRoot -Path $canonicalRoot -Root $ToolchainsRoot)) {
        throw "CUDA13_RUNTIME[ASTRO_CUDA13_RUNTIME_ROOT_ESCAPE]: {code=ASTRO_CUDA13_RUNTIME_ROOT_ESCAPE; message=`"the attested CUDA 13 runtime root escapes the canonical toolchains directory: root=$canonicalRoot; toolchains=$ToolchainsRoot`"; remediation=`"remove ambient runtime overrides and rerun the canonical provisioner from $WorkspaceRoot`"}"
    }

    return $canonicalRoot
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
    if (Test-Path -LiteralPath $emptyDir) {
        throw "robocopy cleanup scratch unexpectedly already exists: $emptyDir"
    }
    [IO.Directory]::CreateDirectory($emptyDir) | Out-Null
    $emptyState = Get-Item -LiteralPath $emptyDir -Force -ErrorAction Stop
    if (-not $emptyState.PSIsContainer -or
        ($emptyState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "robocopy cleanup scratch is not one ordinary directory: $emptyDir"
    }
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
            Remove-Item -LiteralPath $emptyDir -Recurse -Force -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $emptyDir) {
            throw "robocopy cleanup scratch remains after explicit deletion: $emptyDir"
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

function Resolve-CudaHostCompilerPath {
    param([Parameter(Mandatory)][string]$RawPath, [Parameter(Mandatory)][string]$EnvName)

    $expanded = [Environment]::ExpandEnvironmentVariables($RawPath.Trim())
    if ([string]::IsNullOrWhiteSpace($expanded)) {
        throw "CUDA_HOST_COMPILER[ASTRO_CUDA_CCBIN_INVALID]: $EnvName is empty; set it to cl.exe or the Hostx64\x64 directory containing cl.exe"
    }
    $resolved = (Resolve-Path -LiteralPath $expanded -ErrorAction SilentlyContinue).Path
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        throw "CUDA_HOST_COMPILER[ASTRO_CUDA_CCBIN_INVALID]: $EnvName=$RawPath does not resolve to an existing path"
    }
    if (Test-Path -LiteralPath $resolved -PathType Container) {
        $candidate = Join-Path $resolved "cl.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $resolved
        }
    }
    if ((Test-Path -LiteralPath $resolved -PathType Leaf) -and
        [string]::Equals([IO.Path]::GetFileName($resolved), "cl.exe", [StringComparison]::OrdinalIgnoreCase)) {
        return Split-Path -Parent $resolved
    }
    throw "CUDA_HOST_COMPILER[ASTRO_CUDA_CCBIN_INVALID]: $EnvName must point to cl.exe or a directory containing cl.exe"
}

function Get-MsvcVersionKey {
    param([Parameter(Mandatory)][string]$Ccbin)

    $parts = $Ccbin -split '[\\/]'
    for ($i = 0; $i -lt $parts.Length - 1; $i++) {
        if ([string]::Equals($parts[$i], "MSVC", [StringComparison]::OrdinalIgnoreCase)) {
            try {
                return [version]$parts[$i + 1]
            }
            catch {
                return [version]"0.0"
            }
        }
    }
    return [version]"0.0"
}

function Get-MsvcCudaHostCompilerCandidates {
    $roots = @()
    if ($env:ProgramFiles) {
        $roots += (Join-Path $env:ProgramFiles "Microsoft Visual Studio")
    }
    if (${env:ProgramFiles(x86)}) {
        $roots += (Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio")
    }

    $candidates = @()
    foreach ($root in ($roots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }
        Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue
            } |
            ForEach-Object {
                $msvcRoot = Join-Path $_.FullName "VC\Tools\MSVC"
                if (Test-Path -LiteralPath $msvcRoot -PathType Container) {
                    Get-ChildItem -LiteralPath $msvcRoot -Directory -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            $ccbin = Join-Path $_.FullName "bin\Hostx64\x64"
                            if (Test-Path -LiteralPath (Join-Path $ccbin "cl.exe") -PathType Leaf) {
                                $candidates += $ccbin
                            }
                        }
                }
            }
    }
    return $candidates | Sort-Object @{ Expression = { Get-MsvcVersionKey -Ccbin $_ } }, @{ Expression = { $_ } }
}

function Set-CudaHostCompilerEnvironment {
    $nvccOverride = Get-Item -Path "Env:$NvccCcbinEnv" -ErrorAction SilentlyContinue
    if ($null -ne $nvccOverride) {
        $ccbin = Resolve-CudaHostCompilerPath -RawPath $nvccOverride.Value -EnvName $NvccCcbinEnv
        $env:NVCC_CCBIN = $ccbin
        $env:FORGE_CUDA_CCBIN = $ccbin
        Write-Output "CUDA_HOST_COMPILER[ASTRO_CUDA_CCBIN]: using $NvccCcbinEnv=$ccbin"
        return
    }

    $forgeOverride = Get-Item -Path "Env:$ForgeCudaCcbinEnv" -ErrorAction SilentlyContinue
    if ($null -ne $forgeOverride) {
        $ccbin = Resolve-CudaHostCompilerPath -RawPath $forgeOverride.Value -EnvName $ForgeCudaCcbinEnv
        $env:NVCC_CCBIN = $ccbin
        $env:FORGE_CUDA_CCBIN = $ccbin
        Write-Output "CUDA_HOST_COMPILER[ASTRO_CUDA_CCBIN]: using $ForgeCudaCcbinEnv=$ccbin"
        return
    }

    $pathCl = Get-Command "cl.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $pathCl) {
        $ccbin = Resolve-CudaHostCompilerPath -RawPath $pathCl.Source -EnvName "PATH"
        $env:NVCC_CCBIN = $ccbin
        $env:FORGE_CUDA_CCBIN = $ccbin
        Write-Output "CUDA_HOST_COMPILER[ASTRO_CUDA_CCBIN]: using cl.exe from PATH at $ccbin"
        return
    }

    $ccbin = @(Get-MsvcCudaHostCompilerCandidates | Select-Object -Last 1)
    if ($ccbin.Count -gt 0) {
        $env:NVCC_CCBIN = $ccbin[0]
        $env:FORGE_CUDA_CCBIN = $ccbin[0]
        Write-Output "CUDA_HOST_COMPILER[ASTRO_CUDA_CCBIN]: discovered $($ccbin[0])"
        return
    }

    if ($env:CUDA_PATH -and (Test-Path -LiteralPath (Join-Path $env:CUDA_PATH "bin\nvcc.exe") -PathType Leaf)) {
        Write-Output "CUDA_HOST_COMPILER[ASTRO_CUDA_CCBIN_UNSET]: CUDA nvcc is installed but no cl.exe host compiler was found; CUDA crate builds that invoke nvcc will fail closed. Install Visual Studio Build Tools MSVC x64 tools or set NVCC_CCBIN."
    }
}

function Add-NvccAppendFlag {
    param([Parameter(Mandatory)][string]$Flag)

    $existingItem = Get-Item -Path "Env:$NvccAppendFlagsEnv" -ErrorAction SilentlyContinue
    $existing = if ($null -ne $existingItem) { $existingItem.Value } else { "" }
    if ($existing -and $existing.Contains($Flag)) {
        return
    }
    if ([string]::IsNullOrWhiteSpace($existing)) {
        $env:NVCC_APPEND_FLAGS = $Flag
    }
    else {
        $env:NVCC_APPEND_FLAGS = "$existing $Flag"
    }
}

function Resolve-MsvcLibRootFromCudaCcbin {
    param([Parameter(Mandatory)][string]$Ccbin)

    $resolved = (Resolve-Path -LiteralPath $Ccbin -ErrorAction SilentlyContinue).Path
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        throw "CUDA_MSVC_RUNTIME_LINK[ASTRO_CUDA_MSVC_LIB_ROOT_INVALID]: CUDA host compiler directory does not resolve: $Ccbin"
    }
    $normalized = $resolved.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $match = [regex]::Match($normalized, '^(?<root>.+[\\/]VC[\\/]Tools[\\/]MSVC[\\/][^\\/]+)[\\/]bin[\\/]Hostx64[\\/]x64$')
    if (-not $match.Success) {
        throw "CUDA_MSVC_RUNTIME_LINK[ASTRO_CUDA_MSVC_LIB_ROOT_INVALID]: CUDA host compiler path must be an MSVC Hostx64\x64 directory, found $resolved"
    }
    $libRoot = Join-Path $match.Groups["root"].Value "lib\x64"
    if (-not (Test-Path -LiteralPath $libRoot -PathType Container)) {
        throw "CUDA_MSVC_RUNTIME_LINK[ASTRO_CUDA_MSVC_LIB_ROOT_MISSING]: MSVC x64 lib root is missing: $libRoot"
    }
    $archive = Join-Path $libRoot $MsvcRuntimeArchiveName
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
        throw "CUDA_MSVC_RUNTIME_LINK[ASTRO_CUDA_MSVC_LIB_MISSING]: required $MsvcRuntimeArchiveName is missing from $libRoot"
    }
    return $libRoot
}

function Prepend-PathListEnv {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )

    $existingItem = Get-Item -Path "Env:$Name" -ErrorAction SilentlyContinue
    $existing = if ($null -ne $existingItem) { $existingItem.Value } else { "" }
    $parts = @($existing -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    foreach ($part in $parts) {
        if ([string]::Equals($part, $Value, [StringComparison]::OrdinalIgnoreCase)) {
            return
        }
    }
    if ([string]::IsNullOrWhiteSpace($existing)) {
        Set-Item -Path "Env:$Name" -Value $Value
    }
    else {
        Set-Item -Path "Env:$Name" -Value "$Value;$existing"
    }
}

function Add-Rustflags {
    param([Parameter(Mandatory)][string[]]$Tokens)

    $addition = ($Tokens -join " ")
    $existingItem = Get-Item -Path "Env:RUSTFLAGS" -ErrorAction SilentlyContinue
    $existing = if ($null -ne $existingItem) { $existingItem.Value } else { "" }
    if ($existing -and $existing.Contains($addition)) {
        return
    }
    if ([string]::IsNullOrWhiteSpace($existing)) {
        $env:RUSTFLAGS = $addition
    }
    else {
        $env:RUSTFLAGS = "$existing $addition"
    }
}

function Expand-MsvcRuntimeSupportObjects {
    param(
        [Parameter(Mandatory)][string]$MsvcLibRoot,
        [Parameter(Mandatory)][string]$LlvmBin,
        [Parameter(Mandatory)][string]$WorkspaceTemp
    )

    $archive = Join-Path $MsvcLibRoot $MsvcRuntimeArchiveName
    Require-Path $archive "MSVC runtime archive is missing"
    $llvmAr = Join-Path $LlvmBin "llvm-ar.exe"
    Require-Path $llvmAr "pinned LLVM archiver is missing"

    $outDir = Join-Path $WorkspaceTemp "cuda-msvc-runtime-support"
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null

    $list = Invoke-NativeCapture -Exe $llvmAr -Arguments @("t", $archive)
    if ($list.ExitCode -ne 0) {
        throw "CUDA_MSVC_RUNTIME_LINK[ASTRO_CUDA_MSVC_AR_LIST_FAILED]: llvm-ar could not list $archive (exit $($list.ExitCode)): $($list.Output -join ' | ')"
    }

    $members = @()
    foreach ($required in $MsvcRuntimeSupportMembers) {
        $member = @($list.Output | Where-Object {
                [string]::Equals([IO.Path]::GetFileName($_), $required, [StringComparison]::OrdinalIgnoreCase)
            } | Select-Object -First 1)
        if ($member.Count -eq 0) {
            throw "CUDA_MSVC_RUNTIME_LINK[ASTRO_CUDA_MSVC_MEMBER_MISSING]: $archive does not contain required support member $required"
        }
        $members += $member[0]
    }

    Push-Location $outDir
    try {
        $extract = Invoke-NativeCapture -Exe $llvmAr -Arguments (@("x", $archive) + $members)
        if ($extract.ExitCode -ne 0) {
            throw "CUDA_MSVC_RUNTIME_LINK[ASTRO_CUDA_MSVC_AR_EXTRACT_FAILED]: llvm-ar could not extract CUDA/MSVC support members from $archive (exit $($extract.ExitCode)): $($extract.Output -join ' | ')"
        }
    }
    finally {
        Pop-Location
    }

    $paths = @()
    foreach ($required in $MsvcRuntimeSupportMembers) {
        $path = Join-Path $outDir $required
        Require-Path $path "extracted CUDA/MSVC support object is missing"
        $paths += $path
    }
    return $paths
}

function Expand-MsvcVcStartupSupportObjects {
    param(
        [Parameter(Mandatory)][string]$MsvcLibRoot,
        [Parameter(Mandatory)][string]$LlvmBin,
        [Parameter(Mandatory)][string]$WorkspaceTemp
    )

    $archive = Join-Path $MsvcLibRoot $MsvcVcStartupArchiveName
    Require-Path $archive "MSVC VC startup archive is missing"
    $llvmAr = Join-Path $LlvmBin "llvm-ar.exe"
    Require-Path $llvmAr "pinned LLVM archiver is missing"

    $outDir = Join-Path $WorkspaceTemp "cuda-msvc-vcstartup-support"
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null

    $list = Invoke-NativeCapture -Exe $llvmAr -Arguments @("t", $archive)
    if ($list.ExitCode -ne 0) {
        throw "CUDA_MSVC_RUNTIME_LINK[ASTRO_CUDA_MSVC_VCSTARTUP_AR_LIST_FAILED]: llvm-ar could not list $archive (exit $($list.ExitCode)): $($list.Output -join ' | ')"
    }

    $members = @()
    foreach ($required in $MsvcVcStartupSupportMembers) {
        $member = @($list.Output | Where-Object {
                [string]::Equals([IO.Path]::GetFileName($_), $required, [StringComparison]::OrdinalIgnoreCase)
            } | Select-Object -First 1)
        if ($member.Count -eq 0) {
            throw "CUDA_MSVC_RUNTIME_LINK[ASTRO_CUDA_MSVC_VCSTARTUP_MEMBER_MISSING]: $archive does not contain required support member $required"
        }
        $members += $member[0]
    }

    Push-Location $outDir
    try {
        $extract = Invoke-NativeCapture -Exe $llvmAr -Arguments (@("x", $archive) + $members)
        if ($extract.ExitCode -ne 0) {
            throw "CUDA_MSVC_RUNTIME_LINK[ASTRO_CUDA_MSVC_VCSTARTUP_AR_EXTRACT_FAILED]: llvm-ar could not extract CUDA/MSVC VC startup members from $archive (exit $($extract.ExitCode)): $($extract.Output -join ' | ')"
        }
    }
    finally {
        Pop-Location
    }

    $paths = @()
    foreach ($required in $MsvcVcStartupSupportMembers) {
        $path = Join-Path $outDir $required
        Require-Path $path "extracted CUDA/MSVC VC startup object is missing"
        $paths += $path
    }
    return $paths
}

function Copy-MsvcRuntimeImportLibs {
    param(
        [Parameter(Mandatory)][string]$MsvcLibRoot,
        [Parameter(Mandatory)][string]$WorkspaceTemp
    )

    $outDir = Join-Path $WorkspaceTemp "cuda-msvc-runtime-imports"
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null

    $paths = @()
    foreach ($name in $MsvcRuntimeImportLibNames) {
        $source = Join-Path $MsvcLibRoot $name
        Require-Path $source "required MSVC runtime import library is missing"
        $dest = Join-Path $outDir $name
        Copy-Item -LiteralPath $source -Destination $dest -Force
        Require-Path $dest "copied MSVC runtime import library is missing"
        $paths += $dest
    }
    return $paths
}

function Resolve-WindowsKitUcrtLibPath {
    $kitsLibRoot = "C:\Program Files (x86)\Windows Kits\10\Lib"
    if (-not (Test-Path -LiteralPath $kitsLibRoot -PathType Container)) {
        throw "CUDA_MSVC_RUNTIME_LINK[ASTRO_WINDOWS_KIT_UCRT_ROOT_MISSING]: Windows Kit Lib root is missing: $kitsLibRoot"
    }

    $candidates = @(Get-ChildItem -LiteralPath $kitsLibRoot -Directory | ForEach-Object {
            $ucrt = Join-Path $_.FullName (Join-Path "ucrt\x64" $WindowsKitUcrtImportLibName)
            if (Test-Path -LiteralPath $ucrt -PathType Leaf) {
                [version]$parsed = "0.0"
                [void][version]::TryParse($_.Name, [ref]$parsed)
                [pscustomobject]@{
                    Version = $parsed
                    Path = $ucrt
                }
            }
        })
    if ($candidates.Count -eq 0) {
        throw "CUDA_MSVC_RUNTIME_LINK[ASTRO_WINDOWS_KIT_UCRT_MISSING]: no $WindowsKitUcrtImportLibName found under $kitsLibRoot\*\ucrt\x64"
    }

    return @($candidates | Sort-Object -Property Version -Descending | Select-Object -First 1)[0].Path
}

function Copy-UcrtImportLib {
    param([Parameter(Mandatory)][string]$WorkspaceTemp)

    $source = Resolve-WindowsKitUcrtLibPath
    $outDir = Join-Path $WorkspaceTemp "cuda-windowskit-ucrt-import"
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    $dest = Join-Path $outDir $WindowsKitUcrtImportLibName
    Copy-Item -LiteralPath $source -Destination $dest -Force
    Require-Path $dest "copied Windows Kit UCRT import library is missing"
    return $dest
}

function Resolve-CudaToolkitRoot {
    if ([string]::IsNullOrWhiteSpace($env:CUDA_PATH)) {
        throw "CUDA_IMPORT_LINK[ASTRO_CUDA_PATH_MISSING]: CUDA_PATH is not set; install CUDA Toolkit or set CUDA_PATH to the toolkit root before running CUDA-enabled builds"
    }

    $toolkitRoot = (Resolve-Path -LiteralPath $env:CUDA_PATH -ErrorAction SilentlyContinue).Path
    if ([string]::IsNullOrWhiteSpace($toolkitRoot)) {
        throw "CUDA_IMPORT_LINK[ASTRO_CUDA_PATH_INVALID]: CUDA_PATH does not resolve: $env:CUDA_PATH"
    }
    return $toolkitRoot
}

function Resolve-CudaToolkitLibRoot {
    $toolkitRoot = Resolve-CudaToolkitRoot
    $libRoot = Join-Path $toolkitRoot "lib\x64"
    if (-not (Test-Path -LiteralPath $libRoot -PathType Container)) {
        throw "CUDA_IMPORT_LINK[ASTRO_CUDA_LIB_ROOT_MISSING]: CUDA x64 library root is missing: $libRoot"
    }
    foreach ($name in $CudaImportLibNames) {
        $source = Join-Path $libRoot $name
        Require-Path $source "required CUDA import library is missing"
    }
    return $libRoot
}

function New-CudaToolkitNoSpaceView {
    param([Parameter(Mandatory)][string]$WorkspaceTemp)

    $toolkitRoot = Resolve-CudaToolkitRoot
    $libRoot = Resolve-CudaToolkitLibRoot
    $viewRoot = Join-Path $WorkspaceTemp "cuda-toolkit-root"
    $viewBin = Join-Path $viewRoot "bin"
    $viewInclude = Join-Path $viewRoot "include"
    $viewLib = Join-Path $viewRoot "lib"
    $viewLibRoot = Join-Path $viewLib "x64"
    New-Item -ItemType Directory -Path $viewRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $viewLibRoot -Force | Out-Null

    Get-ChildItem -LiteralPath $toolkitRoot -File -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $viewRoot $_.Name) -Force
    }

    $rootJunctionNames = @(
        "bin",
        "compute-sanitizer",
        "extras",
        "include",
        "nvml",
        "nvvm",
        "src",
        "tools"
    )
    foreach ($name in $rootJunctionNames) {
        $target = Join-Path $toolkitRoot $name
        if (-not (Test-Path -LiteralPath $target -PathType Container)) {
            continue
        }
        $path = Join-Path $viewRoot $name
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -ItemType Junction -Path $path -Target $target | Out-Null
        }
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            throw "CUDA_IMPORT_LINK[ASTRO_CUDA_TOOLKIT_VIEW_LINK_FAILED]: CUDA toolkit view link was not created: $path -> $target"
        }
    }

    Get-ChildItem -LiteralPath (Join-Path $toolkitRoot "lib") -Directory -ErrorAction SilentlyContinue |
        Where-Object { -not [string]::Equals($_.Name, "x64", [StringComparison]::OrdinalIgnoreCase) } |
        ForEach-Object {
            $path = Join-Path $viewLib $_.Name
            if (-not (Test-Path -LiteralPath $path)) {
                New-Item -ItemType Junction -Path $path -Target $_.FullName | Out-Null
            }
            if (-not (Test-Path -LiteralPath $path -PathType Container)) {
                throw "CUDA_IMPORT_LINK[ASTRO_CUDA_TOOLKIT_VIEW_LINK_FAILED]: CUDA toolkit lib view link was not created: $path -> $($_.FullName)"
            }
        }

    foreach ($link in @(
            @{ Path = $viewBin; Target = (Join-Path $toolkitRoot "bin") },
            @{ Path = $viewInclude; Target = (Join-Path $toolkitRoot "include") },
            @{ Path = (Join-Path $viewRoot "nvvm"); Target = (Join-Path $toolkitRoot "nvvm") }
        )) {
        if (-not (Test-Path -LiteralPath $link.Target -PathType Container)) {
            throw "CUDA_IMPORT_LINK[ASTRO_CUDA_TOOLKIT_VIEW_TARGET_MISSING]: CUDA toolkit view target is missing: $($link.Target)"
        }
        if (-not (Test-Path -LiteralPath $link.Path -PathType Container)) {
            throw "CUDA_IMPORT_LINK[ASTRO_CUDA_TOOLKIT_VIEW_LINK_FAILED]: CUDA toolkit view link was not created: $($link.Path) -> $($link.Target)"
        }
    }

    foreach ($name in $CudaImportLibNames) {
        $source = Join-Path $libRoot $name
        $dest = Join-Path $viewLibRoot $name
        Copy-Item -LiteralPath $source -Destination $dest -Force
        Require-Path $dest "copied CUDA import library is missing"
    }

    $env:CUDA_PATH = $viewRoot
    $env:CUDA_HOME = $viewRoot
    $env:PATH = "$viewBin;$env:PATH"
    return $viewLibRoot
}

function Set-CudaMsvcRuntimeLinkEnvironment {
    param(
        [Parameter(Mandatory)][string]$LlvmBin,
        [Parameter(Mandatory)][string]$WorkspaceTemp
    )

    if (-not $env:FORGE_CUDA_CCBIN) {
        return
    }

    $libRoot = Resolve-MsvcLibRootFromCudaCcbin -Ccbin $env:FORGE_CUDA_CCBIN
    $supportObjects = Expand-MsvcRuntimeSupportObjects -MsvcLibRoot $libRoot -LlvmBin $LlvmBin -WorkspaceTemp $WorkspaceTemp
    $vcStartupObjects = Expand-MsvcVcStartupSupportObjects -MsvcLibRoot $libRoot -LlvmBin $LlvmBin -WorkspaceTemp $WorkspaceTemp
    $importLibs = Copy-MsvcRuntimeImportLibs -MsvcLibRoot $libRoot -WorkspaceTemp $WorkspaceTemp
    $ucrtImportLib = Copy-UcrtImportLib -WorkspaceTemp $WorkspaceTemp
    $cudaImportLibDir = New-CudaToolkitNoSpaceView -WorkspaceTemp $WorkspaceTemp
    $pinnedLld = Assert-GccResolvesPinnedLld -GccExe $env:CC -LlvmBin $LlvmBin -ScratchDir $WorkspaceTemp
    $lldPrefix = ($LlvmBin.TrimEnd('\', '/')) + '\'
    $rustFlagTokens = @(
        "-L", "native=$cudaImportLibDir",
        "-C", "link-arg=-B$lldPrefix",
        "-C", "link-arg=-fuse-ld=lld",
        "-C", "link-arg=-Wl,/nodefaultlib:libcpmt",
        "-C", "link-arg=-Wl,/nodefaultlib:LIBCMT",
        "-C", "link-arg=-Wl,/nodefaultlib:OLDNAMES"
    )
    foreach ($object in $supportObjects) {
        $rustFlagTokens += @("-C", "link-arg=$object")
    }
    foreach ($object in $vcStartupObjects) {
        $rustFlagTokens += @("-C", "link-arg=$object")
    }
    foreach ($importLib in $importLibs) {
        $rustFlagTokens += @("-C", "link-arg=$importLib")
    }
    $rustFlagTokens += @("-C", "link-arg=$ucrtImportLib")
    $rustFlagTokens += @("-C", "link-arg=-lkernel32")
    Add-Rustflags -Tokens $rustFlagTokens
    Write-Output "CUDA_MSVC_RUNTIME_LINK[ASTRO_CUDA_MSVC_SUPPORT_OBJECTS]: verified pinned LLD at $pinnedLld; extracted $($supportObjects.Count) support object(s) from $MsvcRuntimeArchiveName, $($vcStartupObjects.Count) support object(s) from $MsvcVcStartupArchiveName, copied $($importLibs.Count + 1) MSVC/UCRT import lib(s), copied $($CudaImportLibNames.Count) CUDA import lib(s), set CUDA_PATH to no-space view $env:CUDA_PATH, and enabled MSVC defaultlib suppression under $WorkspaceTemp"
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
        [string]$SccacheServerPort,
        # #534/#566: the launcher-owned canonical Cargo target root. Exported as an
        # authoritative CARGO_TARGET_DIR so every Cargo child -- including a nested
        # `--manifest-path calyx/Cargo.toml` invocation that would otherwise select
        # calyx/target -- writes into the one directory the launcher owns and cleans.
        [Parameter(Mandatory)][string]$CargoTargetRoot
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
    # #534/#566: authoritative CARGO_TARGET_DIR. Cargo precedence is CLI --target-dir > env
    # CARGO_TARGET_DIR > env CARGO_BUILD_TARGET_DIR > config, so exporting this pins every
    # Cargo descendant -- root workspace, nested `--manifest-path calyx/Cargo.toml`, and the
    # nested cargo trybuild would spawn -- to the launcher-owned target root regardless of the
    # manifest it resolves. A child `--target-dir` (which would outrank this) is refused up
    # front by Assert-NoCargoTargetDirOverride, and an escaping ambient value is refused by
    # Assert-NoAmbientCargoTargetEscape, so this value is the single, owned target directory.
    $env:CARGO_TARGET_DIR = $CargoTargetRoot
    # #242: every descendant of the child command -- cargo, its parallel rustc processes,
    # and the NESTED cargo that trybuild spawns -- inherits these two, so they all address
    # the single server this launcher pre-starts on this root's port and none of them ever
    # takes the auto-start path that produced the os error 10048 bind race. RUSTC_WRAPPER
    # is deliberately NOT unset for nested cargo: an unset wrapper would silently drop the
    # trybuild phase out of the cache (an unlabelled degradation), whereas server
    # inheritance keeps one consistent, cached, deterministic compile path.
    $env:SCCACHE_SERVER_PORT = $SccacheServerPort
    $env:SCCACHE_IDLE_TIMEOUT = $SccacheIdleTimeout
    Set-CudaHostCompilerEnvironment
    Add-NvccAppendFlag -Flag "-Xcompiler=/Zc:preprocessor"
    Add-NvccAppendFlag -Flag "-DCCCL_DISABLE_NVTX"
    Add-NvccAppendFlag -Flag "-DNVTX_DISABLE"
    Write-Output "CUDA_HOST_COMPILER[ASTRO_NVCC_APPEND_FLAGS]: $NvccAppendFlagsEnv=$env:NVCC_APPEND_FLAGS"
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
    # Preserve the caller's CBM_CACHE_DIR/HOME/USERPROFILE exactly. The launcher owns
    # compiler/build state; it must not silently relocate product data for arbitrary
    # child commands. Real product FSV supplies an explicit store at the product edge.
}

# #611/#617: exact launcher process-generation attribution. A Windows Job Object
# receives JOB_OBJECT_MSG_NEW_PROCESS/EXIT_PROCESS for every descendant and remains
# the kernel source of truth across owner death. The persisted interval history is
# diagnostic provenance; cleanup authority is the exact owner identity plus the exact
# named Job membership, never a PID-only poll or a deleted verification registry.
$AstroTreeRecorderSource = @'
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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
    [DllImport("kernel32", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32", SetLastError = true)]
    static extern bool QueryInformationJobObject(IntPtr job, int cls, IntPtr info, uint len, out uint returnedLength);
    [DllImport("kernel32", SetLastError = true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle file, int cls, IntPtr info, uint len);
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint pathLength, uint flags);
    [DllImport("kernel32", SetLastError = true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle file, out BY_HANDLE_FILE_INFORMATION info);
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile
    );
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateHardLinkW(
        string newFileName,
        string existingFileName,
        IntPtr securityAttributes
    );
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint GetFileAttributesW(string fileName);
    [DllImport("kernel32", SetLastError = true)]
    static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        int informationClass,
        IntPtr information,
        uint bufferSize
    );

    const int JobObjectAssociateCompletionPortInformation = 7;
    const int JobObjectExtendedLimitInformation = 9;
    const int JobObjectBasicProcessIdList = 3;
    const int FileRenameInfo = 3;
    const int FileDispositionInfo = 4;
    const int FileIdInfo = 18;
    const uint JOB_OBJECT_MSG_NEW_PROCESS = 6;
    const uint JOB_OBJECT_MSG_EXIT_PROCESS = 7;
    const uint JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS = 8;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    const uint STOP_SENTINEL = 0xFFFFFFFF;
    const int ERROR_ALREADY_EXISTS = 183;
    const int ERROR_MORE_DATA = 234;
    const int WAIT_TIMEOUT = 258;
    const int ERROR_FILE_NOT_FOUND = 2;
    const int ERROR_PATH_NOT_FOUND = 3;
    // The manifest is cumulative process-lifetime provenance. Its size is determined
    // by the observed Job history, not by a policy threshold. The only format bound is
    // the CLR byte-array addressability required by exact in-memory CAS/readback.
    const long MAX_IN_MEMORY_FILE_BYTES = Int32.MaxValue;
    const int MAX_JOB_PROCESS_IDS = 65536;
    const long OPEN = -1L;
    const uint GENERIC_READ = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const uint DELETE_ACCESS = 0x00010000;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint FILE_SHARE_WRITE = 0x00000002;
    const uint FILE_SHARE_DELETE = 0x00000004;
    const uint CREATE_NEW = 1;
    const uint OPEN_EXISTING = 3;
    const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    const uint FILE_FLAG_WRITE_THROUGH = 0x80000000;
    const uint FILE_FLAG_DELETE_ON_CLOSE = 0x04000000;
    const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    const uint INVALID_FILE_ATTRIBUTES = 0xffffffff;

    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_ASSOCIATE_COMPLETION_PORT { public IntPtr CompletionKey; public IntPtr CompletionPort; }

    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IO_COUNTERS {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct BY_HANDLE_FILE_INFORMATION {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    IntPtr job, port;
    Thread thread;
    readonly ManualResetEventSlim workerReady = new ManualResetEventSlim(false);
    Exception workerFault;
    bool workerStopped;
    // #278 attempts 6+7: pid alone is ambiguous under PID REUSE, and first-seen
    // alone still false-attributes DEAD instances (attempt 7: four foreign-sweep
    // pids collided with startup children of ours first seen at 14:2x and long
    // dead when later state appeared. Record each pid's INSTANCE
    // LIFETIME intervals [first_seen, last_seen] -- the port delivers both
    // NEW_PROCESS and (ABNORMAL_)EXIT_PROCESS -- a list per pid, because the OS
    // can recycle a pid WITHIN our own tree. last = OPEN(-1) means the instance
    // had not exited when the manifest was written (serialized as null; recovery
    // treats it as open provenance and still consults the exact kernel Job).
    readonly Dictionary<int, List<long[]>> pidIntervals = new Dictionary<int, List<long[]>>();
    readonly object gate = new object();
    string manifestPath;
    int launcherPid;
    long launcherProcessStartUtcTicks;
    string launcherLockSha256;
    long launcherLeaseStartUtcTicks;
    string jobObjectName;
    long runStartedNs;
    bool dirty;
    long lastFlushNs;
    long lastTimestampNs;
    byte[] lastManifestBytes;
    string lastManifestFileIdentity;
    static readonly long UnixEpochTicks = new DateTime(
        1970, 1, 1, 0, 0, 0, DateTimeKind.Utc
    ).Ticks;

    static long UtcTicksToUnixNs(long ticks) {
        return checked((ticks - UnixEpochTicks) * 100L);
    }

    long NowUnixNs() {
        lock (gate) {
            long raw = UtcTicksToUnixNs(DateTime.UtcNow.Ticks);
            long next = raw;
            if (next <= lastTimestampNs) {
                next = checked(lastTimestampNs + 100L);
            }
            lastTimestampNs = next;
            return next;
        }
    }

    static void RequireLowerSha256(string value, string description) {
        if (value == null || value.Length != 64) {
            throw new ArgumentException(description + " must be exactly 64 lowercase hexadecimal characters");
        }
        for (int i = 0; i < value.Length; i++) {
            char c = value[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                throw new ArgumentException(description + " must be exactly 64 lowercase hexadecimal characters");
            }
        }
    }

    static string ExpectedManifestLeaf(int pid, long processTicks, string lockSha) {
        return "no-escape-attribution-v3.pid-" + pid.ToString(CultureInfo.InvariantCulture) +
            ".ticks-" + processTicks.ToString(CultureInfo.InvariantCulture) +
            ".lock-sha256-" + lockSha + ".json";
    }

    public static AstroTreeRecorder Start(
        string manifestPath,
        int launcherPid,
        long launcherProcessStartUtcTicks,
        string launcherLockSha256,
        long launcherLeaseStartUtcTicks,
        string jobObjectName
    ) {
        if (launcherPid <= 0) throw new ArgumentOutOfRangeException("launcherPid");
        if (launcherProcessStartUtcTicks <= 0 || launcherProcessStartUtcTicks > DateTime.MaxValue.Ticks)
            throw new ArgumentOutOfRangeException("launcherProcessStartUtcTicks");
        if (launcherLeaseStartUtcTicks < launcherProcessStartUtcTicks ||
            launcherLeaseStartUtcTicks > DateTime.MaxValue.Ticks)
            throw new ArgumentOutOfRangeException("launcherLeaseStartUtcTicks");
        RequireLowerSha256(launcherLockSha256, "launcher lock SHA-256");
        if (String.IsNullOrEmpty(jobObjectName) ||
            !jobObjectName.StartsWith("Global\\Astrolabe.LauncherTree.", StringComparison.Ordinal))
            throw new ArgumentException("job object name must use the exact Global Astrolabe launcher-tree namespace", "jobObjectName");
        string manifestFull = Path.GetFullPath(manifestPath);
        string expectedLeaf = ExpectedManifestLeaf(
            launcherPid,
            launcherProcessStartUtcTicks,
            launcherLockSha256
        );
        if (!String.Equals(Path.GetFileName(manifestFull), expectedLeaf, StringComparison.Ordinal))
            throw new ArgumentException("attribution manifest leaf does not bind the exact launcher generation and lock SHA: expected " + expectedLeaf, "manifestPath");
        if (File.Exists(manifestFull) || Directory.Exists(manifestFull))
            throw new IOException("exact-session attribution manifest already exists: " + manifestFull);

        AstroTreeRecorder r = new AstroTreeRecorder();
        r.manifestPath = manifestFull;
        r.launcherPid = launcherPid;
        r.launcherProcessStartUtcTicks = launcherProcessStartUtcTicks;
        r.launcherLockSha256 = launcherLockSha256;
        r.launcherLeaseStartUtcTicks = launcherLeaseStartUtcTicks;
        r.jobObjectName = jobObjectName;
        long minimumClockNs = Math.Max(
            UtcTicksToUnixNs(launcherProcessStartUtcTicks),
            UtcTicksToUnixNs(launcherLeaseStartUtcTicks)
        );
        r.lastTimestampNs = checked(minimumClockNs - 100L);
        r.runStartedNs = r.NowUnixNs();
        bool selfAssignedToKillOnCloseJob = false;
        try {
            r.job = CreateJobObjectW(IntPtr.Zero, jobObjectName);
            int createError = Marshal.GetLastWin32Error();
            if (r.job == IntPtr.Zero)
                throw new Win32Exception(createError, "CreateJobObjectW failed for " + jobObjectName);
            if (createError == ERROR_ALREADY_EXISTS)
                throw new IOException("exact-session Job Object name already exists: " + jobObjectName);

            // #617: v2 proved that a named Job can become unopenable after its last owner
            // handle closes while associated descendants remain alive. KILL_ON_JOB_CLOSE is
            // the kernel guarantee that makes dead-owner + absent exact name authoritative.
            // No breakaway flag is present, so descendants also cannot leave the causal job.
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            IntPtr limitBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(limits));
            try {
                Marshal.StructureToPtr(limits, limitBuffer, false);
                if (!SetInformationJobObject(
                    r.job,
                    JobObjectExtendedLimitInformation,
                    limitBuffer,
                    (uint)Marshal.SizeOf(limits)
                )) throw new Win32Exception(Marshal.GetLastWin32Error(), "could not enforce kill-on-close non-breakaway Job Object limits");
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION observed =
                    (JOBOBJECT_EXTENDED_LIMIT_INFORMATION)Marshal.PtrToStructure(
                        limitBuffer,
                        typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
                    );
                uint returnedLength;
                if (!QueryInformationJobObject(
                    r.job,
                    JobObjectExtendedLimitInformation,
                    limitBuffer,
                    (uint)Marshal.SizeOf(limits),
                    out returnedLength
                )) throw new Win32Exception(Marshal.GetLastWin32Error(), "could not read back kill-on-close Job Object limits");
                observed = (JOBOBJECT_EXTENDED_LIMIT_INFORMATION)Marshal.PtrToStructure(
                    limitBuffer,
                    typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
                );
                if (observed.BasicLimitInformation.LimitFlags !=
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
                    throw new InvalidDataException(
                        "Job Object limit readback differs from exact KILL_ON_JOB_CLOSE contract: " +
                        observed.BasicLimitInformation.LimitFlags.ToString(CultureInfo.InvariantCulture)
                    );
            } finally {
                Marshal.FreeHGlobal(limitBuffer);
            }

            r.port = CreateIoCompletionPort(new IntPtr(-1), IntPtr.Zero, UIntPtr.Zero, 1);
            if (r.port == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateIoCompletionPort failed");
            JOBOBJECT_ASSOCIATE_COMPLETION_PORT assoc = new JOBOBJECT_ASSOCIATE_COMPLETION_PORT();
            assoc.CompletionKey = r.job;
            assoc.CompletionPort = r.port;
            IntPtr assocBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(assoc));
            try {
                Marshal.StructureToPtr(assoc, assocBuffer, false);
                if (!SetInformationJobObject(
                    r.job,
                    JobObjectAssociateCompletionPortInformation,
                    assocBuffer,
                    (uint)Marshal.SizeOf(assoc)
                )) throw new Win32Exception(Marshal.GetLastWin32Error(), "could not associate Job Object completion port");
            } finally {
                Marshal.FreeHGlobal(assocBuffer);
            }

            if (!AssignProcessToJobObject(r.job, GetCurrentProcess()))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "could not assign launcher to exact-session Job Object");
            selfAssignedToKillOnCloseJob = true;
            lock (r.gate) {
                List<long[]> spans = new List<long[]>();
                spans.Add(new long[] { r.runStartedNs, OPEN });
                r.pidIntervals[launcherPid] = spans;
                r.dirty = true;
            }

            // The first complete, independently read-back manifest exists before the worker
            // starts and before the caller is allowed to publish the active launcher lock.
            r.Flush();
            r.thread = new Thread(r.Loop);
            r.thread.IsBackground = true;
            r.thread.Name = "Astrolabe exact tree attribution recorder";
            r.thread.Start();
            if (!r.workerReady.Wait(TimeSpan.FromSeconds(30)))
                throw new TimeoutException("tree-attribution worker did not reach its startup barrier");
            r.ThrowIfWorkerFaulted();
            return r;
        } catch (Exception startFault) {
            List<Exception> faults = new List<Exception>();
            faults.Add(startFault);
            if (r.thread != null && r.thread.IsAlive) {
                if (!PostQueuedCompletionStatus(r.port, STOP_SENTINEL, UIntPtr.Zero, IntPtr.Zero))
                    faults.Add(new Win32Exception(Marshal.GetLastWin32Error(), "could not post startup-failure stop sentinel"));
                if (!r.thread.Join(TimeSpan.FromSeconds(30)))
                    faults.Add(new TimeoutException("tree-attribution worker did not terminate after startup failure"));
            }
            if (r.port != IntPtr.Zero && !CloseHandle(r.port))
                faults.Add(new Win32Exception(Marshal.GetLastWin32Error(), "could not close completion port after recorder startup failure"));
            if (!selfAssignedToKillOnCloseJob && r.job != IntPtr.Zero &&
                !CloseHandle(r.job))
                faults.Add(new Win32Exception(Marshal.GetLastWin32Error(), "could not close unassigned Job Object after recorder startup failure"));
            // #625: after the launcher is associated, the Job handle is intentionally
            // process-lifetime-owned even when later startup fails. Closing it here
            // would kill the launcher before PowerShell could persist the real fault.
            // A reserved manifest may already have become visible. Never path-delete it
            // from an error path: preserve the complete bytes for explicit inspection.
            if (faults.Count == 1) throw;
            throw new AggregateException("tree-attribution recorder startup and cleanup failed", faults);
        }
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
                if (spans.Count > 0 && now <= spans[spans.Count - 1][1])
                    now = checked(spans[spans.Count - 1][1] + 100L);
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
                    if (now < spans[spans.Count - 1][0]) now = spans[spans.Count - 1][0];
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

    void Loop() {
        workerReady.Set();
        try {
            while (true) {
                uint bytes; UIntPtr key; IntPtr ov;
                bool got = GetQueuedCompletionStatus(port, out bytes, out key, out ov, 500);
                if (got) {
                    if (bytes == STOP_SENTINEL) break;
                    long now = NowUnixNs();
                    if (bytes == JOB_OBJECT_MSG_NEW_PROCESS) {
                        OnNewProcess((int)ov.ToInt64(), now);
                    } else if (bytes == JOB_OBJECT_MSG_EXIT_PROCESS || bytes == JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS) {
                        OnExitProcess((int)ov.ToInt64(), now);
                    }
                } else {
                    int waitError = Marshal.GetLastWin32Error();
                    if (waitError != WAIT_TIMEOUT)
                        throw new Win32Exception(waitError, "Job Object completion-port wait failed");
                }
                // Throttled persistence: thousands of short-lived children generate
                // ~2 messages each; run one typed destination-CAS refresh at most once a second.
                long tick = NowUnixNs();
                bool doFlush;
                lock (gate) { doFlush = dirty && (tick - lastFlushNs > 1000000000L); }
                if (doFlush) Flush();
            }
        } catch (Exception fault) {
            lock (gate) { workerFault = fault; }
        }
    }

    void ThrowIfWorkerFaulted() {
        Exception fault;
        lock (gate) { fault = workerFault; }
        if (fault != null)
            throw new InvalidOperationException(
                "tree-attribution worker failed: " + DescribeExceptionChain(fault),
                fault
            );
    }

    static string DescribeExceptionChain(Exception fault) {
        StringBuilder detail = new StringBuilder();
        int depth = 0;
        for (Exception current = fault; current != null; current = current.InnerException) {
            if (depth > 0) detail.Append(" <- ");
            detail.Append("depth=").Append(depth.ToString(CultureInfo.InvariantCulture));
            detail.Append(" type=").Append(current.GetType().FullName);
            detail.Append(" hresult=0x").Append(
                current.HResult.ToString("x8", CultureInfo.InvariantCulture)
            );
            Win32Exception native = current as Win32Exception;
            if (native != null) {
                detail.Append(" native_error=").Append(
                    native.NativeErrorCode.ToString(CultureInfo.InvariantCulture)
                );
            }
            detail.Append(" message=");
            AppendJsonString(detail, current.Message ?? String.Empty);
            depth++;
        }
        return detail.ToString();
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

    static void AppendLong(StringBuilder sb, long value) {
        sb.Append(value.ToString(CultureInfo.InvariantCulture));
    }

    static void AppendInt(StringBuilder sb, int value) {
        sb.Append(value.ToString(CultureInfo.InvariantCulture));
    }

    static bool BytesEqual(byte[] left, byte[] right) {
        if (left == null || right == null || left.Length != right.Length) return false;
        for (int i = 0; i < left.Length; i++) if (left[i] != right[i]) return false;
        return true;
    }

    static uint RequireOrdinaryFile(SafeFileHandle handle, string description) {
        BY_HANDLE_FILE_INFORMATION info;
        if (!GetFileInformationByHandle(handle, out info))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "could not inspect " + description);
        const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
        const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
        if ((info.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
            throw new InvalidOperationException(description + " is not an ordinary non-reparse file");
        return info.NumberOfLinks;
    }

    static void RequireOrdinarySingleLink(SafeFileHandle handle, string description) {
        uint links = RequireOrdinaryFile(handle, description);
        if (links != 1)
            throw new InvalidOperationException(description + " must have exactly one filesystem link; observed " + links);
    }

    static string GetFileIdentity(SafeFileHandle handle) {
        IntPtr buffer = Marshal.AllocHGlobal(24);
        try {
            for (int i = 0; i < 24; i++) Marshal.WriteByte(buffer, i, 0);
            if (!GetFileInformationByHandleEx(handle, FileIdInfo, buffer, 24))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "could not read retained manifest FILE_ID_INFO");
            ulong volume = unchecked((ulong)Marshal.ReadInt64(buffer, 0));
            byte[] fileId = new byte[16];
            Marshal.Copy(IntPtr.Add(buffer, 8), fileId, 0, fileId.Length);
            bool allZero = true;
            bool allOnes = true;
            for (int i = 0; i < fileId.Length; i++) {
                allZero &= fileId[i] == 0;
                allOnes &= fileId[i] == 0xff;
            }
            if (allZero || allOnes)
                throw new InvalidOperationException(
                    "FILE_ID_INFO returned a reserved all-zero/all-ones file identifier"
                );
            StringBuilder result = new StringBuilder(49);
            result.Append(volume.ToString("x16", CultureInfo.InvariantCulture));
            result.Append(':');
            for (int i = 0; i < fileId.Length; i++) result.Append(fileId[i].ToString("x2", CultureInfo.InvariantCulture));
            return result.ToString();
        } finally {
            Marshal.FreeHGlobal(buffer);
        }
    }

    static string GetFinalPath(SafeFileHandle handle) {
        StringBuilder buffer = new StringBuilder(1024);
        uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0) throw new Win32Exception(Marshal.GetLastWin32Error(), "could not read retained manifest final path");
        if (length >= buffer.Capacity) {
            buffer = new StringBuilder(checked((int)length + 1));
            length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "could not read complete retained manifest final path");
        }
        string result = buffer.ToString();
        if (result.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
            result = "\\\\" + result.Substring(8);
        else if (result.StartsWith("\\\\?\\", StringComparison.Ordinal))
            result = result.Substring(4);
        return Path.GetFullPath(result);
    }

    static void RequireAttributionProtocolPath(
        SafeFileHandle handle,
        string expectedPath,
        string description
    ) {
        string actual = GetFinalPath(handle);
        string expected = Path.GetFullPath(expectedPath);
        if (!String.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_RETAINED_PATH_MISMATCH]: " +
                description + " retained path differs from its bound destination " +
                "(expected=" + expected + ", observed=" + actual + ")"
            );
        string actualLeaf = Path.GetFileName(actual);
        string expectedLeaf = Path.GetFileName(expected);
        string actualParent = Path.GetDirectoryName(actual);
        string actualParentLeaf = String.IsNullOrEmpty(actualParent)
            ? String.Empty
            : Path.GetFileName(actualParent.TrimEnd(new char[] { '\\', '/' }));
        if (!String.Equals(actualParentLeaf, ".tmp", StringComparison.Ordinal) ||
            !String.Equals(actualLeaf, expectedLeaf, StringComparison.Ordinal))
            throw new InvalidDataException(
                "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_RETAINED_PATH_CASE_DRIFT]: " +
                description + " retained path lacks the exact protocol components " +
                "(expected_parent=.tmp, observed_parent=" + actualParentLeaf +
                ", expected_leaf=" + expectedLeaf + ", observed_leaf=" + actualLeaf +
                ", final_path=" + actual + ")"
            );
    }

    static string GetExtendedLengthPath(string path) {
        string full = Path.GetFullPath(path);
        if (full.StartsWith("\\\\?\\", StringComparison.Ordinal)) return full;
        if (full.StartsWith("\\\\", StringComparison.Ordinal))
            return "\\\\?\\UNC\\" + full.Substring(2);
        return "\\\\?\\" + full;
    }

    static void RenameHandleNoReplace(SafeFileHandle source, string destination) {
        // SetFileInformationByHandle is a Unicode Win32 API, but an ordinary DOS
        // absolute path still hits MAX_PATH. Always use the canonical extended-
        // length form; the U+0000 terminator remains outside FileNameLength.
        byte[] nameBytes = Encoding.Unicode.GetBytes(
            GetExtendedLengthPath(destination)
        );
        int rootOffset = IntPtr.Size == 8 ? 8 : 4;
        int lengthOffset = rootOffset + IntPtr.Size;
        int nameOffset = lengthOffset + 4;
        // FILE_RENAME_INFO is variable-length, but the native structure carries
        // WCHAR FileName[1] and the Windows API consumes an aligned information
        // buffer.  Keep one explicit zero UTF-16 code unit after FileName and pass
        // pointer-size-aligned storage, matching the hardened shared rename helpers.
        // The former exact-length allocation produced a real trailing U+7FFE leaf
        // corruption under #624.
        int rawSize = checked(nameOffset + nameBytes.Length + 2);
        int bufferSize = checked(
            ((rawSize + IntPtr.Size - 1) / IntPtr.Size) * IntPtr.Size
        );
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try {
            for (int i = 0; i < bufferSize; i++) Marshal.WriteByte(buffer, i, 0);
            Marshal.WriteInt32(buffer, 0, 0);
            Marshal.WriteIntPtr(buffer, rootOffset, IntPtr.Zero);
            Marshal.WriteInt32(buffer, lengthOffset, nameBytes.Length);
            Marshal.Copy(nameBytes, 0, IntPtr.Add(buffer, nameOffset), nameBytes.Length);
            if (!SetFileInformationByHandle(source, FileRenameInfo, buffer, (uint)bufferSize)) {
                int nativeError = Marshal.GetLastWin32Error();
                throw new Win32Exception(
                    nativeError,
                    "exact-handle no-replace attribution namespace transition failed; native_error=" +
                    nativeError.ToString(CultureInfo.InvariantCulture)
                );
            }
        } finally {
            Marshal.FreeHGlobal(buffer);
        }
    }

    static void SetDeleteDisposition(SafeFileHandle source, string description) {
        IntPtr buffer = Marshal.AllocHGlobal(1);
        try {
            Marshal.WriteByte(buffer, 0, 1);
            if (!SetFileInformationByHandle(source, FileDispositionInfo, buffer, 1))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "could not set exact FILE_DISPOSITION_INFO for " + description
                );
        } finally {
            Marshal.FreeHGlobal(buffer);
        }
    }

    static string Sha256Hex(byte[] bytes) {
        using (SHA256 sha = SHA256.Create()) {
            byte[] digest = sha.ComputeHash(bytes);
            StringBuilder result = new StringBuilder(64);
            for (int i = 0; i < digest.Length; i++) result.Append(digest[i].ToString("x2", CultureInfo.InvariantCulture));
            return result.ToString();
        }
    }

    static void RequirePathAbsent(string path, string description) {
        uint attributes = GetFileAttributesW(GetExtendedLengthPath(path));
        if (attributes != INVALID_FILE_ATTRIBUTES)
            throw new IOException(description + " remains present: " + path);
        int error = Marshal.GetLastWin32Error();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
            throw new Win32Exception(error, "could not prove " + description + " absent: " + path);
    }

    static byte[] ReadAllExact(FileStream stream) {
        if (stream.Length < 0 || stream.Length > MAX_IN_MEMORY_FILE_BYTES)
            throw new InvalidDataException(
                "attribution protocol file length exceeds CLR byte-array addressability 0.." +
                MAX_IN_MEMORY_FILE_BYTES.ToString(CultureInfo.InvariantCulture) +
                ": " + stream.Length.ToString(CultureInfo.InvariantCulture)
            );
        byte[] result = new byte[(int)stream.Length];
        stream.Position = 0;
        int offset = 0;
        while (offset < result.Length) {
            int read = stream.Read(result, offset, result.Length - offset);
            if (read <= 0) throw new EndOfStreamException("attribution manifest read ended at byte " + offset + " of " + result.Length);
            offset += read;
        }
        if (stream.Length != result.Length)
            throw new InvalidDataException("attribution manifest length changed during readback");
        return result;
    }

    static FileStream CreateExactDeleteOnCloseScratch(string path) {
        SafeFileHandle handle = CreateFileW(
            GetExtendedLengthPath(path),
            GENERIC_READ | GENERIC_WRITE | DELETE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            IntPtr.Zero,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH |
                FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero
        );
        if (handle == null || handle.IsInvalid) {
            int error = Marshal.GetLastWin32Error();
            if (handle != null) handle.Dispose();
            throw new Win32Exception(
                error,
                "could not create exact delete-on-close attribution scratch file: " + path
            );
        }
        try {
            return new FileStream(handle, FileAccess.ReadWrite, 4096, false);
        } catch {
            handle.Dispose();
            throw;
        }
    }

    static FileStream OpenExactNativeStream(
        string path,
        uint desiredAccess,
        uint shareMode,
        FileAccess fileAccess,
        string description
    ) {
        SafeFileHandle handle = CreateFileW(
            GetExtendedLengthPath(path),
            desiredAccess,
            shareMode,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH |
                FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero
        );
        if (handle == null || handle.IsInvalid) {
            int error = Marshal.GetLastWin32Error();
            if (handle != null) handle.Dispose();
            throw new Win32Exception(error, "could not open exact " + description + ": " + path);
        }
        try {
            return new FileStream(handle, fileAccess, 4096, false);
        } catch {
            handle.Dispose();
            throw;
        }
    }

    static FileStream OpenProtectedRead(string path, string description) {
        return OpenExactNativeStream(
            path,
            GENERIC_READ,
            FILE_SHARE_READ,
            FileAccess.Read,
            description
        );
    }

    static FileStream OpenProtectedMutation(string path, string description) {
        return OpenExactNativeStream(
            path,
            GENERIC_READ | DELETE_ACCESS,
            FILE_SHARE_READ,
            FileAccess.Read,
            description
        );
    }

    static FileStream OpenLinkedObserver(string path, string description) {
        return OpenExactNativeStream(
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FileAccess.Read,
            description
        );
    }

    static FileStream PublishScratchHardLinkAndProtect(
        ref FileStream scratch,
        string scratchPath,
        string destination,
        byte[] intended,
        bool retainMutationAuthority,
        string description
    ) {
        if (scratch == null || scratch.SafeFileHandle.IsInvalid || scratch.SafeFileHandle.IsClosed)
            throw new InvalidOperationException(description + " requires one live scratch handle");
        string scratchIdentity = GetFileIdentity(scratch.SafeFileHandle);
        byte[] scratchBytes = ReadAllExact(scratch);
        if (!BytesEqual(scratchBytes, intended))
            throw new InvalidDataException(description + " scratch bytes changed before publication");
        if (!CreateHardLinkW(
                GetExtendedLengthPath(destination),
                GetExtendedLengthPath(scratchPath),
                IntPtr.Zero
            )) {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                description + " no-replace CreateHardLinkW publication failed"
            );
        }
        scratch.Flush(true);

        FileStream observer = null;
        FileStream retained = null;
        try {
            observer = OpenLinkedObserver(destination, description + " linked observer");
            if (!String.Equals(GetFileIdentity(observer.SafeFileHandle), scratchIdentity, StringComparison.Ordinal) ||
                !BytesEqual(ReadAllExact(observer), intended))
                throw new InvalidDataException(description + " linked observer does not match the exact scratch object/bytes");

            scratch.Dispose();
            scratch = null;
            RequirePathAbsent(scratchPath, description + " delete-on-close scratch");

            retained = retainMutationAuthority
                ? OpenProtectedMutation(destination, description + " protected mutation lease")
                : OpenProtectedRead(destination, description + " protected read lease");
            RequireOrdinarySingleLink(retained.SafeFileHandle, description + " published final");
            RequireAttributionProtocolPath(
                retained.SafeFileHandle,
                destination,
                description + " published final"
            );
            if (!String.Equals(GetFileIdentity(retained.SafeFileHandle), scratchIdentity, StringComparison.Ordinal) ||
                !BytesEqual(ReadAllExact(retained), intended))
                throw new InvalidDataException(description + " protected final path/FILE_ID/bytes differ from its scratch binding");
            return retained;
        } catch {
            if (retained != null) retained.Dispose();
            throw;
        } finally {
            if (observer != null) observer.Dispose();
        }
    }

    static byte[] BuildRefreshEnvelope(
        int launcherPid,
        long launcherProcessStartUtcTicks,
        string launcherLockSha256,
        long launcherLeaseStartUtcTicks,
        string jobObjectName,
        string nonce,
        string finalPath,
        string oldIdentity,
        byte[] oldBytes,
        string newScratchPath,
        string newIdentity,
        byte[] newBytes,
        string oldTombstonePath,
        string preparedEnvelopePath,
        string dispositionProofPath
    ) {
        StringBuilder sb = new StringBuilder();
        sb.Append("{\"schema\":\"astrolabe.no_escape_attribution.refresh.v1\",\"launcher_pid\":");
        AppendInt(sb, launcherPid);
        sb.Append(",\"launcher_process_start_utc_ticks\":");
        AppendLong(sb, launcherProcessStartUtcTicks);
        sb.Append(",\"launcher_lock_sha256\":");
        AppendJsonString(sb, launcherLockSha256);
        sb.Append(",\"launcher_lease_start_utc_ticks\":");
        AppendLong(sb, launcherLeaseStartUtcTicks);
        sb.Append(",\"job_object_name\":");
        AppendJsonString(sb, jobObjectName);
        sb.Append(",\"transaction_nonce\":");
        AppendJsonString(sb, nonce);
        sb.Append(",\"final_path\":");
        AppendJsonString(sb, Path.GetFullPath(finalPath));
        sb.Append(",\"old_final_path\":");
        AppendJsonString(sb, Path.GetFullPath(finalPath));
        sb.Append(",\"old_final_file_identity\":");
        AppendJsonString(sb, oldIdentity);
        sb.Append(",\"old_final_length\":");
        AppendLong(sb, oldBytes.LongLength);
        sb.Append(",\"old_final_sha256\":");
        AppendJsonString(sb, Sha256Hex(oldBytes));
        sb.Append(",\"new_scratch_path\":");
        AppendJsonString(sb, Path.GetFullPath(newScratchPath));
        sb.Append(",\"new_scratch_file_identity\":");
        AppendJsonString(sb, newIdentity);
        sb.Append(",\"new_manifest_length\":");
        AppendLong(sb, newBytes.LongLength);
        sb.Append(",\"new_manifest_sha256\":");
        AppendJsonString(sb, Sha256Hex(newBytes));
        sb.Append(",\"old_tombstone_path\":");
        AppendJsonString(sb, Path.GetFullPath(oldTombstonePath));
        sb.Append(",\"prepared_envelope_path\":");
        AppendJsonString(sb, Path.GetFullPath(preparedEnvelopePath));
        sb.Append(",\"disposition_proof_path\":");
        AppendJsonString(sb, Path.GetFullPath(dispositionProofPath));
        sb.Append('}');
        byte[] bytes = new UTF8Encoding(false, true).GetBytes(sb.ToString());
        if (bytes.Length == 0)
            throw new InvalidDataException("refresh envelope must not be empty");
        return bytes;
    }

    static FileStream PublishRefreshEnvelope(
        byte[] envelopeBytes,
        string scratchPath,
        string envelopePath
    ) {
        FileStream scratch = null;
        try {
            scratch = CreateExactDeleteOnCloseScratch(scratchPath);
            RequireOrdinarySingleLink(scratch.SafeFileHandle, "refresh-envelope scratch");
            scratch.Write(envelopeBytes, 0, envelopeBytes.Length);
            scratch.Flush(true);
            if (!BytesEqual(ReadAllExact(scratch), envelopeBytes))
                throw new InvalidDataException("durable refresh-envelope scratch readback differs from intended bytes");
            return PublishScratchHardLinkAndProtect(
                ref scratch,
                scratchPath,
                envelopePath,
                envelopeBytes,
                true,
                "refresh envelope"
            );
        } finally {
            if (scratch != null) scratch.Dispose();
        }
    }

    string PublishManifestBytes(byte[] intended, byte[] expectedPrevious, string expectedPreviousIdentity) {
        if (intended == null || intended.Length == 0)
            throw new InvalidDataException("serialized attribution manifest must not be empty");
        string directory = Path.GetDirectoryName(manifestPath);
        string nonce = Guid.NewGuid().ToString("N");
        string scratchPath = Path.Combine(
            directory,
            ".astro-manifest-refresh-scratch-v1.pid-" + launcherPid.ToString(CultureInfo.InvariantCulture) +
            ".ticks-" + launcherProcessStartUtcTicks.ToString(CultureInfo.InvariantCulture) +
            ".lock-sha256-" + launcherLockSha256 +
            ".nonce-" + nonce + ".tmp"
        );
        string preparedEnvelopePath = Path.Combine(
            directory,
            ".astro-attribution-refresh.v1.prepared.pid-" + launcherPid.ToString(CultureInfo.InvariantCulture) +
            ".ticks-" + launcherProcessStartUtcTicks.ToString(CultureInfo.InvariantCulture) +
            ".lock-sha256-" + launcherLockSha256 + ".nonce-" + nonce + ".json"
        );
        string dispositionProofPath = Path.Combine(
            directory,
            ".astro-attribution-refresh.v1.old-disposition-set.pid-" + launcherPid.ToString(CultureInfo.InvariantCulture) +
            ".ticks-" + launcherProcessStartUtcTicks.ToString(CultureInfo.InvariantCulture) +
            ".lock-sha256-" + launcherLockSha256 + ".nonce-" + nonce + ".json"
        );
        string oldTombstonePath = Path.Combine(
            directory,
            ".astro-attribution-refresh-old.v1.pid-" + launcherPid.ToString(CultureInfo.InvariantCulture) +
            ".ticks-" + launcherProcessStartUtcTicks.ToString(CultureInfo.InvariantCulture) +
            ".lock-sha256-" + launcherLockSha256 + ".nonce-" + nonce + ".bin"
        );
        string envelopeScratchPath = Path.Combine(
            directory,
            ".astro-manifest-refresh-envelope-scratch-v1.pid-" + launcherPid.ToString(CultureInfo.InvariantCulture) +
            ".ticks-" + launcherProcessStartUtcTicks.ToString(CultureInfo.InvariantCulture) +
            ".lock-sha256-" + launcherLockSha256 + ".nonce-" + nonce + ".tmp"
        );
        FileStream newScratch = null;
        FileStream previous = null;
        FileStream envelope = null;
        FileStream published = null;
        try {
            newScratch = CreateExactDeleteOnCloseScratch(scratchPath);
            RequireOrdinarySingleLink(newScratch.SafeFileHandle, "new attribution-manifest scratch");
            newScratch.Write(intended, 0, intended.Length);
            newScratch.Flush(true);
            if (!BytesEqual(ReadAllExact(newScratch), intended))
                throw new InvalidDataException("durable new-manifest scratch readback differs from intended bytes");
            string newIdentity = GetFileIdentity(newScratch.SafeFileHandle);

            if (expectedPrevious == null) {
                if (!String.IsNullOrEmpty(expectedPreviousIdentity))
                    throw new InvalidOperationException("first attribution publication unexpectedly supplied a previous FILE_ID binding");
                published = PublishScratchHardLinkAndProtect(
                    ref newScratch,
                    scratchPath,
                    manifestPath,
                    intended,
                    false,
                    "initial attribution manifest"
                );
                string initialIdentity = GetFileIdentity(published.SafeFileHandle);
                if (!String.Equals(initialIdentity, newIdentity, StringComparison.Ordinal))
                    throw new InvalidDataException("initial published manifest lost its scratch FILE_ID binding");
                return initialIdentity;
            }

            if (String.IsNullOrEmpty(expectedPreviousIdentity))
                throw new InvalidOperationException("refresh attribution FILE_ID binding is missing");
            previous = OpenProtectedMutation(manifestPath, "previous attribution manifest");
            RequireOrdinarySingleLink(previous.SafeFileHandle, "previous attribution manifest");
            RequireAttributionProtocolPath(
                previous.SafeFileHandle,
                manifestPath,
                "previous attribution manifest"
            );
            string oldIdentity = GetFileIdentity(previous.SafeFileHandle);
            byte[] oldBytes = ReadAllExact(previous);
            if (!String.Equals(oldIdentity, expectedPreviousIdentity, StringComparison.Ordinal) ||
                !BytesEqual(oldBytes, expectedPrevious))
                throw new InvalidDataException("previous attribution FILE_ID/bytes drifted before refresh preparation");

            byte[] envelopeBytes = BuildRefreshEnvelope(
                launcherPid,
                launcherProcessStartUtcTicks,
                launcherLockSha256,
                launcherLeaseStartUtcTicks,
                jobObjectName,
                nonce,
                manifestPath,
                oldIdentity,
                oldBytes,
                scratchPath,
                newIdentity,
                intended,
                oldTombstonePath,
                preparedEnvelopePath,
                dispositionProofPath
            );
            envelope = PublishRefreshEnvelope(
                envelopeBytes,
                envelopeScratchPath,
                preparedEnvelopePath
            );

            RenameHandleNoReplace(previous.SafeFileHandle, oldTombstonePath);
            previous.Flush(true);
            RequireAttributionProtocolPath(
                previous.SafeFileHandle,
                oldTombstonePath,
                "old attribution refresh tombstone"
            );
            if (!String.Equals(GetFileIdentity(previous.SafeFileHandle), oldIdentity, StringComparison.Ordinal) ||
                !BytesEqual(ReadAllExact(previous), oldBytes))
                throw new InvalidDataException("old attribution tombstone lost its exact FILE_ID/bytes binding");
            RequirePathAbsent(manifestPath, "refresh final after old-manifest tombstoning");

            published = PublishScratchHardLinkAndProtect(
                ref newScratch,
                scratchPath,
                manifestPath,
                intended,
                false,
                "refreshed attribution manifest"
            );
            if (!String.Equals(GetFileIdentity(published.SafeFileHandle), newIdentity, StringComparison.Ordinal) ||
                !BytesEqual(ReadAllExact(published), intended))
                throw new InvalidDataException("refreshed final does not match the envelope-bound new FILE_ID/bytes");

            // The proof phase is named while the exact old tombstone handle is still
            // retained and deletion-denied. Consequently a proof envelope without its
            // old tombstone can arise only after this producer crossed exact disposition.
            RenameHandleNoReplace(envelope.SafeFileHandle, dispositionProofPath);
            envelope.Flush(true);
            RequireAttributionProtocolPath(
                envelope.SafeFileHandle,
                dispositionProofPath,
                "attribution refresh proof envelope"
            );
            if (!BytesEqual(ReadAllExact(envelope), envelopeBytes))
                throw new InvalidDataException("refresh proof envelope lost its exact path/bytes binding");
            RequirePathAbsent(preparedEnvelopePath, "prepared refresh envelope after proof transition");

            if (!String.Equals(GetFileIdentity(previous.SafeFileHandle), oldIdentity, StringComparison.Ordinal) ||
                !BytesEqual(ReadAllExact(previous), oldBytes))
                throw new InvalidDataException("old attribution tombstone changed before disposition");
            SetDeleteDisposition(previous.SafeFileHandle, "old attribution refresh tombstone");
            previous.Dispose();
            previous = null;
            RequirePathAbsent(oldTombstonePath, "old attribution refresh tombstone");

            // The envelope is the last transaction artifact disposed. The final remains
            // retained write/delete-denied while its exact FILE_ID and bytes are re-read.
            if (!String.Equals(GetFileIdentity(published.SafeFileHandle), newIdentity, StringComparison.Ordinal) ||
                !BytesEqual(ReadAllExact(published), intended))
                throw new InvalidDataException("refreshed final changed before envelope disposition");
            if (!BytesEqual(ReadAllExact(envelope), envelopeBytes))
                throw new InvalidDataException("refresh proof envelope changed before disposition");
            SetDeleteDisposition(envelope.SafeFileHandle, "attribution refresh disposition-proof envelope");
            envelope.Dispose();
            envelope = null;
            RequirePathAbsent(dispositionProofPath, "attribution refresh disposition-proof envelope");
            RequirePathAbsent(scratchPath, "new attribution-manifest scratch");
            RequirePathAbsent(envelopeScratchPath, "refresh-envelope scratch");
            return newIdentity;
        } catch (Exception fault) {
            throw new IOException(
                "attribution destination-CAS publication failed; exact typed refresh state was preserved " +
                "(final=" + manifestPath + ", prepared_envelope=" + preparedEnvelopePath +
                ", disposition_proof=" + dispositionProofPath + ", old_tombstone=" +
                oldTombstonePath + ")",
                fault
            );
        } finally {
            if (published != null) published.Dispose();
            if (envelope != null) envelope.Dispose();
            if (previous != null) previous.Dispose();
            if (newScratch != null) newScratch.Dispose();
        }
    }

    void Flush() {
        List<KeyValuePair<int, List<long[]>>> snap = new List<KeyValuePair<int, List<long[]>>>();
        long flushNs;
        byte[] previousBytes;
        string previousIdentity;
        lock (gate) {
            foreach (KeyValuePair<int, List<long[]>> entry in pidIntervals) {
                List<long[]> copy = new List<long[]>();
                foreach (long[] span in entry.Value) copy.Add(new long[] { span[0], span[1] });
                snap.Add(new KeyValuePair<int, List<long[]>>(entry.Key, copy));
            }
            flushNs = NowUnixNs();
            previousBytes = lastManifestBytes == null
                ? null
                : (byte[])lastManifestBytes.Clone();
            previousIdentity = lastManifestFileIdentity;
        }
        snap.Sort(delegate(
            KeyValuePair<int, List<long[]>> left,
            KeyValuePair<int, List<long[]>> right
        ) { return left.Key.CompareTo(right.Key); });
        StringBuilder sb = new StringBuilder();
        sb.Append("{\"schema\":\"astrolabe.no_escape_attribution.v3\",\"launcher_pid\":");
        AppendInt(sb, launcherPid);
        sb.Append(",\"launcher_process_start_utc_ticks\":");
        AppendLong(sb, launcherProcessStartUtcTicks);
        sb.Append(",\"launcher_lock_sha256\":");
        AppendJsonString(sb, launcherLockSha256);
        sb.Append(",\"launcher_lease_start_utc_ticks\":");
        AppendLong(sb, launcherLeaseStartUtcTicks);
        sb.Append(",\"job_object_name\":");
        AppendJsonString(sb, jobObjectName);
        sb.Append(",\"job_limit_flags\":");
        AppendLong(sb, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE);
        sb.Append(",\"run_started_unix_ns\":");
        AppendLong(sb, runStartedNs);
        // written_at stamps this exact durable generation. Recovery validates its
        // temporal relation to the lease and PID intervals; it never infers a newer
        // process-tree state from an older manifest generation.
        sb.Append(",\"written_at\":");
        AppendLong(sb, flushNs);
        sb.Append(",\"tree_pids\":[");
        for (int i = 0; i < snap.Count; i++) { if (i > 0) sb.Append(','); AppendInt(sb, snap[i].Key); }
        sb.Append("],\"pid_first_seen\":{");
        for (int i = 0; i < snap.Count; i++) {
            if (i > 0) sb.Append(',');
            sb.Append('"'); AppendInt(sb, snap[i].Key); sb.Append("\":"); AppendLong(sb, snap[i].Value[0][0]);
        }
        sb.Append("},\"pid_intervals\":{");
        for (int i = 0; i < snap.Count; i++) {
            if (i > 0) sb.Append(',');
            sb.Append('"'); AppendInt(sb, snap[i].Key); sb.Append("\":[");
            List<long[]> spans = snap[i].Value;
            for (int j = 0; j < spans.Count; j++) {
                if (j > 0) sb.Append(',');
                sb.Append('['); AppendLong(sb, spans[j][0]); sb.Append(',');
                if (spans[j][1] == OPEN) sb.Append("null"); else AppendLong(sb, spans[j][1]);
                sb.Append(']');
            }
            sb.Append(']');
        }
        // #621: owned_paths belonged to the retired no-escape gate's Restart Manager
        // store scan. Preserve the strict versioned field and canonical shape, but publish the
        // honest empty set; exact Job membership is the production cleanup authority.
        sb.Append("},\"owned_paths\":[]}");
        byte[] intended = new UTF8Encoding(false, true).GetBytes(sb.ToString());
        string publishedIdentity = PublishManifestBytes(
            intended,
            previousBytes,
            previousIdentity
        );
        lock (gate) {
            lastManifestBytes = (byte[])intended.Clone();
            lastManifestFileIdentity = publishedIdentity;
            lastFlushNs = flushNs;
            dirty = false;
        }
    }

    public void Stop() {
        if (workerStopped) return;
        ThrowIfWorkerFaulted();
        if (!PostQueuedCompletionStatus(port, STOP_SENTINEL, UIntPtr.Zero, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "could not post tree-attribution stop barrier");
        if (thread == null || !thread.Join(TimeSpan.FromSeconds(30)))
            throw new TimeoutException("tree-attribution worker did not terminate at the stop barrier");
        ThrowIfWorkerFaulted();
        // Final atomic publication happens only after every completion queued before the
        // sentinel was drained by the single worker. Anything still in the kernel job is
        // independently queried by cleanup/reclaim and remains an open interval.
        Flush();
        workerStopped = true;
    }

    public byte[] GetLastManifestBytes() {
        lock (gate) {
            if (lastManifestBytes == null) throw new InvalidOperationException("no durable attribution manifest has been published");
            return (byte[])lastManifestBytes.Clone();
        }
    }

    public int[] GetActiveProcessIds() {
        int capacity = 64;
        while (capacity <= MAX_JOB_PROCESS_IDS) {
            int size = checked(8 + capacity * IntPtr.Size);
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try {
                for (int i = 0; i < size; i++) Marshal.WriteByte(buffer, i, 0);
                uint returned;
                if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList, buffer, (uint)size, out returned)) {
                    int error = Marshal.GetLastWin32Error();
                    if (error == ERROR_MORE_DATA) { capacity = checked(capacity * 2); continue; }
                    throw new Win32Exception(error, "could not query exact-session Job Object process list");
                }
                uint assigned = unchecked((uint)Marshal.ReadInt32(buffer, 0));
                uint listed = unchecked((uint)Marshal.ReadInt32(buffer, 4));
                if (listed > assigned || listed > capacity)
                    throw new InvalidDataException("Job Object returned an inconsistent process-list header");
                int[] result = new int[listed];
                for (int i = 0; i < listed; i++) {
                    long raw = IntPtr.Size == 8
                        ? Marshal.ReadInt64(buffer, 8 + i * IntPtr.Size)
                        : Marshal.ReadInt32(buffer, 8 + i * IntPtr.Size);
                    if (raw <= 0 || raw > Int32.MaxValue)
                        throw new InvalidDataException("Job Object returned an invalid process id: " + raw);
                    result[i] = (int)raw;
                }
                Array.Sort(result);
                return result;
            } finally {
                Marshal.FreeHGlobal(buffer);
            }
        }
        throw new InvalidDataException("Job Object process membership exceeds the fail-closed cap of " + MAX_JOB_PROCESS_IDS);
    }

    // #625: there is deliberately no in-process Job-handle close operation.
    // KILL_ON_JOB_CLOSE includes the dedicated launcher itself, so closing the last
    // handle here would terminate the cleanup authority. The raw Job and completion-
    // port handles remain owned by the dedicated native PowerShell process until its
    // process-object teardown, after all protocol cleanup and exit-code publication.
}
'@

function Start-AstroTreeAttribution {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][int]$LauncherPid,
        [Parameter(Mandatory)][long]$LauncherProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$LauncherLockSha256,
        [Parameter(Mandatory)][long]$LauncherLeaseStartUtcTicks,
        [Parameter(Mandatory)][string]$JobObjectName
    )
    if (-not ([System.Management.Automation.PSTypeName]'AstroTreeRecorder').Type) {
        Add-Type -TypeDefinition $AstroTreeRecorderSource -Language CSharp -ErrorAction Stop
    }
    $recorder = [AstroTreeRecorder]::Start(
        $ManifestPath,
        $LauncherPid,
        $LauncherProcessStartUtcTicks,
        $LauncherLockSha256,
        $LauncherLeaseStartUtcTicks,
        $JobObjectName
    )
    try {
        $intended = $recorder.GetLastManifestBytes()
        $snapshot = Get-AstroFileSnapshot `
            -LiteralPath $ManifestPath `
            -Share ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        if ($snapshot.Length -ne $intended.Length -or
            [Convert]::ToBase64String($snapshot.Bytes) -cne
                [Convert]::ToBase64String($intended)) {
            throw "initial attribution manifest independent readback differs from the recorder's durable bytes: $ManifestPath"
        }
        return $recorder
    }
    catch {
        try { $recorder.Stop() }
        catch {
            throw "initial attribution readback failed and recorder stop also failed: $($_.Exception.Message)"
        }
        throw
    }
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
    $probeNonce = [Guid]::NewGuid().ToString('N')
    $trivialC = Join-Path $ScratchDir "astro-lld-probe.pid-$PID.nonce-$probeNonce.c"
    $trivialExe = Join-Path $ScratchDir "astro-lld-probe.pid-$PID.nonce-$probeNonce.exe"
    Write-NewDurableUtf8File `
        -LiteralPath $trivialC `
        -Text 'int main(void){return 0;}'
    try {
        $probe = Invoke-NativeCapture -Exe $GccExe -Arguments @("-B$lldPrefix", "-fuse-ld=lld", $trivialC, "-o", $trivialExe, "-Wl,--version")
        $versionText = ($probe.Output -join "`n").Trim()
        if ($versionText -notmatch [regex]::Escape("LLD $ExpectedLldVersion")) {
            throw "LAUNCHER_BOUNDARY[ASTRO_LLD_RESOLUTION_POISONED]: {code=ASTRO_LLD_RESOLUTION_POISONED; message=`"gcc -fuse-ld=lld resolved a linker other than the pinned LLD $ExpectedLldVersion (pinned=$pinnedLld); linker reported: $versionText`"; remediation=`"an unpinned ld.lld (e.g. this host's MSVS BuildTools LLD 12.0.0) is shadowing the pinned bundle; the launcher prepends $LlvmBin to PATH and pins collect2 to it via -B$lldPrefix -- if this still fires the pinned bundle is broken, so rerun 'scripts\windows-gnu-toolchain.ps1 -Issue <driving-issue> -Bootstrap' from $ExpectedWorkspace`"}"
        }
    }
    finally {
        foreach ($probeArtifact in @($trivialC, $trivialExe)) {
            if (Test-Path -LiteralPath $probeArtifact) {
                Remove-Item `
                    -LiteralPath $probeArtifact `
                    -Force `
                    -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $probeArtifact) {
                throw "pinned-LLD probe artifact remains after explicit cleanup: $probeArtifact"
            }
        }
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
if ($RecoverPreservedTarget) {
    $expectedRecoveryEntryCount = 0
    if (-not $isCanonicalRoot -or $Bootstrap -or
        -not [string]::IsNullOrWhiteSpace($Command) -or
        $CommandArgsJson -cne '[]' -or
        $ExpectedTargetInventorySha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not [int]::TryParse(
            $ExpectedTargetEntryCount,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$expectedRecoveryEntryCount
        ) -or $expectedRecoveryEntryCount -le 0 -or
        $PriorRecoveryTransactionId -cnotmatch '^[0-9a-f]{32}$' -or
        $TrackerCommentUrl -cnotmatch "^https://github\.com/ChrisRoyse/Astrolabe/issues/$drivingIssue#issuecomment-[1-9][0-9]*$") {
        throw "TARGET_RECOVERY[ASTRO_PRESERVED_TARGET_ARGUMENT_INVALID]: {code=ASTRO_PRESERVED_TARGET_ARGUMENT_INVALID; message=`"preserved-target recovery requires the canonical root, no child command/bootstrap, exact lowercase inventory/transaction hashes, a positive entry count, and a tracker URL for the driving issue`"; remediation=`"post the exact inventory evidence on the driving issue and pass only the documented recovery parameters`"}"
    }
}
elseif (-not [string]::IsNullOrEmpty($TrackerCommentUrl) -or
    -not [string]::IsNullOrEmpty($ExpectedTargetInventorySha256) -or
    -not [string]::IsNullOrEmpty($ExpectedTargetEntryCount) -or
    -not [string]::IsNullOrEmpty($PriorRecoveryTransactionId)) {
    throw "TARGET_RECOVERY[ASTRO_PRESERVED_TARGET_ARGUMENT_UNBOUND]: recovery-only arguments require -RecoverPreservedTarget"
}

# #625: KILL_ON_JOB_CLOSE is authoritative only if its last handle follows a real
# process-lifetime boundary. The Job contains its owner, so a caller process that will
# continue after this script returns must never be that owner, and the owner must never
# explicitly close the Job while cleanup is still running. Every public mutating
# invocation therefore re-execs this script in one dedicated native PowerShell process.
# The private mode binds the child to its exact live parent generation and a one-use
# token inherited through that child's environment; fabricated/direct private-mode
# invocation fails before .tmp, target, toolchain, or lock state is touched.
$dedicatedEnvironmentNames = @(
    'ASTRO_LAUNCHER_WRAPPER_TOKEN',
    'ASTRO_LAUNCHER_WRAPPER_PID',
    'ASTRO_LAUNCHER_WRAPPER_TICKS'
)
if ([string]::IsNullOrEmpty($InternalDedicatedToken)) {
    $wrapperProcess = [Diagnostics.Process]::GetCurrentProcess()
    $wrapperTicks = $wrapperProcess.StartTime.ToUniversalTime().Ticks
    $wrapperToken = [Guid]::NewGuid().ToString('N')
    $encodeArgument = {
        param([AllowNull()][string]$Value)
        return [Convert]::ToBase64String(
            [Text.Encoding]::UTF8.GetBytes([string]$Value)
        )
    }
    $scriptPathBase64 = & $encodeArgument $PSCommandPath
    $commandBase64 = & $encodeArgument $Command
    $commandArgsBase64 = & $encodeArgument $CommandArgsJson
    $issueBase64 = & $encodeArgument $Issue
    $trackerCommentUrlBase64 = & $encodeArgument $TrackerCommentUrl
    $expectedTargetInventoryBase64 = & $encodeArgument $ExpectedTargetInventorySha256
    $expectedTargetEntryCountBase64 = & $encodeArgument $ExpectedTargetEntryCount
    $priorRecoveryTransactionBase64 = & $encodeArgument $PriorRecoveryTransactionId
    $tokenBase64 = & $encodeArgument $wrapperToken
    $bootstrapLiteral = if ($Bootstrap) { '$true' } else { '$false' }
    $recoverPreservedTargetLiteral = if ($RecoverPreservedTarget) { '$true' } else { '$false' }
    $dedicatedCommand = @"
`$decode = {
    param([string]`$Value)
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(`$Value))
}
`$dedicatedScript = & `$decode '$scriptPathBase64'
`$dedicatedParameters = @{
    Bootstrap = $bootstrapLiteral
    Command = & `$decode '$commandBase64'
    CommandArgsJson = & `$decode '$commandArgsBase64'
    Issue = & `$decode '$issueBase64'
    RecoverPreservedTarget = $recoverPreservedTargetLiteral
    TrackerCommentUrl = & `$decode '$trackerCommentUrlBase64'
    ExpectedTargetInventorySha256 = & `$decode '$expectedTargetInventoryBase64'
    ExpectedTargetEntryCount = & `$decode '$expectedTargetEntryCountBase64'
    PriorRecoveryTransactionId = & `$decode '$priorRecoveryTransactionBase64'
    InternalDedicatedToken = & `$decode '$tokenBase64'
}
& `$dedicatedScript @dedicatedParameters
`$dedicatedExit = if (`$null -eq `$LASTEXITCODE) { 0 } else { [int]`$LASTEXITCODE }
exit `$dedicatedExit
"@
    $encodedDedicatedCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($dedicatedCommand)
    )
    $hostExecutable = $wrapperProcess.MainModule.FileName
    if ([string]::IsNullOrWhiteSpace($hostExecutable) -or
        -not (Test-Path -LiteralPath $hostExecutable -PathType Leaf)) {
        throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_DEDICATED_HOST_UNEVALUABLE]: {code=ASTRO_LAUNCHER_DEDICATED_HOST_UNEVALUABLE; message=`"the current native PowerShell executable path is unavailable: '$hostExecutable'`"; remediation=`"invoke the launcher from a native powershell.exe or pwsh.exe process with an ordinary executable image`"}"
    }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $hostExecutable
    $startInfo.Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encodedDedicatedCommand"
    $startInfo.WorkingDirectory = $root
    $startInfo.UseShellExecute = $false
    $startInfo.EnvironmentVariables['ASTRO_LAUNCHER_WRAPPER_TOKEN'] =
        $wrapperToken
    $startInfo.EnvironmentVariables['ASTRO_LAUNCHER_WRAPPER_PID'] =
        $PID.ToString([Globalization.CultureInfo]::InvariantCulture)
    $startInfo.EnvironmentVariables['ASTRO_LAUNCHER_WRAPPER_TICKS'] =
        $wrapperTicks.ToString([Globalization.CultureInfo]::InvariantCulture)
    $dedicatedProcess = [Diagnostics.Process]::new()
    $dedicatedProcess.StartInfo = $startInfo
    try {
        if (-not $dedicatedProcess.Start()) {
            throw 'native process creation returned false'
        }
        $dedicatedPid = $dedicatedProcess.Id
        $dedicatedTicks =
            $dedicatedProcess.StartTime.ToUniversalTime().Ticks
        Write-Output "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_DEDICATED_STARTED]: pid=$dedicatedPid; owner_process_start_utc_ticks=$dedicatedTicks; wrapper_pid=$PID; wrapper_process_start_utc_ticks=$wrapperTicks"
        $dedicatedProcess.WaitForExit()
        $dedicatedExit = [int]$dedicatedProcess.ExitCode
    }
    catch {
        throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_DEDICATED_START_FAILED]: {code=ASTRO_LAUNCHER_DEDICATED_START_FAILED; message=`"the dedicated native launcher process could not be executed/read back: $($_.Exception.Message)`"; remediation=`"preserve all existing protocol state, repair native PowerShell process creation, and retry the public launcher invocation`"}"
    }
    finally {
        $dedicatedProcess.Dispose()
        $wrapperProcess.Dispose()
    }
    Write-Output "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_DEDICATED_TERMINAL]: pid=$dedicatedPid; owner_process_start_utc_ticks=$dedicatedTicks; process_state=absent; exit_code=$dedicatedExit"
    exit $dedicatedExit
}

if ($InternalDedicatedToken -cnotmatch '^[0-9a-f]{32}$' -or
    $env:ASTRO_LAUNCHER_WRAPPER_TOKEN -cne $InternalDedicatedToken) {
    throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_DEDICATED_HANDSHAKE_INVALID]: {code=ASTRO_LAUNCHER_DEDICATED_HANDSHAKE_INVALID; message=`"the private dedicated-launcher token is absent, malformed, or does not match the inherited child environment`"; remediation=`"invoke the public launcher without InternalDedicatedToken; it creates the exact dedicated process automatically`"}"
}
$wrapperPid = 0
$wrapperStartTicks = 0L
if (-not [int]::TryParse(
        $env:ASTRO_LAUNCHER_WRAPPER_PID,
        [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$wrapperPid
    ) -or $wrapperPid -le 0 -or
    -not [long]::TryParse(
        $env:ASTRO_LAUNCHER_WRAPPER_TICKS,
        [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$wrapperStartTicks
    ) -or $wrapperStartTicks -le 0 -or
    $wrapperStartTicks -gt [DateTime]::MaxValue.Ticks) {
    throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_DEDICATED_PARENT_INVALID]: {code=ASTRO_LAUNCHER_DEDICATED_PARENT_INVALID; message=`"the inherited wrapper process identity is not canonical`"; remediation=`"invoke only the public launcher boundary and investigate altered child environment state`"}"
}
$currentProcessRows = @(
    Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $PID" `
        -ErrorAction Stop
)
$wrapperIdentity = try {
    [Diagnostics.Process]::GetProcessById($wrapperPid)
}
catch {
    $null
}
try {
    if ($currentProcessRows.Count -ne 1 -or
        [int]$currentProcessRows[0].ParentProcessId -ne $wrapperPid -or
        $null -eq $wrapperIdentity -or
        $wrapperIdentity.StartTime.ToUniversalTime().Ticks -ne
            $wrapperStartTicks) {
        throw "parent_pid=$(@($currentProcessRows.ParentProcessId) -join ','); expected_pid=$wrapperPid; expected_ticks=$wrapperStartTicks; observed_ticks=$(if ($null -ne $wrapperIdentity) { $wrapperIdentity.StartTime.ToUniversalTime().Ticks } else { '<absent>' })"
    }
}
catch {
    throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_DEDICATED_PARENT_MISMATCH]: {code=ASTRO_LAUNCHER_DEDICATED_PARENT_MISMATCH; message=`"the private launcher is not the exact child of its bound live wrapper generation: $($_.Exception.Message)`"; remediation=`"preserve all protocol state and retry through one public launcher invocation`"}"
}
finally {
    if ($null -ne $wrapperIdentity) { $wrapperIdentity.Dispose() }
}
foreach ($environmentName in $dedicatedEnvironmentNames) {
    Remove-Item -Path "Env:$environmentName" -ErrorAction SilentlyContinue
}
Write-Output "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_DEDICATED_VERIFIED]: pid=$PID; wrapper_pid=$wrapperPid; wrapper_process_start_utc_ticks=$wrapperStartTicks; token_consumed=true"

if ($isWorktreeRoot) {
    Write-Output "LAUNCHER_WORKTREE[ASTRO_WORKTREE_ROOT]: root=$root; pinned tools and sccache shared from $ExpectedWorkspace; target/, .tmp/, and session lock stay worktree-local"
}
# #588: toolchain-bundle roots are pure path derivations here (no download, extraction, or
# move). The pinned CUDA runtime provisioning that MUTATES .toolchains, and every pinned-tool
# install, run later -- inside the lock-guarded try/finally below -- so the session lock is
# always HELD before any toolchain mutation and every failure path removes it (#589). The
# earlier design ran provisioning before the claim to avoid a stranded lock; that is now
# guaranteed by the finally instead, without leaving a live install stage unattributed.
$toolsRoot = Join-Path $ExpectedWorkspace ".toolchains"
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
$workspaceTemp = $null
$launcherLock = Join-Path $workspaceTempParent "astrolabe-launcher.lock"
# Initialise every value referenced by the post-claim try/finally before the atomic claim.
# Once the active lock is published, the main protected try begins immediately.
$mingwRoot = Join-Path $toolsRoot $ToolchainDirectoryName
$mingwBin = Join-Path $mingwRoot "bin"
$llvmRoot = Join-Path $toolsRoot $LlvmDirectoryName
$llvmBin = Join-Path $llvmRoot "bin"
$cppcheckRoot = Join-Path $toolsRoot $CppcheckDirectoryName
$ripgrepRoot = Join-Path $toolsRoot $RipgrepDirectoryName
$sccacheRoot = Join-Path $toolsRoot $SccacheDirectoryName
$sccacheExe = Join-Path $sccacheRoot "sccache.exe"
$sccacheDir = Join-Path $ExpectedWorkspace ".sccache"
$gitRoot = $GitInstallRoot
$gitBin = Join-Path $gitRoot "bin"
$gitUsrBin = Join-Path $gitRoot "usr\bin"
$commandExit = $null
$launcherFault = $null
$cleanupErrors = @()
$treeRecorder = $null
$treeRecorderStopped = $false
$launcherTreeJobObjectName = $null
$sccacheOwnedJobMembers = @()
$sccacheDaemonStarted = $false
$attributionManifest = $null
$launcherProtocolDirectoryLease = $null
$workspaceTempLease = $null
$gitMutationFreezeLease = $null
$previousTempEnvironment = @{}
foreach ($name in @("TEMP", "TMP", "TMPDIR", "GIT_CEILING_DIRECTORIES", "ASTRO_NO_ESCAPE_ATTRIBUTION")) {
    $previousTempEnvironment[$name] = Get-Item -Path "Env:$name" -ErrorAction SilentlyContinue
}
# #534/#566: the complete set of Cargo target directories this launcher owns and must clean
# (root target + calyx/target). An authoritative CARGO_TARGET_DIR exported under the lock
# (Set-ToolchainEnvironment) confines every Cargo child to the root target; this list drives
# the preflight reclaim and the finally sweep of any pre-existing nested debris.
$ownedTargetRoots = @(Get-AstroOwnedCargoTargetRoots -Root $root)
# #534/#566: refuse an ambient CARGO_TARGET_DIR/CARGO_BUILD_TARGET_DIR that would steer a
# Cargo child out of the owned root. Checked before the lock claim so a misconfigured
# environment fails fast without lock churn; the authoritative value is exported later,
# under the held lock, by Set-ToolchainEnvironment.
Assert-NoAmbientCargoTargetEscape -OwnedTargetRoot $target
# #197/#611: the session-lock semantics live in one audited, dot-sourceable place that has
# no capability to stop any process. Live, malformed, unevaluable, and stale locks all refuse;
# stale ownership is removed only by the tracker-bound explicit reclaim command. Claim and
# reclaim share one crash-released named mutex so check/create/archive operations cannot race.
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
# #620: recursive TEMP disposition cannot atomically exclude every metadata writer.
# The only production lifecycle is a durable append-only pair archive transaction.
. (Join-Path $PSScriptRoot "launcher-state-archive.ps1")
# #611: `.tmp` is the protocol directory. Creating an absent `.tmp` is the only write before
# the typed claim transition. The exact empty session TEMP is then created and verified while
# that transition is visible; active publication occurs only after the strict manifest/TEMP/
# Job pair is complete. Target/config/toolchain mutation remains active-lock-only.
# Reparse/alias roots are refused consistently across claim and recovery.
Assert-AstroLauncherRootCanonical $root
$workspaceTempParentState = Get-AstroPathEntryState $workspaceTempParent
if ($workspaceTempParentState.State -eq 'absent') {
    [IO.Directory]::CreateDirectory($workspaceTempParent) | Out-Null
}
elseif ($workspaceTempParentState.State -ne 'present' -or
    ($workspaceTempParentState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
    ($workspaceTempParentState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_PROTOCOL_DIRECTORY_INVALID]: .tmp is not an evaluable ordinary directory (state=$($workspaceTempParentState.State), attributes=$($workspaceTempParentState.Attributes), error=$($workspaceTempParentState.Error)): $workspaceTempParent"
}

# Everything below until the atomic move is read-only preparation. The full manifest bytes
# and hash are known before the first claim-transition file is created.
$launcherCommand = ("$Command $CommandArgsJson").Trim()
if ([string]::IsNullOrWhiteSpace($launcherCommand)) {
    $launcherCommand = if ($Bootstrap) {
        "bootstrap"
    }
    elseif ($RecoverPreservedTarget) {
        "recover-preserved-target transaction=$PriorRecoveryTransactionId inventory=$ExpectedTargetInventorySha256 entries=$expectedRecoveryEntryCount"
    }
    else { "environment-probe" }
}
# #424/#519: the launcher lock is also the repository EVIDENCE LEASE. Record the exact
# tree the coming build is attributable to (HEAD + content-level dirty-state fingerprint)
# in the lock manifest itself, so any session can identify the frozen tree and the finally
# block can refuse closure evidence when HEAD/index/tracked bytes changed inside the lease.
$evidenceGitExe = Join-Path (Join-Path $GitInstallRoot "bin") "git.exe"
Require-Path $evidenceGitExe "native Git for Windows git.exe is required"
$repoEvidenceBefore = Get-AstroRepoEvidenceState -GitExe $evidenceGitExe -Root $root
Write-Output "GIT_FREEZE[ASTRO_EVIDENCE_LEASE]: head=$($repoEvidenceBefore.HeadSha) status_sha256=$($repoEvidenceBefore.StatusSha256) diff_sha256=$($repoEvidenceBefore.DiffSha256) recorded in the launcher lock (#424/#519)"
$launcherProcess = Get-Process -Id $PID -ErrorAction Stop
$launcherProcessStartUtcTicks = [long]$launcherProcess.StartTime.ToUniversalTime().Ticks
$launcherProcessStartedUtc = [DateTime]::new(
    $launcherProcessStartUtcTicks,
    [DateTimeKind]::Utc
).ToString('o')
$launcherLeaseStartedUtc = [DateTime]::UtcNow
$launcherLeaseStartUtcTicks = [long]$launcherLeaseStartedUtc.Ticks
$launcherLockJson = [ordered]@{
    schema = 'astrolabe.launcher-lock.v2'
    pid = $PID
    issue = $drivingIssue
    started = $launcherLeaseStartedUtc.ToString('o')
    lease_start_utc_ticks = $launcherLeaseStartUtcTicks
    owner_process_start_utc_ticks = $launcherProcessStartUtcTicks
    owner_process_started_utc = $launcherProcessStartedUtc
    command = $launcherCommand
    head_sha = $repoEvidenceBefore.HeadSha
    status_sha256 = $repoEvidenceBefore.StatusSha256
    diff_sha256 = $repoEvidenceBefore.DiffSha256
} | ConvertTo-Json -Compress
$launcherLockBytes = [Text.UTF8Encoding]::new($false).GetBytes($launcherLockJson)
if ($launcherLockBytes.Length -gt $script:AstroLauncherLockMaxBytes) {
    throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_MANIFEST_TOO_LARGE]: serialized launcher manifest is $($launcherLockBytes.Length) bytes; maximum is $script:AstroLauncherLockMaxBytes bytes. Shorten the child command/argument payload before any protocol file is written."
}
$launcherLockSha256 = Get-AstroByteSha256 $launcherLockBytes
$workspaceTemp = Join-Path $workspaceTempParent (
    "windows-gnu-toolchain-v2.pid-$PID.ticks-$launcherProcessStartUtcTicks.lock-sha256-$launcherLockSha256"
)
$attributionManifest = Join-Path $workspaceTempParent (
    "no-escape-attribution-v3.pid-$PID.ticks-$launcherProcessStartUtcTicks.lock-sha256-$launcherLockSha256.json"
)
$claimNonce = [Guid]::NewGuid().ToString('N')
$launcherLockScratch = Join-Path $workspaceTempParent (
    ".astro-preclaim-scratch.$claimNonce.tmp"
)
$launcherLockClaimLeaf = "astrolabe-launcher.lock.claim.v2.pid-$PID.issue-$drivingIssue.ticks-$launcherProcessStartUtcTicks.sha256-$launcherLockSha256.$claimNonce"
$launcherLockClaim = Join-Path $workspaceTempParent $launcherLockClaimLeaf
$launcherLockLeaseHandle = $null
$launcherPreclaimScratchLease = $null
$claimTransitionPublished = $false
$launcherClaimMutex = Enter-AstroLauncherLockMutex $launcherLock
if (-not $launcherClaimMutex.Acquired) {
    Exit-AstroLauncherLockMutex $launcherClaimMutex
    throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_CLAIM_BUSY]: another process owns the machine-wide launcher-lock protocol mutex ($($launcherClaimMutex.Name)); retry after its bounded transition: $launcherLock"
}
if ($launcherClaimMutex.WasAbandoned) {
    Write-Output "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_MUTEX_ABANDONED]: recovered abandoned Global protocol mutex $($launcherClaimMutex.Name); active and transition bytes will be fully classified before claim"
}
try {
    $launcherProtocolDirectoryLease =
        Open-AstroLauncherPinnedDirectoryLease $workspaceTempParent
    Assert-AstroLauncherLockClaimable -LockPath $launcherLock

    # The unreserved scratch has FILE_FLAG_DELETE_ON_CLOSE from its creation syscall.
    # Therefore a hard death before publication removes it in-kernel. Once its complete
    # durable bytes are independently read back, CreateHardLinkW atomically publishes the
    # typed no-replace claim. A hard death after that syscall leaves the complete claim and
    # removes only the scratch link; there is no incomplete classifier-visible stage.
    $launcherPreclaimScratchLease = New-AstroLauncherPreclaimScratchLease `
        -Path $launcherLockScratch `
        -Bytes $launcherLockBytes `
        -DirectoryLease $launcherProtocolDirectoryLease
    $scratchReadback = Assert-AstroLauncherLockLeaseCurrent `
        $launcherPreclaimScratchLease
    if ($scratchReadback.Length -ne [uint64]$launcherLockBytes.Length -or
        $scratchReadback.Sha256 -cne $launcherLockSha256 -or
        [Convert]::ToBase64String($scratchReadback.Bytes) -cne
            [Convert]::ToBase64String($launcherLockBytes)) {
        throw "durable delete-on-close claim scratch readback differs from intended manifest bytes: $launcherLockScratch"
    }
    [void](Assert-AstroLauncherPinnedDirectoryLease (
            $launcherProtocolDirectoryLease
        ))
    [AstroLauncherTempNative]::CreateExactHardLinkNoReplace(
        $launcherPreclaimScratchLease.SafeFileHandle,
        $launcherLockScratch,
        $launcherLockClaim
    )
    # This assignment is deliberately the first PowerShell operation after the atomic
    # publication syscall. Every subsequent fault preserves the typed claim transition.
    $claimTransitionPublished = $true
    $publishedScratchLinkCount =
        [AstroLauncherTempNative]::GetExactFileLinkCount(
            $launcherPreclaimScratchLease.SafeFileHandle
        )
    if ($publishedScratchLinkCount -ne 2) {
        throw "typed claim publication did not yield exactly scratch+claim links (observed=$publishedScratchLinkCount)"
    }
    $launcherLockLeaseHandle =
        Complete-AstroLauncherPreclaimScratchPublication `
            -ScratchLease $launcherPreclaimScratchLease `
            -ClaimPath $launcherLockClaim `
            -ExpectedBytes $launcherLockBytes
    $scratchTerminal = Get-AstroPathEntryState $launcherLockScratch
    $claimTransitions = Get-AstroLauncherLockTransitions $launcherLock
    $claimSnapshot = Assert-AstroLauncherLockLeaseCurrent $launcherLockLeaseHandle
    if ($claimTransitions.State -cne 'present' -or
        @($claimTransitions.Paths).Count -ne 1 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath(@($claimTransitions.Paths)[0]),
            [IO.Path]::GetFullPath($launcherLockClaim),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            $claimSnapshot.Path,
            [IO.Path]::GetFullPath($launcherLockClaim),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $claimSnapshot.FileId -cne $scratchReadback.FileId -or
        $claimSnapshot.Sha256 -cne $launcherLockSha256 -or
        $scratchTerminal.State -cne 'absent' -or
        (Get-AstroPathEntryState $launcherLock).State -cne 'absent') {
        throw "typed claim transition failed exact sole-transition/FILE_ID/hash/active-absent/scratch-absent readback: $launcherLockClaim"
    }

    $launcherTreeJobObjectName = Get-AstroLauncherTreeJobObjectName `
        -RootIdentity $launcherClaimMutex.RootIdentity `
        -LauncherPid $PID `
        -LauncherProcessStartUtcTicks $launcherProcessStartUtcTicks `
        -LauncherLeaseStartUtcTicks $launcherLeaseStartUtcTicks `
        -LauncherLockSha256 $launcherLockSha256
    $treeRecorder = Start-AstroTreeAttribution `
        -ManifestPath $attributionManifest `
        -LauncherPid $PID `
        -LauncherProcessStartUtcTicks $launcherProcessStartUtcTicks `
        -LauncherLockSha256 $launcherLockSha256 `
        -LauncherLeaseStartUtcTicks $launcherLeaseStartUtcTicks `
        -JobObjectName $launcherTreeJobObjectName

    $workspaceTempState = Get-AstroPathEntryState $workspaceTemp
    if ($workspaceTempState.State -cne 'absent') {
        throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_TEMP_GENERATION_COLLISION]: exact-session TEMP path is not absent while the typed claim is held (state=$($workspaceTempState.State), error=$($workspaceTempState.Error)); preserve the interrupted claim for explicit recovery: $workspaceTemp"
    }
    [IO.Directory]::CreateDirectory($workspaceTemp) | Out-Null
    $workspaceTempLease = Open-AstroLiveLauncherTempLease `
        -Path $workspaceTemp `
        -LauncherPid $PID `
        -LauncherProcessStartUtcTicks $launcherProcessStartUtcTicks `
        -LauncherLockSha256 $launcherLockSha256 `
        -DirectoryLease $launcherProtocolDirectoryLease
    $workspaceTempState = Get-AstroPathEntryState $workspaceTemp
    if ($workspaceTempState.State -cne 'present' -or
        ($workspaceTempState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
        ($workspaceTempState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_TEMP_CREATE_INVALID]: exact-session TEMP path did not become one ordinary non-reparse directory while the typed claim is held (state=$($workspaceTempState.State), attributes=$($workspaceTempState.Attributes), error=$($workspaceTempState.Error)): $workspaceTemp"
    }
    Write-Output "NO_ESCAPE[ASTRO_TEMP_LIVE_LEASE]: path=$workspaceTemp; file_id=$($workspaceTempLease.RootFileId); final_path=$($workspaceTempLease.InitialFinalPath); initial_entries=$($workspaceTempLease.CreationSnapshot.EntryCount); inventory_sha256=$($workspaceTempLease.CreationSnapshot.InventorySha256); share=read-write; delete_share=denied"

    # Re-read every source of truth while the global mutex, exact claim handle, named Job,
    # and pinned protocol directory are all retained. Only a complete exact manifest/TEMP
    # pair and exact Job membership {launcher} can advance claim -> active.
    $claimManifestExpectedBytes = $treeRecorder.GetLastManifestBytes()
    $claimManifestProbe = Get-AstroAttributionManifestProbe `
        -ManifestPath $attributionManifest `
        -RootIdentity $launcherClaimMutex.RootIdentity
    [int[]]$claimJobPids = @()
    if ($claimManifestProbe.Valid -and
        $null -ne $claimManifestProbe.JobObjectProbe) {
        $claimJobPids = [int[]]@(
            $claimManifestProbe.JobObjectProbe.ProcessIds
        )
    }
    $claimOwnerState = if ($null -ne $claimManifestProbe.OwnerProbe) {
        $claimManifestProbe.OwnerProbe.State
    } else { '<absent>' }
    $claimJobState = if ($null -ne $claimManifestProbe.JobObjectProbe) {
        $claimManifestProbe.JobObjectProbe.State
    } else { '<absent>' }
    if (-not $claimManifestProbe.Valid -or
        $claimOwnerState -cne 'exact-live' -or
        $claimJobState -cne 'observed' -or
        $claimJobPids.Count -ne 1 -or
        $claimJobPids[0] -ne $PID -or
        $claimManifestProbe.Parsed.LauncherPid -ne $PID -or
        $claimManifestProbe.Parsed.LauncherProcessStartUtcTicks -ne
            $launcherProcessStartUtcTicks -or
        $claimManifestProbe.Parsed.LauncherLeaseStartUtcTicks -ne
            $launcherLeaseStartUtcTicks -or
        $claimManifestProbe.Parsed.LauncherLockSha256 -cne
            $launcherLockSha256 -or
        $claimManifestProbe.Parsed.JobObjectName -cne
            $launcherTreeJobObjectName -or
        $claimManifestProbe.Parsed.SchemaVersion -ne 3 -or
        -not $claimManifestProbe.Parsed.KillOnJobCloseBound -or
        $claimManifestProbe.Parsed.JobLimitFlags -ne 8192 -or
        -not [string]::Equals(
            $claimManifestProbe.ExpectedTempPath,
            [IO.Path]::GetFullPath($workspaceTemp),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $claimManifestProbe.Snapshot.Length -ne
            [uint64]$claimManifestExpectedBytes.LongLength -or
        [Convert]::ToBase64String($claimManifestProbe.Snapshot.Bytes) -cne
            [Convert]::ToBase64String($claimManifestExpectedBytes)) {
        throw "strict attribution manifest/TEMP/Job binding failed immediately before active publication (valid=$($claimManifestProbe.Valid), error=$($claimManifestProbe.Error), owner=$claimOwnerState, job=$claimJobState, job_pids=$($claimJobPids -join ',')): $attributionManifest"
    }
    $workspaceTempState = Get-AstroPathEntryState $workspaceTemp
    $claimTempLeaseSnapshot = Get-AstroLauncherTempTreeSnapshot `
        $workspaceTempLease
    if ($workspaceTempState.State -cne 'present' -or
        ($workspaceTempState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
        ($workspaceTempState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $claimTempLeaseSnapshot.RootFileId -cne $workspaceTempLease.RootFileId -or
        -not [string]::Equals(
            $claimTempLeaseSnapshot.RootFinalPath,
            [IO.Path]::GetFullPath($workspaceTemp),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "exact-session TEMP changed before active publication (state=$($workspaceTempState.State), attributes=$($workspaceTempState.Attributes), error=$($workspaceTempState.Error)): $workspaceTemp"
    }
    $claimTransitions = Get-AstroLauncherLockTransitions $launcherLock
    $claimSnapshot = Assert-AstroLauncherLockLeaseCurrent $launcherLockLeaseHandle
    if ($claimTransitions.State -cne 'present' -or
        @($claimTransitions.Paths).Count -ne 1 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath(@($claimTransitions.Paths)[0]),
            [IO.Path]::GetFullPath($launcherLockClaim),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            $claimSnapshot.Path,
            [IO.Path]::GetFullPath($launcherLockClaim),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $claimSnapshot.FileId -cne $scratchReadback.FileId -or
        $claimSnapshot.Sha256 -cne $launcherLockSha256 -or
        (Get-AstroPathEntryState $launcherLock).State -cne 'absent') {
        throw "typed claim transition changed during subordinate pair construction: $launcherLockClaim"
    }

    [void](Rename-AstroExactFileHandleNoReplace `
        -Lease $launcherLockLeaseHandle `
        -DestinationDirectoryLease $launcherProtocolDirectoryLease `
        -DestinationLeaf ([IO.Path]::GetFileName($launcherLock)))

    $published = $launcherLockLeaseHandle.State
    if ($launcherLockLeaseHandle.Length -ne $launcherLockBytes.Length -or
        $launcherLockLeaseHandle.Sha256 -cne $launcherLockSha256 -or
        [Convert]::ToBase64String($launcherLockLeaseHandle.Bytes) -cne
            [Convert]::ToBase64String($launcherLockBytes) -or
        $published.State -ne 'held' -or
        $published.OwnerPid -ne $PID -or
        $published.Issue -ne $drivingIssue -or
        $published.OwnerProcessStartUtcTicks -ne
            $launcherProcessStartUtcTicks -or
        $published.HeadSha -cne $repoEvidenceBefore.HeadSha -or
        $published.StatusSha256 -cne $repoEvidenceBefore.StatusSha256 -or
        $published.DiffSha256 -cne $repoEvidenceBefore.DiffSha256) {
        throw "published launcher lock failed exact byte/owner/fingerprint readback: $launcherLock"
    }
    $publishedSnapshot = $launcherLockLeaseHandle.CurrentSnapshot
    if ($publishedSnapshot.Path -cne [IO.Path]::GetFullPath($launcherLock) -or
        $publishedSnapshot.Sha256 -cne $launcherLockSha256 -or
        $publishedSnapshot.FileId -cne $scratchReadback.FileId) {
        throw "published launcher lock did not retain the exact staged FILE_ID/path/hash: $launcherLock"
    }
    $activeTransitions = Get-AstroLauncherLockTransitions $launcherLock
    $activeManifestProbe = Get-AstroAttributionManifestProbe `
        -ManifestPath $attributionManifest `
        -RootIdentity $launcherClaimMutex.RootIdentity
    [int[]]$activeJobPids = @()
    if ($activeManifestProbe.Valid -and
        $null -ne $activeManifestProbe.JobObjectProbe) {
        $activeJobPids = [int[]]@(
            $activeManifestProbe.JobObjectProbe.ProcessIds
        )
    }
    $activeOwnerState = if ($null -ne $activeManifestProbe.OwnerProbe) {
        $activeManifestProbe.OwnerProbe.State
    } else { '<absent>' }
    $activeJobState = if ($null -ne $activeManifestProbe.JobObjectProbe) {
        $activeManifestProbe.JobObjectProbe.State
    } else { '<absent>' }
    $activeTempState = Get-AstroPathEntryState $workspaceTemp
    $activeTempLeaseSnapshot = Get-AstroLauncherTempTreeSnapshot `
        $workspaceTempLease
    if ($activeTransitions.State -cne 'clear' -or
        -not $activeManifestProbe.Valid -or
        $activeOwnerState -cne 'exact-live' -or
        $activeJobState -cne 'observed' -or
        $activeJobPids.Count -ne 1 -or
        $activeJobPids[0] -ne $PID -or
        $activeManifestProbe.Parsed.SchemaVersion -ne 3 -or
        -not $activeManifestProbe.Parsed.KillOnJobCloseBound -or
        $activeManifestProbe.Parsed.JobLimitFlags -ne 8192 -or
        $activeManifestProbe.Snapshot.Length -ne
            [uint64]$claimManifestExpectedBytes.LongLength -or
        [Convert]::ToBase64String($activeManifestProbe.Snapshot.Bytes) -cne
            [Convert]::ToBase64String($claimManifestExpectedBytes) -or
        -not [string]::Equals(
            $activeManifestProbe.ExpectedTempPath,
            [IO.Path]::GetFullPath($workspaceTemp),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $activeTempState.State -cne 'present' -or
        ($activeTempState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
        ($activeTempState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $activeTempLeaseSnapshot.RootFileId -cne $workspaceTempLease.RootFileId -or
        -not [string]::Equals(
            $activeTempLeaseSnapshot.RootFinalPath,
            [IO.Path]::GetFullPath($workspaceTemp),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "active publication did not retain a transition-clear exact manifest/TEMP/Job pair (transition_state=$($activeTransitions.State), manifest_valid=$($activeManifestProbe.Valid), manifest_error=$($activeManifestProbe.Error), owner=$activeOwnerState, job=$activeJobState, job_pids=$($activeJobPids -join ','), temp_state=$($activeTempState.State)): $launcherLock"
    }
    Write-Output "LAUNCHER_LOCK[ASTRO_LAUNCHER_LOCK_PUBLISHED]: path=$launcherLock sha256=$launcherLockSha256 pid=$PID owner_process_start_utc_ticks=$launcherProcessStartUtcTicks issue=#$drivingIssue mutex=$($launcherClaimMutex.Name) job=$launcherTreeJobObjectName attribution=$attributionManifest temp_file_id=$($workspaceTempLease.RootFileId); exact lock, live TEMP, and pinned .tmp handles retained"
}
catch {
    $claimFault = $_
    $claimCleanupErrors = @()
    if ($null -ne $launcherPreclaimScratchLease -and
        $null -ne $launcherPreclaimScratchLease.SafeFileHandle -and
        -not $launcherPreclaimScratchLease.SafeFileHandle.IsClosed) {
        try { Close-AstroLauncherPreclaimScratchLease $launcherPreclaimScratchLease }
        catch {
            $claimCleanupErrors += "delete-on-close scratch handle release failed after claim construction fault: $($_.Exception.Message)"
        }
    }
    $claimScratchTerminal = Get-AstroPathEntryState $launcherLockScratch
    if ($claimScratchTerminal.State -ne 'absent') {
        $claimCleanupErrors += "delete-on-close scratch is not terminally absent after claim construction fault (state=$($claimScratchTerminal.State), error=$($claimScratchTerminal.Error)): $launcherLockScratch"
    }
    $transitions = $null
    try {
        $transitions = Get-AstroLauncherLockTransitions $launcherLock
    }
    catch {
        $claimCleanupErrors += "claim-failure transition inventory could not be read: $($_.Exception.Message)"
    }
    $activeState = Get-AstroPathEntryState $launcherLock
    $claimManifestState = Get-AstroPathEntryState $attributionManifest
    $claimTempState = Get-AstroPathEntryState $workspaceTemp
    $preserveProtocol = $claimTransitionPublished -or
        $null -ne $treeRecorder -or
        $activeState.State -ne 'absent' -or
        $null -eq $transitions -or
        $transitions.State -ne 'clear' -or
        $claimManifestState.State -ne 'absent' -or
        $claimTempState.State -ne 'absent'

    if ($null -ne $treeRecorder) {
        try {
            $treeRecorder.Stop()
            $treeRecorderStopped = $true
            [void]$treeRecorder.GetLastManifestBytes()
        }
        catch {
            $claimCleanupErrors += "tree-attribution recorder stop failed after claim failure: $($_.Exception.Message)"
        }
        # #625: retain the KILL_ON_JOB_CLOSE handle until this dedicated owner
        # process exits. Closing it here would terminate the cleanup authority.
    }

    if ($null -ne $workspaceTempLease -and
        $null -ne $workspaceTempLease.Handle -and
        -not $workspaceTempLease.Handle.IsClosed) {
        try { Close-AstroLauncherTempMutationLease $workspaceTempLease }
        catch {
            $claimCleanupErrors += "claim-failure retained live TEMP handle disposal failed while preserving state: $($_.Exception.Message)"
        }
    }

    if ($null -ne $launcherLockLeaseHandle) {
        if ($preserveProtocol) {
            try { $launcherLockLeaseHandle.SafeFileHandle.Dispose() }
            catch {
                $claimCleanupErrors += "claim-failure retained lock handle disposal failed: $($_.Exception.Message)"
            }
        }
        else {
            try {
                $discard = Invoke-AstroExactFileDispositionDelete $launcherLockLeaseHandle
                if ($discard.State -ne 'absent') {
                    throw "exact staging deletion ended in state '$($discard.State)': $($discard.Error)"
                }
            }
            catch {
                $claimCleanupErrors += "unpublished exact claim-object cleanup failed: $($_.Exception.Message)"
            }
        }
        $launcherLockLeaseHandle = $null
    }
    if ($null -ne $launcherProtocolDirectoryLease) {
        try { $launcherProtocolDirectoryLease.SafeFileHandle.Dispose() }
        catch {
            $claimCleanupErrors += "pinned protocol-directory handle disposal failed after claim failure: $($_.Exception.Message)"
        }
        $launcherProtocolDirectoryLease = $null
    }
    $transitionPaths = if ($null -ne $transitions) {
        @($transitions.Paths) -join '; '
    } else {
        '<unevaluable>'
    }
    $cleanupSuffix = if ($claimCleanupErrors.Count -gt 0) {
        "; claim_failure_cleanup_errors=" + ($claimCleanupErrors -join '; ')
    } else {
        ''
    }
    throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_LOCK_CLAIM_FAILED]: serialized claim construction failed; delete-on-close scratch is absent, and every typed claim/manifest/TEMP/active object was preserved for explicit recovery (active_state=$($activeState.State), transitions=$transitionPaths, manifest_state=$($claimManifestState.State), temp_state=$($claimTempState.State), scratch_state=$($claimScratchTerminal.State)): $($claimFault.Exception.Message)$cleanupSuffix"
}
finally {
    Exit-AstroLauncherLockMutex $launcherClaimMutex
}

# The session lock is now durably published, strictly read back, and physically immutable.
# Every workspace/config/toolchain mutation is inside this try/finally.
$preservedTargetCleanupAuthorized = -not $RecoverPreservedTarget
$preservedTargetRecoveryFinalizationPath = $null
try {
    $env:ASTRO_NO_ESCAPE_ATTRIBUTION = $attributionManifest
    Write-Output "NO_ESCAPE[ASTRO_ATTRIBUTION_RECORDING]: strict v3 kill-on-close process tree -> $attributionManifest; job=$launcherTreeJobObjectName; job_limit_flags=8192"
    Write-Output 'NO_ESCAPE[ASTRO_RETIRED_GATE_STORE_SCAN_ABSENT]: owned_paths is the canonical empty v2 set; no retired gate registry or operator-store Restart Manager scan is part of the production launcher (#621)'
    $gitMutationFreezeLease = New-AstroGitMutationFreezeLease `
        -GitExe $evidenceGitExe `
        -Root $root `
        -Issue $drivingIssue `
        -OwnerProcessStartUtcTicks $launcherProcessStartUtcTicks `
        -LauncherLockPath $launcherLock `
        -LauncherLockSha256 $launcherLockSha256 `
        -EvidenceBefore $repoEvidenceBefore
    $gitFreezeReadback = Assert-AstroGitMutationFreezeLease `
        $gitMutationFreezeLease
    Write-Output "GIT_FREEZE[ASTRO_GIT_MUTATION_FREEZE_HELD]: index_lock=$($gitFreezeReadback.IndexInterlockPath); index_file_id=$($gitFreezeReadback.IndexInterlockFileId); index_sha256=$($gitFreezeReadback.IndexInterlockSha256); source_paths=$($gitFreezeReadback.SourcePathCount); metadata_paths=$($gitFreezeReadback.MetadataPathCount); handles=$($gitFreezeReadback.HandleCount); path_set_sha256=$($gitFreezeReadback.PathSetSha256); ownership=dedicated-process-lifetime-delete-on-close"
    # Active publication already proved the exact TEMP/manifest pair under the claim mutex.
    # Re-read the TEMP here; never create or repair subordinate protocol state after active.
    $workspaceTempState = Get-AstroPathEntryState $workspaceTemp
    $runTempLeaseSnapshot = Get-AstroLauncherTempTreeSnapshot `
        $workspaceTempLease
    if ($workspaceTempState.State -ne 'present' -or
        ($workspaceTempState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
        ($workspaceTempState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $runTempLeaseSnapshot.RootFileId -cne $workspaceTempLease.RootFileId -or
        -not [string]::Equals(
            $runTempLeaseSnapshot.RootFinalPath,
            [IO.Path]::GetFullPath($workspaceTemp),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_ACTIVE_PAIR_INVALID]: active lock does not retain its prepublication ordinary exact-session TEMP (state=$($workspaceTempState.State), attributes=$($workspaceTempState.Attributes), error=$($workspaceTempState.Error)): $workspaceTemp"
    }
    try {
        # The paired TEMP cleaner owns the only legal dead-generation mutation order:
        # exact TEMP first, then its exact manifest/stage evidence. Running the manifest
        # classifier first could erase the sole authority needed to classify that TEMP.
        $tempSweep = Clear-DeadLauncherTempDirs `
            -Directory $workspaceTempParent `
            -SelfPid $PID
        foreach ($decision in @($tempSweep.Decisions)) {
            Write-Output "NO_ESCAPE[ASTRO_TEMP_SWEEP_DECISION]: temp=$($decision.TempPath); manifest=$($decision.ManifestPath); action=$($decision.Action); reason=$($decision.Reason); owner=$($decision.OwnerState); job=$($decision.JobState); job_pids=$(@($decision.JobProcessIds) -join ',')"
        }
        foreach ($stageDecision in @($tempSweep.StageDecisions)) {
            Write-Output "NO_ESCAPE[ASTRO_TEMP_SWEEP_STAGE_DECISION]: $($stageDecision | ConvertTo-Json -Compress -Depth 10)"
        }
        foreach ($transaction in @($tempSweep.Transactions)) {
            Write-Output "NO_ESCAPE[ASTRO_TEMP_SWEEP_TRANSACTION]: $($transaction | ConvertTo-Json -Compress -Depth 10)"
        }
        Write-Output "NO_ESCAPE[ASTRO_TEMP_SWEEP_READBACK]: state=$($tempSweep.State); removed=$(@($tempSweep.Removed) -join ';'); removed_manifests=$(@($tempSweep.RemovedManifests) -join ';'); removed_stages=$(@($tempSweep.RemovedStages) -join ';'); removed_tombstones=$(@($tempSweep.RemovedTombstones) -join ';'); kept=$(@($tempSweep.Kept) -join ';'); skipped=$(@($tempSweep.Skipped) -join ';')"
        if ($tempSweep.State -ceq 'unevaluable' -or
            @($tempSweep.Errors).Count -gt 0) {
            throw "paired launcher TEMP/attribution inventory or cleanup is unevaluable: $(@($tempSweep.Errors) -join '; ')"
        }

        # Classify again after the pair transaction. This pass is read-only and must see
        # no remaining dead generation eligible for cleanup; the exact current owner is
        # retained and reported as skipped.
        $attributionSweep = Clear-DeadAttributionManifests `
            -Directory $workspaceTempParent `
            -SelfPid $PID
        foreach ($decision in @($attributionSweep.Decisions)) {
            Write-Output "NO_ESCAPE[ASTRO_ATTRIBUTION_SWEEP_DECISION]: path=$($decision.Path); kind=$($decision.Kind); eligible=$($decision.Eligible); reason=$($decision.Reason); owner=$($decision.OwnerState); job=$($decision.JobState); job_pids=$(@($decision.JobProcessIds) -join ',')"
        }
        foreach ($refreshDecision in @($attributionSweep.RefreshTransactions)) {
            Write-Output "NO_ESCAPE[ASTRO_ATTRIBUTION_SWEEP_REFRESH]: key=$($refreshDecision.Key); initial=$($refreshDecision.InitialState); action=$($refreshDecision.Action); owner=$($refreshDecision.OwnerState); job=$($refreshDecision.JobState)"
        }
        Write-Output "NO_ESCAPE[ASTRO_ATTRIBUTION_SWEEP_READBACK]: state=$($attributionSweep.State); removed=$(@($attributionSweep.Removed) -join ';'); eligible_pairs=$(@($attributionSweep.EligiblePairs).Count); eligible_stages=$(@($attributionSweep.EligibleStages).Count); refresh_transactions=$(@($attributionSweep.Inventory.RefreshTransactions).Count); kept=$(@($attributionSweep.Kept) -join ';'); skipped=$(@($attributionSweep.Skipped) -join ';')"
        $eligiblePairCount = @($attributionSweep.EligiblePairs).Count
        $eligiblePairsBlockStartup =
            -not $RecoverPreservedTarget -and $eligiblePairCount -gt 0
        if ($RecoverPreservedTarget -and $eligiblePairCount -gt 0) {
            # The explicit pair archiver requires target/ absent, while the target
            # handoff can start only after the dead owner's lock was archived.  A
            # recovery owner therefore observes but never mutates already-proven
            # dead complete pairs, finalizes/deletes only the hash-bound target,
            # and leaves those pairs for the tracker-bound archiver afterward.
            Write-Output "TARGET_RECOVERY[ASTRO_PRESERVED_DEAD_PAIRS_OBSERVED]: eligible_pairs=$eligiblePairCount; pairs=$(@($attributionSweep.EligiblePairs) -join ';'); action=preserve-until-target-absent"
        }
        if ($attributionSweep.State -ceq 'unevaluable' -or
            @($attributionSweep.Errors).Count -gt 0 -or
            @($attributionSweep.EligibleStages).Count -gt 0 -or
            $eligiblePairsBlockStartup) {
            throw "post-pair attribution inventory is not stable/complete (state=$($attributionSweep.State), errors=$(@($attributionSweep.Errors) -join '; '), eligible_stages=$(@($attributionSweep.EligibleStages).Count), eligible_pairs=$(@($attributionSweep.EligiblePairs).Count))"
        }
        Write-Output "NO_ESCAPE[ASTRO_ATTRIBUTION_SWEEP]: exact dead-generation TEMP pairs=$(@($tempSweep.Removed).Count), manifests=$(@($tempSweep.RemovedManifests).Count), stages=$(@($tempSweep.RemovedStages).Count), tombstones=$(@($tempSweep.RemovedTombstones).Count); current exact generation preserved"
    }
    catch {
        # A dead, complete pair is intentionally tracker-archived rather than swept.
        # Its presence is a run-precondition failure, not evidence that this exact
        # launcher's Job membership or cleanup authority is unsafe.  Keeping it out
        # of cleanupErrors lets the already-published exact owner remove target/ and
        # archive its own state in finally; otherwise target presence and pair
        # archival form an unrecoverable cycle (#620).
        throw
    }
    # #651: a stale-owner reclaim may correctly archive the only prior lease while
    # preserving target/. A fresh ordinary launcher cannot infer ownership from those
    # bytes. This explicit mode binds the exact tree to a pre-existing tracker comment,
    # publishes durable authorization under the new exact live lease, deletes only an
    # unchanged handle-bound inventory, and reads back terminal absence + completion.
    if ($RecoverPreservedTarget) {
        $targetState = Get-AstroPathEntryState $target
        if ($targetState.State -cne 'present' -or
            ($targetState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
            ($targetState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "TARGET_RECOVERY[ASTRO_PRESERVED_TARGET_STATE_INVALID]: expected one ordinary preserved target directory (state=$($targetState.State), attributes=$($targetState.Attributes), error=$($targetState.Error)): $target"
        }

        $commentIdText = $TrackerCommentUrl.Substring($TrackerCommentUrl.LastIndexOf('-') + 1)
        $commentId = 0L
        if (-not [long]::TryParse(
                $commentIdText,
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$commentId
            ) -or $commentId -le 0) {
            throw "TARGET_RECOVERY[ASTRO_PRESERVED_TARGET_TRACKER_INVALID]: tracker comment id is not a positive integer: $TrackerCommentUrl"
        }
        $markerJson = [ordered]@{
            schema = 'astrolabe.preserved-target-recovery.request.v1'
            issue = $drivingIssue
            path = [IO.Path]::GetFullPath($target)
            inventory_sha256 = $ExpectedTargetInventorySha256
            entry_count = $expectedRecoveryEntryCount
            prior_recovery_transaction_id = $PriorRecoveryTransactionId
        } | ConvertTo-Json -Compress
        $expectedMarker = "ASTROLABE_TARGET_RECOVERY $markerJson"
        $ghCommand = Get-Command gh.exe -ErrorAction Stop

        $readTrackerComment = {
            $capture = Invoke-NativeCapture `
                -Exe $ghCommand.Source `
                -Arguments @('api', "repos/ChrisRoyse/Astrolabe/issues/comments/$commentId")
            if ($capture.ExitCode -ne 0) {
                throw "gh api failed while reading tracker comment (exit=$($capture.ExitCode)): $(@($capture.Output) -join ' ')"
            }
            $comment = (@($capture.Output) -join "`n") | ConvertFrom-Json -ErrorAction Stop
            if ([long]$comment.id -ne $commentId -or
                [string]$comment.html_url -cne $TrackerCommentUrl) {
                throw 'tracker API response does not bind the requested comment id/URL'
            }
            $matchingLines = @(
                ([string]$comment.body -split "`r?`n") |
                    Where-Object { $_ -ceq $expectedMarker }
            )
            if ($matchingLines.Count -ne 1) {
                throw 'tracker comment does not contain exactly one canonical preserved-target request marker'
            }
            $bodyBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes([string]$comment.body)
            $bodySha = [Security.Cryptography.SHA256]::Create()
            try {
                $bodyHash = ([BitConverter]::ToString($bodySha.ComputeHash($bodyBytes)) -replace '-', '').ToLowerInvariant()
            }
            finally { $bodySha.Dispose() }
            return [pscustomobject]@{
                Id = [long]$comment.id
                Url = [string]$comment.html_url
                UpdatedAt = [string]$comment.updated_at
                BodySha256 = $bodyHash
            }
        }

        $targetHandle = $null
        try {
            $portableBefore = Get-AstroPreservedTargetInventory -LiteralPath $target
            if ($portableBefore.InventorySha256 -cne $ExpectedTargetInventorySha256 -or
                $portableBefore.EntryCount -ne $expectedRecoveryEntryCount) {
                throw "preserved target portable inventory does not match tracker authority (expected=$ExpectedTargetInventorySha256/$expectedRecoveryEntryCount, observed=$($portableBefore.InventorySha256)/$($portableBefore.EntryCount))"
            }
            $trackerFirst = & $readTrackerComment
            $portableSecond = Get-AstroPreservedTargetInventory -LiteralPath $target
            if ($portableSecond.InventorySha256 -cne $portableBefore.InventorySha256 -or
                $portableSecond.EntryCount -ne $portableBefore.EntryCount) {
                throw 'preserved target changed between the first tracker-bound portable inventory reads'
            }

            $recoveryDirectory = Join-Path $workspaceTempParent 'preserved-target-recovery'
            if (-not (Test-Path -LiteralPath $recoveryDirectory)) {
                [IO.Directory]::CreateDirectory($recoveryDirectory) | Out-Null
            }
            $recoveryDirectoryState = Get-AstroPathEntryState $recoveryDirectory
            if ($recoveryDirectoryState.State -cne 'present' -or
                ($recoveryDirectoryState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
                ($recoveryDirectoryState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "preserved-target recovery record directory is not an ordinary directory: $recoveryDirectory"
            }
            $recoveryTransactionId = [Guid]::NewGuid().ToString('N')
            $authorizationPath = Join-Path $recoveryDirectory "$recoveryTransactionId.authorization.json"
            $finalizationPath = Join-Path $recoveryDirectory "$recoveryTransactionId.finalization.json"
            $completionPath = Join-Path $recoveryDirectory "$recoveryTransactionId.completion.json"
            $authorization = [ordered]@{
                schema = 'astrolabe.preserved-target-recovery.authorization.v1'
                phase = 'tracker-and-portable-inventory-authorized'
                transaction_id = $recoveryTransactionId
                recorded_at_utc = [DateTime]::UtcNow.ToString('o')
                prior_recovery_transaction_id = $PriorRecoveryTransactionId
                tracker = [ordered]@{
                    url = $trackerFirst.Url
                    comment_id = $trackerFirst.Id
                    updated_at = $trackerFirst.UpdatedAt
                    body_sha256 = $trackerFirst.BodySha256
                    marker = $expectedMarker
                }
                owner = [ordered]@{
                    pid = $PID
                    owner_process_start_utc_ticks = $launcherProcessStartUtcTicks
                    issue = $drivingIssue
                    launcher_lock_sha256 = $launcherLockSha256
                    head_sha = $repoEvidenceBefore.HeadSha
                    status_sha256 = $repoEvidenceBefore.StatusSha256
                    diff_sha256 = $repoEvidenceBefore.DiffSha256
                }
                target = [ordered]@{
                    path = $portableBefore.Path
                    portable_inventory_sha256 = $portableBefore.InventorySha256
                    entry_count = $portableBefore.EntryCount
                }
            }
            $authorizationText = $authorization | ConvertTo-Json -Compress -Depth 8
            Write-NewDurableUtf8File -LiteralPath $authorizationPath -Text $authorizationText
            $authorizationReadback = [IO.File]::ReadAllText(
                $authorizationPath,
                [Text.UTF8Encoding]::new($false, $true)
            )
            if ($authorizationReadback -cne $authorizationText) {
                throw 'durable preserved-target authorization readback differs from written bytes'
            }
            $authorizationHash = (Get-Sha256Hex -LiteralPath $authorizationPath).Hash.ToLowerInvariant()

            $targetHandle = [AstroLauncherTempNative]::OpenExactLiveDirectoryLease(
                [IO.Path]::GetFullPath($target)
            )
            $targetLease = [pscustomobject]@{
                Path = [IO.Path]::GetFullPath($target)
                Handle = $targetHandle
            }
            $exactBefore = Get-AstroLauncherTempTreeSnapshot $targetLease
            $exactSecond = Get-AstroLauncherTempTreeSnapshot $targetLease
            Assert-AstroLauncherTempSnapshotsEqual $exactBefore $exactSecond
            if (-not [string]::Equals(
                    $exactBefore.RootFinalPath,
                    [IO.Path]::GetFullPath($target),
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw "exact preserved-target handle resolved outside the canonical target: $($exactBefore.RootFinalPath)"
            }
            $trackerSecond = & $readTrackerComment
            if ($trackerSecond.UpdatedAt -cne $trackerFirst.UpdatedAt -or
                $trackerSecond.BodySha256 -cne $trackerFirst.BodySha256) {
                throw 'tracker comment changed after preserved-target authorization publication'
            }

            $finalization = [ordered]@{
                schema = 'astrolabe.preserved-target-recovery.finalization.v1'
                phase = 'exact-inventory-finalized-before-delete'
                transaction_id = $recoveryTransactionId
                recorded_at_utc = [DateTime]::UtcNow.ToString('o')
                authorization = [ordered]@{
                    path = $authorizationPath
                    sha256 = $authorizationHash
                }
                tracker = [ordered]@{
                    url = $trackerSecond.Url
                    comment_id = $trackerSecond.Id
                    updated_at = $trackerSecond.UpdatedAt
                    body_sha256 = $trackerSecond.BodySha256
                }
                owner = [ordered]@{
                    pid = $PID
                    owner_process_start_utc_ticks = $launcherProcessStartUtcTicks
                    launcher_lock_sha256 = $launcherLockSha256
                }
                target = [ordered]@{
                    path = $portableBefore.Path
                    root_file_id = $exactBefore.RootFileId
                    exact_inventory_sha256 = $exactBefore.InventorySha256
                    portable_inventory_sha256 = $portableBefore.InventorySha256
                    entry_count = $portableBefore.EntryCount
                }
            }
            $finalizationText = $finalization | ConvertTo-Json -Compress -Depth 8
            Write-NewDurableUtf8File -LiteralPath $finalizationPath -Text $finalizationText
            $finalizationReadback = [IO.File]::ReadAllText(
                $finalizationPath,
                [Text.UTF8Encoding]::new($false, $true)
            )
            if ($finalizationReadback -cne $finalizationText) {
                throw 'durable preserved-target finalization readback differs from written bytes'
            }
            $finalizationHash = (Get-Sha256Hex -LiteralPath $finalizationPath).Hash.ToLowerInvariant()
            $preservedTargetRecoveryFinalizationPath = $finalizationPath
            $preservedTargetCleanupAuthorized = $true

            [AstroLauncherTempNative]::DeleteExactTreeContents(
                $targetHandle,
                [string[]]$exactBefore.Entries
            )
            $emptyTarget = Get-AstroLauncherTempTreeSnapshot $targetLease
            if ($emptyTarget.RootFileId -cne $exactBefore.RootFileId -or
                $emptyTarget.EntryCount -ne 0) {
                throw 'preserved target root changed identity or remained nonempty after exact content deletion'
            }
            [AstroLauncherTempNative]::MarkExactDirectoryDeletePending(
                $targetHandle,
                $emptyTarget.RootState
            )
            $targetHandle.Dispose()
            $targetHandle = $null
            $targetTerminal = Get-AstroPathEntryState $target
            if ($targetTerminal.State -cne 'absent') {
                throw "preserved target is not absent after exact disposition (state=$($targetTerminal.State), error=$($targetTerminal.Error))"
            }

            $completion = [ordered]@{
                schema = 'astrolabe.preserved-target-recovery.completion.v1'
                phase = 'complete-target-absent'
                transaction_id = $recoveryTransactionId
                completed_at_utc = [DateTime]::UtcNow.ToString('o')
                authorization = [ordered]@{
                    path = $authorizationPath
                    sha256 = $authorizationHash
                }
                finalization = [ordered]@{
                    path = $finalizationPath
                    sha256 = $finalizationHash
                }
                target = [ordered]@{
                    path = [IO.Path]::GetFullPath($target)
                    state = $targetTerminal.State
                    prior_root_file_id = $exactBefore.RootFileId
                    prior_exact_inventory_sha256 = $exactBefore.InventorySha256
                    prior_portable_inventory_sha256 = $portableBefore.InventorySha256
                    prior_entry_count = $portableBefore.EntryCount
                    empty_exact_inventory_sha256 = $emptyTarget.InventorySha256
                }
            }
            $completionText = $completion | ConvertTo-Json -Compress -Depth 8
            Write-NewDurableUtf8File -LiteralPath $completionPath -Text $completionText
            $completionReadback = [IO.File]::ReadAllText(
                $completionPath,
                [Text.UTF8Encoding]::new($false, $true)
            )
            if ($completionReadback -cne $completionText -or
                (Get-AstroPathEntryState $target).State -cne 'absent') {
                throw 'preserved-target completion or terminal absence failed independent readback'
            }
            $completionHash = (Get-Sha256Hex -LiteralPath $completionPath).Hash.ToLowerInvariant()
            Write-Output "TARGET_RECOVERY[ASTRO_PRESERVED_TARGET_COMPLETE]: transaction=$recoveryTransactionId; target=$target; entries=$($portableBefore.EntryCount); portable_inventory_sha256=$($portableBefore.InventorySha256); exact_inventory_sha256=$($exactBefore.InventorySha256); authorization=$authorizationPath; authorization_sha256=$authorizationHash; finalization=$finalizationPath; finalization_sha256=$finalizationHash; completion=$completionPath; completion_sha256=$completionHash; terminal=absent"
        }
        finally {
            if ($null -ne $targetHandle) {
                $targetHandle.Dispose()
            }
        }
    }

    # #280: a warm target is permitted only inside an explicitly owned contiguous batch.
    if ((Test-Path -LiteralPath $target) -and
        ($env:ASTROLABE_CONTIGUOUS_BATCH -ne "1")) {
        throw "target must be absent before toolchain work: $target"
    }
    if (($env:ASTROLABE_CONTIGUOUS_BATCH -eq "1") -and
        (Test-Path -LiteralPath $target)) {
        Write-Output "TARGET[ASTRO_BATCH_WARM]: ASTROLABE_CONTIGUOUS_BATCH=1 -> reusing warm target/ from this session's batch"
    }
    # Nested target reclamation is now owner-attributed: the complete immutable lease exists
    # before a single directory is removed.
    if ($env:ASTROLABE_CONTIGUOUS_BATCH -ne "1") {
        $rootTargetFull = [IO.Path]::GetFullPath($target)
        foreach ($ownedTarget in $ownedTargetRoots) {
            if ([string]::Equals(
                    $ownedTarget,
                    $rootTargetFull,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                continue
            }
            if (Test-Path -LiteralPath $ownedTarget) {
                Remove-TreeResilient -Path $ownedTarget
                if (Test-Path -LiteralPath $ownedTarget) {
                    throw "nested Cargo target could not be reclaimed under the published lease: $ownedTarget"
                }
                Write-Output "TARGET[ASTRO_NESTED_TARGET_RECLAIMED]: reclaimed nested Cargo target under exact launcher ownership: $ownedTarget"
            }
        }
    }

    # Preserved manifests/TEMP roots from prior generations are tracker-bound recovery
    # state. This launcher never reaps them automatically on a numeric-PID inference.

    if ($isCanonicalRoot) {
        # core.hooksPath is shared repo config. It may be written only while the canonical
        # exact lease is already published and immutable.
        $hooksProbe = Invoke-NativeCapture `
            -Exe $evidenceGitExe `
            -Arguments @("-C", $root, "config", "core.hooksPath")
        $hooksCurrent = (@($hooksProbe.Output) -join "`n").Trim()
        if ($hooksProbe.ExitCode -eq 0 -and
            -not [string]::IsNullOrWhiteSpace($hooksCurrent) -and
            $hooksCurrent -ne "scripts/githooks") {
            throw "GIT_FREEZE[ASTRO_GIT_FREEZE_HOOKS_CONFLICT]: {code=ASTRO_GIT_FREEZE_HOOKS_CONFLICT; message=`"core.hooksPath is already set to '$hooksCurrent'; expected scripts/githooks`"; remediation=`"reconcile the existing hook path, then rerun`"}"
        }
        if ($hooksCurrent -ne "scripts/githooks") {
            $hooksSet = Invoke-NativeCapture `
                -Exe $evidenceGitExe `
                -Arguments @("-C", $root, "config", "core.hooksPath", "scripts/githooks")
            if ($hooksSet.ExitCode -ne 0) {
                throw "GIT_FREEZE[ASTRO_GIT_FREEZE_HOOKS_UNINSTALLED]: {code=ASTRO_GIT_FREEZE_HOOKS_UNINSTALLED; message=`"could not install hooks (git exit=$($hooksSet.ExitCode): $(@($hooksSet.Output) -join ' | '))`"; remediation=`"repair repository config write access, then rerun`"}"
            }
            Write-Output "GIT_FREEZE[ASTRO_GIT_FREEZE_HOOKS]: installed core.hooksPath=scripts/githooks under the exact launcher lease"
        }
    }

    # #588: CUDA-runtime provisioning MUTATES the pinned toolchains (it downloads/extracts into
    # .toolchains/.installing-ort-cuda13-* before publishing the immutable content-addressed
    # root), so it runs here, under the held lock -- not before the claim as it once did. A
    # download or attestation fault is a launcher fault caught below; the finally then removes
    # this run's lock, so a concurrent session never mistakes a live install stage for
    # abandoned debris (the #197 lock-discipline breach #588 fixes).
    $cuda13RuntimeProvisioner = Join-Path $ExpectedWorkspace "scripts\windows-cuda13-runtime.ps1"
    $cuda13RuntimeLock = Join-Path $ExpectedWorkspace "scripts\toolchains\ort-cuda13.3-windows-x86_64.lock.json"
    $cuda13RuntimeRoot = Resolve-PinnedCuda13Runtime -Provisioner $cuda13RuntimeProvisioner -LockManifest $cuda13RuntimeLock -WorkspaceRoot $ExpectedWorkspace -ToolchainsRoot $toolsRoot
    $env:CALYX_CUDA13_RUNTIME_ROOT = $cuda13RuntimeRoot
    Write-Output "CUDA13_RUNTIME[ASTRO_CUDA13_RUNTIME_ROOT]: attested pinned runtime root exported via CALYX_CUDA13_RUNTIME_ROOT=$cuda13RuntimeRoot (PATH unchanged)"

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
    Set-ToolchainEnvironment -MingwBin $mingwBin -LlvmBin $llvmBin -CppcheckRoot $cppcheckRoot -RipgrepRoot $ripgrepRoot -GitBin $gitBin -GitUsrBin $gitUsrBin -SccacheExe $sccacheExe -SccacheDir $sccacheDir -SccacheServerPort $sccacheServerPort -CargoTargetRoot $target
    # #534/#566: announce the authoritative, owned Cargo target root BEFORE any child runs, and
    # list every target directory the finally will verify absent on exit.
    Write-Output "TARGET[ASTRO_CARGO_TARGET_ROOT]: CARGO_TARGET_DIR=$target (authoritative; nested manifests confined; owned roots: $(($ownedTargetRoots | Sort-Object) -join '; '))"
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
        $pinnedLld = Assert-GccResolvesPinnedLld -GccExe $env:CC -LlvmBin $llvmBin -ScratchDir $workspaceTemp
        $lldPrefix = ($llvmBin.TrimEnd('\', '/')) + '\'
        $lldPinArg = "-Clink-arg=-B$lldPrefix"
        if ($env:RUSTFLAGS -notmatch [regex]::Escape($lldPinArg)) {
            $env:RUSTFLAGS = "$lldPinArg $($env:RUSTFLAGS)"
        }
        Write-Output "LLD[ASTRO_PINNED_LLD]: lld-enabled build detected in RUSTFLAGS; verified gcc resolves $pinnedLld (LLD $ExpectedLldVersion); pinned collect2 ld.lld search via -B$lldPrefix ahead of PATH"
    }

    if ([string]::IsNullOrWhiteSpace($Command)) {
        # Environment-probe mode: the toolchain env is set up and reported ready, no child runs.
        # The finally still removes the lock and the (unused) per-run TEMP; $sccacheDaemonStarted
        # stays false, so no sccache daemon is touched.
        Write-Output 'Ready. Example: .\scripts\windows-gnu-toolchain.ps1 -Issue <driving-issue> -Command cargo -CommandArgsJson ''["test","-p","cbm-sys","--lib"]'''
        $commandExit = 0
    }
    else {
        # Windows PowerShell 5.1's ConvertFrom-Json emits a JSON array as ONE object instead of
        # enumerating it, so `@(ConvertFrom-Json '["a","b"]')` yields an array-of-one-array there
        # while PowerShell 7 unrolls it into two strings. Under 5.1 -- the host CLAUDE.md documents
        # for `powershell -ExecutionPolicy Bypass -File scripts\windows-gnu-toolchain.ps1` -- that
        # made every multi-argument invocation (including CLAUDE.md's own
        # '["test","-p","cbm-sys","--lib"]' example) fail the string check below. Normalise both
        # hosts to a flat argument list before validating. #589: this parse runs under the held
        # lock's finally, so a malformed CommandArgsJson exits nonzero AND removes the lock/TEMP.
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
        # #534/#566: a child --target-dir outranks the launcher's authoritative CARGO_TARGET_DIR,
        # so it is refused (never overridden) before the child runs, under the lock's finally.
        Assert-NoCargoTargetDirOverride -CommandArgs $commandArgs
    Set-WorkspaceTempEnvironment -WorkspaceTemp $workspaceTemp
    Set-CudaMsvcRuntimeLinkEnvironment -LlvmBin $llvmBin -WorkspaceTemp $workspaceTemp
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
    # #588/#589: from here on this run manages the sccache daemon on this root's port, so the
    # finally must attempt to stop it even if the start/zero-stats handshake below faults. An
    # environment-probe (empty $Command) never reaches this branch, so its finally skips sccache.
    $sccacheDaemonStarted = $true
    $sccachePreStop = Invoke-NativeCapture -Exe $sccacheExe -Arguments @("--stop-server")
    if ($sccachePreStop.ExitCode -eq 0) {
        Write-Output "SCCACHE[ASTRO_CACHE_SERVER_REPLACED]: stopped a pre-existing sccache daemon on 127.0.0.1:$sccacheServerPort before starting this session's daemon"
    }
    $sccacheJobPidsBeforeStart = @($treeRecorder.GetActiveProcessIds())
    if (-not ($sccacheJobPidsBeforeStart -contains $PID)) {
        throw "LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_JOB_SELF_MISSING]: exact-session Job Object did not contain launcher PID $PID immediately before sccache startup"
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
    $sccacheJobPidsAfterStart = @($treeRecorder.GetActiveProcessIds())
    $newSccacheJobPids = @(
        $sccacheJobPidsAfterStart |
            Where-Object {
                $_ -ne $PID -and
                $sccacheJobPidsBeforeStart -notcontains $_
            } |
            Sort-Object -Unique
    )
    if ($newSccacheJobPids.Count -eq 0) {
        throw "LAUNCHER_BOUNDARY[ASTRO_SCCACHE_JOB_ATTRIBUTION_MISSING]: sccache answered on the exact root port, but no causally new process remained in Job Object $launcherTreeJobObjectName"
    }
    $pinnedSccachePath = [IO.Path]::GetFullPath($sccacheExe)
    $pinnedConhostPath = [IO.Path]::GetFullPath((Join-Path `
        ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) `
        'conhost.exe'
    ))
    $causalMembers = [Collections.Generic.List[object]]::new()
    foreach ($sccachePid in $newSccacheJobPids) {
        $identity = Get-AstroProcessIdentityProbe $sccachePid
        if ($identity.State -ne 'observed') {
            throw "LAUNCHER_BOUNDARY[ASTRO_SCCACHE_JOB_IDENTITY_UNEVALUABLE]: Job Object member PID $sccachePid could not be bound to an exact process generation (state=$($identity.State), error=$($identity.Error))"
        }
        $processRows = @(
            Get-CimInstance `
                -ClassName Win32_Process `
                -Filter "ProcessId = $sccachePid" `
                -ErrorAction Stop
        )
        if ($processRows.Count -ne 1 -or
            [string]::IsNullOrWhiteSpace(
                [string]$processRows[0].ExecutablePath
            )) {
            throw "LAUNCHER_BOUNDARY[ASTRO_SCCACHE_JOB_IDENTITY_UNEVALUABLE]: Job Object member PID $sccachePid did not yield exactly one process row with an executable path"
        }
        $imagePath = [IO.Path]::GetFullPath(
            [string]$processRows[0].ExecutablePath
        )
        $role = if ([string]::Equals(
                $imagePath,
                $pinnedSccachePath,
                [StringComparison]::OrdinalIgnoreCase
            )) { 'server' } elseif ([string]::Equals(
                $imagePath,
                $pinnedConhostPath,
                [StringComparison]::OrdinalIgnoreCase
            )) { 'console-host' } else { 'unexpected' }
        if ($role -ceq 'unexpected') {
            throw "LAUNCHER_BOUNDARY[ASTRO_SCCACHE_JOB_IDENTITY_MISMATCH]: causally new Job Object PID $sccachePid is neither the pinned sccache executable '$pinnedSccachePath' nor the exact Windows console host '$pinnedConhostPath' (observed='$imagePath')"
        }
        $causalMembers.Add([pscustomobject]@{
            Pid = [int]$sccachePid
            ProcessStartUtcTicks = [long]$identity.ProcessStartUtcTicks
            ImagePath = $imagePath
            ParentPid = [int]$processRows[0].ParentProcessId
            Role = $role
        })
    }
    $serverMembers = @($causalMembers | Where-Object { $_.Role -ceq 'server' })
    $consoleMembers = @(
        $causalMembers | Where-Object { $_.Role -ceq 'console-host' }
    )
    if ($serverMembers.Count -ne 1 -or $consoleMembers.Count -gt 1) {
        throw "LAUNCHER_BOUNDARY[ASTRO_SCCACHE_JOB_TOPOLOGY_INVALID]: startup must produce exactly one pinned sccache server and at most one exact conhost companion (servers=$($serverMembers.Count), console_hosts=$($consoleMembers.Count), members=$($newSccacheJobPids -join ','))"
    }
    if ($consoleMembers.Count -eq 1 -and
        ($consoleMembers[0].ParentPid -ne $serverMembers[0].Pid -or
            $consoleMembers[0].ProcessStartUtcTicks -lt
                $serverMembers[0].ProcessStartUtcTicks)) {
        throw "LAUNCHER_BOUNDARY[ASTRO_SCCACHE_JOB_TOPOLOGY_INVALID]: conhost PID $($consoleMembers[0].Pid) is not the exact creation-time-ordered child of sccache PID $($serverMembers[0].Pid) (parent=$($consoleMembers[0].ParentPid), conhost_ticks=$($consoleMembers[0].ProcessStartUtcTicks), server_ticks=$($serverMembers[0].ProcessStartUtcTicks))"
    }
    $listeners = @(
        Get-NetTCPConnection `
            -State Listen `
            -LocalAddress '127.0.0.1' `
            -LocalPort $sccacheServerPort `
            -ErrorAction Stop
    )
    if ($listeners.Count -ne 1 -or
        [int]$listeners[0].OwningProcess -ne $serverMembers[0].Pid) {
        throw "LAUNCHER_BOUNDARY[ASTRO_SCCACHE_LISTENER_IDENTITY_MISMATCH]: exact 127.0.0.1:$sccacheServerPort listener does not belong uniquely to captured sccache PID $($serverMembers[0].Pid) (count=$($listeners.Count), owners=$(@($listeners.OwningProcess) -join ','))"
    }
    $sccacheOwnedJobMembers = @($causalMembers)
    $sccacheMemberDescription = @(
        $sccacheOwnedJobMembers |
            ForEach-Object {
                "role=$($_.Role),pid=$($_.Pid),ticks=$($_.ProcessStartUtcTicks),parent=$($_.ParentPid)"
            }
    ) -join '; '
    Write-Output "SCCACHE[ASTRO_CACHE_JOB_BOUND]: exact infrastructure process generation(s): $sccacheMemberDescription"
    Write-Output "SCCACHE[ASTRO_CACHE_ENABLED]: dir=$sccacheDir; size=$SccacheCacheSize; wrapper=$sccacheExe; CARGO_INCREMENTAL=0; SCCACHE_SERVER_PORT=$sccacheServerPort; SCCACHE_IDLE_TIMEOUT=$SccacheIdleTimeout"
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
}
catch {
    # #239: a fault in the launcher itself (bad sccache daemon, unlaunchable command, ...)
    # is NOT a child exit code. Record it, let the finally run, and report it below under
    # its own reserved code so it can never be mistaken for the child's result.
    $launcherFault = $_
}
finally {
    # #424/#519: re-fingerprint the evidence tree before cleanup. A mismatch becomes a
    # cleanup error, preserving a red child and converting a green child to exit 71.
    try {
        if ($null -eq $gitMutationFreezeLease) {
            throw 'complete Git index/source mutation freeze was never acquired'
        }
        $gitFreezeTerminal = Assert-AstroGitMutationFreezeLease `
            $gitMutationFreezeLease
        Write-Output "GIT_FREEZE[ASTRO_GIT_MUTATION_FREEZE_STABLE]: index_file_id=$($gitFreezeTerminal.IndexInterlockFileId); source_paths=$($gitFreezeTerminal.SourcePathCount); metadata_paths=$($gitFreezeTerminal.MetadataPathCount); handles=$($gitFreezeTerminal.HandleCount); path_set_sha256=$($gitFreezeTerminal.PathSetSha256)"
    }
    catch {
        $cleanupErrors += "GIT_FREEZE[ASTRO_GIT_MUTATION_FREEZE_UNVERIFIED]: {code=ASTRO_GIT_MUTATION_FREEZE_UNVERIFIED; message=`"the process-lifetime Git index/source freeze could not be re-verified: $($_.Exception.Message)`"; remediation=`"treat this run as non-evidence, preserve protocol state, and repair the exact handle/interlock fault before rebuilding`"}"
    }
    try {
        $repoEvidenceAfter = Get-AstroRepoEvidenceState -GitExe $evidenceGitExe -Root $root
        if ($repoEvidenceAfter.HeadSha -cne $repoEvidenceBefore.HeadSha -or
            $repoEvidenceAfter.StatusSha256 -cne $repoEvidenceBefore.StatusSha256 -or
            $repoEvidenceAfter.DiffSha256 -cne $repoEvidenceBefore.DiffSha256) {
            $cleanupErrors += "GIT_FREEZE[ASTRO_LAUNCHER_TREE_MUTATED]: {code=ASTRO_LAUNCHER_TREE_MUTATED; message=`"the build root $root mutated during the evidence lease: head $($repoEvidenceBefore.HeadSha) -> $($repoEvidenceAfter.HeadSha), status_sha256 $($repoEvidenceBefore.StatusSha256) -> $($repoEvidenceAfter.StatusSha256), diff_sha256 $($repoEvidenceBefore.DiffSha256) -> $($repoEvidenceAfter.DiffSha256); this run's artifacts are NOT closure evidence (#424)`"; remediation=`"freeze the checkout for the whole build+FSV window (mutate only in an independent registered worktree), then rebuild`"}"
        }
        else {
            Write-Output "GIT_FREEZE[ASTRO_EVIDENCE_LEASE_STABLE]: head=$($repoEvidenceAfter.HeadSha) unchanged; status/diff fingerprints unchanged across the lease window (#424/#519)"
        }
    }
    catch {
        $cleanupErrors += "GIT_FREEZE[ASTRO_EVIDENCE_LEASE_UNVERIFIED]: {code=ASTRO_EVIDENCE_LEASE_UNVERIFIED; message=`"the evidence-lease tree fingerprint could not be re-verified: $($_.Exception.Message)`"; remediation=`"treat this run's artifacts as non-evidence; repair the repository state and rebuild`"}"
    }

    # The named Job Object is the kernel source of truth for current membership. Before
    # stopping the session-owned sccache daemon, distinguish only the exact process
    # generation(s) captured causally at its startup. Every other member protects the full
    # state; there are no image-name fallbacks and no telemetry exceptions.
    $deferCleanupForLiveChildren = $false
    $unexpectedJobPids = @()
    $preStopJobPids = @()
    try {
        if ($null -eq $treeRecorder) {
            throw 'strict v3 kill-on-close tree recorder is absent after active lock publication'
        }
        $preStopJobPids = @($treeRecorder.GetActiveProcessIds())
        if (-not ($preStopJobPids -contains $PID)) {
            throw "exact-session Job Object does not contain launcher PID $PID"
        }
        foreach ($jobPid in @($preStopJobPids | Where-Object { $_ -ne $PID })) {
            $infrastructure = @(
                $sccacheOwnedJobMembers |
                    Where-Object { $_.Pid -eq $jobPid }
            )
            if ($infrastructure.Count -ne 1) {
                $unexpectedJobPids += $jobPid
                continue
            }
            $identity = Get-AstroProcessIdentityProbe $jobPid
            if ($identity.State -ne 'observed' -or
                [long]$identity.ProcessStartUtcTicks -ne
                    [long]$infrastructure[0].ProcessStartUtcTicks) {
                throw "sccache Job Object member PID $jobPid no longer binds its captured process generation (state=$($identity.State), expected_ticks=$($infrastructure[0].ProcessStartUtcTicks), observed_ticks=$($identity.ProcessStartUtcTicks), error=$($identity.Error))"
            }
            $rows = @(Get-CimInstance `
                -ClassName Win32_Process `
                -Filter "ProcessId = $jobPid" `
                -ErrorAction Stop)
            if ($rows.Count -ne 1 -or
                [string]::IsNullOrWhiteSpace([string]$rows[0].ExecutablePath) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$rows[0].ExecutablePath),
                    [string]$infrastructure[0].ImagePath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                [int]$rows[0].ParentProcessId -ne
                    [int]$infrastructure[0].ParentPid) {
                throw "captured sccache infrastructure PID $jobPid changed exact image/parent topology before shutdown"
            }
        }
    }
    catch {
        $deferCleanupForLiveChildren = $true
        $cleanupErrors += "exact-session Job Object membership is unevaluable: $($_.Exception.Message)"
    }
    if ($unexpectedJobPids.Count -gt 0) {
        $deferCleanupForLiveChildren = $true
        $cleanupErrors += "unexpected exact-session Job Object member PID(s) remain live: $($unexpectedJobPids -join ', ')"
    }

    # Stop only the exact infrastructure generation(s) created by this lease, and only
    # when no other member needs the build state. All daemon command failures are cleanup
    # errors; none are relabeled as an acceptable empty result.
    if (-not $deferCleanupForLiveChildren -and $sccacheDaemonStarted) {
        try {
            Write-Output "SCCACHE[ASTRO_CACHE_STATS]:"
            $sccacheStats = Invoke-NativeCapture -Exe $sccacheExe -Arguments @("--show-stats")
            foreach ($line in $sccacheStats.Output) { Write-Output $line }
            if ($sccacheStats.ExitCode -ne 0) {
                $cleanupErrors += "sccache stats readback failed with exit $($sccacheStats.ExitCode): $($sccacheStats.Output -join ' | ')"
            }
            $sccacheStop = Invoke-NativeCapture -Exe $sccacheExe -Arguments @("--stop-server")
            if ($sccacheStop.ExitCode -ne 0) {
                $cleanupErrors += "exact session sccache stop failed with exit $($sccacheStop.ExitCode): $($sccacheStop.Output -join ' | ')"
            }
            else {
                $shutdownDeadline = [DateTime]::UtcNow.AddSeconds(10)
                do {
                    $sameGenerationLive = @(
                        $sccacheOwnedJobMembers | Where-Object {
                            $probe = Get-AstroProcessIdentityProbe $_.Pid
                            $probe.State -eq 'observed' -and
                                [long]$probe.ProcessStartUtcTicks -eq
                                    [long]$_.ProcessStartUtcTicks
                        }
                    )
                    if ($sameGenerationLive.Count -eq 0) { break }
                    Start-Sleep -Milliseconds 50
                } while ([DateTime]::UtcNow -lt $shutdownDeadline)
                if ($sameGenerationLive.Count -ne 0) {
                    $liveDescriptions = @(
                        $sameGenerationLive | ForEach-Object {
                            '{0}:{1}:{2}' -f @(
                                $_.Role,
                                $_.Pid,
                                $_.ProcessStartUtcTicks
                            )
                        }
                    )
                    $cleanupErrors += "exact sccache infrastructure generation(s) remained live after graceful --stop-server: $($liveDescriptions -join ', ')"
                }
                $remainingListeners = @(
                    Get-NetTCPConnection `
                        -State Listen `
                        -LocalAddress '127.0.0.1' `
                        -LocalPort $sccacheServerPort `
                        -ErrorAction SilentlyContinue
                )
                if ($remainingListeners.Count -ne 0) {
                    $cleanupErrors += "127.0.0.1:$sccacheServerPort still has listener owner(s) after graceful sccache stop: $(@($remainingListeners.OwningProcess) -join ',')"
                }
            }
        }
        catch {
            $cleanupErrors += "exact session sccache lifecycle readback/stop failed: $($_.Exception.Message)"
        }
    }

    # Drain every completion packet queued before the sentinel, require worker termination,
    # then independently read the producer bytes and both the JSON reader and kernel job.
    $finalManifestExpectedBytes = $null
    if ($null -ne $treeRecorder) {
        try {
            $treeRecorder.Stop()
            $treeRecorderStopped = $true
            $finalManifestExpectedBytes = $treeRecorder.GetLastManifestBytes()
            $manifestSnapshot = Get-AstroFileSnapshot `
                -LiteralPath $attributionManifest `
                -Share ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            if ($manifestSnapshot.Length -ne
                    [uint64]$finalManifestExpectedBytes.LongLength -or
                [Convert]::ToBase64String($manifestSnapshot.Bytes) -cne
                    [Convert]::ToBase64String($finalManifestExpectedBytes)) {
                throw 'final attribution manifest independent bytes differ from the producer readback'
            }
            $attributionProbe = Get-AstroLiveAttributedPids `
                -ManifestPath $attributionManifest `
                -SelfPid $PID
            if (-not $attributionProbe.ManifestReadable) {
                throw 'shared attribution reader reported ManifestReadable=false'
            }
            $terminalJobPids = @($treeRecorder.GetActiveProcessIds())
            $externalJobProbe = Get-AstroLauncherJobObjectProbe `
                -Name $launcherTreeJobObjectName
            if ($externalJobProbe.State -ne 'observed') {
                throw "independent named Job Object probe is '$($externalJobProbe.State)' ($($externalJobProbe.Error))"
            }
            $externalPids = @($externalJobProbe.ProcessIds | Sort-Object -Unique)
            if ((@($terminalJobPids | Sort-Object -Unique) -join ',') -cne
                ($externalPids -join ',')) {
                throw "in-process and independently opened Job Object membership differ (in_process=$($terminalJobPids -join ','), external=$($externalPids -join ','))"
            }
            $terminalChildren = @($terminalJobPids | Where-Object { $_ -ne $PID })
            if ($terminalChildren.Count -gt 0) {
                $deferCleanupForLiveChildren = $true
                $cleanupErrors += "exact-session Job Object still contains child PID(s) after the recorder stop barrier: $($terminalChildren -join ', ')"
            }
            $manifestLivePids = @($attributionProbe.LivePids)
            if ($manifestLivePids.Count -gt 0) {
                $deferCleanupForLiveChildren = $true
                $cleanupErrors += "strict attribution manifest still reports live child PID(s): $($manifestLivePids -join ', ')"
            }
        }
        catch {
            $deferCleanupForLiveChildren = $true
            $cleanupErrors += "tree-attribution stop/readback failed: $($_.Exception.Message)"
        }
        # #625: the exact Job and completion-port handles stay open through every
        # target/TEMP/manifest/lock operation. Native process teardown closes them
        # only after the dedicated launcher has published its terminal exit state.
    }
    else {
        $deferCleanupForLiveChildren = $true
        $cleanupErrors += 'tree-attribution recorder is absent at cleanup'
    }

    $launcherLockRemoved = $false
    $attributionManifestArchived = $false
    $workspaceTempArchived = $false
    $workspaceTempArchivePath = $null
    $attributionManifestArchivePath = $null
    $launcherArchiveCompletionPath = $null
    $manifestArchiveLease = $null
    $launcherStateArchiveTransaction = $null
    $launcherLockCleanupTransaction = $null
    $cleanupTargetRoots = if ($preservedTargetCleanupAuthorized) {
        [string[]]@($ownedTargetRoots)
    }
    else {
        $canonicalTarget = [IO.Path]::GetFullPath($target)
        [string[]]@(
            $ownedTargetRoots | Where-Object {
                -not [string]::Equals(
                    [IO.Path]::GetFullPath($_),
                    $canonicalTarget,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
        )
    }
    if ($RecoverPreservedTarget -and -not $preservedTargetCleanupAuthorized) {
        $targetPreservedState = Get-AstroPathEntryState $target
        Write-Output "TARGET_RECOVERY[ASTRO_PRESERVED_TARGET_UNAUTHORIZED_PRESERVED]: target=$target; state=$($targetPreservedState.State); finalization=$(if ($null -eq $preservedTargetRecoveryFinalizationPath) { '<absent>' } else { $preservedTargetRecoveryFinalizationPath }); generic cleanup is not authorized to mutate the preserved target"
    }
    if (-not $deferCleanupForLiveChildren -and $cleanupErrors.Count -eq 0) {
        try {
            # Recorder Stop/readback completed above while its Job handle remains retained.
            # Before the first destructive target/TEMP operation, independently require
            # exact kernel membership {PID}.
            $preCleanupJobProbe = Get-AstroLauncherJobObjectProbe `
                -Name $launcherTreeJobObjectName
            $preCleanupJobPids = @(
                $preCleanupJobProbe.ProcessIds | Sort-Object -Unique
            )
            if ($preCleanupJobProbe.State -ne 'observed' -or
                $preCleanupJobPids.Count -ne 1 -or
                $preCleanupJobPids[0] -ne $PID) {
                throw "named Job Object membership is not exact launcher-only state before cleanup (state=$($preCleanupJobProbe.State), pids=$($preCleanupJobPids -join ','), error=$($preCleanupJobProbe.Error))"
            }
        }
        catch {
            $deferCleanupForLiveChildren = $true
            $cleanupErrors += "pre-cleanup exact Job Object proof failed: $($_.Exception.Message)"
        }
    }

    if (-not $deferCleanupForLiveChildren -and $cleanupErrors.Count -eq 0) {
        try {
            $launcherLockCleanupTransaction =
                Start-LauncherLockCleanupTransaction `
                    -LockPath $launcherLock `
                    -ExpectedPid $PID `
                    -ExpectedIssue $drivingIssue `
                    -ExpectedOwnerProcessStartUtcTicks `
                        $launcherProcessStartUtcTicks `
                    -ExpectedSha256 $launcherLockSha256 `
                    -LeaseHandle $launcherLockLeaseHandle `
                    -ProtocolDirectoryLease $launcherProtocolDirectoryLease
            Write-Output "LAUNCHER_LOCK[ASTRO_LAUNCHER_CLEANUP_TRANSITION]: active -> $($launcherLockCleanupTransaction.CleanupPath); file_id=$($launcherLockCleanupTransaction.FileId); sha256=$($launcherLockCleanupTransaction.Sha256); Global mutex retained across subordinate cleanup"
        }
        catch {
            $cleanupErrors += "launcher cleanup transaction begin failed: $($_.Exception.Message)"
        }
    }

    if ($null -ne $launcherLockCleanupTransaction) {
        try {
            # The visible cleanup transition and Global mutex are retained before
            # target cleanup and the append-only TEMP/manifest archive transaction.
            # Stop at the first failure and preserve every source/archive byte plus
            # the exact transition for authorized recovery.
            foreach ($ownedTarget in $cleanupTargetRoots) {
                $targetState = Get-AstroPathEntryState $ownedTarget
                if ($targetState.State -eq 'present') {
                    # #421: depth-independent, not MAX_PATH-bound.
                    Remove-TreeResilient -Path $ownedTarget
                }
                elseif ($targetState.State -ne 'absent') {
                    throw "target presence is unevaluable before cleanup (state=$($targetState.State), error=$($targetState.Error)): $ownedTarget"
                }
                $targetTerminal = Get-AstroPathEntryState $ownedTarget
                if ($targetTerminal.State -ne 'absent') {
                    throw "target is not absent after cleanup (state=$($targetTerminal.State), error=$($targetTerminal.Error)): $ownedTarget"
                }
            }

            if ($null -eq $workspaceTempLease -or
                $null -eq $workspaceTempLease.Handle -or
                $workspaceTempLease.Handle.IsClosed) {
                throw 'producer no longer retains the exact live TEMP root handle'
            }
            if ($null -eq $finalManifestExpectedBytes) {
                throw 'producer did not supply exact final manifest bytes'
            }
            $manifestProbe = Get-AstroAttributionManifestProbe `
                -ManifestPath $attributionManifest
            $manifestArchiveLease = Open-AstroAttributionArchiveLease `
                -ManifestProbe $manifestProbe `
                -AuthorityMode live-owner `
                -ExpectedBytes $finalManifestExpectedBytes
            $launcherStateArchiveTransaction =
                Start-AstroLauncherStateArchiveTransaction `
                    -ProtocolDirectory $workspaceTempParent `
                    -ProtocolDirectoryLease $launcherProtocolDirectoryLease `
                    -TempLease $workspaceTempLease `
                    -ManifestLease $manifestArchiveLease `
                    -AuthorityMode live-owner `
                    -DrivingIssue $drivingIssue
            $tempArchive = Move-AstroLauncherStateArchiveTemp `
                -Transaction $launcherStateArchiveTransaction
            $workspaceTempArchivePath = $tempArchive.DestinationPath
            $manifestArchive = Move-AstroLauncherStateArchiveManifest `
                -Transaction $launcherStateArchiveTransaction
            $attributionManifestArchivePath =
                $manifestArchive.DestinationPath
            $archiveCompletion =
                Complete-AstroLauncherStateArchiveTransaction `
                    -Transaction $launcherStateArchiveTransaction
            $launcherArchiveCompletionPath = $archiveCompletion.CompletionPath

            foreach ($sourcePath in @($workspaceTemp, $attributionManifest)) {
                $sourceState = Get-AstroPathEntryState $sourcePath
                if ($sourceState.State -ne 'absent') {
                    throw "launcher archive source is not independently absent (state=$($sourceState.State), error=$($sourceState.Error)): $sourcePath"
                }
            }
            foreach ($archivePath in @(
                    $workspaceTempArchivePath,
                    $attributionManifestArchivePath,
                    $launcherArchiveCompletionPath
                )) {
                $archiveState = Get-AstroPathEntryState $archivePath
                if ($archiveState.State -ne 'present') {
                    throw "launcher archive destination is not independently present (state=$($archiveState.State), error=$($archiveState.Error)): $archivePath"
                }
            }
            Write-Output "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_STATE_ARCHIVE_READBACK]: transaction=$($archiveCompletion.TransactionId); transaction_path=$($archiveCompletion.TransactionPath); authorization_sha256=$($archiveCompletion.AuthorizationSha256); completion_sha256=$($archiveCompletion.CompletionSha256); temp_source=absent; temp_archive=$($archiveCompletion.TempArchivePath); temp_file_id=$($archiveCompletion.TempRootFileId); temp_inventory_state=$($archiveCompletion.TempInventoryState); temp_inventory_error=$($archiveCompletion.TempInventoryError); temp_entries=$($archiveCompletion.TempEntryCount); temp_inventory_sha256=$($archiveCompletion.TempInventorySha256); manifest_source=absent; manifest_archive=$($archiveCompletion.ManifestArchivePath); manifest_file_id=$($archiveCompletion.ManifestFileId); manifest_bytes=$($archiveCompletion.ManifestLength); manifest_sha256=$($archiveCompletion.ManifestSha256); cleanup_transition=$($launcherLockCleanupTransaction.CleanupPath)"
            $workspaceTempArchived = $true
            $attributionManifestArchived = $true
        }
        catch {
            $cleanupErrors += "subordinate cleanup under retained transition failed: $($_.Exception.Message)"
        }
        finally {
            # Releasing retained handles never deletes archive or source bytes.
            # An interrupted transaction remains classification-visible through
            # its authorization record and the cleanup transition.
            if ($null -ne $launcherStateArchiveTransaction) {
                try {
                    Close-AstroLauncherStateArchiveTransaction `
                        $launcherStateArchiveTransaction
                }
                catch {
                    $cleanupErrors += "launcher state archive handle release failed while preserving transaction state: $($_.Exception.Message)"
                }
            }
            else {
                if ($null -ne $manifestArchiveLease -and
                    $null -ne $manifestArchiveLease.Handle -and
                    -not $manifestArchiveLease.Handle.IsClosed) {
                    try { $manifestArchiveLease.Handle.Dispose() }
                    catch {
                        $cleanupErrors += "manifest archive lease release failed while preserving source: $($_.Exception.Message)"
                    }
                }
                if ($null -ne $workspaceTempLease -and
                    $null -ne $workspaceTempLease.Handle -and
                    -not $workspaceTempLease.Handle.IsClosed) {
                    try { Close-AstroLauncherTempMutationLease $workspaceTempLease }
                    catch {
                        $cleanupErrors += "retained live TEMP handle release failed while preserving source: $($_.Exception.Message)"
                    }
                }
            }
            if (-not $workspaceTempArchived -or
                -not $attributionManifestArchived) {
                $tempSource = Get-AstroPathEntryState $workspaceTemp
                $manifestSource = Get-AstroPathEntryState $attributionManifest
                Write-Output "LAUNCHER_ARCHIVE[ASTRO_LAUNCHER_STATE_ARCHIVE_PRESERVED]: transaction=$(if ($null -ne $launcherStateArchiveTransaction) { $launcherStateArchiveTransaction.TransactionPath } else { '<not-published>' }); temp_source=$($tempSource.State); temp_archive=$workspaceTempArchivePath; manifest_source=$($manifestSource.State); manifest_archive=$attributionManifestArchivePath; cleanup_transition=$($launcherLockCleanupTransaction.CleanupPath)"
            }
        }

        if ($cleanupErrors.Count -eq 0) {
            try {
                $protocolCleanup = Complete-LauncherLockCleanupTransaction `
                    -Transaction $launcherLockCleanupTransaction `
                    -OwnedTargetRoots $cleanupTargetRoots `
                    -WorkspaceTemp $workspaceTemp `
                    -WorkspaceTempArchivePath $workspaceTempArchivePath `
                    -AttributionManifest $attributionManifest `
                    -AttributionManifestArchivePath `
                        $attributionManifestArchivePath `
                    -ArchiveCompletionPath $launcherArchiveCompletionPath `
                    -JobObjectName $launcherTreeJobObjectName `
                    -ExpectedPid $PID
                if ($protocolCleanup.State -cne 'absent' -or
                    -not $protocolCleanup.DispositionSet -or
                    -not $protocolCleanup.Completed -or
                    -not $protocolCleanup.MutexReleased -or
                    $protocolCleanup.TerminalPathState -cne 'absent') {
                    throw "terminal cleanup transaction returned incomplete state (state=$($protocolCleanup.State), disposition_set=$($protocolCleanup.DispositionSet), completed=$($protocolCleanup.Completed), mutex_released=$($protocolCleanup.MutexReleased), terminal=$($protocolCleanup.TerminalPathState))"
                }
                Write-Output "LAUNCHER_LOCK[ASTRO_LAUNCHER_CLEANUP_COMPLETE]: transition absent last; file_id=$($protocolCleanup.FileId); sha256=$($protocolCleanup.Sha256); terminal=$($protocolCleanup.TerminalPathState); mutex_released=$($protocolCleanup.MutexReleased)"
                $launcherLockRemoved = $true
            }
            catch {
                $cleanupErrors += "launcher cleanup transaction completion failed: $($_.Exception.Message)"
            }
        }

        if (-not $launcherLockCleanupTransaction.Released) {
            try {
                $preserved = Stop-LauncherLockCleanupTransaction `
                    -Transaction $launcherLockCleanupTransaction `
                    -Reason ($cleanupErrors -join '; ')
                Write-Output "LAUNCHER_LOCK[ASTRO_LAUNCHER_CLEANUP_PRESERVED]: transition=$($preserved.CleanupPath); file_id=$($preserved.FileId); sha256=$($preserved.Sha256); mutex_released=$($preserved.MutexReleased); reason=$($preserved.Reason)"
            }
            catch {
                $cleanupErrors += "cleanup transition preservation/release failed: $($_.Exception.Message)"
            }
        }
    }

    # Release retained handles only after every authorized exact operation. When state is
    # preserved, closing these handles permits the tracker-bound reclaimer to inspect it;
    # it never grants deletion authority to this failed cleanup path.
    if ($null -ne $workspaceTempLease -and
        $null -ne $workspaceTempLease.Handle -and
        -not $workspaceTempLease.Handle.IsClosed) {
        try { Close-AstroLauncherTempMutationLease $workspaceTempLease }
        catch {
            $cleanupErrors += "retained live TEMP handle disposal failed while preserving state: $($_.Exception.Message)"
        }
    }
    if (-not $launcherLockRemoved -and
        $null -ne $launcherLockLeaseHandle -and
        $null -ne $launcherLockLeaseHandle.SafeFileHandle -and
        -not $launcherLockLeaseHandle.SafeFileHandle.IsClosed) {
        try { $launcherLockLeaseHandle.SafeFileHandle.Dispose() }
        catch {
            $cleanupErrors += "retained launcher-lock handle disposal failed while preserving state: $($_.Exception.Message)"
        }
    }
    if ($null -ne $launcherProtocolDirectoryLease -and
        $null -ne $launcherProtocolDirectoryLease.SafeFileHandle -and
        -not $launcherProtocolDirectoryLease.SafeFileHandle.IsClosed) {
        try { $launcherProtocolDirectoryLease.SafeFileHandle.Dispose() }
        catch {
            $cleanupErrors += "pinned protocol-directory handle disposal failed: $($_.Exception.Message)"
        }
    }
    if ($deferCleanupForLiveChildren) {
        [Console]::Error.WriteLine("LAUNCHER_BOUNDARY[ASTRO_LAUNCHER_CLEANUP_DEFERRED]: exact-session child/job/manifest state is live or unevaluable; target, TEMP, active lock or cleanup transition, and attribution manifest are preserved for tracker-bound recovery")
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
    if (-not $deferCleanupForLiveChildren -and
        $cleanupErrors.Count -eq 0 -and
        $launcherLockRemoved -and
        $attributionManifestArchived -and
        $workspaceTempArchived) {
        if ($preservedTargetCleanupAuthorized) {
            Write-Output "CLEANUP[ASTRO_TARGET]: absent: $(($ownedTargetRoots | Sort-Object) -join '; ')"
        }
        else {
            Write-Output "CLEANUP[ASTRO_TARGET]: preserved without authorization: $target"
        }
        Write-Output "CLEANUP[ASTRO_WORKSPACE_TEMP_ARCHIVE]: source=$workspaceTemp is absent; archive=$workspaceTempArchivePath is present"
        Write-Output "CLEANUP[ASTRO_LAUNCHER_PROTOCOL]: active lock, every transition, and direct attribution manifest are absent; append-only archive transaction remains at $($launcherStateArchiveTransaction.TransactionPath)"
        Write-Output "GIT_FREEZE[ASTRO_GIT_MUTATION_FREEZE_PROCESS_LIFETIME]: index/source handles remain retained through dedicated owner exit; DELETE_ON_CLOSE removes the exact Git index interlock in-kernel"
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
