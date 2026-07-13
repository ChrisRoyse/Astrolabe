#!/usr/bin/env python3
"""Guard the pinned, native Windows GNU toolchain launcher contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "windows-gnu-toolchain.ps1"
LAUNCHER_LOCK = ROOT / "scripts" / "launcher-lock.ps1"
ATTRIBUTION_MANIFEST = ROOT / "scripts" / "attribution-manifest.ps1"
MAKEFILE = ROOT / "patches" / "cbm" / "Makefile.cbm"
GITIGNORE = ROOT / ".gitignore"
AGENTS = ROOT / "AGENTS.md"
CLAUDE = ROOT / "CLAUDE.md"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Windows GNU toolchain contract failed: {message}")


def appears_before(text: str, first: str, second: str) -> bool:
    return first in text and second in text and text.index(first) < text.index(second)


def main() -> None:
    require(RUNNER.is_file(), "the native Windows GNU launcher must exist")
    runner = RUNNER.read_text(encoding="utf-8")
    require(LAUNCHER_LOCK.is_file(), "the shared launcher-lock helper must exist")
    lock_helper = LAUNCHER_LOCK.read_text(encoding="utf-8")
    require(ATTRIBUTION_MANIFEST.is_file(), "the attribution-manifest lifecycle helper must exist")
    attribution_helper = ATTRIBUTION_MANIFEST.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")
    gitignore = GITIGNORE.read_text(encoding="utf-8")
    agents = AGENTS.read_text(encoding="utf-8")
    claude = CLAUDE.read_text(encoding="utf-8")

    require(
        '$ExpectedWorkspace = "C:\\code\\Astrolabe"' in runner,
        "the launcher must reject non-canonical workspaces",
    )
    require(
        '$RustToolchain = "1.95.0-x86_64-pc-windows-gnu"' in runner,
        "the launcher must select the pinned GNU Rust host",
    )
    require(
        'x86_64-14.1.0-release-posix-seh-msvcrt-rt_v12-rev0.7z' in runner
        and 'BC0DE4321141730E83FD2457B1F7639946CC66787BF98BA9B03770D06D414DF1'
        in runner,
        "the launcher must pin and hash-check Rust CI's compatible MinGW bundle",
    )
    require(
        'clang+llvm-20.1.8-x86_64-pc-windows-msvc.tar.xz' in runner
        and 'F229769F11D6A6EDC8ADA599C0CDA964B7DEE6AB1A08C6CF9DD7F513E85B107F'
        in runner
        and 'function Install-PinnedLlvm' in runner
        and 'outer extraction of $LlvmArchiveName' in runner
        and 'inner extraction of $LlvmArchiveName' in runner,
        "the launcher must pin and hash-check a compatible workspace-local LLVM archive",
    )
    require(
        '$CppcheckRepository = "https://github.com/cppcheck-opensource/cppcheck.git"'
        in runner
        and '$CppcheckTag = "2.20.0"' in runner
        and '$CppcheckCommit = "502C802A69C78F3D8CFD9973AA2108AE169C73B5"'
        in runner
        and 'function Install-PinnedCppcheck' in runner
        and '& $gitExe clone --depth 1 --branch $CppcheckTag $CppcheckRepository $source'
        in runner
        and 'rev-parse HEAD' in runner
        and 'RDYNAMIC=' in runner,
        "the launcher must build cppcheck from the pinned upstream source commit",
    )
    require(
        '$ExpectedGccVersion = "14.1.0"' in runner
        and '$ExpectedGccTriple = "x86_64-w64-mingw32"' in runner,
        "the launcher must validate the compiler identity",
    )
    require(
        '$ExpectedMakeSha256 = "35F7A48546FC3A64B39E3B6AB13CBBCDBF2DAC9C79707714858975E94C7E8A0B"'
        in runner
        and "Ensure-BundledMakeAlias" in runner
        and 'Copy-Item -LiteralPath $source -Destination $alias' in runner
        and '"mingw32-make.exe",' in runner
        and '"make.exe"' in runner,
        "the launcher must expose a hash-verified make.exe alias from the pinned bundle",
    )
    require(
        '"libgcc_s_seh-1.dll", "libwinpthread-1.dll"' in runner
        and 'Get-Sha256Hex' in runner
        and 'runtime DLL mismatch' in runner,
        "the launcher must reject a mixed MinGW runtime",
    )
    require(
        '$env:PATH = "$MingwBin;$LlvmBin;$CppcheckRoot;$RipgrepRoot;$GitUsrBin;$GitBin;$env:PATH"'
        in runner
        and '$env:BASH = Join-Path $GitBin "bash.exe"' in runner
        and '$env:MAKE = Join-Path $MingwBin "make.exe"' in runner
        and '$env:CLANG_TIDY = Join-Path $LlvmBin "clang-tidy.exe"' in runner
        and '$env:CLANG_FORMAT = Join-Path $LlvmBin "clang-format.exe"' in runner
        and '$env:CPPCHECK = Join-Path $CppcheckRoot "cppcheck.exe"' in runner
        and '$ExpectedClangTidyVersion = "20.1.8"' in runner,
        "the launcher must select pinned LLVM and cppcheck tools with the bundled GNU Make",
    )
    require(
        'function Install-PinnedRipgrep' in runner
        and 'function Remove-StalePinnedRipgrep' in runner
        and '$env:RIPGREP = Join-Path $RipgrepRoot "rg.exe"' in runner
        and '$ExpectedRipgrepSha256' in runner,
        "the launcher must provision pinned ripgrep so check-unsafe-boundary can scan",
    )
    require(
        'function Remove-StalePinnedLlvm' in runner
        and 'Remove-StalePinnedLlvm -ToolsRoot $toolsRoot -LlvmRoot $llvmRoot' in runner,
        "the launcher must prune obsolete launcher-managed LLVM cache roots after bootstrap",
    )
    require(
        'function Remove-StalePinnedCppcheck' in runner
        and 'Remove-StalePinnedCppcheck -ToolsRoot $toolsRoot -CppcheckRoot $cppcheckRoot'
        in runner
        and 'Join-Path $package "cfg\\std.cfg"' in runner,
        "the launcher must retain cppcheck data and prune obsolete launcher-managed cppcheck cache roots",
    )
    require(
        '$workspaceTempParent = Join-Path $root ".tmp"' in runner
        and '$workspaceTemp = Join-Path $workspaceTempParent "windows-gnu-toolchain-$PID"'
        in runner
        and '$workspaceTemp = Join-Path $target "tmp"' not in runner
        and 'Set-WorkspaceTempEnvironment -WorkspaceTemp $workspaceTemp' in runner
        and 'function Set-WorkspaceTempEnvironment' in runner
        and '$env:TEMP = $WorkspaceTemp' in runner
        and '$env:TMP = $WorkspaceTemp' in runner
        and '$env:TMPDIR = $WorkspaceTemp' in runner
        and 'New-Item -ItemType Directory -Path $workspaceTemp -Force' in runner
        and 'Remove-Item -LiteralPath $workspaceTemp -Recurse -Force' in runner
        and 'CLEANUP[ASTRO_WORKSPACE_TEMP]' in runner,
        "the launcher must confine and remove child temporary output within the workspace",
    )
    forbidden_host_state = (
        '$WslInstallRoot',
        '$WslUninstallRegistryRoots',
        '$WslDistributionRegistryRoot',
        '$ForbiddenWslServiceNames',
        '$ForbiddenWslProcessNames',
        'Assert-NoWslState',
        'ASTRO_WSL_SERVICE_PRESENT',
        'ASTRO_WSL_INSTALL_ROOT_PRESENT',
        'ASTRO_WSL_PACKAGE_PRESENT',
        'ASTRO_WSL_DISTRIBUTION_PRESENT',
        'ASTRO_WSL_PROCESS_ACTIVE',
        'ASTRO_NON_GIT_BASH_ACTIVE',
        'Get-Process -Name "bash"',
        'Windows\\CurrentVersion\\Lxss',
        'C:\\Program Files\\WSL',
        '$HostServicingProcessNames',
        'Assert-NoActiveHostServicing',
        'Assert-HostMaintenanceBoundary',
        'host-maintenance.lock',
        'ASTRO_DISM_PROCESS_ACTIVE',
        'ASTRO_HOST_MAINTENANCE_',
        'DismHost.exe',
    )
    for token in forbidden_host_state:
        require(
            token not in runner,
            f"the launcher must not inspect or manage personal WSL or host servicing ({token})",
        )
    for name, document in (("AGENTS.md", agents), ("CLAUDE.md", claude)):
        require(
            "WSL coexistence" in document
            and "must never fail closed on its presence" in document
            and "must never stop, disable, uninstall" in document
            and "no operating-system servicing" in document,
            f"{name} must keep personal WSL and host servicing outside project authority",
        )
    require(
        '$launcherLock = Join-Path $workspaceTempParent "astrolabe-launcher.lock"'
        in runner
        and '. (Join-Path $PSScriptRoot "launcher-lock.ps1")' in runner
        and "Assert-AstroLauncherLockClaimable -LockPath $launcherLock" in runner
        and "function Remove-LauncherLockFile" in runner
        and "launcher lock cleanup failed" in runner
        and appears_before(
            runner,
            "Assert-AstroLauncherLockClaimable -LockPath $launcherLock",
            "target must be absent before toolchain work",
        ),
        "the launcher must route its session lock check through the audited launcher-lock helper before claiming, and release the lock on every exit path",
    )
    require(
        "function Read-AstroLauncherLock" in lock_helper
        and "function Assert-AstroLauncherLockClaimable" in lock_helper
        and "ASTRO_LAUNCHER_LOCK_HELD" in lock_helper
        and "ASTRO_LAUNCHER_LOCK_UNREADABLE" in lock_helper
        and "ASTRO_LAUNCHER_LOCK_STALE" in lock_helper
        and "Get-Process -Id $ownerPid" in lock_helper
        and "Stop-Process" not in lock_helper
        and "Get-Process -Name" not in lock_helper
        and appears_before(
            lock_helper,
            "ASTRO_LAUNCHER_LOCK_HELD",
            "Remove-Item -LiteralPath $LockPath",
        ),
        "the launcher-lock helper must classify the session lock fail-closed, refuse a live holder, remove only dead-pid stale locks, and never stop a process",
    )
    require(
        '$launcherLockStage = "$launcherLock.$PID.tmp"' in runner
        and "Move-Item -LiteralPath $launcherLockStage -Destination $launcherLock" in runner
        and "ASTRO_LAUNCHER_LOCK_RACE" in runner
        and "Move-Item -LiteralPath $launcherLockStage -Destination $launcherLock -Force"
        not in runner,
        "the launcher must claim its session lock atomically: stage the full manifest beside the lock, move without clobbering, and refuse a lost claim race with a named boundary (#197)",
    )
    require(
        "[int]::TryParse([string]$state.pid" in lock_helper
        and "$parsed -gt 0" in lock_helper,
        "the launcher-lock helper must validate the lock pid schema fail-closed: a non-integer or non-positive pid is the named UNREADABLE boundary, never an unnamed cast error (#197)",
    )
    require(
        '$previousTempEnvironment = @{}' in runner
        and 'Set-Item -Path "Env:$name" -Value $previous.Value' in runner
        and 'Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue' in runner,
        "the launcher must restore its caller's temporary-directory environment",
    )
    require(
        '[string]$CommandArgsJson = "[]"' in runner
        and 'ConvertFrom-Json -InputObject $CommandArgsJson' in runner,
        "the launcher must forward command arguments without PowerShell flag parsing",
    )
    for variable in ("RUSTUP_TOOLCHAIN", "CC", "CXX", "AR", "LD", "NM", "OBJCOPY", "CPPCHECK"):
        require(
            f'$env:{variable}' in runner,
            f"the launcher must set {variable} for child commands",
        )
    require(
        '$env:OS -ne "Windows_NT"' in runner
        and '$env:WSL_DISTRO_NAME -or $env:WSL_INTEROP' in runner
        and "ASTRO_NATIVE_CONTEXT_REQUIRED" in runner
        and '$GitInstallRoot = "C:\\Program Files\\Git"' in runner,
        "the launcher must require an actual native Windows execution context without probing host WSL state",
    )
    require(
        "function Assert-AllowedBashCommand" in runner
        and "ASTRO_BASH_COMMAND_FORBIDDEN" in runner
        # Commit 70866c7 removed ambient bash.exe *resolution* policing: with WSL
        # coexisting (permitted, direction reversed 2026-07-11), bash.exe resolves to
        # multiple ambient paths and the old Get-Command/.Source path crashed every
        # native gate at startup. The launcher must keep the bash-command allowlist
        # but MUST NOT reintroduce resolution policing (WSL-coexistence invariant).
        and "Assert-NativeGitBashResolution" not in runner
        and 'Get-Command -Name "bash.exe" -CommandType Application' not in runner,
        "the launcher must allowlist bash commands without policing ambient bash.exe resolution (WSL coexistence)",
    )
    require(
        appears_before(
            runner, "ASTRO_NATIVE_CONTEXT_REQUIRED", "if ($Bootstrap)"
        )
        and appears_before(
            runner,
            "Assert-AllowedBashCommand -Command $Command -GitRoot $gitRoot",
            "if ($Bootstrap)",
        ),
        "native-context and Bash-command checks must run before bootstrap work",
    )
    require(
        'Remove-Item -LiteralPath $target -Recurse -Force' in runner
        and 'CLEANUP[ASTRO_TARGET]' in runner
        and 'finally {' in runner,
        "the launcher must remove target in a finally cleanup path",
    )
    require(
        "/.toolchains/" in gitignore,
        "the repository-local pinned toolchain cache must remain untracked",
    )
    require(
        "MINGW_RELOC_LD_FLAGS := --allow-multiple-definition" in makefile
        and "$(MINGW_RELOC_LD_FLAGS)" in makefile,
        "the relocatable libcbm link must tolerate MinGW CRT import duplicates",
    )
    require(
        'CC_FOR_SHELL := $(subst \\,/,$(CC))' in makefile
        and 'CC_FAMILY := $(shell dump="$$(echo | $(CC_FOR_SHELL) -dM -E -' in makefile
        and 'IS_MINGW := $(shell echo | $(CC_FOR_SHELL) -dM -E -' in makefile,
        "the CBM overlay must normalize a native compiler path before POSIX shell probes",
    )
    # #274: compiler-family detection must be fail-closed. A probe that cannot run
    # the compiler (or a non-GCC/non-Clang compiler) must raise $(error) rather
    # than silently resolving IS_GCC to a suppression state.
    require(
        'IS_GCC := $(if $(filter gcc,$(CC_FAMILY)),yes,no)' in makefile
        and '$(error [#274] Makefile.cbm could not classify the compiler family'
        in makefile
        and 'ifeq ($(filter gcc clang,$(CC_FAMILY)),)' in makefile,
        "the CBM overlay must fail closed when the compiler family cannot be classified (#274)",
    )

    # #279: the launcher must record the process tree AND populate owned_paths from a
    # causal owned-path probe over the recorded tree's open handles on the protected CBM
    # store roots, failing closed (owned_paths=null) when the probe mechanism cannot run.
    require(
        "class AstroTreeRecorder" in runner
        and "public static List<string> ProbeOwnedStorePaths(int[] treePids, string[] roots)" in runner
        and "rstrtmgr.dll" in runner
        and "RmStartSession" in runner
        and "RmGetList" in runner
        and "RunOwnedProbe" in runner
        # fail-closed: probe mechanism failure latches ownedProbeFailed -> owned_paths null,
        # never a silent empty. The '[]' path is only reached when the probe RAN.
        and "ownedProbeFailed" in runner
        and '\\"owned_paths\\":' in runner
        # fail-closed: owned_paths serializes as JSON null when the probe latched failed.
        and "if (probeFailedSnap) {" in runner
        and 'sb.Append("null");' in runner,
        "the launcher's attribution recorder must populate owned_paths via a causal Restart-Manager "
        "probe over the recorded tree and fail closed (owned_paths=null) when the probe cannot run (#279)",
    )
    require(
        "function Get-AstroAttributedStoreRoots" in runner
        and "no-escape-roots.json" in runner
        and "$root.mode -ne 'attributed'" in runner
        and "-StoreRoots $attributedStoreRoots" in runner
        and "ASTRO_OWNED_PATH_PROBE" in runner,
        "the launcher must resolve the attributed CBM-store roots from the gate registry and pass "
        "them to the owned-path probe (single source of truth, no drift) (#279)",
    )
    # #301: the launcher must dot-source the audited attribution-manifest helper, sweep dead-PID
    # manifests at startup, and remove its OWN manifest on every exit path (finally).
    require(
        '. (Join-Path $PSScriptRoot "attribution-manifest.ps1")' in runner
        and "Clear-DeadAttributionManifests -Directory $workspaceTempParent -SelfPid $PID" in runner
        and "Remove-AstroAttributionManifest -Path $attributionManifest" in runner
        and "ASTRO_ATTRIBUTION_SWEEP" in runner
        and "CLEANUP[ASTRO_ATTRIBUTION_MANIFEST]" in runner
        and appears_before(
            runner,
            "Clear-DeadAttributionManifests -Directory $workspaceTempParent -SelfPid $PID",
            "Remove-AstroAttributionManifest -Path $attributionManifest",
        ),
        "the launcher must sweep dead-PID attribution manifests at startup and remove its own "
        "manifest on every exit path via the audited helper (#301)",
    )
    require(
        "function Clear-DeadAttributionManifests" in attribution_helper
        and "function Remove-AstroAttributionManifest" in attribution_helper
        and "Get-Process -Id $OwnerPid" in attribution_helper
        # #197: the sweep must never stop a process nor sweep by name; a live-PID manifest is
        # inviolable (kept), only dead-PID ones are removed.
        and "Stop-Process" not in attribution_helper
        and "Get-Process -Name" not in attribution_helper
        and "$SelfPid" in attribution_helper,
        "the attribution-manifest helper must classify by exact-PID liveness, keep live-PID "
        "manifests inviolable, skip the self PID, and never stop a process (#301/#197)",
    )

    print("Windows GNU toolchain contract verified")


if __name__ == "__main__":
    main()
