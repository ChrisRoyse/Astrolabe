#!/usr/bin/env python3
"""Guard the pinned, native Windows GNU toolchain launcher contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "windows-gnu-toolchain.ps1"
MAKEFILE = ROOT / "patches" / "cbm" / "Makefile.cbm"
GITIGNORE = ROOT / ".gitignore"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Windows GNU toolchain contract failed: {message}")


def appears_before(text: str, first: str, second: str) -> bool:
    return first in text and second in text and text.index(first) < text.index(second)


def main() -> None:
    require(RUNNER.is_file(), "the native Windows GNU launcher must exist")
    runner = RUNNER.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")
    gitignore = GITIGNORE.read_text(encoding="utf-8")

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
        and 'Get-FileHash -Algorithm SHA256' in runner
        and 'runtime DLL mismatch' in runner,
        "the launcher must reject a mixed MinGW runtime",
    )
    require(
        '$env:PATH = "$MingwBin;$LlvmBin;$CppcheckRoot;$GitUsrBin;$GitBin;$env:PATH"'
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
        "WSL_DISTRO_NAME" in runner
        and '$GitInstallRoot = "C:\\Program Files\\Git"' in runner
        and '$ForbiddenWslProcessNames = @("wsl", "wslhost", "vmmemWSL", "wslservice")'
        in runner
        and "function Assert-NoWslState" in runner
        and 'Get-Service -Name "WSLService"' in runner
        and 'Get-Process -Name $name' in runner
        and 'Get-Process -Name "bash"' in runner
        and "ASTRO_WSL_SERVICE_PRESENT" in runner
        and "ASTRO_WSL_PROCESS_ACTIVE" in runner
        and "ASTRO_NON_GIT_BASH_ACTIVE" in runner,
        "the launcher must fail closed on installed WSL or active WSL/non-Git Bash processes",
    )
    require(
        "function Assert-AllowedBashCommand" in runner
        and "function Assert-NativeGitBashResolution" in runner
        and 'Get-Command -Name "bash.exe" -CommandType Application' in runner
        and "ASTRO_BASH_COMMAND_FORBIDDEN" in runner
        and "ASTRO_BASH_RESOLUTION_FORBIDDEN" in runner,
        "the launcher must reject Bash resolution outside the pinned Git for Windows root",
    )
    require(
        appears_before(
            runner, "Assert-NoWslState -GitRoot $gitRoot", "if ($Bootstrap)"
        )
        and appears_before(
            runner,
            "Assert-AllowedBashCommand -Command $Command -GitRoot $gitRoot",
            "if ($Bootstrap)",
        ),
        "the WSL and Bash-command preflight must run before bootstrap work",
    )
    require(
        appears_before(
            runner,
            "Assert-NativeGitBashResolution -GitRoot $gitRoot -Command $Command",
            "Test-PinnedToolchain -MingwBin $mingwBin",
        ),
        "Git Bash resolution must be verified before toolchain command work",
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
        and 'IS_GCC := $(shell echo | $(CC_FOR_SHELL) -dM -E -' in makefile
        and 'IS_MINGW := $(shell echo | $(CC_FOR_SHELL) -dM -E -' in makefile,
        "the CBM overlay must normalize a native compiler path before POSIX shell probes",
    )

    print("Windows GNU toolchain contract verified")


if __name__ == "__main__":
    main()
