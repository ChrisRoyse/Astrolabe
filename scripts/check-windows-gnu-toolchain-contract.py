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
        '$env:PATH = "$MingwBin;$GitUsrBin;$GitBin;$env:PATH"' in runner
        and '$env:MAKE = Join-Path $MingwBin "make.exe"' in runner,
        "the launcher must place its runtime first and use the bundled GNU Make",
    )
    require(
        '$workspaceTemp = Join-Path $target "tmp"' in runner
        and 'Set-WorkspaceTempEnvironment -WorkspaceTemp $workspaceTemp' in runner
        and 'function Set-WorkspaceTempEnvironment' in runner
        and '$env:TEMP = $WorkspaceTemp' in runner
        and '$env:TMP = $WorkspaceTemp' in runner
        and '$env:TMPDIR = $WorkspaceTemp' in runner
        and 'New-Item -ItemType Directory -Path $workspaceTemp -Force' in runner,
        "the launcher must confine child temporary output to target/tmp",
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
    for variable in ("RUSTUP_TOOLCHAIN", "CC", "CXX", "AR", "LD", "NM", "OBJCOPY"):
        require(
            f'$env:{variable}' in runner,
            f"the launcher must set {variable} for child commands",
        )
    require(
        "WSL_DISTRO_NAME" in runner,
        "the launcher must fail rather than run from a WSL environment",
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
