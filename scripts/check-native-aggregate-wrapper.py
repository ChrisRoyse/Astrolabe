#!/usr/bin/env python3
"""Guard the stdout-only native Windows aggregate entry point."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "invoke-native-aggregate.ps1"
README = ROOT / "README.md"
AGENTS = ROOT / "AGENTS.md"
CLAUDE = ROOT / "CLAUDE.md"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Native aggregate wrapper contract failed: {message}")


def main() -> None:
    require(WRAPPER.is_file(), "scripts/invoke-native-aggregate.ps1 must exist")
    wrapper = WRAPPER.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    agents = AGENTS.read_text(encoding="utf-8")
    claude = CLAUDE.read_text(encoding="utf-8")

    require(
        '$ExpectedWorkspace = "C:\\code\\Astrolabe"' in wrapper
        and '$env:WSL_DISTRO_NAME -or $env:WSL_INTEROP' in wrapper
        and "ASTRO_NATIVE_CONTEXT_REQUIRED" in wrapper
        and '$env:OS -ne "Windows_NT"' in wrapper,
        "the wrapper must require canonical native Windows execution",
    )
    for token in (
        "Get-Service",
        "Get-Process",
        "Get-AppxPackage",
        "Lxss",
        "host-maintenance",
        "DismHost",
    ):
        require(
            token not in wrapper,
            f"the wrapper must not inspect personal WSL or host servicing via {token}",
        )
    require(
        '$gitBash = "C:\\Program Files\\Git\\bin\\bash.exe"' in wrapper
        and '"scripts\\windows-gnu-toolchain.ps1"' in wrapper
        and "& $launcher -Command $gitBash -CommandArgsJson $commandArgsJson"
        in wrapper,
        "the wrapper must delegate through the pinned launcher and Git for Windows Bash",
    )
    require(
        '[ValidateSet("portable", "full", "release")]' in wrapper
        and 'portable = "scripts/check.sh"' in wrapper
        and 'full = "scripts/check-full.sh"' in wrapper
        and 'release = "scripts/check-release.sh"' in wrapper,
        "the wrapper must expose only repository aggregate gates",
    )
    require(
        "NATIVE_AGGREGATE[ASTRO_STDOUT_ONLY]" in wrapper
        and "no log file is created" in wrapper,
        "the wrapper must label its stream-only evidence contract",
    )
    forbidden = (
        "Tee-Object",
        "Start-Transcript",
        "Out-File",
        "Set-Content",
        "Add-Content",
        "$env:TEMP",
        "GetTempPath",
        "AppData",
        "scratchpad",
    )
    for token in forbidden:
        require(
            token not in wrapper,
            f"the wrapper must stream evidence without external log token {token}",
        )
    require(
        "$previousTimeout = Get-Item" in wrapper
        and "finally {" in wrapper
        and '$env:ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS = "0"' in wrapper
        and 'Remove-Item -Path "Env:ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS"'
        in wrapper
        and "$previousTimeout.Value" in wrapper,
        "the wrapper must restore the bounded-test environment in a finally path",
    )
    for name, document in (("README.md", readme), ("AGENTS.md", agents), ("CLAUDE.md", claude)):
        require(
            "invoke-native-aggregate.ps1" in document and "Tee-Object" in document,
            f"{name} must require the stdout-only wrapper and forbid host-side Tee-Object capture",
        )

    print("Native aggregate wrapper contract verified")


if __name__ == "__main__":
    main()
