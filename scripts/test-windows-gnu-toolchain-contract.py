#!/usr/bin/env python3
"""Negative tests for the native Windows launcher contract checker."""

from __future__ import annotations

import atexit
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILES = (
    ".gitignore",
    "AGENTS.md",
    "CLAUDE.md",
    "patches/cbm/Makefile.cbm",
    "scripts/check-windows-gnu-toolchain-contract.py",
    "scripts/windows-gnu-toolchain.ps1",
)


def copy_fixture(destination: Path) -> None:
    for relative in FILES:
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def rewrite(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise AssertionError(f"expected one fixture occurrence of {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")


def rewrite_all(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"expected at least one fixture occurrence of {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")


def run_checker(fixture: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/check-windows-gnu-toolchain-contract.py"],
        cwd=fixture,
        check=False,
        capture_output=True,
        text=True,
    )


def expect_pass(result: subprocess.CompletedProcess[str]) -> None:
    if result.returncode != 0:
        raise AssertionError(f"expected pass, got:\n{result.stdout}\n{result.stderr}")


def expect_failure(result: subprocess.CompletedProcess[str], fragment: str) -> None:
    output = result.stdout + result.stderr
    if result.returncode == 0 or fragment not in output:
        raise AssertionError(
            f"expected failure containing {fragment!r}, got:\n{output}"
        )


def main() -> int:
    scratch_parent = ROOT / ".tmp"
    scratch_parent_existed = scratch_parent.exists()
    scratch = scratch_parent / "windows-toolchain-contract"
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True, exist_ok=True)

    def cleanup_scratch() -> None:
        shutil.rmtree(scratch, ignore_errors=True)
        if not scratch_parent_existed:
            try:
                scratch_parent.rmdir()
            except OSError:
                pass

    atexit.register(cleanup_scratch)
    with tempfile.TemporaryDirectory(prefix="contract-", dir=scratch) as temp:
        fixture = Path(temp)
        runner = fixture / "scripts/windows-gnu-toolchain.ps1"

        copy_fixture(fixture)
        expect_pass(run_checker(fixture))

        rewrite(
            runner,
            '$ForbiddenWslServiceNames = @("WSLService", "LxssManager")',
            '$ForbiddenWslServiceNames = @()',
        )
        expect_failure(run_checker(fixture), "WSL services")

        copy_fixture(fixture)
        rewrite(
            runner,
            '$ForbiddenWslProcessNames = @("wsl", "wslhost", "vmmemWSL", "wslservice")',
            '$ForbiddenWslProcessNames = @("wsl")',
        )
        expect_failure(run_checker(fixture), "active WSL/non-Git Bash")

        copy_fixture(fixture)
        rewrite(
            runner,
            '$WslInstallRoot = "C:\\Program Files\\WSL"',
            '$WslInstallRoot = "C:\\Program Files\\WSL-removed"',
        )
        expect_failure(run_checker(fixture), "install roots")

        copy_fixture(fixture)
        rewrite(
            runner,
            '$WslDistributionRegistryRoot = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss"',
            '$WslDistributionRegistryRoot = "HKCU:\\Software\\Removed"',
        )
        expect_failure(run_checker(fixture), "distributions")

        copy_fixture(fixture)
        rewrite(
            runner,
            "Assert-NoWslState -GitRoot $gitRoot",
            "Write-Output 'WSL preflight removed'",
        )
        expect_failure(run_checker(fixture), "preflight must run before bootstrap")

        copy_fixture(fixture)
        rewrite(
            runner,
            "ASTRO_HOST_MAINTENANCE_ACTIVE",
            "ASTRO_HOST_MAINTENANCE_REMOVED",
        )
        expect_failure(run_checker(fixture), "host maintenance")

        copy_fixture(fixture)
        rewrite(
            runner,
            "ASTRO_DISM_PROCESS_ACTIVE",
            "ASTRO_DISM_PROCESS_IGNORED",
        )
        expect_failure(run_checker(fixture), "active DISM servicing")

        copy_fixture(fixture)
        rewrite(
            runner,
            "Assert-NoActiveHostServicing\nAssert-HostMaintenanceBoundary -LockPath $hostMaintenanceLock -WorkspaceRoot $root",
            "Write-Output 'DISM preflight removed'\nAssert-HostMaintenanceBoundary -LockPath $hostMaintenanceLock -WorkspaceRoot $root",
        )
        expect_failure(run_checker(fixture), "active DISM servicing")

        copy_fixture(fixture)
        rewrite_all(
            runner,
            "ASTRO_HOST_MAINTENANCE_LOCK_UNREADABLE",
            "ASTRO_HOST_MAINTENANCE_LOCK_IGNORED",
        )
        expect_failure(run_checker(fixture), "owner-bound host maintenance")

        copy_fixture(fixture)
        rewrite_all(
            runner,
            "result_paths",
            "unowned_paths",
        )
        expect_failure(run_checker(fixture), "owner-bound host maintenance")

        copy_fixture(fixture)
        rewrite(
            runner,
            "ASTRO_HOST_MAINTENANCE_STALE",
            "ASTRO_HOST_MAINTENANCE_REMOVED",
        )
        expect_failure(run_checker(fixture), "owner-bound host maintenance")

        copy_fixture(fixture)
        rewrite(
            fixture / "AGENTS.md",
            "active native DISM",
            "untracked servicing",
        )
        expect_failure(run_checker(fixture), "doctrine")

        copy_fixture(fixture)
        rewrite(
            runner,
            "Get-Process -Id $process.Id -ErrorAction SilentlyContinue",
            "Get-Process -Id 0 -ErrorAction SilentlyContinue",
        )
        expect_failure(run_checker(fixture), "WSL services")

        copy_fixture(fixture)
        rewrite(
            runner,
            "ASTRO_LAUNCHER_LOCK_HELD",
            "ASTRO_LAUNCHER_LOCK_DISABLED",
        )
        expect_failure(run_checker(fixture), "session lock")

        copy_fixture(fixture)
        rewrite(
            runner,
            "ASTRO_LAUNCHER_LOCK_STALE",
            "ASTRO_LAUNCHER_LOCK_QUIET",
        )
        expect_failure(run_checker(fixture), "session lock")

        copy_fixture(fixture)
        rewrite(
            runner,
            "function Remove-LauncherLockFile",
            "function Remove-LauncherLockDisabled",
        )
        expect_failure(run_checker(fixture), "session lock")

        copy_fixture(fixture)
        rewrite(
            runner,
            'Get-Command -Name "bash.exe" -CommandType Application',
            'Get-Command -Name "bash.exe"',
        )
        expect_failure(run_checker(fixture), "Bash resolution outside")

        copy_fixture(fixture)
        rewrite(
            runner,
            "Assert-NativeGitBashResolution -GitRoot $gitRoot -Command $Command",
            "Write-Output 'Bash resolution check removed'",
        )
        expect_failure(run_checker(fixture), "resolution must be verified")

    print("Windows GNU toolchain contract negative tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
