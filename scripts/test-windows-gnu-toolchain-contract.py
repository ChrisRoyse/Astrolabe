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
            'Get-Service -Name "WSLService"',
            'Get-Service -Name "WSLServiceRemoved"',
        )
        expect_failure(run_checker(fixture), "installed WSL")

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
            "Assert-NoWslState -GitRoot $gitRoot",
            "Write-Output 'WSL preflight removed'",
        )
        expect_failure(run_checker(fixture), "preflight must run before bootstrap")

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
