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
    "scripts/launcher-lock.ps1",
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
        helper = fixture / "scripts/launcher-lock.ps1"

        copy_fixture(fixture)
        expect_pass(run_checker(fixture))

        rewrite(
            runner,
            '$env:WSL_DISTRO_NAME -or $env:WSL_INTEROP',
            '$env:WSL_DISTRO_NAME',
        )
        expect_failure(run_checker(fixture), "actual native Windows execution context")

        copy_fixture(fixture)
        rewrite(
            runner,
            "ASTRO_NATIVE_CONTEXT_REQUIRED",
            "ASTRO_NATIVE_CONTEXT_REMOVED",
        )
        expect_failure(run_checker(fixture), "actual native Windows execution context")

        copy_fixture(fixture)
        rewrite(
            runner,
            '$GitInstallRoot = "C:\\Program Files\\Git"',
            '$GitInstallRoot = "C:\\Program Files\\Git"\n$WslInstallRoot = "C:\\Program Files\\WSL"',
        )
        expect_failure(run_checker(fixture), "must not inspect or manage personal WSL")

        copy_fixture(fixture)
        rewrite(
            runner,
            "function Assert-AllowedBashCommand {",
            'Get-Process -Name "bash" | Out-Null\n\nfunction Assert-AllowedBashCommand {',
        )
        expect_failure(run_checker(fixture), "must not inspect or manage personal WSL")

        copy_fixture(fixture)
        rewrite(
            runner,
            '$launcherLock = Join-Path $workspaceTempParent "astrolabe-launcher.lock"',
            '$hostMaintenanceLock = Join-Path $workspaceTempParent "host-maintenance.lock"\n$launcherLock = Join-Path $workspaceTempParent "astrolabe-launcher.lock"',
        )
        expect_failure(run_checker(fixture), "must not inspect or manage personal WSL")

        copy_fixture(fixture)
        rewrite(
            fixture / "AGENTS.md",
            "must never fail closed on its presence",
            "may fail closed on its presence",
        )
        expect_failure(run_checker(fixture), "outside project authority")

        copy_fixture(fixture)
        rewrite(
            runner,
            "Assert-AllowedBashCommand -Command $Command -GitRoot $gitRoot",
            "Write-Output 'Bash command check removed'",
        )
        expect_failure(run_checker(fixture), "checks must run before bootstrap")

        copy_fixture(fixture)
        rewrite(
            helper,
            "ASTRO_LAUNCHER_LOCK_HELD",
            "ASTRO_LAUNCHER_LOCK_DISABLED",
        )
        expect_failure(run_checker(fixture), "session lock")

        copy_fixture(fixture)
        rewrite(
            helper,
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

        # #197: dropping the staged atomic claim (writing the lock in place
        # again) must be caught.
        copy_fixture(fixture)
        rewrite(
            runner,
            '$launcherLockStage = "$launcherLock.$PID.tmp"',
            "$launcherLockStage = $launcherLock",
        )
        expect_failure(run_checker(fixture), "atomically")

        # #197: a clobbering move would let a lost claim race overwrite a live
        # session's lock.
        copy_fixture(fixture)
        rewrite(
            runner,
            "Move-Item -LiteralPath $launcherLockStage -Destination $launcherLock -ErrorAction Stop",
            "Move-Item -LiteralPath $launcherLockStage -Destination $launcherLock -Force -ErrorAction Stop",
        )
        expect_failure(run_checker(fixture), "atomically")

        # #197: the lost-race refusal must stay a named boundary.
        copy_fixture(fixture)
        rewrite(
            runner,
            "ASTRO_LAUNCHER_LOCK_RACE",
            "ASTRO_LAUNCHER_LOCK_SILENT",
        )
        expect_failure(run_checker(fixture), "atomically")

        # #197: pid schema validation must stay a parse, not a bare cast.
        copy_fixture(fixture)
        rewrite(
            helper,
            "[int]::TryParse([string]$state.pid",
            "[int]::Parse([string]$state.pid",
        )
        expect_failure(run_checker(fixture), "pid schema")

        # #197: zero/negative pids must stay invalid.
        copy_fixture(fixture)
        rewrite(
            helper,
            "$parsed -gt 0",
            "$parsed -ge 0",
        )
        expect_failure(run_checker(fixture), "pid schema")

        copy_fixture(fixture)
        rewrite(
            runner,
            "ASTRO_BASH_COMMAND_FORBIDDEN",
            "ASTRO_BASH_COMMAND_UNGUARDED",
        )
        expect_failure(run_checker(fixture), "allowlist bash commands")

        # Reintroducing ambient bash.exe resolution policing (removed in 70866c7 because
        # it crashes when WSL coexists) must be caught by the contract's `not in runner`
        # guard.
        copy_fixture(fixture)
        rewrite(
            runner,
            "function Assert-AllowedBashCommand {",
            'Get-Command -Name "bash.exe" -CommandType Application | Out-Null\n\nfunction Assert-AllowedBashCommand {',
        )
        expect_failure(run_checker(fixture), "policing ambient bash.exe resolution")

    print("Windows GNU toolchain contract negative tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
