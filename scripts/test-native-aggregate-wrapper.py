#!/usr/bin/env python3
"""Mutation tests for the native aggregate wrapper contract."""

from __future__ import annotations

import atexit
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "AGENTS.md",
    "CLAUDE.md",
    "README.md",
    "scripts/check-native-aggregate-wrapper.py",
    "scripts/invoke-native-aggregate.ps1",
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
        [sys.executable, "scripts/check-native-aggregate-wrapper.py"],
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
    scratch = scratch_parent / "native-aggregate-wrapper"
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
    with tempfile.TemporaryDirectory(prefix="wrapper-", dir=scratch) as temp:
        fixture = Path(temp)
        wrapper = fixture / "scripts/invoke-native-aggregate.ps1"

        copy_fixture(fixture)
        expect_pass(run_checker(fixture))

        rewrite(
            wrapper,
            "NATIVE_AGGREGATE[ASTRO_STDOUT_ONLY]",
            "NATIVE_AGGREGATE[ASTRO_LOG_FILE_ALLOWED]",
        )
        expect_failure(run_checker(fixture), "stream-only evidence contract")

        copy_fixture(fixture)
        rewrite(
            wrapper,
            "& $launcher -Command $gitBash -CommandArgsJson $commandArgsJson",
            '& $launcher -Command $gitBash -CommandArgsJson $commandArgsJson | Tee-Object -FilePath "$env:TEMP\\aggregate.log"',
        )
        expect_failure(run_checker(fixture), "external log token Tee-Object")

        copy_fixture(fixture)
        rewrite(
            wrapper,
            '$gitBash = "C:\\Program Files\\Git\\bin\\bash.exe"',
            '$gitBash = "C:\\Windows\\System32\\bash.exe"',
        )
        expect_failure(run_checker(fixture), "Git for Windows Bash")

        copy_fixture(fixture)
        rewrite(wrapper, "finally {", "if ($false) {")
        expect_failure(run_checker(fixture), "finally path")

        copy_fixture(fixture)
        readme = fixture / "README.md"
        rewrite(
            readme,
            ".\\scripts\\invoke-native-aggregate.ps1",
            ".\\scripts\\windows-gnu-toolchain.ps1",
        )
        expect_failure(run_checker(fixture), "README.md")

    print("Native aggregate wrapper mutation tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
