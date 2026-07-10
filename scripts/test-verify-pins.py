#!/usr/bin/env python3
"""Regression tests for staged and working-tree vendor pin verification."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "verify-pins.sh"


def native_bash() -> str:
    if os.name != "nt":
        candidate = shutil.which("bash")
        if candidate:
            return candidate
        raise RuntimeError("bash not found")

    candidates = []
    override = os.environ.get("ASTROLABE_NATIVE_BASH")
    if override:
        candidates.append(Path(override))
    program_files = Path(os.environ.get("ProgramFiles", "C:/Program Files"))
    candidates.extend(
        [
            program_files / "Git" / "bin" / "bash.exe",
            program_files / "Git" / "usr" / "bin" / "bash.exe",
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError("native Git for Windows bash.exe not found")


def run(argv: list[str], cwd: Path, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        argv,
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and process.returncode != 0:
        raise AssertionError(
            f"command failed ({process.returncode}): {argv!r}\n"
            f"stdout:\n{process.stdout}\nstderr:\n{process.stderr}"
        )
    return process


def git(repo: Path, *args: str) -> str:
    process = run(["git", *args], repo)
    return process.stdout.strip()


def write_vendored(path: Path, calyx_pin: str, cbm_pin: str) -> None:
    path.write_text(
        "\n".join(
            [
                "# Vendored Parent Systems",
                "",
                "| System | Path | Source | Binding tree SHA |",
                "|---|---|---|---|",
                f"| Calyx | `vendor/calyx` | fixture | `{calyx_pin}` |",
                f"| codebase-memory-mcp | `vendor/codebase-memory-mcp` | fixture | `{cbm_pin}` |",
                "",
            ]
        ),
        encoding="utf-8",
    )


def tree_pin(repo: Path, path: str) -> str:
    root_tree = git(repo, "write-tree")
    return git(repo, "rev-parse", f"{root_tree}:{path}")


def checker(repo: Path, bash: str) -> subprocess.CompletedProcess[str]:
    return run([bash, "scripts/verify-pins.sh"], repo, check=False)


def expect_pass(process: subprocess.CompletedProcess[str], label: str) -> None:
    if process.returncode != 0 or "vendor pins verified" not in process.stdout:
        raise AssertionError(
            f"{label} should pass\nstdout:\n{process.stdout}\nstderr:\n{process.stderr}"
        )


def expect_fail(
    process: subprocess.CompletedProcess[str], label: str, *fragments: str
) -> None:
    output = process.stdout + process.stderr
    if process.returncode == 0:
        raise AssertionError(f"{label} unexpectedly passed: {output}")
    for fragment in fragments:
        if fragment not in output:
            raise AssertionError(f"{label} missing {fragment!r}: {output}")


def main() -> int:
    bash = native_bash()
    scratch = ROOT / "target"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="verify-pins-", dir=scratch) as temp:
        repo = Path(temp)
        calyx_file = repo / "vendor" / "calyx" / "source.txt"
        cbm_file = repo / "vendor" / "codebase-memory-mcp" / "source.txt"
        calyx_file.parent.mkdir(parents=True)
        cbm_file.parent.mkdir(parents=True)
        calyx_file.write_text("calyx pinned\n", encoding="utf-8")
        cbm_file.write_text("cbm pinned\n", encoding="utf-8")

        git(repo, "init", "-q")
        git(repo, "config", "user.name", "Astrolabe Pin Test")
        git(repo, "config", "user.email", "pins@example.invalid")
        git(repo, "config", "core.autocrlf", "false")
        git(repo, "config", "core.filemode", "false")
        git(repo, "add", "vendor")
        calyx_pin = tree_pin(repo, "vendor/calyx")
        cbm_pin = tree_pin(repo, "vendor/codebase-memory-mcp")

        scripts = repo / "scripts"
        scripts.mkdir()
        shutil.copyfile(CHECKER, scripts / "verify-pins.sh")
        vendored = repo / "VENDORED.md"
        write_vendored(vendored, calyx_pin, cbm_pin)
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "fixture baseline")

        expect_pass(checker(repo, bash), "clean vendor roots")

        calyx_file.write_text("calyx unstaged drift\n", encoding="utf-8")
        expect_fail(
            checker(repo, bash),
            "tracked working-tree drift",
            "ASTRO_VENDOR_WORKTREE_DIRTY",
            "vendor/calyx",
        )
        git(repo, "restore", "--worktree", "--", "vendor/calyx/source.txt")

        untracked = repo / "vendor" / "calyx" / "untracked.txt"
        untracked.write_text("not pinned\n", encoding="utf-8")
        expect_fail(
            checker(repo, bash),
            "untracked vendor path",
            "ASTRO_VENDOR_UNTRACKED",
            "vendor/calyx/untracked.txt",
        )
        untracked.unlink()

        cbm_file.write_text("cbm staged update\n", encoding="utf-8")
        git(repo, "add", "vendor/codebase-memory-mcp/source.txt")
        expect_fail(
            checker(repo, bash),
            "staged update with old pin",
            "codebase-memory-mcp tree pin mismatch",
        )

        updated_cbm_pin = tree_pin(repo, "vendor/codebase-memory-mcp")
        write_vendored(vendored, calyx_pin, updated_cbm_pin)
        git(repo, "add", "VENDORED.md")
        expect_pass(checker(repo, bash), "staged update with matching pin")

        cbm_file.write_text("cbm staged update plus drift\n", encoding="utf-8")
        expect_fail(
            checker(repo, bash),
            "unstaged drift after valid staged update",
            "ASTRO_VENDOR_WORKTREE_DIRTY",
            "vendor/codebase-memory-mcp",
        )

    print("vendor pin working-tree self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
