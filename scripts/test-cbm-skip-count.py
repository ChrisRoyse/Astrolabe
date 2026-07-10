#!/usr/bin/env python3
"""Self-tests for exact CBM platform skip-count enforcement."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-cbm-skip-count.sh"
MANIFEST = ROOT / "ci" / "known-skips.md"
EXPECTED = {
    "linux-x64-gcc": 1,
    "linux-x64-clang": 1,
    "macos-arm64-clang": 1,
    "windows-x64-mingw": 18,
}


def native_bash() -> str:
    if os.name != "nt":
        candidate = shutil.which("bash")
        if candidate:
            return candidate
        raise RuntimeError("bash not found")
    program_files = Path(os.environ.get("ProgramFiles", "C:/Program Files"))
    candidates = [
        Path(os.environ["ASTROLABE_NATIVE_BASH"])
        if os.environ.get("ASTROLABE_NATIVE_BASH")
        else None,
        program_files / "Git" / "bin" / "bash.exe",
        program_files / "Git" / "usr" / "bin" / "bash.exe",
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return str(candidate)
    raise RuntimeError("native Git for Windows bash.exe not found")


def invoke(
    bash: str, checker: Path, label: str, actual: object, manifest: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [bash, str(checker), label, str(actual), str(manifest)],
        cwd=manifest.parents[1],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def expect_pass(process: subprocess.CompletedProcess[str], label: str) -> None:
    if process.returncode != 0 or "CBM skip count verified" not in process.stdout:
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


def copy_fixture(root: Path) -> tuple[Path, Path]:
    checker = root / "scripts" / CHECKER.name
    manifest = root / "ci" / MANIFEST.name
    checker.parent.mkdir(parents=True)
    manifest.parent.mkdir(parents=True)
    shutil.copyfile(CHECKER, checker)
    shutil.copyfile(MANIFEST, manifest)
    return checker, manifest


def main() -> int:
    bash = native_bash()
    scratch = ROOT / "target"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cbm-skip-count-", dir=scratch) as temp:
        fixture = Path(temp)
        checker, manifest = copy_fixture(fixture)

        for label, expected in EXPECTED.items():
            expect_pass(
                invoke(bash, checker, label, expected, manifest),
                f"exact baseline for {label}",
            )
            expect_fail(
                invoke(bash, checker, label, expected + 1, manifest),
                f"added skip for {label}",
                "ASTRO_CBM_SKIP_COUNT_MISMATCH",
                f"expected {expected}",
                f"actual {expected + 1}",
            )
            expect_fail(
                invoke(bash, checker, label, expected - 1, manifest),
                f"removed skip for {label}",
                "ASTRO_CBM_SKIP_COUNT_MISMATCH",
                f"expected {expected}",
                f"actual {expected - 1}",
            )

        expect_fail(
            invoke(bash, checker, "unknown-platform", 0, manifest),
            "unknown label",
            "ASTRO_CBM_SKIP_BASELINE_AMBIGUOUS",
            "found 0",
        )
        expect_fail(
            invoke(bash, checker, "linux-x64-gcc", "many", manifest),
            "invalid actual count",
            "ASTRO_CBM_SKIP_ACTUAL_INVALID",
        )
        expect_fail(
            invoke(bash, checker, "linux-x64-gcc", "01", manifest),
            "noncanonical actual count",
            "ASTRO_CBM_SKIP_ACTUAL_INVALID",
        )

        baseline = manifest.read_text(encoding="utf-8")
        first_row = next(
            line for line in baseline.splitlines() if "| linux-x64-gcc |" in line
        )
        manifest.write_text(baseline + first_row + "\n", encoding="utf-8")
        expect_fail(
            invoke(bash, checker, "linux-x64-gcc", 1, manifest),
            "duplicate baseline",
            "ASTRO_CBM_SKIP_BASELINE_AMBIGUOUS",
            "found 2",
        )

        manifest.write_text(
            baseline.replace("| linux-x64-gcc | 1 |", "| linux-x64-gcc | many |"),
            encoding="utf-8",
        )
        expect_fail(
            invoke(bash, checker, "linux-x64-gcc", 1, manifest),
            "malformed baseline",
            "ASTRO_CBM_SKIP_BASELINE_INVALID",
        )

    print("CBM exact skip-count self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
