#!/usr/bin/env python3
"""Exercise the platform ownership split in the CBM lint wrapper."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LINT = ROOT / "scripts" / "ci-cbm-lint.sh"
SKIP = "SKIP[ASTRO_CBM_CLANG_TIDY_LINUX_REQUIRED]"


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


def write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(0o755)


def fixture(root: Path) -> Path:
    script = root / "scripts" / LINT.name
    script.parent.mkdir(parents=True)
    lint = LINT.read_text(encoding="utf-8")
    host_probe = 'HOST_OS="$(uname -s)"'
    if lint.count(host_probe) != 1:
        raise AssertionError("expected one host-platform probe in the CBM lint wrapper")
    write_executable(script, lint.replace(host_probe, 'HOST_OS="$ASTROLABE_TEST_UNAME"'))

    check_no_skips = (
        root / "vendor" / "codebase-memory-mcp" / "scripts" / "check-no-test-skips.sh"
    )
    check_no_skips.parent.mkdir(parents=True)
    write_executable(check_no_skips, "#!/usr/bin/env bash\nprintf 'MOCK_NO_SKIPS\\n'\n")

    bin_dir = root / "bin"
    bin_dir.mkdir()
    write_executable(bin_dir / "make", "#!/usr/bin/env bash\nprintf 'MOCK_MAKE %s\\n' \"$*\"\n")
    return script


def invoke(bash: str, script: Path, host: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["ASTROLABE_TEST_UNAME"] = host
    environment["PATH"] = str(script.parents[1] / "bin") + os.pathsep + environment["PATH"]
    return subprocess.run(
        [bash, str(script)],
        cwd=script.parents[1],
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def assert_path(
    process: subprocess.CompletedProcess[str],
    host: str,
    expect_tidy: bool,
) -> None:
    output = process.stdout + process.stderr
    require(process.returncode == 0, f"{host} lint fixture failed:\n{output}")
    require("MOCK_NO_SKIPS" in output, f"{host} omitted the no-skips check:\n{output}")
    for target in ("lint-cppcheck", "lint-format", "lint-no-suppress"):
        require(target in output, f"{host} omitted {target}:\n{output}")

    if expect_tidy:
        require("lint-tidy" in output, f"{host} omitted clang-tidy:\n{output}")
        require(SKIP not in output, f"{host} unexpectedly skipped clang-tidy:\n{output}")
        require("--platform=unix64" not in output, f"{host} changed cppcheck ABI:\n{output}")
    else:
        require("lint-tidy" not in output, f"{host} unexpectedly ran clang-tidy:\n{output}")
        require(SKIP in output, f"{host} omitted the named ownership skip:\n{output}")
        require("required Linux CI job" in output, f"{host} omitted the CI owner:\n{output}")
        require(
            "INFO[ASTRO_CBM_CPPCHECK_LINUX_ABI]" in output,
            f"{host} omitted the cppcheck ABI marker:\n{output}",
        )
        require("--platform=unix64" in output, f"{host} omitted the cppcheck ABI:\n{output}")


def main() -> int:
    bash = native_bash()
    scratch_parent = ROOT / ".tmp"
    scratch_parent_existed = scratch_parent.exists()
    scratch = scratch_parent / "cbm-lint-platform"
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True)

    try:
        with tempfile.TemporaryDirectory(prefix="fixture-", dir=scratch) as temp:
            script = fixture(Path(temp))
            assert_path(invoke(bash, script, "Linux"), "Linux", expect_tidy=True)
            assert_path(invoke(bash, script, "MINGW64_NT-10.0"), "Windows", expect_tidy=False)
            assert_path(invoke(bash, script, "Darwin"), "macOS", expect_tidy=False)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        if not scratch_parent_existed:
            try:
                scratch_parent.rmdir()
            except OSError:
                pass

    require(not scratch.exists(), "lint platform fixture leaked temporary output")
    print("CBM lint platform contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
