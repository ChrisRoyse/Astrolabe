#!/usr/bin/env python3
"""Regression test for the literal missing-libcbm diagnostic."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-libcbm-symbols.sh"


def native_bash() -> str:
    if os.name != "nt":
        candidate = shutil.which("bash")
        if candidate:
            return candidate
        raise RuntimeError("bash not found")

    program_files = Path(os.environ.get("ProgramFiles", "C:/Program Files"))
    for candidate in (
        program_files / "Git" / "bin" / "bash.exe",
        program_files / "Git" / "usr" / "bin" / "bash.exe",
    ):
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError("native Git for Windows bash.exe not found")


def main() -> int:
    target = ROOT / "target"
    target_existed = target.exists()
    target.mkdir(parents=True, exist_ok=True)

    try:
        with tempfile.TemporaryDirectory(prefix="libcbm-symbols-", dir=target) as temp:
            scratch = Path(temp)
            marker = scratch / "cargo-invoked"
            fake_bin = scratch / "fake-bin"
            fake_bin.mkdir()
            fake_cargo = fake_bin / "cargo"
            fake_cargo.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'invoked' > \"$ASTRO_TEST_CARGO_MARKER\"\n"
                "exit 97\n",
                encoding="utf-8",
            )
            fake_cargo.chmod(fake_cargo.stat().st_mode | stat.S_IXUSR)

            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}{os.pathsep}{env.get('PATH', '')}"
            env["ASTRO_TEST_CARGO_MARKER"] = str(marker)
            result = subprocess.run(
                [native_bash(), str(CHECKER), str(scratch / "missing-libcbm.a")],
                cwd=ROOT,
                env=env,
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            output = result.stdout + result.stderr
            if result.returncode != 1:
                raise AssertionError(
                    f"missing-libcbm path returned {result.returncode}: {output}"
                )
            expected = "Run `cargo test -p cbm-sys --no-run` first or pass the path."
            if expected not in output:
                raise AssertionError(f"literal diagnostic missing {expected!r}: {output}")
            if marker.exists():
                raise AssertionError(f"diagnostic invoked cargo: {marker.read_text()}")
    finally:
        if not target_existed:
            target.rmdir()

    print("libcbm missing-archive diagnostic self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
