#!/usr/bin/env python3
"""Self-test for scripts/check-release-failpoint-strings.py (issue #291).

Drives the gate against synthetic fixture binaries to prove it fails closed on
a failpoint marker and passes on clean bytes:

  1. A binary whose bytes contain the crash-fsv marker  =>  gate exits nonzero
     and names the marker.
  2. Clean binaries                                      =>  gate exits 0.
  3. A manifest naming a missing binary                  =>  gate fails closed
     (a missing binary can never be proven clean).
  4. The .exe fallback resolves a bare path to <name>.exe.

Uses the real gate script and a real temp manifest + real fixture files (no
mocks). Nothing here builds cargo or touches the shared workspace target/.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check-release-failpoint-strings.py"
MARKER = b"CALYX_ASTER_CRASH_FSV_AFTER_WAL_APPEND_MARKER"


def python_bin() -> str:
    return sys.executable or "python"


def run_gate(manifest: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [python_bin(), str(GATE), "--manifest", str(manifest)],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def write_manifest(path: Path, binaries: list[dict]) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "astrolabe.binary_size_gate.v1",
                "max_bytes": 157286400,
                "binaries": binaries,
            }
        ),
        encoding="utf-8",
    )


def rel(path: Path) -> str:
    # The gate resolves paths relative to the repo ROOT, so express fixture
    # paths as ROOT-relative POSIX strings.
    return path.relative_to(ROOT).as_posix()


def main() -> int:
    # Nest fixtures under target/ (disposable, gitignored) so an interrupted run
    # never leaves a stray dir at the repo root for a git-clean gate to trip on.
    holder = ROOT / "target"
    holder_existed = holder.exists()
    holder.mkdir(parents=True, exist_ok=True)
    try:
        _run_cases(holder)
    finally:
        if not holder_existed:
            try:
                holder.rmdir()
            except OSError:
                pass  # target/ acquired other content; leave it for the owner's cleanup.
    print("release failpoint-string gate self-test passed")
    return 0


def _run_cases(holder: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="failpoint-strings-", dir=holder) as temp:
        scratch = Path(temp)

        clean = scratch / "clean-bin"
        clean.write_bytes(b"\x00\x01harmless bytes without any failpoint\x02\x03")
        dirty = scratch / "dirty-bin"
        dirty.write_bytes(b"prefix\x00" + MARKER + b"\x00suffix")

        # (1) marker present -> fail closed and name the marker.
        m1 = scratch / "m-dirty.json"
        write_manifest(m1, [{"name": "dirty", "path": rel(dirty)}])
        r1 = run_gate(m1)
        if r1.returncode == 0:
            raise AssertionError(f"gate passed a binary containing the marker:\n{r1.stdout}")
        if "CALYX_ASTER_CRASH_FSV" not in r1.stdout:
            raise AssertionError(f"failure did not name the marker:\n{r1.stdout}")

        # (2) clean binaries -> pass.
        m2 = scratch / "m-clean.json"
        write_manifest(m2, [{"name": "clean", "path": rel(clean)}])
        r2 = run_gate(m2)
        if r2.returncode != 0:
            raise AssertionError(f"gate failed clean binaries (exit {r2.returncode}):\n{r2.stdout}")
        if "release failpoint-string gate verified" not in r2.stdout:
            raise AssertionError(f"clean pass missing verified line:\n{r2.stdout}")

        # (3) missing binary -> fail closed.
        m3 = scratch / "m-missing.json"
        write_manifest(m3, [{"name": "gone", "path": rel(scratch / "does-not-exist")}])
        r3 = run_gate(m3)
        if r3.returncode == 0:
            raise AssertionError(f"gate passed a manifest naming a missing binary:\n{r3.stdout}")
        if "missing" not in r3.stdout:
            raise AssertionError(f"missing-binary failure not diagnosed:\n{r3.stdout}")

        # (4) .exe fallback: bare path resolves to <name>.exe, and the marker in
        #     it is still caught.
        exe = scratch / "winbin.exe"
        exe.write_bytes(b"leader" + MARKER + b"trailer")
        bare = scratch / "winbin"  # no such file; only winbin.exe exists
        m4 = scratch / "m-exe.json"
        write_manifest(m4, [{"name": "winbin", "path": rel(bare)}])
        r4 = run_gate(m4)
        if r4.returncode == 0:
            raise AssertionError(f".exe-fallback binary with marker was not caught:\n{r4.stdout}")
        if "CALYX_ASTER_CRASH_FSV" not in r4.stdout:
            raise AssertionError(f".exe-fallback failure did not name the marker:\n{r4.stdout}")


if __name__ == "__main__":
    raise SystemExit(main())
