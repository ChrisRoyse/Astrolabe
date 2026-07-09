#!/usr/bin/env python3
"""Self-tests for scripts/write-bench-ratios-artifact.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRITER = ROOT / "scripts" / "write-bench-ratios-artifact.py"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="astrolabe-bench-ratios-") as temp:
        root = Path(temp)
        pass_report = root / "pass.json"
        write_report(pass_report, status="pass", ratio=0.95, gate=1.30)
        artifact = run_writer(root, pass_report, 0)
        assert artifact["status"] == "pass"
        assert artifact["reason"] is None
        assert artifact["benchmarks"][0]["row_sink_overhead_ratio"] == 0.95

        fail_report = root / "fail.json"
        write_report(fail_report, status="fail", ratio=1.51, gate=1.30)
        artifact = run_writer(root, fail_report, 1)
        assert artifact["status"] == "fail"
        assert "1.510 exceeded gate 1.300" in artifact["reason"]

        missing = root / "missing.json"
        artifact = run_writer(root, missing, 101)
        assert artifact["status"] == "fail"
        assert "benchmark did not write" in artifact["reason"]
        assert artifact["benchmarks"] == []

    print("bench ratios artifact self-test passed")
    return 0


def run_writer(root: Path, source: Path, return_code: int) -> dict:
    artifact_dir = root / f"artifact-{return_code}-{source.stem}"
    subprocess.run(
        [
            sys.executable,
            str(WRITER),
            "--source",
            str(source),
            "--artifact-dir",
            str(artifact_dir),
            "--return-code",
            str(return_code),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads((artifact_dir / "bench-ratios.json").read_text(encoding="utf-8"))


def write_report(path: Path, *, status: str, ratio: float, gate: float) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "astrolabe-row-sink-overhead-bench-v1",
                "status": status,
                "mode": "full",
                "source": "fixture",
                "repo": "/tmp/fixture",
                "generated_files": 12,
                "repeats": 3,
                "corpus_class": "small",
                "baseline_median_us": 100,
                "row_sink_median_us": ratio * 100,
                "row_sink_overhead_ratio": ratio,
                "gate": {"row_sink_overhead_max_ratio": gate},
            },
            sort_keys=True,
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
