#!/usr/bin/env python3
"""Publish the bench_ratios release-predicate artifact from benchmark JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ARTIFACT_NAME = "bench-ratios.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--return-code", required=True, type=int)
    args = parser.parse_args()

    artifact = build_artifact(args.source, args.return_code)
    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    (args.artifact_dir / ARTIFACT_NAME).write_text(
        json.dumps(artifact, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


def build_artifact(source_path: Path, return_code: int) -> dict[str, Any]:
    artifact: dict[str, Any] = {
        "schema": "astrolabe.bench_ratios.v1",
        "status": "fail",
        "source": "scripts/bench-row-sink-overhead.sh",
        "source_artifact": str(source_path),
        "command_returncode": return_code,
        "benchmarks": [],
        "reason": None,
    }

    try:
        report = json.loads(source_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        artifact["reason"] = f"benchmark did not write {source_path}"
        return artifact
    except json.JSONDecodeError as exc:
        artifact["reason"] = f"benchmark wrote invalid JSON: {exc}"
        return artifact

    ratio = numeric(report.get("row_sink_overhead_ratio"))
    gate = numeric(report.get("gate", {}).get("row_sink_overhead_max_ratio"))
    artifact["benchmarks"].append(
        {
            "name": "row_sink_overhead",
            "schema": report.get("schema"),
            "status": report.get("status"),
            "mode": report.get("mode"),
            "corpus_class": report.get("corpus_class"),
            "source": report.get("source"),
            "repo": report.get("repo"),
            "repeats": report.get("repeats"),
            "generated_files": report.get("generated_files"),
            "baseline_median_us": report.get("baseline_median_us"),
            "row_sink_median_us": report.get("row_sink_median_us"),
            "row_sink_overhead_ratio": ratio,
            "row_sink_overhead_max_ratio": gate,
            "gate": report.get("gate"),
        }
    )

    if return_code == 0 and report.get("status") == "pass":
        artifact["status"] = "pass"
        return artifact
    if report.get("status") == "fail" and ratio is not None and gate is not None:
        artifact["reason"] = f"row_sink_overhead_ratio {ratio:.3f} exceeded gate {gate:.3f}"
    elif return_code != 0:
        artifact["reason"] = f"benchmark command failed with exit code {return_code}"
    else:
        artifact["reason"] = f"benchmark status is {report.get('status')!r}"
    return artifact


def numeric(value: Any) -> float | int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    return None


if __name__ == "__main__":
    raise SystemExit(main())
