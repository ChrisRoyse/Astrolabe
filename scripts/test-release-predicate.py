#!/usr/bin/env python3
"""Self-tests for scripts/release-predicate.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PREDICATE = ROOT / "scripts" / "release-predicate.py"
ARTIFACTS = {
    "agent_eval_l7": "agent-eval-l7.json",
    "inherited_gates": "inherited-gates.json",
    "l1_l4": "l1-l4.json",
    "l5_baselines": "l5-baselines.json",
    "bench_ratios": "bench-ratios.json",
    "verify_chain_soak": "verify-chain-soak.json",
    "parity_dashboard": "parity-dashboard.json",
    "license_gate": "license-gate.json",
    "nightly_reproduce_sample": "reproduce-sample.json",
}


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="astrolabe-release-predicate-") as temp:
        artifact_dir = Path(temp)
        write_green_artifacts(artifact_dir)
        expect_pass(artifact_dir)
        for key in ARTIFACTS:
            write_green_artifacts(artifact_dir)
            force_red(artifact_dir, key)
            expect_fail(artifact_dir, key)
        write_green_artifacts(artifact_dir)
        write_l5_waiver(artifact_dir)
        expect_pass_with_waiver(artifact_dir)
        write_green_artifacts(artifact_dir)
        write_reproduce_drift(artifact_dir)
        expect_fail(artifact_dir, "nightly_reproduce_sample", "answer:pack-7")
    print("release predicate self-test passed")
    return 0


def write_green_artifacts(artifact_dir: Path) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    for key, filename in ARTIFACTS.items():
        write_json(
            artifact_dir / filename,
            {
                "status": "pass",
                "source": f"fixture:{key}",
                "measured": {"value": 1},
            },
        )


def force_red(artifact_dir: Path, key: str) -> None:
    write_json(
        artifact_dir / ARTIFACTS[key],
        {
            "status": "fail",
            "reason": f"forced red for {key}",
        },
    )


def write_l5_waiver(artifact_dir: Path) -> None:
    write_json(
        artifact_dir / ARTIFACTS["l5_baselines"],
        {
            "status": "waived",
            "waiver_file": "ci/fixtures/release-waivers/l5-baseline-waiver.json",
            "published_numbers": {
                "pack_recall": 0.93,
                "required_pack_recall": 0.95,
            },
        },
    )


def write_reproduce_drift(artifact_dir: Path) -> None:
    write_json(
        artifact_dir / ARTIFACTS["nightly_reproduce_sample"],
        {
            "status": "fail",
            "code": "REPRODUCE_DRIFT_EXCEEDED",
            "answer_id": "answer:pack-7",
            "reason": "drift 0.002 exceeds bound 0.001",
        },
    )


def expect_pass(artifact_dir: Path) -> None:
    result = run_predicate(artifact_dir)
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    if "ASTROLABE_DONE: pass" not in result.stdout:
        raise AssertionError(result.stdout)


def expect_pass_with_waiver(artifact_dir: Path) -> None:
    result = run_predicate(artifact_dir)
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    if "WAIVER l5_baselines" not in result.stdout:
        raise AssertionError(result.stdout)
    if "pack_recall" not in json_output(artifact_dir)["active_waivers"][0]["published_numbers"]:
        raise AssertionError("waiver published numbers missing from JSON output")


def expect_fail(artifact_dir: Path, key: str, extra: str | None = None) -> None:
    result = run_predicate(artifact_dir)
    if result.returncode == 0:
        raise AssertionError("predicate unexpectedly passed")
    combined = result.stdout + result.stderr
    if key not in combined:
        raise AssertionError(combined)
    if extra and extra not in combined:
        raise AssertionError(combined)


def json_output(artifact_dir: Path) -> dict:
    result = subprocess.run(
        [sys.executable, str(PREDICATE), "--artifacts", str(artifact_dir), "--json"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


def run_predicate(artifact_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(PREDICATE), "--artifacts", str(artifact_dir)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
