#!/usr/bin/env python3
"""Self-tests for scripts/release-predicate.py.

Covers the original per-conjunct red/waiver behaviour plus the #88 provenance
binding: an artifact that is unstamped, from another commit, stale, mixed-vintage,
or stamped in the future must be REJECTED with a coded error before its `status`
is ever read. A green status in an unbound artifact is the false-green this
predicate exists to prevent.
"""

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

COMMIT = "0" * 40
OTHER_COMMIT = "f" * 40
NOW = 1_800_000_000


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

        # #88: provenance binding. Each case mutates ONE artifact's stamp and
        # requires the predicate to fail closed with the right coded error --
        # even though every artifact still says status: pass.
        print("=== #88 provenance binding: green status must not survive a broken stamp ===")

        write_green_artifacts(artifact_dir)
        strip_stamp(artifact_dir, "license_gate", "commit")
        expect_code(artifact_dir, "RELEASE_PREDICATE_UNSTAMPED", "license_gate (no commit)")

        write_green_artifacts(artifact_dir)
        strip_stamp(artifact_dir, "bench_ratios", "generated_at_unix")
        expect_code(artifact_dir, "RELEASE_PREDICATE_UNSTAMPED", "bench_ratios (no timestamp)")

        write_green_artifacts(artifact_dir)
        patch(artifact_dir, "verify_chain_soak", {"commit": OTHER_COMMIT})
        expect_code(
            artifact_dir, "RELEASE_PREDICATE_WRONG_COMMIT", "verify_chain_soak (other commit)"
        )

        write_green_artifacts(artifact_dir)
        patch(artifact_dir, "verify_chain_soak", {"generated_at_unix": NOW - 400_000})
        expect_code(
            artifact_dir, "RELEASE_PREDICATE_STALE_ARTIFACT", "verify_chain_soak (5 days old)"
        )

        write_green_artifacts(artifact_dir)
        # Fresh enough to survive the age bound, but far enough from its peers to
        # prove it was carried over from an earlier run.
        patch(artifact_dir, "license_gate", {"generated_at_unix": NOW - 60_000})
        expect_code(artifact_dir, "RELEASE_PREDICATE_MIXED_VINTAGE", "license_gate (older run)")

        write_green_artifacts(artifact_dir)
        patch(artifact_dir, "parity_dashboard", {"generated_at_unix": NOW + 3_600})
        expect_code(
            artifact_dir, "RELEASE_PREDICATE_FUTURE_ARTIFACT", "parity_dashboard (future stamp)"
        )

        write_green_artifacts(artifact_dir)
        expect_pass(artifact_dir)
        print("  a fully-bound artifact set still passes")

    print("release predicate self-test passed")
    return 0


def write_green_artifacts(artifact_dir: Path) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    for key, filename in ARTIFACTS.items():
        write_json(
            artifact_dir / filename,
            stamped(
                {
                    "status": "pass",
                    "source": f"fixture:{key}",
                    "measured": {"value": 1},
                }
            ),
        )


def stamped(payload: dict) -> dict:
    bound = dict(payload)
    bound["stamp_schema"] = "astrolabe.release_artifact_stamp.v1"
    bound["commit"] = COMMIT
    bound["commit_dirty"] = False
    bound["generated_at_unix"] = NOW
    bound["generated_at_utc"] = "2027-01-15T08:00:00Z"
    return bound


def patch(artifact_dir: Path, key: str, changes: dict) -> None:
    path = artifact_dir / ARTIFACTS[key]
    data = json.loads(path.read_text(encoding="utf-8"))
    data.update(changes)
    write_json(path, data)


def strip_stamp(artifact_dir: Path, key: str, field: str) -> None:
    path = artifact_dir / ARTIFACTS[key]
    data = json.loads(path.read_text(encoding="utf-8"))
    data.pop(field, None)
    write_json(path, data)


def force_red(artifact_dir: Path, key: str) -> None:
    write_json(
        artifact_dir / ARTIFACTS[key],
        stamped({"status": "fail", "reason": f"forced red for {key}"}),
    )


def write_l5_waiver(artifact_dir: Path) -> None:
    write_json(
        artifact_dir / ARTIFACTS["l5_baselines"],
        stamped(
            {
                "status": "waived",
                "waiver_file": "ci/fixtures/release-waivers/l5-baseline-waiver.json",
                "published_numbers": {
                    "pack_recall": 0.93,
                    "required_pack_recall": 0.95,
                },
            }
        ),
    )


def write_reproduce_drift(artifact_dir: Path) -> None:
    write_json(
        artifact_dir / ARTIFACTS["nightly_reproduce_sample"],
        stamped(
            {
                "status": "fail",
                "code": "REPRODUCE_DRIFT_EXCEEDED",
                "answer_id": "answer:pack-7",
                "reason": "drift 0.002 exceeds bound 0.001",
            }
        ),
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


def expect_code(artifact_dir: Path, code: str, label: str) -> None:
    result = run_predicate(artifact_dir)
    combined = result.stdout + result.stderr
    if result.returncode == 0:
        raise AssertionError(f"{label}: predicate passed a broken stamp\n{combined}")
    if code not in combined:
        raise AssertionError(f"{label}: expected {code}\n{combined}")
    verdict = json_output(artifact_dir, check=False)
    if verdict["code"] != code:
        raise AssertionError(f"{label}: JSON verdict code is {verdict['code']!r}")
    for field in ("code", "message", "remediation"):
        if not verdict["error"].get(field):
            raise AssertionError(f"{label}: coded error is missing {field}")
    print(f"  REJECTED {label}: {code}")


def json_output(artifact_dir: Path, check: bool = True) -> dict:
    result = subprocess.run(
        [
            sys.executable,
            str(PREDICATE),
            "--artifacts",
            str(artifact_dir),
            "--commit",
            COMMIT,
            "--now-unix",
            str(NOW),
            "--json",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=check,
    )
    return json.loads(result.stdout)


def run_predicate(artifact_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(PREDICATE),
            "--artifacts",
            str(artifact_dir),
            "--commit",
            COMMIT,
            "--now-unix",
            str(NOW),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
