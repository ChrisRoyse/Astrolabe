#!/usr/bin/env python3
"""Evaluate the ASTROLABE_DONE release predicate from published artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Conjunct:
    key: str
    label: str
    filename: str
    waivable: bool = False


CONJUNCTS: tuple[Conjunct, ...] = (
    Conjunct("agent_eval_l7", "L7 agent eval comparison", "agent-eval-l7.json"),
    Conjunct("inherited_gates", "Inherited gates", "inherited-gates.json"),
    Conjunct("l1_l4", "L1-L4 verification gates", "l1-l4.json"),
    Conjunct("l5_baselines", "L5 baselines", "l5-baselines.json", waivable=True),
    Conjunct("bench_ratios", "Bench overhead ratios", "bench-ratios.json"),
    Conjunct("verify_chain_soak", "verify_chain soak", "verify-chain-soak.json"),
    Conjunct("parity_dashboard", "Parity dashboard", "parity-dashboard.json"),
    Conjunct("license_gate", "License notices", "license-gate.json"),
    Conjunct("nightly_reproduce_sample", "Nightly reproduce sample", "reproduce-sample.json"),
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifacts",
        default=None,
        help="Directory containing release predicate JSON artifacts.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON verdict instead of text.",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    artifact_dir = Path(args.artifacts or "target/astrolabe-release-predicate").resolve()
    verdict = evaluate(root, artifact_dir)
    if args.json:
        print(json.dumps(verdict, sort_keys=True, indent=2))
    elif verdict["status"] == "pass":
        print("ASTROLABE_DONE: pass")
        for waiver in verdict["active_waivers"]:
            print(f"WAIVER {waiver['key']}: {waiver['body']}")
    else:
        print(
            f"ASTROLABE_DONE: fail {verdict['failing_key']}: {verdict['reason']}",
            file=sys.stderr,
        )
    return 0 if verdict["status"] == "pass" else 1


def evaluate(root: Path, artifact_dir: Path) -> dict[str, Any]:
    active_waivers: list[dict[str, str]] = []
    checked: list[dict[str, Any]] = []

    for conjunct in CONJUNCTS:
        path = artifact_dir / conjunct.filename
        if not path.exists():
            return failure(conjunct, f"missing artifact {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return failure(conjunct, f"invalid JSON in {path}: {exc}")

        status = data.get("status")
        if status == "pass":
            checked.append({"key": conjunct.key, "status": "pass", "artifact": str(path)})
            continue
        if status == "waived":
            if not conjunct.waivable:
                return failure(conjunct, "waiver is not allowed for this conjunct")
            waiver = load_waiver(root, artifact_dir, conjunct, data)
            if "error" in waiver:
                return failure(conjunct, waiver["error"])
            active_waivers.append(waiver)
            checked.append({"key": conjunct.key, "status": "waived", "artifact": str(path)})
            continue

        reason = data.get("reason") or f"artifact status is {status!r}"
        if data.get("answer_id") and data.get("code"):
            reason = f"{data['code']} answer_id={data['answer_id']}: {reason}"
        return failure(conjunct, reason)

    return {
        "schema": "astrolabe.release_predicate.v1",
        "status": "pass",
        "checked": checked,
        "active_waivers": active_waivers,
    }


def failure(conjunct: Conjunct, reason: str) -> dict[str, Any]:
    return {
        "schema": "astrolabe.release_predicate.v1",
        "status": "fail",
        "failing_key": conjunct.key,
        "failing_label": conjunct.label,
        "reason": reason,
        "active_waivers": [],
    }


def load_waiver(
    root: Path,
    artifact_dir: Path,
    conjunct: Conjunct,
    data: dict[str, Any],
) -> dict[str, str]:
    waiver_file = data.get("waiver_file")
    if not waiver_file:
        return {"error": "waiver_file is required for waived L5 baselines"}
    candidates = [Path(waiver_file)]
    if not Path(waiver_file).is_absolute():
        candidates = [artifact_dir / waiver_file, root / waiver_file]
    waiver_path = next((candidate for candidate in candidates if candidate.exists()), None)
    if waiver_path is None:
        return {"error": f"waiver file not found: {waiver_file}"}
    body = waiver_path.read_text(encoding="utf-8").strip()
    if not body:
        return {"error": f"waiver file is empty: {waiver_file}"}
    published_numbers = data.get("published_numbers")
    if not isinstance(published_numbers, dict) or not published_numbers:
        return {"error": "waived L5 baselines require published_numbers"}
    return {
        "key": conjunct.key,
        "file": str(waiver_path),
        "body": body,
        "published_numbers": json.dumps(published_numbers, sort_keys=True),
    }


if __name__ == "__main__":
    raise SystemExit(main())
