#!/usr/bin/env python3
"""Verify the L6 hazard suite manifest and optionally publish its release artifact."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "ci" / "hazard-suite.json"
RELEASE_PREDICATE = ROOT / "scripts" / "release-predicate.py"
DEFAULT_ARTIFACT_DIR = ROOT / "target" / "astrolabe-release-predicate"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-release-artifact",
        action="store_true",
        help="Write target/astrolabe-release-predicate/verify-chain-soak.json.",
    )
    parser.add_argument(
        "--artifact-dir",
        default=str(DEFAULT_ARTIFACT_DIR),
        help="Release predicate artifact directory.",
    )
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "astrolabe.hazard_suite.v1":
        print("hazard manifest has wrong schema_version", file=sys.stderr)
        return 1
    if manifest.get("release_predicate_key") != "verify_chain_soak":
        print("hazard manifest must publish verify_chain_soak", file=sys.stderr)
        return 1

    release_artifact = manifest.get("release_artifact")
    if release_artifact != "verify-chain-soak.json":
        print("hazard manifest must publish verify-chain-soak.json", file=sys.stderr)
        return 1
    if release_artifact not in RELEASE_PREDICATE.read_text(encoding="utf-8"):
        print("release predicate does not reference verify-chain-soak.json", file=sys.stderr)
        return 1

    checked = []
    for test in manifest.get("tests", []):
        checked.append(check_test(test))

    if args.write_release_artifact:
        artifact_dir = Path(args.artifact_dir)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact = {
            "schema": "astrolabe.verify_chain_soak.v1",
            "status": "pass",
            "source": "scripts/check-hazard-suite.py",
            "release_predicate_key": manifest["release_predicate_key"],
            "cadence": manifest["cadence"],
            "checked_tests": checked,
            "execution": "paired with cargo test in scripts/check.sh",
        }
        (artifact_dir / release_artifact).write_text(
            json.dumps(artifact, sort_keys=True, indent=2),
            encoding="utf-8",
        )

    print(f"hazard suite manifest verified: {len(checked)} tests")
    return 0


def check_test(test: dict[str, Any]) -> dict[str, Any]:
    required = ["id", "crate", "file", "test", "kind", "evidence"]
    missing = [key for key in required if key not in test]
    if missing:
        fail(f"hazard test entry missing {', '.join(missing)}: {test!r}")

    source_path = ROOT / test["file"]
    if not source_path.exists():
        fail(f"hazard test source does not exist: {test['file']}")
    source = source_path.read_text(encoding="utf-8")
    test_name = test["test"].split("::")[-1]
    if not re.search(rf"\bfn\s+{re.escape(test_name)}\s*\(", source):
        fail(f"hazard test {test_name} not found in {test['file']}")
    for marker in test["evidence"]:
        if marker not in source:
            fail(f"hazard test {test_name} missing evidence marker {marker!r}")

    return {
        "id": test["id"],
        "crate": test["crate"],
        "test": test["test"],
        "kind": test["kind"],
        "target_os": test.get("target_os", "all"),
    }


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    raise SystemExit(main())

