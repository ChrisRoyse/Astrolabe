#!/usr/bin/env python3
"""Provenance stamping for release-predicate artifacts (#88).

Every release-predicate artifact is an *attestation*: it claims that some gate
ran and passed. Before this module existed the artifacts carried no binding to
*what* was tested or *when*, so `release-predicate.py` could consume a green
artifact produced by an ancient run, by a different commit, or by a run that
died before its tests executed. That is the classic false-green
"attestation without execution" path.

The fix borrows the binding fields the software-supply-chain attestation
formats settled on (in-toto Statement / SLSA Provenance: a *subject* digest
plus *runDetails.metadata* start/finish timestamps -- see
https://slsa.dev/spec/v1.0/provenance). Our subject is the source tree, and its
digest is the git commit; our timestamp is the UTC instant the attesting gate
finished. Both are mandatory, and `release-predicate.py` fails closed when they
are missing, stale, mixed-vintage, or from the wrong commit.

Contract for producers:

    from release_artifact import write_artifact
    write_artifact(artifact_dir, "license-gate.json", payload)

`write_artifact` must be called *after* the attested work succeeded, never
before. A producer that writes its artifact up front re-introduces the exact
defect this module exists to close.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STAMP_SCHEMA = "astrolabe.release_artifact_stamp.v1"

ROOT = Path(__file__).resolve().parents[1]


def fail(code: str, message: str, remediation: str, details: dict[str, Any] | None = None) -> None:
    """Fail closed with the project's {code, message, remediation} error shape."""
    payload: dict[str, Any] = {"code": code, "message": message, "remediation": remediation}
    if details:
        payload["details"] = details
    print(f"ERROR: {json.dumps(payload, sort_keys=True)}", file=sys.stderr)
    raise SystemExit(1)


def git_commit(root: Path | None = None) -> tuple[str, bool]:
    """Return (commit_sha, dirty) for the checkout that produced this artifact.

    Fails closed: an artifact that cannot name its subject commit is not an
    attestation, and must not be written.
    """
    cwd = root or ROOT
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if head.returncode != 0:
        fail(
            "RELEASE_ARTIFACT_NO_COMMIT",
            "cannot resolve the git commit that a release-predicate artifact would attest",
            "run the gate from the Astrolabe git checkout so the artifact can be bound to HEAD",
            {"stderr": head.stderr.strip(), "cwd": str(cwd)},
        )
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if status.returncode != 0:
        fail(
            "RELEASE_ARTIFACT_NO_STATUS",
            "cannot determine whether the working tree is clean",
            "run the gate from a readable git checkout",
            {"stderr": status.stderr.strip(), "cwd": str(cwd)},
        )
    return head.stdout.strip(), bool(status.stdout.strip())


def stamp(payload: dict[str, Any], root: Path | None = None) -> dict[str, Any]:
    """Bind an artifact payload to its subject commit and generation instant."""
    commit, dirty = git_commit(root)
    now = time.time()
    stamped = dict(payload)
    stamped["stamp_schema"] = STAMP_SCHEMA
    stamped["commit"] = commit
    stamped["commit_dirty"] = dirty
    stamped["generated_at_unix"] = int(now)
    stamped["generated_at_utc"] = (
        datetime.fromtimestamp(int(now), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    )
    return stamped


def write_artifact(
    artifact_dir: Path,
    filename: str,
    payload: dict[str, Any],
    root: Path | None = None,
) -> Path:
    """Stamp and write a release-predicate artifact. Call only after the work passed."""
    artifact_dir = Path(artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    stamped = stamp(payload, root)
    path = artifact_dir / filename
    path.write_text(json.dumps(stamped, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(
        f"release artifact wrote: {path} "
        f"(commit={stamped['commit'][:12]} dirty={stamped['commit_dirty']} "
        f"at={stamped['generated_at_utc']})"
    )
    return path
