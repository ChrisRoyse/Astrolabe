#!/usr/bin/env python3
"""Evaluate the ASTROLABE_DONE release predicate from published artifacts.

#88: an artifact is an attestation, and an attestation that is not bound to a
subject and an instant proves nothing. Before every conjunct is read for its
`status`, each artifact must present the stamp written by
`scripts/release_artifact.py`:

  * `commit`             -- the subject commit the gate ran against
  * `commit_dirty`       -- whether that tree had uncommitted changes
  * `generated_at_unix`  -- when the attesting gate finished

Four fail-closed rejections apply *before* status is considered, because a green
`status` in an unbound artifact is exactly the false-green this predicate exists
to prevent:

  RELEASE_PREDICATE_UNSTAMPED        artifact carries no commit/timestamp binding
  RELEASE_PREDICATE_WRONG_COMMIT     artifact attests a different commit than HEAD
  RELEASE_PREDICATE_STALE_ARTIFACT   artifact is older than --max-age-secs
  RELEASE_PREDICATE_MIXED_VINTAGE    artifacts span more than --max-vintage-spread-secs
  RELEASE_PREDICATE_FUTURE_ARTIFACT  artifact is stamped in the future (clock skew/forgery)

The design follows the binding that in-toto/SLSA provenance settled on: a
subject digest (here, the git commit) plus run metadata timestamps
(https://slsa.dev/spec/v1.0/provenance).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
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

# Registry-declared freshness knobs (standing invariant 4). A native aggregate
# plus release build is a multi-hour run, so the vintage spread must tolerate a
# long but bounded single run; the max age bounds how long a completed run's
# artifacts may be replayed.
DEFAULT_MAX_AGE_SECS = 86_400  # 24h: a day-old artifact set is not release evidence.
DEFAULT_MAX_VINTAGE_SPREAD_SECS = 43_200  # 12h: one contiguous native release gate.
DEFAULT_FUTURE_SKEW_SECS = 300  # 5m of tolerated clock skew.


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
    parser.add_argument(
        "--commit",
        default=None,
        help="Subject commit every artifact must attest (default: git rev-parse HEAD).",
    )
    parser.add_argument(
        "--max-age-secs",
        type=int,
        default=DEFAULT_MAX_AGE_SECS,
        help="Reject artifacts older than this many seconds.",
    )
    parser.add_argument(
        "--max-vintage-spread-secs",
        type=int,
        default=DEFAULT_MAX_VINTAGE_SPREAD_SECS,
        help="Reject an artifact set whose oldest and newest stamps differ by more than this.",
    )
    parser.add_argument(
        "--now-unix",
        type=int,
        default=None,
        help="Evaluation instant (default: now). Present so freshness itself is testable.",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    artifact_dir = Path(args.artifacts or "target/astrolabe-release-predicate").resolve()
    commit = args.commit or head_commit(root)
    now = args.now_unix if args.now_unix is not None else int(time.time())

    verdict = evaluate(
        root,
        artifact_dir,
        commit=commit,
        now=now,
        max_age_secs=args.max_age_secs,
        max_vintage_spread_secs=args.max_vintage_spread_secs,
    )
    if args.json:
        print(json.dumps(verdict, sort_keys=True, indent=2))
    elif verdict["status"] == "pass":
        print(f"ASTROLABE_DONE: pass (subject commit {verdict['commit']})")
        for note in verdict["notes"]:
            print(note)
        for waiver in verdict["active_waivers"]:
            print(f"WAIVER {waiver['key']}: {waiver['body']}")
    else:
        print(
            f"ASTROLABE_DONE: fail {verdict['failing_key']}: {verdict['reason']}",
            file=sys.stderr,
        )
        print(f"ERROR: {json.dumps(verdict['error'], sort_keys=True)}", file=sys.stderr)
    return 0 if verdict["status"] == "pass" else 1


def head_commit(root: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        print(
            "ERROR: "
            + json.dumps(
                {
                    "code": "RELEASE_PREDICATE_NO_COMMIT",
                    "message": "cannot resolve HEAD, so no artifact can be bound to a subject",
                    "remediation": "run the predicate inside the Astrolabe git checkout, "
                    "or pass --commit explicitly",
                    "details": {"stderr": proc.stderr.strip()},
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(2)
    return proc.stdout.strip()


def evaluate(
    root: Path,
    artifact_dir: Path,
    *,
    commit: str,
    now: int,
    max_age_secs: int,
    max_vintage_spread_secs: int,
) -> dict[str, Any]:
    active_waivers: list[dict[str, str]] = []
    checked: list[dict[str, Any]] = []
    stamps: list[tuple[str, int]] = []
    dirty_keys: list[str] = []

    for conjunct in CONJUNCTS:
        path = artifact_dir / conjunct.filename
        if not path.exists():
            return failure(
                conjunct,
                "RELEASE_PREDICATE_MISSING_ARTIFACT",
                f"missing artifact {path}",
                "run the gate that publishes this conjunct; the predicate never "
                "assumes an unpublished conjunct passed",
                commit,
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return failure(
                conjunct,
                "RELEASE_PREDICATE_INVALID_JSON",
                f"invalid JSON in {path}: {exc}",
                "re-run the publishing gate; a truncated artifact is not evidence",
                commit,
            )

        binding = check_binding(
            conjunct,
            path,
            data,
            commit=commit,
            now=now,
            max_age_secs=max_age_secs,
        )
        if binding is not None:
            return binding
        stamps.append((conjunct.key, int(data["generated_at_unix"])))
        if data.get("commit_dirty"):
            dirty_keys.append(conjunct.key)

        status = data.get("status")
        if status == "pass":
            checked.append(record(conjunct, "pass", path, data))
            continue
        if status == "waived":
            if not conjunct.waivable:
                return failure(
                    conjunct,
                    "RELEASE_PREDICATE_WAIVER_NOT_ALLOWED",
                    "waiver is not allowed for this conjunct",
                    "fix the gate; only l5_baselines may be waived",
                    commit,
                )
            waiver = load_waiver(root, artifact_dir, conjunct, data)
            if "error" in waiver:
                return failure(
                    conjunct,
                    "RELEASE_PREDICATE_INVALID_WAIVER",
                    waiver["error"],
                    "publish a complete waiver: waiver_file plus published_numbers",
                    commit,
                )
            active_waivers.append(waiver)
            checked.append(record(conjunct, "waived", path, data))
            continue

        reason = data.get("reason") or f"artifact status is {status!r}"
        if data.get("answer_id") and data.get("code"):
            reason = f"{data['code']} answer_id={data['answer_id']}: {reason}"
        return failure(
            conjunct,
            "RELEASE_PREDICATE_CONJUNCT_FAILED",
            reason,
            "fix the failing gate and re-publish its artifact",
            commit,
        )

    spread = max(value for _, value in stamps) - min(value for _, value in stamps)
    if spread > max_vintage_spread_secs:
        oldest = min(stamps, key=lambda item: item[1])
        newest = max(stamps, key=lambda item: item[1])
        conjunct = next(item for item in CONJUNCTS if item.key == oldest[0])
        return failure(
            conjunct,
            "RELEASE_PREDICATE_MIXED_VINTAGE",
            f"artifact set spans {spread}s (limit {max_vintage_spread_secs}s): "
            f"{oldest[0]} is the oldest, {newest[0]} the newest",
            "publish every conjunct from one contiguous gate run; a mixed-vintage set "
            "means some conjunct was carried over from an earlier run",
            commit,
            details={"spread_secs": spread, "stamps": dict(stamps)},
        )

    notes: list[str] = []
    if dirty_keys:
        # Labeled and counted, never silent (standing invariant 3). The commit
        # hash does not fully identify a dirty tree's content; see the tracked
        # dirty-tree gap.
        notes.append(
            f"INFO[ASTRO_RELEASE_ARTIFACT_DIRTY_TREE]: {len(dirty_keys)} artifact(s) were "
            f"stamped from a dirty working tree ({', '.join(sorted(dirty_keys))}); the commit "
            "hash does not fully identify the tested content"
        )

    return {
        "schema": "astrolabe.release_predicate.v1",
        "status": "pass",
        "commit": commit,
        "evaluated_at_unix": now,
        "vintage_spread_secs": spread,
        "dirty_artifacts": sorted(dirty_keys),
        "notes": notes,
        "checked": checked,
        "active_waivers": active_waivers,
    }


def check_binding(
    conjunct: Conjunct,
    path: Path,
    data: dict[str, Any],
    *,
    commit: str,
    now: int,
    max_age_secs: int,
) -> dict[str, Any] | None:
    """Reject an artifact that is not bound to this commit and a fresh instant."""
    artifact_commit = data.get("commit")
    generated = data.get("generated_at_unix")
    if not isinstance(artifact_commit, str) or not artifact_commit:
        return failure(
            conjunct,
            "RELEASE_PREDICATE_UNSTAMPED",
            f"{path.name} carries no subject commit; it attests nothing",
            "publish this artifact through scripts/release_artifact.py so it is bound to "
            "the commit and instant of the run that produced it",
            commit,
            details={"artifact": str(path)},
        )
    if not isinstance(generated, int) or isinstance(generated, bool):
        return failure(
            conjunct,
            "RELEASE_PREDICATE_UNSTAMPED",
            f"{path.name} carries no integer generated_at_unix; its vintage is unknown",
            "publish this artifact through scripts/release_artifact.py so it is bound to "
            "the commit and instant of the run that produced it",
            commit,
            details={"artifact": str(path), "generated_at_unix": generated},
        )
    if artifact_commit != commit:
        return failure(
            conjunct,
            "RELEASE_PREDICATE_WRONG_COMMIT",
            f"{path.name} attests commit {artifact_commit} but the predicate is being "
            f"evaluated for {commit}",
            "re-run the publishing gate at this commit; an artifact from another commit "
            "says nothing about this tree",
            commit,
            details={"artifact": str(path), "artifact_commit": artifact_commit},
        )
    age = now - generated
    if age > max_age_secs:
        return failure(
            conjunct,
            "RELEASE_PREDICATE_STALE_ARTIFACT",
            f"{path.name} is {age}s old (limit {max_age_secs}s)",
            "re-run the publishing gate; a stale artifact may predate the failure you are "
            "about to ship",
            commit,
            details={"artifact": str(path), "age_secs": age, "max_age_secs": max_age_secs},
        )
    if age < -DEFAULT_FUTURE_SKEW_SECS:
        return failure(
            conjunct,
            "RELEASE_PREDICATE_FUTURE_ARTIFACT",
            f"{path.name} is stamped {-age}s in the future",
            "fix the clock on the publishing host, or investigate a hand-edited artifact",
            commit,
            details={"artifact": str(path), "age_secs": age},
        )
    return None


def record(conjunct: Conjunct, status: str, path: Path, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "key": conjunct.key,
        "status": status,
        "artifact": str(path),
        "commit": data["commit"],
        "commit_dirty": bool(data.get("commit_dirty")),
        "generated_at_unix": int(data["generated_at_unix"]),
        "generated_at_utc": data.get("generated_at_utc"),
    }


def failure(
    conjunct: Conjunct,
    code: str,
    reason: str,
    remediation: str,
    commit: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {
        "code": code,
        "message": f"{conjunct.key}: {reason}",
        "remediation": remediation,
    }
    if details:
        error["details"] = details
    return {
        "schema": "astrolabe.release_predicate.v1",
        "status": "fail",
        "commit": commit,
        "failing_key": conjunct.key,
        "failing_label": conjunct.label,
        "code": code,
        "reason": reason,
        "error": error,
        "notes": [],
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
