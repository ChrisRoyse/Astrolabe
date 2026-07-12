#!/usr/bin/env python3
"""Verify the L6 hazard suite manifest and, on request, EXECUTE it and publish its artifact.

#88: this gate used to write `verify-chain-soak.json` with `status: "pass"` after
nothing more than a manifest-existence check -- it grepped each source file for
`fn <name>(` and then declared the suite "paired with cargo test in
scripts/check.sh". That is attestation without execution: the artifact attested
nothing, and `release-predicate.py` consumed it as a satisfied conjunct.

The artifact is now written only after this script has *run* every manifest test
that the host can run, parsed libtest's own summary line, and required exactly
one passing, non-ignored test per manifest entry. A test that fails, is filtered
to zero, or is silently `#[ignore]`d fails the gate closed and leaves no
artifact on disk.

Two modes:

  * no flags            -- manifest lint only (schema, sources, evidence markers).
                           Cheap; safe to run early in an aggregate.
  * --write-release-artifact
                        -- lint, then execute every host-eligible manifest test
                           with cargo, then stamp and write the artifact.
                           MUST be wired AFTER the workspace test phase.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from release_artifact import fail, write_artifact  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "ci" / "hazard-suite.json"
RELEASE_PREDICATE = ROOT / "scripts" / "release-predicate.py"
DEFAULT_ARTIFACT_DIR = ROOT / "target" / "astrolabe-release-predicate"

# libtest's own summary line is the source of truth for "did this test run".
TEST_RESULT = re.compile(
    r"^test result: (?P<verdict>\w+)\. "
    r"(?P<passed>\d+) passed; (?P<failed>\d+) failed; (?P<ignored>\d+) ignored; "
    r"(?P<measured>\d+) measured; (?P<filtered>\d+) filtered out",
    re.MULTILINE,
)

PLATFORM_SKIP = "ASTRO_HAZARD_TEST_PLATFORM_SKIP"


def host_os() -> str:
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "darwin":
        return "macos"
    if system == "linux":
        return "linux"
    return system


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-release-artifact",
        action="store_true",
        help="Execute the manifest tests and write the verify_chain_soak artifact on success.",
    )
    parser.add_argument(
        "--artifact-dir",
        default=str(DEFAULT_ARTIFACT_DIR),
        help="Release predicate artifact directory.",
    )
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST),
        help="Hazard suite manifest (default ci/hazard-suite.json).",
    )
    parser.add_argument(
        "--root",
        default=str(ROOT),
        help="Repository root the manifest paths resolve against.",
    )
    parser.add_argument(
        "--cargo",
        default=os.environ.get("CARGO", "cargo"),
        help="Cargo binary used to execute the manifest tests.",
    )
    parser.add_argument(
        "--test-timeout-secs",
        type=int,
        default=int(os.environ.get("ASTROLABE_HAZARD_TEST_TIMEOUT_SECS", "1800")),
        help="Per-test execution deadline.",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    manifest_path = Path(args.manifest).resolve()
    manifest = load_manifest(manifest_path)

    checked = [check_test(root, test) for test in manifest["tests"]]

    if not args.write_release_artifact:
        print(f"hazard suite manifest verified: {len(checked)} tests (no execution requested)")
        return 0

    artifact_dir = Path(args.artifact_dir)
    release_name = manifest["release_artifact"]

    # #60/#88 fail-closed sentinel. Before executing a single test, atomically
    # replace whatever artifact a prior run left with an explicit non-"pass"
    # status. Two false-green paths close here:
    #   * A run that begins and then dies mid-suite -- process kill, power loss,
    #     or a test that hangs and never returns -- would otherwise leave the
    #     PREVIOUS run's "pass" on disk. The predicate binds artifacts to HEAD
    #     and a freshness window, so a same-commit re-run inside that window
    #     could replay that stale green. After this write, an interrupted run
    #     leaves "incomplete", never "pass".
    #   * A definitively failed/ambiguous test aborts via fail() below without
    #     overwriting this sentinel, so the artifact still reads non-"pass".
    # release-predicate.py treats any non-pass/non-waived status as a failed
    # conjunct, so neither path can be mistaken for a proven suite.
    write_incomplete_sentinel(artifact_dir, release_name, manifest, checked, root)
    _selftest_pause_after_sentinel()

    executed, skipped = execute_suite(root, args, manifest["tests"])
    if not executed:
        fail(
            "hazard.no_tests_executed",
            "the hazard suite attested nothing: no manifest test was executed on this host",
            "run the gate on a host that can execute at least one hazard test, or fix the "
            "manifest's target_os declarations",
            {"host_os": host_os(), "skipped": len(skipped)},
        )

    artifact = {
        "schema": "astrolabe.verify_chain_soak.v1",
        "status": "pass",
        "source": "scripts/check-hazard-suite.py",
        "release_predicate_key": manifest["release_predicate_key"],
        "cadence": manifest["cadence"],
        "checked_tests": checked,
        "executed_tests": executed,
        "skipped_tests": skipped,
        "host_os": host_os(),
        "cargo": args.cargo,
        "execution": (
            "scripts/check-hazard-suite.py executed each manifest test with "
            "cargo test and required exactly one passing, non-ignored test per entry"
        ),
    }
    write_artifact(artifact_dir, release_name, artifact, root)

    for entry in skipped:
        print(
            f"SKIP[{PLATFORM_SKIP}]: {entry['id']} declares target_os="
            f"{entry['target_os']} and did not run on {host_os()}"
        )
    print(
        f"hazard suite executed: {len(executed)} tests passed, "
        f"{len(skipped)} skipped (platform), {len(checked)} in manifest"
    )
    return 0


def write_incomplete_sentinel(
    artifact_dir: Path,
    filename: str,
    manifest: dict[str, Any],
    checked: list[dict[str, Any]],
    root: Path,
) -> None:
    """Stamp an explicit non-"pass" artifact before any test executes (#60/#88).

    This is deliberately written *up front* -- the one case where writing before
    the work is correct, because its status is the opposite of a false-green: it
    fails the release predicate closed. It is overwritten with the "pass" artifact
    only after every host-eligible test has actually passed.
    """
    write_artifact(
        artifact_dir,
        filename,
        {
            "schema": "astrolabe.verify_chain_soak.v1",
            "status": "incomplete",
            "reason": (
                "hazard suite execution started but has not completed; a persisting "
                "'incomplete' status means the run died mid-suite (crash, kill, hang) "
                "or a test failed, and the suite proved nothing"
            ),
            "source": "scripts/check-hazard-suite.py",
            "release_predicate_key": manifest["release_predicate_key"],
            "cadence": manifest["cadence"],
            "checked_tests": checked,
            "host_os": host_os(),
        },
        root,
    )


def _selftest_pause_after_sentinel() -> None:
    """Deterministic mid-run-death hook for scripts/test-check-hazard-suite.py.

    Inert in production: without ASTROLABE_HAZARD_SELFTEST_PAUSE_AFTER_SENTINEL the
    gate returns immediately. When that variable names a path, the gate has just
    written its "incomplete" sentinel; it touches that path (so the self-test knows
    the sentinel is on disk) and then blocks forever, with no cargo child yet
    spawned. The self-test kills it here to reproduce a process that dies AFTER the
    sentinel is written but BEFORE the suite completes, and proves the artifact left
    behind is "incomplete", never a stale "pass". This mirrors the env-gated crash
    failpoints the Calyx vault uses for its own crash-FSV tests.
    """
    ready = os.environ.get("ASTROLABE_HAZARD_SELFTEST_PAUSE_AFTER_SENTINEL")
    if not ready:
        return
    Path(ready).write_text("paused\n", encoding="utf-8")
    while True:
        time.sleep(3600)


def load_manifest(manifest_path: Path) -> dict[str, Any]:
    if not manifest_path.exists():
        fail(
            "hazard.missing_manifest",
            "hazard suite manifest is missing",
            "restore ci/hazard-suite.json",
            {"path": str(manifest_path)},
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(
            "hazard.invalid_json",
            "hazard suite manifest is not valid JSON",
            "fix ci/hazard-suite.json so it parses",
            {"path": str(manifest_path), "error": str(exc)},
        )
    if manifest.get("schema_version") != "astrolabe.hazard_suite.v1":
        fail(
            "hazard.schema",
            "hazard manifest has wrong schema_version",
            "set schema_version to astrolabe.hazard_suite.v1",
        )
    if manifest.get("release_predicate_key") != "verify_chain_soak":
        fail(
            "hazard.predicate_key",
            "hazard manifest must publish verify_chain_soak",
            "set release_predicate_key to verify_chain_soak",
        )
    release_artifact = manifest.get("release_artifact")
    if release_artifact != "verify-chain-soak.json":
        fail(
            "hazard.artifact_name",
            "hazard manifest must publish verify-chain-soak.json",
            "set release_artifact to verify-chain-soak.json",
        )
    if release_artifact not in RELEASE_PREDICATE.read_text(encoding="utf-8"):
        fail(
            "hazard.predicate_unwired",
            "release predicate does not reference verify-chain-soak.json",
            "add the verify_chain_soak conjunct to scripts/release-predicate.py",
        )
    if not isinstance(manifest.get("tests"), list) or not manifest["tests"]:
        fail(
            "hazard.no_tests",
            "hazard manifest declares no tests",
            "add at least one hazard test entry to ci/hazard-suite.json",
        )
    return manifest


def check_test(root: Path, test: dict[str, Any]) -> dict[str, Any]:
    required = ["id", "crate", "file", "test", "kind", "evidence"]
    missing = [key for key in required if key not in test]
    if missing:
        fail(
            "hazard.malformed_test",
            f"hazard test entry missing {', '.join(missing)}",
            "every hazard test entry needs id, crate, file, test, kind, evidence",
            {"test": test},
        )

    source_path = root / test["file"]
    if not source_path.exists():
        fail(
            "hazard.missing_source",
            "hazard test source does not exist",
            "correct the manifest file path or restore the test source",
            {"file": test["file"]},
        )
    source = source_path.read_text(encoding="utf-8")
    test_name = test["test"].split("::")[-1]
    if not re.search(rf"\bfn\s+{re.escape(test_name)}\s*\(", source):
        fail(
            "hazard.missing_test_fn",
            f"hazard test {test_name} not found in {test['file']}",
            "restore the test function or correct the manifest entry",
            {"file": test["file"], "test": test_name},
        )
    for marker in test["evidence"]:
        if marker not in source:
            fail(
                "hazard.missing_evidence_marker",
                f"hazard test {test_name} missing evidence marker {marker!r}",
                "restore the evidence assertion or correct the manifest entry",
                {"file": test["file"], "marker": marker},
            )

    return {
        "id": test["id"],
        "crate": test["crate"],
        "test": test["test"],
        "kind": test["kind"],
        "target_os": test.get("target_os", "all"),
    }


def execute_suite(
    root: Path, args: argparse.Namespace, tests: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    executed: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    this_os = host_os()
    for test in tests:
        target_os = test.get("target_os", "all")
        if target_os not in ("all", this_os):
            skipped.append(
                {
                    "id": test["id"],
                    "crate": test["crate"],
                    "test": test["test"],
                    "target_os": target_os,
                    "code": PLATFORM_SKIP,
                    "reason": f"manifest declares target_os={target_os}; host is {this_os}",
                }
            )
            continue
        executed.append(execute_test(root, args, test))
    return executed, skipped


def execute_test(root: Path, args: argparse.Namespace, test: dict[str, Any]) -> dict[str, Any]:
    test_name = test["test"].split("::")[-1]
    # The manifest records a bare test-fn name, not its full module path, so an
    # `--exact` filter cannot be constructed from it. We filter by name and then
    # require libtest's summary to report exactly one passing, non-ignored test:
    # that proves both that the filter was unambiguous and that the test ran.
    command = [
        args.cargo,
        "test",
        "-p",
        test["crate"],
        "--lib",
        "--",
        "--nocapture",
        test_name,
    ]

    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            cwd=root,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=args.test_timeout_secs,
            check=False,
        )
    except FileNotFoundError:
        fail(
            "hazard.cargo_missing",
            f"cargo binary not found: {args.cargo}",
            "install the pinned toolchain or pass --cargo with an explicit path",
            {"cargo": args.cargo},
        )
    except subprocess.TimeoutExpired:
        fail(
            "hazard.test_timeout",
            f"hazard test {test['id']} exceeded the {args.test_timeout_secs}s deadline",
            "raise ASTROLABE_HAZARD_TEST_TIMEOUT_SECS or fix the hanging hazard test",
            {"id": test["id"], "command": command},
        )
    duration = round(time.monotonic() - started, 3)
    output = proc.stdout or ""

    if proc.returncode != 0:
        fail(
            "hazard.test_failed",
            f"hazard test {test['id']} ({test['test']}) failed; "
            "the verify_chain_soak artifact was NOT written",
            "fix the failing hazard test; the release predicate must never consume an "
            "artifact for a suite that did not pass",
            {
                "id": test["id"],
                "command": command,
                "returncode": proc.returncode,
                "output_tail": output[-2000:],
            },
        )

    matches = TEST_RESULT.findall(output)
    summary = parse_summary(output)
    if summary is None:
        fail(
            "hazard.no_test_summary",
            f"hazard test {test['id']} produced no libtest summary line; "
            "execution cannot be attested",
            "confirm the crate and test name in ci/hazard-suite.json resolve to a real "
            "unit test in that crate's lib target",
            {"id": test["id"], "command": command, "output_tail": output[-2000:]},
        )
    if summary["passed"] != 1 or summary["failed"] != 0 or summary["ignored"] != 0:
        fail(
            "hazard.ambiguous_execution",
            f"hazard test {test['id']} did not resolve to exactly one passing, "
            f"non-ignored test (passed={summary['passed']} failed={summary['failed']} "
            f"ignored={summary['ignored']})",
            "make the manifest test name select exactly one #[test] fn in the crate's lib "
            "target, and remove any #[ignore] from it",
            {"id": test["id"], "command": command, "summary": summary},
        )

    print(
        f"hazard test executed: {test['id']} ({test['crate']}::{test_name}) "
        f"passed in {duration}s"
    )
    return {
        "id": test["id"],
        "crate": test["crate"],
        "test": test["test"],
        "kind": test["kind"],
        "target_os": test.get("target_os", "all"),
        "command": command,
        "returncode": proc.returncode,
        "libtest_summary": summary,
        "summary_lines": len(matches),
        "duration_secs": duration,
    }


def parse_summary(output: str) -> dict[str, int] | None:
    """Return the counts from the libtest summary line that actually ran tests.

    `cargo test --lib` prints one summary per test binary. The crate's lib target
    is the only binary here, but doctest/other summaries with zero tests must not
    mask the real one, so the summary with a nonzero passed+failed+ignored count
    wins; if none exists the first summary is returned so the caller fails closed
    on a zero-execution filter.
    """
    summaries: list[dict[str, int]] = []
    for match in TEST_RESULT.finditer(output):
        summaries.append(
            {
                "passed": int(match.group("passed")),
                "failed": int(match.group("failed")),
                "ignored": int(match.group("ignored")),
                "measured": int(match.group("measured")),
                "filtered_out": int(match.group("filtered")),
            }
        )
    if not summaries:
        return None
    for summary in summaries:
        if summary["passed"] + summary["failed"] + summary["ignored"] > 0:
            return summary
    return summaries[0]


if __name__ == "__main__":
    raise SystemExit(main())
