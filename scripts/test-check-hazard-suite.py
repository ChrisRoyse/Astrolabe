#!/usr/bin/env python3
"""Self-tests for scripts/check-hazard-suite.py (#88).

The defect this guards: check-hazard-suite used to publish
`verify-chain-soak.json` with `status: "pass"` after nothing more than a
manifest-existence check. The release predicate then consumed that artifact as a
satisfied conjunct. Attestation without execution is the classic false-green.

The control proof is therefore the whole test: point the gate at a REAL cargo
crate with a REAL failing test and require that NO artifact reaches disk; point
it at a passing test and require the artifact to carry the ACTUAL current commit.

No test doubles: this compiles and runs a real probe crate with a real cargo, and
every assertion is an independent read of the bytes on disk.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check-hazard-suite.py"
SCRATCH = ROOT / "target" / "hazard-suite-selftest"
CRATE = SCRATCH / "probe"
ARTIFACT_DIR = SCRATCH / "artifacts"
ARTIFACT = ARTIFACT_DIR / "verify-chain-soak.json"

CARGO_TOML = """\
[package]
name = "hazard_probe"
version = "0.0.0"
edition = "2021"
publish = false

[lib]
path = "src/lib.rs"

# Detached from the Astrolabe workspace: this probe exists only to give the
# hazard gate a real cargo target to execute.
[workspace]
"""

LIB_RS = """\
//! Probe crate for scripts/test-check-hazard-suite.py.

/// Stands in for a hazard test that passes and leaves its evidence markers.
#[test]
fn hazard_probe_passes() {
    let evidence = "CALYX_PROBE_EVIDENCE";
    assert_eq!(evidence, "CALYX_PROBE_EVIDENCE", "probe_rows");
}

/// Stands in for a hazard test that fails. The gate must publish no artifact.
#[test]
fn hazard_probe_fails() {
    let evidence = "CALYX_PROBE_EVIDENCE";
    assert_eq!(evidence, "probe_rows", "a real failing hazard test");
}

/// Stands in for a hazard test that is silently skipped. Attesting an ignored
/// test is the same false-green as attesting an unexecuted one.
#[test]
#[ignore]
fn hazard_probe_ignored() {
    let evidence = "CALYX_PROBE_EVIDENCE";
    assert_eq!(evidence, "CALYX_PROBE_EVIDENCE", "probe_rows");
}
"""


def manifest_for(test_name: str) -> dict:
    return {
        "schema_version": "astrolabe.hazard_suite.v1",
        "release_predicate_key": "verify_chain_soak",
        "release_artifact": "verify-chain-soak.json",
        "cadence": {"short": "nightly", "full": "weekly"},
        "tests": [
            {
                "id": f"probe_{test_name}",
                "crate": "hazard_probe",
                "file": "src/lib.rs",
                "test": test_name,
                "kind": "selftest_probe",
                "evidence": ["CALYX_PROBE_EVIDENCE", "probe_rows"],
            }
        ],
    }


def build_fixture() -> None:
    if SCRATCH.exists():
        shutil.rmtree(SCRATCH)
    (CRATE / "src").mkdir(parents=True)
    (CRATE / "Cargo.toml").write_text(CARGO_TOML, encoding="utf-8")
    (CRATE / "src" / "lib.rs").write_text(LIB_RS, encoding="utf-8")
    ARTIFACT_DIR.mkdir(parents=True)


def cargo_bin() -> str:
    for candidate in ("cargo", "cargo.exe"):
        found = shutil.which(candidate)
        if found:
            return found
    for base in (os.environ.get("USERPROFILE"), os.environ.get("HOME")):
        if not base:
            continue
        for name in ("cargo.exe", "cargo"):
            candidate_path = Path(base) / ".cargo" / "bin" / name
            if candidate_path.exists():
                return str(candidate_path)
    raise SystemExit(
        "ERROR: "
        + json.dumps(
            {
                "code": "hazard_selftest.cargo_missing",
                "message": "cargo is required: this self-test proves the hazard gate by "
                "executing a real crate, and refuses to substitute a stand-in",
                "remediation": "run the gate through the pinned toolchain launcher so cargo "
                "is on PATH",
            },
            sort_keys=True,
        )
    )


def run_gate(test_name: str, cargo: str) -> subprocess.CompletedProcess:
    manifest_path = SCRATCH / f"manifest-{test_name}.json"
    manifest_path.write_text(json.dumps(manifest_for(test_name), indent=2), encoding="utf-8")
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = str(SCRATCH / "cargo-target")
    return subprocess.run(
        [
            sys.executable,
            str(GATE),
            "--write-release-artifact",
            "--manifest",
            str(manifest_path),
            "--root",
            str(CRATE),
            "--artifact-dir",
            str(ARTIFACT_DIR),
            "--cargo",
            cargo,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


def head_commit() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()


def artifact_state() -> str:
    """Independent readback of the source of truth: the artifact file on disk."""
    if not ARTIFACT.exists():
        return "<no artifact on disk>"
    return ARTIFACT.read_text(encoding="utf-8")


def main() -> int:
    build_fixture()
    atexit.register(lambda: shutil.rmtree(SCRATCH, ignore_errors=True))
    cargo = cargo_bin()
    print(f"cargo: {cargo}")

    print("=== 1. CONTROL: the attested test FAILS -- no artifact may be published ===")
    print(f"  artifact before: {artifact_state()}")
    result = run_gate("hazard_probe_fails", cargo)
    if result.returncode == 0:
        raise AssertionError(f"gate passed a failing hazard test\n{result.stdout}{result.stderr}")
    if "hazard.test_failed" not in result.stderr:
        raise AssertionError(f"gate failed without the coded error\n{result.stderr}")
    print(f"  artifact after : {artifact_state()}")
    if ARTIFACT.exists():
        raise AssertionError("a failing hazard suite still published a pass artifact")
    print("  CONTROL PROOF: exit 1, hazard.test_failed, NO artifact on disk")

    print("=== 2. CONTROL: an #[ignore]d test cannot be attested ===")
    result = run_gate("hazard_probe_ignored", cargo)
    if result.returncode == 0 or "hazard.ambiguous_execution" not in result.stderr:
        raise AssertionError(f"gate attested an ignored test\n{result.stdout}{result.stderr}")
    if ARTIFACT.exists():
        raise AssertionError("an ignored hazard test still published a pass artifact")
    print("  CONTROL PROOF: exit 1, hazard.ambiguous_execution, NO artifact on disk")

    print("=== 3. the attested test PASSES -- artifact is published and commit-bound ===")
    before = int(time.time())
    result = run_gate("hazard_probe_passes", cargo)
    if result.returncode != 0:
        raise AssertionError(f"gate failed a passing hazard test\n{result.stdout}{result.stderr}")
    if not ARTIFACT.exists():
        raise AssertionError("a passing hazard suite published no artifact")

    # Independent readback: parse the bytes off disk, not the gate's stdout.
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    print(f"  artifact on disk: {ARTIFACT}")
    print(f"    commit            : {artifact.get('commit')}")
    print(f"    commit_dirty      : {artifact.get('commit_dirty')}")
    print(f"    generated_at_utc  : {artifact.get('generated_at_utc')}")
    print(f"    status            : {artifact.get('status')}")
    print(f"    executed_tests    : {json.dumps(artifact.get('executed_tests'), indent=6)[:400]}")

    commit = head_commit()
    if artifact.get("commit") != commit:
        raise AssertionError(
            f"artifact commit {artifact.get('commit')!r} != git rev-parse HEAD {commit!r}"
        )
    print(f"  commit field == git rev-parse HEAD ({commit})")
    if artifact.get("status") != "pass":
        raise AssertionError(f"artifact status is {artifact.get('status')!r}")
    generated = artifact.get("generated_at_unix")
    if not isinstance(generated, int) or generated < before - 5:
        raise AssertionError(f"artifact timestamp {generated} is not from this run")
    executed = artifact.get("executed_tests") or []
    if len(executed) != 1 or executed[0]["libtest_summary"]["passed"] != 1:
        raise AssertionError(f"artifact does not record a real execution: {executed}")
    if executed[0]["libtest_summary"]["ignored"] != 0:
        raise AssertionError("artifact attests an ignored test")

    shutil.rmtree(SCRATCH, ignore_errors=True)
    print("hazard suite self-test passed: no execution, no artifact; execution, commit-bound artifact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
