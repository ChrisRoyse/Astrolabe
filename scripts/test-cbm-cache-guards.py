#!/usr/bin/env python3
"""Regression for the CBM store hermeticity guards (#194/#232).

A gate that has never failed is not a gate. This exercises both halves against
isolated fixture roots — never the live workspace or the operator's store:

* `check-cbm-cache-paths.py` must accept the pinned vendor tree, and must fail
  closed with ASTRO_CBM_CACHE_PATH_DRIFT the moment a new hand-built
  `$HOME/.cache/codebase-memory-mcp` path appears in it.
* `check-cbm-cache-hermeticity.py` must accept an unchanged store, fail closed
  with ASTRO_CBM_CACHE_LEAK on a single added registration, tolerate transient
  SQLite sidecar churn, and refuse an empty run-scoped store
  (ASTRO_CBM_RUN_SCOPED_STORE_EMPTY) so a silently no-op'ing suite cannot pass.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATHS_GATE = ROOT / "scripts" / "check-cbm-cache-paths.py"
STORE_GATE = ROOT / "scripts" / "check-cbm-cache-hermeticity.py"
MANIFEST = ROOT / "ci" / "cbm-cache-path-offenders.md"
CBM = ROOT / "vendor" / "codebase-memory-mcp"

HAND_BUILT_PATH = (
    'snprintf(cache_dir, sizeof(cache_dir), "%s/.cache/codebase-memory-mcp", getenv("HOME"));'
)


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"CBM cache guard regression failed: {message}")


def expect_code(result: subprocess.CompletedProcess[str], code: str) -> None:
    require(result.returncode != 0, f"expected a fail-closed exit for {code}, got 0")
    require(
        code in result.stderr,
        f"expected {code} in stderr, got:\n{result.stderr}\n{result.stdout}",
    )
    require(
        "remediation:" in result.stderr,
        f"{code} must carry a remediation line, got:\n{result.stderr}",
    )


def check_paths_gate(tmp: Path) -> None:
    clean = run([str(PATHS_GATE)])
    require(
        clean.returncode == 0,
        f"pinned vendor tree must satisfy the manifest, got:\n{clean.stderr}{clean.stdout}",
    )

    # Isolated copy of the pinned tree: the gate must fire on a NEW offender
    # without the live vendor subtree ever being written.
    fixture = tmp / "cbm"
    for subtree in ("src", "tests", "internal", "scripts"):
        base = CBM / subtree
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.suffix not in (".c", ".h", ".cpp", ".sh") or not path.is_file():
                continue
            rel = path.relative_to(CBM)
            if "vendored" in rel.parts:
                continue
            (fixture / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, fixture / rel)

    baseline = run([str(PATHS_GATE), "--cbm-root", str(fixture), "--manifest", str(MANIFEST)])
    require(
        baseline.returncode == 0,
        f"fixture copy of the pinned tree must satisfy the manifest, got:\n{baseline.stderr}",
    )

    # A regression: one more test file rebuilds the store path by hand.
    offender = fixture / "tests" / "test_new_probe.c"
    offender.write_text(
        "#include <stdio.h>\nvoid setup(void) {\n    char cache_dir[1024];\n    "
        + HAND_BUILT_PATH
        + "\n}\n",
        encoding="utf-8",
    )
    fired = run([str(PATHS_GATE), "--cbm-root", str(fixture), "--manifest", str(MANIFEST)])
    expect_code(fired, "ASTRO_CBM_CACHE_PATH_DRIFT")
    require(
        "tests/test_new_probe.c" in fired.stderr,
        f"drift report must name the new offender, got:\n{fired.stderr}",
    )
    offender.unlink()

    # A removal is drift too: the manifest is an exact record, not a ceiling.
    (fixture / "tests" / "test_integration.c").unlink()
    shrunk = run([str(PATHS_GATE), "--cbm-root", str(fixture), "--manifest", str(MANIFEST)])
    expect_code(shrunk, "ASTRO_CBM_CACHE_PATH_DRIFT")

    require(
        (CBM / "tests" / "test_integration.c").is_file(),
        "the regression must never write to the pinned vendor subtree",
    )


def check_store_gate(tmp: Path) -> None:
    store = tmp / "store"
    store.mkdir(parents=True)
    (store / "_config.db").write_bytes(b"config-bytes")
    (store / "C-code-Real-Project.db").write_bytes(b"operator-project-bytes")

    before = tmp / "before.manifest"
    snap = run([str(STORE_GATE), "snapshot", "--cache-dir", str(store), "--out", str(before)])
    require(snap.returncode == 0, f"snapshot must succeed, got:\n{snap.stderr}")
    require(
        "registrations  : 2" in snap.stdout,
        f"snapshot must count both registrations, got:\n{snap.stdout}",
    )

    unchanged = run([str(STORE_GATE), "verify", "--cache-dir", str(store), "--before", str(before)])
    require(
        unchanged.returncode == 0,
        f"an untouched store must verify clean, got:\n{unchanged.stderr}",
    )

    # Sidecar churn from a live operator-owned server is not a registration.
    (store / "C-code-Real-Project.db-wal").write_bytes(b"wal")
    churn = run([str(STORE_GATE), "verify", "--cache-dir", str(store), "--before", str(before)])
    require(
        churn.returncode == 0,
        f"sidecar churn must not fail the gate, got:\n{churn.stderr}",
    )
    require(
        "ASTRO_CBM_CACHE_SIDECAR_CHURN" in churn.stdout,
        f"sidecar churn must be reported, got:\n{churn.stdout}",
    )

    # One leaked fixture registration is a hard failure.
    leaked = store / "C-code-Astrolabe-.tmp-cbm_excl_a00001.db"
    leaked.write_bytes(b"leaked-fixture-index")
    fired = run([str(STORE_GATE), "verify", "--cache-dir", str(store), "--before", str(before)])
    expect_code(fired, "ASTRO_CBM_CACHE_LEAK")
    require(
        "cbm_excl_a00001.db" in fired.stderr,
        f"leak report must name the offending db, got:\n{fired.stderr}",
    )
    leaked.unlink()

    # A modified operator project is a leak too (an index that overwrote it).
    (store / "C-code-Real-Project.db").write_bytes(b"clobbered")
    clobbered = run([str(STORE_GATE), "verify", "--cache-dir", str(store), "--before", str(before)])
    expect_code(clobbered, "ASTRO_CBM_CACHE_LEAK")

    # And the run-scoped store must prove the suite really wrote to it.
    empty = tmp / "run-scoped"
    empty.mkdir(parents=True)
    silent = run([str(STORE_GATE), "require-writes", "--cache-dir", str(empty)])
    expect_code(silent, "ASTRO_CBM_RUN_SCOPED_STORE_EMPTY")

    (empty / "C-code-Astrolabe-.tmp-cbm_test_a00001.db").write_bytes(b"fixture-index")
    wrote = run([str(STORE_GATE), "require-writes", "--cache-dir", str(empty)])
    require(wrote.returncode == 0, f"a written run-scoped store must pass, got:\n{wrote.stderr}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="astro-cbm-cache-guard-") as raw:
        tmp = Path(raw)
        check_paths_gate(tmp / "paths")
        check_store_gate(tmp / "store-gate")
    print("CBM cache hermeticity guard regression passed")


if __name__ == "__main__":
    main()
