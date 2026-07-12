#!/usr/bin/env python3
"""Causal-attribution control proof for scripts/check-no-escape.py (#278).

The no-escape gate protects roots the operator SHARES with the OS and -- on this
machine -- with other Calyx/codebase-memory checkouts and concurrent MCP servers.
Classifying a shared-root delta as "ours" by NAME PATTERN (calyx*, cbm*) is unsound
there: a `cargo test` in the operator's own Calyx repo drops `calyx-retention-<pid>`
dirs into %TEMP%, and a second Claude session's MCP server writes the CBM store --
both match the project signature yet neither is ours. That is exactly the
false-positive that reddened native aggregate attempt 5.

This is the standing control proof that attribution is now CAUSAL, driven against
fixture roots (never the operator's real state, #197(5)). Every case takes a byte
snapshot, mutates the fixture on disk, runs `verify` with an explicit process-tree
attribution manifest, and asserts the outcome by an INDEPENDENT readback of disk:

  * an OUR-TREE escape (delta whose pid token is in the tree, or whose path the
    launcher recorded as owned) still fails the build -- the #133/#236/#246 class
    is not weakened;
  * a FOREIGN entry (same project-signature name, a pid NOT in our tree; or an
    un-owned store write) is counted and labeled, never used to fail;
  * an EXCLUSIVE root (truly project-only) still fails on ANY delta;
  * a missing attribution manifest FAILS CLOSED -- the gate refuses to fall back to
    the unsound name-pattern classification.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check-no-escape.py"
SCRATCH = ROOT / ".tmp" / "no-escape-attribution-selftest"

# Synthetic, deterministic PIDs: attribution is by pid TOKEN vs the recorded tree
# set, so no live process is needed -- the control is fully reproducible.
TREE_PID = 424242
FOREIGN_PID = 313131


def build_fixture() -> dict[str, Path]:
    if SCRATCH.exists():
        shutil.rmtree(SCRATCH)
    SCRATCH.mkdir(parents=True)
    paths = {
        "fixture": SCRATCH,
        "temp": SCRATCH / "operator-temp",
        "store": SCRATCH / "cbm-store",
        "excl": SCRATCH / "astrolabe-state",
        "registry": SCRATCH / "roots.json",
        "before": SCRATCH / "before.json",
        "manifest": SCRATCH / "attribution.json",
    }
    paths["temp"].mkdir()
    (paths["temp"] / "unrelated-os-file.tmp").write_text("foreign os churn\n", encoding="utf-8")
    paths["store"].mkdir()
    (paths["store"] / "_config.db").write_text("operator store baseline\n", encoding="utf-8")
    paths["excl"].mkdir()
    (paths["excl"] / "state.db").write_text("astrolabe home state\n", encoding="utf-8")

    registry = {
        "schema": "astrolabe.no_escape_roots.v1",
        "signature_globs": ["astrolabe*", "calyx*", "cbm*", "codebase-memory*"],
        "limits": {"max_entries_per_root": 20000, "max_hash_bytes_per_root": 536870912},
        "roots": [
            {
                "name": "fixture_operator_temp",
                "path": "${ASTRO_NO_ESCAPE_FIXTURE}/operator-temp",
                "mode": "signature",
                "max_depth": 1,
            },
            {
                "name": "fixture_cbm_store",
                "path": "${ASTRO_NO_ESCAPE_FIXTURE}/cbm-store",
                "mode": "attributed",
            },
            {
                "name": "fixture_astrolabe_state",
                "path": "${ASTRO_NO_ESCAPE_FIXTURE}/astrolabe-state",
                "mode": "exclusive",
            },
        ],
    }
    paths["registry"].write_text(json.dumps(registry, indent=2), encoding="utf-8")
    return paths


def write_manifest(path: Path, owned_paths: list[Path]) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "astrolabe.no_escape_attribution.v1",
                "launcher_pid": TREE_PID,
                "tree_pids": [TREE_PID],
                "owned_paths": [str(entry) for entry in owned_paths],
            }
        ),
        encoding="utf-8",
    )


def gate(paths: dict[str, Path], *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["ASTRO_NO_ESCAPE_FIXTURE"] = str(paths["fixture"])
    env.pop("ASTRO_NO_ESCAPE_ATTRIBUTION", None)
    return subprocess.run(
        [sys.executable, str(GATE), "--roots", str(paths["registry"]), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


def snapshot(paths: dict[str, Path]) -> None:
    result = gate(paths, "snapshot", "--out", str(paths["before"]))
    if result.returncode != 0:
        raise AssertionError(f"snapshot failed:\n{result.stdout}\n{result.stderr}")


def verify(paths: dict[str, Path], manifest: Path | None) -> subprocess.CompletedProcess:
    args = ["verify", "--before", str(paths["before"])]
    if manifest is not None:
        args += ["--attribution", str(manifest)]
    return gate(paths, *args)


def listing(root: Path) -> list[str]:
    if not root.is_dir():
        return ["<absent>"]
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))


def expect_red(result: subprocess.CompletedProcess, needle: str, label: str) -> None:
    combined = result.stdout + result.stderr
    if result.returncode == 0:
        raise AssertionError(f"{label}: gate PASSED a real escape\n{combined}")
    if "ASTRO_TEST_SANDBOX_ESCAPE" not in combined:
        raise AssertionError(f"{label}: not an escape failure\n{combined}")
    if needle not in combined:
        raise AssertionError(f"{label}: gate did not name {needle!r}\n{combined}")
    print(f"  CONTROL [{label}]: RED, named {needle}")


def expect_clean(result: subprocess.CompletedProcess, label: str) -> None:
    combined = result.stdout + result.stderr
    if result.returncode != 0:
        raise AssertionError(f"{label}: gate failed a non-escape\n{combined}")
    if "no-escape verified" not in combined:
        raise AssertionError(f"{label}: no verification line\n{combined}")
    print(f"  CONTROL [{label}]: clean (counted, not policed)")


def main() -> int:
    paths = build_fixture()
    atexit.register(lambda: shutil.rmtree(SCRATCH, ignore_errors=True))
    write_manifest(paths["manifest"], owned_paths=[])
    print("=== fixture roots ===")
    for key in ("temp", "store", "excl"):
        print(f"  {key:<6}: {paths[key]} -> {listing(paths[key])}")

    print("=== 1. OUR-TREE signature escape (pid in the recorded tree) -> RED ===")
    snapshot(paths)
    ours = paths["temp"] / f"calyx-retention-mixed-{TREE_PID}"
    ours.mkdir()
    (ours / "vault.calyx").write_text("leaked\n", encoding="utf-8")
    expect_red(verify(paths, paths["manifest"]), ours.name, "our-tree temp escape")
    if not ours.is_dir():
        raise AssertionError("control vacuous: our-tree dir absent on disk")
    print(f"  independent readback: {ours} exists on disk")
    shutil.rmtree(ours)

    print("=== 2. FOREIGN signature entry (same calyx* name, pid NOT in tree) -> counted ===")
    snapshot(paths)
    foreign = paths["temp"] / f"calyx-retention-mixed-{FOREIGN_PID}"
    foreign.mkdir()
    (foreign / "vault.calyx").write_text("a concurrent Calyx checkout's scratch\n", encoding="utf-8")
    result = verify(paths, paths["manifest"])
    expect_clean(result, "foreign temp churn")
    if "ASTRO_NO_ESCAPE_FOREIGN_CHURN" not in result.stdout:
        raise AssertionError(f"foreign churn not labeled:\n{result.stdout}")
    if foreign.name in (result.stdout + result.stderr).split("ASTRO_NO_ESCAPE_FOREIGN_CHURN")[0]:
        raise AssertionError("foreign entry was policed as an escape")
    print(f"  independent readback: {foreign} exists and was counted, not policed")
    shutil.rmtree(foreign)

    print("=== 3. ATTRIBUTED store: foreign MCP write (un-owned, no pid) -> counted ===")
    snapshot(paths)
    shm = paths["store"] / "_config.db-shm"
    shm.write_text("a concurrent MCP server's shared-memory sidecar\n", encoding="utf-8")
    result = verify(paths, paths["manifest"])
    expect_clean(result, "foreign store churn")
    if not shm.is_file():
        raise AssertionError("control vacuous: store sidecar absent")
    print(f"  independent readback: {shm} exists and was counted, not policed")
    shm.unlink()

    print("=== 4. ATTRIBUTED store: OUR write (launcher-recorded owned path) -> RED ===")
    snapshot(paths)
    ours_db = paths["store"] / "leaked-project.db"
    ours_db.write_text("our test registered a project in the real store (#246)\n", encoding="utf-8")
    owned_manifest = paths["fixture"] / "attribution-owned.json"
    write_manifest(owned_manifest, owned_paths=[ours_db])
    expect_red(verify(paths, owned_manifest), "leaked-project.db", "our-tree store escape")
    print(f"  independent readback: {ours_db} exists on disk ({ours_db.stat().st_size} bytes)")
    ours_db.unlink()

    print("=== 5. EXCLUSIVE root: ANY delta is ours -> RED even with attribution ===")
    snapshot(paths)
    with (paths["excl"] / "state.db").open("a", encoding="utf-8") as handle:
        handle.write("mutated operator state\n")
    expect_red(verify(paths, paths["manifest"]), "MODIFIED", "exclusive modify")
    (paths["excl"] / "state.db").write_text("astrolabe home state\n", encoding="utf-8")

    print("=== 6. FAIL CLOSED: shared roots declared but NO attribution manifest -> refuse ===")
    snapshot(paths)
    result = verify(paths, None)
    combined = result.stdout + result.stderr
    if result.returncode == 0 or "ASTRO_NO_ESCAPE_NO_ATTRIBUTION" not in combined:
        raise AssertionError(f"gate did not fail closed without attribution:\n{combined}")
    print("  CONTROL [no-attribution]: ASTRO_NO_ESCAPE_NO_ATTRIBUTION, exit 1")

    print("=== 7. clean run WITH attribution and no mutation -> pass ===")
    snapshot(paths)
    expect_clean(verify(paths, paths["manifest"]), "clean")

    shutil.rmtree(SCRATCH, ignore_errors=True)
    print("no-escape attribution control passed: causal, not nominal (#278)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
