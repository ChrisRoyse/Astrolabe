#!/usr/bin/env python3
"""Self-tests for scripts/check-no-escape.py (#237).

A gate that has never caught anything is decorative. This suite is the standing
control proof: it builds fixture protected roots, launches a REAL child process
that deliberately escapes into them, and requires check-no-escape to FAIL and to
name the exact escaped path. It then requires a clean run to pass with the roots
byte-identical.

Everything happens against fixture roots under .tmp/, never the operator's real
home, temp, or cache (multi-session lock discipline #197(5): FSV of containment
semantics uses isolated fixture roots, never the live shared workspace). The
registry's ${VAR} expansion resolves ASTRO_NO_ESCAPE_FIXTURE from the environment,
which is how the fixture roots are substituted for the real ones.

No test doubles: the leaker is a real program doing real writes, and every
assertion is an independent read of the bytes on disk.
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
GATE = ROOT / "scripts" / "check-no-escape.py"
SCRATCH = ROOT / ".tmp" / "no-escape-selftest"

LEAKER = '''\
import os
import sys
from pathlib import Path

# The child is contained: HOME/TMP/XDG were redirected into the sandbox. It
# always writes there (a real suite doing real work), and, when told to, it
# ALSO escapes by absolute path -- which is the only escape hatch layer 1 leaves.
sandbox_tmp = Path(os.environ["TMP"])
sandbox_tmp.mkdir(parents=True, exist_ok=True)
(sandbox_tmp / "suite-work.txt").write_text("real work inside the sandbox\\n", encoding="utf-8")
(Path(os.environ["HOME"]) / ".suite-state").write_text("home state\\n", encoding="utf-8")

mode = sys.argv[1]
if mode == "clean":
    pass
elif mode == "leak-exclusive":
    target = Path(sys.argv[2]) / "leaked-project.db"
    target.write_text("registered a fixture project in the operator store\\n", encoding="utf-8")
elif mode == "leak-signature-dir":
    # The exact shape of #236 / #133: a vault dir left in the operator's temp. The
    # dir name embeds THIS process's id (the vendored scratch-dir convention), which
    # is how causal attribution (#278) recognises it as ours: the launcher/run tree
    # contains this pid, so the leak is policed and RED -- while an identical name
    # carrying a foreign pid would be counted, not policed.
    target = Path(sys.argv[2]) / f"astrolabe-anchors-{os.getpid()}"
    target.mkdir(parents=True, exist_ok=True)
    (target / "vault.calyx").write_text("leaked vault\\n", encoding="utf-8")
elif mode == "leak-foreign":
    # Third-party churn in a shared root: counted, never policed.
    (Path(sys.argv[2]) / "SomeVendor_installer.log").write_text("unrelated\\n", encoding="utf-8")
elif mode == "modify-exclusive":
    target = Path(sys.argv[2]) / "operator-project.db"
    with target.open("a", encoding="utf-8") as handle:
        handle.write("mutated operator state\\n")
elif mode == "remove-exclusive":
    (Path(sys.argv[2]) / "operator-project.db").unlink()
else:
    raise SystemExit(f"unknown leaker mode: {mode}")
print(f"leaker mode={mode} done")
'''


def build_fixture() -> dict[str, Path]:
    if SCRATCH.exists():
        shutil.rmtree(SCRATCH)
    SCRATCH.mkdir(parents=True)

    paths = {
        "fixture": SCRATCH,
        "exclusive": SCRATCH / "operator-store",
        "empty": SCRATCH / "empty-store",
        "absent": SCRATCH / "absent-store",
        "deep": SCRATCH / "deep-store",
        "shared": SCRATCH / "operator-temp",
        "sandbox": SCRATCH / "sandbox",
        "leaker": SCRATCH / "leaker.py",
        "registry": SCRATCH / "roots.json",
    }

    paths["exclusive"].mkdir()
    (paths["exclusive"] / "operator-project.db").write_text(
        "the operator's own registration\n", encoding="utf-8"
    )
    paths["empty"].mkdir()  # edge (a): an empty protected root
    # edge (b): paths["absent"] is deliberately never created
    # edge (c): a deep root -- 8 levels, 24 files
    deep = paths["deep"]
    current = deep
    for level in range(8):
        current = current / f"level{level}"
        current.mkdir(parents=True)
        for index in range(3):
            (current / f"file{index}.bin").write_bytes(bytes([level, index]) * 512)
    paths["shared"].mkdir()
    (paths["shared"] / "unrelated-os-file.tmp").write_text("foreign\n", encoding="utf-8")
    paths["leaker"].write_text(LEAKER, encoding="utf-8")

    registry = {
        "schema": "astrolabe.no_escape_roots.v1",
        "signature_globs": ["astrolabe*", "calyx*", "cbm*", "codebase-memory*"],
        "limits": {"max_entries_per_root": 20000, "max_hash_bytes_per_root": 536870912},
        "roots": [
            {
                "name": "fixture_operator_store",
                "path": "${ASTRO_NO_ESCAPE_FIXTURE}/operator-store",
                "mode": "exclusive",
            },
            {
                "name": "fixture_empty_store",
                "path": "${ASTRO_NO_ESCAPE_FIXTURE}/empty-store",
                "mode": "exclusive",
            },
            {
                "name": "fixture_absent_store",
                "path": "${ASTRO_NO_ESCAPE_FIXTURE}/absent-store",
                "mode": "exclusive",
            },
            {
                "name": "fixture_deep_store",
                "path": "${ASTRO_NO_ESCAPE_FIXTURE}/deep-store",
                "mode": "exclusive",
            },
            {
                "name": "fixture_unresolvable",
                "path": "${ASTRO_NO_ESCAPE_NO_SUCH_VAR}/nowhere",
                "mode": "exclusive",
            },
            {
                "name": "fixture_operator_temp",
                "path": "${ASTRO_NO_ESCAPE_FIXTURE}/operator-temp",
                "mode": "signature",
                "max_depth": 1,
            },
        ],
    }
    paths["registry"].write_text(json.dumps(registry, indent=2), encoding="utf-8")
    return paths


def clean_env(paths: dict[str, Path]) -> dict[str, str]:
    """Child env for an inner gate invocation, with attribution EXPLICITLY controlled.

    HERMETICITY (#278 attempt 8): when the aggregate launcher runs this suite it
    exports ASTRO_NO_ESCAPE_ATTRIBUTION describing the LIVE session's process tree.
    An inner `run`/`verify` here builds its OWN fixture world; if it inherited that
    ambient manifest it would judge a fixture leak against the live tree -- the
    fixture leaker's pid is not in the live tree, so its escape would misclassify as
    foreign and the escape controls would spuriously PASS (that is exactly the
    attempt-8 red). So every inner invocation SCRUBS the ambient var; controls that
    need attribution pass a fixture manifest explicitly (the `run` path attributes
    from its captured tree). The scrub makes the suite independent of the caller.
    """
    env = dict(os.environ)
    env["ASTRO_NO_ESCAPE_FIXTURE"] = str(paths["fixture"])
    env.pop("ASTRO_NO_ESCAPE_NO_SUCH_VAR", None)
    env.pop("ASTRO_NO_ESCAPE_ATTRIBUTION", None)
    return env


def run_gate(paths: dict[str, Path], mode: str, target: Path | None) -> subprocess.CompletedProcess:
    env = clean_env(paths)
    command = [
        sys.executable,
        str(GATE),
        "--roots",
        str(paths["registry"]),
        "run",
        "--sandbox",
        str(paths["sandbox"]),
        "--fresh",
        "--require-sandbox-writes",
        "--",
        sys.executable,
        str(paths["leaker"]),
        mode,
    ]
    if target is not None:
        command.append(str(target))
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False, env=env)


def listing(root: Path) -> list[str]:
    """Independent readback: what is actually on disk, right now."""
    if not root.is_dir():
        return ["<absent>"]
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))


def expect_escape(result: subprocess.CompletedProcess, needle: str, label: str) -> None:
    combined = result.stdout + result.stderr
    if result.returncode == 0:
        raise AssertionError(f"{label}: gate PASSED an escaping run\n{combined}")
    if "ASTRO_TEST_SANDBOX_ESCAPE" not in combined:
        raise AssertionError(f"{label}: gate failed without the escape code\n{combined}")
    if needle not in combined:
        raise AssertionError(f"{label}: gate did not name {needle!r}\n{combined}")
    print(f"  CONTROL PROOF [{label}]: gate FAILED closed and named {needle}")


def expect_clean(result: subprocess.CompletedProcess, label: str) -> None:
    combined = result.stdout + result.stderr
    if result.returncode != 0:
        raise AssertionError(f"{label}: gate failed a clean run\n{combined}")
    if "no-escape verified" not in combined:
        raise AssertionError(f"{label}: gate did not report verification\n{combined}")
    print(f"  {label}: gate PASSED and reported byte-identical protected roots")


def main() -> int:
    paths = build_fixture()
    atexit.register(lambda: shutil.rmtree(SCRATCH, ignore_errors=True))

    print("=== fixture protected roots (edge triad) ===")
    print(f"  (a) empty root      : {paths['empty']} -> {listing(paths['empty'])}")
    print(f"  (b) absent root     : {paths['absent']} -> {listing(paths['absent'])}")
    print(f"  (c) deep root       : {paths['deep']} -> {len(listing(paths['deep']))} entries")
    print(f"  exclusive root      : {paths['exclusive']} -> {listing(paths['exclusive'])}")
    print(f"  shared root         : {paths['shared']} -> {listing(paths['shared'])}")

    print("=== 1. clean run: the suite works entirely inside its sandbox ===")
    before = {key: listing(paths[key]) for key in ("exclusive", "empty", "deep", "shared")}
    expect_clean(run_gate(paths, "clean", None), "clean run")
    after = {key: listing(paths[key]) for key in ("exclusive", "empty", "deep", "shared")}
    if before != after:
        raise AssertionError(f"clean run mutated a protected root: {before} != {after}")
    print(f"  independent readback: protected roots unchanged ({after['exclusive']})")

    print("=== 2. CONTROL: a deliberately-leaking suite escapes into an exclusive root ===")
    result = run_gate(paths, "leak-exclusive", paths["exclusive"])
    expect_escape(result, str(paths["exclusive"] / "leaked-project.db"), "exclusive add")
    leaked = paths["exclusive"] / "leaked-project.db"
    if not leaked.is_file():
        raise AssertionError("the leaker did not actually leak; the control proof is vacuous")
    print(f"  independent readback: {leaked} exists on disk ({leaked.stat().st_size} bytes)")
    leaked.unlink()

    print("=== 3. CONTROL: the #236 / #133 shape -- a vault dir in the operator's temp ===")
    result = run_gate(paths, "leak-signature-dir", paths["shared"])
    expect_escape(result, "astrolabe-anchors-", "signature dir add")
    leaked_dirs = [
        child
        for child in paths["shared"].iterdir()
        if child.is_dir() and child.name.startswith("astrolabe-anchors-")
    ]
    if not leaked_dirs:
        raise AssertionError("the leaker did not create the vault dir; control proof is vacuous")
    print(f"  independent readback: {leaked_dirs[0]} exists on disk")
    for leaked_dir in leaked_dirs:
        shutil.rmtree(leaked_dir)

    print("=== 4. CONTROL: modifying operator state in an exclusive root ===")
    original = (paths["exclusive"] / "operator-project.db").read_bytes()
    result = run_gate(paths, "modify-exclusive", paths["exclusive"])
    expect_escape(result, "MODIFIED", "exclusive modify")
    (paths["exclusive"] / "operator-project.db").write_bytes(original)

    print("=== 5. CONTROL: removing operator state from an exclusive root ===")
    result = run_gate(paths, "remove-exclusive", paths["exclusive"])
    expect_escape(result, "REMOVED", "exclusive remove")
    (paths["exclusive"] / "operator-project.db").write_bytes(original)

    print("=== 6. foreign churn in a shared root is counted, never used to fail ===")
    result = run_gate(paths, "leak-foreign", paths["shared"])
    expect_clean(result, "foreign churn")
    foreign = paths["shared"] / "SomeVendor_installer.log"
    if not foreign.is_file():
        raise AssertionError("the foreign-churn probe wrote nothing; the case is vacuous")
    if "ASTRO_NO_ESCAPE_FOREIGN_CHURN" not in result.stdout:
        raise AssertionError(f"foreign churn was not counted:\n{result.stdout}")
    print(f"  independent readback: {foreign} exists and was counted, not policed")
    foreign.unlink()

    print("=== 7. containment: the suite's own writes landed in the sandbox, not the host ===")
    sandbox_work = list(paths["sandbox"].rglob("suite-work.txt"))
    if not sandbox_work:
        raise AssertionError("the suite's sandbox write is missing; containment is unproven")
    print(f"  independent readback: {sandbox_work[0]} ({sandbox_work[0].read_text().strip()!r})")

    print("=== 8. a missing baseline fails closed -- containment is never assumed ===")
    env = clean_env(paths)
    result = subprocess.run(
        [
            sys.executable,
            str(GATE),
            "--roots",
            str(paths["registry"]),
            "verify",
            "--before",
            str(SCRATCH / "does-not-exist.json"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    if result.returncode == 0 or "ASTRO_NO_ESCAPE_NO_BASELINE" not in result.stderr:
        raise AssertionError(f"verify without a baseline did not fail closed:\n{result.stderr}")
    print("  verify without a baseline: ASTRO_NO_ESCAPE_NO_BASELINE, exit 1")

    print("=== 9. HERMETICITY (#278 attempt 8, 'Control 16'): POISONED ambient attribution var ===")
    # The exact attempt-8 repro. When the launcher runs this suite it exports
    # ASTRO_NO_ESCAPE_ATTRIBUTION pointing at the LIVE session's process-tree
    # manifest. Rerun the key escape control (the #236/#133 signature-dir leak) with
    # that variable POISONED -- pointing at a synthetic live-like manifest whose tree
    # does NOT contain the fixture leaker's pid. Before the fix, the inner `run`
    # inherited the poison, judged the fixture leak against the live tree, classified
    # our own child's escape 'foreign', and PASSED an escaping run. The suite must
    # still RED it: the scrub (clean_env) plus `run` ignoring the ambient var means
    # attribution comes from the captured tree, not the poison.
    poison = paths["fixture"] / "poison-live-attribution.json"
    now_ns = time.time_ns()
    poison.write_text(
        json.dumps(
            {
                "schema": "astrolabe.no_escape_attribution.v1",
                "launcher_pid": 999001,
                "run_started_unix_ns": now_ns - 3600 * 1_000_000_000,
                "written_at": now_ns,
                # Deliberately NONE of the fixture leaker's pids: a foreign live tree.
                "tree_pids": [999001, 999002, 999003],
                "pid_first_seen": {"999001": now_ns - 3600 * 1_000_000_000},
                "pid_intervals": {"999001": [[now_ns - 3600 * 1_000_000_000, None]]},
                "owned_paths": [],
            }
        ),
        encoding="utf-8",
    )
    saved = os.environ.get("ASTRO_NO_ESCAPE_ATTRIBUTION")
    os.environ["ASTRO_NO_ESCAPE_ATTRIBUTION"] = str(poison)
    try:
        result = run_gate(paths, "leak-signature-dir", paths["shared"])
        expect_escape(result, "astrolabe-anchors-", "poisoned-ambient signature dir add")
    finally:
        if saved is None:
            os.environ.pop("ASTRO_NO_ESCAPE_ATTRIBUTION", None)
        else:
            os.environ["ASTRO_NO_ESCAPE_ATTRIBUTION"] = saved
    leaked_dirs = [
        child
        for child in paths["shared"].iterdir()
        if child.is_dir() and child.name.startswith("astrolabe-anchors-")
    ]
    if not leaked_dirs:
        raise AssertionError("the leaker did not create the vault dir; control 16 is vacuous")
    print(f"  independent readback: {leaked_dirs[0]} policed despite the poisoned ambient var")
    for leaked_dir in leaked_dirs:
        shutil.rmtree(leaked_dir)

    shutil.rmtree(SCRATCH, ignore_errors=True)
    print("no-escape self-test passed: the gate catches escapes and passes clean runs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
