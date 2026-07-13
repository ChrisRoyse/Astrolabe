#!/usr/bin/env python3
"""Self-test of the suite-level impact gate (scripts/check-suite-impact.py).

Proves the fail-closed contract on a fixture git repo (never the live
workspace): unknown state always RUNS, a recorded green skips ONLY while the
input bytes are identical, and every mutation class (tracked edit, untracked
add, deletion, manifest corruption, forced-all) re-runs the suite.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check-suite-impact.py"

REGISTRY = json.dumps({"demo": {"paths": ["src"], "tools": []}})


def run_gate(fixture: Path, cache: Path, *args: str, gate_all: bool = False) -> tuple[int, str]:
    env = dict(os.environ)
    env["ASTRO_SUITE_ROOT"] = str(fixture)
    env["ASTRO_SUITE_CACHE_DIR"] = str(cache)
    env["ASTRO_SUITE_REGISTRY_JSON"] = REGISTRY
    env.pop("ASTRO_SUITE_GATE", None)
    if gate_all:
        env["ASTRO_SUITE_GATE"] = "all"
    proc = subprocess.run(
        [sys.executable, str(GATE), *args],
        cwd=fixture,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return proc.returncode, proc.stdout


def git(fixture: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(fixture), *args],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def expect(cond: bool, label: str, detail: str = "") -> None:
    if not cond:
        print(f"FAIL: {label}\n{detail}", file=sys.stderr)
        raise SystemExit(1)
    print(f"ok: {label}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="astro-suite-impact-") as tmp:
        fixture = Path(tmp) / "repo"
        cache = Path(tmp) / "cache"
        (fixture / "src").mkdir(parents=True)
        (fixture / "src" / "a.txt").write_text("alpha\n", encoding="utf-8")
        git(fixture, "init", "-q")
        git(fixture, "config", "user.email", "gate@astrolabe.invalid")
        git(fixture, "config", "user.name", "Astrolabe Gate Selftest")
        git(fixture, "add", ".")
        git(fixture, "commit", "-qm", "seed")

        # 1. No manifest -> fail closed -> RUN.
        rc, out = run_gate(fixture, cache, "should-run", "demo")
        expect(rc == 0 and "FAILCLOSED" in out, "no manifest => run", out)

        # 2. Unregistered suite -> fail closed -> RUN.
        rc, out = run_gate(fixture, cache, "should-run", "nope")
        expect(rc == 0 and "FAILCLOSED" in out, "unregistered suite => run", out)

        # 3. record-green then identical bytes -> SKIP with the named label.
        rc, out = run_gate(fixture, cache, "record-green", "demo", "--note", "n=1")
        expect(rc == 0 and "GREEN_RECORDED" in out, "record-green", out)
        rc, out = run_gate(fixture, cache, "should-run", "demo")
        expect(
            rc == 3 and "SKIP[ASTRO_SUITE_UNCHANGED]" in out and "suite=demo" in out,
            "unchanged => skip(3) with label",
            out,
        )

        # 4. Tracked-file WORKING-TREE edit (no commit) -> RUN.
        (fixture / "src" / "a.txt").write_text("alpha CHANGED\n", encoding="utf-8")
        rc, out = run_gate(fixture, cache, "should-run", "demo")
        expect(rc == 0 and "IMPACTED" in out, "dirty tracked edit => run", out)

        # 5. Re-green at the dirty state, then an untracked add -> RUN.
        run_gate(fixture, cache, "record-green", "demo")
        rc, out = run_gate(fixture, cache, "should-run", "demo")
        expect(rc == 3, "re-green at dirty state => skip", out)
        (fixture / "src" / "new.txt").write_text("fresh\n", encoding="utf-8")
        rc, out = run_gate(fixture, cache, "should-run", "demo")
        expect(rc == 0 and "IMPACTED" in out, "untracked add => run", out)

        # 6. Deletion of a tracked input -> RUN.
        run_gate(fixture, cache, "record-green", "demo")
        (fixture / "src" / "new.txt").unlink()
        (fixture / "src" / "a.txt").unlink()
        rc, out = run_gate(fixture, cache, "should-run", "demo")
        expect(rc == 0, "tracked deletion => run", out)
        # Restore for the remaining probes.
        git(fixture, "checkout", "--", "src/a.txt")

        # 7. Corrupt manifest -> fail closed -> RUN.
        run_gate(fixture, cache, "record-green", "demo")
        (cache / "suite-green.json").write_text("{not json", encoding="utf-8")
        rc, out = run_gate(fixture, cache, "should-run", "demo")
        expect(rc == 0 and "FAILCLOSED" in out, "corrupt manifest => run", out)

        # 8. ASTRO_SUITE_GATE=all overrides a valid green -> RUN.
        run_gate(fixture, cache, "record-green", "demo")
        rc, out = run_gate(fixture, cache, "should-run", "demo")
        expect(rc == 3, "green restored => skip", out)
        rc, out = run_gate(fixture, cache, "should-run", "demo", gate_all=True)
        expect(rc == 0 and "ASTRO_SUITE_GATE_ALL" in out, "gate=all => run", out)

        # 9. A registry (input-set) change invalidates the recorded green.
        global REGISTRY
        old_registry = REGISTRY
        REGISTRY = json.dumps({"demo": {"paths": ["src"], "tools": [["git", "--version"]]}})
        rc, out = run_gate(fixture, cache, "should-run", "demo")
        expect(rc == 0 and "IMPACTED" in out, "registry change => run", out)
        REGISTRY = old_registry

        # 10. fingerprint subcommand: sound on a valid tree, exits 1 when the
        # input set matches nothing (callers must then rebuild, fail closed).
        rc, out = run_gate(fixture, cache, "fingerprint", "demo")
        expect(rc == 0 and len(out.strip()) == 64, "fingerprint emitted", out)
        REGISTRY = json.dumps({"demo": {"paths": ["does-not-exist"], "tools": []}})
        rc, out = run_gate(fixture, cache, "fingerprint", "demo")
        expect(rc == 1, "fingerprint over empty input set => unsound => exit 1", out)
        REGISTRY = old_registry

    print("check-suite-impact self-test OK (10 fail-closed/skip contracts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
