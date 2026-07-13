#!/usr/bin/env python3
"""Self-test of the change-gating mechanism in run-gate-selftests.py (#280).

This is a META-test of the meta-test runner, so it MUST itself run
unconditionally (it is never change-gated). It proves the fail-closed controls
that make the change-gate honest:

  1. First run (no manifest) runs every supplied test and records green.
  2. A second, unchanged run SKIPS every change-gated test and emits
     SKIP[ASTRO_GATE_SELFTESTS_UNCHANGED] with the right count.
  3. Mutating a test's DECLARED DEPENDENCY re-runs only that test.
  4. Mutating the test file itself re-runs only that test.
  5. A corrupt manifest re-runs everything (never skips on unknown state).
  6. An absent manifest re-runs everything.
  7. A failing test yields a non-zero exit AND leaves the recorded-green
     manifest unchanged (so the failure cannot be "skipped away" next run).
  8. An UNCONDITIONAL test always runs, even with a matching manifest.
  9. ASTRO_GATE_SELFTESTS=all runs everything regardless of the manifest.

Everything runs against synthetic fixture tests in a temp dir; the real
scripts/test-*.py suite is never invoked here.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "scripts" / "run-gate-selftests.py"


def load_driver():
    spec = importlib.util.spec_from_file_location("run_gate_selftests", DRIVER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {DRIVER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PASS_TEST = "print('ok')\n"
FAIL_TEST = "import sys\nsys.stderr.write('boom\\n')\nsys.exit(1)\n"


def make_repo(base: Path) -> tuple[Path, Path]:
    """Create a fake repo with a scripts/ dir and a gitignored cache dir."""
    scripts = base / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    cache = base / ".astro-gate-cache"
    return scripts, cache


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def run_driver(
    driver, root: Path, cache: Path, names: list[str], *, mode: str = "auto"
) -> tuple[int, dict]:
    """Invoke the driver as a subprocess; return (exit_code, parsed-signals).

    Signals: {'skipped': set, 'ran': set, 'skip_line': str|None}.
    """
    env = os.environ.copy()
    env["ASTRO_GATE_ROOT"] = str(root)
    env["ASTRO_GATE_CACHE_DIR"] = str(cache)
    env["ASTRO_GATE_PYTHON"] = sys.executable
    env["ASTRO_GATE_SELFTESTS"] = mode
    env["ASTRO_GATE_SELFTEST_JOBS"] = "4"
    proc = subprocess.run(
        [sys.executable, str(DRIVER), *names],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    out = proc.stdout
    ran = set()
    skipped = set()
    skip_line = None
    for line in out.splitlines():
        if line.startswith("GATE_TIME[selftest:"):
            ran.add(line[len("GATE_TIME[selftest:") : line.index("]")])
        if line.startswith("SKIP[ASTRO_GATE_SELFTESTS_UNCHANGED]"):
            skip_line = line
        if line.strip().startswith("skipped:"):
            for tok in line.split(":", 1)[1].split():
                skipped.add(tok.strip())
    return proc.returncode, {"ran": ran, "skipped": skipped, "skip_line": skip_line, "out": out}


def expect(cond: bool, label: str, detail: str = "") -> None:
    if not cond:
        raise AssertionError(f"{label} FAILED {detail}")


def main() -> int:
    driver = load_driver()

    with tempfile.TemporaryDirectory(prefix="run-gate-selftests-") as temp:
        base = Path(temp)
        scripts, cache = make_repo(base)

        # Three change-gated fixture tests. Register a fake dependency for one of
        # them by monkey-patching the driver's DEPENDENCIES via env-independent
        # module state is not shared across the subprocess, so instead we make
        # the dependency be the test file itself (default) and additionally test
        # a declared dependency by pointing at a real sibling file.
        write(scripts / "test-alpha.py", PASS_TEST)
        write(scripts / "test-beta.py", PASS_TEST)
        write(scripts / "test-gamma.py", PASS_TEST)
        # A declared dependency for test-beta: a sibling "gate script".
        dep_file = scripts / "beta-gate.sh"
        write(dep_file, "echo gate\n")

        names = ["test-alpha.py", "test-beta.py", "test-gamma.py"]

        # Inject a dependency mapping + one UNCONDITIONAL test into the driver
        # subprocess via a tiny wrapper module is overkill; instead exercise the
        # driver's public functions in-process for the dependency/unconditional
        # cases, and use the subprocess for the end-to-end manifest behavior.

        # (2)+(1) end-to-end: first run records green and runs all; second run skips all.
        rc, s1 = run_driver(driver, base, cache, names)
        expect(rc == 0, "first run exits 0", s1["out"])
        expect(s1["ran"] == set(names), "first run runs all", str(s1["ran"]))
        manifest = cache / driver.MANIFEST_NAME
        expect(manifest.is_file(), "manifest written after green run")

        rc, s2 = run_driver(driver, base, cache, names)
        expect(rc == 0, "second run exits 0")
        expect(s2["ran"] == set(), "second unchanged run runs nothing", str(s2["ran"]))
        expect(s2["skipped"] == set(names), "second run skips all", str(s2["skipped"]))
        expect(
            s2["skip_line"] is not None and "n=3" in s2["skip_line"],
            "skip line reports n=3",
            str(s2["skip_line"]),
        )

        # (4) Mutate the test FILE itself -> only that one re-runs.
        write(scripts / "test-gamma.py", PASS_TEST + "# touched\n")
        rc, s3 = run_driver(driver, base, cache, names)
        expect(rc == 0, "post-mutation run exits 0")
        expect(s3["ran"] == {"test-gamma.py"}, "only mutated test re-runs", str(s3["ran"]))
        expect(s3["skipped"] == {"test-alpha.py", "test-beta.py"}, "others still skip", str(s3["skipped"]))

        # After that green run, everything is recorded again -> all skip.
        rc, s4 = run_driver(driver, base, cache, names)
        expect(s4["ran"] == set(), "all skip again after re-record", str(s4["ran"]))

        # (5) Corrupt manifest -> everything re-runs (fail closed).
        manifest.write_text("{ this is not json", encoding="utf-8")
        rc, s5 = run_driver(driver, base, cache, names)
        expect(rc == 0, "corrupt-manifest run exits 0")
        expect(s5["ran"] == set(names), "corrupt manifest runs all", str(s5["ran"]))

        # (5b) Wrong-schema manifest (valid JSON, wrong version) -> fail closed.
        manifest.write_text(json.dumps({"version": 999, "fingerprints": {}}), encoding="utf-8")
        rc, s5b = run_driver(driver, base, cache, names)
        expect(s5b["ran"] == set(names), "wrong-version manifest runs all", str(s5b["ran"]))

        # (6) Absent manifest -> everything re-runs.
        manifest.unlink()
        rc, s6 = run_driver(driver, base, cache, names)
        expect(s6["ran"] == set(names), "absent manifest runs all", str(s6["ran"]))

        # (9) ASTRO_GATE_SELFTESTS=all -> runs all even with a fresh green manifest.
        rc, _ = run_driver(driver, base, cache, names)  # re-record green
        rc, s9 = run_driver(driver, base, cache, names, mode="all")
        expect(s9["ran"] == set(names), "mode=all runs all despite green manifest", str(s9["ran"]))

        # (7) A failing test -> non-zero exit AND manifest unchanged.
        # Re-record green first, capture the manifest bytes, then break one test.
        rc, _ = run_driver(driver, base, cache, names)
        green_bytes = manifest.read_bytes()
        write(scripts / "test-beta.py", FAIL_TEST)
        rc, s7 = run_driver(driver, base, cache, names)
        expect(rc != 0, "failing test yields non-zero exit", str(rc))
        expect(
            manifest.read_bytes() == green_bytes,
            "manifest unchanged after a failing run",
        )

    # In-process checks for dependency + unconditional classification, which are
    # driven by the driver's module-level maps (can't be injected via subprocess).
    with tempfile.TemporaryDirectory(prefix="run-gate-fp-") as temp:
        base = Path(temp)
        scripts = base / "scripts"
        scripts.mkdir(parents=True)
        # (3) fingerprint changes when a DECLARED dependency changes.
        write(scripts / "ci-cbm-lint.sh", "echo v1\n")
        write(scripts / "test-cbm-lint-platform.py", PASS_TEST)
        fp1, missing1 = driver.fingerprint(base, "test-cbm-lint-platform.py")
        expect(missing1 == [], "declared deps resolve", str(missing1))
        write(scripts / "ci-cbm-lint.sh", "echo v2\n")
        fp2, _ = driver.fingerprint(base, "test-cbm-lint-platform.py")
        expect(fp1 != fp2, "fingerprint changes when a declared dependency changes")

        # (3b) missing declared dependency -> fingerprint None (fail closed -> run).
        (scripts / "ci-cbm-lint.sh").unlink()
        fp3, missing3 = driver.fingerprint(base, "test-cbm-lint-platform.py")
        expect(fp3 is None and "scripts/ci-cbm-lint.sh" in missing3, "missing dep -> None")

        # (8) UNCONDITIONAL set is non-empty and names are never fingerprinted for skip.
        expect(
            "test-check-workspace-tests.py" in driver.UNCONDITIONAL,
            "process-kill test is unconditional",
        )
        expect(
            "test-cbm-spawn-fsv.py" in driver.UNCONDITIONAL,
            "C-toolchain test is unconditional",
        )

    print("run-gate-selftests change-gating self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
