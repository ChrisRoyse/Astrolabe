#!/usr/bin/env python3
"""Change-gated, parallel runner for the gate-tooling self-tests (#280).

The ~two dozen ``scripts/test-*.py`` scripts in the first block of
``scripts/check.sh`` are META-TESTS of the gate tooling: they drive a gate
script (or a patch applier) with fixtures and assert it fails/passes closed.
They verify the *tooling*, not the product, so re-running every one on every
Tier-1 ``check.sh`` -- even when no gate script changed -- is the dead weight
#280 targets.

This driver runs each eligible self-test only when its dependency fingerprint
differs from the last recorded GREEN state, and runs the eligible ones in
bounded parallel with serialized, grouped output plus a per-gate ``GATE_TIME``
line. It fails closed on every ambiguity.

FAIL-CLOSED CONTRACT (unknown state => run, never skip)
    * Manifest absent, unreadable, non-JSON, wrong schema/version, or missing a
      test's entry  =>  that test (or all tests) RUN.
    * ``ASTRO_GATE_SELFTESTS=all``  =>  every test runs regardless of manifest
      (check-full.sh / check-release.sh set this, so the aggregate always runs
      the full suite; the change-gate is a Tier-1-only optimization).
    * A self-test classified UNCONDITIONAL (its pass/fail depends on live host
      state, not just repo bytes) always runs and is never fingerprinted.
    * The manifest is refreshed only from tests that actually PASSED this run;
      a failing run leaves the recorded green state untouched.

FINGERPRINT
    For a change-gated test, the fingerprint is SHA-256 over the sorted
    ``(relpath, sha256(bytes))`` pairs of its dependency set: the test file
    itself plus the specific gate scripts / patch appliers / manifests it
    drives (see DEPENDENCIES). Vendored source trees are NOT hashed here: their
    bytes are byte-pinned by ``scripts/verify-pins.sh`` (unconditional, fail
    closed) earlier in the same run, so a vendor change cannot silently alter a
    self-test's premise without a deliberate pin bump -- and the aggregate tier
    re-runs every self-test regardless.

RECORDED-GREEN LOCATION
    ``.astro-gate-cache/gate-selftests-green.json`` at the repo root. It must be
    durable across ``target/`` wipes (``target/`` is deleted every run) and must
    NOT be the launcher-owned ``.tmp/`` (cleared on launcher exit), so a fresh
    top-level gitignored cache dir is used. Override with
    ``ASTRO_GATE_CACHE_DIR`` (used by this driver's own self-test).
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[1]

MANIFEST_VERSION = 1
MANIFEST_NAME = "gate-selftests-green.json"

# Self-tests whose pass/fail depends on LIVE HOST STATE (process-kill semantics,
# a real C/Rust toolchain, real process-tree attribution) rather than solely on
# repo bytes. A fingerprint of repo files cannot capture their premise, so they
# are never change-gated: they always run. This is the fail-closed default made
# explicit -- when in doubt, a test belongs here.
UNCONDITIONAL = {
    # Spawns real child processes and asserts OS process-group / taskkill kill
    # semantics (os.name-branched); outcome is a live-OS property.
    "test-check-workspace-tests.py",
    # Resolves and drives the real cargo toolchain (shutil.which + ~/.cargo/bin);
    # outcome depends on the installed host toolchain.
    "test-check-hazard-suite.py",
    # Compiles and links a C probe with the host CC and needs git; outcome
    # depends on the host C toolchain.
    "test-cbm-spawn-fsv.py",
    # Spawns a real process tree to prove shared-root policing is causal (by
    # process tree, not name pattern); a live-process property.
    "test-no-escape-attribution.py",
}

# Dependency set per change-gated self-test, as repo-relative paths. Each set is
# the test file itself (added automatically) PLUS the gate script(s) / patch
# applier(s) / fixture manifest(s) it drives, so "changed script => its
# self-test runs" holds. Derived by reading each test's CHECKER/PATCH/MANIFEST
# constants. A test absent from this map falls back to [test file only]; its
# script-change coverage then relies on the aggregate tier (which runs all),
# and that fallback is logged, never silent.
DEPENDENCIES: dict[str, list[str]] = {
    "test-verify-pins.py": ["scripts/verify-pins.sh"],
    "test-cbm-skip-count.py": [
        "scripts/check-cbm-skip-count.sh",
        "ci/known-skips.md",
    ],
    "test-cbm-lint-platform.py": ["scripts/ci-cbm-lint.sh"],
    "test-cbm-format-overlay.py": [
        "patches/cbm/apply_graph_buffer_format_patch.py",
    ],
    "test-cbm-cache-guards.py": [
        "scripts/check-cbm-cache-paths.py",
        "scripts/check-cbm-cache-hermeticity.py",
        "ci/cbm-cache-path-offenders.md",
    ],
    "test-check-libcbm-symbols.py": ["scripts/check-libcbm-symbols.sh"],
    "test-parity-corpus-contract.py": [
        "scripts/check-mcp-parity.py",
        "scripts/check-cli-parity.py",
    ],
    "test-native-cargo-fmt.py": ["scripts/native-cargo-fmt.py"],
    "test-check-no-mocks.py": ["scripts/check-no-mocks.py"],
    "test-gate-wiring.py": [
        "scripts/check-gate-wiring.py",
        "scripts/check.sh",
        "scripts/check-full.sh",
        "scripts/check-release.sh",
        "scripts/ci-cbm-lint.sh",
        "scripts/ci-cbm-test.sh",
        "scripts/ci-rust-gate.sh",
        "scripts/check-workspace-tests.py",
        "scripts/clean-target.sh",
    ],
    "test-degradation-labels.py": ["scripts/check-degradation-labels.py"],
    "test-verify-chain-native-path.py": [
        "scripts/check-astrolabe-verify-chain.sh",
    ],
    "test-native-binary-resolution.py": [
        "scripts/check-cli-parity.py",
        "scripts/check-compat-shim.py",
        "scripts/check-installer-roundtrip.py",
        "scripts/check-hook-contracts.py",
    ],
    "test-installer-roundtrip-fixture.py": [
        "scripts/check-installer-roundtrip.py",
    ],
    "test-egress-platform.py": ["scripts/check-egress-deny.py"],
    "test-release-predicate.py": ["scripts/release-predicate.py"],
    "test-check-no-escape.py": ["scripts/check-no-escape.py"],
    "test-cbm-spawn-patch.py": [
        "patches/cbm/apply_spawn_artifact_patch.py",
        "patches/cbm/apply_spawn_git_context_patch.py",
        "patches/cbm/apply_spawn_githistory_patch.py",
        "patches/cbm/apply_spawn_watcher_patch.py",
        "patches/cbm/astro_spawn.c",
        "patches/cbm/astro_spawn.h",
    ],
    "test-cbm-env-store-patch.py": [
        "patches/cbm/env_apply_store_patch.py",
        "patches/cbm/env_store_config.c",
        "patches/cbm/env_store_config.h",
        "crates/astrolabe-bridge/src/lib.rs",
    ],
    "test-cbm-env-contract.py": ["scripts/check-cbm-env-contract.py"],
    "test-bench-ratios-artifact.py": ["scripts/write-bench-ratios-artifact.py"],
    "test-cbm-mem-pressure-patch.py": [
        "patches/cbm/apply_mem_pressure_patch.py",
        "vendor/codebase-memory-mcp/src/foundation/mem.c",
    ],
    "test-windows-gnu-toolchain-contract.py": [
        "scripts/check-windows-gnu-toolchain-contract.py",
        "scripts/windows-gnu-toolchain.ps1",
    ],
    "test-native-aggregate-wrapper.py": [
        "scripts/check-native-aggregate-wrapper.py",
        "scripts/invoke-native-aggregate.ps1",
    ],
    "test-check-hook-contracts.py": [
        "scripts/check-hook-contracts.py",
        "ci/hook-contracts.json",
    ],
    "test-cbm-worker-diag-patch.py": [
        "patches/cbm/apply_worker_diag_patch.py",
        "patches/cbm/env_apply_store_patch.py",
        "patches/cbm/astro_overlay.py",
    ],
}


def _fmt_secs(seconds: float) -> str:
    return f"{seconds:.3f}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def test_name(arg: str) -> str:
    """Normalize a CLI argument (``scripts/test-x.py`` or ``test-x.py``) to a name."""
    return Path(arg).name


def dependency_paths(root: Path, name: str) -> tuple[list[Path], list[str]]:
    """Return (existing dependency files, missing-relpaths) for a self-test."""
    rels = [f"scripts/{name}", *DEPENDENCIES.get(name, [])]
    existing: list[Path] = []
    missing: list[str] = []
    for rel in rels:
        candidate = root / rel
        if candidate.is_file():
            existing.append(candidate)
        else:
            missing.append(rel)
    return existing, missing


def fingerprint(root: Path, name: str) -> tuple[str | None, list[str]]:
    """SHA-256 over the sorted (relpath, filehash) of the dependency set.

    Returns (fingerprint, missing). A missing dependency yields ``None`` so the
    caller fails closed (runs the test) rather than skipping on a stale premise.
    """
    existing, missing = dependency_paths(root, name)
    if missing:
        return None, missing
    parts = []
    for path in existing:
        rel = path.relative_to(root).as_posix()
        parts.append(f"{rel}\0{sha256_file(path)}")
    joined = "\n".join(sorted(parts)).encode("utf-8")
    return hashlib.sha256(joined).hexdigest(), []


def load_manifest(path: Path) -> tuple[dict[str, str], bool]:
    """Load the recorded-green manifest. Returns (entries, manifest_ok).

    ``manifest_ok`` is False on any corruption/absence/schema-mismatch; the
    caller then treats every change-gated test as changed (fail closed).
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return {}, False
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {}, False
    if not isinstance(data, dict) or data.get("version") != MANIFEST_VERSION:
        return {}, False
    entries = data.get("fingerprints")
    if not isinstance(entries, dict):
        return {}, False
    clean = {k: v for k, v in entries.items() if isinstance(k, str) and isinstance(v, str)}
    return clean, True


def write_manifest(path: Path, entries: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": MANIFEST_VERSION,
        "fingerprints": dict(sorted(entries.items())),
    }
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def run_one(root: Path, name: str, python_bin: str) -> tuple[int, str, float]:
    """Run a single self-test, capturing combined output and wall time."""
    start = time.monotonic()
    proc = subprocess.run(
        [python_bin, str(root / "scripts" / name)],
        cwd=root,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    elapsed = time.monotonic() - start
    return proc.returncode, proc.stdout, elapsed


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    root = Path(os.environ.get("ASTRO_GATE_ROOT", str(DEFAULT_ROOT))).resolve()
    python_bin = os.environ.get("ASTRO_GATE_PYTHON", sys.executable or "python")
    mode = os.environ.get("ASTRO_GATE_SELFTESTS", "auto").strip().lower()
    force_all = mode == "all"
    try:
        jobs = max(1, int(os.environ.get("ASTRO_GATE_SELFTEST_JOBS", "6")))
    except ValueError:
        jobs = 6
    cache_dir = Path(
        os.environ.get("ASTRO_GATE_CACHE_DIR", str(root / ".astro-gate-cache"))
    )
    manifest_path = cache_dir / MANIFEST_NAME

    names = [test_name(a) for a in argv]
    if not names:
        print("ERROR[ASTRO_GATE_SELFTESTS_EMPTY]: no self-tests supplied", file=sys.stderr)
        print("  remediation: pass the test-*.py paths as arguments", file=sys.stderr)
        return 2

    recorded, manifest_ok = load_manifest(manifest_path)

    to_run: list[str] = []
    skipped: list[str] = []
    fallback_notes: list[str] = []
    fresh_fingerprints: dict[str, str] = {}

    for name in names:
        if name in UNCONDITIONAL:
            to_run.append(name)
            continue
        if force_all or not manifest_ok:
            to_run.append(name)
            continue
        fp, missing = fingerprint(root, name)
        if fp is None:
            # A dependency file vanished -> unknown state -> run (fail closed).
            fallback_notes.append(
                f"{name}: missing dependency {missing} -> running (fail closed)"
            )
            to_run.append(name)
            continue
        if name not in DEPENDENCIES:
            fallback_notes.append(
                f"{name}: no declared script deps -> fingerprint of test file only "
                "(script-change coverage falls to the aggregate tier)"
            )
        fresh_fingerprints[name] = fp
        if recorded.get(name) == fp:
            skipped.append(name)
        else:
            to_run.append(name)

    # Report the change-gate decision up front, before any output interleaves.
    if not force_all and manifest_ok and skipped:
        print(
            f"SKIP[ASTRO_GATE_SELFTESTS_UNCHANGED]: n={len(skipped)} manifest_ok=true"
        )
        print(f"  skipped: {' '.join(sorted(skipped))}")
    elif force_all:
        print("INFO[ASTRO_GATE_SELFTESTS_ALL]: ASTRO_GATE_SELFTESTS=all -> running every self-test")
    elif not manifest_ok:
        print(
            "INFO[ASTRO_GATE_SELFTESTS_FAILCLOSED]: recorded-green manifest "
            f"absent/corrupt at {manifest_path} -> running every change-gated self-test"
        )
    for note in fallback_notes:
        print(f"  NOTE[ASTRO_GATE_SELFTESTS]: {note}")

    group_start = time.monotonic()
    results: dict[str, tuple[int, str, float]] = {}
    first_failure: str | None = None

    if to_run:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(jobs, len(to_run))) as pool:
            futures = {pool.submit(run_one, root, name, python_bin): name for name in to_run}
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                rc, output, elapsed = future.result()
                results[name] = (rc, output, elapsed)
                if rc != 0 and first_failure is None:
                    first_failure = name
                    # Fail-fast: drop any not-yet-started tests; in-flight ones
                    # finish (their capture completes) so evidence stays whole.
                    for pending, pending_name in futures.items():
                        if pending_name not in results:
                            pending.cancel()
                    break
            pool.shutdown(wait=True, cancel_futures=True)

    # Serialized, grouped output in the input order for greppable evidence.
    for name in to_run:
        if name not in results:
            continue
        rc, output, elapsed = results[name]
        marker = "OK" if rc == 0 else f"FAIL(exit={rc})"
        print(f"--- selftest[{name}] {marker} ---")
        sys.stdout.write(output)
        if output and not output.endswith("\n"):
            sys.stdout.write("\n")
        print(f"GATE_TIME[selftest:{name}]={_fmt_secs(elapsed)}")

    print(f"GATE_TIME[gate-selftests]={_fmt_secs(time.monotonic() - group_start)}")

    if first_failure is not None:
        rc = results[first_failure][0]
        print(
            f"ERROR[ASTRO_GATE_SELFTEST_FAILED]: {first_failure} exited {rc}; "
            "recorded-green manifest left unchanged",
            file=sys.stderr,
        )
        return rc

    # All ran-tests passed: refresh the recorded green fingerprints. Keep prior
    # entries for tests skipped this run; overwrite the ones that just passed.
    # UNCONDITIONAL tests are never fingerprinted (they always run).
    merged = dict(recorded)
    for name in to_run:
        if name in UNCONDITIONAL:
            continue
        fp = fresh_fingerprints.get(name)
        if fp is None:
            fp, missing = fingerprint(root, name)
        if fp is not None:
            merged[name] = fp
    # Drop stale entries for tests no longer in the supplied set.
    merged = {k: v for k, v in merged.items() if k in names and k not in UNCONDITIONAL}
    try:
        write_manifest(manifest_path, merged)
    except OSError as exc:
        print(
            f"WARN[ASTRO_GATE_SELFTESTS]: could not write manifest {manifest_path}: {exc}",
            file=sys.stderr,
        )

    ran = len([n for n in to_run if n in results])
    print(
        f"gate self-tests OK: ran={ran} skipped={len(skipped)} "
        f"unconditional={len([n for n in to_run if n in UNCONDITIONAL])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
