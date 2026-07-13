#!/usr/bin/env python3
"""Suite-level impact gate (#280): a test suite runs ONLY when code changes
impact it (owner directive, 2026-07-12 — "no test suite should ever be run if
no code changes impact the test").

Each registered suite declares its INPUT SET: the repo paths whose bytes feed
the suite (sources it compiles, fixtures it reads, the gate scripts that drive
it) plus the identity of the toolchain that executes it. The gate fingerprints
that input set and compares it to the recorded-green manifest:

    fingerprint unchanged since last GREEN run  =>  SKIP (named, counted)
    anything else                               =>  RUN

FAIL-CLOSED CONTRACT (unknown state => run, never skip)
    * Manifest absent/corrupt/wrong-schema, git unavailable, a tool version
      unreadable, any subprocess failure  =>  RUN.
    * ``ASTRO_SUITE_GATE=all``  =>  RUN regardless of the manifest
      (scripts/check-release.sh sets this: the release tier always runs all).
    * ``record-green`` is invoked by the caller ONLY after the suite itself
      passed; a red run leaves the recorded green state untouched.
    * The registry entry itself is part of the fingerprint, so widening or
      narrowing a suite's declared inputs invalidates its recorded green.

FINGERPRINT (content-exact, fast)
    * ``git ls-files -s -- <paths>`` supplies (mode, blob-sha, path) for every
      tracked input — index blob hashes, no re-hashing of clean bytes.
    * ``git status --porcelain=v2 -z --untracked-files=all -- <paths>``
      supplies the dirty overlay; each dirty/untracked file's WORKING-TREE
      bytes are hashed (a deleted file contributes a deletion marker). This is
      what makes the gate sound on a dirty tree — the recorded state is the
      bytes that actually ran, not whatever HEAD says.
    * Declared tool commands (e.g. ``rustc -V``) are salted in, so a toolchain
      bump re-runs every suite it executes.

EXIT CODES
    should-run:  0 = run the suite, 3 = skip (unchanged since recorded green).
                 Internal ambiguity NEVER propagates as failure — it prints an
                 INFO and exits 0 (run). Only usage errors exit 2.
    record-green: 0 always (a failed write prints WARN — the only consequence
                 is that the next run runs again, which is the safe direction).
    fingerprint: 0 with the fingerprint on stdout, 1 if it cannot be computed
                 soundly (callers keying caches on it must then rebuild).

RECORDED-GREEN LOCATION
    ``.astro-gate-cache/suite-green.json`` (durable across target/ wipes,
    gitignored, never launcher-owned). Override: ASTRO_SUITE_CACHE_DIR.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[1]

MANIFEST_VERSION = 1
MANIFEST_NAME = "suite-green.json"

# ── Suite registry ───────────────────────────────────────────────────────────
#
# paths: repo-relative files or directories (a directory means every tracked +
#        untracked-not-ignored file under it).
# tools: argv lists whose stdout identifies the executing toolchain; the raw
#        output is salted into the fingerprint.
#
# A suite ABSENT from this registry cannot be gated: should-run exits 0 (run)
# with a fail-closed INFO. When in doubt, declare MORE inputs — a too-wide set
# costs an occasional extra run; a too-narrow set is a soundness hole.
SUITES: dict[str, dict[str, list]] = {
    # The vendored/owned CBM C suite (ci-cbm-test.sh): compiles the whole CBM
    # tree and reads fixtures from anywhere inside it.
    "cbm-c-suite": {
        "paths": [
            "vendor/codebase-memory-mcp",
            "patches/cbm",
            "scripts/ci-cbm-test.sh",
            "scripts/check-cbm-cache-hermeticity.py",
            "scripts/check-cbm-skip-count.sh",
            "ci/cbm-test-totals.md",
            "ci/known-skips.md",
        ],
        "tools": [
            ["gcc", "-dumpfullversion"],
            ["g++", "-dumpfullversion"],
            ["make", "--version"],
        ],
    },
    # check.sh's dynamic block: the workspace test phase plus every downstream
    # gate that drives the built astrolabe/codebase-memory-mcp binaries. The
    # Rust workspace links libcbm (cbm-sys compiles the owned CBM sources) and
    # the parity gates execute the CBM prod binary, so the CBM tree and the
    # patches/cbm build wiring are genuine inputs of this block, not just of
    # the C suite.
    "workspace-block": {
        "paths": [
            "crates",
            "vendor/calyx",
            "vendor/codebase-memory-mcp",
            "patches/cbm",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".config/nextest.toml",
            ".cargo",
            "ci",
            "scripts/check-workspace-tests.py",
            "scripts/check-astrolabe-verify-chain.sh",
            "scripts/check-single-mimalloc.sh",
            "scripts/check-mcp-parity.sh",
            "scripts/check-mcp-parity.py",
            "scripts/check-cli-parity.py",
            "scripts/check-compat-shim.py",
            "scripts/check-installer-roundtrip.py",
            "scripts/check-hook-contracts.py",
            "scripts/check-server-manifest.py",
            "scripts/check-lowered-parity.py",
            "scripts/check-shadow-parity.py",
            "scripts/check-license-notices.py",
            "scripts/check-hazard-suite.py",
            "scripts/check-cross-process-vault.py",
            "scripts/check-cross-process-servers.py",
            "scripts/check-astrolabe-watchdog.sh",
            "scripts/check-egress-deny.py",
            "scripts/check-no-escape.py",
            "scripts/cbm-prod-build.sh",
            "scripts/release_artifact.py",
            "scripts/no-escape-roots.json",
            "scripts/native-cargo-fmt.py",
            "scripts/check-calyx-path-deps.py",
        ],
        "tools": [
            ["rustc", "-V"],
            ["cargo", "nextest", "--version"],
            ["gcc", "-dumpfullversion"],
        ],
    },
    # The full Rust lint/doc/Calyx tier (ci-rust-gate.sh), owned by
    # check-release.sh after the #280 tier restructure.
    "rust-gate": {
        "paths": [
            "crates",
            "vendor/calyx",
            "vendor/codebase-memory-mcp",
            "patches/cbm",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".config/nextest.toml",
            ".cargo",
            "scripts/ci-rust-gate.sh",
            "scripts/native-cargo-fmt.py",
            "scripts/rust_prod_lines.py",
        ],
        "tools": [
            ["rustc", "-V"],
            ["cargo", "nextest", "--version"],
            ["gcc", "-dumpfullversion"],
        ],
    },
    # The CBM production parity binary (scripts/cbm-prod-build.sh): a pure
    # function of the owned CBM sources + the patches/cbm Makefile/glue + the
    # C toolchain. This entry is not a runnable suite — its fingerprint is the
    # binary cache key, and it is content-exact over the WORKING TREE, so a
    # dirty vendor tree can never restore a binary built from different bytes
    # (the former HEAD:-keyed cache could).
    "cbm-parity-binary": {
        "paths": [
            "vendor/codebase-memory-mcp",
            "patches/cbm",
        ],
        "tools": [
            ["gcc", "-dumpfullversion"],
            ["g++", "-dumpfullversion"],
            ["make", "--version"],
        ],
    },
    # The CBM C static-analysis tier (ci-cbm-lint.sh), owned by
    # check-release.sh after the #280 tier restructure.
    "cbm-lint": {
        "paths": [
            "vendor/codebase-memory-mcp",
            "patches/cbm",
            "scripts/ci-cbm-lint.sh",
            "scripts/check-cbm-cache-paths.py",
            "ci/cbm-cache-path-offenders.md",
            "ci/known-skips.md",
        ],
        "tools": [
            ["cppcheck", "--version"],
            ["clang-format", "--version"],
        ],
    },
}


def _load_registry_override() -> None:
    """Self-test seam: ASTRO_SUITE_REGISTRY_JSON replaces the registry.

    Production callers never set it (the launcher does not export it); the
    self-test uses it to prove the mechanism on a fixture repo. A malformed
    override empties the registry, which fails closed (every suite RUNS).
    """
    raw = os.environ.get("ASTRO_SUITE_REGISTRY_JSON")
    if raw is None:
        return
    global SUITES
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("registry override must be a JSON object")
        SUITES = parsed
    except ValueError as exc:
        print(f"INFO[ASTRO_SUITE_GATE_FAILCLOSED]: bad registry override ({exc})", flush=True)
        SUITES = {}


def _p(msg: str) -> None:
    print(msg, flush=True)


def _run_git(root: Path, args: list[str]) -> bytes:
    proc = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args[:3])}... exited {proc.returncode}: "
            f"{proc.stderr.decode('utf-8', 'replace').strip()[:200]}"
        )
    return proc.stdout


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tool_id(argv: list[str]) -> str:
    proc = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"tool id {' '.join(argv)} exited {proc.returncode}")
    return proc.stdout.decode("utf-8", "replace").strip()


def compute_fingerprint(root: Path, suite: str) -> str:
    """Content-exact fingerprint of the suite's declared input set.

    Raises RuntimeError on ANY ambiguity — callers translate that into the
    fail-closed direction (run / rebuild), never into a skip.
    """
    entry = SUITES[suite]
    paths: list[str] = entry["paths"]
    digest = hashlib.sha256()

    # The registry entry itself: changed input declarations invalidate greens.
    digest.update(json.dumps(entry, sort_keys=True).encode("utf-8"))

    # Tracked state from the index: (mode, blob sha, path) triplets. This is
    # content-exact for clean files without re-hashing them.
    ls = _run_git(root, ["ls-files", "-s", "-z", "--", *paths])
    if not ls.strip():
        raise RuntimeError(f"suite {suite}: git ls-files matched no tracked files")
    digest.update(b"tracked\0")
    digest.update(ls)

    # Dirty overlay: modified, deleted, and untracked files under the input
    # paths, hashed from the WORKING TREE (the bytes that will actually run).
    status = _run_git(
        root,
        [
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignored=no",
            "--",
            *paths,
        ],
    )
    digest.update(b"dirty\0")
    for record in status.split(b"\0"):
        if not record:
            continue
        text = record.decode("utf-8", "replace")
        kind = text[0:1]
        if kind == "1" or kind == "2":
            rel = text.split(" ", 8)[8]
        elif kind == "?":
            rel = text[2:]
        elif kind == "u":
            rel = text.split(" ", 10)[10]
        else:
            continue
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        candidate = root / rel
        if candidate.is_file():
            digest.update(_hash_file(candidate).encode("ascii"))
        else:
            digest.update(b"<absent>")
        digest.update(b"\0")

    # Toolchain identity.
    digest.update(b"tools\0")
    for argv in entry["tools"]:
        digest.update(_tool_id(argv).encode("utf-8"))
        digest.update(b"\0")

    return digest.hexdigest()


def manifest_path(root: Path) -> Path:
    cache_dir = Path(os.environ.get("ASTRO_SUITE_CACHE_DIR", str(root / ".astro-gate-cache")))
    return cache_dir / MANIFEST_NAME


def load_manifest(path: Path) -> tuple[dict, bool]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}, False
    if not isinstance(data, dict) or data.get("version") != MANIFEST_VERSION:
        return {}, False
    suites = data.get("suites")
    if not isinstance(suites, dict):
        return {}, False
    return suites, True


def write_manifest(path: Path, suites: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": MANIFEST_VERSION, "suites": suites}
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def cmd_should_run(root: Path, suite: str) -> int:
    if suite not in SUITES:
        _p(f"INFO[ASTRO_SUITE_GATE_FAILCLOSED]: suite={suite} not in registry -> RUN")
        return 0
    mode = os.environ.get("ASTRO_SUITE_GATE", "auto").strip().lower()
    if mode == "all":
        _p(f"INFO[ASTRO_SUITE_GATE_ALL]: ASTRO_SUITE_GATE=all -> suite={suite} RUNS")
        return 0
    recorded, ok = load_manifest(manifest_path(root))
    if not ok:
        _p(
            f"INFO[ASTRO_SUITE_GATE_FAILCLOSED]: recorded-green manifest absent/corrupt "
            f"at {manifest_path(root)} -> suite={suite} RUNS"
        )
        return 0
    entry = recorded.get(suite)
    if not isinstance(entry, dict) or not isinstance(entry.get("fingerprint"), str):
        _p(f"INFO[ASTRO_SUITE_IMPACTED]: suite={suite} has no recorded green -> RUNS")
        return 0
    try:
        current = compute_fingerprint(root, suite)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        _p(f"INFO[ASTRO_SUITE_GATE_FAILCLOSED]: suite={suite} fingerprint error ({exc}) -> RUNS")
        return 0
    if current == entry["fingerprint"]:
        note = entry.get("note", "")
        _p(
            f"SKIP[ASTRO_SUITE_UNCHANGED]: suite={suite} fingerprint={current[:12]} "
            f"recorded_green={entry.get('recorded_utc', '?')}"
            + (f" note={note}" if note else "")
        )
        _p(
            f"  doctrine: no suite runs when no code change impacts it (#280); "
            f"this suite's input set is byte-identical to its last green run. "
            f"Force with ASTRO_SUITE_GATE=all (check-release runs all)."
        )
        return 3
    _p(f"INFO[ASTRO_SUITE_IMPACTED]: suite={suite} fingerprint changed -> RUNS")
    return 0


def cmd_record_green(root: Path, suite: str, note: str) -> int:
    if suite not in SUITES:
        _p(f"WARN[ASTRO_SUITE_GATE]: record-green for unregistered suite={suite} ignored")
        return 0
    try:
        current = compute_fingerprint(root, suite)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        _p(f"WARN[ASTRO_SUITE_GATE]: suite={suite} green not recorded ({exc}); next run re-runs")
        return 0
    path = manifest_path(root)
    recorded, _ok = load_manifest(path)
    recorded[suite] = {
        "fingerprint": current,
        "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": note,
    }
    try:
        write_manifest(path, recorded)
    except OSError as exc:
        _p(f"WARN[ASTRO_SUITE_GATE]: could not write {path}: {exc}; next run re-runs")
        return 0
    _p(f"INFO[ASTRO_SUITE_GREEN_RECORDED]: suite={suite} fingerprint={current[:12]}")
    return 0


def cmd_fingerprint(root: Path, suite: str) -> int:
    if suite not in SUITES:
        print(f"ERROR: unknown suite {suite}", file=sys.stderr)
        return 1
    try:
        print(compute_fingerprint(root, suite))
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: fingerprint unavailable: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2 or argv[0] not in {"should-run", "record-green", "fingerprint"}:
        print(
            "usage: check-suite-impact.py {should-run|record-green|fingerprint} <suite> [--note N]",
            file=sys.stderr,
        )
        return 2
    command, suite = argv[0], argv[1]
    _load_registry_override()
    note = ""
    if "--note" in argv[2:]:
        idx = argv.index("--note")
        if idx + 1 < len(argv):
            note = argv[idx + 1]
    root = Path(os.environ.get("ASTRO_SUITE_ROOT", str(DEFAULT_ROOT))).resolve()
    if command == "should-run":
        return cmd_should_run(root, suite)
    if command == "record-green":
        return cmd_record_green(root, suite, note)
    return cmd_fingerprint(root, suite)


if __name__ == "__main__":
    raise SystemExit(main())
