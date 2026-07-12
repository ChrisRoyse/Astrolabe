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
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check-no-escape.py"
SCRATCH = ROOT / ".tmp" / "no-escape-attribution-selftest"

# Synthetic, deterministic PIDs: attribution is by pid TOKEN vs the recorded tree
# set, so no live process is needed -- the control is fully reproducible.
TREE_PID = 424242
FOREIGN_PID = 313131
# Mirrors the live registry's attribution.skew_margin_secs knob (invariant 4).
SKEW_SECS = 2
NS = 1_000_000_000


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
        # Invariant-4 knob, same value the live registry declares (see
        # scripts/no-escape-roots.json attribution._doc for the derivation).
        "attribution": {"skew_margin_secs": SKEW_SECS},
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


def write_manifest(
    path: Path,
    owned_paths: list[Path],
    run_started_ns: int | None = None,
    pid_first_seen: dict[int, int] | None = None,
    pid_intervals: dict[int, list[tuple[int, int | None]]] | None = None,
    tree_pids: list[int] | None = None,
    written_at: int | None = None,
) -> None:
    manifest: dict = {
        "schema": "astrolabe.no_escape_attribution.v1",
        "launcher_pid": TREE_PID,
        "tree_pids": tree_pids if tree_pids is not None else [TREE_PID],
        "owned_paths": [str(entry) for entry in owned_paths],
    }
    if run_started_ns is not None:
        manifest["run_started_unix_ns"] = run_started_ns
    if written_at is not None:
        manifest["written_at"] = written_at
    if pid_first_seen is not None:
        manifest["pid_first_seen"] = {str(pid): ns for pid, ns in pid_first_seen.items()}
    if pid_intervals is not None:
        manifest["pid_intervals"] = {
            str(pid): [[first, last] for first, last in spans]
            for pid, spans in pid_intervals.items()
        }
    path.write_text(json.dumps(manifest), encoding="utf-8")


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
    # Escapes are printed to stderr; a counted entry appears only in the stdout
    # COUNTED[...] evidence lines. Policing would have put it on stderr + exit 1.
    if foreign.name in result.stderr:
        raise AssertionError(f"foreign entry was policed as an escape:\n{result.stderr}")
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

    # ---- attempt-6 refinements (#278): run-window, stale dir mtime, pid reuse ----
    now_ns = time.time_ns()

    print("=== 8. STALE/PRE-RUN: MODIFIED dir, pre-run mtimes, COLLIDING tree pid -> counted ===")
    # The exact attempt-6 shape: calyx-leapable-*-<pid> whose baseline AND observed
    # mtimes both predate the run, where <pid> collides with a recycled pid in our
    # tree. Must be counted + labeled, never policed.
    stale_dir = paths["temp"] / f"calyx-leapable-stdio-lifecycle-{TREE_PID}"
    stale_dir.mkdir()
    old_ns = now_ns - 3600 * NS
    os.utime(stale_dir, ns=(old_ns, old_ns))
    snapshot(paths)
    # NTFS-lagging-duplicated-info analogue: the timestamp moves ~200ms but both
    # values predate run_started (attempt 6 measured 164-168 ms of skew).
    os.utime(stale_dir, ns=(old_ns + 200_000_000, old_ns + 200_000_000))
    window_manifest = paths["fixture"] / "attribution-window.json"
    write_manifest(
        window_manifest,
        owned_paths=[],
        run_started_ns=now_ns,
        pid_first_seen={TREE_PID: now_ns},
    )
    result = verify(paths, window_manifest)
    expect_clean(result, "pre-run stale dir mtime")
    if "ASTRO_NO_ESCAPE_STALE_DIR_MTIME" not in result.stdout:
        raise AssertionError(f"stale dir mtime was not labeled:\n{result.stdout}")
    print(f"  independent readback: {stale_dir} exists, mtimes pre-run, counted under STALE_DIR_MTIME")
    shutil.rmtree(stale_dir)

    print("=== 9. REGRESSION GUARD: in-window MODIFIED + ADDED with tree pid -> still RED ===")
    mod_dir = paths["temp"] / f"calyx-retention-mixed-{TREE_PID}"
    mod_dir.mkdir()
    os.utime(mod_dir, ns=(old_ns, old_ns))
    snapshot(paths)
    now_ns = time.time_ns()
    os.utime(mod_dir, ns=(now_ns, now_ns))  # a real in-window write to an existing dir
    add_dir = paths["temp"] / f"calyx-retention-retain-{TREE_PID}"
    add_dir.mkdir()  # a real in-window creation
    write_manifest(
        window_manifest,
        owned_paths=[],
        run_started_ns=now_ns - 60 * NS,
        pid_first_seen={TREE_PID: now_ns - 60 * NS},
    )
    result = verify(paths, window_manifest)
    expect_red(result, mod_dir.name, "in-window modified")
    if add_dir.name not in (result.stdout + result.stderr):
        raise AssertionError(f"in-window ADDED was not policed:\n{result.stdout}\n{result.stderr}")
    print(f"  independent readback: {mod_dir} and {add_dir} in-window, both policed")
    shutil.rmtree(mod_dir)
    shutil.rmtree(add_dir)

    print("=== 10. BOUNDARY: skew margin respected on the run-window guard ===")
    snapshot(paths)
    now_ns = time.time_ns()
    in_margin = paths["temp"] / f"calyx-retention-already-{TREE_PID}"
    in_margin.mkdir()
    in_margin_ts = now_ns - (SKEW_SECS * NS - NS // 2)  # run_started - skew + 0.5s: inside
    os.utime(in_margin, ns=(in_margin_ts, in_margin_ts))
    out_margin = paths["temp"] / f"calyx-retention-failures-{TREE_PID}"
    out_margin.mkdir()
    out_margin_ts = now_ns - (SKEW_SECS * NS + 5 * NS)  # run_started - skew - 5s: outside
    os.utime(out_margin, ns=(out_margin_ts, out_margin_ts))
    write_manifest(
        window_manifest,
        owned_paths=[],
        run_started_ns=now_ns,
        pid_first_seen={TREE_PID: now_ns - 60 * NS},
    )
    result = verify(paths, window_manifest)
    expect_red(result, in_margin.name, "inside skew margin")
    combined = result.stdout + result.stderr
    if f"COUNTED[pre_run] ADDED" not in combined or out_margin.name not in result.stdout:
        raise AssertionError(f"outside-margin entry was not counted as pre-run:\n{combined}")
    escape_section = result.stderr
    if out_margin.name in escape_section:
        raise AssertionError(f"outside-margin entry was policed:\n{escape_section}")
    print(f"  boundary: {in_margin.name} (t-{SKEW_SECS - 0.5:.1f}s) RED; {out_margin.name} (t-{SKEW_SECS + 5}s) counted")
    shutil.rmtree(in_margin)
    shutil.rmtree(out_margin)

    print("=== 11. PID REUSE: in-window entry predating our pid instance's first-seen -> counted ===")
    snapshot(paths)
    now_ns = time.time_ns()
    reused = paths["temp"] / f"calyx-retention-rollup-scan-{TREE_PID}"
    reused.mkdir()
    entry_ts = now_ns - 30 * NS  # within the run window ...
    os.utime(reused, ns=(entry_ts, entry_ts))
    write_manifest(
        window_manifest,
        owned_paths=[],
        run_started_ns=now_ns - 120 * NS,
        # ... but our pid instance was first seen AFTER the entry existed: the
        # token matches a recycled pid, not our process.
        pid_first_seen={TREE_PID: now_ns},
    )
    result = verify(paths, window_manifest)
    expect_clean(result, "recycled pid")
    if "ASTRO_NO_ESCAPE_PID_INSTANCE_MISMATCH" not in result.stdout:
        raise AssertionError(f"pid-instance mismatch was not labeled:\n{result.stdout}")
    print(f"  independent readback: {reused} predates our pid instance, counted not policed")
    shutil.rmtree(reused)

    # ---- attempt-7 refinements (#278): pid instance LIFETIME windows ----

    print("=== 12. DEAD INSTANCE (attempt-7 shape, real numbers): entry after our exit -> counted ===")
    # Attempt 7 ground truth: foreign pid 46128 collided with a launcher-startup
    # child of ours first seen 14:24:53 and long dead when the foreign sweep's dir
    # appeared at 14:34:47. Reconstruct with the real offsets: run 14:20:00, our
    # instance [14:24:53, 14:25:30], entry 14:34:47 -- in the run window, in the
    # tree, INSIDE no lifetime interval.
    snapshot(paths)
    now_ns = time.time_ns()
    base = now_ns - 20 * 60 * NS  # "14:20:00" = t0
    dead_pid = 46128
    dead_dir = paths["temp"] / f"calyx-erase-ledger-basic-{dead_pid}"
    dead_dir.mkdir()
    entry_ts = base + (14 * 60 + 47) * NS  # 14:34:47
    os.utime(dead_dir, ns=(entry_ts, entry_ts))
    lifetime_manifest = paths["fixture"] / "attribution-lifetime.json"
    write_manifest(
        lifetime_manifest,
        owned_paths=[],
        run_started_ns=base,
        tree_pids=[TREE_PID, dead_pid],
        pid_intervals={
            TREE_PID: [(base, None)],
            dead_pid: [(base + (4 * 60 + 53) * NS, base + (5 * 60 + 30) * NS)],  # 14:24:53-14:25:30
        },
    )
    result = verify(paths, lifetime_manifest)
    expect_clean(result, "dead-instance collision")
    if "ASTRO_NO_ESCAPE_PID_INSTANCE_MISMATCH" not in result.stdout:
        raise AssertionError(f"dead-instance collision was not labeled:\n{result.stdout}")
    print(f"  independent readback: {dead_dir} postdates our pid {dead_pid} instance's exit, counted")
    shutil.rmtree(dead_dir)

    print("=== 13. REGRESSION GUARD: leak DURING the instance's lifetime -> still RED ===")
    snapshot(paths)
    now_ns = time.time_ns()
    live_dir = paths["temp"] / f"calyx-retention-bad-metadata-{TREE_PID}"
    live_dir.mkdir()
    entry_ts = now_ns - 30 * NS
    os.utime(live_dir, ns=(entry_ts, entry_ts))
    write_manifest(
        lifetime_manifest,
        owned_paths=[],
        run_started_ns=now_ns - 120 * NS,
        # closed interval that CONTAINS the entry: instance alive at write time
        pid_intervals={TREE_PID: [(now_ns - 60 * NS, now_ns - 10 * NS)]},
    )
    expect_red(verify(paths, lifetime_manifest), live_dir.name, "leak within lifetime")
    print(f"  independent readback: {live_dir} written during our instance's lifetime, policed")
    shutil.rmtree(live_dir)

    print("=== 14. ALIVE INSTANCE (no exit stamp): open window still attributes in-window -> RED ===")
    snapshot(paths)
    now_ns = time.time_ns()
    alive_dir = paths["temp"] / f"calyx-retention-all-expired-{TREE_PID}"
    alive_dir.mkdir()  # mtime now, in-window
    write_manifest(
        lifetime_manifest,
        owned_paths=[],
        run_started_ns=now_ns - 60 * NS,
        # null upper bound = never got an exit message = still alive: never 'assume dead'
        pid_intervals={TREE_PID: [(now_ns - 60 * NS, None)]},
    )
    expect_red(verify(paths, lifetime_manifest), alive_dir.name, "open-window alive instance")
    print(f"  independent readback: {alive_dir} attributed through the open (alive) window, policed")
    shutil.rmtree(alive_dir)

    print("=== 15. INTRA-TREE REUSE: same pid, two of OUR instances -> entry in ANY interval RED, between -> counted ===")
    snapshot(paths)
    now_ns = time.time_ns()
    in_second = paths["temp"] / f"calyx-retention-rollup-apply-{TREE_PID}"
    in_second.mkdir()
    second_ts = now_ns - 20 * NS  # inside our second instance [t-30, t-10]
    os.utime(in_second, ns=(second_ts, second_ts))
    between = paths["temp"] / f"calyx-leapable-stdio-lifecycle-{TREE_PID}"
    between.mkdir()
    between_ts = now_ns - 45 * NS  # in the gap between our two instances
    os.utime(between, ns=(between_ts, between_ts))
    write_manifest(
        lifetime_manifest,
        owned_paths=[],
        run_started_ns=now_ns - 120 * NS,
        pid_intervals={TREE_PID: [(now_ns - 100 * NS, now_ns - 55 * NS), (now_ns - 30 * NS, now_ns - 10 * NS)]},
    )
    result = verify(paths, lifetime_manifest)
    expect_red(result, in_second.name, "second-instance leak")
    if f"COUNTED[pid_instance] ADDED" not in result.stdout or between.name not in result.stdout:
        raise AssertionError(f"between-instances entry was not counted:\n{result.stdout}")
    if between.name in result.stderr:
        raise AssertionError(f"between-instances entry was policed:\n{result.stderr}")
    print(f"  {in_second.name} inside instance 2 -> RED; {between.name} between instances -> counted")
    shutil.rmtree(in_second)
    shutil.rmtree(between)

    # ---- attempt-8 refinement (#278): throttle-race stale-manifest guard ----

    print("=== 16. STALE MANIFEST ('Control 17'): delta POSTDATES written_at -> RED, not foreign ===")
    # THROTTLE RACE: the launcher's recorder rewrites the manifest ~1/sec while the
    # run is live, and `verify` reads it MID-SESSION, before the teardown's final
    # flush. So a process that leaked AFTER the last flush is not yet in tree_pids.
    # Here a delta with a pid NOT in the tree lands AFTER the manifest's written_at:
    # without the guard its pid-mismatch classifies FOREIGN (counted, PASS); with the
    # guard the gate sees the delta postdates the flush and CANNOT trust 'foreign', so
    # it POLICES it (ASTRO_NO_ESCAPE_STALE_MANIFEST -> RED). Fail-closed, never silent.
    snapshot(paths)
    now_ns = time.time_ns()
    post_flush = paths["temp"] / f"calyx-retention-post-flush-{FOREIGN_PID}"
    post_flush.mkdir()
    os.utime(post_flush, ns=(now_ns, now_ns))  # entry timestamp = "now"
    stale_manifest = paths["fixture"] / "attribution-stale.json"
    write_manifest(
        stale_manifest,
        owned_paths=[],
        run_started_ns=now_ns - 120 * NS,  # in-window (not pre-run)
        written_at=now_ns - 60 * NS,  # flushed 60s BEFORE the delta: stale for it
        tree_pids=[TREE_PID],  # FOREIGN_PID is NOT in the tree
        pid_intervals={TREE_PID: [(now_ns - 120 * NS, None)]},
    )
    manifest_bytes = stale_manifest.read_bytes()
    print(f"  FSV manifest byte-readback: {manifest_bytes.decode('utf-8')}")
    result = verify(paths, stale_manifest)
    expect_red(result, post_flush.name, "stale-manifest post-flush delta")
    if "ASTRO_NO_ESCAPE_STALE_MANIFEST" not in (result.stdout + result.stderr):
        raise AssertionError(f"stale-manifest delta was not labeled:\n{result.stdout}\n{result.stderr}")
    print("  FSV gate output (stale-manifest label + RED):")
    for line in (result.stdout + result.stderr).splitlines():
        if "STALE_MANIFEST" in line or "stale_manifest" in line or "ASTRO_TEST_SANDBOX_ESCAPE" in line:
            print(f"    {line}")
    print(f"  gate exit code: {result.returncode}")
    if not post_flush.is_dir():
        raise AssertionError("control vacuous: post-flush dir absent on disk")
    print(f"  independent readback: {post_flush} postdates written_at, POLICED not foreign")
    shutil.rmtree(post_flush)

    print("=== 17. GUARD BOUND: delta at/inside written_at + skew stays counted (foreign) ===")
    # The dual of control 16: a foreign delta whose timestamp is WITHIN the skew
    # margin of written_at is NOT stale (a healthy recorder flushes within skew), so
    # it must remain counted -- proving the guard reddens only genuinely-late deltas,
    # not normal in-window foreign churn, and does not re-redden the whole shared root.
    snapshot(paths)
    now_ns = time.time_ns()
    within = paths["temp"] / f"calyx-retention-within-skew-{FOREIGN_PID}"
    within.mkdir()
    within_ts = now_ns  # entry "now"
    os.utime(within, ns=(within_ts, within_ts))
    fresh_manifest = paths["fixture"] / "attribution-fresh.json"
    write_manifest(
        fresh_manifest,
        owned_paths=[],
        run_started_ns=now_ns - 120 * NS,
        written_at=now_ns,  # flushed at the delta time: within skew, NOT stale
        tree_pids=[TREE_PID],
        pid_intervals={TREE_PID: [(now_ns - 120 * NS, None)]},
    )
    result = verify(paths, fresh_manifest)
    expect_clean(result, "within-skew foreign churn")
    if "ASTRO_NO_ESCAPE_STALE_MANIFEST" in (result.stdout + result.stderr):
        raise AssertionError(f"within-skew delta was wrongly flagged stale:\n{result.stdout}")
    if within.name in result.stderr:
        raise AssertionError(f"within-skew foreign delta was policed:\n{result.stderr}")
    print(f"  independent readback: {within} within skew of written_at, counted not policed")
    shutil.rmtree(within)

    shutil.rmtree(SCRATCH, ignore_errors=True)
    print("no-escape attribution control passed: causal, windowed, instance-lifetime-aware (#278)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
