#!/usr/bin/env python3
"""Self-test for the ASTROLABE #260 upstream-pending Calyx RAII scratch guard.

Fail-closed. Drives the *shipped* reference guard (patches/calyx/scratch_dir.rs)
against a faithful reproduction of the current vendored leak pattern, then reads
back the filesystem (FSV) to assert:

  1. the current `env::temp_dir().join(prefix-pid)` pattern LEAKS on panic,
  2. the reference `ScratchDir` guard SELF-CLEANS the same dir on panic,
  3. the guard source introduces NO `tempfile` dependency (Calyx has none),
  4. the enumerated producers still exist in vendor/ (census stays honest;
     drift fails this test instead of silently going stale).

Needs only `rustc` (no cargo, no target/). Compiles into a scratch dir that it
removes on exit. Exit 0 = pass; non-zero = fail.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GUARD = REPO / "patches" / "calyx" / "scratch_dir.rs"

# Producers named in issue #260 body — census anchor. Drift => fail-closed.
ENUMERATED = [
    "vendor/calyx/crates/calyx-aster/src/supply_chain/tests.rs",
    "vendor/calyx/crates/calyx-aster/src/retention/tests.rs",
    "vendor/calyx/crates/calyx-aster/tests/fsv_support/mod.rs",
    "vendor/calyx/crates/calyx-testkit/src/lib.rs",
    "vendor/calyx/crates/calyx-fsv/src/lib.rs",
]

HARNESS = r"""
mod scratch_dir; // included below

use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use scratch_dir::ScratchDir;

static SEQ: AtomicU64 = AtomicU64::new(0);

// Faithful copy of the CURRENT vendored pattern (fsv_support::temp_root).
fn buggy(root: &Path, name: &str) -> PathBuf {
    let id = SEQ.fetch_add(1, Ordering::Relaxed);
    let d = root.join(format!("calyx-aster-{name}-{}-{id}", process::id()));
    fs::create_dir_all(&d).unwrap();
    d
}

fn main() {
    let root = PathBuf::from(std::env::args().nth(1).expect("sandbox arg"));
    let s1 = root.join("case1"); fs::create_dir_all(&s1).unwrap();
    let s2 = root.join("case2"); fs::create_dir_all(&s2).unwrap();

    // Case 1: current pattern panics -> must leak.
    let b = std::sync::Mutex::new(PathBuf::new());
    let _ = std::panic::catch_unwind(|| {
        let d = buggy(&s1, "issue2011-physical-residue");
        *b.lock().unwrap() = d.clone();
        panic!("sim");
    });
    let bpath = b.lock().unwrap().clone();

    // Case 2: RAII guard panics while held -> must self-clean.
    let g = std::sync::Mutex::new(PathBuf::new());
    let _ = std::panic::catch_unwind(|| {
        let sd = ScratchDir::new(&s2, "calyx-aster", "issue2011-physical-residue").unwrap();
        *g.lock().unwrap() = sd.path().to_path_buf();
        panic!("sim");
    });
    let gpath = g.lock().unwrap().clone();

    println!("case1_leaks={}", bpath.exists());
    println!("case2_selfcleans={}", !gpath.exists());
    if bpath.exists() && !gpath.exists() {
        println!("SELFTEST=PASS");
    } else {
        println!("SELFTEST=FAIL");
        process::exit(2);
    }
}
"""


def fail(msg: str) -> None:
    print(f"FAIL[ASTRO_CALYX_RAII_SELFTEST]: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if not GUARD.is_file():
        fail(f"guard source missing: {GUARD}")
    guard_src = GUARD.read_text(encoding="utf-8")

    # (3) dependency-free invariant. Detect real *usage* (not doc prose that
    # explains why the crate is deliberately avoided).
    code_lines = [
        ln for ln in guard_src.splitlines()
        if not ln.lstrip().startswith("//")
    ]
    code = "\n".join(code_lines)
    if "tempfile::" in code or "use tempfile" in code or "extern crate tempfile" in code:
        fail("reference guard *uses* `tempfile`; Calyx must stay tempfile-free")
    if "impl Drop for ScratchDir" not in guard_src:
        fail("reference guard has no Drop impl — not RAII")

    # (4) census anchor.
    for rel in ENUMERATED:
        if not (REPO / rel).is_file():
            fail(f"enumerated producer vanished (census drift): {rel}")

    rustc = subprocess.run(
        ["rustc", "--version"], capture_output=True, text=True
    )
    if rustc.returncode != 0:
        fail("rustc unavailable")
    print(f"rustc: {rustc.stdout.strip()}")

    with tempfile.TemporaryDirectory(prefix="calyx-raii-selftest-") as td:
        tdp = Path(td)
        # Ship the SAME guard the repo carries; harness `mod scratch_dir` pulls it.
        (tdp / "scratch_dir.rs").write_text(guard_src, encoding="utf-8")
        main_rs = tdp / "harness.rs"
        main_rs.write_text(HARNESS, encoding="utf-8")
        exe = tdp / ("harness.exe" if os.name == "nt" else "harness")
        cc = subprocess.run(
            ["rustc", "-O", str(main_rs), "-o", str(exe)],
            capture_output=True, text=True, cwd=td,
        )
        if cc.returncode != 0:
            fail(f"reference guard failed to compile:\n{cc.stderr}")

        sandbox = tdp / "sbx"
        sandbox.mkdir()
        env = dict(os.environ, TMP=str(sandbox), TEMP=str(sandbox), TMPDIR=str(sandbox))
        run = subprocess.run(
            [str(exe), str(sandbox)], capture_output=True, text=True, env=env
        )
        print(run.stdout.strip())
        # FSV byte readback: assert both dirs' actual on-disk state.
        case1 = list((sandbox / "case1").glob("calyx-aster-*"))
        case2 = list((sandbox / "case2").glob("calyx-aster-*"))
        print(f"readback case1 (expect leak) : {[p.name for p in case1]}")
        print(f"readback case2 (expect empty): {[p.name for p in case2]}")
        if "SELFTEST=PASS" not in run.stdout:
            fail(f"harness verdict not PASS:\n{run.stdout}\n{run.stderr}")
        if not case1:
            fail("expected current pattern to leak in case1 but it did not")
        if case2:
            fail(f"RAII guard leaked in case2: {[p.name for p in case2]}")

    print("PASS[ASTRO_CALYX_RAII_SELFTEST]: current pattern leaks on panic; "
          "reference ScratchDir self-cleans on panic (FSV readback).")


if __name__ == "__main__":
    main()
