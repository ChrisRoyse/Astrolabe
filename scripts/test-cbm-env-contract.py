#!/usr/bin/env python3
"""Self-test for scripts/check-cbm-env-contract.py (#240).

Proves the env-as-IPC gate is load-bearing: a deliberately-added bare
`set_var("CBM_CACHE_DIR", ...)` in Rust must FAIL the gate, a doc-comment mention
of the same call must NOT, and a `set_var` over a non-libcbm variable must NOT.
The gate is exercised against fixture roots, never the live workspace.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check-cbm-env-contract.py"
CBM_ROOT = ROOT / "vendor" / "codebase-memory-mcp"


def build_fixture(base: Path, rust_body: str) -> Path:
    (base / "crates" / "demo" / "src").mkdir(parents=True, exist_ok=True)
    (base / "crates" / "demo" / "src" / "lib.rs").write_text(rust_body, encoding="utf-8")
    return base


def run_gate(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-B", str(GATE), "--root", str(root), "--cbm-root", str(CBM_ROOT)],
        capture_output=True,
        text=True,
    )


def expect(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        raise SystemExit(1)
    print(f"ok: {msg}")


def main() -> None:
    if not CBM_ROOT.is_dir():
        print("SKIP: vendored CBM tree absent", file=sys.stderr)
        raise SystemExit(1)

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)

        # 1. A bare set_var for CBM_CACHE_DIR must FAIL closed.
        offender = build_fixture(
            base / "offender",
            'pub fn boom() {\n'
            '    unsafe { std::env::set_var("CBM_CACHE_DIR", "/tmp/x"); }\n'
            '}\n',
        )
        result = run_gate(offender)
        expect(result.returncode != 0, "bare set_var(CBM_CACHE_DIR) fails the gate")
        expect(
            "ASTRO_CBM_ENV_AS_IPC" in result.stderr,
            "the failure carries the named ASTRO_CBM_ENV_AS_IPC code",
        )

        # 2. A remove_var over an inherited libcbm var (HOME) must also FAIL.
        remover = build_fixture(
            base / "remover",
            'pub fn nuke() {\n'
            '    unsafe { env::remove_var("HOME"); }\n'
            '}\n',
        )
        expect(run_gate(remover).returncode != 0, "remove_var(HOME) fails the gate")

        # 3. A doc-comment mention must NOT trip the gate.
        documented = build_fixture(
            base / "documented",
            '/// Never call `std::env::set_var("CBM_CACHE_DIR", ...)`; it is invisible to libcbm.\n'
            'pub fn safe() {}\n',
        )
        expect(run_gate(documented).returncode == 0, "a doc-comment mention passes the gate")

        # 4. set_var over a non-libcbm variable must NOT trip the gate.
        unrelated = build_fixture(
            base / "unrelated",
            'pub fn ok() {\n'
            '    unsafe { std::env::set_var("MY_OWN_APP_FLAG", "1"); }\n'
            '}\n',
        )
        expect(run_gate(unrelated).returncode == 0, "set_var over a non-libcbm var passes")

    print("test-cbm-env-contract: all cases passed")


if __name__ == "__main__":
    main()
