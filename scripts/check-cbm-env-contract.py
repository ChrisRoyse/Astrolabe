#!/usr/bin/env python3
"""Ban env-as-IPC across the Rust/libcbm boundary (#240).

Root cause the gate defends: on Windows Rust's `std::env::set_var` writes the
Win32 environment block (`SetEnvironmentVariableW`), while libcbm's
`cbm_safe_getenv` reads the C runtime's `environ` array. Those are two separate
stores, synchronised by the OS only for the environment a process INHERITED, so a
runtime `set_var("CBM_CACHE_DIR", ...)` is invisible to libcbm — which then
resolves a different store and reports no error (a standing-invariant-3 silent
fallback, and the mechanism by which #194's cache leak reappears).

The durable contract is to pass configuration across the FFI boundary as a
parameter (astrolabe_bridge::set_cbm_cache_dir), never through the environment.
This gate fails closed if any Rust code calls `set_var`/`remove_var` for a
variable libcbm actually reads.

The offending-variable set is MEASURED, not hand-picked: it is every variable
name passed to `cbm_safe_getenv(...)` or `getenv(...)` in the pinned CBM tree.
When the CBM pin moves, the ban list tracks it automatically.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[1]

# A libcbm env read: cbm_safe_getenv("NAME", ...) or getenv("NAME").
CBM_ENV_READ = re.compile(r'(?:cbm_safe_getenv|getenv)\(\s*"([A-Za-z_][A-Za-z0-9_]*)"')
# A Rust environment mutation, with its first string-literal argument.
RUST_ENV_MUTATION = re.compile(
    r'(?:std::env::|env::)?(set_var|remove_var)\s*\(\s*"([A-Za-z_][A-Za-z0-9_]*)"'
)

CBM_SCANNED_SUBTREES = ("src", "internal")
CBM_EXCLUDED_PARTS = ("vendored",)
CBM_SUFFIXES = (".c", ".h", ".cpp")


def fail(code: str, message: str, remediation: str) -> None:
    print(f"ERROR[{code}]: {message}", file=sys.stderr)
    print(f"  remediation: {remediation}", file=sys.stderr)
    raise SystemExit(1)


def strip_line_comment(line: str) -> str:
    """Drop a // or /// line comment so a doc comment mentioning set_var("X")
    is not a false positive. String literals in Rust do not contain a bare `//`
    in this codebase's env-mutation call sites, so a simple split is sufficient
    and deliberately conservative."""
    idx = line.find("//")
    return line if idx < 0 else line[:idx]


def cbm_consumed_vars(cbm_root: Path) -> set[str]:
    names: set[str] = set()
    for subtree in CBM_SCANNED_SUBTREES:
        base = cbm_root / subtree
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.suffix not in CBM_SUFFIXES or not path.is_file():
                continue
            if any(part in CBM_EXCLUDED_PARTS for part in path.relative_to(cbm_root).parts):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            names.update(CBM_ENV_READ.findall(text))
    return names


def rust_sources(root: Path) -> list[Path]:
    found: list[Path] = []
    for crate_dir in sorted((root / "crates").glob("*")):
        if not crate_dir.is_dir():
            continue
        for path in crate_dir.rglob("*.rs"):
            parts = path.relative_to(root).parts
            if "target" in parts:
                continue
            found.append(path)
    return sorted(found)


def scan(root: Path, cbm_root: Path) -> list[str]:
    consumed = cbm_consumed_vars(cbm_root)
    if not consumed:
        fail(
            "ASTRO_CBM_ENV_CONTRACT_NO_VARS",
            f"no libcbm-consumed environment variables found under {cbm_root}",
            "Run the gate from the canonical workspace with the vendored CBM subtree present.",
        )
    offenders: list[str] = []
    for path in rust_sources(root):
        for lineno, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            code = strip_line_comment(raw)
            for match in RUST_ENV_MUTATION.finditer(code):
                func, var = match.group(1), match.group(2)
                if var in consumed:
                    offenders.append(
                        f"{path.relative_to(root).as_posix()}:{lineno}: {func}(\"{var}\", ...) "
                        f"mutates an environment variable libcbm reads via its CRT environ array; "
                        f"on Windows that write is invisible to libcbm"
                    )
    return offenders


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--cbm-root", type=Path, default=None)
    args = parser.parse_args()

    root: Path = args.root
    cbm_root: Path = args.cbm_root or root / "vendor" / "codebase-memory-mcp"
    if not cbm_root.is_dir():
        fail(
            "ASTRO_CBM_ENV_CONTRACT_TREE_MISSING",
            f"CBM source tree not found at {cbm_root}",
            "Run the gate from the canonical workspace with the vendored subtree present.",
        )

    offenders = scan(root, cbm_root)
    if offenders:
        for offense in offenders:
            print(f"  {offense}", file=sys.stderr)
        fail(
            "ASTRO_CBM_ENV_AS_IPC",
            f"{len(offenders)} Rust env mutation(s) target a libcbm-consumed variable",
            "Pass the value across the FFI boundary as a parameter "
            "(e.g. astrolabe_bridge::set_cbm_cache_dir) instead of std::env::set_var. "
            "Rust's set_var writes the Win32 environment block; libcbm reads the CRT environ "
            "array, and the two are synchronised only for inherited environment.",
        )

    consumed = cbm_consumed_vars(cbm_root)
    print(
        f"CBM env-as-IPC contract clean: no set_var/remove_var over "
        f"{len(consumed)} libcbm-consumed variable(s) in crates Rust"
    )


if __name__ == "__main__":
    main()
