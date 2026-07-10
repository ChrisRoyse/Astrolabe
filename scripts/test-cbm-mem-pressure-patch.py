#!/usr/bin/env python3
"""Regression for the patch-only CBM pressure-log buffer correction."""

from __future__ import annotations

import runpy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patches" / "cbm" / "apply_mem_pressure_patch.py"
VENDOR_MEM = ROOT / "vendor" / "codebase-memory-mcp" / "src" / "foundation" / "mem.c"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"CBM pressure patch regression failed: {message}")


def main() -> None:
    patch_module = runpy.run_path(str(PATCH))
    source = VENDOR_MEM.read_text(encoding="utf-8")
    patched = patch_module["patch_source"](source)
    old = patch_module["PERCENT_BUFFER_DECLARATION"]
    new = patch_module["PATCHED_PERCENT_BUFFER_DECLARATION"]
    expected = patch_module["EXPECTED_PERCENT_BUFFER_COUNT"]

    require(source.count(old) == expected, "vendor source must retain both original buffers")
    require(patched.count(old) == 0, "overlay must remove every undersized percentage buffer")
    require(
        patched.count(new) == expected,
        "overlay must expand both size_t percentage buffers to CBM_SZ_32",
    )
    try:
        patch_module["patch_source"](source.replace(old, "", 1))
    except ValueError:
        pass
    else:
        raise SystemExit("CBM pressure patch regression failed: missing buffer must be refused")
    require(
        VENDOR_MEM.read_text(encoding="utf-8") == source,
        "patch regression must not mutate the vendor source",
    )
    print("CBM pressure-log patch regression passed")


if __name__ == "__main__":
    main()
