#!/usr/bin/env python3
"""Regression for the hash-checked CBM graph-buffer formatting overlay."""

from __future__ import annotations

import hashlib
import runpy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patches" / "cbm" / "apply_graph_buffer_format_patch.py"
VENDOR_SOURCE = ROOT / "vendor" / "codebase-memory-mcp" / "src" / "graph_buffer" / "graph_buffer.c"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"CBM format overlay regression failed: {message}")


def main() -> None:
    patch_module = runpy.run_path(str(PATCH))
    source = VENDOR_SOURCE.read_text(encoding="utf-8")
    patched = patch_module["patch_source"](source)
    original = patch_module["ORIGINAL"]
    formatted = patch_module["FORMATTED"]

    require(
        hashlib.sha256(source.encode("utf-8")).hexdigest()
        == patch_module["EXPECTED_SOURCE_SHA256"],
        "the pinned vendor source must match the reviewed overlay baseline",
    )
    require(source.count(original) == 1, "vendor source must retain the original fragment")
    require(patched.count(original) == 0, "overlay must remove the original fragment")
    require(
        patched.count(formatted) == source.count(formatted) + 1,
        "overlay must add exactly one formatted fragment",
    )
    try:
        patch_module["patch_source"](source.replace(original, formatted))
    except ValueError:
        pass
    else:
        raise SystemExit("CBM format overlay regression failed: changed source must be refused")
    require(
        VENDOR_SOURCE.read_text(encoding="utf-8") == source,
        "overlay regression must not mutate the vendor source",
    )
    print("CBM graph-buffer format overlay regression passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
