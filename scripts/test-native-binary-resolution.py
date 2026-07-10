#!/usr/bin/env python3
"""Exercise extensionless binary resolution against native Windows outputs."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    ("check_cli_parity", "check-cli-parity.py", "astrolabe"),
    ("check_compat_shim", "check-compat-shim.py", "astrolabe"),
    ("check_installer_roundtrip", "check-installer-roundtrip.py", "astrolabe"),
    ("check_hook_contracts", "check-hook-contracts.py", "codebase-memory-mcp"),
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    sys.dont_write_bytecode = True
    scratch_parent = ROOT / ".tmp"
    scratch_parent_existed = scratch_parent.exists()
    scratch_parent.mkdir(exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(
            prefix="native-binary-resolution-", dir=scratch_parent
        ) as temp:
            root = Path(temp)
            for module_name, filename, binary_name in MODULES:
                expected = root / f"{binary_name}.exe"
                expected.write_bytes(b"")
                module = load_module(module_name, ROOT / "scripts" / filename)
                actual = module.resolve_binary(root / binary_name)
                if actual != expected:
                    raise AssertionError(
                        f"{filename} resolved {actual!s}, expected {expected!s}"
                    )
    finally:
        if not scratch_parent_existed:
            try:
                scratch_parent.rmdir()
            except OSError:
                pass

    print("native binary resolution self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
