#!/usr/bin/env python3
"""Verify that installer fixtures isolate every platform's agent roots."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-installer-roundtrip.py"
PLATFORM_AGENTS = {
    "zed": {
        "dir": ".config/zed",
        "windows_dir": "AppData/Local/Zed",
        "macos_dir": "Library/Application Support/Zed",
    },
    "kilocode": {
        "dir": ".config/Code/User/globalStorage/kilocode.kilo-code",
        "windows_dir": "AppData/Roaming/Code/User/globalStorage/kilocode.kilo-code",
        "macos_dir": "Library/Application Support/Code/User/globalStorage/kilocode.kilo-code",
    },
    "vscode": {
        "dir": ".config/Code/User",
        "windows_dir": "AppData/Roaming/Code/User",
        "macos_dir": "Library/Application Support/Code/User",
    },
}


def load_script():
    spec = importlib.util.spec_from_file_location("installer_roundtrip", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    sys.dont_write_bytecode = True
    module = load_script()
    fixture = module.load_fixture()
    agents = {agent["id"]: agent["detect"] for agent in fixture["agents"]}
    for agent, expected in PLATFORM_AGENTS.items():
        detect = agents.get(agent)
        if detect != expected:
            raise AssertionError(f"fixture detection paths for {agent} drifted: {detect!r}")
        if module.fixture_detect_dir(detect, os_name="nt", platform="win32") != expected[
            "windows_dir"
        ]:
            raise AssertionError(f"Windows path selection failed for {agent}")
        if module.fixture_detect_dir(detect, os_name="posix", platform="darwin") != expected[
            "macos_dir"
        ]:
            raise AssertionError(f"macOS path selection failed for {agent}")
        if module.fixture_detect_dir(detect, os_name="posix", platform="linux") != expected[
            "dir"
        ]:
            raise AssertionError(f"Linux path selection failed for {agent}")
    if module.installed_binary_relative_path(os_name="nt") != ".local/bin/codebase-memory-mcp.exe":
        raise AssertionError("Windows installer binary path lost its .exe suffix")
    if module.installed_binary_relative_path(os_name="posix") != ".local/bin/codebase-memory-mcp":
        raise AssertionError("POSIX installer binary path unexpectedly has an .exe suffix")

    scratch_parent = ROOT / ".tmp"
    scratch_parent_existed = scratch_parent.exists()
    scratch_parent.mkdir(exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(
            prefix="installer-roundtrip-fixture-", dir=scratch_parent
        ) as temp:
            home = Path(temp)
            fakebin = module.setup_fake_home(home, fixture)
            env = module.fixture_environment(home, fakebin)
            nested = home / ".local" / "bin" / "codebase-memory-mcp.exe"
            nested.parent.mkdir(parents=True)
            nested.write_bytes(b"fixture")
            if ".local/bin/codebase-memory-mcp.exe" not in module.snapshot_files(home):
                raise AssertionError("installer snapshots must normalize path separators")
            for agent, expected in PLATFORM_AGENTS.items():
                detect_dir = module.fixture_detect_dir(agents[agent])
                if not (home / detect_dir).is_dir():
                    raise AssertionError(f"fixture did not create {agent} detection root")
            for name, expected in {
                "HOME": home,
                "USERPROFILE": home,
                "XDG_CONFIG_HOME": home / ".config",
                "APPDATA": home / "AppData" / "Roaming",
                "LOCALAPPDATA": home / "AppData" / "Local",
                "TEMP": home / "tmp",
                "TMP": home / "tmp",
            }.items():
                if Path(env[name]) != expected:
                    raise AssertionError(f"fixture environment {name} escaped the fake home")
    finally:
        if not scratch_parent_existed:
            try:
                scratch_parent.rmdir()
            except OSError:
                pass

    print("installer roundtrip fixture self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
