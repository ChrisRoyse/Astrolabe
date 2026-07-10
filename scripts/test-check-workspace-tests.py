#!/usr/bin/env python3
"""Self-test native process-tree termination for the bounded workspace runner."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "check-workspace-tests.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("check_workspace_tests", RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {RUNNER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def process_alive(pid: int) -> bool:
    if os.name == "nt":
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
            check=False,
            capture_output=True,
            text=True,
        )
        return re.search(rf"\b{pid}\b", result.stdout) is not None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def stop_pid(pid: int) -> None:
    if not process_alive(pid):
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        os.kill(pid, signal.SIGKILL)


def wait_for(path: Path, *, timeout_secs: float) -> None:
    deadline = time.monotonic() + timeout_secs
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {path}")


def wait_for_exit(pid: int, *, timeout_secs: float) -> None:
    deadline = time.monotonic() + timeout_secs
    while time.monotonic() < deadline:
        if not process_alive(pid):
            return
        time.sleep(0.05)
    raise AssertionError(f"child process {pid} survived the timeout cleanup")


def main() -> int:
    runner = load_runner()
    target = ROOT / "target"
    target_existed = target.exists()
    target.mkdir(parents=True, exist_ok=True)
    child_pid = None

    try:
        with tempfile.TemporaryDirectory(prefix="workspace-test-timeout-", dir=target) as temp:
            scratch = Path(temp)
            pid_file = scratch / "child.pid"
            child = scratch / "child.py"
            parent = scratch / "parent.py"
            child.write_text(
                "import os, pathlib, sys, time\n"
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding='utf-8')\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )
            parent.write_text(
                "import pathlib, subprocess, sys, time\n"
                "child = subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])\n"
                "deadline = time.monotonic() + 5\n"
                "while not pathlib.Path(sys.argv[2]).exists() and time.monotonic() < deadline:\n"
                "    time.sleep(0.05)\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )

            try:
                result = runner.run_command(
                    [sys.executable, str(parent), str(child), str(pid_file)],
                    cwd=scratch,
                    timeout_secs=1,
                )
                if result != runner.DEFERRED_EXIT:
                    raise AssertionError(
                        f"timeout returned {result}, expected {runner.DEFERRED_EXIT}"
                    )
                wait_for(pid_file, timeout_secs=2)
                child_pid = int(pid_file.read_text(encoding="utf-8"))
                wait_for_exit(child_pid, timeout_secs=5)
            finally:
                if child_pid is None and pid_file.exists():
                    child_pid = int(pid_file.read_text(encoding="utf-8"))
                if child_pid is not None:
                    stop_pid(child_pid)
    finally:
        if not target_existed:
            target.rmdir()

    print("bounded workspace-test runner self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
