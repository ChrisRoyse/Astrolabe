#!/usr/bin/env python3
"""Run cargo workspace tests with an optional process-tree deadline."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFERRED_EXIT = 125


class ProcessInterrupted(Exception):
    def __init__(self, signum: int) -> None:
        self.signum = signum


def start_process(argv: list[str], *, cwd: Path) -> subprocess.Popen[object]:
    kwargs: dict[str, object] = {"cwd": cwd}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(argv, **kwargs)


def terminate_process_tree(process: subprocess.Popen[object]) -> None:
    if process.poll() is not None:
        return

    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return

    try:
        process.wait(timeout=10)
        return
    except subprocess.TimeoutExpired:
        pass

    if os.name == "nt":
        process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
    process.wait(timeout=10)


def run_command(argv: list[str], *, cwd: Path, timeout_secs: int) -> int:
    if timeout_secs < 0:
        raise ValueError("timeout_secs must be zero or positive")

    process = start_process(argv, cwd=cwd)
    previous_handlers: dict[int, object] = {}

    def interrupt(signum: int, _frame: object) -> None:
        raise ProcessInterrupted(signum)

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, interrupt)

    try:
        return process.wait(timeout=None if timeout_secs == 0 else timeout_secs)
    except subprocess.TimeoutExpired:
        terminate_process_tree(process)
        print(
            "DEFERRED[ASTRO_WORKSPACE_TEST_TIMEOUT]: "
            f"cargo test --workspace exceeded {timeout_secs}s; process tree terminated",
            file=sys.stderr,
        )
        return DEFERRED_EXIT
    except ProcessInterrupted as exc:
        terminate_process_tree(process)
        print(
            "ERROR[ASTRO_WORKSPACE_TEST_INTERRUPTED]: "
            f"received signal {exc.signum}; process tree terminated",
            file=sys.stderr,
        )
        return 128 + exc.signum
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo", help="Cargo executable to invoke.")
    parser.add_argument(
        "--timeout-secs",
        type=int,
        required=True,
        help="Workspace-test deadline; zero runs without a deadline.",
    )
    parser.add_argument(
        "--nextest-profile",
        default=None,
        help=(
            "When set, run `cargo nextest run --profile <name> --workspace` "
            "instead of `cargo test --workspace`. #280 Tier-1 uses the #264 "
            "`fast` profile, whose .config/nextest.toml default-filter tiers out "
            "the heavy tests; ci-rust-gate.sh runs the full set + doctests."
        ),
    )
    args = parser.parse_args()

    if args.nextest_profile:
        argv = [
            args.cargo,
            "nextest",
            "run",
            "--profile",
            args.nextest_profile,
            "--workspace",
        ]
    else:
        argv = [args.cargo, "test", "--workspace"]

    try:
        return run_command(
            argv,
            cwd=ROOT,
            timeout_secs=args.timeout_secs,
        )
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
