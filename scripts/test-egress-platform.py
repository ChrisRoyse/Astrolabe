#!/usr/bin/env python3
"""Self-tests for the egress harness platform capability boundary."""

from __future__ import annotations

import contextlib
import importlib.util
import io
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "check-egress-deny.py"


def load_harness():
    spec = importlib.util.spec_from_file_location("check_egress_deny", HARNESS)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {HARNESS}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expect_exit(call, code):
    try:
        call()
    except SystemExit as error:
        if code not in str(error):
            raise AssertionError(f"expected {code!r}, got {error!r}") from error
    else:
        raise AssertionError(f"expected SystemExit containing {code!r}")


def main() -> int:
    harness = load_harness()

    with mock.patch.object(harness.sys, "platform", "win32"):
        output = io.StringIO()
        argv = [
            str(HARNESS),
            "--allow-unsupported-platform",
            "--astrolabe",
            str(ROOT / "target" / "not-built"),
        ]
        with mock.patch.object(harness.sys, "argv", argv):
            with contextlib.redirect_stdout(output):
                result = harness.main()
        if result is not None:
            raise AssertionError(f"unsupported aggregate returned {result!r}")
        skip = output.getvalue()
        for fragment in (
            "SKIP[ASTRO_EGRESS_LINUX_REQUIRED]",
            "scripts/check-egress-deny.py is the only skipped gate",
            "CI job portable-gates",
        ):
            if fragment not in skip:
                raise AssertionError(f"missing {fragment!r} in skip output: {skip!r}")
        expect_exit(
            harness.require_strace,
            "ASTRO_EGRESS_LINUX_REQUIRED",
        )

    with mock.patch.object(harness.sys, "platform", "linux"):
        with mock.patch.object(harness.shutil, "which", return_value=None):
            expect_exit(
                harness.require_strace,
                "ASTRO_EGRESS_STRACE_UNAVAILABLE",
            )
        with mock.patch.object(
            harness.shutil, "which", return_value="/usr/bin/strace"
        ):
            actual = harness.require_strace()
            if actual != "/usr/bin/strace":
                raise AssertionError(f"unexpected strace path: {actual!r}")

    print("egress platform policy self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
