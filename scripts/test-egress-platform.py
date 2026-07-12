#!/usr/bin/env python3
"""Self-tests for the egress harness platform capability boundary."""
# ASTRO_ALLOW_TEST_DOUBLE_FILE(platform-dispatch branches cannot all be real on one host; sys.platform/shutil.which are patched only to select the branch, whose real behavior is owned by a native run on that platform -- a tracked coverage gap, #238, never a CI job)

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
            # The skip must carry the port-phase deferral classification and name
            # its tracking issue -- never a CI job (hosted CI is banned; #224/#238).
            "DEFERRED[ASTRO_PORT_PHASE]",
            "tracked in #238",
            "no CI job owns it.",
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

    # #92: datagram sends must be traced AND injected — an unconnected UDP socket
    # exfiltrates via sendto/sendmsg/sendmmsg without ever calling connect(2).
    for syscall in ("sendto(", "sendmsg(", "sendmmsg("):
        if syscall not in harness.TRACE_SYSCALLS:
            raise AssertionError(f"{syscall!r} missing from TRACE_SYSCALLS")
    prefix = harness.strace_prefix("/usr/bin/strace", "/tmp/trace")
    inject = next(arg for arg in prefix if arg.startswith("inject="))
    for syscall in ("connect", "sendto", "sendmsg", "sendmmsg"):
        if syscall not in inject:
            raise AssertionError(f"{syscall!r} missing from strace injection: {inject!r}")

    # Synthetic-trace policy check: non-local injected datagram sends are
    # violations; loopback/AF_UNIX injected sends are counted and labeled but
    # not fatal; the report shape feeds assert_trace_clean fail-closed.
    import tempfile

    remote_send = (
        '1000  sendto(3, "x", 1, 0, {sa_family=AF_INET, sin_port=htons(53), '
        'sin_addr=inet_addr("8.8.8.8")}, 16) = -1 ENETUNREACH (INJECTED)'
    )
    local_send = (
        '1000  sendto(4, "x", 1, 0, {sa_family=AF_INET, sin_port=htons(514), '
        'sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ENETUNREACH (INJECTED)'
    )
    unix_send = (
        '1000  sendmsg(5, {msg_name={sa_family=AF_UNIX, '
        'sun_path="/run/x.sock"}, ...}, 0) = -1 ENETUNREACH (INJECTED)'
    )
    with tempfile.TemporaryDirectory() as tmp:
        trace = Path(tmp) / "synthetic.trace"
        trace.write_text(
            "\n".join([remote_send, local_send, unix_send]) + "\n", encoding="utf-8"
        )
        report = harness.trace_report(trace)
        if report["blocked_send_count"] != 1 or "8.8.8.8" not in report["blocked_sends"][0]:
            raise AssertionError(f"remote datagram send not flagged: {report!r}")
        if report["local_blocked_send_count"] != 2:
            raise AssertionError(f"local datagram sends not labeled: {report!r}")
        expect_exit(
            lambda: harness.assert_trace_clean("synthetic", report),
            "denied datagram egress",
        )

        trace.write_text("\n".join([local_send, unix_send]) + "\n", encoding="utf-8")
        local_only = harness.trace_report(trace)
        if local_only["blocked_send_count"] != 0:
            raise AssertionError(f"local-only sends must not be violations: {local_only!r}")
        harness.assert_trace_clean("synthetic-local", local_only)

    print("egress platform policy self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
