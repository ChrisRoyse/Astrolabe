#!/usr/bin/env python3
"""Run Astrolabe index/serve paths with outbound connect(2) denied."""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROJECT = "astrolabe_egress_deny"
SHADOW_VAULT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
# #92: datagram sends are traced AND denied — an unconnected UDP socket can
# exfiltrate via sendto/sendmsg/sendmmsg without ever calling connect(2).
SEND_SYSCALLS = ("sendto(", "sendmsg(", "sendmmsg(")
TRACE_SYSCALLS = ("connect(", "bind(", "listen(", "socket(") + SEND_SYSCALLS
INJECTED_SYSCALLS = "connect,sendto,sendmsg,sendmmsg"


def run(argv, *, env=None, timeout=240):
    proc = subprocess.run(
        [str(arg) for arg in argv],
        cwd=ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"command failed ({proc.returncode}): {' '.join(map(str, argv))}\n"
            f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
        )
    return proc


def default_astrolabe():
    exe = ".exe" if os.name == "nt" else ""
    for candidate in [
        ROOT / "target" / "debug" / f"astrolabe{exe}",
        ROOT / "target" / "debug" / "astrolabe",
    ]:
        if candidate.exists():
            return candidate
    return None


def base_env(cache):
    env = dict(os.environ)
    env["CBM_CACHE_DIR"] = str(cache)
    # #292: "error", never "none" — a fatal startup/index failure must print its
    # {code, message, remediation} instead of dying as a bare silent rc=1.
    env["CBM_LOG_LEVEL"] = "error"
    env["NO_COLOR"] = "1"
    env["ASTROLABE_VERIFY_CHAIN_LOOP"] = "0"
    return env


def require_strace(*, allow_unsupported_platform=False):
    if not sys.platform.startswith("linux"):
        if allow_unsupported_platform:
            # Hosted CI is banned (owner directive 2026-07-11): no CI job owns
            # this probe and none may be claimed. The strace-based egress harness needs
            # a Linux host, and Astrolabe is Windows-only scope until the system is
            # fully operational natively -- so this coverage is deferred to the
            # scheduled port phase, not abandoned and not awaiting a CI run.
            # Named, counted, never passing evidence.
            print(
                "SKIP[ASTRO_EGRESS_LINUX_REQUIRED]: "
                "scripts/check-egress-deny.py is the only skipped gate; "
                "the strace egress probe needs a Linux host, so egress-deny is "
                "UNPROVEN on this platform."
            )
            print(
                "DEFERRED[ASTRO_PORT_PHASE]: strace egress-deny coverage is "
                "deferred to the port phase (Windows-only scope, owner directive "
                "2026-07-11); tracked in #238. Not passing evidence; "
                "no CI job owns it."
            )
            return None
        raise SystemExit(
            "ASTRO_EGRESS_LINUX_REQUIRED: egress-deny harness requires Linux strace injection"
        )
    strace = shutil.which("strace")
    if strace is None:
        raise SystemExit(
            "ASTRO_EGRESS_STRACE_UNAVAILABLE: install strace to run the egress-deny harness"
        )
    return strace


def strace_prefix(strace, trace_path):
    return [
        strace,
        "-f",
        "-qq",
        "-o",
        trace_path,
        "-e",
        "trace=network",
        "-e",
        f"inject={INJECTED_SYSCALLS}:error=ENETUNREACH",
    ]


def write_fixture(repo):
    src = repo / "src"
    src.mkdir(parents=True)
    (src / "main.c").write_text(
        "\n".join(
            [
                "static int alpha(int x) { return x + 1; }",
                "static int beta(int x) { return alpha(x) + 2; }",
                "static int gamma(int x) { return beta(x) + 3; }",
                "int main(void) { return gamma(0); }",
                "",
            ]
        ),
        encoding="utf-8",
    )


def run_straced_command(strace, trace_path, argv, *, env, timeout=240):
    proc = run(strace_prefix(strace, trace_path) + [str(arg) for arg in argv], env=env, timeout=timeout)
    return proc


def parse_tool_payload(stdout, tool):
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise SystemExit(f"{tool} did not return JSON: {error}\n{stdout}") from error
    if payload.get("isError") is True:
        raise SystemExit(f"{tool} returned isError=true: {payload}")
    content = payload.get("structuredContent")
    if not isinstance(content, dict):
        raise SystemExit(f"{tool} returned no structuredContent: {payload}")
    return content


def trace_report(trace_path):
    text = Path(trace_path).read_text(encoding="utf-8", errors="replace")
    lines = [line for line in text.splitlines() if any(syscall in line for syscall in TRACE_SYSCALLS)]
    blocked = [line for line in lines if "connect(" in line and "(INJECTED)" in line]
    injected_sends = [
        line
        for line in lines
        if any(syscall in line for syscall in SEND_SYSCALLS) and "(INJECTED)" in line
    ]
    # #92: denied datagram sends to non-local destinations are egress violations;
    # loopback/AF_UNIX-destined sends are counted and labeled separately so the
    # whitelist is visible, never silent.
    blocked_sends = [line for line in injected_sends if not is_local_send_dest(line)]
    local_blocked_sends = [line for line in injected_sends if is_local_send_dest(line)]
    non_loopback_binds = [
        line
        for line in lines
        if "bind(" in line
        and ("AF_INET" in line or "AF_INET6" in line)
        and not is_loopback_bind(line)
    ]
    return {
        "path": str(trace_path),
        "network_syscall_count": len(lines),
        "blocked_connect_count": len(blocked),
        "blocked_connects": blocked[:10],
        "blocked_send_count": len(blocked_sends),
        "blocked_sends": blocked_sends[:10],
        "local_blocked_send_count": len(local_blocked_sends),
        "local_blocked_sends": local_blocked_sends[:10],
        "non_loopback_binds": non_loopback_binds[:10],
    }


def is_loopback_bind(line):
    return (
        'inet_addr("127.0.0.1")' in line
        or 'inet_addr("127.' in line
        or 'inet_pton(AF_INET6, "::1"' in line
    )


def is_local_send_dest(line):
    """True for datagram sends whose destination is loopback or an AF_UNIX path."""
    return "AF_UNIX" in line or is_loopback_bind(line)


def assert_trace_clean(label, report):
    if report["blocked_connect_count"]:
        raise SystemExit(
            f"{label} attempted denied network egress: {json.dumps(report['blocked_connects'], indent=2)}"
        )
    if report["blocked_send_count"]:
        raise SystemExit(
            f"{label} attempted denied datagram egress: {json.dumps(report['blocked_sends'], indent=2)}"
        )
    if report["non_loopback_binds"]:
        raise SystemExit(
            f"{label} bound a non-loopback listener: {json.dumps(report['non_loopback_binds'], indent=2)}"
        )


class StracedServer:
    def __init__(self, strace, trace_path, binary, cache):
        self.trace_path = trace_path
        self.proc = subprocess.Popen(
            strace_prefix(strace, trace_path) + [str(binary)],
            cwd=ROOT,
            env=base_env(cache),
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.next_id = 1

    def call(self, tool, args, timeout=120):
        request_id = self.next_id
        self.next_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": args},
        }
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

        out = queue.Queue(maxsize=1)

        def read_one():
            out.put(self.proc.stdout.readline())

        thread = threading.Thread(target=read_one, daemon=True)
        thread.start()
        try:
            line = out.get(timeout=timeout)
        except queue.Empty:
            self.kill()
            raise SystemExit(f"server timed out waiting for {tool} response")
        if not line:
            stderr = self.drain_stderr()
            raise SystemExit(f"server closed stdout during {tool}; stderr={stderr}")
        payload = json.loads(line)
        if payload.get("id") != request_id:
            raise SystemExit(f"server returned wrong id: {payload}")
        result = payload.get("result")
        if not isinstance(result, dict):
            raise SystemExit(f"server response missing result: {payload}")
        if result.get("isError") is True:
            raise SystemExit(f"server {tool} returned isError=true: {result}")
        content = result.get("structuredContent")
        if not isinstance(content, dict):
            raise SystemExit(f"server {tool} returned no structuredContent: {result}")
        return content

    def stop(self):
        if self.proc.poll() is not None:
            return
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.kill()

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass

    def drain_stderr(self):
        if self.proc.stderr is None:
            return ""
        try:
            return self.proc.stderr.read()
        except Exception:
            return ""


def deep_verify(astrolabe, cache):
    vault_dir = cache / f"{PROJECT}.astrolabe-vault"
    proc = run(
        [
            astrolabe,
            "verify",
            "--deep",
            "--json",
            "--vault",
            vault_dir,
            "--vault-id",
            SHADOW_VAULT_ID,
            "--vault-salt",
            f"astrolabe-shadow-v1:{PROJECT}",
        ],
        env=base_env(cache),
        timeout=120,
    )
    return json.loads(proc.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--astrolabe", type=Path)
    parser.add_argument("--keep-temp", action="store_true")
    parser.add_argument(
        "--allow-unsupported-platform",
        action="store_true",
        help="Emit a named skip outside Linux; intended only for the cross-platform aggregate.",
    )
    args = parser.parse_args()

    strace = require_strace(
        allow_unsupported_platform=args.allow_unsupported_platform
    )
    if strace is None:
        return
    astrolabe = args.astrolabe or default_astrolabe()
    if astrolabe is None or not astrolabe.exists():
        raise SystemExit(
            "ASTRO_EGRESS_BINARY_MISSING: build astrolabe first or pass --astrolabe"
        )

    tmp = Path(tempfile.mkdtemp(prefix="astrolabe-egress-deny-"))
    server = None
    try:
        repo = tmp / "repo"
        cache = tmp / "cache"
        traces = tmp / "traces"
        repo.mkdir()
        cache.mkdir()
        traces.mkdir()
        write_fixture(repo)

        index_trace = traces / "index.trace"
        index_proc = run_straced_command(
            strace,
            index_trace,
            [
                astrolabe,
                "cli",
                "--json",
                "index_repository",
                json.dumps(
                    {
                        "repo_path": str(repo),
                        "mode": "fast",
                        "name": PROJECT,
                        "calyx": "shadow",
                    },
                    separators=(",", ":"),
                ),
            ],
            env=base_env(cache),
            timeout=240,
        )
        index_content = parse_tool_payload(index_proc.stdout, "index_repository")
        grounding = index_content.get("grounding_summary", {})
        lowered = grounding.get("lowered_sqlite", {}) if isinstance(grounding, dict) else {}
        if (
            index_content.get("calyx") != "shadow"
            or grounding.get("verify_chain") != "intact"
            or lowered.get("exists") is not True
            or lowered.get("nodes", 0) < 1
            or lowered.get("edges", 0) < 1
        ):
            raise SystemExit(f"index did not complete shadow import: {index_content}")

        server_trace = traces / "server.trace"
        server = StracedServer(strace, server_trace, astrolabe, cache)
        status = server.call("index_status", {"project": PROJECT})
        if status.get("vault", {}).get("verify_chain") != "intact":
            raise SystemExit(f"server status did not verify intact vault: {status}")
        search = server.call(
            "search_graph",
            {
                "project": PROJECT,
                "label": "Function",
                "name_pattern": "gamma",
                "limit": 5,
            },
        )
        if search.get("total", 0) < 1:
            raise SystemExit(f"server search_graph did not find fixture symbol: {search}")
        server.stop()
        server = None

        deep = deep_verify(astrolabe, cache)
        if deep.get("ledger_chain_status") != "intact":
            raise SystemExit(f"deep verify failed: {deep}")
        if deep.get("sqlite_constellation_rows", 0) < 1 or deep.get("sqlite_edge_rows", 0) < 1:
            raise SystemExit(f"deep verify did not observe lowered rows: {deep}")

        reports = {
            "index": trace_report(index_trace),
            "server": trace_report(server_trace),
        }
        for label, report in reports.items():
            assert_trace_clean(label, report)

        summary = {
            "schema": "astrolabe.egress_deny.v1",
            "status": "verified",
            "project": PROJECT,
            "harness": "strace_connect_send_enetunreach",
            "blocked_connect_count": sum(
                report["blocked_connect_count"] for report in reports.values()
            ),
            "blocked_send_count": sum(
                report["blocked_send_count"] for report in reports.values()
            ),
            "local_blocked_send_count": sum(
                report["local_blocked_send_count"] for report in reports.values()
            ),
            "index_shadow": {
                "calyx": index_content.get("calyx"),
                "verify_chain": grounding.get("verify_chain"),
                "lowered_sqlite": grounding.get("lowered_sqlite"),
                "vault_import": grounding.get("vault_import"),
            },
            "server_verify_chain": status.get("vault", {}).get("verify_chain"),
            "search_total": search.get("total"),
            "deep_verify": {
                "ledger_chain_status": deep.get("ledger_chain_status"),
                "sqlite_constellation_rows": deep.get("sqlite_constellation_rows"),
                "sqlite_edge_rows": deep.get("sqlite_edge_rows"),
                "ledger_payload_rows": deep.get("ledger_payload_rows"),
            },
            "traces": reports,
            "astrolabe": str(astrolabe),
        }
        print(json.dumps(summary, sort_keys=True))
    finally:
        if server is not None:
            server.stop()
        if args.keep_temp:
            print(f"kept temp dir: {tmp}", file=sys.stderr)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
