#!/usr/bin/env python3
import argparse
import json
import os
import queue
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROJECT = "astrolabe_cross_process_servers"
SHADOW_VAULT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def run(argv, *, env=None, cwd=ROOT, timeout=240):
    proc = subprocess.run(
        [str(arg) for arg in argv],
        cwd=cwd,
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


def default_upstream():
    exe = ".exe" if os.name == "nt" else ""
    for candidate in [
        ROOT / "target" / "cbm-parity" / f"codebase-memory-mcp{exe}",
        ROOT / "target" / "cbm-parity" / "codebase-memory-mcp",
    ]:
        if candidate.exists():
            return candidate
    return None


def default_astrolabe():
    exe = ".exe" if os.name == "nt" else ""
    for candidate in [
        ROOT / "target" / "debug" / f"astrolabe{exe}",
        ROOT / "target" / "debug" / "astrolabe",
    ]:
        if candidate.exists():
            return candidate
    return None


def build_upstream():
    build_dir = ROOT / "target" / "cbm-parity"
    exe = ".exe" if os.name == "nt" else ""
    run(
        [
            "make",
            "-C",
            ROOT / "vendor" / "codebase-memory-mcp",
            "-f",
            ROOT / "patches" / "cbm" / "Makefile.cbm",
            f"BUILD_DIR={build_dir}",
            "cbm",
        ],
        timeout=300,
    )
    built = build_dir / f"codebase-memory-mcp{exe}"
    if not built.exists():
        built = build_dir / "codebase-memory-mcp"
    if not built.exists():
        raise SystemExit(f"upstream build did not produce {built}")
    return built


def build_astrolabe():
    exe = ".exe" if os.name == "nt" else ""
    run(["cargo", "build", "-p", "astrolabe-server", "--bin", "astrolabe"], timeout=300)
    built = ROOT / "target" / "debug" / f"astrolabe{exe}"
    if not built.exists():
        built = ROOT / "target" / "debug" / "astrolabe"
    if not built.exists():
        raise SystemExit(f"astrolabe build did not produce {built}")
    return built


def base_env(cache):
    env = dict(os.environ)
    env["CBM_CACHE_DIR"] = str(cache)
    env["CBM_LOG_LEVEL"] = "none"
    env["NO_COLOR"] = "1"
    return env


def write_fixture(repo):
    src = repo / "src"
    src.mkdir(parents=True)
    for index in range(80):
        (src / f"unit_{index:03}.c").write_text(
            f"static int helper_{index}(int x) {{ return x + {index}; }}\n"
            f"static int other_{index}(int x) {{ return helper_{index}(x) + 1; }}\n"
            f"int exported_{index}(void) {{ return other_{index}(0); }}\n",
            encoding="utf-8",
        )


def cli_payload(binary, cache, tool, args):
    proc = run(
        [binary, "cli", "--json", tool, json.dumps(args, separators=(",", ":"))],
        env=base_env(cache),
        timeout=240,
    )
    payload = json.loads(proc.stdout)
    if payload.get("isError") is True:
        raise SystemExit(f"{tool} returned isError=true: {payload}")
    return payload


def persist_shadow_dial(cache):
    connection = sqlite3.connect(cache / "_config.db")
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
        connection.execute(
            "INSERT OR REPLACE INTO config(key, value) VALUES (?, ?)",
            (f"astrolabe.calyx.{PROJECT}", "shadow"),
        )
        connection.commit()
    finally:
        connection.close()


class StdioServer:
    def __init__(self, binary, cache, label):
        self.label = label
        self.proc = subprocess.Popen(
            [str(binary)],
            env=base_env(cache),
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.next_id = 1

    def call(self, tool, args, timeout=240):
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
            raise SystemExit(f"{self.label} timed out waiting for {tool} response")
        if not line:
            stderr = self.drain_stderr()
            raise SystemExit(f"{self.label} closed stdout during {tool}; stderr={stderr}")
        payload = json.loads(line)
        if payload.get("id") != request_id:
            raise SystemExit(f"{self.label} returned wrong id: {payload}")
        result = payload.get("result")
        if not isinstance(result, dict):
            raise SystemExit(f"{self.label} missing JSON-RPC result: {payload}")
        if result.get("isError") is True:
            raise SystemExit(f"{self.label} {tool} returned isError=true: {result}")
        return result

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


def call_async(server, tool, args):
    result = queue.Queue(maxsize=1)

    def worker():
        try:
            result.put((server.call(tool, args), None))
        except BaseException as exc:
            result.put((None, exc))

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return thread, result


def wait_async(thread, result, label, timeout=240):
    thread.join(timeout=timeout)
    if thread.is_alive():
        raise SystemExit(f"{label} did not finish")
    value, error = result.get_nowait()
    if error is not None:
        raise error
    return value


def structured(result):
    content = result.get("structuredContent")
    if not isinstance(content, dict):
        raise SystemExit(f"missing structuredContent: {result}")
    return content


def wait_for_lock_file(path, first_thread):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if path.exists():
            return True
        if not first_thread.is_alive():
            return False
        time.sleep(0.01)
    return False


def assert_busy_label(content):
    shadow = content.get("shadow_import")
    if not isinstance(shadow, dict):
        raise SystemExit(f"busy response missing shadow_import: {content}")
    if shadow.get("status") != "busy":
        raise SystemExit(f"expected busy shadow_import, got: {shadow}")
    if shadow.get("freshness") != "stale_ok" or shadow.get("trust") != "provisional":
        raise SystemExit(f"busy response lacks honest labels: {shadow}")
    if not shadow.get("lock_path") or not shadow.get("remediation"):
        raise SystemExit(f"busy response lacks lock path/remediation: {shadow}")


def assert_background_lane_pair(contents, label):
    lanes = []
    for content in contents:
        lane = content.get("background_lane")
        if not isinstance(lane, dict):
            raise SystemExit(f"{label} missing background_lane: {content}")
        if lane.get("schema") != "astrolabe-background-lane-v1":
            raise SystemExit(f"{label} background_lane schema drift: {lane}")
        for lane_name in ["watcher", "anneal"]:
            worker = lane.get("lanes", {}).get(lane_name)
            if not isinstance(worker, dict):
                raise SystemExit(f"{label} missing {lane_name} worker lane: {lane}")
            if worker.get("active") is not False:
                raise SystemExit(f"{label} shadow-stage {lane_name} worker must be inactive: {lane}")
            if worker.get("activation") != "not_enabled_in_shadow_stage":
                raise SystemExit(f"{label} {lane_name} activation label drift: {lane}")
        lanes.append(lane)

    owners = [lane for lane in lanes if lane.get("status") == "owner"]
    followers = [lane for lane in lanes if lane.get("status") == "follower"]
    if len(owners) != 1 or len(followers) != 1:
        raise SystemExit(f"{label} expected exactly one background owner and one follower: {lanes}")

    owner = owners[0]
    if owner.get("owner") != "this-process":
        raise SystemExit(f"{label} owner label drift: {owner}")
    if owner.get("freshness") != "fresh" or owner.get("trust") != "verified":
        raise SystemExit(f"{label} owner lacks verified/fresh labels: {owner}")
    if owner.get("remediation") is not None:
        raise SystemExit(f"{label} owner should not have remediation: {owner}")
    if owner.get("lanes", {}).get("watcher", {}).get("eligible_owner") is not True:
        raise SystemExit(f"{label} owner watcher lane is not marked eligible: {owner}")
    if owner.get("lanes", {}).get("anneal", {}).get("eligible_owner") is not True:
        raise SystemExit(f"{label} owner anneal lane is not marked eligible: {owner}")

    follower = followers[0]
    if follower.get("owner") != "another-process":
        raise SystemExit(f"{label} follower label drift: {follower}")
    if follower.get("freshness") != "stale_ok" or follower.get("trust") != "provisional":
        raise SystemExit(f"{label} follower lacks provisional/stale_ok labels: {follower}")
    if not follower.get("lock_path") or not follower.get("remediation"):
        raise SystemExit(f"{label} follower lacks lock path/remediation: {follower}")
    if follower.get("lanes", {}).get("watcher", {}).get("eligible_owner") is not False:
        raise SystemExit(f"{label} follower watcher lane is not marked ineligible: {follower}")
    if follower.get("lanes", {}).get("anneal", {}).get("eligible_owner") is not False:
        raise SystemExit(f"{label} follower anneal lane is not marked ineligible: {follower}")

    return {"owner": owner, "follower": follower}


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
        timeout=120,
    )
    return json.loads(proc.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--astrolabe", type=Path)
    parser.add_argument("--keep-temp", action="store_true")
    args = parser.parse_args()

    upstream = args.upstream or default_upstream() or build_upstream()
    astrolabe = args.astrolabe or default_astrolabe() or build_astrolabe()
    if not upstream.exists():
        raise SystemExit(f"missing upstream binary: {upstream}")
    if not astrolabe.exists():
        raise SystemExit(f"missing astrolabe binary: {astrolabe}")

    tmp = Path(tempfile.mkdtemp(prefix="astrolabe-cross-server-"))
    servers = []
    try:
        repo = tmp / "repo"
        cache = tmp / "cache"
        repo.mkdir()
        cache.mkdir()
        write_fixture(repo)

        cli_payload(
            upstream,
            cache,
            "index_repository",
            {"repo_path": str(repo), "mode": "fast", "name": PROJECT},
        )
        persist_shadow_dial(cache)

        first = StdioServer(astrolabe, cache, "server-a")
        second = StdioServer(astrolabe, cache, "server-b")
        servers.extend([first, second])

        first_thread, first_result = call_async(first, "index_status", {"project": PROJECT})
        lock_path = cache / f"{PROJECT}.astrolabe-shadow-import.lock"
        observed_lock = wait_for_lock_file(lock_path, first_thread)
        second_thread, second_result = call_async(second, "index_status", {"project": PROJECT})
        first_payload = wait_async(first_thread, first_result, "server-a index_status")
        second_payload = wait_async(second_thread, second_result, "server-b index_status")
        first_content = structured(first_payload)
        second_content = structured(second_payload)

        busy_responses = [
            content
            for content in [first_content, second_content]
            if content.get("shadow_import", {}).get("status") == "busy"
        ]
        if observed_lock and not busy_responses:
            raise SystemExit(
                "observed shadow import lock while first server was running, but no server response was labeled busy"
            )
        for content in busy_responses:
            assert_busy_label(content)

        initial_background_lanes = assert_background_lane_pair(
            [first_content, second_content], "initial two-server status"
        )

        stable_first = structured(first.call("index_status", {"project": PROJECT}))
        stable_second = structured(second.call("index_status", {"project": PROJECT}))
        stable_background_lanes = assert_background_lane_pair(
            [stable_first, stable_second], "stable two-server status"
        )
        if stable_first.get("vault", {}).get("verify_chain") != "intact":
            raise SystemExit(f"stable server status did not verify intact vault: {stable_first}")
        if stable_first.get("shadow_import", {}).get("status") != "current":
            raise SystemExit(
                f"stable server status did not report current shadow import: {stable_first}"
            )

        search = structured(
            second.call(
                "search_graph",
                {
                    "project": PROJECT,
                    "label": "Function",
                    "name_pattern": "helper_0",
                    "limit": 5,
                },
            )
        )
        if search.get("total", 0) < 1:
            raise SystemExit(f"legacy search failed after two server processes: {search}")

        deep = deep_verify(astrolabe, cache)
        if deep["ledger_chain_status"] != "intact":
            raise SystemExit(f"deep verify failed after two server processes: {deep}")
        if deep["sqlite_constellation_rows"] < 1 or deep["ledger_payload_rows"] < 1:
            raise SystemExit(f"deep verify did not observe imported vault rows: {deep}")

        summary = {
            "schema": "astrolabe-cross-process-servers-v1",
            "status": "verified",
            "project": PROJECT,
            "processes": 2,
            "transport": "stdio-jsonrpc",
            "observed_shadow_lock": observed_lock,
            "busy_responses": len(busy_responses),
            "first_shadow_import": first_content.get("shadow_import"),
            "second_shadow_import": second_content.get("shadow_import"),
            "initial_background_lanes": initial_background_lanes,
            "stable_background_lanes": stable_background_lanes,
            "stable_shadow_import": stable_first.get("shadow_import"),
            "stable_verify_chain": stable_first.get("vault", {}).get("verify_chain"),
            "deep_verify": deep,
            "legacy_search_total": search.get("total"),
            "upstream": str(upstream),
            "astrolabe": str(astrolabe),
        }
        print(json.dumps(summary, sort_keys=True))
    finally:
        for server in servers:
            server.stop()
        if args.keep_temp:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
