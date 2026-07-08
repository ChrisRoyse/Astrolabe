#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "ci" / "mcp-parity-corpus.json"
NORMALIZERS = ROOT / "ci" / "mcp-parity-normalizers.json"


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def base_env(cache_dir, quiet=True):
    env = dict(os.environ)
    env["CBM_CACHE_DIR"] = str(cache_dir)
    env["CBM_LOG_FORMAT"] = "text"
    env["NO_COLOR"] = "1"
    if quiet:
        env["CBM_LOG_LEVEL"] = "none"
    return env


def run_process(argv, *, stdin="", cache_dir, timeout=90, quiet=True):
    proc = subprocess.run(
        argv,
        input=stdin,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=base_env(cache_dir, quiet=quiet),
        timeout=timeout,
        check=False,
    )
    return {
        "rc": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def run_pair(upstream, astrolabe, run_fn):
    with tempfile.TemporaryDirectory(prefix="astrolabe-parity-") as tmp:
        cache = Path(tmp) / "cache"
        cache.mkdir()
        left = run_fn(upstream, cache)
        shutil.rmtree(cache)
        cache.mkdir()
        right = run_fn(astrolabe, cache)
    return left, right


def normalize_value(value, drop_keys):
    if isinstance(value, dict):
        return {
            key: normalize_value(val, drop_keys)
            for key, val in value.items()
            if key not in drop_keys
        }
    if isinstance(value, list):
        return [normalize_value(item, drop_keys) for item in value]
    return value


def normalize_json_text(text, drop_keys):
    value = json.loads(text)
    value = normalize_value(value, drop_keys)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def normalize_stdout(text, drop_keys):
    lines = [line for line in text.splitlines() if line.strip()]
    return "\n".join(normalize_json_text(line, drop_keys) for line in lines)


def filtered_stderr(text):
    kept = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("level="):
            continue
        if stripped.startswith(("INFO ", "WARN ", "ERROR ", "DEBUG ")):
            continue
        if stripped.startswith("warning: passing raw JSON"):
            continue
        kept.append(stripped)
    return "\n".join(kept)


def assert_equal(label, left, right):
    if left != right:
        print(f"ERROR: parity mismatch for {label}", file=sys.stderr)
        print("--- upstream ---", file=sys.stderr)
        print(left, file=sys.stderr)
        print("--- astrolabe ---", file=sys.stderr)
        print(right, file=sys.stderr)
        sys.exit(1)


def server_request(binary, cache, request):
    payload = json.dumps(request, separators=(",", ":"), ensure_ascii=False) + "\n"
    return run_process([str(binary)], stdin=payload, cache_dir=cache)


def cli_request(binary, cache, tool, args, raw):
    argv = [str(binary), "cli"]
    if raw:
        argv.append("--json")
    argv.extend([tool, json.dumps(args, separators=(",", ":"), ensure_ascii=False)])
    return run_process(argv, cache_dir=cache)


def check_server_parity(upstream, astrolabe, corpus, drop_keys):
    cases = list(corpus["server_requests"])
    next_id = 100
    for tool in corpus["tool_cases"]:
        for case in tool["cases"]:
            cases.append(
                {
                    "name": f"tool/{tool['tool']}/{case['name']}",
                    "request": {
                        "jsonrpc": "2.0",
                        "id": f"{next_id}",
                        "method": "tools/call",
                        "params": {"name": tool["tool"], "arguments": case["args"]},
                    },
                }
            )
            next_id += 1

    for case in cases:
        left, right = run_pair(
            upstream,
            astrolabe,
            lambda binary, cache, req=case["request"]: server_request(binary, cache, req),
        )
        assert_equal(f"{case['name']} rc", left["rc"], right["rc"])
        assert_equal(
            f"{case['name']} stdout",
            normalize_stdout(left["stdout"], drop_keys),
            normalize_stdout(right["stdout"], drop_keys),
        )
        assert_equal(
            f"{case['name']} stderr",
            filtered_stderr(left["stderr"]),
            filtered_stderr(right["stderr"]),
        )


def check_cli_parity(upstream, astrolabe, corpus, drop_keys):
    for tool in corpus["tool_cases"]:
        for case in tool["cases"]:
            for raw in (True, False):
                label = f"cli/{'json' if raw else 'text'}/{tool['tool']}/{case['name']}"
                left, right = run_pair(
                    upstream,
                    astrolabe,
                    lambda binary, cache, tool=tool["tool"], args=case["args"], raw=raw: cli_request(
                        binary, cache, tool, args, raw
                    ),
                )
                assert_equal(f"{label} rc", left["rc"], right["rc"])
                if raw:
                    left_stdout = normalize_stdout(left["stdout"], drop_keys)
                    right_stdout = normalize_stdout(right["stdout"], drop_keys)
                else:
                    left_stdout = left["stdout"].strip()
                    right_stdout = right["stdout"].strip()
                assert_equal(f"{label} stdout", left_stdout, right_stdout)
                assert_equal(
                    f"{label} stderr",
                    filtered_stderr(left["stderr"]),
                    filtered_stderr(right["stderr"]),
                )


def check_log_channel(astrolabe):
    with tempfile.TemporaryDirectory(prefix="astrolabe-log-channel-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        cache = root / "cache"
        repo.mkdir()
        cache.mkdir()
        (repo / "simple.c").write_text(
            "static int helper(int x) { return x + 1; }\n"
            "int main(void) { return helper(41); }\n",
            encoding="utf-8",
        )
        request = {
            "jsonrpc": "2.0",
            "id": 900,
            "method": "tools/call",
            "params": {
                "name": "index_repository",
                "arguments": {
                    "repo_path": str(repo),
                    "mode": "fast",
                    "name": "astrolabe_log_channel_fixture",
                },
            },
        }
        result = server_request(astrolabe, cache, request)
        if result["rc"] != 0:
            print(result["stderr"], file=sys.stderr)
            raise SystemExit("ERROR: log-channel index request failed")
        lines = [line for line in result["stdout"].splitlines() if line.strip()]
        if not lines:
            raise SystemExit("ERROR: log-channel test produced no protocol response")
        for line in lines:
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"ERROR: stdout contained non-JSON protocol bytes: {line!r}") from exc
            if parsed.get("jsonrpc") != "2.0":
                raise SystemExit(f"ERROR: stdout JSON was not JSON-RPC: {line!r}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--astrolabe", required=True)
    args = parser.parse_args()

    upstream = Path(args.upstream)
    astrolabe = Path(args.astrolabe)
    if not upstream.exists():
        raise SystemExit(f"missing upstream binary: {upstream}")
    if not astrolabe.exists():
        raise SystemExit(f"missing astrolabe binary: {astrolabe}")

    corpus = load_json(CORPUS)
    drop_keys = set(load_json(NORMALIZERS)["drop_keys"])
    check_server_parity(upstream, astrolabe, corpus, drop_keys)
    check_cli_parity(upstream, astrolabe, corpus, drop_keys)
    check_log_channel(astrolabe)
    print("MCP parity verified")


if __name__ == "__main__":
    main()
