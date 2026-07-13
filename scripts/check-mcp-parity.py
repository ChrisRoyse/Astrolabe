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


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def workspace_tempdir(prefix):
    target = ROOT / "target"
    target.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(prefix=prefix, dir=target)


def base_env(cache_dir, quiet=True):
    env = dict(os.environ)
    env["CBM_CACHE_DIR"] = str(cache_dir)
    env["CBM_LOG_FORMAT"] = "text"
    env["NO_COLOR"] = "1"
    if quiet:
        # #292: "error", never "none" — a fatal startup/index failure must print
        # its {code, message, remediation} instead of dying as a bare silent rc=1.
        env["CBM_LOG_LEVEL"] = "error"
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
    with workspace_tempdir("astrolabe-parity-") as tmp:
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
        # Dual-path consistency: the "left" side is the standalone C production
        # binary built from the SAME owned CBM sources as the astrolabe host.
        print("--- production binary (same owned sources) ---", file=sys.stderr)
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


def jsonrpc_result(result, label):
    if result["rc"] != 0:
        fail(f"{label} returned rc={result['rc']}: {result['stderr']}")
    lines = [line for line in result["stdout"].splitlines() if line.strip()]
    if len(lines) != 1:
        fail(f"{label} expected one JSON-RPC response, got {len(lines)}: {result['stdout']!r}")
    try:
        response = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        fail(f"{label} response was not JSON: {lines[0]!r}: {exc}")
    if "error" in response:
        fail(f"{label} returned JSON-RPC error: {response['error']!r}")
    result = response.get("result")
    if not isinstance(result, dict):
        fail(f"{label} result was not an object: {result!r}")
    return result


def advertised_tools(binary):
    with workspace_tempdir("astrolabe-mcp-tools-") as tmp:
        cache = Path(tmp) / "cache"
        cache.mkdir()
        tools = []
        cursor = None
        request_id = 1
        while True:
            params = {} if cursor is None else {"cursor": cursor}
            result = jsonrpc_result(
                server_request(
                    binary,
                    cache,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": "tools/list",
                        "params": params,
                    },
                ),
                f"{binary.name} tools/list",
            )
            request_id += 1
            page = result.get("tools")
            if not isinstance(page, list):
                fail(f"{binary.name} tools/list result missing tools array")
            for definition in page:
                name = definition.get("name") if isinstance(definition, dict) else None
                if not isinstance(name, str) or not name:
                    fail(f"{binary.name} tools/list returned invalid tool: {definition!r}")
                tools.append(name)
            cursor = result.get("nextCursor")
            if cursor is None:
                break
            if not isinstance(cursor, str) or not cursor:
                fail(f"{binary.name} tools/list returned invalid nextCursor: {cursor!r}")
    if len(tools) != len(set(tools)):
        fail(f"{binary.name} tools/list returned duplicate tool names")
    return tools


def corpus_tool_names(corpus):
    tool_cases = corpus.get("tool_cases")
    if not isinstance(tool_cases, list) or not tool_cases:
        fail("MCP parity corpus must contain a non-empty tool_cases array")
    names = []
    for entry in tool_cases:
        if not isinstance(entry, dict):
            fail(f"MCP parity tool case must be an object: {entry!r}")
        name = entry.get("tool")
        cases = entry.get("cases")
        if not isinstance(name, str) or not name:
            fail(f"MCP parity tool case missing non-empty tool name: {entry!r}")
        if not isinstance(cases, list) or not cases:
            fail(f"MCP parity tool case for {name} must contain at least one case")
        names.append(name)
    if len(names) != len(set(names)):
        fail("MCP parity corpus contains duplicate tool entries")
    return set(names)


def check_tool_case_coverage(upstream_tools, astrolabe_tools, corpus):
    shared = set(upstream_tools) & set(astrolabe_tools)
    covered = corpus_tool_names(corpus)
    missing = sorted(shared - covered)
    if missing:
        fail("shared advertised tools missing MCP parity cases: " + ", ".join(missing))


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
    with workspace_tempdir("astrolabe-log-channel-") as tmp:
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

    target = ROOT / "target"
    target_existed = target.exists()
    try:
        corpus = load_json(CORPUS)
        drop_keys = set(load_json(NORMALIZERS)["drop_keys"])
        check_tool_case_coverage(advertised_tools(upstream), advertised_tools(astrolabe), corpus)
        check_server_parity(upstream, astrolabe, corpus, drop_keys)
        check_cli_parity(upstream, astrolabe, corpus, drop_keys)
        check_log_channel(astrolabe)
        print("MCP parity verified")
    finally:
        if not target_existed and target.exists():
            target.rmdir()


if __name__ == "__main__":
    main()
