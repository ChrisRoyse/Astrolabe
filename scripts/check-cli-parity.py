#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "ci" / "cli-parity-fixtures.json"


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def base_env(cache_dir):
    env = dict(os.environ)
    env["CBM_CACHE_DIR"] = str(cache_dir)
    env["CBM_LOG_FORMAT"] = "text"
    env["CBM_LOG_LEVEL"] = "none"
    env["NO_COLOR"] = "1"
    return env


def run_process(argv, *, stdin="", cache_dir, timeout=90):
    return subprocess.run(
        [str(arg) for arg in argv],
        input=stdin,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=base_env(cache_dir),
        timeout=timeout,
        check=False,
    )


def jsonrpc(binary, cache_dir, request):
    payload = json.dumps(request, separators=(",", ":"), ensure_ascii=False) + "\n"
    proc = run_process([binary], stdin=payload, cache_dir=cache_dir)
    if proc.returncode != 0:
        fail(f"tools/list process failed rc={proc.returncode}\nstderr={proc.stderr}")
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        fail(f"tools/list expected one JSON-RPC response, got {len(lines)} lines: {proc.stdout!r}")
    try:
        response = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        fail(f"tools/list response was not JSON: {lines[0]!r}: {exc}")
    if "error" in response:
        fail(f"tools/list returned JSON-RPC error: {response['error']}")
    return response["result"]


def advertised_tools(binary, cache_dir):
    tools = []
    cursor = None
    request_id = 1
    while True:
        params = {} if cursor is None else {"cursor": cursor}
        result = jsonrpc(
            binary,
            cache_dir,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/list",
                "params": params,
            },
        )
        request_id += 1
        page = result.get("tools")
        if not isinstance(page, list):
            fail("tools/list result missing tools array")
        for tool in page:
            name = tool.get("name")
            if not isinstance(name, str) or not name:
                fail(f"tool entry missing non-empty name: {tool!r}")
            tools.append(name)
        cursor = result.get("nextCursor")
        if cursor is None:
            break
        if not isinstance(cursor, str) or not cursor:
            fail(f"invalid nextCursor: {cursor!r}")
    return tools


def check_fixture_coverage(advertised, fixtures):
    advertised_set = set(advertised)
    fixture_set = set(fixtures)
    missing = sorted(advertised_set - fixture_set)
    extra = sorted(fixture_set - advertised_set)
    if missing:
        fail("advertised tools missing CLI fixtures: " + ", ".join(missing))
    if extra:
        fail("CLI fixtures reference non-advertised tools: " + ", ".join(extra))
    if len(advertised) != len(advertised_set):
        fail("tools/list advertised duplicate tool names")


def check_cli_tool(binary, cache_dir, tool, args):
    proc = run_process(
        [
            binary,
            "cli",
            "--json",
            "--progress",
            tool,
            json.dumps(args, separators=(",", ":"), ensure_ascii=False),
        ],
        cache_dir=cache_dir,
    )
    if proc.returncode != 0:
        fail(f"CLI {tool} returned nonzero rc={proc.returncode}\nstderr={proc.stderr}")
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        fail(f"CLI {tool} expected one JSON result line, got {len(lines)}: {proc.stdout!r}")
    try:
        payload = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        fail(f"CLI {tool} stdout was not JSON: {lines[0]!r}: {exc}")
    if not isinstance(payload.get("isError"), bool):
        fail(f"CLI {tool} result missing boolean isError")
    if not isinstance(payload.get("content"), list):
        fail(f"CLI {tool} result missing content array")
    if f"astrolabe cli progress: start tool={tool}" not in proc.stderr:
        fail(f"CLI {tool} missing progress start line: {proc.stderr!r}")
    if f"astrolabe cli progress: done tool={tool} exit=0" not in proc.stderr:
        fail(f"CLI {tool} missing progress done line: {proc.stderr!r}")
    return payload


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def resolve_binary(path):
    binary = Path(path)
    if binary.exists():
        return binary
    if os.name == "nt" and binary.with_suffix(binary.suffix + ".exe").exists():
        return binary.with_suffix(binary.suffix + ".exe")
    if binary.suffix == "" and binary.with_name(binary.name + ".exe").exists():
        return binary.with_name(binary.name + ".exe")
    fail(f"missing astrolabe binary: {path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--astrolabe", default=str(ROOT / "target" / "debug" / "astrolabe"))
    args = parser.parse_args()

    binary = resolve_binary(args.astrolabe)
    fixtures = load_json(FIXTURES)
    if fixtures.get("schema") != "astrolabe.cli_parity_fixtures.v1":
        fail("CLI parity fixture schema mismatch")
    tool_fixtures = fixtures.get("tools")
    if not isinstance(tool_fixtures, dict) or not tool_fixtures:
        fail("CLI parity fixtures must contain a non-empty tools object")

    with tempfile.TemporaryDirectory(prefix="astrolabe-cli-parity-") as tmp:
        cache = Path(tmp) / "cache"
        cache.mkdir()
        advertised = advertised_tools(binary, cache)
        check_fixture_coverage(advertised, tool_fixtures)
        results = {}
        for tool in advertised:
            fixture = tool_fixtures[tool]
            if not isinstance(fixture, dict):
                fail(f"fixture for {tool} must be a JSON object")
            results[tool] = check_cli_tool(binary, cache, tool, fixture)

    print(
        "CLI parity verified: "
        + json.dumps(
            {
                "schema": "astrolabe.cli_parity.v1",
                "tool_count": len(results),
                "tools": sorted(results),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
