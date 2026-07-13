#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "ci" / "compat-shim-fixtures.json"
CLI_FIXTURES = ROOT / "ci" / "cli-parity-fixtures.json"


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_binary(path):
    binary = Path(path)
    if binary.exists():
        return binary
    if os.name == "nt" and binary.with_suffix(binary.suffix + ".exe").exists():
        return binary.with_suffix(binary.suffix + ".exe")
    if binary.suffix == "" and binary.with_name(binary.name + ".exe").exists():
        return binary.with_name(binary.name + ".exe")
    fail(f"missing binary: {path}")


def base_env(cache_dir):
    env = dict(os.environ)
    env["CBM_CACHE_DIR"] = str(cache_dir)
    env["CBM_LOG_FORMAT"] = "text"
    # #292: "error", never "none" — a fatal startup/index failure must print its
    # {code, message, remediation} instead of dying as a bare silent rc=1.
    env["CBM_LOG_LEVEL"] = "error"
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
        fail(f"{binary.name} JSON-RPC process failed rc={proc.returncode}\nstderr={proc.stderr}")
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        fail(f"{binary.name} expected one JSON-RPC response, got {len(lines)}: {proc.stdout!r}")
    try:
        response = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        fail(f"{binary.name} response was not JSON: {lines[0]!r}: {exc}")
    if "error" in response:
        fail(f"{binary.name} returned JSON-RPC error: {response['error']}")
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
            fail(f"{binary.name} tools/list result missing tools array")
        tools.extend(tool.get("name") for tool in page)
        cursor = result.get("nextCursor")
        if cursor is None:
            break
        if not isinstance(cursor, str) or not cursor:
            fail(f"{binary.name} invalid nextCursor: {cursor!r}")
    if not all(isinstance(tool, str) and tool for tool in tools):
        fail(f"{binary.name} tools/list returned invalid tool names: {tools!r}")
    if len(tools) != len(set(tools)):
        fail(f"{binary.name} tools/list returned duplicate tool names")
    return tools


def validate_fixtures(fixtures):
    if fixtures.get("schema") != "astrolabe.compat_shim_fixtures.v1":
        fail("compat shim fixture schema mismatch")
    legacy_command = fixtures.get("legacy_command")
    if legacy_command != "codebase-memory-mcp":
        fail(f"legacy_command must be codebase-memory-mcp, got {legacy_command!r}")
    targets = fixtures.get("targets")
    if not isinstance(targets, list) or len(targets) != 13:
        fail("compat shim fixtures must declare exactly 13 agent targets")
    seen = set()
    for target in targets:
        agent = target.get("agent")
        if not isinstance(agent, str) or not agent:
            fail(f"target missing agent name: {target!r}")
        if agent in seen:
            fail(f"duplicate agent target: {agent}")
        seen.add(agent)
        config_path = target.get("config_path")
        if not isinstance(config_path, str) or not config_path:
            fail(f"{agent} missing config_path")
        config = target.get("config")
        if not isinstance(config, dict):
            fail(f"{agent} missing config object")
        if config.get("command") != legacy_command:
            fail(f"{agent} command is not {legacy_command!r}: {config.get('command')!r}")
        args = config.get("args")
        if args is not None and not isinstance(args, list):
            fail(f"{agent} args must be an array when present")
    return legacy_command, targets


def check_cli_smoke(binary, cache_dir):
    proc = run_process(
        [binary, "cli", "--json", "list_projects", "{}"],
        cache_dir=cache_dir,
    )
    if proc.returncode != 0:
        fail(f"{binary.name} cli list_projects failed rc={proc.returncode}\nstderr={proc.stderr}")
    try:
        payload = json.loads(proc.stdout.strip())
    except json.JSONDecodeError as exc:
        fail(f"{binary.name} cli stdout was not JSON: {proc.stdout!r}: {exc}")
    if not isinstance(payload.get("isError"), bool):
        fail(f"{binary.name} cli result missing boolean isError")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--shim", default=str(ROOT / "target" / "debug" / "codebase-memory-mcp"))
    parser.add_argument("--astrolabe", default=str(ROOT / "target" / "debug" / "astrolabe"))
    args = parser.parse_args()

    shim = resolve_binary(args.shim)
    astrolabe = resolve_binary(args.astrolabe)
    _, targets = validate_fixtures(load_json(FIXTURES))
    expected_tools = set(load_json(CLI_FIXTURES).get("tools", {}))
    if not expected_tools:
        fail("CLI parity fixtures did not declare expected tools")

    with tempfile.TemporaryDirectory(prefix="astrolabe-compat-shim-") as tmp:
        cache = Path(tmp) / "cache"
        cache.mkdir()
        shim_tools = advertised_tools(shim, cache)
        astrolabe_tools = advertised_tools(astrolabe, cache)
        if set(shim_tools) != set(astrolabe_tools):
            fail(
                "shim tools differ from astrolabe: "
                + json.dumps(
                    {
                        "shim_only": sorted(set(shim_tools) - set(astrolabe_tools)),
                        "astrolabe_only": sorted(set(astrolabe_tools) - set(shim_tools)),
                    },
                    sort_keys=True,
                )
            )
        missing = sorted(expected_tools - set(shim_tools))
        if missing:
            fail("shim missing expected tools from CLI fixtures: " + ", ".join(missing))
        check_cli_smoke(shim, cache)

    print(
        "compat shim verified: "
        + json.dumps(
            {
                "schema": "astrolabe.compat_shim.v1",
                "legacy_command": "codebase-memory-mcp",
                "agent_targets": len(targets),
                "tool_count": len(shim_tools),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
