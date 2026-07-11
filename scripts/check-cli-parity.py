#!/usr/bin/env python3
"""Verify every advertised Astrolabe CLI tool has a successful fixture."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "ci" / "cli-parity-fixtures.json"
# Canonical provenance surface shared with the Rust reader. Single source of truth for
# the seeded get_provenance surface schema (#221); a Rust guard test
# (cli_parity_provenance_seed_matches_production_schema) asserts this exact file
# deserializes through the production reader, so a schema rename fails fast there instead
# of silently rotting this seed (the checked_to -> checked_end drift that broke cli-parity).
PROVENANCE_SEED = ROOT / "ci" / "cli-parity-provenance-seed.json"
FIXTURE_REPO_TOKEN = "$ASTROLABE_CLI_PARITY_REPO"
FIXTURE_REINDEX_REPO_TOKEN = "$ASTROLABE_CLI_PARITY_REINDEX_REPO"
FIXTURE_ARTIFACT_TOKEN = "$ASTROLABE_CLI_PARITY_ARTIFACT_DIR"
CONFIG_KEY_PREFIX = "astrolabe.calyx."
PRIMARY_PROJECT = "cli_parity"


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def base_env(cache_dir):
    env = dict(os.environ)
    env["CBM_CACHE_DIR"] = str(cache_dir)
    env["CBM_LOG_FORMAT"] = "text"
    env["CBM_LOG_LEVEL"] = "none"
    # Keep fixture indexing in-process so any future host-side supervisor policy
    # cannot detach the bridge's borrowed row-sink callbacks.
    env["CBM_INDEX_SUPERVISOR"] = "0"
    # CBM honours global Git exclusions. Point both Windows and POSIX home
    # lookups at the per-run root so a developer's Git configuration cannot
    # change the indexed fixture surface.
    fixture_home = cache_dir.parent / "home"
    env["HOME"] = str(fixture_home)
    env["USERPROFILE"] = str(fixture_home)
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


def assert_happy_payload(tool, payload):
    if not isinstance(payload.get("isError"), bool):
        fail(f"CLI {tool} result missing boolean isError")
    if payload["isError"]:
        fail(
            f"CLI {tool} returned isError=true for its happy-path fixture: "
            + json.dumps(payload, sort_keys=True)
        )
    if not isinstance(payload.get("content"), list):
        fail(f"CLI {tool} result missing content array")


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
    assert_happy_payload(tool, payload)
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


def validate_tool_fixture(tool, fixture):
    if not isinstance(fixture, dict):
        fail(f"fixture for {tool} must be an object")
    args = fixture.get("args")
    if not isinstance(args, dict):
        fail(f"fixture for {tool} must provide an args object")
    allow_empty_args = fixture.get("allow_empty_args", False)
    if not isinstance(allow_empty_args, bool):
        fail(f"fixture for {tool} allow_empty_args must be boolean")
    if not args and not allow_empty_args:
        fail(f"fixture for {tool} must use non-empty happy-path args")
    return args


def validate_fixtures(fixtures):
    if fixtures.get("schema") != "astrolabe.cli_parity_fixtures.v2":
        fail("CLI parity fixture schema mismatch")
    setup = fixtures.get("setup")
    if not isinstance(setup, list) or not setup:
        fail("CLI parity fixtures must contain a non-empty setup array")
    for index, step in enumerate(setup):
        if not isinstance(step, dict):
            fail(f"CLI parity setup[{index}] must be an object")
        tool = step.get("tool")
        if not isinstance(tool, str) or not tool:
            fail(f"CLI parity setup[{index}] missing non-empty tool")
        validate_tool_fixture(f"setup[{index}]/{tool}", step)

    tool_fixtures = fixtures.get("tools")
    if not isinstance(tool_fixtures, dict) or not tool_fixtures:
        fail("CLI parity fixtures must contain a non-empty tools object")
    for tool, fixture in tool_fixtures.items():
        if not isinstance(tool, str) or not tool:
            fail(f"CLI parity fixture has invalid tool name: {tool!r}")
        validate_tool_fixture(tool, fixture)
    return setup, tool_fixtures


def resolve_fixture_value(value, context):
    if isinstance(value, str):
        return context.get(value, value)
    if isinstance(value, list):
        return [resolve_fixture_value(item, context) for item in value]
    if isinstance(value, dict):
        return {key: resolve_fixture_value(item, context) for key, item in value.items()}
    return value


def create_fixture_repo(root):
    repo = root / "repo"
    repo.mkdir(parents=True)
    source = repo / "src" / "main.c"
    change_marker = repo / "README.md"
    source.parent.mkdir()
    source.write_text(
        "int helper(void) { return 41; }\n"
        "int main(void) { return helper() + 1; }\n",
        encoding="utf-8",
    )
    change_marker.write_text("CLI parity fixture baseline\n", encoding="utf-8")
    return repo


def initialize_fixture_git(repo):
    for command in (
        ["git", "init", "-q", str(repo)],
        ["git", "-C", str(repo), "config", "user.email", "astrolabe@example.invalid"],
        ["git", "-C", str(repo), "config", "user.name", "Astrolabe Parity"],
        ["git", "-C", str(repo), "add", "src/main.c", "README.md"],
        ["git", "-C", str(repo), "commit", "-qm", "fixture baseline"],
    ):
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        if result.returncode != 0:
            fail(f"fixture repository setup failed: {command!r}\n{result.stderr}")
    (repo / ".git" / "info" / "exclude").write_text("", encoding="utf-8")
    (repo / "README.md").write_text("CLI parity fixture change\n", encoding="utf-8")


def seed_provenance_metadata(cache_dir, project):
    # Load the canonical surface from the shared fixture rather than hand-duplicating the
    # provenance schema here. The prior inline dict silently rotted when production renamed
    # the chain field checked_to -> checked_end, so get_provenance failed only in the slow
    # native cli-parity gate (#221). The shared file is guard-tested by the Rust reader.
    if not PROVENANCE_SEED.is_file():
        fail(f"provenance seed fixture is missing: {PROVENANCE_SEED}")
    surface = load_json(PROVENANCE_SEED)
    surface.pop("_comment", None)
    if surface.get("status") == "unavailable" or "store" not in surface:
        fail(f"provenance seed fixture must carry a built surface with a store: {PROVENANCE_SEED}")
    key = f"{CONFIG_KEY_PREFIX}{project}.provenance_json"
    connection = sqlite3.connect(cache_dir / "_config.db")
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
        connection.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            (key, json.dumps(surface, sort_keys=True, separators=(",", ":"))),
        )
        connection.commit()
    finally:
        connection.close()


def run_setup(binary, cache_dir, setup, context):
    for step in setup:
        tool = step["tool"]
        args = resolve_fixture_value(validate_tool_fixture(tool, step), context)
        check_cli_tool(binary, cache_dir, tool, args)
    initialize_fixture_git(Path(context[FIXTURE_REPO_TOKEN]))
    seed_provenance_metadata(cache_dir, PRIMARY_PROJECT)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--astrolabe", default=str(ROOT / "target" / "debug" / "astrolabe"))
    args = parser.parse_args()

    binary = resolve_binary(args.astrolabe)
    setup, tool_fixtures = validate_fixtures(load_json(FIXTURES))
    target = ROOT / "target"
    target_existed = target.exists()
    target.mkdir(parents=True, exist_ok=True)

    try:
        with (
            tempfile.TemporaryDirectory(prefix="astrolabe-cli-parity-run-", dir=target) as tmp,
            tempfile.TemporaryDirectory(prefix="astrolabe-cli-parity-fixture-", dir=ROOT) as source_tmp,
        ):
            root = Path(tmp)
            cache = root / "cache"
            artifact_dir = root / "team-artifact"
            cache.mkdir()
            context = {
                FIXTURE_REPO_TOKEN: str(create_fixture_repo(Path(source_tmp) / "primary")),
                FIXTURE_REINDEX_REPO_TOKEN: str(
                    create_fixture_repo(Path(source_tmp) / "reindex")
                ),
                FIXTURE_ARTIFACT_TOKEN: str(artifact_dir),
            }
            advertised = advertised_tools(binary, cache)
            check_fixture_coverage(advertised, tool_fixtures)
            run_setup(binary, cache, setup, context)
            results = {}
            for tool in advertised:
                fixture = tool_fixtures[tool]
                tool_args = resolve_fixture_value(validate_tool_fixture(tool, fixture), context)
                results[tool] = check_cli_tool(binary, cache, tool, tool_args)
    finally:
        if not target_existed and target.exists():
            target.rmdir()

    print(
        "CLI parity verified: "
        + json.dumps(
            {
                "schema": "astrolabe.cli_parity.v2",
                "tool_count": len(results),
                "tools": sorted(results),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
