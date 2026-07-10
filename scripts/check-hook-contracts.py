#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "ci" / "hook-contracts.json"
CBM_CLI_SOURCE = ROOT / "vendor" / "codebase-memory-mcp" / "src" / "cli" / "cli.c"
SYMBOL = "someIndexedSymbol"


EXPECTED_HOOK_IDS = {
    "claude-pretooluse-grep-glob",
    "claude-sessionstart",
    "claude-subagentstart",
    "codex-sessionstart",
    "gemini-beforetool",
    "gemini-sessionstart",
    "antigravity-sessionstart",
}


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_binary(path):
    candidate = Path(path)
    if candidate.exists():
        return candidate
    if candidate.suffix == "" and candidate.with_name(candidate.name + ".exe").exists():
        return candidate.with_name(candidate.name + ".exe")
    fail(f"binary not found: {candidate}")


def run(argv, *, stdin=None, env=None, timeout=120):
    return subprocess.run(
        [str(arg) for arg in argv],
        input=stdin,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=timeout,
        check=False,
    )


def validate_contract(contract):
    if contract.get("schema") != "astrolabe.hook_contracts.v1":
        fail("hook contract schema mismatch")
    budget_ms = contract.get("budget_ms")
    if not isinstance(budget_ms, int) or budget_ms <= 0:
        fail("hook contract budget_ms must be a positive integer")
    if budget_ms != 300:
        fail("hook contract budget_ms must remain the published 300ms")
    timeout_exit_ceiling_ms = contract.get("timeout_exit_ceiling_ms")
    if not isinstance(timeout_exit_ceiling_ms, int) or timeout_exit_ceiling_ms < budget_ms:
        fail("hook contract timeout_exit_ceiling_ms must be >= budget_ms")

    hooks = contract.get("hooks")
    if not isinstance(hooks, list):
        fail("hook contract hooks must be a list")
    ids = {hook.get("id") for hook in hooks if isinstance(hook, dict)}
    if ids != EXPECTED_HOOK_IDS:
        fail(f"hook contract ids mismatch: {sorted(ids)}")
    binary_hooks = [hook for hook in hooks if hook.get("mode") == "binary_augmenter"]
    if len(binary_hooks) != 1 or binary_hooks[0].get("command") != "hook-augment":
        fail("expected exactly one binary hook-augment contract")
    for hook in hooks:
        for key in ["id", "agent", "event", "matcher", "mode"]:
            if not isinstance(hook.get(key), str) or not hook[key]:
                fail(f"hook {hook.get('id')} missing {key}")
        if hook["mode"] == "static_reminder" and not hook.get("source_marker"):
            fail(f"static hook {hook['id']} missing source_marker")
    return budget_ms, timeout_exit_ceiling_ms


def validate_source_markers(contract):
    source = CBM_CLI_SOURCE.read_text(encoding="utf-8")
    for hook in contract["hooks"]:
        marker = hook.get("source_marker")
        if marker and marker not in source:
            fail(f"hook source marker missing for {hook['id']}: {marker}")
    if "#define CMM_HOOK_TIMEOUT_SEC 5" not in source:
        fail("Claude PreToolUse shell backstop timeout is not the expected 5 seconds")
    if '#define CMM_HOOK_MATCHER "Grep|Glob"' not in source:
        fail("Claude PreToolUse matcher drifted from Grep|Glob")


def assert_hook_process(proc, elapsed_ms, *, budget_ms, label, expect_empty):
    if proc.returncode != 0:
        fail(f"{label} returned rc={proc.returncode}, stderr={proc.stderr[:200]!r}")
    if elapsed_ms > budget_ms:
        fail(f"{label} exceeded {budget_ms}ms budget: {elapsed_ms:.1f}ms")
    if proc.stderr:
        fail(f"{label} wrote stderr on hook path: {proc.stderr[:200]!r}")
    if expect_empty and proc.stdout:
        fail(f"{label} wrote stdout for no-op hook: {proc.stdout[:200]!r}")


def invoke_hook(binary, payload, env, budget_ms, label, expect_empty):
    start = time.perf_counter()
    proc = run([binary, "hook-augment"], stdin=payload, env=env, timeout=5)
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert_hook_process(
        proc,
        elapsed_ms,
        budget_ms=budget_ms,
        label=label,
        expect_empty=expect_empty,
    )
    return proc.stdout, elapsed_ms


def assert_noop_hooks(binary, env, budget_ms):
    cases = [
        ("invalid-json", "not-json"),
        (
            "non-search-tool",
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Read",
                    "cwd": "/tmp",
                    "tool_input": {"pattern": SYMBOL},
                }
            ),
        ),
        (
            "short-token",
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Grep",
                    "cwd": "/tmp",
                    "tool_input": {"pattern": "abc"},
                }
            ),
        ),
        (
            "relative-cwd",
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Glob",
                    "cwd": "relative/path",
                    "tool_input": {"pattern": SYMBOL},
                }
            ),
        ),
    ]
    timings = {}
    for case, payload in cases:
        _, elapsed_ms = invoke_hook(
            binary,
            payload,
            env,
            budget_ms,
            f"{binary.name} {case}",
            expect_empty=True,
        )
        timings[case] = round(elapsed_ms, 1)
    return timings


def assert_timeout_is_silent(binary, env, timeout_exit_ceiling_ms):
    start = time.perf_counter()
    proc = subprocess.Popen(
        [str(binary), "hook-augment"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        proc.wait(timeout=timeout_exit_ceiling_ms / 1000)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        fail(f"{binary.name} held-open stdin did not exit before timeout ceiling")
    elapsed_ms = (time.perf_counter() - start) * 1000
    stdout = proc.stdout.read() if proc.stdout else ""
    stderr = proc.stderr.read() if proc.stderr else ""
    if proc.stdin:
        proc.stdin.close()
    if proc.returncode != 0:
        fail(f"{binary.name} held-open stdin timeout returned rc={proc.returncode}")
    if stdout or stderr:
        fail(
            f"{binary.name} held-open stdin timeout was not silent: "
            f"stdout={stdout[:100]!r} stderr={stderr[:100]!r}"
        )
    return round(elapsed_ms, 1)


def index_fixture(astrolabe, env, repo):
    proc = run(
        [
            astrolabe,
            "cli",
            "--json",
            "index_repository",
            json.dumps({"repo_path": str(repo)}),
        ],
        env=env,
        timeout=180,
    )
    if proc.returncode != 0:
        fail(f"index_repository failed rc={proc.returncode}\nstderr={proc.stderr[:400]}")
    if '"nodes"' not in proc.stdout:
        fail(f"index_repository did not report nodes: {proc.stdout[:400]}")


def assert_indexed_hook(binary, env, repo, budget_ms):
    payload = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Grep",
            "cwd": str(repo),
            "tool_input": {"pattern": SYMBOL},
        }
    )
    stdout, elapsed_ms = invoke_hook(
        binary,
        payload,
        env,
        budget_ms,
        f"{binary.name} indexed-grep",
        expect_empty=False,
    )
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as error:
        fail(f"{binary.name} hook output was not JSON: {error}: {stdout[:200]!r}")
    hook_output = value.get("hookSpecificOutput")
    if not isinstance(hook_output, dict):
        fail(f"{binary.name} hook output missing hookSpecificOutput")
    if hook_output.get("hookEventName") != "PreToolUse":
        fail(f"{binary.name} hookEventName mismatch")
    context = hook_output.get("additionalContext")
    if not isinstance(context, str):
        fail(f"{binary.name} hook output missing additionalContext")
    for marker in [SYMBOL, "trust=provisional", "freshness=best_effort"]:
        if marker not in context:
            fail(f"{binary.name} hook context missing {marker!r}: {context[:300]!r}")
    return round(elapsed_ms, 1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--astrolabe", default=str(ROOT / "target" / "debug" / "astrolabe"))
    parser.add_argument(
        "--shim", default=str(ROOT / "target" / "debug" / "codebase-memory-mcp")
    )
    args = parser.parse_args()

    contract = load_json(CONTRACT)
    budget_ms, timeout_exit_ceiling_ms = validate_contract(contract)
    validate_source_markers(contract)
    astrolabe = resolve_binary(args.astrolabe)
    shim = resolve_binary(args.shim)

    work = Path(tempfile.mkdtemp(prefix="astrolabe-hook-contract-"))
    try:
        repo = work / "repo"
        src = repo / "src"
        src.mkdir(parents=True)
        (src / "main.ts").write_text(
            f"export function {SYMBOL}(a: number): number {{ return a + 1; }}\n",
            encoding="utf-8",
        )
        cache = work / "cache"
        env = dict(os.environ)
        env["CBM_CACHE_DIR"] = str(cache)

        index_fixture(astrolabe, env, repo)
        timings = {
            "noop": {
                "astrolabe": assert_noop_hooks(astrolabe, env, budget_ms),
                "codebase-memory-mcp": assert_noop_hooks(shim, env, budget_ms),
            },
            "indexed_grep_ms": {
                "astrolabe": assert_indexed_hook(astrolabe, env, repo, budget_ms),
                "codebase-memory-mcp": assert_indexed_hook(shim, env, repo, budget_ms),
            },
            "held_open_stdin_timeout_ms": {
                "astrolabe": assert_timeout_is_silent(
                    astrolabe, env, timeout_exit_ceiling_ms
                ),
                "codebase-memory-mcp": assert_timeout_is_silent(
                    shim, env, timeout_exit_ceiling_ms
                ),
            },
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print(
        "hook contracts verified: "
        + json.dumps(
            {
                "schema": "astrolabe.hook_contract_check.v1",
                "budget_ms": budget_ms,
                "hooks": len(contract["hooks"]),
                "timings": timings,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
