#!/usr/bin/env python3
"""Self-tests for MCP coverage and CLI happy-path fixture contracts."""

from __future__ import annotations

import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expect_failure(callback, label: str) -> None:
    # The validators under test report rejection by printing an "ERROR: ..." line
    # to stderr and raising SystemExit(1). These negative cases are *expected* to
    # fire, so their ERROR lines must not leak into the aggregate gate's evidence
    # stream where they read as real failures. Capture stderr here, confirm the
    # rejection was genuine (an ERROR message plus exit code 1), and keep the
    # noise out of the stream.
    captured = io.StringIO()
    try:
        with contextlib.redirect_stderr(captured):
            callback()
    except SystemExit as exc:
        if exc.code != 1:
            raise AssertionError(f"{label} exited {exc.code}, expected 1") from exc
        if "ERROR:" not in captured.getvalue():
            raise AssertionError(
                f"{label} exited 1 without an ERROR message: {captured.getvalue()!r}"
            )
    else:
        raise AssertionError(f"{label} unexpectedly passed")


def main() -> int:
    mcp = load_module("check_mcp_parity", ROOT / "scripts" / "check-mcp-parity.py")
    cli = load_module("check_cli_parity", ROOT / "scripts" / "check-cli-parity.py")

    corpus = {
        "tool_cases": [
            {"tool": "shared", "cases": [{"name": "happy", "args": {"value": 1}}]},
            {"tool": "legacy_alias", "cases": [{"name": "alias", "args": {}}]},
        ]
    }
    mcp.check_tool_case_coverage(["shared", "upstream_only"], ["shared", "astrolabe_only"], corpus)
    expect_failure(
        lambda: mcp.check_tool_case_coverage(
            ["shared", "missing"], ["shared", "missing"], corpus
        ),
        "missing shared MCP case",
    )
    expect_failure(
        lambda: mcp.corpus_tool_names(
            {
                "tool_cases": [
                    {"tool": "shared", "cases": [{"name": "one", "args": {}}]},
                    {"tool": "shared", "cases": [{"name": "two", "args": {}}]},
                ]
            }
        ),
        "duplicate MCP case",
    )

    fixtures = {
        "schema": "astrolabe.cli_parity_fixtures.v2",
        "setup": [
            {"tool": "index_repository", "args": {"repo_path": "$ASTROLABE_CLI_PARITY_REPO"}}
        ],
        "tools": {
            "index_repository": {"args": {"repo_path": "$ASTROLABE_CLI_PARITY_REPO"}},
            "list_projects": {"args": {}, "allow_empty_args": True},
        },
    }
    setup, tool_fixtures = cli.validate_fixtures(fixtures)
    assert setup[0]["tool"] == "index_repository"
    cli.check_fixture_coverage(["index_repository", "list_projects"], tool_fixtures)
    assert cli.resolve_fixture_value(
        {"repo_path": "$ASTROLABE_CLI_PARITY_REPO"},
        {"$ASTROLABE_CLI_PARITY_REPO": "C:/fixture"},
    ) == {"repo_path": "C:/fixture"}
    assert cli.resolve_fixture_value(
        {"repo_path": "$ASTROLABE_CLI_PARITY_REINDEX_REPO"},
        {"$ASTROLABE_CLI_PARITY_REINDEX_REPO": "C:/fixture-reindex"},
    ) == {"repo_path": "C:/fixture-reindex"}
    cli.assert_happy_payload("index_repository", {"isError": False, "content": []})
    env = cli.base_env(Path("C:/fixture-cache"))
    assert env["CBM_INDEX_SUPERVISOR"] == "0"
    assert Path(env["HOME"]).name == "home"
    assert env["HOME"] == env["USERPROFILE"]
    with tempfile.TemporaryDirectory(prefix="astrolabe-parity-fixture-contract-", dir=ROOT) as tmp:
        fixture_root = Path(tmp)
        primary = cli.create_fixture_repo(fixture_root / "primary")
        reindex = cli.create_fixture_repo(fixture_root / "reindex")
        assert (primary / "src" / "main.c").is_file()
        assert not (primary / ".git").exists()
        assert not (reindex / ".git").exists()
        cli.initialize_fixture_git(primary)
        assert (primary / ".git").is_dir()
        assert (primary / "README.md").read_text(encoding="utf-8") == "CLI parity fixture change\n"
    # #243: the seed-provenance self-test was removed with seed_provenance_metadata.
    # The CLI-parity gate no longer seeds a fake surface; it reads back the real
    # persisted provenance surface and asserts its deterministic fail-closed
    # contract (get_provenance expect_error fixture), so there is nothing to seed
    # or schema-check here anymore.
    expect_failure(
        lambda: cli.validate_fixtures(
            {
                "schema": "astrolabe.cli_parity_fixtures.v2",
                "setup": fixtures["setup"],
                "tools": {"index_repository": {}},
            }
        ),
        "empty CLI args",
    )
    expect_failure(
        lambda: cli.assert_happy_payload("index_repository", {"isError": True, "content": []}),
        "CLI isError payload",
    )

    print("parity corpus contract self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
