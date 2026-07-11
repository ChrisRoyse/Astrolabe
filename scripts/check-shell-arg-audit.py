#!/usr/bin/env python3
"""Verify Astrolabe shell-sensitive production call sites are audited."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import rust_prod_lines

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "ci" / "shell-arg-audit.json"
SHELL_SENSITIVE_CALLS = {
    "cbm_watcher_watch": re.compile(r"\bcbm_watcher_watch\s*\("),
    "Command::new": re.compile(r"\bCommand::new\s*\("),
}
FN_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "astrolabe.shell_arg_audit.v1":
        print("shell-arg audit manifest has wrong schema_version", file=sys.stderr)
        return 1

    discovered = discover_sites()
    expected_entries = manifest.get("sites", [])
    expected = {(entry["file"], entry["function"], entry["call"]) for entry in expected_entries}
    missing = sorted(discovered - expected)
    stale = sorted(expected - discovered)
    incomplete = [
        entry
        for entry in expected_entries
        if not entry.get("validator")
        or not entry.get("payload_contract")
        or not entry.get("coverage")
    ]
    unvalidated = [
        entry
        for entry in expected_entries
        if not validator_precedes_call(entry)
    ]

    if missing or stale or incomplete or unvalidated:
        if missing:
            print("undocumented shell-sensitive production call sites:", file=sys.stderr)
            for file, function, call in missing:
                print(f"  {file}:{function}:{call}", file=sys.stderr)
        if stale:
            print("stale shell-arg audit manifest entries:", file=sys.stderr)
            for file, function, call in stale:
                print(f"  {file}:{function}:{call}", file=sys.stderr)
        if incomplete:
            print("manifest entries missing validator/payload_contract/coverage:", file=sys.stderr)
            for entry in incomplete:
                print(
                    f"  {entry.get('file')}:{entry.get('function')}:{entry.get('call')}",
                    file=sys.stderr,
                )
        if unvalidated:
            print("manifest entries whose validator does not precede the call:", file=sys.stderr)
            for entry in unvalidated:
                print(
                    f"  {entry.get('file')}:{entry.get('function')}:{entry.get('call')}"
                    f" validator={entry.get('validator')!r}",
                    file=sys.stderr,
                )
        return 1

    print(f"shell-arg audit verified: {len(discovered)} production call sites")
    return 0


def discover_sites() -> set[tuple[str, str, str]]:
    sites: set[tuple[str, str, str]] = set()
    test_files, test_dirs = rust_prod_lines.cfg_test_module_files(ROOT / "crates")
    for path in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
        relative = path.relative_to(ROOT).as_posix()
        if relative == "crates/cbm-sys/src/bindings.rs":
            continue
        if rust_prod_lines.is_test_only_file(path, test_files, test_dirs):
            continue
        lines = rust_prod_lines.strip_test_spans(
            path.read_text(encoding="utf-8").splitlines()
        )
        for index, line in enumerate(lines):
            for call, pattern in SHELL_SENSITIVE_CALLS.items():
                if pattern.search(line) is None:
                    continue
                sites.add((relative, enclosing_function(lines, index), call))
    return sites


def validator_precedes_call(entry: dict) -> bool:
    """Structural check (#118): the validator CALL must appear before the audited
    call inside the named function's code, evaluated on the comment/string-blanked
    view — a comment or string mentioning the validator can no longer satisfy it."""
    path = ROOT / entry["file"]
    source_lines = rust_prod_lines.strip_test_spans(
        path.read_text(encoding="utf-8").splitlines()
    )
    view_lines = rust_prod_lines.code_view("\n".join(source_lines)).split("\n")
    infos = rust_prod_lines.line_depths(view_lines)
    function = entry["function"]
    validator_name = entry["validator"].split("(")[0].strip()
    call = entry["call"]
    validator_re = re.compile(rf"\b{re.escape(validator_name)}\s*\(")
    call_re = re.compile(rf"\b{re.escape(call)}\s*\(")

    index = 0
    total = len(view_lines)
    while index < total:
        match = FN_RE.match(view_lines[index])
        if match is None or match.group(1) != function:
            index += 1
            continue
        base_depth = infos[index][0]
        end = index
        opened = False
        while end < total:
            _start, end_depth, max_depth, _semis = infos[end]
            if max_depth > base_depth:
                opened = True
            if opened and end_depth <= base_depth:
                break
            end += 1
        body = "\n".join(view_lines[index : min(end + 1, total)])
        validator_match = validator_re.search(body)
        call_match = call_re.search(body)
        if call_match is None:
            index = end + 1
            continue
        return validator_match is not None and validator_match.start() < call_match.start()
    return False


def enclosing_function(lines: list[str], index: int) -> str:
    for line in reversed(lines[: index + 1]):
        match = FN_RE.match(line)
        if match:
            return match.group(1)
    return "<module>"


if __name__ == "__main__":
    raise SystemExit(main())
