#!/usr/bin/env python3
"""Verify Astrolabe shell-sensitive production call sites are audited."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


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
    for path in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
        relative = path.relative_to(ROOT).as_posix()
        if relative == "crates/cbm-sys/src/bindings.rs":
            continue
        lines = production_lines(path.read_text(encoding="utf-8").splitlines())
        for index, line in enumerate(lines):
            for call, pattern in SHELL_SENSITIVE_CALLS.items():
                if pattern.search(line) is None:
                    continue
                sites.add((relative, enclosing_function(lines, index), call))
    return sites


def validator_precedes_call(entry: dict) -> bool:
    path = ROOT / entry["file"]
    lines = production_lines(path.read_text(encoding="utf-8").splitlines())
    validator = entry["validator"]
    call = entry["call"]
    function = entry["function"]
    in_function = False
    saw_validator = False
    for line in lines:
        match = FN_RE.match(line)
        if match:
            in_function = match.group(1) == function
            saw_validator = False
        if not in_function:
            continue
        if validator in line:
            saw_validator = True
        if call in line:
            return saw_validator
    return False


def production_lines(lines: list[str]) -> list[str]:
    for index, line in enumerate(lines):
        if line.strip() == "#[cfg(test)]":
            return lines[:index]
    return lines


def enclosing_function(lines: list[str], index: int) -> str:
    for line in reversed(lines[: index + 1]):
        match = FN_RE.match(line)
        if match:
            return match.group(1)
    return "<module>"


if __name__ == "__main__":
    raise SystemExit(main())
