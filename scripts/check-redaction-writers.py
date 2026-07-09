#!/usr/bin/env python3
"""Verify that Astrolabe production ledger writers are redaction-audited."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "ci" / "redaction-writers.json"
WRITER_METHODS = ("append_ledger_entry", "write_cf_batch_with_ledger_entry")
FN_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "astrolabe.redaction_writers.v1":
        print("redaction writer manifest has wrong schema_version", file=sys.stderr)
        return 1

    discovered = discover_writers()
    expected_entries = manifest.get("writers", [])
    expected = {
        (entry["file"], entry["function"], entry["method"]) for entry in expected_entries
    }

    missing = sorted(discovered - expected)
    stale = sorted(expected - discovered)
    incomplete = [
        entry
        for entry in expected_entries
        if not entry.get("payload_contract") or not entry.get("coverage")
    ]

    if missing or stale or incomplete:
        if missing:
            print("undocumented production ledger writer call sites:", file=sys.stderr)
            for file, function, method in missing:
                print(f"  {file}:{function}:{method}", file=sys.stderr)
        if stale:
            print("stale redaction writer manifest entries:", file=sys.stderr)
            for file, function, method in stale:
                print(f"  {file}:{function}:{method}", file=sys.stderr)
        if incomplete:
            print("manifest entries missing payload_contract or coverage:", file=sys.stderr)
            for entry in incomplete:
                print(
                    f"  {entry.get('file')}:{entry.get('function')}:{entry.get('method')}",
                    file=sys.stderr,
                )
        return 1

    print(f"redaction writer audit verified: {len(discovered)} production call sites")
    return 0


def discover_writers() -> set[tuple[str, str, str]]:
    writers: set[tuple[str, str, str]] = set()
    for path in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
        relative = path.relative_to(ROOT).as_posix()
        lines = production_lines(path.read_text(encoding="utf-8").splitlines())
        for index, line in enumerate(lines):
            for method in WRITER_METHODS:
                if method not in line:
                    continue
                writers.add((relative, enclosing_function(lines, index), method))
    return writers


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

