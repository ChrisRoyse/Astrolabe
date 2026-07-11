#!/usr/bin/env python3
"""Fail-closed scan for mock-like constructs in repository test code.

Tests must verify real persisted state, never a mocked stand-in (standing
invariant 5; issue #181). A deterministic scan is the bootstrap for the
Calyx-native test-honesty lens; it fails closed on any unmarked mock-like
construct. A legitimate, unavoidable test double must carry an inline
justification marker on or within two lines above the match:

    ASTRO_ALLOW_TEST_DOUBLE(<nonempty reason>)

or a file-level marker within the first 40 lines:

    ASTRO_ALLOW_TEST_DOUBLE_FILE(<nonempty reason>)

Allowed doubles are counted and listed, never silent.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = {"vendor", "target", ".toolchains", ".tmp", ".git", "node_modules"}
SELF_NAMES = {"check-no-mocks.py", "test-check-no-mocks.py"}

RUST_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(mockall|mockito|unimock|httpmock|wiremock|faux)\b"), "mock framework"),
    (re.compile(r"#\[automock\]"), "automock attribute"),
    (re.compile(r"\b(?:mock|stub|fake|dummy)_[a-z0-9_]+"), "test-double binding"),
    (re.compile(r"\bMock[A-Z][A-Za-z0-9]*"), "Mock-prefixed type"),
    (re.compile(r"assert!\(\s*true\s*\)"), "vacuous assertion"),
]
PYTHON_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bunittest\.mock\b|\bfrom\s+unittest\s+import\s+mock\b"), "unittest.mock import"),
    (re.compile(r"\bmock\.patch\b|\bMagicMock\b|\bmonkeypatch\b"), "mock patching"),
]
CARGO_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"^\s*(mockall|mockito|unimock|httpmock|wiremock|faux)\s*="),
        "mock crate dependency",
    ),
]
ALLOW_LINE = re.compile(r"ASTRO_ALLOW_TEST_DOUBLE\(([^)]+)\)")
ALLOW_FILE = re.compile(r"ASTRO_ALLOW_TEST_DOUBLE_FILE\(([^)]+)\)")
FILE_MARKER_WINDOW = 40


def is_excluded(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    if any(part in EXCLUDED_PARTS for part in relative.parts):
        return True
    return path.name in SELF_NAMES


def patterns_for(path: Path) -> list[tuple[re.Pattern[str], str]]:
    if path.suffix == ".rs":
        return RUST_PATTERNS
    if path.suffix == ".py":
        return PYTHON_PATTERNS
    if path.name == "Cargo.toml":
        return CARGO_PATTERNS
    return []


def scan_file(path: Path) -> tuple[list[tuple[int, str, str]], list[tuple[int, str, str]]]:
    """Return (violations, allowed) as (line_no, kind, excerpt) tuples."""
    patterns = patterns_for(path)
    if not patterns:
        return [], []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    file_marker = None
    for line in lines[:FILE_MARKER_WINDOW]:
        match = ALLOW_FILE.search(line)
        if match and match.group(1).strip():
            file_marker = match.group(1).strip()
            break
    violations: list[tuple[int, str, str]] = []
    allowed: list[tuple[int, str, str]] = []
    for index, line in enumerate(lines):
        for pattern, kind in patterns:
            if not pattern.search(line):
                continue
            reason = file_marker
            if reason is None:
                for probe in lines[max(0, index - 2) : index + 1]:
                    line_marker = ALLOW_LINE.search(probe)
                    if line_marker and line_marker.group(1).strip():
                        reason = line_marker.group(1).strip()
                        break
            record = (index + 1, kind, line.strip()[:160])
            if reason is None:
                violations.append(record)
            else:
                allowed.append(record)
            break
    return violations, allowed


def scan(root: Path) -> tuple[dict[Path, list], dict[Path, list], int]:
    violations: dict[Path, list] = {}
    allowed: dict[Path, list] = {}
    scanned = 0
    scan_roots = [root / "crates", root / "scripts", root / "ci"]
    candidates: list[Path] = [root / "Cargo.toml"]
    for scan_root in scan_roots:
        if not scan_root.is_dir():
            continue
        candidates.extend(scan_root.rglob("*.rs"))
        candidates.extend(scan_root.rglob("*.py"))
        candidates.extend(scan_root.rglob("Cargo.toml"))
    for path in candidates:
        if not path.is_file() or is_excluded(path, root):
            continue
        scanned += 1
        file_violations, file_allowed = scan_file(path)
        if file_violations:
            violations[path] = file_violations
        if file_allowed:
            allowed[path] = file_allowed
    return violations, allowed, scanned


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()
    root = args.root.resolve()

    violations, allowed, scanned = scan(root)
    for path, records in sorted(allowed.items()):
        for line_no, kind, excerpt in records:
            print(
                f"ALLOWED[ASTRO_TEST_DOUBLE]: {path.relative_to(root)}:{line_no} "
                f"({kind}): {excerpt}"
            )
    if violations:
        for path, records in sorted(violations.items()):
            for line_no, kind, excerpt in records:
                print(
                    f"ERROR: ASTRO_MOCK_IN_TEST: {path.relative_to(root)}:{line_no} "
                    f"({kind}): {excerpt}",
                    file=sys.stderr,
                )
        print(
            "ERROR: mock-like constructs found; verify against real persisted state "
            "or justify with ASTRO_ALLOW_TEST_DOUBLE(reason)",
            file=sys.stderr,
        )
        return 1
    allowed_count = sum(len(records) for records in allowed.values())
    print(
        f"no-mock gate verified: files_scanned={scanned} "
        f"allowed_test_doubles={allowed_count} violations=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
