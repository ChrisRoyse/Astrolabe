#!/usr/bin/env python3
"""Pin the CBM cache-path construction sites (#194/#232).

Root cause of the store leak: `cbm_resolve_cache_dir()`
(`src/foundation/platform.c`) is the library's single definition of the CBM cache
directory, but the vendored test suite does not call it — 21 test files rebuild
the same `$HOME/.cache/codebase-memory-mcp` formula by hand from `getenv("HOME")`.
Two sources of truth for one path is what makes a `CBM_CACHE_DIR` redirect split
the library's write path from the tests' read path, and it is why the store leaks
into the operator's profile at all.

`vendor/codebase-memory-mcp` is a byte-pinned subtree, so those duplications
cannot be deleted here (that is an upstream change). What CAN be enforced is that
they never grow: this gate recomputes every cache-path construction site under
the pinned tree and requires an exact match against `ci/cbm-cache-path-offenders.md`.
A new hand-built cache path, or a new `getenv("HOME")` fixture site, fails the
gate closed; Astrolabe-owned C under `patches/cbm/` is banned from the pattern
outright.

Re-derive the manifest with `--print-baseline` whenever the CBM vendor pin moves,
and review the delta: a shrinking count means upstream adopted the resolver.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[1]

# The literal formula the library owns in exactly one place.
CACHE_LITERAL = ".cache/codebase-memory-mcp"
# Fixture code that reaches for the home directory itself instead of the resolver.
HOME_GETENV = re.compile(r'getenv\("(?:HOME|USERPROFILE)"\)')

# Vendored CBM source under review (upstream third-party trees are excluded: they
# are not CBM code and cannot construct a CBM store path). Shell harnesses are
# scanned too: tests/test_cpp_index_hang.sh and tests/smoke_guard.sh rebuild the
# same $HOME formula, so they would have desynced under a CBM_CACHE_DIR redirect
# exactly like the C tests do.
SCANNED_SUBTREES = ("src", "tests", "internal", "scripts")
EXCLUDED_PARTS = ("vendored",)
SOURCE_SUFFIXES = (".c", ".h", ".cpp", ".sh")

# Astrolabe-owned C that participates in the CBM build. No cache-path
# construction is permitted here at all: this code is ours to keep correct.
ASTROLABE_C_GLOB = "patches/cbm/*.c"


def fail(code: str, message: str, remediation: str) -> None:
    print(f"ERROR[{code}]: {message}", file=sys.stderr)
    print(f"  remediation: {remediation}", file=sys.stderr)
    raise SystemExit(1)


def sources(cbm_root: Path) -> list[Path]:
    found: list[Path] = []
    for subtree in SCANNED_SUBTREES:
        base = cbm_root / subtree
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.suffix not in SOURCE_SUFFIXES or not path.is_file():
                continue
            if any(part in EXCLUDED_PARTS for part in path.relative_to(cbm_root).parts):
                continue
            found.append(path)
    return sorted(found)


def measure(cbm_root: Path) -> dict[str, tuple[int, int]]:
    """Map relative path -> (cache-literal count, home-getenv count) for offenders."""
    counts: dict[str, tuple[int, int]] = {}
    for path in sources(cbm_root):
        text = path.read_text(encoding="utf-8", errors="replace")
        literals = text.count(CACHE_LITERAL)
        homes = len(HOME_GETENV.findall(text))
        if literals or homes:
            counts[path.relative_to(cbm_root).as_posix()] = (literals, homes)
    return counts


def parse_manifest(manifest: Path) -> dict[str, tuple[int, int]]:
    expected: dict[str, tuple[int, int]] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        rel = cells[0].strip("`")
        try:
            expected[rel] = (int(cells[1]), int(cells[2]))
        except ValueError:
            fail(
                "ASTRO_CBM_CACHE_PATH_MANIFEST_INVALID",
                f"non-integer counts in {manifest.name} for {rel}: {cells[1]!r}, {cells[2]!r}",
                "Each manifest row must be | `path` | <literals> | <home-getenv sites> | <note> |.",
            )
    if not expected:
        fail(
            "ASTRO_CBM_CACHE_PATH_MANIFEST_EMPTY",
            f"{manifest} declares no cache-path construction sites",
            "Re-derive the manifest with scripts/check-cbm-cache-paths.py --print-baseline "
            "and commit the reviewed table.",
        )
    return expected


def render_baseline(counts: dict[str, tuple[int, int]]) -> str:
    rows = [f"| `{rel}` | {lit} | {home} |  |" for rel, (lit, home) in sorted(counts.items())]
    return "\n".join(rows)


def check_astrolabe_owned(root: Path) -> None:
    offenders: list[str] = []
    for path in sorted(root.glob(ASTROLABE_C_GLOB)):
        text = path.read_text(encoding="utf-8", errors="replace")
        if CACHE_LITERAL in text or HOME_GETENV.search(text):
            offenders.append(path.relative_to(root).as_posix())
    if offenders:
        fail(
            "ASTRO_CBM_CACHE_PATH_BANNED",
            "Astrolabe-owned CBM C sources construct a CBM cache path by hand: "
            + ", ".join(offenders),
            "Call cbm_resolve_cache_dir() (src/foundation/platform.h) instead of rebuilding "
            "$HOME/.cache/codebase-memory-mcp. The store has exactly one resolver.",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--cbm-root", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--print-baseline", action="store_true")
    args = parser.parse_args()

    root: Path = args.root
    cbm_root: Path = args.cbm_root or root / "vendor" / "codebase-memory-mcp"
    manifest: Path = args.manifest or root / "ci" / "cbm-cache-path-offenders.md"

    if not cbm_root.is_dir():
        fail(
            "ASTRO_CBM_CACHE_PATH_TREE_MISSING",
            f"CBM source tree not found at {cbm_root}",
            "Run the gate from the canonical workspace with the vendored subtree present.",
        )

    counts = measure(cbm_root)
    if args.print_baseline:
        print(render_baseline(counts))
        return

    if not manifest.is_file():
        fail(
            "ASTRO_CBM_CACHE_PATH_MANIFEST_MISSING",
            f"cache-path manifest not found at {manifest}",
            "Restore ci/cbm-cache-path-offenders.md; it is the pinned record of every "
            "cache-path construction site in the vendored CBM tree.",
        )

    check_astrolabe_owned(root)

    expected = parse_manifest(manifest)
    added = sorted(set(counts) - set(expected))
    removed = sorted(set(expected) - set(counts))
    changed = sorted(rel for rel in set(counts) & set(expected) if counts[rel] != expected[rel])

    if added or removed or changed:
        for rel in added:
            lit, home = counts[rel]
            print(
                f"  NEW      {rel}: {lit} cache-path literal(s), {home} home-getenv site(s)",
                file=sys.stderr,
            )
        for rel in removed:
            print(f"  GONE     {rel}: recorded in the manifest but no longer present", file=sys.stderr)
        for rel in changed:
            lit, home = counts[rel]
            exp_lit, exp_home = expected[rel]
            print(
                f"  CHANGED  {rel}: expected {exp_lit}/{exp_home}, measured {lit}/{home}",
                file=sys.stderr,
            )
        fail(
            "ASTRO_CBM_CACHE_PATH_DRIFT",
            f"cache-path construction sites drifted from {manifest.name}: "
            f"{len(added)} new, {len(removed)} gone, {len(changed)} changed",
            "New code must call cbm_resolve_cache_dir(): the store has exactly one resolver, "
            "and a second copy of the $HOME/.cache/codebase-memory-mcp formula is what splits "
            "the library's write path from the tests' read path (#194/#232). If the CBM vendor "
            "pin moved, re-derive with --print-baseline and commit the reviewed table.",
        )

    total_literals = sum(lit for lit, _ in counts.values())
    total_homes = sum(home for _, home in counts.values())
    print(
        f"CBM cache-path sites pinned: {len(counts)} files, "
        f"{total_literals} path literal(s), {total_homes} home-getenv site(s) -- no drift"
    )


if __name__ == "__main__":
    main()
