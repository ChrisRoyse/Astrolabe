#!/usr/bin/env python3
"""Fail-closed hermeticity guard for the codebase-memory-mcp project store (#194/#232).

The CBM store has no registry table: a project is "registered" purely by the
presence of `<slug>.db` in the resolved cache directory. Gate runs therefore
register their fixture repositories permanently in whatever cache directory the
CBM library resolves, and a test that forgets to unlink its db leaves operator
state behind forever.

This guard is the un-forgeable half of the fix. A grep gate cannot see
subprocesses, shell tests, or Python harnesses; a byte manifest of the real
store can. `snapshot` records every entry (sha256 + size), `verify` re-reads the
same directory and fails closed if a single registration was added, removed, or
modified, and `require-writes` proves the redirected run-scoped store actually
received the writes (a silently no-op'ing suite must never pass as hermetic).

SQLite sidecars (`*.db-wal`, `*.db-shm`, `*.db-journal`) are reported but not
fatal: a long-lived MCP server owned by the operator may check-point an existing
database at any time. A registration — the `.db` file itself — is the assertion.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

# Sidecars are transient SQLite artifacts of an *existing* database, not
# registrations. Any new registration still surfaces through its `.db` entry.
SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")

READ_BLOCK_BYTES = 1 << 20


def is_sidecar(name: str) -> bool:
    return any(name.endswith(suffix) for suffix in SIDECAR_SUFFIXES)


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(READ_BLOCK_BYTES)
            if not block:
                break
            sha.update(block)
    return sha.hexdigest()


def scan(cache_dir: Path) -> dict[str, tuple[str, int]]:
    """Map relative path -> (sha256, size) for every regular file in the store."""
    entries: dict[str, tuple[str, int]] = {}
    if not cache_dir.is_dir():
        return entries
    for path in sorted(cache_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(cache_dir).as_posix()
        entries[rel] = (digest(path), path.stat().st_size)
    return entries


def render(entries: dict[str, tuple[str, int]]) -> str:
    lines = [f"{sha}  {size}  {rel}" for rel, (sha, size) in sorted(entries.items())]
    return "\n".join(lines) + ("\n" if lines else "")


def parse(text: str) -> dict[str, tuple[str, int]]:
    entries: dict[str, tuple[str, int]] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        sha, size, rel = line.split("  ", 2)
        entries[rel] = (sha, int(size))
    return entries


def fail(code: str, message: str, remediation: str) -> None:
    print(f"ERROR[{code}]: {message}", file=sys.stderr)
    print(f"  remediation: {remediation}", file=sys.stderr)
    raise SystemExit(1)


def summarize(cache_dir: Path, entries: dict[str, tuple[str, int]]) -> None:
    registrations = [rel for rel in entries if rel.endswith(".db")]
    total = sum(size for _, size in entries.values())
    print(f"  cache dir      : {cache_dir}")
    print(f"  entries        : {len(entries)}")
    print(f"  registrations  : {len(registrations)} (*.db)")
    print(f"  total bytes    : {total}")
    for rel in sorted(registrations):
        sha, size = entries[rel]
        print(f"    {sha[:16]}  {size:>10}  {rel}")


def cmd_snapshot(args: argparse.Namespace) -> None:
    entries = scan(args.cache_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render(entries), encoding="utf-8")
    print(f"CBM cache snapshot -> {args.out}")
    summarize(args.cache_dir, entries)


def cmd_verify(args: argparse.Namespace) -> None:
    before = parse(args.before.read_text(encoding="utf-8"))
    after = scan(args.cache_dir)
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(render(after), encoding="utf-8")

    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    modified = sorted(rel for rel in set(before) & set(after) if before[rel] != after[rel])

    churn = [rel for rel in added + removed + modified if is_sidecar(rel)]
    for rel in sorted(churn):
        print(
            "INFO[ASTRO_CBM_CACHE_SIDECAR_CHURN]: transient SQLite sidecar changed "
            f"outside the gate's control: {rel}"
        )

    added = [rel for rel in added if not is_sidecar(rel)]
    removed = [rel for rel in removed if not is_sidecar(rel)]
    modified = [rel for rel in modified if not is_sidecar(rel)]

    if added or removed or modified:
        for rel in added:
            print(f"  ADDED    {rel}", file=sys.stderr)
        for rel in removed:
            print(f"  REMOVED  {rel}", file=sys.stderr)
        for rel in modified:
            print(f"  MODIFIED {rel}", file=sys.stderr)
        fail(
            "ASTRO_CBM_CACHE_LEAK",
            f"the run mutated the protected CBM store at {args.cache_dir}: "
            f"{len(added)} added, {len(removed)} removed, {len(modified)} modified",
            "A test or gate resolved the CBM cache directory outside the run-scoped "
            "store. Redirect HOME (and USERPROFILE) for that phase (cbm_resolve_cache_dir "
            "and the vendored tests both derive the store from HOME, so they only stay in "
            "sync when HOME moves) and unlink every project db the phase creates.",
        )

    print(f"CBM cache hermeticity verified: {args.cache_dir} is byte-identical")
    summarize(args.cache_dir, after)


def cmd_require_writes(args: argparse.Namespace) -> None:
    entries = scan(args.cache_dir)
    if not entries:
        fail(
            "ASTRO_CBM_RUN_SCOPED_STORE_EMPTY",
            f"the run-scoped CBM store at {args.cache_dir} received no writes",
            "The suite indexed nothing into the redirected store, so a clean operator "
            "cache proves nothing. Confirm HOME/USERPROFILE reach the native test binary "
            "and that the CBM phase actually ran before trusting the hermeticity result.",
        )
    print("CBM run-scoped store received the suite's writes:")
    summarize(args.cache_dir, entries)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    snap = sub.add_parser("snapshot", help="record a byte manifest of a CBM store")
    snap.add_argument("--cache-dir", type=Path, required=True)
    snap.add_argument("--out", type=Path, required=True)
    snap.set_defaults(func=cmd_snapshot)

    verify = sub.add_parser("verify", help="fail closed if the store changed")
    verify.add_argument("--cache-dir", type=Path, required=True)
    verify.add_argument("--before", type=Path, required=True)
    verify.add_argument("--out", type=Path, default=None)
    verify.set_defaults(func=cmd_verify)

    writes = sub.add_parser("require-writes", help="prove the run-scoped store was written")
    writes.add_argument("--cache-dir", type=Path, required=True)
    writes.set_defaults(func=cmd_require_writes)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
