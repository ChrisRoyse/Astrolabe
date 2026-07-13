#!/usr/bin/env python3
"""Fail closed if a shipped release binary embeds a test-only failpoint marker.

Root cause (issue #291): ``calyx-aster`` carries a ``crash-fsv`` cargo feature
that compiles the ``crash_fsv_after_wal_append`` failpoint used by
``astrolabe-ingest``'s child-process crash-recovery test. The failpoint reads
the ``CALYX_ASTER_CRASH_FSV_AFTER_WAL_APPEND_MARKER`` environment variable and,
when set, writes a marker file and then parks the process forever. That must
never exist in a shipped Astrolabe binary.

The feature is wired ONLY through ``astrolabe-ingest``'s ``[dev-dependencies]``
and is not in any crate's ``default`` feature set, so with resolver = "2" the
normal/bin feature resolution of ``astrolabe`` never activates ``crash-fsv`` and
the failpoint's string literals are cfg'd out of the release binary. This gate
is the standing, byte-level proof of that exclusion: it reads the actual bytes
of every release binary named in the binary-size manifest and asserts none of
them contain a failpoint marker. It regresses loudly if anyone ever promotes
``crash-fsv`` to a normal dependency, adds it to a default feature set, or the
cargo feature-unification behaviour changes so a dev-dependency feature leaks
onto the shipped bin.

Fail-closed contract:
  * A binary named in the manifest that does not exist  =>  ERROR (never a skip:
    a missing release binary cannot be proven clean).
  * Any forbidden marker present in any binary           =>  ERROR, naming the
    binary, the marker, and the byte offset.
  * Manifest absent / wrong schema / no binaries         =>  ERROR.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "ci" / "binary-size-gate.json"

# Test-only failpoint markers that must never appear in a shipped binary. Each
# is the exact byte literal the corresponding failpoint compiles into its
# source when the (test-only) feature is enabled. Stored as bytes so this gate
# script's own source is not itself matchable by a naive source scan.
FORBIDDEN_MARKERS: tuple[bytes, ...] = (
    # calyx-aster crash-fsv failpoint env var (issue #291).
    b"CALYX_ASTER_CRASH_FSV_AFTER_WAL_APPEND_MARKER",
)


def fail(message: str) -> None:
    print(f"ERROR[ASTRO_RELEASE_FAILPOINT_STRING]: {message}", file=sys.stderr)
    print(
        "  remediation: keep the crash-fsv feature in astrolabe-ingest's "
        "[dev-dependencies] only (never a normal dep or a default feature); see "
        "issue #291.",
        file=sys.stderr,
    )
    raise SystemExit(1)


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        fail(f"cannot read manifest {path}: {exc}")
    except (json.JSONDecodeError, ValueError) as exc:
        fail(f"manifest {path} is not valid JSON: {exc}")


def resolve_binary(rel_path: str) -> Path:
    candidate = ROOT / rel_path
    if candidate.exists():
        return candidate
    if candidate.suffix == "" and candidate.with_name(candidate.name + ".exe").exists():
        return candidate.with_name(candidate.name + ".exe")
    fail(f"release binary missing: {rel_path} (cannot prove it is failpoint-free)")


def scan_binary(path: Path) -> list[tuple[str, int]]:
    data = path.read_bytes()
    hits: list[tuple[str, int]] = []
    for marker in FORBIDDEN_MARKERS:
        offset = data.find(marker)
        if offset >= 0:
            hits.append((marker.decode("ascii"), offset))
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(MANIFEST))
    args = parser.parse_args(argv)

    manifest_path = Path(args.manifest)
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("schema") != "astrolabe.binary_size_gate.v1":
        fail(f"manifest {manifest_path} schema mismatch (need astrolabe.binary_size_gate.v1)")
    binaries = manifest.get("binaries")
    if not isinstance(binaries, list) or not binaries:
        fail(f"manifest {manifest_path} lists no binaries to scan")

    scanned = []
    for entry in binaries:
        if not isinstance(entry, dict):
            fail(f"binary entry must be an object: {entry!r}")
        name = entry.get("name")
        rel_path = entry.get("path")
        if not isinstance(name, str) or not name:
            fail(f"binary entry missing name: {entry!r}")
        if not isinstance(rel_path, str) or not rel_path:
            fail(f"binary entry {name} missing path")
        path = resolve_binary(rel_path)
        hits = scan_binary(path)
        if hits:
            detail = ", ".join(f"{marker!r}@byte{offset}" for marker, offset in hits)
            fail(
                f"binary {name} ({path.relative_to(ROOT)}) embeds test-only "
                f"failpoint marker(s): {detail}"
            )
        scanned.append({"name": name, "path": str(path.relative_to(ROOT))})

    print(
        "release failpoint-string gate verified: "
        + json.dumps(
            {
                "schema": "astrolabe.release_failpoint_strings.v1",
                "markers_checked": [m.decode("ascii") for m in FORBIDDEN_MARKERS],
                "binaries": scanned,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
