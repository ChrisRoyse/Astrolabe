#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "ci" / "binary-size-gate.json"
MIB = 1024 * 1024


def fail(message, *, breakdown=None):
    print(f"ERROR: {message}", file=sys.stderr)
    if breakdown is not None:
        print(
            json.dumps(
                {
                    "schema": "astrolabe.binary_size_breakdown.v1",
                    "breakdown": breakdown,
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
    raise SystemExit(1)


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_binary(path):
    candidate = ROOT / path
    if candidate.exists():
        return candidate
    if candidate.suffix == "" and candidate.with_name(candidate.name + ".exe").exists():
        return candidate.with_name(candidate.name + ".exe")
    fail(f"release binary missing: {path}")


def binary_row(entry):
    path = resolve_binary(entry["path"])
    size = path.stat().st_size
    return {
        "name": entry["name"],
        "path": str(path.relative_to(ROOT)),
        "bytes": size,
        "mib": round(size / MIB, 3),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=str(MANIFEST))
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    manifest = load_json(manifest_path)
    if manifest.get("schema") != "astrolabe.binary_size_gate.v1":
        fail("binary size gate manifest schema mismatch")
    max_bytes = manifest.get("max_bytes")
    if not isinstance(max_bytes, int) or max_bytes <= 0:
        fail("binary size gate manifest requires positive integer max_bytes")
    binaries = manifest.get("binaries")
    if not isinstance(binaries, list) or not binaries:
        fail("binary size gate manifest requires binaries")

    breakdown = []
    seen = set()
    for entry in binaries:
        if not isinstance(entry, dict):
            fail(f"binary entry must be an object: {entry!r}")
        name = entry.get("name")
        path = entry.get("path")
        if not isinstance(name, str) or not name:
            fail(f"binary entry missing name: {entry!r}")
        if name in seen:
            fail(f"duplicate binary entry: {name}")
        seen.add(name)
        if not isinstance(path, str) or not path:
            fail(f"binary entry {name} missing path")
        breakdown.append(binary_row(entry))

    oversized = [row for row in breakdown if row["bytes"] > max_bytes]
    if oversized:
        fail(
            "release binary size gate exceeded; "
            + manifest.get("remediation", "reduce binary size or update the manifest with evidence"),
            breakdown=breakdown,
        )

    print(
        "binary size verified: "
        + json.dumps(
            {
                "schema": "astrolabe.binary_size_gate.v1",
                "max_bytes": max_bytes,
                "max_mib": round(max_bytes / MIB, 3),
                "binaries": breakdown,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
