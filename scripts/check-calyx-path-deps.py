#!/usr/bin/env python3
import json
import os
import subprocess
import sys


def load_metadata() -> dict:
    """Load workspace metadata, preferring the aggregate-run cache (#192).

    When ASTRO_CARGO_METADATA_JSON is set the file MUST be readable JSON —
    a broken cache is an error, never a silent fallback to a live resolve.
    """
    cache_path = os.environ.get("ASTRO_CARGO_METADATA_JSON")
    if cache_path:
        try:
            with open(cache_path, encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            print(
                "ERROR: ASTRO_CARGO_METADATA_JSON is set but unreadable "
                f"({cache_path}): {exc}",
                file=sys.stderr,
            )
            sys.exit(1)
    return json.loads(
        subprocess.check_output(
            [
                os.environ.get("CARGO", "cargo"),
                "metadata",
                "--format-version",
                "1",
                "--no-deps",
            ],
            text=True,
        )
    )


def workspace_packages(metadata: dict) -> list[dict]:
    """Filter to workspace members so a full-resolve cache matches --no-deps."""
    members = set(metadata.get("workspace_members") or [])
    packages = metadata["packages"]
    if not members:
        return packages
    return [package for package in packages if package.get("id") in members]


metadata = load_metadata()

bad = []
for package in workspace_packages(metadata):
    for dependency in package.get("dependencies", []):
        name = dependency["name"]
        if name.startswith("calyx-") and dependency.get("source") is not None:
            bad.append((package["name"], name, dependency["source"]))

if bad:
    for package, name, source in bad:
        print(
            f"ERROR: {package} depends on {name} from non-path source {source}",
            file=sys.stderr,
        )
    sys.exit(1)

print("calyx-* dependencies are path-only in cargo metadata")
