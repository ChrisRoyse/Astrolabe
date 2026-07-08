#!/usr/bin/env python3
import json
import os
import subprocess
import sys

metadata = json.loads(
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

bad = []
for package in metadata["packages"]:
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
