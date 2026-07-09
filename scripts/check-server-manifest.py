#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "server.json"
SCHEMA_URL = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def workspace_version():
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r"(?m)^\[workspace\.package\]\s*$(.*?)^\[", text + "\n[", re.S)
    if not match:
        fail("Cargo.toml missing [workspace.package]")
    block = match.group(1)
    version = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', block)
    if not version:
        fail("Cargo.toml [workspace.package] missing version")
    return version.group(1)


def resolve_binary(name, release=False):
    profile = "release" if release else "debug"
    candidate = ROOT / "target" / profile / name
    if os.name == "nt":
        if candidate.suffix:
            exe_candidate = candidate.with_suffix(candidate.suffix + ".exe")
        else:
            exe_candidate = candidate.with_name(candidate.name + ".exe")
        if exe_candidate.exists():
            return exe_candidate
        fail(f"manifest runtime binary is not built: {exe_candidate}")
    if candidate.exists():
        return candidate
    fail(f"manifest runtime binary is not built: {candidate}")


def run_version(binary):
    proc = subprocess.run(
        [str(binary), "--version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        fail(f"{binary.name} --version failed rc={proc.returncode}\nstderr={proc.stderr}")
    return proc.stdout.strip()


def validate_manifest(manifest, version):
    if manifest.get("$schema") != SCHEMA_URL:
        fail("server.json schema URL mismatch")
    for key in ["name", "description", "version"]:
        if not isinstance(manifest.get(key), str) or not manifest[key].strip():
            fail(f"server.json missing non-empty {key}")
    if manifest["name"] != "io.github.ChrisRoyse/Astrolabe":
        fail(f"server.json name mismatch: {manifest['name']!r}")
    if manifest["version"] != version:
        fail(f"server.json version {manifest['version']!r} does not match workspace {version!r}")
    repository = manifest.get("repository")
    if not isinstance(repository, dict):
        fail("server.json repository must be an object")
    if repository.get("url") != "https://github.com/ChrisRoyse/Astrolabe":
        fail("server.json repository.url mismatch")
    if repository.get("source") != "github":
        fail("server.json repository.source must be github")

    meta = manifest.get("_meta")
    if not isinstance(meta, dict):
        fail("server.json _meta must be an object")
    if meta.get("astrolabe.schema") != "astrolabe.server_manifest.v1":
        fail("server.json _meta astrolabe schema mismatch")
    if meta.get("astrolabe.primary.command") != "astrolabe":
        fail("server.json primary command must be astrolabe")
    if meta.get("astrolabe.compatibility.command") != "codebase-memory-mcp":
        fail("server.json compatibility command must be codebase-memory-mcp")
    publication = meta.get("astrolabe.packagePublication")
    if not isinstance(publication, dict):
        fail("server.json packagePublication must be an object")
    if publication.get("status") != "not_published":
        fail("server.json packagePublication.status must stay not_published until package channels are verified")
    if not isinstance(publication.get("remediation"), str) or not publication["remediation"]:
        fail("server.json packagePublication requires remediation")
    if "packages" in manifest:
        fail("server.json must not claim public package entries while packagePublication.status is not_published")

    binaries = meta.get("astrolabe.runtimeBinaries")
    if not isinstance(binaries, list) or len(binaries) != 2:
        fail("server.json must declare the two runtime binaries")
    names = {item.get("name") for item in binaries if isinstance(item, dict)}
    if names != {"astrolabe", "codebase-memory-mcp"}:
        fail(f"server.json runtime binary names mismatch: {sorted(names)}")
    for item in binaries:
        if item.get("transport") != "stdio":
            fail(f"runtime binary {item.get('name')} must use stdio transport")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", action="store_true", help="check target/release binaries")
    args = parser.parse_args()

    version = workspace_version()
    manifest = load_json(MANIFEST)
    validate_manifest(manifest, version)
    binaries = manifest["_meta"]["astrolabe.runtimeBinaries"]
    version_readbacks = {}
    for item in binaries:
        binary = resolve_binary(item["name"], release=args.release)
        reported = run_version(binary)
        expected = f"astrolabe {version}"
        if reported != expected:
            fail(f"{binary.name} reported {reported!r}, expected {expected!r}")
        version_readbacks[item["name"]] = reported

    print(
        "server manifest verified: "
        + json.dumps(
            {
                "schema": "astrolabe.server_manifest_check.v1",
                "manifest": "server.json",
                "version": version,
                "runtime_binaries": version_readbacks,
                "package_publication": manifest["_meta"]["astrolabe.packagePublication"]["status"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
