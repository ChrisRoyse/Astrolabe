#!/usr/bin/env python3
"""Verify root LICENSE/NOTICE coverage for release-critical vendored components."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "ci" / "license-notices.json"


def main() -> int:
    manifest = load_manifest()
    notice = read_required_file("NOTICE")
    for required in manifest["required_files"]:
        read_required_file(required)
    for component in manifest["components"]:
        check_component(component, notice)
    print(
        "license notices verified: "
        f"{len(manifest['components'])} components, schema={manifest['schema']}"
    )
    return 0


def load_manifest() -> dict[str, Any]:
    if not MANIFEST.exists():
        fail(f"missing license notice manifest: {MANIFEST}")
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {MANIFEST}: {exc}")
    if manifest.get("schema") != "astrolabe.license_notices.v1":
        fail("license notice manifest schema mismatch")
    if not isinstance(manifest.get("components"), list) or not manifest["components"]:
        fail("license notice manifest has no components")
    return manifest


def check_component(component: dict[str, Any], notice: str) -> None:
    name = component.get("name")
    license_file = component.get("license_file")
    notice_terms = component.get("notice_terms")
    if not name or not license_file or not isinstance(notice_terms, list):
        fail(f"malformed component entry: {component!r}")
    license_path = ROOT / license_file
    if not license_path.exists():
        fail(f"{name}: missing license file {license_file}")
    license_text = license_path.read_text(encoding="utf-8", errors="replace").strip()
    if not license_text:
        fail(f"{name}: empty license file {license_file}")
    for term in notice_terms:
        if term not in notice:
            fail(f"{name}: NOTICE missing required term {term!r}")


def read_required_file(path_text: str) -> str:
    path = ROOT / path_text
    if not path.exists():
        fail(f"missing required file {path_text}")
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        fail(f"required file is empty: {path_text}")
    return text


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    raise SystemExit(main())
