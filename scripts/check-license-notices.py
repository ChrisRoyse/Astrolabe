#!/usr/bin/env python3
"""Verify root LICENSE/NOTICE coverage for release-critical vendored components."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from release_artifact import write_artifact  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "ci" / "license-notices.json"
DEFAULT_ARTIFACT_DIR = ROOT / "target" / "astrolabe-release-predicate"
LICENSE_GATE_ARTIFACT = "license-gate.json"
VENDOR_NOTICE_NAMES = {"LICENSE", "LICENSE.md", "NOTICE", "NOTICE.md", "COPYING", "COPYING.md"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-release-artifact",
        action="store_true",
        help="Write the license_gate release-predicate artifact on success.",
    )
    parser.add_argument(
        "--artifact-dir",
        default=str(DEFAULT_ARTIFACT_DIR),
        help="Directory for release-predicate artifacts.",
    )
    args = parser.parse_args()

    summary = verify_license_notices()
    if args.write_release_artifact:
        write_release_artifact(summary, Path(args.artifact_dir))
    print(
        "license notices verified: "
        f"{summary['component_count']} components, "
        f"{summary['coverage_group_count']} coverage groups, "
        f"{summary['vendor_notice_file_count']} vendor notice files, "
        f"schema={summary['manifest_schema']}"
    )
    return 0


def verify_license_notices() -> dict[str, Any]:
    manifest = load_manifest()
    notice = read_required_file("NOTICE")
    for required in manifest["required_files"]:
        read_required_file(required)
    discovered = discover_vendor_notice_files()
    covered = set()
    for component in manifest["components"]:
        covered.update(check_component(component, notice))
    for group in manifest.get("coverage_groups", []):
        covered.update(check_coverage_group(group, notice, discovered))
    uncovered = sorted(set(discovered) - covered)
    if uncovered:
        fail(
            "notice.uncovered_vendor_file",
            "vendor license/notice file has no manifest-backed NOTICE coverage",
            "add an explicit component or coverage group to ci/license-notices.json "
            "and a matching entry in NOTICE",
            {"first_uncovered": uncovered[0], "uncovered_count": len(uncovered)},
        )
    return {
        "manifest_schema": manifest["schema"],
        "component_count": len(manifest["components"]),
        "coverage_group_count": len(manifest.get("coverage_groups", [])),
        "vendor_notice_file_count": len(discovered),
        "covered_vendor_notice_file_count": len(covered),
        "component_names": [component["name"] for component in manifest["components"]],
        "coverage_group_names": [
            group["name"] for group in manifest.get("coverage_groups", [])
        ],
    }


def write_release_artifact(summary: dict[str, Any], artifact_dir: Path) -> None:
    """Publish the license_gate artifact. Called only after verification succeeded (#88)."""
    artifact = {
        "schema": "astrolabe.license_gate.v1",
        "status": "pass",
        "source": "scripts/check-license-notices.py",
        "manifest": normalize_path(str(MANIFEST.relative_to(ROOT))),
        "notice": "NOTICE",
        "vendor_discovery": "git ls-files vendor",
        **summary,
    }
    write_artifact(artifact_dir, LICENSE_GATE_ARTIFACT, artifact, ROOT)


def load_manifest() -> dict[str, Any]:
    if not MANIFEST.exists():
        fail(
            "notice.missing_manifest",
            "missing license notice manifest",
            "restore ci/license-notices.json",
            {"path": str(MANIFEST.relative_to(ROOT))},
        )
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(
            "notice.invalid_json",
            "invalid JSON in license notice manifest",
            "fix ci/license-notices.json so it parses as JSON",
            {"error": str(exc)},
        )
    if manifest.get("schema") != "astrolabe.license_notices.v2":
        fail(
            "notice.schema",
            "license notice manifest schema mismatch",
            "update ci/license-notices.json to schema astrolabe.license_notices.v2",
        )
    if not isinstance(manifest.get("components"), list) or not manifest["components"]:
        fail(
            "notice.no_components",
            "license notice manifest has no components",
            "add at least one component entry to ci/license-notices.json",
        )
    if not isinstance(manifest.get("coverage_groups", []), list):
        fail(
            "notice.bad_groups",
            "license notice manifest coverage_groups must be a list",
            "make coverage_groups an array or remove it",
        )
    return manifest


def check_component(component: dict[str, Any], notice: str) -> set[str]:
    name = component.get("name")
    license_file = component.get("license_file")
    notice_terms = component.get("notice_terms")
    if not name or not license_file or not isinstance(notice_terms, list):
        fail(
            "notice.malformed_component",
            "malformed component entry",
            "component entries require name, license_file, and notice_terms",
            {"component": component},
        )
    covered = {check_nonempty_vendor_file(name, license_file)}
    source_notice_files = component.get("source_notice_files", [])
    if not isinstance(source_notice_files, list):
        fail(
            "notice.bad_source_notice_files",
            f"{name}: source_notice_files must be a list",
            "make source_notice_files an array of paths or remove it",
            {"source_notice_files": source_notice_files},
        )
    for notice_file in source_notice_files:
        covered.add(check_nonempty_vendor_file(name, notice_file))
    for term in notice_terms:
        if term not in notice:
            fail(
                "notice.missing_term",
                f"{name}: NOTICE missing required term",
                "add the required term to NOTICE or correct ci/license-notices.json",
                {"term": term},
            )
    return covered


def check_coverage_group(
    group: dict[str, Any], notice: str, discovered: list[str]
) -> set[str]:
    name = group.get("name")
    path_prefix = normalize_path(group.get("path_prefix", ""))
    file_names = group.get("file_names")
    notice_terms = group.get("notice_terms")
    if (
        not name
        or not path_prefix
        or not isinstance(file_names, list)
        or not file_names
        or not isinstance(notice_terms, list)
    ):
        fail(
            "notice.malformed_group",
            "malformed coverage group entry",
            "coverage groups require name, path_prefix, file_names, and notice_terms",
            {"group": group},
        )
    prefix = path_prefix.rstrip("/") + "/"
    names = set(file_names)
    matches = {
        path
        for path in discovered
        if path.startswith(prefix) and Path(path).name in names
    }
    if not matches:
        fail(
            "notice.empty_group",
            f"{name}: coverage group matched no vendor notice files",
            "update the path_prefix/file_names or remove the stale coverage group",
            {"path_prefix": path_prefix},
        )
    for term in notice_terms:
        if term not in notice:
            fail(
                "notice.group_missing_term",
                f"{name}: NOTICE missing required group term",
                "add the required grouped notice text to NOTICE",
                {"term": term},
            )
    return matches


def check_nonempty_vendor_file(name: str, path_text: str) -> str:
    normalized = normalize_path(path_text)
    path = ROOT / normalized
    if not path.exists():
        fail(
            "notice.missing_vendor_file",
            f"{name}: missing vendor notice file",
            "restore the vendor license/notice file or update ci/license-notices.json",
            {"path": normalized},
        )
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        fail(
            "notice.empty_vendor_file",
            f"{name}: empty vendor notice file",
            "restore the upstream license/notice text before distributing",
            {"path": normalized},
        )
    return normalized


def discover_vendor_notice_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "vendor"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail(
            "notice.git_ls_files",
            "failed to enumerate tracked vendor files",
            "run this check from a Git checkout with git available",
            {"stderr": result.stderr.strip()},
        )
    paths = [
        normalize_path(line)
        for line in result.stdout.splitlines()
        if Path(line).name in VENDOR_NOTICE_NAMES
    ]
    if not paths:
        fail(
            "notice.no_vendor_files",
            "no tracked vendor license/notice files were discovered",
            "restore vendor/calyx and vendor/codebase-memory-mcp before release checks",
        )
    return sorted(paths)


def read_required_file(path_text: str) -> str:
    path = ROOT / path_text
    if not path.exists():
        fail(
            "notice.missing_required_file",
            "missing required root notice file",
            "restore the required release notice file",
            {"path": path_text},
        )
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        fail(
            "notice.empty_required_file",
            "required root notice file is empty",
            "restore the required release notice text",
            {"path": path_text},
        )
    return text


def normalize_path(path_text: str) -> str:
    return str(path_text).replace("\\", "/")


def fail(
    code: str,
    message: str,
    remediation: str,
    details: dict[str, Any] | None = None,
) -> None:
    payload: dict[str, Any] = {
        "code": code,
        "message": message,
        "remediation": remediation,
    }
    if details:
        payload["details"] = details
    print(f"ERROR: {json.dumps(payload, sort_keys=True)}", file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    raise SystemExit(main())
