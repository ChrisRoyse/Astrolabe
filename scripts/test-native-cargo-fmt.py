#!/usr/bin/env python3
"""Regression checks for the native Windows cargo-fmt batching shim."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / "scripts" / "native-cargo-fmt.py"


def load_shim():
    spec = importlib.util.spec_from_file_location("native_cargo_fmt", SHIM)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SHIM}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def target(path: Path, edition: str = "2024") -> dict:
    return {"src_path": str(path), "edition": edition, "kind": ["lib"]}


def main() -> int:
    shim = load_shim()
    scratch_root = ROOT / ".native-cargo-fmt-test"
    scratch_root.mkdir(exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="native-cargo-fmt-", dir=scratch_root) as temp:
            temp_path = Path(temp)
            root_manifest = temp_path / "Cargo.toml"
            dependency_dir = temp_path / "dependency"
            dependency_manifest = dependency_dir / "Cargo.toml"
            root_source = temp_path / "src" / "lib.rs"
            dependency_source = dependency_dir / "src" / "lib.rs"
            for path in (root_manifest, dependency_manifest, root_source, dependency_source):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("", encoding="utf-8")

            metadata = {
                None: {
                    "packages": [
                        {
                            "manifest_path": str(root_manifest),
                            "targets": [target(root_source)],
                            "dependencies": [
                                {"name": "local-dependency", "path": str(dependency_dir)}
                            ],
                        }
                    ]
                },
                dependency_manifest.resolve(): {
                    "packages": [
                        {
                            "manifest_path": str(dependency_manifest),
                            "targets": [target(dependency_source), target(root_source)],
                            "dependencies": [],
                        }
                    ]
                },
            }

            def metadata_loader(manifest: Path | None) -> dict:
                key = None if manifest is None else manifest.resolve()
                return metadata[key]

            collected = shim.collect_all_targets(metadata_loader=metadata_loader)
            assert [entry[0] for entry in collected] == sorted(
                {root_source.resolve(), dependency_source.resolve()}, key=str
            )

            parsed = shim.parse_all_options(["--all", "--check"])
            assert parsed.all and parsed.check
            cargo_args, rustfmt_args = shim.split_arguments(["--all", "--", "--check"])
            assert cargo_args == ["--all"]
            assert rustfmt_args == ["--check"]

            long_targets = [
                (temp_path / ("x" * 180) / f"source-{index}.rs", "2024", "lib")
                for index in range(80)
            ]
            batches = shim.batch_targets(
                long_targets,
                "2024",
                ["--check"],
                "rustfmt.exe",
                limit=1_000,
            )
            assert len(batches) > 1
            for batch in batches:
                command = [
                    "rustfmt.exe",
                    *(str(entry[0]) for entry in batch),
                    "--edition",
                    "2024",
                    "--check",
                ]
                assert shim.command_length(command) <= 1_000
    finally:
        shutil.rmtree(scratch_root, ignore_errors=True)
    assert not scratch_root.exists()
    check_workspace_metadata_reuse(shim)
    check_metadata_cache_env(shim)
    print("native cargo fmt batching contract passed")
    return 0


def check_workspace_metadata_reuse(shim) -> None:
    """Crates sharing an external workspace must reuse one metadata resolve (#192)."""
    scratch_root = ROOT / ".native-cargo-fmt-test"
    scratch_root.mkdir(exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="native-cargo-fmt-", dir=scratch_root) as temp:
            temp_path = Path(temp)
            root_manifest = temp_path / "Cargo.toml"
            root_source = temp_path / "src" / "lib.rs"
            vendor = temp_path / "vendor"
            dep_a_dir = vendor / "dep-a"
            dep_b_dir = vendor / "dep-b"
            dep_a_manifest = dep_a_dir / "Cargo.toml"
            dep_b_manifest = dep_b_dir / "Cargo.toml"
            dep_a_source = dep_a_dir / "src" / "lib.rs"
            dep_b_source = dep_b_dir / "src" / "lib.rs"
            for path in (
                root_manifest,
                root_source,
                dep_a_manifest,
                dep_b_manifest,
                dep_a_source,
                dep_b_source,
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("", encoding="utf-8")

            vendor_workspace = {
                "packages": [
                    {
                        "manifest_path": str(dep_a_manifest),
                        "targets": [target(dep_a_source)],
                        "dependencies": [],
                    },
                    {
                        "manifest_path": str(dep_b_manifest),
                        "targets": [target(dep_b_source)],
                        "dependencies": [],
                    },
                ]
            }
            metadata = {
                None: {
                    "packages": [
                        {
                            "manifest_path": str(root_manifest),
                            "targets": [target(root_source)],
                            "dependencies": [
                                {"name": "dep-a", "path": str(dep_a_dir)},
                                {"name": "dep-b", "path": str(dep_b_dir)},
                            ],
                        }
                    ]
                },
                dep_a_manifest.resolve(): vendor_workspace,
                dep_b_manifest.resolve(): vendor_workspace,
            }

            loads: list[Path | None] = []

            def metadata_loader(manifest: Path | None) -> dict:
                loads.append(manifest)
                key = None if manifest is None else manifest.resolve()
                return metadata[key]

            collected = shim.collect_all_targets(metadata_loader=metadata_loader)
            assert [entry[0] for entry in collected] == sorted(
                {
                    root_source.resolve(),
                    dep_a_source.resolve(),
                    dep_b_source.resolve(),
                },
                key=str,
            )
            # Exactly one live resolve per workspace: the root plus the FIRST
            # vendor crate; the second vendor crate reuses the first resolve.
            assert loads == [None, dep_a_manifest], loads
    finally:
        shutil.rmtree(scratch_root, ignore_errors=True)
    assert not scratch_root.exists()


def check_metadata_cache_env(shim) -> None:
    """load_metadata(None) must honor ASTRO_CARGO_METADATA_JSON fail-closed (#192)."""
    scratch_root = ROOT / ".native-cargo-fmt-test"
    scratch_root.mkdir(exist_ok=True)
    saved = os.environ.get("ASTRO_CARGO_METADATA_JSON")
    try:
        with tempfile.TemporaryDirectory(prefix="native-cargo-fmt-", dir=scratch_root) as temp:
            temp_path = Path(temp)
            cache_file = temp_path / "metadata.json"
            member_manifest = temp_path / "member" / "Cargo.toml"
            member_source = temp_path / "member" / "src" / "lib.rs"
            for path in (member_manifest, member_source):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("", encoding="utf-8")
            cached = {
                "workspace_members": ["member-id"],
                "packages": [
                    {
                        "id": "member-id",
                        "manifest_path": str(member_manifest),
                        "targets": [target(member_source)],
                        "dependencies": [],
                    },
                    {
                        "id": "registry-dep-id",
                        "manifest_path": str(temp_path / "registry" / "Cargo.toml"),
                        "targets": [target(temp_path / "registry" / "src" / "lib.rs")],
                        "dependencies": [],
                    },
                ],
            }
            cache_file.write_text(json.dumps(cached), encoding="utf-8")

            os.environ["ASTRO_CARGO_METADATA_JSON"] = str(cache_file)
            # The cache is served without running cargo.
            assert shim.load_metadata(None) == cached
            # Full-resolve caches are filtered to workspace members downstream.
            collected = shim.collect_all_targets(metadata_loader=shim.load_metadata)
            assert [entry[0] for entry in collected] == [member_source.resolve()]

            # A set-but-unreadable cache fails closed, never falls back.
            os.environ["ASTRO_CARGO_METADATA_JSON"] = str(temp_path / "missing.json")
            try:
                shim.load_metadata(None)
            except shim.FormatterError:
                pass
            else:
                raise AssertionError("unreadable metadata cache must fail closed")
    finally:
        if saved is None:
            os.environ.pop("ASTRO_CARGO_METADATA_JSON", None)
        else:
            os.environ["ASTRO_CARGO_METADATA_JSON"] = saved
        shutil.rmtree(scratch_root, ignore_errors=True)
    assert not scratch_root.exists()


if __name__ == "__main__":
    raise SystemExit(main())
