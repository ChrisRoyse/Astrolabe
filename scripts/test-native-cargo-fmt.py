#!/usr/bin/env python3
"""Regression checks for the native Windows cargo-fmt batching shim."""

from __future__ import annotations

import importlib.util
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
    print("native cargo fmt batching contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
