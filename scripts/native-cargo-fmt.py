#!/usr/bin/env python3
"""Run ``cargo fmt --all`` in Windows-safe rustfmt batches.

The upstream cargo-fmt command discovers local path dependencies correctly,
but it gives every discovered target to one rustfmt process. That command line
exceeds Windows limits once the Calyx workspace is included. This wrapper
preserves cargo-fmt's recursive local-dependency traversal and batches each
edition before invoking rustfmt.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path


WINDOWS_SAFE_COMMAND_LIMIT = 6_000
INFO_RUSTFMT_ARGS = {"--print-config", "-h", "--help", "-V", "--version"}
Target = tuple[Path, str, str]
MetadataLoader = Callable[[Path | None], dict]


class FormatterError(RuntimeError):
    """An error that should be presented as a cargo-fmt failure."""


def cargo_binary() -> str:
    return os.environ.get("CARGO", "cargo")


def canonical_path(path: Path) -> Path:
    try:
        return path.resolve(strict=True)
    except OSError:
        return path


def workspace_packages(metadata: dict) -> list[dict]:
    """Filter to workspace members so a full-resolve cache matches --no-deps."""
    members = set(metadata.get("workspace_members") or [])
    packages = metadata.get("packages", [])
    if not members:
        return packages
    filtered = [package for package in packages if package.get("id") in members]
    return filtered or packages


def load_metadata(manifest_path: Path | None = None) -> dict:
    if manifest_path is None:
        # Reuse the aggregate run's single metadata resolve when the driver
        # provides one (#192). A set-but-unreadable cache is an error, never a
        # silent fallback to a live resolve.
        cache_path = os.environ.get("ASTRO_CARGO_METADATA_JSON")
        if cache_path:
            try:
                with open(cache_path, encoding="utf-8") as handle:
                    return json.load(handle)
            except (OSError, json.JSONDecodeError) as exc:
                raise FormatterError(
                    "ASTRO_CARGO_METADATA_JSON is set but unreadable "
                    f"({cache_path}): {exc}"
                ) from exc

    base_command = [
        cargo_binary(),
        "metadata",
        "--format-version",
        "1",
        "--no-deps",
    ]
    if manifest_path is not None:
        base_command.extend(["--manifest-path", str(manifest_path)])

    errors: list[str] = []
    for offline in (True, False):
        command = [*base_command]
        if offline:
            command.append("--offline")
        try:
            result = subprocess.run(
                command,
                check=False,
                text=True,
                capture_output=True,
            )
        except OSError as exc:
            raise FormatterError(f"could not run cargo metadata: {exc}") from exc
        if result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise FormatterError(f"cargo metadata returned invalid JSON: {exc}") from exc
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        errors.append(detail)

    target = str(manifest_path) if manifest_path is not None else "the current workspace"
    raise FormatterError(f"cargo metadata failed for {target}: {'; '.join(errors)}")


def collect_all_targets(
    manifest_path: Path | None = None,
    metadata_loader: MetadataLoader = load_metadata,
) -> list[Target]:
    """Match cargo-fmt's recursive collection of local path dependencies."""

    targets: dict[Path, Target] = {}
    visited_dependency_names: set[str] = set()
    # One `cargo metadata` resolve returns every package of its workspace, so
    # crates sharing a workspace (the 8+ vendor/calyx path deps) must reuse the
    # first resolve instead of re-running cargo per manifest (#192).
    loaded_workspaces: list[tuple[set[Path], dict]] = []

    def load_with_workspace_reuse(current_manifest: Path | None) -> dict:
        if current_manifest is not None:
            manifest = canonical_path(current_manifest)
            for known_manifests, metadata in loaded_workspaces:
                if manifest in known_manifests:
                    return metadata
        return metadata_loader(current_manifest)

    def visit(current_manifest: Path | None) -> None:
        metadata = load_with_workspace_reuse(current_manifest)
        packages = workspace_packages(metadata)
        package_manifests = {
            canonical_path(Path(package["manifest_path"]))
            for package in packages
            if package.get("manifest_path")
        }
        loaded_workspaces.append((package_manifests, metadata))

        for package in packages:
            for target in package.get("targets", []):
                source = canonical_path(Path(target["src_path"]))
                edition = str(target.get("edition") or package.get("edition") or "2015")
                kinds = target.get("kind") or ["unknown"]
                targets.setdefault(source, (source, edition, str(kinds[0])))

        for package in packages:
            for dependency in package.get("dependencies", []):
                dependency_path = dependency.get("path")
                dependency_name = dependency.get("name")
                if not dependency_path or not dependency_name:
                    continue
                if dependency_name in visited_dependency_names:
                    continue

                dependency_manifest = Path(dependency_path) / "Cargo.toml"
                if (
                    dependency_manifest.exists()
                    and canonical_path(dependency_manifest) not in package_manifests
                ):
                    visited_dependency_names.add(dependency_name)
                    visit(dependency_manifest)

    visit(manifest_path)
    if not targets:
        raise FormatterError("failed to find formatter targets")
    return sorted(targets.values(), key=lambda target: str(target[0]))


def command_length(command: list[str]) -> int:
    return sum(len(argument) + 1 for argument in command)


def batch_targets(
    targets: list[Target],
    edition: str,
    rustfmt_args: list[str],
    rustfmt: str,
    limit: int = WINDOWS_SAFE_COMMAND_LIMIT,
) -> list[list[Target]]:
    """Partition target paths without exceeding a conservative Windows limit."""

    fixed_arguments = [rustfmt, "--edition", edition, *rustfmt_args]
    fixed_length = command_length(fixed_arguments)
    batches: list[list[Target]] = []
    current: list[Target] = []
    current_length = fixed_length

    for target in targets:
        next_length = current_length + len(str(target[0])) + 1
        if current and next_length > limit:
            batches.append(current)
            current = []
            current_length = fixed_length
        current.append(target)
        current_length += len(str(target[0])) + 1

    if current:
        batches.append(current)
    return batches


def split_arguments(arguments: list[str]) -> tuple[list[str], list[str]]:
    try:
        separator = arguments.index("--")
    except ValueError:
        return arguments, []
    return arguments[:separator], arguments[separator + 1 :]


def asks_for_rustfmt_information(rustfmt_args: list[str]) -> bool:
    return any(
        argument in INFO_RUSTFMT_ARGS
        or argument.startswith("--help=")
        or argument.startswith("--print-config=")
        for argument in rustfmt_args
    )


def parse_all_options(cargo_args: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="cargo fmt", add_help=False)
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-p", "--package", dest="packages", action="append", nargs="+")
    parser.add_argument("--manifest-path")
    parser.add_argument("--message-format")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(cargo_args)


def apply_message_format(rustfmt_args: list[str], message_format: str | None) -> None:
    if message_format is None or message_format == "human":
        return
    contains_emit = any(argument.startswith("--emit") for argument in rustfmt_args)
    contains_check = "--check" in rustfmt_args
    contains_list_files = "-l" in rustfmt_args or "--files-with-diff" in rustfmt_args
    if message_format == "short":
        if not contains_list_files:
            rustfmt_args.append("-l")
        return
    if message_format == "json":
        if contains_emit:
            raise FormatterError(
                "cannot include --emit arg when --message-format is set to json"
            )
        if contains_check:
            raise FormatterError(
                "cannot include --check arg when --message-format is set to json"
            )
        rustfmt_args.extend(["--emit", "json"])
        return
    raise FormatterError(
        "invalid --message-format value: "
        f"{message_format}. Allowed values are: short|json|human"
    )


def run_batched_rustfmt(
    targets: list[Target],
    rustfmt_args: list[str],
    *,
    quiet: bool,
    verbose: bool,
) -> int:
    rustfmt = os.environ.get("RUSTFMT", "rustfmt")
    targets_by_edition: dict[str, list[Target]] = {}
    for target in targets:
        targets_by_edition.setdefault(target[1], []).append(target)

    first_failure = 0
    for edition in sorted(targets_by_edition):
        edition_targets = targets_by_edition[edition]
        if verbose:
            for path, _, kind in edition_targets:
                print(f"[{kind} ({edition})] {path}")
        for batch in batch_targets(edition_targets, edition, rustfmt_args, rustfmt):
            command = [
                rustfmt,
                *(str(target[0]) for target in batch),
                "--edition",
                edition,
                *rustfmt_args,
            ]
            if verbose:
                print(" ".join(command))
            try:
                result = subprocess.run(
                    command,
                    check=False,
                    stdout=subprocess.DEVNULL if quiet else None,
                )
            except OSError as exc:
                print(
                    f"Could not run rustfmt, please make sure it is in your PATH: {exc}",
                    file=sys.stderr,
                )
                return 1
            if result.returncode != 0 and first_failure == 0:
                first_failure = result.returncode if result.returncode > 0 else 1
    return first_failure


def external_cargo_fmt() -> str:
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    names = ("cargo-fmt.exe", "cargo-fmt") if os.name == "nt" else ("cargo-fmt",)
    for name in names:
        candidate = cargo_home / "bin" / name
        if candidate.is_file():
            return str(candidate)
    for name in names:
        candidate = shutil.which(name)
        if candidate is not None:
            return candidate
    raise FormatterError("could not find the upstream cargo-fmt command")


def delegate_to_upstream(arguments: list[str]) -> int:
    try:
        result = subprocess.run([external_cargo_fmt(), "fmt", *arguments], check=False)
    except OSError as exc:
        raise FormatterError(f"could not run upstream cargo-fmt: {exc}") from exc
    return result.returncode if result.returncode >= 0 else 1


def main(arguments: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    if arguments[:1] == ["fmt"]:
        arguments = arguments[1:]
    cargo_args, rustfmt_args = split_arguments(arguments)

    if "--all" not in cargo_args:
        return delegate_to_upstream(arguments)
    if "--help" in cargo_args or "--version" in cargo_args:
        return delegate_to_upstream(arguments)
    if asks_for_rustfmt_information(rustfmt_args):
        return delegate_to_upstream(arguments)

    options = parse_all_options(cargo_args)
    if not options.all:
        return delegate_to_upstream(arguments)
    if options.quiet and options.verbose:
        raise FormatterError("quiet mode and verbose mode are not compatible")
    if options.manifest_path is not None and not options.manifest_path.endswith("Cargo.toml"):
        raise FormatterError("the manifest-path must be a path to a Cargo.toml file")
    if options.check and "--check" not in rustfmt_args:
        rustfmt_args.append("--check")
    apply_message_format(rustfmt_args, options.message_format)
    manifest_path = Path(options.manifest_path) if options.manifest_path is not None else None
    return run_batched_rustfmt(
        collect_all_targets(manifest_path),
        rustfmt_args,
        quiet=options.quiet,
        verbose=options.verbose,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FormatterError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
