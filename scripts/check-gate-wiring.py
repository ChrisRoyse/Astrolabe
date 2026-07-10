#!/usr/bin/env python3
"""Verify that aggregate, release, and scheduled gates have durable callers."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


DEFAULT_ROOT = Path(__file__).resolve().parents[1]


def read(root: Path, relative: str, errors: list[str]) -> str:
    path = root / relative
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"cannot read {relative}: {exc}")
        return ""


def require(text: str, needle: str, location: str, errors: list[str]) -> None:
    if needle not in text:
        errors.append(f"{location} must contain {needle!r}")


def require_order(
    text: str, needles: tuple[str, ...], location: str, errors: list[str]
) -> None:
    cursor = 0
    for needle in needles:
        index = text.find(needle, cursor)
        if index < 0:
            errors.append(f"{location} must invoke {needle!r} in the required order")
            return
        cursor = index + len(needle)


def workflow_job(workflow: str, name: str, errors: list[str]) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\s*$\n(.*?)(?=^  [A-Za-z0-9_-]+:\s*$|\Z)",
        workflow,
    )
    if match is None:
        errors.append(f"ci.yml is missing job {name!r}")
        return ""
    return match.group(1)


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    workflow = read(root, ".github/workflows/ci.yml", errors)
    check = read(root, "scripts/check.sh", errors)
    full = read(root, "scripts/check-full.sh", errors)
    release = read(root, "scripts/check-release.sh", errors)
    cbm_test = read(root, "scripts/ci-cbm-test.sh", errors)
    workspace_test = read(root, "scripts/check-workspace-tests.py", errors)
    clean_target = read(root, "scripts/clean-target.sh", errors)

    require(
        check,
        "scripts/check-gate-wiring.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-gate-wiring.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-egress-platform.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-verify-pins.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-cbm-skip-count.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-check-libcbm-symbols.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-parity-corpus-contract.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/check-allocator-contract.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-check-workspace-tests.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/check-workspace-tests.py",
        "scripts/check.sh",
        errors,
    )
    require(check, "scripts/clean-target.sh", "scripts/check.sh", errors)
    require_order(
        check,
        (
            "scripts/check-lowered-parity.py",
            "scripts/check-shadow-parity.py",
            "scripts/check-cross-process-vault.py",
            "scripts/check-cross-process-servers.py",
            "scripts/check-astrolabe-watchdog.sh",
            "scripts/check-egress-deny.py",
        ),
        "scripts/check.sh portable-before-egress order",
        errors,
    )
    require(
        check,
        "scripts/check-egress-deny.py --allow-unsupported-platform",
        "scripts/check.sh",
        errors,
    )

    require_order(
        full,
        (
            "bash scripts/check.sh",
            "bash scripts/ci-cbm-lint.sh",
            "bash scripts/ci-cbm-test.sh",
            "bash scripts/ci-rust-gate.sh",
        ),
        "scripts/check-full.sh",
        errors,
    )
    require(full, "rustc -vV", "scripts/check-full.sh", errors)
    require(full, "ASTROLABE_RUST_TARGET", "scripts/check-full.sh", errors)
    require(full, 'HOST_TARGET" != "$RUSTC_HOST', "scripts/check-full.sh", errors)
    require(full, "x86_64-pc-windows-gnu", "scripts/check-full.sh", errors)
    require(
        full,
        "ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS",
        "scripts/check-full.sh",
        errors,
    )
    require(
        full,
        "DEFERRED[ASTRO_NATIVE_AGGREGATE]",
        "scripts/check-full.sh",
        errors,
    )
    require(full, "scripts/clean-target.sh", "scripts/check-full.sh", errors)
    for label in (
        "linux-x64-gcc",
        "linux-x64-clang",
        "macos-arm64-clang",
        "windows-x64-mingw",
    ):
        require(full, label, "scripts/check-full.sh", errors)
    require(
        full,
        'bash scripts/ci-cbm-test.sh "$LABEL" "$CC_BIN" "$CXX_BIN"',
        "scripts/check-full.sh",
        errors,
    )
    require(
        full,
        'bash scripts/ci-rust-gate.sh "$LABEL" "$HOST_TARGET"',
        "scripts/check-full.sh",
        errors,
    )
    require(
        cbm_test,
        'bash "$ROOT/scripts/check-cbm-skip-count.sh" "$LABEL" "$skipped"',
        "scripts/ci-cbm-test.sh",
        errors,
    )

    require_order(
        release,
        (
            "bash scripts/check-full.sh",
            "cargo build --workspace --release",
            "scripts/check-binary-size.py",
            "scripts/release-predicate.sh",
        ),
        "scripts/check-release.sh",
        errors,
    )
    require(release, "scripts/clean-target.sh", "scripts/check-release.sh", errors)
    require(release, "trap cleanup_target EXIT", "scripts/check-release.sh", errors)
    executable_lines = [
        line.strip()
        for line in release.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    expected_last = 'bash "$ROOT/scripts/release-predicate.sh" "$@"'
    if not executable_lines or executable_lines[-1] != expected_last:
        errors.append("scripts/check-release.sh must execute release-predicate.sh last")

    require(
        workspace_test,
        "subprocess.CREATE_NEW_PROCESS_GROUP",
        "scripts/check-workspace-tests.py",
        errors,
    )
    require(workspace_test, '"taskkill"', "scripts/check-workspace-tests.py", errors)
    require(
        workspace_test,
        "DEFERRED_EXIT = 125",
        "scripts/check-workspace-tests.py",
        errors,
    )
    require(clean_target, 'rm -rf -- "$TARGET_DIR"', "scripts/clean-target.sh", errors)
    require(
        clean_target,
        "CLEANUP[ASTRO_TARGET]",
        "scripts/clean-target.sh",
        errors,
    )

    if not re.search(r"(?ms)^  schedule:\s*$\n\s+- cron:", workflow):
        errors.append("ci.yml must define a scheduled trigger")

    pins = workflow_job(workflow, "pins", errors)
    require(
        pins,
        "python3 scripts/check-gate-wiring.py",
        "ci.yml pins job",
        errors,
    )

    portable = workflow_job(workflow, "portable-gates", errors)
    require(
        portable,
        "run: bash scripts/check.sh",
        "ci.yml portable-gates job",
        errors,
    )
    require(portable, "strace", "ci.yml portable-gates job", errors)

    benchmark = workflow_job(workflow, "row-sink-benchmark", errors)
    require(
        benchmark,
        "github.event_name == 'schedule'",
        "ci.yml row-sink-benchmark job",
        errors,
    )
    require(
        benchmark,
        'ASTROLABE_ROW_SINK_BENCH_WRITE_RELEASE_ARTIFACT: "1"',
        "ci.yml row-sink-benchmark job",
        errors,
    )
    require(
        benchmark,
        "run: bash scripts/bench-row-sink-overhead.sh",
        "ci.yml row-sink-benchmark job",
        errors,
    )
    require(
        benchmark,
        "target/astrolabe-row-sink-overhead-bench.json",
        "ci.yml row-sink-benchmark upload",
        errors,
    )
    require(
        benchmark,
        "target/astrolabe-release-predicate/bench-ratios.json",
        "ci.yml row-sink-benchmark upload",
        errors,
    )
    require(
        benchmark,
        "uses: actions/upload-artifact@v4",
        "ci.yml row-sink-benchmark upload",
        errors,
    )

    ci_ok = workflow_job(workflow, "ci-ok", errors)
    if not re.search(r"needs:\s*\[[^\]]*portable-gates[^\]]*\]", ci_ok):
        errors.append("ci.yml ci-ok job must require portable-gates")
    if not re.search(r"needs:\s*\[[^\]]*row-sink-benchmark[^\]]*\]", ci_ok):
        errors.append("ci.yml ci-ok job must account for row-sink-benchmark")
    require(
        ci_ok,
        'optional_skips = {"row-sink-benchmark"}',
        "ci.yml ci-ok job",
        errors,
    )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()

    errors = validate(args.root.resolve())
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("gate wiring verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
