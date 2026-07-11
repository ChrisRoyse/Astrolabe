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
    cbm_lint = read(root, "scripts/ci-cbm-lint.sh", errors)
    cbm_test = read(root, "scripts/ci-cbm-test.sh", errors)
    rust_gate = read(root, "scripts/ci-rust-gate.sh", errors)
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
        "scripts/test-cbm-lint-platform.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-cbm-format-overlay.py",
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
        "scripts/test-native-cargo-fmt.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/check-no-mocks.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-check-no-mocks.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/native-cargo-fmt.py --all -- --check",
        "scripts/check.sh",
        errors,
    )
    require(
        rust_gate,
        'python3 "$ROOT/scripts/native-cargo-fmt.py" --all -- --check',
        "scripts/ci-rust-gate.sh",
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
        "scripts/check-windows-gnu-toolchain-contract.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-windows-gnu-toolchain-contract.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/check-native-aggregate-wrapper.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-native-aggregate-wrapper.py",
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
        "scripts/test-verify-chain-native-path.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-native-binary-resolution.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-installer-roundtrip-fixture.py",
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
    require(
        cbm_test,
        "SKIP[ASTRO_CBM_SANITIZERS_LINUX_REQUIRED]",
        "scripts/ci-cbm-test.sh",
        errors,
    )
    require(
        cbm_test,
        "-fsanitize=address,undefined",
        "scripts/ci-cbm-test.sh",
        errors,
    )
    require(
        cbm_test,
        "ci/cbm-test-totals.md",
        "scripts/ci-cbm-test.sh",
        errors,
    )
    require(
        cbm_test,
        "ERROR: sanitizers are required on Linux CBM gates",
        "scripts/ci-cbm-test.sh",
        errors,
    )
    require(
        cbm_test,
        "SKIP[ASTRO_CBM_INCREMENTAL_LINUX_REQUIRED]",
        "scripts/ci-cbm-test.sh",
        errors,
    )
    require(
        cbm_test,
        "GIT_CEILING_DIRECTORIES",
        "scripts/ci-cbm-test.sh",
        errors,
    )
    require(
        cbm_test,
        'CC_BIN="${2//\\\\//}"',
        "scripts/ci-cbm-test.sh compiler-path normalization",
        errors,
    )
    require(
        cbm_test,
        'CXX_BIN="${3//\\\\//}"',
        "scripts/ci-cbm-test.sh compiler-path normalization",
        errors,
    )
    require(cbm_lint, 'HOST_OS="$(uname -s)"', "scripts/ci-cbm-lint.sh", errors)
    require(
        cbm_lint,
        "SKIP[ASTRO_CBM_CLANG_TIDY_LINUX_REQUIRED]",
        "scripts/ci-cbm-lint.sh",
        errors,
    )
    require(
        cbm_lint,
        "INFO[ASTRO_CBM_CPPCHECK_LINUX_ABI]",
        "scripts/ci-cbm-lint.sh",
        errors,
    )
    require(
        cbm_lint,
        "--platform=unix64",
        "scripts/ci-cbm-lint.sh",
        errors,
    )
    require(
        cbm_lint,
        'if [[ "$HOST_OS" == "Linux" ]]; then',
        "scripts/ci-cbm-lint.sh",
        errors,
    )
    require(
        cbm_lint,
        "make -f Makefile.cbm lint-tidy",
        "scripts/ci-cbm-lint.sh",
        errors,
    )
    require(
        cbm_lint,
        "INFO[ASTRO_CBM_FORMAT_OVERLAY]",
        "scripts/ci-cbm-lint.sh",
        errors,
    )
    require(
        cbm_lint,
        'make -f "$ROOT/patches/cbm/Makefile.cbm" lint-format-astrolabe',
        "scripts/ci-cbm-lint.sh",
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

    lint = workflow_job(workflow, "cbm-lint", errors)
    require(lint, "runs-on: ubuntu-latest", "ci.yml cbm-lint job", errors)
    require(
        lint,
        "run: bash scripts/ci-cbm-lint.sh",
        "ci.yml cbm-lint job",
        errors,
    )

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
    # CI actions are pinned to full commit SHAs (see commit "Pin CI actions to
    # commit SHAs + add Dependabot to keep them fresh") with a trailing "# vN"
    # annotation that Dependabot maintains. Require the upload-artifact pin to be
    # a SHA annotated as major version 4 so the gate keeps guarding the v4 major
    # (a v5 bump would carry "# v5" and fail closed here) without regressing the
    # SHA-pinning hardening back to a mutable tag.
    if not re.search(
        r"uses:\s*actions/upload-artifact@[0-9a-fA-F]{40}\s*#\s*v4(?!\d)",
        benchmark,
    ):
        errors.append(
            "ci.yml row-sink-benchmark upload must pin "
            "actions/upload-artifact to a commit SHA annotated '# v4'"
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
