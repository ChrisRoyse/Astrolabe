#!/usr/bin/env python3
"""Verify that aggregate and release gates have durable local callers.

Hosted CI/CD is banned (owner directive 2026-07-11; see issue #224): there is
no workflow file to validate, and no gate may claim a CI job as its caller.
Every gate's durable caller is a local script reachable from check.sh,
check-full.sh, or check-release.sh.
"""

from __future__ import annotations

import argparse
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


def validate(root: Path) -> list[str]:
    errors: list[str] = []
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
    # #224: the degradation-label gate is what keeps CI-ownership claims from
    # coming back and keeps every platform-limited skip classified as a tracked
    # port-phase deferral. It is only durable if the aggregate always runs it.
    require(
        check,
        "scripts/check-degradation-labels.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-degradation-labels.py",
        "scripts/check.sh",
        errors,
    )
    # #237: the sandbox-escape gate is only load-bearing if the aggregate both
    # runs its self-test AND brackets the build/test phase with snapshot->verify.
    require(check, "scripts/test-check-no-escape.py", "scripts/check.sh", errors)
    require(check, "scripts/check-no-escape.py snapshot", "scripts/check.sh", errors)
    require(check, "scripts/check-no-escape.py verify", "scripts/check.sh", errors)
    require_order(
        check,
        (
            "scripts/check-no-escape.py snapshot",
            "build --workspace",
            "scripts/check-no-escape.py verify",
        ),
        "scripts/check.sh",
        errors,
    )
    # #246: every path that RUNS workspace/Calyx tests must self-contain
    # std::env::temp_dir() to the run-scoped suite-tmp sandbox, so no invocation
    # leaks calyx-* / astrolabe-* scratch into the operator's real %TEMP%. The #237
    # bracket lives INSIDE check.sh and does NOT cover ci-rust-gate.sh's Calyx
    # nextest/doctest (they run as a later check-full phase, after check.sh's verify),
    # so containment there cannot depend on the gate -- it must be a self-set property
    # of the script itself. Both runners set the SAME sandbox path, so inheritance from
    # check-full.sh remains an idempotent no-op.
    for gate_text, gate_name in (
        (check, "scripts/check.sh"),
        (rust_gate, "scripts/ci-rust-gate.sh"),
    ):
        require(gate_text, 'SUITE_TMP="$SUITE_CEIL/tmp"', gate_name, errors)
        require(
            gate_text,
            'export TMP="$SUITE_TMP" TEMP="$SUITE_TMP" TMPDIR="$SUITE_TMP"',
            gate_name,
            errors,
        )
        require(gate_text, "GIT_CEILING_DIRECTORIES", gate_name, errors)
    # ci-rust-gate must establish the sandbox BEFORE it runs any test.
    require_order(
        rust_gate,
        (
            'export TMP="$SUITE_TMP" TEMP="$SUITE_TMP" TMPDIR="$SUITE_TMP"',
            "nextest run",
        ),
        "scripts/ci-rust-gate.sh",
        errors,
    )
    # #88: hazard-suite must execute its tests (self-test wired) and predicate
    # artifacts must be written AFTER the workspace test, never before it.
    require(check, "scripts/test-check-hazard-suite.py", "scripts/check.sh", errors)
    require_order(
        check,
        ("test --workspace", "scripts/check-license-notices.py --write-release-artifact"),
        "scripts/check.sh",
        errors,
    )
    require_order(
        check,
        ("test --workspace", "scripts/check-hazard-suite.py --write-release-artifact"),
        "scripts/check.sh",
        errors,
    )
    # #227/#228: shell-free CBM git spawn + validator mirror self-tests.
    require(check, "scripts/test-cbm-spawn-patch.py", "scripts/check.sh", errors)
    require(check, "scripts/test-cbm-spawn-fsv.py", "scripts/check.sh", errors)
    # #240/#241: env-as-IPC lint gate + resolver-hardening overlay self-tests.
    require(check, "scripts/check-cbm-env-contract.py", "scripts/check.sh", errors)
    require(check, "scripts/test-cbm-env-contract.py", "scripts/check.sh", errors)
    require(check, "scripts/test-cbm-env-store-patch.py", "scripts/check.sh", errors)
    require(
        check,
        "scripts/test-egress-platform.py",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/test-cbm-cache-guards.py",
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
        "scripts/check-launcher-lock.sh",
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
    # #193: the C phases run concurrently. That is only safe to keep if a failure
    # in ANY phase still fails the aggregate with its phase named, and if every
    # started phase is waited on before cleanup. Both are load-bearing.
    require(full, "wait_phases", "scripts/check-full.sh", errors)
    require(full, "PHASE_FAIL[", "scripts/check-full.sh", errors)
    require(full, "ASTRO_GATE_PHASE_FAILED", "scripts/check-full.sh", errors)
    # #189: the native aggregate must not fork a second artifact tree. ci-rust-gate
    # refuses a cross-target request instead of silently building non-native
    # evidence into target/<triple>/debug.
    require(
        rust_gate,
        "ASTRO_RUST_GATE_CROSS_TARGET",
        "scripts/ci-rust-gate.sh",
        errors,
    )
    require(
        rust_gate,
        '--target-dir "$ROOT/target"',
        "scripts/ci-rust-gate.sh shared calyx target tree",
        errors,
    )
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
    # #194/#232: the CBM phase must run against a run-scoped store and prove the
    # operator's store came out byte-identical. Both halves are load-bearing.
    require(
        cbm_test,
        'export HOME="$CBM_TEST_HOME"',
        "scripts/ci-cbm-test.sh run-scoped CBM store",
        errors,
    )
    require(
        cbm_test,
        'export USERPROFILE="$CBM_TEST_HOME"',
        "scripts/ci-cbm-test.sh run-scoped CBM store",
        errors,
    )
    require(
        cbm_test,
        "INFO[ASTRO_CBM_RUN_SCOPED_STORE]",
        "scripts/ci-cbm-test.sh run-scoped CBM store",
        errors,
    )
    require_order(
        cbm_test,
        (
            'check-cbm-cache-hermeticity.py" snapshot',
            "scripts/test.sh",
            'check-cbm-cache-hermeticity.py" verify',
            'check-cbm-cache-hermeticity.py" require-writes',
        ),
        "scripts/ci-cbm-test.sh store hermeticity order",
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
    require(
        cbm_lint,
        "scripts/check-cbm-cache-paths.py",
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

    # No hosted CI exists to validate (banned; #224). The row-sink overhead
    # benchmark lost its scheduled CI caller with the workflow's removal;
    # scripts/bench-row-sink-overhead.sh remains locally runnable and its
    # coverage gap is tracked on #224.

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
