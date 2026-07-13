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
    # #278: the causal-attribution control proof must run every aggregate -- it is the
    # standing guard that shared-root policing is by process tree, not name pattern.
    require(check, "scripts/test-no-escape-attribution.py", "scripts/check.sh", errors)
    # #281: the hook-budget measurement is min-of-N with per-trial correctness;
    # its self-test must stay wired so a single-sample regression cannot return.
    require(check, "scripts/test-check-hook-contracts.py", "scripts/check.sh", errors)
    require(check, "scripts/check-no-escape.py snapshot", "scripts/check.sh", errors)
    require(check, "scripts/check-no-escape.py verify", "scripts/check.sh", errors)
    # #280: the standalone `cargo build --workspace` was dropped (cargo test
    # --workspace builds a superset); the no-escape bracket now spans the test
    # phase. The snapshot must still precede the test phase and the verify follow
    # it, and a fail-closed binary-existence assertion must guard the dropped
    # build so a missing bin is a hard error, never a silent skip.
    require_order(
        check,
        (
            "scripts/check-no-escape.py snapshot",
            "scripts/check-workspace-tests.py",
            "scripts/check-no-escape.py verify",
        ),
        "scripts/check.sh",
        errors,
    )
    require(check, "ASTRO_DEBUG_BINARY_MISSING", "scripts/check.sh", errors)
    # #280: the gate-tooling self-tests are change-gated through this driver, and
    # the fail-closed mechanism itself is proven by an unconditional meta-test.
    require(check, "scripts/run-gate-selftests.py", "scripts/check.sh", errors)
    require(check, "scripts/test-run-gate-selftests.py", "scripts/check.sh", errors)
    # #280 + #264: the workspace-test phase runs the nextest `fast` profile.
    # The >60s tests were DELETED (owner directive 2026-07-12: no individual
    # test may exceed 60s), so fast == full workspace coverage; the doctests
    # remain the one tiered omission, which check-release runs via
    # ci-rust-gate.sh.
    require(check, "--nextest-profile fast", "scripts/check.sh", errors)
    require(check, "INFO[ASTRO_FAST_TIER_FULL_COVERAGE]", "scripts/check.sh", errors)
    require(check, "SKIP[ASTRO_FAST_TIER_DOCTESTS]", "scripts/check.sh", errors)
    # #280: the suite impact gate — no suite runs when no code change impacts
    # it, and a green run must record its fingerprint. Both halves are
    # load-bearing: should-run without record-green never skips; record-green
    # without should-run skips nothing. The gate's own self-test must be wired.
    require(
        check,
        "scripts/check-suite-impact.py should-run workspace-block",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "scripts/check-suite-impact.py record-green workspace-block",
        "scripts/check.sh",
        errors,
    )
    require(check, "scripts/test-check-suite-impact.py", "scripts/check.sh", errors)
    # #280: the dropped `cargo build --workspace` is replaced by a targeted bin
    # build (nextest may not build [[bin]] targets) plus the fail-closed assertion.
    require(check, "build -p astrolabe-server --bins", "scripts/check.sh", errors)
    # #264: ci-rust-gate.sh (the tier check-full runs) runs the full workspace
    # nextest (every test, incl. the heavy pair) and the doctests.
    require(rust_gate, "cargo nextest run --workspace", "scripts/ci-rust-gate.sh", errors)
    require(rust_gate, "cargo test --workspace --doc", "scripts/ci-rust-gate.sh", errors)
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
    # #227/#228: shell-free CBM git spawn behavior FSV self-test.
    require(check, "scripts/test-cbm-spawn-fsv.py", "scripts/check.sh", errors)
    # #286: the absorbed-overlay source-guard test (worker-diag/env-store/spawn/
    # shellarg/mem/ui-werror behaviors + the per-artifact ASTRO_* flag matrix).
    require(check, "scripts/test-cbm-overlay-sources.py", "scripts/check.sh", errors)
    # #240/#241: env-as-IPC lint gate + its self-test (real ban-list behavior).
    require(check, "scripts/check-cbm-env-contract.py", "scripts/check.sh", errors)
    require(check, "scripts/test-cbm-env-contract.py", "scripts/check.sh", errors)
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
    # #280: check.sh formats only workspace-local crates; the owned vendor/ tree
    # is full-graph-formatted by the Rust gate below.
    require(
        check,
        "scripts/native-cargo-fmt.py --all --workspace-only -- --check",
        "scripts/check.sh",
        errors,
    )
    require(
        check,
        "INFO[ASTRO_FMT_VENDOR_EXCLUDED]",
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
    # #280: the self-isolated binary gates run concurrently in one gate_group
    # (each must stay wired), while the ordering contract that remains is:
    # lowered-parity collected before shadow-parity, egress after both, and
    # the no-escape verify bracket last (checked separately above).
    for member in (
        "scripts/check-astrolabe-verify-chain.sh",
        "scripts/check-single-mimalloc.sh",
        "scripts/check-mcp-parity.sh",
        "scripts/check-cli-parity.py",
        "scripts/check-compat-shim.py",
        "scripts/check-installer-roundtrip.py",
        "scripts/check-hook-contracts.py",
        "scripts/check-server-manifest.py",
        "scripts/check-cross-process-vault.py",
        "scripts/check-cross-process-servers.py",
        "scripts/check-astrolabe-watchdog.sh",
    ):
        require(check, member, "scripts/check.sh", errors)
    require_order(
        check,
        (
            "scripts/check-lowered-parity.py",
            "gate lowered-parity -- lowered_parity_wait",
            "scripts/check-shadow-parity.py --write-release-artifact",
            "scripts/check-egress-deny.py --allow-unsupported-platform",
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

    # #280: check-full is the sub-3-minute FULL TEST SUITE — the portable
    # check.sh aggregate and the CBM C runtime suite, concurrent. The
    # lint/doc/Calyx phases are tiered to check-release with counted labels.
    require_order(
        full,
        (
            "bash scripts/check.sh",
            "bash scripts/ci-cbm-test.sh",
        ),
        "scripts/check-full.sh",
        errors,
    )
    require(full, "SKIP[ASTRO_RELEASE_TIER_RUST_GATE]", "scripts/check-full.sh", errors)
    require(full, "SKIP[ASTRO_RELEASE_TIER_CBM_LINT]", "scripts/check-full.sh", errors)
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
    # #280: check-release is the tier that defeats BOTH fail-closed fast-path
    # gates — the suite impact gate and the self-test change-gate — so nothing
    # is permanently skippable: every suite and every self-test has a durable
    # forced caller.
    require(release, "export ASTRO_GATE_SELFTESTS=all", "scripts/check-release.sh", errors)
    require(release, "export ASTRO_SUITE_GATE=all", "scripts/check-release.sh", errors)
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
        release,
        'bash scripts/ci-rust-gate.sh "$LABEL" "$HOST_TARGET"',
        "scripts/check-release.sh",
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
    # #280: the CBM suite is impact-gated (fail-closed) and records its green
    # fingerprint only after every count/hermeticity check passed; the runtime
    # itself is the sharded runner with the incremental (premise-stamped) build.
    require(
        cbm_test,
        "scripts/check-suite-impact.py\" should-run cbm-c-suite",
        "scripts/ci-cbm-test.sh",
        errors,
    )
    require(
        cbm_test,
        "scripts/check-suite-impact.py\" record-green cbm-c-suite",
        "scripts/ci-cbm-test.sh",
        errors,
    )
    cbm_test_sh = read(root, "vendor/codebase-memory-mcp/scripts/test.sh", errors)
    require(
        cbm_test_sh,
        "scripts/test-shards.sh",
        "vendor/codebase-memory-mcp/scripts/test.sh",
        errors,
    )
    require(
        cbm_test_sh,
        "INFO[CBM_INCREMENTAL_BUILD]",
        "vendor/codebase-memory-mcp/scripts/test.sh",
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
        "INFO[ASTRO_CBM_FORMAT]",
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
            "bash scripts/ci-cbm-lint.sh",
            "bash scripts/ci-rust-gate.sh",
            "cargo build --workspace --release",
            "scripts/check-binary-size.py",
            # #291: failpoint-string scan runs on the freshly built release
            # binaries, after the size gate and before the release predicate.
            "scripts/check-release-failpoint-strings.py",
            "scripts/release-predicate.sh",
        ),
        "scripts/check-release.sh",
        errors,
    )
    # #291: the failpoint-string gate's self-test must stay wired into the
    # change-gated Tier-1 self-test block so the gate itself is proven fail-closed.
    require(
        check,
        "scripts/test-check-release-failpoint-strings.py",
        "scripts/check.sh",
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

    # No hosted CI exists to validate (banned; the CI-ownership retirement landed
    # with #224, now closed). The row-sink overhead benchmark lost its scheduled
    # caller with that removal; scripts/bench-row-sink-overhead.sh remains locally
    # runnable, but its lack of a scheduled cadence caller post-CI-ban is an
    # evidence-owner gap recorded on #238 (the live register), not on a closed issue.

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
