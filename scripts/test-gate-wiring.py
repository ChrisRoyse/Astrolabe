#!/usr/bin/env python3
"""Self-tests for scripts/check-gate-wiring.py."""

from __future__ import annotations

import atexit
import importlib.util
import shutil
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-gate-wiring.py"
FILES = (
    "scripts/check.sh",
    "scripts/check-full.sh",
    "scripts/check-release.sh",
    "scripts/ci-cbm-lint.sh",
    "scripts/ci-cbm-test.sh",
    "scripts/ci-rust-gate.sh",
    "scripts/check-workspace-tests.py",
    "scripts/clean-target.sh",
    "vendor/codebase-memory-mcp/scripts/test.sh",
)


def load_checker():
    spec = importlib.util.spec_from_file_location("check_gate_wiring", CHECKER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CHECKER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_fixture(destination: Path) -> None:
    for relative in FILES:
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def rewrite(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise AssertionError(f"expected one fixture occurrence of {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")


def require_error(errors: list[str], fragment: str) -> None:
    if not any(fragment in error for error in errors):
        raise AssertionError(f"missing {fragment!r} in errors: {errors}")


def main() -> int:
    checker = load_checker()
    scratch_parent = ROOT / ".tmp"
    scratch_parent_existed = scratch_parent.exists()
    scratch = scratch_parent / "gate-wiring"
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True, exist_ok=True)

    def cleanup_scratch() -> None:
        shutil.rmtree(scratch, ignore_errors=True)
        if not scratch_parent_existed:
            try:
                scratch_parent.rmdir()
            except OSError:
                pass

    atexit.register(cleanup_scratch)
    with tempfile.TemporaryDirectory(prefix="gate-wiring-", dir=scratch) as temp:
        fixture = Path(temp)
        copy_fixture(fixture)
        assert checker.validate(fixture) == []

        check = fixture / "scripts/check.sh"
        rewrite(
            check,
            'gate watchdog -- bash scripts/check-astrolabe-watchdog.sh "$ROOT/target/debug/astrolabe"\n'
            'gate egress-deny -- "$PYTHON_BIN" scripts/check-egress-deny.py --allow-unsupported-platform --astrolabe "$ROOT/target/debug/astrolabe"',
            'gate egress-deny -- "$PYTHON_BIN" scripts/check-egress-deny.py --allow-unsupported-platform --astrolabe "$ROOT/target/debug/astrolabe"\n'
            'gate watchdog -- bash scripts/check-astrolabe-watchdog.sh "$ROOT/target/debug/astrolabe"',
        )
        require_error(checker.validate(fixture), "portable-before-egress order")
        copy_fixture(fixture)

        rewrite(
            check,
            "scripts/check-egress-deny.py --allow-unsupported-platform",
            "scripts/check-egress-deny.py",
        )
        require_error(checker.validate(fixture), "allow-unsupported-platform")
        copy_fixture(fixture)

        # #280: the gate-tooling self-tests are now listed in a bash array and
        # dispatched through scripts/run-gate-selftests.py, and several always-run
        # static gates are grouped through gate_group. The wiring contract still
        # requires each script's path to appear in check.sh, so renaming the path
        # (breaking the wiring) must still be caught. Substring swaps are robust
        # to the exact invocation form.
        rewrite(check, "scripts/test-check-libcbm-symbols.py", "scripts/removed-1.py")
        require_error(checker.validate(fixture), "test-check-libcbm-symbols.py")
        copy_fixture(fixture)

        rewrite(check, "scripts/test-cbm-lint-platform.py", "scripts/removed-2.py")
        require_error(checker.validate(fixture), "test-cbm-lint-platform.py")
        copy_fixture(fixture)

        rewrite(check, "scripts/test-cbm-overlay-sources.py", "scripts/removed-3.py")
        require_error(checker.validate(fixture), "test-cbm-overlay-sources.py")
        copy_fixture(fixture)

        rewrite(check, "scripts/test-parity-corpus-contract.py", "scripts/removed-4.py")
        require_error(checker.validate(fixture), "test-parity-corpus-contract.py")
        copy_fixture(fixture)

        rewrite(check, "scripts/test-native-cargo-fmt.py", "scripts/removed-5.py")
        require_error(checker.validate(fixture), "test-native-cargo-fmt.py")
        copy_fixture(fixture)

        rewrite(check, "scripts/test-verify-chain-native-path.py", "scripts/removed-6.py")
        require_error(
            checker.validate(fixture), "test-verify-chain-native-path.py"
        )
        copy_fixture(fixture)

        rewrite(check, "scripts/test-native-binary-resolution.py", "scripts/removed-7.py")
        require_error(
            checker.validate(fixture), "test-native-binary-resolution.py"
        )
        copy_fixture(fixture)

        rewrite(check, "scripts/test-installer-roundtrip-fixture.py", "scripts/removed-8.py")
        require_error(
            checker.validate(fixture), "test-installer-roundtrip-fixture.py"
        )
        copy_fixture(fixture)

        rewrite(
            check,
            "scripts/check-windows-gnu-toolchain-contract.py",
            "scripts/removed-9.py",
        )
        require_error(
            checker.validate(fixture), "check-windows-gnu-toolchain-contract.py"
        )
        copy_fixture(fixture)

        rewrite(
            check,
            "scripts/test-windows-gnu-toolchain-contract.py",
            "scripts/removed-10.py",
        )
        require_error(
            checker.validate(fixture), "test-windows-gnu-toolchain-contract.py"
        )
        copy_fixture(fixture)

        rewrite(
            check,
            "scripts/check-native-aggregate-wrapper.py",
            "scripts/removed-11.py",
        )
        require_error(
            checker.validate(fixture), "check-native-aggregate-wrapper.py"
        )
        copy_fixture(fixture)

        rewrite(
            check,
            "scripts/test-native-aggregate-wrapper.py",
            "scripts/removed-12.py",
        )
        require_error(
            checker.validate(fixture), "test-native-aggregate-wrapper.py"
        )
        copy_fixture(fixture)

        rewrite(
            check,
            "--all --workspace-only -- --check",
            "--all -- --check",
        )
        require_error(
            checker.validate(fixture),
            "native-cargo-fmt.py --all --workspace-only -- --check",
        )
        copy_fixture(fixture)

        rust_gate = fixture / "scripts/ci-rust-gate.sh"
        rewrite(
            rust_gate,
            'python3 "$ROOT/scripts/native-cargo-fmt.py" --all -- --check',
            "cargo fmt --check --all",
        )
        require_error(checker.validate(fixture), "scripts/ci-rust-gate.sh")
        copy_fixture(fixture)

        full = fixture / "scripts/check-full.sh"
        # #280: unwiring the concurrent CBM phase from check-full must be caught.
        rewrite(
            full,
            'start_phase "cbm-test" bash scripts/ci-cbm-test.sh "$LABEL" "$CC_BIN" "$CXX_BIN"',
            'start_phase "cbm-test" true',
        )
        require_error(checker.validate(fixture), "ci-cbm-test.sh")
        copy_fixture(fixture)

        # #280: the tiered-out phases must stay COUNTED omissions in check-full.
        rewrite(
            full,
            "SKIP[ASTRO_RELEASE_TIER_RUST_GATE]",
            "INFO[ASTRO_RELEASE_TIER_RUST_GATE]",
        )
        require_error(checker.validate(fixture), "ASTRO_RELEASE_TIER_RUST_GATE")
        copy_fixture(fixture)

        # #280: the suite impact gate is load-bearing in both directions.
        rewrite(
            check,
            "scripts/check-suite-impact.py should-run workspace-block",
            "scripts/check-suite-impact.py always-run workspace-block",
        )
        require_error(
            checker.validate(fixture),
            "check-suite-impact.py should-run workspace-block",
        )
        copy_fixture(fixture)

        rewrite(
            check,
            "scripts/check-suite-impact.py record-green workspace-block",
            "scripts/check-suite-impact.py forget-green workspace-block",
        )
        require_error(
            checker.validate(fixture),
            "check-suite-impact.py record-green workspace-block",
        )
        copy_fixture(fixture)

        # #280: check-release must defeat both fail-closed fast-path gates.
        release_pre = fixture / "scripts/check-release.sh"
        rewrite(release_pre, "export ASTRO_SUITE_GATE=all", "export ASTRO_SUITE_GATE=auto2")
        require_error(checker.validate(fixture), "ASTRO_SUITE_GATE=all")
        copy_fixture(fixture)

        # #280: the sharded CBM runner and the premise-stamped incremental build
        # must stay wired inside the owned test.sh.
        cbm_test_sh = fixture / "vendor/codebase-memory-mcp/scripts/test.sh"
        rewrite(cbm_test_sh, "scripts/test-shards.sh", "scripts/test-serial.sh")
        require_error(checker.validate(fixture), "test-shards.sh")
        copy_fixture(fixture)

        # #193: a failure in ANY concurrent phase must fail the aggregate with the
        # phase named. Deleting the failure-attribution machinery must be caught.
        rewrite(full, "ASTRO_GATE_PHASE_FAILED", "ASTRO_GATE_PHASE_IGNORED")
        require_error(checker.validate(fixture), "ASTRO_GATE_PHASE_FAILED")
        copy_fixture(fixture)

        full_text = full.read_text(encoding="utf-8")
        full.write_text(
            full_text.replace("wait_phases", "join_phases"), encoding="utf-8"
        )
        require_error(checker.validate(fixture), "wait_phases")
        copy_fixture(fixture)

        # #189: the native gate must refuse a cross-target request rather than
        # silently forking a second artifact tree.
        rewrite(
            rust_gate,
            "ASTRO_RUST_GATE_CROSS_TARGET",
            "ASTRO_RUST_GATE_ANYTARGET_OK",
        )
        require_error(checker.validate(fixture), "ASTRO_RUST_GATE_CROSS_TARGET")
        copy_fixture(fixture)

        cbm_lint = fixture / "scripts/ci-cbm-lint.sh"
        rewrite(
            cbm_lint,
            "SKIP[ASTRO_CBM_CLANG_TIDY_LINUX_REQUIRED]",
            "SKIP[ASTRO_CBM_CLANG_TIDY_REMOVED]",
        )
        require_error(checker.validate(fixture), "ASTRO_CBM_CLANG_TIDY_LINUX_REQUIRED")
        copy_fixture(fixture)

        rewrite(
            cbm_lint,
            "--platform=unix64",
            "--platform=removed",
        )
        require_error(checker.validate(fixture), "--platform=unix64")
        copy_fixture(fixture)

        rewrite(
            cbm_lint,
            "INFO[ASTRO_CBM_FORMAT]",
            "INFO[ASTRO_CBM_FORMAT_REMOVED]",
        )
        require_error(checker.validate(fixture), "ASTRO_CBM_FORMAT")
        copy_fixture(fixture)

        cbm_test = fixture / "scripts/ci-cbm-test.sh"
        rewrite(
            cbm_test,
            "SKIP[ASTRO_CBM_SANITIZERS_LINUX_REQUIRED]",
            "SKIP[ASTRO_CBM_SANITIZERS_REMOVED]",
        )
        require_error(checker.validate(fixture), "ASTRO_CBM_SANITIZERS_LINUX_REQUIRED")
        copy_fixture(fixture)

        rewrite(
            cbm_test,
            "ERROR: sanitizers are required on Linux CBM gates",
            "WARN: sanitizers are optional on Linux CBM gates",
        )
        require_error(
            checker.validate(fixture), "sanitizers are required on Linux CBM gates"
        )
        copy_fixture(fixture)

        rewrite(
            cbm_test,
            "SKIP[ASTRO_CBM_INCREMENTAL_LINUX_REQUIRED]",
            "SKIP[ASTRO_CBM_INCREMENTAL_REMOVED]",
        )
        require_error(
            checker.validate(fixture), "ASTRO_CBM_INCREMENTAL_LINUX_REQUIRED"
        )
        copy_fixture(fixture)

        rewrite(cbm_test, 'CC_BIN="${2//\\\\//}"', 'CC_BIN="$2"')
        require_error(checker.validate(fixture), "compiler-path normalization")
        copy_fixture(fixture)

        rewrite(cbm_test, 'CXX_BIN="${3//\\\\//}"', 'CXX_BIN="$3"')
        require_error(checker.validate(fixture), "compiler-path normalization")
        copy_fixture(fixture)

        workspace_test = fixture / "scripts/check-workspace-tests.py"
        rewrite(workspace_test, '"taskkill"', '"taskkill-disabled"')
        require_error(checker.validate(fixture), "taskkill")
        copy_fixture(fixture)

        clean_target = fixture / "scripts/clean-target.sh"
        rewrite(clean_target, 'rm -rf -- "$TARGET_DIR"', 'rm -rf -- "$ROOT"')
        require_error(checker.validate(fixture), "clean-target.sh")
        copy_fixture(fixture)

        release = fixture / "scripts/check-release.sh"
        rewrite(
            release,
            '"$PYTHON_BIN" scripts/check-binary-size.py\n',
            "",
        )
        require_error(checker.validate(fixture), "check-binary-size.py")
        copy_fixture(fixture)

        rewrite(
            release,
            'bash "$ROOT/scripts/release-predicate.sh" "$@"',
            'bash "$ROOT/scripts/release-predicate.sh" "$@"\necho "predicate was not final"',
        )
        require_error(checker.validate(fixture), "release-predicate.sh last")

    cleanup_scratch()
    assert not scratch.exists()
    print("gate wiring self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
