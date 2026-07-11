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
    ".github/workflows/ci.yml",
    "scripts/check.sh",
    "scripts/check-full.sh",
    "scripts/check-release.sh",
    "scripts/ci-cbm-lint.sh",
    "scripts/ci-cbm-test.sh",
    "scripts/ci-rust-gate.sh",
    "scripts/check-workspace-tests.py",
    "scripts/clean-target.sh",
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

        workflow = fixture / ".github/workflows/ci.yml"
        rewrite(
            workflow,
            "run: bash scripts/check.sh",
            "run: bash scripts/check-missing.sh",
        )
        require_error(checker.validate(fixture), "portable-gates job")
        copy_fixture(fixture)

        check = fixture / "scripts/check.sh"
        rewrite(
            check,
            'bash scripts/check-astrolabe-watchdog.sh "$ROOT/target/debug/astrolabe"\n"$PYTHON_BIN" scripts/check-egress-deny.py --allow-unsupported-platform',
            '"$PYTHON_BIN" scripts/check-egress-deny.py --allow-unsupported-platform\nbash scripts/check-astrolabe-watchdog.sh "$ROOT/target/debug/astrolabe"',
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

        rewrite(
            check,
            '"$PYTHON_BIN" scripts/test-check-libcbm-symbols.py\n',
            "",
        )
        require_error(checker.validate(fixture), "test-check-libcbm-symbols.py")
        copy_fixture(fixture)

        rewrite(
            check,
            '"$PYTHON_BIN" scripts/test-cbm-lint-platform.py\n',
            "",
        )
        require_error(checker.validate(fixture), "test-cbm-lint-platform.py")
        copy_fixture(fixture)

        rewrite(
            check,
            '"$PYTHON_BIN" scripts/test-cbm-format-overlay.py\n',
            "",
        )
        require_error(checker.validate(fixture), "test-cbm-format-overlay.py")
        copy_fixture(fixture)

        rewrite(
            check,
            '"$PYTHON_BIN" scripts/test-parity-corpus-contract.py\n',
            "",
        )
        require_error(checker.validate(fixture), "test-parity-corpus-contract.py")
        copy_fixture(fixture)

        rewrite(
            check,
            '"$PYTHON_BIN" scripts/test-native-cargo-fmt.py\n',
            "",
        )
        require_error(checker.validate(fixture), "test-native-cargo-fmt.py")
        copy_fixture(fixture)

        rewrite(
            check,
            '"$PYTHON_BIN" scripts/test-verify-chain-native-path.py\n',
            "",
        )
        require_error(
            checker.validate(fixture), "test-verify-chain-native-path.py"
        )
        copy_fixture(fixture)

        rewrite(
            check,
            '"$PYTHON_BIN" scripts/test-native-binary-resolution.py\n',
            "",
        )
        require_error(
            checker.validate(fixture), "test-native-binary-resolution.py"
        )
        copy_fixture(fixture)

        rewrite(
            check,
            '"$PYTHON_BIN" scripts/test-installer-roundtrip-fixture.py\n',
            "",
        )
        require_error(
            checker.validate(fixture), "test-installer-roundtrip-fixture.py"
        )
        copy_fixture(fixture)

        rewrite(
            check,
            '"$PYTHON_BIN" scripts/check-windows-gnu-toolchain-contract.py\n',
            "",
        )
        require_error(
            checker.validate(fixture), "check-windows-gnu-toolchain-contract.py"
        )
        copy_fixture(fixture)

        rewrite(
            check,
            '"$PYTHON_BIN" scripts/test-windows-gnu-toolchain-contract.py\n',
            "",
        )
        require_error(
            checker.validate(fixture), "test-windows-gnu-toolchain-contract.py"
        )
        copy_fixture(fixture)

        rewrite(
            check,
            '"$PYTHON_BIN" scripts/check-native-aggregate-wrapper.py\n',
            "",
        )
        require_error(
            checker.validate(fixture), "check-native-aggregate-wrapper.py"
        )
        copy_fixture(fixture)

        rewrite(
            check,
            '"$PYTHON_BIN" scripts/test-native-aggregate-wrapper.py\n',
            "",
        )
        require_error(
            checker.validate(fixture), "test-native-aggregate-wrapper.py"
        )
        copy_fixture(fixture)

        rewrite(
            check,
            '"$PYTHON_BIN" scripts/native-cargo-fmt.py --all -- --check\n',
            "",
        )
        require_error(checker.validate(fixture), "native-cargo-fmt.py --all -- --check")
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
        rewrite(
            full,
            "bash scripts/ci-cbm-lint.sh\n\necho \"=== Upstream CBM runtime suite ===\"\nbash scripts/ci-cbm-test.sh",
            "bash scripts/ci-cbm-test.sh\n\necho \"=== Upstream CBM runtime suite ===\"\nbash scripts/ci-cbm-lint.sh",
        )
        require_error(checker.validate(fixture), "required order")
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
            "INFO[ASTRO_CBM_FORMAT_OVERLAY]",
            "INFO[ASTRO_CBM_FORMAT_REMOVED]",
        )
        require_error(checker.validate(fixture), "ASTRO_CBM_FORMAT_OVERLAY")
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
        copy_fixture(fixture)

        rewrite(
            workflow,
            'ASTROLABE_ROW_SINK_BENCH_WRITE_RELEASE_ARTIFACT: "1"',
            'ASTROLABE_ROW_SINK_BENCH_WRITE_RELEASE_ARTIFACT: "0"',
        )
        require_error(checker.validate(fixture), "WRITE_RELEASE_ARTIFACT")

    cleanup_scratch()
    assert not scratch.exists()
    print("gate wiring self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
