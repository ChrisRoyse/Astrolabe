#!/usr/bin/env python3
"""Self-tests for scripts/check-gate-wiring.py."""

from __future__ import annotations

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
    "scripts/ci-cbm-test.sh",
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
    scratch = ROOT / "target"
    scratch.mkdir(parents=True, exist_ok=True)
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

        full = fixture / "scripts/check-full.sh"
        rewrite(
            full,
            "bash scripts/ci-cbm-lint.sh\n\necho \"=== Upstream CBM runtime suite ===\"\nbash scripts/ci-cbm-test.sh",
            "bash scripts/ci-cbm-test.sh\n\necho \"=== Upstream CBM runtime suite ===\"\nbash scripts/ci-cbm-lint.sh",
        )
        require_error(checker.validate(fixture), "required order")
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

    print("gate wiring self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
