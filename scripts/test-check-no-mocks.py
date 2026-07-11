#!/usr/bin/env python3
"""Self-tests for scripts/check-no-mocks.py against real fixture trees."""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-no-mocks.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_no_mocks", CHECKER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CHECKER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    checker = load_checker()
    scratch_parent = ROOT / ".tmp"
    scratch = scratch_parent / "no-mocks-selftest"
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True, exist_ok=True)
    try:
        fixture = scratch / "fixture"

        write(
            fixture / "crates" / "demo" / "src" / "lib.rs",
            "pub fn add(a: u64, b: u64) -> u64 { a + b }\n"
            "#[cfg(test)]\nmod tests {\n"
            "    #[test]\n    fn adds() { assert_eq!(super::add(2, 2), 4); }\n}\n",
        )
        violations, allowed, scanned = checker.scan(fixture)
        assert not violations, f"clean fixture flagged: {violations}"
        assert not allowed, f"clean fixture allowed-list nonempty: {allowed}"
        assert scanned >= 1

        write(
            fixture / "crates" / "demo" / "tests" / "bad.rs",
            "use mockall::mock;\n#[test]\nfn fake_path() {\n"
            "    let mock_store = 1;\n    assert!(true);\n}\n",
        )
        violations, allowed, scanned = checker.scan(fixture)
        assert violations, "planted mock constructs were not flagged"
        kinds = {kind for records in violations.values() for _, kind, _ in records}
        assert "mock framework" in kinds, kinds
        assert "test-double binding" in kinds, kinds
        assert "vacuous assertion" in kinds, kinds

        write(
            fixture / "crates" / "demo" / "tests" / "bad.rs",
            "// ASTRO_ALLOW_TEST_DOUBLE_FILE(fixture proving marker accounting)\n"
            "use mockall::mock;\n#[test]\nfn fake_path() {\n"
            "    let mock_store = 1;\n    assert!(true);\n}\n",
        )
        violations, allowed, scanned = checker.scan(fixture)
        assert not violations, f"file marker did not clear findings: {violations}"
        assert allowed, "marker-cleared findings must still be counted as allowed"

        write(
            fixture / "scripts" / "test-thing.py",
            "from unittest import mock\n\n"
            "def test_it():\n"
            "    # ASTRO_ALLOW_TEST_DOUBLE(branch selection only)\n"
            "    with mock.patch('x'):\n        pass\n",
        )
        violations, allowed, scanned = checker.scan(fixture)
        assert len(violations) == 1, f"expected only the unmarked import: {violations}"
        (path,) = violations
        assert path.name == "test-thing.py"
        line_nos = [line_no for line_no, _, _ in violations[path]]
        assert line_nos == [1], line_nos

        write(
            fixture / "crates" / "demo" / "Cargo.toml",
            "[package]\nname = \"demo\"\n[dev-dependencies]\nmockito = \"1\"\n",
        )
        violations, allowed, scanned = checker.scan(fixture)
        cargo_hits = [
            kind
            for records in violations.values()
            for _, kind, _ in records
            if kind == "mock crate dependency"
        ]
        assert cargo_hits, "mock dev-dependency was not flagged"

        vendor_file = fixture / "vendor" / "upstream" / "tests" / "mocky.rs"
        write(vendor_file, "use mockall::mock;\n")
        violations, allowed, scanned = checker.scan(fixture)
        flagged_paths = {p for p in violations}
        assert vendor_file not in flagged_paths, "vendor tree must be excluded"
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    print("no-mock gate self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
