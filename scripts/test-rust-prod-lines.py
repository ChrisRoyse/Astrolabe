#!/usr/bin/env python3
"""Self-tests for the shared production-source view used by gate scripts (#118)."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import rust_prod_lines  # noqa: E402


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    # 1. Production code AFTER an inline cfg(test) mod stays visible (the old
    #    first-line truncation hid it), while the test span itself is blanked.
    source = "\n".join(
        [
            "fn early_writer() {",
            "    vault.append_ledger_entry(a, b, c, d);",
            "}",
            "",
            "#[cfg(test)]",
            "mod tests {",
            "    fn hidden_test_writer() {",
            "        vault.append_ledger_entry(a, b, c, d);",
            "    }",
            "}",
            "",
            "fn late_writer() {",
            "    vault.append_ledger_entry(a, b, c, d);",
            "}",
        ]
    )
    stripped = rust_prod_lines.strip_test_spans(source.splitlines())
    joined = "\n".join(stripped)
    check("early_writer" in joined, "pre-test production code lost")
    check("late_writer" in joined, "post-test production code invisible (old truncation bug)")
    check("hidden_test_writer" not in joined, "cfg(test) span not blanked")
    check(len(stripped) == len(source.splitlines()), "line indices not preserved")

    # 2. Braces inside strings/comments must not break the span walk.
    tricky = "\n".join(
        [
            "#[cfg(test)]",
            "mod tests {",
            '    const T: &str = "unbalanced { brace and // not a comment";',
            "    // a } in a comment",
            "}",
            "fn after() { call(); }",
        ]
    )
    stripped = rust_prod_lines.strip_test_spans(tricky.splitlines())
    check("after" in "\n".join(stripped), "string/comment braces broke span tracking")
    check("unbalanced" not in "\n".join(stripped), "test span content leaked")

    # 3. `#[cfg(test)] mod x;` resolves the out-of-line module file and subtree.
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        (src / "migration").mkdir(parents=True)
        (src / "migration" / "mod.rs").write_text(
            "#[cfg(test)]\nmod tests;\nmod real;\n", encoding="utf-8"
        )
        (src / "migration" / "tests.rs").write_text(
            "fn t() { vault.append_ledger_entry(a, b, c, d); }\n", encoding="utf-8"
        )
        (src / "migration" / "real.rs").write_text(
            "fn r() { vault.append_ledger_entry(a, b, c, d); }\n", encoding="utf-8"
        )
        test_files, test_dirs = rust_prod_lines.cfg_test_module_files(src)
        tests_path = src / "migration" / "tests.rs"
        real_path = src / "migration" / "real.rs"
        check(
            rust_prod_lines.is_test_only_file(tests_path, test_files, test_dirs),
            "out-of-line cfg(test) module file not excluded",
        )
        check(
            not rust_prod_lines.is_test_only_file(real_path, test_files, test_dirs),
            "production module wrongly excluded",
        )

    # 4. The shell-arg precedes-check is structural: a comment naming the
    #    validator no longer satisfies it; a real preceding call does.
    shell = load_module("check_shell_arg_audit", ROOT / "scripts" / "check-shell-arg-audit.py")
    with tempfile.TemporaryDirectory() as tmp:
        crate = Path(tmp) / "crates" / "demo" / "src"
        crate.mkdir(parents=True)
        target = crate / "lib.rs"
        entry = {
            "file": str(target.relative_to(tmp)).replace("\\", "/"),
            "function": "watch",
            "call": "cbm_watcher_watch",
            "validator": "validate_shell_arg(root_path)",
        }
        old_root = shell.ROOT
        shell.ROOT = Path(tmp)
        try:
            target.write_text(
                "\n".join(
                    [
                        "fn watch() {",
                        "    // validate_shell_arg is called by someone else, honest!",
                        "    cbm_watcher_watch(w, p, root);",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            check(
                not shell.validator_precedes_call(entry),
                "comment mentioning the validator satisfied the precedes-check",
            )
            target.write_text(
                "\n".join(
                    [
                        "fn watch() {",
                        "    validate_shell_arg(root_path)?;",
                        "    cbm_watcher_watch(w, p, root);",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            check(
                shell.validator_precedes_call(entry),
                "real preceding validator call rejected",
            )
        finally:
            shell.ROOT = old_root

    print("rust production-view self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
