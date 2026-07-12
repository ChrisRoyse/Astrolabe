#!/usr/bin/env python3
"""#228: build-local overlay teaching cbm_validate_shell_arg the cmd.exe classes.

The Rust bridge validator (crates/astrolabe-bridge, #136) rejects `%`, `^` and
`!` on Windows because cmd.exe substitutes `%VAR%` / `%X:~n,m%` at PARSE time,
defers `!VAR!` under delayed expansion, and uses `^` as its escape character —
all before any quoting is applied. The vendored C mirror only split on `\\`.
This overlay brings the C validator to parity so the two halves of Astrolabe
agree on what a shell-unsafe argument is.

This is defence in depth. #227 removes the shell from every git path outright;
the validator is no longer the only barrier, but it must not lie about which
byte classes it rejects.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from astro_overlay import replace_once, verify_source_hash  # noqa: E402

SOURCE_NAME = "src/foundation/str_util.c"
EXPECTED_SOURCE_SHA256 = "1ab57a57395c57b6944b4749d99b991aef5165da23571c449879563dc2a04c77"

ORIGINAL_VALIDATOR = """        case '\\n':
        case '\\r':
#ifndef _WIN32
        case '\\\\':
#endif
            return false;"""

PATCHED_VALIDATOR = """        case '\\n':
        case '\\r':
#ifndef _WIN32
        case '\\\\':
#else
        /* cmd.exe substitutes %VAR% and %X:~n,m% at parse time, defers !VAR!
         * under delayed expansion, and treats ^ as its escape character — all
         * BEFORE quoting applies, so quotes cannot make these inert. Mirrors the
         * Rust bridge validator (#136). */
        case '%':
        case '^':
        case '!':
#endif
            return false;"""


def patch_source(source: str) -> str:
    """Extend the vendored validator's Windows rejection set (#228)."""
    verify_source_hash(source, EXPECTED_SOURCE_SHA256, SOURCE_NAME)
    return replace_once(source, ORIGINAL_VALIDATOR, PATCHED_VALIDATOR, "shell-arg validator")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    patched = patch_source(args.source.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(patched, encoding="utf-8")


if __name__ == "__main__":
    main()
