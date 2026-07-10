#!/usr/bin/env python3
"""Generate the temporary Astrolabe overlay for CBM pressure logging."""

from __future__ import annotations

import argparse
from pathlib import Path


PERCENT_BUFFER_DECLARATION = "char pct_str[CBM_SZ_16];"
PATCHED_PERCENT_BUFFER_DECLARATION = "char pct_str[CBM_SZ_32];"
EXPECTED_PERCENT_BUFFER_COUNT = 2


def patch_source(source: str) -> str:
    """Expand only the two size_t percentage buffers in CBM's pressure logger."""
    count = source.count(PERCENT_BUFFER_DECLARATION)
    if count != EXPECTED_PERCENT_BUFFER_COUNT:
        raise ValueError(
            "expected exactly "
            f"{EXPECTED_PERCENT_BUFFER_COUNT} pressure percentage buffers, found {count}"
        )
    return source.replace(
        PERCENT_BUFFER_DECLARATION,
        PATCHED_PERCENT_BUFFER_DECLARATION,
    )


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
