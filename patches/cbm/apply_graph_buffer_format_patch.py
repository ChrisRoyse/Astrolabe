#!/usr/bin/env python3
"""Generate the checked Astrolabe formatting overlay for CBM graph_buffer.c."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


EXPECTED_SOURCE_SHA256 = "faee9f71fe465eeabc5cf9c3f6154665e11f0e3f377d5c5651a1bd54c3dde805"
ORIGINAL = """        dump_edges = build_dump_edges(gb, temp_to_final, max_temp_id, &edge_idx, &url_paths,
                                      &local_names);"""
FORMATTED = """        dump_edges =
            build_dump_edges(gb, temp_to_final, max_temp_id, &edge_idx, &url_paths, &local_names);"""


def patch_source(source: str) -> str:
    """Apply the one format-only integration overlay to the pinned source."""
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if digest != EXPECTED_SOURCE_SHA256:
        raise ValueError(
            f"unexpected graph_buffer.c source hash: expected {EXPECTED_SOURCE_SHA256}, got {digest}"
        )
    count = source.count(ORIGINAL)
    if count != 1:
        raise ValueError(f"expected exactly one graph-buffer formatting fragment, found {count}")
    return source.replace(ORIGINAL, FORMATTED)


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
