#!/usr/bin/env python3
"""Shared primitives for Astrolabe's hash-checked, build-local CBM overlays.

Every overlay generator pins the exact bytes of the vendored source it rewrites
(`vendor/codebase-memory-mcp` is a pinned subtree — see VENDORED.md). If upstream
moves, the pin fails closed with the expected and found digests instead of
silently patching a source it has never seen. No generator ever writes into
`vendor/`; they emit a build-local copy that `patches/cbm/Makefile.cbm` compiles.
"""

from __future__ import annotations

import hashlib


class OverlayError(ValueError):
    """Fail-closed overlay error: {code, message, remediation}."""

    def __init__(self, code: str, message: str, remediation: str) -> None:
        super().__init__(f"{code}: {message} — remediation: {remediation}")
        self.code = code
        self.message = message
        self.remediation = remediation


def verify_source_hash(source: str, expected_sha256: str, name: str) -> None:
    """Refuse to patch a vendored source whose bytes are not the reviewed ones."""
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if digest != expected_sha256:
        raise OverlayError(
            "ASTRO_OVERLAY_SOURCE_DRIFT",
            f"{name} does not match the reviewed baseline "
            f"(expected {expected_sha256}, got {digest})",
            "re-review the upstream change, then update EXPECTED_SOURCE_SHA256 "
            "and the overlay fragments in this generator",
        )


def replace_once(source: str, original: str, patched: str, label: str) -> str:
    """Replace exactly one occurrence of `original`; refuse any other count."""
    count = source.count(original)
    if count != 1:
        raise OverlayError(
            "ASTRO_OVERLAY_FRAGMENT_DRIFT",
            f"expected exactly one occurrence of the {label} fragment, found {count}",
            "re-review the upstream change and update the overlay fragment",
        )
    return source.replace(original, patched, 1)


def replace_span(source: str, start: str, end: str, patched: str, label: str) -> str:
    """Replace the unique span from `start` through the end of `end`.

    Both anchors must occur exactly once and in order, so a span can never be
    silently mis-sliced by an upstream edit that duplicates or reorders them.
    """
    if source.count(start) != 1:
        raise OverlayError(
            "ASTRO_OVERLAY_ANCHOR_DRIFT",
            f"the {label} start anchor must occur exactly once, "
            f"found {source.count(start)}",
            "re-review the upstream change and update the overlay anchors",
        )
    if source.count(end) != 1:
        raise OverlayError(
            "ASTRO_OVERLAY_ANCHOR_DRIFT",
            f"the {label} end anchor must occur exactly once, found {source.count(end)}",
            "re-review the upstream change and update the overlay anchors",
        )
    begin = source.index(start)
    finish = source.index(end) + len(end)
    if finish <= begin:
        raise OverlayError(
            "ASTRO_OVERLAY_ANCHOR_DRIFT",
            f"the {label} end anchor precedes its start anchor",
            "re-review the upstream change and update the overlay anchors",
        )
    return source[:begin] + patched + source[finish:]
