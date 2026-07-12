#!/usr/bin/env python3
"""Self-test (FSV) for the CBM production-binary -Werror overlay (#229).

Verifies patches/cbm/apply_ui_werror_patch.py against the live pinned CBM sources:
  * every declared source hash still matches (the pin has not silently moved);
  * every reviewed overlay is load-bearing (changes the source) and leaves the
    vendored source untouched on disk (the generator never writes into vendor/);
  * each root-cause fix is actually present in the persisted overlay bytes read
    back from disk — the strnlen+memcpy bounded copies (pass_envscan / watcher)
    the fail-closed range guard before the compute_call_depth allocation
    (layout3d), and the fail-closed negative-file_count guard before the two
    calloc((size_t)file_count, ...) sites (pass_definitions), with the flagged
    strncpy / unchecked-malloc idioms removed;
  * the edge-case triad fails closed with {code, message, remediation}:
      - drifted source (byte mutated)         -> ASTRO_OVERLAY_SOURCE_DRIFT
      - a re-applied (already-patched) source  -> fails closed (double-apply)
      - empty source                           -> fails closed
      - unknown --file selector                -> ASTRO_OVERLAY_UNKNOWN_FILE
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CBM_ROOT = ROOT / "vendor" / "codebase-memory-mcp"
PATCH = ROOT / "patches" / "cbm" / "apply_ui_werror_patch.py"

ENVSCAN = "src/pipeline/pass_envscan.c"
WATCHER = "src/watcher/watcher.c"
LAYOUT = "src/ui/layout3d.c"
DEFS = "src/pipeline/pass_definitions.c"


def load_patch_module():
    spec = importlib.util.spec_from_file_location("apply_ui_werror_patch", PATCH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def expect(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        raise SystemExit(1)
    print(f"ok: {msg}")


def expect_fail_closed(fn, msg: str, code: str | None = None) -> None:
    """`fn` must raise a fail-closed ValueError (astro_overlay.OverlayError)."""
    try:
        fn()
    except ValueError as exc:
        if code is not None and code not in str(exc):
            print(f"FAIL: {msg}: wrong code, got {exc!r}", file=sys.stderr)
            raise SystemExit(1)
        print(f"ok: {msg}")
    else:
        print(f"FAIL: {msg}: did not fail closed", file=sys.stderr)
        raise SystemExit(1)


def main() -> None:
    if not CBM_ROOT.is_dir():
        print("SKIP: vendored CBM tree absent", file=sys.stderr)
        raise SystemExit(1)

    mod = load_patch_module()

    # ── Overlay generation + persisted-byte readback (FSV) ─────────────────
    patched_by_file: dict[str, str] = {}
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        for relative in mod.PATCHED_FILES:
            src_path = CBM_ROOT / relative
            source = src_path.read_text(encoding="utf-8")
            source_bytes_before = src_path.read_bytes()

            # Generate through patch_source, then persist and read the bytes back
            # from a *separate* file handle — the overlay's source of truth is the
            # file the Makefile compiles, not the return value.
            patched = mod.patch_source(relative, source)
            out_path = tmpdir / relative
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(patched, encoding="utf-8", newline="\n")
            persisted = out_path.read_text(encoding="utf-8")
            patched_by_file[relative] = persisted

            expect(persisted == patched, f"{relative}: persisted overlay bytes match generator output")
            expect(persisted != source, f"{relative}: overlay changes the source (load-bearing)")
            # The generator must never mutate the pinned vendored source.
            expect(
                src_path.read_bytes() == source_bytes_before,
                f"{relative}: vendored source left byte-identical (no vendor/ write)",
            )

            # Double-apply must fail closed: the patched text no longer matches the
            # pinned hash, so re-patching raises rather than corrupting.
            expect_fail_closed(
                lambda p=persisted, r=relative: mod.patch_source(r, p),
                f"{relative}: re-applying the overlay fails closed (double-apply)",
            )

    # ── pass_envscan.c: strnlen+memcpy bounded copy replaces the strncpy idiom ─
    env = patched_by_file[ENVSCAN]
    expect(
        "strnlen(full_path, sizeof(path_stack[0]) - SKIP_ONE)" in env
        and "memcpy(path_stack[*stack_top], full_path, entry_len)" in env,
        "pass_envscan.c: path-stack copy is a bounded strnlen+memcpy",
    )
    expect(
        "strncpy(path_stack[*stack_top], full_path" not in env,
        "pass_envscan.c: the -Wstringop-truncation strncpy site is gone",
    )

    # ── watcher.c: both last_head copies are bounded+terminated ────────────────
    wat = patched_by_file[WATCHER]
    expect(
        "strncpy(s->last_head, head" not in wat,
        "watcher.c: neither last_head strncpy truncation site remains",
    )
    expect(
        wat.count("strnlen(head, sizeof(s->last_head) - 1)") == 2
        and wat.count("memcpy(s->last_head, head, head_len)") == 2,
        "watcher.c: both last_head copies are bounded strnlen+memcpy (NUL-terminated)",
    )
    expect(
        wat.count("s->last_head[head_len] = '\\0';") == 2,
        "watcher.c: both copies write an explicit NUL terminator",
    )

    # ── layout3d.c: fail-closed range guard before the flagged allocation ──────
    lay = patched_by_file[LAYOUT]
    guard = "if (n <= 0 || n > HARD_MAX_NODES) {"
    expect(guard in lay, "layout3d.c: compute_call_depth guards n against HARD_MAX_NODES")
    expect(
        "CBM_E_LAYOUT_NODE_COUNT_RANGE" in lay and "remediation" in lay,
        "layout3d.c: guard fails closed with a {code, message, remediation} log record",
    )
    # The guard (and its return) must physically precede the flagged malloc so the
    # allocation is unreachable with an out-of-range n.
    expect(
        0 <= lay.index(guard) < lay.index("int *q = malloc((size_t)n * sizeof(int));"),
        "layout3d.c: the range guard precedes the malloc it protects",
    )

    # ── pass_definitions.c: fail-closed negative-file_count guard before calloc ─
    defs = patched_by_file[DEFS]
    defs_guard = "if (file_count < 0) {"
    expect(defs_guard in defs, "pass_definitions.c: guards file_count against a negative count")
    expect(
        "CBM_E_DEFS_FILE_COUNT_RANGE" in defs and "remediation" in defs,
        "pass_definitions.c: guard fails closed with a {code, message, remediation} log record",
    )
    expect(
        "return CBM_NOT_FOUND;" in defs,
        "pass_definitions.c: the negative-count guard returns a fail-closed status",
    )
    # The guard must physically precede BOTH flagged callocs so neither allocation
    # is reachable with a negative (huge-when-cast) file_count.
    guard_at = defs.index(defs_guard)
    expect(
        0 <= guard_at < defs.index("calloc((size_t)file_count, sizeof(CBMFileResult *))")
        and guard_at < defs.index("calloc((size_t)file_count, sizeof(char *))"),
        "pass_definitions.c: the range guard precedes both file_count callocs it protects",
    )
    # The vendored calloc call-sites themselves are unchanged (root-cause guard,
    # not a rewrite of the allocations).
    expect(
        "calloc((size_t)file_count, sizeof(char *))" in defs,
        "pass_definitions.c: the guarded namespace-map calloc is preserved",
    )

    # A drifted pass_definitions source fails closed on its own hash pin.
    defs_good = (CBM_ROOT / DEFS).read_text(encoding="utf-8")
    defs_drifted = defs_good.replace("int file_count) {", "int file_count) { /* moved */", 1)
    expect_fail_closed(
        lambda: mod.patch_source(DEFS, defs_drifted),
        "pass_definitions.c: a drifted source fails closed on the hash pin",
        code="ASTRO_OVERLAY_SOURCE_DRIFT",
    )

    # ── Edge-case triad: drift / empty / unknown selector all fail closed ──────
    good = (CBM_ROOT / LAYOUT).read_text(encoding="utf-8")
    drifted = good.replace("compute_call_depth", "compute_call_depth /* moved */", 1)
    expect_fail_closed(
        lambda: mod.patch_source(LAYOUT, drifted),
        "layout3d.c: a drifted source fails closed on the hash pin",
        code="ASTRO_OVERLAY_SOURCE_DRIFT",
    )
    expect_fail_closed(
        lambda: mod.patch_source(LAYOUT, ""),
        "empty source fails closed",
        code="ASTRO_OVERLAY_SOURCE_DRIFT",
    )
    expect_fail_closed(
        lambda: mod.patch_source("src/does/not/exist.c", good),
        "unknown --file selector fails closed",
        code="ASTRO_OVERLAY_UNKNOWN_FILE",
    )

    print("test-cbm-ui-werror-patch: all cases passed")


if __name__ == "__main__":
    main()
