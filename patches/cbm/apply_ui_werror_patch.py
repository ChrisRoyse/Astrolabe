#!/usr/bin/env python3
"""Generate hash-checked CBM overlays that clear the native MinGW GCC 14.1 -Werror
diagnostics blocking the `cbm-with-ui` build (#229).

`vendor/codebase-memory-mcp` is a byte-pinned subtree and is never edited. This
script reads a pinned CBM source, verifies its SHA-256 through
`patches/cbm/astro_overlay.py`, applies an exact, reviewed sequence of textual
edits, and writes a build-local overlay that `patches/cbm/Makefile.cbm` compiles
into the `cbm` / `cbm-with-ui` production binaries in place of the vendored
object. If upstream moves, the hash check fails closed (with the expected vs
found digest) instead of silently patching the wrong bytes.

Three diagnostics are repaired at the source — root-cause fixes, not warning
suppression:

  src/pipeline/pass_envscan.c  — -Wstringop-truncation. The vendored
      strncpy(dst, src, sizeof-1) + explicit-NUL idiom is replaced by an
      strnlen-bounded memcpy with an explicit terminator: identical semantics
      (truncate-to-buffer, always NUL-terminated), no truncation diagnostic.

  src/watcher/watcher.c        — -Wstringop-truncation AND a genuine latent bug:
      the two strncpy(s->last_head, head, sizeof-1) calls do NOT terminate when
      `head` fills the 64-byte buffer, leaving s->last_head unterminated. The
      strnlen-bounded memcpy + explicit NUL fixes both.

  src/pipeline/pass_definitions.c — -Walloc-size-larger-than, the same class of
      GENUINE bug: cbm_pipeline_pass_definitions() feeds a signed `int file_count`
      straight into two calloc((size_t)file_count, ...) calls (the local_cache and
      namespace-map `rels` allocations). A negative count casts to an enormous
      size_t. A single entry guard refuses a negative file_count and fails closed
      with a {code, message, remediation} record, narrowing the value to
      [0, INT_MAX] for both allocations; file_count == 0 stays a valid no-op.

  src/ui/layout3d.c            — -Walloc-size-larger-than, a GENUINE bug surface:
      compute_call_depth() feeds a bare `int n` straight into
      malloc((size_t)n * sizeof(int)). `n` is a search-result count already
      clamped to <= HARD_MAX_NODES before the query, but the compiler cannot see
      that bound, so it must assume the full int range and an out-of-range n would
      request an absurd allocation. A range guard (0 < n <= HARD_MAX_NODES) is
      added before the allocation; an out-of-range count fails closed with a
      {code, message, remediation} log record and leaves the caller's
      zero-initialized depth[] untouched. HARD_MAX_NODES is the file's existing
      hard node ceiling — no new constant is introduced.

Usage:
    apply_ui_werror_patch.py --file src/ui/layout3d.c <source> <output>

Verify with `python -B scripts/test-cbm-ui-werror-patch.py`. Temporary
integration patch; intended for upstreaming to CBM.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running both as `patches/cbm/apply_ui_werror_patch.py` (Makefile) and as a
# module import from the test harness: astro_overlay lives next to this file.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from astro_overlay import OverlayError, replace_once, verify_source_hash  # noqa: E402

# ── src/pipeline/pass_envscan.c ───────────────────────────────────────

ENVSCAN_OLD = """            strncpy(path_stack[*stack_top], full_path, sizeof(path_stack[0]) - 1);
            path_stack[*stack_top][sizeof(path_stack[0]) - SKIP_ONE] = '\\0';
"""

ENVSCAN_NEW = """            /* #229: bounded copy with a guaranteed terminator. The vendored
             * strncpy(dst, src, sizeof-1) truncation idiom trips GCC 14
             * -Wstringop-truncation under -Werror on the native MinGW toolchain.
             * strnlen caps the length, memcpy copies exactly that many bytes, and
             * the explicit NUL terminates — identical semantics, no diagnostic. */
            size_t entry_len = strnlen(full_path, sizeof(path_stack[0]) - SKIP_ONE);
            memcpy(path_stack[*stack_top], full_path, entry_len);
            path_stack[*stack_top][entry_len] = '\\0';
"""

# ── src/watcher/watcher.c ─────────────────────────────────────────────
# Two strncpy(s->last_head, ...) calls; they differ only in indentation (12 vs 8
# spaces), so each fragment is anchored with its surrounding lines to stay unique.

WATCHER_A_OLD = """            /* HEAD moved — commit, checkout, pull */
            strncpy(s->last_head, head, sizeof(s->last_head) - 1);
            return true;
"""

WATCHER_A_NEW = """            /* HEAD moved — commit, checkout, pull */
            /* #229: bounded copy with a guaranteed NUL terminator. The vendored
             * strncpy(dst, src, sizeof-1) does not terminate when `head` fills the
             * buffer (a genuine latent bug) and trips GCC 14 -Wstringop-truncation
             * under -Werror on native MinGW. */
            size_t head_len = strnlen(head, sizeof(s->last_head) - 1);
            memcpy(s->last_head, head, head_len);
            s->last_head[head_len] = '\\0';
            return true;
"""

WATCHER_B_OLD = """        }
        strncpy(s->last_head, head, sizeof(s->last_head) - 1);
"""

WATCHER_B_NEW = """        }
        /* #229: bounded copy with a guaranteed NUL terminator (see above). */
        size_t head_len = strnlen(head, sizeof(s->last_head) - 1);
        memcpy(s->last_head, head, head_len);
        s->last_head[head_len] = '\\0';
"""

# ── src/pipeline/pass_definitions.c ───────────────────────────────────

DEFS_OLD = """    cbm_log_info("pass.start", "pass", "definitions", "files", itoa_log(file_count));

    /* Ensure extraction library is initialized */
    cbm_init();"""

DEFS_NEW = """    cbm_log_info("pass.start", "pass", "definitions", "files", itoa_log(file_count));

    /* #229: `file_count` is a signed count fed unchecked into
     * calloc((size_t)file_count, ...) twice below — the local_cache allocation
     * and the namespace-map `rels` allocation. A negative count (a caller
     * contract violation or an upstream integer wraparound) casts to an enormous
     * size_t: GCC 14 sees the (size_t)file_count range include [INT_MIN..-1] and
     * trips -Walloc-size-larger-than under -Werror on native MinGW, and such a
     * count really would request an absurd allocation. Refuse a negative count
     * and fail closed with a {code, message, remediation} log record; an empty
     * file set (file_count == 0) stays valid and flows through as a no-op. The
     * early return narrows file_count to [0, INT_MAX] for both allocations. */
    if (file_count < 0) {
        cbm_log_error("pass.definitions.file_count",
                      "code", "CBM_E_DEFS_FILE_COUNT_RANGE",
                      "message", "definitions pass received a negative file_count",
                      "remediation",
                      "pass a non-negative file_count; a negative value indicates a "
                      "caller contract violation or an integer overflow upstream");
        return CBM_NOT_FOUND;
    }

    /* Ensure extraction library is initialized */
    cbm_init();"""

# ── src/ui/layout3d.c ─────────────────────────────────────────────────

LAYOUT_OLD = """    for (int i = 0; i < n; i++)
        depth[i] = -1;
    int *q = malloc((size_t)n * sizeof(int));
"""

LAYOUT_NEW = """    /* #229: `n` is a search-result count, already clamped to <= HARD_MAX_NODES by
     * clamp_max_nodes() before the query that produced it — but the compiler cannot
     * see that bound. A bare int spans up to INT_MAX, so (size_t)n * sizeof(int)
     * trips GCC 14 -Walloc-size-larger-than under -Werror, and an out-of-range n
     * really would request an absurd allocation. Refuse a non-positive or over-cap
     * count and fail closed: log a {code, message, remediation} record and leave
     * the caller's zero-initialized depth[] untouched. */
    if (n <= 0 || n > HARD_MAX_NODES) {
        cbm_log_error("layout3d.call_depth", "code", "CBM_E_LAYOUT_NODE_COUNT_RANGE",
                      "message", "call-depth node count is out of the representable range",
                      "remediation",
                      "lower the layout node ceiling (CBM_UI_MAX_RENDER_NODES) or the "
                      "requested max_nodes so the result set stays within HARD_MAX_NODES");
        return;
    }
    for (int i = 0; i < n; i++)
        depth[i] = -1;
    int *q = malloc((size_t)n * sizeof(int));
"""

# Ordered edit programme per pinned source. Each entry is (old, new, label); the
# edits are applied in order via astro_overlay.replace_once, which fails closed
# unless the pinned fragment occurs exactly once.
PATCHES: dict[str, dict[str, object]] = {
    "src/pipeline/pass_envscan.c": {
        "sha256": "f2bbd868abd3d538417112c373be611f616ddd0bb82881ce37a09cceb54fcdb4",
        "edits": [(ENVSCAN_OLD, ENVSCAN_NEW, "pass_envscan strncpy truncation")],
    },
    "src/watcher/watcher.c": {
        "sha256": "869086cb4439b93dddf429d7b57d1a88538b9930679282e0451f65e5289a60b4",
        "edits": [
            (WATCHER_A_OLD, WATCHER_A_NEW, "watcher last_head strncpy (HEAD moved)"),
            (WATCHER_B_OLD, WATCHER_B_NEW, "watcher last_head strncpy (baseline)"),
        ],
    },
    "src/pipeline/pass_definitions.c": {
        "sha256": "5a49f941ffd96879ff8fe2c5832862a6cd8a4c9b497eca1b2eacd27fa53d753f",
        "edits": [(DEFS_OLD, DEFS_NEW, "pass_definitions file_count alloc-size")],
    },
    "src/ui/layout3d.c": {
        "sha256": "c5fcd801d9d390252e07e768c35bc5aca7e90b084f8eab7be8ccf1937ae08541",
        "edits": [(LAYOUT_OLD, LAYOUT_NEW, "layout3d compute_call_depth alloc-size")],
    },
}

PATCHED_FILES = tuple(PATCHES)


def patch_source(relative: str, source: str) -> str:
    """Apply the reviewed overlay for `relative` to its pinned source text."""
    spec = PATCHES.get(relative)
    if spec is None:
        raise OverlayError(
            "ASTRO_OVERLAY_UNKNOWN_FILE",
            f"no CBM UI -Werror overlay is declared for {relative}",
            f"pass --file with one of: {', '.join(PATCHED_FILES)}",
        )

    verify_source_hash(source, spec["sha256"], relative)  # type: ignore[arg-type]

    patched = source
    for old, new, label in spec["edits"]:  # type: ignore[assignment]
        patched = replace_once(patched, old, new, label)
    if patched == source:
        raise OverlayError(
            "ASTRO_OVERLAY_NO_CHANGE",
            f"{relative} overlay produced no change; the patch is not load-bearing",
            "re-review the overlay fragments against the pinned source",
        )
    return patched


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True, choices=PATCHED_FILES)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    patched = patch_source(args.file, args.source.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(patched, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
