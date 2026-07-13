#!/usr/bin/env python3
"""Source-guard self-test for the absorbed CBM overlays (#286).

The former patches/cbm appliers were dissolved: every overlay is now a plain
edit in the owned CBM source, guarded by an ``ASTRO_*`` macro so each build
artifact selects the exact behavior it had before (the pre-#286 behavior
matrix). This test reads the OWNED sources and proves, per overlay, that the
load-bearing behavior:

  * is PRESENT when its flag is defined, and
  * is ABSENT when its flag is undefined,

which is exactly "the behavior is guarded by that flag, and only that flag".
It also asserts the Makefile wires the flags to the right artifacts
(libcbm gets all five libcbm features but NOT ui-werror; the production
binaries get only ui-werror + worker-diag).

Fail-closed: any missing marker, wrong guard, or wrong flag wiring exits 1.
Replaces the deleted overlay-mechanics tests (test-cbm-{worker-diag,env-store,
mem-pressure,spawn,ui-werror}-patch.py) with assertions against the real,
persisted, owned bytes rather than a patch applier's output.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CBM = ROOT / "vendor" / "codebase-memory-mcp"
MAKEFILE = ROOT / "patches" / "cbm" / "Makefile.cbm"

ASTRO_FLAGS = {
    "ASTRO_ENV_STORE",
    "ASTRO_SPAWN",
    "ASTRO_SHELLARG",
    "ASTRO_MEM_PRESSURE",
    "ASTRO_WORKER_DIAG",
    "ASTRO_UI_WERROR",
}

failures: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        failures.append(msg)


def _is_astro(head: str, parts: list[str]) -> bool:
    return head in ("#ifdef", "#ifndef") and len(parts) >= 2 and parts[1] in ASTRO_FLAGS


def preprocess(text: str, defined: set[str]) -> str:
    """Evaluate ONLY the ASTRO_* guards for `defined`; pass every foreign
    preprocessor directive (and its nested structure) through verbatim."""
    out: list[str] = []
    stack: list[tuple[str, bool | None]] = []  # ("astro", active) | ("foreign", None)

    def active() -> bool:
        return all(a for (k, a) in stack if k == "astro")

    for ln in text.splitlines(keepends=True):
        parts = ln.split()
        head = parts[0] if parts else ""
        if head in ("#if", "#ifdef", "#ifndef"):
            if _is_astro(head, parts):
                flag = parts[1]
                val = (flag in defined) if head == "#ifdef" else (flag not in defined)
                stack.append(("astro", val))
            else:
                if active():
                    out.append(ln)
                stack.append(("foreign", None))
            continue
        if head == "#else" and stack and stack[-1][0] == "astro":
            stack[-1] = ("astro", not stack[-1][1])
            continue
        if head == "#endif" and stack and stack[-1][0] == "astro":
            stack.pop()
            continue
        if head in ("#else", "#elif", "#endif") and stack and stack[-1][0] == "foreign":
            if head == "#endif":
                stack.pop()
            if active():
                out.append(ln)
            continue
        if active():
            out.append(ln)
    return "".join(out)


def guarded(relpath: str, flag: str, marker: str, absent_marker: str | None = None) -> None:
    """Assert `marker` appears only when `flag` is defined (i.e. it is guarded by
    exactly that flag). If given, `absent_marker` must appear only when the flag
    is UNDEFINED (proving the #else branch keeps the original)."""
    path = CBM / relpath
    if not path.is_file():
        failures.append(f"{relpath}: missing owned source")
        return
    text = path.read_text(encoding="utf-8")
    on = preprocess(text, {flag})
    off = preprocess(text, set())
    check(marker in on, f"{relpath}: marker {marker!r} absent when {flag} defined")
    check(
        marker not in off,
        f"{relpath}: marker {marker!r} present even when {flag} undefined "
        f"(not guarded by {flag})",
    )
    if absent_marker is not None:
        check(
            absent_marker in off,
            f"{relpath}: #else marker {absent_marker!r} absent when {flag} undefined",
        )
        check(
            absent_marker not in on,
            f"{relpath}: #else marker {absent_marker!r} present when {flag} defined",
        )


# ── #282 worker-failure diagnostics (libcbm + production binaries) ────────────
guarded("src/mcp/mcp.c", "ASTRO_WORKER_DIAG", '"worker_exit_code"')
guarded("src/mcp/mcp.c", "ASTRO_WORKER_DIAG", '"worker_response_tail"')
# index_supervisor.c slurps the worker response on EVERY outcome (not only CLEAN)
guarded("src/mcp/index_supervisor.c", "ASTRO_WORKER_DIAG", "on EVERY outcome")

# ── #240/#241 store resolution (libcbm only) ──────────────────────────────────
guarded("src/foundation/platform.c", "ASTRO_ENV_STORE", '#include "env_store_config.h"')

# ── #227/#228 shell-free git spawn + validator (libcbm only) ──────────────────
guarded("src/git/git_context.c", "ASTRO_SPAWN", "cbm_spawn_capture")
guarded("src/foundation/str_util.c", "ASTRO_SHELLARG", "case '%':")

# ── #149 pressure-log buffers (libcbm only): CBM_SZ_16 -> CBM_SZ_32 ───────────
guarded(
    "src/foundation/mem.c",
    "ASTRO_MEM_PRESSURE",
    "char pct_str[CBM_SZ_32];",
    absent_marker="char pct_str[CBM_SZ_16];",
)

# ── #229 production-binary -Werror root-cause fixes (production binaries only) ─
guarded("src/ui/layout3d.c", "ASTRO_UI_WERROR", "CBM_E_LAYOUT_NODE_COUNT_RANGE")

# ── Makefile flag wiring: the per-artifact behavior matrix ─────────────────────
if not MAKEFILE.is_file():
    failures.append("patches/cbm/Makefile.cbm: missing")
else:
    mk = MAKEFILE.read_text(encoding="utf-8")
    # libcbm gets the five libcbm-only/shared features, and NOT ui-werror.
    for flag in ("ASTRO_ENV_STORE", "ASTRO_SPAWN", "ASTRO_SHELLARG",
                 "ASTRO_MEM_PRESSURE", "ASTRO_WORKER_DIAG"):
        check(
            f"-D{flag}" in mk and "LIBCBM_ASTRO_DEFS" in mk,
            f"Makefile: libcbm must define -D{flag}",
        )
    # Extract the two defs lines and assert exact reach.
    libcbm_defs = "".join(
        l for l in mk.splitlines() if "LIBCBM_ASTRO_DEFS" in l or
        (l.strip().startswith("-DASTRO_") and "MEM_PRESSURE" in l)
    )
    check(
        "ASTRO_UI_WERROR" not in libcbm_defs,
        "Makefile: libcbm must NOT define ASTRO_UI_WERROR (it reaches prod only)",
    )
    prod_line = next((l for l in mk.splitlines() if l.startswith("ASTRO_PROD_DEFS")), "")
    check("-DASTRO_UI_WERROR" in prod_line, "Makefile: ASTRO_PROD_DEFS must define ASTRO_UI_WERROR")
    check("-DASTRO_WORKER_DIAG" in prod_line, "Makefile: ASTRO_PROD_DEFS must define ASTRO_WORKER_DIAG")
    for banned in ("ASTRO_ENV_STORE", "ASTRO_SPAWN", "ASTRO_SHELLARG", "ASTRO_MEM_PRESSURE"):
        check(
            banned not in prod_line,
            f"Makefile: ASTRO_PROD_DEFS must NOT define {banned} (libcbm-only)",
        )


if failures:
    print("FAIL[ASTRO_CBM_OVERLAY_SOURCES]: absorbed-overlay source guards violated")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)

print("OK: absorbed-overlay source guards present, per-artifact flag matrix intact")
