#!/usr/bin/env python3
"""Self-test for the #227/#228 CBM overlays (patch-byte regression).

Proves, WITHOUT mutating the pinned vendor tree, that every overlay generator:
  - refuses to run against a source whose sha256 is not the reviewed baseline
    (fail-closed with expected/found digests);
  - actually removes the shelled-out `cbm_popen(cmd, ...)` git call from every
    git path (#227) and routes it through cbm_spawn_capture with an argv array;
  - extends cbm_validate_shell_arg to reject %, ^, ! under _WIN32 while leaving
    the POSIX branch untouched (#228);
  - leaves the vendor bytes on disk byte-for-byte unchanged.

This is the "prove the gate is load-bearing" self-test the vendor-patch flow
requires. The FSV that git receives an un-expanded argv lives in
scripts/test-cbm-spawn-fsv.py (it needs a real git and a compiler).
"""

from __future__ import annotations

import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCH_DIR = ROOT / "patches" / "cbm"
VENDOR = ROOT / "vendor" / "codebase-memory-mcp"

# Each spawn overlay: (generator, vendored source, human label).
SPAWN_OVERLAYS = [
    ("apply_spawn_git_context_patch.py", "src/git/git_context.c", "git_context"),
    ("apply_spawn_artifact_patch.py", "src/pipeline/artifact.c", "artifact"),
    ("apply_spawn_watcher_patch.py", "src/watcher/watcher.c", "watcher"),
    ("apply_spawn_githistory_patch.py", "src/pipeline/pass_githistory.c", "githistory"),
]
STR_UTIL_OVERLAY = ("apply_shellarg_str_util_patch.py", "src/foundation/str_util.c")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"CBM spawn patch regression failed: {message}")


def load(generator: str):
    return runpy.run_path(str(PATCH_DIR / generator))


def check_hash_pin(module, source: str, label: str) -> None:
    """A drifted vendor source must fail closed, not patch blind."""
    mutated = source + "\n/* upstream drift */\n"
    try:
        module["patch_source"](mutated)
    except ValueError as exc:
        require(
            "SOURCE_DRIFT" in str(exc) or "hash" in str(exc).lower(),
            f"{label}: drift must be reported as a hash mismatch, got: {exc}",
        )
    else:
        raise SystemExit(
            f"CBM spawn patch regression failed: {label} accepted a drifted source"
        )


def main() -> None:
    # ── #227: every git shell-out is de-shelled ──────────────────────────
    for generator, rel, label in SPAWN_OVERLAYS:
        module = load(generator)
        source = (VENDOR / rel).read_text(encoding="utf-8")

        require(
            "cbm_popen" in source,
            f"{label}: baseline vendor source must still contain the shelled cbm_popen call "
            "(otherwise this regression proves nothing)",
        )

        patched = module["patch_source"](source)

        # The load-bearing assertion: no shell invocation remains on the git path.
        for banned in ("cbm_popen(", "cbm_pclose(", "_popen(", "popen(", "system("):
            require(
                banned not in strip_comments(patched),
                f"{label}: overlay still contains a shell invocation `{banned}` on a git path",
            )
        require(
            "cbm_spawn_capture(" in patched,
            f"{label}: overlay must route git through cbm_spawn_capture",
        )
        require(
            '#include "astro_spawn.h"' in patched,
            f"{label}: overlay must include the shell-free spawn header",
        )

        check_hash_pin(module, source, label)

        require(
            (VENDOR / rel).read_text(encoding="utf-8") == source,
            f"{label}: generator must not mutate the vendor source",
        )
        print(f"[#227] {label}: git shell-out removed, routed through cbm_spawn_capture")

    # ── prove the gate would CATCH a reintroduced _popen ─────────────────
    prove_popen_reintroduction_is_caught()

    # ── #228: str_util validator gains %, ^, ! under _WIN32 ──────────────
    generator, rel = STR_UTIL_OVERLAY
    module = load(generator)
    source = (VENDOR / rel).read_text(encoding="utf-8")
    patched = module["patch_source"](source)

    win_block = extract_win32_case_block(patched)
    for ch in ("'%'", "'^'", "'!'"):
        require(
            f"case {ch}:" in win_block,
            f"[#228] the _WIN32 branch must reject {ch}",
        )
    # The POSIX branch must be untouched: backslash stays #ifndef _WIN32, and the
    # three new characters must NOT leak into the shared (POSIX) case list.
    posix_only = extract_ifndef_win32_case_block(patched)
    require("case '\\\\':" in posix_only, "[#228] POSIX branch must still reject backslash")
    for ch in ("'%'", "'^'", "'!'"):
        require(
            f"case {ch}:" not in posix_only,
            f"[#228] {ch} must be Windows-only, not added to the POSIX/shared branch",
        )
    check_hash_pin(module, source, "str_util")
    require(
        (VENDOR / rel).read_text(encoding="utf-8") == source,
        "str_util: generator must not mutate the vendor source",
    )
    print("[#228] cbm_validate_shell_arg rejects %, ^, ! under _WIN32 (POSIX branch intact)")

    print("CBM spawn/validator patch regression passed")


def prove_popen_reintroduction_is_caught() -> None:
    """If a future edit re-adds a cbm_popen git call to an overlay OUTPUT, this
    self-test's banned-substring scan must flag it. Simulate that here so the
    gate itself is demonstrably load-bearing (not a no-op)."""
    reintroduced = 'FILE *fp = cbm_popen(cmd, "r"); /* regression */'
    caught = "cbm_popen(" in strip_comments(reintroduced + " cbm_spawn_capture(x);")
    require(caught, "the self-test's banned-substring scan is not actually load-bearing")
    print("[#227] gate is load-bearing: a reintroduced cbm_popen on a git path is caught")


def strip_comments(text: str) -> str:
    """Blank out /* */ and // spans so a `cbm_popen` mentioned in prose is not a
    false positive; only real code tokens count as a shell invocation."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def extract_win32_case_block(patched: str) -> str:
    """Return the `#else` (Windows) arm of the validator's #ifndef _WIN32 split."""
    marker = "#ifndef _WIN32"
    start = patched.index(marker)
    end = patched.index("#endif", start)
    block = patched[start:end]
    if "#else" not in block:
        raise SystemExit("CBM spawn patch regression failed: validator lost its #else arm")
    return block.split("#else", 1)[1]


def extract_ifndef_win32_case_block(patched: str) -> str:
    marker = "#ifndef _WIN32"
    start = patched.index(marker)
    end = patched.index("#endif", start)
    block = patched[start:end]
    return block.split("#else", 1)[0]


if __name__ == "__main__":
    main()
