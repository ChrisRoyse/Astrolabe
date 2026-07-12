#!/usr/bin/env python3
"""#227: build-local overlay routing artifact.c's git shell-outs through cbm_spawn_capture.

`git rev-parse HEAD` (artifact metadata) and `git config merge.ours.driver true`
(.gitattributes setup) were composed as command STRINGS and executed by
cmd.exe / sh through cbm_popen. They now spawn git with an explicit argv, so no
shell parses the repo path. cbm_artifact_repo_path_is_shell_safe stays as
defence in depth.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from astro_overlay import replace_once, replace_span, verify_source_hash  # noqa: E402

SOURCE_NAME = "src/pipeline/artifact.c"
EXPECTED_SOURCE_SHA256 = "b69efe0b59eab647aaa42890439cc65a30decc50326e9b7b57dfa04f76a8b44c"

ORIGINAL_INCLUDES = """#include "pipeline/artifact.h"
#include "store/store.h"
"""

PATCHED_INCLUDES = """#include "astro_spawn.h"
#include "pipeline/artifact.h"
#include "store/store.h"
"""

ORIGINAL_NULL_DEV = """#ifdef _WIN32
#define ARTIFACT_NULL_DEV "NUL"
#else
#define ARTIFACT_NULL_DEV "/dev/null"
#endif

"""

PATCHED_NULL_DEV = ""

ORIGINAL_SHELL_SAFE_DOC = """/* See artifact.h. Mirrors git_context.c's git_validate_repo_path (the best-hardened
 * git shell-out): cbm_validate_shell_arg rejects quote / backslash / substitution
 * metacharacters, and on Windows we also reject the cmd.exe expansion metacharacters
 * % ! ^. Callers then use DOUBLE quotes (honored by both POSIX sh and cmd.exe, unlike
 * single quotes on cmd.exe), so a repo path may legitimately contain spaces. */"""

PATCHED_SHELL_SAFE_DOC = """/* See artifact.h. Defence in depth (#227): the git callers below no longer use a
 * shell at all — git is spawned with an explicit argv — so this validator is not
 * what makes interpolation safe; there is no interpolation left to make safe. It
 * still refuses a repo path carrying shell metacharacters (cbm_validate_shell_arg,
 * plus the cmd.exe expansion characters % ! ^ on Windows) instead of silently
 * accepting one. A path may legitimately contain spaces: argv needs no quoting. */"""

HEAD_HASH_START = "static bool git_head_hash(const char *repo_path, char *buf, size_t bufsz) {"
HEAD_HASH_END = """    (void)cbm_pclose(fp);
    return buf[0] != '\\0';
}"""

PATCHED_HEAD_HASH = """static bool git_head_hash(const char *repo_path, char *buf, size_t bufsz) {
    if (bufsz == 0) {
        return false;
    }
    buf[0] = '\\0';
    if (!cbm_artifact_repo_path_is_shell_safe(repo_path)) {
        return false;
    }

    /* Shell-free spawn (#227): git receives this argv verbatim. There is no
     * command string to compose (so nothing can be truncated into a malformed
     * shell line), no quoting to get right, and no `2>NUL` / `2>/dev/null`
     * suffix — cbm_spawn_capture binds the child's stderr to the null device. */
    const char *const argv[] = {"git", "-C", repo_path, "rev-parse", "HEAD", NULL};
    char *data = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    if (cbm_spawn_capture(argv, &data, &len, &err) != 0) {
        /* A non-zero git status just means "no HEAD here"; anything else is a
         * real degradation and is labelled rather than swallowed. */
        if (err.code != CBM_SPAWN_E_EXIT) {
            cbm_log_warn("artifact.git_head.spawn_failed", "code", err.code_name, "message",
                         err.message, "remediation", err.remediation);
        }
        free(data);
        return false;
    }

    size_t line = 0;
    while (line < len && data[line] != '\\n' && data[line] != '\\r') {
        line++;
    }
    if (line >= bufsz) {
        line = bufsz - ART_NUL;
    }
    memcpy(buf, data, line);
    buf[line] = '\\0';
    free(data);
    return buf[0] != '\\0';
}"""

MERGE_DRIVER_START = """    /* Best-effort: configure merge driver */
    if (!cbm_artifact_repo_path_is_shell_safe(repo_path)) {
        return;
    }"""
MERGE_DRIVER_END = """    FILE *p = cbm_popen(cmd, "r");
    if (p) {
        (void)cbm_pclose(p);
    }
}"""

PATCHED_MERGE_DRIVER = """    /* Best-effort: configure merge driver */
    if (!cbm_artifact_repo_path_is_shell_safe(repo_path)) {
        return;
    }

    /* Shell-free spawn (#227). */
    const char *const argv[] = {"git",  "-C", repo_path, "config", "merge.ours.driver",
                                "true", NULL};
    char *data = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    if (cbm_spawn_capture(argv, &data, &len, &err) != 0 && err.code != CBM_SPAWN_E_EXIT) {
        cbm_log_warn("artifact.merge_driver.spawn_failed", "code", err.code_name, "message",
                     err.message, "remediation", err.remediation);
    }
    free(data);
}"""


def patch_source(source: str) -> str:
    """Route every artifact.c git invocation through the shell-free spawn (#227)."""
    verify_source_hash(source, EXPECTED_SOURCE_SHA256, SOURCE_NAME)
    patched = replace_once(source, ORIGINAL_INCLUDES, PATCHED_INCLUDES, "artifact includes")
    patched = replace_once(patched, ORIGINAL_NULL_DEV, PATCHED_NULL_DEV, "artifact null-device")
    patched = replace_once(
        patched, ORIGINAL_SHELL_SAFE_DOC, PATCHED_SHELL_SAFE_DOC, "shell-safe validator doc"
    )
    patched = replace_span(
        patched, HEAD_HASH_START, HEAD_HASH_END, PATCHED_HEAD_HASH, "git_head_hash"
    )
    patched = replace_span(
        patched,
        MERGE_DRIVER_START,
        MERGE_DRIVER_END,
        PATCHED_MERGE_DRIVER,
        "merge-driver configuration",
    )
    return patched


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
