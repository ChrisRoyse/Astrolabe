#!/usr/bin/env python3
"""#227: build-local overlay routing git_context.c's git shell-outs through cbm_spawn_capture.

Before: a command STRING was composed and handed to cbm_popen(), which executes
`cmd.exe /c <string>` on Windows and `/bin/sh -c <string>` on POSIX — a shell
that re-parses the interpolated repo path (cmd.exe expands %VAR% at parse time,
before quoting applies).

After: git is spawned with an explicit argv array (CreateProcessW / posix_spawnp,
see patches/cbm/astro_spawn.c). No shell exists on the path, so no metacharacter
class can be interpreted and none has to be blocklisted. git_validate_repo_path
stays as defence in depth.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from astro_overlay import replace_once, replace_span, verify_source_hash  # noqa: E402

SOURCE_NAME = "src/git/git_context.c"
EXPECTED_SOURCE_SHA256 = "dcc71a52fc432ea537970ff99f3c81d8232c100fc7de0bc13757fa72e8398bcb"

ORIGINAL_INCLUDES = """#include "foundation/compat_fs.h"
#include "foundation/constants.h"
#include "foundation/str_util.h"
"""

PATCHED_INCLUDES = """#include "astro_spawn.h"
#include "foundation/constants.h"
#include "foundation/log.h"
#include "foundation/str_util.h"
"""

ORIGINAL_ENUM = """enum {
    GIT_CMD_MAX = 1024,
    GIT_OUTPUT_MAX = 4096,
};"""

PATCHED_ENUM = """enum {
    /* git + -C + <repo path> + the longest argument tail below, with headroom. */
    GIT_ARGV_MAX = 16,
};"""

CAPTURE_START = "static int git_capture(const char *repo_path, const char *git_args, char **out) {"
CAPTURE_END = """    *out = git_strdup(buf);
    return *out ? 0 : CBM_NOT_FOUND;
}"""

PATCHED_CAPTURE = """static int git_capture(const char *repo_path, const char *const *git_args, char **out) {
    if (!out) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    if (!repo_path || !git_args || !git_validate_repo_path(repo_path)) {
        return CBM_NOT_FOUND;
    }

    /* Shell-free spawn (#227): git receives this argv verbatim through
     * CreateProcessW / posix_spawnp. No cmd.exe or /bin/sh re-parses the repo
     * path, so there is no quoting to get right, no %VAR% substitution, and no
     * redirection metacharacter to escape — cbm_spawn_capture binds the child's
     * stderr to the null device itself. */
    const char *argv[GIT_ARGV_MAX];
    size_t argc = 0;
    argv[argc++] = "git";
    argv[argc++] = "-C";
    argv[argc++] = repo_path;
    for (size_t i = 0; git_args[i]; i++) {
        if (argc + 1 >= (size_t)GIT_ARGV_MAX) {
            return CBM_NOT_FOUND;
        }
        argv[argc++] = git_args[i];
    }
    argv[argc] = NULL;

    char *data = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    if (cbm_spawn_capture((const char *const *)argv, &data, &len, &err) != 0) {
        /* A non-zero git exit is an ordinary answer here (no upstream, not a
         * repo, ...). Anything else is a real degradation and is labelled. */
        if (err.code != CBM_SPAWN_E_EXIT) {
            cbm_log_warn("git.spawn_failed", "code", err.code_name, "message", err.message,
                         "remediation", err.remediation);
        }
        free(data);
        return CBM_NOT_FOUND;
    }

    char *newline = (char *)memchr(data, '\\n', len);
    if (newline) {
        *newline = '\\0';
    }
    trim_newlines(data);
    if (data[0] == '\\0') {
        free(data);
        return CBM_NOT_FOUND;
    }

    *out = data;
    return 0;
}"""

CALL_SITES = [
    (
        """    if (git_capture(path, "rev-parse --show-toplevel", &out->worktree_root) != 0) {""",
        """    if (git_capture(path, (const char *const[]){"rev-parse", "--show-toplevel", NULL},
                    &out->worktree_root) != 0) {""",
    ),
    (
        """    if (git_capture(path, "rev-parse --git-dir", &out->git_dir) != 0) {""",
        """    if (git_capture(path, (const char *const[]){"rev-parse", "--git-dir", NULL}, """
        """&out->git_dir) !=
        0) {""",
    ),
    (
        """    if (git_capture(path, "rev-parse --git-common-dir", &out->git_common_dir) != 0) {""",
        """    if (git_capture(path, (const char *const[]){"rev-parse", "--git-common-dir", NULL},
                    &out->git_common_dir) != 0) {""",
    ),
    (
        """    if (git_capture(path, "rev-parse --verify HEAD", &out->head_sha) != 0) {""",
        """    if (git_capture(path, (const char *const[]){"rev-parse", "--verify", "HEAD", NULL},
                    &out->head_sha) != 0) {""",
    ),
    (
        """    if (git_capture(path, "symbolic-ref --quiet --short HEAD", &out->branch) != 0) {""",
        """    if (git_capture(path, """
        """(const char *const[]){"symbolic-ref", "--quiet", "--short", "HEAD", NULL},
                    &out->branch) != 0) {""",
    ),
    (
        """    (void)git_capture(path, "rev-parse --path-format=absolute --git-common-dir", """
        """&abs_common_dir);""",
        """    (void)git_capture(
        path,
        (const char *const[]){"rev-parse", "--path-format=absolute", "--git-common-dir", NULL},
        &abs_common_dir);""",
    ),
    (
        """    if (git_capture(path, "merge-base HEAD @{upstream}", &out->base_sha) != 0) {""",
        """    if (git_capture(path, (const char *const[]){"merge-base", "HEAD", "@{upstream}", NULL},
                    &out->base_sha) != 0) {""",
    ),
]


def patch_source(source: str) -> str:
    """Route every git_context.c git invocation through the shell-free spawn (#227)."""
    verify_source_hash(source, EXPECTED_SOURCE_SHA256, SOURCE_NAME)
    patched = replace_once(source, ORIGINAL_INCLUDES, PATCHED_INCLUDES, "git_context includes")
    patched = replace_once(patched, ORIGINAL_ENUM, PATCHED_ENUM, "git_context sizing enum")
    patched = replace_span(patched, CAPTURE_START, CAPTURE_END, PATCHED_CAPTURE, "git_capture")
    for index, (original, replacement) in enumerate(CALL_SITES):
        patched = replace_once(patched, original, replacement, f"git_capture call site {index}")
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
