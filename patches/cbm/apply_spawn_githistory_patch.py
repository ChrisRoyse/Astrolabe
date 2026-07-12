#!/usr/bin/env python3
"""#227: build-local overlay routing pass_githistory.c's `git log` through cbm_spawn_capture.

The change-coupling pass ran `git log --name-only --pretty=format:... --since="1 year ago"`
as a command STRING through cbm_popen (cmd.exe /c on Windows). The pretty format
itself had to be `%%H` because the string went through snprintf and then a shell
that treats `%` as a substitution sigil. With an explicit argv, the format string
and the `--since=1 year ago` argument are passed to git byte-for-byte, and no
shell exists to interpret either.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from astro_overlay import replace_once, replace_span, verify_source_hash  # noqa: E402

SOURCE_NAME = "src/pipeline/pass_githistory.c"
EXPECTED_SOURCE_SHA256 = "d69b00f49b68263892259325e7162ff856d98eb5f87700d34d6b30ba5dc5e0d5"

ORIGINAL_INCLUDES = """#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/str_util.h"
"""

PATCHED_INCLUDES = """#include "astro_spawn.h"
#include "foundation/compat.h"
#include "foundation/str_util.h"
"""

LOG_START = """/* ── git log parsing (popen "git log") ────────────────────────────── */"""
LOG_END = """    cbm_pclose(fp);
    *out = commits;
    *out_count = count;
    return 0;
}"""

PATCHED_LOG = """/* ── git log parsing (shell-free `git log` spawn, #227) ───────────── */

static int parse_git_log(const char *repo_path, commit_t **out, int *out_count) {
    *out = NULL;
    *out_count = 0;

    /* Defence in depth (#227/#228): the spawn below never reaches a shell, but a
     * repo path carrying shell metacharacters is still refused. */
    if (!cbm_validate_shell_arg(repo_path)) {
        return CBM_NOT_FOUND;
    }

    /* Shell-free spawn: git receives every element verbatim. `--since=1 year ago`
     * needs no quotes because there is no word splitting, and the pretty format
     * keeps its single `%` because no cmd.exe substitutes %VAR% at parse time. */
    const char *const argv[] = {"git",
                                "-C",
                                repo_path,
                                "log",
                                "--name-only",
                                "--pretty=format:COMMIT:%H:%ct",
                                "--since=1 year ago",
                                "--max-count=10000",
                                NULL};
    char *data = NULL;
    size_t data_len = 0;
    cbm_spawn_error_t err;
    if (cbm_spawn_capture(argv, &data, &data_len, &err) != 0) {
        /* A non-zero git status means "no history here"; anything else is a real
         * degradation and is labelled rather than swallowed. */
        if (err.code != CBM_SPAWN_E_EXIT) {
            cbm_log_warn("githistory.git_log.spawn_failed", "code", err.code_name, "message",
                         err.message, "remediation", err.remediation);
        }
        free(data);
        return CBM_NOT_FOUND;
    }

    int cap = CBM_SZ_64;
    commit_t *commits = malloc(cap * sizeof(commit_t));
    int count = 0;
    commit_t current = {0};

    char *cursor = data;
    char *end = data + data_len;
    while (cursor < end) {
        char *line = cursor;
        char *newline = (char *)memchr(cursor, '\\n', (size_t)(end - cursor));
        if (newline) {
            *newline = '\\0';
            cursor = newline + SKIP_ONE;
        } else {
            cursor = end;
        }
        size_t len = strlen(line);
        while (len > 0 && line[len - SKIP_ONE] == '\\r') {
            line[--len] = '\\0';
        }
        if (len == 0) {
            continue;
        }

        if (strncmp(line, "COMMIT:", SLEN("COMMIT:")) == 0) {
            if (current.count > 0) {
                if (count >= cap) {
                    cap *= PAIR_LEN;
                    commits = safe_realloc(commits, cap * sizeof(commit_t));
                }
                commits[count++] = current;
                memset(&current, 0, sizeof(current));
            }
            /* Parse the unix timestamp from "COMMIT:<hash>:<unix_epoch>".
             * Older callers / stripped-down git output without %ct land on 0. */
            const char *hash_end = strchr(line + SLEN("COMMIT:"), ':');
            if (hash_end) {
                current.timestamp = strtoll(hash_end + 1, NULL, 10);
            }
            continue;
        }

        if (cbm_is_trackable_file(line)) {
            commit_add_file(&current, line);
        }
    }
    if (current.count > 0) {
        if (count >= cap) {
            cap *= PAIR_LEN;
            commits = safe_realloc(commits, cap * sizeof(commit_t));
        }
        commits[count++] = current;
    } else {
        commit_free(&current);
    }

    free(data);
    *out = commits;
    *out_count = count;
    return 0;
}"""


def patch_source(source: str) -> str:
    """Route pass_githistory.c's git log through the shell-free spawn (#227)."""
    verify_source_hash(source, EXPECTED_SOURCE_SHA256, SOURCE_NAME)
    patched = replace_once(source, ORIGINAL_INCLUDES, PATCHED_INCLUDES, "githistory includes")
    patched = replace_span(patched, LOG_START, LOG_END, PATCHED_LOG, "parse_git_log")
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
