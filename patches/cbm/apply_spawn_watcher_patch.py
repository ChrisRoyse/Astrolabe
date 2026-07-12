#!/usr/bin/env python3
"""#227: build-local overlay routing watcher.c's git helpers through cbm_spawn_capture.

The watcher polls git four ways (rev-parse --git-dir, rev-parse HEAD,
status --porcelain, ls-files). Each composed a command STRING for cbm_popen —
i.e. cmd.exe /c on Windows. Each now spawns git with an explicit argv, so the
watched root path is never re-parsed by a shell.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from astro_overlay import replace_once, replace_span, verify_source_hash  # noqa: E402

SOURCE_NAME = "src/watcher/watcher.c"
EXPECTED_SOURCE_SHA256 = "869086cb4439b93dddf429d7b57d1a88538b9930679282e0451f65e5289a60b4"

ORIGINAL_INCLUDES = """#include "watcher/watcher.h"
#include "store/store.h"
"""

PATCHED_INCLUDES = """#include "astro_spawn.h"
#include "watcher/watcher.h"
#include "store/store.h"
"""

HELPERS_START = """/* Portable command pieces: cbm_popen runs through cmd.exe on Windows, which does"""
HELPERS_END = """    cbm_pclose(fp);
    return count;
}"""

PATCHED_HELPERS = """/* Shell-free git helpers (#227): every git call below hands an explicit argv to
 * cbm_spawn_capture (CreateProcessW / posix_spawnp). No cmd.exe and no /bin/sh
 * parse the watched root path, so quoting rules, %VAR% expansion and the
 * platform null-device redirection (`2>NUL` / `2>/dev/null`) are gone — the
 * spawner binds the child's stderr to the null device itself. */

/* A non-zero git status is an ordinary answer (not a repo, no HEAD, ...). Every
 * other failure is a real degradation and gets labelled rather than swallowed. */
static void watcher_log_spawn_failure(const char *event, const cbm_spawn_error_t *err) {
    if (err->code == CBM_SPAWN_E_EXIT) {
        return;
    }
    cbm_log_warn(event, "code", err->code_name, "message", err->message, "remediation",
                 err->remediation);
}

/* True when the child's first output line carries content — the upstream
 * "one porcelain line means dirty" semantics, without a line buffer. */
static bool git_first_line_nonempty(const char *data, size_t len) {
    size_t line = 0;
    while (line < len && data[line] != '\\n' && data[line] != '\\r') {
        line++;
    }
    return line > 0;
}

static bool is_git_repo(const char *root_path) {
    const char *const argv[] = {"git", "-C", root_path, "rev-parse", "--git-dir", NULL};
    char *data = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    int rc = cbm_spawn_capture(argv, &data, &len, &err);
    if (rc != 0) {
        watcher_log_spawn_failure("watcher.is_git_repo.spawn_failed", &err);
    }
    free(data);
    return rc == 0;
}

static int git_head(const char *root_path, char *out, size_t out_size) {
    if (!out || out_size == 0) {
        return CBM_NOT_FOUND;
    }
    const char *const argv[] = {"git", "-C", root_path, "rev-parse", "HEAD", NULL};
    char *data = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    if (cbm_spawn_capture(argv, &data, &len, &err) != 0) {
        watcher_log_spawn_failure("watcher.git_head.spawn_failed", &err);
        free(data);
        return CBM_NOT_FOUND;
    }

    size_t line = 0;
    while (line < len && data[line] != '\\n' && data[line] != '\\r') {
        line++;
    }
    if (line >= out_size) {
        line = out_size - SKIP_ONE;
    }
    memcpy(out, data, line);
    out[line] = '\\0';
    bool captured = len > 0;
    free(data);
    return captured ? 0 : CBM_NOT_FOUND;
}

/* Returns true if working tree has changes (modified, untracked, etc.).
 * Also checks submodules via `git submodule foreach` to detect uncommitted
 * changes inside submodules that `git status` alone would not report. */
static bool git_is_dirty(const char *root_path) {
    const char *const argv[] = {
        "git",         "--no-optional-locks",      "-C", root_path, "status",
        "--porcelain", "--untracked-files=normal", NULL};
    char *data = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    if (cbm_spawn_capture(argv, &data, &len, &err) != 0) {
        watcher_log_spawn_failure("watcher.git_status.spawn_failed", &err);
        free(data);
        return false;
    }
    bool dirty = git_first_line_nonempty(data, len);
    free(data);

    if (dirty) {
        return true;
    }

#if !defined(_WIN32)
    /* Check submodules: uncommitted changes inside a submodule are invisible
     * to the parent's git status. `git submodule foreach` runs its argument in
     * git's OWN shell inside each submodule; that argument is a compile-time
     * constant with no interpolation, so nothing from the environment reaches a
     * shell. POSIX-only for parity with upstream (Apple Git lacks
     * --recurse-submodules, and the inner command is POSIX shell syntax). */
    const char *const sub_argv[] = {
        "git",     "--no-optional-locks", "-C",
        root_path, "submodule",           "foreach",
        "--quiet", "--recursive",         "git status --porcelain --untracked-files=normal",
        NULL};
    char *sub_data = NULL;
    size_t sub_len = 0;
    if (cbm_spawn_capture(sub_argv, &sub_data, &sub_len, &err) != 0) {
        watcher_log_spawn_failure("watcher.git_submodule_status.spawn_failed", &err);
        free(sub_data);
        return false;
    }
    dirty = git_first_line_nonempty(sub_data, sub_len);
    free(sub_data);
#endif
    return dirty;
}

/* Count tracked files via git ls-files */
static int git_file_count(const char *root_path) {
    const char *const argv[] = {"git", "-C", root_path, "ls-files", NULL};
    char *data = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    if (cbm_spawn_capture(argv, &data, &len, &err) != 0) {
        watcher_log_spawn_failure("watcher.git_file_count.spawn_failed", &err);
        free(data);
        return 0;
    }

    /* One tracked file per line. */
    int count = 0;
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\\n') {
            count++;
        }
    }
    free(data);
    return count;
}"""

ORIGINAL_WATCH_COMMENT = """    /* Reject paths with shell metacharacters — all git helpers use popen/system */
    if (!cbm_validate_shell_arg(root_path)) {"""

PATCHED_WATCH_COMMENT = """    /* Defence in depth (#227/#228): the git helpers no longer use a shell at all,
     * so this is no longer the only barrier — but a path carrying shell
     * metacharacters is still refused rather than silently watched. */
    if (!cbm_validate_shell_arg(root_path)) {"""


def patch_source(source: str) -> str:
    """Route every watcher.c git helper through the shell-free spawn (#227)."""
    verify_source_hash(source, EXPECTED_SOURCE_SHA256, SOURCE_NAME)
    patched = replace_once(source, ORIGINAL_INCLUDES, PATCHED_INCLUDES, "watcher includes")
    patched = replace_span(patched, HELPERS_START, HELPERS_END, PATCHED_HELPERS, "watcher git helpers")
    patched = replace_once(
        patched, ORIGINAL_WATCH_COMMENT, PATCHED_WATCH_COMMENT, "watcher validator comment"
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
