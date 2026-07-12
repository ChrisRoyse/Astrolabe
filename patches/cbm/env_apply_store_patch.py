#!/usr/bin/env python3
"""Generate the hash-checked Astrolabe store-resolution overlay for CBM (#240/#241).

`vendor/codebase-memory-mcp` is a byte-pinned subtree and is never edited. This
script reads a pinned CBM source, verifies its SHA-256, applies an exact,
reviewed sequence of textual edits, and writes a build-local overlay that
`patches/cbm/Makefile.cbm` compiles into `libcbm.a` in place of the vendored
object. If upstream moves, the hash check fails loudly instead of silently
patching the wrong bytes.

Two defects are repaired, one class: a resolver that can fail, consumed as if it
cannot.

#240 — `cbm_resolve_cache_dir()` learns an explicit override
    (`cbm_astro_cache_dir_override()`, implemented in `patches/cbm/env_store_config.c`)
    that the Rust host sets by **passing the store path across the FFI boundary as
    a parameter**. Rust's `std::env::set_var` writes only the Win32 environment
    block (`SetEnvironmentVariableW`), while `cbm_safe_getenv` walks the C
    runtime's `environ` array; Windows synchronises those two stores only for the
    environment a process inherits, so env-as-IPC silently does nothing across
    this boundary.

#241 — `cbm_safe_getenv` detects `snprintf` truncation and fails closed with a
    named code instead of silently resolving a different directory; the store-path
    environment buffers are widened from `CBM_SZ_256` to `CBM_SZ_1K`, the size of
    the result buffer the resolvers actually publish; and every site that fed
    `cbm_resolve_cache_dir()` straight into `snprintf("%s", ...)` without a NULL
    check now refuses.

Usage:
    env_apply_store_patch.py --file src/foundation/platform.c <source> <output>

Verify with `python -B scripts/test-cbm-env-store-patch.py`. Temporary
integration patch; intended for upstreaming to CBM.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

# ── src/foundation/platform.c ─────────────────────────────────────────

PLATFORM_INCLUDE_OLD = """#include "platform.h"

#include "foundation/constants.h"
"""
PLATFORM_INCLUDE_NEW = """#include "platform.h"

#include "env_store_config.h"
#include "foundation/constants.h"
"""

PLATFORM_SAFE_GETENV_OLD = """const char *cbm_safe_getenv(const char *name, char *buf, size_t buf_sz, const char *fallback) {
    char **env = CBM_ENVIRON;
    if (env) {
        size_t nlen = strlen(name);
        for (; *env; env++) {
            if (strncmp(*env, name, nlen) == 0 && (*env)[nlen] == '=') {
                snprintf(buf, buf_sz, "%s", *env + nlen + SKIP_ONE);
                return buf;
            }
        }
    }
    if (fallback) {
        snprintf(buf, buf_sz, "%s", fallback);
        return buf;
    }
    buf[0] = '\\0';
    return NULL;
}
"""

PLATFORM_SAFE_GETENV_NEW = """/* Copy an environment value into the caller's buffer, refusing to truncate.
 *
 * #241: the vendored implementation discarded snprintf's return value, so a value
 * longer than the caller's buffer was silently cut and the library then resolved a
 * DIFFERENT path than the one configured — a store nobody asked for, with no error.
 * A truncated value is never a usable answer here, so truncation is detected
 * (snprintf returns the length it WOULD have written), the buffer is emptied so no
 * partial value can escape, a {code, message, remediation} fault is published, and
 * the read fails closed. */
static const char *cbm_astro_copy_env_value(const char *name, const char *value, char *buf,
                                            size_t buf_sz) {
    int written = snprintf(buf, buf_sz, "%s", value);
    if (written < 0 || (size_t)written >= buf_sz) {
        buf[0] = '\\0';
        cbm_astro_env_record_truncation(name, strlen(value), buf_sz);
        return NULL;
    }
    return buf;
}

const char *cbm_safe_getenv(const char *name, char *buf, size_t buf_sz, const char *fallback) {
    if (!name || !buf || buf_sz == 0) {
        return NULL;
    }
    char **env = CBM_ENVIRON;
    if (env) {
        size_t nlen = strlen(name);
        for (; *env; env++) {
            if (strncmp(*env, name, nlen) == 0 && (*env)[nlen] == '=') {
                return cbm_astro_copy_env_value(name, *env + nlen + SKIP_ONE, buf, buf_sz);
            }
        }
    }
    if (fallback) {
        return cbm_astro_copy_env_value(name, fallback, buf, buf_sz);
    }
    buf[0] = '\\0';
    return NULL;
}
"""

PLATFORM_RESOLVE_OLD = """const char *cbm_resolve_cache_dir(void) {
    static char buf[CBM_SZ_1K];
    char tmp[CBM_SZ_256] = "";
    cbm_safe_getenv("CBM_CACHE_DIR", tmp, sizeof(tmp), NULL);
    if (tmp[0]) {
        snprintf(buf, sizeof(buf), "%s", tmp);
        cbm_normalize_path_sep(buf);
        return buf;
    }
    const char *home = cbm_get_home_dir();
    if (!home) {
        return NULL;
    }
    snprintf(buf, sizeof(buf), "%s/.cache/codebase-memory-mcp", home);
    return buf;
}
"""

PLATFORM_RESOLVE_NEW = """const char *cbm_resolve_cache_dir(void) {
    static char buf[CBM_SZ_1K];
    char tmp[CBM_SZ_1K] = "";

    /* #240: explicit configuration wins, and it is the only mechanism that works
     * from the Rust host. `std::env::set_var` writes the Win32 environment block;
     * CBM_ENVIRON above is the C runtime's array. Windows keeps those two stores
     * in sync only for the environment the process INHERITED, so a runtime env
     * mutation is invisible here and CBM would resolve the home store instead —
     * silently. The host therefore passes the store across the FFI boundary as a
     * parameter (cbm_astro_set_cache_dir), not as an environment variable. */
    const char *override_dir = cbm_astro_cache_dir_override();
    if (override_dir) {
        snprintf(buf, sizeof(buf), "%s", override_dir);
        cbm_normalize_path_sep(buf);
        return buf;
    }

    cbm_safe_getenv("CBM_CACHE_DIR", tmp, sizeof(tmp), NULL);
    /* #241: an unreadable CBM_CACHE_DIR must NOT fall through to the home store.
     * Falling through is exactly how a configured store silently relocates into
     * the operator's profile (#194). Refuse; the fault is already published. */
    if (cbm_astro_env_faulted_for("CBM_CACHE_DIR")) {
        return NULL;
    }
    if (tmp[0]) {
        snprintf(buf, sizeof(buf), "%s", tmp);
        cbm_normalize_path_sep(buf);
        return buf;
    }
    const char *home = cbm_get_home_dir();
    if (!home) {
        cbm_astro_env_record_unresolvable_store();
        return NULL;
    }
    int written = snprintf(buf, sizeof(buf), "%s/.cache/codebase-memory-mcp", home);
    if (written < 0 || (size_t)written >= sizeof(buf)) {
        cbm_astro_env_record_truncation("HOME", (size_t)(written < 0 ? 0 : written), sizeof(buf));
        return NULL;
    }
    return buf;
}
"""

# The remaining three store-path resolvers (cbm_get_home_dir, cbm_app_config_dir,
# cbm_app_local_dir) read an environment value into a 256-byte scratch buffer and
# then copy it into a 1024-byte result buffer. The 256 was an artificial cut with
# no relationship to what the library can represent: on Windows a home or app-data
# path longer than 255 bytes is routine, and the library silently resolved a
# different directory. Widen the scratch buffer to the size of the result buffer
# the function already publishes; anything that still does not fit is refused by
# cbm_safe_getenv above rather than truncated.
PLATFORM_TMP_OLD = '    char tmp[CBM_SZ_256] = "";\n'
PLATFORM_TMP_NEW = '    char tmp[CBM_SZ_1K] = "";\n'

# ── src/pipeline/pipeline.c ───────────────────────────────────────────

PIPELINE_RESOLVE_DB_OLD = """    if (p->db_path) {
        snprintf(path, 1024, "%s", p->db_path);
    } else {
        snprintf(path, 1024, "%s/%s.db", cbm_resolve_cache_dir(), p->project_name);
    }
    return path;
}
"""

PIPELINE_RESOLVE_DB_NEW = """    if (p->db_path) {
        snprintf(path, 1024, "%s", p->db_path);
        return path;
    }
    /* #241: cbm_resolve_cache_dir() returns NULL when no store can be resolved
     * (platform.c). Passing that pointer to "%s" is undefined behaviour, and the
     * one caller of this function already treats NULL as "no database". Refuse. */
    const char *cache_dir = cbm_resolve_cache_dir();
    if (!cache_dir) {
        free(path);
        return NULL;
    }
    snprintf(path, 1024, "%s/%s.db", cache_dir, p->project_name);
    return path;
}
"""

# ── src/cli/cli.c ─────────────────────────────────────────────────────

CLI_GET_CACHE_DIR_OLD = """    snprintf(buf, sizeof(buf), "%s", cbm_resolve_cache_dir());
    return buf;
}
"""

CLI_GET_CACHE_DIR_NEW = """    /* #241: a non-NULL home no longer implies a resolvable store — an unreadable
     * CBM_CACHE_DIR now fails closed instead of relocating the store. NULL here is
     * a real outcome, and "%s" on NULL is undefined behaviour. */
    const char *cache_dir = cbm_resolve_cache_dir();
    if (!cache_dir) {
        return NULL;
    }
    snprintf(buf, sizeof(buf), "%s", cache_dir);
    return buf;
}
"""

CLI_CONFIG_CACHE_OLD = """    char cache_dir[CLI_BUF_1K];
    snprintf(cache_dir, sizeof(cache_dir), "%s", cbm_resolve_cache_dir());

    cbm_config_t *cfg = cbm_config_open(cache_dir);
"""

CLI_CONFIG_CACHE_NEW = """    /* #241: see get_cache_dir(). The resolver can fail even with a good home. */
    const char *resolved_cache = cbm_resolve_cache_dir();
    if (!resolved_cache) {
        (void)fprintf(stderr, "error: cannot resolve the CBM cache directory\\n");
        return CLI_TRUE;
    }
    char cache_dir[CLI_BUF_1K];
    snprintf(cache_dir, sizeof(cache_dir), "%s", resolved_cache);

    cbm_config_t *cfg = cbm_config_open(cache_dir);
"""

# ── src/mcp/mcp.c ─────────────────────────────────────────────────────

MCP_SESSION_DB_OLD = """    const char *home = cbm_get_home_dir();
    if (home) {
        char db_check[CBM_SZ_1K];
        snprintf(db_check, sizeof(db_check), "%s/%s.db", cbm_resolve_cache_dir(),
                 srv->session_project);
"""

MCP_SESSION_DB_NEW = """    const char *home = cbm_get_home_dir();
    /* #241: a resolvable home no longer implies a resolvable store, and "%s" on a
     * NULL cache directory is undefined behaviour. Resolve first, then check. */
    const char *session_cache = cbm_resolve_cache_dir();
    if (home && session_cache) {
        char db_check[CBM_SZ_1K];
        snprintf(db_check, sizeof(db_check), "%s/%s.db", session_cache, srv->session_project);
"""

# ── src/ui/http_server.c ──────────────────────────────────────────────

HTTP_UI_CONFIG_OLD = """    const char *lang = NULL;
    char cache_dir[1024];
    snprintf(cache_dir, sizeof(cache_dir), "%s", cbm_resolve_cache_dir());
    cbm_config_t *cfg = cbm_config_open(cache_dir);
    if (cfg) {
"""

HTTP_UI_CONFIG_NEW = """    const char *lang = NULL;
    char cache_dir[1024];
    /* #241: this site passed cbm_resolve_cache_dir() straight to "%s" with no NULL
     * check at all. The resolver returns NULL whenever the store cannot be
     * resolved, which is undefined behaviour here. Serve the detected language
     * from the request instead of dereferencing NULL. */
    const char *resolved = cbm_resolve_cache_dir();
    cbm_config_t *cfg = NULL;
    if (resolved) {
        snprintf(cache_dir, sizeof(cache_dir), "%s", resolved);
        cfg = cbm_config_open(cache_dir);
    }
    if (cfg) {
"""

# Ordered edit programme per pinned source. Each entry is
# (old, new, expected_occurrences); the edits are applied in order, so an edit may
# depend on an earlier one having already run.
PATCHES: dict[str, dict[str, object]] = {
    "src/foundation/platform.c": {
        "sha256": "3a9ca1b91a54ec63ec7b1972c2dbfb9af46057fe5eea6a5bb2083aae51da62ca",
        "edits": [
            (PLATFORM_INCLUDE_OLD, PLATFORM_INCLUDE_NEW, 1),
            (PLATFORM_SAFE_GETENV_OLD, PLATFORM_SAFE_GETENV_NEW, 1),
            (PLATFORM_RESOLVE_OLD, PLATFORM_RESOLVE_NEW, 1),
            # cbm_resolve_cache_dir's own scratch buffer was rewritten above, so the
            # three remaining 256-byte scratch buffers are the ones left.
            (PLATFORM_TMP_OLD, PLATFORM_TMP_NEW, 3),
        ],
    },
    "src/pipeline/pipeline.c": {
        "sha256": "9404b8d46c7d9fab681866fd8b4a0f38151091e5eeef1089f8649e7c6c2f8ebe",
        "edits": [(PIPELINE_RESOLVE_DB_OLD, PIPELINE_RESOLVE_DB_NEW, 1)],
    },
    "src/cli/cli.c": {
        "sha256": "8aedb88dae4a40e03bb0c1855f856eb4fff0a9ce9f6dd33c6af22fbdcf3dee38",
        "edits": [
            (CLI_GET_CACHE_DIR_OLD, CLI_GET_CACHE_DIR_NEW, 1),
            (CLI_CONFIG_CACHE_OLD, CLI_CONFIG_CACHE_NEW, 1),
        ],
    },
    "src/mcp/mcp.c": {
        "sha256": "18a803f3fd93fd2269e3f1198cd65587e707df8c415970b9dd6121f45e63d234",
        "edits": [(MCP_SESSION_DB_OLD, MCP_SESSION_DB_NEW, 1)],
    },
    "src/ui/http_server.c": {
        "sha256": "7c931ac4feadb9f40c35e962df2ad7ece81565bcf7908a2f36564e411c5cd9cb",
        "edits": [(HTTP_UI_CONFIG_OLD, HTTP_UI_CONFIG_NEW, 1)],
    },
}

PATCHED_FILES = tuple(PATCHES)


def patch_source(relative: str, source: str) -> str:
    """Apply the reviewed overlay for `relative` to its pinned source text."""
    spec = PATCHES.get(relative)
    if spec is None:
        raise ValueError(
            f"no CBM store overlay is declared for {relative}; "
            f"declared files: {', '.join(PATCHED_FILES)}"
        )

    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    expected = spec["sha256"]
    if digest != expected:
        raise ValueError(
            f"unexpected {relative} source hash: expected {expected}, got {digest}. "
            "The CBM vendor pin moved; re-review this overlay against the new source "
            "before updating the hash."
        )

    patched = source
    for index, (old, new, count) in enumerate(spec["edits"]):  # type: ignore[assignment]
        found = patched.count(old)
        if found != count:
            raise ValueError(
                f"{relative} edit {index}: expected {count} occurrence(s) of the pinned "
                f"fragment, found {found}"
            )
        patched = patched.replace(old, new)
    if patched == source:
        raise ValueError(f"{relative} overlay produced no change; the patch is not load-bearing")
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
