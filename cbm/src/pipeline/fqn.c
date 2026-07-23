/*
 * fqn.c — Fully Qualified Name computation for graph nodes.
 *
 * Implements the FQN scheme: project.dir.parts.name
 * Handles Python __init__.py, JS/TS index.{js,ts}, path separators.
 */
#include "pipeline/pipeline.h"
#include "foundation/compat_fs.h"
#include "foundation/constants.h"
#include "foundation/log.h"
#include "foundation/platform.h"
#include "foundation/sha256.h"

#include <stdbool.h>
#include <stddef.h> // NULL
#include <stdint.h> // uint32_t
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // strdup
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#endif

/* Max bytes for a derived project name. The name becomes a single filename
 * component: the C side writes "<cache>/<name>.db" (+ sidecars ".db-wal" /
 * ".db.corrupt"), and the Rust host writes "<name>.astrolabe-lowered.db" (21
 * bytes) and "<name>.astrolabe-vault" (16 bytes) from the SAME derived name, so
 * the component must stay under the filesystem's 255-byte per-component limit
 * (NTFS MAX_PATH component == 255). A cap of 128 keeps every consumer's longest
 * suffix (128 + 21 = 149) comfortably under 255. #571 hex-encodes each
 * non-ASCII byte to 2 chars, so a deep CJK path (or any deep tree) can flatten
 * far past 255 and make the DB file un-openable (#624/#409) — this cap is the
 * single structural fix, applied at the one derivation point below. */
#define FQN_MAX_NAME_LEN 128

/* Disambiguating hash suffix width: the first 8 bytes of SHA-256 rendered as 16
 * lowercase hex chars ([0-9a-f]). 64 bits of digest makes collisions between two
 * distinct long paths astronomically unlikely. */
#define FQN_HASH_HEX_LEN 16

/* Bytes of the sanitized name kept when it overflows the cap: the tail of the
 * name (the corpus directory end — the human-meaningful part), plus one '-'
 * separator, plus the hash, sums to exactly FQN_MAX_NAME_LEN. */
#define FQN_NAME_TAIL_LEN (FQN_MAX_NAME_LEN - 1 - FQN_HASH_HEX_LEN)

/* File nodes are containers, not language modules. Their QN must therefore
 * retain the complete normalized relative path rather than the extensionless
 * module spelling used by symbols/imports. Domain-separate the path digest in
 * the visible QN so File aliases cannot collide merely because two languages
 * share a stem (foo.rs / foo.ts), or because dots and directory separators
 * flatten to the same display spelling (a.b/c.rs / a/b.c.rs).
 *
 * The exact path remains separately stored in file_path and participates in
 * the stable atom_id. This digest is only the deterministic, injective-in-
 * practice File lookup alias needed by graph passes. */
#define FQN_FILE_DOMAIN ".__file_path_sha256__."

/* ── Internal helpers ─────────────────────────────────────────────── */

/* Build a dot-joined string from segments. Returns heap-allocated string. */
static char *join_segments(const char **segments, size_t count) {
    if (count == 0) {
        return strdup("");
    }
    size_t total = 0;
    for (size_t i = 0; i < count; i++) {
        size_t segment_len = strlen(segments[i]);
        if (total > SIZE_MAX - segment_len || (i > 0 && total + segment_len == SIZE_MAX)) {
            return NULL;
        }
        total += segment_len;
        if (i > 0) {
            total++; /* dot separator */
        }
    }
    char *result = malloc(total + SKIP_ONE);
    if (!result) {
        return NULL;
    }
    char *p = result;
    for (size_t i = 0; i < count; i++) {
        if (i > 0) {
            *p++ = '.';
        }
        size_t len = strlen(segments[i]);
        memcpy(p, segments[i], len);
        p += len;
    }
    *p = '\0';
    return result;
}

/* Strip file extension from the last path component. */
static void strip_file_extension(char *path) {
    char *last_slash = strrchr(path, '/');
    char *start = last_slash ? last_slash + SKIP_ONE : path;
    char *ext = strrchr(start, '.');
    if (ext) {
        *ext = '\0';
    }
}

/* Tokenize path by '/' into a caller-sized segments array. */
static size_t tokenize_path(char *path, const char **segments) {
    size_t count = 0;
    if (path[0] == '\0') {
        return 0;
    }
    char *tok = path;
    while (tok && *tok) {
        char *slash = strchr(tok, '/');
        if (slash) {
            *slash = '\0';
        }
        if (tok[0] != '\0') {
            segments[count++] = tok;
        }
        tok = slash ? slash + SKIP_ONE : NULL;
    }
    return count;
}

/* Strip __init__ (Python) / index (JS/TS) from the last segment when a
 * symbol name is provided. Keeps it when no name is given to avoid QN
 * collision with Folder nodes for the same directory. */
static void strip_init_or_index(const char **segments, size_t *seg_count, const char *name) {
    if (*seg_count <= SKIP_ONE) {
        return;
    }
    const char *last = segments[*seg_count - SKIP_ONE];
    if (strcmp(last, "__init__") != 0 && strcmp(last, "index") != 0) {
        return;
    }
    if (name && name[0] != '\0') {
        (*seg_count)--;
    }
}

/* ── Public API ──────────────────────────────────────────────────── */

static char *compute_file_fqn(const char *project, const char *rel_path) {
    if (!project || project[0] == '\0' || !rel_path || rel_path[0] == '\0') {
        cbm_log_error("fqn.file_identity_failed", "code", "CBM_FILE_QN_INPUT_INVALID",
                      "project", project ? project : "<null>", "path",
                      rel_path ? rel_path : "<null>", "message",
                      "file identity requires a non-empty project and relative path",
                      "remediation",
                      "pass the canonical project name and discovered repository-relative path");
        return NULL;
    }

    char *normalized = strdup(rel_path);
    if (!normalized) {
        cbm_log_error("fqn.file_identity_failed", "code", "CBM_FILE_QN_ALLOC_FAILED",
                      "operation", "normalize_path", "path", rel_path, "message",
                      "file path allocation failed", "remediation",
                      "free memory and retry the complete index operation");
        return NULL;
    }
    cbm_normalize_path_sep(normalized);

    char digest[CBM_SHA256_HEX_LEN + 1];
    cbm_sha256_hex(normalized, strlen(normalized), digest);
    free(normalized);

    size_t project_len = strlen(project);
    size_t domain_len = strlen(FQN_FILE_DOMAIN);
    if (project_len > SIZE_MAX - domain_len ||
        project_len + domain_len > SIZE_MAX - CBM_SHA256_HEX_LEN) {
        cbm_log_error("fqn.file_identity_failed", "code", "CBM_FILE_QN_SIZE_OVERFLOW",
                      "project", project, "path", rel_path, "message",
                      "file qualified-name length overflowed size_t", "remediation",
                      "use a valid bounded project name and repository-relative path");
        return NULL;
    }
    size_t result_len = project_len + domain_len + CBM_SHA256_HEX_LEN;
    if (result_len == SIZE_MAX) {
        cbm_log_error("fqn.file_identity_failed", "code", "CBM_FILE_QN_SIZE_OVERFLOW",
                      "project", project, "path", rel_path, "message",
                      "file qualified-name terminator overflowed size_t", "remediation",
                      "use a valid bounded project name and repository-relative path");
        return NULL;
    }
    char *result = malloc(result_len + 1);
    if (!result) {
        cbm_log_error("fqn.file_identity_failed", "code", "CBM_FILE_QN_ALLOC_FAILED",
                      "operation", "qualified_name", "path", rel_path, "message",
                      "file qualified-name allocation failed", "remediation",
                      "free memory and retry the complete index operation");
        return NULL;
    }
    int written = snprintf(result, result_len + 1, "%s%s%s", project, FQN_FILE_DOMAIN, digest);
    if (written < 0 || (size_t)written != result_len) {
        cbm_log_error("fqn.file_identity_failed", "code", "CBM_FILE_QN_FORMAT_FAILED",
                      "project", project, "path", rel_path, "message",
                      "file qualified-name formatting was not byte-exact", "remediation",
                      "inspect the runtime formatter and rebuild the native artifact");
        free(result);
        return NULL;
    }
    return result;
}

char *cbm_pipeline_fqn_compute(const char *project, const char *rel_path, const char *name) {
    if (!project) {
        return strdup("");
    }
    if (name && strcmp(name, "__file__") == 0) {
        return compute_file_fqn(project, rel_path);
    }

    char *path = strdup(rel_path ? rel_path : "");
    if (!path) {
        return NULL;
    }
    cbm_normalize_path_sep(path);
    strip_file_extension(path);

    size_t segment_capacity = PAIR_LEN + SKIP_ONE;
    for (const char *p = path; *p; p++) {
        if (*p == '/') {
            if (segment_capacity == SIZE_MAX) {
                free(path);
                return NULL;
            }
            segment_capacity++;
        }
    }
    if (segment_capacity > SIZE_MAX / sizeof(char *)) {
        free(path);
        return NULL;
    }
    const char **segments = malloc(segment_capacity * sizeof(char *));
    if (!segments) {
        free(path);
        return NULL;
    }
    size_t seg_count = 0;
    segments[seg_count++] = project;
    seg_count += tokenize_path(path, segments + seg_count);

    strip_init_or_index(segments, &seg_count, name);

    if (name && name[0] != '\0') {
        segments[seg_count++] = name;
    }

    char *result = join_segments(segments, seg_count);
    free(segments);
    free(path);
    return result;
}

char *cbm_pipeline_fqn_module(const char *project, const char *rel_path) {
    return cbm_pipeline_fqn_compute(project, rel_path, NULL);
}

char *cbm_pipeline_fqn_module_dir(const char *project, const char *rel_path, bool module_is_dir) {
    if (!module_is_dir) {
        /* Filename-stem module (default for all but Java/Go). */
        return cbm_pipeline_fqn_module(project, rel_path);
    }
    /* Directory-module languages (Java package, Go package): the module is the
     * CONTAINING DIRECTORY — strip the basename so a sibling file in the same
     * dir shares the module QN. This MUST agree with the extraction-side
     * cbm_fqn_module_source_lang() (internal/cbm/helpers.c) so the cross-file
     * LSP caller_qn matches the def-node QN. */
    const char *src = rel_path ? rel_path : "";
    /* Strip the last path segment using either separator (the extraction side
     * normalizes too); look for the rightmost '/' or '\\'. */
    const char *last_fwd = strrchr(src, '/');
    const char *last_bwd = strrchr(src, '\\');
    const char *last_sep = last_fwd;
    if (!last_sep || (last_bwd && last_bwd > last_sep)) {
        last_sep = last_bwd;
    }
    if (!last_sep) {
        /* Root file: empty directory → module is just the project. */
        return cbm_pipeline_fqn_folder(project, "");
    }
    size_t dir_len = (size_t)(last_sep - src);
    char *dir = (char *)malloc(dir_len + 1); /* +1 for NUL */
    if (!dir) {
        return NULL;
    }
    memcpy(dir, src, dir_len);
    dir[dir_len] = '\0';
    char *res = cbm_pipeline_fqn_folder(project, dir);
    free(dir);
    return res;
}

enum {
    FQN_SEP_LEN = 1, /* one byte for the '/' separator */
    FQN_NUL_LEN = 1, /* one byte for the terminating NUL */
    FQN_DOTDOT_LEN = 2,
    FQN_MIN_PY_DOTS = 1, /* first leading dot is "current package", not a pop */
    FQN_REL_KIND_NONE = 0,
    FQN_REL_KIND_PYTHON = 1,
    FQN_REL_KIND_JS = 2,
};

/* Append a single path segment to a mutable buffer that already holds a
 * normalized slash-separated path.  Adds a '/' separator when needed,
 * returns false if the buffer would overflow. */
static bool path_append_segment(char *buf, size_t buf_size, const char *seg, size_t seg_len) {
    size_t cur = strlen(buf);
    size_t separator = cur > 0 ? FQN_SEP_LEN : 0;
    if (cur > SIZE_MAX - separator || cur + separator > SIZE_MAX - seg_len ||
        cur + separator + seg_len == SIZE_MAX) {
        return false;
    }
    size_t need = cur + separator + seg_len + FQN_NUL_LEN;
    if (need > buf_size) {
        return false;
    }
    if (cur > 0) {
        buf[cur++] = '/';
    }
    memcpy(buf + cur, seg, seg_len);
    buf[cur + seg_len] = '\0';
    return true;
}

/* Pop the last segment from a mutable slash-separated path. */
static bool path_pop_segment(char *buf) {
    if (!buf[0]) {
        return false;
    }
    char *last = strrchr(buf, '/');
    if (last) {
        *last = '\0';
    } else {
        buf[0] = '\0';
    }
    return true;
}

/* Seed `buf` with the source file's directory (strip the basename) and
 * normalize backslashes. */
static void seed_source_dir(char *buf, const char *source_rel) {
    strcpy(buf, source_rel ? source_rel : "");
    for (char *p = buf; *p; p++) {
        if (*p == '\\') {
            *p = '/';
        }
    }
    char *last = strrchr(buf, '/');
    if (last) {
        *last = '\0';
    } else {
        buf[0] = '\0';
    }
}

/* Detect the flavor of relative import based on the leading characters.
 * Returns 1 for Python dotted form (e.g. ".foo" or "..bar.baz"),
 *         2 for JS/TS slash form (e.g. "./foo" or "../bar/baz"),
 *         0 for anything not relative (caller should skip). */
static int classify_relative_import(const char *module_path) {
    if (!module_path || module_path[0] != '.') {
        return FQN_REL_KIND_NONE;
    }
    bool has_slash = strchr(module_path, '/') != NULL;
    bool js_like = module_path[FQN_SEP_LEN] == '/' ||
                   (module_path[FQN_SEP_LEN] == '.' && module_path[FQN_DOTDOT_LEN] == '/');
    if (has_slash || js_like) {
        return FQN_REL_KIND_JS;
    }
    return FQN_REL_KIND_PYTHON;
}

/* Python relative import: ".foo", "..bar.baz" → resolve against source dir. */
static int resolve_python_relative(char *buf, size_t buf_size, const char *module_path) {
    const char *p = module_path;
    size_t dot_count = 0;
    while (*p == '.') {
        dot_count++;
        p++;
    }
    for (size_t i = FQN_MIN_PY_DOTS; i < dot_count; i++) {
        if (!path_pop_segment(buf)) {
            return CBM_RELATIVE_IMPORT_INVALID;
        }
    }
    while (*p) {
        const char *seg_start = p;
        while (*p && *p != '.') {
            p++;
        }
        size_t seg_len = (size_t)(p - seg_start);
        if (seg_len > 0 && !path_append_segment(buf, buf_size, seg_start, seg_len)) {
            return CBM_RELATIVE_IMPORT_ERROR;
        }
        if (*p == '.') {
            p++;
        }
    }
    return CBM_RELATIVE_IMPORT_RESOLVED;
}

/* Strip a trailing file extension from a segment (e.g. "helpers.ts" → "helpers").
 * Returns the new segment length. */
static size_t strip_ext(const char *seg_start, size_t seg_len) {
    if (seg_len == 0) {
        return 0;
    }
    const char *seg_end = seg_start + seg_len;
    const char *dot = NULL;
    for (const char *d = seg_end; d > seg_start;) {
        d--;
        if (*d == '.') {
            dot = d;
            break;
        }
    }
    if (dot && dot > seg_start) {
        return (size_t)(dot - seg_start);
    }
    return seg_len;
}

/* JS/TS relative import: "./foo", "../bar/baz" → resolve against source dir. */
static int resolve_js_relative(char *buf, size_t buf_size, const char *module_path) {
    const char *p = module_path;
    while (*p) {
        while (*p == '/') {
            p++;
        }
        if (!*p) {
            break;
        }
        const char *seg_start = p;
        while (*p && *p != '/') {
            p++;
        }
        size_t seg_len = (size_t)(p - seg_start);
        if (seg_len == FQN_SEP_LEN && seg_start[0] == '.') {
            continue;
        }
        if (seg_len == FQN_DOTDOT_LEN && seg_start[0] == '.' && seg_start[FQN_SEP_LEN] == '.') {
            if (!path_pop_segment(buf)) {
                return CBM_RELATIVE_IMPORT_INVALID;
            }
            continue;
        }
        if (*p == '\0') {
            seg_len = strip_ext(seg_start, seg_len);
        }
        if (seg_len > 0 && !path_append_segment(buf, buf_size, seg_start, seg_len)) {
            return CBM_RELATIVE_IMPORT_ERROR;
        }
    }
    return CBM_RELATIVE_IMPORT_RESOLVED;
}

int cbm_pipeline_resolve_relative_import_checked(const char *source_rel, const char *module_path,
                                                 char **out) {
    if (!out) {
        return CBM_RELATIVE_IMPORT_ERROR;
    }
    *out = NULL;
    int kind = classify_relative_import(module_path);
    if (kind == FQN_REL_KIND_NONE) {
        return CBM_RELATIVE_IMPORT_NOT_RELATIVE;
    }
    size_t source_len = strlen(source_rel ? source_rel : "");
    size_t module_len = strlen(module_path);
    if (source_len > SIZE_MAX - module_len || source_len + module_len > SIZE_MAX - PAIR_LEN) {
        return CBM_RELATIVE_IMPORT_ERROR;
    }
    size_t buf_size = source_len + module_len + PAIR_LEN;
    char *buf = malloc(buf_size);
    if (!buf) {
        return CBM_RELATIVE_IMPORT_ERROR;
    }
    seed_source_dir(buf, source_rel);
    int status;
    if (kind == FQN_REL_KIND_PYTHON) {
        status = resolve_python_relative(buf, buf_size, module_path);
    } else {
        status = resolve_js_relative(buf, buf_size, module_path);
    }
    if (status == CBM_RELATIVE_IMPORT_RESOLVED) {
        *out = buf;
    } else {
        free(buf);
    }
    return status;
}

char *cbm_pipeline_fqn_folder(const char *project, const char *rel_dir) {
    if (!project) {
        return strdup("");
    }

    /* Work on mutable copy */
    char *dir = strdup(rel_dir ? rel_dir : "");
    if (!dir) {
        return NULL;
    }
    cbm_normalize_path_sep(dir);

    size_t segment_capacity = PAIR_LEN;
    for (const char *p = dir; *p; p++) {
        if (*p == '/') {
            if (segment_capacity == SIZE_MAX) {
                free(dir);
                return NULL;
            }
            segment_capacity++;
        }
    }
    if (segment_capacity > SIZE_MAX / sizeof(char *)) {
        free(dir);
        return NULL;
    }
    const char **segments = malloc(segment_capacity * sizeof(char *));
    if (!segments) {
        free(dir);
        return NULL;
    }
    size_t seg_count = 0;
    segments[seg_count++] = project;

    if (dir[0] != '\0') {
        char *tok = dir;
        while (tok && *tok) {
            char *slash = strchr(tok, '/');
            if (slash) {
                *slash = '\0';
            }
            if (tok[0] != '\0') {
                segments[seg_count++] = tok;
            }
            tok = slash ? slash + SKIP_ONE : NULL;
        }
    }

    char *result = join_segments(segments, seg_count);
    free(segments);
    free(dir);
    return result;
}

/* Bound a derived project name to FQN_MAX_NAME_LEN bytes so every consumer's
 * filename component ("<cache>/<name>.db" on the C side, "<name>.astrolabe-
 * lowered.db" / "<name>.astrolabe-vault" on the Rust host) stays within the
 * filesystem's 255-byte per-component limit (#624/#409). This is the SINGLE
 * derivation point; because all consumers route through cbm_project_name_from_
 * path (C pipeline, mcp session-root, Rust FFI), bounding here keeps them
 * coherent with no additional plumbing.
 *
 * Behavior:
 *  - Names within the cap are returned byte-UNCHANGED (no drift — short paths
 *    keep their historical name exactly).
 *  - Longer names are rewritten to
 *        <last FQN_NAME_TAIL_LEN sanitized bytes>-<16 hex>
 *    where the 16 hex chars are the first 8 bytes of SHA-256 over the FULL
 *    sanitized name. Two deep paths that share a truncated tail but differ
 *    anywhere in the full name still hash differently → distinct names.
 *    Deterministic: same input path → same bounded name, forever.
 *
 * We keep the TAIL (not the head): the head is the drive/home prefix, the tail
 * is the corpus directory name — the human-meaningful part. The kept tail is
 * advanced past any leading '.'/'-' so the result never begins with a dot
 * (cbm_validate_project_name rejects a leading dot); the sanitizer already
 * collapsed ".." and consecutive dashes, so no ".." can appear in any
 * substring, and the "-<hex>" suffix always ends in a validator-safe hex
 * digit. */
static char *fqn_bound_name_len(char *name) {
    if (!name) {
        return name;
    }
    size_t n = strlen(name);
    if (n <= FQN_MAX_NAME_LEN) {
        return name; /* within cap → returned byte-unchanged, no drift */
    }

    /* First 8 SHA-256 digest bytes = first 16 hex chars over the FULL name. */
    char hex[CBM_SHA256_HEX_LEN + 1];
    cbm_sha256_hex(name, n, hex);
    hex[FQN_HASH_HEX_LEN] = '\0';

    /* Keep the tail; skip any leading '.'/'-' so the spliced name is validator-
     * safe. The sanitized name has no "--"/".." runs, so this run is short and
     * cannot consume the whole tail for a real (content-bearing) path; guard the
     * degenerate all-punctuation tail by falling back to the hash alone (which
     * begins with a hex digit, itself validator-safe). */
    char *tail = name + (n - FQN_NAME_TAIL_LEN);
    while (*tail == '.' || *tail == '-') {
        tail++;
    }
    size_t tail_len = strlen(tail); /* ≤ FQN_NAME_TAIL_LEN */
    if (tail_len == 0) {
        memcpy(name, hex, FQN_HASH_HEX_LEN);
        name[FQN_HASH_HEX_LEN] = '\0';
        return name;
    }
    /* Layout: <tail_len bytes>-<16 hex>, total ≤ FQN_MAX_NAME_LEN. The buffer
     * holds n+1 bytes with n > FQN_MAX_NAME_LEN, so the write fits. memmove
     * because source (tail) and destination (name) overlap. */
    memmove(name, tail, tail_len);
    name[tail_len] = '-';
    memcpy(name + tail_len + 1, hex, FQN_HASH_HEX_LEN);
    name[tail_len + 1 + FQN_HASH_HEX_LEN] = '\0';
    return name;
}

static bool path_is_root_syntax(const char *path) {
    if (!path || !path[0]) {
        return false;
    }
    for (const char *p = path; *p; p++) {
        if (*p != '/' && *p != '\\' && *p != ':') {
            return false;
        }
    }
    return true;
}

char *cbm_project_name_from_path(const char *abs_path) {
    if (!abs_path || !abs_path[0]) {
        return strdup("root");
    }
    if (path_is_root_syntax(abs_path)) {
        return strdup("root");
    }

    /* #432: canonicalize via the long-path-safe wrapper. The old ANSI
     * `_access(...,0) + _fullpath` pair (Windows) was MAX_PATH-bound, so a source
     * file whose absolute path exceeds 260 chars failed to canonicalize and the
     * project name was derived from the raw un-normalized path. cbm_canonicalize_
     * existing_path resolves through GetFullPathNameW + cbm_path_exists
     * ("\\?\"-widened) on Windows and realpath on POSIX, returning a heap string
     * (free()) or NULL. On NULL we keep the original abs_path (no ANSI fallback). */
    char *canonical = cbm_canonicalize_existing_path(abs_path);
    const char *name_path = abs_path;
    if (canonical) {
        cbm_normalize_path_sep(canonical);
        name_path = canonical;
    }

    /* Work on mutable copy */
    char *path = strdup(name_path);
    free(canonical);
    if (!path) {
        return NULL;
    }
    size_t len = strlen(path);

    /* Normalize path separators */
    cbm_normalize_path_sep(path);

    /* Map every character that is unsafe for portable project DB names. We
     * keep derived names in [A-Za-z0-9._-], so anything else — path
     * separators, ':', spaces, '@', '+', … — must be normalized here.
     * Otherwise a repo like
     * "/home/u/my project" yields the name "home-u-my project": indexing
     * creates the DB and it shows in list_projects, but resolve_store rejects
     * the space and reports project-not-found (#349).
     *
     * Non-ASCII bytes (UTF-8 of CJK and other scripts, all >= 0x80) are NOT
     * dropped to '-' — that silently erased whole path segments and produced
     * unrecognizable / colliding names (#571). Instead each non-ASCII byte is
     * transliterated to its two lowercase hex digits, which use only [0-9a-f]
     * and therefore stay validator-safe while preserving the segment. */
    static const char hex_digits[] = "0123456789abcdef";
    char *mapped = malloc(len * 2 + 1); /* worst case: every byte → 2 hex chars */
    if (!mapped) {
        free(path);
        return strdup("root");
    }
    size_t mlen = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)path[i];
        bool safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                    c == '.' || c == '_' || c == '-';
        if (safe) {
            mapped[mlen++] = (char)c;
        } else if (c >= 0x80) {
            mapped[mlen++] = hex_digits[(c >> 4) & 0xF];
            mapped[mlen++] = hex_digits[c & 0xF];
        } else {
            mapped[mlen++] = '-';
        }
    }
    mapped[mlen] = '\0';
    free(path);
    path = mapped;
    len = mlen;

    /* Collapse consecutive dashes, and consecutive dots (the validator also
     * rejects any ".." sequence). */
    char *dst = path;
    char prev = 0;
    for (size_t i = 0; i < len; i++) {
        if ((path[i] == '-' && prev == '-') || (path[i] == '.' && prev == '.')) {
            continue;
        }
        *dst++ = path[i];
        prev = path[i];
    }
    *dst = '\0';

    /* Trim leading dashes and dots (the validator rejects a leading dot). */
    char *start = path;
    while (*start == '-' || *start == '.') {
        start++;
    }

    /* Trim trailing dashes */
    size_t slen = strlen(start);
    while (slen > 0 && start[slen - SKIP_ONE] == '-') {
        start[--slen] = '\0';
    }

    if (*start == '\0') {
        free(path);
        return strdup("root");
    }

    char *result = strdup(start);
    free(path);
    if (result) {
        result = fqn_bound_name_len(result); /* #624/#409: cap filename-component length */
    }
    return result;
}
