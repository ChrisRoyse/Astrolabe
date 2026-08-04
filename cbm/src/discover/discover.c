/*
 * discover.c — Recursive directory walk with filtering.
 *
 * Walks a repository directory tree, applying:
 *   1. Hardcoded directory skip patterns (60+ dirs like .git, node_modules)
 *   2. Hardcoded suffix filters (.pyc, .png, .wasm, etc.)
 *   3. Fast-mode additional file filters (lock files, generated suffixes, etc.)
 *   4. Gitignore-style pattern matching
 *   5. Language detection for accepted files
 */
#include "discover/discover.h"
#include "cbm.h" // CBMLanguage, CBM_LANG_COUNT, CBM_LANG_JSON

#include "foundation/constants.h"
#include "foundation/compat_fs.h"
#include "foundation/log.h"
#include "foundation/platform.h"
#include "astro_spawn.h"
#ifdef _WIN32
#include "foundation/win_utf8.h"
#endif
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h> // int64_t
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // strdup
#include <sys/stat.h>

int cbm_gitignore_match_result(const cbm_gitignore_t *gi, const char *rel_path, bool is_dir);

/* ── Hardcoded always-skip directories ──────────────────────────── */

static const char *ALWAYS_SKIP_DIRS[] = {
    /* VCS */
    ".git", ".hg", ".svn", ".worktrees",
    /* IDE */
    ".idea", ".vs", ".vscode", ".eclipse", ".claude", ".claude-worktrees", "Antigravity",
    /* Python */
    ".cache", ".eggs", ".env", ".mypy_cache", ".nox", ".pytest_cache", ".ruff_cache", ".tox",
    ".venv", "__pycache__", "env", "htmlcov", "site-packages", "venv",
    /* JS/TS */
    ".npm", ".nyc_output", ".pnpm-store", ".yarn", "bower_components", "coverage", "node_modules",
    ".next", ".nuxt", ".svelte-kit", ".angular", ".turbo", ".parcel-cache", ".docusaurus", ".expo",
    /* Build artifacts */
    "dist", "obj", "Pods", "target", "temp", "tmp", ".terraform", ".serverless", "bazel-bin",
    "bazel-out", "bazel-testlogs",
    /* Language caches */
    ".cargo", ".stack-work", ".dart_tool", "zig-cache", "zig-out", ".metals", ".bloop", ".bsp",
    ".ccls-cache", ".clangd", "elm-stuff", "_opam", ".cpcache", ".shadow-cljs",
    /* Deploy */
    ".vercel", ".netlify", "deploy", "deployed",
    /* Misc */
    ".qdrant_code_embeddings", ".tmp", CBM_REPOSITORY_STATE_DIR, "vendor", "vendored", NULL};

/* ── Ignored suffixes ───────────────────────────────── */

static const char *ALWAYS_IGNORED_SUFFIXES[] = {
    ".tmp",    "~",        ".pyc",  ".pyo",   ".o",   ".a",   ".so",  ".dll",
    ".class",  ".png",     ".jpg",  ".jpeg",  ".gif", ".ico", ".bmp", ".tiff",
    ".webp",   ".svg",     ".wasm", ".node",  ".exe", ".bin", ".dat", ".db",
    ".sqlite", ".sqlite3", ".woff", ".woff2", ".ttf", ".eot", ".otf", NULL};

static const char *FAST_IGNORED_SUFFIXES[] = {
    ".zip", ".tar",  ".gz",       ".bz2",  ".xz",  ".rar",    ".7z",      ".jar",
    ".war", ".ear",  ".mp3",      ".mp4",  ".avi", ".mov",    ".wav",     ".flac",
    ".ogg", ".mkv",  ".webm",     ".pdf",  ".doc", ".docx",   ".xls",     ".xlsx",
    ".ppt", ".pptx", ".odt",      ".ods",  ".map", ".min.js", ".min.css", ".pem",
    ".crt", ".key",  ".cer",      ".p12",  ".pb",  ".avro",   ".parquet", ".beam",
    ".elc", ".rlib", ".coverage", ".prof", ".out", ".patch",  ".diff",    NULL};

/* ── Fast-mode skip filenames ─────────────────────── */

static const char *FAST_SKIP_FILENAMES[] = {
    "LICENSE",        "LICENSE.txt",     "LICENSE.md",   "LICENSE-MIT",   "LICENSE-APACHE",
    "LICENCE",        "LICENCE.txt",     "LICENCE.md",   "CHANGELOG",     "CHANGELOG.md",
    "CHANGES.md",     "HISTORY",         "HISTORY.md",   "AUTHORS",       "AUTHORS.md",
    "CONTRIBUTORS",   "CONTRIBUTORS.md", "CODEOWNERS",   "go.sum",        "yarn.lock",
    "pnpm-lock.yaml", "Pipfile.lock",    "poetry.lock",  "Gemfile.lock",  "Cargo.lock",
    "mix.lock",       "flake.lock",      "pubspec.lock", "composer.lock", "package-lock.json",
    "configure",      "Makefile.in",     "config.guess", "config.sub",    NULL};

/* ── Fast-mode substring patterns ───────────────────── */

static const char *FAST_PATTERNS[] = {".d.ts",      ".bundle.", ".chunk.", ".generated.",
                                      ".pb.go",     "_pb2.py",  ".pb2.py", "_grpc.pb.go",
                                      "_string.go", "mock_",    "_mock.",  "_test_helpers.",
                                      ".stories.",  ".spec.",   ".test.",  NULL};

/* ── Ignored JSON filenames ──────────────────────── */

static const char *IGNORED_JSON_FILES[] = {"package.json",
                                           "package-lock.json",
                                           "tsconfig.json",
                                           "jsconfig.json",
                                           "composer.json",
                                           "composer.lock",
                                           ".codebase-memory.json",
                                           "compile_commands.json",
                                           "yarn.lock",
                                           "openapi.json",
                                           "swagger.json",
                                           "jest.config.json",
                                           ".eslintrc.json",
                                           ".prettierrc.json",
                                           ".babelrc.json",
                                           "tslint.json",
                                           "angular.json",
                                           "firebase.json",
                                           "renovate.json",
                                           "lerna.json",
                                           "turbo.json",
                                           ".stylelintrc.json",
                                           "pnpm-lock.json",
                                           "deno.json",
                                           "biome.json",
                                           "devcontainer.json",
                                           ".devcontainer.json",
                                           "launch.json",
                                           "settings.json",
                                           "extensions.json",
                                           "tasks.json",
                                           NULL};

/* ── Helper: check if string is in NULL-terminated array ─────────── */

static bool str_in_list(const char *s, const char *const *list) {
    for (int i = 0; list[i]; i++) {
#ifdef _WIN32
        /* Match the filesystem's component semantics.  FindFirstFileW returns
         * the stored spelling, but ordinary Windows lookups are
         * case-insensitive; an alternate-case state/cache directory is still
         * the same namespace object and must not be rediscovered as source. */
        if (_stricmp(s, list[i]) == 0) {
#else
        if (strcmp(s, list[i]) == 0) {
#endif
            return true;
        }
    }
    return false;
}

bool cbm_is_auxiliary_input_name(const char *filename) {
    if (!filename || !filename[0]) {
        return false;
    }
    static const char *const EXACT_NAMES[] = {"package.json",
                                              "composer.json",
                                              "tsconfig.json",
                                              "jsconfig.json",
                                              "compile_commands.json",
                                              "Cargo.toml",
                                              "go.mod",
                                              "pyproject.toml",
                                              "pubspec.yaml",
                                              "pom.xml",
                                              "build.gradle",
                                              "build.gradle.kts",
                                              "mix.exs",
                                              "requirements.txt",
                                              "Gemfile",
                                              ".codebase-memory.json",
                                              ".cbmignore",
                                              ".gitignore",
                                              ".gitattributes",
                                              NULL};
    if (str_in_list(filename, EXACT_NAMES)) {
        return true;
    }
    size_t len = strlen(filename);
    if (len >= 8 && strcmp(filename + len - 8, ".gemspec") == 0) {
        return true;
    }
    char lower[CBM_SZ_256];
    if (len >= sizeof(lower)) {
        return false;
    }
    for (size_t i = 0; i <= len; i++) {
        lower[i] = (char)tolower((unsigned char)filename[i]);
    }
    return strcmp(lower, ".env") == 0 || strncmp(lower, ".env.", 5) == 0 ||
           (len > 4 && strcmp(lower + len - 4, ".env") == 0) || strcmp(lower, "dockerfile") == 0 ||
           strncmp(lower, "dockerfile.", 11) == 0 ||
           (len > 11 && strcmp(lower + len - 11, ".dockerfile") == 0);
}

/* ── Helper: check if string ends with suffix ────────────── */

static bool ends_with(const char *s, const char *suffix) {
    size_t slen = strlen(s);
    size_t sufflen = strlen(suffix);
    if (sufflen > slen) {
        return false;
    }
    return strcmp(s + slen - sufflen, suffix) == 0;
}

/* ── Helper: check if string contains substring ───────────── */

static bool str_contains(const char *s, const char *sub) {
    return strstr(s, sub) != NULL;
}

/* ── Git global excludes resolution ───────────────────────────── */

static char *trim_ws(char *s) {
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
    return s;
}

static bool has_trailing_sep(const char *path) {
    size_t len = strlen(path);
    return len > 0 && (path[len - SKIP_ONE] == '/' || path[len - SKIP_ONE] == '\\');
}

static bool discover_path_is_absolute(const char *path);

static void path_join(char *out, size_t out_sz, const char *base, const char *rel) {
    if (!out || out_sz == 0) {
        return;
    }
    if (!base || base[0] == '\0') {
        snprintf(out, out_sz, "%s", rel ? rel : "");
    } else if (!rel || rel[0] == '\0') {
        snprintf(out, out_sz, "%s", base);
    } else if (has_trailing_sep(base)) {
        snprintf(out, out_sz, "%s%s", base, rel);
    } else {
        snprintf(out, out_sz, "%s/%s", base, rel);
    }
    cbm_normalize_path_sep(out);
}

static bool resolve_xdg_git_config_dir(char *out, size_t out_sz) {
    char env[CBM_SZ_4K];
    if (cbm_safe_getenv("XDG_CONFIG_HOME", env, sizeof(env), NULL) && env[0] != '\0') {
        snprintf(out, out_sz, "%s", env);
        cbm_normalize_path_sep(out);
        return true;
    }

    const char *home = cbm_get_home_dir();
    if (!home || home[0] == '\0') {
        return false;
    }
    path_join(out, out_sz, home, ".config");
    return out[0] != '\0';
}

typedef enum {
    GLOBAL_EXCLUDES_RESOLUTION_FAILED = -1,
    GLOBAL_EXCLUDES_DEFAULT = 0,
    GLOBAL_EXCLUDES_EXPLICIT = 1,
} global_excludes_resolution_t;

static void log_global_excludes_resolution_failed(const char *code, const char *operation,
                                                  const char *repo_path, const char *detail,
                                                  const char *native_error) {
    cbm_log_error("discover.failed", "code", code, "operation", operation, "path", repo_path,
                  "detail", detail ? detail : "", "native_error",
                  native_error ? native_error : "", "message",
                  "the complete Git global exclusion policy could not be resolved",
                  "remediation",
                  "restore Git configuration and the Git executable, then retry indexing");
}

static bool write_resolved_git_path(const char *repo_path, const char *path, char *out,
                                    size_t out_sz) {
    if (!repo_path || !repo_path[0] || !path || !path[0] || !out || out_sz == 0) {
        return false;
    }

    int written;
    if (discover_path_is_absolute(path)) {
        written = snprintf(out, out_sz, "%s", path);
    } else if (has_trailing_sep(repo_path)) {
        written = snprintf(out, out_sz, "%s%s", repo_path, path);
    } else {
        written = snprintf(out, out_sz, "%s/%s", repo_path, path);
    }
    if (written < 0 || (size_t)written >= out_sz) {
        out[0] = '\0';
        return false;
    }
    cbm_normalize_path_sep(out);
    return true;
}

static global_excludes_resolution_t resolve_default_global_excludes_path(
    const char *repo_path, char *out, size_t out_sz) {
    char xdg_config[CBM_SZ_4K];
    if (!resolve_xdg_git_config_dir(xdg_config, sizeof(xdg_config)) ||
        !write_resolved_git_path(xdg_config, "git/ignore", out, out_sz)) {
        log_global_excludes_resolution_failed(
            "CBM_DISCOVER_GLOBAL_EXCLUDE_DEFAULT_UNRESOLVED", "resolve_default_global_exclude",
            repo_path, "XDG_CONFIG_HOME and the user home directory did not yield a safe path",
            "");
        return GLOBAL_EXCLUDES_RESOLUTION_FAILED;
    }
    return GLOBAL_EXCLUDES_DEFAULT;
}

static global_excludes_resolution_t resolve_global_excludes_path(const char *repo_path, char *out,
                                                                  size_t out_sz) {
    /*
     * Git configuration is a precedence-ordered language, not an INI file:
     * system/global/local/worktree scopes, include/includeIf, environment-provided
     * config, and path interpolation all affect the effective value. Ask Git's
     * own parser through the shell-free spawn boundary instead of maintaining a
     * partial second implementation here.
     */
    const char *argv[] = {"git", "-C", repo_path, "config", "--path", "--get",
                          "core.excludesFile", NULL};
    char *data = NULL;
    size_t data_len = 0;
    cbm_spawn_error_t spawn_error;
    int spawn_rc = cbm_spawn_capture(argv, &data, &data_len, &spawn_error);
    if (spawn_rc != 0) {
        /*
         * `git config --get` returns 1, with no output, when the key has no
         * effective value. That is not a failed read: Git then uses the optional
         * XDG default. Every other exit/spawn/read outcome is a real loss of
         * policy information and must cancel discovery.
         */
        if (spawn_error.code == CBM_SPAWN_E_EXIT && spawn_error.exit_code == 1 &&
            data_len == 0) {
            free(data);
            return resolve_default_global_excludes_path(repo_path, out, out_sz);
        }

        char native_error[32];
        char detail[128];
        snprintf(native_error, sizeof(native_error), "%lu", spawn_error.os_error);
        snprintf(detail, sizeof(detail), "%s (exit=%d)", spawn_error.code_name,
                 spawn_error.exit_code);
        log_global_excludes_resolution_failed("CBM_DISCOVER_GIT_CONFIG_RESOLVE_FAILED",
                                              "resolve_core_excludes_file", repo_path, detail,
                                              native_error);
        free(data);
        return GLOBAL_EXCLUDES_RESOLUTION_FAILED;
    }

    while (data_len > 0 && (data[data_len - SKIP_ONE] == '\n' ||
                            data[data_len - SKIP_ONE] == '\r')) {
        data[--data_len] = '\0';
    }
    if (data_len == 0 || memchr(data, '\0', data_len) != NULL ||
        memchr(data, '\n', data_len) != NULL || memchr(data, '\r', data_len) != NULL) {
        log_global_excludes_resolution_failed(
            "CBM_DISCOVER_GIT_CONFIG_OUTPUT_INVALID", "decode_core_excludes_file", repo_path,
            "git config returned an empty, multiline, or embedded-NUL path", "");
        free(data);
        return GLOBAL_EXCLUDES_RESOLUTION_FAILED;
    }
    if (!write_resolved_git_path(repo_path, data, out, out_sz)) {
        log_global_excludes_resolution_failed(
            "CBM_DISCOVER_GLOBAL_EXCLUDE_PATH_INVALID", "resolve_core_excludes_file_path",
            repo_path, "the resolved core.excludesFile path is empty or exceeds the path limit",
            "");
        free(data);
        return GLOBAL_EXCLUDES_RESOLUTION_FAILED;
    }
    free(data);
    return GLOBAL_EXCLUDES_EXPLICIT;
}

/* ── Public filter functions ─────────────────────── */

bool cbm_should_skip_dir(const char *dirname, cbm_index_mode_t mode) {
    (void)mode;

    if (!dirname) {
        return false;
    }

    /* A basename alone never proves that a directory is non-source. These
     * candidates avoid unbounded walks through ordinary generated state, but
     * discovery admits their tracked descendants below. Only the safety core
     * remains non-negatable (Astrolabe #752/#965). */
    return str_in_list(dirname, ALWAYS_SKIP_DIRS);
}

bool cbm_has_ignored_suffix(const char *filename, cbm_index_mode_t mode) {
    if (!filename) {
        return false;
    }

    for (int i = 0; ALWAYS_IGNORED_SUFFIXES[i]; i++) {
        if (ends_with(filename, ALWAYS_IGNORED_SUFFIXES[i])) {
            return true;
        }
    }

    if (mode != CBM_MODE_FULL) {
        for (int i = 0; FAST_IGNORED_SUFFIXES[i]; i++) {
            if (ends_with(filename, FAST_IGNORED_SUFFIXES[i])) {
                return true;
            }
        }
    }

    return false;
}

bool cbm_should_skip_filename(const char *filename, cbm_index_mode_t mode) {
    if (!filename) {
        return false;
    }

    if (mode != CBM_MODE_FULL) {
        if (str_in_list(filename, FAST_SKIP_FILENAMES)) {
            return true;
        }
    }

    return false;
}

bool cbm_matches_fast_pattern(const char *filename, cbm_index_mode_t mode) {
    if (!filename || mode == CBM_MODE_FULL) {
        return false;
    }

    for (int i = 0; FAST_PATTERNS[i]; i++) {
        if (str_contains(filename, FAST_PATTERNS[i])) {
            return true;
        }
    }

    return false;
}

/* ── Dynamic file list ────────────────────────── */

typedef struct {
    cbm_file_info_t *files;
    int count;
    int capacity;
    /* Directories skipped during the walk (rel paths), so callers can surface
     * which subtrees were dropped (#411). strdup'd; freed by the caller via
     * cbm_discover_free_excluded or internally when not requested. */
    char **excluded;
    int excluded_count;
    int excluded_cap;
    bool failed;
} file_list_t;

static void discovery_fail(file_list_t *fl, const char *code, const char *operation,
                           const char *path, unsigned long native_error) {
    if (!fl || fl->failed) {
        return;
    }
    fl->failed = true;
    char error_buf[32];
    snprintf(error_buf, sizeof(error_buf), "%lu", native_error);
    cbm_log_error("discover.failed", "code", code, "operation", operation, "path", path ? path : "",
                  "native_error", error_buf, "message",
                  "repository discovery could not produce a complete namespace", "remediation",
                  "restore access and stable filesystem state, then retry indexing");
}

static bool grow_int_capacity(int current, int minimum, int initial, int *out) {
    if (!out || minimum < 0) {
        return false;
    }
    int candidate = current > 0 ? current : initial;
    while (candidate < minimum) {
        if (candidate > INT_MAX / PAIR_LEN) {
            return false;
        }
        candidate *= PAIR_LEN;
    }
    *out = candidate;
    return true;
}

static bool file_list_add_excluded(file_list_t *fl, const char *rel_path) {
    if (!rel_path || rel_path[0] == '\0') {
        return true;
    }
    if (fl->excluded_count >= fl->excluded_cap) {
        int new_cap = 0;
        if (!grow_int_capacity(fl->excluded_cap, fl->excluded_count + 1, CBM_SZ_64, &new_cap) ||
            (size_t)new_cap > SIZE_MAX / sizeof(char *)) {
            discovery_fail(fl, "CBM_DISCOVER_EXCLUDED_CAPACITY_OVERFLOW", "grow_excluded", rel_path,
                           0);
            return false;
        }
        char **grown = realloc(fl->excluded, (size_t)new_cap * sizeof(char *));
        if (!grown) {
            discovery_fail(fl, "CBM_DISCOVER_EXCLUDED_ALLOC_FAILED", "grow_excluded", rel_path, 0);
            return false;
        }
        fl->excluded = grown;
        fl->excluded_cap = new_cap;
    }
    char *copy = strdup(rel_path);
    if (!copy) {
        discovery_fail(fl, "CBM_DISCOVER_EXCLUDED_ALLOC_FAILED", "copy_excluded", rel_path, 0);
        return false;
    }
    fl->excluded[fl->excluded_count++] = copy;
    return true;
}

static bool fl_add(file_list_t *fl, const char *abs_path, const char *rel_path, CBMLanguage lang,
                   int64_t size, bool auxiliary, bool interpretation_input) {
    if (fl->count >= fl->capacity) {
        int new_cap = 0;
        if (!grow_int_capacity(fl->capacity, fl->count + 1, CBM_SZ_256, &new_cap) ||
            (size_t)new_cap > SIZE_MAX / sizeof(cbm_file_info_t)) {
            discovery_fail(fl, "CBM_DISCOVER_FILE_CAPACITY_OVERFLOW", "grow_files", rel_path, 0);
            return false;
        }
        cbm_file_info_t *new_files = realloc(fl->files, (size_t)new_cap * sizeof(cbm_file_info_t));
        if (!new_files) {
            discovery_fail(fl, "CBM_DISCOVER_FILE_ALLOC_FAILED", "grow_files", rel_path, 0);
            return false;
        }
        fl->files = new_files;
        fl->capacity = new_cap;
    }

    char *path_copy = strdup(abs_path);
    char *rel_copy = strdup(rel_path);
    if (!path_copy || !rel_copy) {
        free(path_copy);
        free(rel_copy);
        discovery_fail(fl, "CBM_DISCOVER_FILE_ALLOC_FAILED", "copy_file_record", rel_path, 0);
        return false;
    }
    cbm_file_info_t *fi = &fl->files[fl->count];
    memset(fi, 0, sizeof(*fi));
    fi->path = path_copy;
    fi->live_path = NULL;
    fi->rel_path = rel_copy;
    fi->language = lang;
    fi->size = size;
    fi->mtime_ns = 0;
    fi->sha256[0] = '\0';
    fi->auxiliary = auxiliary;
    fi->interpretation_input = interpretation_input;
    fl->count++;
    return true;
}

/* ── Recursive walk ─────────────────────────────── */

/* Compute path relative to a nested .gitignore's directory.
 * "webapp/src/foo.js" with prefix "webapp" → "src/foo.js". */
static const char *local_rel_path(const char *rel_path, const char *local_prefix) {
    if (!local_prefix || local_prefix[0] == '\0') {
        return rel_path;
    }
    size_t prefix_len = strlen(local_prefix);
    if (strncmp(rel_path, local_prefix, prefix_len) == 0 && rel_path[prefix_len] == '/') {
        return rel_path + prefix_len + SKIP_ONE;
    }
    return rel_path;
}

/* Non-negatable safety core: neither .cbmignore negation nor tracked paths can
 * un-skip these directories. .git holds VCS internals (and info/exclude,
 * #489), node_modules is dependency state rather than repository source, the
 * repository state directory is Astrolabe-owned output, and the worktree
 * directories contain parallel checkouts whose indexing would duplicate the
 * corpus (#802). Every other built-in basename is only a generated-state
 * candidate: a tracked descendant proves that the repository owns source
 * beneath it (#965). */
static bool is_safety_core_dir(const char *name) {
    static const char *const SAFETY_CORE_DIRS[] = {
        ".git", "node_modules", CBM_REPOSITORY_STATE_DIR, ".worktrees", ".claude-worktrees", NULL};
    return str_in_list(name, SAFETY_CORE_DIRS);
}

/* Git ignore rules apply only to untracked files. Keep one compact, sorted
 * view over `git ls-files -z --cached` so the filesystem walk can distinguish
 * an ignored build-output candidate from tracked source that happens to use
 * the same basename. The item pointers borrow `storage`; no pathname bytes are
 * duplicated. */
typedef struct {
    char *storage;
    char **items;
    size_t count;
    size_t bytes;
} tracked_paths_t;

static int tracked_path_compare(const char *left, const char *right) {
#ifdef _WIN32
    return _stricmp(left, right);
#else
    return strcmp(left, right);
#endif
}

static int tracked_path_pointer_compare(const void *left, const void *right) {
    const char *const *left_path = left;
    const char *const *right_path = right;
    return tracked_path_compare(*left_path, *right_path);
}

static size_t tracked_path_lower_bound(const tracked_paths_t *tracked, const char *path) {
    size_t low = 0;
    size_t high = tracked ? tracked->count : 0;
    while (low < high) {
        size_t middle = low + (high - low) / PAIR_LEN;
        if (tracked_path_compare(tracked->items[middle], path) < 0) {
            low = middle + SKIP_ONE;
        } else {
            high = middle;
        }
    }
    return low;
}

static bool tracked_path_is_exact(const tracked_paths_t *tracked, const char *path) {
    if (!tracked || tracked->count == 0 || !path || path[0] == '\0') {
        return false;
    }
    size_t at = tracked_path_lower_bound(tracked, path);
    return at < tracked->count && tracked_path_compare(tracked->items[at], path) == 0;
}

static bool tracked_path_is_descendant(const tracked_paths_t *tracked, const char *directory) {
    if (!tracked || tracked->count == 0 || !directory || directory[0] == '\0') {
        return false;
    }
    size_t directory_len = strlen(directory);
    size_t at = tracked_path_lower_bound(tracked, directory);
    while (at < tracked->count) {
        const char *candidate = tracked->items[at++];
#ifdef _WIN32
        if (_strnicmp(candidate, directory, directory_len) != 0) {
#else
        if (strncmp(candidate, directory, directory_len) != 0) {
#endif
            return false;
        }
        if (candidate[directory_len] == '/') {
            return true;
        }
    }
    return false;
}

static void tracked_paths_free(tracked_paths_t *tracked) {
    if (!tracked) {
        return;
    }
    free(tracked->items);
    free(tracked->storage);
    memset(tracked, 0, sizeof(*tracked));
}

/* Check if a directory entry should be skipped (hardcoded dirs + gitignore). */
static bool should_skip_directory(const char *entry_name, const char *rel_path,
                                  const cbm_discover_opts_t *opts, const cbm_gitignore_t *gitignore,
                                  const cbm_gitignore_t *global_gi,
                                  const cbm_gitignore_t *cbmignore, const cbm_gitignore_t *local_gi,
                                  const char *local_gi_prefix,
                                  const tracked_paths_t *tracked) {
    bool has_tracked_descendant = tracked_path_is_descendant(tracked, rel_path);
    if (cbm_should_skip_dir(entry_name, opts ? opts->mode : CBM_MODE_FULL)) {
        /* #500/#965: an explicit .cbmignore negation or an exact tracked
         * descendant un-skips a generated-state candidate. The safety core is
         * never traversed. Fall through so ignore rules still govern any
         * untracked siblings beneath an admitted directory. */
        bool safety_core = is_safety_core_dir(entry_name);
        bool explicitly_unskipped = cbmignore && !safety_core &&
                                    cbm_gitignore_match_result(cbmignore, rel_path, true) < 0;
        if (safety_core || (!explicitly_unskipped && !has_tracked_descendant)) {
            return true;
        }
    }
    if (gitignore && cbm_gitignore_matches(gitignore, rel_path, true) &&
        !has_tracked_descendant) {
        return true;
    }
    bool global_ignored = global_gi && cbm_gitignore_matches(global_gi, rel_path, true);
    if (local_gi) {
        const char *lrel = local_rel_path(rel_path, local_gi_prefix);
        if (cbm_gitignore_matches(local_gi, lrel, true) && !has_tracked_descendant) {
            return true;
        }
    }
    if (cbmignore) {
        int cbm_result = cbm_gitignore_match_result(cbmignore, rel_path, true);
        if (cbm_result > 0) {
            return true;
        }
        if (cbm_result < 0 && global_ignored) {
            return false;
        }
    }
    return global_ignored && !has_tracked_descendant;
}

/* Check if a regular file should be skipped (filters + gitignore + size). */
static bool should_skip_file(const char *entry_name, const char *rel_path,
                             const cbm_discover_opts_t *opts, const cbm_gitignore_t *gitignore,
                             const cbm_gitignore_t *global_gi, const cbm_gitignore_t *cbmignore,
                             const cbm_gitignore_t *local_gi, const char *local_gi_prefix,
                             off_t file_size, const tracked_paths_t *tracked) {
    cbm_index_mode_t mode = opts ? opts->mode : CBM_MODE_FULL;
    if (cbm_has_ignored_suffix(entry_name, mode)) {
        return true;
    }
    if (cbm_should_skip_filename(entry_name, mode)) {
        return true;
    }
    if (cbm_matches_fast_pattern(entry_name, mode)) {
        return true;
    }
    bool is_tracked = tracked_path_is_exact(tracked, rel_path);
    if (gitignore && cbm_gitignore_matches(gitignore, rel_path, false) && !is_tracked) {
        return true;
    }
    bool global_ignored = global_gi && cbm_gitignore_matches(global_gi, rel_path, false);
    if (local_gi) {
        const char *lrel = local_rel_path(rel_path, local_gi_prefix);
        if (cbm_gitignore_matches(local_gi, lrel, false) && !is_tracked) {
            return true;
        }
    }
    if (cbmignore) {
        int cbm_result = cbm_gitignore_match_result(cbmignore, rel_path, false);
        if (cbm_result > 0) {
            return true;
        }
        if (cbm_result < 0 && global_ignored) {
            global_ignored = false;
        }
    }
    if (opts && opts->max_file_size > 0 && file_size > opts->max_file_size) {
        return true;
    }
    return global_ignored && !is_tracked;
}

/* Detect language for a file, handling .m disambiguation and JSON filtering. */
static int detect_file_language(const char *entry_name, const char *abs_path, CBMLanguage *out) {
    CBMLanguage lang = cbm_language_for_filename(entry_name);
    if (lang == CBM_LANG_COUNT) {
        *out = CBM_LANG_COUNT;
        return 0;
    }
    /* Special: .m files need content-based disambiguation */
    const char *dot = strrchr(entry_name, '.');
    if (dot && strcmp(dot, ".m") == 0) {
        if (cbm_disambiguate_m_checked(abs_path, &lang) != 0) {
            return CBM_NOT_FOUND;
        }
    }
    /* Check ignored JSON files */
    if (lang == CBM_LANG_JSON && str_in_list(entry_name, IGNORED_JSON_FILES)) {
        lang = CBM_LANG_COUNT;
    }
    *out = lang;
    return 0;
}

/* UTF-8-safe stat: wide API on Windows, regular stat on POSIX. */
static int wide_stat(const char *path, struct stat *st) {
#ifdef _WIN32
    /* #383: extended-length widen so a source file deeper than MAX_PATH (260) stats
     * successfully instead of returning CBM_NOT_FOUND — a silent discovery skip. */
    wchar_t *wpath = cbm_utf8_to_wide_path(path);
    if (!wpath) {
        return CBM_NOT_FOUND;
    }
    struct _stat64 wst;
    int ret = _wstat64(wpath, &wst);
    free(wpath);
    if (ret != 0) {
        return CBM_NOT_FOUND;
    }
    st->st_mode = wst.st_mode;
    st->st_size = wst.st_size;
    st->st_mtime = wst.st_mtime;
    return 0;
#else
    return stat(path, st);
#endif
}

/* Stat a path, skipping symlinks (POSIX) and junctions / reparse points
 * (Windows). Returns 0 on success, -1 to skip. Skipping reparse points keeps
 * discovery from walking through a junction that points outside the project
 * root, mirroring the POSIX S_ISLNK skip. */
/* Returns 0 for a regular filesystem object, 1 for an intentionally excluded
 * symlink/reparse point, and -1 for an I/O/encoding fault. */
static int safe_stat(const char *abs_path, struct stat *st, unsigned long *native_error) {
    if (native_error) {
        *native_error = 0;
    }
#ifdef _WIN32
    /* #383: extended-length widen so the reparse-point probe on a >260-char path
     * reads real attributes instead of failing (which would skip the check). */
    wchar_t *wpath = cbm_utf8_to_wide_path(abs_path);
    if (!wpath) {
        if (native_error) {
            *native_error = GetLastError();
        }
        return CBM_NOT_FOUND;
    }
    DWORD attr = GetFileAttributesW(wpath);
    free(wpath);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        if (native_error) {
            *native_error = GetLastError();
        }
        return CBM_NOT_FOUND;
    }
    if ((attr & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return SKIP_ONE;
    }
    int rc = wide_stat(abs_path, st);
    if (rc != 0 && native_error) {
        *native_error = GetLastError();
    }
    return rc;
#else
    if (lstat(abs_path, st) != 0) {
        if (native_error) {
            *native_error = (unsigned long)errno;
        }
        return CBM_NOT_FOUND;
    }
    if (S_ISLNK(st->st_mode)) {
        return SKIP_ONE;
    }
    return 0;
#endif
}

/* Process a single regular file entry during directory walk. */
static bool walk_dir_process_file(const char *abs_path, const char *rel_path, const char *name,
                                  const cbm_discover_opts_t *opts, const cbm_gitignore_t *gitignore,
                                  const cbm_gitignore_t *global_gi,
                                  const cbm_gitignore_t *cbmignore, const cbm_gitignore_t *local_gi,
                                  const char *local_gi_prefix, off_t size,
                                  const tracked_paths_t *tracked, file_list_t *out) {
    if (should_skip_file(name, rel_path, opts, gitignore, global_gi, cbmignore, local_gi,
                         local_gi_prefix, size, tracked)) {
        return true;
    }
    CBMLanguage lang = CBM_LANG_COUNT;
    if (detect_file_language(name, abs_path, &lang) != 0) {
        discovery_fail(out, "CBM_DISCOVER_LANGUAGE_PROBE_FAILED", "read_language_probe", abs_path,
                       (unsigned long)errno);
        return false;
    }
    bool interpretation_input = cbm_is_auxiliary_input_name(name);
    if (lang == CBM_LANG_COUNT && !interpretation_input) {
        return true;
    }
    return fl_add(out, abs_path, rel_path, lang, size, lang == CBM_LANG_COUNT,
                  interpretation_input);
}

typedef struct {
    char *dir;
    char *prefix;
    cbm_gitignore_t *local_gi; /* nested .gitignore for this subtree */
    char *local_gi_prefix;     /* rel_prefix when local_gi was loaded */
} walk_frame_t;

static void walk_frame_free(walk_frame_t *frame) {
    if (!frame) {
        return;
    }
    free(frame->dir);
    free(frame->prefix);
    free(frame->local_gi_prefix);
    memset(frame, 0, sizeof(*frame));
}

static char *join_path_alloc(const char *left, const char *right) {
    if (!left || !right) {
        return NULL;
    }
    size_t left_len = strlen(left);
    size_t right_len = strlen(right);
    bool separator = left_len > 0 && left[left_len - 1] != '/' && left[left_len - 1] != '\\';
    if (left_len > SIZE_MAX - right_len - (separator ? PAIR_LEN : SKIP_ONE)) {
        return NULL;
    }
    size_t total = left_len + right_len + (separator ? SKIP_ONE : 0);
    char *joined = malloc(total + SKIP_ONE);
    if (!joined) {
        return NULL;
    }
    memcpy(joined, left, left_len);
    size_t offset = left_len;
    if (separator) {
        joined[offset++] = '/';
    }
    memcpy(joined + offset, right, right_len);
    joined[total] = '\0';
    return joined;
}

/* Load and compose the nested ignore policy for one directory. Parent rules
 * precede child rules so the child's later matches retain Git semantics. */
static bool load_nested_gitignore(const walk_frame_t *frame, cbm_gitignore_t **out,
                                  file_list_t *files) {
    *out = NULL;
    if (!frame->prefix || frame->prefix[0] == '\0') {
        return true;
    }
    char *gi_path = join_path_alloc(frame->dir, ".gitignore");
    if (!gi_path) {
        discovery_fail(files, "CBM_DISCOVER_GITIGNORE_PATH_ALLOC_FAILED", "join_nested_gitignore",
                       frame->dir, 0);
        return false;
    }
    cbm_gitignore_t *loaded = NULL;
    if (cbm_gitignore_load_checked(gi_path, true, &loaded) != 0) {
        discovery_fail(files, "CBM_DISCOVER_GITIGNORE_READ_FAILED", "read_nested_gitignore",
                       gi_path, (unsigned long)errno);
        free(gi_path);
        return false;
    }
    free(gi_path);
    if (!loaded) {
        return true;
    }
    if (!frame->local_gi) {
        *out = loaded;
        return true;
    }
    cbm_gitignore_t *combined = cbm_gitignore_parse("");
    if (!combined || !cbm_gitignore_merge(combined, frame->local_gi) ||
        !cbm_gitignore_merge(combined, loaded)) {
        cbm_gitignore_free(combined);
        cbm_gitignore_free(loaded);
        discovery_fail(files, "CBM_DISCOVER_GITIGNORE_MERGE_FAILED", "compose_gitignore",
                       frame->prefix, 0);
        return false;
    }
    cbm_gitignore_free(loaded);
    *out = combined;
    return true;
}

/* Push a subdirectory onto the walk stack, inheriting local gitignore context. */
static bool walk_push_subdir(walk_frame_t **stack, size_t *top, size_t *capacity,
                             const char *abs_path, const char *rel_path, const walk_frame_t *parent,
                             file_list_t *out) {
    if (*top >= *capacity) {
        size_t next = *capacity ? *capacity * PAIR_LEN : CBM_SZ_64;
        if (next < *capacity || next > SIZE_MAX / sizeof(walk_frame_t)) {
            discovery_fail(out, "CBM_DISCOVER_STACK_CAPACITY_OVERFLOW", "grow_walk_stack", rel_path,
                           0);
            return false;
        }
        walk_frame_t *grown = realloc(*stack, next * sizeof(walk_frame_t));
        if (!grown) {
            discovery_fail(out, "CBM_DISCOVER_STACK_ALLOC_FAILED", "grow_walk_stack", rel_path, 0);
            return false;
        }
        memset(grown + *capacity, 0, (next - *capacity) * sizeof(walk_frame_t));
        *stack = grown;
        *capacity = next;
    }
    walk_frame_t *child = &(*stack)[*top];
    child->dir = strdup(abs_path);
    child->prefix = strdup(rel_path);
    child->local_gi_prefix = strdup(parent->local_gi_prefix ? parent->local_gi_prefix : "");
    if (!child->dir || !child->prefix || !child->local_gi_prefix) {
        walk_frame_free(child);
        discovery_fail(out, "CBM_DISCOVER_STACK_ALLOC_FAILED", "copy_walk_frame", rel_path, 0);
        return false;
    }
    child->local_gi = parent->local_gi;
    (*top)++;
    return true;
}

static bool walk_dir_process_entry(cbm_dirent_t *entry, const walk_frame_t *frame,
                                   const cbm_discover_opts_t *opts,
                                   const cbm_gitignore_t *gitignore,
                                   const cbm_gitignore_t *global_gi,
                                   const cbm_gitignore_t *cbmignore,
                                   const tracked_paths_t *tracked, walk_frame_t **stack,
                                   size_t *top, size_t *capacity, file_list_t *out) {
    char *abs_path = join_path_alloc(frame->dir, entry->name);
    char *rel_path = frame->prefix && frame->prefix[0] != '\0'
                         ? join_path_alloc(frame->prefix, entry->name)
                         : strdup(entry->name);
    if (!abs_path || !rel_path) {
        free(abs_path);
        free(rel_path);
        discovery_fail(out, "CBM_DISCOVER_PATH_ALLOC_FAILED", "join_entry_path", entry->name, 0);
        return false;
    }

    struct stat st;
    unsigned long native_error = 0;
    int stat_result = safe_stat(abs_path, &st, &native_error);
    if (stat_result > 0) {
        free(abs_path);
        free(rel_path);
        return true;
    }
    if (stat_result < 0) {
        discovery_fail(out, "CBM_DISCOVER_ENTRY_STAT_FAILED", "stat_entry", abs_path, native_error);
        free(abs_path);
        free(rel_path);
        return false;
    }

    bool ok = true;
    if (S_ISDIR(st.st_mode)) {
        if (!should_skip_directory(entry->name, rel_path, opts, gitignore, global_gi, cbmignore,
                                   frame->local_gi, frame->local_gi_prefix, tracked)) {
            ok = walk_push_subdir(stack, top, capacity, abs_path, rel_path, frame, out);
        } else {
            /* Record the excluded subtree root so callers can report it (#411). */
            ok = file_list_add_excluded(out, rel_path);
        }
    } else if (S_ISREG(st.st_mode)) {
        ok = walk_dir_process_file(abs_path, rel_path, entry->name, opts, gitignore, global_gi,
                                   cbmignore, frame->local_gi, frame->local_gi_prefix, st.st_size,
                                   tracked, out);
    }
    free(abs_path);
    free(rel_path);
    return ok;
}

static int walk_dir(const char *dir_path, const char *rel_prefix, const cbm_discover_opts_t *opts,
                    const cbm_gitignore_t *gitignore, const cbm_gitignore_t *global_gi,
                    const cbm_gitignore_t *cbmignore, const tracked_paths_t *tracked,
                    file_list_t *out) {
    walk_frame_t *stack = NULL;
    size_t stack_count = 0;
    size_t stack_capacity = 0;
    /* Collect all owned gitignores — freed at the end because child frames
     * on the stack hold borrowed pointers to them. */
    cbm_gitignore_t **owned_gis = NULL;
    size_t owned_count = 0;
    size_t owned_capacity = 0;

    walk_frame_t root = {.local_gi = NULL, .local_gi_prefix = ""};
    if (!walk_push_subdir(&stack, &stack_count, &stack_capacity, dir_path, rel_prefix, &root,
                          out)) {
        free(stack);
        return CBM_NOT_FOUND;
    }

    while (stack_count > 0 && !out->failed) {
        walk_frame_t frame = stack[--stack_count];
        memset(&stack[stack_count], 0, sizeof(stack[stack_count]));

        cbm_gitignore_t *loaded = NULL;
        if (!load_nested_gitignore(&frame, &loaded, out)) {
            walk_frame_free(&frame);
            break;
        }
        if (loaded) {
            frame.local_gi = loaded;
            char *prefix_copy = strdup(frame.prefix ? frame.prefix : "");
            if (!prefix_copy) {
                cbm_gitignore_free(loaded);
                discovery_fail(out, "CBM_DISCOVER_GITIGNORE_ALLOC_FAILED", "copy_gitignore_scope",
                               frame.prefix, 0);
                walk_frame_free(&frame);
                break;
            }
            free(frame.local_gi_prefix);
            frame.local_gi_prefix = prefix_copy;
            if (owned_count >= owned_capacity) {
                size_t next = owned_capacity ? owned_capacity * PAIR_LEN : CBM_SZ_64;
                if (next < owned_capacity || next > SIZE_MAX / sizeof(*owned_gis)) {
                    cbm_gitignore_free(loaded);
                    discovery_fail(out, "CBM_DISCOVER_GITIGNORE_CAPACITY_OVERFLOW",
                                   "grow_gitignore_owners", frame.prefix, 0);
                    walk_frame_free(&frame);
                    break;
                }
                cbm_gitignore_t **grown = realloc(owned_gis, next * sizeof(*owned_gis));
                if (!grown) {
                    cbm_gitignore_free(loaded);
                    discovery_fail(out, "CBM_DISCOVER_GITIGNORE_ALLOC_FAILED",
                                   "grow_gitignore_owners", frame.prefix, 0);
                    walk_frame_free(&frame);
                    break;
                }
                owned_gis = grown;
                owned_capacity = next;
            }
            owned_gis[owned_count++] = loaded;
        }

        cbm_dir_t *d = cbm_opendir(frame.dir);
        if (!d) {
            discovery_fail(out, "CBM_DISCOVER_DIRECTORY_OPEN_FAILED", "open_directory", frame.dir,
                           cbm_fs_last_error());
            walk_frame_free(&frame);
            break;
        }

        cbm_dirent_t *entry;
        while (!out->failed && (entry = cbm_readdir(d)) != NULL) {
            if (!walk_dir_process_entry(entry, &frame, opts, gitignore, global_gi, cbmignore,
                                        tracked, &stack, &stack_count, &stack_capacity, out)) {
                break;
            }
        }
        unsigned long read_error = cbm_dir_error(d);
        if (!out->failed && read_error != 0) {
            discovery_fail(out, "CBM_DISCOVER_DIRECTORY_READ_FAILED", "read_directory", frame.dir,
                           read_error);
        }
        cbm_closedir(d);
        walk_frame_free(&frame);
    }
    for (size_t i = 0; i < stack_count; i++) {
        walk_frame_free(&stack[i]);
    }
    for (size_t i = 0; i < owned_count; i++) {
        cbm_gitignore_free(owned_gis[i]);
    }
    free(owned_gis);
    free(stack);
    return out->failed ? CBM_NOT_FOUND : 0;
}

/* ── Public API ───────────────────────────────── */

static bool discover_path_is_absolute(const char *path) {
    if (!path || !path[0]) {
        return false;
    }
    if (path[0] == '/' || path[0] == '\\') {
        return true;
    }
#ifdef _WIN32
    return isalpha((unsigned char)path[0]) && path[1] == ':';
#else
    return false;
#endif
}

static bool tracked_path_shape_valid(const char *path) {
    if (!path || path[0] == '\0' || path[0] == '/' || path[0] == '\\') {
        return false;
    }
    const char *component = path;
    for (const char *cursor = path;; cursor++) {
#ifdef _WIN32
        if (*cursor == '\\') {
            return false;
        }
#endif
        if (*cursor != '/' && *cursor != '\0') {
            continue;
        }
        size_t length = (size_t)(cursor - component);
        if (length == 0 || (length == SKIP_ONE && component[0] == '.') ||
            (length == PAIR_LEN && component[0] == '.' && component[1] == '.')) {
            return false;
        }
        if (*cursor == '\0') {
            break;
        }
        component = cursor + SKIP_ONE;
    }
#ifdef _WIN32
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0) <= 0) {
        return false;
    }
#endif
    return true;
}

static bool load_tracked_paths(const char *repo_path, bool is_git_repo,
                               tracked_paths_t *out) {
    memset(out, 0, sizeof(*out));
    if (!is_git_repo) {
        return true;
    }
    const char *const argv[] = {"git",       "-C",          repo_path, "ls-files",
                                "-z",        "--cached",    "--deduplicate",
                                "--",        NULL};
    char *data = NULL;
    size_t data_len = 0;
    cbm_spawn_error_t spawn_error = {0};
    if (cbm_spawn_capture(argv, &data, &data_len, &spawn_error) != 0) {
        char native_error[32];
        char exit_code[32];
        snprintf(native_error, sizeof(native_error), "%lu", spawn_error.os_error);
        snprintf(exit_code, sizeof(exit_code), "%d", spawn_error.exit_code);
        cbm_log_error(
            "discover.failed", "code", "CBM_DISCOVER_GIT_INDEX_ENUM_FAILED", "operation",
            "git_ls_files_cached", "path", repo_path, "spawn_code",
            spawn_error.code_name ? spawn_error.code_name : "CBM_SPAWN_UNKNOWN", "native_error",
            native_error, "exit_code", exit_code, "message",
            "Git's tracked source namespace could not be enumerated", "remediation",
            "repair the repository index or Git executable, then retry complete discovery");
        free(data);
        return false;
    }
    if (data_len == 0) {
        free(data);
        return true;
    }
    if (data[data_len - SKIP_ONE] != '\0') {
        cbm_log_error("discover.failed", "code", "CBM_DISCOVER_GIT_INDEX_OUTPUT_TRUNCATED",
                      "operation", "decode_git_ls_files_cached", "path", repo_path, "message",
                      "Git's NUL-delimited tracked source namespace has no terminal delimiter",
                      "remediation", "preserve the output and repair the Git process stream");
        free(data);
        return false;
    }
    size_t raw_count = 0;
    for (size_t i = 0; i < data_len; i++) {
        if (data[i] == '\0') {
            raw_count++;
        }
    }
    if (raw_count > SIZE_MAX / sizeof(char *)) {
        cbm_log_error("discover.failed", "code", "CBM_DISCOVER_GIT_INDEX_CAPACITY_OVERFLOW",
                      "operation", "allocate_git_ls_files_cached", "path", repo_path, "message",
                      "Git's tracked source count exceeds addressable memory", "remediation",
                      "index a smaller exact repository scope with its own Git index");
        free(data);
        return false;
    }
    char **items = calloc(raw_count, sizeof(char *));
    if (!items) {
        cbm_log_error("discover.failed", "code", "CBM_DISCOVER_GIT_INDEX_ALLOC_FAILED",
                      "operation", "allocate_git_ls_files_cached", "path", repo_path, "message",
                      "the compact tracked source pointer index could not be allocated",
                      "remediation", "free memory and retry complete discovery");
        free(data);
        return false;
    }
    size_t start = 0;
    size_t item_count = 0;
    for (size_t i = 0; i < data_len; i++) {
        if (data[i] != '\0') {
            continue;
        }
        const char *path = data + start;
        if (i == start || !tracked_path_shape_valid(path)) {
            char ordinal[32];
            snprintf(ordinal, sizeof(ordinal), "%zu", item_count);
            cbm_log_error(
                "discover.failed", "code", "CBM_DISCOVER_GIT_INDEX_PATH_INVALID", "operation",
                "decode_git_ls_files_cached", "path", repo_path, "ordinal", ordinal, "message",
                "Git's tracked source namespace contains an empty, non-relative, or unrepresentable path",
                "remediation", "repair the exact Git index path and retry complete discovery");
            free(items);
            free(data);
            return false;
        }
        items[item_count++] = data + start;
        start = i + SKIP_ONE;
    }
    qsort(items, item_count, sizeof(char *), tracked_path_pointer_compare);
    size_t unique_count = 0;
    for (size_t i = 0; i < item_count; i++) {
        if (unique_count == 0 ||
            tracked_path_compare(items[unique_count - SKIP_ONE], items[i]) != 0) {
            items[unique_count++] = items[i];
        }
    }
    out->storage = data;
    out->items = items;
    out->count = unique_count;
    out->bytes = data_len;
    return true;
}

static bool load_ignore_policy(const char *path, bool optional, const char *code,
                               const char *operation, cbm_gitignore_t **out) {
    if (cbm_gitignore_load_checked(path, optional, out) == 0) {
        return true;
    }
    /* The loader reports failures through errno (a C library error code), NOT a
     * Win32 native error. Log it under distinct `errno`/`errno_name` keys: the
     * former "native_error" key made a reader interpret e.g. errno=EIO(5) as the
     * Win32 code 5 = ERROR_ACCESS_DENIED, which is a different, misleading
     * failure. */
    int saved_errno = errno;
    char errno_num[32];
    snprintf(errno_num, sizeof(errno_num), "%d", saved_errno);
    cbm_log_error("discover.failed", "code", code, "operation", operation, "path", path, "errno",
                  errno_num, "errno_name", strerror(saved_errno), "message",
                  "the complete ignore policy could not be read", "remediation",
                  "restore the ignore input and retry indexing");
    return false;
}

/* Resolve the shared "common" git directory for repo_path.
 * Handles three layouts:
 *   1. <repo>/.git is a directory    - ordinary repo; common_dir == <repo>/.git
 *   2. <repo>/.git is a regular file - linked worktree gitlink "gitdir: <path>";
 *      the common dir is read from <git_dir>/commondir (git stores info/exclude +
 *      config there, shared across worktrees). Falls back to git_dir when no
 *      commondir file exists.
 *   3. neither - not a git repo.
 * Returns true when a git dir was resolved. Fixes the worktree case where
 * .git/info/exclude and core.excludesfile were silently dropped because the old
 * check required .git to be a directory (issue #489 only covered ordinary repos). */
static bool resolve_git_common_dir(const char *repo_path, char *common_dir, size_t cd_sz) {
    char dot_git[CBM_SZ_4K];
    snprintf(dot_git, sizeof(dot_git), "%s/.git", repo_path);
    struct stat st;
    if (wide_stat(dot_git, &st) != 0) {
        return false;
    }
    if (S_ISDIR(st.st_mode)) {
        snprintf(common_dir, cd_sz, "%s", dot_git);
        cbm_normalize_path_sep(common_dir);
        return true;
    }
    if (!S_ISREG(st.st_mode)) {
        return false;
    }

    /* Linked worktree: parse "gitdir: <path>" from the gitlink file.
     * cbm_fopen (not raw fopen) so non-ASCII repo paths open on Windows. */
    FILE *f = cbm_fopen(dot_git, "r");
    if (!f) {
        return false;
    }
    char git_dir[CBM_SZ_4K];
    bool got_git_dir = false;
    char line[CBM_SZ_4K];
    while (fgets(line, sizeof(line), f)) {
        char *gs = trim_ws(line);
        if (strncmp(gs, "gitdir:", 7) == 0) {
            char *val = trim_ws(gs + 7);
            if (val[0] != '\0') {
                if (discover_path_is_absolute(val)) {
                    snprintf(git_dir, sizeof(git_dir), "%s", val);
                    cbm_normalize_path_sep(git_dir);
                } else {
                    path_join(git_dir, sizeof(git_dir), repo_path, val);
                }
                got_git_dir = true;
            }
            break;
        }
    }
    fclose(f);
    if (!got_git_dir) {
        return false;
    }

    /* The shared dir holding info/exclude + config is named in <git_dir>/commondir
     * (typically a relative path like "../.."). Absent in single-worktree gitdirs. */
    char commondir_path[CBM_SZ_4K];
    path_join(commondir_path, sizeof(commondir_path), git_dir, "commondir");
    FILE *cf = cbm_fopen(commondir_path, "r");
    if (cf) {
        char cbuf[CBM_SZ_4K];
        bool resolved = false;
        if (fgets(cbuf, sizeof(cbuf), cf)) {
            char *cs = trim_ws(cbuf);
            if (cs[0] != '\0') {
                if (discover_path_is_absolute(cs)) {
                    snprintf(common_dir, cd_sz, "%s", cs);
                    cbm_normalize_path_sep(common_dir);
                } else {
                    path_join(common_dir, cd_sz, git_dir, cs);
                }
                resolved = true;
            }
        }
        fclose(cf);
        if (resolved) {
            return true;
        }
    }

    snprintf(common_dir, cd_sz, "%s", git_dir);
    cbm_normalize_path_sep(common_dir);
    return true;
}

int cbm_discover(const char *repo_path, const cbm_discover_opts_t *opts, cbm_file_info_t **out,
                 int *count) {
    return cbm_discover_ex(repo_path, opts, out, count, NULL, NULL);
}

int cbm_discover_ex(const char *repo_path, const cbm_discover_opts_t *opts, cbm_file_info_t **out,
                    int *count, char ***excluded_out, int *excluded_count_out) {
    if (excluded_out) {
        *excluded_out = NULL;
    }
    if (excluded_count_out) {
        *excluded_count_out = 0;
    }
    if (!repo_path || !out || !count) {
        return CBM_NOT_FOUND;
    }

    *out = NULL;
    *count = 0;

    /* Verify directory exists */
    struct stat st;
    if (wide_stat(repo_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return CBM_NOT_FOUND;
    }

    /* Load gitignore sources for ordinary repos AND linked worktrees.
     * Sources merged in order (later patterns win on conflict):
     *   1. <repo>/.gitignore     — committed exclusions
     *   2. <common>/info/exclude — per-clone exclusions, not committed
     * <common> is the git common dir, resolved via resolve_git_common_dir() so a
     * worktree (where .git is a gitlink file) reads the shared info/exclude/config
     * just like a normal checkout. Both are folded into a single matcher so all
     * downstream call paths remain unchanged. Fixes issue #489: OOM on repos whose
     * worktrees are excluded only via .git/info/exclude (e.g. Sandcastle). */
    cbm_gitignore_t *gitignore = NULL;
    char gi_path[CBM_SZ_4K];
    /* Resolve the git common dir, transparently following a worktree gitlink so the
     * .git/info/exclude and core.excludesfile sources are honoured inside linked
     * worktrees too (where .git is a file pointing at the shared dir, not a directory). */
    char git_common_dir[CBM_SZ_4K];
    bool is_git_repo = resolve_git_common_dir(repo_path, git_common_dir, sizeof(git_common_dir));
    /* Always honour the .gitignore at the indexed-directory root, even when the
     * directory is not a git repo root (e.g. indexing a sub-package directly).
     * Fixes issue #510: a root .gitignore was silently ignored without .git/. */
    snprintf(gi_path, sizeof(gi_path), "%s/.gitignore", repo_path);
    if (!load_ignore_policy(gi_path, true, "CBM_DISCOVER_ROOT_GITIGNORE_READ_FAILED",
                            "read_root_gitignore", &gitignore)) {
        return CBM_NOT_FOUND;
    }
    if (is_git_repo) {
        char exc_path[CBM_SZ_4K];
        path_join(exc_path, sizeof(exc_path), git_common_dir, "info/exclude");
        cbm_gitignore_t *git_exclude = NULL;
        if (!load_ignore_policy(exc_path, true, "CBM_DISCOVER_GIT_EXCLUDE_READ_FAILED",
                                "read_git_exclude", &git_exclude)) {
            cbm_gitignore_free(gitignore);
            return CBM_NOT_FOUND;
        }
        if (git_exclude) {
            if (!gitignore) {
                gitignore = git_exclude;
            } else {
                if (!cbm_gitignore_merge(gitignore, git_exclude)) {
                    cbm_log_error("discover.failed", "code",
                                  "CBM_DISCOVER_GIT_EXCLUDE_MERGE_FAILED", "operation",
                                  "merge_git_exclude", "path", exc_path, "message",
                                  "the complete Git exclusion policy could not be represented",
                                  "remediation", "free memory and retry indexing");
                    cbm_gitignore_free(git_exclude);
                    cbm_gitignore_free(gitignore);
                    return CBM_NOT_FOUND;
                }
                cbm_gitignore_free(git_exclude);
            }
        }
    }

    cbm_gitignore_t *global_gi = NULL;
    if (is_git_repo) {
        global_excludes_resolution_t global_resolution =
            resolve_global_excludes_path(repo_path, gi_path, sizeof(gi_path));
        if (global_resolution == GLOBAL_EXCLUDES_RESOLUTION_FAILED) {
            cbm_gitignore_free(gitignore);
            return CBM_NOT_FOUND;
        }
        bool optional = global_resolution == GLOBAL_EXCLUDES_DEFAULT;
        if (!load_ignore_policy(gi_path, optional, "CBM_DISCOVER_GLOBAL_EXCLUDE_READ_FAILED",
                                "read_global_exclude", &global_gi)) {
            cbm_gitignore_free(gitignore);
            return CBM_NOT_FOUND;
        }
    }

    /* Load cbmignore if specified or exists at repo root */
    cbm_gitignore_t *cbmignore = NULL;
    if (opts && opts->ignore_file) {
        if (!load_ignore_policy(opts->ignore_file, false, "CBM_DISCOVER_CBMIGNORE_READ_FAILED",
                                "read_explicit_cbmignore", &cbmignore)) {
            cbm_gitignore_free(gitignore);
            cbm_gitignore_free(global_gi);
            return CBM_NOT_FOUND;
        }
    } else {
        snprintf(gi_path, sizeof(gi_path), "%s/.cbmignore", repo_path);
        if (!load_ignore_policy(gi_path, true, "CBM_DISCOVER_CBMIGNORE_READ_FAILED",
                                "read_root_cbmignore", &cbmignore)) {
            cbm_gitignore_free(gitignore);
            cbm_gitignore_free(global_gi);
            return CBM_NOT_FOUND;
        }
    }

    /* Git ignore files govern only untracked files. Enumerate the index once so
     * tracked sources remain visible even below an ignored directory such as a
     * Rust module namespace named `build`. */
    tracked_paths_t tracked = {0};
    if (!load_tracked_paths(repo_path, is_git_repo, &tracked)) {
        cbm_gitignore_free(gitignore);
        cbm_gitignore_free(global_gi);
        cbm_gitignore_free(cbmignore);
        return CBM_NOT_FOUND;
    }

    /* Walk */
    file_list_t fl = {0};
    int walk_rc = walk_dir(repo_path, "", opts, gitignore, global_gi, cbmignore, &tracked, &fl);

    /* Cleanup */
    tracked_paths_free(&tracked);
    cbm_gitignore_free(gitignore);
    cbm_gitignore_free(global_gi);
    cbm_gitignore_free(cbmignore);

    if (walk_rc != 0 || fl.failed) {
        cbm_discover_free(fl.files, fl.count);
        cbm_discover_free_excluded(fl.excluded, fl.excluded_count);
        return CBM_NOT_FOUND;
    }

    *out = fl.files;
    *count = fl.count;

    /* Hand the excluded-dir list to the caller, or free it if not requested. */
    if (excluded_out) {
        *excluded_out = fl.excluded;
        if (excluded_count_out) {
            *excluded_count_out = fl.excluded_count;
        }
    } else {
        cbm_discover_free_excluded(fl.excluded, fl.excluded_count);
    }
    return 0;
}

void cbm_discover_free(cbm_file_info_t *files, int count) {
    if (!files) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free(files[i].path);
        free(files[i].live_path);
        free(files[i].rel_path);
    }
    free(files);
}

void cbm_discover_free_excluded(char **excluded, int count) {
    if (!excluded) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free(excluded[i]);
    }
    free(excluded);
}
