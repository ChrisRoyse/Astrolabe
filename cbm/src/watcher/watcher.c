/*
 * watcher.c — Git-based file change watcher.
 *
 * Strategy: one branch-aware Git status observation plus exact dirty bytes.
 * For non-git projects, the watcher skips polling (no fsnotify/dirmtime yet).
 *
 *
 * Per-project state tracks:
 *   - Last coherent Git source fingerprint (branch, HEAD, index, worktree)
 *   - Last poll time + adaptive interval
 *   - Whether the project is a git repo
 *
 * Adaptive interval: 5s base + 1s per 500 files, capped at 60s.
 * Matches the Go watcher's `pollInterval()` logic.
 */
#include <stdint.h>
#ifdef ASTRO_SPAWN
#include "astro_spawn.h"
#endif
#include "watcher/watcher.h"
#include "store/store.h"
#include "foundation/constants.h"
#include "foundation/log.h"
#include "foundation/hash_table.h"
#include "foundation/compat.h"
#include "foundation/compat_thread.h"
#include "foundation/compat_fs.h"
#include "foundation/platform.h"
#include "foundation/sha256.h"
#include "foundation/str_util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <sys/stat.h>

/* ── Per-project state ──────────────────────────────────────────── */

#ifdef ASTRO_SPAWN
typedef struct {
    char *project_name;
    char *root_path;
    char *git_dir_arg;   /* explicit --git-dir=... disables parent discovery */
    char *work_tree_arg; /* exact --work-tree=... paired with git_dir_arg */
    char *git_work_tree; /* absolute path used to open porcelain-named files */
    char source_sha256[CBM_SHA256_HEX_LEN + 1]; /* last successfully indexed Git source state */
    bool is_git;                                /* false → skip polling */
    bool git_context_ready;                     /* exact repository context was resolved */
    bool observation_failed;                    /* a native source read has not yet recovered */
    bool baseline_done;                         /* true after first poll */
    int file_count;                             /* approximate, for interval calc */
    int interval_ms;                            /* adaptive poll interval */
    int64_t next_poll_ns;                       /* next poll time (monotonic ns) */
} project_state_t;

/* ── Watcher struct ─────────────────────────────────────────────── */

struct cbm_watcher {
    cbm_store_t *store;
    cbm_index_fn index_fn;
    void *user_data;
    CBMHashTable *projects; /* name → project_state_t* */
    cbm_mutex_t projects_lock;
    atomic_int stopped;
    /* Deferred-free list: freed after the next poll_once. */
    project_state_t **pending_free;
    int pending_free_count;
    int pending_free_cap;
};

/* ── Constants ─────────────────────────────────────────────────── */

/* Time unit conversions */
#define NS_PER_SEC 1000000000LL
#define US_PER_MS 1000000LL

/* Adaptive poll interval parameters (ms) */
#define POLL_BASE_MS 5000
#define POLL_FILE_STEP 500 /* add 1s per this many files */
#define POLL_MAX_MS 60000

/* Sleep chunk for responsive shutdown (ms) */
#define SLEEP_CHUNK_MS 500

/* ── Time helper ────────────────────────────────────────────────── */

static int64_t now_ns(void) {
    struct timespec ts;
    cbm_clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((int64_t)ts.tv_sec * NS_PER_SEC) + ts.tv_nsec;
}

/* ── Adaptive interval ──────────────────────────────────────────── */

int cbm_watcher_poll_interval_ms(int file_count) {
    int ms = POLL_BASE_MS + ((file_count / POLL_FILE_STEP) * CBM_MSEC_PER_SEC);
    if (ms > POLL_MAX_MS) {
        ms = POLL_MAX_MS;
    }
    return ms;
}

/* ── Git helpers ────────────────────────────────────────────────── */

#ifdef ASTRO_SPAWN
/* Shell-free git helpers (#227): every git call below hands an explicit argv to
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

#else
/* Portable command pieces: cbm_popen runs through cmd.exe on Windows, which does
 * NOT strip single quotes (git would receive a literal-quoted path → "cannot find
 * the path") and has no /dev/null. Use double quotes (stripped by both cmd.exe and
 * POSIX sh) and the platform null device. */
#if defined(_WIN32)
#define WATCHER_NULDEV "NUL"
#else
#define WATCHER_NULDEV "/dev/null"
#endif
#endif

typedef enum {
    GIT_CONTEXT_NOT_REPOSITORY = 0,
    GIT_CONTEXT_READY = 1,
    GIT_CONTEXT_FAILED = 2,
} git_context_result_t;

static char *watcher_prefixed_arg(const char *prefix, const char *value) {
    size_t prefix_len = strlen(prefix);
    size_t value_len = strlen(value);
    if (prefix_len > SIZE_MAX - value_len - 1) {
        return NULL;
    }
    char *arg = malloc(prefix_len + value_len + 1);
    if (!arg) {
        return NULL;
    }
    memcpy(arg, prefix, prefix_len);
    memcpy(arg + prefix_len, value, value_len + 1);
    return arg;
}

/* Copy exactly one non-empty line from a Git path query. Paths containing a
 * newline cannot be represented by the option contract and therefore refuse
 * instead of being truncated or reinterpreted. */
static char *watcher_git_path_line(const char *data, size_t len) {
    if (!data) {
        return NULL;
    }
    while (len > 0 && (data[len - 1] == '\n' || data[len - 1] == '\r')) {
        len--;
    }
    if (len == 0 || memchr(data, '\0', len) || memchr(data, '\n', len) || memchr(data, '\r', len)) {
        return NULL;
    }
    char *copy = malloc(len + 1);
    if (!copy) {
        return NULL;
    }
    memcpy(copy, data, len);
    copy[len] = '\0';
    return copy;
}

static bool watcher_bind_git_context(project_state_t *s, const char *git_dir,
                                     const char *work_tree) {
    char *git_dir_arg = watcher_prefixed_arg("--git-dir=", git_dir);
    char *work_tree_arg = watcher_prefixed_arg("--work-tree=", work_tree);
    char *work_tree_copy = strdup(work_tree);
    if (!git_dir_arg || !work_tree_arg || !work_tree_copy) {
        free(git_dir_arg);
        free(work_tree_arg);
        free(work_tree_copy);
        return false;
    }
    free(s->git_dir_arg);
    free(s->work_tree_arg);
    free(s->git_work_tree);
    s->git_dir_arg = git_dir_arg;
    s->work_tree_arg = work_tree_arg;
    s->git_work_tree = work_tree_copy;
    s->git_context_ready = true;
    return true;
}

/* Resolve repository identity once at watch admission, then pass it explicitly
 * to every poll child. Git documents that --git-dir disables parent discovery;
 * this prevents a malformed nested repository from silently observing an
 * enclosing checkout. A direct .git entry is resolved with --resolve-git-dir,
 * which supports both ordinary repositories and linked-worktree gitfiles. A
 * configured watch is a repository-root contract: a missing direct .git entry
 * is a coded observation failure, never permission to discover a parent. */
static git_context_result_t watcher_resolve_git_context(project_state_t *s) {
    size_t root_len = strlen(s->root_path);
    if (root_len > SIZE_MAX - sizeof("/.git")) {
        cbm_log_warn("watcher.git_context.path_overflow", "code", CBM_WATCHER_GIT_CONTEXT_FAILED,
                     "project", s->project_name, "remediation",
                     "use a repository path representable by the native runtime");
        return GIT_CONTEXT_FAILED;
    }
    char *git_entry = malloc(root_len + sizeof("/.git"));
    if (!git_entry) {
        cbm_log_warn("watcher.git_context.alloc_failed", "code", CBM_WATCHER_GIT_CONTEXT_FAILED,
                     "project", s->project_name, "remediation",
                     "free memory before watcher registration");
        return GIT_CONTEXT_FAILED;
    }
    memcpy(git_entry, s->root_path, root_len);
    memcpy(git_entry + root_len, "/.git", sizeof("/.git"));

    struct stat entry_stat;
    bool direct_entry = stat(git_entry, &entry_stat) == 0;
    if (!direct_entry) {
        char errno_text[CBM_SZ_64];
        snprintf(errno_text, sizeof(errno_text), "%d", errno);
        cbm_log_warn(
            errno == ENOENT ? "watcher.git_context.entry_missing"
                            : "watcher.git_context.entry_unreadable",
            "code", CBM_WATCHER_GIT_CONTEXT_FAILED, "project", s->project_name, "path", git_entry,
            "errno", errno_text, "remediation",
            "restore the direct .git directory or gitfile at the registered repository root");
        free(git_entry);
        return GIT_CONTEXT_FAILED;
    }

    char *git_dir_data = NULL;
    size_t git_dir_len = 0;
    cbm_spawn_error_t git_dir_error;
    int git_dir_rc;
    const char *const argv[] = {"git", "rev-parse", "--resolve-git-dir", git_entry, NULL};
    git_dir_rc = cbm_spawn_capture(argv, &git_dir_data, &git_dir_len, &git_dir_error);
    if (git_dir_rc != 0) {
        cbm_log_warn("watcher.git_context.resolve_failed", "code", CBM_WATCHER_GIT_CONTEXT_FAILED,
                     "project", s->project_name, "spawn_code", git_dir_error.code_name, "message",
                     git_dir_error.message, "remediation",
                     "repair the exact registered .git entry; parent repositories are never used");
        free(git_dir_data);
        free(git_entry);
        return GIT_CONTEXT_FAILED;
    }
    char *git_dir = watcher_git_path_line(git_dir_data, git_dir_len);
    free(git_dir_data);
    if (!git_dir) {
        cbm_log_warn("watcher.git_context.git_dir_invalid", "code", CBM_WATCHER_GIT_CONTEXT_FAILED,
                     "project", s->project_name, "remediation",
                     "inspect git rev-parse repository-path output");
        free(git_entry);
        return GIT_CONTEXT_FAILED;
    }

    char *work_tree = strdup(s->root_path);
    free(git_entry);
    if (!work_tree || !watcher_bind_git_context(s, git_dir, work_tree)) {
        cbm_log_warn("watcher.git_context.bind_failed", "code", CBM_WATCHER_GIT_CONTEXT_FAILED,
                     "project", s->project_name, "remediation",
                     "free memory and retry watcher registration");
        free(work_tree);
        free(git_dir);
        return GIT_CONTEXT_FAILED;
    }
    free(work_tree);
    free(git_dir);
    return GIT_CONTEXT_READY;
}

typedef struct {
    bool oid_seen;
    bool head_seen;
    bool initial;
    bool detached;
} git_status_identity_t;

static bool status_value_is_hex_oid(const char *value, size_t len) {
    if (len != 40 && len != CBM_SHA256_HEX_LEN) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f') ||
              (value[i] >= 'A' && value[i] <= 'F'))) {
            return false;
        }
    }
    return true;
}

/* Porcelain v2 --branch is Git's stable, machine-readable identity stream. It
 * binds both the current object and the immediate symbolic/detached HEAD state;
 * accepting a stream without exactly one of each header would recreate the
 * same incomplete-input bug this watcher exists to prevent. */
static bool git_status_identity(const char *data, size_t len, git_status_identity_t *identity) {
    static const char oid_prefix[] = "# branch.oid ";
    static const char head_prefix[] = "# branch.head ";
    if (!data || !identity) {
        return false;
    }
    memset(identity, 0, sizeof(*identity));
    for (size_t offset = 0; offset < len;) {
        size_t end = offset;
        while (end < len && data[end] != '\0' && data[end] != '\n' && data[end] != '\r') {
            end++;
        }
        size_t record_len = end - offset;
        if (record_len >= sizeof(oid_prefix) - 1 &&
            memcmp(data + offset, oid_prefix, sizeof(oid_prefix) - 1) == 0) {
            if (identity->oid_seen) {
                return false;
            }
            const char *value = data + offset + sizeof(oid_prefix) - 1;
            size_t value_len = record_len - (sizeof(oid_prefix) - 1);
            identity->oid_seen = true;
            identity->initial = value_len == sizeof("(initial)") - 1 &&
                                memcmp(value, "(initial)", sizeof("(initial)") - 1) == 0;
            if (!identity->initial && !status_value_is_hex_oid(value, value_len)) {
                return false;
            }
        } else if (record_len >= sizeof(head_prefix) - 1 &&
                   memcmp(data + offset, head_prefix, sizeof(head_prefix) - 1) == 0) {
            if (identity->head_seen) {
                return false;
            }
            const char *value = data + offset + sizeof(head_prefix) - 1;
            size_t value_len = record_len - (sizeof(head_prefix) - 1);
            if (value_len == 0) {
                return false;
            }
            identity->head_seen = true;
            identity->detached = value_len == sizeof("(detached)") - 1 &&
                                 memcmp(value, "(detached)", sizeof("(detached)") - 1) == 0;
        }
        while (end < len && (data[end] == '\0' || data[end] == '\n' || data[end] == '\r')) {
            end++;
        }
        offset = end;
    }
    return identity->oid_seen && identity->head_seen && !(identity->initial && identity->detached);
}
#endif

/* Captures every Git input that can affect a watcher publication without an
 * extra HEAD process: branch/OID identity, index/worktree names and states,
 * exact untracked bytes, and the complete tracked patch. The first-commit
 * (initial) form diffs worktree against index because no HEAD tree exists. */
static bool git_source_fingerprint(const project_state_t *s, char out[CBM_SHA256_HEX_LEN + 1],
                                   const char **failure_code) {
    if (failure_code) {
        *failure_code = NULL;
    }
    if (!s || !s->git_context_ready || !s->git_dir_arg || !s->work_tree_arg || !s->git_work_tree) {
        if (failure_code) {
            *failure_code = CBM_WATCHER_GIT_CONTEXT_FAILED;
        }
        return false;
    }
    cbm_sha256_ctx hash;
    cbm_sha256_init(&hash);
#ifdef ASTRO_SPAWN
    const char *const argv[] = {"git",
                                "--no-optional-locks",
                                s->git_dir_arg,
                                s->work_tree_arg,
                                "status",
                                "--porcelain=v2",
                                "--branch",
                                "-z",
                                "--untracked-files=all",
                                NULL};
    char *data = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    if (cbm_spawn_capture(argv, &data, &len, &err) != 0) {
        cbm_log_warn(
            "watcher.git_status.failed", "code", CBM_WATCHER_GIT_STATUS_FAILED, "project",
            s->project_name, "path", s->root_path, "spawn_code", err.code_name, "message",
            err.message, "remediation",
            "repair the exact registered Git directory; parent repositories are never used");
        if (failure_code) {
            *failure_code = CBM_WATCHER_GIT_STATUS_FAILED;
        }
        free(data);
#else
    char cmd[CBM_SZ_1K];
    snprintf(cmd, sizeof(cmd),
             "git --no-optional-locks -C \"%s\" status --porcelain=v2 --branch "
             "--untracked-files=all 2>%s",
             s->root_path, WATCHER_NULDEV);
    FILE *fp = cbm_popen(cmd, "r");
    if (!fp) {
#endif
        return false;
    }
#ifdef ASTRO_SPAWN
    git_status_identity_t identity;
    if (!git_status_identity(data, len, &identity)) {
        cbm_log_warn("watcher.git_status.identity_invalid", "code",
                     CBM_WATCHER_GIT_IDENTITY_INVALID, "project", s->project_name, "path",
                     s->root_path, "remediation",
                     "inspect git status --porcelain=v2 --branch and repair HEAD before polling");
        if (failure_code) {
            *failure_code = CBM_WATCHER_GIT_IDENTITY_INVALID;
        }
        free(data);
        return false;
    }
    cbm_sha256_update(&hash, data, len);
    /* Porcelain names untracked files but does not include their contents.
     * Fold those bytes in so repeated edits to a still-untracked file are not
     * mistaken for the already-indexed dirty state. `-z` makes paths literal. */
    for (size_t offset = 0; offset < len;) {
        size_t end = offset;
        while (end < len && data[end] != '\0') {
            end++;
        }
        if (end >= offset + 2 && data[offset] == '?' && data[offset + 1] == ' ') {
            size_t path_len = end - (offset + 2);
            size_t root_len = strlen(s->git_work_tree);
            char *path = malloc(root_len + path_len + 2);
            if (!path) {
                cbm_log_warn("watcher.git_status.untracked_alloc_failed", "code",
                             CBM_WATCHER_UNTRACKED_ALLOC_FAILED, "project", s->project_name, "path",
                             s->root_path, "remediation",
                             "free memory before polling the complete Git source state");
                if (failure_code) {
                    *failure_code = CBM_WATCHER_UNTRACKED_ALLOC_FAILED;
                }
                free(data);
                return false;
            }
            memcpy(path, s->git_work_tree, root_len);
            path[root_len] = '/';
            memcpy(path + root_len + 1, data + offset + 2, path_len);
            path[root_len + path_len + 1] = '\0';
            FILE *untracked = fopen(path, "rb");
            if (!untracked) {
                char errno_text[CBM_SZ_64];
                snprintf(errno_text, sizeof(errno_text), "%d", errno);
                cbm_log_warn("watcher.git_status.untracked_read_failed", "code",
                             CBM_WATCHER_UNTRACKED_READ_FAILED, "project", s->project_name, "path",
                             path, "errno", errno_text, "remediation",
                             "restore the exact porcelain-named file or change Git source state");
                if (failure_code) {
                    *failure_code = CBM_WATCHER_UNTRACKED_READ_FAILED;
                }
                free(path);
                free(data);
                return false;
            }
            char chunk[CBM_SZ_1K];
            size_t chunk_len;
            while ((chunk_len = fread(chunk, 1, sizeof(chunk), untracked)) > 0) {
                cbm_sha256_update(&hash, chunk, chunk_len);
            }
            if (ferror(untracked)) {
                char errno_text[CBM_SZ_64];
                snprintf(errno_text, sizeof(errno_text), "%d", errno);
                cbm_log_warn("watcher.git_status.untracked_read_failed", "code",
                             CBM_WATCHER_UNTRACKED_READ_FAILED, "project", s->project_name, "path",
                             path, "errno", errno_text, "remediation",
                             "restore the exact porcelain-named file or change Git source state");
                if (failure_code) {
                    *failure_code = CBM_WATCHER_UNTRACKED_READ_FAILED;
                }
                fclose(untracked);
                free(path);
                free(data);
                return false;
            }
            fclose(untracked);
            free(path);
        }
        offset = end + 1;
    }
    free(data);

    /* Porcelain status contains names/status only. Fold the complete tracked
     * patch in so successive edits to the same dirty path produce new state. */
    const char *const diff_committed_argv[] = {"git",
                                               "--no-optional-locks",
                                               s->git_dir_arg,
                                               s->work_tree_arg,
                                               "diff",
                                               "--binary",
                                               "--no-ext-diff",
                                               "--no-textconv",
                                               "--no-renames",
                                               "HEAD",
                                               "--",
                                               NULL};
    const char *const diff_initial_argv[] = {
        "git",      "--no-optional-locks", s->git_dir_arg,  s->work_tree_arg, "diff",
        "--binary", "--no-ext-diff",       "--no-textconv", "--no-renames",   "--",
        NULL};
    const char *const *diff_argv = identity.initial ? diff_initial_argv : diff_committed_argv;
    data = NULL;
    len = 0;
    if (cbm_spawn_capture(diff_argv, &data, &len, &err) != 0) {
        cbm_log_warn("watcher.git_diff.failed", "code", CBM_WATCHER_GIT_DIFF_FAILED, "project",
                     s->project_name, "path", s->root_path, "spawn_code", err.code_name, "message",
                     err.message, "remediation",
                     "repair the exact registered Git directory before watcher retry");
        if (failure_code) {
            *failure_code = CBM_WATCHER_GIT_DIFF_FAILED;
        }
        free(data);
        return false;
    }
    cbm_sha256_update(&hash, data, len);
    free(data);
#else
    char chunk[CBM_SZ_1K];
    size_t chunk_len;
    while ((chunk_len = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        cbm_sha256_update(&hash, chunk, chunk_len);
    }
    int rc = cbm_pclose(fp);
    if (rc != 0) {
        return false;
    }
    /* Porcelain status carries names/status only: it is byte-identical across
     * successive edits to an already-modified tracked file (` M file` stays
     * ` M file`). Fold the complete tracked patch in — parity with the
     * ASTRO_SPAWN path's `git diff --binary HEAD` fold above — so each distinct
     * edit to the same dirty path yields a new fingerprint and is reindexed
     * once, instead of the watcher going blind after the first edit. */
    char diff_cmd[CBM_SZ_1K];
    snprintf(diff_cmd, sizeof(diff_cmd),
             "git --no-optional-locks -C \"%s\" diff --binary --no-ext-diff --no-textconv "
             "--no-renames HEAD -- 2>%s",
             s->root_path, WATCHER_NULDEV);
    FILE *dfp = cbm_popen(diff_cmd, "r");
    if (!dfp) {
        return false;
    }
    while ((chunk_len = fread(chunk, 1, sizeof(chunk), dfp)) > 0) {
        cbm_sha256_update(&hash, chunk, chunk_len);
    }
    if (cbm_pclose(dfp) != 0) {
        return false;
    }
#endif
    uint8_t digest[CBM_SHA256_DIGEST_LEN];
    cbm_sha256_final(&hash, digest);
    for (size_t i = 0; i < CBM_SHA256_DIGEST_LEN; i++) {
        snprintf(out + (i * 2), 3, "%02x", digest[i]);
    }
    out[CBM_SHA256_HEX_LEN] = '\0';
    return true;
}

/* Count tracked files via git ls-files */
static int git_file_count(const project_state_t *s) {
#ifdef ASTRO_SPAWN
    if (!s || !s->git_context_ready || !s->git_dir_arg || !s->work_tree_arg) {
        return 0;
    }
    const char *const argv[] = {"git", s->git_dir_arg, s->work_tree_arg, "ls-files", NULL};
    char *data = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    if (cbm_spawn_capture(argv, &data, &len, &err) != 0) {
        watcher_log_spawn_failure("watcher.git_file_count.spawn_failed", &err);
        free(data);
#else
    char cmd[CBM_SZ_1K];
    snprintf(cmd, sizeof(cmd), "git -C \"%s\" ls-files 2>%s", s->root_path, WATCHER_NULDEV);
    FILE *fp = cbm_popen(cmd, "r");
    if (!fp) {
#endif
        return 0;
    }

#ifdef ASTRO_SPAWN
    /* One tracked file per line. */
#else
    /* Count newlines (one tracked file per line). `wc -l` is unavailable on
     * Windows, so count in C, robust to paths longer than the read buffer. */
#endif
    int count = 0;
#ifdef ASTRO_SPAWN
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\n') {
            count++;
#else
    char buf[CBM_SZ_1K];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        for (size_t i = 0; i < n; i++) {
            if (buf[i] == '\n') {
                count++;
            }
#endif
        }
    }
#ifdef ASTRO_SPAWN
    free(data);
#else
    cbm_pclose(fp);
#endif
    return count;
}

/* ── Project state lifecycle ────────────────────────────────────── */

static project_state_t *state_new(const char *name, const char *root_path) {
    project_state_t *s = calloc(CBM_ALLOC_ONE, sizeof(*s));
    if (!s) {
        return NULL;
    }
    s->project_name = strdup(name);
    s->root_path = strdup(root_path);
    s->interval_ms = POLL_BASE_MS;
    return s;
}

static void state_free(project_state_t *s) {
    if (!s) {
        return;
    }
    free(s->project_name);
    free(s->root_path);
    free(s->git_dir_arg);
    free(s->work_tree_arg);
    free(s->git_work_tree);
    free(s);
}

/* Move a state onto the deferred-free list (caller holds projects_lock).
 * The state may still be referenced by a poll_once snapshot; poll_once
 * drains the list at the start of its next cycle. Returns false when
 * growing the list fails (OOM): the state is left untouched and the
 * caller must keep it registered — freeing it immediately here could be
 * a use-after-free against an in-flight poll snapshot. */
static bool defer_state_free(cbm_watcher_t *w, project_state_t *s) {
    if (w->pending_free_count >= w->pending_free_cap) {
        int new_cap = w->pending_free_cap ? w->pending_free_cap * 2 : 8;
        project_state_t **tmp =
            realloc(w->pending_free, (size_t)new_cap * sizeof(project_state_t *));
        if (!tmp) {
            cbm_log_warn("watcher.unwatch.oom", "project", s->project_name);
            return false;
        }
        w->pending_free = tmp;
        w->pending_free_cap = new_cap;
    }
    w->pending_free[w->pending_free_count++] = s;
    return true;
}

/* Hash table foreach callback to free state entries */
static void free_state_entry(const char *key, void *val, void *ud) {
    (void)key;
    (void)ud;
    state_free(val);
}

/* ── Watcher lifecycle ──────────────────────────────────────────── */

cbm_watcher_t *cbm_watcher_new(cbm_store_t *store, cbm_index_fn index_fn, void *user_data) {
    cbm_watcher_t *w = calloc(CBM_ALLOC_ONE, sizeof(*w));
    if (!w) {
        return NULL;
    }
    w->store = store;
    w->index_fn = index_fn;
    w->user_data = user_data;
    w->projects = cbm_ht_create(CBM_SZ_32);
    if (!w->projects) {
        free(w);
        return NULL;
    }
    cbm_mutex_init(&w->projects_lock);
    atomic_init(&w->stopped, 0);
    return w;
}

void cbm_watcher_free(cbm_watcher_t *w) {
    if (!w) {
        return;
    }
    /* Safety net: ensure stopped is set before draining pending_free.
     * In production the caller should cbm_watcher_stop() + join first. */
    atomic_store(&w->stopped, 1);
    cbm_mutex_lock(&w->projects_lock);
    cbm_ht_foreach(w->projects, free_state_entry, NULL);
    cbm_ht_free(w->projects);
    for (int i = 0; i < w->pending_free_count; i++) {
        state_free(w->pending_free[i]);
    }
    free(w->pending_free);
    cbm_mutex_unlock(&w->projects_lock);
    cbm_mutex_destroy(&w->projects_lock);
    free(w);
}

/* ── Watch list management ──────────────────────────────────────── */

void cbm_watcher_watch(cbm_watcher_t *w, const char *project_name, const char *root_path) {
    if (!w || !project_name || !root_path) {
        return;
    }

#ifdef ASTRO_SPAWN
    /* Defence in depth (#227/#228): the git helpers no longer use a shell at all,
     * so this is no longer the only barrier — but a path carrying shell
     * metacharacters is still refused rather than silently watched. */
#else
    /* Reject paths with shell metacharacters — all git helpers use popen/system */
#endif
    if (!cbm_validate_shell_arg(root_path)) {
        cbm_log_warn("watcher.watch.reject", "project", project_name, "reason",
                     "path contains shell metacharacters");
        return;
    }

    cbm_mutex_lock(&w->projects_lock);
    project_state_t *s = state_new(project_name, root_path);
    if (!s) {
        cbm_mutex_unlock(&w->projects_lock);
        cbm_log_warn("watcher.watch.oom", "project", project_name, "path", root_path);
        return;
    }
    void *previous = NULL;
    if (!cbm_ht_set_checked(w->projects, s->project_name, s, &previous)) {
        state_free(s);
        cbm_mutex_unlock(&w->projects_lock);
        cbm_log_error("watcher.watch.insert_failed", "code", "CBM_HASH_INSERT_FAILED", "component",
                      "watcher.projects", "operation", "watch.replace", "key", project_name,
                      "message", "watch registration could not be committed", "remediation",
                      "free memory and retry; the prior watch remains active");
        return;
    }
    state_free(previous);
    cbm_mutex_unlock(&w->projects_lock);
    cbm_log_info("watcher.watch", "project", project_name, "path", root_path);
}

void cbm_watcher_unwatch(cbm_watcher_t *w, const char *project_name) {
    if (!w || !project_name) {
        return;
    }
    bool removed = false;
    cbm_mutex_lock(&w->projects_lock);
    project_state_t *s = cbm_ht_get(w->projects, project_name);
    if (s && defer_state_free(w, s)) {
        /* The entry leaves the table only once its state is safely on
         * the deferred-free list; on OOM the watch stays registered. */
        cbm_ht_delete(w->projects, project_name);
        removed = true;
    }
    cbm_mutex_unlock(&w->projects_lock);
    if (removed) {
        cbm_log_info("watcher.unwatch", "project", project_name);
    }
}

void cbm_watcher_touch(cbm_watcher_t *w, const char *project_name) {
    if (!w || !project_name) {
        return;
    }
    cbm_mutex_lock(&w->projects_lock);
    project_state_t *s = cbm_ht_get(w->projects, project_name);
    if (s) {
        /* Reset backoff — poll immediately on next cycle */
        s->next_poll_ns = 0;
    }
    cbm_mutex_unlock(&w->projects_lock);
}

void cbm_watcher_invalidate(cbm_watcher_t *w, const char *project_name) {
    if (!w || !project_name) {
        return;
    }
    cbm_mutex_lock(&w->projects_lock);
    project_state_t *s = cbm_ht_get(w->projects, project_name);
    if (s) {
        /* A SHA-256 Git source fingerprint is exactly 64 lowercase hex bytes;
         * this non-hex sentinel can never equal a real observation. */
        snprintf(s->source_sha256, sizeof(s->source_sha256), "%s", "invalidated");
        s->next_poll_ns = 0;
    }
    cbm_mutex_unlock(&w->projects_lock);
}

int cbm_watcher_watch_count(cbm_watcher_t *w) {
    if (!w) {
        return 0;
    }
    cbm_mutex_lock(&w->projects_lock);
    int count = (int)cbm_ht_count(w->projects);
    cbm_mutex_unlock(&w->projects_lock);
    return count;
}

/* ── Single poll cycle ──────────────────────────────────────────── */

/* Init one coherent Git source baseline for a project. */
static void init_baseline(project_state_t *s) {
    struct stat st;
    if (stat(s->root_path, &st) != 0) {
        cbm_log_warn("watcher.root_gone", "project", s->project_name, "path", s->root_path);
        s->baseline_done = true;
        s->is_git = false;
        return;
    }

    git_context_result_t context = watcher_resolve_git_context(s);
    s->is_git = context != GIT_CONTEXT_NOT_REPOSITORY;
    s->baseline_done = true;

    if (context == GIT_CONTEXT_READY) {
        const char *failure_code = NULL;
        (void)git_source_fingerprint(s, s->source_sha256, &failure_code);
        s->file_count = git_file_count(s);
        s->interval_ms = cbm_watcher_poll_interval_ms(s->file_count);
        cbm_log_info("watcher.baseline", "project", s->project_name, "strategy", "git", "files",
                     s->file_count > 0 ? "yes" : "0");
    } else if (context == GIT_CONTEXT_FAILED) {
        cbm_log_warn("watcher.baseline.refused", "project", s->project_name, "code",
                     CBM_WATCHER_GIT_CONTEXT_FAILED, "remediation",
                     "repair the exact registered Git context before watcher retry");
    } else {
        cbm_log_info("watcher.baseline", "project", s->project_name, "strategy", "none");
    }

    s->next_poll_ns = now_ns() + ((int64_t)s->interval_ms * US_PER_MS);
}

typedef struct {
    char source_sha256[CBM_SHA256_HEX_LEN + 1];
    bool source_observed;
    const char *failure_code;
} project_observation_t;

typedef enum {
    PROJECT_OBSERVATION_FAILED = -1,
    PROJECT_OBSERVATION_UNCHANGED = 0,
    PROJECT_OBSERVATION_CHANGED = 1,
    PROJECT_OBSERVATION_RECOVERED = 2,
} project_observation_result_t;

/* Observe whether a project has changes without advancing the successful
 * baseline. The exact pre-callback source observation is committed only after the
 * index callback succeeds. This is deliberately transactional: acknowledging
 * identity before a failed callback makes a source change invisible to every
 * later poll, while re-observing after success can swallow bytes that changed
 * during the index generation itself. */
static project_observation_result_t check_changes(project_state_t *s,
                                                  project_observation_t *observation) {
    if (!s->is_git) {
        return PROJECT_OBSERVATION_UNCHANGED;
    }

    memset(observation, 0, sizeof(*observation));

    if (!s->git_context_ready && watcher_resolve_git_context(s) != GIT_CONTEXT_READY) {
        observation->failure_code = CBM_WATCHER_GIT_CONTEXT_FAILED;
        s->observation_failed = true;
        return PROJECT_OBSERVATION_FAILED;
    }

    observation->source_observed =
        git_source_fingerprint(s, observation->source_sha256, &observation->failure_code);
    if (!observation->source_observed) {
        if (!observation->failure_code) {
            observation->failure_code = CBM_WATCHER_GIT_CONTEXT_FAILED;
        }
        s->observation_failed = true;
        return PROJECT_OBSERVATION_FAILED;
    }
    if (strcmp(observation->source_sha256, s->source_sha256) != 0) {
        return PROJECT_OBSERVATION_CHANGED;
    }
    return s->observation_failed ? PROJECT_OBSERVATION_RECOVERED : PROJECT_OBSERVATION_UNCHANGED;
}

static void commit_observation(project_state_t *s, const project_observation_t *observation) {
    if (observation->source_observed) {
        snprintf(s->source_sha256, sizeof(s->source_sha256), "%s", observation->source_sha256);
    }
}

/* Context for poll_once foreach callback */
typedef struct {
    cbm_watcher_t *w;
    int64_t now;
    int reindexed;
} poll_ctx_t;

static void poll_project(const char *key, void *val, void *ud) {
    (void)key;
    poll_ctx_t *ctx = ud;
    project_state_t *s = val;
    if (!s) {
        return;
    }

    /* Initialize baseline on first poll */
    if (!s->baseline_done) {
        init_baseline(s);
        return;
    }

    /* Skip non-git projects */
    if (!s->is_git) {
        return;
    }

    /* Respect adaptive interval */
    if (ctx->now < s->next_poll_ns) {
        return;
    }

    /* Check for changes */
    project_observation_t observation;
    project_observation_result_t observation_result = check_changes(s, &observation);
    if (observation_result == PROJECT_OBSERVATION_UNCHANGED) {
        s->next_poll_ns = ctx->now + ((int64_t)s->interval_ms * US_PER_MS);
        return;
    }

    const char *trigger_code = observation_result == PROJECT_OBSERVATION_CHANGED
                                   ? CBM_WATCHER_SOURCE_CHANGED
                                   : (observation_result == PROJECT_OBSERVATION_RECOVERED
                                          ? CBM_WATCHER_SOURCE_OBSERVATION_RECOVERED
                                          : observation.failure_code);
    if (observation_result == PROJECT_OBSERVATION_CHANGED) {
        cbm_log_info("watcher.changed", "project", s->project_name, "strategy", "git");
    } else if (observation_result == PROJECT_OBSERVATION_FAILED) {
        cbm_log_warn("watcher.observation.refused", "project", s->project_name, "code",
                     trigger_code, "remediation",
                     "inspect the preceding Git observation diagnostic and repair the exact "
                     "registered repository");
    }
    if (ctx->w->index_fn) {
        int rc = ctx->w->index_fn(s->project_name, s->root_path, trigger_code, ctx->w->user_data);
        if (rc == 0) {
            if (observation_result == PROJECT_OBSERVATION_CHANGED) {
                ctx->reindexed++;
                commit_observation(s, &observation);
                /* Refresh file count for interval */
                s->file_count = git_file_count(s);
                s->interval_ms = cbm_watcher_poll_interval_ms(s->file_count);
            }
            if (observation_result == PROJECT_OBSERVATION_CHANGED ||
                observation_result == PROJECT_OBSERVATION_RECOVERED) {
                s->observation_failed = false;
            }
        } else {
            if (rc != 0) {
                cbm_log_warn("watcher.index.err", "project", s->project_name, "trigger_code",
                             trigger_code);
            }
        }
    }

    s->next_poll_ns = ctx->now + ((int64_t)s->interval_ms * US_PER_MS);
}

/* Callback to snapshot project state pointers into an array. */
typedef struct {
    project_state_t **items;
    int count;
    int cap;
} snapshot_ctx_t;

static void snapshot_project(const char *key, void *val, void *ud) {
    (void)key;
    snapshot_ctx_t *sc = ud;
    if (val && sc->count < sc->cap) {
        sc->items[sc->count++] = val;
    }
}

int cbm_watcher_poll_once(cbm_watcher_t *w) {
    if (!w) {
        return 0;
    }

    /* Snapshot project pointers under lock, then poll without holding it.
     * This keeps the critical section small — poll_project does git I/O
     * and may invoke index_fn which runs the full pipeline. */
    cbm_mutex_lock(&w->projects_lock);

    /* Free deferred entries from the previous cycle. */
    for (int i = 0; i < w->pending_free_count; i++) {
        state_free(w->pending_free[i]);
    }
    w->pending_free_count = 0;

    int n = cbm_ht_count(w->projects);
    if (n == 0) {
        cbm_mutex_unlock(&w->projects_lock);
        return 0;
    }
    project_state_t **snap = malloc(n * sizeof(project_state_t *));
    if (!snap) {
        cbm_mutex_unlock(&w->projects_lock);
        return 0;
    }
    snapshot_ctx_t sc = {.items = snap, .count = 0, .cap = n};
    cbm_ht_foreach(w->projects, snapshot_project, &sc);
    cbm_mutex_unlock(&w->projects_lock);

    poll_ctx_t ctx = {
        .w = w,
        .now = now_ns(),
        .reindexed = 0,
    };
    for (int i = 0; i < sc.count; i++) {
        poll_project(NULL, snap[i], &ctx);
    }
    free(snap);
    return ctx.reindexed;
}

/* ── Blocking run loop ──────────────────────────────────────────── */

void cbm_watcher_stop(cbm_watcher_t *w) {
    if (w) {
        atomic_store(&w->stopped, 1);
    }
}

int cbm_watcher_run(cbm_watcher_t *w, int base_interval_ms) {
    if (!w) {
        return CBM_NOT_FOUND;
    }
    if (base_interval_ms <= 0) {
        base_interval_ms = POLL_BASE_MS;
    }

    cbm_log_info("watcher.start", "interval_ms", base_interval_ms > 999 ? "multi-sec" : "fast");

    while (!atomic_load(&w->stopped)) {
        cbm_watcher_poll_once(w);

        /* Sleep in small increments to allow responsive shutdown */
        int slept = 0;
        while (slept < base_interval_ms && !atomic_load(&w->stopped)) {
            int chunk = base_interval_ms - slept;
            if (chunk > SLEEP_CHUNK_MS) {
                chunk = SLEEP_CHUNK_MS;
            }
            cbm_usleep((unsigned)chunk * CBM_MSEC_PER_SEC);
            slept += chunk;
        }
    }

    cbm_log_info("watcher.stop");
    return 0;
}
