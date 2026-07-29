/*
 * watcher.c — Git-based file change watcher.
 *
 * Strategy: git status + HEAD tracking (the most reliable approach).
 * For non-git projects, the watcher skips polling (no fsnotify/dirmtime yet).
 *
 *
 * Per-project state tracks:
 *   - Last git HEAD hash (detects commits, checkout, pull)
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

typedef struct {
    char *project_name;
    char *root_path;
    char last_head[CBM_SZ_64];                    /* git HEAD hash */
    char worktree_sha256[CBM_SHA256_HEX_LEN + 1]; /* last successfully indexed porcelain state */
    bool is_git;                                  /* false → skip polling */
    bool baseline_done;                           /* true after first poll */
    int missing_root_count;    /* consecutive polls where root was missing (ENOENT/ENOTDIR) */
    uint64_t first_missing_ms; /* cbm_now_ms() of the streak's first miss (0 = no streak) */
    int file_count;            /* approximate, for interval calc */
    int interval_ms;           /* adaptive poll interval */
    int64_t next_poll_ns;      /* next poll time (monotonic ns) */
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

/* Stale-root pruning (#286): a watched project whose root directory stays
 * missing is pruned — its cached DB is deleted and the watch entry removed.
 * Deletion is destructive (the DB can hold user-authored data such as the
 * ADR), so it requires BOTH a streak of consecutive missing polls AND a
 * sustained-absence grace window measured from the streak's first miss. */
#define MISSING_ROOT_DELETE_AFTER 3
#define PRUNE_GRACE_DEFAULT_S 600 /* 10 min; override: CBM_WATCHER_PRUNE_GRACE_S */

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

static bool is_git_repo(const char *root_path) {
#ifdef ASTRO_SPAWN
    const char *const argv[] = {"git", "-C", root_path, "rev-parse", "--git-dir", NULL};
    char *data = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    int rc = cbm_spawn_capture(argv, &data, &len, &err);
    if (rc != 0) {
        watcher_log_spawn_failure("watcher.is_git_repo.spawn_failed", &err);
#else
    char cmd[CBM_SZ_1K];
    snprintf(cmd, sizeof(cmd), "git -C \"%s\" rev-parse --git-dir 2>%s", root_path, WATCHER_NULDEV);
    FILE *fp = cbm_popen(cmd, "r");
    if (!fp) {
        return false;
#endif
    }
#ifdef ASTRO_SPAWN
    free(data);
#else
    /* Drain output so pclose gets a clean exit status. */
    char drain[CBM_SZ_128];
    while (fgets(drain, (int)sizeof(drain), fp)) { /* discard */
    }
    int rc = cbm_pclose(fp);
#endif
    return rc == 0;
}

static int git_head(const char *root_path, char *out, size_t out_size) {
#ifdef ASTRO_SPAWN
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
#else
    char cmd[CBM_SZ_1K];
    snprintf(cmd, sizeof(cmd), "git -C \"%s\" rev-parse HEAD 2>%s", root_path, WATCHER_NULDEV);
    FILE *fp = cbm_popen(cmd, "r");
    if (!fp) {
#endif
        return CBM_NOT_FOUND;
    }

#ifdef ASTRO_SPAWN
    size_t line = 0;
    while (line < len && data[line] != '\n' && data[line] != '\r') {
        line++;
#else
    if (fgets(out, (int)out_size, fp)) {
        size_t len = strlen(out);
        while (len > 0 && (out[len - SKIP_ONE] == '\n' || out[len - SKIP_ONE] == '\r')) {
            out[--len] = '\0';
        }
        cbm_pclose(fp);
        return 0;
#endif
    }
#ifdef ASTRO_SPAWN
    if (line >= out_size) {
        line = out_size - SKIP_ONE;
    }
    memcpy(out, data, line);
    out[line] = '\0';
    bool captured = len > 0;
    free(data);
    return captured ? 0 : CBM_NOT_FOUND;
#else
    cbm_pclose(fp);
    return CBM_NOT_FOUND;
#endif
}

/* Captures a deterministic fingerprint of the working-tree state. Unlike a
 * boolean "dirty" probe, this distinguishes successive edits while the tree
 * remains dirty and prevents the watcher from reindexing the same dirty bytes
 * forever. The porcelain stream is stable and includes submodule dirtiness. */
static bool git_worktree_fingerprint(const char *root_path, char out[CBM_SHA256_HEX_LEN + 1]) {
    cbm_sha256_ctx hash;
    cbm_sha256_init(&hash);
#ifdef ASTRO_SPAWN
    const char *const argv[] = {"git",    "--no-optional-locks", "-C", root_path,
                                "status", "--porcelain=v1",      "-z", "--untracked-files=normal",
                                NULL};
    char *data = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    if (cbm_spawn_capture(argv, &data, &len, &err) != 0) {
        watcher_log_spawn_failure("watcher.git_status.spawn_failed", &err);
        free(data);
#else
    char cmd[CBM_SZ_1K];
    snprintf(cmd, sizeof(cmd),
             "git --no-optional-locks -C \"%s\" status --porcelain "
             "--untracked-files=normal 2>%s",
             root_path, WATCHER_NULDEV);
    FILE *fp = cbm_popen(cmd, "r");
    if (!fp) {
#endif
        return false;
    }
#ifdef ASTRO_SPAWN
    cbm_sha256_update(&hash, data, len);
    /* Porcelain names untracked files but does not include their contents.
     * Fold those bytes in so repeated edits to a still-untracked file are not
     * mistaken for the already-indexed dirty state. `-z` makes paths literal. */
    for (size_t offset = 0; offset < len;) {
        size_t end = offset;
        while (end < len && data[end] != '\0') {
            end++;
        }
        if (end >= offset + 3 && data[offset] == '?' && data[offset + 1] == '?' &&
            data[offset + 2] == ' ') {
            size_t path_len = end - (offset + 3);
            size_t root_len = strlen(root_path);
            char *path = malloc(root_len + path_len + 2);
            if (path) {
                memcpy(path, root_path, root_len);
                path[root_len] = '/';
                memcpy(path + root_len + 1, data + offset + 3, path_len);
                path[root_len + path_len + 1] = '\0';
                FILE *untracked = fopen(path, "rb");
                if (untracked) {
                    char chunk[CBM_SZ_1K];
                    size_t chunk_len;
                    while ((chunk_len = fread(chunk, 1, sizeof(chunk), untracked)) > 0) {
                        cbm_sha256_update(&hash, chunk, chunk_len);
                    }
                    fclose(untracked);
                }
                free(path);
            }
        }
        offset = end + 1;
    }
    free(data);

    /* Porcelain status contains names/status only. Fold the complete tracked
     * patch in so successive edits to the same dirty path produce new state. */
    const char *const diff_argv[] = {
        "git", "--no-optional-locks", "-C", root_path, "diff", "--binary", "HEAD", NULL};
    data = NULL;
    len = 0;
    if (cbm_spawn_capture(diff_argv, &data, &len, &err) != 0) {
        watcher_log_spawn_failure("watcher.git_diff.spawn_failed", &err);
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
             "git --no-optional-locks -C \"%s\" diff --binary HEAD 2>%s", root_path,
             WATCHER_NULDEV);
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
static int git_file_count(const char *root_path) {
#ifdef ASTRO_SPAWN
    const char *const argv[] = {"git", "-C", root_path, "ls-files", NULL};
    char *data = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    if (cbm_spawn_capture(argv, &data, &len, &err) != 0) {
        watcher_log_spawn_failure("watcher.git_file_count.spawn_failed", &err);
        free(data);
#else
    char cmd[CBM_SZ_1K];
    snprintf(cmd, sizeof(cmd), "git -C \"%s\" ls-files 2>%s", root_path, WATCHER_NULDEV);
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

/* ── Stale-root pruning (#286) ──────────────────────────────────── */

bool cbm_watcher_root_missing_errno(int err) {
    /* Only ENOENT/ENOTDIR mean the root itself is gone. Anything else
     * (EACCES, EIO, ELOOP, a transient network mount, macOS TCC permission
     * revocation) is uncertainty: the directory may still exist even though
     * we cannot see it right now — never treat it as a deletion signal.
     * Windows (mingw/UCRT) maps ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND
     * to ENOENT, so the same check holds there (same convention as
     * find_deleted_files in pipeline_incremental.c). */
    return err == ENOENT || err == ENOTDIR;
}

typedef enum {
    ROOT_PRESENT = 0, /* stat succeeded and the root is a directory */
    ROOT_MISSING,     /* genuinely gone: ENOENT/ENOTDIR (or replaced by a non-directory) */
    ROOT_UNCERTAIN,   /* any other stat failure — must NOT count toward pruning */
} root_status_t;

static root_status_t root_status(const char *root_path, int *out_errno) {
    *out_errno = 0;
    if (!root_path) {
        return ROOT_UNCERTAIN;
    }
    struct stat st;
    if (stat(root_path, &st) == 0) {
        /* Exists but is no longer a directory → the root directory is gone. */
        return S_ISDIR(st.st_mode) ? ROOT_PRESENT : ROOT_MISSING;
    }
    *out_errno = errno;
    return cbm_watcher_root_missing_errno(errno) ? ROOT_MISSING : ROOT_UNCERTAIN;
}

/* Sustained-absence window (seconds) before a missing root may be pruned.
 * Generous default: 10 minutes. Override with CBM_WATCHER_PRUNE_GRACE_S
 * (>= 0; 0 prunes as soon as the missing-poll streak is reached). Read on
 * each call so tests/operators can adjust via setenv without a restart —
 * same convention as cbm_max_file_bytes in limits.c. */
static long prune_grace_s(void) {
    const char *raw = getenv("CBM_WATCHER_PRUNE_GRACE_S");
    if (raw && raw[0]) {
        errno = 0;
        char *end = NULL;
        long v = strtol(raw, &end, 10);
        if (errno == 0 && end != raw && *end == '\0' && v >= 0) {
            return v;
        }
        /* Unparseable / negative → fall through to the safe default. */
    }
    return PRUNE_GRACE_DEFAULT_S;
}

/* Format int to string for logging (poll thread only, one use per call). */
static const char *itoa_buf(int v) {
    static CBM_TLS char buf[CBM_SZ_32];
    snprintf(buf, sizeof(buf), "%d", v);
    return buf;
}

static void delete_cached_project_db(const char *project_name) {
    if (!cbm_validate_project_name(project_name)) {
        return;
    }

    const char *cache_dir = cbm_resolve_cache_dir();
    if (!cache_dir) {
        return;
    }

    char path[CBM_SZ_1K];
    char wal[CBM_SZ_1K];
    char shm[CBM_SZ_1K];
    snprintf(path, sizeof(path), "%s/%s.db", cache_dir, project_name);
    snprintf(wal, sizeof(wal), "%s-wal", path);
    snprintf(shm, sizeof(shm), "%s-shm", path);
    (void)cbm_unlink(path);
    (void)cbm_unlink(wal);
    (void)cbm_unlink(shm);
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
        /* A SHA-256 worktree fingerprint is exactly 64 lowercase hex bytes;
         * this non-hex sentinel can never equal a real observation. */
        snprintf(s->worktree_sha256, sizeof(s->worktree_sha256), "%s", "invalidated");
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

/* Init baseline for a project: check if git, get HEAD, count files */
static void init_baseline(project_state_t *s) {
    struct stat st;
    if (stat(s->root_path, &st) != 0) {
        cbm_log_warn("watcher.root_gone", "project", s->project_name, "path", s->root_path);
        s->baseline_done = true;
        s->is_git = false;
        return;
    }

    s->is_git = is_git_repo(s->root_path);
    s->baseline_done = true;

    if (s->is_git) {
        git_head(s->root_path, s->last_head, sizeof(s->last_head));
        (void)git_worktree_fingerprint(s->root_path, s->worktree_sha256);
        s->file_count = git_file_count(s->root_path);
        s->interval_ms = cbm_watcher_poll_interval_ms(s->file_count);
        cbm_log_info("watcher.baseline", "project", s->project_name, "strategy", "git", "files",
                     s->file_count > 0 ? "yes" : "0");
    } else {
        cbm_log_info("watcher.baseline", "project", s->project_name, "strategy", "none");
    }

    s->next_poll_ns = now_ns() + ((int64_t)s->interval_ms * US_PER_MS);
}

/* Check if a project has changes. Returns true if reindex needed. */
static bool check_changes(project_state_t *s) {
    if (!s->is_git) {
        return false;
    }

    /* Check HEAD movement */
    char head[CBM_SZ_64] = {0};
    if (git_head(s->root_path, head, sizeof(head)) == 0) {
        if (s->last_head[0] != '\0' && strcmp(head, s->last_head) != 0) {
            /* HEAD moved — commit, checkout, pull */
            /* #229/#273: bounded copy with a guaranteed NUL terminator. The vendored
             * strncpy(dst, src, sizeof-1) does not terminate when `head` fills the
             * buffer (a genuine latent bug) and trips GCC 14 -Wstringop-truncation.
             * strnlen caps the length, memcpy copies exactly that many bytes, and the
             * explicit NUL terminates. Unconditional (#273): the fix ships in libcbm.a
             * too, instead of being masked by a blanket -Wno-stringop-truncation. */
            size_t head_len = strnlen(head, sizeof(s->last_head) - 1);
            memcpy(s->last_head, head, head_len);
            s->last_head[head_len] = '\0';
            return true;
        }
        /* #229/#273: bounded copy with a guaranteed NUL terminator (see above). */
        size_t head_len = strnlen(head, sizeof(s->last_head) - 1);
        memcpy(s->last_head, head, head_len);
        s->last_head[head_len] = '\0';
    }

    /* Check whether the porcelain state changed since the last successful
     * indexing tick, including successive edits while the tree remains dirty. */
    char worktree_sha256[CBM_SHA256_HEX_LEN + 1] = {0};
    return git_worktree_fingerprint(s->root_path, worktree_sha256) &&
           strcmp(worktree_sha256, s->worktree_sha256) != 0;
}

/* Context for poll_once foreach callback */
typedef struct {
    cbm_watcher_t *w;
    int64_t now;
    int reindexed;
} poll_ctx_t;

static void prune_missing_project(cbm_watcher_t *w, project_state_t *s) {
    if (!w || !s || !s->project_name) {
        return;
    }

    char project_name[CBM_SZ_1K];
    snprintf(project_name, sizeof(project_name), "%s", s->project_name);

    bool removed = false;
    cbm_mutex_lock(&w->projects_lock);
    project_state_t *current = cbm_ht_get(w->projects, project_name);
    /* Deferred free (same discipline as cbm_watcher_unwatch): this state
     * is referenced by the poll_once snapshot iterating us. On OOM the
     * watch stays registered and pruning retries on the next cycle. */
    if (current == s && defer_state_free(w, s)) {
        delete_cached_project_db(project_name);
        cbm_ht_delete(w->projects, project_name);
        removed = true;
    }
    cbm_mutex_unlock(&w->projects_lock);

    if (removed) {
        cbm_log_info("watcher.root_pruned", "project", project_name);
    }
}

static void poll_project(const char *key, void *val, void *ud) {
    (void)key;
    poll_ctx_t *ctx = ud;
    project_state_t *s = val;
    if (!s) {
        return;
    }

    /* Stale-root pruning (#286): classify the root BEFORE the baseline /
     * is_git / interval gates so vanished roots are noticed even for
     * non-git projects and regardless of adaptive backoff. */
    int stat_errno = 0;
    root_status_t rs = root_status(s->root_path, &stat_errno);
    if (rs == ROOT_UNCERTAIN) {
        /* EACCES / EIO / network blip / TCC revocation — the root may still
         * exist. Never count toward pruning; restart the streak so only an
         * uninterrupted run of genuine ENOENT/ENOTDIR observations can
         * delete user data. */
        if (s->missing_root_count > 0) {
            s->missing_root_count = 0;
            s->first_missing_ms = 0;
        }
        cbm_log_warn("watcher.root_stat_error", "project", s->project_name, "path", s->root_path,
                     "errno", itoa_buf(stat_errno));
        return;
    }
    if (rs == ROOT_MISSING) {
        uint64_t now_ms = cbm_now_ms();
        if (s->missing_root_count == 0) {
            s->first_missing_ms = now_ms;
        }
        s->missing_root_count++;
        cbm_log_warn("watcher.root_missing", "project", s->project_name, "path", s->root_path,
                     "polls", itoa_buf(s->missing_root_count));
        if (s->missing_root_count >= MISSING_ROOT_DELETE_AFTER &&
            now_ms - s->first_missing_ms >= (uint64_t)prune_grace_s() * CBM_MSEC_PER_SEC) {
            prune_missing_project(ctx->w, s);
        }
        return;
    }
    if (s->missing_root_count > 0) {
        cbm_log_info("watcher.root_restored", "project", s->project_name, "path", s->root_path);
        s->missing_root_count = 0;
        s->first_missing_ms = 0;
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
    bool changed = check_changes(s);
    if (!changed) {
        s->next_poll_ns = ctx->now + ((int64_t)s->interval_ms * US_PER_MS);
        return;
    }

    /* Trigger reindex */
    cbm_log_info("watcher.changed", "project", s->project_name, "strategy", "git");
    if (ctx->w->index_fn) {
        int rc = ctx->w->index_fn(s->project_name, s->root_path, ctx->w->user_data);
        if (rc == 0) {
            ctx->reindexed++;
            /* Update HEAD after successful reindex */
            git_head(s->root_path, s->last_head, sizeof(s->last_head));
            (void)git_worktree_fingerprint(s->root_path, s->worktree_sha256);
            /* Refresh file count for interval */
            s->file_count = git_file_count(s->root_path);
            s->interval_ms = cbm_watcher_poll_interval_ms(s->file_count);
        } else {
            cbm_log_warn("watcher.index.err", "project", s->project_name);
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
