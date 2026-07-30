/*
 * pass_githistory.c — Analyze git log to find change coupling.
 *
 * Runs `git log --name-only --since=6 months ago` and computes
 * file pairs that change together frequently. Creates FILE_CHANGES_WITH
 * edges between File nodes with coupling_score properties.
 *
 * Skips commits with >20 files (refactoring/merge noise).
 * Requires minimum 3 co-changes for an edge.
 *
 * Depends on: pass_structure having created File nodes
 */
#include "foundation/constants.h"

enum { GH_RING = 4, GH_RING_MASK = 3, GH_INIT_CAP = 16, GH_MIN_COMMITS = 3, GH_MAX_FILES = 20 };

#define SLEN(s) (sizeof(s) - 1)
#include "pipeline/pipeline.h"
#include "pipeline/pipeline_internal.h"
#include "graph_buffer/graph_buffer.h"
#include "foundation/hash_table.h"
#include "foundation/dyn_array.h"
#include "foundation/log.h"
#include "foundation/platform.h"
#ifdef ASTRO_SPAWN
#include "astro_spawn.h"
#endif
#include "foundation/compat.h"
#ifndef ASTRO_SPAWN
#include "foundation/compat_fs.h"
#endif
#include "foundation/str_util.h"

/* Minimum coupling score to create an edge */
#define MIN_COUPLING_SCORE 0.3

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *itoa_log(int val) {
    static CBM_TLS char bufs[GH_RING][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + SKIP_ONE) & GH_RING_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", val);
    return bufs[i];
}

static bool ends_with(const char *s, size_t slen, const char *suffix) {
    size_t sflen = strlen(suffix);
    return slen >= sflen && strcmp(s + slen - sflen, suffix) == 0;
}

bool cbm_is_trackable_file(const char *path) {
    if (!path) {
        return false;
    }
    /* Skip directory prefixes */
#define LEN_NODE_MODULES_SLASH 13 /* strlen("node_modules/") */
    if (strncmp(path, ".git/", SLEN(".git/")) == 0 ||
        strncmp(path, "node_modules/", LEN_NODE_MODULES_SLASH) == 0 ||
        strncmp(path, "vendor/", SLEN("vendor/")) == 0 ||
        strncmp(path, "__pycache__/", SLEN("__pycache__/")) == 0 ||
        strncmp(path, ".cache/", SLEN(".cache/")) == 0) {
        return false;
    }
    /* Skip lock/generated file names */
    const char *base = strrchr(path, '/');
    base = base ? base + SKIP_ONE : path;
    if (strcmp(base, "package-lock.json") == 0 || strcmp(base, "yarn.lock") == 0 ||
        strcmp(base, "pnpm-lock.yaml") == 0 || strcmp(base, "Cargo.lock") == 0 ||
        strcmp(base, "poetry.lock") == 0 || strcmp(base, "composer.lock") == 0 ||
        strcmp(base, "Gemfile.lock") == 0 || strcmp(base, "Pipfile.lock") == 0) {
        return false;
    }
    /* Skip non-source file extensions */
    size_t len = strlen(path);
    if (ends_with(path, len, ".lock") || ends_with(path, len, ".sum") ||
        ends_with(path, len, ".min.js") || ends_with(path, len, ".min.css") ||
        ends_with(path, len, ".map") || ends_with(path, len, ".wasm") ||
        ends_with(path, len, ".png") || ends_with(path, len, ".jpg") ||
        ends_with(path, len, ".gif") || ends_with(path, len, ".ico") ||
        ends_with(path, len, ".svg")) {
        return false;
    }
    return true;
}

/* ── Commit parsing ───────────────────────────────────────────────── */

typedef struct {
    char **files;
    int count;
    int cap;
    long long timestamp; /* unix epoch of this commit; 0 when unknown */
} commit_t;

static bool commit_add_file(commit_t *c, const char *file) {
    if (!cbm_da_ensure_capacity((void **)&c->files, &c->cap, c->count + 1, sizeof(*c->files))) {
        return false;
    }
    char *copy = strdup(file);
    if (!copy) {
        return false;
    }
    c->files[c->count++] = copy;
    return true;
}

static void commit_free(commit_t *c) {
    for (int i = 0; i < c->count; i++) {
        free(c->files[i]);
    }
    free(c->files);
}

#ifdef ASTRO_SPAWN
/* ── git log parsing (shell-free `git log` spawn, #227) ───────────── */
#else
/* ── git log parsing (popen "git log") ────────────────────────────── */
#endif

static int parse_git_log(const char *repo_path, commit_t **out, int *out_count) {
    *out = NULL;
    *out_count = 0;

#ifdef ASTRO_SPAWN
    /* Defence in depth (#227/#228): the spawn below never reaches a shell, but a
     * repo path carrying shell metacharacters is still refused. */
#endif
    if (!cbm_validate_shell_arg(repo_path)) {
        return CBM_NOT_FOUND;
    }

#ifdef ASTRO_SPAWN
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
#else
    char cmd[CBM_SZ_1K];
#ifdef _WIN32
    /* cmd.exe does not recognize single quotes, and '/dev/null' is a POSIX path. */
    const char *null_dev = "NUL";
#else
    const char *null_dev = "/dev/null";
#endif
    /* git -C "<path>" works on both cmd.exe and POSIX shells. Double quotes are
     * safe here because cbm_validate_shell_arg (above) rejects ", $, `, \ and the
     * other shell metacharacters that would otherwise be active inside them. */
    snprintf(cmd, sizeof(cmd),
             "git -C \"%s\" log --name-only --pretty=format:COMMIT:%%H:%%ct "
             "--since=\"1 year ago\" --max-count=10000 2>%s",
             repo_path, null_dev);

    FILE *fp = cbm_popen(cmd, "r");
    if (!fp) {
#endif
        return CBM_NOT_FOUND;
    }

    int cap = 0;
    commit_t *commits = NULL;
    int count = 0;
    commit_t current = {0};

#ifdef ASTRO_SPAWN
    char *cursor = data;
    char *end = data + data_len;
    while (cursor < end) {
        char *line = cursor;
        char *newline = (char *)memchr(cursor, '\n', (size_t)(end - cursor));
        if (newline) {
            *newline = '\0';
            cursor = newline + SKIP_ONE;
        } else {
            cursor = end;
        }
#else
    char line[CBM_SZ_1K];
    while (fgets(line, sizeof(line), fp)) {
#endif
        size_t len = strlen(line);
#ifdef ASTRO_SPAWN
        while (len > 0 && line[len - SKIP_ONE] == '\r') {
#else
        while (len > 0 && (line[len - SKIP_ONE] == '\n' || line[len - SKIP_ONE] == '\r')) {
#endif
            line[--len] = '\0';
        }
        if (len == 0) {
            continue;
        }

        if (strncmp(line, "COMMIT:", SLEN("COMMIT:")) == 0) {
            if (current.count > 0) {
                if (!cbm_da_ensure_capacity((void **)&commits, &cap, count + 1, sizeof(*commits))) {
                    goto allocation_failed;
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
            if (!commit_add_file(&current, line)) {
                goto allocation_failed;
            }
        }
    }
    if (current.count > 0) {
        if (!cbm_da_ensure_capacity((void **)&commits, &cap, count + 1, sizeof(*commits))) {
            goto allocation_failed;
        }
        commits[count++] = current;
    } else {
        commit_free(&current);
    }

#ifdef ASTRO_SPAWN
    free(data);
#else
    cbm_pclose(fp);
#endif
    *out = commits;
    *out_count = count;
    return 0;

allocation_failed:
    commit_free(&current);
    for (int i = 0; i < count; i++) {
        commit_free(&commits[i]);
    }
    free(commits);
#ifdef ASTRO_SPAWN
    free(data);
#else
    cbm_pclose(fp);
#endif
    cbm_log_error(
        "githistory.parse_failed", "code", "CBM_GIT_HISTORY_ALLOCATION_FAILED", "component",
        "githistory.parse", "operation", "grow", "key", repo_path, "message",
        "git history allocation failed", "remediation",
        "free memory or reduce history size, then retry; no partial history was returned");
    return CBM_NOT_FOUND;
}

/* Callback to free hash table entries. */
static void free_counter(const char *key, void *val, void *ud) {
    (void)ud;
    safe_str_free(&key);
    free(val);
}

/* ── Standalone coupling computation (testable) ──────────────────── */

/* Context for collect_coupling_result callback. */
typedef struct {
    CBMHashTable *file_counts;
    CBMHashTable *pair_timestamps; /* pair_key → long long*: max commit ts */
    cbm_change_coupling_t *out;
    int out_count;
    int max_out;
} collect_coupling_ctx_t;

static void collect_coupling_cb(const char *pair_key, void *val, void *ud) {
    collect_coupling_ctx_t *cctx = ud;
    int co_count = *(int *)val;
    if (co_count < GH_MIN_COMMITS) {
        return;
    }
    if (cctx->out_count >= cctx->max_out) {
        return;
    }

    const char *sep = strchr(pair_key, '\x01');
    if (!sep) {
        return;
    }
    size_t la = sep - pair_key;
    const char *file_b = sep + SKIP_ONE;

    char file_a_buf[CBM_SZ_512];
    if (la >= sizeof(file_a_buf)) {
        return;
    }
    memcpy(file_a_buf, pair_key, la);
    file_a_buf[la] = '\0';

    int *count_a = cbm_ht_get(cctx->file_counts, file_a_buf);
    int *count_b = cbm_ht_get(cctx->file_counts, file_b);
    if (!count_a || !count_b) {
        return;
    }

    int min_total = *count_a < *count_b ? *count_a : *count_b;
    if (min_total == 0) {
        return;
    }

    double score = (double)co_count / (double)min_total;
    if (score < MIN_COUPLING_SCORE) {
        return;
    }

    cbm_change_coupling_t *cc = &cctx->out[cctx->out_count++];
    snprintf(cc->file_a, sizeof(cc->file_a), "%s", file_a_buf);
    snprintf(cc->file_b, sizeof(cc->file_b), "%s", file_b);
    cc->co_change_count = co_count;
    cc->coupling_score = score;
    long long *ts = cbm_ht_get(cctx->pair_timestamps, pair_key);
    cc->last_co_change = ts ? *ts : 0;
}

int cbm_compute_change_coupling(const cbm_commit_files_t *commits, int commit_count,
                                cbm_change_coupling_t *out, int max_out) {
    CBMHashTable *file_counts = cbm_ht_create(CBM_SZ_1K);
    CBMHashTable *pair_counts = cbm_ht_create(CBM_SZ_2K);
    /* Parallel table mapping pair_key → max commit timestamp seen for that
     * pair, so the resulting edge can carry last_co_change. The pair_counts
     * table consumes its key on insert; pair_timestamps gets its own copy. */
    CBMHashTable *pair_timestamps = cbm_ht_create(CBM_SZ_2K);
    if (!file_counts || !pair_counts || !pair_timestamps) {
        cbm_log_error("githistory.coupling_failed", "code", "CBM_GIT_MAP_ALLOC_FAILED", "component",
                      "githistory.coupling_maps", "operation", "create", "key", "", "message",
                      "change-coupling maps could not be allocated", "remediation",
                      "free memory or reduce history size, then retry");
        goto fail;
    }

    for (int c = 0; c < commit_count; c++) {
        if (commits[c].count > GH_MAX_FILES) {
            continue;
        }

        for (int i = 0; i < commits[c].count; i++) {
            int *val = cbm_ht_get(file_counts, commits[c].files[i]);
            if (val) {
                (*val)++;
            } else {
                int *nv = malloc(sizeof(int));
                char *owned_file = strdup(commits[c].files[i]);
                if (!nv || !owned_file) {
                    free(nv);
                    free(owned_file);
                    cbm_log_error("githistory.coupling_failed", "code",
                                  "CBM_GIT_FILE_COUNT_ALLOC_FAILED", "component",
                                  "githistory.file_counts", "operation", "entry_alloc", "key",
                                  commits[c].files[i], "message",
                                  "file change-count entry could not be allocated", "remediation",
                                  "free memory or reduce history size, then retry");
                    goto fail;
                }
                *nv = SKIP_ONE;
                if (!cbm_ht_set_checked(file_counts, owned_file, nv, NULL)) {
                    cbm_log_error(
                        "githistory.coupling_failed", "code", "CBM_GIT_FILE_COUNT_INSERT_FAILED",
                        "component", "githistory.file_counts", "operation", "insert", "key",
                        owned_file, "message", "file change-count map could not retain an entry",
                        "remediation", "free memory or reduce history size, then retry");
                    free(owned_file);
                    free(nv);
                    goto fail;
                }
            }
        }

        for (int i = 0; i < commits[c].count; i++) {
            for (int j = i + SKIP_ONE; j < commits[c].count; j++) {
                const char *a = commits[c].files[i];
                const char *b = commits[c].files[j];
                if (strcmp(a, b) > 0) {
                    const char *t = a;
                    a = b;
                    b = t;
                }
                size_t la = strlen(a);
                size_t lb = strlen(b);
                if (la > SIZE_MAX - lb - 2) {
                    cbm_log_error("githistory.coupling_failed", "code",
                                  "CBM_GIT_PAIR_KEY_TOO_LARGE", "component",
                                  "githistory.pair_counts", "operation", "key_length", "key", a,
                                  "message", "change-coupling key length overflowed", "remediation",
                                  "reduce path lengths and retry");
                    goto fail;
                }
                size_t pk_len = la + SKIP_ONE + lb + SKIP_ONE;
                char *pk = malloc(pk_len);
                if (!pk) {
                    cbm_log_error("githistory.coupling_failed", "code",
                                  "CBM_GIT_PAIR_KEY_ALLOC_FAILED", "component",
                                  "githistory.pair_counts", "operation", "key_alloc", "key", a,
                                  "message", "change-coupling key could not be allocated",
                                  "remediation", "free memory or reduce history size, then retry");
                    goto fail;
                }
                memcpy(pk, a, la);
                pk[la] = '\x01';
                memcpy(pk + la + SKIP_ONE, b, lb + SKIP_ONE);

                int *val = cbm_ht_get(pair_counts, pk);
                if (val) {
                    (*val)++;
                    long long *ts = cbm_ht_get(pair_timestamps, pk);
                    if (ts && commits[c].timestamp > *ts) {
                        *ts = commits[c].timestamp;
                    }
                    free(pk);
                } else {
                    int *nv = malloc(sizeof(int));
                    *nv = SKIP_ONE;
                    /* pair_counts takes ownership of pk; pair_timestamps
                     * needs its own copy. */
                    char *pk2 = malloc(pk_len);
                    long long *nts = malloc(sizeof(long long));
                    if (!nv || !pk2 || !nts) {
                        free(pk);
                        free(nv);
                        free(pk2);
                        free(nts);
                        cbm_log_error(
                            "githistory.coupling_failed", "code", "CBM_GIT_PAIR_ENTRY_ALLOC_FAILED",
                            "component", "githistory.pair_counts", "operation", "entry_alloc",
                            "key", a, "message", "change-coupling entry could not be allocated",
                            "remediation", "free memory or reduce history size, then retry");
                        goto fail;
                    }
                    memcpy(pk2, pk, pk_len);
                    *nts = commits[c].timestamp;
                    if (!cbm_ht_set_checked(pair_counts, pk, nv, NULL)) {
                        cbm_log_error("githistory.coupling_failed", "code",
                                      "CBM_GIT_PAIR_COUNT_INSERT_FAILED", "component",
                                      "githistory.pair_counts", "operation", "insert", "key", pk,
                                      "message", "change-coupling map could not retain an entry",
                                      "remediation",
                                      "free memory or reduce history size, then retry");
                        free(pk);
                        free(nv);
                        free(pk2);
                        free(nts);
                        goto fail;
                    }
                    if (!cbm_ht_set_checked(pair_timestamps, pk2, nts, NULL)) {
                        cbm_log_error(
                            "githistory.coupling_failed", "code", "CBM_GIT_PAIR_TIME_INSERT_FAILED",
                            "component", "githistory.pair_timestamps", "operation", "insert", "key",
                            pk2, "message",
                            "change-coupling timestamp map could not retain an entry",
                            "remediation", "free memory or reduce history size, then retry");
                        free(pk2);
                        free(nts);
                        goto fail;
                    }
                }
            }
        }
    }

    collect_coupling_ctx_t cctx = {
        .file_counts = file_counts,
        .pair_timestamps = pair_timestamps,
        .out = out,
        .out_count = 0,
        .max_out = max_out,
    };
    cbm_ht_foreach(pair_counts, collect_coupling_cb, &cctx);

    cbm_ht_foreach(pair_counts, free_counter, NULL);
    cbm_ht_free(pair_counts);
    cbm_ht_foreach(pair_timestamps, free_counter, NULL);
    cbm_ht_free(pair_timestamps);
    cbm_ht_foreach(file_counts, free_counter, NULL);
    cbm_ht_free(file_counts);

    return cctx.out_count;

fail:
    if (pair_counts) {
        cbm_ht_foreach(pair_counts, free_counter, NULL);
        cbm_ht_free(pair_counts);
    }
    if (pair_timestamps) {
        cbm_ht_foreach(pair_timestamps, free_counter, NULL);
        cbm_ht_free(pair_timestamps);
    }
    if (file_counts) {
        cbm_ht_foreach(file_counts, free_counter, NULL);
        cbm_ht_free(file_counts);
    }
    return CBM_NOT_FOUND;
}

/* ── Split pass: compute (I/O-bound) + apply (gbuf writes) ───────── */

/* Pre-computed coupling result buffer for fused post-pass parallelism. */
#define MAX_COUPLINGS 8192
#define MAX_FILE_TEMPORAL 16384

/* Compute change couplings without touching the graph buffer.
 * Can run on a separate thread while other passes use the gbuf. */
int cbm_pipeline_githistory_compute(const char *repo_path, cbm_githistory_result_t *result) {
    result->couplings = NULL;
    result->count = 0;
    result->commit_count = 0;
    result->file_temporal = NULL;
    result->file_temporal_count = 0;

    commit_t *commits = NULL;
    int commit_count = 0;
    int rc = parse_git_log(repo_path, &commits, &commit_count);
    if (rc != 0) {
        free(commits);
        return CBM_NOT_FOUND;
    }
    if (commit_count == 0) {
        free(commits);
        return 0;
    }

    result->commit_count = commit_count;

    /* Convert to testable format */
    cbm_commit_files_t *cf = calloc((size_t)commit_count, sizeof(cbm_commit_files_t));
    if (!cf) {
        for (int c = 0; c < commit_count; c++) {
            commit_free(&commits[c]);
        }
        free(commits);
        cbm_log_error("githistory.compute_failed", "code", "CBM_GIT_COMMIT_VIEW_ALLOC_FAILED",
                      "component", "githistory.compute", "operation", "commit_view_alloc", "key",
                      repo_path, "message", "commit history view could not be allocated",
                      "remediation", "free memory or reduce history size, then retry");
        return CBM_NOT_FOUND;
    }
    for (int c = 0; c < commit_count; c++) {
        cf[c].files = commits[c].files;
        cf[c].count = commits[c].count;
        cf[c].timestamp = commits[c].timestamp;
    }

    cbm_change_coupling_t *couplings = malloc(MAX_COUPLINGS * sizeof(cbm_change_coupling_t));
    if (!couplings) {
        cbm_log_error("githistory.compute_failed", "code", "CBM_GIT_COUPLING_ALLOC_FAILED",
                      "component", "githistory.compute", "operation", "coupling_alloc", "key",
                      repo_path, "message", "change-coupling output could not be allocated",
                      "remediation", "free memory or reduce history size, then retry");
        free(cf);
        for (int c = 0; c < commit_count; c++) {
            commit_free(&commits[c]);
        }
        free(commits);
        return CBM_NOT_FOUND;
    }
    int coupling_count = cbm_compute_change_coupling(cf, commit_count, couplings, MAX_COUPLINGS);
    if (coupling_count < 0) {
        free(couplings);
        free(cf);
        for (int c = 0; c < commit_count; c++) {
            commit_free(&commits[c]);
        }
        free(commits);
        return CBM_NOT_FOUND;
    }

    /* Per-file temporal aggregation: change_count + last_modified.
     * Single hash-table pass over the same commit set used for coupling so
     * we don't re-scan history. This is one authoritative result: allocation
     * failure cancels it rather than returning a partial coupling-only view. */
    cbm_file_temporal_t *ft_arr = malloc(MAX_FILE_TEMPORAL * sizeof(cbm_file_temporal_t));
    if (!ft_arr) {
        cbm_log_error("githistory.compute_failed", "code", "CBM_GIT_TEMPORAL_ALLOC_FAILED",
                      "component", "githistory.file_temporal", "operation", "output_alloc", "key",
                      repo_path, "message", "file temporal output could not be allocated",
                      "remediation", "free memory or reduce history size, then retry");
        free(couplings);
        free(cf);
        for (int c = 0; c < commit_count; c++) {
            commit_free(&commits[c]);
        }
        free(commits);
        return CBM_NOT_FOUND;
    }
    {
        int ft_count = 0;
        CBMHashTable *file_idx = cbm_ht_create(CBM_SZ_1K);
        if (!file_idx) {
            cbm_log_error("githistory.compute_failed", "code", "CBM_GIT_FILE_INDEX_ALLOC_FAILED",
                          "component", "githistory.file_temporal", "operation", "index_create",
                          "key", repo_path, "message", "file temporal index could not be allocated",
                          "remediation", "free memory or reduce history size, then retry");
            free(ft_arr);
            free(couplings);
            free(cf);
            for (int c = 0; c < commit_count; c++) {
                commit_free(&commits[c]);
            }
            free(commits);
            return CBM_NOT_FOUND;
        }
        for (int c = 0; c < commit_count; c++) {
            if (cf[c].count > GH_MAX_FILES) {
                continue;
            }
            for (int f = 0; f < cf[c].count; f++) {
                const char *fp = cf[c].files[f];
                int *idx = cbm_ht_get(file_idx, fp);
                if (idx) {
                    ft_arr[*idx].change_count++;
                    if (cf[c].timestamp > ft_arr[*idx].last_modified) {
                        ft_arr[*idx].last_modified = cf[c].timestamp;
                    }
                } else if (ft_count < MAX_FILE_TEMPORAL) {
                    int new_idx = ft_count++;
                    snprintf(ft_arr[new_idx].file_path, sizeof(ft_arr[new_idx].file_path), "%s",
                             fp);
                    ft_arr[new_idx].change_count = 1;
                    ft_arr[new_idx].last_modified = cf[c].timestamp;
                    int *nidx = malloc(sizeof(int));
                    char *owned_fp = strdup(fp);
                    if (!nidx || !owned_fp) {
                        free(nidx);
                        free(owned_fp);
                        cbm_log_error(
                            "githistory.compute_failed", "code",
                            "CBM_GIT_FILE_INDEX_ENTRY_ALLOC_FAILED", "component",
                            "githistory.file_temporal", "operation", "entry_alloc", "key", fp,
                            "message", "file temporal index entry could not be allocated",
                            "remediation", "free memory or reduce history size, then retry");
                        cbm_ht_foreach(file_idx, free_counter, NULL);
                        cbm_ht_free(file_idx);
                        free(ft_arr);
                        free(couplings);
                        free(cf);
                        for (int ci = 0; ci < commit_count; ci++) {
                            commit_free(&commits[ci]);
                        }
                        free(commits);
                        return CBM_NOT_FOUND;
                    }
                    *nidx = new_idx;
                    if (!cbm_ht_set_checked(file_idx, owned_fp, nidx, NULL)) {
                        cbm_log_error(
                            "githistory.compute_failed", "code", "CBM_GIT_FILE_INDEX_INSERT_FAILED",
                            "component", "githistory.file_temporal", "operation", "insert", "key",
                            owned_fp, "message", "file temporal index could not retain an entry",
                            "remediation", "free memory or reduce history size, then retry");
                        free(owned_fp);
                        free(nidx);
                        cbm_ht_foreach(file_idx, free_counter, NULL);
                        cbm_ht_free(file_idx);
                        free(ft_arr);
                        free(couplings);
                        free(cf);
                        for (int ci = 0; ci < commit_count; ci++) {
                            commit_free(&commits[ci]);
                        }
                        free(commits);
                        return CBM_NOT_FOUND;
                    }
                }
            }
        }
        cbm_ht_foreach(file_idx, free_counter, NULL);
        cbm_ht_free(file_idx);
        result->file_temporal = ft_arr;
        result->file_temporal_count = ft_count;
    }

    free(cf);
    for (int c = 0; c < commit_count; c++) {
        commit_free(&commits[c]);
    }
    free(commits);

    result->couplings = couplings;
    result->count = coupling_count;
    return 0;
}

/* Apply pre-computed couplings to the graph buffer (must be on main thread). */
int cbm_pipeline_githistory_apply(cbm_pipeline_ctx_t *ctx, const cbm_githistory_result_t *result) {
    int edge_count = 0;

    for (int i = 0; i < result->count; i++) {
        const cbm_change_coupling_t *cc = &result->couplings[i];

        char *qn_a = cbm_pipeline_fqn_compute(ctx->project_name, cc->file_a, "__file__");
        char *qn_b = cbm_pipeline_fqn_compute(ctx->project_name, cc->file_b, "__file__");

        const cbm_gbuf_node_t *node_a = cbm_gbuf_find_by_qn(ctx->gbuf, qn_a);
        const cbm_gbuf_node_t *node_b = cbm_gbuf_find_by_qn(ctx->gbuf, qn_b);

        free(qn_a);
        free(qn_b);

        if (!node_a || !node_b || node_a->id == node_b->id) {
            continue;
        }

        char props[CBM_SZ_128];
        snprintf(props, sizeof(props),
                 "{\"co_changes\":%d,\"coupling_score\":%.2f,\"last_co_change\":%lld}",
                 cc->co_change_count, cc->coupling_score, cc->last_co_change);

        cbm_gbuf_insert_edge(ctx->gbuf, node_a->id, node_b->id, "FILE_CHANGES_WITH", props);
        edge_count++;
    }

    /* Apply temporal metadata as an object patch so independent enrichment
     * domains compose instead of erasing one another. */
    for (int i = 0; i < result->file_temporal_count; i++) {
        const cbm_file_temporal_t *ft = &result->file_temporal[i];
        char *qn = cbm_pipeline_fqn_compute(ctx->project_name, ft->file_path, "__file__");
        const cbm_gbuf_node_t *node = cbm_gbuf_find_by_qn(ctx->gbuf, qn);
        free(qn);
        if (!node) {
            continue;
        }

        char props[CBM_SZ_128];
        snprintf(props, sizeof(props), "{\"last_modified\":%lld,\"change_count\":%d}",
                 ft->last_modified, ft->change_count);
        if (cbm_gbuf_merge_source_container_properties(ctx->gbuf, "File", ft->file_path, props) !=
            0) {
            return CBM_NOT_FOUND;
        }
    }

    return edge_count;
}

/* ── Main pass (original serial interface) ───────────────────────── */

int cbm_pipeline_pass_githistory(cbm_pipeline_ctx_t *ctx) {
    cbm_log_info("pass.start", "pass", "githistory");

    cbm_githistory_result_t result = {0};
    if (cbm_pipeline_githistory_compute(ctx->repo_path, &result) != 0) {
        return CBM_NOT_FOUND;
    }

    int edge_count = 0;
    if (result.count > 0 || result.file_temporal_count > 0) {
        edge_count = cbm_pipeline_githistory_apply(ctx, &result);
    }

    free(result.couplings);
    free(result.file_temporal);

    if (edge_count < 0) {
        return CBM_NOT_FOUND;
    }
    cbm_log_info("pass.done", "pass", "githistory", "commits", itoa_log(result.commit_count),
                 "edges", itoa_log(edge_count));
    return 0;
}
