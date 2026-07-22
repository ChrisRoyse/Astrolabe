/*
 * pipeline_incremental.c — Disk-based incremental re-indexing.
 *
 * Operates on the existing SQLite DB directly (not RAM-first graph buffer).
 * Compares file mtime+size against stored hashes to classify changed/unchanged.
 * Deletes changed files' nodes (edges cascade via ON DELETE CASCADE),
 * re-parses only changed files through passes into a temp graph buffer,
 * then merges new nodes/edges into the disk DB. Persists updated hashes.
 *
 * Called from pipeline.c when a DB with stored hashes already exists.
 */
#include "foundation/constants.h"

enum { INCR_RING_BUF = 4, INCR_RING_MASK = 3, INCR_TS_BUF = 24, INCR_WAL_BUF = 1040 };
#include "pipeline/pipeline.h"
#include "pipeline/artifact.h"
#include <stdio.h>
#include <time.h>
#include "pipeline/pipeline_internal.h"
#include "store/store.h"
#include "graph_buffer/graph_buffer.h"
#include "discover/discover.h"
#include "foundation/log.h"
#include "foundation/hash_table.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/platform.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdatomic.h>
#include <stdint.h>

/* ── Constants ───────────────────────────────────────────────────── */

#define CBM_MS_PER_SEC 1000.0
#define CBM_NS_PER_MS 1000000.0
#define CBM_NS_PER_SEC 1000000000LL

/* ── Timing helper (same as pipeline.c) ──────────────────────────── */

static double elapsed_ms(struct timespec start) {
    struct timespec now;
    cbm_clock_gettime(CLOCK_MONOTONIC, &now);
    double s = (double)(now.tv_sec - start.tv_sec);
    double ns = (double)(now.tv_nsec - start.tv_nsec);
    return (s * CBM_MS_PER_SEC) + (ns / CBM_NS_PER_MS);
}

/* itoa into static buffer — matches pipeline.c helper */
static const char *itoa_buf(int v) {
    static _Thread_local char buf[INCR_RING_BUF][INCR_TS_BUF];
    static _Thread_local int idx = 0;
    idx = (idx + SKIP_ONE) & INCR_RING_MASK;
    snprintf(buf[idx], sizeof(buf[idx]), "%d", v);
    return buf[idx];
}

static int remove_optional_file(const char *path, const char *code) {
    if (!cbm_path_exists(path)) {
        return 0;
    }
    if (cbm_unlink(path) == 0 && !cbm_path_exists(path)) {
        return 0;
    }
    cbm_log_error("incremental.file_remove_failed", "code", code, "path", path, "message",
                  "a transaction-owned or stale SQLite file could not be removed", "remediation",
                  "close the process holding this file and retry");
    return CBM_NOT_FOUND;
}

/* ── Platform-portable mtime_ns ──────────────────────────────────── */

static int64_t stat_mtime_ns(const struct stat *st) {
#ifdef __APPLE__
    return ((int64_t)st->st_mtimespec.tv_sec * CBM_NS_PER_SEC) + (int64_t)st->st_mtimespec.tv_nsec;
#elif defined(_WIN32)
    return (int64_t)st->st_mtime * CBM_NS_PER_SEC;
#else
    return ((int64_t)st->st_mtim.tv_sec * CBM_NS_PER_SEC) + (int64_t)st->st_mtim.tv_nsec;
#endif
}

/* ── File classification ─────────────────────────────────────────── */

/* Classify discovered files against stored hashes using mtime+size.
 * Returns a boolean array: changed[i] = true if files[i] needs re-parsing.
 * Caller must free the returned array. */
static bool *classify_files(cbm_file_info_t *files, int file_count, cbm_file_hash_t *stored,
                            int stored_count, int *out_changed, int *out_unchanged) {
    size_t changed_cap = (size_t)(file_count > 0 ? file_count : 1);
    bool *changed = calloc(changed_cap, sizeof(bool));
    if (!changed) {
        return NULL;
    }

    int n_changed = 0;
    int n_unchanged = 0;

    /* Build lookup: rel_path -> stored hash */
    CBMHashTable *ht =
        cbm_ht_create(stored_count > 0 ? (size_t)stored_count * PAIR_LEN : CBM_SZ_64);
    if (!ht) {
        cbm_log_error("incremental.classify_failed", "code",
                      "CBM_INCREMENTAL_HASH_INDEX_ALLOC_FAILED", "message",
                      "the stored-file classification index could not be allocated",
                      "remediation", "free memory or reduce repository size, then retry");
        free(changed);
        return NULL;
    }
    for (int i = 0; i < stored_count; i++) {
        cbm_ht_set(ht, stored[i].rel_path, &stored[i]);
    }

    for (int i = 0; i < file_count; i++) {
        cbm_file_hash_t *h = cbm_ht_get(ht, files[i].rel_path);
        if (!h) {
            /* New file */
            changed[i] = true;
            n_changed++;
            continue;
        }

        struct stat st;
        if (stat(files[i].path, &st) != 0) {
            cbm_log_error("incremental.classify_failed", "code",
                          "CBM_INCREMENTAL_FILE_STAT_FAILED", "rel_path", files[i].rel_path,
                          "message", "a discovered file could not be stated during classification",
                          "remediation", "stabilize file access and retry the index");
            cbm_ht_free(ht);
            free(changed);
            return NULL;
        }

        if (stat_mtime_ns(&st) != h->mtime_ns || st.st_size != h->size) {
            changed[i] = true;
            n_changed++;
        } else {
            n_unchanged++;
        }
    }

    cbm_ht_free(ht);
    *out_changed = n_changed;
    *out_unchanged = n_unchanged;
    return changed;
}

/* Classify stored files that are absent from current discovery. Returns status,
 * writes the true-deletion count, and collects mode-skipped files (caller frees).
 *
 * A stored file is classified as:
 *   - "deleted"      — `stat()` returns ENOENT or ENOTDIR. Its nodes will
 *                       be purged and its hash row dropped.
 *   - "mode-skipped" — `stat()` succeeds. The file exists on disk but the
 *                       current discovery pass didn't visit it (e.g. excluded
 *                       by FAST_SKIP_DIRS in fast/moderate mode). Its nodes
 *                       must be preserved AND its hash row must be carried
 *                       forward into the new DB so subsequent reindexes can
 *                       still see it as "known" rather than treating it as
 *                       new-or-deleted.
 *
 * Without this distinction, a fast-mode reindex after a full-mode index
 * would silently purge every file under `tools/`, `scripts/`, `bin/`,
 * `build/`, `docs/`, `__tests__/`, etc. — see task
 * claude-connectors/codebase-memory-index-repository-is-destructive-...
 * and the 2026-04-13 Skyline incident (packages/mcp/src/tools/ vanished
 * from a live graph mid-session).
 *
 * Mode-skipped hash preservation is the second half of the additive-merge
 * contract: dump_and_persist re-upserts these hash rows so the next reindex
 * can correctly detect a real on-disk deletion of a mode-skipped file (as
 * opposed to seeing it as "never existed" → noop → orphaned graph nodes).
 *
 * Any uncertainty (missing root, truncated path, stat fault, or allocation
 * failure) is a structured hard error. No guessed preservation/deletion set
 * may reach the staged commit.
 *
 * Note: we use stat() (not lstat()) on purpose. A symlink whose target was
 * deleted should be classified as deleted from the indexer's perspective
 * because the indexer follows symlinks during discovery — a stale symlink
 * has no source to parse. */
static int find_deleted_files(const char *repo_path, cbm_file_info_t *files, int file_count,
                              cbm_file_hash_t *stored, int stored_count, char ***out_deleted,
                              int *out_deleted_count, cbm_file_hash_t **out_mode_skipped,
                              int *out_mode_skipped_count) {
    *out_deleted = NULL;
    *out_deleted_count = 0;
    *out_mode_skipped = NULL;
    *out_mode_skipped_count = 0;

    if (!repo_path) {
        cbm_log_error("incremental.classify_failed", "code",
                      "CBM_INCREMENTAL_REPO_PATH_MISSING", "message",
                      "incremental deletion classification requires the repository path",
                      "remediation", "configure the canonical repository path and retry");
        return CBM_NOT_FOUND;
    }

    CBMHashTable *current =
        cbm_ht_create(file_count > 0 ? (size_t)file_count * PAIR_LEN : CBM_SZ_64);
    if (!current) {
        cbm_log_error("incremental.classify_failed", "code",
                      "CBM_INCREMENTAL_CURRENT_PATHS_ALLOC_FAILED", "message",
                      "the current-file membership index could not be allocated", "remediation",
                      "free memory or reduce repository size, then retry");
        return CBM_NOT_FOUND;
    }
    for (int i = 0; i < file_count; i++) {
        cbm_ht_set(current, files[i].rel_path, &files[i]);
    }

    int del_count = 0;
    int del_cap = CBM_SZ_64;
    int ms_count = 0;
    int ms_cap = CBM_SZ_64;
    cbm_file_hash_t *mode_skipped = NULL;
    char **deleted = malloc((size_t)del_cap * sizeof(char *));
    if (!deleted) {
        cbm_log_error("incremental.classify_failed", "code",
                      "CBM_INCREMENTAL_DELETED_LIST_ALLOC_FAILED", "message",
                      "the deleted-file list could not be allocated", "remediation",
                      "free memory or reduce repository size, then retry");
        goto fail;
    }

    mode_skipped = malloc((size_t)ms_cap * sizeof(cbm_file_hash_t));
    if (!mode_skipped) {
        cbm_log_error("incremental.classify_failed", "code",
                      "CBM_INCREMENTAL_PRESERVED_LIST_ALLOC_FAILED", "message",
                      "the mode-preserved file list could not be allocated", "remediation",
                      "free memory or reduce repository size, then retry");
        goto fail;
    }

    for (int i = 0; i < stored_count; i++) {
        if (cbm_ht_get(current, stored[i].rel_path)) {
            continue; /* still visited by current pass */
        }
        /* Not in current discovery — check if it's truly deleted or just
         * mode-skipped (excluded by FAST_SKIP_DIRS etc.). */
        bool preserve = false;
        char abs_path[CBM_SZ_4K];
        int n = snprintf(abs_path, sizeof(abs_path), "%s/%s", repo_path, stored[i].rel_path);
        if (n < 0 || n >= (int)sizeof(abs_path)) {
            cbm_log_error("incremental.classify_failed", "code",
                          "CBM_INCREMENTAL_ABSOLUTE_PATH_TOO_LONG", "rel_path",
                          stored[i].rel_path, "message",
                          "a stored file path cannot be represented for deletion classification",
                          "remediation", "shorten the repository path and retry");
            goto fail;
        } else {
            struct stat st;
            if (stat(abs_path, &st) == 0) {
                /* File exists on disk — mode-skipped, not deleted. */
                preserve = true;
            } else if (errno != ENOENT && errno != ENOTDIR) {
                cbm_log_error("incremental.classify_failed", "code",
                              "CBM_INCREMENTAL_STORED_FILE_STAT_FAILED", "rel_path",
                              stored[i].rel_path, "errno", itoa_buf(errno), "message",
                              "stored-file presence could not be determined exactly",
                              "remediation", "restore file access and retry");
                goto fail;
            }
        }

        if (preserve) {
            /* Carry forward the existing hash row so subsequent reindexes
             * can correctly classify this file. */
            if (ms_count >= ms_cap) {
                ms_cap *= PAIR_LEN;
                cbm_file_hash_t *tmp = realloc(mode_skipped, (size_t)ms_cap * sizeof(*tmp));
                if (!tmp) {
                    cbm_log_error("incremental.classify_failed", "code",
                                  "CBM_INCREMENTAL_PRESERVED_LIST_ALLOC_FAILED", "message",
                                  "the complete mode-preserved file list could not be retained",
                                  "remediation", "free memory or reduce repository size, then retry");
                    goto fail;
                }
                mode_skipped = tmp;
            }
            char *rp = strdup(stored[i].rel_path);
            char *sh = stored[i].sha256 ? strdup(stored[i].sha256) : NULL;
            if (!rp || (stored[i].sha256 && !sh)) {
                cbm_log_error("incremental.classify_failed", "code",
                              "CBM_INCREMENTAL_PRESERVED_ROW_ALLOC_FAILED", "rel_path",
                              stored[i].rel_path, "message",
                              "one complete mode-preserved hash row could not be retained",
                              "remediation", "free memory or reduce repository size, then retry");
                free(rp);
                free(sh);
                goto fail;
            }
            mode_skipped[ms_count].project = NULL; /* unused by upsert API */
            mode_skipped[ms_count].rel_path = rp;
            mode_skipped[ms_count].sha256 = sh;
            mode_skipped[ms_count].mtime_ns = stored[i].mtime_ns;
            mode_skipped[ms_count].size = stored[i].size;
            ms_count++;
            continue;
        }

        /* File is truly gone — record for purge. */
        if (del_count >= del_cap) {
            del_cap *= PAIR_LEN;
            char **tmp = realloc(deleted, (size_t)del_cap * sizeof(char *));
            if (!tmp) {
                cbm_log_error("incremental.classify_failed", "code",
                              "CBM_INCREMENTAL_DELETED_LIST_ALLOC_FAILED", "message",
                              "the complete deleted-file list could not be retained", "remediation",
                              "free memory or reduce repository size, then retry");
                goto fail;
            }
            deleted = tmp;
        }
        deleted[del_count] = strdup(stored[i].rel_path);
        if (!deleted[del_count]) {
            cbm_log_error("incremental.classify_failed", "code",
                          "CBM_INCREMENTAL_DELETED_ROW_ALLOC_FAILED", "rel_path",
                          stored[i].rel_path, "message",
                          "one deleted-file identity could not be retained", "remediation",
                          "free memory or reduce repository size, then retry");
            goto fail;
        }
        del_count++;
    }

    cbm_ht_free(current);
    *out_deleted = deleted;
    *out_deleted_count = del_count;
    *out_mode_skipped = mode_skipped;
    *out_mode_skipped_count = ms_count;
    return 0;

fail:
    cbm_ht_free(current);
    if (deleted) {
        for (int i = 0; i < del_count; i++) {
            free(deleted[i]);
        }
        free(deleted);
    }
    if (mode_skipped) {
        for (int i = 0; i < ms_count; i++) {
            free((void *)mode_skipped[i].rel_path);
            free((void *)mode_skipped[i].sha256);
        }
        free(mode_skipped);
    }
    return CBM_NOT_FOUND;
}

/* Free a mode_skipped array allocated by find_deleted_files. */
static void free_mode_skipped(cbm_file_hash_t *ms, int count) {
    if (!ms) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free((void *)ms[i].rel_path);
        free((void *)ms[i].sha256);
    }
    free(ms);
}

/* ── Inbound cross-file edge preservation (incremental correctness) ──
 *
 * The purge step (cbm_gbuf_delete_by_file) removes a changed file's nodes,
 * and the cascade then drops every edge referencing them — INCLUDING inbound
 * edges whose source lives in an UNCHANGED file (e.g. StudyService.grade ->
 * SM2.review, or a Folder -> File containment edge). Because incremental only
 * re-parses the changed files, the resolution passes never regenerate those
 * inbound edges, so the graph silently loses cross-file CALLS / USAGE /
 * CONTAINS_FILE / INHERITS / ... edges on every edit and diverges from a
 * clean full reindex (which resolves every file).
 *
 * Fix: snapshot the inbound cross-file edges into changed files BEFORE the
 * purge. The unchanged source is bound by stable atom ID; the changed target
 * is matched by its exact semantic locator (QN/path/label/name/signature), then
 * re-linked AFTER re-resolution + post-passes. Notes:
 *   - Only edges whose target is in a changed file and whose source is NOT
 *     are snapshotted; edges out of a changed file are regenerated when that
 *     file is re-resolved.
 *   - Edge types recomputed wholesale by post-passes (SIMILAR_TO,
 *     SEMANTICALLY_RELATED) are skipped — re-linking a stale snapshot could
 *     add edges a full reindex would not produce.
 *   - cbm_gbuf_insert_edge dedups, so re-linking an edge the resolver already
 *     recreated is a harmless no-op.
 *   - A target whose semantic locator no longer exists (symbol deleted or
 *     renamed by the edit) is dropped — matching full-reindex semantics.
 *   - An ambiguous or signature-incompatible successor fails closed before
 *     the original on-disk database is mutated. */

typedef struct {
    char *source_atom_id;
    char *target_qn;
    char *target_file_path;
    char *target_label;
    char *target_name;
    char *target_properties;
    char *type;
    char *props;
} cbm_saved_edge_t;

typedef struct {
    cbm_gbuf_t *gbuf;
    CBMHashTable *changed_paths; /* rel_path -> non-NULL sentinel (membership set) */
    cbm_saved_edge_t *items;
    int count;
    int cap;
    bool failed;
} cbm_edge_capture_t;

/* Edge types that must NOT be re-linked from the pre-purge snapshot, because a
 * full reindex (re)computes them via a pass whose result can differ from the
 * snapshot — restoring a stale copy could leave wrong properties or even an
 * edge a full reindex would not produce:
 *   - SIMILAR_TO / SEMANTICALLY_RELATED: rebuilt wholesale by the incremental
 *     post-passes (similarity / semantic_edges) over a drifting corpus.
 *   - FILE_CHANGES_WITH (git-history coupling) and DATA_FLOWS (route data flow):
 *     produced only by full-pipeline post-passes (githistory / route_nodes)
 *     that do NOT run during incremental; they remain a known incremental
 *     limitation rather than something to restore stale.
 * Every other edge type IS safe to re-link, by one of two routes that both
 * match a full reindex: edges re-emitted by the per-file resolution passes that
 * run incrementally (CALLS, USAGE, DEFINES, DEFINES_METHOD, INHERITS,
 * IMPLEMENTS) are deduped on re-link, while structural containment edges
 * (CONTAINS_FILE, CONTAINS_FOLDER) — which the full-only structure pass does
 * NOT regenerate incrementally — are preserved precisely by this snapshot. */
static bool incr_edge_type_is_recomputed(const char *type) {
    return type && (strcmp(type, "SIMILAR_TO") == 0 || strcmp(type, "SEMANTICALLY_RELATED") == 0 ||
                    strcmp(type, "FILE_CHANGES_WITH") == 0 || strcmp(type, "DATA_FLOWS") == 0);
}

/* cbm_gbuf_foreach_edge visitor: snapshot inbound cross-file edges into
 * changed files so they survive the purge and can be re-linked afterward. */
static void incr_capture_inbound_edge(const cbm_gbuf_edge_t *edge, void *userdata) {
    cbm_edge_capture_t *cap = (cbm_edge_capture_t *)userdata;
    if (incr_edge_type_is_recomputed(edge->type)) {
        return;
    }
    const cbm_gbuf_node_t *src = cbm_gbuf_find_by_id(cap->gbuf, edge->source_id);
    const cbm_gbuf_node_t *tgt = cbm_gbuf_find_by_id(cap->gbuf, edge->target_id);
    if (!src || !tgt || !src->atom_id || !tgt->qualified_name || !tgt->file_path ||
        !tgt->label || !tgt->name || !tgt->properties_json) {
        cap->failed = true;
        cbm_log_error("incremental.edge_snapshot_failed", "code",
                      "CBM_INCREMENTAL_EDGE_ENDPOINT_INVALID", "message",
                      "a live edge endpoint lacks its stable atom or semantic locator",
                      "remediation", "rebuild the existing store before incremental ingestion");
        return;
    }
    /* Keep only edges that the purge would orphan permanently: target is in a
     * changed file (its node is deleted + re-created), source is NOT (its file
     * is never re-parsed, so the resolver won't regenerate the edge). */
    if (!cbm_ht_get(cap->changed_paths, tgt->file_path) ||
        cbm_ht_get(cap->changed_paths, src->file_path)) {
        return;
    }
    if (cap->count >= cap->cap) {
        int ncap = (cap->cap > 0) ? cap->cap * PAIR_LEN : CBM_SZ_64;
        cbm_saved_edge_t *tmp = realloc(cap->items, (size_t)ncap * sizeof(*tmp));
        if (!tmp) {
            cap->failed = true;
            cbm_log_error("incremental.edge_snapshot_failed", "code",
                          "CBM_INCREMENTAL_EDGE_SNAPSHOT_ALLOC_FAILED", "captured",
                          itoa_buf(cap->count), "message",
                          "the complete inbound-edge snapshot could not be allocated",
                          "remediation", "free memory or reduce the repository size, then retry");
            return;
        }
        cap->items = tmp;
        cap->cap = ncap;
    }
    cbm_saved_edge_t *s = &cap->items[cap->count];
    memset(s, 0, sizeof(*s));
    s->source_atom_id = strdup(src->atom_id);
    s->target_qn = strdup(tgt->qualified_name);
    s->target_file_path = strdup(tgt->file_path);
    s->target_label = strdup(tgt->label);
    s->target_name = strdup(tgt->name);
    s->target_properties = strdup(tgt->properties_json);
    s->type = strdup(edge->type);
    s->props = strdup(edge->properties_json ? edge->properties_json : "{}");
    if (!s->source_atom_id || !s->target_qn || !s->target_file_path || !s->target_label ||
        !s->target_name || !s->target_properties || !s->type || !s->props) {
        free(s->source_atom_id);
        free(s->target_qn);
        free(s->target_file_path);
        free(s->target_label);
        free(s->target_name);
        free(s->target_properties);
        free(s->type);
        free(s->props);
        memset(s, 0, sizeof(*s));
        cap->failed = true;
        cbm_log_error("incremental.edge_snapshot_failed", "code",
                      "CBM_INCREMENTAL_EDGE_SNAPSHOT_ALLOC_FAILED", "captured",
                      itoa_buf(cap->count), "message",
                      "one complete inbound-edge snapshot record could not be retained",
                      "remediation", "free memory or reduce the repository size, then retry");
        return;
    }
    cap->count++;
}

/* Re-link snapshotted inbound edges to the freshly re-created target nodes.
 * Returns the number of edges re-linked. */
static int incr_restore_inbound_edges(cbm_gbuf_t *gbuf, cbm_edge_capture_t *cap) {
    int restored = 0;
    for (int i = 0; i < cap->count; i++) {
        cbm_saved_edge_t *s = &cap->items[i];
        const cbm_gbuf_node_t *src = cbm_gbuf_find_by_atom_id(gbuf, s->source_atom_id);
        if (!src) {
            cbm_log_error("incremental.edge_relink_failed", "code",
                          "CBM_INCREMENTAL_SOURCE_ATOM_MISSING", "source_atom_id",
                          s->source_atom_id, "message",
                          "an unchanged inbound-edge source atom disappeared during re-index",
                          "remediation", "preserve the store and run a clean re-index");
            return CBM_NOT_FOUND;
        }
        const cbm_gbuf_node_t *tgt = cbm_gbuf_find_successor_node(
            gbuf, s->target_qn, s->target_file_path, s->target_label, s->target_name,
            s->target_properties);
        if (!tgt) {
            if (cbm_gbuf_resolution_failed(gbuf)) {
                return CBM_NOT_FOUND;
            }
            continue; /* Exact old entity was deleted or renamed. */
        }
        if (cbm_gbuf_insert_edge(gbuf, src->id, tgt->id, s->type, s->props) <= 0) {
            cbm_log_error("incremental.edge_relink_failed", "code",
                          "CBM_INCREMENTAL_EDGE_INSERT_FAILED", "source_atom_id",
                          s->source_atom_id, "target_atom_id", tgt->atom_id, "type", s->type,
                          "message", "the resolved inbound edge could not be inserted",
                          "remediation", "inspect the graph-buffer error and retry");
            return CBM_NOT_FOUND;
        }
        restored++;
    }
    return restored;
}

static void incr_free_edge_capture(cbm_edge_capture_t *cap) {
    for (int i = 0; i < cap->count; i++) {
        free(cap->items[i].source_atom_id);
        free(cap->items[i].target_qn);
        free(cap->items[i].target_file_path);
        free(cap->items[i].target_label);
        free(cap->items[i].target_name);
        free(cap->items[i].target_properties);
        free(cap->items[i].type);
        free(cap->items[i].props);
    }
    free(cap->items);
    cap->items = NULL;
    cap->count = 0;
    cap->cap = 0;
}

/* ── Persist file hashes ─────────────────────────────────────────── */

/* Persist file hash rows for the current discovery and any mode-skipped
 * files preserved from the previous DB.
 *
 * Every row is part of the incremental commit. Any stat or upsert failure
 * rejects the staged database so partial classification state can never
 * replace the previous source of truth. */
static int persist_hashes(cbm_store_t *store, const char *project, cbm_file_info_t *files,
                          int file_count, const cbm_file_hash_t *mode_skipped,
                          int mode_skipped_count) {

    /* Current discovery: re-stat to capture any mtime/size that changed
     * during the run, and write fresh hash rows for visited files. */
    for (int i = 0; i < file_count; i++) {
        struct stat st;
        if (stat(files[i].path, &st) != 0) {
            cbm_log_error("incremental.persist_hash_failed", "code",
                          "CBM_INCREMENTAL_FILE_STAT_FAILED", "scope", "current", "rel_path",
                          files[i].rel_path, "message",
                          "a discovered file could not be re-statted before commit",
                          "remediation", "stabilize the file and retry the incremental index");
            return CBM_NOT_FOUND;
        }
        int rc = cbm_store_upsert_file_hash(store, project, files[i].rel_path, "",
                                            stat_mtime_ns(&st), st.st_size);
        if (rc != CBM_STORE_OK) {
            cbm_log_error("incremental.persist_hash_failed", "code",
                          "CBM_INCREMENTAL_HASH_UPSERT_FAILED", "scope", "current", "rel_path",
                          files[i].rel_path, "rc", itoa_buf(rc), "message",
                          "a current-file hash row could not be persisted", "remediation",
                          "inspect the SQLite store error and retry");
            return CBM_NOT_FOUND;
        }
    }

    /* Mode-skipped (preserved): re-upsert hash rows from the previous DB
     * so the next reindex can still classify these files correctly. Without
     * this, an orphaned-node bug emerges where:
     *   - full mode indexes everything
     *   - fast mode runs and drops mode-skipped hash rows
     *   - file is then deleted on disk
     *   - next reindex's stored hashes don't include the file → noop or
     *     can't detect the deletion → graph nodes for the deleted file
     *     remain forever (or until a destructive rebuild).
     *
     * A failure here is more serious than a current-files failure because
     * it can revive the orphaned-node bug for that specific file. Logged
     * with scope=mode_skipped so the warning is searchable. */
    if (mode_skipped) {
        for (int i = 0; i < mode_skipped_count; i++) {
            int rc =
                cbm_store_upsert_file_hash(store, project, mode_skipped[i].rel_path,
                                           mode_skipped[i].sha256 ? mode_skipped[i].sha256 : "",
                                           mode_skipped[i].mtime_ns, mode_skipped[i].size);
            if (rc != CBM_STORE_OK) {
                cbm_log_error("incremental.persist_hash_failed", "code",
                              "CBM_INCREMENTAL_HASH_UPSERT_FAILED", "scope", "mode_skipped",
                              "rel_path", mode_skipped[i].rel_path, "rc", itoa_buf(rc),
                              "message", "a preserved hash row could not be persisted",
                              "remediation", "inspect the SQLite store error and retry");
                return CBM_NOT_FOUND;
            }
        }
    }

    return 0;
}

/* ── Registry seed visitor ────────────────────────────────────────── */

/* Labels the full-index definition pass seeds into the registry
 * (pass_definitions.c — KEEP IN SYNC). Incremental re-resolution must see the
 * SAME symbol set, or it diverges from a clean full reindex: seeding extra
 * container nodes (File / Module / Folder / ...) lets a type usage like `Word`
 * resolve to the same-named Module node instead of the Class node. Only
 * callable / declared symbols belong in the registry. */
static bool incr_label_is_registry_symbol(const char *label) {
    /* Mirror pass_definitions.c / pass_parallel.c registry seeding EXACTLY:
     * callables + every type-like container (Class/Struct/Interface/Enum/Type/
     * Trait) + Variable/Field. Struct included so an incremental re-resolve seeds
     * the same struct type nodes a full reindex would. */
    return label && (strcmp(label, "Function") == 0 || strcmp(label, "Method") == 0 ||
                     cbm_label_is_type_like(label) || strcmp(label, "Variable") == 0 ||
                     strcmp(label, "Field") == 0);
}

/* Callback for cbm_gbuf_foreach_node: seed the registry with the existing
 * project's definition symbols so the resolver can match cross-file symbols
 * during incremental. Mirrors the full-index registry contents exactly so an
 * incremental re-resolve picks the same nodes a full reindex would. */
static void registry_visitor(const cbm_gbuf_node_t *node, void *userdata) {
    cbm_registry_t *r = (cbm_registry_t *)userdata;
    if (!incr_label_is_registry_symbol(node->label)) {
        return;
    }
    cbm_registry_add(r, node->name, node->qualified_name, node->label);
}

/* Run parallel or sequential extract+resolve for changed files. */
static void run_extract_resolve(cbm_pipeline_ctx_t *ctx, cbm_file_info_t *changed_files, int ci) {
    struct timespec t;

    /* Per-file LSP always runs (every mode). Cross-file LSP stays disabled in
     * incremental regardless (cbm_parallel_resolve is called with NULL
     * cross_registries below). */

#define MIN_FILES_FOR_PARALLEL_INCR 50
    int worker_count = cbm_default_worker_count(true);
    bool use_parallel = (worker_count > SKIP_ONE && ci > MIN_FILES_FOR_PARALLEL_INCR);

    if (use_parallel) {
        cbm_log_info("incremental.mode", "mode", "parallel", "workers", itoa_buf(worker_count),
                     "changed", itoa_buf(ci));

        _Atomic int64_t shared_ids;
        atomic_init(&shared_ids, cbm_gbuf_next_id(ctx->gbuf));

        CBMFileResult **cache = (CBMFileResult **)calloc(ci, sizeof(CBMFileResult *));
        if (cache) {
            cbm_clock_gettime(CLOCK_MONOTONIC, &t);
            cbm_parallel_extract(ctx, changed_files, ci, cache, &shared_ids, worker_count);
            cbm_gbuf_set_next_id(ctx->gbuf, atomic_load(&shared_ids));
            cbm_log_info("pass.timing", "pass", "incr_extract", "elapsed_ms",
                         itoa_buf((int)elapsed_ms(t)));

            cbm_clock_gettime(CLOCK_MONOTONIC, &t);
            cbm_build_registry_from_cache(ctx, changed_files, ci, cache);
            cbm_log_info("pass.timing", "pass", "incr_registry", "elapsed_ms",
                         itoa_buf((int)elapsed_ms(t)));

            /* Incremental skips cross-file LSP precondition build — it
             * would need all_defs from the full project, not just the
             * changed slice. Per-file LSP (run inside cbm_extract_file)
             * still fires; cross-file resolution is deferred to the
             * next full re-index. Pass NULL/0/NULL to make the fused
             * step in resolve_worker a no-op. */
            cbm_clock_gettime(CLOCK_MONOTONIC, &t);
            cbm_parallel_resolve(ctx, changed_files, ci, cache, &shared_ids, worker_count, NULL, 0,
                                 NULL, NULL /* module_def_index */,
                                 NULL /* cross_registries — incremental skips Tier 2 prebuild */);
            cbm_gbuf_set_next_id(ctx->gbuf, atomic_load(&shared_ids));
            cbm_log_info("pass.timing", "pass", "incr_resolve", "elapsed_ms",
                         itoa_buf((int)elapsed_ms(t)));

            for (int j = 0; j < ci; j++) {
                if (cache[j]) {
                    cbm_free_result(cache[j]);
                }
            }
            free(cache);
        }
    } else {
        cbm_log_info("incremental.mode", "mode", "sequential", "changed", itoa_buf(ci));
        cbm_pipeline_pass_definitions(ctx, changed_files, ci);
        cbm_pipeline_pass_calls(ctx, changed_files, ci);
        cbm_pipeline_pass_usages(ctx, changed_files, ci);
        cbm_pipeline_pass_semantic(ctx, changed_files, ci);
    }
}

/* Run post-extraction passes (tests, decorator tags, configlink). */
static void run_postpasses(cbm_pipeline_ctx_t *ctx, cbm_file_info_t *changed_files, int ci,
                           const char *project) {
    struct timespec t;

    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    cbm_pipeline_pass_tests(ctx, changed_files, ci);
    cbm_log_info("pass.timing", "pass", "incr_tests", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));

    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    cbm_pipeline_pass_decorator_tags(ctx->gbuf, project);
    cbm_log_info("pass.timing", "pass", "incr_decorator_tags", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t)));

    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    cbm_pipeline_pass_configlink(ctx);
    cbm_log_info("pass.timing", "pass", "incr_configlink", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t)));

    /* SIMILAR_TO + SEMANTICALLY_RELATED edges only in moderate/full modes */
    if (ctx->mode <= CBM_MODE_MODERATE) {
        cbm_clock_gettime(CLOCK_MONOTONIC, &t);
        cbm_pipeline_pass_similarity(ctx);
        cbm_log_info("pass.timing", "pass", "incr_similarity", "elapsed_ms",
                     itoa_buf((int)elapsed_ms(t)));

        cbm_clock_gettime(CLOCK_MONOTONIC, &t);
        cbm_pipeline_pass_semantic_edges(ctx);
        cbm_log_info("pass.timing", "pass", "incr_semantic_edges", "elapsed_ms",
                     itoa_buf((int)elapsed_ms(t)));
    }
}
/* Build the complete replacement beside the live DB, finalize all mandatory
 * state, then atomically swap it into place. The prior source of truth remains
 * byte-for-byte untouched on any pre-swap failure. */
static int dump_and_persist(cbm_gbuf_t *gbuf, const char *db_path, const char *project,
                            cbm_file_info_t *files, int file_count,
                            const cbm_file_hash_t *mode_skipped, int mode_skipped_count,
                            const char *repo_path) {
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);

    char stage[INCR_WAL_BUF];
    char wal[INCR_WAL_BUF];
    char shm[INCR_WAL_BUF];
    int stage_len = snprintf(stage, sizeof(stage), "%s.incremental-stage", db_path);
    if (stage_len <= 0 || (size_t)stage_len >= sizeof(stage)) {
        cbm_log_error("incremental.dump_failed", "code", "CBM_INCREMENTAL_STAGE_PATH_TOO_LONG",
                      "message", "the staged database path exceeds the supported path buffer",
                      "remediation", "shorten the repository storage path and retry");
        return CBM_NOT_FOUND;
    }
    snprintf(wal, sizeof(wal), "%s-wal", stage);
    snprintf(shm, sizeof(shm), "%s-shm", stage);
    if (remove_optional_file(stage, "CBM_INCREMENTAL_STALE_STAGE_REMOVE_FAILED") != 0 ||
        remove_optional_file(wal, "CBM_INCREMENTAL_STALE_STAGE_WAL_REMOVE_FAILED") != 0 ||
        remove_optional_file(shm, "CBM_INCREMENTAL_STALE_STAGE_SHM_REMOVE_FAILED") != 0) {
        return CBM_NOT_FOUND;
    }

    int dump_rc = cbm_gbuf_dump_to_sqlite(gbuf, stage);
    cbm_log_info("incremental.dump", "rc", itoa_buf(dump_rc), "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t)));
    if (dump_rc != 0) {
        cbm_unlink(stage);
        cbm_unlink(wal);
        cbm_unlink(shm);
        return CBM_NOT_FOUND;
    }

    cbm_store_t *hash_store = cbm_store_open_path(stage);
    if (!hash_store) {
        cbm_log_error("incremental.dump_failed", "code", "CBM_INCREMENTAL_STAGE_OPEN_FAILED",
                      "message", "the completed staged database could not be reopened",
                      "remediation", "inspect the SQLite open error and retry");
        cbm_unlink(stage);
        cbm_unlink(wal);
        cbm_unlink(shm);
        return CBM_NOT_FOUND;
    }

    int final_rc =
        persist_hashes(hash_store, project, files, file_count, mode_skipped, mode_skipped_count);
    if (final_rc == 0 &&
        cbm_store_exec(hash_store, "INSERT INTO nodes_fts(nodes_fts) VALUES('delete-all');") !=
            CBM_STORE_OK) {
        final_rc = CBM_NOT_FOUND;
    }
    if (final_rc == 0 &&
        cbm_store_exec(hash_store,
                       "INSERT INTO nodes_fts(rowid, name, qualified_name, label, file_path) "
                       "SELECT id, cbm_camel_split(name), qualified_name, label, file_path "
                       "FROM nodes;") != CBM_STORE_OK) {
        final_rc = CBM_NOT_FOUND;
    }
    if (final_rc == 0 &&
        (cbm_store_exec(hash_store, "PRAGMA wal_checkpoint(TRUNCATE);") != CBM_STORE_OK ||
         cbm_store_exec(hash_store, "PRAGMA journal_mode=DELETE;") != CBM_STORE_OK)) {
        final_rc = CBM_NOT_FOUND;
    }
    cbm_store_close(hash_store);

    if (final_rc != 0) {
        cbm_log_error("incremental.dump_failed", "code",
                      "CBM_INCREMENTAL_STAGE_FINALIZE_FAILED", "message",
                      "hash, FTS, or WAL finalization failed in the staged database",
                      "remediation", "inspect the SQLite store error and retry");
        cbm_unlink(stage);
        cbm_unlink(wal);
        cbm_unlink(shm);
        return CBM_NOT_FOUND;
    }

    if (cbm_path_exists(wal) || cbm_path_exists(shm)) {
        cbm_log_error("incremental.dump_failed", "code",
                      "CBM_INCREMENTAL_STAGE_WAL_NOT_FINALIZED", "message",
                      "the closed staged database still has a WAL or shared-memory sidecar",
                      "remediation", "inspect SQLite checkpoint errors and retry");
        remove_optional_file(stage, "CBM_INCREMENTAL_FAILED_STAGE_REMOVE_FAILED");
        return CBM_NOT_FOUND;
    }

    snprintf(wal, sizeof(wal), "%s-wal", db_path);
    snprintf(shm, sizeof(shm), "%s-shm", db_path);
    if (remove_optional_file(wal, "CBM_INCREMENTAL_LIVE_WAL_REMOVE_FAILED") != 0 ||
        remove_optional_file(shm, "CBM_INCREMENTAL_LIVE_SHM_REMOVE_FAILED") != 0) {
        remove_optional_file(stage, "CBM_INCREMENTAL_FAILED_STAGE_REMOVE_FAILED");
        return CBM_NOT_FOUND;
    }
    if (cbm_rename_replace(stage, db_path) != 0) {
        cbm_log_error("incremental.dump_failed", "code", "CBM_INCREMENTAL_ATOMIC_SWAP_FAILED",
                      "message", "the complete staged database could not replace the prior store",
                      "remediation", "close readers holding the store and retry");
        cbm_unlink(stage);
        return CBM_NOT_FOUND;
    }

    /* Auto-update artifact if one already exists (persistence was enabled previously) */
    if (repo_path && cbm_artifact_exists(repo_path)) {
        if (cbm_artifact_export(db_path, repo_path, project, CBM_ARTIFACT_FAST) != 0) {
            cbm_log_error("incremental.artifact_failed", "code",
                          "CBM_INCREMENTAL_ARTIFACT_EXPORT_FAILED", "message",
                          "the updated store could not be exported to the configured artifact",
                          "remediation", "inspect the artifact error and retry a clean export");
            return CBM_NOT_FOUND;
        }
    }
    return 0;
}

/* ── Incremental pipeline entry point ────────────────────────────── */

int cbm_pipeline_run_incremental(cbm_pipeline_t *p, const char *db_path, cbm_file_info_t *files,
                                 int file_count) {
    struct timespec t0;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t0);

    const char *project = cbm_pipeline_project_name(p);

    /* Open existing disk DB */
    cbm_store_t *store = cbm_store_open_path(db_path);
    if (!store) {
        cbm_log_error("incremental.err", "msg", "open_db_failed", "path", db_path);
        return CBM_NOT_FOUND;
    }

    /* Load stored file hashes */
    cbm_file_hash_t *stored = NULL;
    int stored_count = 0;
    cbm_store_get_file_hashes(store, project, &stored, &stored_count);

    /* Classify files */
    int n_changed = 0;
    int n_unchanged = 0;
    bool *is_changed =
        classify_files(files, file_count, stored, stored_count, &n_changed, &n_unchanged);
    if (!is_changed) {
        cbm_store_free_file_hashes(stored, stored_count);
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }

    /* Classify stored files absent from current discovery: truly-deleted
     * (purge) vs mode-skipped (preserve nodes AND hash rows). */
    char **deleted = NULL;
    cbm_file_hash_t *mode_skipped = NULL;
    int mode_skipped_count = 0;
    int deleted_count = 0;
    int deleted_rc = find_deleted_files(cbm_pipeline_repo_path(p), files, file_count, stored,
                                        stored_count, &deleted, &deleted_count, &mode_skipped,
                                        &mode_skipped_count);
    if (deleted_rc != 0) {
        free(is_changed);
        cbm_store_free_file_hashes(stored, stored_count);
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }

    cbm_log_info("incremental.classify", "changed", itoa_buf(n_changed), "unchanged",
                 itoa_buf(n_unchanged), "deleted", itoa_buf(deleted_count), "mode_skipped",
                 itoa_buf(mode_skipped_count));

    /* Fast path: nothing changed → skip. The on-disk DB is left untouched,
     * which means existing hash rows (including for any mode-skipped files
     * that were already preserved by an earlier run) remain intact. */
    if (n_changed == 0 && deleted_count == 0) {
        cbm_log_info("incremental.noop", "reason", "no_changes");
        free(is_changed);
        free(deleted);
        free_mode_skipped(mode_skipped, mode_skipped_count);
        cbm_store_free_file_hashes(stored, stored_count);
        cbm_store_close(store);
        return 0;
    }

    cbm_store_free_file_hashes(stored, stored_count);

    /* Build list of changed files */
    cbm_file_info_t *changed_files =
        (n_changed > 0) ? malloc((size_t)n_changed * sizeof(cbm_file_info_t)) : NULL;
    if (n_changed > 0 && !changed_files) {
        cbm_log_error("incremental.reparse_failed", "code",
                      "CBM_INCREMENTAL_CHANGED_FILES_ALLOC_FAILED", "message",
                      "the complete changed-file list could not be allocated", "remediation",
                      "free memory or reduce repository size, then retry");
        for (int i = 0; i < deleted_count; i++) {
            free(deleted[i]);
        }
        free(deleted);
        free_mode_skipped(mode_skipped, mode_skipped_count);
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }
    int ci = 0;
    for (int i = 0; i < file_count; i++) {
        if (is_changed[i]) {
            changed_files[ci++] = files[i];
        }
    }
    free(is_changed);

    cbm_log_info("incremental.reparse", "files", itoa_buf(ci));

    struct timespec t;

    /* Step 1: Load existing graph into RAM */
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    cbm_gbuf_t *existing = cbm_gbuf_new(project, cbm_pipeline_repo_path(p));
    int load_rc = cbm_gbuf_load_from_db(existing, db_path, project);
    cbm_log_info("incremental.load_db", "rc", itoa_buf(load_rc), "nodes",
                 itoa_buf(cbm_gbuf_node_count(existing)), "edges",
                 itoa_buf(cbm_gbuf_edge_count(existing)), "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t)));

    if (load_rc != 0) {
        cbm_log_error("incremental.err", "msg", "load_db_failed");
        cbm_gbuf_free(existing);
        free(changed_files);
        for (int i = 0; i < deleted_count; i++) {
            free(deleted[i]);
        }
        free(deleted);
        free_mode_skipped(mode_skipped, mode_skipped_count);
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }

    cbm_store_close(store);

    /* Snapshot inbound cross-file edges into changed files BEFORE purging, so
     * the cascade delete doesn't permanently drop edges whose source lives in
     * an unchanged (never-re-parsed) file. Re-linked after re-resolution. */
    cbm_edge_capture_t edge_cap = {0};
    edge_cap.gbuf = existing;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    {
        CBMHashTable *changed_paths = cbm_ht_create(ci > 0 ? (size_t)ci * PAIR_LEN : CBM_SZ_64);
        if (!changed_paths) {
            edge_cap.failed = true;
            cbm_log_error("incremental.edge_snapshot_failed", "code",
                          "CBM_INCREMENTAL_CHANGED_PATHS_ALLOC_FAILED", "message",
                          "the changed-path membership index could not be allocated",
                          "remediation", "free memory or reduce the repository size, then retry");
        } else {
            for (int i = 0; i < ci; i++) {
                cbm_ht_set(changed_paths, changed_files[i].rel_path, &changed_files[i]);
            }
            edge_cap.changed_paths = changed_paths;
            cbm_gbuf_foreach_edge(existing, incr_capture_inbound_edge, &edge_cap);
            edge_cap.changed_paths = NULL;
            cbm_ht_free(changed_paths); /* keys borrowed from changed_files; not freed here */
        }
    }
    cbm_log_info("incremental.edge_snapshot", "captured", itoa_buf(edge_cap.count), "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t)));
    if (edge_cap.failed) {
        incr_free_edge_capture(&edge_cap);
        cbm_gbuf_free(existing);
        free(changed_files);
        for (int i = 0; i < deleted_count; i++) {
            free(deleted[i]);
        }
        free(deleted);
        free_mode_skipped(mode_skipped, mode_skipped_count);
        return CBM_NOT_FOUND;
    }

    /* Step 2: Purge stale nodes */
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    for (int i = 0; i < ci; i++) {
        cbm_gbuf_delete_by_file(existing, changed_files[i].rel_path);
    }
    for (int i = 0; i < deleted_count; i++) {
        cbm_gbuf_delete_by_file(existing, deleted[i]);
        free(deleted[i]);
    }
    free(deleted);
    cbm_log_info("incremental.purge", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));

    /* Step 3-5: Registry + extract + resolve */
    cbm_registry_t *registry = cbm_registry_new();
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    cbm_gbuf_foreach_node(existing, registry_visitor, registry);
    cbm_log_info("incremental.registry_seed", "symbols", itoa_buf(cbm_registry_size(registry)),
                 "elapsed_ms", itoa_buf((int)elapsed_ms(t)));

    /* Discovery exclusions (gitignore + skip dirs) captured by the run that
     * routed here. Borrowed from the pipeline so the auxiliary repo walks
     * (pkgmap via merge_pkg_entries, path aliases) skip excluded subtrees on
     * incremental runs too — same borrow as the full path (#792/#804). */
    char **excluded_dirs = NULL;
    int excluded_count = 0;
    cbm_pipeline_get_excluded(p, &excluded_dirs, &excluded_count);

    cbm_path_alias_collection_t *path_aliases =
        cbm_load_path_aliases_excluded(cbm_pipeline_repo_path(p), excluded_dirs, excluded_count);

    cbm_pipeline_ctx_t ctx = {
        .project_name = project,
        .repo_path = cbm_pipeline_repo_path(p),
        .gbuf = existing,
        .registry = registry,
        .cancelled = cbm_pipeline_cancelled_ptr(p),
        .pipeline = p, /* so passes can record per-file skips (Track B) */
        .mode = cbm_pipeline_get_mode(p),
        .path_aliases = path_aliases,
        .excluded_dirs = excluded_dirs,
        .excluded_count = excluded_count,
    };

    bool file_source_failed = false;
    for (int i = 0; i < ci; i++) {
        char *file_qn = cbm_pipeline_fqn_compute(project, changed_files[i].rel_path, "__file__");
        if (file_qn) {
            const char *slash = strrchr(changed_files[i].rel_path, '/');
            const char *basename = slash ? slash + SKIP_ONE : changed_files[i].rel_path;
            const char *ext = strrchr(basename, '.');
            char props[CBM_SZ_256];
            snprintf(props, sizeof(props), "{\"extension\":\"%s\"}", ext ? ext : "");
            size_t source_len = 0;
            uint8_t *source_bytes =
                cbm_pipeline_read_file_identity_bytes(&changed_files[i], &source_len);
            int64_t file_id = source_bytes
                                  ? cbm_gbuf_upsert_source_node(
                                        existing, "File", basename, file_qn,
                                        changed_files[i].rel_path, 0, 0, source_bytes, source_len, 0,
                                        (uint64_t)source_len, props)
                                  : 0;
            free(source_bytes);
            free(file_qn);
            if (file_id <= 0) {
                file_source_failed = true;
                break;
            }
        } else {
            file_source_failed = true;
            break;
        }
    }

    if (file_source_failed) {
        cbm_log_error("incremental.err", "code", "CBM_INCREMENTAL_FILE_SOURCE_FAILED",
                      "message", "changed File node could not retain exact source", "remediation",
                      "inspect the preceding source read or graph-buffer error and retry");
        incr_free_edge_capture(&edge_cap);
        free(changed_files);
        cbm_registry_free(registry);
        cbm_path_alias_collection_free(path_aliases);
        free_mode_skipped(mode_skipped, mode_skipped_count);
        cbm_gbuf_free(existing);
        return CBM_NOT_FOUND;
    }

    run_extract_resolve(&ctx, changed_files, ci);
    cbm_pipeline_pass_k8s(&ctx, changed_files, ci);
    run_postpasses(&ctx, changed_files, ci, project);

    free(changed_files);
    cbm_registry_free(registry);
    cbm_path_alias_collection_free(path_aliases);

    /* Re-link inbound cross-file edges that the purge orphaned. Runs after
     * re-resolution AND post-passes so the freshly re-created target nodes
     * exist and nothing downstream clobbers the restored edges; insert_edge
     * dedups, so any edge the resolver already recreated is a no-op. */
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    int relinked = incr_restore_inbound_edges(existing, &edge_cap);
    cbm_log_info("incremental.edge_relink", "relinked", itoa_buf(relinked), "captured",
                 itoa_buf(edge_cap.count), "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    incr_free_edge_capture(&edge_cap);
    if (relinked < 0) {
        free_mode_skipped(mode_skipped, mode_skipped_count);
        cbm_gbuf_free(existing);
        return CBM_NOT_FOUND;
    }

    /* Step 7: Dump to disk (preserves mode-skipped hash rows so the next
     * reindex can correctly classify those files instead of seeing them
     * as never-existed; also exports a fast-mode artifact when one is
     * already present alongside the repo). */
    /* Record committed counts before dump_and_persist (whose dump frees the
     * gbuf node index, zeroing the count) so the #334 plausibility gate also
     * covers incremental reindexes, not just full ones. */
    cbm_pipeline_set_committed_counts(p, cbm_gbuf_node_count(existing),
                                      cbm_gbuf_edge_count(existing));
    int persist_rc = dump_and_persist(existing, db_path, project, files, file_count, mode_skipped,
                                      mode_skipped_count, cbm_pipeline_repo_path(p));
    free_mode_skipped(mode_skipped, mode_skipped_count);
    cbm_gbuf_free(existing);

    if (persist_rc != 0) {
        return CBM_NOT_FOUND;
    }
    cbm_log_info("incremental.done", "elapsed_ms", itoa_buf((int)elapsed_ms(t0)));
    return 0;
}
