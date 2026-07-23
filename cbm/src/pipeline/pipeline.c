/*
 * pipeline.c — Indexing pipeline orchestrator.
 *
 * Coordinates multi-pass indexing:
 *   1. Discover files
 *   2. Build structure (Project/Folder/Package/File nodes)
 *   3. Bulk load sources (read + LZ4 HC compress)
 *   4. Extract definitions (fused: extract + write nodes + build registry)
 *   5. Resolve imports, calls, usages, semantic edges
 *   6. Post-passes: tests, communities, HTTP links, git history
 *   7. Dump graph buffer to SQLite
 */
#include "foundation/constants.h"

enum { CBM_DIR_PERMS = 0755, PL_RING = 4, PL_RING_MASK = 3, PL_SEQ_PASSES = 6, PL_WAL_BUF = 1040 };
#include "pipeline/pipeline.h"
#include "pipeline/artifact.h"
#include "pipeline/pipeline_internal.h"
#include "pipeline/pass_lsp_cross.h"
#include "pipeline/source_snapshot.h"
#include "pipeline/worker_pool.h"
#include "graph_buffer/graph_buffer.h"
#include "mcp/index_supervisor.h" /* cbm_index_worker_active — #405 FSV abort hook gate */
#include "git/git_context.h"
#include "store/store.h"
#include "discover/discover.h"
#include "discover/userconfig.h"
#include "foundation/platform.h"
#include "foundation/compat_fs.h"
#include "foundation/log.h"
#include "foundation/str_util.h"
#include "foundation/hash_table.h"
#include "foundation/compat.h"
#include "foundation/compat_thread.h"
#include "foundation/profile.h"
#include "foundation/mem.h"
#include "foundation/sha256.h"
#include "foundation/schema_version.h"

#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <time.h>
#include <windows.h>

enum { PL_ROUTE_FULL = CBM_INCREMENTAL_REBUILD_REQUIRED };

static inline void *intptr_to_ptr(intptr_t v) {
    void *p;
    memcpy(&p, &v, sizeof(p));
    return p;
}

/* ── Global index lock ─────────────────────────────────────────── */
/* Prevents concurrent pipeline runs on the same DB file.
 * Atomic spinlock: 0 = free, 1 = locked. */
static atomic_int g_pipeline_busy = 0;

bool cbm_pipeline_try_lock(void) {
    return atomic_exchange(&g_pipeline_busy, 1) == 0;
}

#define LOCK_SPIN_NS 100000000 /* 100ms between lock retries */

void cbm_pipeline_lock(void) {
    while (atomic_exchange(&g_pipeline_busy, 1) != 0) {
        struct timespec ts = {0, LOCK_SPIN_NS};
        cbm_nanosleep(&ts, NULL);
    }
}

void cbm_pipeline_unlock(void) {
    atomic_store(&g_pipeline_busy, 0);
}

int cbm_pipeline_unique_stage_path(const char *db_path, const char *kind, char **out_path) {
    if (!db_path || !kind || !out_path || db_path[0] == '\0' || kind[0] == '\0') {
        cbm_log_error("pipeline.stage_identity_failed", "code",
                      "CBM_PIPELINE_STAGE_IDENTITY_INVALID", "message",
                      "the live database or stage kind is empty", "remediation",
                      "supply the exact live database path and a non-empty transaction kind");
        return CBM_NOT_FOUND;
    }
    *out_path = NULL;
    LARGE_INTEGER counter;
    if (!QueryPerformanceCounter(&counter)) {
        char native_error[32];
        (void)snprintf(native_error, sizeof(native_error), "%lu", (unsigned long)GetLastError());
        cbm_log_error("pipeline.stage_identity_failed", "code", "CBM_PIPELINE_STAGE_CLOCK_FAILED",
                      "native_error_kind", "win32", "native_error", native_error, "message",
                      "a unique staging identity could not be derived", "remediation",
                      "resolve the reported Windows timing failure and retry indexing");
        return CBM_NOT_FOUND;
    }
    static volatile LONG sequence;
    LONG generation = InterlockedIncrement(&sequence);
    if (generation <= 0) {
        cbm_log_error("pipeline.stage_identity_failed", "code",
                      "CBM_PIPELINE_STAGE_SEQUENCE_EXHAUSTED", "message",
                      "the process-local staging sequence exhausted its positive range",
                      "remediation", "restart the indexing worker and retry");
        return CBM_NOT_FOUND;
    }

    size_t db_len = strlen(db_path);
    size_t kind_len = strlen(kind);
    const size_t suffix_capacity = 96;
    if (db_len > SIZE_MAX - kind_len || db_len + kind_len > SIZE_MAX - suffix_capacity) {
        cbm_log_error("pipeline.stage_identity_failed", "code", "CBM_PIPELINE_STAGE_PATH_OVERFLOW",
                      "message", "the unique staging path exceeds addressable memory",
                      "remediation", "shorten the configured store path and retry indexing");
        return CBM_NOT_FOUND;
    }
    size_t capacity = db_len + kind_len + suffix_capacity;
    char *path = (char *)malloc(capacity);
    if (!path) {
        cbm_log_error("pipeline.stage_identity_failed", "code",
                      "CBM_PIPELINE_STAGE_PATH_ALLOC_FAILED", "message",
                      "the unique staging path could not be allocated", "remediation",
                      "free memory or shorten the configured store path, then retry indexing");
        return CBM_NOT_FOUND;
    }
    int written = snprintf(path, capacity, "%s.%s-stage-%lu-%016llx-%ld", db_path, kind,
                           (unsigned long)GetCurrentProcessId(),
                           (unsigned long long)counter.QuadPart, (long)generation);
    if (written <= 0 || (size_t)written >= capacity || cbm_path_exists(path)) {
        cbm_log_error("pipeline.stage_identity_failed", "code",
                      "CBM_PIPELINE_STAGE_IDENTITY_COLLISION", "path", path, "message",
                      "the generated staging identity is not absent", "remediation",
                      "preserve the colliding path and retry with a new indexing request");
        free(path);
        return CBM_NOT_FOUND;
    }
    *out_path = path;
    return 0;
}

/* ── Internal state ──────────────────────────────────────────────── */

struct cbm_pipeline {
    char *repo_path;
    const char *source_root;
    char *db_path;
    char *project_name;
    cbm_git_context_t git_ctx;
    char *branch_qn;
    cbm_index_mode_t mode;
    atomic_int cancelled;
    bool persistence; /* write .codebase-memory/graph.db.zst after indexing */
    cbm_pipeline_row_sink_v1_t row_sink;
    bool row_sink_active;
    bool row_sink_completed;

    /* Indexing state (set during run) */
    cbm_gbuf_t *gbuf;
    cbm_registry_t *registry;

    /* Directory subtrees skipped during discovery (rel paths). Captured from
     * cbm_discover_ex so the MCP layer can report excluded subtrees (#411).
     * Owned by the pipeline; freed in cbm_pipeline_free. */
    char **excluded_dirs;
    int excluded_count;

    /* Per-file indexing failures (skipped files) surfaced via MCP/CLI/logfile
     * (Stage 2 / Track B). A skip is the expected handled outcome of a bad or
     * oversized file — the run still succeeds ("indexed"). Owned by the
     * pipeline; freed in cbm_pipeline_free. */
    cbm_file_error_t *file_errors;
    int file_errors_count;
    int file_errors_cap;

    /* User-defined extension overrides (loaded once per run) */
    cbm_userconfig_t *userconfig;

    /* Committed graph size at dump time (-1 = dump did not run). #334 gate axis. */
    int committed_nodes;
    int committed_edges;

    /* ADR (project_summaries) captured before a full-reindex DB delete, so it
     * can be restored after the rebuild. NULL when no ADR existed. Issue #516. */
    char *saved_adr;
};

/* ── Global pkgmap (one active pipeline at a time) ─────────────── */

static CBMHashTable *g_pkgmap = NULL;

CBMHashTable *cbm_pipeline_get_pkgmap(void) {
    return g_pkgmap;
}

void cbm_pipeline_set_pkgmap(CBMHashTable *map) {
    g_pkgmap = map;
}

/* ── Timing helper ──────────────────────────────────────────────── */

static double elapsed_ms(struct timespec start) {
    struct timespec now;
    cbm_clock_gettime(CLOCK_MONOTONIC, &now);
    return ((double)(now.tv_sec - start.tv_sec) * CBM_MS_PER_SEC) +
           ((double)(now.tv_nsec - start.tv_nsec) / CBM_US_PER_SEC_F);
}

/* Format int to string for logging. Thread-safe via TLS rotating buffers. */
static const char *itoa_buf(int val) {
    static CBM_TLS char bufs[PL_RING][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + SKIP_ONE) & PL_RING_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", val);
    return bufs[i];
}

/* Log current + peak RSS at a pipeline phase boundary (memory profiling). */
static void log_phase_mem(const char *phase) {
    enum { PL_BYTES_PER_MB = 1024 * 1024 };
    cbm_log_info("mem.phase", "phase", phase, "rss_mb",
                 itoa_buf((int)(cbm_mem_rss() / PL_BYTES_PER_MB)), "peak_mb",
                 itoa_buf((int)(cbm_mem_peak_rss() / PL_BYTES_PER_MB)));
}

/* ── Lifecycle ──────────────────────────────────────────────────── */

cbm_pipeline_t *cbm_pipeline_new(const char *repo_path, const char *db_path,
                                 cbm_index_mode_t mode) {
    if (!repo_path) {
        return NULL;
    }

    cbm_pipeline_t *p = calloc(CBM_ALLOC_ONE, sizeof(cbm_pipeline_t));
    if (!p) {
        return NULL;
    }

    p->repo_path = strdup(repo_path);
    p->db_path = db_path ? strdup(db_path) : NULL;
    p->project_name = cbm_project_name_from_path(repo_path);
    (void)cbm_git_context_resolve(repo_path, &p->git_ctx);
    p->branch_qn = cbm_git_context_branch_qn(p->project_name, &p->git_ctx);
    p->mode = mode;
    p->persistence = false;
    p->committed_nodes = -1;
    p->committed_edges = -1;
    atomic_init(&p->cancelled, 0);

    return p;
}

void cbm_pipeline_set_persistence(cbm_pipeline_t *p, bool enabled) {
    if (p) {
        p->persistence = enabled;
    }
}

int cbm_pipeline_set_sink(cbm_pipeline_t *p, const cbm_pipeline_row_sink_v1_t *sink) {
    if (!p) {
        cbm_log_error("pipeline.row_sink_refused", "code", "CBM_PIPELINE_ROW_SINK_PIPELINE_NULL",
                      "message", "a row sink cannot be installed on a NULL pipeline", "remediation",
                      "create the pipeline successfully before installing a sink");
        return CBM_NOT_FOUND;
    }
    if (!sink) {
        memset(&p->row_sink, 0, sizeof(p->row_sink));
        p->row_sink_active = false;
        p->row_sink_completed = false;
        if (p->gbuf) {
            cbm_gbuf_set_row_sink(p->gbuf, NULL, NULL, NULL);
        }
        return 0;
    }
    if (sink->abi_version != CBM_PIPELINE_ROW_SINK_ABI_V1 ||
        sink->struct_size != sizeof(cbm_pipeline_row_sink_v1_t)) {
        cbm_log_error("pipeline.row_sink_refused", "code", "CBM_PIPELINE_ROW_SINK_ABI_UNSUPPORTED",
                      "message", "the row-sink ABI version or descriptor size is unsupported",
                      "remediation",
                      "construct the exact frozen cbm_pipeline_row_sink_v1_t descriptor");
        return CBM_NOT_FOUND;
    }
    if (!sink->node || !sink->edge || !sink->file_hash || !sink->complete || !sink->ctx) {
        cbm_log_error(
            "pipeline.row_sink_refused", "code", "CBM_PIPELINE_ROW_SINK_INCOMPLETE", "message",
            "a complete snapshot sink requires node, edge, file-hash, completion, and "
            "context fields",
            "remediation", "install every v1 callback together or pass NULL to disable the sink");
        return CBM_NOT_FOUND;
    }
    p->row_sink = *sink;
    p->row_sink_active = true;
    p->row_sink_completed = false;
    if (p->gbuf) {
        cbm_gbuf_set_row_sink(p->gbuf, sink->node, sink->edge, sink->ctx);
    }
    return 0;
}

bool cbm_pipeline_set_project_name(cbm_pipeline_t *p, const char *name) {
    if (!p || !name || !name[0]) {
        return false;
    }

    char *normalized = cbm_project_name_from_path(name);
    if (!normalized) {
        return false;
    }
    if (!cbm_validate_project_name(normalized)) {
        free(normalized);
        return false;
    }

    free(p->project_name);
    p->project_name = normalized;
    free(p->branch_qn);
    p->branch_qn = cbm_git_context_branch_qn(p->project_name, &p->git_ctx);
    return true;
}

void cbm_pipeline_free(cbm_pipeline_t *p) {
    if (!p) {
        return;
    }
    free(p->repo_path);
    free(p->db_path);
    free(p->project_name);
    cbm_discover_free_excluded(p->excluded_dirs, p->excluded_count);
    p->excluded_dirs = NULL;
    p->excluded_count = 0;
    for (int i = 0; i < p->file_errors_count; i++) {
        free(p->file_errors[i].path);
        free(p->file_errors[i].reason);
        free(p->file_errors[i].phase);
    }
    free(p->file_errors);
    p->file_errors = NULL;
    p->file_errors_count = 0;
    p->file_errors_cap = 0;
    free(p->branch_qn);
    free(p->saved_adr); /* freed here too: error paths can exit before the
                         * restore in dump_and_persist_hashes runs. Issue #516. */
    p->saved_adr = NULL;
    cbm_git_context_free(&p->git_ctx);
    /* gbuf, store, registry freed during/after run */
    /* Defensively free userconfig in case run() was never called or panicked */
    if (p->userconfig) {
        cbm_set_user_lang_config(NULL);
        cbm_userconfig_free(p->userconfig);
        p->userconfig = NULL;
    }
    free(p);
}

void cbm_pipeline_cancel(cbm_pipeline_t *p) {
    if (p) {
        atomic_store(&p->cancelled, 1);
    }
}

const char *cbm_pipeline_project_name(const cbm_pipeline_t *p) {
    return p ? p->project_name : NULL;
}

const char *cbm_pipeline_repo_path(const cbm_pipeline_t *p) {
    return p ? p->repo_path : NULL;
}

const char *cbm_pipeline_source_root(const cbm_pipeline_t *p) {
    return p ? p->source_root : NULL;
}

atomic_int *cbm_pipeline_cancelled_ptr(cbm_pipeline_t *p) {
    return p ? &p->cancelled : NULL;
}

int cbm_pipeline_get_mode(const cbm_pipeline_t *p) {
    return p ? (int)p->mode : 0;
}

void cbm_pipeline_get_excluded(const cbm_pipeline_t *p, char ***out, int *count) {
    if (out) {
        *out = p ? p->excluded_dirs : NULL;
    }
    if (count) {
        *count = p ? p->excluded_count : 0;
    }
}

/* NULL-safe heap strdup (avoids a strdup dependency + guards NULL inputs). */
static char *fe_strdup(const char *s) {
    if (!s) {
        return NULL;
    }
    size_t n = strlen(s) + 1;
    char *d = (char *)malloc(n);
    if (d) {
        memcpy(d, s, n);
    }
    return d;
}

void cbm_pipeline_add_file_error(cbm_pipeline_t *p, const char *path, const char *reason,
                                 const char *phase) {
    if (!p) {
        return;
    }
    if (p->file_errors_count >= p->file_errors_cap) {
        int ncap = p->file_errors_cap ? p->file_errors_cap * 2 : 16;
        cbm_file_error_t *grown =
            (cbm_file_error_t *)realloc(p->file_errors, (size_t)ncap * sizeof(*grown));
        if (!grown) {
            /* Never abort indexing just to record a skip — drop this record. */
            return;
        }
        p->file_errors = grown;
        p->file_errors_cap = ncap;
    }
    cbm_file_error_t *e = &p->file_errors[p->file_errors_count];
    e->path = fe_strdup(path);
    e->reason = fe_strdup(reason);
    e->phase = fe_strdup(phase);
    p->file_errors_count++;
}

void cbm_pipeline_get_file_errors(const cbm_pipeline_t *p, cbm_file_error_t **out, int *count) {
    if (out) {
        *out = p ? p->file_errors : NULL;
    }
    if (count) {
        *count = p ? p->file_errors_count : 0;
    }
}

void cbm_pipeline_get_committed_counts(const cbm_pipeline_t *p, int *nodes, int *edges) {
    if (nodes) {
        *nodes = p ? p->committed_nodes : -1;
    }
    if (edges) {
        *edges = p ? p->committed_edges : -1;
    }
}

void cbm_pipeline_set_committed_counts(cbm_pipeline_t *p, int nodes, int edges) {
    if (p) {
        p->committed_nodes = nodes;
        p->committed_edges = edges;
    }
}

bool cbm_pipeline_row_sink_active(const cbm_pipeline_t *p) {
    return p && p->row_sink_active;
}

void cbm_pipeline_attach_row_sink(cbm_pipeline_t *p, cbm_gbuf_t *gbuf) {
    if (!gbuf) {
        return;
    }
    if (p && p->row_sink_active) {
        cbm_gbuf_set_row_sink(gbuf, p->row_sink.node, p->row_sink.edge, p->row_sink.ctx);
    } else {
        cbm_gbuf_set_row_sink(gbuf, NULL, NULL, NULL);
    }
}

int cbm_pipeline_emit_file_hash(cbm_pipeline_t *p, const char *project, const char *rel_path,
                                const char *sha256, int64_t mtime_ns, int64_t size) {
    if (!p || !p->row_sink_active) {
        return 0;
    }
    if (!project || !project[0] || !rel_path || !rel_path[0] || !sha256 ||
        strlen(sha256) != CBM_SHA256_HEX_LEN) {
        cbm_log_error("pipeline.row_sink_refused", "code",
                      "CBM_PIPELINE_ROW_SINK_FILE_HASH_INVALID", "rel_path",
                      rel_path ? rel_path : "", "message",
                      "a persisted file-hash row is incomplete or malformed", "remediation",
                      "repair source-snapshot identity capture before publishing rows");
        return CBM_NOT_FOUND;
    }
    cbm_pipeline_row_file_hash_t row = {
        .project = project,
        .rel_path = rel_path,
        .sha256 = sha256,
        .mtime_ns = mtime_ns,
        .size = size,
    };
    if (p->row_sink.file_hash(&row, p->row_sink.ctx) != 0) {
        cbm_log_error("pipeline.row_sink_refused", "code",
                      "CBM_PIPELINE_ROW_SINK_FILE_HASH_CALLBACK_FAILED", "rel_path", rel_path,
                      "message", "the consumer refused a persisted file-hash row", "remediation",
                      "inspect the consumer's structured callback error and retry");
        return CBM_NOT_FOUND;
    }
    return 0;
}

int cbm_pipeline_complete_row_sink(cbm_pipeline_t *p, size_t file_hash_count) {
    if (!p || !p->row_sink_active) {
        return 0;
    }
    if (p->row_sink_completed || p->committed_nodes < 0 || p->committed_edges < 0) {
        cbm_log_error(
            "pipeline.row_sink_refused", "code", "CBM_PIPELINE_ROW_SINK_COMPLETION_INVALID",
            "message", "the snapshot completion manifest is duplicate or lacks committed counts",
            "remediation", "emit exactly one manifest after all graph and file-hash rows");
        return CBM_NOT_FOUND;
    }
    cbm_pipeline_row_manifest_t manifest = {
        .project = p->project_name,
        .node_count = (size_t)p->committed_nodes,
        .edge_count = (size_t)p->committed_edges,
        .file_hash_count = file_hash_count,
        .graph_schema_version = CBM_GRAPH_SCHEMA_VERSION,
    };
    if (p->row_sink.complete(&manifest, p->row_sink.ctx) != 0) {
        cbm_log_error("pipeline.row_sink_refused", "code",
                      "CBM_PIPELINE_ROW_SINK_COMPLETION_CALLBACK_FAILED", "message",
                      "the consumer refused the completed snapshot manifest", "remediation",
                      "compare observed rows to the declared counts and repair the producer or "
                      "consumer contract");
        return CBM_NOT_FOUND;
    }
    p->row_sink_completed = true;
    return 0;
}

static int effective_worker_count(bool initial) {
    return cbm_default_worker_count(initial);
}

/* Resolve the DB path for this pipeline. Caller must free(). */
static char *resolve_db_path(const cbm_pipeline_t *p) {
    char *path = malloc(CBM_SZ_1K);
    if (!path) {
        return NULL;
    }
    if (p->db_path) {
        snprintf(path, 1024, "%s", p->db_path);
#ifdef ASTRO_ENV_STORE
        return path;
#else
    } else {
        snprintf(path, 1024, "%s/%s.db", cbm_resolve_cache_dir(), p->project_name);
#endif
    }
#ifdef ASTRO_ENV_STORE
    /* #241: cbm_resolve_cache_dir() returns NULL when no store can be resolved
     * (platform.c). Passing that pointer to "%s" is undefined behaviour, and the
     * one caller of this function already treats NULL as "no database". Refuse. */
    const char *cache_dir = cbm_resolve_cache_dir();
    if (!cache_dir) {
        free(path);
        return NULL;
    }
    snprintf(path, 1024, "%s/%s.db", cache_dir, p->project_name);
#endif
    return path;
}

static int check_cancel(const cbm_pipeline_t *p) {
    return atomic_load(&p->cancelled) ? CBM_NOT_FOUND : 0;
}

/* ── Hash table cleanup callback ─────────────────────────────────── */

static void free_seen_dir_key(const char *key, void *val, void *ud) {
    (void)val;
    (void)ud;
    free((void *)key);
}

/* ── Pass 1: Structure ──────────────────────────────────────────── */

/* Create Project, Folder/Package, and File nodes in the graph buffer. */
/* Walk directory chain upward, creating Folder nodes and CONTAINS_FOLDER edges. */
static int create_folder_chain(cbm_pipeline_t *p, const char *dir, CBMHashTable *seen_dirs) {
    char *walk = strdup(dir);
    if (!walk) {
        cbm_log_error("structure.folder_index_failed", "code", "CBM_FOLDER_PATH_ALLOC_FAILED",
                      "component", "structure.seen_dirs", "operation", "path_copy", "key",
                      dir ? dir : "", "message", "folder path could not be retained", "remediation",
                      "free memory or reduce repository size, then retry");
        return CBM_NOT_FOUND;
    }
    while (walk[0] != '\0' && !cbm_ht_get(seen_dirs, walk)) {
        char *owned_walk = strdup(walk);
        if (!owned_walk ||
            !cbm_ht_set_checked(seen_dirs, owned_walk, intptr_to_ptr(SKIP_ONE), NULL)) {
            free(owned_walk);
            cbm_log_error("structure.folder_index_failed", "code", "CBM_FOLDER_INDEX_INSERT_FAILED",
                          "component", "structure.seen_dirs", "operation", "insert", "key", walk,
                          "message", "folder membership index could not retain an entry",
                          "remediation", "free memory or reduce repository size, then retry");
            free(walk);
            return CBM_NOT_FOUND;
        }
        char *folder_qn = cbm_pipeline_fqn_folder(p->project_name, walk);
        const char *dir_base = strrchr(walk, '/');
        dir_base = dir_base ? dir_base + SKIP_ONE : walk;
        cbm_gbuf_upsert_node(p->gbuf, "Folder", dir_base, folder_qn, walk, 0, 0, "{}");

        char *pdir = strdup(walk);
        char *ps = strrchr(pdir, '/');
        if (ps) {
            *ps = '\0';
        } else {
            free(pdir);
            pdir = strdup("");
        }
        const char *pqn;
        char *pqn_heap = NULL;
        if (pdir[0] == '\0') {
            pqn = p->branch_qn ? p->branch_qn : p->project_name;
        } else {
            pqn_heap = cbm_pipeline_fqn_folder(p->project_name, pdir);
            pqn = pqn_heap;
        }
        const cbm_gbuf_node_t *fn = cbm_gbuf_find_by_qn(p->gbuf, folder_qn);
        const cbm_gbuf_node_t *pn = cbm_gbuf_find_by_qn(p->gbuf, pqn);
        if (fn && pn) {
            cbm_gbuf_insert_edge(p->gbuf, pn->id, fn->id, "CONTAINS_FOLDER", "{}");
        }
        free(folder_qn);
        free(pqn_heap);
        char *up = strrchr(walk, '/');
        if (up) {
            *up = '\0';
        } else {
            walk[0] = '\0';
        }
        free(pdir);
    }
    free(walk);
    return 0;
}

uint8_t *cbm_pipeline_read_file_identity_bytes(const cbm_file_info_t *file, size_t *out_len) {
    *out_len = 0;
    if (!file || !file->path || file->size < 0 || (uint64_t)file->size > SIZE_MAX - 1) {
        cbm_log_error("structure.file_source_refused", "code", "CBM_FILE_SOURCE_SIZE_INVALID",
                      "path", file && file->path ? file->path : "", "message",
                      "discovery supplied an invalid exact-source size", "remediation",
                      "re-run discovery after repairing the file metadata");
        return NULL;
    }
    size_t expected = (size_t)file->size;
    FILE *stream = cbm_fopen(file->path, "rb");
    if (!stream) {
        cbm_log_error("structure.file_source_refused", "code", "CBM_FILE_SOURCE_OPEN_FAILED",
                      "path", file->path, "message", "exact source file could not be opened",
                      "remediation", "restore read access and retry the index");
        return NULL;
    }
    uint8_t *bytes = malloc(expected + 1);
    if (!bytes) {
        (void)fclose(stream);
        cbm_log_error("structure.file_source_refused", "code", "CBM_FILE_SOURCE_ALLOC_FAILED",
                      "path", file->path, "message", "exact file source allocation failed",
                      "remediation", "free memory or reduce repository size, then retry");
        return NULL;
    }
    size_t actual = expected > 0 ? fread(bytes, 1, expected, stream) : 0;
    int extra = fgetc(stream);
    bool failed = actual != expected || extra != EOF || ferror(stream) != 0;
    (void)fclose(stream);
    if (failed) {
        free(bytes);
        cbm_log_error("structure.file_source_refused", "code", "CBM_FILE_SOURCE_CHANGED", "path",
                      file->path, "message",
                      "file bytes changed or became unreadable after discovery", "remediation",
                      "stop concurrent writers and retry from a stable checkout");
        return NULL;
    }
    bytes[expected] = 0;
    *out_len = expected;
    return bytes;
}

static int pass_structure(cbm_pipeline_t *p, const cbm_file_info_t *files, int file_count) {
    cbm_log_info("pass.start", "pass", "structure", "files", itoa_buf(file_count));

    /* Project node */
    cbm_gbuf_upsert_node(p->gbuf, "Project", p->project_name, p->project_name, NULL, 0, 0, "{}");
    const char *branch_qn = p->branch_qn ? p->branch_qn : p->project_name;
    const char *branch_name = p->git_ctx.branch ? p->git_ctx.branch : "working-tree";
    char branch_props[CBM_SZ_2K];
    const char *branch_props_json = "{}";
    if (cbm_git_context_props_json(&p->git_ctx, branch_props, sizeof(branch_props)) > 0) {
        branch_props_json = branch_props;
    }
    if (p->branch_qn) {
        int64_t branch_id = cbm_gbuf_upsert_node(p->gbuf, "Branch", branch_name, branch_qn, NULL, 0,
                                                 0, branch_props_json);
        const cbm_gbuf_node_t *project_node = cbm_gbuf_find_by_qn(p->gbuf, p->project_name);
        if (project_node && branch_id > 0) {
            cbm_gbuf_insert_edge(p->gbuf, project_node->id, branch_id, "HAS_BRANCH",
                                 branch_props_json);
        }
    }

    /* Collect unique directories and create Folder/Package nodes */
    CBMHashTable *seen_dirs = cbm_ht_create(CBM_SZ_256);
    if (!seen_dirs) {
        cbm_log_error("structure.folder_index_failed", "code", "CBM_FOLDER_INDEX_ALLOC_FAILED",
                      "component", "structure.seen_dirs", "operation", "create", "key", "",
                      "message", "folder membership index could not be allocated", "remediation",
                      "free memory or reduce repository size, then retry");
        return CBM_NOT_FOUND;
    }

    for (int i = 0; i < file_count; i++) {
        const char *rel = files[i].rel_path;
        if (!rel) {
            continue;
        }

        /* Create File node */
        char *file_qn = cbm_pipeline_fqn_compute(p->project_name, rel, "__file__");
        /* Extract basename */
        const char *slash = strrchr(rel, '/');
        const char *basename = slash ? slash + SKIP_ONE : rel;

        char props[CBM_SZ_256];
        const char *ext = strrchr(basename, '.');
        snprintf(props, sizeof(props), "{\"extension\":\"%s\"}", ext ? ext : "");

        const char *qualified_name = file_qn;
        const char *file_path = rel;
        size_t source_len = 0;
        uint8_t *source_bytes = cbm_pipeline_read_file_identity_bytes(&files[i], &source_len);
        if (!source_bytes) {
            free(file_qn);
            cbm_ht_foreach(seen_dirs, free_seen_dir_key, NULL);
            cbm_ht_free(seen_dirs);
            return CBM_NOT_FOUND;
        }
        int64_t file_id =
            cbm_gbuf_upsert_source_node(p->gbuf, "File", basename, qualified_name, file_path, 0, 0,
                                        source_bytes, source_len, 0, (uint64_t)source_len, props);
        free(source_bytes);
        if (file_id <= 0) {
            free(file_qn);
            cbm_ht_foreach(seen_dirs, free_seen_dir_key, NULL);
            cbm_ht_free(seen_dirs);
            return CBM_NOT_FOUND;
        }

        /* CONTAINS_FILE edge: parent dir -> file */
        char *dir = strdup(rel);
        char *last_slash = strrchr(dir, '/');
        if (last_slash) {
            {
                *last_slash = '\0';
            }
        } else {
            free(dir);
            dir = strdup("");
        }

        const char *parent_qn;
        char *parent_qn_heap = NULL;
        if (dir[0] == '\0') {
            parent_qn = branch_qn;
        } else {
            parent_qn_heap = cbm_pipeline_fqn_folder(p->project_name, dir);
            parent_qn = parent_qn_heap;
        }

        /* Walk up directory chain, creating Folder nodes */
        if (create_folder_chain(p, dir, seen_dirs) != 0) {
            free(file_qn);
            free(dir);
            free(parent_qn_heap);
            cbm_ht_foreach(seen_dirs, free_seen_dir_key, NULL);
            cbm_ht_free(seen_dirs);
            return CBM_NOT_FOUND;
        }

        /* Now create the CONTAINS_FILE edge */
        const cbm_gbuf_node_t *fnode = cbm_gbuf_find_by_qn(p->gbuf, file_qn);
        const cbm_gbuf_node_t *pnode = cbm_gbuf_find_by_qn(p->gbuf, parent_qn);
        if (fnode && pnode) {
            cbm_gbuf_insert_edge(p->gbuf, pnode->id, fnode->id, "CONTAINS_FILE", "{}");
        }

        free(file_qn);
        free(dir);
        free(parent_qn_heap);
    }

    /* Free seen_dirs keys */
    cbm_ht_foreach(seen_dirs, free_seen_dir_key, NULL);
    cbm_ht_free(seen_dirs);

    cbm_log_info("pass.done", "pass", "structure", "nodes", itoa_buf(cbm_gbuf_node_count(p->gbuf)),
                 "edges", itoa_buf(cbm_gbuf_edge_count(p->gbuf)));
    return 0;
}

/* ── Pass 2: Definitions ─────────────────────────────────────────── */

/* Implemented in pass_definitions.c via cbm_pipeline_pass_definitions() */

/* ── Githistory compute thread (for fused post-pass parallelism) ─── */

typedef struct {
    const char *repo_path;
    cbm_githistory_result_t *result;
} gh_compute_arg_t;

static void *gh_compute_thread_fn(void *arg) {
    gh_compute_arg_t *a = arg;
    cbm_pipeline_githistory_compute(a->repo_path, a->result);
    return NULL;
}

/* Extract Route nodes from URL strings found in config files (YAML, HCL, TOML).
 * These are infrastructure-defined endpoints (Cloud Scheduler, Terraform). */
/* Process infra bindings: topic→URL pairs from IaC configs.
 * Creates Route nodes for endpoints and HANDLES edges linking
 * topic Routes to endpoint Routes (bridging the gap). */
/* Process one infra binding: create Route node + INFRA_MAPS edge. */
static int process_one_infra_binding(cbm_gbuf_t *gbuf, const CBMInfraBinding *ib,
                                     const char *rel_path) {
    char url_route_qn[CBM_ROUTE_QN_SIZE];
    snprintf(url_route_qn, sizeof(url_route_qn), "__route__infra__%s", ib->target_url);
    int64_t url_route_id = cbm_gbuf_upsert_node(gbuf, "Route", ib->target_url, url_route_qn,
                                                rel_path, 0, 0, "{\"source\":\"infra\"}");
    char topic_route_qn[CBM_ROUTE_QN_SIZE];
    snprintf(topic_route_qn, sizeof(topic_route_qn), "__route__%s__%s",
             ib->broker ? ib->broker : "async", ib->source_name);
    const cbm_gbuf_node_t *topic_route = cbm_gbuf_find_by_qn(gbuf, topic_route_qn);
    int64_t topic_route_id;
    if (topic_route) {
        topic_route_id = topic_route->id;
    } else {
        /* The config file IS the declaration that the topic/queue/schedule exists;
         * upsert its Route node so the binding maps even when no code-side dispatch
         * call created the node first (e.g. a standalone scheduler/subscription
         * manifest). */
        topic_route_id = cbm_gbuf_upsert_node(gbuf, "Route", ib->source_name, topic_route_qn,
                                              rel_path, 0, 0, ib->broker ? ib->broker : "async");
        if (topic_route_id <= 0) {
            return 0;
        }
    }
    char props[CBM_SZ_512];
    snprintf(props, sizeof(props), "{\"broker\":\"%s\",\"topic\":\"%s\",\"endpoint\":\"%s\"}",
             ib->broker ? ib->broker : "async", ib->source_name, ib->target_url);
    cbm_gbuf_insert_edge(gbuf, topic_route_id, url_route_id, "INFRA_MAPS", props);
    return SKIP_ONE;
}

static void cbm_pipeline_process_infra_bindings(cbm_gbuf_t *gbuf, const cbm_file_info_t *files,
                                                CBMFileResult **result_cache, int file_count) {
    int bindings = 0;
    for (int i = 0; i < file_count; i++) {
        if (!result_cache[i]) {
            continue;
        }
        for (int bi = 0; bi < result_cache[i]->infra_bindings.count; bi++) {
            const CBMInfraBinding *ib = &result_cache[i]->infra_bindings.items[bi];
            if (ib->source_name && ib->target_url) {
                bindings += process_one_infra_binding(gbuf, ib, files[i].rel_path);
            }
        }
    }
    if (bindings > 0) {
        char buf[CBM_SZ_16];
        snprintf(buf, sizeof(buf), "%d", bindings);
        cbm_log_info("pass.infra_bindings", "linked", buf);
    }
}

static bool is_infra_file(const char *fp) {
    return fp != NULL &&
           (strstr(fp, ".yaml") != NULL || strstr(fp, ".yml") != NULL ||
            strstr(fp, ".tf") != NULL || strstr(fp, ".hcl") != NULL || strstr(fp, ".toml") != NULL);
}

/* True when a YAML key path denotes an UPSTREAM dependency, CONFIG value, or
 * HEALTHCHECK target rather than an endpoint this service exposes. Such URLs
 * (auth JWKS, downstream service base URLs, package-registry URLs, healthcheck
 * curl targets) are NOT routes the service serves and must not mint Route nodes
 * (#521). Exposed-endpoint keys (push_endpoint, post_url, callback, webhook)
 * are intentionally absent here so they still produce infra Route nodes. */
static bool is_upstream_config_key(const char *key_path) {
    if (!key_path) {
        /* No key context (e.g. flat string) — keep prior behaviour and mint. */
        return false;
    }
    static const char *const deny[] = {"jwks",     "registry",     "registries", "healthcheck",
                                       "upstream", "_service_url", "auth",       NULL};
    for (int i = 0; deny[i]; i++) {
        if (strstr(key_path, deny[i]) != NULL) {
            return true;
        }
    }
    return false;
}

/* Try to create an infra Route node from one string_ref. */
static void try_upsert_infra_route(cbm_gbuf_t *gbuf, const CBMStringRef *sr, const char *fp) {
    if (sr->kind != CBM_STRREF_URL || !sr->value || !strstr(sr->value, "://")) {
        return;
    }
    /* Skip upstream/config/healthcheck URLs — they are not exposed routes (#521). */
    if (is_upstream_config_key(sr->key_path)) {
        return;
    }
    char route_qn[CBM_ROUTE_QN_SIZE];
    snprintf(route_qn, sizeof(route_qn), "__route__infra__%s", sr->value);
    char route_props[CBM_SZ_512];
    if (sr->key_path) {
        /* key_path is raw parser-derived config-key text: route it through the
         * UTF-8-safe JSON escaper so a quote/control/non-UTF-8 byte cannot make
         * the Route node's properties JSON invalid and get the repo refused —
         * same bypass class as #511. */
        char esc_kp[CBM_SZ_256];
        cbm_json_escape(esc_kp, sizeof(esc_kp), sr->key_path);
        snprintf(route_props, sizeof(route_props), "{\"source\":\"infra\",\"key_path\":\"%s\"}",
                 esc_kp);
    } else {
        snprintf(route_props, sizeof(route_props), "{\"source\":\"infra\"}");
    }
    cbm_gbuf_upsert_node(gbuf, "Route", sr->value, route_qn, fp, 0, 0, route_props);
}

/* A URL string_ref that does NOT denote a route the service serves: a value
 * containing whitespace is a command/sentence with an embedded URL (e.g. a
 * Docker healthcheck `curl --fail http://... || exit 1`); a NULL key_path is a
 * context-less/duplicate ref; an upstream/config/healthcheck key is an external
 * dependency, not an exposed route. (#521) */
static bool route_sr_denied(const CBMStringRef *sr) {
    if (!sr->value || strchr(sr->value, ' ')) {
        return true;
    }
    if (!sr->key_path) {
        return true;
    }
    return is_upstream_config_key(sr->key_path);
}

static int cbm_pipeline_extract_infra_routes(cbm_gbuf_t *gbuf, const cbm_file_info_t *files,
                                             CBMFileResult **result_cache, int file_count) {
    /* DENY-WINS-BY-VALUE: the same URL is often extracted as several string_refs
     * at different key_path granularities (full path, leaf key, flat). The Route
     * node is keyed by VALUE, so it would be minted if ANY granularity passed the
     * per-ref guard — e.g. a denied full path `registries.terraform-registry.url`
     * is defeated by a sibling leaf `url`. So pass 1 collects every URL value
     * denied under ANY of its refs; pass 2 mints only values never denied. (#521) */
    CBMHashTable *denied = cbm_ht_create(16);
    if (!denied) {
        cbm_log_error("infra_routes.index_failed", "code", "CBM_ROUTE_DENY_INDEX_ALLOC_FAILED",
                      "component", "infra_routes.denied", "operation", "create", "key", "",
                      "message", "route denial index could not be allocated", "remediation",
                      "free memory or reduce repository size, then retry");
        return CBM_NOT_FOUND;
    }
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < file_count; i++) {
            if (!result_cache[i] || !is_infra_file(files[i].rel_path)) {
                continue;
            }
            for (int si = 0; si < result_cache[i]->string_refs.count; si++) {
                const CBMStringRef *sr = &result_cache[i]->string_refs.items[si];
                if (sr->kind != CBM_STRREF_URL || !sr->value || !strstr(sr->value, "://")) {
                    continue;
                }
                if (pass == 0) {
                    if (denied && route_sr_denied(sr)) {
                        if (!cbm_ht_set_checked(denied, sr->value, (void *)1, NULL)) {
                            cbm_log_error(
                                "infra_routes.index_failed", "code",
                                "CBM_ROUTE_DENY_INDEX_INSERT_FAILED", "component",
                                "infra_routes.denied", "operation", "insert", "key", sr->value,
                                "message", "route denial index could not retain an entry",
                                "remediation", "free memory or reduce repository size, then retry");
                            cbm_ht_free(denied);
                            return CBM_NOT_FOUND;
                        }
                    }
                } else if (!denied || !cbm_ht_has(denied, sr->value)) {
                    try_upsert_infra_route(gbuf, sr, files[i].rel_path);
                }
            }
        }
    }
    cbm_ht_free(denied);
    return 0;
}

/* Run decorator_tags, configlink, and route matching passes. */
typedef int (*predump_pass_fn)(cbm_pipeline_ctx_t *);
static int predump_deco(cbm_pipeline_ctx_t *ctx) {
    return cbm_pipeline_pass_decorator_tags(ctx->gbuf, ctx->project_name);
}
static int predump_route(cbm_pipeline_ctx_t *ctx) {
    cbm_pipeline_create_route_nodes(ctx->gbuf);
    return 0;
}
static int predump_sim(cbm_pipeline_ctx_t *ctx) {
    return cbm_pipeline_pass_similarity(ctx);
}
static int predump_sem(cbm_pipeline_ctx_t *ctx) {
    return cbm_pipeline_pass_semantic_edges(ctx);
}
static int predump_cfg(cbm_pipeline_ctx_t *ctx) {
    return cbm_pipeline_pass_configlink(ctx);
}
static int predump_complexity(cbm_pipeline_ctx_t *ctx) {
    cbm_pipeline_pass_complexity(ctx);
    return 0;
}

static int run_predump_passes(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx) {
    static const struct {
        predump_pass_fn fn;
        const char *name;
        bool moderate_only; /* true = skip in fast mode */
    } passes[] = {
        {predump_deco, "decorator_tags", false}, {predump_cfg, "configlink", false},
        {predump_route, "route_match", false},   {predump_sim, "similarity", true},
        {predump_sem, "semantic_edges", true},   {predump_complexity, "complexity", false},
    };
    enum { PREDUMP_PASS_COUNT = 6 };
    struct timespec t;
    for (int i = 0; i < PREDUMP_PASS_COUNT && !check_cancel(p); i++) {
        /* "moderate_only" passes (similarity/semantic edges) run in FULL,
         * MODERATE and ADVANCED — they are skipped only in FAST. Compare
         * explicitly against FAST rather than `> MODERATE` so ADVANCED
         * (numerically 3) is not mistaken for a lighter mode than FULL. */
        if (passes[i].moderate_only && p->mode == CBM_MODE_FAST) {
            continue;
        }
        cbm_clock_gettime(CLOCK_MONOTONIC, &t);
        int rc = passes[i].fn(ctx);
        cbm_log_info("pass.timing", "pass", passes[i].name, "elapsed_ms",
                     itoa_buf((int)elapsed_ms(t)));
        /* Predump pass return contract: NEGATIVE == hard failure (CBM_NOT_FOUND
         * and friends are -1), ZERO/POSITIVE == success. Several passes return a
         * non-negative COUNT of work done on success rather than a bare 0 —
         * decorator_tags returns the number of nodes tagged and configlink the
         * number of edges created — so a `rc != 0` gate misreads a productive
         * pass (e.g. a Rust repo where 2+ nodes share a derive/decorator word)
         * as CBM_PREDUMP_PASS_FAILED and aborts the whole index before the
         * database dump. Gate on `rc < 0` so only a real negative error code
         * fails the pass while a legitimate success-count is allowed through.
         * Every pass that can return a negative code (similarity, semantic_edges)
         * logs its own structured {code,message,remediation} before returning it,
         * so the gate's "inspect the preceding structured pass error" remediation
         * always has a real error to point at — never a swallowed one. */
        if (rc < 0) {
            cbm_log_error("pipeline.predump.failed", "pass", passes[i].name, "code",
                          "CBM_PREDUMP_PASS_FAILED", "message",
                          "predump pass failed before database dump", "remediation",
                          "inspect the preceding structured pass error and retry after fixing the "
                          "reported cause");
            return rc;
        }
    }
    return check_cancel(p) ? CBM_NOT_FOUND : 0;
}

/* Adapter that lets cbm_pipeline_pass_lsp_cross slot into the seq_passes
 * dispatch table. The cross-file LSP needs the per-file CBMFileResult cache
 * to read defs/imports without re-extracting; in the sequential path that
 * cache is ctx->result_cache (set up by run_sequential_pipeline before
 * launching the dispatch loop). When the cache is unavailable (e.g. if the
 * pipeline opted out of caching), the pass becomes a no-op since there are
 * no extracted results to feed cross-file resolution. */
static int seq_pass_lsp_cross_dispatch(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                                       int file_count) {
    if (!ctx || !ctx->result_cache)
        return 0;
    /* Cross-file LSP runs in every mode. */
    return cbm_pipeline_pass_lsp_cross(ctx, files, file_count, ctx->result_cache);
}

/* Run the sequential pipeline path: definitions, k8s, lsp_cross, calls, usages, semantic. */
static int run_sequential_pipeline(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx,
                                   const cbm_file_info_t *files, int file_count,
                                   struct timespec *t) {
    cbm_log_info("pipeline.mode", "mode", "sequential", "files", itoa_buf(file_count));

    /* Build package map from manifest files (sequential: read manifests directly).
     * Use the repo-walking variant so manifests filtered out by the main
     * discoverer (package.json, composer.json) still feed pkgmap and let
     * workspace imports like `@my/pkg` resolve to their target Module. */
    CBMHashTable *pkgmap = NULL;
    if (cbm_pkgmap_build_from_files_checked(ctx->all_files, ctx->all_file_count, ctx->project_name,
                                            &pkgmap) != 0) {
        return CBM_NOT_FOUND;
    }
    cbm_pipeline_set_pkgmap(pkgmap);

    CBMFileResult **seq_cache = (CBMFileResult **)calloc(file_count, sizeof(CBMFileResult *));
    if (seq_cache) {
        ctx->result_cache = seq_cache;
    }
    typedef int (*seq_pass_fn)(cbm_pipeline_ctx_t *, const cbm_file_info_t *, int);
    static const struct {
        seq_pass_fn fn;
        const char *name;
        bool ignore_err;
    } seq_passes[] = {
        {cbm_pipeline_pass_definitions, "definitions", false},
        {cbm_pipeline_pass_k8s, "k8s", true},
        {seq_pass_lsp_cross_dispatch, "lsp_cross", true},
        {cbm_pipeline_pass_calls, "calls", false},
        {cbm_pipeline_pass_usages, "usages", false},
        {cbm_pipeline_pass_semantic, "semantic", false},
    };
    int rc = 0;
    for (int si = 0; si < PL_SEQ_PASSES && rc == 0; si++) {
        cbm_clock_gettime(CLOCK_MONOTONIC, t);
        int pr = seq_passes[si].fn(ctx, files, file_count);
        if (pr != 0 && !seq_passes[si].ignore_err) {
            rc = pr;
        }
        cbm_log_info("pass.timing", "pass", seq_passes[si].name, "elapsed_ms",
                     itoa_buf((int)elapsed_ms(*t)));
        if (check_cancel(p)) {
            rc = CBM_NOT_FOUND;
        }
    }
    /* Consume infra bindings (YAML/HCL topic/queue/scheduler → endpoint) so
     * INFRA_MAPS edges also form on the sequential path, not just the parallel
     * one. process_one_infra_binding self-creates the topic Route node when no
     * code-side dispatch created it (e.g. a standalone scheduler manifest). */
    if (seq_cache && rc == 0) {
        rc = cbm_pipeline_extract_infra_routes(p->gbuf, files, seq_cache, file_count);
        if (rc == 0) {
            cbm_pipeline_process_infra_bindings(p->gbuf, files, seq_cache, file_count);
        }
    }
    if (seq_cache) {
        for (int i = 0; i < file_count; i++) {
            if (seq_cache[i]) {
                cbm_free_result(seq_cache[i]);
            }
        }
        free(seq_cache);
        ctx->result_cache = NULL;
    }
    /* Release the lsp_cross pass's shared registries only now: resolved_calls
     * borrowed registry-owned strings that the calls pass read above. */
    if (ctx->seq_cross_arena_live) {
        cbm_arena_destroy(&ctx->seq_cross_arena);
        ctx->seq_cross_arena_live = false;
    }
    return rc;
}

/* Run the parallel pipeline path: extract, registry, resolve, infra, k8s. */
static int run_parallel_pipeline(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx,
                                 const cbm_file_info_t *files, int file_count, int worker_count,
                                 struct timespec *t) {
    cbm_log_info("pipeline.mode", "mode", "parallel", "workers", itoa_buf(worker_count), "files",
                 itoa_buf(file_count));
    _Atomic int64_t shared_ids;
    atomic_init(&shared_ids, cbm_gbuf_next_id(p->gbuf));
    CBMFileResult **cache = (CBMFileResult **)calloc(file_count, sizeof(CBMFileResult *));
    if (!cache) {
        cbm_log_error("pipeline.err", "phase", "cache_alloc");
        return CBM_NOT_FOUND;
    }
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    int rc = cbm_parallel_extract(ctx, files, file_count, cache, &shared_ids, worker_count);
    cbm_log_info("pass.timing", "pass", "parallel_extract", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(*t)));
    if (rc != 0 || check_cancel(p)) {
        free(cache);
        return rc != 0 ? rc : CBM_NOT_FOUND;
    }
    cbm_gbuf_set_next_id(p->gbuf, atomic_load(&shared_ids));
    /* extract -> registry handoff: return the extract phase's freed-but-retained
     * allocator pages to the OS before registry_build allocates. On a 2x Linux
     * index the extract peak holds ~13 GB of reclaimable pages (peak_mb 20.7 vs
     * live rss_mb 7); not returning them pushed the process over the system
     * memory-pressure threshold and got it SIGKILLed at registry entry. */
    cbm_mem_collect();
    cbm_log_info("mem.collect", "phase", "post_extract", "rss_mb",
                 itoa_buf((int)(cbm_mem_rss() / (1024 * 1024))));
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    rc = cbm_build_registry_from_cache(ctx, files, file_count, cache);
    cbm_log_info("pass.timing", "pass", "registry_build", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(*t)));
    log_phase_mem("registry_build");
    if (rc != 0 || check_cancel(p)) {
        for (int i = 0; i < file_count; i++) {
            if (cache[i]) {
                cbm_free_result(cache[i]);
            }
        }
        free(cache);
        return rc != 0 ? rc : CBM_NOT_FOUND;
    }
    /* Cross-file LSP precondition: build a project-wide CBMLSPDef[]
     * once. The fused resolve_worker invokes cbm_pxc_run_one(_ts) per
     * file using these defs + the file's IMPORTS map, so cross-file
     * type-resolved CALLS land in result->resolved_calls before the
     * CALLS-edge emission. This replaces the old sequential
     * cbm_pipeline_pass_lsp_cross pass which re-read every source from
     * disk and re-parsed every tree on a single thread (~520s on
     * kubernetes). Soft-failure: NULL all_defs / NULL def_modules just
     * mean cross-file LSP no-ops; per-file LSP already ran during
     * extract. */
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    /* Cross-file LSP (type-aware call/usage resolution across files) — the
     * most expensive phase. CBM_DISABLE_LSP_CROSS=1 opts out (it can SIGSEGV
     * on large TS projects — see #340/#344); with cross-LSP off, all_defs
     * stays NULL and the fused resolver simply no-ops cross-file resolution
     * (per-file LSP already ran during extract). */
    char cbm_lsp_cross_env[CBM_SZ_16];
    const bool run_cross_lsp = cbm_safe_getenv("CBM_DISABLE_LSP_CROSS", cbm_lsp_cross_env,
                                               sizeof(cbm_lsp_cross_env), NULL) == NULL;
    if (!run_cross_lsp) {
        cbm_log_info("lsp_cross.skipped", "reason", "CBM_DISABLE_LSP_CROSS env set");
    }
    char **def_modules = NULL;
    int def_count = 0;
    CBMLSPDef *all_defs = NULL;
    if (run_cross_lsp) {
        def_modules = (char **)calloc((size_t)file_count, sizeof(char *));
        all_defs = def_modules
                       ? cbm_pxc_collect_all_defs(cache, files, file_count, ctx->project_name,
                                                  def_modules, &def_count)
                       : NULL;
    }
    /* Build inverted index: module_qn → defs. The fused resolve_worker
     * uses this to filter the global all_defs[] down to just the defs
     * each file actually needs (own_module + imported modules) — the
     * gopls "package summary" pattern. Drops per-file registry build
     * cost from O(all_defs) to O(relevant_defs), typically 50-100×
     * smaller per file. */
    CBMModuleDefIndex *module_def_index =
        all_defs ? cbm_pxc_build_module_def_index(all_defs, def_count) : NULL;
    /* Tier 2 full: pre-build per-language cross-LSP registries.
     * Built ONCE here; shared READ-ONLY across all files of that language
     * during resolve. Per-file work is then: parse + AST walk + O(1) lookups
     * — no registry build, no Phase 1b mutations. Languages added so far:
     * Go, Python. Others (C/C++, TS/JS, PHP, C#) fall back to per-file. */
    CBMArena cross_lsp_arena;
    cbm_arena_init(&cross_lsp_arena);
    CBMCrossLspRegistries cross_registries = {0};
    if (all_defs) {
        cross_registries.go = cbm_go_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        cross_registries.python =
            cbm_py_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        cross_registries.c = cbm_c_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        cross_registries.cs = cbm_cs_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        cross_registries.ts = cbm_ts_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        /* Rust: NOT built here. The shared all_defs registry is built LAZILY on the
         * first NULL-filter rust file (the amplifier files) inside cbm_parallel_resolve
         * — repos whose rust files all filter to subsets never pay the build/RSS. */
    }
    cbm_log_info("pass.timing", "pass", "lsp_cross_prepare", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(*t)));
    log_phase_mem("lsp_cross_prepare");
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    rc = cbm_parallel_resolve(ctx, files, file_count, cache, &shared_ids, worker_count, all_defs,
                              def_count, def_modules, module_def_index, &cross_registries);
    cbm_log_info("pass.timing", "pass", "parallel_resolve", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(*t)));
    log_phase_mem("parallel_resolve");
    cbm_pxc_free_module_def_index(module_def_index);
    cbm_arena_destroy(&cross_lsp_arena); /* releases all per-lang registries */
    free(all_defs);
    if (def_modules) {
        for (int i = 0; i < file_count; i++) {
            free(def_modules[i]);
        }
        free(def_modules);
    }
    cbm_gbuf_set_next_id(p->gbuf, atomic_load(&shared_ids));
    if (rc == 0) {
        rc = cbm_pipeline_extract_infra_routes(p->gbuf, files, cache, file_count);
    }
    if (rc == 0) {
        cbm_pipeline_process_infra_bindings(p->gbuf, files, cache, file_count);
    }
    for (int i = 0; i < file_count; i++) {
        if (cache[i]) {
            cbm_free_result(cache[i]);
        }
    }
    free(cache);
    if (rc != 0) {
        return rc;
    }
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    cbm_pipeline_pass_k8s(ctx, files, file_count);
    cbm_log_info("pass.timing", "pass", "k8s", "elapsed_ms", itoa_buf((int)elapsed_ms(*t)));
    return check_cancel(p) ? CBM_NOT_FOUND : 0;
}

static int prepare_live_store_for_atomic_replacement(const char *db_path) {
    if (!cbm_path_exists(db_path)) {
        return 0;
    }
    cbm_store_t *store = cbm_store_open_path(db_path);
    if (!store || !cbm_store_check_integrity(store)) {
        if (store) {
            cbm_store_close(store);
        }
        cbm_log_error("pipeline.route_failed", "code", "CBM_PIPELINE_REPLACED_STORE_VERIFY_FAILED",
                      "path", db_path, "message",
                      "the live store could not be verified before atomic replacement",
                      "remediation", "preserve and repair or restore the store, then retry");
        return CBM_NOT_FOUND;
    }
    int rc = cbm_store_checkpoint(store);
    if (rc == CBM_STORE_OK) {
        rc = cbm_store_exec(store, "PRAGMA journal_mode=DELETE;");
    }
    cbm_store_close(store);
    if (rc != CBM_STORE_OK) {
        cbm_log_error("pipeline.route_failed", "code",
                      "CBM_PIPELINE_REPLACED_STORE_CHECKPOINT_FAILED", "path", db_path, "message",
                      "the live store could not be checkpointed before atomic replacement",
                      "remediation", "close active readers and retry indexing");
        return CBM_NOT_FOUND;
    }
    return 0;
}

/* Try incremental pipeline or select an atomic full reindex.
 * Returns 0 when incremental completed, PL_ROUTE_FULL when a full rebuild is
 * required, or CBM_NOT_FOUND on a terminal error. */
static int try_incremental_or_delete_db(cbm_pipeline_t *p, cbm_file_info_t *files, int file_count) {
    char *db_path = resolve_db_path(p);
    if (!db_path) {
        return CBM_NOT_FOUND;
    }
    struct stat db_st;
    if (stat(db_path, &db_st) != 0) {
        int stat_error = errno;
        if (stat_error == ENOENT || stat_error == ENOTDIR) {
            free(db_path);
            return PL_ROUTE_FULL;
        }
        cbm_log_error("pipeline.route_failed", "code", "CBM_PIPELINE_STORE_STAT_FAILED", "path",
                      db_path, "message", "the existing store path could not be inspected",
                      "remediation", "restore store access and retry indexing");
        free(db_path);
        return CBM_NOT_FOUND;
    }
    cbm_store_t *check_store = cbm_store_open_path(db_path);
    if (check_store && cbm_store_check_integrity(check_store)) {
        cbm_file_hash_t *hashes = NULL;
        int hash_count = 0;
        int hash_rc = cbm_store_get_file_hashes(check_store, p->project_name, &hashes, &hash_count);
        if (hash_rc != CBM_STORE_OK) {
            cbm_store_close(check_store);
            cbm_log_error("pipeline.route_failed", "code", "CBM_PIPELINE_HASH_ROWS_READ_FAILED",
                          "path", db_path, "message",
                          "the complete incremental identity set could not be read", "remediation",
                          "inspect the structured store error and retry");
            free(db_path);
            return CBM_NOT_FOUND;
        }
        cbm_store_free_file_hashes(hashes, hash_count);
        cbm_store_close(check_store);
        if (hash_count > 0 && file_count <= hash_count + (hash_count / PAIR_LEN)) {
            cbm_log_info("pipeline.route", "path", "incremental", "stored_hashes",
                         itoa_buf(hash_count));
            int rc = cbm_pipeline_run_incremental(p, db_path, files, file_count);
            if (rc == CBM_INCREMENTAL_REBUILD_REQUIRED) {
                cbm_log_info("pipeline.route", "path", "full", "reason",
                             "incremental_content_contract_requires_rebuild");
            } else {
                free(db_path);
                return rc;
            }
        }
        if (hash_count > 0) {
            cbm_log_info("pipeline.route", "path", "mode_change_reindex", "stored_hashes",
                         itoa_buf(hash_count), "discovered", itoa_buf(file_count));
        }
    } else if (check_store) {
        cbm_store_close(check_store);
        cbm_log_error("pipeline.route_failed", "code", "CBM_PIPELINE_STORE_INTEGRITY_FAILED",
                      "path", db_path, "message",
                      "the existing store failed integrity verification", "remediation",
                      "preserve the store and repair or restore it before retrying");
        free(db_path);
        return CBM_NOT_FOUND;
    } else {
        cbm_log_error("pipeline.route_failed", "code", "CBM_PIPELINE_STORE_OPEN_FAILED", "path",
                      db_path, "message", "the existing store could not be opened for routing",
                      "remediation", "inspect the structured store error and retry");
        free(db_path);
        return CBM_NOT_FOUND;
    }
    cbm_log_info("pipeline.route", "path", "reindex", "action", "build_atomic_replacement");
    /* Capture any ADR before the atomic full-reindex replacement. */
    {
        cbm_store_t *adr_store = cbm_store_open_path(db_path);
        if (adr_store) {
            cbm_adr_t existing;
            if (cbm_store_adr_get(adr_store, p->project_name, &existing) == CBM_STORE_OK) {
                if (existing.content) {
                    free(p->saved_adr);
                    p->saved_adr = strdup(existing.content);
                }
                cbm_store_adr_free(&existing);
            }
            cbm_store_close(adr_store);
        }
    }
    if (prepare_live_store_for_atomic_replacement(db_path) != 0) {
        free(db_path);
        return CBM_NOT_FOUND;
    }
    free(db_path);
    return PL_ROUTE_FULL;
}

static int remove_optional_pipeline_file(const char *path, const char *code) {
    if (cbm_unlink(path) == 0 || errno == ENOENT) {
        return 0;
    }
    cbm_log_error("pipeline.persist_failed", "code", code, "path", path, "message",
                  "a stale or sidecar file could not be removed", "remediation",
                  "close processes holding the store and retry indexing");
    return CBM_NOT_FOUND;
}

/* Dump the complete graph to a sibling stage, finalize every mandatory row,
 * then atomically replace the live SQLite source of truth. */
static int dump_and_persist_hashes(cbm_pipeline_t *p, const cbm_file_info_t *files, int file_count,
                                   struct timespec *t) {
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    char *db_path = resolve_db_path(p);
    if (!db_path) {
        cbm_log_error("pipeline.persist_failed", "code", "CBM_PIPELINE_DB_PATH_ALLOC_FAILED",
                      "message", "the destination database path could not be allocated",
                      "remediation", "free memory and retry indexing");
        return CBM_NOT_FOUND;
    }
    char *db_dir = strdup(db_path);
    if (!db_dir) {
        free(db_path);
        return CBM_NOT_FOUND;
    }
    char *last_slash = strrchr(db_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        if (!cbm_mkdir_p(db_dir, CBM_DIR_PERMS)) {
            cbm_log_error("pipeline.persist_failed", "code",
                          "CBM_PIPELINE_DB_DIRECTORY_CREATE_FAILED", "path", db_dir, "message",
                          "the destination database directory could not be created", "remediation",
                          "restore workspace access and retry indexing");
            free(db_dir);
            free(db_path);
            return CBM_NOT_FOUND;
        }
    }
    free(db_dir);
    char *stage = NULL;
    if (cbm_pipeline_unique_stage_path(db_path, "full", &stage) != 0) {
        free(db_path);
        return CBM_NOT_FOUND;
    }
    size_t db_len = strlen(db_path);
    size_t stage_len = strlen(stage);
    if (stage_len > SIZE_MAX - 5) {
        free(stage);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    char *stage_wal = malloc(stage_len + 5);
    char *stage_shm = malloc(stage_len + 5);
    if (!stage_wal || !stage_shm) {
        free(stage_wal);
        free(stage_shm);
        free(stage);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    snprintf(stage_wal, stage_len + 5, "%s-wal", stage);
    snprintf(stage_shm, stage_len + 5, "%s-shm", stage);
    if (cbm_path_exists(stage_wal) || cbm_path_exists(stage_shm)) {
        cbm_log_error("pipeline.persist_failed", "code", "CBM_PIPELINE_STAGE_SIDECAR_COLLISION",
                      "path", stage, "message",
                      "a generated transaction-owned stage sidecar already exists", "remediation",
                      "preserve the colliding files and retry with a new indexing request");
        free(stage);
        free(stage_wal);
        free(stage_shm);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    /* Capture committed counts BEFORE the dump. cbm_gbuf_dump_to_sqlite calls
     * release_gbuf_indexes(), which frees node_by_qn (graph_buffer.c), after
     * which cbm_gbuf_node_count() returns 0. Reading these post-dump left
     * committed_nodes at 0, so the #334 plausibility gate never fired. */
    p->committed_nodes = cbm_gbuf_node_count(p->gbuf);
    p->committed_edges = cbm_gbuf_edge_count(p->gbuf);
    int rc = cbm_gbuf_dump_to_sqlite(p->gbuf, stage);
    if (rc != 0) {
        cbm_log_error("pipeline.persist_failed", "code", "CBM_PIPELINE_STAGE_DUMP_FAILED", "path",
                      stage, "message", "the complete graph could not be dumped to the stage",
                      "remediation", "inspect the preceding graph/store error and retry");
        (void)remove_optional_pipeline_file(stage, "CBM_PIPELINE_FAILED_STAGE_REMOVE_FAILED");
        free(stage);
        free(stage_wal);
        free(stage_shm);
        free(db_path);
        return rc;
    }
    cbm_log_info("pass.timing", "pass", "dump", "elapsed_ms", itoa_buf((int)elapsed_ms(*t)));
    /* Persist-tail spans (phase "persist"): attribute the ~60s that lands here
     * AFTER cbm_gbuf_dump_to_sqlite returns. Active only under CBM_PROFILE. */
    CBM_PROF_START(t_reopen);
    cbm_store_t *hash_store = cbm_store_open_path(stage);
    CBM_PROF_END("persist", "1_reopen", t_reopen);
    int final_rc = 0;
    if (!hash_store) {
        cbm_log_error("pipeline.persist_failed", "code", "CBM_PIPELINE_STAGE_OPEN_FAILED", "path",
                      stage, "message", "the dumped stage could not be reopened", "remediation",
                      "inspect the structured store error and retry");
        final_rc = CBM_NOT_FOUND;
    } else {
        /* Restore the ADR captured before the dump. Surface a failed restore
         * rather than silently dropping the ADR (the original #516 symptom). */
        CBM_PROF_START(t_adr);
        if (p->saved_adr) {
            if (cbm_store_adr_store(hash_store, p->project_name, p->saved_adr) != CBM_STORE_OK) {
                cbm_log_error("pipeline.err", "phase", "adr_restore", "project", p->project_name);
                final_rc = CBM_NOT_FOUND;
            }
        }
        CBM_PROF_END("persist", "3_adr_restore", t_adr);

        /* Batch the per-file hash upserts into ONE transaction. The per-file
         * cbm_store_upsert_file_hash path autocommits, i.e. file_count fsyncs
         * (~89k on the kernel); cbm_store_upsert_file_hash_batch wraps the same
         * cached INSERT ... ON CONFLICT upsert in a single begin/commit. */
        CBM_PROF_START(t_fh);
        cbm_file_hash_t *fhashes = (cbm_file_hash_t *)malloc(
            (size_t)(file_count > 0 ? file_count : 1) * sizeof(cbm_file_hash_t));
        if (!fhashes) {
            cbm_log_error("pipeline.persist_failed", "code",
                          "CBM_PIPELINE_FILE_HASH_ARRAY_ALLOC_FAILED", "message",
                          "the complete digest row set could not be allocated", "remediation",
                          "free memory or reduce repository size, then retry");
            final_rc = CBM_NOT_FOUND;
        } else {
            for (int i = 0; i < file_count; i++) {
                if (strlen(files[i].sha256) != CBM_SHA256_HEX_LEN) {
                    cbm_log_error("pipeline.persist_failed", "code",
                                  "CBM_PIPELINE_CAPTURED_DIGEST_INVALID", "rel_path",
                                  files[i].rel_path, "message",
                                  "a source/config input has no complete captured SHA-256",
                                  "remediation", "inspect source-snapshot diagnostics and retry");
                    final_rc = CBM_NOT_FOUND;
                    break;
                }
                fhashes[i].project = p->project_name;
                fhashes[i].rel_path = files[i].rel_path;
                fhashes[i].sha256 = files[i].sha256;
                fhashes[i].mtime_ns = files[i].mtime_ns;
                fhashes[i].size = files[i].size;
            }
            if (final_rc == 0 &&
                cbm_store_upsert_file_hash_batch(hash_store, fhashes, file_count) != CBM_STORE_OK) {
                cbm_log_error("pipeline.err", "phase", "persist_file_hashes", "project",
                              p->project_name);
                final_rc = CBM_NOT_FOUND;
            }
            for (int i = 0; final_rc == 0 && i < file_count; i++) {
                final_rc = cbm_pipeline_emit_file_hash(p, fhashes[i].project, fhashes[i].rel_path,
                                                       fhashes[i].sha256, fhashes[i].mtime_ns,
                                                       fhashes[i].size);
            }
            free(fhashes);
        }
        CBM_PROF_END_N("persist", "4_file_hashes", t_fh, file_count);

        /* FTS5 backfill: populate nodes_fts with camelCase-split names.
         * Contentless FTS5 requires the special 'delete-all' command instead of
         * DELETE FROM to wipe prior rows (there's no underlying content table).
         * Falls back to plain names if cbm_camel_split is unavailable (which
         * shouldn't happen because we always register it, but we stay defensive). */
        CBM_PROF_START(t_fts);
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
            cbm_log_error("pipeline.persist_failed", "code", "CBM_PIPELINE_FTS_BACKFILL_FAILED",
                          "message", "the complete camel-split search index could not be built",
                          "remediation", "inspect the SQLite extension/store error and retry");
            final_rc = CBM_NOT_FOUND;
        }
        CBM_PROF_END("persist", "5_fts_backfill", t_fts);

        if (final_rc == 0 &&
            (cbm_store_checkpoint(hash_store) != CBM_STORE_OK ||
             cbm_store_exec(hash_store, "PRAGMA journal_mode=DELETE;") != CBM_STORE_OK)) {
            final_rc = CBM_NOT_FOUND;
        }
        if (final_rc == 0 && !cbm_store_check_integrity(hash_store)) {
            final_rc = CBM_NOT_FOUND;
        }
        if (final_rc == 0) {
            final_rc = cbm_pipeline_complete_row_sink(p, (size_t)file_count);
        }
        cbm_store_close(hash_store);
        cbm_log_info("pass.timing", "pass", "persist_hashes", "files", itoa_buf(file_count));
    }
    if (final_rc != 0 || cbm_path_exists(stage_wal) || cbm_path_exists(stage_shm)) {
        if (final_rc == 0) {
            cbm_log_error("pipeline.persist_failed", "code", "CBM_PIPELINE_STAGE_WAL_REMAINS",
                          "path", stage, "message",
                          "the closed replacement still has a WAL or shared-memory sidecar",
                          "remediation", "inspect SQLite checkpoint errors and retry");
        }
        (void)remove_optional_pipeline_file(stage, "CBM_PIPELINE_FAILED_STAGE_REMOVE_FAILED");
        (void)remove_optional_pipeline_file(stage_wal,
                                            "CBM_PIPELINE_FAILED_STAGE_WAL_REMOVE_FAILED");
        (void)remove_optional_pipeline_file(stage_shm,
                                            "CBM_PIPELINE_FAILED_STAGE_SHM_REMOVE_FAILED");
        free(stage);
        free(stage_wal);
        free(stage_shm);
        free(db_path);
        return CBM_NOT_FOUND;
    }

    if (db_len > SIZE_MAX - 5) {
        (void)remove_optional_pipeline_file(stage, "CBM_PIPELINE_FAILED_STAGE_REMOVE_FAILED");
        free(stage);
        free(stage_wal);
        free(stage_shm);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    size_t sidecar_size = db_len + 5;
    char *live_wal = malloc(sidecar_size);
    char *live_shm = malloc(sidecar_size);
    if (!live_wal || !live_shm) {
        free(live_wal);
        free(live_shm);
        (void)remove_optional_pipeline_file(stage, "CBM_PIPELINE_FAILED_STAGE_REMOVE_FAILED");
        free(stage);
        free(stage_wal);
        free(stage_shm);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    snprintf(live_wal, sidecar_size, "%s-wal", db_path);
    snprintf(live_shm, sidecar_size, "%s-shm", db_path);
    if (cbm_path_exists(live_wal) || cbm_path_exists(live_shm)) {
        cbm_log_error("pipeline.persist_failed", "code", "CBM_PIPELINE_LIVE_WAL_PRESENT", "path",
                      db_path, "message",
                      "the verified live store acquired a WAL or shared-memory sidecar before swap",
                      "remediation", "close concurrent readers/writers and retry indexing");
        (void)remove_optional_pipeline_file(stage, "CBM_PIPELINE_FAILED_STAGE_REMOVE_FAILED");
        free(live_wal);
        free(live_shm);
        free(stage);
        free(stage_wal);
        free(stage_shm);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    if (cbm_rename_replace(stage, db_path) != 0) {
        char native_error[32];
        (void)snprintf(native_error, sizeof(native_error), "%lu", cbm_fs_last_error());
        cbm_log_error("pipeline.persist_failed", "code", "CBM_PIPELINE_ATOMIC_SWAP_FAILED", "path",
                      db_path, "native_error_kind", "win32", "native_error", native_error,
                      "message", "the complete staged store could not replace the live store",
                      "remediation", "close readers holding the store and retry");
        (void)remove_optional_pipeline_file(stage, "CBM_PIPELINE_FAILED_STAGE_REMOVE_FAILED");
        free(live_wal);
        free(live_shm);
        free(stage);
        free(stage_wal);
        free(stage_shm);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    free(live_wal);
    free(live_shm);
    free(p->saved_adr);
    p->saved_adr = NULL;

    /* Export persistent artifact if enabled */
    if (p->persistence) {
        CBM_PROF_START(t_art);
        int arc = cbm_artifact_export(db_path, p->repo_path, p->project_name, CBM_ARTIFACT_BEST);
        CBM_PROF_END("persist", "6_artifact_export", t_art);
        if (arc != 0) {
            const char *err = cbm_artifact_export_last_error();
            cbm_log_error("pipeline.err", "phase", "artifact_export", "err", err ? err : "unknown");
            /* A failed persistence export intentionally fails the run; this used to be ignored. */
            free(stage);
            free(stage_wal);
            free(stage_shm);
            free(db_path);
            return arc;
        }
    }

    free(stage);
    free(stage_wal);
    free(stage_shm);
    free(db_path);
    return 0;
}

/* Run githistory pass. */
static int run_githistory(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx) {
    struct timespec t_gh;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t_gh);

    cbm_githistory_result_t gh_result = {0};
    cbm_thread_t gh_thread;
    bool gh_threaded = false;
    gh_compute_arg_t gh_arg = {.repo_path = ctx->repo_path, .result = &gh_result};

    if (p->mode != CBM_MODE_FAST) {
        if (effective_worker_count(true) > SKIP_ONE) {
            if (cbm_thread_create(&gh_thread, 0, gh_compute_thread_fn, &gh_arg) == 0) {
                gh_threaded = true;
            }
        }
        if (!gh_threaded) {
            cbm_pipeline_githistory_compute(ctx->repo_path, &gh_result);
            cbm_log_info("pass.timing", "pass", "githistory_compute", "elapsed_ms",
                         itoa_buf((int)elapsed_ms(t_gh)));
        }
    } else {
        cbm_log_info("pass.skip", "pass", "githistory", "reason", "fast_mode");
    }

    if (gh_threaded) {
        cbm_thread_join(&gh_thread);
        cbm_log_info("pass.timing", "pass", "githistory_compute", "elapsed_ms",
                     itoa_buf((int)elapsed_ms(t_gh)));
    }

    int gh_edges = 0;
    if (gh_result.count > 0 || gh_result.file_temporal_count > 0) {
        gh_edges = cbm_pipeline_githistory_apply(ctx, &gh_result);
    }
    cbm_log_info("pass.done", "pass", "githistory", "commits", itoa_buf(gh_result.commit_count),
                 "edges", itoa_buf(gh_edges));
    free(gh_result.couplings);
    free(gh_result.file_temporal);
    return 0;
}

/* ── Pipeline run ────────────────────────────────────────────────── */

/* Run tests + git history. Returns 0 on success. */
static int run_tests_and_history(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx,
                                 const cbm_file_info_t *files, int file_count) {
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    CBM_PROF_START(t_tests);
    int rc = cbm_pipeline_pass_tests(ctx, files, file_count);
    CBM_PROF_END_N("pipeline", "pass_tests", t_tests, file_count);
    cbm_log_info("pass.timing", "pass", "tests", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    if (rc == 0 && !check_cancel(p)) {
        CBM_PROF_START(t_gh);
        rc = run_githistory(p, ctx);
        CBM_PROF_END("pipeline", "pass_githistory", t_gh);
    }
    if (check_cancel(p)) {
        return CBM_NOT_FOUND;
    }
    return rc;
}

/* Run tests, git history, predump passes, and dump+persist. */
static int run_post_extraction(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx,
                               const cbm_file_info_t *source_files, int source_count,
                               const cbm_file_info_t *all_files, int all_count) {
    int rc = run_tests_and_history(p, ctx, source_files, source_count);
    if (rc != 0) {
        return rc;
    }

    CBM_PROF_START(t_predump);
    rc = run_predump_passes(p, ctx);
    CBM_PROF_END("pipeline", "3_predump_passes_total", t_predump);
    if (rc != 0) {
        return rc;
    }

    if (!check_cancel(p)) {
        struct timespec t;
        CBM_PROF_START(t_dump);
        rc = dump_and_persist_hashes(p, all_files, all_count, &t);
        CBM_PROF_END("pipeline", "4_dump_and_persist", t_dump);
    }
    return rc;
}

#define MIN_FILES_FOR_PARALLEL 50

/* Run structure + extraction passes (parallel or sequential). */
static int run_extraction_phase(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx,
                                const cbm_file_info_t *files, int file_count) {
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    CBM_PROF_START(t_struct);
    if (pass_structure(p, files, file_count) != 0) {
        return CBM_NOT_FOUND;
    }
    CBM_PROF_END_N("pipeline", "pass_structure", t_struct, file_count);
    cbm_log_info("pass.timing", "pass", "structure", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    if (check_cancel(p)) {
        return CBM_NOT_FOUND;
    }

    int worker_count = effective_worker_count(true);
    CBM_PROF_START(t_extract_total);
    int rc = (worker_count > SKIP_ONE && file_count > MIN_FILES_FOR_PARALLEL)
                 ? run_parallel_pipeline(p, ctx, files, file_count, worker_count, &t)
                 : run_sequential_pipeline(p, ctx, files, file_count, &t);
    CBM_PROF_END_N("pipeline", "2_extraction_total", t_extract_total, file_count);
    if (check_cancel(p)) {
        return CBM_NOT_FOUND;
    }
    return rc;
}

int cbm_pipeline_run(cbm_pipeline_t *p) {
    if (!p) {
        return CBM_NOT_FOUND;
    }
    p->row_sink_completed = false;

    CBM_PROF_START(t_pipeline_total);
    struct timespec t0;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t0);
    cbm_path_alias_collection_t *path_aliases = NULL;
    cbm_source_snapshot_t source_snapshot = {0};
    cbm_file_info_t *source_files = NULL;
    int source_count = 0;

    /* C/C++ #define Macro nodes (#375) dominate extraction on macro-dense repos
     * (≈49% of nodes on the Linux kernel), so gate them to full mode — moderate
     * and fast skip them entirely. Set before any extraction dispatch. */
    cbm_set_macro_extraction(p->mode == CBM_MODE_FULL);

    /* Load user-defined extension overrides before discovery. Present invalid
     * configuration is terminal; absence yields an empty explicit config. */
    CBM_PROF_START(t_userconfig);
    if (cbm_userconfig_load_checked(p->repo_path, &p->userconfig) != 0) {
        cbm_log_error("pipeline.err", "phase", "userconfig_load", "code",
                      "CBM_PIPELINE_USERCONFIG_LOAD_FAILED");
        return CBM_NOT_FOUND;
    }
    cbm_set_user_lang_config(p->userconfig);
    CBM_PROF_END("pipeline", "0_userconfig_load", t_userconfig);

    /* Phase 1: Discover files */
    CBM_PROF_START(t_discover);
    cbm_discover_opts_t opts = {
        .mode = p->mode,
        .ignore_file = NULL,
        .max_file_size = 0,
    };
    cbm_file_info_t *files = NULL;
    int file_count = 0;
    /* Capture skipped subtrees on the pipeline so the MCP layer can report
     * which directories were excluded (#411). Replace any prior list (e.g. a
     * re-run on the same pipeline) to avoid leaking the previous one. */
    cbm_discover_free_excluded(p->excluded_dirs, p->excluded_count);
    p->excluded_dirs = NULL;
    p->excluded_count = 0;
    int rc = cbm_discover_ex(p->repo_path, &opts, &files, &file_count, &p->excluded_dirs,
                             &p->excluded_count);
    if (rc != 0) {
        cbm_log_error("pipeline.err", "phase", "discover", "rc", itoa_buf(rc));
    }
    CBM_PROF_END_N("pipeline", "1_discover", t_discover, file_count);
    cbm_log_info("pipeline.discover", "files", itoa_buf(file_count), "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t0)));
    if (rc != 0 || check_cancel(p)) {
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }

    CBM_PROF_START(t_snapshot);
    if (cbm_source_snapshot_capture(p->repo_path, &opts, files, file_count, &source_snapshot) !=
        0) {
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }
    p->source_root = source_snapshot.root;
    cbm_userconfig_t *captured_userconfig = NULL;
    if (cbm_userconfig_load_checked(p->source_root, &captured_userconfig) != 0 ||
        !cbm_userconfig_equal(p->userconfig, captured_userconfig)) {
        cbm_log_error("pipeline.err", "code", "CBM_PIPELINE_USERCONFIG_CAPTURE_DRIFT", "phase",
                      "source_snapshot", "message",
                      "extension classification changed between discovery and immutable capture",
                      "remediation", "stabilize global/project configuration and retry indexing");
        cbm_userconfig_free(captured_userconfig);
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }
    cbm_userconfig_free(p->userconfig);
    p->userconfig = captured_userconfig;
    cbm_set_user_lang_config(p->userconfig);
    for (int i = 0; i < file_count; i++) {
        if (!files[i].auxiliary) {
            source_count++;
        }
    }
    if (source_count == 0) {
        cbm_log_error("pipeline.err", "phase", "source_snapshot", "code",
                      "CBM_PIPELINE_EMPTY_SOURCE_CORPUS", "repo_path", p->repo_path,
                      "discovered_files", itoa_buf(file_count), "message",
                      "repository discovery produced no non-auxiliary source files; refusing a "
                      "structural-only index",
                      "remediation",
                      "add a supported readable source file or correct discovery, mode, and ignore "
                      "configuration before retrying");
        rc = CBM_PIPELINE_EMPTY_SOURCE_CORPUS;
        goto cleanup;
    }
    source_files = malloc((size_t)source_count * sizeof(*source_files));
    if (!source_files) {
        cbm_log_error("pipeline.err", "code", "CBM_PIPELINE_SOURCE_VIEW_ALLOC_FAILED", "phase",
                      "source_snapshot", "message",
                      "the complete source-only snapshot view could not be allocated",
                      "remediation", "free memory or reduce repository size, then retry");
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }
    int source_index = 0;
    for (int i = 0; i < file_count; i++) {
        if (!files[i].auxiliary) {
            source_files[source_index++] = files[i];
        }
    }
    CBM_PROF_END_N("pipeline", "1b_source_snapshot", t_snapshot, file_count);

    /* Check for existing DB → try incremental or delete for reindex */
    rc = try_incremental_or_delete_db(p, files, file_count);
    if (rc == 0 || rc == CBM_NOT_FOUND) {
        goto cleanup;
    }
    if (rc != PL_ROUTE_FULL) {
        cbm_log_error("pipeline.err", "code", "CBM_PIPELINE_ROUTE_STATUS_INVALID", "phase", "route",
                      "message", "the index router returned an unknown status", "remediation",
                      "inspect the router implementation before retrying");
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }
    rc = 0;
    cbm_log_info("pipeline.route", "path", "full");

    /* Phase 2: Create graph buffer and registry */
    p->gbuf = cbm_gbuf_new(p->project_name, p->repo_path);
    cbm_pipeline_attach_row_sink(p, p->gbuf);
    p->registry = cbm_registry_new();

    /* Phase 2b: Load build-tool path aliases (tsconfig/jsconfig today). NULL
     * when no usable configs are found — non-TS projects pay nothing. */
    if (cbm_load_path_aliases_from_files(files, file_count, &path_aliases) != 0) {
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }

    /* Build shared context for pass functions */
    cbm_pipeline_ctx_t ctx = {
        .project_name = p->project_name,
        .repo_path = p->repo_path,
        .source_root = p->source_root,
        .all_files = files,
        .all_file_count = file_count,
        .gbuf = p->gbuf,
        .registry = p->registry,
        .cancelled = &p->cancelled,
        .pipeline = p, /* so passes can record per-file skips (Track B) */
        .mode = (int)p->mode,
        .path_aliases = path_aliases,
        .excluded_dirs = p->excluded_dirs,
        .excluded_count = p->excluded_count,
    };

    rc = run_extraction_phase(p, &ctx, source_files, source_count);
    if (rc != 0) {
        goto cleanup;
    }

    rc = run_post_extraction(p, &ctx, source_files, source_count, files, file_count);
    if (rc != 0) {
        goto cleanup;
    }

    cbm_log_info("pipeline.done", "nodes", itoa_buf(cbm_gbuf_node_count(p->gbuf)), "edges",
                 itoa_buf(cbm_gbuf_edge_count(p->gbuf)), "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t0)));
    CBM_PROF_END("pipeline", "TOTAL", t_pipeline_total);

cleanup:
    cbm_pkgmap_free(cbm_pipeline_get_pkgmap());
    cbm_pipeline_set_pkgmap(NULL);
    free(source_files);
    cbm_gbuf_free(p->gbuf);
    p->gbuf = NULL;
    cbm_registry_free(p->registry);
    p->registry = NULL;
    cbm_path_alias_collection_free(path_aliases);
    /* Clear and free user extension config */
    cbm_set_user_lang_config(NULL);
    cbm_userconfig_free(p->userconfig);
    p->userconfig = NULL;
    p->source_root = NULL;
    if (cbm_source_snapshot_destroy(&source_snapshot) != 0) {
        rc = CBM_NOT_FOUND;
    }
    cbm_discover_free(files, file_count);
    return rc;
}
