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

enum {
    CBM_DIR_PERMS = 0755,
    PL_RING = 16,
    PL_RING_MASK = 15,
    PL_WAL_BUF = 1040,
    PL_ERROR_CODE = 128,
    PL_ERROR_OPERATION = 160,
    PL_ERROR_PHASE = 64,
    /* Windows permits a 32,767-code-unit path. Four UTF-8 bytes per code
     * unit plus NUL retains the exact relative path without allocating on the
     * failure path. */
    PL_ERROR_PATH = 131072,
    PL_ERROR_MESSAGE = 512,
    PL_ERROR_REMEDIATION = 512,
    /* Structured detail pairs carried with the fatal record (#1004/#943). A key is
     * a diagnostic field name; a value holds an atom id (64 hex), a relative
     * path, or a local identifier. Fixed storage keeps the reporting path
     * available even when allocation itself is the failure. */
    PL_ERROR_DETAIL_KEY = 64,
    PL_ERROR_DETAIL_VALUE = 512,
    PL_PARALLEL_DISPATCH_CAPACITY = 64
};
#include "pipeline/pipeline.h"
#include "pipeline/artifact.h"
#include "pipeline/pipeline_internal.h"
#include "pipeline/pass_lsp_cross.h"
#include "pipeline/source_snapshot.h"
#include "pipeline/structured_data.h"
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
#include "foundation/log_internal.h"
#include "foundation/str_util.h"
#include "foundation/hash_table.h"
#include "foundation/compat.h"
#include "foundation/compat_thread.h"
#include "foundation/profile.h"
#include "foundation/mem.h"
#include "foundation/sha256.h"
#include "foundation/worker_progress.h"
#include "foundation/schema_version.h"
#include "foundation/slab_alloc.h"
#include "helpers.h"

#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include <windows.h>

enum {
    PL_ROUTE_FULL = CBM_INCREMENTAL_REBUILD_REQUIRED,
    /* Representation ceiling derived from the finite pipeline topology
     * (currently <=30 records, including an incremental-to-full reroute). It is
     * not a measured tuning threshold; overflow is a structured telemetry
     * failure rather than truncation. */
    PL_PHASE_METRIC_CAPACITY = 32,
};

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
    if (written <= 0 || (size_t)written >= capacity) {
        cbm_log_error("pipeline.stage_identity_failed", "code",
                      "CBM_PIPELINE_STAGE_PATH_REPRESENTATION_FAILED", "path", path, "message",
                      "the generated staging identity could not be represented exactly",
                      "remediation", "shorten the configured store path and retry indexing");
        free(path);
        return CBM_NOT_FOUND;
    }
    unsigned long probe_error = 0;
    cbm_path_probe_result_t probe = cbm_path_probe(path, &probe_error);
    if (probe == CBM_PATH_PROBE_ERROR) {
        char native_error[32];
        (void)snprintf(native_error, sizeof(native_error), "%lu", probe_error);
        cbm_log_error("pipeline.stage_identity_failed", "code",
                      "CBM_PIPELINE_STAGE_IDENTITY_PROBE_FAILED", "path", path,
                      "native_error_kind", "win32", "native_error", native_error, "message",
                      "the generated staging identity could not be classified", "remediation",
                      "resolve the reported path probe failure and retry indexing");
        free(path);
        return CBM_NOT_FOUND;
    }
    if (probe == CBM_PATH_PROBE_PRESENT) {
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
    cbm_pipeline_row_sink_v2_t row_sink;
    bool row_sink_active;
    bool row_sink_completed;
    cbm_pipeline_post_success_fn post_success;
    void *post_success_ctx;
    uint8_t *embedded_compilation_context;
    size_t embedded_compilation_context_bytes;
    cbm_compile_context_index_t *compile_contexts;
    const cbm_source_slab_t *current_source_slab;
    const char *compile_context_authority;
    int compile_context_c_family_files;
    int compile_context_bound_files;
    int compile_context_configuration_absent_files;
    int compile_context_empty_files;
    char **compile_context_configuration_absent_paths;

    /* Indexing state (set during run) */
    cbm_gbuf_t *gbuf;
    cbm_registry_t *registry;

    /* Directory subtrees skipped during discovery (rel paths). Captured from
     * cbm_discover_ex so the MCP layer can report excluded subtrees (#411).
     * Owned by the pipeline; freed in cbm_pipeline_free. */
    char **excluded_dirs;
    int excluded_count;

    /* Per-file indexing failures surfaced through the terminal structured
     * response (Stage 2 / Track B). Any entry blocks publication. Owned by the
     * pipeline; freed in cbm_pipeline_free. */
    cbm_file_error_t *file_errors;
    int file_errors_count;
    int file_errors_cap;

    /* Exact first fatal diagnostic. Fixed storage guarantees the reporting
     * path remains available even when allocation itself is the failure.
     *
     * Parallel resolve workers can fail concurrently, so `claimed` elects
     * exactly one writer and `present` publishes the record only once every
     * field is filled. A reader that sees `present` therefore sees a complete,
     * untorn diagnostic (#1004). */
    atomic_bool fatal_error_claimed;
    atomic_bool fatal_error_present;
    char fatal_error_code[PL_ERROR_CODE];
    char fatal_error_operation[PL_ERROR_OPERATION];
    char fatal_error_phase[PL_ERROR_PHASE];
    char fatal_error_path[PL_ERROR_PATH];
    char fatal_error_message[PL_ERROR_MESSAGE];
    char fatal_error_remediation[PL_ERROR_REMEDIATION];
    size_t fatal_error_requested;
    /* The emitting site's own structured keys, copied verbatim so the public
     * failure response can name the exact cause (#1004/#943). `detail_key_ptrs` /
     * `detail_val_ptrs` alias the fixed storage and are what the reader
     * borrows; they are filled before `present` is published. */
    char fatal_error_detail_keys[CBM_PIPELINE_ERROR_DETAIL_MAX][PL_ERROR_DETAIL_KEY];
    char fatal_error_detail_vals[CBM_PIPELINE_ERROR_DETAIL_MAX][PL_ERROR_DETAIL_VALUE];
    const char *fatal_error_detail_key_ptrs[CBM_PIPELINE_ERROR_DETAIL_MAX];
    const char *fatal_error_detail_val_ptrs[CBM_PIPELINE_ERROR_DETAIL_MAX];
    size_t fatal_error_detail_count;

    /* Exact live-store identity frozen during routing. A full rebuild may only
     * publish over the same bytes; another process replacing or mutating the
     * source while the stage is built is a terminal provenance conflict. */
    bool routed_store_present;
    uint64_t routed_store_bytes;
    char routed_store_sha256[CBM_SHA256_HEX_LEN + 1];

    /* User-defined extension overrides (loaded once per run) */
    cbm_userconfig_t *userconfig;

    /* Committed graph size at dump time (-1 = dump did not run). #334 gate axis. */
    int committed_nodes;
    int committed_edges;

    /* Reference edges skipped because their source syntax resolved to several
     * stable atoms in one semantic domain (#727). Captured from the graph
     * buffer before it is freed so the tool result can disclose the loss. */
    uint_least64_t ambiguous_reference_skips;

    /* Reference edges skipped because an extracted non-empty enclosing
     * callable QN had no exact stable source atom. Kept separate from semantic
     * ambiguity so the success response identifies the actual degradation. */
    uint_least64_t unresolved_reference_source_skips;

    /* Rust `mod` declarations that named NO existing source at either
     * compiler-defined path (#1024). A zero-candidate declaration is a dangling
     * reference, not an ambiguity: there is nothing to guess and no wrong edge
     * to invent, so the IMPORTS edge is skipped and counted instead of refusing
     * the whole corpus. Incremented directly by the resolving pass — which runs
     * in extraction workers against per-worker graph buffers — so the counter
     * lives on the pipeline (shared by every worker context) rather than on a
     * buffer that would need merge-time summing. */
    _Atomic uint_least64_t dangling_rust_module_skips;

    /* Recoverable tree-sitter parse diagnostics persisted as ParseDiagnostic
     * graph rows. A clean run reports zero; a recovered parse reports the
     * exact number of diagnostic rows collected from real source trees. */
    uint_least64_t parse_recovery_diagnostics;

    /* Retained successful-run phase telemetry. Fixed storage makes telemetry
     * collection allocation-free after pipeline creation and prevents clean
     * worker-log retention from accumulating on disk. */
    cbm_pipeline_phase_metric_t phase_metrics[PL_PHASE_METRIC_CAPACITY];
    size_t phase_metric_count;
    bool phase_metrics_complete;

    /* Retained worker-dispatch admission diagnostics. Clean CLI runs suppress
     * info-level logs, so successful responses carry this source of truth. */
    cbm_pipeline_parallel_dispatch_t parallel_dispatches[PL_PARALLEL_DISPATCH_CAPACITY];
    size_t parallel_dispatch_count;
    bool parallel_dispatches_complete;
    cbm_pipeline_execution_route_t execution_route;
    cbm_pipeline_parallel_dispatch_expectation_t parallel_dispatch_expectation;

    /* ADR (project_summaries) captured before a full-reindex DB delete, so it
     * can be restored after the rebuild. NULL when no ADR existed. Issue #516. */
    char *saved_adr;
};

static void clear_compile_context_diagnostics(cbm_pipeline_t *p) {
    if (!p) {
        return;
    }
    for (int i = 0; i < p->compile_context_configuration_absent_files; i++) {
        free(p->compile_context_configuration_absent_paths[i]);
    }
    free(p->compile_context_configuration_absent_paths);
    p->compile_context_configuration_absent_paths = NULL;
    p->compile_context_authority = "not_applicable";
    p->compile_context_c_family_files = 0;
    p->compile_context_bound_files = 0;
    p->compile_context_configuration_absent_files = 0;
    p->compile_context_empty_files = 0;
}

static int compare_owned_paths(const void *left, const void *right) {
    const char *const *a = (const char *const *)left;
    const char *const *b = (const char *const *)right;
    return strcmp(*a, *b);
}

static int capture_compile_context_diagnostics(cbm_pipeline_t *p,
                                               const cbm_file_info_t *files,
                                               int file_count) {
    clear_compile_context_diagnostics(p);
    if (!p || file_count < 0 || (file_count > 0 && !files)) {
        cbm_pipeline_record_fatal_error(
            p, "CBM_COMPILE_CONTEXT_DIAGNOSTIC_INPUT_INVALID",
            "capture_compile_context_diagnostics", "compile_context", "", 0,
            "compile-context coverage received invalid discovered-file metadata",
            "preserve the generation and repair the pipeline context-state handoff");
        return CBM_NOT_FOUND;
    }
    int c_family_files = 0;
    for (int i = 0; i < file_count; i++) {
        CBMLanguage language = files[i].language;
        if (language == CBM_LANG_C || language == CBM_LANG_CPP || language == CBM_LANG_CUDA) {
            c_family_files++;
        }
    }
    char **absent_paths = c_family_files > 0
                              ? calloc((size_t)c_family_files, sizeof(*absent_paths))
                              : NULL;
    if (c_family_files > 0 && !absent_paths) {
        cbm_pipeline_record_fatal_error(
            p, "CBM_COMPILE_CONTEXT_DIAGNOSTIC_ALLOC_FAILED",
            "allocate_configuration_absent_paths", "compile_context", "",
            (size_t)c_family_files * sizeof(*absent_paths),
            "the exact configuration-absence path inventory could not be allocated",
            "free memory and retry the unchanged corpus");
        return CBM_NOT_FOUND;
    }

    int bound_files = 0;
    int absent_files = 0;
    int empty_files = 0;
    for (int i = 0; i < file_count; i++) {
        size_t context_count = 0;
        cbm_compile_context_file_state_t state = cbm_compile_context_file_state(
            p->compile_contexts, files[i].rel_path, files[i].language, files[i].size,
            &context_count);
        switch (state) {
        case CBM_COMPILE_CONTEXT_NOT_APPLICABLE:
            break;
        case CBM_COMPILE_CONTEXT_EMPTY_SOURCE:
            empty_files++;
            break;
        case CBM_COMPILE_CONTEXT_CONFIGURATION_ABSENT:
            absent_paths[absent_files] = strdup(files[i].rel_path);
            if (!absent_paths[absent_files]) {
                for (int j = 0; j < absent_files; j++) {
                    free(absent_paths[j]);
                }
                free(absent_paths);
                cbm_pipeline_record_fatal_error(
                    p, "CBM_COMPILE_CONTEXT_DIAGNOSTIC_ALLOC_FAILED",
                    "copy_configuration_absent_path", "compile_context", files[i].rel_path,
                    strlen(files[i].rel_path) + 1,
                    "a configuration-absent source path could not be retained",
                    "free memory and retry the unchanged corpus");
                return CBM_NOT_FOUND;
            }
            absent_files++;
            break;
        case CBM_COMPILE_CONTEXT_BOUND:
            if (context_count == 0) {
                state = CBM_COMPILE_CONTEXT_STATE_INVALID;
            } else {
                bound_files++;
                break;
            }
            /* fall through */
        case CBM_COMPILE_CONTEXT_STATE_INVALID:
        default:
            for (int j = 0; j < absent_files; j++) {
                free(absent_paths[j]);
            }
            free(absent_paths);
            cbm_pipeline_record_fatal_error(
                p, "CBM_COMPILE_CONTEXT_FILE_STATE_INVALID",
                "capture_compile_context_diagnostics", "compile_context",
                files[i].rel_path ? files[i].rel_path : "", context_count,
                "a discovered C-family source has no valid explicit context state",
                "preserve the generation and rebuild its complete context index");
            return CBM_NOT_FOUND;
        }
    }
    if (absent_files > 1) {
        qsort(absent_paths, (size_t)absent_files, sizeof(*absent_paths), compare_owned_paths);
    }
    p->compile_context_authority =
        cbm_compile_context_authority(p->compile_contexts, c_family_files);
    p->compile_context_c_family_files = c_family_files;
    p->compile_context_bound_files = bound_files;
    p->compile_context_configuration_absent_files = absent_files;
    p->compile_context_empty_files = empty_files;
    p->compile_context_configuration_absent_paths = absent_paths;
    return 0;
}

static bool file_property_context_id_is_canonical(const char *context_id) {
    if (!context_id || strlen(context_id) != CBM_SHA256_HEX_LEN) {
        return false;
    }
    for (const unsigned char *at = (const unsigned char *)context_id; *at; at++) {
        if (!isxdigit(*at)) {
            return false;
        }
    }
    return true;
}

size_t cbm_pipeline_file_properties_capacity(cbm_pipeline_t *pipeline,
                                             const cbm_file_info_t *file) {
    if (!pipeline || !file || !file->rel_path) {
        return 0;
    }
    const char *slash = strrchr(file->rel_path, '/');
    const char *basename = slash ? slash + SKIP_ONE : file->rel_path;
    const char *extension = strrchr(basename, '.');
    extension = extension ? extension : "";
    size_t extension_len = strlen(extension);
    if (extension_len > (SIZE_MAX - CBM_SZ_512) / 6) {
        cbm_pipeline_record_fatal_error(
            pipeline, "CBM_FILE_PROPERTIES_EXTENSION_OVERFLOW", "escape_file_extension",
            "structure", file->rel_path, extension_len,
            "a file extension exceeds the bounded JSON representation",
            "rename the malformed path or extend the file-property representation");
        return 0;
    }
    size_t capacity = CBM_SZ_512 + extension_len * 6;
    cbm_compile_context_language_metadata_t metadata;
    if (cbm_compile_context_language_metadata(pipeline->compile_contexts, file->rel_path,
                                              &metadata) &&
        metadata.owners) {
        for (size_t i = 0; i < metadata.owners->count; i++) {
            const char *context_id = metadata.owners->items[i].context_id;
            if (!file_property_context_id_is_canonical(context_id)) {
                cbm_pipeline_record_fatal_error(
                    pipeline, "CBM_COMPILE_CONTEXT_ID_INVALID", "size_file_properties",
                    "structure", file->rel_path, i,
                    "a File atom owner has a malformed compilation-context identity",
                    "preserve the manifest and regenerate its exact context identities");
                return 0;
            }
            size_t id_len = strlen(context_id);
            if (capacity > SIZE_MAX - id_len - 4) {
                cbm_pipeline_record_fatal_error(
                    pipeline, "CBM_FILE_PROPERTIES_CAPACITY_OVERFLOW",
                    "size_file_properties", "structure", file->rel_path, i,
                    "File atom owner metadata exceeds addressable representation",
                    "reduce contradictory build variants or extend the representation");
                return 0;
            }
            capacity += id_len + 4;
        }
    }
    return capacity;
}

int cbm_pipeline_format_file_properties(cbm_pipeline_t *pipeline,
                                        const cbm_file_info_t *file, char *out,
                                        size_t out_capacity) {
    if (!pipeline || !file || !file->rel_path || !out || out_capacity == 0) {
        return CBM_NOT_FOUND;
    }
    const char *slash = strrchr(file->rel_path, '/');
    const char *basename = slash ? slash + SKIP_ONE : file->rel_path;
    const char *extension = strrchr(basename, '.');
    extension = extension ? extension : "";
    size_t extension_len = strlen(extension);
    if (extension_len > (SIZE_MAX - 1) / 6 || extension_len * 6 + 1 > INT_MAX) {
        cbm_pipeline_record_fatal_error(
            pipeline, "CBM_FILE_PROPERTIES_EXTENSION_OVERFLOW", "escape_file_extension",
            "structure", file->rel_path, extension_len,
            "a file extension exceeds the bounded JSON representation",
            "rename the malformed path or extend the file-property representation");
        return CBM_NOT_FOUND;
    }
    size_t escaped_capacity = extension_len * 6 + 1;
    char *escaped_extension = malloc(escaped_capacity);
    if (!escaped_extension) {
        cbm_pipeline_record_fatal_error(
            pipeline, "CBM_FILE_PROPERTIES_ALLOC_FAILED", "escape_file_extension",
            "structure", file->rel_path, escaped_capacity,
            "the exact file extension could not be escaped",
            "free memory and retry the unchanged corpus");
        return CBM_NOT_FOUND;
    }
    cbm_json_escape(escaped_extension, (int)escaped_capacity, extension);

    size_t context_count = 0;
    cbm_compile_context_file_state_t state = cbm_compile_context_file_state(
        pipeline->compile_contexts, file->rel_path, file->language, file->size,
        &context_count);
    cbm_compile_context_language_metadata_t metadata;
    bool has_metadata = cbm_compile_context_language_metadata(
        pipeline->compile_contexts, file->rel_path, &metadata);
    bool include_language_metadata =
        has_metadata && (metadata.ambiguous_fragment || state == CBM_COMPILE_CONTEXT_BOUND);
    int written = 0;
    switch (state) {
    case CBM_COMPILE_CONTEXT_NOT_APPLICABLE:
        written = snprintf(out, out_capacity, "{\"extension\":\"%s\"", escaped_extension);
        break;
    case CBM_COMPILE_CONTEXT_EMPTY_SOURCE:
        written = snprintf(
            out, out_capacity,
            "{\"extension\":\"%s\",\"compile_context_state\":\"empty\","
            "\"compile_context_reason\":\"empty_source\",\"compile_context_count\":0",
            escaped_extension);
        break;
    case CBM_COMPILE_CONTEXT_CONFIGURATION_ABSENT:
        written = snprintf(
            out, out_capacity,
            "{\"extension\":\"%s\",\"compile_context_state\":\"configuration_absent\","
            "\"compile_context_code\":\"CBM_COMPILE_CONTEXT_CONFIGURATION_ABSENT\","
            "\"compile_context_reason\":\"%s\",\"compile_context_count\":0",
            escaped_extension, cbm_compile_context_absence_reason(pipeline->compile_contexts));
        break;
    case CBM_COMPILE_CONTEXT_BOUND:
        written = snprintf(out, out_capacity,
                           "{\"extension\":\"%s\",\"compile_context_state\":\"bound\","
                           "\"compile_context_count\":%zu",
                           escaped_extension, context_count);
        break;
    case CBM_COMPILE_CONTEXT_STATE_INVALID:
    default:
        cbm_pipeline_record_fatal_error(
            pipeline, "CBM_COMPILE_CONTEXT_FILE_STATE_INVALID", "format_file_properties",
            "structure", file->rel_path, context_count,
            "a File atom has no valid explicit compilation-context state",
            "preserve the generation and rebuild its complete context index");
        free(escaped_extension);
        return CBM_NOT_FOUND;
    }
    if (written <= 0 || (size_t)written >= out_capacity) {
        cbm_pipeline_record_fatal_error(
            pipeline, "CBM_FILE_PROPERTIES_CAPACITY_EXCEEDED", "format_file_properties",
            "structure", file->rel_path, written > 0 ? (size_t)written : 0,
            "the complete File atom properties exceed their bounded representation",
            "extend the File property representation and retry the unchanged corpus");
        free(escaped_extension);
        return CBM_NOT_FOUND;
    }
    size_t used = (size_t)written;
    if (include_language_metadata) {
        const char *declared = cbm_language_name(metadata.declared_language);
        const char *effective = cbm_language_name(file->language);
        written = snprintf(
            out + used, out_capacity - used,
            ",\"declared_language\":\"%s\",\"effective_language\":\"%s\","
            "\"effective_language_family\":\"%s\",\"language_provenance\":\"%s\","
            "\"compiler_language_applied\":%s,\"compile_context_ids\":[",
            declared, effective, metadata.effective_family, metadata.provenance,
            metadata.compiler_language_applied ? "true" : "false");
        if (written <= 0 || (size_t)written >= out_capacity - used) {
            free(escaped_extension);
            return CBM_NOT_FOUND;
        }
        used += (size_t)written;
        for (size_t i = 0; i < metadata.owners->count; i++) {
            const char *context_id = metadata.owners->items[i].context_id;
            if (!file_property_context_id_is_canonical(context_id)) {
                free(escaped_extension);
                return CBM_NOT_FOUND;
            }
            written = snprintf(out + used, out_capacity - used, "%s\"%s\"",
                               i == 0 ? "" : ",", context_id);
            if (written <= 0 || (size_t)written >= out_capacity - used) {
                free(escaped_extension);
                return CBM_NOT_FOUND;
            }
            used += (size_t)written;
        }
        written = snprintf(out + used, out_capacity - used, "]}");
    } else {
        written = snprintf(out + used, out_capacity - used, "}");
    }
    free(escaped_extension);
    if (written <= 0 || (size_t)written >= out_capacity - used) {
        cbm_pipeline_record_fatal_error(
            pipeline, "CBM_FILE_PROPERTIES_CAPACITY_EXCEEDED", "finish_file_properties",
            "structure", file->rel_path, used,
            "the complete File atom properties exceed their measured representation",
            "preserve the context inventory and extend its representation");
        return CBM_NOT_FOUND;
    }
    return 0;
}

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

static const char *u64_buf(uint64_t val) {
    static CBM_TLS char bufs[PL_RING][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + SKIP_ONE) & PL_RING_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%llu", (unsigned long long)val);
    return bufs[i];
}

static bool cbm_pipeline_phase_trace_enabled(void) {
    const char *raw = getenv("ASTRO_CBM_PIPELINE_PHASE_TRACE");
    return raw && (strcmp(raw, "1") == 0 || strcmp(raw, "true") == 0 ||
                   strcmp(raw, "TRUE") == 0);
}

static void cbm_pipeline_phase_trace_event(const char *event, const char *phase,
                                           const cbm_pipeline_t *p,
                                           const PROCESS_MEMORY_COUNTERS_EX *memory,
                                           bool memory_valid) {
    if (!cbm_pipeline_phase_trace_enabled()) {
        return;
    }
    int nodes = (p && p->gbuf) ? cbm_gbuf_node_count(p->gbuf) : -1;
    int edges = (p && p->gbuf) ? cbm_gbuf_edge_count(p->gbuf) : -1;
    uint64_t working_set_bytes = 0;
    uint64_t private_bytes = 0;
    uint64_t peak_working_set_bytes = 0;
    uint64_t peak_private_bytes = 0;
    if (memory && memory_valid) {
        working_set_bytes = (uint64_t)memory->WorkingSetSize;
        private_bytes = (uint64_t)memory->PrivateUsage;
        peak_working_set_bytes = (uint64_t)memory->PeakWorkingSetSize;
        peak_private_bytes = (uint64_t)memory->PeakPagefileUsage;
    }
    cbm_log_pipeline_phase_trace(
        event, phase, (uint64_t)GetCurrentProcessId(), p ? (int)p->mode : -1,
        p && p->row_sink_active, p && p->row_sink_completed, nodes, edges, memory_valid,
        working_set_bytes, private_bytes, peak_working_set_bytes, peak_private_bytes);
}

cbm_pipeline_phase_probe_t cbm_pipeline_phase_probe_start(cbm_pipeline_t *p, const char *phase) {
    cbm_pipeline_phase_probe_t probe = {0};
    cbm_clock_gettime(CLOCK_MONOTONIC, &probe.started);
    probe.io_valid = GetProcessIoCounters(GetCurrentProcess(), &probe.io) != 0;
    if (!probe.io_valid) {
        if (p) {
            p->phase_metrics_complete = false;
        }
        char native_error[CBM_SZ_32];
        snprintf(native_error, sizeof(native_error), "%lu", (unsigned long)GetLastError());
        cbm_log_error("pipeline.telemetry_failed", "code", "CBM_PIPELINE_IO_COUNTER_READ_FAILED",
                      "phase", phase, "native_error_kind", "win32", "native_error", native_error,
                      "message", "the indexing worker I/O baseline could not be read",
                      "remediation", "resolve the reported process-accounting failure and retry");
    }
    probe.memory.cb = sizeof(probe.memory);
    probe.memory_valid =
        GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&probe.memory,
                             sizeof(probe.memory)) != 0;
    if (!probe.memory_valid) {
        if (p) {
            p->phase_metrics_complete = false;
        }
        char native_error[CBM_SZ_32];
        snprintf(native_error, sizeof(native_error), "%lu", (unsigned long)GetLastError());
        cbm_log_error("pipeline.telemetry_failed", "code",
                      "CBM_PIPELINE_MEMORY_COUNTER_READ_FAILED", "phase", phase,
                      "native_error_kind", "win32", "native_error", native_error, "message",
                      "the indexing worker memory baseline could not be read", "remediation",
                      "resolve the reported process-accounting failure and retry");
    }
    cbm_pipeline_phase_trace_event("start", phase, p, &probe.memory, probe.memory_valid);
    return probe;
}

void cbm_pipeline_phase_probe_end(cbm_pipeline_t *p, const char *phase,
                                  const cbm_pipeline_phase_probe_t *probe) {
    IO_COUNTERS current = {0};
    PROCESS_MEMORY_COUNTERS_EX current_memory = {0};
    current_memory.cb = sizeof(current_memory);
    bool current_io_valid =
        probe && probe->io_valid && GetProcessIoCounters(GetCurrentProcess(), &current) != 0;
    DWORD current_io_error = current_io_valid ? ERROR_SUCCESS : GetLastError();
    bool current_memory_valid =
        probe && probe->memory_valid &&
        GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&current_memory,
                             sizeof(current_memory)) != 0;
    DWORD current_memory_error = current_memory_valid ? ERROR_SUCCESS : GetLastError();
    cbm_pipeline_phase_trace_event("end", phase, p, &current_memory, current_memory_valid);
    if (!current_io_valid || !current_memory_valid) {
        if (p) {
            p->phase_metrics_complete = false;
        }
        if (probe && probe->io_valid && !current_io_valid) {
            char native_error[CBM_SZ_32];
            snprintf(native_error, sizeof(native_error), "%lu", (unsigned long)current_io_error);
            cbm_log_error("pipeline.telemetry_failed", "code",
                          "CBM_PIPELINE_IO_COUNTER_READ_FAILED", "phase", phase,
                          "native_error_kind", "win32", "native_error", native_error, "message",
                          "the indexing worker I/O terminal state could not be read", "remediation",
                          "resolve the reported process-accounting failure and retry");
        }
        if (probe && probe->memory_valid && !current_memory_valid) {
            char native_error[CBM_SZ_32];
            snprintf(native_error, sizeof(native_error), "%lu",
                     (unsigned long)current_memory_error);
            cbm_log_error(
                "pipeline.telemetry_failed", "code", "CBM_PIPELINE_MEMORY_COUNTER_READ_FAILED",
                "phase", phase, "native_error_kind", "win32", "native_error", native_error,
                "message", "the indexing worker memory terminal state could not be read",
                "remediation", "resolve the reported process-accounting failure and retry");
        }
        return;
    }
    uint64_t phase_elapsed_ms = (uint64_t)elapsed_ms(probe->started);
    uint64_t phase_read_bytes = (uint64_t)(current.ReadTransferCount - probe->io.ReadTransferCount);
    uint64_t phase_write_bytes =
        (uint64_t)(current.WriteTransferCount - probe->io.WriteTransferCount);
    uint64_t phase_other_bytes =
        (uint64_t)(current.OtherTransferCount - probe->io.OtherTransferCount);
    if (!p || p->phase_metric_count >= PL_PHASE_METRIC_CAPACITY) {
        if (p) {
            p->phase_metrics_complete = false;
        }
        cbm_log_error(
            "pipeline.telemetry_failed", "code", "CBM_PIPELINE_PHASE_METRIC_CAPACITY_EXCEEDED",
            "phase", phase, "message",
            "the finite pipeline phase topology exceeded its retained result representation",
            "remediation",
            "update the phase-metric representation together with the added pipeline phase");
        return;
    }
    cbm_pipeline_phase_metric_t *metric = &p->phase_metrics[p->phase_metric_count++];
    metric->phase = phase;
    metric->elapsed_ms = phase_elapsed_ms;
    metric->read_bytes = phase_read_bytes;
    metric->write_bytes = phase_write_bytes;
    metric->other_bytes = phase_other_bytes;
    metric->start_working_set_bytes = (uint64_t)probe->memory.WorkingSetSize;
    metric->end_working_set_bytes = (uint64_t)current_memory.WorkingSetSize;
    metric->start_peak_working_set_bytes = (uint64_t)probe->memory.PeakWorkingSetSize;
    metric->end_peak_working_set_bytes = (uint64_t)current_memory.PeakWorkingSetSize;
    metric->start_private_bytes = (uint64_t)probe->memory.PrivateUsage;
    metric->end_private_bytes = (uint64_t)current_memory.PrivateUsage;
    metric->start_peak_private_bytes = (uint64_t)probe->memory.PeakPagefileUsage;
    metric->end_peak_private_bytes = (uint64_t)current_memory.PeakPagefileUsage;
    cbm_log_info("pipeline.phase", "phase", phase, "elapsed_ms", u64_buf(phase_elapsed_ms),
                 "read_bytes", u64_buf(phase_read_bytes), "write_bytes", u64_buf(phase_write_bytes),
                 "other_bytes", u64_buf(phase_other_bytes), "start_working_set_bytes",
                 u64_buf(metric->start_working_set_bytes), "end_working_set_bytes",
                 u64_buf(metric->end_working_set_bytes), "start_peak_working_set_bytes",
                 u64_buf(metric->start_peak_working_set_bytes), "end_peak_working_set_bytes",
                 u64_buf(metric->end_peak_working_set_bytes), "start_private_bytes",
                 u64_buf(metric->start_private_bytes), "end_private_bytes",
                 u64_buf(metric->end_private_bytes), "start_peak_private_bytes",
                 u64_buf(metric->start_peak_private_bytes), "end_peak_private_bytes",
                 u64_buf(metric->end_peak_private_bytes));
}

static void copy_parallel_dispatch_field(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0) {
        return;
    }
    (void)snprintf(dst, dst_size, "%s", src ? src : "");
}

void cbm_pipeline_record_parallel_dispatch(cbm_pipeline_t *p, const char *operation,
                                           const char *mode, const char *code, int item_count,
                                           int requested_workers, int admitted_workers,
                                           int created_workers, int failed_worker_index,
                                           int error_domain, unsigned long error_code) {
    if (!p) {
        return;
    }
    if (p->parallel_dispatch_count >= PL_PARALLEL_DISPATCH_CAPACITY) {
        p->parallel_dispatches_complete = false;
        cbm_log_error(
            "pipeline.parallel_dispatch_telemetry_failed", "code",
            "CBM_PIPELINE_PARALLEL_DISPATCH_CAPACITY_EXCEEDED", "operation",
            operation ? operation : "parallel", "message",
            "the finite parallel-dispatch topology exceeded its retained result representation",
            "remediation",
            "update the parallel-dispatch representation together with the added dispatch site");
        return;
    }
    cbm_pipeline_parallel_dispatch_t *dispatch =
        &p->parallel_dispatches[p->parallel_dispatch_count++];
    copy_parallel_dispatch_field(dispatch->operation, sizeof(dispatch->operation),
                                 operation ? operation : "parallel");
    copy_parallel_dispatch_field(dispatch->mode, sizeof(dispatch->mode),
                                 mode ? mode : "unknown");
    copy_parallel_dispatch_field(dispatch->code, sizeof(dispatch->code), code ? code : "");
    dispatch->item_count = item_count;
    dispatch->requested_workers = requested_workers;
    dispatch->admitted_workers = admitted_workers;
    dispatch->created_workers = created_workers;
    dispatch->failed_worker_index = failed_worker_index;
    dispatch->error_domain = error_domain;
    dispatch->error_code = error_code;
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

    char *canonical_repo_path = cbm_real_path_final(repo_path);
    if (!canonical_repo_path || !cbm_is_dir(canonical_repo_path)) {
        cbm_log_error("pipeline.create_failed", "code", "CBM_PIPELINE_ROOT_UNRESOLVABLE",
                      "operation", "cbm_real_path_final", "path", repo_path, "message",
                      "the repository root could not be bound to one final filesystem path",
                      "remediation", "pass an existing readable repository directory and retry");
        free(canonical_repo_path);
        return NULL;
    }

    cbm_pipeline_t *p = calloc(CBM_ALLOC_ONE, sizeof(cbm_pipeline_t));
    if (!p) {
        free(canonical_repo_path);
        return NULL;
    }

    p->repo_path = canonical_repo_path;
    p->db_path = db_path ? strdup(db_path) : NULL;
    p->project_name = cbm_project_name_from_path(p->repo_path);
    (void)cbm_git_context_resolve(p->repo_path, &p->git_ctx);
    p->branch_qn = p->project_name ? cbm_git_context_branch_qn(p->project_name, &p->git_ctx) : NULL;
    if ((db_path && !p->db_path) || !p->project_name || !p->branch_qn) {
        cbm_log_error("pipeline.create_failed", "code", "CBM_PIPELINE_IDENTITY_ALLOC_FAILED",
                      "operation", "derive_project_identity", "path", p->repo_path, "message",
                      "the canonical pipeline identity could not be allocated", "remediation",
                      "free memory and retry the unchanged repository request");
        cbm_pipeline_free(p);
        return NULL;
    }
    p->mode = mode;
    p->persistence = false;
    p->committed_nodes = -1;
    p->committed_edges = -1;
    p->ambiguous_reference_skips = 0;
    p->unresolved_reference_source_skips = 0;
    p->parse_recovery_diagnostics = 0;
    p->phase_metrics_complete = true;
    p->parallel_dispatches_complete = true;
    p->compile_context_authority = "not_applicable";
    atomic_init(&p->dangling_rust_module_skips, 0);
    atomic_init(&p->cancelled, 0);

    return p;
}

void cbm_pipeline_set_persistence(cbm_pipeline_t *p, bool enabled) {
    if (p) {
        p->persistence = enabled;
    }
}

int cbm_pipeline_set_embedded_compilation_context(cbm_pipeline_t *p, const uint8_t *bytes,
                                                  size_t byte_count) {
    if (!p || !bytes || byte_count == 0) {
        cbm_log_error("pipeline.compile_context_refused", "code",
                      "CBM_COMPILE_CONTEXT_EMBEDDED_INVALID", "message",
                      "embedded compilation context requires non-empty artifact-owned bytes",
                      "remediation",
                      "bind the exact astrolabe.compilation-context.v1 artifact before running "
                      "the pipeline");
        return CBM_NOT_FOUND;
    }
    uint8_t *owned_bytes = malloc(byte_count);
    if (!owned_bytes) {
        char requested_bytes[32];
        snprintf(requested_bytes, sizeof(requested_bytes), "%zu", byte_count);
        cbm_log_error("pipeline.compile_context_refused", "code",
                      "CBM_COMPILE_CONTEXT_TRANSPORT_ALLOC_FAILED", "message",
                      "the pipeline could not retain the immutable compilation context",
                      "requested_bytes", requested_bytes, "remediation",
                      "free memory and retry the unchanged repository and context");
        return CBM_NOT_FOUND;
    }
    memcpy(owned_bytes, bytes, byte_count);
    free(p->embedded_compilation_context);
    p->embedded_compilation_context = owned_bytes;
    p->embedded_compilation_context_bytes = byte_count;
    return 0;
}

int cbm_pipeline_set_sink(cbm_pipeline_t *p, const cbm_pipeline_row_sink_v2_t *sink) {
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
    if (sink->abi_version != CBM_PIPELINE_ROW_SINK_ABI_V2 ||
        sink->struct_size != sizeof(cbm_pipeline_row_sink_v2_t)) {
        cbm_log_error("pipeline.row_sink_refused", "code", "CBM_PIPELINE_ROW_SINK_ABI_UNSUPPORTED",
                      "message", "the row-sink ABI version or descriptor size is unsupported",
                      "remediation",
                      "construct the exact frozen cbm_pipeline_row_sink_v2_t descriptor");
        return CBM_NOT_FOUND;
    }
    if (!sink->node || !sink->edge || !sink->file_hash || !sink->complete || !sink->ctx) {
        cbm_log_error(
            "pipeline.row_sink_refused", "code", "CBM_PIPELINE_ROW_SINK_INCOMPLETE", "message",
            "a complete snapshot sink requires node, edge, file-hash, completion, and "
            "context fields",
            "remediation", "install every v2 callback together or pass NULL to disable the sink");
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

int cbm_pipeline_set_post_success_callback(cbm_pipeline_t *p,
                                           cbm_pipeline_post_success_fn callback, void *ctx) {
    if (!p) {
        cbm_log_error(
            "pipeline.post_success_refused", "code", "CBM_PIPELINE_POST_SUCCESS_PIPELINE_NULL",
            "message", "a post-success callback cannot be installed on a NULL pipeline",
            "remediation", "create the pipeline successfully before installing a callback");
        return CBM_NOT_FOUND;
    }
    if (!callback) {
        p->post_success = NULL;
        p->post_success_ctx = NULL;
        return 0;
    }
    if (!ctx) {
        cbm_log_error("pipeline.post_success_refused", "code",
                      "CBM_PIPELINE_POST_SUCCESS_CONTEXT_NULL", "message",
                      "a post-success callback requires a non-NULL context", "remediation",
                      "bind the callback to the exact row-sink state that owns the snapshot");
        return CBM_NOT_FOUND;
    }
    p->post_success = callback;
    p->post_success_ctx = ctx;
    return 0;
}

bool cbm_pipeline_set_project_identity_root(cbm_pipeline_t *p, const char *identity_root) {
    if (!p || !identity_root || !identity_root[0]) {
        return false;
    }

    char *canonical_root = cbm_real_path_final(identity_root);
    if (!canonical_root || !cbm_is_dir(canonical_root)) {
        free(canonical_root);
        return false;
    }
    char *derived = cbm_project_name_from_path(canonical_root);
    free(canonical_root);
    if (!derived || !cbm_validate_project_name(derived)) {
        free(derived);
        return false;
    }

    char *branch_qn = cbm_git_context_branch_qn(derived, &p->git_ctx);
    if (!branch_qn) {
        free(derived);
        return false;
    }
    free(p->project_name);
    p->project_name = derived;
    free(p->branch_qn);
    p->branch_qn = branch_qn;
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
    clear_compile_context_diagnostics(p);
    free(p->branch_qn);
    free(p->embedded_compilation_context);
    p->embedded_compilation_context = NULL;
    p->embedded_compilation_context_bytes = 0;
    cbm_compile_context_index_free(p->compile_contexts);
    p->compile_contexts = NULL;
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

cbm_compile_context_index_t *cbm_pipeline_compile_contexts(const cbm_pipeline_t *p) {
    return p ? p->compile_contexts : NULL;
}

const cbm_source_slab_t *cbm_pipeline_current_source_slab(const cbm_pipeline_t *p) {
    return p ? p->current_source_slab : NULL;
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
            /* The extraction barrier independently rejects every missing
             * non-empty result, even if this diagnostic inventory cannot grow. */
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

void cbm_pipeline_get_phase_metrics(const cbm_pipeline_t *p,
                                    const cbm_pipeline_phase_metric_t **out, size_t *count,
                                    bool *complete) {
    if (out) {
        *out = p ? p->phase_metrics : NULL;
    }
    if (count) {
        *count = p ? p->phase_metric_count : 0;
    }
    if (complete) {
        *complete = p && p->phase_metrics_complete;
    }
}

void cbm_pipeline_get_parallel_dispatches(const cbm_pipeline_t *p,
                                          const cbm_pipeline_parallel_dispatch_t **out,
                                          size_t *count, bool *complete) {
    if (out) {
        *out = p ? p->parallel_dispatches : NULL;
    }
    if (count) {
        *count = p ? p->parallel_dispatch_count : 0;
    }
    if (complete) {
        *complete = p && p->parallel_dispatches_complete;
    }
}

cbm_pipeline_execution_route_t cbm_pipeline_get_execution_route(const cbm_pipeline_t *p) {
    return p ? p->execution_route : CBM_PIPELINE_EXECUTION_ROUTE_UNKNOWN;
}

cbm_pipeline_parallel_dispatch_expectation_t cbm_pipeline_get_parallel_dispatch_expectation(
    const cbm_pipeline_t *p) {
    return p ? p->parallel_dispatch_expectation
             : CBM_PIPELINE_PARALLEL_DISPATCH_EXPECTATION_UNKNOWN;
}

int cbm_pipeline_set_execution_contract(
    cbm_pipeline_t *p, cbm_pipeline_execution_route_t route,
    cbm_pipeline_parallel_dispatch_expectation_t dispatch_expectation) {
    bool unset =
        p && p->execution_route == CBM_PIPELINE_EXECUTION_ROUTE_UNKNOWN &&
        p->parallel_dispatch_expectation == CBM_PIPELINE_PARALLEL_DISPATCH_EXPECTATION_UNKNOWN;
    if (!p || !cbm_pipeline_execution_contract_valid(route, dispatch_expectation) || !unset) {
        cbm_pipeline_record_fatal_error(p, "CBM_PIPELINE_EXECUTION_CONTRACT_INVALID",
                                        "set_execution_contract", "execution_contract",
                                        p ? p->repo_path : "", 0,
                                        "the pipeline selected an invalid, contradictory, or "
                                        "duplicate successful execution contract",
                                        "preserve the source family and repair the exact "
                                        "route-selection branch before retrying");
        return CBM_NOT_FOUND;
    }
    p->execution_route = route;
    p->parallel_dispatch_expectation = dispatch_expectation;
    return 0;
}

void cbm_pipeline_get_compile_context_diagnostics(const cbm_pipeline_t *p,
                                                  cbm_compile_context_diagnostics_t *out) {
    if (!out) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->authority =
        p && p->compile_context_authority ? p->compile_context_authority : "not_applicable";
    if (!p) {
        return;
    }
    out->c_family_files = p->compile_context_c_family_files;
    out->bound_files = p->compile_context_bound_files;
    out->configuration_absent_files = p->compile_context_configuration_absent_files;
    out->empty_files = p->compile_context_empty_files;
    out->configuration_absent_paths =
        (const char *const *)p->compile_context_configuration_absent_paths;
}

bool cbm_pipeline_get_fatal_error(const cbm_pipeline_t *p, cbm_pipeline_error_t *out) {
    if (out) {
        memset(out, 0, sizeof(*out));
    }
    if (!p || !out || !atomic_load_explicit(&p->fatal_error_present, memory_order_acquire)) {
        return false;
    }
    out->code = p->fatal_error_code;
    out->operation = p->fatal_error_operation;
    out->phase = p->fatal_error_phase;
    out->path = p->fatal_error_path;
    out->message = p->fatal_error_message;
    out->remediation = p->fatal_error_remediation;
    out->requested = p->fatal_error_requested;
    out->detail_keys = p->fatal_error_detail_count ? p->fatal_error_detail_key_ptrs : NULL;
    out->detail_vals = p->fatal_error_detail_count ? p->fatal_error_detail_val_ptrs : NULL;
    out->detail_count = p->fatal_error_detail_count;
    return true;
}

void cbm_pipeline_record_fatal_error(cbm_pipeline_t *p, const char *code, const char *operation,
                                     const char *phase, const char *path, size_t requested,
                                     const char *message, const char *remediation) {
    cbm_pipeline_record_fatal_error_detail(p, code, operation, phase, path, requested, message,
                                           remediation, NULL, NULL, 0);
}

/* Record the terminal diagnostic together with the emitting site's own
 * structured keys (#1004/#943). Callers whose diagnostic identity lives in extra
 * fields -- the exact file, the contended local name, the colliding atom ids --
 * pass them here so the public failure response carries the cause instead of
 * directing the caller to a worker log it cannot read. */
void cbm_pipeline_record_fatal_error_detail(cbm_pipeline_t *p, const char *code,
                                            const char *operation, const char *phase,
                                            const char *path, size_t requested,
                                            const char *message, const char *remediation,
                                            const char *const *detail_keys,
                                            const char *const *detail_vals, size_t detail_count) {
    if (!p || atomic_exchange_explicit(&p->fatal_error_claimed, true, memory_order_acq_rel)) {
        /* Another thread already owns the terminal diagnostic; first one wins. */
        return;
    }
    (void)snprintf(p->fatal_error_code, sizeof(p->fatal_error_code), "%s",
                   code ? code : "CBM_PIPELINE_FAILED");
    (void)snprintf(p->fatal_error_operation, sizeof(p->fatal_error_operation), "%s",
                   operation ? operation : "pipeline");
    (void)snprintf(p->fatal_error_phase, sizeof(p->fatal_error_phase), "%s",
                   phase ? phase : "pipeline");
    (void)snprintf(p->fatal_error_path, sizeof(p->fatal_error_path), "%s", path ? path : "");
    (void)snprintf(p->fatal_error_message, sizeof(p->fatal_error_message), "%s",
                   message ? message : "the authoritative ingestion pipeline failed");
    (void)snprintf(p->fatal_error_remediation, sizeof(p->fatal_error_remediation), "%s",
                   remediation ? remediation
                               : "inspect the exact code and operation, fix the cause, then retry");
    p->fatal_error_requested = requested;

    p->fatal_error_detail_count = 0;
    if (detail_keys && detail_vals) {
        for (size_t i = 0; i < detail_count && p->fatal_error_detail_count <
                                                    (size_t)CBM_PIPELINE_ERROR_DETAIL_MAX;
             i++) {
            if (!detail_keys[i] || !detail_keys[i][0] || !detail_vals[i]) {
                continue;
            }
            size_t slot = p->fatal_error_detail_count;
            (void)snprintf(p->fatal_error_detail_keys[slot], PL_ERROR_DETAIL_KEY, "%s",
                           detail_keys[i]);
            (void)snprintf(p->fatal_error_detail_vals[slot], PL_ERROR_DETAIL_VALUE, "%s",
                           detail_vals[i]);
            p->fatal_error_detail_key_ptrs[slot] = p->fatal_error_detail_keys[slot];
            p->fatal_error_detail_val_ptrs[slot] = p->fatal_error_detail_vals[slot];
            p->fatal_error_detail_count = slot + 1;
        }
    }
    /* Publish last: every field above is now filled. */
    atomic_store_explicit(&p->fatal_error_present, true, memory_order_release);

    char requested_text[32];
    (void)snprintf(requested_text, sizeof(requested_text), "%zu", requested);
    cbm_log_error("pipeline.fatal_error", "code", p->fatal_error_code, "operation",
                  p->fatal_error_operation, "phase", p->fatal_error_phase, "path",
                  p->fatal_error_path, "requested", requested_text, "message",
                  p->fatal_error_message, "remediation", p->fatal_error_remediation);
}

/* Publish a graph-buffer refusal as the run's terminal diagnostic (#1022).
 *
 * A refusal inside the graph buffer poisons persistence, but the buffer is a
 * layer below the pipeline and could only log; the run then aborted with no
 * fatal record at all, so the MCP response carried `diagnostic.captured=false`
 * and pointed the operator at a worker log they cannot read. This runs at the
 * single choke point every failing run passes through, so no refusal site can
 * abort silently. record_fatal_error_detail is first-writer-wins: a more
 * specific diagnostic recorded earlier still wins. */
void cbm_pipeline_record_gbuf_refusal(cbm_pipeline_t *p, const cbm_gbuf_t *gb, const char *phase,
                                      const char *path) {
    if (!p || !gb || !cbm_gbuf_resolution_failed(gb)) {
        return;
    }
    cbm_gbuf_refusal_t refusal;
    bool have = cbm_gbuf_get_refusal(gb, &refusal);

    const char *keys[CBM_PIPELINE_ERROR_DETAIL_MAX];
    const char *vals[CBM_PIPELINE_ERROR_DETAIL_MAX];
    char line_buf[CBM_SZ_32];
    char count_buf[CBM_SZ_32];
    char atom_key_buf[CBM_GBUF_REFUSAL_CANDIDATE_MAX][CBM_SZ_32];
    size_t n = 0;

    /* A refusal site that names its own component owns that label: a
     * pkgmap-originated refusal is not a graph_buffer defect and must not
     * report itself as one (#1024). Only when the site supplied no component
     * does the recording layer name itself. */
    bool site_component = false;
    for (int i = 0; have && i < refusal.detail_count; i++) {
        if (refusal.detail_keys[i] && strcmp(refusal.detail_keys[i], "component") == 0) {
            site_component = true;
        }
    }
    if (!site_component) {
        keys[n] = "component";
        vals[n++] = "graph_buffer";
    }
    if (have && refusal.operation) {
        keys[n] = "graph_operation";
        vals[n++] = refusal.operation;
    }
    if (have && refusal.qualified_name) {
        keys[n] = "qualified_name";
        vals[n++] = refusal.qualified_name;
    }
    if (have && refusal.file_path) {
        keys[n] = "file_path";
        vals[n++] = refusal.file_path;
    }
    if (have && refusal.line > 0) {
        (void)snprintf(line_buf, sizeof(line_buf), "%d", refusal.line);
        keys[n] = "line";
        vals[n++] = line_buf;
    }
    if (have && refusal.candidate_count > 0) {
        (void)snprintf(count_buf, sizeof(count_buf), "%d", refusal.candidate_count);
        keys[n] = "candidate_count";
        vals[n++] = count_buf;
    }
    for (int i = 0; have && i < refusal.candidate_atom_id_count &&
                    n + SKIP_ONE < (size_t)CBM_PIPELINE_ERROR_DETAIL_MAX;
         i++) {
        (void)snprintf(atom_key_buf[i], sizeof(atom_key_buf[i]), "candidate_atom_id_%d",
                       i + SKIP_ONE);
        keys[n] = atom_key_buf[i];
        vals[n++] = refusal.candidate_atom_ids[i];
    }
    /* The refusing site's own detail pairs — the paths, module names, and
     * candidate identities it had already computed (#1024). Without these the
     * public diagnostic carried code + operation and nothing else, and the
     * evidence stayed in a worker log. */
    for (int i = 0; have && i < refusal.detail_count && n < (size_t)CBM_PIPELINE_ERROR_DETAIL_MAX;
         i++) {
        if (!refusal.detail_keys[i] || !refusal.detail_keys[i][0] || !refusal.detail_vals[i]) {
            continue;
        }
        keys[n] = refusal.detail_keys[i];
        vals[n++] = refusal.detail_vals[i];
    }

    cbm_pipeline_record_fatal_error_detail(
        p, have ? refusal.code : "CBM_GRAPH_RESOLUTION_FAILED",
        have && refusal.operation ? refusal.operation : "graph_buffer.resolution",
        phase ? phase : "graph", path ? path : "",
        0, /* requested */
        have && refusal.message
            ? refusal.message
            : "the authoritative graph buffer refused a canonical identity or reference "
              "resolution; no store or row-sink mutation was committed",
        "resolve the reported atoms by exact identity — the detail pairs name the operation, the "
        "contended qualified name, its file and line, and every candidate atom",
        keys, vals, n);
}

static const char *cbm_pipeline_code_from_legacy_reason(const char *reason) {
    if (!reason || reason[0] != '[') {
        return NULL;
    }
    static _Thread_local char code[PL_ERROR_CODE];
    const char *end = strchr(reason + 1, ']');
    if (!end) {
        return NULL;
    }
    size_t len = (size_t)(end - (reason + 1));
    if (len == 0 || len >= sizeof(code)) {
        return NULL;
    }
    memcpy(code, reason + 1, len);
    code[len] = '\0';
    return code;
}

int cbm_pipeline_reject_file_failures(cbm_pipeline_t *p, const cbm_file_info_t *files,
                                      int file_count, CBMFileResult *const *results,
                                      const char *phase) {
    if (!p || !files || file_count < 0) {
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_EXTRACTION_BARRIER_INVALID", "reject_file_failures",
            phase ? phase : "extract", "", (size_t)(file_count < 0 ? 0 : file_count),
            "the extraction barrier received invalid result metadata",
            "repair the pipeline result-cache contract before retrying");
        return CBM_NOT_FOUND;
    }
    if (file_count > 0 && !results) {
        cbm_pipeline_record_fatal_error(
            p, "CBM_EXTRACTION_CACHE_ALLOC_FAILED", "allocate_result_cache",
            phase ? phase : "extract", "", (size_t)file_count * sizeof(*results),
            "the authoritative per-file result cache could not be allocated",
            "free memory or reduce concurrent repository workload, then retry the complete corpus");
        return CBM_NOT_FOUND;
    }

    /* Results and read failures are evaluated together in deterministic
     * discovery order, never worker-finish or failure-kind order. */
    for (int i = 0; i < file_count; i++) {
        const char *rel_path = files[i].rel_path;
        if (!rel_path || !rel_path[0] || files[i].size < 0) {
            cbm_pipeline_record_fatal_error(
                p, "CBM_EXTRACTION_FILE_METADATA_INVALID", "validate_discovered_source",
                phase ? phase : "extract", rel_path ? rel_path : "", 0,
                "a discovered source file has invalid path or size metadata",
                "repair source capture/discovery metadata before retrying the corpus");
            return CBM_NOT_FOUND;
        }
        const CBMFileResult *result = results[i];
        if (result && result->has_error) {
            const CBMExtractionError *error = &result->error;
            cbm_pipeline_record_fatal_error(
                p,
                error->code ? error->code : cbm_pipeline_code_from_legacy_reason(result->error_msg),
                error->operation ? error->operation : "cbm_extract_file",
                error->phase ? error->phase : phase, rel_path, error->requested,
                error->message
                    ? error->message
                    : (result->error_msg ? result->error_msg : "authoritative extraction failed"),
                error->remediation ? error->remediation
                                   : "inspect the exact extraction failure, fix the cause, then "
                                     "retry the complete "
                                     "corpus");
            return CBM_NOT_FOUND;
        }
        if (result && cbm_arena_failed(&result->arena)) {
            cbm_pipeline_record_fatal_error(
                p, cbm_arena_failure_code(&result->arena),
                cbm_arena_failure_operation(&result->arena), phase ? phase : "extract", rel_path,
                cbm_arena_failure_bytes(&result->arena),
                "an authoritative per-file arena entered a failed state; no partial extraction may "
                "be persisted",
                "inspect the exact arena code, operation, and requested quantity, fix the cause, "
                "then retry the complete corpus");
            return CBM_NOT_FOUND;
        }
        for (int j = 0; j < p->file_errors_count; j++) {
            const cbm_file_error_t *error = &p->file_errors[j];
            if (!error->path || strcmp(error->path, rel_path) != 0) {
                continue;
            }
            const char *code = cbm_pipeline_code_from_legacy_reason(error->reason);
            if (!code) {
                code = error->phase && strcmp(error->phase, "oversized") == 0
                           ? "CBM_SOURCE_FILE_LIMIT_EXCEEDED"
                       : error->phase && strcmp(error->phase, "read") == 0
                           ? "CBM_SOURCE_READ_FAILED"
                           : "CBM_EXTRACTION_RESULT_MISSING";
            }
            cbm_pipeline_record_fatal_error(
                p, code, error->phase ? error->phase : "extract", phase ? phase : "extract",
                rel_path, (size_t)files[i].size,
                error->reason ? error->reason : "a discovered source file was not extracted",
                "repair the source/read/extraction failure, then retry the complete corpus; "
                "partial "
                "publication is forbidden");
            return CBM_NOT_FOUND;
        }
        if (!result && files[i].size > 0) {
            cbm_pipeline_record_fatal_error(
                p, "CBM_EXTRACTION_RESULT_MISSING", "extract_discovered_source",
                phase ? phase : "extract", rel_path, (size_t)files[i].size,
                "a non-empty discovered source file produced no authoritative extraction result",
                "inspect source read and extraction diagnostics, fix the cause, then retry the "
                "complete corpus");
            return CBM_NOT_FOUND;
        }
    }
    return 0;
}

void cbm_pipeline_set_committed_counts(cbm_pipeline_t *p, int nodes, int edges) {
    if (p) {
        p->committed_nodes = nodes;
        p->committed_edges = edges;
    }
}

void cbm_pipeline_set_ambiguous_reference_skips(cbm_pipeline_t *p, uint_least64_t skips) {
    if (p) {
        p->ambiguous_reference_skips = skips;
    }
}

uint_least64_t cbm_pipeline_get_ambiguous_reference_skips(const cbm_pipeline_t *p) {
    return p ? p->ambiguous_reference_skips : 0;
}

void cbm_pipeline_set_unresolved_reference_source_skips(cbm_pipeline_t *p, uint_least64_t skips) {
    if (p) {
        p->unresolved_reference_source_skips = skips;
    }
}

uint_least64_t cbm_pipeline_get_unresolved_reference_source_skips(const cbm_pipeline_t *p) {
    return p ? p->unresolved_reference_source_skips : 0;
}

uint_least64_t cbm_pipeline_note_dangling_rust_module_skip(cbm_pipeline_t *p) {
    if (!p) {
        return 0;
    }
    return atomic_fetch_add(&p->dangling_rust_module_skips, 1) + 1;
}

uint_least64_t cbm_pipeline_get_dangling_rust_module_skips(const cbm_pipeline_t *p) {
    return p ? atomic_load(&((cbm_pipeline_t *)p)->dangling_rust_module_skips) : 0;
}

void cbm_pipeline_add_parse_recovery_diagnostics(cbm_pipeline_t *p, uint_least64_t count) {
    if (p) {
        p->parse_recovery_diagnostics += count;
    }
}

uint_least64_t cbm_pipeline_get_parse_recovery_diagnostics(const cbm_pipeline_t *p) {
    return p ? p->parse_recovery_diagnostics : 0;
}

const cbm_gbuf_node_t *cbm_pipeline_find_reference_source(
    const cbm_gbuf_t *gbuf, const char *project_name, const char *rel_path, const char *module_qn,
    const char *enclosing_qn, int source_line, const char *operation) {
    if (!gbuf || !project_name || !project_name[0] || !rel_path || !rel_path[0] || !operation ||
        !operation[0]) {
        if (gbuf) {
            cbm_log_error("pipeline.reference_source_invalid", "code",
                          "CBM_REFERENCE_SOURCE_ARGUMENT_INVALID", "operation",
                          operation ? operation : "", "project", project_name ? project_name : "",
                          "file_path", rel_path ? rel_path : "", "message",
                          "reference source resolution requires a graph, project, path, and "
                          "diagnostic operation",
                          "remediation",
                          "preserve the complete source identity frame through extraction and "
                          "resolution");
            const char *detail_keys[] = {"component", "reference_operation", "project",
                                         "file_path"};
            const char *detail_vals[] = {"pipeline.reference_source", operation ? operation : "",
                                         project_name ? project_name : "",
                                         rel_path ? rel_path : ""};
            cbm_gbuf_refuse_resolution_detail(
                (cbm_gbuf_t *)gbuf, "CBM_REFERENCE_SOURCE_ARGUMENT_INVALID",
                "pipeline.reference_source",
                "reference source resolution was called without the complete graph, project, "
                "path, and diagnostic-operation identity frame it requires",
                detail_keys, detail_vals, sizeof(detail_keys) / sizeof(detail_keys[0]));
        }
        return NULL;
    }

    bool has_enclosing = enclosing_qn && enclosing_qn[0];
    if (has_enclosing && (!module_qn || !module_qn[0])) {
        cbm_log_error("pipeline.reference_source_module_missing", "code",
                      "CBM_REFERENCE_MODULE_QN_MISSING", "operation", operation, "project",
                      project_name, "file_path", rel_path, "enclosing_qualified_name", enclosing_qn,
                      "message",
                      "an enclosing scope was extracted without the module identity needed to "
                      "distinguish top-level ownership",
                      "remediation",
                      "preserve the module qualified name from extraction through reference "
                      "resolution, then re-index the complete corpus");
        {
            const char *detail_keys[] = {"component", "reference_operation", "project", "file_path",
                                         "enclosing_qualified_name"};
            const char *detail_vals[] = {"pipeline.reference_source", operation, project_name,
                                         rel_path, enclosing_qn};
            cbm_gbuf_refuse_resolution_detail(
                (cbm_gbuf_t *)gbuf, "CBM_REFERENCE_MODULE_QN_MISSING", "pipeline.reference_source",
                "an enclosing scope was extracted without the module qualified name needed to "
                "distinguish top-level ownership from a nested callable",
                detail_keys, detail_vals, sizeof(detail_keys) / sizeof(detail_keys[0]));
        }
        return NULL;
    }

    bool top_level = !has_enclosing || strcmp(enclosing_qn, module_qn) == 0;
    if (top_level) {
        const cbm_gbuf_node_t *file = cbm_gbuf_find_source_container(gbuf, "File", rel_path);
        if (!file) {
            cbm_log_error("pipeline.reference_file_source_missing", "code",
                          "CBM_REFERENCE_FILE_SOURCE_NOT_FOUND", "operation", operation, "project",
                          project_name, "file_path", rel_path, "message",
                          "top-level reference has no unique source-backed File atom at its exact "
                          "repository path",
                          "remediation",
                          "repair structure-pass File ownership and re-index the complete corpus");
            const char *detail_keys[] = {"component", "reference_operation", "project",
                                         "file_path"};
            const char *detail_vals[] = {"pipeline.reference_source", operation, project_name,
                                         rel_path};
            cbm_gbuf_refuse_resolution_detail(
                (cbm_gbuf_t *)gbuf, "CBM_REFERENCE_FILE_SOURCE_NOT_FOUND",
                "pipeline.reference_source",
                "a top-level reference has no unique source-backed File atom at its exact "
                "repository path",
                detail_keys, detail_vals, sizeof(detail_keys) / sizeof(detail_keys[0]));
        }
        return file;
    }

    bool source_resolution_failed = false;
    const cbm_gbuf_node_t *source =
        source_line > 0
            ? cbm_gbuf_find_reference_owner_at(gbuf, enclosing_qn, rel_path, source_line, operation,
                                               &source_resolution_failed)
            : NULL;
    if (source_resolution_failed) {
        return NULL;
    }
    if (source) {
        return source;
    }

    if (source_line <= 0) {
        char line_buf[CBM_SZ_32];
        snprintf(line_buf, sizeof(line_buf), "%d", source_line);
        cbm_log_error("pipeline.reference_source_location_missing", "code",
                      "CBM_REFERENCE_SOURCE_LOCATION_MISSING", "operation", operation, "project",
                      project_name, "file_path", rel_path, "enclosing_qualified_name", enclosing_qn,
                      "source_line", line_buf, "message",
                      "an enclosing callable reference has no positive 1-based source line",
                      "remediation",
                      "preserve the parser source position through extraction and retry the "
                      "complete corpus");
        {
            const char *detail_keys[] = {"component",  "reference_operation",
                                         "project",    "file_path",
                                         "enclosing_qualified_name", "source_line"};
            const char *detail_vals[] = {"pipeline.reference_source", operation, project_name,
                                         rel_path,                    enclosing_qn, line_buf};
            cbm_gbuf_refuse_resolution_detail(
                (cbm_gbuf_t *)gbuf, "CBM_REFERENCE_SOURCE_LOCATION_MISSING",
                "pipeline.reference_source",
                "an enclosing-callable reference carries no positive 1-based source line, so its "
                "owning atom cannot be resolved by exact location",
                detail_keys, detail_vals, sizeof(detail_keys) / sizeof(detail_keys[0]));
        }
        return NULL;
    }
    cbm_gbuf_record_unresolved_reference_source(gbuf, operation, enclosing_qn, rel_path,
                                                source_line);
    return NULL;
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

int cbm_pipeline_complete_row_sink(cbm_pipeline_t *p, size_t file_hash_count,
                                   const cbm_index_capability_t *capability) {
    if (!p || !p->row_sink_active) {
        return 0;
    }
    if (p->row_sink_completed || p->committed_nodes < 0 || p->committed_edges < 0 ||
        !cbm_index_capability_valid(capability)) {
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
        .index_capability = *capability,
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

static int reject_invalid_worker_count(cbm_pipeline_t *p, const char *phase, int worker_count) {
    const char *raw_workers = getenv("CBM_WORKERS");
    const char *code = raw_workers ? "CBM_WORKERS_INVALID" : "CBM_WORKER_COUNT_INVALID";
    cbm_log_error("pipeline.worker_count_invalid", "code", code, "phase",
                  phase ? phase : "unknown", "worker_count", itoa_buf(worker_count), "message",
                  "worker-count configuration is invalid", "remediation",
                  "set CBM_WORKERS to an integer from 1 through 256 or remove it");
    cbm_pipeline_record_fatal_error(
        p, code, "admit_worker_count", phase ? phase : "worker_config", p ? p->repo_path : NULL, 0,
        raw_workers ? "CBM_WORKERS is present but is not an exact integer from 1 through 256"
                    : "worker-count auto-detection produced no admissible worker",
        "set CBM_WORKERS to an integer from 1 through 256 or remove it to use auto-detection");
    return CBM_NOT_FOUND;
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

typedef enum {
    CBM_BRANCH_REPLAY_FILE = 1,
    CBM_BRANCH_REPLAY_FOLDER = 2,
} cbm_branch_replay_kind_t;

typedef struct {
    cbm_branch_replay_kind_t kind;
    int64_t target_id;
    char *target_atom_id;
    char *properties_json;
} cbm_branch_replay_edge_t;

typedef struct {
    const cbm_gbuf_t *gb;
    int64_t branch_id;
    int64_t project_id;
    cbm_branch_replay_edge_t *items;
    size_t count;
    size_t capacity;
    size_t has_branch_count;
    bool allocation_failed;
    bool invalid;
    char invalid_reason[128];
    char invalid_type[128];
    char invalid_source[64];
    char invalid_target[64];
} cbm_branch_edge_capture_t;

static bool git_properties_capacity_add(size_t *capacity, const char *value) {
    if (!capacity) {
        return false;
    }
    const unsigned char *cursor = (const unsigned char *)(value ? value : "");
    while (*cursor) {
        size_t encoded = *cursor == '"' || *cursor == '\\' || *cursor == '\n' || *cursor == '\r' ||
                                 *cursor == '\t'
                             ? 2
                         : *cursor < 0x20 ? 6
                                          : 1;
        if (encoded > (size_t)INT_MAX - *capacity) {
            return false;
        }
        *capacity += encoded;
        cursor++;
    }
    return true;
}

static char *pipeline_git_context_props_json_alloc(const cbm_git_context_t *ctx) {
    if (!ctx) {
        return NULL;
    }
    const char *fields[] = {ctx->canonical_root, ctx->worktree_root, ctx->git_common_dir,
                            ctx->branch,         ctx->head_sha,      ctx->base_sha};
    size_t capacity = CBM_SZ_512;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (!git_properties_capacity_add(&capacity, fields[i])) {
            return NULL;
        }
    }
    char *json = malloc(capacity);
    if (!json) {
        return NULL;
    }
    if (cbm_git_context_props_json(ctx, json, (int)capacity) <= 0) {
        free(json);
        return NULL;
    }
    return json;
}

static void branch_replay_capture_free(cbm_branch_edge_capture_t *capture) {
    if (!capture) {
        return;
    }
    for (size_t i = 0; i < capture->count; i++) {
        free(capture->items[i].target_atom_id);
        free(capture->items[i].properties_json);
    }
    free(capture->items);
    capture->items = NULL;
    capture->count = 0;
    capture->capacity = 0;
}

static void branch_capture_invalid(cbm_branch_edge_capture_t *capture, const char *reason,
                                   const cbm_gbuf_edge_t *edge) {
    if (!capture || capture->invalid || capture->allocation_failed) {
        return;
    }
    capture->invalid = true;
    (void)snprintf(capture->invalid_reason, sizeof(capture->invalid_reason), "%s",
                   reason ? reason : "invalid_branch_edge");
    (void)snprintf(capture->invalid_type, sizeof(capture->invalid_type), "%s",
                   edge && edge->type ? edge->type : "");
    (void)snprintf(capture->invalid_source, sizeof(capture->invalid_source), "%lld",
                   edge ? (long long)edge->source_id : 0LL);
    (void)snprintf(capture->invalid_target, sizeof(capture->invalid_target), "%lld",
                   edge ? (long long)edge->target_id : 0LL);
}

static bool branch_capture_replay_edge(cbm_branch_edge_capture_t *capture,
                                       cbm_branch_replay_kind_t kind, const cbm_gbuf_node_t *target,
                                       const cbm_gbuf_edge_t *edge) {
    if (!capture || !target || !target->atom_id || !edge || !edge->properties_json) {
        return false;
    }
    if (capture->count == capture->capacity) {
        size_t next = capture->capacity ? capture->capacity * 2 : CBM_SZ_16;
        if (next < capture->capacity || next > SIZE_MAX / sizeof(*capture->items)) {
            capture->allocation_failed = true;
            return false;
        }
        cbm_branch_replay_edge_t *grown = realloc(capture->items, next * sizeof(*grown));
        if (!grown) {
            capture->allocation_failed = true;
            return false;
        }
        capture->items = grown;
        capture->capacity = next;
    }

    char *target_atom_id = strdup(target->atom_id);
    char *properties_json = strdup(edge->properties_json);
    if (!target_atom_id || !properties_json) {
        free(target_atom_id);
        free(properties_json);
        capture->allocation_failed = true;
        return false;
    }
    capture->items[capture->count++] = (cbm_branch_replay_edge_t){
        .kind = kind,
        .target_id = target->id,
        .target_atom_id = target_atom_id,
        .properties_json = properties_json,
    };
    return true;
}

static void capture_branch_edge(const cbm_gbuf_edge_t *edge, void *userdata) {
    cbm_branch_edge_capture_t *capture = (cbm_branch_edge_capture_t *)userdata;
    if (!capture || !edge || capture->invalid || capture->allocation_failed ||
        (edge->source_id != capture->branch_id && edge->target_id != capture->branch_id)) {
        return;
    }

    if (strcmp(edge->type ? edge->type : "", "HAS_BRANCH") == 0) {
        if (edge->source_id != capture->project_id || edge->target_id != capture->branch_id) {
            branch_capture_invalid(capture, "has_branch_orientation_or_endpoint", edge);
            return;
        }
        capture->has_branch_count++;
        return;
    }

    if (edge->source_id != capture->branch_id || edge->target_id == capture->branch_id) {
        branch_capture_invalid(capture, "unsupported_branch_edge_orientation", edge);
        return;
    }

    const cbm_gbuf_node_t *target = cbm_gbuf_find_by_id(capture->gb, edge->target_id);
    if (!target || !target->label || !target->atom_id) {
        branch_capture_invalid(capture, "branch_edge_target_absent", edge);
        return;
    }

    if (strcmp(edge->type ? edge->type : "", "CONTAINS_FILE") == 0 &&
        strcmp(target->label, "File") == 0) {
        (void)branch_capture_replay_edge(capture, CBM_BRANCH_REPLAY_FILE, target, edge);
        return;
    }
    if (strcmp(edge->type ? edge->type : "", "CONTAINS_FOLDER") == 0 &&
        strcmp(target->label, "Folder") == 0) {
        (void)branch_capture_replay_edge(capture, CBM_BRANCH_REPLAY_FOLDER, target, edge);
        return;
    }
    branch_capture_invalid(capture, "unsupported_branch_edge_type_or_target", edge);
}

static int compare_branch_replay_edges(const void *left, const void *right) {
    const cbm_branch_replay_edge_t *a = (const cbm_branch_replay_edge_t *)left;
    const cbm_branch_replay_edge_t *b = (const cbm_branch_replay_edge_t *)right;
    if (a->kind != b->kind) {
        return a->kind < b->kind ? -1 : 1;
    }
    int atom_cmp = strcmp(a->target_atom_id, b->target_atom_id);
    if (atom_cmp != 0) {
        return atom_cmp;
    }
    int props_cmp = strcmp(a->properties_json, b->properties_json);
    if (props_cmp != 0) {
        return props_cmp;
    }
    return (a->target_id > b->target_id) - (a->target_id < b->target_id);
}

static int record_git_structure_error(cbm_pipeline_t *p, const char *code, const char *operation,
                                      const char *message, const char *remediation,
                                      const char *old_qn, const char *new_qn, const char *old_name,
                                      const char *new_name, const char *detail_key,
                                      const char *detail_value) {
    const char *keys[] = {"old_branch_qn", "new_branch_qn", "old_branch_name", "new_branch_name",
                          detail_key};
    const char *values[] = {old_qn ? old_qn : "", new_qn ? new_qn : "", old_name ? old_name : "",
                            new_name ? new_name : "", detail_value ? detail_value : ""};
    cbm_pipeline_record_fatal_error_detail(
        p, code, operation, "incremental_git_structure", p && p->db_path ? p->db_path : "", 0,
        message, remediation, keys, values, detail_key && detail_key[0] ? 5 : 4);
    return CBM_NOT_FOUND;
}

int cbm_pipeline_git_structure_matches_store(cbm_pipeline_t *p, cbm_store_t *store, bool *matches) {
    if (matches) {
        *matches = false;
    }
    if (!p || !store || !matches || !p->project_name || !p->project_name[0] || !p->branch_qn ||
        !p->branch_qn[0] || !p->git_ctx.branch || !p->git_ctx.branch[0]) {
        return record_git_structure_error(
            p, "CBM_INCREMENTAL_GIT_STRUCTURE_CONTEXT_INVALID", "probe_incremental_git_structure",
            "the Git structure admission context is absent",
            "repair Git context capture so the verified store can be compared with the exact "
            "current Project and Branch, then retry",
            "", p ? p->branch_qn : "", "", p && p->git_ctx.branch ? p->git_ctx.branch : "", NULL,
            NULL);
    }

    char *expected_properties = pipeline_git_context_props_json_alloc(&p->git_ctx);
    if (!expected_properties) {
        return record_git_structure_error(
            p, "CBM_INCREMENTAL_GIT_PROPERTIES_SERIALIZE_FAILED",
            "serialize_incremental_git_structure_probe",
            "the exact current Git properties could not be retained for read-only admission",
            "preserve the existing SQLite family, repair the Git context or free memory, then "
            "retry",
            "", p->branch_qn, "", p->git_ctx.branch, NULL, NULL);
    }

    cbm_node_t *projects = NULL;
    cbm_node_t *branches = NULL;
    cbm_edge_t *has_branch = NULL;
    int project_count = 0;
    int branch_count = 0;
    int has_branch_count = 0;
    const char *query_operation = "find_incremental_project_identity";
    int query_status = cbm_store_find_nodes_by_qn(store, p->project_name, p->project_name,
                                                  &projects, &project_count);
    if (query_status == CBM_STORE_OK) {
        query_operation = "find_incremental_branch_identity";
        query_status = cbm_store_find_nodes_by_label(store, p->project_name, "Branch", &branches,
                                                     &branch_count);
    }
    if (query_status == CBM_STORE_OK && branch_count == 1 && branches) {
        query_operation = "find_incremental_has_branch_relation";
        query_status = cbm_store_find_edges_by_target_type(store, branches[0].id, "HAS_BRANCH",
                                                           &has_branch, &has_branch_count);
    }
    if (query_status != CBM_STORE_OK) {
        const char *store_detail = cbm_store_error(store);
        int result = record_git_structure_error(
            p, "CBM_INCREMENTAL_GIT_STRUCTURE_PROBE_FAILED", query_operation,
            store_detail && store_detail[0]
                ? store_detail
                : "the indexed Project/Branch/HAS_BRANCH state could not be read exactly",
            "preserve the existing SQLite family, repair the named store query, then retry",
            branch_count == 1 && branches && branches[0].qualified_name ? branches[0].qualified_name
                                                                        : "",
            p->branch_qn, branch_count == 1 && branches && branches[0].name ? branches[0].name : "",
            p->git_ctx.branch, "store_operation", query_operation);
        cbm_store_free_edges(has_branch, has_branch_count);
        cbm_store_free_nodes(branches, branch_count);
        cbm_store_free_nodes(projects, project_count);
        free(expected_properties);
        return result;
    }

    const char *mismatch_reason = NULL;
    if (project_count != 1 || !projects || !projects[0].project || !projects[0].label ||
        !projects[0].name || !projects[0].qualified_name ||
        strcmp(projects[0].project, p->project_name) != 0 ||
        strcmp(projects[0].label, "Project") != 0 ||
        strcmp(projects[0].name, p->project_name) != 0 ||
        strcmp(projects[0].qualified_name, p->project_name) != 0) {
        mismatch_reason = "project_identity";
    } else if (branch_count != 1 || !branches || !branches[0].project || !branches[0].label ||
               !branches[0].name || !branches[0].qualified_name || !branches[0].properties_json ||
               strcmp(branches[0].project, p->project_name) != 0 ||
               strcmp(branches[0].label, "Branch") != 0 ||
               strcmp(branches[0].name, p->git_ctx.branch) != 0 ||
               strcmp(branches[0].qualified_name, p->branch_qn) != 0 ||
               strcmp(branches[0].properties_json, expected_properties) != 0) {
        mismatch_reason = "branch_identity_or_properties";
    } else if (has_branch_count != 1 || !has_branch || !has_branch[0].project ||
               !has_branch[0].type || strcmp(has_branch[0].project, p->project_name) != 0 ||
               strcmp(has_branch[0].type, "HAS_BRANCH") != 0 ||
               has_branch[0].source_id != projects[0].id ||
               has_branch[0].target_id != branches[0].id || !has_branch[0].properties_json ||
               strcmp(has_branch[0].properties_json, expected_properties) != 0) {
        mismatch_reason = "has_branch_identity_or_properties";
    }

    *matches = mismatch_reason == NULL;
    if (mismatch_reason) {
        char project_count_text[32];
        char branch_count_text[32];
        char relation_count_text[32];
        (void)snprintf(project_count_text, sizeof(project_count_text), "%d", project_count);
        (void)snprintf(branch_count_text, sizeof(branch_count_text), "%d", branch_count);
        (void)snprintf(relation_count_text, sizeof(relation_count_text), "%d", has_branch_count);
        cbm_log_info("incremental.git_structure_admission", "route", "reconcile_required", "reason",
                     mismatch_reason, "old_branch",
                     branch_count == 1 && branches && branches[0].qualified_name
                         ? branches[0].qualified_name
                         : "",
                     "new_branch", p->branch_qn, "project_count", project_count_text,
                     "branch_count", branch_count_text, "has_branch_count", relation_count_text);
    }

    cbm_store_free_edges(has_branch, has_branch_count);
    cbm_store_free_nodes(branches, branch_count);
    cbm_store_free_nodes(projects, project_count);
    free(expected_properties);
    return 0;
}

static int validate_has_branch_relation(cbm_pipeline_t *p, const cbm_gbuf_t *gb,
                                        const cbm_gbuf_node_t *project,
                                        const cbm_gbuf_node_t *branch, const char *new_qn,
                                        const char *new_name, const char *expected_properties) {
    const cbm_gbuf_edge_t **edges = NULL;
    int count = 0;
    if (cbm_gbuf_find_edges_by_target_type(gb, branch->id, "HAS_BRANCH", &edges, &count) != 0 ||
        count != 1 || !edges || edges[0]->source_id != project->id ||
        edges[0]->target_id != branch->id || !edges[0]->properties_json ||
        strcmp(edges[0]->properties_json, expected_properties ? expected_properties : "") != 0) {
        char count_text[32];
        (void)snprintf(count_text, sizeof(count_text), "%d", count);
        return record_git_structure_error(
            p, "CBM_INCREMENTAL_HAS_BRANCH_INVALID", "validate_incremental_has_branch",
            "the loaded graph does not contain exactly one Project-to-Branch HAS_BRANCH relation",
            "preserve the existing SQLite family, repair or explicitly reindex its malformed "
            "structural graph, then retry",
            branch->qualified_name, new_qn, branch->name, new_name, "has_branch_count", count_text);
    }
    return 0;
}

int cbm_pipeline_reconcile_incremental_git_structure(cbm_pipeline_t *p, cbm_gbuf_t *gb) {
    if (!p || !gb || !p->project_name || !p->project_name[0] || !p->branch_qn || !p->branch_qn[0]) {
        return record_git_structure_error(
            p, "CBM_INCREMENTAL_GIT_STRUCTURE_CONTEXT_INVALID", "resolve_incremental_git_structure",
            "the current Git structural context is absent",
            "repair Git context capture so the project and exact branch identity are present, then "
            "retry",
            "", p ? p->branch_qn : "", "", p && p->git_ctx.branch ? p->git_ctx.branch : "", NULL,
            NULL);
    }

    const char *new_qn = p->branch_qn;
    const char *new_name = p->git_ctx.branch ? p->git_ctx.branch : "working-tree";
    char *branch_props = pipeline_git_context_props_json_alloc(&p->git_ctx);
    if (!branch_props) {
        return record_git_structure_error(
            p, "CBM_INCREMENTAL_GIT_PROPERTIES_SERIALIZE_FAILED",
            "serialize_incremental_git_structure",
            "the exact current Git properties could not be retained as canonical JSON",
            "preserve the existing SQLite family, repair the Git context or free memory, then "
            "retry",
            "", new_qn, "", new_name, NULL, NULL);
    }

    const cbm_gbuf_node_t *project = cbm_gbuf_find_by_qn(gb, p->project_name);
    if (!project || !project->label || !project->name || strcmp(project->label, "Project") != 0 ||
        strcmp(project->name, p->project_name) != 0) {
        int result = record_git_structure_error(
            p, "CBM_INCREMENTAL_PROJECT_STRUCTURE_INVALID", "resolve_incremental_project",
            "the loaded graph lacks the exact Project structural atom",
            "preserve the existing SQLite family, repair or explicitly reindex its malformed "
            "structural graph, then retry",
            "", new_qn, "", new_name, NULL, NULL);
        free(branch_props);
        return result;
    }

    const cbm_gbuf_node_t **branches = NULL;
    int branch_count = 0;
    if (cbm_gbuf_find_by_label(gb, "Branch", &branches, &branch_count) != 0 || branch_count != 1 ||
        !branches || !branches[0] || !branches[0]->qualified_name || !branches[0]->name) {
        char count_text[32];
        (void)snprintf(count_text, sizeof(count_text), "%d", branch_count);
        int result = record_git_structure_error(
            p, "CBM_INCREMENTAL_BRANCH_CARDINALITY_INVALID",
            "validate_incremental_branch_cardinality",
            "the loaded graph does not contain exactly one complete Branch structural atom",
            "preserve the existing SQLite family, repair or explicitly reindex its malformed "
            "structural graph, then retry",
            "", new_qn, "", new_name, "branch_count", count_text);
        free(branch_props);
        return result;
    }

    const cbm_gbuf_node_t *old_branch = branches[0];
    if (validate_has_branch_relation(p, gb, project, old_branch, new_qn, new_name,
                                     old_branch->properties_json ? old_branch->properties_json
                                                                 : "") != 0) {
        free(branch_props);
        return CBM_NOT_FOUND;
    }

    if (strcmp(old_branch->qualified_name, new_qn) == 0 &&
        strcmp(old_branch->name, new_name) == 0) {
        int64_t branch_id =
            cbm_gbuf_upsert_node(gb, "Branch", new_name, new_qn, NULL, 0, 0, branch_props);
        int64_t relation_id = branch_id > 0 ? cbm_gbuf_insert_edge(gb, project->id, branch_id,
                                                                   "HAS_BRANCH", branch_props)
                                            : 0;
        const cbm_gbuf_node_t *updated = cbm_gbuf_find_by_qn(gb, new_qn);
        if (branch_id <= 0 || relation_id <= 0 || !updated ||
            strcmp(updated->properties_json ? updated->properties_json : "", branch_props) != 0 ||
            validate_has_branch_relation(p, gb, project, updated, new_qn, new_name, branch_props) !=
                0) {
            int result = record_git_structure_error(
                p, "CBM_INCREMENTAL_GIT_STRUCTURE_UPDATE_FAILED",
                "refresh_incremental_git_structure",
                "the same-branch graph property refresh did not produce the exact current state",
                "preserve the existing SQLite family, inspect the graph-buffer refusal, free "
                "memory "
                "or repair the structural graph, then retry",
                old_branch->qualified_name, new_qn, old_branch->name, new_name, NULL, NULL);
            free(branch_props);
            return result;
        }
        cbm_log_info("incremental.git_structure", "route", "properties_refreshed", "old_branch",
                     old_branch->qualified_name, "new_branch", new_qn, "replayed_edges", "0");
        free(branch_props);
        return 0;
    }

    char *old_qn = strdup(old_branch->qualified_name);
    char *old_name = strdup(old_branch->name);
    if (!old_qn || !old_name) {
        free(old_qn);
        free(old_name);
        int result = record_git_structure_error(
            p, "CBM_INCREMENTAL_BRANCH_REPLAY_ALLOC_FAILED", "capture_incremental_branch_identity",
            "the complete prior Branch identity could not be retained before reconciliation",
            "preserve the existing SQLite family, free memory or reduce repository size, then "
            "retry",
            old_branch->qualified_name, new_qn, old_branch->name, new_name, NULL, NULL);
        free(branch_props);
        return result;
    }

    cbm_branch_edge_capture_t capture = {
        .gb = gb,
        .branch_id = old_branch->id,
        .project_id = project->id,
    };
    cbm_gbuf_foreach_edge(gb, capture_branch_edge, &capture);
    if (capture.allocation_failed) {
        branch_replay_capture_free(&capture);
        int result = record_git_structure_error(
            p, "CBM_INCREMENTAL_BRANCH_REPLAY_ALLOC_FAILED", "capture_incremental_branch_edges",
            "the complete deterministic Branch edge replay plan could not be retained",
            "preserve the existing SQLite family, free memory or reduce repository size, then "
            "retry",
            old_qn, new_qn, old_name, new_name, NULL, NULL);
        free(old_qn);
        free(old_name);
        free(branch_props);
        return result;
    }
    if (capture.invalid || capture.has_branch_count != 1) {
        char detail[512];
        (void)snprintf(detail, sizeof(detail),
                       "reason=%s,type=%s,source_id=%s,target_id=%s,has_branch_count=%zu",
                       capture.invalid_reason, capture.invalid_type, capture.invalid_source,
                       capture.invalid_target, capture.has_branch_count);
        branch_replay_capture_free(&capture);
        int result = record_git_structure_error(
            p, "CBM_INCREMENTAL_BRANCH_EDGE_INVALID", "validate_incremental_branch_edges",
            "the prior Branch touches an undocumented or malformed structural edge",
            "preserve the existing SQLite family, repair or explicitly reindex the named "
            "structural "
            "edge, then retry",
            old_qn, new_qn, old_name, new_name, "edge_detail", detail);
        free(old_qn);
        free(old_name);
        free(branch_props);
        return result;
    }

    if (capture.count > 1) {
        qsort(capture.items, capture.count, sizeof(*capture.items), compare_branch_replay_edges);
    }
    if (cbm_gbuf_delete_by_label(gb, "Branch") != 0) {
        branch_replay_capture_free(&capture);
        int result = record_git_structure_error(
            p, "CBM_INCREMENTAL_BRANCH_REPLACE_FAILED", "delete_prior_incremental_branch",
            "the prior Branch atom and its exact structural edges could not be removed in memory",
            "the on-disk family is unchanged; inspect the graph-buffer refusal, free memory, then "
            "retry",
            old_qn, new_qn, old_name, new_name, NULL, NULL);
        free(old_qn);
        free(old_name);
        free(branch_props);
        return result;
    }

    int64_t new_branch_id =
        cbm_gbuf_upsert_node(gb, "Branch", new_name, new_qn, NULL, 0, 0, branch_props);
    bool replay_failed =
        new_branch_id <= 0 ||
        cbm_gbuf_insert_edge(gb, project->id, new_branch_id, "HAS_BRANCH", branch_props) <= 0;
    size_t file_edges = 0;
    size_t folder_edges = 0;
    for (size_t i = 0; i < capture.count && !replay_failed; i++) {
        const cbm_branch_replay_edge_t *saved = &capture.items[i];
        const cbm_gbuf_node_t *target = cbm_gbuf_find_by_id(gb, saved->target_id);
        if (!target || !target->atom_id || strcmp(target->atom_id, saved->target_atom_id) != 0) {
            replay_failed = true;
            break;
        }
        const char *type =
            saved->kind == CBM_BRANCH_REPLAY_FILE ? "CONTAINS_FILE" : "CONTAINS_FOLDER";
        if (cbm_gbuf_insert_edge(gb, new_branch_id, saved->target_id, type,
                                 saved->properties_json) <= 0) {
            replay_failed = true;
            break;
        }
        file_edges += saved->kind == CBM_BRANCH_REPLAY_FILE ? 1 : 0;
        folder_edges += saved->kind == CBM_BRANCH_REPLAY_FOLDER ? 1 : 0;
    }

    const cbm_gbuf_node_t **after_branches = NULL;
    int after_branch_count = 0;
    const cbm_gbuf_node_t *after_branch = cbm_gbuf_find_by_qn(gb, new_qn);
    const cbm_gbuf_edge_t **after_file_edges = NULL;
    const cbm_gbuf_edge_t **after_folder_edges = NULL;
    int after_file_count = 0;
    int after_folder_count = 0;
    if (!replay_failed) {
        replay_failed =
            cbm_gbuf_find_by_label(gb, "Branch", &after_branches, &after_branch_count) != 0 ||
            after_branch_count != 1 || !after_branches || after_branches[0] != after_branch ||
            !after_branch || strcmp(after_branch->name, new_name) != 0 ||
            strcmp(after_branch->properties_json ? after_branch->properties_json : "",
                   branch_props) != 0 ||
            validate_has_branch_relation(p, gb, project, after_branch, new_qn, new_name,
                                         branch_props) != 0 ||
            cbm_gbuf_find_edges_by_source_type(gb, new_branch_id, "CONTAINS_FILE",
                                               &after_file_edges, &after_file_count) != 0 ||
            cbm_gbuf_find_edges_by_source_type(gb, new_branch_id, "CONTAINS_FOLDER",
                                               &after_folder_edges, &after_folder_count) != 0 ||
            (size_t)after_file_count != file_edges || (size_t)after_folder_count != folder_edges;
    }

    size_t replayed = capture.count;
    branch_replay_capture_free(&capture);
    if (replay_failed) {
        int result = record_git_structure_error(
            p, "CBM_INCREMENTAL_BRANCH_REPLAY_FAILED", "replay_incremental_branch_edges",
            "the deterministic replacement Branch graph did not read back exactly in memory",
            "the on-disk family is unchanged; inspect the graph-buffer refusal or structural "
            "mismatch, repair it, then retry",
            old_qn, new_qn, old_name, new_name, NULL, NULL);
        free(old_qn);
        free(old_name);
        free(branch_props);
        return result;
    }

    char replayed_text[32];
    (void)snprintf(replayed_text, sizeof(replayed_text), "%zu", replayed);
    cbm_log_info("incremental.git_structure", "route", "branch_replaced", "old_branch", old_qn,
                 "new_branch", new_qn, "replayed_edges", replayed_text);
    free(old_qn);
    free(old_name);
    free(branch_props);
    return 0;
}

static int pass_structure(cbm_pipeline_t *p, const cbm_file_info_t *files, int file_count,
                          const cbm_source_slab_t *source_slab) {
    cbm_log_info("pass.start", "pass", "structure", "files", itoa_buf(file_count));

    /* Project node */
    cbm_gbuf_upsert_node(p->gbuf, "Project", p->project_name, p->project_name, NULL, 0, 0, "{}");
    const char *branch_qn = p->branch_qn ? p->branch_qn : p->project_name;
    const char *branch_name = p->git_ctx.branch ? p->git_ctx.branch : "working-tree";
    char *branch_props_json = pipeline_git_context_props_json_alloc(&p->git_ctx);
    if (!branch_props_json) {
        cbm_pipeline_record_fatal_error(
            p, "CBM_GIT_PROPERTIES_SERIALIZE_FAILED", "serialize_git_structure", "structure",
            p->repo_path, 0,
            "the exact current Git properties could not be retained as canonical JSON",
            "repair the Git context or free memory, then retry the complete index");
        return CBM_NOT_FOUND;
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
    free(branch_props_json);

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

        size_t props_capacity = cbm_pipeline_file_properties_capacity(p, &files[i]);
        char props_stack[CBM_SZ_1K];
        bool props_heap_owned = props_capacity > sizeof(props_stack);
        char *props = !props_capacity
                          ? NULL
                          : (props_heap_owned ? malloc(props_capacity) : props_stack);
        if (!props && props_capacity) {
            cbm_pipeline_record_fatal_error(
                p, "CBM_FILE_PROPERTIES_ALLOC_FAILED", "allocate_file_properties",
                "structure", files[i].rel_path, props_capacity,
                "the complete File atom properties could not be allocated",
                "free memory and retry the unchanged corpus");
        }
        if (!props ||
            cbm_pipeline_format_file_properties(p, &files[i], props, props_capacity) != 0) {
            if (props_heap_owned) {
                free(props);
            }
            free(file_qn);
            cbm_ht_foreach(seen_dirs, free_seen_dir_key, NULL);
            cbm_ht_free(seen_dirs);
            return CBM_NOT_FOUND;
        }

        const char *qualified_name = file_qn;
        const char *file_path = rel;
        size_t source_len = 0;
        const uint8_t *source_bytes = cbm_source_slab_get(source_slab, i, &source_len);
        if (!source_bytes) {
            cbm_log_error("structure.file_source_refused", "code",
                          "CBM_FILE_SOURCE_SLAB_ENTRY_INVALID", "path", files[i].path,
                          "message", "the hash-bound source slab entry is absent or malformed",
                          "remediation",
                          "preserve the slab diagnostic and retry the complete unchanged corpus");
            free(file_qn);
            if (props_heap_owned) {
                free(props);
            }
            cbm_ht_foreach(seen_dirs, free_seen_dir_key, NULL);
            cbm_ht_free(seen_dirs);
            return CBM_NOT_FOUND;
        }
        int64_t file_id =
            cbm_gbuf_upsert_source_node_borrowed(p->gbuf, "File", basename, qualified_name,
                                                 file_path, 0, 0, source_bytes, source_len, 0,
                                                 (uint64_t)source_len, props);
        if (props_heap_owned) {
            free(props);
        }
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
        if (cbm_worker_progress_advance_unit(CBM_WORKER_PROGRESS_STAGE_STRUCTURE, "structure",
                                            (uint64_t)file_count) != 0) {
            cbm_pipeline_record_fatal_error(
                p, "CBM_INDEX_WORKER_PROGRESS_WRITE_FAILED", "publish_structure_progress",
                "structure", rel, (size_t)i,
                "the completed structural file unit could not advance semantic progress",
                "preserve the worker workspace, repair the progress stream, and retry the "
                "unchanged repository");
            cbm_ht_foreach(seen_dirs, free_seen_dir_key, NULL);
            cbm_ht_free(seen_dirs);
            return CBM_NOT_FOUND;
        }
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
    uint64_t progress_total = p->mode == CBM_MODE_FAST ? 4U : PREDUMP_PASS_COUNT;
    struct timespec t;
    for (int i = 0; i < PREDUMP_PASS_COUNT && !check_cancel(p); i++) {
        /* "moderate_only" passes (similarity/semantic edges) run in FULL,
         * MODERATE and ADVANCED — they are skipped only in FAST. Compare
         * explicitly against FAST rather than `> MODERATE` so ADVANCED
         * (numerically 3) is not mistaken for a lighter mode than FULL. */
        if (passes[i].moderate_only && p->mode == CBM_MODE_FAST) {
            continue;
        }
        cbm_pipeline_phase_probe_t pass_probe = cbm_pipeline_phase_probe_start(p, passes[i].name);
        cbm_clock_gettime(CLOCK_MONOTONIC, &t);
        int rc = passes[i].fn(ctx);
        cbm_pipeline_phase_probe_end(p, passes[i].name, &pass_probe);
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
        if (cbm_worker_progress_advance_unit(CBM_WORKER_PROGRESS_STAGE_PREDUMP, "predump",
                                            progress_total) != 0) {
            cbm_pipeline_record_fatal_error(
                p, "CBM_INDEX_WORKER_PROGRESS_WRITE_FAILED", "publish_predump_progress",
                "predump", passes[i].name, (size_t)i,
                "the completed predump pass could not advance semantic progress",
                "preserve the worker workspace, repair the progress stream, and retry the "
                "unchanged repository");
            return CBM_NOT_FOUND;
        }
    }
    return check_cancel(p) ? CBM_NOT_FOUND : 0;
}

/* Run the parallel pipeline path: extract, registry, resolve, infra, k8s. */
static int pipeline_progress_publish(cbm_pipeline_t *p, uint32_t stage_order,
                                     const char *stage, uint64_t completed, uint64_t total,
                                     uint32_t step_order, const char *step,
                                     uint64_t step_completed, uint64_t step_total) {
    if (cbm_worker_progress_publish(stage_order, stage, completed, total, step_order, step,
                                    step_completed, step_total) == 0) {
        return 0;
    }
    cbm_pipeline_record_fatal_error(
        p, "CBM_INDEX_WORKER_PROGRESS_WRITE_FAILED", "publish_semantic_progress", stage,
        p && p->repo_path ? p->repo_path : "", (size_t)completed,
        "the supervised worker could not publish its semantic work cursor",
        "preserve the worker workspace, repair the progress stream failure, and retry the "
        "unchanged repository");
    return CBM_NOT_FOUND;
}

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
        return cbm_pipeline_reject_file_failures(p, files, file_count, NULL, "parallel_cache");
    }
    cbm_pipeline_phase_probe_t extract_probe =
        cbm_pipeline_phase_probe_start(p, "parallel_extract");
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    int rc = cbm_parallel_extract(ctx, files, file_count, cache, &shared_ids, worker_count);
    cbm_pipeline_phase_probe_end(p, "parallel_extract", &extract_probe);
    cbm_log_info("pass.timing", "pass", "parallel_extract", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(*t)));
    if (rc != 0 || check_cancel(p)) {
        for (int i = 0; i < file_count; i++) {
            if (cache[i]) {
                cbm_free_result(cache[i]);
            }
        }
        free(cache);
        return rc != 0 ? rc : CBM_NOT_FOUND;
    }
    cbm_pipeline_phase_probe_t compiler_preprocess_probe =
        cbm_pipeline_phase_probe_start(p, "compiler_preprocess");
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    rc = cbm_compile_context_extract_calls(ctx, ctx->compile_contexts, files, file_count, cache);
    if (rc == 0) {
        rc = cbm_pipeline_reject_file_failures(p, files, file_count, cache,
                                               "compiler_preprocess");
    }
    cbm_pipeline_phase_probe_end(p, "compiler_preprocess", &compiler_preprocess_probe);
    cbm_log_info("pass.timing", "pass", "compiler_preprocess", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(*t)));
    if (rc != 0 || check_cancel(p)) {
        for (int i = 0; i < file_count; i++) {
            if (cache[i]) {
                cbm_free_result(cache[i]);
            }
        }
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
    cbm_pipeline_phase_probe_t registry_probe = cbm_pipeline_phase_probe_start(p, "registry_build");
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    rc = cbm_build_registry_from_cache(ctx, files, file_count, cache);
    cbm_pipeline_phase_probe_end(p, "registry_build", &registry_probe);
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
     * kubernetes). Every preparation failure is terminal: silently omitting
     * cross-file associations would publish an incomplete generation. */
    cbm_pipeline_phase_probe_t cross_prepare_probe =
        cbm_pipeline_phase_probe_start(p, "lsp_cross_prepare");
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    char **def_modules = NULL;
    int def_count = 0;
    CBMLSPDef *all_defs = NULL;
    def_modules = (char **)calloc((size_t)file_count, sizeof(char *));
    if (!def_modules) {
        cbm_log_error("lsp_cross.prepare_failed", "code", "CBM_LSP_MODULE_CACHE_ALLOC_FAILED",
                      "component", "lsp_cross.module_cache", "operation", "allocate_entries",
                      "message", "cross-LSP module cache allocation failed", "remediation",
                      "free memory or reduce repository size, then retry");
        rc = CBM_NOT_FOUND;
    } else {
        all_defs = cbm_pxc_collect_all_defs(cache, files, file_count, ctx->project_name,
                                            def_modules, &def_count);
        if (def_count < 0 || (def_count > 0 && !all_defs)) {
            rc = CBM_NOT_FOUND;
        }
    }
    /* Build inverted index: module_qn → defs. The fused resolve_worker
     * uses this to filter the global all_defs[] down to just the defs
     * each file actually needs (own_module + imported modules) — the
     * gopls "package summary" pattern. Drops per-file registry build
     * cost from O(all_defs) to O(relevant_defs), typically 50-100×
     * smaller per file. */
    CBMModuleDefIndex *module_def_index =
        (rc == 0 && all_defs) ? cbm_pxc_build_module_def_index(all_defs, def_count) : NULL;
    if (rc == 0 && def_count > 0 && !module_def_index) {
        rc = CBM_NOT_FOUND;
    }
    /* Tier 2 full: pre-build per-language cross-LSP registries.
     * Built ONCE here; shared READ-ONLY across all files of that language
     * during resolve. Per-file work is then: parse + AST walk + O(1) lookups
     * — no registry build, no Phase 1b mutations. C-family resolution is
     * deliberately excluded here: only exact compiler-expanded contexts may
     * emit C-family semantic facts. */
    CBMArena cross_lsp_arena;
    cbm_arena_init(&cross_lsp_arena);
    CBMCrossLspRegistries cross_registries = {0};
    if (rc == 0 && all_defs) {
        cross_registries.go = cbm_go_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        cross_registries.python =
            cbm_py_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        cross_registries.cs = cbm_cs_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        cross_registries.ts = cbm_ts_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        cross_registries.rust =
            cbm_rust_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        if (cbm_arena_failed(&cross_lsp_arena) || !cross_registries.go ||
            !cross_registries.python || !cross_registries.cs || !cross_registries.ts ||
            !cross_registries.rust) {
            char requested[32];
            snprintf(requested, sizeof(requested), "%zu",
                     cbm_arena_failure_bytes(&cross_lsp_arena));
            cbm_log_error(
                "lsp_cross.prepare_failed", "code", cbm_arena_failure_code(&cross_lsp_arena),
                "component", "lsp_cross.shared_registries", "operation",
                cbm_arena_failure_operation(&cross_lsp_arena), "requested_bytes", requested,
                "message", "a complete project-wide cross-LSP registry could not be built",
                "remediation", "free memory or reduce repository size, then retry");
            rc = CBM_NOT_FOUND;
        }
    }
    cbm_pipeline_phase_probe_end(p, "lsp_cross_prepare", &cross_prepare_probe);
    cbm_log_info("pass.timing", "pass", "lsp_cross_prepare", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(*t)));
    log_phase_mem("lsp_cross_prepare");
    /* registry_build mutates the main graph through its local next-ID counter
     * after parallel_extract last advanced shared_ids. Rebase before another
     * worker phase so resolve IDs begin strictly above every serially created
     * Channel/Env/definition row. A stale handoff here used to regress the
     * main ceiling after resolve and silently strand live high-ID nodes at
     * dump (#841). */
    if (rc == 0) {
        cbm_parallel_rebase_shared_ids(p->gbuf, &shared_ids, "parallel_resolve.post_registry");
        cbm_pipeline_phase_probe_t resolve_probe =
            cbm_pipeline_phase_probe_start(p, "parallel_resolve");
        cbm_clock_gettime(CLOCK_MONOTONIC, t);
        rc = cbm_parallel_resolve(ctx, files, file_count, cache, &shared_ids, worker_count,
                                  all_defs, def_count, def_modules, module_def_index,
                                  &cross_registries);
        if (rc == 0) {
            rc = cbm_pipeline_reject_file_failures(p, files, file_count, cache, "parallel_resolve");
        }
        cbm_pipeline_phase_probe_end(p, "parallel_resolve", &resolve_probe);
        cbm_log_info("pass.timing", "pass", "parallel_resolve", "elapsed_ms",
                     itoa_buf((int)elapsed_ms(*t)));
        log_phase_mem("parallel_resolve");
    }
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
    cbm_pipeline_phase_probe_t k8s_probe = cbm_pipeline_phase_probe_start(p, "k8s");
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    cbm_pipeline_pass_k8s(ctx, files, file_count);
    cbm_pipeline_phase_probe_end(p, "k8s", &k8s_probe);
    cbm_log_info("pass.timing", "pass", "k8s", "elapsed_ms", itoa_buf((int)elapsed_ms(*t)));
    if (check_cancel(p)) {
        return CBM_NOT_FOUND;
    }
    if (cbm_worker_progress_advance_unit(CBM_WORKER_PROGRESS_STAGE_ENRICH, "enrich", 2) != 0) {
        cbm_pipeline_record_fatal_error(
            p, "CBM_INDEX_WORKER_PROGRESS_WRITE_FAILED", "publish_enrichment_progress",
            "enrich", p->repo_path, 1,
            "the completed infrastructure enrichment could not advance semantic progress",
            "preserve the worker workspace, repair the progress stream, and retry the unchanged "
            "repository");
        return CBM_NOT_FOUND;
    }
    return 0;
}

/* A project name is the live database filename identity. Reusing that name for
 * another repository must never authorize replacement of the existing family.
 * Enforce the persisted (name, canonical root) tuple before incremental hash
 * routing, checkpointing, staging, or row-sink publication. Query-time
 * provenance checks are too late: by then atomic publication has already
 * displaced the prior source of truth. */
static int validate_existing_store_project_identity(cbm_pipeline_t *p, cbm_store_t *store,
                                                    const char *db_path) {
    cbm_project_t *projects = NULL;
    int project_count = 0;
    if (cbm_store_list_projects(store, &projects, &project_count) != CBM_STORE_OK) {
        cbm_log_error(
            "pipeline.route_failed", "code", "CBM_PIPELINE_STORE_PROJECT_IDENTITY_READ_FAILED",
            "operation", "validate_existing_store_project_identity", "store_path", db_path,
            "requested_project", p->project_name, "requested_root", p->repo_path,
            "publication_started", "false", "message",
            "the existing store project identity could not be read", "remediation",
            "preserve the complete store family, inspect the store diagnostic, and retry");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_STORE_PROJECT_IDENTITY_READ_FAILED",
            "validate_existing_store_project_identity", "route", db_path, 0,
            "the existing store project identity could not be read before mutation",
            "preserve the complete store family, inspect the store diagnostic, and retry");
        cbm_store_free_projects(projects, project_count);
        return CBM_NOT_FOUND;
    }

    if (project_count != 1 || !projects || !projects[0].name || !projects[0].root_path) {
        char count_text[32];
        (void)snprintf(count_text, sizeof(count_text), "%d", project_count);
        cbm_log_error(
            "pipeline.route_failed", "code", "CBM_PIPELINE_STORE_PROJECT_IDENTITY_INVALID",
            "operation", "validate_existing_store_project_identity", "store_path", db_path,
            "requested_project", p->project_name, "requested_root", p->repo_path,
            "persisted_project_count", count_text, "publication_started", "false", "message",
            "the existing store does not contain one complete project identity", "remediation",
            "preserve the complete store family and repair or explicitly archive it before "
            "retrying");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_STORE_PROJECT_IDENTITY_INVALID",
            "validate_existing_store_project_identity", "route", db_path,
            (size_t)(project_count < 0 ? 0 : project_count),
            "the existing store does not contain one complete project identity",
            "preserve the complete store family and repair or explicitly archive it before "
            "retrying");
        cbm_store_free_projects(projects, project_count);
        return CBM_NOT_FOUND;
    }

    if (strcmp(projects[0].name, p->project_name) != 0) {
        char message[PL_ERROR_MESSAGE];
        (void)snprintf(message, sizeof(message),
                       "the existing store belongs to project '%s', not requested project '%s'",
                       projects[0].name, p->project_name);
        cbm_log_error(
            "pipeline.route_failed", "code", "CBM_PIPELINE_STORE_PROJECT_IDENTITY_MISMATCH",
            "operation", "validate_existing_store_project_identity", "store_path", db_path,
            "existing_project", projects[0].name, "requested_project", p->project_name,
            "existing_root", projects[0].root_path, "requested_root", p->repo_path,
            "publication_started", "false", "message", message, "remediation",
            "use a distinct project name or perform an explicit archive/delete/rebind transaction");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_STORE_PROJECT_IDENTITY_MISMATCH",
            "validate_existing_store_project_identity", "route", db_path, 0, message,
            "use a distinct project name or perform an explicit archive/delete/rebind transaction");
        cbm_store_free_projects(projects, project_count);
        return CBM_NOT_FOUND;
    }

    char *existing_root = cbm_real_path_final(projects[0].root_path);
    char *requested_root = cbm_real_path_final(p->repo_path);
    if (!existing_root || !requested_root) {
        cbm_log_error("pipeline.route_failed", "code",
                      "CBM_PIPELINE_STORE_PROJECT_ROOT_UNRESOLVABLE", "operation",
                      "validate_existing_store_project_identity", "store_path", db_path, "project",
                      p->project_name, "existing_root", projects[0].root_path, "requested_root",
                      p->repo_path, "existing_root_resolved", existing_root ? "true" : "false",
                      "requested_root_resolved", requested_root ? "true" : "false",
                      "publication_started", "false", "message",
                      "the existing or requested repository root is not canonical and readable",
                      "remediation",
                      "restore the exact repository root or explicitly archive the old store "
                      "before rebinding");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_STORE_PROJECT_ROOT_UNRESOLVABLE",
            "validate_existing_store_project_identity", "route", db_path, 0,
            "the existing or requested repository root is not canonical and readable",
            "restore the exact repository root or explicitly archive the old store before "
            "rebinding");
        free(existing_root);
        free(requested_root);
        cbm_store_free_projects(projects, project_count);
        return CBM_NOT_FOUND;
    }
    cbm_normalize_path_sep(existing_root);
    cbm_normalize_path_sep(requested_root);
#ifdef _WIN32
    bool roots_match = _stricmp(existing_root, requested_root) == 0;
#else
    bool roots_match = strcmp(existing_root, requested_root) == 0;
#endif
    if (!roots_match) {
        char message[PL_ERROR_MESSAGE];
        (void)snprintf(message, sizeof(message),
                       "project '%s' is bound to root '%s', not requested root '%s'",
                       p->project_name, existing_root, requested_root);
        cbm_log_error(
            "pipeline.route_failed", "code", "CBM_PIPELINE_STORE_PROJECT_ROOT_MISMATCH",
            "operation", "validate_existing_store_project_identity", "store_path", db_path,
            "project", p->project_name, "existing_root", existing_root, "requested_root",
            requested_root, "publication_started", "false", "message", message, "remediation",
            "use a distinct project name or perform an explicit archive/delete/rebind transaction");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_STORE_PROJECT_ROOT_MISMATCH",
            "validate_existing_store_project_identity", "route", db_path, 0, message,
            "use a distinct project name or perform an explicit archive/delete/rebind transaction");
        free(existing_root);
        free(requested_root);
        cbm_store_free_projects(projects, project_count);
        return CBM_NOT_FOUND;
    }

    free(existing_root);
    free(requested_root);
    cbm_store_free_projects(projects, project_count);
    return 0;
}

static int preserve_existing_adr(cbm_pipeline_t *p, cbm_store_t *store, const char *db_path) {
    cbm_adr_t existing = {0};
    int rc = cbm_store_adr_get(store, p->project_name, &existing);
    if (rc == CBM_STORE_NOT_FOUND) {
        return 0;
    }
    if (rc != CBM_STORE_OK) {
        const char *detail = cbm_store_error(store);
        cbm_log_error("pipeline.route_failed", "code", "CBM_PIPELINE_ADR_READ_FAILED", "operation",
                      "preserve_existing_adr", "store_path", db_path, "project", p->project_name,
                      "publication_started", "false", "message",
                      detail && detail[0] ? detail : "the existing ADR could not be read",
                      "remediation",
                      "preserve the complete store family, inspect the SQLite diagnostic, and "
                      "retry");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_ADR_READ_FAILED", "preserve_existing_adr", "route", db_path, 0,
            detail && detail[0] ? detail : "the existing ADR could not be read",
            "preserve the complete store family, inspect the SQLite diagnostic, and retry");
        return CBM_NOT_FOUND;
    }

    char *saved_adr = NULL;
    if (existing.content) {
        saved_adr = strdup(existing.content);
        if (!saved_adr) {
            cbm_store_adr_free(&existing);
            cbm_log_error("pipeline.route_failed", "code", "CBM_PIPELINE_ADR_ALLOC_FAILED",
                          "operation", "preserve_existing_adr", "store_path", db_path, "project",
                          p->project_name, "publication_started", "false", "message",
                          "the existing ADR could not be retained in memory", "remediation",
                          "free memory and retry the complete corpus");
            cbm_pipeline_record_fatal_error(p, "CBM_PIPELINE_ADR_ALLOC_FAILED",
                                            "preserve_existing_adr", "route", db_path, 0,
                                            "the existing ADR could not be retained in memory",
                                            "free memory and retry the complete corpus");
            return CBM_NOT_FOUND;
        }
    }
    free(p->saved_adr);
    p->saved_adr = saved_adr;
    cbm_store_adr_free(&existing);
    return 0;
}

static int record_path_probe_failure(cbm_pipeline_t *p, const char *event, const char *code,
                                     const char *operation, const char *phase, const char *path,
                                     unsigned long native_error, const char *message,
                                     const char *remediation) {
    char native_error_text[32];
    (void)snprintf(native_error_text, sizeof(native_error_text), "%lu", native_error);
    cbm_log_error(event, "code", code, "operation", operation, "path", path, "native_error_kind",
                  "win32", "native_error", native_error_text, "publication_started", "false",
                  "message", message, "remediation", remediation);
    cbm_pipeline_record_fatal_error(p, code, operation, phase, path, 0, message, remediation);
    return CBM_NOT_FOUND;
}

static int pipeline_close_store(cbm_pipeline_t *p, cbm_store_t **store,
                                const char *operation, const char *phase,
                                const char *fallback_path) {
    cbm_store_close_result_t result;
    cbm_store_close_status_t status = cbm_store_close(store, &result);
    if (status == CBM_STORE_CLOSE_OK) {
        return 0;
    }

    char status_text[32];
    char sqlite_error_text[32];
    char outstanding_text[32];
    (void)snprintf(status_text, sizeof(status_text), "%d", (int)status);
    (void)snprintf(sqlite_error_text, sizeof(sqlite_error_text), "%d",
                   result.sqlite_close_code);
    (void)snprintf(outstanding_text, sizeof(outstanding_text), "%llu",
                   (unsigned long long)result.outstanding_statement_count);
    const char *path = result.db_path[0] ? result.db_path : fallback_path;
    cbm_log_error(
        "pipeline.store_close_failed", "code", "CBM_PIPELINE_STORE_CLOSE_FAILED",
        "operation", operation, "phase", phase, "store_path", path ? path : "",
        "close_status", status_text, "sqlite_error", sqlite_error_text,
        "connection_destroyed", result.connection_destroyed ? "true" : "false",
        "outstanding_statements", outstanding_text, "first_sql_sha256",
        result.first_outstanding_sql_sha256, "first_sql", result.first_outstanding_sql,
        "remediation",
        "preserve the exact store owner and complete the reported SQLite resource before "
        "retrying the generation");
    cbm_pipeline_record_fatal_error(
        p, "CBM_PIPELINE_STORE_CLOSE_FAILED", operation, phase, path ? path : "", 0,
        "the pipeline store connection was not closed through the exact physical-close contract",
        "preserve the exact store owner and complete the reported SQLite resource before "
        "retrying the generation");
    if (!result.connection_destroyed || (store && *store)) {
        /* The pipeline API has no durable store-owner result channel. Returning
         * would drop this stack-local pointer while SQLite still owns the
         * connection, contradicting the preservation diagnostic above. */
        fflush(NULL);
        abort();
    }
    return CBM_NOT_FOUND;
}

/* Before paying for a complete mirrored source generation, prove whether the
 * current repository is byte-identical to the persisted generation. This path
 * is intentionally available only when no complete-row sink is registered:
 * such a sink requires a full materialized stream even for an unchanged graph.
 *
 * Returns 0 when an exact read-only no-op completed, PL_ROUTE_FULL when source
 * capture/routing must continue, or CBM_NOT_FOUND on an unevaluable state. */
static int try_unchanged_before_snapshot(cbm_pipeline_t *p, const cbm_discover_opts_t *opts,
                                         cbm_file_info_t *files, int file_count) {
    if (p->mode == CBM_MODE_FULL || cbm_pipeline_row_sink_active(p)) {
        return PL_ROUTE_FULL;
    }

    char *db_path = resolve_db_path(p);
    if (!db_path) {
        return CBM_NOT_FOUND;
    }
    unsigned long probe_error = 0;
    cbm_path_probe_result_t probe = cbm_path_probe(db_path, &probe_error);
    if (probe == CBM_PATH_PROBE_ABSENT) {
        free(db_path);
        return PL_ROUTE_FULL;
    }
    if (probe == CBM_PATH_PROBE_ERROR) {
        int rc = record_path_probe_failure(
            p, "pipeline.unchanged_failed", "CBM_PIPELINE_UNCHANGED_STORE_PROBE_FAILED",
            "probe_existing_store_before_source_capture", "unchanged_route", db_path, probe_error,
            "the existing store path could not be classified before source capture",
            "preserve the store family, correct the reported native path error, and retry indexing");
        free(db_path);
        return rc;
    }

    cbm_store_t *store = NULL;
    cbm_store_verify_result_t verification = {0};
    cbm_store_verify_status_t status =
        cbm_store_open_path_project_query_verified(db_path, p->project_name, &store, &verification);
    if (status != CBM_STORE_VERIFY_OK || !store) {
        char native_error[32];
        char sqlite_error[32];
        (void)snprintf(native_error, sizeof(native_error), "%lu",
                       (unsigned long)verification.native_error);
        (void)snprintf(sqlite_error, sizeof(sqlite_error), "%d", verification.sqlite_error);
        const char *detail = verification.detail[0]
                                 ? verification.detail
                                 : "the existing store could not be verified before source capture";
        cbm_log_error("pipeline.unchanged_failed", "code",
                      "CBM_PIPELINE_UNCHANGED_STORE_PROVENANCE_FAILED", "operation",
                      verification.operation[0] ? verification.operation : "verify_unchanged_store",
                      "store_path", db_path, "project", p->project_name, "native_error",
                      native_error, "sqlite_error", sqlite_error, "message", detail, "remediation",
                      "preserve the complete store family, repair the exact diagnostic, and retry");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_UNCHANGED_STORE_PROVENANCE_FAILED",
            verification.operation[0] ? verification.operation : "verify_unchanged_store",
            "unchanged_route", db_path, 0, detail,
            "preserve the complete store family, repair the exact diagnostic, and retry");
        if (store) {
            (void)pipeline_close_store(p, &store, "close_unverified_unchanged_store",
                                       "unchanged_route", db_path);
        }
        free(db_path);
        return CBM_NOT_FOUND;
    }
    if (validate_existing_store_project_identity(p, store, db_path) != 0 ||
        preserve_existing_adr(p, store, db_path) != 0) {
        (void)pipeline_close_store(p, &store, "close_rejected_unchanged_store",
                                   "unchanged_route", db_path);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    if (verification.db_sha256[0] == '\0') {
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_UNCHANGED_STORE_DIGEST_MISSING", "verify_unchanged_store",
            "unchanged_route", db_path, 0,
            "verified unchanged routing did not retain the live database SHA-256",
            "preserve the store family and inspect the verifier before retrying");
        (void)pipeline_close_store(p, &store, "close_digestless_unchanged_store",
                                   "unchanged_route", db_path);
        free(db_path);
        return CBM_NOT_FOUND;
    }

    cbm_file_hash_t *hashes = NULL;
    int hash_count = 0;
    if (cbm_store_get_file_hashes(store, p->project_name, &hashes, &hash_count) != CBM_STORE_OK) {
        const char *detail = cbm_store_error(store);
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_UNCHANGED_HASH_ROWS_READ_FAILED", "read_unchanged_file_hashes",
            "unchanged_route", db_path, 0,
            detail && detail[0] ? detail
                                : "the complete persisted file identity set could not be read",
            "preserve the store, repair the exact SQLite diagnostic, and retry");
        cbm_store_free_file_hashes(hashes, hash_count);
        (void)pipeline_close_store(p, &store, "close_failed_hash_read_store",
                                   "unchanged_route", db_path);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    if (hash_count <= 0 || file_count != hash_count) {
        cbm_store_free_file_hashes(hashes, hash_count);
        if (pipeline_close_store(p, &store, "close_changed_file_set_store",
                                 "unchanged_route", db_path) != 0) {
            free(db_path);
            return CBM_NOT_FOUND;
        }
        free(db_path);
        return PL_ROUTE_FULL;
    }

    cbm_pipeline_phase_probe_t verify_probe =
        cbm_pipeline_phase_probe_start(p, "unchanged_source_verify");
    bool unchanged = false;
    int source_status = cbm_source_snapshot_verify_unchanged(p->repo_path, opts, files, file_count,
                                                             hashes, hash_count, &unchanged);
    cbm_pipeline_phase_probe_end(p, "unchanged_source_verify", &verify_probe);
    cbm_store_free_file_hashes(hashes, hash_count);
    if (source_status != 0) {
        (void)pipeline_close_store(p, &store, "close_source_verify_failed_store",
                                   "unchanged_route", db_path);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    if (!unchanged) {
        if (pipeline_close_store(p, &store, "close_changed_source_store",
                                 "unchanged_route", db_path) != 0) {
            free(db_path);
            return CBM_NOT_FOUND;
        }
        free(db_path);
        return PL_ROUTE_FULL;
    }

    bool git_structure_matches = false;
    if (cbm_pipeline_git_structure_matches_store(p, store, &git_structure_matches) != 0) {
        (void)pipeline_close_store(p, &store, "close_git_structure_probe_failed_store",
                                   "unchanged_route", db_path);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    if (!git_structure_matches) {
        if (pipeline_close_store(p, &store, "close_git_structure_changed_store", "unchanged_route",
                                 db_path) != 0) {
            free(db_path);
            return CBM_NOT_FOUND;
        }
        free(db_path);
        return PL_ROUTE_FULL;
    }

    cbm_pipeline_phase_probe_t finish_probe =
        cbm_pipeline_phase_probe_start(p, "unchanged_result_readback");
    int committed_nodes = cbm_store_count_nodes(store, p->project_name);
    int committed_edges = cbm_store_count_edges(store, p->project_name);
    if (committed_nodes < 0 || committed_edges < 0) {
        const char *detail = cbm_store_error(store);
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_UNCHANGED_COUNTS_READ_FAILED", "read_unchanged_graph_counts",
            "unchanged_route", db_path, 0,
            detail && detail[0] ? detail : "the exact persisted graph counts could not be read",
            "preserve the store, repair the exact SQLite diagnostic, and retry");
        (void)pipeline_close_store(p, &store, "close_failed_count_read_store",
                                   "unchanged_route", db_path);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    if (pipeline_close_store(p, &store, "close_unchanged_store", "unchanged_route", db_path) !=
        0) {
        free(db_path);
        return CBM_NOT_FOUND;
    }

    p->routed_store_present = true;
    p->routed_store_bytes = verification.db_bytes;
    (void)snprintf(p->routed_store_sha256, sizeof(p->routed_store_sha256), "%s",
                   verification.db_sha256);
    cbm_pipeline_set_committed_counts(p, committed_nodes, committed_edges);
    if (cbm_pipeline_set_execution_contract(p, CBM_PIPELINE_EXECUTION_ROUTE_UNCHANGED_READ_ONLY,
                                            CBM_PIPELINE_PARALLEL_DISPATCH_EXPECTATION_ZERO) != 0) {
        free(db_path);
        return CBM_NOT_FOUND;
    }
    cbm_pipeline_phase_probe_end(p, "unchanged_result_readback", &finish_probe);
    cbm_log_info("pipeline.route", "path", "unchanged_read_only", "source_snapshot_started",
                 "false", "sqlite_publication_started", "false", "nodes", itoa_buf(committed_nodes),
                 "edges", itoa_buf(committed_edges));
    free(db_path);
    return 0;
}

static const char *route_store_verification_code(
    const cbm_store_verify_result_t *verification) {
    if (!verification) {
        return "CBM_PIPELINE_STORE_PROJECT_PROVENANCE_FAILED";
    }
    if (verification->status == CBM_STORE_VERIFY_SOURCE_MISSING) {
        return "CBM_STORE_SOURCE_MISSING";
    }
    if (verification->status != CBM_STORE_VERIFY_INTEGRITY_FAILED) {
        /* This includes sharing violations, allocation failures, and SQLite
         * I/O failures. Those conditions may clear without any source/store
         * byte change, so resident scheduling must keep them retryable. */
        return "CBM_STORE_VERIFICATION_FAILED";
    }
    if (strstr(verification->operation, "application.user_version.unstamped") != NULL) {
        return "CBM_SCHEMA_VERSION_UNSTAMPED";
    }
    if (strstr(verification->operation, "application.user_version.unsupported") != NULL) {
        return "CBM_SCHEMA_VERSION_UNSUPPORTED";
    }
    if (strstr(verification->operation, "application.project_identity") != NULL ||
        strstr(verification->operation, "application.project_root") != NULL ||
        strstr(verification->operation, "source.project_filename") != NULL ||
        strstr(verification->operation, "source.project_identity") != NULL) {
        return "CBM_STORE_PROVENANCE_FAILED";
    }
    return "CBM_STORE_INTEGRITY_FAILED";
}

/* Try incremental pipeline or select an atomic full reindex.
 * Returns 0 when incremental completed, PL_ROUTE_FULL when a full rebuild is
 * required, or CBM_NOT_FOUND on a terminal error. */
static int try_incremental_or_delete_db(cbm_pipeline_t *p, cbm_file_info_t *files, int file_count) {
    p->routed_store_present = false;
    p->routed_store_bytes = 0;
    p->routed_store_sha256[0] = '\0';
    char *db_path = resolve_db_path(p);
    if (!db_path) {
        return CBM_NOT_FOUND;
    }
    unsigned long probe_error = 0;
    cbm_path_probe_result_t probe = cbm_path_probe(db_path, &probe_error);
    if (probe == CBM_PATH_PROBE_ABSENT) {
        free(db_path);
        return PL_ROUTE_FULL;
    }
    if (probe == CBM_PATH_PROBE_ERROR) {
        int rc = record_path_probe_failure(
            p, "pipeline.route_failed", "CBM_PIPELINE_STORE_PROBE_FAILED",
            "probe_existing_store_for_route", "route", db_path, probe_error,
            "the existing store path could not be classified",
            "preserve the store family, correct the reported native path error, and retry indexing");
        free(db_path);
        return rc;
    }

    /* Provenance admission must be read-only. The ordinary store opener enters
     * SQLite's write-capable lifecycle and can create/checkpoint WAL state even
     * when the identity check subsequently refuses. Freeze and verify the source
     * family first, then compare the incoming root and select the route through
     * the returned read-only query connection. Only the incremental executor may
     * enter a read-write lifecycle after that route is selected. */
    cbm_store_t *identity_store = NULL;
    cbm_store_verify_result_t verification = {0};
    cbm_store_verify_status_t verification_status = cbm_store_open_path_project_query_verified(
        db_path, p->project_name, &identity_store, &verification);
    if (verification_status != CBM_STORE_VERIFY_OK || !identity_store) {
        const char *fault_code = route_store_verification_code(&verification);
        char native_error[32];
        char sqlite_error[32];
        (void)snprintf(native_error, sizeof(native_error), "%lu",
                       (unsigned long)verification.native_error);
        (void)snprintf(sqlite_error, sizeof(sqlite_error), "%d", verification.sqlite_error);
        const char *detail = verification.detail[0]
                                 ? verification.detail
                                 : "the existing store project provenance could not be verified";
        cbm_log_error(
            "pipeline.route_failed", "code", fault_code,
            "operation",
            verification.operation[0] ? verification.operation : "verify_existing_store_project",
            "store_path", db_path, "requested_project", p->project_name, "requested_root",
            p->repo_path, "native_error", native_error, "sqlite_error", sqlite_error, "db_present",
            verification.db_present ? "true" : "false", "wal_present",
            verification.wal_present ? "true" : "false", "shm_present",
            verification.shm_present ? "true" : "false", "family_frozen",
            verification.family_frozen ? "true" : "false", "scratch_cleanup_complete",
            verification.scratch_cleanup_complete ? "true" : "false", "publication_started",
            "false", "message", detail, "remediation",
            "preserve the complete store family and explicitly archive, repair, or delete it "
            "before rebinding");
        cbm_pipeline_record_fatal_error(
            p, fault_code,
            verification.operation[0] ? verification.operation : "verify_existing_store_project",
            "route", db_path, 0, detail,
            "preserve the complete store family and explicitly archive, repair, or delete it "
            "before rebinding");
        if (identity_store) {
            (void)pipeline_close_store(p, &identity_store, "close_unverified_route_store",
                                       "route", db_path);
        }
        free(db_path);
        return CBM_NOT_FOUND;
    }
    if (validate_existing_store_project_identity(p, identity_store, db_path) != 0) {
        (void)pipeline_close_store(p, &identity_store, "close_rejected_route_store", "route",
                                   db_path);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    if (verification.db_sha256[0] == '\0') {
        cbm_log_error(
            "pipeline.route_failed", "code", "CBM_PIPELINE_STORE_IDENTITY_DIGEST_MISSING",
            "operation", "verify_existing_store_project", "store_path", db_path, "project",
            p->project_name, "publication_started", "false", "message",
            "verified routing did not retain the live database SHA-256", "remediation",
            "preserve the complete store family and inspect the verifier before retrying");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_STORE_IDENTITY_DIGEST_MISSING", "verify_existing_store_project",
            "route", db_path, 0, "verified routing did not retain the live database SHA-256",
            "preserve the complete store family and inspect the verifier before retrying");
        (void)pipeline_close_store(p, &identity_store, "close_digestless_route_store", "route",
                                   db_path);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    p->routed_store_present = true;
    p->routed_store_bytes = verification.db_bytes;
    (void)snprintf(p->routed_store_sha256, sizeof(p->routed_store_sha256), "%s",
                   verification.db_sha256);
    if (p->mode == CBM_MODE_FULL) {
        if (verification.wal_present || verification.shm_present) {
            cbm_log_error(
                "pipeline.route_failed", "code", "CBM_PIPELINE_EXPLICIT_FULL_LIVE_SIDECAR_PRESENT",
                "operation", "route_explicit_full", "store_path", db_path, "project",
                p->project_name, "wal_present", verification.wal_present ? "true" : "false",
                "shm_present", verification.shm_present ? "true" : "false", "publication_started",
                "false", "message",
                "the verified live store has an active WAL or shared-memory sidecar", "remediation",
                "finish the active writer, preserve the complete store family, and retry");
            cbm_pipeline_record_fatal_error(
                p, "CBM_PIPELINE_EXPLICIT_FULL_LIVE_SIDECAR_PRESENT", "route_explicit_full",
                "route", db_path, 0,
                "the verified live store has an active WAL or shared-memory sidecar",
                "finish the active writer, preserve the complete store family, and retry");
            (void)pipeline_close_store(p, &identity_store, "close_sidecar_route_store", "route",
                                       db_path);
            free(db_path);
            return CBM_NOT_FOUND;
        }
    }
    if (preserve_existing_adr(p, identity_store, db_path) != 0) {
        (void)pipeline_close_store(p, &identity_store, "close_adr_read_failed_route_store",
                                   "route", db_path);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    cbm_project_t persisted_project = {0};
    if (cbm_store_get_project(identity_store, p->project_name, &persisted_project) != CBM_STORE_OK) {
        const char *detail = cbm_store_error(identity_store);
        cbm_log_error("pipeline.route_failed", "code",
                      "CBM_PIPELINE_INDEX_CAPABILITY_READ_FAILED", "operation",
                      "read_existing_index_capability", "store_path", db_path, "project",
                      p->project_name, "message",
                      detail && detail[0] ? detail
                                          : "the existing index capability could not be read",
                      "remediation", "preserve the store and rebuild it from the exact source");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_INDEX_CAPABILITY_READ_FAILED", "read_existing_index_capability",
            "route", db_path, 0,
            detail && detail[0] ? detail : "the existing index capability could not be read",
            "preserve the store and rebuild it from the exact source");
        cbm_project_free_fields(&persisted_project);
        (void)pipeline_close_store(p, &identity_store, "close_capability_read_failed_store",
                                   "route", db_path);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    bool mode_changed = persisted_project.capability.index_mode != p->mode;
    const char *persisted_mode = cbm_index_mode_name(persisted_project.capability.index_mode);
    cbm_project_free_fields(&persisted_project);
    if (mode_changed) {
        if (pipeline_close_store(p, &identity_store, "close_mode_change_route_store", "route",
                                 db_path) != 0) {
            free(db_path);
            return CBM_NOT_FOUND;
        }
        cbm_log_info("pipeline.route", "path", "full", "reason", "index_mode_changed",
                     "persisted_mode", persisted_mode ? persisted_mode : "invalid",
                     "requested_mode", cbm_index_mode_name(p->mode), "live_store_mutated",
                     "false");
        free(db_path);
        return PL_ROUTE_FULL;
    }
    if (p->mode == CBM_MODE_FULL) {
        if (pipeline_close_store(p, &identity_store, "close_explicit_full_route_store", "route",
                                 db_path) != 0) {
            free(db_path);
            return CBM_NOT_FOUND;
        }
        cbm_log_info("pipeline.route", "path", "full", "reason", "explicit_full_mode",
                     "live_store_mutated", "false");
        cbm_log_info("pipeline.route", "path", "reindex", "action", "build_atomic_replacement");
        free(db_path);
        return PL_ROUTE_FULL;
    }
    cbm_file_hash_t *hashes = NULL;
    int hash_count = 0;
    int hash_rc = cbm_store_get_file_hashes(identity_store, p->project_name, &hashes, &hash_count);
    if (hash_rc != CBM_STORE_OK) {
        const char *detail = cbm_store_error(identity_store);
        cbm_log_error(
            "pipeline.route_failed", "code", "CBM_PIPELINE_HASH_ROWS_READ_FAILED", "operation",
            "read_verified_file_hashes", "path", db_path, "message",
            detail && detail[0] ? detail
                                : "the complete incremental identity set could not be read",
            "remediation", "preserve the store, inspect the SQLite diagnostic, and retry");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_HASH_ROWS_READ_FAILED", "read_verified_file_hashes", "route", db_path,
            0,
            detail && detail[0] ? detail
                                : "the complete incremental identity set could not be read",
            "preserve the store, inspect the SQLite diagnostic, and retry");
        cbm_store_free_file_hashes(hashes, hash_count);
        (void)pipeline_close_store(p, &identity_store, "close_hash_read_failed_route_store",
                                   "route", db_path);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    if (hash_count > 0 && file_count <= hash_count + (hash_count / PAIR_LEN)) {
        cbm_log_info("pipeline.route", "path", "incremental", "stored_hashes",
                     itoa_buf(hash_count));
        cbm_pipeline_phase_probe_t incremental_probe =
            cbm_pipeline_phase_probe_start(p, "incremental_total");
        int rc = cbm_pipeline_run_incremental(p, db_path, files, file_count, identity_store, hashes,
                                              hash_count);
        identity_store = NULL;
        hashes = NULL;
        cbm_pipeline_phase_probe_end(p, "incremental_total", &incremental_probe);
        if (rc == CBM_INCREMENTAL_REBUILD_REQUIRED) {
            cbm_log_info("pipeline.route", "path", "full", "reason",
                         "incremental_content_contract_requires_rebuild");
        } else {
            free(db_path);
            return rc;
        }
    }
    cbm_store_free_file_hashes(hashes, hash_count);
    if (pipeline_close_store(p, &identity_store, "close_full_rebuild_route_store", "route",
                             db_path) != 0) {
        free(db_path);
        return CBM_NOT_FOUND;
    }
    if (hash_count > 0) {
        cbm_log_info("pipeline.route", "path", "mode_change_reindex", "stored_hashes",
                     itoa_buf(hash_count), "discovered", itoa_buf(file_count));
    }
    cbm_log_info("pipeline.route", "path", "reindex", "action", "build_atomic_replacement");
    free(db_path);
    return PL_ROUTE_FULL;
}

static int remove_optional_pipeline_file(const char *path, const char *code) {
    unsigned long before_error = 0;
    cbm_path_probe_result_t before = cbm_path_probe(path, &before_error);
    if (before == CBM_PATH_PROBE_ABSENT) {
        return 0;
    }
    if (before == CBM_PATH_PROBE_ERROR) {
        char native_error[32];
        (void)snprintf(native_error, sizeof(native_error), "%lu", before_error);
        cbm_log_error("pipeline.persist_failed", "code", code, "path", path,
                      "native_error_kind", "win32", "native_error", native_error, "message",
                      "a transaction-owned SQLite path could not be classified before removal",
                      "remediation", "preserve the path, resolve the native probe error, and retry");
        return CBM_NOT_FOUND;
    }
    errno = 0;
    if (cbm_unlink(path) == 0) {
        unsigned long after_error = 0;
        cbm_path_probe_result_t after = cbm_path_probe(path, &after_error);
        if (after == CBM_PATH_PROBE_ABSENT) {
            return 0;
        }
        char native_error[32];
        (void)snprintf(native_error, sizeof(native_error), "%lu", after_error);
        cbm_log_error("pipeline.persist_failed", "code", code, "path", path,
                      "native_error_kind", "win32", "native_error", native_error, "message",
                      after == CBM_PATH_PROBE_PRESENT
                          ? "a removed transaction-owned SQLite path remained present on readback"
                          : "transaction-owned SQLite path absence could not be proven after removal",
                      "remediation", "preserve the remaining namespace state and retry only after inspection");
        return CBM_NOT_FOUND;
    }
    cbm_log_error("pipeline.persist_failed", "code", code, "path", path, "message",
                  "a stale or sidecar file could not be removed", "remediation",
                  "close processes holding the store and retry indexing");
    return CBM_NOT_FOUND;
}

int cbm_pipeline_verify_live_store_before_publication(cbm_pipeline_t *p, const char *db_path,
                                                      const char *live_wal,
                                                      const char *live_shm) {
    unsigned long wal_probe_error = 0;
    cbm_path_probe_result_t wal_probe = cbm_path_probe(live_wal, &wal_probe_error);
    if (wal_probe == CBM_PATH_PROBE_ERROR) {
        return record_path_probe_failure(
            p, "pipeline.persist_failed", "CBM_PIPELINE_LIVE_WAL_PROBE_FAILED",
            "probe_live_wal_before_publication", "persist", live_wal, wal_probe_error,
            "the live WAL path could not be classified before publication",
            "preserve the complete store family, correct the reported native path error, and retry");
    }
    unsigned long shm_probe_error = 0;
    cbm_path_probe_result_t shm_probe = cbm_path_probe(live_shm, &shm_probe_error);
    if (shm_probe == CBM_PATH_PROBE_ERROR) {
        return record_path_probe_failure(
            p, "pipeline.persist_failed", "CBM_PIPELINE_LIVE_SHM_PROBE_FAILED",
            "probe_live_shm_before_publication", "persist", live_shm, shm_probe_error,
            "the live shared-memory path could not be classified before publication",
            "preserve the complete store family, correct the reported native path error, and retry");
    }
    if (wal_probe == CBM_PATH_PROBE_PRESENT || shm_probe == CBM_PATH_PROBE_PRESENT) {
        cbm_log_error("pipeline.persist_failed", "code",
                      "CBM_PIPELINE_LIVE_STORE_SIDECAR_APPEARED",
                      "operation", "verify_live_store_before_publication", "path", db_path,
                      "wal_present",
                      wal_probe == CBM_PATH_PROBE_PRESENT ? "true" : "false", "shm_present",
                      shm_probe == CBM_PATH_PROBE_PRESENT ? "true" : "false",
                      "publication_started", "false", "message",
                      "the live store acquired a WAL or shared-memory sidecar after normalization",
                      "remediation",
                      "preserve the complete family, identify the later SQLite owner, and retry "
                      "only after a fresh quiescent normalization");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_LIVE_STORE_SIDECAR_APPEARED",
            "verify_live_store_before_publication", "persist", db_path, 0,
            "the live store acquired a WAL or shared-memory sidecar after normalization",
            "preserve the complete family, identify the later SQLite owner, and retry only after "
            "a fresh quiescent normalization");
        return CBM_NOT_FOUND;
    }

    unsigned long db_probe_error = 0;
    cbm_path_probe_result_t db_probe = cbm_path_probe(db_path, &db_probe_error);
    if (db_probe == CBM_PATH_PROBE_ERROR) {
        return record_path_probe_failure(
            p, "pipeline.persist_failed", "CBM_PIPELINE_LIVE_STORE_PROBE_FAILED",
            "probe_live_store_before_publication", "persist", db_path, db_probe_error,
            "the live database path could not be classified before publication",
            "preserve the complete store family, correct the reported native path error, and retry");
    }
    if (!p->routed_store_present) {
        if (db_probe == CBM_PATH_PROBE_ABSENT) {
            return 0;
        }
        cbm_log_error(
            "pipeline.persist_failed", "code", "CBM_PIPELINE_LIVE_STORE_APPEARED", "operation",
            "verify_live_store_before_publication", "path", db_path, "publication_started", "false",
            "message", "a live database appeared after routing selected an absent destination",
            "remediation", "preserve the unexpected store, use a distinct project name, and retry");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_LIVE_STORE_APPEARED", "verify_live_store_before_publication",
            "persist", db_path, 0,
            "a live database appeared after routing selected an absent destination",
            "preserve the unexpected store, use a distinct project name, and retry");
        return CBM_NOT_FOUND;
    }
    if (db_probe == CBM_PATH_PROBE_ABSENT) {
        cbm_log_error(
            "pipeline.persist_failed", "code", "CBM_PIPELINE_LIVE_STORE_DISAPPEARED", "operation",
            "verify_live_store_before_publication", "path", db_path, "publication_started", "false",
            "message", "the routed live database disappeared before publication", "remediation",
            "preserve the staged store, restore or explicitly archive the routed generation, and "
            "retry");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_LIVE_STORE_DISAPPEARED", "verify_live_store_before_publication",
            "persist", db_path, 0, "the routed live database disappeared before publication",
            "preserve the staged store, restore or explicitly archive the routed generation, and "
            "retry");
        return CBM_NOT_FOUND;
    }

    cbm_store_verify_result_t verification = {0};
    cbm_store_verify_status_t status =
        cbm_store_verify_path_project_snapshot(db_path, p->project_name, &verification);
    if (status != CBM_STORE_VERIFY_OK) {
        char native_error[32];
        char sqlite_error[32];
        (void)snprintf(native_error, sizeof(native_error), "%lu",
                       (unsigned long)verification.native_error);
        (void)snprintf(sqlite_error, sizeof(sqlite_error), "%d", verification.sqlite_error);
        cbm_log_error(
            "pipeline.persist_failed", "code", "CBM_PIPELINE_LIVE_STORE_REVERIFY_FAILED",
            "operation",
            verification.operation[0] ? verification.operation
                                      : "verify_live_store_before_publication",
            "path", db_path, "project", p->project_name, "native_error_kind", "win32",
            "native_error", native_error, "sqlite_error", sqlite_error, "wal_present",
            verification.wal_present ? "true" : "false", "shm_present",
            verification.shm_present ? "true" : "false", "publication_started", "false", "message",
            verification.detail[0] ? verification.detail : "the live store could not be reverified",
            "remediation",
            "preserve the complete live family and staged store, resolve the reported conflict, "
            "and retry");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_LIVE_STORE_REVERIFY_FAILED",
            verification.operation[0] ? verification.operation
                                      : "verify_live_store_before_publication",
            "persist", db_path, 0,
            verification.detail[0] ? verification.detail : "the live store could not be reverified",
            "preserve the complete live family, resolve the reported conflict, and retry");
        return CBM_NOT_FOUND;
    }
    if (verification.wal_present || verification.shm_present) {
        cbm_log_error("pipeline.persist_failed", "code",
                      "CBM_PIPELINE_LIVE_STORE_SIDECAR_APPEARED",
                      "operation", "verify_live_store_before_publication", "path", db_path,
                      "wal_present", verification.wal_present ? "true" : "false", "shm_present",
                      verification.shm_present ? "true" : "false", "publication_started", "false",
                      "message",
                      "the frozen live-store verification observed a WAL or shared-memory "
                      "sidecar after normalization",
                      "remediation",
                      "preserve the complete family, identify the later SQLite owner, and retry "
                      "only after a fresh quiescent normalization");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_LIVE_STORE_SIDECAR_APPEARED",
            "verify_live_store_before_publication", "persist", db_path, 0,
            "the frozen live-store verification observed a WAL or shared-memory sidecar after "
            "normalization",
            "preserve the complete family, identify the later SQLite owner, and retry only after "
            "a fresh quiescent normalization");
        return CBM_NOT_FOUND;
    }
    if (verification.db_bytes != p->routed_store_bytes ||
        strcmp(verification.db_sha256, p->routed_store_sha256) != 0) {
        char expected_bytes[32];
        char observed_bytes[32];
        (void)snprintf(expected_bytes, sizeof(expected_bytes), "%llu",
                       (unsigned long long)p->routed_store_bytes);
        (void)snprintf(observed_bytes, sizeof(observed_bytes), "%llu",
                       (unsigned long long)verification.db_bytes);
        cbm_log_error(
            "pipeline.persist_failed", "code", "CBM_PIPELINE_LIVE_STORE_PROVENANCE_DRIFT",
            "operation", "verify_live_store_before_publication", "path", db_path, "project",
            p->project_name, "expected_bytes", expected_bytes, "observed_bytes", observed_bytes,
            "expected_sha256", p->routed_store_sha256, "observed_sha256", verification.db_sha256,
            "publication_started", "false", "message",
            "the live database bytes changed after the full rebuild was routed", "remediation",
            "preserve both generations, reconcile the concurrent publisher, and retry from the "
            "current live store");
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_LIVE_STORE_PROVENANCE_DRIFT", "verify_live_store_before_publication",
            "persist", db_path, (size_t)verification.db_bytes,
            "the live database bytes changed after the full rebuild was routed",
            "preserve both generations, reconcile the concurrent publisher, and retry from the "
            "current live store");
        return CBM_NOT_FOUND;
    }
    return 0;
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
    unsigned long stage_wal_probe_error = 0;
    unsigned long stage_shm_probe_error = 0;
    cbm_path_probe_result_t stage_wal_probe =
        cbm_path_probe(stage_wal, &stage_wal_probe_error);
    cbm_path_probe_result_t stage_shm_probe =
        cbm_path_probe(stage_shm, &stage_shm_probe_error);
    if (stage_wal_probe == CBM_PATH_PROBE_ERROR ||
        stage_shm_probe == CBM_PATH_PROBE_ERROR) {
        const char *failed_path = stage_wal_probe == CBM_PATH_PROBE_ERROR ? stage_wal : stage_shm;
        unsigned long native_error = stage_wal_probe == CBM_PATH_PROBE_ERROR
                                         ? stage_wal_probe_error
                                         : stage_shm_probe_error;
        (void)record_path_probe_failure(
            p, "pipeline.persist_failed", "CBM_PIPELINE_STAGE_SIDECAR_PROBE_FAILED",
            "probe_generated_stage_sidecars", "persist", failed_path, native_error,
            "a generated stage sidecar path could not be classified",
            "preserve the path, resolve the native probe error, and retry indexing");
        free(stage);
        free(stage_wal);
        free(stage_shm);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    if (stage_wal_probe == CBM_PATH_PROBE_PRESENT ||
        stage_shm_probe == CBM_PATH_PROBE_PRESENT) {
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
    cbm_pipeline_phase_probe_t dump_probe = cbm_pipeline_phase_probe_start(p, "dump");
    int rc = cbm_gbuf_dump_to_sqlite(p->gbuf, stage);
    cbm_pipeline_phase_probe_end(p, "dump", &dump_probe);
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
    cbm_pipeline_phase_probe_t reopen_probe = cbm_pipeline_phase_probe_start(p, "persist_reopen");
    cbm_store_t *hash_store = cbm_store_open_path(stage);
    cbm_pipeline_phase_probe_end(p, "persist_reopen", &reopen_probe);
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

        cbm_pipeline_phase_probe_t checkpoint_probe =
            cbm_pipeline_phase_probe_start(p, "persist_checkpoint");
        if (final_rc == 0) {
            cbm_store_normalize_result_t normalization;
            if (cbm_store_exec(hash_store, "PRAGMA optimize;") != CBM_STORE_OK ||
                cbm_store_normalize_journal_mode_delete(hash_store, &normalization) !=
                    CBM_STORE_NORMALIZE_OK) {
                final_rc = CBM_NOT_FOUND;
            }
        }
        cbm_pipeline_phase_probe_end(p, "persist_checkpoint", &checkpoint_probe);
        cbm_pipeline_phase_probe_t integrity_probe =
            cbm_pipeline_phase_probe_start(p, "persist_integrity");
        if (final_rc == 0 && !cbm_store_check_integrity(hash_store)) {
            final_rc = CBM_NOT_FOUND;
        }
        cbm_pipeline_phase_probe_end(p, "persist_integrity", &integrity_probe);
        cbm_pipeline_phase_probe_t sink_probe =
            cbm_pipeline_phase_probe_start(p, "persist_row_sink");
        if (final_rc == 0) {
            cbm_index_capability_t capability = {0};
            if (cbm_gbuf_get_index_capability(p->gbuf, &capability) != 0) {
                final_rc = CBM_NOT_FOUND;
            } else {
                final_rc =
                    cbm_pipeline_complete_row_sink(p, (size_t)file_count, &capability);
            }
        }
        cbm_pipeline_phase_probe_end(p, "persist_row_sink", &sink_probe);
        cbm_pipeline_phase_probe_t close_probe = cbm_pipeline_phase_probe_start(p, "persist_close");
        if (pipeline_close_store(p, &hash_store, "close_staged_publication_store", "persist",
                                 stage) != 0) {
            final_rc = CBM_NOT_FOUND;
        }
        cbm_pipeline_phase_probe_end(p, "persist_close", &close_probe);
        cbm_log_info("pass.timing", "pass", "persist_hashes", "files", itoa_buf(file_count));
    }
    bool preserve_unevaluable_stage = false;
    bool stage_sidecar_present = false;
    if (final_rc == 0) {
        stage_wal_probe_error = 0;
        stage_shm_probe_error = 0;
        stage_wal_probe = cbm_path_probe(stage_wal, &stage_wal_probe_error);
        stage_shm_probe = cbm_path_probe(stage_shm, &stage_shm_probe_error);
        preserve_unevaluable_stage = stage_wal_probe == CBM_PATH_PROBE_ERROR ||
                                     stage_shm_probe == CBM_PATH_PROBE_ERROR;
        stage_sidecar_present = stage_wal_probe == CBM_PATH_PROBE_PRESENT ||
                                stage_shm_probe == CBM_PATH_PROBE_PRESENT;
        if (preserve_unevaluable_stage) {
            const char *failed_path =
                stage_wal_probe == CBM_PATH_PROBE_ERROR ? stage_wal : stage_shm;
            unsigned long native_error = stage_wal_probe == CBM_PATH_PROBE_ERROR
                                             ? stage_wal_probe_error
                                             : stage_shm_probe_error;
            (void)record_path_probe_failure(
                p, "pipeline.persist_failed", "CBM_PIPELINE_STAGE_SIDECAR_PROBE_FAILED",
                "readback_closed_stage_sidecars", "persist", failed_path, native_error,
                "closed stage sidecar absence could not be proven",
                "preserve the staged family, resolve the native probe error, and retry indexing");
        }
    }
    if (final_rc != 0 || stage_sidecar_present || preserve_unevaluable_stage) {
        if (final_rc == 0 && stage_sidecar_present) {
            cbm_log_error("pipeline.persist_failed", "code", "CBM_PIPELINE_STAGE_WAL_REMAINS",
                          "path", stage, "message",
                          "the closed replacement still has a WAL or shared-memory sidecar",
                          "remediation", "inspect SQLite checkpoint errors and retry");
        }
        if (hash_store || preserve_unevaluable_stage) {
            cbm_log_error(
                "pipeline.persist_failed", "code", "CBM_PIPELINE_STAGE_CLOSE_PRESERVED", "path",
                stage, "message",
                preserve_unevaluable_stage
                    ? "the staged publication is preserved because physical sidecar state is unevaluable"
                    : "the staged publication and its SQLite connection remain owned after exact physical close failed",
                "remediation",
                "preserve every staged-family byte and inspect the preceding close diagnostic");
        } else {
            (void)remove_optional_pipeline_file(stage,
                                                "CBM_PIPELINE_FAILED_STAGE_REMOVE_FAILED");
            (void)remove_optional_pipeline_file(stage_wal,
                                                "CBM_PIPELINE_FAILED_STAGE_WAL_REMOVE_FAILED");
            (void)remove_optional_pipeline_file(stage_shm,
                                                "CBM_PIPELINE_FAILED_STAGE_SHM_REMOVE_FAILED");
        }
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
    cbm_pipeline_phase_probe_t verify_probe =
        cbm_pipeline_phase_probe_start(p, "persist_verify_live_store");
    if (cbm_pipeline_verify_live_store_before_publication(p, db_path, live_wal, live_shm) != 0) {
        cbm_pipeline_phase_probe_end(p, "persist_verify_live_store", &verify_probe);
        (void)remove_optional_pipeline_file(stage, "CBM_PIPELINE_FAILED_STAGE_REMOVE_FAILED");
        free(live_wal);
        free(live_shm);
        free(stage);
        free(stage_wal);
        free(stage_shm);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    cbm_pipeline_phase_probe_end(p, "persist_verify_live_store", &verify_probe);
    cbm_pipeline_phase_probe_t swap_probe =
        cbm_pipeline_phase_probe_start(p, "persist_atomic_swap");
    if (cbm_rename_replace(stage, db_path) != 0) {
        cbm_pipeline_phase_probe_end(p, "persist_atomic_swap", &swap_probe);
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
    cbm_pipeline_phase_probe_end(p, "persist_atomic_swap", &swap_probe);
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
    cbm_thread_t gh_thread = {0};
    bool gh_threaded = false;
    gh_compute_arg_t gh_arg = {.repo_path = ctx->repo_path, .result = &gh_result};

    if (p->mode != CBM_MODE_FAST) {
        int worker_count = effective_worker_count(true);
        if (worker_count <= 0) {
            return reject_invalid_worker_count(p, "githistory", worker_count);
        }
        if (worker_count > SKIP_ONE) {
            if (cbm_thread_create(&gh_thread, 0, gh_compute_thread_fn, &gh_arg) == 0) {
                gh_threaded = true;
            } else {
                cbm_log_error("pipeline.githistory.dispatch_failed", "code",
                              "CBM_GITHISTORY_THREAD_CREATE_FAILED", "error_domain",
                              itoa_buf(gh_thread.error_domain), "error_code",
                              itoa_buf((int)gh_thread.error_code), "message",
                              "git-history worker thread could not be admitted", "remediation",
                              "inspect worker resource limits and retry only after the resource "
                              "condition changes");
                return CBM_NOT_FOUND;
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
        if (cbm_thread_join(&gh_thread) != 0) {
            cbm_log_error("pipeline.githistory.dispatch_failed", "code",
                          "CBM_GITHISTORY_THREAD_JOIN_FAILED", "error_domain",
                          itoa_buf(gh_thread.error_domain), "error_code",
                          itoa_buf((int)gh_thread.error_code), "message",
                          "git-history worker thread could not be joined", "remediation",
                          "inspect worker thread diagnostics and retry unchanged only after the "
                          "thread state is understood");
            free(gh_result.couplings);
            free(gh_result.file_temporal);
            return CBM_NOT_FOUND;
        }
        cbm_log_info("pass.timing", "pass", "githistory_compute", "elapsed_ms",
                     itoa_buf((int)elapsed_ms(t_gh)));
    }

    int gh_edges = 0;
    if (gh_result.count > 0 || gh_result.file_temporal_count > 0) {
        gh_edges = cbm_pipeline_githistory_apply(ctx, &gh_result);
    }
    if (gh_edges < 0) {
        free(gh_result.couplings);
        free(gh_result.file_temporal);
        return CBM_NOT_FOUND;
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
    cbm_pipeline_phase_probe_t tests_probe = cbm_pipeline_phase_probe_start(p, "tests");
    int rc = cbm_pipeline_pass_tests(ctx, files, file_count);
    cbm_pipeline_phase_probe_end(p, "tests", &tests_probe);
    CBM_PROF_END_N("pipeline", "pass_tests", t_tests, file_count);
    cbm_log_info("pass.timing", "pass", "tests", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    if (rc == 0 && !check_cancel(p)) {
        CBM_PROF_START(t_gh);
        cbm_pipeline_phase_probe_t history_probe = cbm_pipeline_phase_probe_start(p, "githistory");
        rc = run_githistory(p, ctx);
        cbm_pipeline_phase_probe_end(p, "githistory", &history_probe);
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
    if (cbm_worker_progress_advance_unit(CBM_WORKER_PROGRESS_STAGE_ENRICH, "enrich", 2) != 0) {
        cbm_pipeline_record_fatal_error(
            p, "CBM_INDEX_WORKER_PROGRESS_WRITE_FAILED", "publish_enrichment_progress",
            "enrich", p->repo_path, 2,
            "the completed history enrichment could not advance semantic progress",
            "preserve the worker workspace, repair the progress stream, and retry the unchanged "
            "repository");
        return CBM_NOT_FOUND;
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
        if (rc == 0 &&
            cbm_worker_progress_advance_unit(CBM_WORKER_PROGRESS_STAGE_PERSIST, "persist", 1) !=
                0) {
            cbm_pipeline_record_fatal_error(
                p, "CBM_INDEX_WORKER_PROGRESS_WRITE_FAILED", "publish_persist_progress",
                "persist", p->repo_path, 1,
                "the completed store publication could not advance semantic progress",
                "preserve the worker workspace, repair the progress stream, and retry the "
                "unchanged repository");
            return CBM_NOT_FOUND;
        }
    }
    return rc;
}

/* Run structure + the single source-slab-backed extraction path. A one-worker
 * repository uses the same implementation as a large repository; corpus size
 * never selects an older disk-rereading semantic path. */
static int run_extraction_phase(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx,
                                const cbm_file_info_t *files, int file_count) {
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    CBM_PROF_START(t_struct);
    cbm_pipeline_phase_probe_t structure_probe = cbm_pipeline_phase_probe_start(p, "structure");
    if (pass_structure(p, files, file_count, ctx->source_slab) != 0) {
        cbm_pipeline_phase_probe_end(p, "structure", &structure_probe);
        return CBM_NOT_FOUND;
    }
    cbm_pipeline_phase_probe_end(p, "structure", &structure_probe);
    CBM_PROF_END_N("pipeline", "pass_structure", t_struct, file_count);
    cbm_log_info("pass.timing", "pass", "structure", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    if (check_cancel(p)) {
        return CBM_NOT_FOUND;
    }
    if (cbm_pxc_prepare_rust_manifest(ctx) != 0) {
        return CBM_NOT_FOUND;
    }
    int worker_count = effective_worker_count(true);
    if (worker_count <= 0) {
        cbm_pxc_destroy_rust_manifest(ctx);
        return reject_invalid_worker_count(p, "extraction", worker_count);
    }
    CBM_PROF_START(t_extract_total);
    int rc = run_parallel_pipeline(p, ctx, files, file_count, worker_count, &t);
    CBM_PROF_END_N("pipeline", "2_extraction_total", t_extract_total, file_count);
    cbm_pxc_destroy_rust_manifest(ctx);
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
    cbm_compile_context_index_free(p->compile_contexts);
    p->compile_contexts = NULL;
    p->current_source_slab = NULL;
    clear_compile_context_diagnostics(p);

    CBM_PROF_START(t_pipeline_total);
    struct timespec t0;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t0);
    p->phase_metric_count = 0;
    p->phase_metrics_complete = true;
    p->parallel_dispatch_count = 0;
    p->parallel_dispatches_complete = true;
    p->execution_route = CBM_PIPELINE_EXECUTION_ROUTE_UNKNOWN;
    p->parallel_dispatch_expectation = CBM_PIPELINE_PARALLEL_DISPATCH_EXPECTATION_UNKNOWN;
    cbm_pipeline_phase_probe_t total_probe = cbm_pipeline_phase_probe_start(p, "total");
    cbm_path_alias_collection_t *path_aliases = NULL;
    cbm_source_snapshot_t source_snapshot = {0};
    cbm_source_slab_t source_slab = {0};
    cbm_file_info_t *source_files = NULL;
    int source_count = 0;
    uint64_t source_progress_total = 0;
    int rc = 0;

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

    int admitted_worker_count = effective_worker_count(true);
    if (admitted_worker_count <= 0) {
        rc = reject_invalid_worker_count(p, "worker_config", admitted_worker_count);
        goto cleanup;
    }

    /* Phase 1: Discover files */
    CBM_PROF_START(t_discover);
    cbm_pipeline_phase_probe_t discover_probe = cbm_pipeline_phase_probe_start(p, "discovery");
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
    rc = cbm_discover_ex(p->repo_path, &opts, &files, &file_count, &p->excluded_dirs,
                         &p->excluded_count);
    if (rc != 0) {
        cbm_log_error("pipeline.err", "phase", "discover", "rc", itoa_buf(rc));
    }
    CBM_PROF_END_N("pipeline", "1_discover", t_discover, file_count);
    cbm_pipeline_phase_probe_end(p, "discovery", &discover_probe);
    cbm_log_info("pipeline.discover", "files", itoa_buf(file_count), "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t0)));
    if (rc != 0 || check_cancel(p)) {
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }

    for (int i = 0; i < file_count; i++) {
        if (!files[i].auxiliary) {
            source_count++;
        }
    }
    if (source_count == 0) {
        cbm_log_error("pipeline.err", "phase", "discovery", "code",
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
    source_progress_total = (uint64_t)file_count + (uint64_t)source_count;
    if (pipeline_progress_publish(p, CBM_WORKER_PROGRESS_STAGE_DISCOVERY, "discovery", 1, 1, 1,
                                  "complete", 1, 1) != 0) {
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }

    cbm_pipeline_phase_probe_t unchanged_route_probe =
        cbm_pipeline_phase_probe_start(p, "unchanged_route");
    rc = try_unchanged_before_snapshot(p, &opts, files, file_count);
    cbm_pipeline_phase_probe_end(p, "unchanged_route", &unchanged_route_probe);
    if (rc == 0 || rc == CBM_NOT_FOUND) {
        goto cleanup;
    }
    if (rc != PL_ROUTE_FULL) {
        cbm_log_error("pipeline.err", "code", "CBM_PIPELINE_PRE_SNAPSHOT_ROUTE_INVALID", "phase",
                      "unchanged_route", "message",
                      "the pre-snapshot router returned an unknown status", "remediation",
                      "inspect the router implementation before retrying");
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }
    CBM_PROF_START(t_snapshot);
    cbm_pipeline_phase_probe_t snapshot_probe =
        cbm_pipeline_phase_probe_start(p, "source_snapshot");
    char *snapshot_store_path = resolve_db_path(p);
    int snapshot_rc = snapshot_store_path
                          ? cbm_source_snapshot_capture(p->repo_path, snapshot_store_path, &opts,
                                                        files, file_count, source_progress_total,
                                                        &source_snapshot)
                          : CBM_NOT_FOUND;
    if (!snapshot_store_path) {
        cbm_log_error("pipeline.err", "phase", "source_snapshot", "code",
                      "CBM_SOURCE_SNAPSHOT_STORE_UNRESOLVED", "repo_path", p->repo_path,
                      "message", "the exact project store path could not be resolved",
                      "remediation",
                      "configure one writable project store before indexing; no ambient TEMP "
                      "fallback exists");
        cbm_pipeline_record_fatal_error(
            p, "CBM_SOURCE_SNAPSHOT_STORE_UNRESOLVED", "resolve_snapshot_store",
            "source_snapshot", p->repo_path, 0,
            "the exact project store path could not be resolved",
            "configure one writable project store before indexing; no ambient TEMP fallback "
            "exists");
    }
    free(snapshot_store_path);
    cbm_pipeline_phase_probe_end(p, "source_snapshot", &snapshot_probe);
    if (snapshot_rc != 0) {
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }
    p->source_root = source_snapshot.root;
    if (cbm_structured_classify_files(p->repo_path, p->source_root, files, file_count) != 0) {
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }
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

    cbm_pipeline_phase_probe_t source_slab_probe =
        cbm_pipeline_phase_probe_start(p, "source_slab");
    if (cbm_source_slab_build(source_files, source_count, source_progress_total, &source_slab) !=
        0) {
        cbm_pipeline_phase_probe_end(p, "source_slab", &source_slab_probe);
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }
    cbm_pipeline_phase_probe_end(p, "source_slab", &source_slab_probe);
    p->current_source_slab = &source_slab;
    cbm_pipeline_phase_probe_t compile_context_probe =
        cbm_pipeline_phase_probe_start(p, "compile_context");
    cbm_pipeline_ctx_t compile_context_owner = {
        .project_name = p->project_name,
        .repo_path = p->repo_path,
        .source_root = p->source_root,
        .all_files = files,
        .all_file_count = file_count,
        .source_slab = &source_slab,
        .cancelled = &p->cancelled,
        .pipeline = p,
    };
    rc = cbm_compile_context_index_prepare(
        &compile_context_owner, source_files, source_count, p->embedded_compilation_context,
        p->embedded_compilation_context_bytes, &p->compile_contexts);
    cbm_pipeline_phase_probe_end(p, "compile_context", &compile_context_probe);
    if (rc != 0) {
        goto cleanup;
    }
    source_index = 0;
    for (int i = 0; i < file_count; i++) {
        if (files[i].auxiliary) {
            continue;
        }
        if (source_index >= source_count ||
            strcmp(files[i].rel_path, source_files[source_index].rel_path) != 0) {
            cbm_pipeline_record_fatal_error(
                p, "CBM_COMPILE_CONTEXT_SOURCE_VIEW_DRIFT",
                "publish_effective_source_languages", "compile_context",
                files[i].rel_path ? files[i].rel_path : "", (size_t)source_index,
                "the source-only view no longer aligns with complete discovery",
                "preserve the generation and rebuild its immutable source/context index");
            rc = CBM_NOT_FOUND;
            goto cleanup;
        }
        files[i].language = source_files[source_index].language;
        source_index++;
    }
    if (source_index != source_count) {
        cbm_pipeline_record_fatal_error(
            p, "CBM_COMPILE_CONTEXT_SOURCE_VIEW_DRIFT",
            "publish_effective_source_languages", "compile_context", p->repo_path,
            (size_t)source_index,
            "the source-only view contains entries absent from complete discovery",
            "preserve the generation and rebuild its immutable source/context index");
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }
    rc = capture_compile_context_diagnostics(p, source_files, source_count);
    if (rc != 0) {
        goto cleanup;
    }

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
    if (cbm_pipeline_set_execution_contract(p, CBM_PIPELINE_EXECUTION_ROUTE_FULL_MATERIALIZED,
                                            CBM_PIPELINE_PARALLEL_DISPATCH_EXPECTATION_NONZERO) !=
        0) {
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }

    /* Phase 2: Create graph buffer and registry */
    p->gbuf = cbm_gbuf_new(p->project_name, p->repo_path);
    if (!p->gbuf || cbm_gbuf_set_index_mode(p->gbuf, p->mode) != 0) {
        cbm_pipeline_record_fatal_error(
            p, "CBM_PIPELINE_INDEX_MODE_BIND_FAILED", "bind_graph_buffer_index_mode", "graph",
            p->repo_path, 0, "the graph buffer could not retain the requested index mode",
            "inspect the graph-buffer diagnostic and retry the complete index");
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }
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
        .source_slab = &source_slab,
        .gbuf = p->gbuf,
        .registry = p->registry,
        .cancelled = &p->cancelled,
        .pipeline = p, /* so passes can record per-file skips (Track B) */
        .mode = (int)p->mode,
        .path_aliases = path_aliases,
        .compile_contexts = p->compile_contexts,
        .excluded_dirs = p->excluded_dirs,
        .excluded_count = p->excluded_count,
    };

    cbm_pipeline_phase_probe_t extraction_probe = cbm_pipeline_phase_probe_start(p, "extraction");
    rc = run_extraction_phase(p, &ctx, source_files, source_count);
    cbm_pipeline_phase_probe_end(p, "extraction", &extraction_probe);
    if (rc != 0) {
        goto cleanup;
    }

    cbm_pipeline_phase_probe_t post_probe = cbm_pipeline_phase_probe_start(p, "post_and_persist");
    rc = run_post_extraction(p, &ctx, source_files, source_count, files, file_count);
    cbm_pipeline_phase_probe_end(p, "post_and_persist", &post_probe);
    if (rc != 0) {
        goto cleanup;
    }

    cbm_log_info("pipeline.done", "nodes", itoa_buf(cbm_gbuf_node_count(p->gbuf)), "edges",
                 itoa_buf(cbm_gbuf_edge_count(p->gbuf)), "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t0)));
    CBM_PROF_END("pipeline", "TOTAL", t_pipeline_total);

    if (p->post_success) {
        cbm_pipeline_phase_probe_t post_success_probe =
            cbm_pipeline_phase_probe_start(p, "post_success_pre_cleanup");
        int post_success_rc = p->post_success(p->post_success_ctx);
        cbm_pipeline_phase_probe_end(p, "post_success_pre_cleanup", &post_success_probe);
        if (post_success_rc != 0) {
            cbm_log_error(
                "pipeline.post_success_refused", "code",
                "CBM_PIPELINE_POST_SUCCESS_CALLBACK_FAILED", "message",
                "the post-success callback refused the completed pipeline snapshot",
                "remediation",
                "inspect the callback's structured diagnostic; no cleanup-dependent success may "
                "be reported");
            rc = CBM_NOT_FOUND;
        }
    }

cleanup:
    /* Every failing exit of this run funnels here while the graph buffer is
     * still alive: publish its refusal cause before it is destroyed (#1022). */
    if (rc != 0) {
        cbm_pipeline_record_gbuf_refusal(p, p->gbuf, "graph", p->repo_path);
    }
    cbm_pkgmap_free(cbm_pipeline_get_pkgmap());
    cbm_pipeline_set_pkgmap(NULL);
    free(source_files);
    /* Capture the counted degradations before the graph buffer that owns them
     * is destroyed — an unreported skip is a silent loss (#727). */
    p->ambiguous_reference_skips = cbm_gbuf_ambiguous_reference_skips(p->gbuf);
    p->unresolved_reference_source_skips = cbm_gbuf_unresolved_reference_source_skips(p->gbuf);
    cbm_gbuf_free(p->gbuf);
    p->gbuf = NULL;
    cbm_compile_context_index_free(p->compile_contexts);
    p->compile_contexts = NULL;
    p->current_source_slab = NULL;
    cbm_source_slab_destroy(&source_slab);
    cbm_registry_free(p->registry);
    p->registry = NULL;
    cbm_path_alias_collection_free(path_aliases);
    /* Clear and free user extension config */
    cbm_set_user_lang_config(NULL);
    cbm_userconfig_free(p->userconfig);
    p->userconfig = NULL;
    p->source_root = NULL;
    cbm_pipeline_phase_probe_t source_cleanup_probe =
        cbm_pipeline_phase_probe_start(p, "source_snapshot_cleanup");
    if (cbm_source_snapshot_destroy(&source_snapshot) != 0) {
        rc = CBM_NOT_FOUND;
    }
    cbm_pipeline_phase_probe_end(p, "source_snapshot_cleanup", &source_cleanup_probe);
    cbm_discover_free(files, file_count);
    cbm_destroy_thread_parser();
    cbm_slab_reclaim();
    cbm_kind_in_set_free_cache();
    cbm_mem_collect();
    cbm_log_info("pipeline.thread_allocator_cleanup", "parser", "destroyed", "slab",
                 "reclaimed");
    cbm_pipeline_phase_probe_end(p, "total", &total_probe);
    return rc;
}
