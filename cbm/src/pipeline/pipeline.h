/*
 * pipeline.h — Indexing pipeline orchestrator.
 *
 * Orchestrates multi-pass indexing of a repository:
 *   1. Structure: Project/Folder/Package/File nodes
 *   2. Definitions: Extract + write nodes + build registry
 *   3. Imports: Resolve import edges
 *   4. Calls: Call resolution (registry + LSP)
 *   5. Usages: Usage/type_ref edges
 *   6. Semantic: Inherits/decorates/implements
 *   7. Post: Tests, communities, HTTP links, config, git history
 *
 * Depends on: foundation, extraction, lsp, store, graph_buffer, discover
 */
#ifndef CBM_PIPELINE_H
#define CBM_PIPELINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "foundation/index_capability.h"

#include "graph_buffer/row_sink.h"

/* Forward declarations */
typedef struct cbm_store cbm_store_t;
typedef struct cbm_gbuf cbm_gbuf_t;

/* ── Opaque handle ──────────────────────────────────────────────── */

typedef struct cbm_pipeline cbm_pipeline_t;

/* Upper bound on the structured key/value detail pairs a fatal diagnostic can
 * carry alongside its first-class fields (#1004/#943). The emitting site's own
 * diagnostic keys (component, file, local_name, candidate_a_atom_id, ...) travel
 * with the record so the public failure response names the exact cause instead
 * of telling the caller to go read a worker log. */
#define CBM_PIPELINE_ERROR_DETAIL_MAX 16

typedef struct {
    const char *code;
    const char *operation;
    const char *phase;
    const char *path;
    const char *message;
    const char *remediation;
    size_t requested;
    /* Borrowed, NUL-terminated, index-aligned. `detail_count` is 0 when the
     * emitting site recorded no extra structured keys. */
    const char *const *detail_keys;
    const char *const *detail_vals;
    size_t detail_count;
} cbm_pipeline_error_t;

/* Optional success hook invoked after a pipeline has completed every
 * authoritative write/publication step and before teardown frees the graph,
 * source snapshot, registry, and other large native state. Returning non-zero
 * fails the pipeline with a structured native log entry. The callback is for
 * snapshot consumers that need to publish their already-copied row-sink result
 * before native teardown can fault; it is not a replacement for the row-sink
 * completion manifest and is called only on rc==0. */
typedef int (*cbm_pipeline_post_success_fn)(void *ctx);

/* One retained native worker phase measurement. The phase string and array are
 * pipeline-owned and remain valid until cbm_pipeline_free(). I/O counters are
 * exact GetProcessIoCounters transfer-byte deltas for the worker process over
 * this phase; elapsed_ms is measured from the monotonic clock. Memory fields
 * are exact PROCESS_MEMORY_COUNTERS_EX boundary observations: current/peak
 * working set plus current/peak private commit in bytes. */
typedef struct {
    const char *phase;
    uint64_t elapsed_ms;
    uint64_t read_bytes;
    uint64_t write_bytes;
    uint64_t other_bytes;
    uint64_t start_working_set_bytes;
    uint64_t end_working_set_bytes;
    uint64_t start_peak_working_set_bytes;
    uint64_t end_peak_working_set_bytes;
    uint64_t start_private_bytes;
    uint64_t end_private_bytes;
    uint64_t start_peak_private_bytes;
    uint64_t end_peak_private_bytes;
} cbm_pipeline_phase_metric_t;

/* One retained worker-dispatch admission record. This is separate from phase
 * timing: it records the execution mode the pipeline actually admitted, how
 * many workers were requested/admitted/created, and any exact failure code.
 * Strings are pipeline-owned fixed storage and remain valid until
 * cbm_pipeline_free(). */
typedef struct {
    char operation[64];
    char mode[16];
    char code[96];
    int item_count;
    int requested_workers;
    int admitted_workers;
    int created_workers;
    int failed_worker_index;
    int error_domain;
    unsigned long error_code;
} cbm_pipeline_parallel_dispatch_t;

/* Exact terminal accounting for the parallel resolver's immutable work
 * denominator. The resolver independently reconstructs `recounted` after all
 * workers join; a successful measured result requires
 * completed == denominator == recounted. Dynamic cross-LSP rows are processed
 * normally but owned by the already-counted cross-LSP units, so both quantities
 * remain explicit instead of being hidden in an ephemeral worker log. */
typedef struct {
    uint64_t completed;
    uint64_t denominator;
    uint64_t recounted;
    uint64_t dynamic_lsp_items;
    uint64_t cross_lsp_units;
} cbm_pipeline_parallel_resolver_accounting_t;

/* Exact successful execution route. Route describes the persisted operation;
 * worker-dispatch cardinality is an independent measured fact below. UNKNOWN
 * is never a successful response state. */
typedef enum {
    CBM_PIPELINE_EXECUTION_ROUTE_UNKNOWN = 0,
    CBM_PIPELINE_EXECUTION_ROUTE_UNCHANGED_READ_ONLY = 1,
    CBM_PIPELINE_EXECUTION_ROUTE_FULL_MATERIALIZED = 2,
    CBM_PIPELINE_EXECUTION_ROUTE_INCREMENTAL_MATERIALIZED = 3,
} cbm_pipeline_execution_route_t;

/* Exact retained-dispatch cardinality required by the selected successful
 * branch. ZERO is a measured zero, not missing telemetry. NONZERO requires at
 * least one retained dispatch record. UNKNOWN is never successful. */
typedef enum {
    CBM_PIPELINE_PARALLEL_DISPATCH_EXPECTATION_UNKNOWN = 0,
    CBM_PIPELINE_PARALLEL_DISPATCH_EXPECTATION_ZERO = 1,
    CBM_PIPELINE_PARALLEL_DISPATCH_EXPECTATION_NONZERO = 2,
} cbm_pipeline_parallel_dispatch_expectation_t;

/* The single exhaustive route/expectation relation used by both the producer
 * and response verifier. Keep the relation unrepresentable in one place so a
 * future route cannot silently acquire a guessed dispatch policy. */
static inline bool cbm_pipeline_execution_contract_valid(
    cbm_pipeline_execution_route_t route,
    cbm_pipeline_parallel_dispatch_expectation_t expectation) {
    return (route == CBM_PIPELINE_EXECUTION_ROUTE_UNCHANGED_READ_ONLY &&
            expectation == CBM_PIPELINE_PARALLEL_DISPATCH_EXPECTATION_ZERO) ||
           (route == CBM_PIPELINE_EXECUTION_ROUTE_INCREMENTAL_MATERIALIZED &&
            (expectation == CBM_PIPELINE_PARALLEL_DISPATCH_EXPECTATION_ZERO ||
             expectation == CBM_PIPELINE_PARALLEL_DISPATCH_EXPECTATION_NONZERO)) ||
           (route == CBM_PIPELINE_EXECUTION_ROUTE_FULL_MATERIALIZED &&
            expectation == CBM_PIPELINE_PARALLEL_DISPATCH_EXPECTATION_NONZERO);
}

/* Distinct terminal result for a repository with no non-auxiliary source
 * files. Callers must surface this as a structured refusal; it is never a
 * successful structural-only index. */
enum { CBM_PIPELINE_EMPTY_SOURCE_CORPUS = -2001 };

/* ── Index mode ─────────────────────────────────────────────────── */

/* ── Pipeline lifecycle ─────────────────────────────────────────── */

/* Create a new pipeline. Caller owns the result. */
cbm_pipeline_t *cbm_pipeline_new(const char *repo_path, const char *db_path, cbm_index_mode_t mode);

/* Bind the exact artifact- or repository-derived compilation context. The
 * pipeline copies and owns the bytes through cbm_pipeline_free; the caller may
 * release its source buffer immediately. The document must be an immutable
 * astrolabe.compilation-context.v1 value. */
int cbm_pipeline_set_embedded_compilation_context(cbm_pipeline_t *p, const uint8_t *bytes,
                                                  size_t byte_count);

/* Enable persistent artifact export (.codebase-memory/graph.db.zst).
 * When enabled, the pipeline writes a compressed artifact after indexing. */
void cbm_pipeline_set_persistence(cbm_pipeline_t *p, bool enabled);

/* Install the complete v1 source-snapshot sink. NULL restores the normal
 * no-sink path. A non-NULL descriptor is copied and accepted only when its
 * frozen ABI/version/mandatory callbacks validate exactly. Returns 0 on
 * success, -1 on refusal. */
int cbm_pipeline_set_sink(cbm_pipeline_t *p, const cbm_pipeline_row_sink_v2_t *sink);

/* Install or clear the optional post-success/pre-cleanup callback. */
int cbm_pipeline_set_post_success_callback(cbm_pipeline_t *p,
                                           cbm_pipeline_post_success_fn callback,
                                           void *ctx);

/* Free a pipeline and all its internal state. NULL-safe. */
void cbm_pipeline_free(cbm_pipeline_t *p);

/* Run the full indexing pipeline. Returns 0 on success, -1 on a general error,
 * or CBM_PIPELINE_EMPTY_SOURCE_CORPUS before publication when discovery finds
 * no non-auxiliary source file. Discovers files, extracts, resolves, and dumps
 * to SQLite. */
int cbm_pipeline_run(cbm_pipeline_t *p);

/* Request cancellation of a running pipeline (thread-safe). */
void cbm_pipeline_cancel(cbm_pipeline_t *p);

/* Get the project name derived from repo_path. Returned string is
 * owned by the pipeline. Valid until cbm_pipeline_free(). */
const char *cbm_pipeline_project_name(const cbm_pipeline_t *p);

/* Bind semantic row identity to an existing canonical repository root. This is
 * used when a controlled scratch checkout must emit rows for its durable source
 * repository (for example Git archaeology). Arbitrary labels are not accepted. */
bool cbm_pipeline_set_project_identity_root(cbm_pipeline_t *p, const char *identity_root);

/* Get the index mode (CBM_MODE_FULL, CBM_MODE_MODERATE, CBM_MODE_FAST). */
int cbm_pipeline_get_mode(const cbm_pipeline_t *p);

/* Get the list of directory subtrees skipped during discovery (#411).
 * *out receives a borrowed array of rel-path strings (owned by the pipeline,
 * valid until cbm_pipeline_free()); *count receives its length. Both are set
 * to NULL/0 when p is NULL or nothing was excluded. Do not free. */
void cbm_pipeline_get_excluded(const cbm_pipeline_t *p, char ***out, int *count);

/* Committed node/edge counts captured at dump time (-1 when dump did not run).
 * Nodes are the #334 plausibility-gate axis; edges are informational only. */
void cbm_pipeline_get_committed_counts(const cbm_pipeline_t *p, int *nodes, int *edges);

/* Return every completed phase metric in execution order plus an explicit
 * completeness bit. A successful index response must refuse its success
 * postcondition when complete=false; clean-worker logs are intentionally
 * ephemeral, so this array is the retained diagnostic source of truth. */
void cbm_pipeline_get_phase_metrics(const cbm_pipeline_t *p,
                                    const cbm_pipeline_phase_metric_t **out, size_t *count,
                                    bool *complete);

/* Return every retained worker-dispatch admission record plus a completeness
 * bit. A successful index response must carry these records so a clean CLI run
 * does not depend on ephemeral info-level worker logs for no-fallback evidence. */
void cbm_pipeline_get_parallel_dispatches(const cbm_pipeline_t *p,
                                          const cbm_pipeline_parallel_dispatch_t **out,
                                          size_t *count, bool *complete);

/* Return true and copy the retained terminal accounting when the parallel
 * resolver ran. False is an explicit not-run state; callers use the execution
 * route/dispatch contract to decide whether that state is valid. */
bool cbm_pipeline_get_parallel_resolver_accounting(
    const cbm_pipeline_t *p, cbm_pipeline_parallel_resolver_accounting_t *out);

/* Return the exact successful route and dispatch expectation selected by the
 * current run. A caller must reject UNKNOWN and every contradictory tuple. */
cbm_pipeline_execution_route_t cbm_pipeline_get_execution_route(const cbm_pipeline_t *p);
cbm_pipeline_parallel_dispatch_expectation_t cbm_pipeline_get_parallel_dispatch_expectation(
    const cbm_pipeline_t *p);

/* Reference edges skipped because their source syntax resolved to several
 * stable atoms in one semantic domain (#727). The corpus still publishes, so
 * every caller that reports a successful index MUST also report this count —
 * an unreported skip is exactly the silent degradation invariant 3 forbids. */
uint_least64_t cbm_pipeline_get_ambiguous_reference_skips(const cbm_pipeline_t *p);

/* Reference edges skipped because extraction asserted a non-empty enclosing
 * callable QN but no exact stable source atom owned the recorded path/line.
 * A successful index MUST disclose this count; such references are never
 * silently re-attributed to a File node. */
uint_least64_t cbm_pipeline_get_unresolved_reference_source_skips(const cbm_pipeline_t *p);

/* Rust `mod` declarations whose declared source existed at NEITHER
 * compiler-defined path (`<dir>/<mod>.rs`, `<dir>/<mod>/mod.rs`) (#1024). The
 * declaration resolves to nothing, no IMPORTS edge is fabricated, and the
 * corpus still publishes — so a successful index MUST report this count on
 * every run, including zero, or the loss becomes a silent fallback. */
uint_least64_t cbm_pipeline_get_dangling_rust_module_skips(const cbm_pipeline_t *p);

/* Recoverable tree-sitter parse diagnostics that were persisted as
 * ParseDiagnostic graph rows. Successful index responses emit this count on
 * every run, including zero, so malformed-source recovery is never silent. */
uint_least64_t cbm_pipeline_get_parse_recovery_diagnostics(const cbm_pipeline_t *p);

/* Exact compilation-context coverage captured before extraction. Paths are
 * borrowed from the pipeline and remain valid until cbm_pipeline_free(). A
 * configuration-absent file is a real source atom outside the selected build
 * closure; it never receives guessed compiler semantics. */
typedef struct {
    const char *authority;
    int c_family_files;
    int bound_files;
    int configuration_absent_files;
    int empty_files;
    const char *const *configuration_absent_paths;
} cbm_compile_context_diagnostics_t;

void cbm_pipeline_get_compile_context_diagnostics(
    const cbm_pipeline_t *p, cbm_compile_context_diagnostics_t *out);

/* Read the exact first fatal pipeline diagnostic. Returns false and zeroes
 * `out` when no fatal diagnostic has been recorded. Every pointer is borrowed
 * from the pipeline and remains valid until cbm_pipeline_free(). */
bool cbm_pipeline_get_fatal_error(const cbm_pipeline_t *p, cbm_pipeline_error_t *out);

/* ── Per-file indexing failures (Stage 2 / Track B) ─────────────── */

/* One discovered source file that failed before authoritative extraction
 * completed. All strings are owned by the pipeline (copied on record, freed in
 * cbm_pipeline_free). These records feed the extraction barrier: any entry is
 * terminal and prevents publication of a partial graph. Benign zero-byte files
 * do not produce an entry. */
typedef struct {
    char *path;   /* repo-relative path of the failed discovered file */
    char *reason; /* human-readable cause (e.g. "oversized (712 MB > 512 MB)",
                   * "parse timeout", "read failed") */
    char *phase;  /* "read" | "extract" | "oversized". "cross_lsp" is a RESERVED
                   * phase string for Track C's crash-attribution signal and is
                   * intentionally NOT emitted today (the cross-LSP passes are
                   * best-effort/void with no genuine per-file failure). */
} cbm_file_error_t;

/* Record a discovered-file failure. path/reason/phase are copied. NULL-safe on p.
 *
 * NOT thread-safe: call it from the sequential extraction pass, or from the
 * parallel merge step (never from inside a parallel worker — workers collect
 * into per-worker lists and merge sequentially). */
void cbm_pipeline_add_file_error(cbm_pipeline_t *p, const char *path, const char *reason,
                                 const char *phase);

/* Borrowed accessor for the recorded skips (owned by the pipeline, valid until
 * cbm_pipeline_free()). out and count are set to NULL and 0 when p is NULL or
 * nothing was skipped. Do not free. */
void cbm_pipeline_get_file_errors(const cbm_pipeline_t *p, cbm_file_error_t **out, int *count);

/* ── Index lock (prevents concurrent pipeline runs on same DB) ──── */

/* Try to acquire the global index lock. Returns true if acquired,
 * false if another pipeline is already running (non-blocking).
 * Use this in the watcher — skip reindex if busy. */
bool cbm_pipeline_try_lock(void);

/* Acquire the global index lock, blocking until available.
 * Use this in MCP handler and autoindex — wait for busy watcher to finish. */
void cbm_pipeline_lock(void);

/* Release the global index lock. */
void cbm_pipeline_unlock(void);

/* ── FQN helpers (used by passes and external callers) ──────────── */

/* Compute a symbol/module qualified name: project.dir.parts.name.
 * Strips extension, converts / to ., drops __init__ and index. The reserved
 * name "__file__" delegates to the centralized exact-path File contract so
 * callers cannot accidentally collapse file paths into module aliases.
 * Caller must free() the returned string. */
char *cbm_pipeline_fqn_compute(const char *project, const char *rel_path, const char *name);

/* Module QN: project.dir.parts (no name). Caller must free(). */
char *cbm_pipeline_fqn_module(const char *project, const char *rel_path);

/* Language-aware module QN. When `module_is_dir` is true (Java/Go package
 * semantics) the module is derived from the CONTAINING DIRECTORY (the filename
 * stem is dropped), so it agrees with the extraction-side def QNs; when false
 * it is exactly cbm_pipeline_fqn_module(). Caller must free(). */
char *cbm_pipeline_fqn_module_dir(const char *project, const char *rel_path, bool module_is_dir);

/* Folder QN: project.dir.parts. Caller must free(). */
char *cbm_pipeline_fqn_folder(const char *project, const char *rel_dir);

typedef enum {
    CBM_RELATIVE_IMPORT_ERROR = -1,
    CBM_RELATIVE_IMPORT_NOT_RELATIVE = 0,
    CBM_RELATIVE_IMPORT_RESOLVED = 1,
    CBM_RELATIVE_IMPORT_INVALID = 2,
} cbm_relative_import_status_t;

/* Resolve a relative import (./foo, ../bar, .foo) against its importing file.
 * On RESOLVED, `out` owns a complete normalized path without extension. The
 * status distinguishes a bare module, a path that escapes the repository root,
 * and representation/allocation failure so callers cannot reinterpret failure
 * as an ordinary unresolved import. */
int cbm_pipeline_resolve_relative_import_checked(const char *source_rel, const char *module_path,
                                                 char **out);

/* Derive project name from an absolute path.
 * Replaces / and : with -, collapses --, trims leading -.
 * Caller must free() the returned string. */
char *cbm_project_name_from_path(const char *abs_path);

/* ── Function Registry ──────────────────────────────────────────── */

typedef struct cbm_registry cbm_registry_t;

typedef struct {
    const char *qualified_name; /* borrowed from registry */
    const char *strategy;       /* resolution strategy name */
    double confidence;          /* 0.0–1.0 */
    int candidate_count;
} cbm_resolution_t;

/* Create/free a function registry. */
cbm_registry_t *cbm_registry_new(void);
void cbm_registry_free(cbm_registry_t *r);

/* Register a function/method/class. All strings are copied. */
bool cbm_registry_add(cbm_registry_t *r, const char *name, const char *qualified_name,
                      const char *label);
bool cbm_registry_failed(const cbm_registry_t *r);

/* Resolve a callee name using prioritized strategies.
 * import_map: NULL-terminated array of {local_name, resolved_qn} pairs, or NULL.
 * Returns result with qualified_name="" if unresolved. */
cbm_resolution_t cbm_registry_resolve(const cbm_registry_t *r, const char *callee_name,
                                      const char *module_qn, const char **import_map_keys,
                                      const char **import_map_vals, int import_map_count);

/* Evidence-only resolver for persisted graph targets. It admits only an exact
 * import binding, exact same-module identity, or a unique explicit qualified
 * path tail. Repository-global unique-name and scored suffix candidates are
 * diagnostic-only and are never returned as targets. An unresolved result
 * carries a stable strategy reason and candidate_count for aggregate logging. */
cbm_resolution_t cbm_registry_resolve_exact(const cbm_registry_t *r, const char *reference_name,
                                            const char *module_qn, const char **import_map_keys,
                                            const char **import_map_vals, int import_map_count);

/* Per-file memoization cache for is_import_reachable. Thread-local —
 * each resolve worker owns its own cache. Call _begin at the start
 * of resolve_file_calls (or any per-file resolve loop) and _end at
 * the end. The cache MUST be invalidated between files because
 * is_import_reachable's truth depends on the file's import_vals. */
void cbm_registry_reach_cache_begin(int estimated_capacity);
void cbm_registry_reach_cache_end(void);

/* Per-file import-map prefix → module-QN hash. Turns the linear
 * strcmp scan inside resolve_import_map into O(1). Keys/values are
 * BORROWED — caller must keep the import_map arrays alive for the
 * cache lifetime. Invalidate between files via _end. */
void cbm_registry_import_map_cache_begin(const char **keys, const char **vals, int count);
void cbm_registry_import_map_cache_end(void);

/* Per-file full-result cache for cbm_registry_resolve. The same
 * callee_name appears in many call sites within a file; module_qn
 * is constant per file so each name resolves identically. First
 * lookup does the full strategy chain; repeats are O(1) hash hits.
 * This eliminates ~75% of the resolve-chain work on K8s where the
 * same names ("Get", "Add", "New", etc) appear hundreds of times. */
void cbm_registry_resolve_cache_begin(int estimated_capacity);
void cbm_registry_resolve_cache_end(void);
bool cbm_registry_cache_failed(void);

/* Check if a qualified name exists in the registry. */
bool cbm_registry_exists(const cbm_registry_t *r, const char *qn);

/* True if `name` is one of the curated Perl core builtins (perlfunc). Used by
 * the call-resolution passes to suppress generic-resolver CALLS edges from Perl
 * builtin invocations (push/shift/keys/...) to project subs that merely share
 * the name. Perl-scoped: callers gate on the file language. */
bool cbm_perl_is_builtin(const char *name);

/* Decide whether a resolved Perl call edge is generic-resolver noise to drop
 * (#476): true only for Perl, only for a builtin/method call, and only when the
 * match used a weak short-name strategy — high-confidence same_module/import_map
 * matches are kept. Pure; unit-tested in test_registry.c. */
bool cbm_perl_suppress_generic_match(bool is_perl, bool is_method, const char *callee_name,
                                     const char *strategy);

/* Decide whether a resolved TS/JS/TSX member-call edge is weak-strategy noise to
 * drop (#592/#606): true only for TS/JS, only for a member call with a
 * non-this/super receiver (is_method), and only when the match used a weak
 * short-name strategy (suffix_match / unique_name / field_type_hint / fuzzy).
 * Explicit drop-list keeps every lsp_* / import / same-module / qualified match.
 * Pure; unit-tested in test_registry.c. */
bool cbm_tsjs_suppress_weak_method_match(bool is_tsjs, bool is_method, const char *strategy);

/* Get the label of a qualified name, or NULL if not found. */
const char *cbm_registry_label_of(const cbm_registry_t *r, const char *qn);

/* Find all QNs with a given simple name. Sets *out and *count.
 * Caller does NOT free the array (owned by registry). */
int cbm_registry_find_by_name(const cbm_registry_t *r, const char *name, const char ***out,
                              int *count);

/* Return total number of entries. */
int cbm_registry_size(const cbm_registry_t *r);

/* Find all qualified names ending with ".suffix".
 * Sets *out to heap-allocated array of borrowed string pointers.
 * Caller must free(*out) but NOT the individual strings.
 * Returns count of matches. */
int cbm_registry_find_ending_with(const cbm_registry_t *r, const char *suffix, const char ***out);

/* Check if candidate QN's module prefix is reachable via any import value. */
bool cbm_registry_is_import_reachable(const char *candidate_qn, const char **import_vals,
                                      int import_count);

/* Fuzzy resolve: match callee by bare function name (last segment after dots).
 * Returns result with ok=true if found, ok=false if not.
 * Lower confidence than Resolve (0.40 single, 0.30 multiple). */
typedef struct {
    cbm_resolution_t result;
    bool ok;
} cbm_fuzzy_result_t;

cbm_fuzzy_result_t cbm_registry_fuzzy_resolve(const cbm_registry_t *r, const char *callee_name,
                                              const char *module_qn, const char **import_map_keys,
                                              const char **import_map_vals, int import_map_count);

const char *cbm_confidence_band(double score);

#endif /* CBM_PIPELINE_H */
