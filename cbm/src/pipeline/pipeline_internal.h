#include "foundation/constants.h"
/*
 * pipeline_internal.h — Internal pipeline state shared between pass files.
 *
 * NOT a public header. Only included by pipeline.c and pass_*.c files.
 * Exposes the pipeline context struct for direct field access by passes.
 */
#ifndef CBM_PIPELINE_INTERNAL_H
#define CBM_PIPELINE_INTERNAL_H

#include "pipeline/pipeline.h"
#include "pipeline/path_alias.h"
#include "graph_buffer/graph_buffer.h"
#include "graph_buffer/load_error.h"
#include "discover/discover.h"
#include "foundation/hash_table.h"
#include "cbm.h"
#include "lsp/go_lsp.h" /* CBMLSPDef for cbm_parallel_resolve cross-LSP inputs */
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <windows.h>

/* ── Shared pipeline constants ─────────────────────────────────── */

/* Maximum byte budget for tree-sitter extraction per file */
#define CBM_EXTRACT_BUDGET 5000000

/* Route node QN buffer size (must fit __route__METHOD__/full/url/path) */
#define CBM_ROUTE_QN_SIZE 768

/* Canonicalize route-path parameter placeholders (":id", "{id}", "<id>",
 * "${...}") to a single "{}" token so that client call sites and server
 * handlers rendezvous on the same Route QN regardless of framework syntax.
 * Parameter names are intentionally discarded ("/u/{id}" and "/u/{slug}" both
 * canonicalize to "/u/{}"). The result never exceeds the input length, so
 * out_sz >= strlen(in) + 1 always suffices. Returns out. */
const char *cbm_route_canon_path(const char *in, char *out, size_t out_sz);

bool cbm_has_config_extension(const char *path);

/* Only definitions that participate in code name resolution belong in the
 * semantic registry. Config/data keys remain first-class stable graph atoms,
 * but putting them in the code registry lets common keys such as `name` win a
 * weak call/usage resolution in unrelated source files. */
static inline bool cbm_pipeline_definition_is_registry_symbol(const char *label,
                                                              const char *file_path) {
    if (!label) {
        return false;
    }
    if (strcmp(label, "Function") == 0 || strcmp(label, "Method") == 0 ||
        cbm_label_is_type_like(label)) {
        return true;
    }
    if (strcmp(label, "Variable") != 0 && strcmp(label, "Field") != 0) {
        return false;
    }
    return !cbm_has_config_extension(file_path);
}

/* Time unit conversions */
#define CBM_NS_PER_SEC 1000000000LL
#define CBM_US_PER_SEC 1000000LL
#define CBM_MS_PER_SEC 1000.0
#define CBM_US_PER_SEC_F 1e6

/* ── Pipeline context (internal) ─────────────────────────────────── */

/* Per-worker manifest collection entry. */
typedef struct {
    char *pkg_name;  /* heap: "@myorg/pkg", "github.com/foo/bar" */
    char *entry_rel; /* heap: "packages/pkg/src/index" (no extension) */
} cbm_pkg_entry_t;

/* Growable array of package entries (per-worker, no thread contention). */
typedef struct {
    cbm_pkg_entry_t *items;
    int count;
    int cap;
    bool failed;
} cbm_pkg_entries_t;

/* Retain the exact first terminal pipeline diagnostic. Every string is copied
 * into pipeline-owned fixed storage before the originating subsystem is freed. */
void cbm_pipeline_record_fatal_error(cbm_pipeline_t *p, const char *code, const char *operation,
                                     const char *phase, const char *path, size_t requested,
                                     const char *message, const char *remediation);

/* Allocation-free native worker phase probe shared by the full and incremental
 * pipelines. Completion appends one retained metric to the owning pipeline and
 * marks the run incomplete on any process-accounting or representation failure. */
typedef struct {
    struct timespec started;
    IO_COUNTERS io;
    bool io_valid;
} cbm_pipeline_phase_probe_t;

cbm_pipeline_phase_probe_t cbm_pipeline_phase_probe_start(cbm_pipeline_t *p, const char *phase);
void cbm_pipeline_phase_probe_end(cbm_pipeline_t *p, const char *phase,
                                  const cbm_pipeline_phase_probe_t *probe);

void cbm_pkg_entries_init(cbm_pkg_entries_t *e);
void cbm_pkg_entries_free(cbm_pkg_entries_t *e);

/* Shared context passed to each pass function.
 * Derived from cbm_pipeline_t fields during run. */
typedef struct {
    const char *project_name;         /* borrowed from pipeline */
    const char *repo_path;            /* borrowed from pipeline */
    const char *source_root;          /* immutable snapshot root for every source-derived read */
    const cbm_file_info_t *all_files; /* complete captured source + interpretation inputs */
    int all_file_count;
    cbm_gbuf_t *gbuf;         /* owned by pipeline */
    cbm_registry_t *registry; /* owned by pipeline */
    atomic_int *cancelled;    /* pointer to pipeline's cancelled flag */
    cbm_pipeline_t *pipeline; /* back-pointer for recording per-file skips
                               * (Stage 2 / Track B). May be NULL on paths that
                               * don't record; cbm_pipeline_add_file_error is
                               * NULL-safe. */
    int mode;                 /* cbm_index_mode_t (0=full, 1=moderate, 2=fast, 3=advanced) */

    /* Extraction result cache (sequential pipeline optimization).
     * When non-NULL, pass_definitions stores results here instead of freeing,
     * and pass_calls/usages/semantic reuse cached results instead of re-extracting.
     * Indexed by file position in the files[] array. Owned by pipeline.c. */
    CBMFileResult **result_cache;

    /* Build-tool path aliases (tsconfig/jsconfig today; webpack/vite-style
     * configs are an easy follow-on). NULL when no usable configs were found.
     * Owned by pipeline.c / pipeline_incremental.c. */
    const cbm_path_alias_collection_t *path_aliases;

    /* Directory subtrees excluded during discovery. Borrowed from pipeline.c. */
    char **excluded_dirs;
    int excluded_count;

    /* Sequential cross-LSP registry arena. The lsp_cross pass builds its
     * shared per-language registries here; resolved_calls entries may BORROW
     * strings owned by these registries, and the later calls pass still
     * reads them — so the arena is OWNED and destroyed by
     * run_sequential_pipeline AFTER all passes, never by the lsp_cross pass
     * itself (destroying at pass end was a use-after-free in pass_calls).
     * Mirrors the parallel path, where cross_lsp_arena outlives the fused
     * resolve. */
    CBMArena seq_cross_arena;
    bool seq_cross_arena_live;
} cbm_pipeline_ctx_t;

/* Fail-closed barrier over authoritative per-file results. Scans in discovery
 * order so the same corpus always reports the same first causal failure. */
int cbm_pipeline_reject_file_failures(cbm_pipeline_t *pipeline, const cbm_file_info_t *files,
                                      int file_count, CBMFileResult *const *results,
                                      const char *phase);

static inline int cbm_pipeline_relpath_is_excluded(const char *rel_path, char *const *excluded_dirs,
                                                   int excluded_count) {
    if (!rel_path || rel_path[0] == '\0' || !excluded_dirs || excluded_count <= 0) {
        return 0;
    }
    for (int i = 0; i < excluded_count; i++) {
        const char *excluded = excluded_dirs[i];
        if (!excluded || excluded[0] == '\0') {
            continue;
        }
        size_t n = strlen(excluded);
        if (strncmp(rel_path, excluded, n) == 0 && (rel_path[n] == '\0' || rel_path[n] == '/')) {
            return SKIP_ONE;
        }
    }
    return 0;
}

/* Get the current pipeline's package map (NULL if none). */
CBMHashTable *cbm_pipeline_get_pkgmap(void);
void cbm_pipeline_set_pkgmap(CBMHashTable *map);

/* Unified module resolver: relative → pkgmap → fqn_module fallback.
 * Handles bare specifiers via pkgmap lookup with prefix matching.
 * Caller must free() the returned string. */
char *cbm_pipeline_resolve_module(const cbm_pipeline_ctx_t *ctx, const char *source_rel,
                                  const char *module_path);

/* Resolve an import to its in-graph target node, or NULL if unresolvable.
 *
 * Exact source-path candidates are evaluated together and multiple distinct
 * matches refuse persistence. Only after no exact source exists does semantic
 * resolution proceed:
 *   1. Exact source-backed Module by repository-relative file_path. Relative
 *      ECMAScript runtime extensions first use their ordered TypeScript source
 *      substitution family; zero or multiple live candidates refuse.
 *   2. Module-path resolution (relative / pkgmap / fqn_module) → existing node.
 *      This preserves the behavior for Python/TS/Go whose module path maps
 *      directly to a sibling Module/File QN.
 *   3. namespace_map[module_path-prefix] → File node QN (Java/Kotlin/C#/PHP
 *      `using`/`import` of a NAMESPACE that the path-based QN cannot express).
 *   4. Symbol-name fallback: the import's last path segment matched against an
 *      in-graph definition node of the same simple name in a different file
 *      (Rust `use crate::util::helper`, Java `import com.example.Util`, ...).
 * Quoted C-family includes are exact-source assertions and never enter semantic
 * fallback. Angle-bracket includes remain external unless a future captured
 * compilation context supplies their exact include root.
 *
 * `namespace_map` may be NULL (skips step 3).  `source_file_qn` is the importing
 * file's __file__ QN, used to avoid self-imports in step 4. */
const cbm_gbuf_node_t *cbm_pipeline_resolve_import_node(const cbm_pipeline_ctx_t *ctx,
                                                        const char *source_rel,
                                                        const char *source_file_qn,
                                                        const CBMImport *imp,
                                                        CBMHashTable *namespace_map);

/* Serialize and validate the identity properties for one resolved IMPORTS
 * edge. The returned JSON document is heap-owned. Invalid local/resource
 * combinations refuse graph resolution and return NULL. */
char *cbm_pipeline_import_edge_properties(cbm_pipeline_ctx_t *ctx, const char *rel_path,
                                          const CBMImport *imp);
int cbm_pipeline_import_edge_binding(const char *properties_json, CBMImportBinding *out_binding);

/* Build the only authoritative import bindings from resolved IMPORTS edges
 * owned by the exact source File container. Ordinary local aliases are
 * one-to-one and conflicting targets are hard errors. A `*` key is a glob
 * namespace directive, not a local alias: every distinct target remains in the
 * arrays so reachability sees the complete namespace set, while direct alias
 * lookup ignores `*`. Resource edges remain in the graph but never enter code
 * lookup. Unbound code dependencies retain a NULL key and target value so they
 * contribute to reachability without becoming direct aliases. Malformed edges, missing targets, and
 * allocation failures remain hard errors. Values borrow graph-buffer storage;
 * keys and both arrays are released with cbm_pipeline_import_map_free(). */
int cbm_pipeline_import_map_build(const cbm_gbuf_t *gbuf, const char *project_name,
                                  const char *rel_path, const char ***out_keys,
                                  const char ***out_vals, int *out_count);
void cbm_pipeline_import_map_free(const char **keys, const char **vals, int count);

/* Build a namespace → File-node-QN map from a set of extraction results.
 * Each result that declared a namespace/package contributes one entry keyed by
 * the namespace string (e.g. "App.Utils", "com.example").  Returns NULL when no
 * results declared a namespace.  Caller frees via cbm_pipeline_namespace_map_free. */
int cbm_pipeline_namespace_map_build(const char *project_name, CBMFileResult *const *results,
                                     const char *const *rels, int count, CBMHashTable **out_map);
void cbm_pipeline_namespace_map_free(CBMHashTable *map);

/* Parse a manifest file and collect pkg entries. Returns true if basename matched. */
bool cbm_pkgmap_try_parse(const char *basename, const char *rel_path, const char *source,
                          int source_len, cbm_pkg_entries_t *entries);

/* Merge per-worker entries into a hash table. Returns NULL if no entries. */
CBMHashTable *cbm_pkgmap_build(cbm_pkg_entries_t *worker_entries, int worker_count,
                               const char *project_name);

/* Build pkgmap by reading manifest files from the files array (sequential path). */
int cbm_pkgmap_build_from_files_checked(const cbm_file_info_t *files, int file_count,
                                        const char *project_name, CBMHashTable **out);

/* Free pkgmap and all owned strings. */
void cbm_pkgmap_free(CBMHashTable *pkgmap);

/* Check cancellation. Returns non-zero if cancelled. */
static inline int cbm_pipeline_check_cancel(const cbm_pipeline_ctx_t *ctx) {
    return atomic_load(ctx->cancelled) ? CBM_NOT_FOUND : 0;
}

/* ── Testable helpers ────────────────────────────────────────────── */

/* Check if a file path is worth tracking for git history analysis. */
bool cbm_is_trackable_file(const char *path);

/* Check if a file path looks like a test file (language-agnostic). */
bool cbm_is_test_path(const char *path);

/* Check if a function name looks like a test function (language-agnostic). */
bool cbm_is_test_func_name(const char *name);

/* Coupling result from computeChangeCoupling */
typedef struct {
    char file_a[CBM_SZ_512];
    char file_b[CBM_SZ_512];
    int co_change_count;
    double coupling_score;
    /* Unix epoch of the most recent commit that touched both files together.
     * 0 when no timestamp was available (e.g. older callers / popen path
     * without %ct). */
    long long last_co_change;
} cbm_change_coupling_t;

/* Commit data for coupling analysis */
typedef struct {
    char **files;
    int count;
    /* Unix epoch of the commit. 0 means unknown — coupling computation
     * still works but last_co_change on the resulting edge will be 0. */
    long long timestamp;
} cbm_commit_files_t;

/* Per-file temporal metadata. Populated alongside change-coupling so File
 * nodes can carry change_count and last_modified for hotspot / risk
 * analysis queries. */
typedef struct {
    char file_path[CBM_SZ_512];
    int change_count;
    long long last_modified; /* unix epoch of most recent commit */
} cbm_file_temporal_t;

/* Compute change coupling from commit history.
 * Returns number of couplings written to out (up to max_out).
 * Caller owns out[]. */
int cbm_compute_change_coupling(const cbm_commit_files_t *commits, int commit_count,
                                cbm_change_coupling_t *out, int max_out);

/* Go-style implicit interface satisfaction on graph buffer.
 * Finds Interface nodes, matches method sets against Class nodes,
 * creates IMPLEMENTS + OVERRIDE edges. Returns edge count created. */
int cbm_pipeline_implements_go(cbm_pipeline_ctx_t *ctx);

/* ── Git diff helpers (pass_gitdiff.c) ───────────────────────────── */

typedef struct {
    char status[CBM_SZ_4]; /* M/A/D/R */ /* "M", "A", "D", "R" */
    char path[CBM_SZ_512];
    char old_path[CBM_SZ_512]; /* non-empty only for renames */
} cbm_changed_file_t;

typedef struct {
    char path[CBM_SZ_512];
    int start_line;
    int end_line;
} cbm_changed_hunk_t;

/* Parse git diff --name-status output. Returns count written to out. */
int cbm_parse_name_status(const char *output, cbm_changed_file_t *out, int max_out);

/* Parse git diff --unified=0 output. Returns count written to out. */
int cbm_parse_hunks(const char *output, cbm_changed_hunk_t *out, int max_out);

/* Parse "start,count" or "start" → (start, count). */
void cbm_parse_range(const char *s, int *out_start, int *out_count);

/* ── Config helpers (pass_configures.c) ──────────────────────────── */

/* Check if a string looks like an environment variable name
 * (uppercase + underscore + digits, at least 2 chars with uppercase). */
bool cbm_is_env_var_name(const char *s);

/* Normalize a config key: split camelCase/snake/dots, lowercase.
 * Writes normalized form to norm_out (underscore-joined).
 * Returns token count. tokens_out[] receives borrowed pointers into norm_out. */
int cbm_normalize_config_key(const char *key, char *norm_out, size_t norm_sz);

/* ── Enrichment helpers (pass_enrichment.c) ──────────────────────── */

/* Split camelCase string on lowercase→uppercase transitions.
 * Writes substrings to out[]. Returns count. Caller must free each out[i]. */
int cbm_split_camel_case(const char *s, char **out, int max_out);

/* Tokenize a decorator into lowercase words, filtering stopwords.
 * E.g. "@login_required" → ["login", "required"].
 * Writes words to out[]. Returns count. Caller must free each out[i]. */
int cbm_tokenize_decorator(const char *dec, char **out, int max_out);

/* ── Compile commands helpers (pass_compile_commands.c) ──────────── */

typedef struct {
    char **include_paths;
    int include_count;
    char **defines;
    int define_count;
    char standard[CBM_SZ_32];
} cbm_compile_flags_t;

/* Split a shell command string into arguments (handles quoting).
 * Writes args to out[]. Returns count. Caller must free each out[i]. */
int cbm_split_command(const char *cmd, char **out, int max_out);

/* Extract -I, -isystem, -D, -std= flags from compiler arguments.
 * Caller must free result with cbm_compile_flags_free(). */
cbm_compile_flags_t *cbm_extract_flags(const char **args, int argc, const char *directory);

/* Free a compile_flags_t allocated by cbm_extract_flags(). */
void cbm_compile_flags_free(cbm_compile_flags_t *f);

/* Parse compile_commands.json content. Returns map as parallel arrays.
 * out_paths[i] is the relative file path, out_flags[i] is its flags.
 * Returns count. Caller must free out_paths[i] and cbm_compile_flags_free(out_flags[i]). */
int cbm_parse_compile_commands(const char *json_data, const char *repo_path, char ***out_paths,
                               cbm_compile_flags_t ***out_flags);

/* ── Infrascan helpers (pass_infrascan.c) ─────────────────────────── */

/* File identification helpers */
bool cbm_is_dockerfile(const char *name);
bool cbm_is_compose_file(const char *name);
bool cbm_is_cloudbuild_file(const char *name);
bool cbm_is_env_file(const char *name);
bool cbm_is_shell_script(const char *name, const char *ext);
bool cbm_is_kustomize_file(const char *name);
bool cbm_is_k8s_manifest(const char *name, const char *content);

/* Secret detection */
bool cbm_is_secret_binding(const char *key, const char *value);
bool cbm_is_secret_value(const char *value);

/* Clean JSON array brackets from CMD/ENTRYPOINT values.
 * E.g. ["./app", "--flag"] → ./app --flag
 * Writes result to out (up to out_sz). */
void cbm_clean_json_brackets(const char *s, char *out, size_t out_sz);

/* Key-value pair for environment variables / config entries */
typedef struct {
    char key[CBM_SZ_128];
    char value[CBM_SZ_512];
} cbm_env_kv_t;

/* Dockerfile parsing result */
typedef struct {
    char base_image[CBM_SZ_256];
    char stage_images[CBM_SZ_16][CBM_SZ_256];
    char stage_names[CBM_SZ_16][CBM_SZ_128];
    int stage_count;
    char exposed_ports[CBM_SZ_16][CBM_SZ_32];
    int port_count;
    cbm_env_kv_t env_vars[CBM_SZ_64];
    int env_count;
    char build_args[CBM_SZ_32][CBM_SZ_128];
    int build_arg_count;
    char workdir[CBM_SZ_256];
    char cmd[CBM_SZ_512];
    char entrypoint[CBM_SZ_512];
    char healthcheck[CBM_SZ_512];
    char user[CBM_SZ_64];
} cbm_dockerfile_result_t;

/* Dotenv parsing result */
typedef struct {
    cbm_env_kv_t env_vars[CBM_SZ_64];
    int env_count;
} cbm_dotenv_result_t;

/* Shell script parsing result */
typedef struct {
    char shebang[CBM_SZ_256];
    cbm_env_kv_t env_vars[CBM_SZ_64];
    int env_count;
    char sources[CBM_SZ_16][CBM_SZ_256];
    int source_count;
    char docker_cmds[CBM_SZ_16][CBM_SZ_256];
    int docker_cmd_count;
} cbm_shell_result_t;

/* Terraform variable */
typedef struct {
    char name[CBM_SZ_128];
    char type[CBM_SZ_64];
    char default_val[CBM_SZ_256];
    char description[CBM_SZ_256];
} cbm_tf_variable_t;

/* Terraform resource / data source */
typedef struct {
    char type[CBM_SZ_128];
    char name[CBM_SZ_128];
} cbm_tf_resource_t;

/* Terraform module */
typedef struct {
    char tf_name[CBM_SZ_128];
    char source[CBM_SZ_256];
} cbm_tf_module_t;

/* Terraform parsing result */
typedef struct {
    cbm_tf_resource_t resources[CBM_SZ_32];
    int resource_count;
    cbm_tf_variable_t variables[CBM_SZ_32];
    int variable_count;
    char outputs[CBM_SZ_32][CBM_SZ_128];
    int output_count;
    char providers[CBM_SZ_16][CBM_SZ_128];
    int provider_count;
    cbm_tf_module_t modules[CBM_SZ_16];
    int module_count;
    cbm_tf_resource_t data_sources[CBM_SZ_16];
    int data_source_count;
    char backend[CBM_SZ_128];
    bool has_locals;
} cbm_terraform_result_t;

/* Parse a Dockerfile from source text. Returns 0 if parsed, -1 if empty/invalid. */
int cbm_parse_dockerfile_source(const char *source, cbm_dockerfile_result_t *out);

/* Parse a .env file from source text. Returns 0 if parsed, -1 if empty. */
int cbm_parse_dotenv_source(const char *source, cbm_dotenv_result_t *out);

/* Parse a shell script from source text. Returns 0 if parsed, -1 if empty. */
int cbm_parse_shell_source(const char *source, cbm_shell_result_t *out);

/* Parse a Terraform file from source text. Returns 0 if parsed, -1 if empty. */
int cbm_parse_terraform_source(const char *source, cbm_terraform_result_t *out);

/* Helm Chart.yaml parse result: chart name + dependency chart names (#338). */
enum { CBM_HELM_MAX_DEPS = 128, CBM_HELM_NAME_MAX = 128 };
typedef struct {
    char chart_name[CBM_HELM_NAME_MAX];
    char deps[CBM_HELM_MAX_DEPS][CBM_HELM_NAME_MAX];
    int dep_count;
} cbm_helm_chart_t;

/* Parse a Helm Chart.yaml: top-level `name:` and `dependencies:` list names.
 * Returns 0 if parsed (name or deps found), -1 otherwise. */
int cbm_parse_helm_chart(const char *source, cbm_helm_chart_t *out);

/* Build an infrastructure QN. Caller must free the returned string. */
char *cbm_infra_qn(const char *project_name, const char *rel_path, const char *infra_type,
                   const char *service_name);

/* ── Parallel pipeline prototypes (pass_parallel.c) ─────────────── */

/* Phase 3A: Parallel extract + create definition nodes.
 * Each worker creates nodes in a per-worker gbuf, then merges into ctx->gbuf.
 * Caches CBMFileResult* in result_cache[file_idx] for reuse in Phase 3B/4.
 * shared_ids provides globally unique node/edge IDs across workers. */

/* Source-retention tuning for cbm_parallel_extract_ex. Zero-valued byte caps
 * mean "use the derived default" (RAM-fraction total, clamped to an absolute
 * ceiling; modest per-file cap); CBM_RETAIN_TOTAL_MB / CBM_RETAIN_PER_FILE_MB
 * override those. retain_sources_set=false keeps the default retain policy. */
typedef struct {
    bool retain_sources;
    bool retain_sources_set; /* false keeps the default retain_sources policy */
    size_t retain_total_budget_bytes;
    size_t retain_per_file_max_bytes;
} cbm_parallel_extract_opts_t;

int cbm_parallel_extract_ex(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count,
                            CBMFileResult **result_cache, _Atomic int64_t *shared_ids,
                            int worker_count, const cbm_parallel_extract_opts_t *opts);
int cbm_parallel_extract(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count,
                         CBMFileResult **result_cache, _Atomic int64_t *shared_ids,
                         int worker_count);

/* Phase 3B: Serial registry build from cached extraction results.
 * Creates DEFINES, DEFINES_METHOD, and IMPORTS edges in ctx->gbuf.
 * Registers callable symbols (Function/Method/Class) in ctx->registry. */
int cbm_build_registry_from_cache(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                                  int file_count, CBMFileResult **result_cache);

/* Phase 4: Parallel call/usage/semantic resolution.
 * Each worker resolves calls, usages, throws, rw, inherits, decorates,
 * and implements edges into per-worker edge bufs, then merges.
 * Runs Go-style implicit IMPLEMENTS as serial post-step. */
/* Opaque module-def index — defined in pass_lsp_cross.c. Forward-declared
 * here so we can include it in cbm_parallel_resolve's signature without
 * pulling the pass header into every consumer of pipeline_internal.h. */
struct CBMModuleDefIndex;

/* cbm_parallel_resolve's cross_registries param is typed `void*` to avoid
 * pulling lsp/go_lsp.h into every TU that includes pipeline_internal.h.
 * Callers cast a CBMCrossLspRegistries* (defined in pass_lsp_cross.h). */

int cbm_parallel_resolve(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count,
                         CBMFileResult **result_cache, _Atomic int64_t *shared_ids,
                         int worker_count,
                         /* Cross-file LSP inputs — pre-built once by the caller and
                          * shared read-only across workers (typed non-const to match
                          * the existing cbm_run_X_lsp_cross signatures the resolve
                          * worker forwards them to). Pass NULL/0/NULL to skip. */
                         CBMLSPDef *all_defs, int def_count, char *const *def_modules,
                         /* Optional inverted index module_qn → defs[] — fallback
                          * path when there's no pre-built registry for this lang. */
                         struct CBMModuleDefIndex *module_def_index,
                         /* Optional Tier 2 full: pre-built per-language registries.
                          * For each language with a non-NULL entry, workers use the
                          * cbm_run_X_lsp_cross_with_registry fast path (skip per-
                          * file registry build entirely). Falls back to the filter
                          * + per-file build path when entry is NULL or struct is NULL.
                          * Typed as void* here to dodge the typedef/tag ordering
                          * problem — pass_parallel.c casts back to CBMCrossLspRegistries*. */
                         void *cross_registries);

/* Post-merge: create Route nodes for HTTP_CALLS/ASYNC_CALLS edges that
 * have url_path in properties but point to library functions instead of routes.
 * Re-targets these edges to Route nodes for cross-service traversal. */
void cbm_pipeline_create_route_nodes(cbm_gbuf_t *gb);

/* Aggregate the callee names of the calls attributed to one exact definition
 * (matched by enclosing_func_qn and source-line containment — the SAME
 * attribution the guard per-snippet reparse applies) into a newline-delimited
 * "name\tcount" list that seeds the
 * panel S4 (api_callees) encoder. Counts are deduplicated so the index-time S4
 * vector matches a guard reparse of the same body. Writes a NUL-terminated
 * string into buf (empty when the def makes no attributed call) and returns the
 * number of bytes written. Shared by the sequential and parallel definition
 * passes; defined in pass_definitions.c. */
int cbm_pipeline_build_def_callees(const CBMCallArray *calls, const char *def_qn,
                                   int def_start_line, int def_end_line, char *buf, int bufsize);

/* Resolve one extracted definition by its complete source-backed atom, never by
 * its non-unique display qualified name. */
const cbm_gbuf_node_t *cbm_pipeline_find_definition_node(const cbm_gbuf_t *gbuf,
                                                         const CBMDefinition *def,
                                                         const char *fallback_rel_path);

/* Append a ,"args":[{"i":0,"e":"<expr>","v":"<value>"},...] field onto an edge's
 * JSON props (buffer content with NO trailing '}'; caller closes the object).
 * Returns the new write position. Defined in pass_parallel.c; shared with the
 * sequential CALLS finalizer (pass_calls.c) so the <50-file and >=50-file
 * pipelines emit byte-identical "args" arrays — same caps, same #493
 * UTF-8-boundary truncation, same buffer-budget cutoff (#516). */
size_t cbm_pipeline_append_args_json(char *buf, size_t bufsize, size_t pos, const CBMCall *call);

/* ── Pass function prototypes ────────────────────────────────────── */

int cbm_pipeline_pass_definitions(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                                  int file_count);

/* Read exactly the discovery-observed file bytes. The caller owns the returned
 * allocation. A concurrent size/content transition is a structured hard failure. */
uint8_t *cbm_pipeline_read_file_identity_bytes(const cbm_file_info_t *file, size_t *out_len);

int cbm_pipeline_pass_k8s(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count);

int cbm_pipeline_pass_calls(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count);

/* Cross-file LSP type-aware call resolution pass. Augments per-file
 * resolved_calls with cross-file resolutions before call edges are emitted.
 * Implementation: src/pipeline/pass_lsp_cross.c. */
int cbm_pipeline_pass_lsp_cross(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                                int file_count, CBMFileResult **cache);

/* Sub-passes called from pass_calls: pattern-based edge extraction */
int cbm_pipeline_pass_fastapi_depends(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                                      int file_count);

int cbm_pipeline_pass_usages(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count);

int cbm_pipeline_pass_semantic(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                               int file_count);

int cbm_pipeline_pass_tests(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count);

int cbm_pipeline_pass_githistory(cbm_pipeline_ctx_t *ctx);

/* Pre-computed git history result for fused post-pass parallelism. */
typedef struct {
    cbm_change_coupling_t *couplings;
    int count;
    int commit_count;
    /* Per-file temporal data (change_count + last_modified) for File nodes.
     * NULL when the history pass had no commits to analyse. */
    cbm_file_temporal_t *file_temporal;
    int file_temporal_count;
} cbm_githistory_result_t;

/* Compute change couplings without touching the graph buffer.
 * Can run on a separate thread while other passes use the gbuf. */
int cbm_pipeline_githistory_compute(const char *repo_path, cbm_githistory_result_t *result);

/* Apply pre-computed couplings to the graph buffer (main thread only). */
int cbm_pipeline_githistory_apply(cbm_pipeline_ctx_t *ctx, const cbm_githistory_result_t *result);

/* Pre-dump pass: decorator tags enrichment (operates on gbuf). */
int cbm_pipeline_pass_decorator_tags(cbm_gbuf_t *gbuf, const char *project);

/* Pre-dump pass: config ↔ code linking. */
int cbm_pipeline_pass_configlink(cbm_pipeline_ctx_t *ctx);

/* Pre-dump pass: SIMILAR_TO edges via MinHash fingerprinting. */
int cbm_pipeline_pass_similarity(cbm_pipeline_ctx_t *ctx);

/* Pre-dump pass: SEMANTICALLY_RELATED edges via algorithmic embeddings.
 * Opt-in: only runs when CBM_SEMANTIC_ENABLED=1. */
int cbm_pipeline_pass_semantic_edges(cbm_pipeline_ctx_t *ctx);

/* Pre-dump pass: interprocedural complexity propagation (Tier B).
 * Propagates per-function loop_depth along CALLS edges into a transitive
 * worst-case nested-loop estimate (transitive_loop_depth) and flags call-graph
 * cycles (recursive). Runs on the graph buffer before the dump. */
void cbm_pipeline_pass_complexity(cbm_pipeline_ctx_t *ctx);

/* Build a process/request-unique staging identity beside a live database.
 * The caller owns *out_path. The direct writer still opens it with CREATE_NEW,
 * so an identity collision is a hard failure rather than an overwrite. */
int cbm_pipeline_unique_stage_path(const char *db_path, const char *kind, char **out_path);

/* ── Incremental pipeline (pipeline_incremental.c) ───────────────── */

/* Run incremental re-index on an existing disk DB.
 * Classifies files by mtime+size, deletes changed nodes, re-parses changed
 * files, merges into disk DB. Returns 0 on success. */
int cbm_pipeline_run_incremental(cbm_pipeline_t *p, const char *db_path, cbm_file_info_t *files,
                                 int file_count);

enum { CBM_INCREMENTAL_REBUILD_REQUIRED = 2 };

/* Pipeline accessors for incremental use */
const char *cbm_pipeline_repo_path(const cbm_pipeline_t *p);
const char *cbm_pipeline_source_root(const cbm_pipeline_t *p);
atomic_int *cbm_pipeline_cancelled_ptr(cbm_pipeline_t *p);
/* Record committed graph size (#334 gate axis) from the incremental path,
 * which cannot see the opaque cbm_pipeline struct. Call before the dump. */
void cbm_pipeline_set_committed_counts(cbm_pipeline_t *p, int nodes, int edges);

/* Record counted domain-ambiguity skips from a graph buffer the caller owns
 * (the incremental path builds its own) before that buffer is freed (#727). */
void cbm_pipeline_set_ambiguous_reference_skips(cbm_pipeline_t *p, uint_least64_t skips);
/* Record unresolved enclosing-source skips from an incremental graph buffer
 * before the caller frees it. */
void cbm_pipeline_set_unresolved_reference_source_skips(cbm_pipeline_t *p, uint_least64_t skips);

/* Resolve the physical source owner of an extracted semantic reference.
 * An absent enclosing QN, or one exactly equal to the file's module QN, is a
 * top-level reference and belongs to the exact path-indexed File atom. A
 * different enclosing QN must resolve to a callable/type atom at the retained
 * source location; it is never re-attributed to File on a miss. */
const cbm_gbuf_node_t *cbm_pipeline_find_reference_source(
    const cbm_gbuf_t *gbuf, const char *project_name, const char *rel_path, const char *module_qn,
    const char *enclosing_qn, int source_line, const char *operation);

/* Complete-snapshot sink helpers shared with the incremental route. */
bool cbm_pipeline_row_sink_active(const cbm_pipeline_t *p);
void cbm_pipeline_attach_row_sink(cbm_pipeline_t *p, cbm_gbuf_t *gbuf);
int cbm_pipeline_emit_file_hash(cbm_pipeline_t *p, const char *project, const char *rel_path,
                                const char *sha256, int64_t mtime_ns, int64_t size);
int cbm_pipeline_complete_row_sink(cbm_pipeline_t *p, size_t file_hash_count);

/* Parse a gRPC stub call "<service-stub>.<method>" into the canonical proto
 * service name + method. Returns true ONLY when a recognized gRPC stub/client
 * suffix is present (the stub-type signal that gates Route emission, #294).
 * Exposed for testing. */
bool extract_grpc_service_method(const char *callee, char *service, size_t srv_sz, char *method,
                                 size_t meth_sz);

/* Extraction back-pressure observability (pass_parallel.c): nap-cycle counter
 * for the over-budget collect+nap gate. Test hook — asserts the gate stops
 * re-paying the nap tax once a full cycle failed to reclaim under budget
 * (futile: the resident floor, not transients, holds the memory). */
long cbm_pp_bp_nap_cycles(void);
void cbm_pp_bp_nap_cycles_reset(void);

#endif /* CBM_PIPELINE_INTERNAL_H */
