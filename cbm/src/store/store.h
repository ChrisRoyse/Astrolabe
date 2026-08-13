/*
 * store.h — Opaque SQLite graph store for code knowledge graphs.
 *
 * All functions are prefixed cbm_store_*. The store handle is opaque —
 * callers never touch SQLite internals directly.
 *
 * Thread safety: a single store handle must not be used concurrently.
 * Use one store per thread or external synchronization.
 */
#ifndef CBM_STORE_H
#define CBM_STORE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "foundation/index_capability.h"

/* ── Opaque handle ──────────────────────────────────────────────── */

typedef struct cbm_store cbm_store_t;

/* Result of a source-preserving integrity verification. The verifier freezes
 * the complete source DB/WAL/SHM family before use. A sidecar-free database may
 * reuse a prior full verification only through an atomically published receipt
 * bound to its exact bytes, SQLite build, schema, contract, and project; all
 * other generations are inspected through a separate verified snapshot. */
typedef enum {
    CBM_STORE_VERIFY_OK = 0,
    CBM_STORE_VERIFY_SOURCE_MISSING = 1,
    CBM_STORE_VERIFY_INTEGRITY_FAILED = 2,
    CBM_STORE_VERIFY_IO_FAILED = 3,
} cbm_store_verify_status_t;

enum {
    CBM_STORE_VERIFY_OPERATION_MAX = 64,
    CBM_STORE_VERIFY_DETAIL_MAX = 512,
    CBM_STORE_VERIFY_PATH_MAX = 4096,
};

/* Exact physical close result.  Every field crossing the C/Rust boundary has
 * an explicit width; callers must key behavior on status and
 * connection_destroyed rather than inferring closure from pointer ownership.
 * A close can report cached-statement execution/finalize errors even when the
 * underlying SQLite connection was physically destroyed successfully. */
typedef int32_t cbm_store_close_status_t;

enum {
    CBM_STORE_CLOSE_OK = 0,
    CBM_STORE_CLOSE_FINALIZE_FAILED = 1,
    CBM_STORE_CLOSE_OUTSTANDING_STATEMENTS = 2,
    CBM_STORE_CLOSE_FAILED = 3,
    CBM_STORE_CLOSE_INVALID_ARGUMENT = 4,
    CBM_STORE_CLOSE_ABI_VERSION = 1,
    CBM_STORE_CLOSE_CACHED_STATEMENT_COUNT = 34,
    CBM_STORE_CLOSE_STATEMENT_NAME_MAX = 64,
    CBM_STORE_CLOSE_SQL_TEXT_MAX = 512,
    CBM_STORE_CLOSE_SQL_SHA256_MAX = 65,
};

typedef struct {
    int32_t sqlite_error;
    char statement_name[CBM_STORE_CLOSE_STATEMENT_NAME_MAX];
} cbm_store_finalize_error_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    cbm_store_close_status_t status;
    int32_t sqlite_close_code;
    uint32_t connection_was_present;
    uint32_t close_attempted;
    uint32_t connection_destroyed;
    uint32_t db_path_truncated;
    uint64_t db_path_bytes;
    uint32_t cached_statement_count;
    uint32_t finalize_error_count;
    cbm_store_finalize_error_t
        finalize_errors[CBM_STORE_CLOSE_CACHED_STATEMENT_COUNT];
    uint64_t outstanding_statement_count;
    uint64_t first_outstanding_sql_bytes;
    uint32_t first_outstanding_sql_available;
    uint32_t first_outstanding_sql_truncated;
    char first_outstanding_sql_sha256[CBM_STORE_CLOSE_SQL_SHA256_MAX];
    char first_outstanding_sql[CBM_STORE_CLOSE_SQL_TEXT_MAX];
    char db_path[CBM_STORE_VERIFY_PATH_MAX];
} cbm_store_close_result_t;

/* Existing-writer journal normalization result.  This transaction deliberately
 * does not close the store: its caller must consume this result and then use
 * cbm_store_close so connection destruction remains one independent proof. */
typedef int32_t cbm_store_normalize_status_t;

enum {
    CBM_STORE_NORMALIZE_OK = 0,
    CBM_STORE_NORMALIZE_INVALID_ARGUMENT = 1,
    CBM_STORE_NORMALIZE_READ_ONLY = 2,
    CBM_STORE_NORMALIZE_JOURNAL_READ_FAILED = 3,
    CBM_STORE_NORMALIZE_UNSUPPORTED_JOURNAL_MODE = 4,
    CBM_STORE_NORMALIZE_CHECKPOINT_FAILED = 5,
    CBM_STORE_NORMALIZE_CHECKPOINT_INCOMPLETE = 6,
    CBM_STORE_NORMALIZE_SET_DELETE_FAILED = 7,
    CBM_STORE_NORMALIZE_READBACK_FAILED = 8,
    CBM_STORE_NORMALIZE_ABI_VERSION = 1,
    CBM_STORE_NORMALIZE_MODE_MAX = 16,
};

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    cbm_store_normalize_status_t status;
    int32_t sqlite_error;
    int32_t wal_log_frames;
    int32_t wal_checkpointed_frames;
    int32_t wal_remaining_frames;
    char journal_mode_before[CBM_STORE_NORMALIZE_MODE_MAX];
    char journal_mode_after[CBM_STORE_NORMALIZE_MODE_MAX];
    char operation[CBM_STORE_VERIFY_OPERATION_MAX];
    char detail[CBM_STORE_VERIFY_DETAIL_MAX];
} cbm_store_normalize_result_t;

typedef struct {
    cbm_store_verify_status_t status;
    uint32_t native_error;
    int sqlite_error;
    uint32_t schema_metadata_read;
    int32_t observed_schema_version;
    int32_t reader_schema_version;
    bool db_present;
    bool wal_present;
    bool shm_present;
    bool family_frozen;
    bool family_guard_release_complete;
    bool scratch_created;
    bool scratch_cleanup_complete;
    bool sqlite_owned_empty_wal_created;
    uint32_t cleanup_native_error;
    uint64_t db_bytes;
    char db_sha256[65];
    uint64_t wal_bytes;
    char wal_sha256[65];
    char operation[CBM_STORE_VERIFY_OPERATION_MAX];
    char cleanup_operation[CBM_STORE_VERIFY_OPERATION_MAX];
    char detail[CBM_STORE_VERIFY_DETAIL_MAX];
    char scratch_path[CBM_STORE_VERIFY_PATH_MAX];
} cbm_store_verify_result_t;

/* ── Result codes ───────────────────────────────────────────────── */

#define CBM_STORE_OK 0
#define CBM_STORE_ERR (-1)
#define CBM_STORE_NOT_FOUND (-2)
#define CBM_STORE_SEMANTIC_UNAVAILABLE (-3)
#define CBM_STORE_SEMANTIC_STATE_INVALID (-4)
#define CBM_STORE_SEMANTIC_KEYWORD_UNAVAILABLE (-5)
#define CBM_STORE_SEMANTIC_VECTOR_CORRUPT (-6)
#define CBM_STORE_SEMANTIC_KEYWORD_INVALID (-7)

/* ── Data structures ────────────────────────────────────────────── */

typedef struct {
    int64_t id;
    const char *project;
    const char *label;          /* Function, Class, Method, Module, File, ... */
    const char *name;           /* short name */
    const char *atom_id;        /* stable source-atom SHA-256 */
    const char *qualified_name; /* full dotted path */
    const char *file_path;      /* relative file path */
    int start_line;
    int end_line;
    bool source_present;
    const uint8_t *source_bytes;
    size_t source_len;
    const char *source_sha256;
    uint64_t start_byte;
    uint64_t end_byte;
    const char *properties_json; /* JSON string, NULL → "{}" */
} cbm_node_t;

typedef struct {
    int64_t id;
    const char *project;
    int64_t source_id;
    int64_t target_id;
    const char *type;            /* CALLS, HTTP_CALLS, IMPORTS, ... */
    const char *properties_json; /* JSON string, NULL → "{}" */
} cbm_edge_t;

typedef struct {
    const char *name;
    const char *indexed_at; /* ISO 8601 */
    const char *root_path;
    cbm_index_capability_t capability;
} cbm_project_t;

typedef struct {
    int node_vector_count;
    int node_vector_min_dimension;
    int node_vector_max_dimension;
    int token_vector_count;
    int token_vector_min_dimension;
    int token_vector_max_dimension;
} cbm_vector_state_readback_t;

typedef struct {
    const char *project;
    const char *rel_path;
    const char *sha256;
    int64_t mtime_ns;
    int64_t size;
} cbm_file_hash_t;

enum { CBM_FILE_SHA256_CAPACITY = 65 };

/* Fixed-size identity for one indexed file. Unlike cbm_file_hash_t, this is
 * caller-owned and requires no allocation or release. */
typedef struct {
    char sha256[CBM_FILE_SHA256_CAPACITY];
    int64_t mtime_ns;
    int64_t size;
} cbm_file_identity_t;

/* Find nodes overlapping a line range in a file (excludes Module/Package). */
int cbm_store_find_nodes_by_file_overlap(cbm_store_t *s, const char *project, const char *file_path,
                                         int start_line, int end_line, cbm_node_t **out,
                                         int *count);

/* Find nodes whose qualified_name ends with the given suffix (dot-boundary). */
int cbm_store_find_nodes_by_qn_suffix(cbm_store_t *s, const char *project, const char *suffix,
                                      cbm_node_t **out, int *count);

/* Get CALLS degree of a node (inbound and outbound).
 * Returns CBM_STORE_OK only when both exact counts were read. On failure both
 * outputs remain zero and cbm_store_error()/cbm_store_error_code() retain the
 * causal SQLite operation. */
int cbm_store_node_degree(cbm_store_t *s, int64_t node_id, int *in_deg, int *out_deg);

/* Get caller/callee names for a node (CALLS/HTTP_CALLS/ASYNC_CALLS edges).
 * Returns 0 on success. Caller must free each out_callers[i]/out_callees[i]
 * and the arrays themselves. */
int cbm_store_node_neighbor_names(cbm_store_t *s, int64_t node_id, int limit, char ***out_callers,
                                  int *caller_count, char ***out_callees, int *callee_count);

/* Batch count in/out degree for multiple nodes.
 * edge_type: filter by edge type (e.g. "CALLS"), or NULL/"" for all types.
 * out_in[i] and out_out[i] receive the in/out degree for node_ids[i].
 * Returns CBM_STORE_OK or CBM_STORE_ERR. */
int cbm_store_batch_count_degrees(cbm_store_t *s, const int64_t *node_ids, int id_count,
                                  const char *edge_type, int *out_in, int *out_out);

/* Upsert file hashes in batch. */
int cbm_store_upsert_file_hash_batch(cbm_store_t *s, const cbm_file_hash_t *hashes, int count);

/* Find edges whose properties contain a url_path matching the keyword. */
int cbm_store_find_edges_by_url_path(cbm_store_t *s, const char *project, const char *keyword,
                                     cbm_edge_t **out, int *count);

/* Restore database from another store (backup API). */
int cbm_store_restore_from(cbm_store_t *dst, cbm_store_t *src);

/* ── Search ─────────────────────────────────────────────────────── */

typedef struct {
    const char *project;
    const char *label;        /* NULL = any label */
    const char *name_pattern; /* regex on name, NULL = any */
    const char *qn_pattern;   /* regex on qualified_name, NULL = any */
    const char *file_pattern; /* glob on file_path, NULL = any */
    const char *relationship; /* edge type filter, NULL = any */
    const char *direction;    /* "inbound" / "outbound" / "any", NULL = any */
    int min_degree;           /* -1 = no filter (default), 0+ = minimum */
    int max_degree;           /* -1 = no filter (default), 0+ = maximum */
    int limit;                /* 0 = default (10) */
    int offset;
    bool exclude_entry_points;
    bool include_connected;
    const char *sort_by; /* "relevance" / "name" / "degree", NULL = relevance */
    bool case_sensitive;
    const char **exclude_labels; /* NULL-terminated array, or NULL */
} cbm_search_params_t;

typedef struct {
    cbm_node_t node;
    int in_degree;
    int out_degree;
    /* connected_names: allocated array of strings, count in connected_count */
    const char **connected_names;
    int connected_count;
} cbm_search_result_t;

typedef struct {
    cbm_search_result_t *results;
    int count;
    int total; /* total before pagination */
} cbm_search_output_t;

/* ── Traversal ──────────────────────────────────────────────────── */

typedef struct {
    cbm_node_t node;
    int hop; /* BFS depth from root */
} cbm_node_hop_t;

typedef struct {
    const char *from_name;
    const char *to_name;
    const char *type;
    double confidence;
    int64_t source_id; /* edge endpoints — let callers match an edge to a hop node */
    int64_t target_id;
    const char *properties_json; /* raw edge properties (carries CALLS arg expressions) */
} cbm_edge_info_t;

typedef struct {
    cbm_node_t root;
    cbm_node_hop_t *visited;
    int visited_count;
    cbm_edge_info_t *edges;
    int edge_count;
} cbm_traverse_result_t;

/* ── Schema introspection ───────────────────────────────────────── */

typedef struct {
    const char *label;
    int count;
    char **properties; /* distinct property keys for this label (base + JSON) */
    int property_count;
} cbm_label_count_t;

typedef struct {
    const char *type;
    int count;
    char **properties; /* distinct property keys for this edge type (base + JSON) */
    int property_count;
} cbm_type_count_t;

typedef struct {
    cbm_label_count_t *node_labels;
    int node_label_count;
    cbm_type_count_t *edge_types;
    int edge_type_count;
    /* relationship patterns like "(Function)-[CALLS]->(Function) [123x]" */
    const char **rel_patterns;
    int rel_pattern_count;
    const char **sample_func_names;
    int sample_func_count;
    const char **sample_class_names;
    int sample_class_count;
    const char **sample_qns;
    int sample_qn_count;
} cbm_schema_info_t;

/* ── Lifecycle ──────────────────────────────────────────────────── */

/* Open an in-memory database (for testing). */
cbm_store_t *cbm_store_open_memory(void);

/* Open a file-backed database at the given path. Creates if needed. */
cbm_store_t *cbm_store_open_path(const char *db_path);

/* Open an existing file-backed database for querying only. Opened READ-ONLY
 * (no SQLITE_OPEN_CREATE, no write pragmas) so queries never mutate the DB and
 * work on a read-only file / filesystem. Returns NULL if the file does not
 * exist — never creates a new .db file. */
cbm_store_t *cbm_store_open_path_query(const char *db_path);

/* Verify and open an existing database without allowing a change between the
 * verification snapshot and the returned query connection.  On Windows the
 * source DB/WAL/SHM members are held with
 * read-only, no-write/no-delete-share handles while a byte- and SHA-256-checked
 * DB+WAL snapshot is inspected.  WAL-index SHM is intentionally rebuilt in the
 * scratch directory because it is a mutable cache, not database content.  After
 * the snapshot passes, the SHM guard is released and the source query connection
 * is opened while the DB/WAL guards still exclude writers; only then are those
 * guards released.  `out_store` is set on VERIFY_OK.  If cleanup itself finds
 * an exact-close failure, the non-OK result retains the still-owned handle in
 * `out_store` so the caller can inspect and retry closure without losing it.
 *
 * Returns one cbm_store_verify_status_t value and fills `result` with the exact
 * failed operation and native/SQLite diagnostics.  Every non-OK status is
 * fail-closed. */
cbm_store_verify_status_t cbm_store_open_path_query_verified(const char *db_path,
                                                             cbm_store_t **out_store,
                                                             cbm_store_verify_result_t *result);

/* Verify and open the exact named project consumed by MCP query tools.  In
 * addition to the complete query schema contract, the sole persisted project
 * name must equal `project` and its persisted root_path must resolve to the
 * same canonical, currently existing filesystem path.  This is the query
 * admission boundary for project/store provenance: callers must never obtain
 * an alias by scanning for and adopting a differently named database file. */
cbm_store_verify_status_t cbm_store_open_path_project_query_verified(
    const char *db_path, const char *project, cbm_store_t **out_store,
    cbm_store_verify_result_t *result);

/* Verify the complete frozen DB/WAL family and exact project/root provenance
 * without opening the live source through SQLite.  A matching v2 exact-content
 * receipt reuses the full SQLite proof while independently re-canonicalizing
 * its content-bound project root and requiring content-bound DELETE mode.  A
 * receipt miss verifies a byte- and hash-bound scratch snapshot before all
 * source-family guards are released. */
cbm_store_verify_status_t cbm_store_verify_path_project_snapshot(
    const char *db_path, const char *project, cbm_store_verify_result_t *result);

/* Verify the complete frozen DB/WAL family and exact project/root provenance
 * without opening the live source, while accepting either valid WAL or DELETE
 * journal state.  This is the mandatory preservation preflight before a live
 * normalization writer is opened: malformed source DB/WAL bytes fail in the
 * scratch family and cannot cause source SHM creation or source mutation. */
cbm_store_verify_status_t cbm_store_verify_path_project_snapshot_for_normalization(
    const char *db_path, const char *project, cbm_store_verify_result_t *result);

/* Open one already-verified named project for mutation without creating or
 * initializing anything.  The database must already exist and be genuinely
 * writable.  This preserves its current journal mode, applies only
 * connection-local/non-mode-changing pragmas, and verifies the complete query
 * integrity + exact project/root contract on the returned connection.  Keep a
 * previously verified query connection open until this call succeeds to bind
 * the pathname against replacement; close that query connection before the
 * first mutation. */
cbm_store_verify_status_t cbm_store_open_path_project_writer_existing(
    const char *db_path, const char *project, cbm_store_t **out_store,
    cbm_store_verify_result_t *result);

/* Open the existing writer only when its exact DB/WAL bytes still match a
 * successful frozen normalization preflight. The writer acquires SQLite's
 * exclusive ownership before re-hashing the live family, so a pathname or WAL
 * generation change is refused before journal normalization can begin. */
cbm_store_verify_status_t cbm_store_open_path_project_writer_existing_bound(
    const char *db_path, const char *project,
    const cbm_store_verify_result_t *expected_family, cbm_store_t **out_store,
    cbm_store_verify_result_t *result);

/* Verify and open the graph state consumed by cbm_gbuf_load_from_db.  This uses
 * the same source-family freeze, byte/hash-checked snapshot, and race-free
 * read-only publication boundary as cbm_store_open_path_query_verified, but
 * verifies the versioned Project/Node/Edge reload contract rather than
 * requiring query-only projections such as nodes_fts.  The sole persisted
 * project must exactly equal `project`; a different or missing project is an
 * integrity failure, never an empty-graph success or a retry through another
 * open profile.  `out_store` is set on VERIFY_OK or retains the exact handle
 * only when a non-OK cleanup close could not physically destroy it. */
cbm_store_verify_status_t cbm_store_open_path_graph_verified(const char *db_path,
                                                             const char *project,
                                                             cbm_store_t **out_store,
                                                             cbm_store_verify_result_t *result);

/* On-disk path of a file-backed store, or NULL for an in-memory (:memory:)
 * store. The returned pointer is owned by the store. */
const char *cbm_store_db_path(const cbm_store_t *s);

/* Check database integrity. Returns true only when SQLite's full integrity and
 * foreign-key checks pass, the exact query schema/version is present, and the
 * file contains exactly one valid project row with an absolute root path.
 * Returns false if corruption is detected. Callers must preserve the complete
 * database/journal family and fail closed; recovery and re-indexing are explicit
 * operator-controlled transactions, never an automatic delete side effect. */
bool cbm_store_check_integrity(cbm_store_t *s);

/* Open database for a named project in the default cache dir. */
cbm_store_t *cbm_store_open(const char *project);

/* Physically close one owned store.  The pointer is cleared and its wrapper is
 * freed only after sqlite3_close returns SQLITE_OK.  On SQLITE_BUSY, any
 * prepared statement that survives SQLite's virtual-table disconnect is
 * reported and left owned by the unchanged store pointer; it is never silently
 * finalized or converted into a sqlite3_close_v2 zombie. */
cbm_store_close_status_t cbm_store_close(cbm_store_t **store,
                                         cbm_store_close_result_t *result);

/* Close a transient owner whose surrounding legacy API has no result channel.
 * Any non-OK result is logged with the complete close record and terminates the
 * process, so a caller can never return success, discard the retained owner, or
 * continue after an unevaluable physical close. Long-lived owners that can
 * retain and report failure (notably MCP) must call cbm_store_close directly. */
void cbm_store_close_required(cbm_store_t **store, const char *operation);

/* Get the underlying sqlite3 handle (for testing only). */
struct sqlite3 *cbm_store_get_db(cbm_store_t *s);

/* Get the last error message (static string, valid until next call). */
const char *cbm_store_error(cbm_store_t *s);

/* Get SQLite's exact extended result code for the last operation. */
int cbm_store_error_code(cbm_store_t *s);

/* Clear the retained error at the start of a compound store operation. */
void cbm_store_clear_error(cbm_store_t *s);

/* ── Transaction ────────────────────────────────────────────────── */

/* Begin a transaction. Returns CBM_STORE_OK on success. */
int cbm_store_begin(cbm_store_t *s);

/* Commit the current transaction. */
int cbm_store_commit(cbm_store_t *s);

/* Rollback the current transaction. */
int cbm_store_rollback(cbm_store_t *s);

/* ── Bulk write optimization ────────────────────────────────────── */

/* Tune pragmas for bulk write throughput (synchronous=OFF, large cache).
 * WAL journal mode is preserved throughout for crash safety. */
int cbm_store_begin_bulk(cbm_store_t *s);

/* Restore normal pragmas (synchronous=NORMAL, default cache) after bulk writes. */
int cbm_store_end_bulk(cbm_store_t *s);

/* Drop user indexes for faster bulk inserts. */
int cbm_store_drop_indexes(cbm_store_t *s);

/* Recreate user indexes after bulk inserts. */
int cbm_store_create_indexes(cbm_store_t *s);

/* ── WAL / Checkpoint ───────────────────────────────────────────── */

/* Require a complete WAL TRUNCATE checkpoint, then PRAGMA optimize.
 * Active readers/checkpoint owners and all SQLite failures are hard errors. */
int cbm_store_checkpoint(cbm_store_t *s);

/* Normalize one already-verified existing writer to rollback-journal DELETE.
 * DELETE is verified without mutation.  WAL requires an exact TRUNCATE
 * checkpoint with zero remaining frames, then PRAGMA journal_mode=DELETE and
 * an independent DELETE readback.  Every other mode is refused. */
cbm_store_normalize_status_t cbm_store_normalize_journal_mode_delete(
    cbm_store_t *s, cbm_store_normalize_result_t *result);

/* Resolve the mmap_size pragma value applied to on-disk stores from the
 * CBM_SQLITE_MMAP_SIZE environment variable. Defaults to 67108864 (64 MB)
 * only when the variable is absent. Returns -1 for empty, malformed,
 * partially numeric, negative, or overflowed values so store open can fail
 * closed instead of applying a different memory policy. */
int64_t cbm_store_resolve_mmap_size(void);

/* ── Dump / Restore ─────────────────────────────────────────────── */

/* Dump in-memory database to a file. */
int cbm_store_dump_to_file(cbm_store_t *s, const char *dest_path);

/* ── Project CRUD ───────────────────────────────────────────────── */

int cbm_store_upsert_project(cbm_store_t *s, const char *name, const char *root_path,
                             const cbm_index_capability_t *capability);
int cbm_store_get_project(cbm_store_t *s, const char *name, cbm_project_t *out);
int cbm_store_list_projects(cbm_store_t *s, cbm_project_t **out, int *count);
int cbm_store_delete_project(cbm_store_t *s, const char *name);

/* ── Node CRUD ──────────────────────────────────────────────────── */

/* Upsert a single node. Returns node ID (>0) or CBM_STORE_ERR. */
int64_t cbm_store_upsert_node(cbm_store_t *s, const cbm_node_t *n);

/* Upsert nodes in batch. out_ids must have room for count entries. */
int cbm_store_upsert_node_batch(cbm_store_t *s, const cbm_node_t *nodes, int count,
                                int64_t *out_ids);

/* Find node by primary key. Returns CBM_STORE_OK or CBM_STORE_NOT_FOUND. */
int cbm_store_find_node_by_id(cbm_store_t *s, int64_t id, cbm_node_t *out);

/* Find node by stable project-scoped source atom identity. */
int cbm_store_find_node_by_atom_id(cbm_store_t *s, const char *project, const char *atom_id,
                                   cbm_node_t *out);

/* Find node by project + qualified_name. */
int cbm_store_find_node_by_qn(cbm_store_t *s, const char *project, const char *qn, cbm_node_t *out);

/* Find node by qualified_name only. Fails if more than one atom matches. */
int cbm_store_find_node_by_qn_any(cbm_store_t *s, const char *qn, cbm_node_t *out);

/* Find nodes by name (exact match). Returns allocated array, caller frees. */
int cbm_store_find_nodes_by_name(cbm_store_t *s, const char *project, const char *name,
                                 cbm_node_t **out, int *count);

/* Find every node in one project. Returns allocated array, caller frees. */
int cbm_store_find_nodes_by_project(cbm_store_t *s, const char *project, cbm_node_t **out,
                                    int *count);

/* Find nodes by qualified name (exact match). Returns allocated array, caller frees. */
int cbm_store_find_nodes_by_qn(cbm_store_t *s, const char *project, const char *qualified_name,
                               cbm_node_t **out, int *count);

/* Find nodes by name across all projects. Returns allocated array, caller frees. */
int cbm_store_find_nodes_by_name_any(cbm_store_t *s, const char *name, cbm_node_t **out,
                                     int *count);

/* Find nodes by label. */
int cbm_store_find_nodes_by_label(cbm_store_t *s, const char *project, const char *label,
                                  cbm_node_t **out, int *count);

/* Find nodes by file path. */
int cbm_store_find_nodes_by_file(cbm_store_t *s, const char *project, const char *file_path,
                                 cbm_node_t **out, int *count);

/* Batch lookup: map qualified names → node IDs.
 * qns[i] is resolved; out_ids[i] receives the ID or 0 if not found.
 * Returns number of QNs actually found, or CBM_STORE_ERR. */
int cbm_store_find_node_ids_by_qns(cbm_store_t *s, const char *project, const char **qns,
                                   int qn_count, int64_t *out_ids);

/* Count nodes in project. Returns count or CBM_STORE_ERR. */
int cbm_store_count_nodes(cbm_store_t *s, const char *project);

/* Narrow indexed recounts for persisted typed outcomes. These open only the
 * nodes(project,label) / edges(project,type) ranges and never scan row bodies. */
int cbm_store_count_nodes_by_label(cbm_store_t *s, const char *project, const char *label);
int cbm_store_count_nodes_by_label_and_name(cbm_store_t *s, const char *project, const char *label,
                                            const char *name);

int cbm_store_count_nodes_scoped(cbm_store_t *s, const char *project, const char *path);

int cbm_store_count_edges_scoped(cbm_store_t *s, const char *project, const char *path);

/* True when path is a non-empty scope after normalization (issue #604). */
bool cbm_store_arch_path_scoped(const char *path);

/* When scoped, writes normalized directory prefix into norm_out. Returns false if unscoped. */
bool cbm_store_normalize_arch_path(const char *path, char *norm_out, size_t norm_sz);

/* True when architecture aspect `name` belongs to the "overview" subset:
 * every aspect EXCEPT the large per-file listing (file_tree). Shared by both
 * aspect gates — want_aspect (store.c) and aspect_wanted (mcp.c) — so the
 * two sites cannot drift. */
bool cbm_store_arch_aspect_in_overview(const char *name);

/* Delete all nodes for a project (cascade deletes edges). */
int cbm_store_delete_nodes_by_project(cbm_store_t *s, const char *project);

/* Delete nodes by file path. */
int cbm_store_delete_nodes_by_file(cbm_store_t *s, const char *project, const char *file_path);

/* Delete nodes by label. */
int cbm_store_delete_nodes_by_label(cbm_store_t *s, const char *project, const char *label);

/* ── Edge CRUD ──────────────────────────────────────────────────── */

/* Insert or update edge. Returns edge ID (>0) or CBM_STORE_ERR. */
int64_t cbm_store_insert_edge(cbm_store_t *s, const cbm_edge_t *e);

/* Insert edges in batch. */
int cbm_store_insert_edge_batch(cbm_store_t *s, const cbm_edge_t *edges, int count);

/* Find edges by source node. */
int cbm_store_find_edges_by_source(cbm_store_t *s, int64_t source_id, cbm_edge_t **out, int *count);

/* Find edges by target node. */
int cbm_store_find_edges_by_target(cbm_store_t *s, int64_t target_id, cbm_edge_t **out, int *count);

/* Find edges by source + type. */
int cbm_store_find_edges_by_source_type(cbm_store_t *s, int64_t source_id, const char *type,
                                        cbm_edge_t **out, int *count);

/* Find edges by target + type. */
int cbm_store_find_edges_by_target_type(cbm_store_t *s, int64_t target_id, const char *type,
                                        cbm_edge_t **out, int *count);

/* Find all edges of a type in project. */
int cbm_store_find_edges_by_type(cbm_store_t *s, const char *project, const char *type,
                                 cbm_edge_t **out, int *count);

/* Count all edges in project. */
int cbm_store_count_edges(cbm_store_t *s, const char *project);

/* Count edges of given type. */
int cbm_store_count_edges_by_type(cbm_store_t *s, const char *project, const char *type);

/* Delete all edges for a project. */
int cbm_store_delete_edges_by_project(cbm_store_t *s, const char *project);

/* Delete edges by type. */
int cbm_store_delete_edges_by_type(cbm_store_t *s, const char *project, const char *type);

/* ── File hash CRUD ─────────────────────────────────────────────── */

int cbm_store_upsert_file_hash(cbm_store_t *s, const char *project, const char *rel_path,
                               const char *sha256, int64_t mtime_ns, int64_t size);

/* Read every authoritative indexed-file identity in binary path order. */
int cbm_store_get_file_hashes(cbm_store_t *s, const char *project, cbm_file_hash_t **out,
                              int *count);

/* Read the exact persisted identity of one indexed file. */
int cbm_store_get_file_identity(cbm_store_t *s, const char *project, const char *rel_path,
                                cbm_file_identity_t *out);

int cbm_store_delete_file_hash(cbm_store_t *s, const char *project, const char *rel_path);

int cbm_store_delete_file_hashes(cbm_store_t *s, const char *project);

/* ── Search ─────────────────────────────────────────────────────── */

int cbm_store_search(cbm_store_t *s, const cbm_search_params_t *params, cbm_search_output_t *out);

/* Free a search output's allocated memory. */
void cbm_store_search_free(cbm_search_output_t *out);

/* ── Traversal ──────────────────────────────────────────────────── */

int cbm_store_bfs(cbm_store_t *s, int64_t start_id, const char *direction, const char **edge_types,
                  int edge_type_count, int max_depth, int max_results, cbm_traverse_result_t *out);

/* Free a traverse result's allocated memory. */
void cbm_store_traverse_free(cbm_traverse_result_t *out);

/* ── Impact analysis ────────────────────────────────────────────── */

typedef enum {
    CBM_RISK_CRITICAL = 0,
    CBM_RISK_HIGH = 1,
    CBM_RISK_MEDIUM = 2,
    CBM_RISK_LOW = 3,
} cbm_risk_level_t;

/* Map BFS hop depth to risk level. */
cbm_risk_level_t cbm_hop_to_risk(int hop);

/* String representation of risk level. */
const char *cbm_risk_label(cbm_risk_level_t level);

typedef struct {
    int critical;
    int high;
    int medium;
    int low;
    int total;
    bool has_cross_service;
} cbm_impact_summary_t;

/* Build impact summary from visited hops and edges. */
cbm_impact_summary_t cbm_build_impact_summary(const cbm_node_hop_t *hops, int hop_count,
                                              const cbm_edge_info_t *edges, int edge_count);

/* Deduplicate BFS hops, keeping minimum hop per node ID.
 * Returns allocated array and count via out params. Caller frees result. */
int cbm_deduplicate_hops(const cbm_node_hop_t *hops, int hop_count, cbm_node_hop_t **out,
                         int *out_count);

/* ── Schema ─────────────────────────────────────────────────────── */

int cbm_store_get_schema(cbm_store_t *s, const char *project, cbm_schema_info_t *out);

/* Like cbm_store_get_schema but skips per-label/per-type JSON property-key
 * discovery (json_each scans over every row) — for callers that only need
 * label/type counts, e.g. get_architecture. */
int cbm_store_get_schema_counts(cbm_store_t *s, const char *project, cbm_schema_info_t *out);

int cbm_store_get_schema_counts_scoped(cbm_store_t *s, const char *project, const char *path,
                                       cbm_schema_info_t *out);

/* Free a schema info's allocated memory. */
void cbm_store_schema_free(cbm_schema_info_t *out);

/* ── Architecture ───────────────────────────────────────────────── */

typedef struct {
    const char *language;
    int file_count;
} cbm_language_count_t;

typedef struct {
    const char *name;
    int node_count;
    int fan_in;
    int fan_out;
} cbm_package_summary_t;

typedef struct {
    const char *name;
    const char *qualified_name;
    const char *file;
} cbm_entry_point_t;

typedef struct {
    const char *method;
    const char *path;
    const char *handler;
} cbm_route_info_t;

typedef struct {
    const char *name;
    const char *qualified_name;
    int fan_in;
} cbm_hotspot_t;

typedef struct {
    const char *from;
    const char *to;
    int call_count;
} cbm_cross_pkg_boundary_t;

typedef struct {
    const char *from;
    const char *to;
    const char *type;
    int count;
} cbm_service_link_t;

typedef struct {
    const char *name;
    const char *layer;
    const char *reason;
} cbm_package_layer_t;

typedef struct {
    int id;
    const char *label;
    int members;
    double cohesion;
    const char **top_nodes;
    int top_node_count;
    const char **packages;
    int package_count;
    const char **edge_types;
    int edge_type_count;
} cbm_cluster_info_t;

typedef struct {
    const char *path;
    const char *type; /* "dir" or "file" */
    int children;
} cbm_file_tree_entry_t;

typedef struct {
    /* Pointers first to minimize padding */
    cbm_language_count_t *languages;
    cbm_package_summary_t *packages;
    cbm_entry_point_t *entry_points;
    cbm_route_info_t *routes;
    cbm_hotspot_t *hotspots;
    cbm_cross_pkg_boundary_t *boundaries;
    cbm_service_link_t *services;
    cbm_package_layer_t *layers;
    cbm_cluster_info_t *clusters;
    cbm_file_tree_entry_t *file_tree;
    /* Counts after pointers */
    int language_count;
    int package_count;
    int entry_point_count;
    int route_count;
    int hotspot_count;
    int boundary_count;
    int service_count;
    int layer_count;
    int cluster_count;
    int file_tree_count;
} cbm_architecture_info_t;

int cbm_store_get_architecture(cbm_store_t *s, const char *project, const char *path,
                               const char **aspects, int aspect_count,
                               cbm_architecture_info_t *out);
void cbm_store_architecture_free(cbm_architecture_info_t *out);

/* ── ADR (Architecture Decision Record) ────────────────────────── */

#define CBM_ADR_MAX_LENGTH 8000

typedef struct {
    const char *project;
    const char *content;
    const char *created_at;
    const char *updated_at;
} cbm_adr_t;

int cbm_store_adr_store(cbm_store_t *s, const char *project, const char *content);
int cbm_store_adr_get(cbm_store_t *s, const char *project, cbm_adr_t *out);
int cbm_store_adr_delete(cbm_store_t *s, const char *project);
int cbm_store_adr_update_sections(cbm_store_t *s, const char *project, const char **keys,
                                  const char **values, int count, cbm_adr_t *out);
void cbm_store_adr_free(cbm_adr_t *adr);

/* ADR section parsing/rendering (pure functions, no store needed) */

enum { PROPS_MAX = 16 };

typedef struct {
    char *keys[PROPS_MAX];
    char *values[PROPS_MAX];
    int count;
} cbm_adr_sections_t;

cbm_adr_sections_t cbm_adr_parse_sections(const char *content);
char *cbm_adr_render(const cbm_adr_sections_t *sections);
int cbm_adr_validate_content(const char *content, char *errbuf, int errbuf_size);
int cbm_adr_validate_section_keys(const char **keys, int count, char *errbuf, int errbuf_size);
void cbm_adr_sections_free(cbm_adr_sections_t *s);

/* ── Search helpers (exposed for testing) ───────────────────────── */

/* Convert a glob pattern to SQL LIKE pattern. Caller must free result. */
char *cbm_glob_to_like(const char *pattern);

/* Extract literal substrings (>= 3 chars) from a regex pattern for LIKE pre-filtering.
 * Bails on alternation (|). Returns count of hints written to out[].
 * Each out[i] is malloc'd — caller must free each string. */
int cbm_extract_like_hints(const char *pattern, char **out, int max_out);

/* Prepend (?i) to a regex pattern if not already present.
 * Returns a static buffer — do NOT free. */
const char *cbm_ensure_case_insensitive(const char *pattern);

/* Strip leading (?i) from a regex pattern.
 * Returns a static buffer — do NOT free. */
const char *cbm_strip_case_flag(const char *pattern);

/* ── Architecture helpers (exposed for testing) ────────────────── */

const char *cbm_qn_to_package(const char *qn);
const char *cbm_qn_to_top_package(const char *qn);
bool cbm_is_test_file_path(const char *fp);
int cbm_store_find_architecture_docs(cbm_store_t *s, const char *project, char ***out, int *count);

/* ── Community detection (Leiden) ──────────────────────────────── */

typedef struct {
    int64_t src;
    int64_t dst;
} cbm_louvain_edge_t;

typedef struct {
    int64_t node_id;
    int community;
} cbm_louvain_result_t;

/* Multi-level Leiden community detection (Traag, Waltman & van Eck 2019,
 * arXiv:1810.08473): local moving + refinement + aggregation, repeated until
 * the partition can no longer be coarsened. Refinement guarantees every
 * reported community is internally connected. The resolution parameter
 * controls granularity (higher -> more, smaller communities); 1.0 is standard.
 * Allocates *out (length *out_count == node_count); the caller frees it. */
int cbm_leiden(const int64_t *nodes, int node_count, const cbm_louvain_edge_t *edges,
               int edge_count, double resolution, cbm_louvain_result_t **out, int *out_count);

/* Convenience wrapper: cbm_leiden with resolution 1.0. */
int cbm_louvain(const int64_t *nodes, int node_count, const cbm_louvain_edge_t *edges,
                int edge_count, cbm_louvain_result_t **out, int *out_count);

/* ── Memory management helpers ──────────────────────────────────── */

/* Free heap-allocated strings in a stack-allocated node (does NOT free the node itself). */
void cbm_node_free_fields(cbm_node_t *n);

/* Free heap-allocated strings in a stack-allocated project (does NOT free the project itself). */
void cbm_project_free_fields(cbm_project_t *p);

/* Free an array of nodes returned by find_nodes_by_* functions. */
void cbm_store_free_nodes(cbm_node_t *nodes, int count);

/* Free an array of edges returned by find_edges_by_* functions. */
void cbm_store_free_edges(cbm_edge_t *edges, int count);

/* Free an array of projects. */
void cbm_store_free_projects(cbm_project_t *projects, int count);

/* Free an array of file hashes. */
void cbm_store_free_file_hashes(cbm_file_hash_t *hashes, int count);

/* ── Vector search ───────────────────────────────────────────────── */

/* Public request boundary for semantic vector search.  MCP schema,
 * validation, and execution must all consume this exact value. */
#define CBM_VECTOR_SEARCH_MAX_KEYWORDS 32

/* Result from vector similarity search. */
typedef struct {
    int64_t node_id;
    char *atom_id;
    char *name;
    char *qualified_name;
    char *file_path;
    char *label;
    int start_line;
    int end_line;
    uint64_t start_byte;
    uint64_t end_byte;
    double score;
} cbm_vector_result_t;

/* Search for nodes similar to the given query keywords using stored RI vectors.
 * Builds a merged query vector from the keywords, then does cosine scan via
 * the cbm_cosine_i8 SQL function joined with the nodes table.
 * Returns results sorted by score DESC. Caller must free with cbm_store_free_vector_results. */
int cbm_store_vector_search(cbm_store_t *s, const char *project, const char **keywords,
                             int keyword_count, int limit, cbm_vector_result_t **out,
                             int *out_count, cbm_index_capability_t *observed_capability);

/* Free vector search results. */
void cbm_store_free_vector_results(cbm_vector_result_t *results, int count);

/* Count vectors for a project. Returns -1 on any read failure. */
int cbm_store_count_vectors(cbm_store_t *s, const char *project);

/* Publication-only physical readback. This scans V+T exactly once after an
 * index build; discovery and query admission use the O(1) committed manifest. */
int cbm_store_read_vector_state(cbm_store_t *s, const char *project,
                                cbm_vector_state_readback_t *out);

/* Execute an arbitrary SQL statement (pragmas, FTS5 maintenance, etc).
 * Returns CBM_STORE_OK on success. */
int cbm_store_exec(cbm_store_t *s, const char *sql);

#endif /* CBM_STORE_H */
