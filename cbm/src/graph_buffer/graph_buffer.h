/*
 * graph_buffer.h — In-memory graph buffer for pipeline indexing.
 *
 * Holds all nodes and edges in RAM during indexing, then dumps to SQLite.
 * Provides O(1) node lookup by qualified name and edge dedup by key.
 *
 * Depends on: foundation (hash_table, dyn_array), store (data structs)
 */
#ifndef CBM_GRAPH_BUFFER_H
#define CBM_GRAPH_BUFFER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#include "graph_buffer/row_sink.h"
#include "cbm.h"

/* ── Opaque handle ──────────────────────────────────────────────── */

typedef struct cbm_gbuf cbm_gbuf_t;

/* Forward declare store for dump path */
typedef struct cbm_store cbm_store_t;

/* ── Node / Edge structs (owned by the buffer) ───────────────────── */

typedef struct {
    int64_t id;           /* temp ID (sequential from 1) */
    char *label;          /* heap-owned */
    char *name;           /* heap-owned */
    char *atom_id;        /* heap-owned stable source-atom SHA-256 */
    char *qualified_name; /* heap-owned */
    char *file_path;      /* heap-owned */
    int start_line;
    int end_line;
    bool source_present;   /* distinguishes no source from an exact empty source */
    uint8_t *source_bytes; /* heap-owned byte-exact source when source_present */
    size_t source_len;
    char *source_sha256; /* heap-owned lowercase SHA-256 when source_present */
    uint64_t start_byte; /* end-exclusive byte span within the indexed file */
    uint64_t end_byte;
    char *properties_json; /* heap-owned JSON string, "{}" default */
} cbm_gbuf_node_t;

typedef struct {
    int64_t id;            /* temp ID */
    int64_t source_id;     /* temp node ID */
    int64_t target_id;     /* temp node ID */
    char *type;            /* heap-owned */
    char *properties_json; /* heap-owned JSON string, "{}" default */
} cbm_gbuf_edge_t;

/* ── Lifecycle ──────────────────────────────────────────────────── */

/* Create a new graph buffer for a project. */
cbm_gbuf_t *cbm_gbuf_new(const char *project, const char *root_path);

/* Create a graph buffer with a shared atomic ID source.
 * IDs are allocated via atomic_fetch_add on *id_source.
 * Used for parallel extraction where multiple gbufs need unique IDs.
 * If id_source is NULL, behaves like cbm_gbuf_new(). */
cbm_gbuf_t *cbm_gbuf_new_shared_ids(const char *project, const char *root_path,
                                    _Atomic int64_t *id_source);

/* Free the graph buffer and all owned data. NULL-safe. */
void cbm_gbuf_free(cbm_gbuf_t *gb);

/* Merge all nodes and edges from src into dst.
 * Nodes are merged only by stable source atom. Qualified names are non-unique.
 * New nodes are inserted with their original IDs (from shared ID source).
 * Edges are remapped for any QN-colliding nodes, then inserted with dedup.
 * After merge, src can be safely freed (all data is copied).
 * Returns 0 on success, -1 on error. */
int cbm_gbuf_merge(cbm_gbuf_t *dst, cbm_gbuf_t *src);

/* ── Node operations ─────────────────────────────────────────────── */

/* Upsert a structural node without an attached source payload. Returns the temp ID.
 * All string fields are copied (buffer owns the copies). A NULL file_path is
 * canonical identity text for the empty path; a NULL properties_json is the
 * JSON object "{}". Those domains are canonicalized independently before any
 * identity hashing or retention.
 * Returns 0 on error. */
int64_t cbm_gbuf_upsert_node(cbm_gbuf_t *gb, const char *label, const char *name,
                             const char *qualified_name, const char *file_path, int start_line,
                             int end_line, const char *properties_json);

/* Upsert a source-backed node. source_bytes/source_len and the end-exclusive byte
 * span are identity-bearing and cross the row-sink/SQLite boundary unchanged.
 * source_bytes may be NULL only when source_len is zero (an exact empty source).
 * Returns 0 and poisons persistence on malformed input or allocation failure. */
int64_t cbm_gbuf_upsert_source_node(cbm_gbuf_t *gb, const char *label, const char *name,
                                    const char *qualified_name, const char *file_path,
                                    int start_line, int end_line, const uint8_t *source_bytes,
                                    size_t source_len, uint64_t start_byte, uint64_t end_byte,
                                    const char *properties_json);

/* Resolve a source-backed node by the complete canonical identity frame. */
const cbm_gbuf_node_t *cbm_gbuf_find_source_node(const cbm_gbuf_t *gb, const char *label,
                                                 const char *name, const char *qualified_name,
                                                 const char *file_path, int start_line,
                                                 int end_line, const uint8_t *source_bytes,
                                                 size_t source_len, uint64_t start_byte,
                                                 uint64_t end_byte);

/* Resolve an already-known stable atom without consulting its display QN. */
const cbm_gbuf_node_t *cbm_gbuf_find_by_atom_id(const cbm_gbuf_t *gb, const char *atom_id);

/* Resolve one source-backed container by its exact identity-bearing path domain.
 * Qualified names are intentionally not consulted: a semantic module alias may
 * name several physical source/header files. Exactly one live source atom with
 * the requested label and repository-relative file_path is returned. Multiple
 * matches poison persistence and emit complete candidate diagnostics. */
const cbm_gbuf_node_t *cbm_gbuf_find_source_container(const cbm_gbuf_t *gb, const char *label,
                                                      const char *file_path);

/* Mark a caller-diagnosed reference ambiguity as terminal for persistence.
 * Callers must emit a structured diagnostic before invoking this function. */
void cbm_gbuf_refuse_resolution(cbm_gbuf_t *gb);

/* Find a node by qualified name. Returns NULL if not found and poisons
 * persistence when the qualified name maps to multiple stable atoms. */
const cbm_gbuf_node_t *cbm_gbuf_find_by_qn(const cbm_gbuf_t *gb, const char *qn);

/* Resolve a semantic reference within the namespace retained from source
 * syntax. Qualified names are display/search keys, never stable identities.
 * Exactly one live atom in `domain` is returned. Zero in-domain candidates is
 * an ordinary miss (the textual registry candidate belonged to another
 * namespace); multiple in-domain candidates skip and count that reference
 * edge while emitting the operation plus every exact atom candidate. */
const cbm_gbuf_node_t *cbm_gbuf_find_by_qn_domain(const cbm_gbuf_t *gb, const char *qn,
                                                  CBMReferenceDomain domain, const char *operation);

/* Status-bearing form used by source attribution. `ambiguous` is set only
 * when multiple live atoms remain in the requested domain. This lets callers
 * skip that reference edge instead of incorrectly re-attributing it to a file
 * node after the counted ambiguity. */
const cbm_gbuf_node_t *cbm_gbuf_find_by_qn_domain_status(const cbm_gbuf_t *gb, const char *qn,
                                                         CBMReferenceDomain domain,
                                                         const char *operation, bool *ambiguous);

/* Resolve a qualified name at an exact source location. The path and 1-based
 * line are both required. Exactly one live atom whose inclusive line range
 * contains the location is returned; multiple matches poison persistence and
 * emit a structured error rather than selecting an arbitrary atom. */
const cbm_gbuf_node_t *cbm_gbuf_find_by_qn_location(const cbm_gbuf_t *gb, const char *qn,
                                                    const char *file_path, int line);

/* Resolve the persisted source owner of a semantic reference. The exact
 * repository path and 1-based line select live source-backed callable/type
 * atoms; the unique atom whose byte span is contained by every other
 * containing candidate is the owner. A claimed qualified name is used only to
 * disambiguate incomparable same-line siblings because extractor spelling may
 * describe an unpersisted nested callable or retain generic syntax. Invalid
 * spans and unresolved sibling ambiguity poison persistence and set *failed.
 * Zero candidates are an ordinary miss so the pipeline can emit its counted
 * reference-edge skip. */
const cbm_gbuf_node_t *cbm_gbuf_find_reference_owner_at(
    const cbm_gbuf_t *gb, const char *claimed_qn, const char *file_path, int line,
    const char *operation, bool *failed);

/* Match the successor of a changed atom for incremental edge re-resolution.
 * The semantic locator is exact (QN/path/label/name plus the prior signature
 * property when present). A deleted locator returns NULL; an existing but
 * signature-incompatible or ambiguous locator poisons persistence. */
const cbm_gbuf_node_t *cbm_gbuf_find_successor_node(const cbm_gbuf_t *gb,
                                                    const char *qualified_name,
                                                    const char *file_path, const char *label,
                                                    const char *name,
                                                    const char *previous_properties_json);

/* True after any canonical identity or reference-resolution failure. */
bool cbm_gbuf_resolution_failed(const cbm_gbuf_t *gb);

/* Number of reference edges skipped because their source syntax resolved to
 * several stable atoms in one semantic domain (#727). These are counted,
 * labelled degradations rather than failures: the corpus still publishes, so
 * callers MUST surface this count or the loss becomes silent. */
uint_least64_t cbm_gbuf_ambiguous_reference_skips(const cbm_gbuf_t *gb);

/* Record and diagnose a reference edge whose extracted syntax names an
 * enclosing callable but whose exact source atom cannot be found. Such a
 * reference must never be silently re-attributed to the containing File.
 * The corpus may still publish, so every skip is counted for the index result. */
void cbm_gbuf_record_unresolved_reference_source(const cbm_gbuf_t *gb, const char *operation,
                                                 const char *qualified_name, const char *file_path,
                                                 int source_line);
uint_least64_t cbm_gbuf_unresolved_reference_source_skips(const cbm_gbuf_t *gb);

/* Find a node by temp ID. Returns NULL if not found. */
const cbm_gbuf_node_t *cbm_gbuf_find_by_id(const cbm_gbuf_t *gb, int64_t id);

/* Find nodes by label. Sets *out and *count. Caller does NOT free.
 * Returns 0 on success, -1 on error. */
int cbm_gbuf_find_by_label(const cbm_gbuf_t *gb, const char *label, const cbm_gbuf_node_t ***out,
                           int *count);

/* Find nodes by name (exact). Sets *out and *count. Caller does NOT free. */
int cbm_gbuf_find_by_name(const cbm_gbuf_t *gb, const char *name, const cbm_gbuf_node_t ***out,
                          int *count);

/* Count total nodes in buffer. */
int cbm_gbuf_node_count(const cbm_gbuf_t *gb);

/* Get the next ID that would be assigned. Used to initialize shared atomic counters. */
int64_t cbm_gbuf_next_id(const cbm_gbuf_t *gb);

/* Set the next ID counter. Used after merging worker gbufs to sync the main counter. */
void cbm_gbuf_set_next_id(cbm_gbuf_t *gb, int64_t next_id);

/* Delete all nodes with a label. Cascade-deletes referencing edges. */
int cbm_gbuf_delete_by_label(cbm_gbuf_t *gb, const char *label);

/* Delete all nodes for a given file path. Cascade-deletes referencing edges.
 * Used by incremental indexing to remove stale nodes before re-extraction. */
int cbm_gbuf_delete_by_file(cbm_gbuf_t *gb, const char *file_path);

/* Bulk-load all nodes and edges for a project from a source-preserving verified
 * read-only SQLite connection into this graph buffer. The source DB/WAL/SHM
 * family is never opened through a writer or mutated. Returns 0 on success. */
int cbm_gbuf_load_from_db(cbm_gbuf_t *gb, const char *db_path, const char *project);

/* Iterate all live nodes (not deleted from QN index). */
typedef void (*cbm_gbuf_node_visitor_fn)(const cbm_gbuf_node_t *node, void *userdata);
void cbm_gbuf_foreach_node(const cbm_gbuf_t *gb, cbm_gbuf_node_visitor_fn fn, void *userdata);

/* Iterate all edges. */
typedef void (*cbm_gbuf_edge_visitor_fn)(const cbm_gbuf_edge_t *edge, void *userdata);
void cbm_gbuf_foreach_edge(const cbm_gbuf_t *gb, cbm_gbuf_edge_visitor_fn fn, void *userdata);

/* Install row-sink callbacks used by the dump path. NULL callbacks preserve the
 * normal SQLite dump behavior and emit no sink rows. The graph buffer does not
 * take ownership of ctx. */
void cbm_gbuf_set_row_sink(cbm_gbuf_t *gb, cbm_gbuf_row_node_sink_fn node_cb,
                           cbm_gbuf_row_edge_sink_fn edge_cb, void *ctx);

/* ── Edge operations ─────────────────────────────────────────────── */

/* Insert an edge. Deduplicates by (source_id, target_id, type).
 * A NULL properties_json is canonicalized to the JSON object "{}".
 * On duplicate, merges properties (later wins). Returns edge temp ID.
 * Returns 0 on error. */
int64_t cbm_gbuf_insert_edge(cbm_gbuf_t *gb, int64_t source_id, int64_t target_id, const char *type,
                             const char *properties_json);

/* Find edges from source_id with given type.
 * Sets *out and *count. Caller does NOT free. */
int cbm_gbuf_find_edges_by_source_type(const cbm_gbuf_t *gb, int64_t source_id, const char *type,
                                       const cbm_gbuf_edge_t ***out, int *count);

/* Find edges to target_id with given type. */
int cbm_gbuf_find_edges_by_target_type(const cbm_gbuf_t *gb, int64_t target_id, const char *type,
                                       const cbm_gbuf_edge_t ***out, int *count);

/* Find all edges of a given type. */
int cbm_gbuf_find_edges_by_type(const cbm_gbuf_t *gb, const char *type,
                                const cbm_gbuf_edge_t ***out, int *count);

/* Count total edges. */
int cbm_gbuf_edge_count(const cbm_gbuf_t *gb);

/* Count edges of a given type. */
int cbm_gbuf_edge_count_by_type(const cbm_gbuf_t *gb, const char *type);

/* Delete all edges of a type. */
int cbm_gbuf_delete_edges_by_type(cbm_gbuf_t *gb, const char *type);

/* ── Vector storage (for semantic embeddings) ───────────────────── */

/* Store an int8-quantized vector for a node. The vector data is copied.
 * Called by pass_semantic_edges after computing RI vectors.
 * Vectors are carried through to cbm_write_db during the dump phase. */
int cbm_gbuf_store_vector(cbm_gbuf_t *gb, int64_t node_id, const uint8_t *vector, int vector_len);

/* Store an enriched token vector for query-time lookup.
 * Called by pass_semantic_edges after corpus finalization.
 * Token string and vector data are copied. */
int cbm_gbuf_store_token_vector(cbm_gbuf_t *gb, const char *token, const uint8_t *vector,
                                int vector_len, float idf);

/* ── Dump to SQLite ──────────────────────────────────────────────── */

/* Dump the entire buffer to a SQLite file using the direct page writer.
 * Assigns sequential final IDs and remaps edge references.
 * Returns 0 on success, -1 on error. */
int cbm_gbuf_dump_to_sqlite(cbm_gbuf_t *gb, const char *path);

/* Flush the buffer to an existing store via the store API.
 * Deletes existing project data first. Returns 0 on success. */
int cbm_gbuf_flush_to_store(cbm_gbuf_t *gb, cbm_store_t *store);

/* Merge the buffer into an existing store WITHOUT deleting existing data.
 * Upserts nodes, inserts edges. Used for incremental indexing.
 * Returns 0 on success. */
int cbm_gbuf_merge_into_store(cbm_gbuf_t *gb, cbm_store_t *store);

#endif /* CBM_GRAPH_BUFFER_H */
