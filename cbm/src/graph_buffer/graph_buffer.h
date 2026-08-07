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
    uint8_t *source_bytes; /* byte-exact source when source_present */
    size_t source_len;
    bool source_borrowed; /* immutable source slab owns source_bytes when true */
    char *source_sha256;  /* heap-owned lowercase SHA-256 when source_present */
    uint64_t start_byte;  /* end-exclusive byte span within the indexed file */
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
 * After merge, src can be safely freed. Owned data is copied; immutable
 * source-slab references remain borrowed from the enclosing pipeline slab.
 * src's retained refusal record AND its counted skip counters
 * (cbm_gbuf_ambiguous_reference_skips, cbm_gbuf_unresolved_reference_source_skips)
 * both cross into dst, including when src refused or is empty (#1022, #1028):
 * freeing src therefore never deletes a labelled degradation.
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

/* Upsert a source-backed node while borrowing immutable bytes whose lifetime
 * encloses the graph buffer. Identity, hashing, row-sink, and persistence
 * semantics are identical; only the redundant source allocation is removed. */
int64_t cbm_gbuf_upsert_source_node_borrowed(cbm_gbuf_t *gb, const char *label, const char *name,
                                             const char *qualified_name, const char *file_path,
                                             int start_line, int end_line,
                                             const uint8_t *source_bytes, size_t source_len,
                                             uint64_t start_byte, uint64_t end_byte,
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

/* Replace only the derived properties of the unique exact source container.
 * Identity and source bytes remain immutable. Returns 0 on success and poisons
 * persistence on absent/ambiguous input, malformed JSON, or allocation failure. */
int cbm_gbuf_replace_source_container_properties(cbm_gbuf_t *gb, const char *label,
                                                 const char *file_path,
                                                 const char *properties_json);

/* Apply one RFC 7386 object patch to the derived properties of the unique exact
 * source container. Existing unrelated fields are retained and patch keys
 * replace their prior values. Identity and source bytes remain immutable.
 * Returns 0 on success and poisons persistence on absent/ambiguous input,
 * malformed object JSON, merge/write failure, or allocation failure. */
int cbm_gbuf_merge_source_container_properties(cbm_gbuf_t *gb, const char *label,
                                               const char *file_path,
                                               const char *properties_patch_json);

/* Mark a caller-diagnosed reference ambiguity as terminal for persistence.
 * Callers must emit a structured diagnostic before invoking this function AND
 * pass its exact `code` plus the resolving `operation`: the buffer retains them
 * so the owning pipeline can publish the cause as the run's terminal
 * diagnostic. Refusing without a cause left the MCP response with nothing but a
 * pointer to a worker log (#1022), so the cause is not optional. */
void cbm_gbuf_refuse_resolution(cbm_gbuf_t *gb, const char *code, const char *operation);

/* Same, plus the refusing site's own message and structured detail pairs
 * (#1024). The 2-argument form retained only (code, operation), so the paths,
 * module names, and candidate identities a call site had already computed
 * reached nothing but a worker log — exactly the archaeology #1022 set out to
 * delete. `detail_keys`/`detail_vals` are index-aligned; up to
 * CBM_GBUF_REFUSAL_DETAIL_MAX pairs with a non-empty key and non-NULL value are
 * copied into buffer-owned fixed storage (keys truncate at CBM_SZ_64, values at
 * CBM_SZ_512). `message` describes the failing site itself; pass NULL to keep
 * the generic graph-buffer wrapper text. First-writer-wins, exactly like the
 * 2-argument form. */
void cbm_gbuf_refuse_resolution_detail(cbm_gbuf_t *gb, const char *code, const char *operation,
                                       const char *message, const char *const *detail_keys,
                                       const char *const *detail_vals, size_t detail_count);

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
 * contains the location is returned.
 *
 * (file_path, line) is not a discriminating identity on a minified bundle: a
 * whole generated file is one physical line, so every same-named atom in it
 * shares the line and the resolution refused, poisoning the corpus (#1022).
 * Tree-sitter already produces exact end-exclusive byte spans, so the caller
 * passes the reference's own source byte (`ref_byte_valid` false when it has
 * none) and it narrows a multi-candidate line match to the candidates whose
 * span actually contains that byte. Byte narrowing is applied ONLY after the
 * line filter is ambiguous, so single-candidate resolutions — every ordinary
 * source file — keep their exact previous result. No tolerance is invented: if
 * several atoms still contain the byte, the resolution still refuses. */
const cbm_gbuf_node_t *cbm_gbuf_find_by_qn_location(const cbm_gbuf_t *gb, const char *qn,
                                                    const char *file_path, int line,
                                                    uint64_t ref_byte, bool ref_byte_valid);

/* Resolve the persisted source owner of a semantic reference. The exact
 * repository path and 1-based line select live source-backed callable/type
 * atoms; the unique atom whose byte span is contained by every other
 * containing candidate is the owner. A claimed qualified name is used only to
 * disambiguate incomparable same-line siblings because extractor spelling may
 * describe an unpersisted nested callable or retain generic syntax. Invalid
 * spans and unresolved sibling ambiguity poison persistence and set *failed.
 * Zero candidates are an ordinary miss so the pipeline can emit its counted
 * reference-edge skip. */
const cbm_gbuf_node_t *cbm_gbuf_find_reference_owner_at(const cbm_gbuf_t *gb,
                                                        const char *claimed_qn,
                                                        const char *file_path, int line,
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

/* ── Terminal refusal record ─────────────────────────────────────── */

enum { CBM_GBUF_REFUSAL_CANDIDATE_MAX = 4 };

/* Bound on site-supplied refusal detail pairs (#1024). Sized so the widest
 * converted call site — the ECMAScript extension-substitution family, whose
 * evidence is its component, source file, module, match count, and all five
 * probed candidate paths — fits without truncating away a candidate, while the
 * whole record stays fixed-size buffer-owned storage. Pairs beyond this bound
 * are dropped, so a site must order its most identifying pairs first. */
enum { CBM_GBUF_REFUSAL_DETAIL_MAX = 10 };

/* The exact first graph-buffer refusal, retained so the owning pipeline can
 * publish it as the run's terminal diagnostic. Without it a refusal only ever
 * reached a worker log line and the MCP response carried no captured cause
 * (#1022). Every pointer is borrowed from the buffer and valid until
 * cbm_gbuf_free(). Absent fields are NULL / 0. */
typedef struct {
    const char *code;           /* CBM_* refusal code, never NULL when present */
    const char *operation;      /* resolving operation, may be NULL */
    const char *qualified_name; /* contended identity, may be NULL */
    const char *file_path;      /* owning repository path, may be NULL */
    int line;                   /* 1-based source line, 0 when unknown */
    int candidate_count;        /* live candidates that tied, 0 when N/A */
    const char *candidate_atom_ids[CBM_GBUF_REFUSAL_CANDIDATE_MAX];
    int candidate_atom_id_count;
    /* Site-supplied cause (#1024). `message` is NULL when the refusing site
     * supplied none, and the reader keeps its generic wrapper text. The detail
     * arrays are index-aligned and hold `detail_count` borrowed pairs. */
    const char *message;
    const char *detail_keys[CBM_GBUF_REFUSAL_DETAIL_MAX];
    const char *detail_vals[CBM_GBUF_REFUSAL_DETAIL_MAX];
    int detail_count;
} cbm_gbuf_refusal_t;

/* Read the retained first refusal. Returns false and zeroes `out` when the
 * buffer recorded no structured refusal (resolution may still have failed —
 * callers must consult cbm_gbuf_resolution_failed separately). */
bool cbm_gbuf_get_refusal(const cbm_gbuf_t *gb, cbm_gbuf_refusal_t *out);

/* Number of reference edges skipped because their source syntax resolved to
 * several stable atoms in one semantic domain (#727). These are counted,
 * labelled degradations rather than failures: the corpus still publishes, so
 * callers MUST surface this count or the loss becomes silent. The count is
 * cumulative over every buffer merged into this one (#1028), so reading it from
 * the pipeline's own graph buffer is complete regardless of worker count. */
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

/* Advance the next-ID counter after merging worker gbufs. A regressing handoff
 * poisons the graph so persistence refuses instead of hiding live high-ID rows. */
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

/* Insert an edge. Deduplicates by the schema-v5 tuple
 * (source_id, target_id, type, IMPORTS local_name, preprocess_context_id).
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
