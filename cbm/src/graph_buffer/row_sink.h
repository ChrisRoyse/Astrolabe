/*
 * row_sink.h - Borrowed dump-row callback contracts.
 *
 * The graph-buffer callbacks are the low-level node/edge dump hooks. The
 * pipeline v2 descriptor is the complete source-snapshot contract consumed by
 * embedders: every registered callback is mandatory and the final manifest is
 * emitted exactly once only after all rows have been accepted.
 */
#ifndef CBM_GRAPH_BUFFER_ROW_SINK_H
#define CBM_GRAPH_BUFFER_ROW_SINK_H

#include <stddef.h>
#include <stdint.h>

#include "foundation/index_capability.h"
#include "foundation/schema_version.h"

/* Dump-row sink structs. These rows are borrowed and valid only for the
 * callback duration. IDs are final SQLite IDs, not temporary graph-buffer IDs. */
typedef struct {
    int64_t id;
    const char *project;
    const char *label;
    const char *name;
    const char *atom_id;
    const char *qualified_name;
    const char *file_path;
    int start_line;
    int end_line;
    int source_present;
    const uint8_t *source_bytes;
    size_t source_len;
    const char *source_sha256;
    uint64_t start_byte;
    uint64_t end_byte;
    const char *properties_json;
} cbm_gbuf_row_node_t;

typedef struct {
    int64_t id;
    const char *project;
    int64_t source_id;
    int64_t target_id;
    const char *type;
    const char *properties_json;
    const char *url_path_gen;
    const char *local_name_gen;
} cbm_gbuf_row_edge_t;

typedef struct {
    const char *project;
    const char *rel_path;
    const char *sha256;
    int64_t mtime_ns;
    int64_t size;
} cbm_pipeline_row_file_hash_t;

typedef struct {
    const char *project;
    size_t node_count;
    size_t edge_count;
    size_t file_hash_count;
    uint32_t graph_schema_version;
    cbm_index_capability_t index_capability;
} cbm_pipeline_row_manifest_t;

/* Return 0 to continue. Any non-zero return aborts the publication. */
typedef int (*cbm_gbuf_row_node_sink_fn)(const cbm_gbuf_row_node_t *node, void *ctx);
typedef int (*cbm_gbuf_row_edge_sink_fn)(const cbm_gbuf_row_edge_t *edge, void *ctx);
typedef int (*cbm_pipeline_row_file_hash_sink_fn)(const cbm_pipeline_row_file_hash_t *file_hash,
                                                  void *ctx);
typedef int (*cbm_pipeline_row_complete_sink_fn)(const cbm_pipeline_row_manifest_t *manifest,
                                                 void *ctx);

/*
 * Frozen pipeline snapshot ABI v2. Do not append fields: publish a v3
 * descriptor for any incompatible extension. A non-NULL descriptor is accepted
 * only when abi_version/struct_size match exactly and every callback/context is
 * non-NULL. The pipeline copies the descriptor; callback rows remain borrowed
 * for the duration of each call.
 */
#define CBM_PIPELINE_ROW_SINK_ABI_V2 2U
typedef struct {
    uint32_t abi_version;
    size_t struct_size;
    cbm_gbuf_row_node_sink_fn node;
    cbm_gbuf_row_edge_sink_fn edge;
    cbm_pipeline_row_file_hash_sink_fn file_hash;
    cbm_pipeline_row_complete_sink_fn complete;
    void *ctx;
} cbm_pipeline_row_sink_v2_t;

#endif /* CBM_GRAPH_BUFFER_ROW_SINK_H */
