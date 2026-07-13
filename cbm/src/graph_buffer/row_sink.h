/*
 * row_sink.h - Borrowed dump-row callback contract for graph-buffer and pipeline sinks.
 */
#ifndef CBM_GRAPH_BUFFER_ROW_SINK_H
#define CBM_GRAPH_BUFFER_ROW_SINK_H

#include <stdint.h>

/* Dump-row sink structs. These rows are borrowed and valid only for the
 * callback duration. IDs are final SQLite IDs, not temporary graph-buffer IDs. */
typedef struct {
    int64_t id;
    const char *project;
    const char *label;
    const char *name;
    const char *qualified_name;
    const char *file_path;
    int start_line;
    int end_line;
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

/* Return 0 to continue. Any non-zero return aborts the dump with -1. */
typedef int (*cbm_gbuf_row_node_sink_fn)(const cbm_gbuf_row_node_t *node, void *ctx);
typedef int (*cbm_gbuf_row_edge_sink_fn)(const cbm_gbuf_row_edge_t *edge, void *ctx);

#endif /* CBM_GRAPH_BUFFER_ROW_SINK_H */
