/*
 * load_error.h — Exact diagnostic handoff for verified graph reloads.
 *
 * This is an internal pipeline/graph-buffer boundary, not an FFI surface.
 * Fixed storage keeps the first causal failure valid after every SQLite
 * statement, verified snapshot, and graph buffer has been released.
 */
#ifndef CBM_GRAPH_BUFFER_LOAD_ERROR_H
#define CBM_GRAPH_BUFFER_LOAD_ERROR_H

#include "foundation/constants.h"
#include "graph_buffer/graph_buffer.h"

#include <stddef.h>

typedef struct {
    char code[CBM_SZ_64];
    char operation[CBM_SZ_128];
    char phase[CBM_SZ_64];
    char path[CBM_SZ_1K];
    char message[CBM_SZ_512];
    char remediation[CBM_SZ_512];
    size_t requested;
} cbm_gbuf_load_error_t;

/*
 * Load through the same verified, source-preserving boundary as
 * cbm_gbuf_load_from_db and retain the exact first failure in `error`.
 * `error` is cleared before use and may be NULL when only the return status is
 * required. No failure is retried through a writer or weaker verifier.
 */
int cbm_gbuf_load_from_db_checked(cbm_gbuf_t *gb, const char *db_path, const char *project,
                                  cbm_gbuf_load_error_t *error);

/* Restore vector rows and the persisted semantic capability as well as graph
 * rows. This is reserved for unchanged generations that will be re-materialized;
 * changed incremental generations recompute enrichment instead. */
int cbm_gbuf_load_from_db_checked_with_semantics(cbm_gbuf_t *gb, const char *db_path,
                                                 const char *project,
                                                 cbm_gbuf_load_error_t *error);

#endif
