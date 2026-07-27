#ifndef CBM_SOURCE_SNAPSHOT_H
#define CBM_SOURCE_SNAPSHOT_H

#include "discover/discover.h"
#include "store/store.h"

typedef struct {
    char *root;
} cbm_source_snapshot_t;

/* Capture every discovered source/config input into one immutable, mirrored
 * snapshot and bind each file record to the captured bytes. */
int cbm_source_snapshot_capture(const char *repo_path, const cbm_discover_opts_t *opts,
                                cbm_file_info_t *files, int file_count,
                                cbm_source_snapshot_t *snapshot);

/* Prove whether the complete live discovery is byte-identical to the persisted
 * file-hash generation without creating a mirrored snapshot. Every candidate is
 * hashed through a retained read-only/write-denying handle, its exact identity
 * is re-read, and the repository namespace is rediscovered before true is
 * returned. A content/path/size difference is an ordinary false result; any
 * unevaluable identity or namespace is a terminal error. */
int cbm_source_snapshot_verify_unchanged(const char *repo_path, const cbm_discover_opts_t *opts,
                                         cbm_file_info_t *files, int file_count,
                                         const cbm_file_hash_t *stored, int stored_count,
                                         bool *out_unchanged);

/* Remove the exact unique snapshot tree. Returns non-zero if any derived file
 * remains; callers must fail the run rather than orphaning opaque state. */
int cbm_source_snapshot_destroy(cbm_source_snapshot_t *snapshot);

#endif
