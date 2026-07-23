#ifndef CBM_SOURCE_SNAPSHOT_H
#define CBM_SOURCE_SNAPSHOT_H

#include "discover/discover.h"

typedef struct {
    char *root;
} cbm_source_snapshot_t;

/* Capture every discovered source/config input into one immutable, mirrored
 * snapshot and bind each file record to the captured bytes. */
int cbm_source_snapshot_capture(const char *repo_path, const cbm_discover_opts_t *opts,
                                cbm_file_info_t *files, int file_count,
                                cbm_source_snapshot_t *snapshot);

/* Remove the exact unique snapshot tree. Returns non-zero if any derived file
 * remains; callers must fail the run rather than orphaning opaque state. */
int cbm_source_snapshot_destroy(cbm_source_snapshot_t *snapshot);

#endif
