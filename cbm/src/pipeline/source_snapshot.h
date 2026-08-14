#ifndef CBM_SOURCE_SNAPSHOT_H
#define CBM_SOURCE_SNAPSHOT_H

#include "discover/discover.h"
#include "store/store.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char *root;
} cbm_source_snapshot_t;

/* One content-addressed, immutable in-memory view of the captured source
 * corpus. Every entry is NUL-terminated for parsers that inspect text while
 * its authoritative length remains byte-exact. Each index is bound to an exact
 * relative path; copied/subset file views retain that stable index rather than
 * reinterpreting their local position. */
typedef struct {
    uint8_t *bytes;
    size_t *offsets;
    size_t *lengths;
    const char **rel_paths;
    size_t source_bytes;
    size_t storage_bytes;
    size_t allocated_bytes;
    int file_count;
    char sha256[65];
} cbm_source_slab_t;

/* Capture every discovered source/config input into one immutable, mirrored
 * snapshot and bind each file record to the captured bytes. All workers are
 * joined before return. Once root creation succeeds, snapshot owns that root on
 * both success and failure; the caller must invoke cbm_source_snapshot_destroy
 * exactly once so partial derived files have one cleanup owner. */
int cbm_source_snapshot_capture(const char *repo_path, const char *store_path,
                                const cbm_discover_opts_t *opts, cbm_file_info_t *files,
                                int file_count, uint64_t progress_total,
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

/* Read every immutable captured source exactly once, verify its recorded
 * SHA-256, and publish one ordered source slab. The operation is atomic: on
 * failure slab remains empty and no consumer can observe a partial corpus. */
int cbm_source_slab_build(const cbm_file_info_t *files, int file_count,
                          uint64_t progress_total, cbm_source_slab_t *slab);

void cbm_source_slab_destroy(cbm_source_slab_t *slab);

#endif
