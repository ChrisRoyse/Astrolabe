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
 * its authoritative length remains byte-exact. Offsets follow the caller's
 * file order, so no path lookup or per-consumer source copy is required. */
typedef struct {
    uint8_t *bytes;
    size_t *offsets;
    size_t *lengths;
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

/* Read every immutable captured source exactly once, verify its recorded
 * SHA-256, and publish one ordered source slab. The operation is atomic: on
 * failure slab remains empty and no consumer can observe a partial corpus. */
int cbm_source_slab_build(const cbm_file_info_t *files, int file_count,
                          cbm_source_slab_t *slab);

/* Borrow one immutable entry. Returns NULL for an invalid index or malformed
 * slab; an exact empty source returns a non-NULL pointer with length zero. */
const uint8_t *cbm_source_slab_get(const cbm_source_slab_t *slab, int file_index,
                                   size_t *out_len);

void cbm_source_slab_destroy(cbm_source_slab_t *slab);

#endif
