/*
 * artifact.h — Persistent artifact export/import for team sharing.
 *
 * Exports the SQLite knowledge graph as a zstd-compressed artifact
 * to .codebase-memory/graph.db.zst in the repository. Teammates
 * can import the artifact to bootstrap their local index instead
 * of running a full pipeline from scratch.
 */
#ifndef CBM_ARTIFACT_H
#define CBM_ARTIFACT_H

#include <stdbool.h>
#include <stdint.h>

#include "foundation/constants.h"

#define CBM_ARTIFACT_FILENAME "graph.db.zst"
#define CBM_ARTIFACT_META "artifact.json"
#define CBM_ARTIFACT_DIR CBM_REPOSITORY_STATE_DIR

/* Export quality levels */
enum {
    CBM_ARTIFACT_FAST = 0, /* zstd -3, no index stripping (watcher path) */
    CBM_ARTIFACT_BEST = 1, /* zstd -9 + drop indexes + VACUUM INTO (explicit index) */
};

typedef int32_t cbm_artifact_import_status_t;
enum {
    CBM_ARTIFACT_IMPORT_OK = 0,
    CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION = 1,
    CBM_ARTIFACT_IMPORT_FAILED_AFTER_PUBLICATION = 2,
    CBM_ARTIFACT_IMPORT_INVALID_ARGUMENT = 3,
    /* v2 carries the exact installed-generation provenance (#976): what was
     * imported, from which artifact bytes, and which historical generation it
     * represents. Without those fields an installed bootstrap is physically
     * indistinguishable from a live index of the requested generation. */
    CBM_ARTIFACT_IMPORT_ABI_VERSION = 2,
};

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    cbm_artifact_import_status_t status;
    uint32_t publication_started;
    uint32_t publication_committed;
    int32_t destination_probe;
    uint32_t destination_probe_native_error;
    char operation[128];
    char detail[512];
    char destination_db_path[4096];
    /* Exact provenance of the installed generation (#976). Populated as soon as
     * each fact is verified, so a failure diagnostic carries everything already
     * proven. `installed_*` describe the database this import published; the
     * revert path binds to them so it can only ever remove its own bytes. */
    char artifact_source_path[4096];
    char artifact_compressed_sha256[65];
    char installed_database_sha256[65];
    char artifact_commit[64];
    char artifact_created_utc[32];
    int32_t artifact_nodes;
    int32_t artifact_edges;
    uint64_t installed_database_bytes;
} cbm_artifact_import_result_t;

typedef int32_t cbm_artifact_revert_status_t;
enum {
    /* The exact bootstrap-installed family was removed and its absence read back. */
    CBM_ARTIFACT_REVERT_REMOVED = 0,
    /* The destination no longer matches the exact installed identity, so nothing
     * was deleted. Preserving unexpected bytes always outranks reverting. */
    CBM_ARTIFACT_REVERT_IDENTITY_MISMATCH = 1,
    /* The identity matched but removal or its absence readback failed. */
    CBM_ARTIFACT_REVERT_REMOVE_FAILED = 2,
    CBM_ARTIFACT_REVERT_INVALID_ARGUMENT = 3,
    CBM_ARTIFACT_REVERT_ABI_VERSION = 1,
};

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    cbm_artifact_revert_status_t status;
    int32_t destination_probe;
    uint32_t destination_probe_native_error;
    uint32_t sidecars_absent;
    uint64_t observed_bytes;
    uint64_t expected_bytes;
    char observed_sha256[65];
    char expected_sha256[65];
    char operation[128];
    char detail[512];
} cbm_artifact_revert_result_t;

/* Export DB to .codebase-memory/graph.db.zst artifact.
 * quality: CBM_ARTIFACT_FAST or CBM_ARTIFACT_BEST.
 * Creates .codebase-memory/ dir, .gitattributes, and artifact.json.
 * Returns 0 on success, -1 on error. */
int cbm_artifact_export(const char *db_path, const char *repo_path, const char *project_name,
                        int quality);

/* Get details for the most recent export failure on this thread.
 * Returns NULL if no export error is recorded. */
const char *cbm_artifact_export_last_error(void);

/* Import artifact from .codebase-memory/graph.db.zst to cache_db_path.
 * Decompresses, verifies its content-bound metadata and expected project,
 * normalizes the private database, and publishes it with no replacement.
 * Returns an exact CBM_ARTIFACT_IMPORT_* status and fills result. */
cbm_artifact_import_status_t cbm_artifact_import(
    const char *repo_path, const char *cache_db_path, const char *expected_project,
    cbm_artifact_import_result_t *result);

/* Revert an artifact bootstrap whose indexing generation did not publish (#976).
 * A bootstrap installs a historical graph at the canonical destination *before*
 * the live pipeline runs; if that pipeline never publishes, leaving the import
 * in place would expose an older generation as though the failed request had
 * produced it. This removes the destination only when it is still byte-for-byte
 * the family this import installed: DB present at `expected_bytes` hashing to
 * `expected_sha256`, with -wal/-shm exactly absent. Any other observation is an
 * identity mismatch that preserves every byte and refuses. */
cbm_artifact_revert_status_t cbm_artifact_revert_bootstrap(
    const char *cache_db_path, const char *expected_sha256, uint64_t expected_bytes,
    cbm_artifact_revert_result_t *result);

/* Check if a compatible artifact exists in repo_path/.codebase-memory/.
 * Returns true only when the metadata contract, compressed size/hash, and
 * decompressed frame size all match the physical payload. */
bool cbm_artifact_exists(const char *repo_path);

/* Get the git commit hash from artifact metadata. Caller must free().
 * Returns NULL if artifact doesn't exist or has no commit field. */
char *cbm_artifact_commit(const char *repo_path);

/* Whether repo_path is safe to interpolate into a double-quoted `git -C "…"` shell
 * command (as artifact.c does via cbm_popen). Rejects quote / backslash / shell
 * substitution metacharacters (cbm_validate_shell_arg); on Windows also rejects the
 * cmd.exe expansion metacharacters % ! ^. Spaces ARE allowed — double quotes handle
 * them on both POSIX sh and cmd.exe (single quotes, which cmd.exe does not honor,
 * were the pre-existing bug). Exposed so the shell-safety contract is unit-tested. */
bool cbm_artifact_repo_path_is_shell_safe(const char *repo_path);

#endif /* CBM_ARTIFACT_H */
