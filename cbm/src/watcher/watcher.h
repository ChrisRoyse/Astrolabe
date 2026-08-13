/*
 * watcher.h — File change watcher for auto-reindexing.
 *
 * Polls indexed projects for git changes (HEAD movement or dirty working tree)
 * and triggers re-indexing via a callback. Uses adaptive polling intervals
 * based on project size (5s base + 1s per 500 files, capped at 60s).
 *
 * Depends on: foundation, store (for project metadata)
 */
#ifndef CBM_WATCHER_H
#define CBM_WATCHER_H

#include <stdbool.h>
#include <stdint.h>

/* Forward declarations */
typedef struct cbm_store cbm_store_t;

/* ── Opaque handle ──────────────────────────────────────────────── */

typedef struct cbm_watcher cbm_watcher_t;

/* ── Index callback ─────────────────────────────────────────────── */

/* Stable callback triggers. Keep these in the public FFI contract so the C
 * watcher, standalone server, generated Rust binding, and resident lane cannot
 * silently assign different meanings to the same callback. */
#define CBM_WATCHER_SOURCE_CHANGED "CBM_WATCHER_SOURCE_CHANGED"
#define CBM_WATCHER_SOURCE_OBSERVATION_RECOVERED "CBM_WATCHER_SOURCE_OBSERVATION_RECOVERED"
#define CBM_WATCHER_GIT_CONTEXT_FAILED "CBM_WATCHER_GIT_CONTEXT_FAILED"
#define CBM_WATCHER_GIT_STATUS_FAILED "CBM_WATCHER_GIT_STATUS_FAILED"
#define CBM_WATCHER_GIT_IDENTITY_INVALID "CBM_WATCHER_GIT_IDENTITY_INVALID"
#define CBM_WATCHER_UNTRACKED_ALLOC_FAILED "CBM_WATCHER_UNTRACKED_ALLOC_FAILED"
#define CBM_WATCHER_UNTRACKED_READ_FAILED "CBM_WATCHER_UNTRACKED_READ_FAILED"
#define CBM_WATCHER_GIT_DIFF_FAILED "CBM_WATCHER_GIT_DIFF_FAILED"

/* Called when file changes or a fail-closed source-observation fault is detected.
 * trigger_code is CBM_WATCHER_SOURCE_CHANGED for an ordinary source delta,
 * CBM_WATCHER_SOURCE_OBSERVATION_RECOVERED after a prior observation fault
 * becomes readable without a source delta, and a stable CBM_WATCHER_* failure
 * code otherwise. Return 0 only after the trigger has been durably handled; the
 * watcher advances its source baseline only for CBM_WATCHER_SOURCE_CHANGED.
 * Return -1 on error.
 * project_name: project identifier
 * root_path: absolute path to the repository root */
typedef int (*cbm_index_fn)(const char *project_name, const char *root_path,
                            const char *trigger_code, void *user_data);

/* ── Lifecycle ──────────────────────────────────────────────────── */

/* Create a new watcher. store is used for project metadata lookups.
 * index_fn is called when file changes are detected.
 * user_data is passed to index_fn. */
cbm_watcher_t *cbm_watcher_new(cbm_store_t *store, cbm_index_fn index_fn, void *user_data);

/* Free the watcher and all per-project state. NULL-safe.
 * Precondition: cbm_watcher_stop() + thread join must have completed. */
void cbm_watcher_free(cbm_watcher_t *w);

/* ── Watch list management ──────────────────────────────────────── */

/* Add a project to the watch list. root_path is copied. */
void cbm_watcher_watch(cbm_watcher_t *w, const char *project_name, const char *root_path);

/* Remove a project from the watch list. */
void cbm_watcher_unwatch(cbm_watcher_t *w, const char *project_name);

/* Refresh a project's timestamp (resets adaptive backoff). */
void cbm_watcher_touch(cbm_watcher_t *w, const char *project_name);
/* Force one callback on the next due poll even when Git bytes are unchanged.
 * Used when the exact store/config observation that caused a durable fault moves. */
void cbm_watcher_invalidate(cbm_watcher_t *w, const char *project_name);

/* ── Polling ────────────────────────────────────────────────────── */

/* Run a single poll cycle — check each watched project for changes.
 * Returns the number of projects that were reindexed. */
int cbm_watcher_poll_once(cbm_watcher_t *w);

/* Run the blocking poll loop. Polls every base_interval_ms until
 * cbm_watcher_stop() is called. Returns 0 on clean shutdown. */
int cbm_watcher_run(cbm_watcher_t *w, int base_interval_ms);

/* Request the run loop to stop (thread-safe). */
void cbm_watcher_stop(cbm_watcher_t *w);

/* ── Introspection (for testing) ────────────────────────────────── */

/* Return the number of projects in the watch list. */
int cbm_watcher_watch_count(cbm_watcher_t *w);

/* Return the adaptive poll interval (ms) for a given file count. */
int cbm_watcher_poll_interval_ms(int file_count);

#endif /* CBM_WATCHER_H */
