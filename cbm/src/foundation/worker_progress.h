/*
 * worker_progress.h — private semantic progress protocol for supervised work.
 *
 * Operational logs are diagnostic output, not a liveness contract.  A worker
 * publishes fixed-size, hash-chained records here only after real computation
 * advances. The supervisor consumes each new record once, validates the exact
 * attempt and hierarchical work cursor before resetting its quiet budget, and
 * re-reads the bounded stream once at terminal state to detect prior rewrites.
 */
#ifndef CBM_WORKER_PROGRESS_H
#define CBM_WORKER_PROGRESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    CBM_WORKER_PROGRESS_ATTEMPT_HEX_LEN = 64,
    CBM_WORKER_PROGRESS_NAME_CAP = 32,
    CBM_WORKER_PROGRESS_RECORD_SIZE = 288,
    /* Actual semantic advancement is reported at most this far apart. This is
     * 1/30 of the supervisor's unchanged 900-second no-progress budget. */
    CBM_WORKER_PROGRESS_MAX_REPORT_INTERVAL_MS = 30000,
};

/* An explicitly unknown denominator. It is encoded, validated, and surfaced as
 * unknown; callers must never invent an estimated total merely to fill a field. */
#define CBM_WORKER_PROGRESS_TOTAL_UNKNOWN UINT64_MAX

/* Ordered top-level stages. A route may skip stages, but it may never regress. */
typedef enum {
    CBM_WORKER_PROGRESS_STAGE_STARTUP = 1,
    CBM_WORKER_PROGRESS_STAGE_DISCOVERY = 2,
    CBM_WORKER_PROGRESS_STAGE_SOURCE_CAPTURE = 3,
    CBM_WORKER_PROGRESS_STAGE_STRUCTURE = 4,
    CBM_WORKER_PROGRESS_STAGE_PARALLEL_EXTRACT = 5,
    CBM_WORKER_PROGRESS_STAGE_COMPILER_PREPROCESS = 6,
    CBM_WORKER_PROGRESS_STAGE_REGISTRY = 7,
    CBM_WORKER_PROGRESS_STAGE_RESOLVE = 8,
    CBM_WORKER_PROGRESS_STAGE_ENRICH = 9,
    CBM_WORKER_PROGRESS_STAGE_PREDUMP = 10,
    CBM_WORKER_PROGRESS_STAGE_PERSIST = 11,
    CBM_WORKER_PROGRESS_STAGE_COMPLETE = 12,
} cbm_worker_progress_stage_t;

/* Configure/reset the one worker-local writer. Configure requires an absent
 * path and a 64-character lowercase hexadecimal attempt identity. */
int cbm_worker_progress_configure(const char *path, const char *attempt);
void cbm_worker_progress_reset(void);
bool cbm_worker_progress_active(void);
bool cbm_worker_progress_failed(void);

/* Publish one strictly-forward hierarchical cursor. Within a stage,
 * completed/total describe completed top-level units. step_order and the step
 * counts describe forward work inside the current top-level unit. A higher
 * stage or completed count may reset the subordinate cursor; otherwise the
 * subordinate cursor must advance. Inactive (non-worker) processes succeed
 * without creating state. */
int cbm_worker_progress_publish(uint32_t stage_order, const char *stage, uint64_t completed,
                                uint64_t total, uint32_t step_order, const char *step,
                                uint64_t step_completed, uint64_t step_total);

/* Thread-safe completion counter for a stage. The first completion, actual work
 * observed after the bounded report interval, and the terminal completion emit
 * records. Increment and sequence state are serialized together, so parallel
 * completion order cannot manufacture a regressed cursor. */
int cbm_worker_progress_advance_unit(uint32_t stage_order, const char *stage, uint64_t total);

/* Publish the terminal semantic record after the response file has been fully
 * written and closed. A successful/result-bearing worker may not exit without
 * this record. */
int cbm_worker_progress_complete(void);

typedef enum {
    CBM_WORKER_PROGRESS_POLL_INVALID = -1,
    CBM_WORKER_PROGRESS_POLL_IDLE = 0,
    CBM_WORKER_PROGRESS_POLL_ADVANCED = 1,
} cbm_worker_progress_poll_result_t;

typedef struct cbm_worker_progress_reader cbm_worker_progress_reader_t;

cbm_worker_progress_reader_t *cbm_worker_progress_reader_new(const char *path,
                                                             const char *attempt);
void cbm_worker_progress_reader_free(cbm_worker_progress_reader_t *reader);

/* terminal=true additionally requires a present stream with no partial tail
 * and re-hashes every consumed byte to detect an earlier rewrite. */
cbm_worker_progress_poll_result_t
cbm_worker_progress_reader_poll(cbm_worker_progress_reader_t *reader, bool terminal);

const char *cbm_worker_progress_reader_error_code(const cbm_worker_progress_reader_t *reader);
const char *cbm_worker_progress_reader_error_detail(const cbm_worker_progress_reader_t *reader);
uint64_t cbm_worker_progress_reader_record_count(const cbm_worker_progress_reader_t *reader);
uint32_t cbm_worker_progress_reader_stage_order(const cbm_worker_progress_reader_t *reader);
uint64_t cbm_worker_progress_reader_completed(const cbm_worker_progress_reader_t *reader);
uint64_t cbm_worker_progress_reader_total(const cbm_worker_progress_reader_t *reader);
const char *cbm_worker_progress_reader_stage(const cbm_worker_progress_reader_t *reader);
bool cbm_worker_progress_reader_complete(const cbm_worker_progress_reader_t *reader);

#endif /* CBM_WORKER_PROGRESS_H */
