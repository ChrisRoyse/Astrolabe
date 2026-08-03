/*
 * worker_pool.h — Generic parallel-for dispatch.
 *
 * Backend: pthreads with 8MB stacks and atomic work-stealing index.
 * Each worker pulls from a shared counter — zero contention, natural
 * load balancing across heterogeneous cores (P/E on Apple Silicon).
 *
 * Explicit serial mode when count <= 1 or max_workers <= 1.
 */
#ifndef CBM_WORKER_POOL_H
#define CBM_WORKER_POOL_H

#include <stdbool.h>

/* Worker callback: called once per iteration with index [0..count-1]. */
typedef void (*cbm_parallel_fn)(int idx, void *ctx);

/* Options for parallel dispatch. */
typedef struct {
    int max_workers;     /* 0 = auto-detect from cbm_default_worker_count */
    bool force_pthreads; /* unused, kept for API compat */
    const char *operation; /* diagnostic phase/caller name */
} cbm_parallel_for_opts_t;

typedef enum {
    CBM_PARALLEL_DISPATCH_MODE_NOOP = 0,
    CBM_PARALLEL_DISPATCH_MODE_SERIAL = 1,
    CBM_PARALLEL_DISPATCH_MODE_PARALLEL = 2
} cbm_parallel_dispatch_mode_t;

typedef enum {
    CBM_PARALLEL_DISPATCH_OK = 0,
    CBM_PARALLEL_DISPATCH_INVALID_CALLBACK = 1,
    CBM_PARALLEL_DISPATCH_THREAD_ARRAY_ALLOC_FAILED = 2,
    CBM_PARALLEL_DISPATCH_THREAD_CREATE_FAILED = 3,
    CBM_PARALLEL_DISPATCH_THREAD_JOIN_FAILED = 4,
    CBM_PARALLEL_DISPATCH_WORKER_CONFIG_INVALID = 5
} cbm_parallel_dispatch_status_t;

typedef struct {
    cbm_parallel_dispatch_status_t status;
    cbm_parallel_dispatch_mode_t mode;
    const char *code;
    const char *operation;
    int item_count;
    int requested_workers;
    int admitted_workers;
    int created_workers;
    int failed_worker_index;
    int error_domain;
    unsigned long error_code;
} cbm_parallel_for_result_t;

/* Dispatch `count` iterations of `fn(idx, ctx)` across worker threads.
 * Each index [0..count-1] is visited exactly once.
 * Blocks until all iterations complete.
 *
 * If count <= 0, this is a no-op.
 * If count <= 1 or workers <= 1, runs the explicitly declared serial mode.
 * Returns 0 only after the requested mode has been admitted and completed. */
int cbm_parallel_for(int count, cbm_parallel_fn fn, void *ctx, cbm_parallel_for_opts_t opts,
                     cbm_parallel_for_result_t *result);

#endif /* CBM_WORKER_POOL_H */
