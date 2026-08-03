/*
 * worker_pool.c — Parallel-for dispatch with pthreads.
 *
 * Uses pthreads with 8MB stacks and atomic work-stealing index.
 * GCD is avoided because its worker threads have 512KB stacks,
 * which overflows on deeply nested ASTs (tree-sitter + walk_defs).
 *
 * Each worker pulls indices from a shared atomic counter — zero
 * contention, natural load balancing across heterogeneous cores.
 */
#include "pipeline/worker_pool.h"
#include "foundation/constants.h"
#include "foundation/log.h"

enum { WP_TRUE = 1, WP_MIN = 1, WP_STEP = 1 };
#include "foundation/platform.h"
#include "foundation/compat_thread.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

/* 8 MB stack per worker — matches main thread default.
 * Required for deep AST recursion (tree-sitter + walk_defs). */
#define CBM_WORKER_STACK_SIZE ((size_t)8 * CBM_SZ_1K * CBM_SZ_1K)

/* ── Explicit serial mode ────────────────────────────────────────── */

static void run_serial(int count, cbm_parallel_fn fn, void *ctx) {
    for (int i = 0; i < count; i++) {
        fn(i, ctx);
    }
}

static const char *mode_name(cbm_parallel_dispatch_mode_t mode) {
    switch (mode) {
    case CBM_PARALLEL_DISPATCH_MODE_NOOP:
        return "noop";
    case CBM_PARALLEL_DISPATCH_MODE_SERIAL:
        return "serial";
    case CBM_PARALLEL_DISPATCH_MODE_PARALLEL:
        return "parallel";
    }
    return "unknown";
}

static const char *status_code(cbm_parallel_dispatch_status_t status) {
    switch (status) {
    case CBM_PARALLEL_DISPATCH_OK:
        return "CBM_PARALLEL_DISPATCH_OK";
    case CBM_PARALLEL_DISPATCH_INVALID_CALLBACK:
        return "CBM_PARALLEL_DISPATCH_INVALID_CALLBACK";
    case CBM_PARALLEL_DISPATCH_THREAD_ARRAY_ALLOC_FAILED:
        return "CBM_PARALLEL_DISPATCH_THREAD_ARRAY_ALLOC_FAILED";
    case CBM_PARALLEL_DISPATCH_THREAD_CREATE_FAILED:
        return "CBM_PARALLEL_DISPATCH_THREAD_CREATE_FAILED";
    case CBM_PARALLEL_DISPATCH_THREAD_JOIN_FAILED:
        return "CBM_PARALLEL_DISPATCH_THREAD_JOIN_FAILED";
    case CBM_PARALLEL_DISPATCH_WORKER_CONFIG_INVALID:
        return "CBM_PARALLEL_DISPATCH_WORKER_CONFIG_INVALID";
    }
    return "CBM_PARALLEL_DISPATCH_UNKNOWN";
}

static void init_result(cbm_parallel_for_result_t *result, int count, int requested_workers,
                        const char *operation) {
    if (!result) {
        return;
    }
    result->status = CBM_PARALLEL_DISPATCH_OK;
    result->mode = CBM_PARALLEL_DISPATCH_MODE_NOOP;
    result->code = status_code(CBM_PARALLEL_DISPATCH_OK);
    result->operation = operation ? operation : "parallel_for";
    result->item_count = count;
    result->requested_workers = requested_workers;
    result->admitted_workers = 0;
    result->created_workers = 0;
    result->failed_worker_index = -1;
    result->error_domain = CBM_THREAD_ERROR_NONE;
    result->error_code = 0;
}

static void mark_failure(cbm_parallel_for_result_t *result,
                         cbm_parallel_dispatch_status_t status, int failed_worker_index,
                         int error_domain, unsigned long error_code) {
    if (!result) {
        return;
    }
    result->status = status;
    result->code = status_code(status);
    result->failed_worker_index = failed_worker_index;
    result->error_domain = error_domain;
    result->error_code = error_code;
}

static void log_dispatch_result(const cbm_parallel_for_result_t *result) {
    if (!result) {
        return;
    }
    char items[CBM_SZ_32];
    char requested[CBM_SZ_32];
    char admitted[CBM_SZ_32];
    char created[CBM_SZ_32];
    char failed[CBM_SZ_32];
    char domain[CBM_SZ_32];
    char code[CBM_SZ_32];
    snprintf(items, sizeof(items), "%d", result->item_count);
    snprintf(requested, sizeof(requested), "%d", result->requested_workers);
    snprintf(admitted, sizeof(admitted), "%d", result->admitted_workers);
    snprintf(created, sizeof(created), "%d", result->created_workers);
    snprintf(failed, sizeof(failed), "%d", result->failed_worker_index);
    snprintf(domain, sizeof(domain), "%d", result->error_domain);
    snprintf(code, sizeof(code), "%lu", result->error_code);
    if (result->status == CBM_PARALLEL_DISPATCH_OK) {
        cbm_log_info("parallel.dispatch", "operation", result->operation, "mode",
                     mode_name(result->mode), "items", items, "requested_workers", requested,
                     "admitted_workers", admitted, "created_workers", created, "code",
                     result->code);
        return;
    }
    cbm_log_error("parallel.dispatch.failed", "code", result->code, "operation",
                  result->operation, "mode", mode_name(result->mode), "items", items,
                  "requested_workers", requested, "admitted_workers", admitted,
                  "created_workers", created, "failed_worker_index", failed, "error_domain",
                  domain, "error_code", code, "message",
                  "parallel dispatch could not admit the requested execution mode",
                  "remediation",
                  "inspect worker resource limits and thread diagnostics; retry unchanged only "
                  "after the exact resource/configuration condition changes");
}

/* ── pthreads backend ────────────────────────────────────────────── */

typedef struct {
    cbm_parallel_fn fn;
    void *ctx;
    _Atomic int *next_idx;
    _Atomic int *started;
    _Atomic int *cancelled;
    int count;
} pthread_worker_arg_t;

static void *pthread_worker(void *arg) {
    pthread_worker_arg_t *wa = arg;
    while (!atomic_load_explicit(wa->started, memory_order_acquire)) {
        if (atomic_load_explicit(wa->cancelled, memory_order_acquire)) {
            return NULL;
        }
    }
    while (WP_TRUE) {
        if (atomic_load_explicit(wa->cancelled, memory_order_acquire)) {
            break;
        }
        int idx = atomic_fetch_add_explicit(wa->next_idx, WP_STEP, memory_order_relaxed);
        if (idx >= wa->count) {
            break;
        }
        wa->fn(idx, wa->ctx);
    }
    return NULL;
}

static int run_pthreads(int count, cbm_parallel_fn fn, void *ctx, int nworkers,
                        cbm_parallel_for_result_t *result) {
    _Atomic int next_idx = 0;
    _Atomic int started = 0;
    _Atomic int cancelled = 0;

    pthread_worker_arg_t wa = {
        .fn = fn,
        .ctx = ctx,
        .next_idx = &next_idx,
        .started = &started,
        .cancelled = &cancelled,
        .count = count,
    };

    cbm_thread_t *threads = (cbm_thread_t *)malloc((size_t)nworkers * sizeof(cbm_thread_t));
    if (!threads) {
        mark_failure(result, CBM_PARALLEL_DISPATCH_THREAD_ARRAY_ALLOC_FAILED, -1,
                     CBM_THREAD_ERROR_ERRNO, (unsigned long)(errno ? errno : ENOMEM));
        log_dispatch_result(result);
        return CBM_NOT_FOUND;
    }

    int created = 0;
    int create_rc = 0;
    cbm_thread_t create_error = {0};
    for (; created < nworkers; created++) {
        create_rc = cbm_thread_create(&threads[created], CBM_WORKER_STACK_SIZE, pthread_worker, &wa);
        if (create_rc != 0) {
            create_error = threads[created];
            break;
        }
    }
    if (result) {
        result->created_workers = created;
        result->admitted_workers = created;
    }

    if (create_rc != 0) {
        atomic_store_explicit(&cancelled, 1, memory_order_release);
        atomic_store_explicit(&started, 1, memory_order_release);
        mark_failure(result, CBM_PARALLEL_DISPATCH_THREAD_CREATE_FAILED, created,
                     create_error.error_domain, create_error.error_code);
        for (int i = 0; i < created; i++) {
            cbm_thread_t join_state = threads[i];
            if (cbm_thread_join(&join_state) != 0 &&
                result &&
                    result->status == CBM_PARALLEL_DISPATCH_THREAD_CREATE_FAILED) {
                result->error_domain = join_state.error_domain;
                result->error_code = join_state.error_code;
            }
        }
        free(threads);
        log_dispatch_result(result);
        return CBM_NOT_FOUND;
    }

    atomic_store_explicit(&started, 1, memory_order_release);

    /* Main thread participates only after all worker threads are admitted. */
    while (WP_TRUE) {
        int idx = atomic_fetch_add_explicit(&next_idx, WP_STEP, memory_order_relaxed);
        if (idx >= count) {
            break;
        }
        fn(idx, ctx);
    }

    int join_rc = 0;
    cbm_thread_t join_error = {0};
    for (int i = 0; i < created; i++) {
        cbm_thread_t joined = threads[i];
        if (cbm_thread_join(&joined) != 0 && join_rc == 0) {
            join_rc = CBM_NOT_FOUND;
            join_error = joined;
            mark_failure(result, CBM_PARALLEL_DISPATCH_THREAD_JOIN_FAILED, i,
                         join_error.error_domain, join_error.error_code);
        }
    }

    free(threads);
    log_dispatch_result(result);
    return join_rc == 0 ? 0 : CBM_NOT_FOUND;
}

/* ── Public API ──────────────────────────────────────────────────── */

int cbm_parallel_for(int count, cbm_parallel_fn fn, void *ctx, cbm_parallel_for_opts_t opts,
                     cbm_parallel_for_result_t *result) {
    int requested_workers = opts.max_workers;
    if (requested_workers <= 0) {
        requested_workers = cbm_default_worker_count(true);
    }
    init_result(result, count, requested_workers, opts.operation);

    if (requested_workers < WP_MIN) {
        mark_failure(result, CBM_PARALLEL_DISPATCH_WORKER_CONFIG_INVALID, -1,
                     CBM_THREAD_ERROR_NONE, 0);
        log_dispatch_result(result);
        return CBM_NOT_FOUND;
    }

    if (count <= 0) {
        if (result) {
            result->mode = CBM_PARALLEL_DISPATCH_MODE_NOOP;
        }
        log_dispatch_result(result);
        return 0;
    }

    if (!fn) {
        mark_failure(result, CBM_PARALLEL_DISPATCH_INVALID_CALLBACK, -1, 0, 0);
        log_dispatch_result(result);
        return CBM_NOT_FOUND;
    }

    if (requested_workers <= WP_MIN || count <= WP_MIN) {
        if (result) {
            result->mode = CBM_PARALLEL_DISPATCH_MODE_SERIAL;
            result->admitted_workers = SKIP_ONE;
            result->created_workers = 0;
        }
        run_serial(count, fn, ctx);
        log_dispatch_result(result);
        return 0;
    }

    if (result) {
        result->mode = CBM_PARALLEL_DISPATCH_MODE_PARALLEL;
    }
    return run_pthreads(count, fn, ctx, requested_workers, result);
}
