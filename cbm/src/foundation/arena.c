/*
 * arena.c — Bump allocator implementation.
 *
 * Restructured from internal/cbm/arena.c with additions:
 *   - cbm_arena_init_sized() for custom block sizes
 *   - cbm_arena_calloc() for zero-initialized allocations
 *   - cbm_arena_reset() for reuse without full destroy
 *   - cbm_arena_total() for allocation tracking
 *
 * Arena blocks use malloc/free (= mimalloc in production builds).
 */
#include "arena.h"
#include "foundation/constants.h"

enum { ARENA_ALIGN = 7, ARENA_GROW_OK = 1 };
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>

#define CBM_ARENA_ALLOC_FAILED "CBM_ARENA_ALLOC_FAILED"
#define CBM_ARENA_CAPACITY_OVERFLOW "CBM_ARENA_CAPACITY_OVERFLOW"

void cbm_arena_mark_failed(CBMArena *a, const char *code, const char *operation,
                           size_t requested_bytes) {
    if (!a) {
        return;
    }
    if (!a->failed || (a->failure_operation && strncmp(a->failure_operation, "arena_", 6) == 0)) {
        a->failure_code = code;
        a->failure_operation = operation;
        a->failure_bytes = requested_bytes;
    }
    a->failed = true;
}

bool cbm_arena_failed(const CBMArena *a) {
    return a && a->failed;
}

const char *cbm_arena_failure_code(const CBMArena *a) {
    return a && a->failure_code ? a->failure_code : CBM_ARENA_ALLOC_FAILED;
}

const char *cbm_arena_failure_operation(const CBMArena *a) {
    return a && a->failure_operation ? a->failure_operation : "arena_alloc";
}

size_t cbm_arena_failure_bytes(const CBMArena *a) {
    return a ? a->failure_bytes : 0;
}

void cbm_arena_init(CBMArena *a) {
    cbm_arena_init_sized(a, CBM_ARENA_DEFAULT_BLOCK_SIZE);
}

void cbm_arena_init_sized(CBMArena *a, size_t block_size) {
    memset(a, 0, sizeof(*a));
    if (block_size < CBM_SZ_64) {
        block_size = CBM_SZ_64; /* minimum sanity */
    }
    a->block_size = block_size;
    a->blocks[0] = (char *)malloc(block_size);
    if (a->blocks[0]) {
        a->block_sizes[0] = block_size;
        a->nblocks = SKIP_ONE;
    } else {
        cbm_arena_mark_failed(a, CBM_ARENA_ALLOC_FAILED, "arena_init", block_size);
    }
}

static int arena_grow(CBMArena *a, size_t min_size) {
    if (a->nblocks >= CBM_ARENA_MAX_BLOCKS) {
        cbm_arena_mark_failed(a, CBM_ARENA_ALLOC_FAILED, "arena_block_limit", min_size);
        return 0;
    }
    size_t new_size = a->block_size;
    if (new_size < min_size) {
        new_size = min_size;
    } else if (new_size <= SIZE_MAX / PAIR_LEN) {
        new_size *= PAIR_LEN;
    } else {
        cbm_arena_mark_failed(a, CBM_ARENA_CAPACITY_OVERFLOW, "arena_grow", min_size);
        return 0;
    }
    char *block = (char *)malloc(new_size);
    if (!block) {
        cbm_arena_mark_failed(a, CBM_ARENA_ALLOC_FAILED, "arena_grow", new_size);
        return 0;
    }
    a->blocks[a->nblocks] = block;
    a->block_sizes[a->nblocks] = new_size;
    a->nblocks++;
    a->block_size = new_size;
    a->used = 0;
    return ARENA_GROW_OK;
}

void *cbm_arena_alloc(CBMArena *a, size_t n) {
    if (!a || n == 0) {
        return NULL;
    }
    /* 8-byte alignment */
    if (n > SIZE_MAX - ARENA_ALIGN) {
        cbm_arena_mark_failed(a, CBM_ARENA_CAPACITY_OVERFLOW, "arena_alloc", n);
        return NULL;
    }
    n = (n + ARENA_ALIGN) & ~(size_t)ARENA_ALIGN;
    if (a->nblocks == 0) {
        cbm_arena_mark_failed(a, CBM_ARENA_ALLOC_FAILED, "arena_alloc", n);
        return NULL;
    }
    if (a->used > a->block_size || n > a->block_size - a->used) {
        if (!arena_grow(a, n)) {
            return NULL;
        }
    }
    if (a->total_alloc > SIZE_MAX - n) {
        cbm_arena_mark_failed(a, CBM_ARENA_CAPACITY_OVERFLOW, "arena_total", n);
        return NULL;
    }
    char *ptr = a->blocks[a->nblocks - SKIP_ONE] + a->used;
    a->used += n;
    a->total_alloc += n;
    return ptr;
}

void *cbm_arena_calloc(CBMArena *a, size_t n) {
    void *p = cbm_arena_alloc(a, n);
    if (p) {
        memset(p, 0, n);
    }
    return p;
}

char *cbm_arena_strdup(CBMArena *a, const char *s) {
    if (!s) {
        return NULL;
    }
    size_t len = strlen(s);
    char *dst = (char *)cbm_arena_alloc(a, len + SKIP_ONE);
    if (dst) {
        memcpy(dst, s, len + SKIP_ONE);
    }
    return dst;
}

char *cbm_arena_strndup(CBMArena *a, const char *s, size_t len) {
    if (!s) {
        return NULL;
    }
    if (len == SIZE_MAX) {
        cbm_arena_mark_failed(a, CBM_ARENA_CAPACITY_OVERFLOW, "arena_strndup", len);
        return NULL;
    }
    char *dst = (char *)cbm_arena_alloc(a, len + SKIP_ONE);
    if (dst) {
        memcpy(dst, s, len);
        dst[len] = '\0';
    }
    return dst;
}

char *cbm_arena_sprintf(CBMArena *a, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int needed = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (needed < 0) {
        return NULL;
    }

    char *dst = (char *)cbm_arena_alloc(a, (size_t)needed + SKIP_ONE);
    if (!dst) {
        return NULL;
    }

    va_start(args, fmt);
    vsnprintf(dst, (size_t)needed + SKIP_ONE, fmt, args);
    va_end(args);
    return dst;
}

void cbm_arena_reset(CBMArena *a) {
    /* Keep first block, free the rest */
    for (int i = SKIP_ONE; i < a->nblocks; i++) {
        free(a->blocks[i]);
        a->blocks[i] = NULL;
        a->block_sizes[i] = 0;
    }
    if (a->nblocks > SKIP_ONE) {
        a->nblocks = SKIP_ONE;
    }
    a->used = 0;
    a->total_alloc = 0;
    a->failed = false;
    a->failure_code = NULL;
    a->failure_operation = NULL;
    a->failure_bytes = 0;
    /* Reset block_size to match surviving block — prevents overflow if
     * block_size grew during previous allocations (e.g., CBM_SZ_128 → CBM_SZ_256). */
    if (a->nblocks == SKIP_ONE) {
        a->block_size = a->block_sizes[0];
    }
}

void cbm_arena_destroy(CBMArena *a) {
    for (int i = 0; i < a->nblocks; i++) {
        free(a->blocks[i]);
    }
    memset(a, 0, sizeof(*a));
}

size_t cbm_arena_total(const CBMArena *a) {
    return a->total_alloc;
}
// #280 warm-impacted proof probe (2026-07-13)
