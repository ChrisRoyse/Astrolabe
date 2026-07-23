#include "arena.h"
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
    /* Preserve the first concrete failure, but allow an array wrapper to refine
     * the allocator's generic context immediately after a NULL return. */
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
    memset(a, 0, sizeof(*a));
    a->block_size = CBM_ARENA_DEFAULT_BLOCK_SIZE;
    a->blocks[0] = (char *)malloc(a->block_size);
    if (a->blocks[0]) {
        a->block_sizes[0] = a->block_size;
        a->nblocks = SKIP_ONE;
    } else {
        cbm_arena_mark_failed(a, CBM_ARENA_ALLOC_FAILED, "arena_init", a->block_size);
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
    return 1;
}

void *cbm_arena_alloc(CBMArena *a, size_t n) {
    if (!a || n == 0) {
        return NULL;
    }
    // 8-byte alignment
    if (n > SIZE_MAX - 7) {
        cbm_arena_mark_failed(a, CBM_ARENA_CAPACITY_OVERFLOW, "arena_alloc", n);
        return NULL;
    }
    n = (n + 7) & ~(size_t)7;

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

char *cbm_arena_strdup(CBMArena *a, const char *s) {
    if (!s)
        return NULL;
    size_t len = strlen(s);
    char *dst = (char *)cbm_arena_alloc(a, len + SKIP_ONE);
    if (dst) {
        memcpy(dst, s, len + SKIP_ONE);
    }
    return dst;
}

char *cbm_arena_strndup(CBMArena *a, const char *s, size_t len) {
    if (!s)
        return NULL;
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
    // First pass: compute length
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

void cbm_arena_destroy(CBMArena *a) {
    for (int i = 0; i < a->nblocks; i++) {
        free(a->blocks[i]);
    }
    memset(a, 0, sizeof(*a));
}
