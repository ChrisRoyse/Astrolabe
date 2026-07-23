#ifndef CBM_LSP_SEMANTIC_ARRAY_H
#define CBM_LSP_SEMANTIC_ARRAY_H

#include "arena.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/*
 * Grow an arena-owned authoritative semantic array without losing prior
 * elements.  Bump arenas cannot realloc, so growth allocates a larger span and
 * copies the live prefix.  The old span remains arena-owned until the file
 * analysis ends.
 *
 * `minimum` is the number of elements the caller must be able to address; it
 * should include any required sentinel.  Every arithmetic/allocation failure
 * is sticky on the file arena so no partial semantic result can be published.
 */
static inline bool cbm_lsp_semantic_array_reserve(CBMArena *arena, void **items, size_t live_count,
                                                  size_t *capacity, size_t element_size,
                                                  size_t minimum, const char *operation) {
    if (!arena || !items || !capacity || element_size == 0) {
        if (arena) {
            cbm_arena_mark_failed(arena, "CBM_LSP_SEMANTIC_ARRAY_INVALID", operation, minimum);
        }
        return false;
    }
    if (minimum <= *capacity) {
        return true;
    }
    size_t next = *capacity ? *capacity : 8;
    while (next < minimum) {
        if (next > SIZE_MAX / 2) {
            next = minimum;
            break;
        }
        next *= 2;
    }
    if (next < minimum || next > SIZE_MAX / element_size || live_count > SIZE_MAX / element_size) {
        cbm_arena_mark_failed(arena, "CBM_LSP_SEMANTIC_CARDINALITY_OVERFLOW", operation, minimum);
        return false;
    }
    void *grown = cbm_arena_alloc(arena, next * element_size);
    if (!grown) {
        return false;
    }
    if (*items && live_count) {
        memcpy(grown, *items, live_count * element_size);
    }
    *items = grown;
    *capacity = next;
    return true;
}

#endif /* CBM_LSP_SEMANTIC_ARRAY_H */
