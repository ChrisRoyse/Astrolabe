/*
 * dyn_array.h — Type-safe growable arrays via macros (header-only).
 *
 * Usage:
 *   CBM_DYN_ARRAY(int) nums = {0};    // zero-init
 *   if (!cbm_da_push_checked(&nums, 42)) return false;
 *   if (!cbm_da_push_checked(&nums, 99)) return false;
 *   for (int i = 0; i < nums.count; i++)
 *       printf("%d\n", nums.items[i]);
 *   cbm_da_free(&nums);
 *
 * Design:
 *   - Items are contiguous in memory (cache-friendly)
 *   - Grows by 2x (amortized O(1) push)
 *   - Uses realloc — NOT arena-compatible (use CBMDefArray etc. for arena)
 *   - Header-only: no .c file needed
 */
#ifndef CBM_DYN_ARRAY_H
#define CBM_DYN_ARRAY_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Declare a dynamic array type for a given element type. */
#define CBM_DYN_ARRAY(T) \
    struct {             \
        T *items;        \
        int count;       \
        int cap;         \
    }

static inline bool cbm_da_ensure_capacity(void **items, int *capacity, int required,
                                          size_t item_size) {
    if (!items || !capacity || *capacity < 0 || required < 0 || item_size == 0 ||
        (*capacity > 0 && !*items)) {
        return false;
    }
    if (required <= *capacity) {
        return true;
    }

    size_t grown_capacity = *capacity > 0 ? (size_t)*capacity : 8U;
    while (grown_capacity < (size_t)required) {
        if (grown_capacity > (size_t)INT32_MAX / 2U) {
            grown_capacity = (size_t)required;
            break;
        }
        grown_capacity *= 2U;
    }
    if (grown_capacity > (size_t)INT32_MAX || grown_capacity > SIZE_MAX / item_size) {
        return false;
    }

    void *grown = realloc(*items, grown_capacity * item_size);
    if (!grown) {
        return false;
    }
    *items = grown;
    *capacity = (int)grown_capacity;
    return true;
}

/* Fallible operations are expressions returning bool. The array is byte-for-byte
 * unchanged when allocation or capacity arithmetic fails. */
#define cbm_da_push_checked(da, item)                                                        \
    ((da)->count < 0 || (da)->cap < 0 || (da)->count > (da)->cap || (da)->count == INT32_MAX \
         ? false                                                                             \
         : (cbm_da_ensure_capacity((void **)&(da)->items, &(da)->cap, (da)->count + 1,       \
                                   sizeof(*(da)->items))                                     \
                ? ((da)->items[(da)->count++] = (item), true)                                \
                : false))

/* Pop last element. Returns the element. Undefined if empty. */
#define cbm_da_pop(da) ((da)->items[--(da)->count])

/* Get last element without removing. Undefined if empty. */
#define cbm_da_last(da) ((da)->items[(da)->count - 1])

/* Clear without freeing (reset count to 0). */
#define cbm_da_clear(da) ((da)->count = 0)

/* Free all memory. */
#define cbm_da_free(da)     \
    do {                    \
        free((da)->items);  \
        (da)->items = NULL; \
        (da)->count = 0;    \
        (da)->cap = 0;      \
    } while (0)

/* Reserve capacity (grow if needed, never shrink), with explicit status. */
#define cbm_da_reserve_checked(da, n) \
    cbm_da_ensure_capacity((void **)&(da)->items, &(da)->cap, (n), sizeof(*(da)->items))

/* Remove at index, shifting elements left. */
#define cbm_da_remove(da, idx)                                                 \
    do {                                                                       \
        if ((idx) < (da)->count - 1) {                                         \
            memmove(&(da)->items[(idx)], &(da)->items[(idx) + 1],              \
                    (size_t)((da)->count - 1 - (idx)) * sizeof(*(da)->items)); \
        }                                                                      \
        (da)->count--;                                                         \
    } while (0)

#endif /* CBM_DYN_ARRAY_H */
