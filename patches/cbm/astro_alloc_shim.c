#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#include "cbm.h"
#include "mimalloc.h"

#if !defined(CBM_API)
#if defined(_WIN32)
#define CBM_API __declspec(dllexport)
#else
#define CBM_API __attribute__((visibility("default")))
#endif
#endif

CBM_API void cbm_free_string(char *value) {
    free(value);
}

CBM_API void *cbm_mimalloc_malloc(size_t size) {
    return mi_malloc(size);
}

CBM_API void *cbm_mimalloc_malloc_aligned(size_t size, size_t alignment) {
    return mi_malloc_aligned(size, alignment);
}

CBM_API void *cbm_mimalloc_zalloc_aligned(size_t size, size_t alignment) {
    return mi_zalloc_aligned(size, alignment);
}

CBM_API void *cbm_mimalloc_realloc_aligned(void *p, size_t newsize, size_t alignment) {
    return mi_realloc_aligned(p, newsize, alignment);
}

CBM_API void cbm_mimalloc_free(void *p) {
    mi_free(p);
}

CBM_API size_t cbm_mimalloc_usable_size(const void *p) {
    return mi_malloc_usable_size(p);
}

CBM_API void cbm_mimalloc_collect(bool force) {
    mi_collect(force);
}

CBM_API int cbm_mimalloc_version(void) {
    return mi_version();
}

CBM_API void cbm_mimalloc_process_info(size_t *elapsed_msecs,
                                       size_t *user_msecs,
                                       size_t *system_msecs,
                                       size_t *current_rss,
                                       size_t *peak_rss,
                                       size_t *current_commit,
                                       size_t *peak_commit,
                                       size_t *page_faults) {
    mi_process_info(elapsed_msecs, user_msecs, system_msecs, current_rss, peak_rss,
                    current_commit, peak_commit, page_faults);
}
