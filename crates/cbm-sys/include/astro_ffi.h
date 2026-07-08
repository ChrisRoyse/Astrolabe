#ifndef ASTROLABE_ASTRO_FFI_H
#define ASTROLABE_ASTRO_FFI_H

#if !defined(CBM_API)
#if defined(_WIN32)
#define CBM_API __declspec(dllexport)
#else
#define CBM_API __attribute__((visibility("default")))
#endif
#endif

#include <stdbool.h>
#include <stddef.h>

#include "cbm.h"
#include "discover/discover.h"
#include "git/git_context.h"
#include "mcp/mcp.h"
#include "pipeline/pipeline.h"
#include "store/store.h"

CBM_API void *cbm_mimalloc_malloc(size_t size);
CBM_API void *cbm_mimalloc_malloc_aligned(size_t size, size_t alignment);
CBM_API void *cbm_mimalloc_zalloc_aligned(size_t size, size_t alignment);
CBM_API void *cbm_mimalloc_realloc_aligned(void *p, size_t newsize, size_t alignment);
CBM_API void cbm_mimalloc_free(void *p);
CBM_API size_t cbm_mimalloc_usable_size(const void *p);
CBM_API void cbm_mimalloc_collect(bool force);
CBM_API int cbm_mimalloc_version(void);
CBM_API void cbm_mimalloc_process_info(size_t *elapsed_msecs,
                                       size_t *user_msecs,
                                       size_t *system_msecs,
                                       size_t *current_rss,
                                       size_t *peak_rss,
                                       size_t *current_commit,
                                       size_t *peak_commit,
                                       size_t *page_faults);

#endif /* ASTROLABE_ASTRO_FFI_H */
