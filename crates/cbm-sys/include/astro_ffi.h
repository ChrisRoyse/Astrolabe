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
#include "foundation/log.h"
#include "foundation/mem.h"
#include "foundation/platform.h"
#include "git/git_context.h"
#include "mcp/mcp.h"
#include "pipeline/pipeline.h"
#include "store/store.h"
#include "watcher/watcher.h"

CBM_API void cbm_cli_set_version(const char *ver);
CBM_API int cbm_cmd_install(int argc, char **argv);
CBM_API int cbm_cmd_uninstall(int argc, char **argv);
CBM_API int cbm_cmd_update(int argc, char **argv);
CBM_API char *cbm_build_install_plan_json(const char *home, const char *binary_path);
CBM_API void cbm_index_set_worker_role(bool is_worker, const char *response_out);
CBM_API void cbm_index_supervisor_mark_host(void);
CBM_API void cbm_http_server_set_binary_path(const char *path);

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
