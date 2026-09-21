#ifndef ASTROLABE_ASTRO_FFI_H
#define ASTROLABE_ASTRO_FFI_H

#if !defined(CBM_API)
#if defined(CBM_STATIC_LIB)
#define CBM_API
#elif defined(_WIN32)
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
/* #416: per-tool `--help` formatter shared with the standalone binary. Prints
 * the supported input forms and the tool's JSON argument schema to stdout,
 * using `prog` as the program name in the Usage lines. Returns 0 if the tool
 * is known, non-zero (and prints nothing) if it is not. */
CBM_API int cbm_cli_print_tool_help_prog(const char *prog, const char *tool_name);
CBM_API int cbm_cmd_install(int argc, char **argv);
CBM_API int cbm_cmd_uninstall(int argc, char **argv);
CBM_API int cbm_cmd_update(int argc, char **argv);
CBM_API char *cbm_build_install_plan_json(const char *home, const char *binary_path);
/* Single strict persisted-boolean parser shared by libcbm and the Rust host.
 * Returns CBM_CONFIG_BOOL_OK (0) on success and never substitutes a default. */
CBM_API int cbm_config_parse_bool_strict(const char *value, bool *out);
/* Release a heap string returned by a CBM API through CBM's own allocator. */
CBM_API void cbm_free_string(char *value);
CBM_API int cbm_index_set_worker_role(bool is_worker, const char *response_out,
                                      const char *progress_out, const char *progress_attempt);
CBM_API int cbm_index_worker_progress_complete(void);
CBM_API void cbm_index_set_transition_writer_project(const char *project);
/* The fused host replaces cbm/main.c and must run this native startup
 * initializer before it activates the supervisor (#767). */
CBM_API void cbm_profile_init(void);
CBM_API bool cbm_profile_is_active(void);
CBM_API void cbm_index_supervisor_mark_host(void);
CBM_API bool cbm_index_supervisor_should_wrap(void);
/* Keep this bindgen-facing definition byte-for-byte aligned with
 * cbm/src/ui/http_server.h. The guard permits native translation units that
 * include both public surfaces without redefining the ABI type. */
#ifndef CBM_WORKER_BINARY_STATUS_DEFINED
#define CBM_WORKER_BINARY_STATUS_DEFINED
typedef enum {
    CBM_WORKER_BINARY_OK = 0,
    CBM_WORKER_BINARY_UNBOUND = 1,
    CBM_WORKER_BINARY_INVALID_ARGUMENT = 2,
    CBM_WORKER_BINARY_SELF_RESOLVE_FAILED = 3,
    CBM_WORKER_BINARY_PATH_NOT_ABSOLUTE = 4,
    CBM_WORKER_BINARY_PATH_ENCODING_FAILED = 5,
    CBM_WORKER_BINARY_OPEN_FAILED = 6,
    CBM_WORKER_BINARY_NOT_REGULAR_FILE = 7,
    CBM_WORKER_BINARY_REPARSE_POINT = 8,
    CBM_WORKER_BINARY_NOT_EXECUTABLE = 9,
    CBM_WORKER_BINARY_IDENTITY_READ_FAILED = 10,
    CBM_WORKER_BINARY_FINAL_PATH_FAILED = 11,
    CBM_WORKER_BINARY_PATH_TOO_LONG = 12,
    CBM_WORKER_BINARY_ALLOCATION_FAILED = 13,
    CBM_WORKER_BINARY_CAPABILITY_MISMATCH = 14,
    CBM_WORKER_BINARY_BIND_IN_PROGRESS = 15,
    CBM_WORKER_BINARY_CONFLICT = 16,
} cbm_worker_binary_status_t;
#endif
CBM_API cbm_worker_binary_status_t
cbm_http_server_bind_self_binary(unsigned long *native_error);
CBM_API cbm_worker_binary_status_t
cbm_http_server_bind_explicit_binary(const char *path, unsigned long *native_error);
CBM_API const char *cbm_http_server_binary_path(void);
CBM_API const char *cbm_http_server_binary_status_code(int status);
CBM_API const char *cbm_http_server_binary_status_message(int status);
CBM_API const char *cbm_http_server_binary_status_remediation(int status);

/* One canonical merge boundary for every cross-LSP resolver route. Success
 * commits the exact per-file accounting receipt while preserving first-row
 * order and the highest-confidence non-identity payload; every invalid
 * identity, allocation failure, or count mismatch latches a terminal error. */
CBM_API bool cbm_pxc_canonicalize_appended_results(CBMFileResult *result, int seeded_count);

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

/* Native test probes implemented by Astrolabe's libcbm patch. They make the
 * C compiler's size, alignment, and field offsets observable to Rust tests. */
CBM_API int cbm_abi_layout_size(const char *type_name, size_t *size_out, size_t *align_out);
CBM_API int cbm_abi_layout_offset(const char *type_name, const char *field_name,
                                  size_t *offset_out);

/* Store configuration across the FFI boundary (#240) and the fail-closed
 * environment fault record (#241). Implemented by patches/cbm/env_store_config.c
 * and consumed by the store-resolution overlay of the pinned CBM sources.
 *
 * These exist because the environment is NOT a usable channel between the Rust
 * host and libcbm on Windows: `std::env::set_var` writes the Win32 environment
 * block, while `cbm_safe_getenv` walks the C runtime's `environ` array, and the
 * two are synchronised only for the environment the process inherited. Passing
 * the store path as a parameter is the durable contract; see
 * astrolabe_bridge::set_cbm_cache_dir. */
CBM_API int cbm_astro_set_cache_dir(const char *path);
CBM_API void cbm_astro_clear_cache_dir(void);
CBM_API const char *cbm_astro_cache_dir_override(void);
CBM_API void cbm_astro_env_record_fault(const char *code, const char *var, const char *message,
                                        const char *remediation);
CBM_API void cbm_astro_env_record_truncation(const char *name, size_t needed, size_t capacity);
CBM_API void cbm_astro_env_record_unresolvable_store(void);
CBM_API int cbm_astro_env_faulted_for(const char *name);
CBM_API const char *cbm_astro_env_fault_code(void);
CBM_API const char *cbm_astro_env_fault_message(void);
CBM_API const char *cbm_astro_env_fault_remediation(void);
CBM_API void cbm_astro_env_fault_clear(void);

#endif /* ASTROLABE_ASTRO_FFI_H */
