/*
 * http_server.h — Embedded HTTP server for the graph visualization UI.
 *
 * Binds to 127.0.0.1:<port> only (localhost).
 * Serves embedded frontend assets and proxies /rpc to a dedicated
 * read-only cbm_mcp_server_t instance.
 *
 * Runs in a background pthread, same pattern as the watcher thread.
 */
#ifndef CBM_UI_HTTP_SERVER_H
#define CBM_UI_HTTP_SERVER_H

#include <stdbool.h>
#include <stddef.h>

typedef struct cbm_http_server cbm_http_server_t;
struct cbm_watcher;

/* Create an HTTP server on the given port.
 * Creates its own cbm_mcp_server_t with a separate read-only SQLite connection.
 * Returns NULL on failure (e.g. port in use). */
cbm_http_server_t *cbm_http_server_new(int port);

/* Free the HTTP server (call after thread has been joined). */
void cbm_http_server_free(cbm_http_server_t *srv);

/* Signal the HTTP server to stop (safe to call from any thread). */
void cbm_http_server_stop(cbm_http_server_t *srv);

/* Run the HTTP server event loop (call from background thread).
 * Blocks until cbm_http_server_stop() is called. */
void cbm_http_server_run(cbm_http_server_t *srv);

/* Check if the server started successfully (listener bound). */
bool cbm_http_server_is_running(const cbm_http_server_t *srv);

/* The actually-bound port (useful when constructed with port 0 in tests). */
int cbm_http_server_port(const cbm_http_server_t *srv);

/* Override the per-connection receive deadline (tests use short values). */
void cbm_http_server_set_recv_deadline_ms(cbm_http_server_t *srv, int ms);

/* Set external watcher reference for UI project lifecycle actions. Not owned. */
void cbm_http_server_set_watcher(cbm_http_server_t *srv, struct cbm_watcher *watcher);

/* Initialize the log ring buffer mutex. Must be called once before any threads. */
void cbm_ui_log_init(void);

/* Append a log line to the UI ring buffer (called from log hook). */
void cbm_ui_log_append(const char *line);

/* Exact worker-executable binding result. A non-OK result never changes an
 * existing binding. `native_error` receives a Win32 error (or errno on POSIX)
 * only when the operating system supplied one; otherwise it is set to zero. */
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

/* Bind the running OS process image without consulting argv or PATH. */
cbm_worker_binary_status_t cbm_http_server_bind_self_binary(unsigned long *native_error);

/* Bind one absolute, existing ordinary executable. The path is opened first;
 * its final path and stable file identity are read from that handle, and the
 * handle is retained for the process lifetime with write/delete sharing denied.
 * The first identity wins. Rebinding that same identity is idempotent; a
 * different identity is a conflict and leaves the original binding untouched. */
cbm_worker_binary_status_t cbm_http_server_bind_explicit_binary(const char *path,
                                                                unsigned long *native_error);

/* Return the immutable final path retained by a successful bind, or NULL. The
 * returned process-lifetime string must not be freed or modified. */
const char *cbm_http_server_binary_path(void);

/* Stable diagnostic fields for every binding status. Unknown integers map to
 * an explicit unknown-status diagnostic rather than an empty string. */
const char *cbm_http_server_binary_status_code(int status);
const char *cbm_http_server_binary_status_message(int status);
const char *cbm_http_server_binary_status_remediation(int status);

/* Pure git-remote URL helpers used by GET /api/repo-info. Exposed for tests. */

/* Normalize a git remote (scp-style / ssh:// / https://) to a canonical
 * "https://host/org/repo" web base, with trailing ".git" and any embedded
 * credentials removed. malloc'd or NULL. Caller frees. */
char *cbm_ui_git_web_base(const char *url);

/* Copy `url` with any "user[:password]@" userinfo stripped from a
 * scheme://authority URL (scp-style is left unchanged). malloc'd, or NULL when
 * `url` is NULL. Caller frees. */
char *cbm_ui_git_strip_credentials(const char *url);

#endif /* CBM_UI_HTTP_SERVER_H */
