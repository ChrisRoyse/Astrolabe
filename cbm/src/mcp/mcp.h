/*
 * mcp.h — MCP (Model Context Protocol) server for codebase-memory-mcp.
 *
 * Implements JSON-RPC 2.0 over stdio with the MCP tool calling protocol.
 * Provides 14 graph analysis tools (search, trace, query, index, etc.)
 */
#ifndef CBM_MCP_H
#define CBM_MCP_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "graph_buffer/row_sink.h"

/* ── Astrolabe reserved store-dir sidecar suffixes (#414) ─────────
 *
 * The Astrolabe Rust host writes per-project sidecar artifacts into the SAME
 * CBM store (cache) directory that holds the "<name>.db" project stores. The
 * lowered-SQLite mirror is written as "<name>.astrolabe-lowered.db": it ends in
 * ".db" but is NOT a project store. Without a filter it surfaces in
 * list_projects as a phantom 0-node project and can be adopted by resolve_store
 * as a stand-in for the real store. Every store-dir walk routes through
 * is_project_db_file() (mcp.c), which rejects any file ending in a suffix listed
 * here — the single reserved-suffix contract.
 *
 * DRIFT CONTRACT: this string MUST byte-match the Rust host's write-side
 * constant LOWERED_SQLITE_SUFFIX in
 * crates/astrolabe-server/src/migration/mod.rs. It is placed in this
 * bindgen-visible header (crates/cbm-sys parses via astro_ffi.h → mcp/mcp.h) so
 * the Rust side binds the two with a compile-time assertion; editing either
 * without the other fails the astrolabe-server build. */
#define CBM_ASTRO_LOWERED_DB_SUFFIX ".astrolabe-lowered.db"

/* Second reserved family: the git-archaeology scratch store
 * ".astrolabe-archaeology-<pid>-<nanos>.db" (written by the Rust host's
 * historical-commit indexer into the same store dir; transient, but live during
 * an archaeology pass and left behind by a crash). Its nonce tail varies, so
 * this family is matched by PREFIX. Same drift contract: MUST byte-match
 * ARCHAEOLOGY_DB_PREFIX in
 * crates/astrolabe-server/src/migration/git_archaeology.rs. */
#define CBM_ASTRO_ARCHAEOLOGY_DB_PREFIX ".astrolabe-archaeology-"

/* ── Forward declarations ─────────────────────────────────────── */

typedef struct cbm_store cbm_store_t; /* from store/store.h */
struct cbm_watcher;                   /* from watcher/watcher.h */
struct cbm_config;                    /* from cli/cli.h */

/* ── JSON-RPC types ───────────────────────────────────────────── */

typedef struct {
    const char *jsonrpc;    /* "2.0" */
    const char *method;     /* e.g. "initialize", "tools/call" */
    int64_t id;             /* request ID (numeric form; -1 if notification) */
    const char *id_str;     /* non-NULL when id is a JSON string (issue #253) */
    bool has_id;            /* false for notifications */
    const char *params_raw; /* raw JSON string of params */
} cbm_jsonrpc_request_t;

typedef struct {
    int64_t id;
    const char *id_str;      /* non-NULL to echo a string id verbatim (issue #253) */
    const char *result_json; /* JSON string for result (success) */
    const char *error_json;  /* JSON string for error (failure), NULL on success */
    int error_code;          /* JSON-RPC error code */
} cbm_jsonrpc_response_t;

/* ── JSON-RPC parsing / formatting ────────────────────────────── */

/* Parse a JSON-RPC request line. Returns 0 on success, -1 on error.
 * Caller must call cbm_jsonrpc_request_free(). */
int cbm_jsonrpc_parse(const char *line, cbm_jsonrpc_request_t *out);
void cbm_jsonrpc_request_free(cbm_jsonrpc_request_t *r);

/* Format a JSON-RPC response. Returns heap-allocated JSON string. */
char *cbm_jsonrpc_format_response(const cbm_jsonrpc_response_t *resp);

/* Format a JSON-RPC error response. Returns heap-allocated JSON string. */
char *cbm_jsonrpc_format_error(int64_t id, int code, const char *message);

/* ── MCP protocol helpers ─────────────────────────────────────── */

/* Format an MCP tool result with text content. Returns heap-allocated JSON. */
char *cbm_mcp_text_result(const char *text, bool is_error);

/* Return true when notifications/cancelled params target the active request. */
bool cbm_mcp_cancel_request_matches(const char *params_json, int64_t active_id,
                                    const char *active_id_str);

/* Format the tools/list response. Returns heap-allocated JSON. */
char *cbm_mcp_tools_list(void);

/* Return a tool's JSON input_schema string by name (static; do not free), or
 * NULL if the tool is unknown. Backs the CLI flag parser + per-tool --help. */
const char *cbm_mcp_tool_input_schema(const char *tool_name);

/* Format the initialize response. params_json is the raw initialize params
 * (used for protocol version negotiation). Returns heap-allocated JSON. */
char *cbm_mcp_initialize_response(const char *params_json);

/* ── Tool argument helpers ────────────────────────────────────── */

/* Extract a string argument from the tools/call params JSON.
 * Returns heap-allocated copy, or NULL if not found. */
char *cbm_mcp_get_string_arg(const char *args_json, const char *key);

/* Extract an int argument. Returns default_val if not found. */
int cbm_mcp_get_int_arg(const char *args_json, const char *key, int default_val);

/* Extract a bool argument. Returns false if not found. */
bool cbm_mcp_get_bool_arg(const char *args_json, const char *key);

/* Extract the tool name from a tools/call params JSON. Heap-allocated. */
char *cbm_mcp_get_tool_name(const char *params_json);

/* Extract the arguments sub-object from tools/call params. Heap-allocated JSON string. */
char *cbm_mcp_get_arguments(const char *params_json);

/* ── MCP Server ───────────────────────────────────────────────── */

typedef struct cbm_mcp_server cbm_mcp_server_t;

/* Create an MCP server. store_path is the SQLite database directory. */
cbm_mcp_server_t *cbm_mcp_server_new(const char *store_path);

/* Free an MCP server. */
void cbm_mcp_server_free(cbm_mcp_server_t *srv);

/* Set external watcher reference (for auto-index registration). Not owned. */
void cbm_mcp_server_set_watcher(cbm_mcp_server_t *srv, struct cbm_watcher *w);

/* Set external config store reference (for auto_index setting). Not owned. */
void cbm_mcp_server_set_config(cbm_mcp_server_t *srv, struct cbm_config *cfg);

/* Install row-sink callbacks for index_repository pipelines created by this
 * server. Passing NULL callbacks restores the default no-sink behavior. */
void cbm_mcp_server_set_row_sink(cbm_mcp_server_t *srv, cbm_gbuf_row_node_sink_fn node_cb,
                                 cbm_gbuf_row_edge_sink_fn edge_cb, void *ctx);

/* Run the MCP server event loop on the given streams (typically stdin/stdout).
 * Blocks until EOF on input. Returns 0 on success, -1 on error. */
int cbm_mcp_server_run(cbm_mcp_server_t *srv, FILE *in, FILE *out);

/* Process a single JSON-RPC request line and return the response.
 * Returns heap-allocated JSON response string, or NULL for notifications. */
char *cbm_mcp_server_handle(cbm_mcp_server_t *srv, const char *line);

/* ── Tool handler dispatch (for testing) ──────────────────────── */

/* Handle a tools/call request. Returns MCP tool result JSON. */
char *cbm_mcp_handle_tool(cbm_mcp_server_t *srv, const char *tool_name, const char *args_json);

/* ── Supervised background index (RSS isolation, #832) ────────── */

/* Run a full index of root_path in a supervised worker SUBPROCESS (the same
 * crash/hang-isolating runner used by handle_index_repository), so the child
 * returns 100% of its RSS to the OS on exit instead of ratcheting the long-lived
 * parent. Builds {"repo_path": root_path} internally. Returns the worker's
 * response string (caller frees) on success, or NULL to signal the caller must
 * degrade to the in-process path (kill switch set, spawn failure, or the process
 * is not a supervisor host). This is the shared entry the watcher re-index
 * (main.c) and the session auto-index (mcp.c) route through. */
char *cbm_mcp_index_run_supervised_path(const char *root_path);

/* Run a full index of args_json's repo_path in a supervised worker SUBPROCESS,
 * FAILING CLOSED instead of degrading to the in-process pipeline (#405). This is
 * the shadow full-index entry: the CBM pipeline pass runs OUT OF PROCESS so a hard
 * abort (segfault/abort-class) is contained in the child and can never leave a
 * partially-written vault; the parent rebuilds the graph row stream from the
 * child's persisted <project>.db after a clean exit (it registers no row sink —
 * an FFI callback cannot cross the process boundary). On a clean worker exit this
 * returns the worker's own index_repository response verbatim. A spawn failure, an
 * unavailable supervisor, or a contained worker crash/hang is returned as a
 * fail-closed {isError} tool result carrying `outcome` (and, in diagnostic builds,
 * the worker's exit code and log tail) so the caller refuses before it touches the
 * vault. Unlike cbm_mcp_index_run_supervised_path this NEVER returns NULL and
 * NEVER degrades to an in-process run. */
char *cbm_mcp_index_repository_supervised_strict(cbm_mcp_server_t *srv, const char *args);

/* ── Idle store eviction ──────────────────────────────────────── */

/* Evict the cached project store if idle for more than timeout_s seconds.
 * Protects initial in-memory stores (those never accessed via a named project).
 * Called automatically by the event loop on poll() timeout. */
void cbm_mcp_server_evict_idle(cbm_mcp_server_t *srv, int timeout_s);

/* Check if the server currently has a cached store open. */
bool cbm_mcp_server_has_cached_store(cbm_mcp_server_t *srv);

/* ── Testing helpers ───────────────────────────────────────────── */

/* Get the store handle from a server (for test setup). */
cbm_store_t *cbm_mcp_server_store(cbm_mcp_server_t *srv);

/* Set the project name associated with the server's current store (for test setup).
 * This prevents resolve_store() from trying to open a .db file when tools specify a project. */
void cbm_mcp_server_set_project(cbm_mcp_server_t *srv, const char *project);

/* ── Cancellation support ─────────────────────────────────────── */

struct cbm_pipeline; /* forward decl */

/* Get the currently active pipeline (for signal handler cancellation).
 * Returns NULL if no pipeline is running. */
struct cbm_pipeline *cbm_mcp_server_active_pipeline(cbm_mcp_server_t *srv);

/* ── URI helpers ───────────────────────────────────────────────── */

/* Parse a file:// URI and extract the filesystem path.
 * Writes to out_path (up to out_size bytes). Returns true on success.
 * On Windows, strips leading / from /C:/path. */
bool cbm_parse_file_uri(const char *uri, char *out_path, int out_size);

#endif /* CBM_MCP_H */
